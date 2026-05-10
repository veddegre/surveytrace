<?php
/**
 * Credentialed-check job scheduling — cron parsing / next-fire computation (UTC storage).
 *
 * Mirrors semantics in daemon/scheduler_daemon.py (parse_cron, next_cron_run, PRESETS).
 * Limitations: 5-field cron only; dow uses 0=Sunday like standard cron; no L/W/# modifiers;
 * month/day names not supported; step/range/list same as Python helper.
 *
 * @see docs/CREDENTIALED_CHECKS_ENGINE.md
 */

declare(strict_types=1);

/** @var array<string, string> */
const ST_CC_CRON_PRESETS = [
    '@yearly'   => '0 0 1 1 *',
    '@annually' => '0 0 1 1 *',
    '@monthly'  => '0 0 1 * *',
    '@weekly'   => '0 0 * * 0',
    '@daily'    => '0 0 * * *',
    '@midnight' => '0 0 * * *',
    '@hourly'   => '0 * * * *',
];

/**
 * @return array{0: string, 1: string, 2: string, 3: string, 4: string}|null
 */
function st_cc_schedule_parse_cron(string $expr): ?array
{
    $expr = trim($expr);
    if ($expr === '') {
        return null;
    }
    if (isset(ST_CC_CRON_PRESETS[$expr])) {
        $expr = ST_CC_CRON_PRESETS[$expr];
    }
    $parts = preg_split('/\s+/', $expr, -1, PREG_SPLIT_NO_EMPTY);
    if ($parts === false || count($parts) !== 5) {
        return null;
    }

    /** @var array{0: string, 1: string, 2: string, 3: string, 4: string} */
    return [$parts[0], $parts[1], $parts[2], $parts[3], $parts[4]];
}

function st_cc_schedule_matches_field(int $value, string $field): bool
{
    if ($field === '*') {
        return true;
    }
    foreach (explode(',', $field) as $part) {
        $part = trim($part);
        if ($part === '') {
            continue;
        }
        if (str_contains($part, '/')) {
            [$rangePart, $stepStr] = explode('/', $part, 2);
            $step = (int) $stepStr;
            if ($step < 1) {
                continue;
            }
            if ($rangePart === '*') {
                $start = 0;
                $end = 59;
            } elseif (str_contains($rangePart, '-')) {
                [$lo, $hi] = array_map('intval', explode('-', $rangePart, 2));
                $start = $lo;
                $end = $hi;
            } else {
                $start = $end = (int) $rangePart;
            }
            if ($value >= $start && $value <= $end && (($value - $start) % $step) === 0) {
                return true;
            }
        } elseif (str_contains($part, '-')) {
            [$lo, $hi] = array_map('intval', explode('-', $part, 2));
            if ($value >= $lo && $value <= $hi) {
                return true;
            }
        } else {
            if ($value === (int) $part) {
                return true;
            }
        }
    }

    return false;
}

function st_cc_schedule_cron_matches(string $expr, \DateTimeImmutable $dtLocal): bool
{
    $parsed = st_cc_schedule_parse_cron($expr);
    if ($parsed === null) {
        return false;
    }
    [$minute, $hour, $dom, $month, $dow] = $parsed;
    $cronDow = (int) $dtLocal->format('w');

    return st_cc_schedule_matches_field((int) $dtLocal->format('i'), $minute)
        && st_cc_schedule_matches_field((int) $dtLocal->format('G'), $hour)
        && st_cc_schedule_matches_field((int) $dtLocal->format('j'), $dom)
        && st_cc_schedule_matches_field((int) $dtLocal->format('n'), $month)
        && st_cc_schedule_matches_field($cronDow, $dow);
}

/**
 * Next fire strictly after $afterUtc (naive UTC string or DateTimeInterface UTC).
 *
 * @throws InvalidArgumentException
 */
function st_cc_schedule_next_run_utc(string $expr, string $timezone, \DateTimeInterface $afterUtc): \DateTimeImmutable
{
    $exprNorm = trim($expr);
    if ($exprNorm === '') {
        throw new InvalidArgumentException('empty cron');
    }
    if (st_cc_schedule_parse_cron($exprNorm) === null) {
        throw new InvalidArgumentException('invalid cron expression');
    }
    try {
        $tz = new \DateTimeZone(trim($timezone) !== '' ? $timezone : 'UTC');
    } catch (\Throwable) {
        throw new InvalidArgumentException('invalid timezone');
    }
    $afterUtcImm = $afterUtc instanceof \DateTimeImmutable
        ? $afterUtc->setTimezone(new \DateTimeZone('UTC'))
        : \DateTimeImmutable::createFromInterface($afterUtc)->setTimezone(new \DateTimeZone('UTC'));
    $afterLocal = $afterUtcImm->setTimezone($tz);
    $probe = $afterLocal->setTime((int) $afterLocal->format('G'), (int) $afterLocal->format('i'), 0)->modify('+1 minute');

    $cap = 366 * 24 * 60;
    for ($i = 0; $i < $cap; ++$i) {
        if (st_cc_schedule_cron_matches($exprNorm, $probe)) {
            return $probe->setTimezone(new \DateTimeZone('UTC'));
        }
        $probe = $probe->modify('+1 minute');
    }
    throw new InvalidArgumentException('could not compute next run (cron too restrictive?)');
}

/**
 * @return ?string error message or null if ok
 */
function st_cc_schedule_validate_cron(?string $expr): ?string
{
    if ($expr === null || trim((string) $expr) === '') {
        return 'schedule_cron is required when scheduling is enabled';
    }
    if (st_cc_schedule_parse_cron((string) $expr) === null) {
        return 'invalid cron expression (expect 5 fields, @hourly/@daily/… or see docs)';
    }

    return null;
}

/**
 * @return ?string error or null
 */
function st_cc_schedule_validate_timezone(?string $tzName): ?string
{
    $t = trim((string) $tzName);
    if ($t === '') {
        return null;
    }
    try {
        new \DateTimeZone($t);

        return null;
    } catch (\Throwable) {
        return 'invalid schedule_timezone (not a valid PHP/zoneinfo identifier)';
    }
}

/**
 * SQLite-friendly UTC naive timestamp.
 */
function st_cc_schedule_next_run_sqlite(string $cronExpr, string $timezone, \DateTimeInterface $afterUtc): string
{
    $next = st_cc_schedule_next_run_utc($cronExpr, $timezone, $afterUtc);

    return $next->format('Y-m-d H:i:s');
}
