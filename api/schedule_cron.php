<?php
/**
 * Scan schedule cron helpers — mirrors daemon/scheduler_daemon.py (PRESETS, next_cron_run).
 * Computes next fire as UTC-naive "Y-m-d H:i:s" for SQLite, matching the scheduler daemon.
 */

/** @var array<string,string> */
const ST_SCHEDULE_CRON_PRESETS = [
    '@yearly' => '0 0 1 1 *',
    '@annually' => '0 0 1 1 *',
    '@monthly' => '0 0 1 * *',
    '@weekly' => '0 0 * * 0',
    '@daily' => '0 0 * * *',
    '@midnight' => '0 0 * * *',
    '@hourly' => '0 * * * *',
];

/**
 * @return array{0:string,1:string,2:string,3:string,4:string}
 */
function st_schedule_parse_cron(string $expr): array
{
    $expr = trim($expr);
    if (isset(ST_SCHEDULE_CRON_PRESETS[$expr])) {
        $expr = ST_SCHEDULE_CRON_PRESETS[$expr];
    }
    $parts = preg_split('/\s+/', $expr, -1, PREG_SPLIT_NO_EMPTY);
    if (!is_array($parts) || count($parts) !== 5) {
        throw new InvalidArgumentException('cron_expr must be 5 fields or a @preset');
    }
    return [$parts[0], $parts[1], $parts[2], $parts[3], $parts[4]];
}

function st_schedule_matches_field(int $value, string $field): bool
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
            if ($step <= 0) {
                continue;
            }
            if ($rangePart === '*') {
                $start = 0;
                $end = 59;
            } elseif (str_contains($rangePart, '-')) {
                [$start, $end] = array_map('intval', explode('-', $rangePart, 2));
            } else {
                $start = $end = (int) $rangePart;
            }
            if ($value >= $start && $value <= $end && ($value - $start) % $step === 0) {
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

function st_schedule_cron_matches(string $expr, DateTimeImmutable $dtLocal): bool
{
    try {
        [$minute, $hour, $dom, $month, $dow] = st_schedule_parse_cron($expr);
    } catch (Throwable $e) {
        return false;
    }
    $cronDow = (int) $dtLocal->format('w');

    return st_schedule_matches_field((int) $dtLocal->format('i'), $minute)
        && st_schedule_matches_field((int) $dtLocal->format('G'), $hour)
        && st_schedule_matches_field((int) $dtLocal->format('j'), $dom)
        && st_schedule_matches_field((int) $dtLocal->format('n'), $month)
        && st_schedule_matches_field($cronDow, $dow);
}

/**
 * Next cron fire strictly after $afterUtc, in schedule timezone, returned as UTC-naive datetime string.
 *
 * @throws InvalidArgumentException when no slot is found within the search horizon
 */
function st_schedule_next_run_utc_naive(string $cronExpr, string $timezone, ?DateTimeImmutable $afterUtc = null): string
{
    $cronExpr = trim($cronExpr);
    if ($cronExpr === '') {
        throw new InvalidArgumentException('empty cron_expr');
    }
    if ($afterUtc === null) {
        $afterUtc = new DateTimeImmutable('now', new DateTimeZone('UTC'));
    } else {
        $afterUtc = $afterUtc->setTimezone(new DateTimeZone('UTC'));
    }
    try {
        $tz = new DateTimeZone($timezone !== '' ? $timezone : 'UTC');
    } catch (Throwable $e) {
        $tz = new DateTimeZone('UTC');
    }

    $afterLocal = $afterUtc->setTimezone($tz);
    $dtLocal = $afterLocal->setTime((int) $afterLocal->format('H'), (int) $afterLocal->format('i'), 0);
    $dtLocal = $dtLocal->modify('+1 minute');

    $max = 366 * 24 * 60;
    for ($i = 0; $i < $max; $i++) {
        if (st_schedule_cron_matches($cronExpr, $dtLocal)) {
            return $dtLocal->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s');
        }
        $dtLocal = $dtLocal->modify('+1 minute');
    }

    throw new InvalidArgumentException('Could not find next run for cron: ' . $cronExpr);
}
