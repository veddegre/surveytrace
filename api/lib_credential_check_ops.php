<?php
/**
 * SurveyTrace — credentialed check job templates + runs (slice 6 queueing; worker SSH + SNMPv3 plugins per slice 9).
 *
 * @see docs/CREDENTIALED_CHECKS_ENGINE.md
 */

declare(strict_types=1);

require_once __DIR__ . '/lib_credentialed_checks.php';
require_once __DIR__ . '/lib_credential_profiles.php';
require_once __DIR__ . '/lib_worker_jobs.php';
require_once __DIR__ . '/lib_scan_scopes.php';

/** Worker substrate job_type for credentialed check runs. */
const ST_CC_WORKER_JOB_TYPE = 'credentialed_check';

/** entity_type on worker_jobs referencing credential_check_runs.id */
const ST_CC_WORKER_ENTITY_TYPE = 'credential_check_run';

function st_cc_ops_tables_ready(PDO $pdo): bool
{
    if (! st_cred_tables_ready($pdo) || ! st_cred_profile_tables_ready($pdo)) {
        return false;
    }
    try {
        $n = $pdo->query(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'credential_check_jobs' LIMIT 1"
        )->fetchColumn();

        return $n !== false && $n !== null;
    } catch (Throwable) {
        return false;
    }
}

/**
 * @param array<string, mixed>|null $raw
 *
 * @return array{0:?string,1:?string}
 */
function st_cc_ops_encode_json(?array $raw, string $label): array
{
    if ($raw === null || $raw === []) {
        return [null, null];
    }
    try {
        $s = json_encode($raw, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($s === false) {
            return [null, $label . ' encode failed'];
        }

        return [$s, null];
    } catch (Throwable) {
        return [null, $label . ' encode failed'];
    }
}

/**
 * @return array<string, mixed>
 */
function st_cc_ops_default_policy(): array
{
    return [
        'max_concurrency' => 4,
        'timeout_ms'      => 600000,
    ];
}

/**
 * @param mixed $policyJson
 *
 * @return array{0: array<string, mixed>, 1: ?string}
 */
function st_cc_ops_decode_policy_json(mixed $policyJson): array
{
    $def = st_cc_ops_default_policy();
    if ($policyJson === null || $policyJson === '') {
        return [$def, null];
    }
    if (is_string($policyJson)) {
        $t = trim($policyJson);
        if ($t === '') {
            return [$def, null];
        }
        try {
            $tmp = json_decode($t, true, 32, JSON_THROW_ON_ERROR);
            $arr = is_array($tmp) ? $tmp : [];
        } catch (Throwable) {
            return [$def, 'policy_json must be valid JSON object'];
        }
    } elseif (is_array($policyJson)) {
        $arr = $policyJson;
    } else {
        return [$def, 'policy_json must be object or JSON string'];
    }
    $mc = isset($arr['max_concurrency']) ? (int) $arr['max_concurrency'] : (int) $def['max_concurrency'];
    $mc = max(1, min(50, $mc));
    $to = isset($arr['timeout_ms']) ? (int) $arr['timeout_ms'] : (int) $def['timeout_ms'];
    $to = max(5000, min(3600000, $to));

    return [['max_concurrency' => $mc, 'timeout_ms' => $to], null];
}

/**
 * @param mixed $raw
 *
 * @return array{0: list<array{plugin_key:string,version:string}>, 1: ?string}
 */
function st_cc_ops_parse_plugin_selection(mixed $raw): array
{
    if (! is_array($raw) || $raw === []) {
        return [[], 'plugin_selection_json must be a non-empty array'];
    }
    $out = [];
    foreach ($raw as $i => $row) {
        if (! is_array($row)) {
            return [[], 'plugin_selection_json[' . $i . '] must be object'];
        }
        $pk = isset($row['plugin_key']) ? trim((string) $row['plugin_key']) : '';
        $ver = isset($row['version']) ? trim((string) $row['version']) : '';
        if ($pk === '') {
            return [[], 'plugin_selection_json[' . $i . '].plugin_key required'];
        }
        $out[] = ['plugin_key' => $pk, 'version' => $ver];
    }
    if ($out === []) {
        return [[], 'plugin_selection_json must list at least one plugin'];
    }

    return [$out, null];
}

/**
 * @param list<array{plugin_key:string,version:string}> $plugins
 *
 * @return array{0: list<string>,1: list<array{plugin_key:string,version:string,state:string}>}
 */
function st_cc_ops_plugin_warnings(PDO $pdo, array $plugins): array
{
    $errs = [];
    $exp = [];
    foreach ($plugins as $p) {
        $pl = st_cred_get_plugin($pdo, $p['plugin_key'], $p['version'] !== '' ? $p['version'] : null);
        if ($pl === null) {
            $errs[] = 'Unknown plugin: ' . $p['plugin_key'] . ($p['version'] !== '' ? '@' . $p['version'] : '');

            continue;
        }
        $st = strtolower(trim((string) ($pl['state'] ?? '')));
        if ($st === 'experimental') {
            $exp[] = [
                'plugin_key' => $p['plugin_key'],
                'version'    => (string) ($pl['version'] ?? ''),
                'state'      => $st,
            ];
        }
    }

    return [$errs, $exp];
}

/**
 * @param list<array{plugin_key:string,version:string}> $plugins
 *
 * @return array{0: bool, 1: ?string, 2: list<string>}
 */
function st_cc_ops_validate_plugins_for_profile(PDO $pdo, string $profileTransport, array $plugins): array
{
    $errs = [];
    foreach ($plugins as $p) {
        $pl = st_cred_get_plugin($pdo, $p['plugin_key'], $p['version'] !== '' ? $p['version'] : null);
        if ($pl === null) {
            $errs[] = 'Plugin not found: ' . $p['plugin_key'];

            continue;
        }
        $t = strtolower(trim((string) ($pl['transport'] ?? '')));
        if ($t !== strtolower($profileTransport)) {
            $errs[] = 'Plugin ' . $p['plugin_key'] . ' transport ' . $t . ' does not match profile transport ' . $profileTransport;
        }
    }

    return [$errs === [], $errs === [] ? null : implode('; ', $errs), $errs];
}

/**
 * @param array<string, mixed> $targetJson
 *
 * @return array{0: list<int>, 1: ?string}
 */
function st_cc_ops_resolve_asset_ids(PDO $pdo, string $targetMode, array $targetJson): array
{
    $mode = strtolower(trim($targetMode));
    if ($mode === 'assets') {
        $raw = $targetJson['asset_ids'] ?? null;
        if (! is_array($raw) || $raw === []) {
            return [[], 'target_json.asset_ids must be a non-empty array'];
        }
        $ids = [];
        foreach ($raw as $v) {
            $n = (int) $v;
            if ($n >= 1) {
                $ids[$n] = true;
            }
        }
        $uniq = array_keys($ids);
        sort($uniq, SORT_NUMERIC);
        if ($uniq === []) {
            return [[], 'No valid asset IDs'];
        }
        $ph = implode(',', array_fill(0, count($uniq), '?'));
        $st = $pdo->prepare("SELECT id FROM assets WHERE id IN ($ph)");
        $st->execute($uniq);
        $found = [];
        foreach ($st->fetchAll(PDO::FETCH_COLUMN) as $col) {
            $found[(int) $col] = true;
        }
        foreach ($uniq as $id) {
            if (! isset($found[$id])) {
                return [[], 'Unknown or missing asset id: ' . $id];
            }
        }

        return [$uniq, null];
    }
    if ($mode === 'scope') {
        if (! st_assets_has_scope_id($pdo)) {
            return [[], 'Scope-based targets require assets.scope_id (run DB migrations)'];
        }
        $raw = $targetJson['scope_ids'] ?? null;
        if (! is_array($raw) || $raw === []) {
            return [[], 'target_json.scope_ids must be a non-empty array'];
        }
        $scopeIds = [];
        foreach ($raw as $v) {
            $n = (int) $v;
            if ($n >= 1) {
                $scopeIds[$n] = true;
            }
        }
        $scopes = array_keys($scopeIds);
        sort($scopes, SORT_NUMERIC);
        if ($scopes === []) {
            return [[], 'No valid scope IDs'];
        }
        $phs = implode(',', array_fill(0, count($scopes), '?'));
        $chk = $pdo->prepare("SELECT id FROM scan_scopes WHERE id IN ($phs)");
        $chk->execute($scopes);
        $haveS = [];
        foreach ($chk->fetchAll(PDO::FETCH_COLUMN) as $c) {
            $haveS[(int) $c] = true;
        }
        foreach ($scopes as $sid) {
            if (! isset($haveS[$sid])) {
                return [[], 'Unknown scope id: ' . $sid];
            }
        }
        $pha = implode(',', array_fill(0, count($scopes), '?'));
        $sql = "SELECT DISTINCT id FROM assets WHERE scope_id IN ($pha)
            AND (lifecycle_status IS NULL OR lifecycle_status = '' OR lower(lifecycle_status) = 'active')
            AND (retired_at IS NULL OR retired_at = '')";
        $st = $pdo->prepare($sql);
        $st->execute($scopes);
        $assetIds = [];
        foreach ($st->fetchAll(PDO::FETCH_COLUMN) as $col) {
            $assetIds[] = (int) $col;
        }
        sort($assetIds, SORT_NUMERIC);
        if ($assetIds === []) {
            return [[], 'No active assets found for the selected scope(s)'];
        }

        return [$assetIds, null];
    }

    return [[], 'target_mode must be assets or scope'];
}

/**
 * @param array<string, mixed> $in
 *
 * @return array{0: ?array<string, mixed>, 1: ?string, 2: list<string>, 3: list<array<string, mixed>>}
 *     [normalized, error, validation_errors, experimental_warnings]
 */
function st_cc_ops_normalize_job_input(PDO $pdo, array $in): array
{
    $warnings = [];
    $errs = [];
    $name = substr(trim((string) ($in['name'] ?? '')), 0, 200);
    if ($name === '') {
        $errs[] = 'name is required';
    }
    $desc = isset($in['description']) ? trim((string) $in['description']) : null;
    if ($desc !== null && strlen($desc) > 8000) {
        $desc = substr($desc, 0, 8000);
    }
    $pfId = isset($in['credential_profile_id']) ? (int) $in['credential_profile_id'] : 0;
    if ($pfId < 1) {
        $errs[] = 'credential_profile_id required';
    }
    $prof = $pfId >= 1 ? st_cred_profile_get_active($pdo, $pfId) : null;
    if ($pfId >= 1 && $prof === null) {
        $errs[] = 'credential profile not found';
    }
    if (is_array($prof) && empty($prof['enabled'])) {
        $errs[] = 'credential profile is disabled';
    }
    $transport = is_array($prof) ? strtolower(trim((string) ($prof['transport'] ?? ''))) : '';
    $tm = strtolower(trim((string) ($in['target_mode'] ?? '')));
    if (! in_array($tm, ['assets', 'scope'], true)) {
        $errs[] = 'target_mode must be assets or scope';
    }
    $tj = $in['target_json'] ?? null;
    if (! is_array($tj)) {
        $errs[] = 'target_json must be object';
        $tj = [];
    }
    [$plugins, $pe] = st_cc_ops_parse_plugin_selection($in['plugin_selection_json'] ?? null);
    if ($pe !== null) {
        $errs[] = $pe;
    }
    [$pol, $polErr] = st_cc_ops_decode_policy_json($in['policy_json'] ?? null);
    if ($polErr !== null) {
        $errs[] = $polErr;
    }
    $enabled = isset($in['enabled']) ? ((bool) $in['enabled'] || (string) $in['enabled'] === '1') : true;

    if ($plugins !== [] && $transport !== '' && $errs === []) {
        [$okP, $msgP, $elist] = st_cc_ops_validate_plugins_for_profile($pdo, $transport, $plugins);
        if (! $okP) {
            $errs = array_merge($errs, $elist);
        }
        [$pErrs, $exp] = st_cc_ops_plugin_warnings($pdo, $plugins);
        if ($pErrs !== []) {
            $errs = array_merge($errs, $pErrs);
        }
        foreach ($exp as $ex) {
            $warnings[] = $ex;
        }
    }

    [$assetIds, $resErr] = ($tm !== '' && $errs === []) ? st_cc_ops_resolve_asset_ids($pdo, $tm, $tj) : [[], null];
    if ($resErr !== null) {
        $errs[] = $resErr;
    }

    [$tjEnc, $e1] = st_cc_ops_encode_json($tj, 'target_json');
    if ($e1 !== null) {
        $errs[] = $e1;
    }
    [$pjEnc, $e2] = st_cc_ops_encode_json($plugins, 'plugin_selection_json');
    if ($e2 !== null) {
        $errs[] = $e2;
    }
    [$polEnc, $e3] = st_cc_ops_encode_json($pol, 'policy_json');
    if ($e3 !== null) {
        $errs[] = $e3;
    }

    if ($errs !== []) {
        return [null, implode('; ', $errs), $errs, $warnings];
    }

    return [[
        'name'                  => $name,
        'description'           => $desc,
        'credential_profile_id' => $pfId,
        'target_mode'           => $tm,
        'target_json'           => $tjEnc,
        'plugin_selection_json' => $pjEnc,
        'policy_json'           => $polEnc,
        'enabled'               => $enabled ? 1 : 0,
        '_resolved_asset_count' => count($assetIds),
    ], null, [], $warnings];
}

/**
 * @return list<array<string, mixed>>
 */
function st_cc_job_list(PDO $pdo): array
{
    if (! st_cc_ops_tables_ready($pdo)) {
        return [];
    }
    $st = $pdo->query(
        'SELECT j.id, j.name, j.description, j.credential_profile_id, j.target_mode, j.target_json, j.plugin_selection_json,
                j.policy_json, j.schedule_cron, j.enabled, j.created_by, j.created_at, j.updated_at,
                p.name AS profile_name, p.transport AS profile_transport
         FROM credential_check_jobs j
         LEFT JOIN credential_profiles p ON p.id = j.credential_profile_id AND p.deleted_at IS NULL
         ORDER BY j.updated_at DESC, j.id DESC'
    );
    $out = [];
    foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) {
        if (is_array($r)) {
            $out[] = $r;
        }
    }

    return $out;
}

/**
 * @return array<string, mixed>|null
 */
function st_cc_job_get(PDO $pdo, int $id): ?array
{
    if (! st_cc_ops_tables_ready($pdo) || $id < 1) {
        return null;
    }
    $st = $pdo->prepare(
        'SELECT j.id, j.name, j.description, j.credential_profile_id, j.target_mode, j.target_json, j.plugin_selection_json,
                j.policy_json, j.schedule_cron, j.enabled, j.created_by, j.created_at, j.updated_at,
                p.name AS profile_name, p.transport AS profile_transport
         FROM credential_check_jobs j
         LEFT JOIN credential_profiles p ON p.id = j.credential_profile_id AND p.deleted_at IS NULL
         WHERE j.id = ? LIMIT 1'
    );
    $st->execute([$id]);
    $r = $st->fetch(PDO::FETCH_ASSOC);

    return is_array($r) ? $r : null;
}

/**
 * @return array{0: int, 1: ?string} job id or error
 */
function st_cc_job_create(PDO $pdo, array $in, ?int $actorUserId): array
{
    if (! st_cc_ops_tables_ready($pdo)) {
        return [0, 'Credentialed checks schema not available'];
    }
    [$norm, $err, ,] = st_cc_ops_normalize_job_input($pdo, $in);
    if ($norm === null || $err !== null) {
        return [0, $err ?? 'validation failed'];
    }
    try {
        $pdo->prepare(
            'INSERT INTO credential_check_jobs (name, description, credential_profile_id, target_mode, target_json, plugin_selection_json, policy_json, schedule_cron, enabled, created_by, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, datetime(\'now\'), datetime(\'now\'))'
        )->execute([
            $norm['name'],
            $norm['description'],
            $norm['credential_profile_id'],
            $norm['target_mode'],
            $norm['target_json'],
            $norm['plugin_selection_json'],
            $norm['policy_json'],
            $norm['enabled'],
            $actorUserId !== null && $actorUserId > 0 ? $actorUserId : null,
        ]);

        return [(int) $pdo->lastInsertId(), null];
    } catch (Throwable $e) {
        return [0, 'Save failed'];
    }
}

/**
 * @return ?string error or null on success
 */
function st_cc_job_update(PDO $pdo, int $id, array $in): ?string
{
    if (! st_cc_ops_tables_ready($pdo) || $id < 1) {
        return 'Not found';
    }
    if (st_cc_job_get($pdo, $id) === null) {
        return 'Job not found';
    }
    $in['name'] = $in['name'] ?? '';
    [$norm, $err, ,] = st_cc_ops_normalize_job_input($pdo, $in);
    if ($norm === null || $err !== null) {
        return $err ?? 'validation failed';
    }
    try {
        $pdo->prepare(
            'UPDATE credential_check_jobs SET name = ?, description = ?, credential_profile_id = ?, target_mode = ?,
                target_json = ?, plugin_selection_json = ?, policy_json = ?, enabled = ?, updated_at = datetime(\'now\')
             WHERE id = ?'
        )->execute([
            $norm['name'],
            $norm['description'],
            $norm['credential_profile_id'],
            $norm['target_mode'],
            $norm['target_json'],
            $norm['plugin_selection_json'],
            $norm['policy_json'],
            $norm['enabled'],
            $id,
        ]);

        return null;
    } catch (Throwable $e) {
        return 'Update failed';
    }
}

function st_cc_job_delete(PDO $pdo, int $id): bool
{
    if (! st_cc_ops_tables_ready($pdo) || $id < 1) {
        return false;
    }
    try {
        $st = $pdo->prepare('DELETE FROM credential_check_jobs WHERE id = ?');
        $st->execute([$id]);

        return $st->rowCount() === 1;
    } catch (Throwable) {
        return false;
    }
}

/**
 * @return array{0: bool, 1: ?string, 2: ?array<string, mixed>, 3: ?array<string, mixed>}
 *     On failure, element 3 may hold e.g. experimental_plugins for the client.
 */
function st_cc_run_launch(PDO $pdo, int $jobId, string $actorUsername, bool $acceptExperimental): array
{
    if (! st_worker_tables_ready($pdo)) {
        return [false, 'Worker substrate not available', null, null];
    }
    if (! st_cc_ops_tables_ready($pdo) || $jobId < 1) {
        return [false, 'Job not found', null, null];
    }
    $job = st_cc_job_get($pdo, $jobId);
    if ($job === null) {
        return [false, 'Job not found', null, null];
    }
    if (empty($job['enabled'])) {
        return [false, 'Job is disabled', null, null];
    }
    $tj = [];
    if (! empty($job['target_json'])) {
        try {
            $tmp = json_decode((string) $job['target_json'], true, 64, JSON_THROW_ON_ERROR);
            $tj = is_array($tmp) ? $tmp : [];
        } catch (Throwable) {
            $tj = [];
        }
    }
    $plugins = [];
    if (! empty($job['plugin_selection_json'])) {
        try {
            $tmp = json_decode((string) $job['plugin_selection_json'], true, 64, JSON_THROW_ON_ERROR);
            $plugins = is_array($tmp) ? $tmp : [];
        } catch (Throwable) {
            $plugins = [];
        }
    }
    [$plist, $pe] = st_cc_ops_parse_plugin_selection($plugins);
    if ($pe !== null) {
        return [false, $pe, null, null];
    }
    $prof = st_cred_profile_get_active($pdo, (int) $job['credential_profile_id']);
    if ($prof === null || empty($prof['enabled'])) {
        return [false, 'Credential profile missing or disabled', null, null];
    }
    $transport = strtolower(trim((string) ($prof['transport'] ?? '')));
    [$okP, $msgP] = st_cc_ops_validate_plugins_for_profile($pdo, $transport, $plist);
    if (! $okP) {
        return [false, $msgP ?? 'Plugin validation failed', null, null];
    }
    [, $expWarn] = st_cc_ops_plugin_warnings($pdo, $plist);
    if ($expWarn !== [] && ! $acceptExperimental) {
        return [false, 'Experimental plugins require accept_experimental: true', null, ['experimental_plugins' => $expWarn]];
    }
    $tm = strtolower(trim((string) ($job['target_mode'] ?? '')));
    [$assetIds, $resErr] = st_cc_ops_resolve_asset_ids($pdo, $tm, $tj);
    if ($resErr !== null || $assetIds === []) {
        return [false, $resErr ?? 'No targets', null, null];
    }

    $actor = trim($actorUsername) !== '' ? substr(trim($actorUsername), 0, 200) : 'unknown';

    try {
        $pdo->exec('BEGIN IMMEDIATE');
        $pdo->prepare(
            'INSERT INTO credential_check_runs (job_id, worker_job_id, status, initiated_by, summary_json, started_at)
             VALUES (?, NULL, \'resolving_targets\', ?, NULL, datetime(\'now\'))'
        )->execute([$jobId, $actor]);
        $runId = (int) $pdo->lastInsertId();
        if ($runId < 1) {
            $pdo->exec('ROLLBACK');

            return [false, 'Could not create run', null, null];
        }
        $insT = $pdo->prepare(
            'INSERT INTO credential_check_run_targets (run_id, asset_id, status, started_at, finished_at)
             VALUES (?, ?, \'pending\', NULL, NULL)'
        );
        foreach ($assetIds as $aid) {
            $insT->execute([$runId, $aid]);
        }
        $summary = [
            'target_count'          => count($assetIds),
            'resolved_mode'         => $tm,
            'credential_profile_id' => (int) $job['credential_profile_id'],
            'executor'              => 'credential_check_worker',
            'slice'                 => 7,
        ];
        $sumJ = json_encode($summary, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        $pdo->prepare(
            'UPDATE credential_check_runs SET status = \'queued\', summary_json = ? WHERE id = ?'
        )->execute([$sumJ ?: '{}', $runId]);

        $wjid = st_worker_enqueue_job($pdo, [
            'job_type'       => ST_CC_WORKER_JOB_TYPE,
            'entity_type'    => ST_CC_WORKER_ENTITY_TYPE,
            'entity_id'      => $runId,
            'priority'       => 0,
            'max_attempts'   => 3,
            'payload_json'   => [
                'credential_check_run_id' => $runId,
                'credential_check_job_id' => $jobId,
            ],
        ]);
        if ($wjid < 1) {
            $pdo->exec('ROLLBACK');

            return [false, 'Could not enqueue worker job', null, null];
        }
        $pdo->prepare('UPDATE credential_check_runs SET worker_job_id = ? WHERE id = ?')->execute([$wjid, $runId]);
        $pdo->exec('COMMIT');

        $row = $pdo->prepare('SELECT * FROM credential_check_runs WHERE id = ? LIMIT 1');
        $row->execute([$runId]);
        $out = $row->fetch(PDO::FETCH_ASSOC);

        return [true, null, is_array($out) ? $out : null, null];
    } catch (Throwable $e) {
        try {
            $pdo->exec('ROLLBACK');
        } catch (Throwable) {
        }

        return [false, 'Launch failed', null, null];
    }
}

/**
 * @return array{0: bool, 1: ?string}
 */
function st_cc_run_cancel(PDO $pdo, int $runId, string $actorUsername): array
{
    if (! st_cc_ops_tables_ready($pdo) || $runId < 1) {
        return [false, 'Run not found'];
    }
    $st = $pdo->prepare('SELECT id, job_id, worker_job_id, status FROM credential_check_runs WHERE id = ? LIMIT 1');
    $st->execute([$runId]);
    $r = $st->fetch(PDO::FETCH_ASSOC);
    if (! is_array($r)) {
        return [false, 'Run not found'];
    }
    $stRun = (string) ($r['status'] ?? '');
    if (! in_array($stRun, ['queued', 'resolving_targets', 'ready', 'running'], true)) {
        return [false, 'Run cannot be cancelled in status ' . $stRun];
    }
    $actor = trim($actorUsername) !== '' ? substr(trim($actorUsername), 0, 200) : 'unknown';
    $wjid = isset($r['worker_job_id']) ? (int) $r['worker_job_id'] : 0;

    try {
        $pdo->exec('BEGIN IMMEDIATE');
        $upd = $pdo->prepare(
            "UPDATE credential_check_runs SET status = 'cancelled', finished_at = datetime('now') WHERE id = ? AND status IN ('queued','resolving_targets','ready','running')"
        );
        $upd->execute([$runId]);
        if ($upd->rowCount() !== 1) {
            $pdo->exec('ROLLBACK');

            return [false, 'Run cannot be cancelled (already finished or concurrent update)'];
        }
        $pdo->prepare(
            "UPDATE credential_check_run_targets SET status = 'skipped', error_code = 'user_cancelled', error_message_safe = 'cancelled', finished_at = datetime('now')
             WHERE run_id = ? AND status = 'pending'"
        )->execute([$runId]);
        if ($wjid >= 1 && st_worker_tables_ready($pdo)) {
            st_worker_request_cancel($pdo, $wjid, $actor);
            st_worker_finalize_queued_cancel($pdo, $wjid);
            st_worker_finalize_leased_cancel($pdo, $wjid);
        }
        $pdo->exec('COMMIT');

        return [true, null];
    } catch (Throwable $e) {
        try {
            $pdo->exec('ROLLBACK');
        } catch (Throwable) {
        }

        return [false, 'Cancel failed'];
    }
}

/**
 * Approximate run wall duration in ms (null if cannot compute).
 */
function st_cc_run_duration_ms_approx(?string $startedAt, ?string $finishedAt): ?int
{
    $s = $startedAt !== null ? trim($startedAt) : '';
    if ($s === '') {
        return null;
    }
    $e = $finishedAt !== null && trim($finishedAt) !== '' ? trim($finishedAt) : date('Y-m-d H:i:s');
    $ts1 = strtotime($s);
    $ts2 = strtotime($e);
    if ($ts1 === false || $ts2 === false) {
        return null;
    }

    return max(0, (int) round(($ts2 - $ts1) * 1000));
}

/**
 * Filters: status?, transport?, plugin_substr?, profile_id?
 *
 * @param array<string, mixed> $filters
 *
 * @return list<array<string, mixed>>
 */
function st_cc_run_list(PDO $pdo, ?int $jobId = null, int $limit = 100, array $filters = []): array
{
    if (! st_cc_ops_tables_ready($pdo)) {
        return [];
    }
    $limit = max(1, min(500, $limit));
    $where = ['1=1'];
    $params = [];
    if ($jobId !== null && $jobId > 0) {
        $where[] = 'r.job_id = ?';
        $params[] = $jobId;
    }
    $stF = isset($filters['status']) ? strtolower(trim((string) $filters['status'])) : '';
    if ($stF !== '') {
        $where[] = 'r.status = ?';
        $params[] = $stF;
    }
    $trF = isset($filters['transport']) ? strtolower(trim((string) $filters['transport'])) : '';
    if ($trF !== '') {
        $where[] = 'LOWER(COALESCE(p.transport, \'\')) = ?';
        $params[] = $trF;
    }
    $profF = isset($filters['profile_id']) ? (int) $filters['profile_id'] : 0;
    if ($profF > 0) {
        $where[] = 'j.credential_profile_id = ?';
        $params[] = $profF;
    }
    $plugF = isset($filters['plugin_substr']) ? trim((string) $filters['plugin_substr']) : '';
    if ($plugF !== '') {
        $where[] = 'COALESCE(j.plugin_selection_json, \'\') LIKE ?';
        $params[] = '%' . str_replace(['%', '_'], ['\\%', '\\_'], $plugF) . '%';
    }
    $sql = 'SELECT r.*, j.name AS job_name, j.credential_profile_id,
                    COALESCE(p.transport, \'\') AS profile_transport, COALESCE(p.name, \'\') AS profile_name,
                    COALESCE(tc.targets_total, 0) AS targets_total,
                    COALESCE(tc.targets_completed, 0) AS targets_completed,
                    COALESCE(tc.targets_failed, 0) AS targets_failed,
                    COALESCE(tc.targets_pending, 0) AS targets_pending,
                    COALESCE(tc.targets_skipped, 0) AS targets_skipped,
                    COALESCE(rc.partial_n, 0) AS result_partial_count,
                    COALESCE(rc.failed_n, 0) AS result_failed_count
             FROM credential_check_runs r
             LEFT JOIN credential_check_jobs j ON j.id = r.job_id
             LEFT JOIN credential_profiles p ON p.id = j.credential_profile_id AND p.deleted_at IS NULL
             LEFT JOIN (
                SELECT run_id,
                    COUNT(*) AS targets_total,
                    SUM(CASE WHEN status = \'completed\' THEN 1 ELSE 0 END) AS targets_completed,
                    SUM(CASE WHEN status = \'failed\' THEN 1 ELSE 0 END) AS targets_failed,
                    SUM(CASE WHEN status = \'pending\' THEN 1 ELSE 0 END) AS targets_pending,
                    SUM(CASE WHEN status = \'skipped\' THEN 1 ELSE 0 END) AS targets_skipped
                FROM credential_check_run_targets GROUP BY run_id
             ) tc ON tc.run_id = r.id
             LEFT JOIN (
                SELECT run_id,
                    SUM(CASE WHEN status = \'partial\' THEN 1 ELSE 0 END) AS partial_n,
                    SUM(CASE WHEN status = \'failed\' THEN 1 ELSE 0 END) AS failed_n
                FROM credential_check_results GROUP BY run_id
             ) rc ON rc.run_id = r.id
             WHERE ' . implode(' AND ', $where) . '
             ORDER BY r.started_at DESC, r.id DESC
             LIMIT ' . (int) $limit;
    $st = $pdo->prepare($sql);
    $st->execute($params);
    $out = [];
    foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $row) {
        if (! is_array($row)) {
            continue;
        }
        // List API: omit per-run summary blob (unbounded growth; detail endpoint serves it).
        unset($row['summary_json']);
        $row['duration_ms'] = st_cc_run_duration_ms_approx(
            isset($row['started_at']) ? (string) $row['started_at'] : null,
            isset($row['finished_at']) ? (string) $row['finished_at'] : null
        );
        $out[] = $row;
    }

    return $out;
}

/**
 * Run-detail API: return only allowlisted `metrics_json` fields (defense in depth vs future columns).
 *
 * @return array<string, mixed>
 */
function st_cc_result_metrics_public(?string $metricsJson): array
{
    if ($metricsJson === null || trim($metricsJson) === '') {
        return [];
    }
    try {
        $d = json_decode($metricsJson, true, 16, JSON_THROW_ON_ERROR);
    } catch (Throwable) {
        return [];
    }
    if (! is_array($d)) {
        return [];
    }
    $allow = [
        'duration_ms',
        'plugin_key',
        'plugin_version',
        'stderr_snippet_len',
        'exit_code',
        'package_manager',
        'detector',
        'bytes_stdout',
        'parse_dropped',
        'truncated_read',
        'oids_present',
    ];
    $out = [];
    foreach ($allow as $k) {
        if (array_key_exists($k, $d)) {
            $out[$k] = $d[$k];
        }
    }

    return $out;
}

/**
 * Run-detail: bounded preview of normalized_json (never full package list for ssh.linux.package_inventory).
 */
function st_cc_normalized_preview_public(string $pluginKey, string $normalizedJson): string
{
    if ($pluginKey === 'snmpv3.device_identity' && $normalizedJson !== '') {
        try {
            $d = json_decode($normalizedJson, true, 24, JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            $preview = substr($normalizedJson, 0, 400);

            return strlen($normalizedJson) > 400 ? $preview . '…' : $preview;
        }
        if (! is_array($d)) {
            $preview = substr($normalizedJson, 0, 400);

            return strlen($normalizedJson) > 400 ? $preview . '…' : $preview;
        }
        $id = isset($d['snmpv3_identity']) && is_array($d['snmpv3_identity']) ? $d['snmpv3_identity'] : [];
        $nid = isset($d['normalized_identity']) && is_array($d['normalized_identity']) ? $d['normalized_identity'] : [];
        $sd = isset($id['sys_descr']) ? (string) $id['sys_descr'] : '';
        $so = isset($id['sys_object_id']) ? (string) $id['sys_object_id'] : '';
        $sn = isset($id['sys_name']) ? (string) $id['sys_name'] : '';
        $prev = [
            'error_code'           => $d['error_code'] ?? null,
            'partial'              => $d['partial'] ?? null,
            'sys_descr_preview'    => $sd !== '' ? substr($sd, 0, 180) : '',
            'sys_object_id_preview'=> $so !== '' ? substr($so, 0, 120) : '',
            'sys_name_preview'     => $sn !== '' ? substr($sn, 0, 120) : '',
            'vendor_hint'          => $nid['vendor_hint'] ?? null,
            'name_hint'            => $nid['name'] ?? null,
            'source'               => $d['source'] ?? null,
        ];
        $enc = json_encode($prev, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if (! is_string($enc)) {
            return '…';
        }
        if (strlen($enc) > 1200) {
            return substr($enc, 0, 1200) . '…';
        }

        return $enc;
    }
    if ($pluginKey === 'ssh.linux.package_inventory' && $normalizedJson !== '') {
        try {
            $d = json_decode($normalizedJson, true, 24, JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            $preview = substr($normalizedJson, 0, 400);

            return strlen($normalizedJson) > 400 ? $preview . '…' : $preview;
        }
        if (! is_array($d)) {
            $preview = substr($normalizedJson, 0, 400);

            return strlen($normalizedJson) > 400 ? $preview . '…' : $preview;
        }
        $pkgs = isset($d['packages']) && is_array($d['packages']) ? $d['packages'] : [];
        $sample = array_slice($pkgs, 0, 5);
        $prev = [
            'package_manager' => $d['package_manager'] ?? null,
            'package_count'   => $d['package_count'] ?? null,
            'partial'         => $d['partial'] ?? null,
            'truncated'       => $d['truncated'] ?? null,
            'packages_sample' => $sample,
            'source'          => $d['source'] ?? null,
        ];
        $enc = json_encode($prev, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if (! is_string($enc)) {
            return '…';
        }
        if (strlen($enc) > 1200) {
            return substr($enc, 0, 1200) . '…';
        }

        return $enc;
    }
    $preview = $normalizedJson !== '' ? substr($normalizedJson, 0, 400) : '';
    if (strlen($normalizedJson) > 400) {
        $preview .= '…';
    }

    return $preview;
}

/**
 * Bounded summaries for host modal (no raw package lists).
 *
 * @return array<string, mixed>
 */
function st_cc_asset_cred_summary(PDO $pdo, int $assetId, ?string $osPlatformExplanation): array
{
    $out = [
        'tables_ready'              => false,
        'has_activity'              => false,
        'last_target_touch'         => null,
        'last_successful_run'       => null,
        'recent_runs'               => [],
        'package_inventory_summary' => null,
        'snmp_identity_summary'     => null,
        'os_trust_note'             => null,
    ];
    if (! st_cc_ops_tables_ready($pdo) || $assetId < 1) {
        return $out;
    }
    $out['tables_ready'] = true;
    $expl = $osPlatformExplanation !== null ? trim($osPlatformExplanation) : '';
    if ($expl !== '' && (stripos($expl, 'authenticated') !== false || stripos($expl, 'credentialed') !== false)) {
        $out['os_trust_note'] = strlen($expl) > 220 ? substr($expl, 0, 220) . '…' : $expl;
    }
    try {
        $st = $pdo->prepare(
            'SELECT t.id AS target_row_id, t.run_id, t.status AS target_status, t.error_code, t.error_message_safe,
                    t.started_at AS target_started_at, t.finished_at AS target_finished_at,
                    r.status AS run_status, r.started_at AS run_started_at, r.finished_at AS run_finished_at,
                    j.name AS job_name, j.plugin_selection_json
             FROM credential_check_run_targets t
             JOIN credential_check_runs r ON r.id = t.run_id
             LEFT JOIN credential_check_jobs j ON j.id = r.job_id
             WHERE t.asset_id = ?
             ORDER BY datetime(COALESCE(t.finished_at, t.started_at, r.finished_at, r.started_at)) DESC, r.id DESC, t.id DESC
             LIMIT 32'
        );
        $st->execute([$assetId]);
        $rows = $st->fetchAll(PDO::FETCH_ASSOC) ?: [];
        if ($rows === []) {
            return $out;
        }
        $out['has_activity'] = true;
        $first = $rows[0];
        if (is_array($first)) {
            $out['last_target_touch'] = [
                'run_id'          => (int) ($first['run_id'] ?? 0),
                'run_status'      => (string) ($first['run_status'] ?? ''),
                'target_status'   => (string) ($first['target_status'] ?? ''),
                'error_code'      => (string) ($first['error_code'] ?? ''),
                'finished_at'     => $first['target_finished_at'] ?? $first['run_finished_at'] ?? null,
                'job_name'        => (string) ($first['job_name'] ?? ''),
                'plugins_planned' => st_cc_parse_plugin_labels((string) ($first['plugin_selection_json'] ?? '')),
            ];
        }
        $seenRuns = [];
        foreach ($rows as $r) {
            if (! is_array($r)) {
                continue;
            }
            $rid = (int) ($r['run_id'] ?? 0);
            if ($rid < 1 || isset($seenRuns[$rid])) {
                continue;
            }
            $seenRuns[$rid] = true;
            $ts = strtolower((string) ($r['target_status'] ?? ''));
            $rs = strtolower((string) ($r['run_status'] ?? ''));
            if ($ts === 'completed') {
                $plugins = st_cc_results_plugins_for_asset_run($pdo, $rid, $assetId);
                $out['last_successful_run'] = [
                    'run_id'            => $rid,
                    'run_status'        => (string) ($r['run_status'] ?? ''),
                    'finished_at'       => $r['run_finished_at'] ?? $r['target_finished_at'] ?? null,
                    'job_name'          => (string) ($r['job_name'] ?? ''),
                    'plugins_executed'  => $plugins,
                    'plugins_planned'   => st_cc_parse_plugin_labels((string) ($r['plugin_selection_json'] ?? '')),
                ];
                break;
            }
        }
        $recent = [];
        $n = 0;
        foreach ($rows as $r) {
            if (! is_array($r)) {
                continue;
            }
            $rid = (int) ($r['run_id'] ?? 0);
            if ($rid < 1) {
                continue;
            }
            $key = $rid;
            if (isset($recent[$key])) {
                continue;
            }
            $recent[$key] = [
                'run_id'        => $rid,
                'run_status'    => (string) ($r['run_status'] ?? ''),
                'target_status' => (string) ($r['target_status'] ?? ''),
                'started_at'    => $r['run_started_at'] ?? null,
                'job_name'      => (string) ($r['job_name'] ?? ''),
            ];
            if (++$n >= 8) {
                break;
            }
        }
        $out['recent_runs'] = array_values($recent);

        $pkg = $pdo->prepare(
            "SELECT normalized_json, status, created_at FROM credential_check_results
             WHERE asset_id = ? AND plugin_key = 'ssh.linux.package_inventory'
             ORDER BY datetime(created_at) DESC, id DESC LIMIT 1"
        );
        $pkg->execute([$assetId]);
        $pr = $pkg->fetch(PDO::FETCH_ASSOC);
        if (is_array($pr)) {
            $out['package_inventory_summary'] = st_cc_package_summary_from_normalized((string) ($pr['normalized_json'] ?? ''), (string) ($pr['status'] ?? ''));
        }

        $sn = $pdo->prepare(
            "SELECT normalized_json, status, created_at FROM credential_check_results
             WHERE asset_id = ? AND plugin_key = 'snmpv3.device_identity'
             ORDER BY datetime(created_at) DESC, id DESC LIMIT 1"
        );
        $sn->execute([$assetId]);
        $sr = $sn->fetch(PDO::FETCH_ASSOC);
        if (is_array($sr)) {
            $out['snmp_identity_summary'] = st_cc_snmp_identity_summary_from_normalized((string) ($sr['normalized_json'] ?? ''), (string) ($sr['status'] ?? ''));
        }
    } catch (Throwable $e) {
        @error_log('SurveyTrace st_cc_asset_cred_summary: ' . $e->getMessage());
    }

    return $out;
}

/**
 * @return list<string>
 */
function st_cc_parse_plugin_labels(string $pluginJson): array
{
    if ($pluginJson === '') {
        return [];
    }
    try {
        $tmp = json_decode($pluginJson, true, 64, JSON_THROW_ON_ERROR);
    } catch (Throwable) {
        return [];
    }
    if (! is_array($tmp)) {
        return [];
    }
    $out = [];
    foreach ($tmp as $row) {
        if (! is_array($row)) {
            continue;
        }
        $pk = trim((string) ($row['plugin_key'] ?? ''));
        $ver = trim((string) ($row['version'] ?? ''));
        if ($pk === '') {
            continue;
        }
        $out[] = $ver !== '' ? $pk . '@' . $ver : $pk;
    }

    return $out;
}

/**
 * @return list<string>
 */
function st_cc_results_plugins_for_asset_run(PDO $pdo, int $runId, int $assetId): array
{
    if ($runId < 1 || $assetId < 1) {
        return [];
    }
    try {
        $st = $pdo->prepare(
            'SELECT DISTINCT plugin_key, plugin_version FROM credential_check_results
             WHERE run_id = ? AND asset_id = ? ORDER BY plugin_key ASC, plugin_version ASC'
        );
        $st->execute([$runId, $assetId]);
        $out = [];
        foreach ($st->fetchAll(PDO::FETCH_ASSOC) ?: [] as $r) {
            if (! is_array($r)) {
                continue;
            }
            $pk = (string) ($r['plugin_key'] ?? '');
            $pv = (string) ($r['plugin_version'] ?? '');
            if ($pk === '') {
                continue;
            }
            $out[] = $pv !== '' ? $pk . '@' . $pv : $pk;
        }

        return $out;
    } catch (Throwable) {
        return [];
    }
}

/**
 * @return array<string, mixed>
 */
function st_cc_package_summary_from_normalized(string $normalizedJson, string $resultStatus): array
{
    $out = [
        'package_manager' => null,
        'package_count'     => null,
        'partial'           => null,
        'truncated'         => null,
        'result_status'     => strtolower(trim($resultStatus)),
    ];
    if ($normalizedJson === '') {
        return $out;
    }
    try {
        $d = json_decode($normalizedJson, true, 16, JSON_THROW_ON_ERROR);
    } catch (Throwable) {
        return $out;
    }
    if (! is_array($d)) {
        return $out;
    }
    $out['package_manager'] = isset($d['package_manager']) ? (string) $d['package_manager'] : null;
    $out['package_count'] = isset($d['package_count']) ? (int) $d['package_count'] : null;
    $out['partial'] = isset($d['partial']) ? (bool) $d['partial'] : null;
    $out['truncated'] = isset($d['truncated']) ? (bool) $d['truncated'] : null;

    return $out;
}

/**
 * @return array<string, mixed>
 */
function st_cc_snmp_identity_summary_from_normalized(string $normalizedJson, string $resultStatus): array
{
    $out = [
        'result_status' => strtolower(trim($resultStatus)),
        'sys_name'      => null,
        'vendor_hint'   => null,
        'name_hint'     => null,
        'partial'       => null,
    ];
    if ($normalizedJson === '') {
        return $out;
    }
    try {
        $d = json_decode($normalizedJson, true, 24, JSON_THROW_ON_ERROR);
    } catch (Throwable) {
        return $out;
    }
    if (! is_array($d)) {
        return $out;
    }
    $id = isset($d['snmpv3_identity']) && is_array($d['snmpv3_identity']) ? $d['snmpv3_identity'] : [];
    $nid = isset($d['normalized_identity']) && is_array($d['normalized_identity']) ? $d['normalized_identity'] : [];
    $sn = isset($id['sys_name']) ? trim((string) $id['sys_name']) : '';
    $out['sys_name'] = $sn !== '' ? (strlen($sn) > 120 ? substr($sn, 0, 120) . '…' : $sn) : null;
    $out['vendor_hint'] = isset($nid['vendor_hint']) ? (string) $nid['vendor_hint'] : null;
    $out['name_hint'] = isset($nid['name']) ? (string) $nid['name'] : null;
    $out['partial'] = isset($d['partial']) ? (bool) $d['partial'] : null;

    return $out;
}

/**
 * @return array<string, mixed>|null
 */
function st_cc_run_get_detail(PDO $pdo, int $runId, bool $includeWorkerDebug = false): ?array
{
    if (! st_cc_ops_tables_ready($pdo) || $runId < 1) {
        return null;
    }
    $st = $pdo->prepare(
        'SELECT r.*, j.name AS job_name, j.credential_profile_id, j.plugin_selection_json AS job_plugin_selection_json,
                p.name AS profile_name, COALESCE(p.transport, \'\') AS profile_transport
         FROM credential_check_runs r
         LEFT JOIN credential_check_jobs j ON j.id = r.job_id
         LEFT JOIN credential_profiles p ON p.id = j.credential_profile_id AND p.deleted_at IS NULL
         WHERE r.id = ? LIMIT 1'
    );
    $st->execute([$runId]);
    $run = $st->fetch(PDO::FETCH_ASSOC);
    if (! is_array($run)) {
        return null;
    }
    $ts = $pdo->prepare(
        'SELECT t.id, t.run_id, t.asset_id, t.status, t.error_code, t.error_message_safe, t.started_at, t.finished_at,
                a.ip AS asset_ip, a.hostname AS asset_hostname
         FROM credential_check_run_targets t
         LEFT JOIN assets a ON a.id = t.asset_id
         WHERE t.run_id = ?
         ORDER BY t.id ASC'
    );
    $ts->execute([$runId]);
    $targets = [];
    foreach ($ts->fetchAll(PDO::FETCH_ASSOC) as $tr) {
        if (is_array($tr)) {
            $targets[] = $tr;
        }
    }
    $c = ['pending' => 0, 'skipped' => 0, 'completed' => 0, 'failed' => 0, 'other' => 0];
    foreach ($targets as $tr) {
        $s = strtolower(trim((string) ($tr['status'] ?? '')));
        if (isset($c[$s])) {
            ++$c[$s];
        } else {
            ++$c['other'];
        }
    }
    $run['targets'] = $targets;
    $run['target_counts'] = $c;
    $run['worker_job_id_public'] = isset($run['worker_job_id']) ? (int) $run['worker_job_id'] : null;

    $resStmt = $pdo->prepare(
        'SELECT id, target_id, asset_id, plugin_key, plugin_version, status, normalized_json, metrics_json, created_at '
        . 'FROM credential_check_results WHERE run_id = ? ORDER BY id ASC'
    );
    $resStmt->execute([$runId]);
    $results = [];
    foreach ($resStmt->fetchAll(PDO::FETCH_ASSOC) as $rr) {
        if (! is_array($rr)) {
            continue;
        }
        $nj = isset($rr['normalized_json']) ? (string) $rr['normalized_json'] : '';
        $pkey = (string) ($rr['plugin_key'] ?? '');
        $rr['normalized_preview'] = st_cc_normalized_preview_public($pkey, $nj);
        unset($rr['normalized_json']);
        $rr['metrics'] = st_cc_result_metrics_public(isset($rr['metrics_json']) ? (string) $rr['metrics_json'] : null);
        unset($rr['metrics_json']);
        $results[] = $rr;
    }
    $run['results'] = $results;
    $rc = ['success' => 0, 'partial' => 0, 'failed' => 0];
    foreach ($results as $rr) {
        $stR = strtolower(trim((string) ($rr['status'] ?? '')));
        if (isset($rc[$stR])) {
            ++$rc[$stR];
        }
    }
    $run['result_counts'] = $rc;
    $run['duration_ms'] = st_cc_run_duration_ms_approx(
        isset($run['started_at']) ? (string) $run['started_at'] : null,
        isset($run['finished_at']) ? (string) $run['finished_at'] : null
    );
    $run['job_plugins_planned'] = st_cc_parse_plugin_labels((string) ($run['job_plugin_selection_json'] ?? ''));

    $run['observations_written'] = [];
    require_once __DIR__ . '/lib_reconciliation.php';
    if (st_recon_tables_ready($pdo)) {
        try {
            st_recon_seed_sources($pdo);
            $sidCred = st_recon_source_id($pdo, 'credentialed_check');
            if ($sidCred !== null) {
                $pref = 'run:' . $runId . ':';
                $obSt = $pdo->prepare(
                    "SELECT o.id, o.asset_id, o.observation_type, o.source_object_ref, o.observed_at
                     FROM asset_observations o
                     WHERE o.source_id = ? AND o.source_object_ref LIKE ?
                     ORDER BY o.id ASC LIMIT 120"
                );
                $obSt->execute([$sidCred, $pref . '%']);
                foreach ($obSt->fetchAll(PDO::FETCH_ASSOC) ?: [] as $or) {
                    if (is_array($or)) {
                        $run['observations_written'][] = $or;
                    }
                }
            }
        } catch (Throwable $e) {
            @error_log('SurveyTrace st_cc_run_get_detail observations: ' . $e->getMessage());
        }
    }

    $run['artifact_summaries'] = [];
    try {
        $aSt = $pdo->prepare(
            'SELECT ca.id, ca.kind, ca.sha256, ca.size_bytes, ca.created_at, ca.result_id
             FROM credential_check_artifacts ca
             INNER JOIN credential_check_results res ON res.id = ca.result_id
             WHERE res.run_id = ?
             ORDER BY ca.id ASC LIMIT 48'
        );
        $aSt->execute([$runId]);
        foreach ($aSt->fetchAll(PDO::FETCH_ASSOC) ?: [] as $ar) {
            if (is_array($ar)) {
                $run['artifact_summaries'][] = $ar;
            }
        }
    } catch (Throwable $e) {
        @error_log('SurveyTrace st_cc_run_get_detail artifacts: ' . $e->getMessage());
    }

    $run['worker_debug'] = null;
    if ($includeWorkerDebug && st_worker_tables_ready($pdo)) {
        $wjid = isset($run['worker_job_id']) ? (int) $run['worker_job_id'] : 0;
        if ($wjid > 0) {
            try {
                $wst = $pdo->prepare(
                    'SELECT id, status, attempts, max_attempts, next_attempt_at, leased_at, lease_expires_at, error_code,
                            created_at, updated_at, finished_at, cancel_requested_at
                     FROM worker_jobs WHERE id = ? LIMIT 1'
                );
                $wst->execute([$wjid]);
                $wj = $wst->fetch(PDO::FETCH_ASSOC);
                $run['worker_debug'] = is_array($wj) ? $wj : null;
            } catch (Throwable $e) {
                @error_log('SurveyTrace st_cc_run_get_detail worker_debug: ' . $e->getMessage());
            }
        }
    }

    $run['retention_note'] = 'Results and artifacts are bounded per run; long-term retention is operational — prune old runs if SQLite grows.';

    return $run;
}

/**
 * @return array<string, mixed>
 */
function st_cc_health_snapshot_runs(PDO $pdo): array
{
    $out = [
        'tables_ready'                      => st_cc_ops_tables_ready($pdo),
        'queued_or_active'                  => 0,
        'running'                           => 0,
        'completed_recent_24h'              => 0,
        'failed_recent_24h'                 => 0,
        'partial_results_recent_24h'        => 0,
        'last_successful_run_at'            => null,
        'avg_duration_ms_completed_24h'     => null,
        'stale_active_runs'                 => 0,
        'enabled_jobs_on_disabled_profiles' => 0,
        'approx_result_rows'                => 0,
        'approx_artifact_rows'              => 0,
        'summary'                           => 'Credentialed check runs: unavailable.',
        'warning_hints'                     => [],
    ];
    if (! $out['tables_ready']) {
        return $out;
    }
    try {
        $out['queued_or_active'] = (int) $pdo->query(
            "SELECT COUNT(*) FROM credential_check_runs WHERE status IN ('queued','resolving_targets','ready','running')"
        )->fetchColumn();
        $out['running'] = (int) $pdo->query(
            "SELECT COUNT(*) FROM credential_check_runs WHERE status = 'running'"
        )->fetchColumn();
        $out['completed_recent_24h'] = (int) $pdo->query(
            "SELECT COUNT(*) FROM credential_check_runs WHERE status = 'completed' AND datetime(COALESCE(finished_at, started_at)) >= datetime('now', '-1 day')"
        )->fetchColumn();
        $out['failed_recent_24h'] = (int) $pdo->query(
            "SELECT COUNT(*) FROM credential_check_runs WHERE status = 'failed' AND datetime(started_at) >= datetime('now', '-1 day')"
        )->fetchColumn();
        $out['partial_results_recent_24h'] = (int) $pdo->query(
            "SELECT COUNT(*) FROM credential_check_results WHERE status = 'partial' AND datetime(created_at) >= datetime('now', '-1 day')"
        )->fetchColumn();
        $lastOk = $pdo->query(
            "SELECT MAX(finished_at) FROM credential_check_runs WHERE status = 'completed' AND finished_at IS NOT NULL"
        )->fetchColumn();
        if ($lastOk !== false && $lastOk !== null && $lastOk !== '') {
            $out['last_successful_run_at'] = (string) $lastOk;
        }
        $avg = $pdo->query(
            "SELECT AVG((julianday(COALESCE(finished_at, started_at)) - julianday(started_at)) * 86400000.0)
             FROM credential_check_runs
             WHERE status = 'completed' AND finished_at IS NOT NULL AND datetime(finished_at) >= datetime('now', '-1 day')"
        )->fetchColumn();
        if ($avg !== false && $avg !== null && is_numeric($avg)) {
            $out['avg_duration_ms_completed_24h'] = (int) round((float) $avg);
        }
        $out['stale_active_runs'] = (int) $pdo->query(
            "SELECT COUNT(*) FROM credential_check_runs
             WHERE status IN ('queued','resolving_targets','ready','running')
             AND datetime(started_at) < datetime('now', '-3 hours')"
        )->fetchColumn();
        $out['enabled_jobs_on_disabled_profiles'] = (int) $pdo->query(
            "SELECT COUNT(*) FROM credential_check_jobs j
             INNER JOIN credential_profiles p ON p.id = j.credential_profile_id
             WHERE j.enabled = 1 AND (p.enabled = 0 OR p.deleted_at IS NOT NULL)"
        )->fetchColumn();
        $out['approx_result_rows'] = (int) $pdo->query('SELECT COUNT(*) FROM credential_check_results')->fetchColumn();
        $out['approx_artifact_rows'] = (int) $pdo->query('SELECT COUNT(*) FROM credential_check_artifacts')->fetchColumn();
        $out['summary'] = 'Queued/active runs: ' . $out['queued_or_active'] . '; running: ' . $out['running']
            . '; completed (24h): ' . $out['completed_recent_24h']
            . '; failed (24h): ' . $out['failed_recent_24h']
            . '; partial results (24h): ' . $out['partial_results_recent_24h'];
        if ($out['stale_active_runs'] > 0) {
            $out['warning_hints'][] = (string) $out['stale_active_runs'] . ' credentialed run(s) active >3h — check worker connectivity.';
        }
        if ($out['enabled_jobs_on_disabled_profiles'] > 0) {
            $out['warning_hints'][] = (string) $out['enabled_jobs_on_disabled_profiles'] . ' enabled job(s) reference disabled/archived credential profiles.';
        }
        if ($out['failed_recent_24h'] > 5) {
            $out['warning_hints'][] = 'Several credentialed runs failed in the last 24h — review run detail errors.';
        }
    } catch (Throwable) {
        $out['summary'] = 'Credentialed check run counts unavailable.';
    }

    return $out;
}
