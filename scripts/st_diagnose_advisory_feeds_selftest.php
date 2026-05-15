<?php
/**
 * Lightweight selftest for diagnose_advisory_feeds helpers.
 *
 *   php scripts/st_diagnose_advisory_feeds_selftest.php
 */
declare(strict_types=1);

define('ST_DIAG_ADVISORY_FEEDS_NO_MAIN', true);
require_once __DIR__ . '/diagnose_advisory_feeds.php';

function st_daf_selftest_fail(string $msg): void
{
    fwrite(STDERR, 'FAIL: ' . $msg . "\n");
    exit(1);
}

if (st_diag_af_suggest_next_action(['cve_test_count' => 1]) !== 'remove_test_advisories') {
    st_daf_selftest_fail('CVE-TEST should suggest remove_test_advisories');
}
if (st_diag_af_suggest_next_action(['nvd_db_exists' => false, 'nvd_bridge_last_import_at' => 'x']) !== 'run_nvd_sync') {
    st_daf_selftest_fail('missing nvd.db should suggest run_nvd_sync');
}
if (st_diag_af_suggest_next_action([
    'nvd_db_exists' => true,
    'nvd_bridge_last_import_at' => null,
]) !== 'run_nvd_bridge') {
    st_daf_selftest_fail('missing bridge should suggest run_nvd_bridge');
}
if (st_diag_af_suggest_next_action([
    'nvd_db_exists' => true,
    'nvd_bridge_last_import_at' => '2026-01-01',
    'vendor_distro_package_rule_count' => 0,
]) !== 'import_vendor_advisories') {
    st_daf_selftest_fail('no vendor rules should suggest import_vendor_advisories');
}
if (st_diag_af_suggest_next_action([
    'nvd_db_exists' => true,
    'nvd_bridge_last_import_at' => '2026-01-01',
    'vendor_distro_package_rule_count' => 100,
    'active_inventory_rows' => 0,
]) !== 'collect_credentialed_inventory') {
    st_daf_selftest_fail('no inventory should suggest collect_credentialed_inventory');
}
if (st_diag_af_suggest_next_action([
    'nvd_db_exists' => true,
    'nvd_bridge_last_import_at' => '2026-01-01',
    'vendor_distro_package_rule_count' => 100,
    'active_inventory_rows' => 50,
    'queued_correlation_jobs' => 2,
]) !== 'run_correlation') {
    st_daf_selftest_fail('queued jobs should suggest run_correlation');
}
if (st_diag_af_suggest_next_action([
    'nvd_db_exists' => true,
    'nvd_bridge_last_import_at' => '2026-01-01',
    'vendor_distro_package_rule_count' => 100,
    'active_inventory_rows' => 50,
    'queued_correlation_jobs' => 0,
    'last_correlation_finished_at' => '2026-05-15',
]) !== 'no_action') {
    st_daf_selftest_fail('healthy state should suggest no_action');
}

$probe = st_diag_af_probe_nvd_db('/nonexistent/nvd.db');
if ($probe['exists'] !== false || $probe['cve_count'] !== null) {
    st_daf_selftest_fail('missing nvd.db probe shape');
}

$paths = st_diag_af_resolve_paths('/opt/surveytrace', null);
if ($paths['nvd_db'] !== '/opt/surveytrace/data/nvd.db') {
    st_daf_selftest_fail('install-root path resolution');
}

$pdo = new PDO('sqlite::memory:');
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->exec('CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT)');
$pdo->exec("INSERT INTO config VALUES ('nvd_bridge_last_modified_at', '2026-05-01')");
if (st_diag_af_config_get($pdo, 'nvd_bridge_last_modified_at') !== '2026-05-01') {
    st_daf_selftest_fail('config get');
}

echo "OK st_diagnose_advisory_feeds_selftest\n";
exit(0);
