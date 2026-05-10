<?php
/**
 * Read-only row counts + freshness for normalized software_inventory* tables.
 *
 *   php scripts/diagnose_software_inventory.php
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/api/db.php';
require_once dirname(__DIR__) . '/api/lib_software_inventory.php';

$db = st_db();
if (! st_si_tables_ready($db)) {
    fwrite(STDERR, "software_inventory tables not present (run app migrations).\n");
    exit(1);
}

$nInv = st_si_total_inventory_rows($db);
$nVer = (int) $db->query('SELECT COUNT(*) FROM software_inventory_versions')->fetchColumn();
$nState = (int) $db->query('SELECT COUNT(*) FROM software_inventory_asset_state')->fetchColumn();
$nActive = (int) $db->query('SELECT COUNT(*) FROM software_inventory_asset_state WHERE active = 1')->fetchColumn();
$mx = st_si_global_latest_last_seen($db);

echo "software_inventory rows: {$nInv}\n";
echo "software_inventory_versions rows: {$nVer}\n";
echo "software_inventory_asset_state rows: {$nState} (active={$nActive})\n";
echo "latest active last_seen_at (global): " . ($mx ?? '(none)') . "\n";
