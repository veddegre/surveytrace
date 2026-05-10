<?php
/**
 * Delegates to daemon/software_inventory_selftest.py (normalization + persist + diff).
 *
 *   php scripts/st_software_inventory_normalization_selftest.php
 */

declare(strict_types=1);

$root = dirname(__DIR__);
$py = $root . '/daemon/software_inventory_selftest.py';
if (! is_readable($py)) {
    fwrite(STDERR, "FAIL: missing {$py}\n");
    exit(2);
}
chdir($root);
passthru('python3 ' . escapeshellarg($py), $code);
exit((int) $code);
