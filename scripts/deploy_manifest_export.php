#!/usr/bin/env php
<?php
/**
 * Emit newline-separated manifest entries for bash (deploy.sh).
 *
 * Usage: SRC=/path/to/repo php scripts/deploy_manifest_export.php api_files
 */
declare(strict_types=1);

$m = require __DIR__ . '/deploy_file_manifest.php';
$key = $argv[1] ?? '';
if ($key === '' || !array_key_exists($key, $m)) {
    fwrite(STDERR, 'usage: deploy_manifest_export.php <' . implode('|', array_keys($m)) . ">\n");
    exit(2);
}
foreach ($m[$key] as $line) {
    echo $line, "\n";
}
