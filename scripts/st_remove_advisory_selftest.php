<?php
/**
 * Policy selftest for advisory removal gates (no database).
 *
 *   php scripts/st_remove_advisory_selftest.php
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/api/lib_vulnerability_advisory_import.php';

function st_ra_selftest_fail(string $m): void
{
    fwrite(STDERR, 'FAIL: ' . $m . "\n");
    exit(1);
}

// Allowed without --force
foreach (
    [
        [['advisory_key' => 'CVE-TEST-0001', 'source' => 'ubuntu', 'package_authority' => 'vendor_distro'], null],
        [['advisory_key' => 'CVE-2024-1', 'source' => 'internal', 'package_authority' => 'internal'], null],
        [['advisory_key' => 'X', 'source' => 'sample', 'package_authority' => 'internal'], null],
        [['advisory_key' => 'CVE-2024-1', 'source' => 'nvd', 'package_authority' => 'metadata_only'], null],
    ] as $pair
) {
    if (st_vuln_advisory_removal_refused_reason($pair[0], false) !== null) {
        st_ra_selftest_fail('expected allow without force');
    }
}

// Refused without --force
if (st_vuln_advisory_removal_refused_reason(
    ['advisory_key' => 'CVE-2024-99999', 'source' => 'ubuntu', 'package_authority' => 'vendor_distro'],
    false
) !== 'vendor_distro_advisory_requires_force') {
    st_ra_selftest_fail('vendor_distro must require force');
}
if (st_vuln_advisory_removal_refused_reason(
    ['advisory_key' => 'CVE-2024-1', 'source' => 'redhat', 'package_authority' => 'internal'],
    false
) !== 'non_test_advisory_requires_force') {
    st_ra_selftest_fail('non-test non-internal should require force');
}

// --force allows
if (st_vuln_advisory_removal_refused_reason(
    ['advisory_key' => 'CVE-2024-1', 'source' => 'ubuntu', 'package_authority' => 'vendor_distro'],
    true
) !== null) {
    st_ra_selftest_fail('force should allow vendor');
}

echo "OK st_remove_advisory_selftest\n";
exit(0);
