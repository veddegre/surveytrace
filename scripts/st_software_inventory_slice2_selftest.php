<?php
/**
 * Slice 2 — software inventory summary resolver (no DB).
 *
 *   php scripts/st_software_inventory_slice2_selftest.php
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/api/lib_reconciliation.php';

function st_sw2_fail(string $msg): void
{
    fwrite(STDERR, 'FAIL: ' . $msg . "\n");
    exit(1);
}

function mk_ev(array $overrides): array
{
    return array_merge([
        'package_inventory_id'          => null,
        'package_inventory_raw'         => '',
        'package_inventory_observed_at' => null,
        'software_observed_count'       => 0,
        'software_observation_ids_sample' => [],
        'software_first_raw'            => '',
        'software_first_provenance'     => '',
        'software_max_observed_at'      => null,
        'evidence_max_observed_at'      => null,
    ], $overrides);
}

$fresh = date('Y-m-d H:i:s');

$r0 = st_recon_resolve_software_inventory_summary_evidence(mk_ev([]));
if (($r0['skip'] ?? false) !== true) {
    st_sw2_fail('empty evidence should skip');
}

$r1 = st_recon_resolve_software_inventory_summary_evidence(mk_ev([
    'package_inventory_id'          => 10,
    'package_inventory_raw'         => json_encode([
        'package_manager' => 'dpkg',
        'package_count'   => 42,
        'partial'         => false,
        'truncated'       => false,
    ], JSON_UNESCAPED_SLASHES),
    'package_inventory_observed_at' => $fresh,
    'software_observed_count'       => 0,
]));
if (($r1['skip'] ?? true) || ($r1['confidence'] ?? '') !== 'medium' || ($r1['partial'] ?? true)) {
    st_sw2_fail('fresh summary-only complete → medium');
}
if (strpos($r1['explanation'], 'Confidence is MEDIUM') === false || strpos($r1['explanation'], ST_RECON_SW_INV_HEALTH_MARKER_OBS_GAP) === false) {
    st_sw2_fail('pkg-only fresh explanation must include MEDIUM rationale + bounded-row observation gap note');
}
if (($r1['observation_gap'] ?? false) !== true || ($r1['has_bounded_sw_obs'] ?? true) !== false || ($r1['stale_band'] ?? '') !== 'fresh') {
    st_sw2_fail('pkg-only evidence must flag observation_gap and stale_band=fresh');
}

$r2 = st_recon_resolve_software_inventory_summary_evidence(mk_ev([
    'package_inventory_id'          => 11,
    'package_inventory_raw'         => json_encode([
        'package_manager' => 'rpm',
        'package_count'   => 100,
        'partial'         => true,
        'truncated'       => false,
    ], JSON_UNESCAPED_SLASHES),
    'package_inventory_observed_at' => $fresh,
    'software_observed_count'       => 0,
]));
if (($r2['confidence'] ?? '') !== 'low' || ($r2['partial'] ?? false) !== true) {
    st_sw2_fail('partial pkg summary → low');
}
if (strpos($r2['explanation'], 'Confidence is LOW') === false) {
    st_sw2_fail('partial inventory must explain LOW confidence');
}

$r3 = st_recon_resolve_software_inventory_summary_evidence(mk_ev([
    'package_inventory_id'          => 12,
    'package_inventory_raw'         => json_encode([
        'package_manager' => 'dpkg',
        'package_count'   => 10,
        'partial'         => false,
    ], JSON_UNESCAPED_SLASHES),
    'package_inventory_observed_at' => '2001-01-01 00:00:00',
    'software_observed_count'       => 0,
]));
if (($r3['confidence'] ?? '') !== 'low' || ($r3['stale'] ?? false) !== true) {
    st_sw2_fail('stale evidence → low');
}
if (strpos($r3['explanation'], 'Confidence is LOW') === false || ($r3['stale_band'] ?? '') !== 'over_180') {
    st_sw2_fail('very old evidence → LOW rationale + over_180 band');
}
if (strpos($r3['explanation'], (string) ST_RECON_SOFTWARE_INVENTORY_STALE_DAYS) === false) {
    st_sw2_fail('stale explanation mentions threshold days');
}

$r4 = st_recon_resolve_software_inventory_summary_evidence(mk_ev([
    'package_inventory_id'          => 13,
    'package_inventory_raw'         => json_encode([
        'package_manager' => 'dpkg',
        'package_count'   => 500,
        'partial'         => false,
    ], JSON_UNESCAPED_SLASHES),
    'package_inventory_observed_at' => $fresh,
    'software_observed_count'       => 128,
    'software_first_raw'            => json_encode([
        'name' => 'x',
        'normalized_name' => 'x',
        'version' => '1',
        'manager' => 'dpkg',
        'source' => 'credentialed_check',
        'partial' => true,
    ], JSON_UNESCAPED_SLASHES),
    'software_first_provenance'     => json_encode([
        'aggregate_package_count' => 500,
        'bounded_truncation'      => true,
    ], JSON_UNESCAPED_SLASHES),
    'software_max_observed_at'      => $fresh,
]));
if (($r4['display_count'] ?? 0) !== 500 || ($r4['partial'] ?? false) !== true) {
    st_sw2_fail('aggregate count + bounded truncation → partial');
}
if (($r4['observation_gap'] ?? true) !== false || ($r4['has_bounded_sw_obs'] ?? false) !== true) {
    st_sw2_fail('bounded rows present → no observation_gap');
}

$r5 = st_recon_resolve_software_inventory_summary_evidence(mk_ev([
    'package_inventory_id'          => 0,
    'software_observed_count'       => 12,
    'software_first_raw'            => json_encode([
        'name' => 'curl',
        'normalized_name' => 'curl',
        'version' => '1',
        'manager' => 'rpm',
        'source' => 'credentialed_check',
        'partial' => false,
    ], JSON_UNESCAPED_SLASHES),
    'software_max_observed_at'      => $fresh,
    'evidence_max_observed_at'      => $fresh,
]));
if (($r5['skip'] ?? true) || ($r5['display_count'] ?? 0) !== 12 || ($r5['confidence'] ?? '') !== 'medium') {
    st_sw2_fail('software_observed-only fresh complete → medium, count from row cardinality');
}
if (($r5['observation_gap'] ?? true) !== false || strpos($r5['explanation'], ST_RECON_SW_INV_HEALTH_MARKER_OBS_GAP) !== false) {
    st_sw2_fail('software_observed-only must not claim observation_gap');
}

foreach ([$r1, $r2, $r3, $r4, $r5] as $rx) {
    if (stripos($rx['explanation'], 'CVE') === false || stripos($rx['explanation'], 'credentialed SSH package inventory') === false) {
        st_sw2_fail('explanation must disclaim CVE and cite cred inventory');
    }
}

echo "OK st_software_inventory_slice2_selftest\n";
