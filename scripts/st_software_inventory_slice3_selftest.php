<?php
/**
 * Slice 3 — bounded software evidence contract (no DB): API shape, stale/partial markers, payload bounds.
 *
 *   php scripts/st_software_inventory_slice3_selftest.php
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/api/lib_reconciliation.php';

function st_sw3_fail(string $msg): void
{
    fwrite(STDERR, 'FAIL: ' . $msg . "\n");
    exit(1);
}

function mk_ev(array $overrides): array
{
    return array_merge([
        'package_inventory_id'            => null,
        'package_inventory_raw'             => '',
        'package_inventory_observed_at'     => null,
        'software_observed_count'           => 0,
        'software_observation_ids_sample'     => [],
        'software_first_raw'                => '',
        'software_first_provenance'         => '',
        'software_max_observed_at'          => null,
        'evidence_max_observed_at'          => null,
    ], $overrides);
}

$keys = st_recon_slice3_expected_asset_top_level_software_keys();
if ($keys !== array_values(array_unique($keys))) {
    st_sw3_fail('duplicate keys in st_recon_slice3_expected_asset_top_level_software_keys');
}
$wantKeys = [
    'software_inventory_summary',
    'software_inventory_confidence',
    'software_inventory_explanation',
    'software_inventory_count',
    'software_inventory_has_bounded_observations',
    'software_inventory_manager',
    'software_inventory_observation_gap',
    'software_inventory_observed_at',
    'software_inventory_partial',
    'software_inventory_source',
    'software_inventory_stale',
    'software_inventory_stale_band',
];
sort($keys);
sort($wantKeys);
if ($keys !== $wantKeys) {
    st_sw3_fail('software_inventory top-level key contract drift — update assets.php + docs together');
}

$fresh = date('Y-m-d H:i:s');

$rFresh = st_recon_resolve_software_inventory_summary_evidence(mk_ev([
    'package_inventory_id'          => 101,
    'package_inventory_raw'         => json_encode([
        'package_manager' => 'dpkg',
        'package_count'   => 40,
        'partial'         => false,
    ], JSON_UNESCAPED_SLASHES),
    'package_inventory_observed_at' => $fresh,
]));
$bf = st_recon_software_inventory_bundle_from_resolve($rFresh);
if (($bf['software_inventory_stale'] ?? null) !== false) {
    st_sw3_fail('fresh bundle must set software_inventory_stale false');
}
if (($bf['software_inventory_stale_band'] ?? '') !== 'fresh' || ($bf['software_inventory_observation_gap'] ?? null) !== true) {
    st_sw3_fail('pkg-only bundle must expose stale_band=fresh and observation_gap');
}
if (! is_string($bf['software_inventory_source'] ?? null) || strpos((string) $bf['software_inventory_source'], 'ssh.linux.package_inventory') === false) {
    st_sw3_fail('bundle must expose software_inventory_source with plugin ref');
}

$rStale = st_recon_resolve_software_inventory_summary_evidence(mk_ev([
    'package_inventory_id'          => 102,
    'package_inventory_raw'         => json_encode([
        'package_manager' => 'rpm',
        'package_count'   => 5,
        'partial'         => false,
    ], JSON_UNESCAPED_SLASHES),
    'package_inventory_observed_at' => '1999-06-01 00:00:00',
]));
if (($rStale['stale'] ?? false) !== true) {
    st_sw3_fail('old observed_at → stale');
}
if (strpos($rStale['explanation'], ST_RECON_SW_INV_HEALTH_MARKER_STALE) === false) {
    st_sw3_fail('stale explanation must contain health marker substring');
}
$bs = st_recon_software_inventory_bundle_from_resolve($rStale);
if (($bs['software_inventory_stale'] ?? null) !== true) {
    st_sw3_fail('stale bundle propagates software_inventory_stale');
}

$rPartial = st_recon_resolve_software_inventory_summary_evidence(mk_ev([
    'package_inventory_id'          => 103,
    'package_inventory_raw'         => json_encode([
        'package_manager' => 'dpkg',
        'package_count'   => 9,
        'partial'         => true,
    ], JSON_UNESCAPED_SLASHES),
    'package_inventory_observed_at' => $fresh,
]));
if (($rPartial['partial'] ?? false) !== true || strpos($rPartial['explanation'], ST_RECON_SW_INV_HEALTH_MARKER_PARTIAL) === false) {
    st_sw3_fail('partial pkg summary must embed health marker for diagnostics');
}

$okDetail = [
    'tables_ready'      => true,
    'software_observed' => [
        'observation_count' => 128,
        'preview'           => [
            ['label' => 'a 1', 'normalized_value' => 'a'],
            ['label' => 'b 2', 'normalized_value' => 'b'],
            ['label' => 'c 3', 'normalized_value' => 'c'],
        ],
    ],
];
$viol = st_recon_slice3_assert_bounded_software_payload($okDetail);
if ($viol !== []) {
    st_sw3_fail('bounded preview shape should pass: ' . implode('; ', $viol));
}

$badDetail = array_merge($okDetail, ['packages' => []]);
if (st_recon_slice3_assert_bounded_software_payload($badDetail) === []) {
    st_sw3_fail('must reject recon_detail.packages');
}

$badSw = $okDetail;
$badSw['software_observed']['packages'] = [];
if (st_recon_slice3_assert_bounded_software_payload($badSw) === []) {
    st_sw3_fail('must reject software_observed.packages');
}

$tooMany = $okDetail;
$tooMany['software_observed']['preview'][] = ['label' => 'd', 'normalized_value' => 'd'];
if (st_recon_slice3_assert_bounded_software_payload($tooMany) === []) {
    st_sw3_fail('must reject >3 preview rows');
}

echo "OK st_software_inventory_slice3_selftest\n";
