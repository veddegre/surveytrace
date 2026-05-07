<?php
/**
 * Slice 4 — confidence bands, observation gap, health trusted_data safety (no DB).
 *
 *   php scripts/st_software_inventory_slice4_selftest.php
 */

declare(strict_types=1);

require_once dirname(__DIR__) . '/api/lib_reconciliation.php';

function st_sw4_fail(string $msg): void
{
    fwrite(STDERR, 'FAIL: ' . $msg . "\n");
    exit(1);
}

function mk_ev(array $overrides): array
{
    return array_merge([
        'package_inventory_id'            => null,
        'package_inventory_raw'           => '',
        'package_inventory_observed_at'   => null,
        'software_observed_count'         => 0,
        'software_observation_ids_sample' => [],
        'software_first_raw'              => '',
        'software_first_provenance'       => '',
        'software_max_observed_at'        => null,
        'evidence_max_observed_at'        => null,
    ], $overrides);
}

$fresh = date('Y-m-d H:i:s');
$past100 = date('Y-m-d H:i:s', time() - (100 * 86400));

$rBand = st_recon_resolve_software_inventory_summary_evidence(mk_ev([
    'package_inventory_id'          => 501,
    'package_inventory_raw'         => json_encode([
        'package_manager' => 'dpkg',
        'package_count'   => 3,
        'partial'         => false,
    ], JSON_UNESCAPED_SLASHES),
    'package_inventory_observed_at' => $past100,
    'software_observed_count'       => 0,
]));
if (($rBand['stale'] ?? false) !== true || ($rBand['stale_band'] ?? '') !== '90_180') {
    st_sw4_fail('~100d old pkg-only evidence → stale band 90_180');
}

$violHealth = st_recon_slice4_assert_health_trusted_software_diag_bounded([
    'tables_ready'                       => true,
    'software_inventory_summary_assets' => 1,
    'packages'                           => [],
]);
if ($violHealth === []) {
    st_sw4_fail('health contract must reject packages[] in trusted_data');
}

$violOk = st_recon_slice4_assert_health_trusted_software_diag_bounded([
    'software_inventory_summary_stale_evidence_90_180d_assets' => 0,
]);
if ($violOk !== []) {
    st_sw4_fail('scalar diagnostics should pass health contract: ' . implode('; ', $violOk));
}

echo "OK st_software_inventory_slice4_selftest\n";
