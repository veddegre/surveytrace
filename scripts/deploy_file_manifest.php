<?php
/**
 * Single source of truth for deploy.sh / setup.sh parity: which repo paths ship on master installs.
 * CLI consumers use deploy_manifest_export.php (do not execute this file directly for listing).
 *
 * Policy — any new runtime, admin/maintenance, or production-safe selftest file MUST be added here
 * under the correct category (e.g. api_files, scripts_php, scripts_sh, daemon_optional_py), OR explicitly listed
 * as intentionally dev-only (scripts_dev_only, daemon_dev_only_py). There is no third category: if it is
 * missing from both, check_deploy_coverage.php and CI/deploy will flag drift and installs may omit it.
 *
 * Feature parity — when you add a new first-class shipped surface (especially under api/), also extend the
 * post-verify spot-checks in deploy.sh and setup.sh (check_file / check_readable_as_user) for the same paths
 * so a bad deploy is caught the same way after setup and after upgrade.
 *
 * @return array<string, list<string>>
 */
declare(strict_types=1);

return [
    // api/*.php deployed by deploy.sh (explicit list — avoids shipping dev-only endpoints).
    'api_files' => [
        'st_version.php',
        'db.php',
        'lib_ai_cloud.php',
        'ai_actions.php',
        'assets.php',
        'change_alerts.php',
        'findings.php',
        'findings_export.php',
        'scan_start.php',
        'scan_status.php',
        'scan_abort.php',
        'scan_delete.php',
        'auth.php',
        'auth_oidc.php',
        'auth_qr.php',
        'schedules.php',
        'schedule_cron.php',
        'enrichment.php',
        'dashboard.php',
        'feeds.php',
        'feed_sync_lib.php',
        'lib_collectors.php',
        'lib_credentialed_checks.php',
        'lib_secrets.php',
        'lib_software_inventory.php',
        'lib_version_compare.php',
        'lib_vulnerability_priority.php',
        'lib_vulnerability_correlation.php',
        'lib_vulnerability_triage.php',
        'lib_cred_secret_helper.php',
        'lib_credential_profiles.php',
        'lib_credential_check_ops.php',
        'lib_credential_schedule.php',
        'lib_scheduler_health.php',
        'lib_credential_profile_transport_test.php',
        'collector_checkin.php',
        'credential_profiles.php',
        'cred_secret_helper_debug.php',
        'credential_check_jobs.php',
        'credential_check_runs.php',
        'collector_jobs.php',
        'collector_submit.php',
        'collectors.php',
        'credentialed_checks.php',
        'scan_history.php',
        'scan_priority.php',
        'software_inventory.php',
        'vulnerabilities.php',
        'vulnerability_triage.php',
        'logout.php',
        'settings.php',
        'health.php',
        'export.php',
        'devices.php',
        'lib_reporting_event_model.php',
        'lib_integrations_outbound.php',
        'lib_integrations.php',
        'lib_rate_limit.php',
        'lib_reconciliation.php',
        'lib_worker_jobs.php',
        'integrations.php',
        'integrations_metrics.php',
        'integrations_events.php',
        'integrations_report_summary.php',
        'integrations_dashboard.php',
        'lib_integrations_dashboard.php',
        'lib_reporting.php',
        'lib_scan_scopes.php',
        'lib_zabbix.php',
        'zabbix.php',
        'zabbix_sync_worker.php',
        'zabbix_output_worker.php',
        'scan_scopes.php',
        'scopes.php',
        'reporting.php',
        'reporting_cli.php',
        'recon_diagnostics.php',
    ],

    // daemon/*.py always copied when present (master).
    'daemon_core_py' => [
        'sqlite_pragmas.py',
        'surveytrace_paths.py',
        'surveytrace_version.py',
        'scanner_daemon.py',
        'recon_observations.py',
        'worker_jobs.py',
        'change_detection.py',
        'asset_lifecycle.py',
        'finding_triage.py',
        'scheduler_daemon.py',
        'ai_cloud_client.py',
        'fingerprint.py',
        'profiles.py',
        'cred_transport_cli.py',
        'cred_transport_ssh.py',
        'cred_transport_snmp.py',
    ],

    'daemon_sources_py' => [
        '__init__.py',
        'unifi.py',
        'snmp.py',
        'dhcp.py',
        'dns_logs.py',
        'firewall_logs.py',
        'stubs.py',
    ],

    // Copied when present (optional integrations / workers).
    'daemon_optional_py' => [
        'sync_nvd.py',
        'sync_oui.py',
        'sync_webfp.py',
        'sync_cve_intel.py',
        'collector_ingest_worker.py',
        'collector_ingest_mirror.py',
        'credential_check_worker.py',
        'cred_check_run.py',
        'software_inventory_normalize.py',
        'software_inventory_persist.py',
        'software_inventory_selftest.py',
        'vuln_correlation_jobs.py',
        'cred_check_ssh_os_release.py',
        'cred_check_ssh_packages.py',
        'cred_check_snmp_identity.py',
        'cred_secret_decrypt.py',
        'cred_check_os_release_selftest.py',
        'cred_check_package_inventory_selftest.py',
        'cred_check_snmp_identity_selftest.py',
        'cred_ssh_probe_cli.py',
        'st_software_observation_selftest.py',
    ],

    // Non-Python daemon payloads.
    'daemon_other_files' => [
        'feed_sync_worker.php',
        'feed_sync_cancel.py',
        'backup_db.sh',
        'restore_db.sh',
        'cred_decrypt_cli.php',
        'cred_secret_ops_cli.php',
    ],

    // scripts/*.php shipped to /opt/surveytrace/scripts (maintenance + production selftests).
    // scripts/*.sh shipped to /opt/surveytrace/scripts (ops / migration; bash).
    'scripts_sh' => [
        'migrate_apache_modphp_to_phpfpm.sh',
    ],

    'scripts_php' => [
        'validate_backup_restore_readiness.php',
        'rewrap_credential_secrets.php',
        'prune_operational_history.php',
        'prune_credential_runtime_history.php',
        'recover_stale_worker_jobs.php',
        'st_backup_restore_readiness_selftest.php',
        'st_cred_secret_rewrap_selftest.php',
        'st_credential_secret_no_leak_selftest.php',
        'st_cred_secret_helper_web_parity_selftest.php',
        'st_operational_prune_selftest.php',
        'st_stale_worker_recovery_selftest.php',
        'st_collector_ingest_worker_hardening_selftest.php',
        'diagnose_software_inventory.php',
        'st_software_inventory_normalization_selftest.php',
        'st_software_inventory_summary_selftest.php',
        'st_software_inventory_evidence_selftest.php',
        'st_software_inventory_diagnostics_selftest.php',
        'import_advisories.php',
        'run_vulnerability_correlation.php',
        'diagnose_vulnerability_correlation.php',
        'st_vulnerability_correlation_selftest.php',
        'diagnose_vulnerability_triage.php',
        'prune_vulnerability_activity.php',
        'resync_vulnerability_triage_priority.php',
        'st_vulnerability_triage_selftest.php',
        'st_recon_trusted_data_selftest.php',
        'st_cc_normalized_preview_selftest.php',
        'st_cc_run_visibility_selftest.php',
        'st_credential_schedule_selftest.php',
        'st_scheduler_health_selftest.php',
        'credential_schedule_tick.php',
        'st_assets_quick_search_selftest.php',
        'diagnose_collector_ingest_queue.php',
        'diagnose_scan_failure.php',
        'diagnose_scheduler.php',
        'check_deploy_coverage.php',
        'security_runtime_audit.php',
        'release_security_gate.php',
        'cleanup_deployed_stale_files.php',
        'deploy_manifest_export.php',
        'deploy_file_manifest.php',
        'st_security_runtime_audit_selftest.php',
    ],

    'public_files' => [
        'public/index.php',
        'public/css/app.css',
    ],

    'sql_files' => [
        'sql/schema.sql',
    ],

    'service_units' => [
        'surveytrace-daemon.service',
        'surveytrace-scheduler.service',
        'surveytrace-collector-ingest.service',
        'surveytrace-credential-check-worker.service',
    ],

    /**
     * Repo-only / CI helpers — intentionally not installed by deploy.sh.
     * Listed here so check_deploy_coverage.php does not flag them as missing from deploy.
     */
    'daemon_dev_only_py' => [
        'collector_agent.py',
        'collector_parity_runner.py',
    ],

    'scripts_dev_only' => [
        'smoke_credential_checks_placeholder.php',
        'smoke_credential_checks_placeholder.sh',
        'verify_schedule_cron_parity.py',
    ],
];
