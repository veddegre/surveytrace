# SurveyTrace Documentation

[← Back to Documentation](README.md)

SurveyTrace documentation for installation, operation, and understanding how the system works in practice.

---

## Getting started

- [Getting started](getting-started.md) — Install SurveyTrace, verify services, and run your first scan.
- [Installation (master)](setup-master.md) — Full master node setup, including services, permissions, and validation.
- [Collector setup](setup-collector.md) — Configure and verify remote scan workers.
- [Deployment updates](deployment.md) — Safely update an existing installation and validate results.

---

## Core concepts

- [Concepts](concepts.md) — Understand scan jobs vs inventory, scope behavior, and why reports behave the way they do.

---

## Daily workflows

- [Scanning](scanning.md) — Start scans, monitor progress, and interpret results.
- [Enrichment](enrichment.md) — Sync Zabbix data, review matches, and apply asset enrichment.
- [Reporting](reporting.md) — Generate reports, choose the correct mode, and troubleshoot missing data.

---

## System overview

- [System Guide](system-guide.md) — Deep explanation of how SurveyTrace processes scans, enrichment, and reporting end-to-end.

---

## Integrations and configuration

- [API keys](api-keys.md) — Configure NVD, Zabbix, and AI credentials, including validation and troubleshooting.
- [Integrations](integrations.md) — Set up and operate Zabbix integration, including sync, matching, availability, and output.
- [Integration Event Model](integrations-event-model.md) — Event schema and payload structure used across integrations.
- [Integrations (Data Flow)](integrations-data-flow.md) — Pull and push integration patterns, endpoints, and delivery behavior.

---

## Troubleshooting

- [Troubleshooting](troubleshooting.md) — Diagnose common issues with scans, enrichment, reporting, and system health.
- [Deployment updates](deployment.md) — Includes manual maintenance and backup/restore readiness runbooks.

---

## Advanced / internal documentation

- [Device identity](../DEVICE_IDENTITY.md) — How assets map to logical devices and how merging works.
- [Connector development guide](../CONNECTOR_DEVELOPMENT_GUIDE.md) — Internal guide for building new integrations.
- [Trusted data model](../TRUSTED_DATA_MODEL.md) — Observations, assertions, evidence, and operational “trusted” display rules.
- [Credentialed Checks Engine (design)](../CREDENTIALED_CHECKS_ENGINE.md) — Engine model plus implemented MVP slice notes and deferred boundaries.
- [Credentialed Checks MVP plan](../CREDENTIALED_CHECKS_MVP_PLAN.md) — Staged implementation record (slices 1–11 implemented; hardening slice deferred).
- [Release readiness checklist](../RELEASE_READINESS_CHECKLIST.md) — Pre-tag verification for stabilization releases.
- [Credential secret security model](security_model.md) — Helper architecture, env/sudo boundary, audit/retention, and operator must-not rules.
- [Credentialed checks vs collectors & scans](credentialed-checks-integration.md) — Where jobs run, what scans do not do yet, and history pruning pointers.
- [Worker / job execution substrate](../WORKER_EXECUTION_SUBSTRATE.md) — Shared background job design (queues, retries, health).
- [Worker execution MVP plan](../WORKER_EXECUTION_MVP_PLAN.md) — Staged implementation before coding.

---

## How to use this documentation

- Start with **Getting started** if this is a new install.
- Use **Daily workflows** for routine operations.
- Refer to **Core concepts** when behavior is unclear.
- Use **System Guide** to understand how everything fits together.
- Use **Troubleshooting** when something does not behave as expected.