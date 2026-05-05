# SurveyTrace

SurveyTrace is a security and asset visibility platform that combines scanning, enrichment, vulnerability tracking, and reporting into a single operator-focused interface.

It provides both historical scan insight and current asset state without forcing everything into one model.

SurveyTrace 1.0.0 marks the first stable release.

## What “SurveyTrace” means

SurveyTrace combines two ideas at the core of network visibility.

Survey refers to systematically examining an area to map what exists within it, similar to how a land surveyor documents every boundary and structure on a property. Trace refers to following connections to their source and keeping a record of what was found and when.

Together, the name describes exactly what the tool does: it surveys your network to discover what is there, then traces those assets over time so you can understand how your environment changes.

## Core capabilities

- Asset discovery and tracking
- Vulnerability detection and lifecycle management
- Enrichment (Zabbix integration, AI summaries)
- Reporting and analysis (job scope and inventory scope)
- Role-based access control
- Distributed scanning with collectors

## Key concepts

- **Scan jobs**: completed scans are stored as historical snapshots.
- **Inventory**: current asset state updated independently of scans.
- **Job scope**: scope assigned to a scan job (used for historical reporting).
- **Inventory scope**: scope assigned to assets (used for grouping and enrichment).

A scope with assets does not automatically have scan history. Reports separate:

- Job-based reporting (historical)
- Inventory-based reporting (current state)

## Installation

### Master node

```bash
sudo ./setup.sh
```

Installs application, services, permissions, and runs validation checks.

### Deploy updates

```bash
sudo ./deploy.sh
```

Updates files, validates permissions, and restarts services.

### Collector node (optional)

```bash
cd collector
sudo ./setup.sh
```

Collectors are remote scan workers with their own validation.

## Basic usage

- Start scans from Scan control
- Monitor progress in Scan history
- Review assets in Assets
- Open Host details for ports, enrichment, AI summaries, and vulnerabilities
- Use Reports & Analysis for job-based and inventory-based reporting
- Use Enrichment for Zabbix mapping and data workflows

## Interface overview

- Dashboard — high-level summary
- Assets — current inventory
- Scan history — job queue and completed scans
- Reports & Analysis — reporting and comparisons
- Enrichment — Zabbix mapping and enrichment workflows
- Integrations — external system configuration
- System Health — service and integration status

## Documentation

- [Connector development guide](docs/CONNECTOR_DEVELOPMENT_GUIDE.md)

## Wiki

- [Wiki index](docs/wiki/)

## Changelog

See [CHANGELOG.md](./CHANGELOG.md) for version history.

## Notes

- Zabbix output requires `zabbix_sender` on Debian/Ubuntu
- Install scripts include post-run validation
- Collector installs validate independently
