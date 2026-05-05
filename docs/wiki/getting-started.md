# Getting Started

## What SurveyTrace is

- SurveyTrace is a security and asset visibility platform for running scans, enriching asset context, and reviewing risk in one interface.
- It is designed for operators who need both current inventory visibility and historical scan evidence.

## Master vs Collector

- **Master node**
  - Hosts the web UI, API, database, scheduler, and core workers.
  - Central place where scans, assets, enrichment, and reports are managed.
- **Collector node**
  - Optional remote scan worker.
  - Runs scans near remote networks and sends results back to the master.

## Installation summary

- **Install master**
  - `sudo ./setup.sh`
- **Deploy updates**
  - `sudo ./deploy.sh`
- **Install optional collector**
  - `cd collector`
  - `sudo ./setup.sh`

## First steps

- Start a scan from **Scan control**.
- Watch progress and completion state in **Scan history**.
- Open **Assets** to review discovered hosts and findings.
