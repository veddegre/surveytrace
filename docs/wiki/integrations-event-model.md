# Integration Event Model

[← Back to Documentation](README.md)

## When to use this

- Use this page when integrating SurveyTrace with external systems.
- This defines the structure of events sent via:
  - Splunk
  - syslog
  - webhooks
  - Grafana Loki

---

## Overview

SurveyTrace emits structured events for external consumption.

Events are:

- JSON-based
- consistent across integrations
- designed for SIEM and automation use

---

## Common event structure

```json
{
  "event": "scan.completed",
  "timestamp": "2026-05-05T14:30:00Z",
  "asset": {
    "id": 123,
    "ip": "192.168.1.10",
    "hostname": "host1"
  },
  "context": {
    "source": "scan",
    "integration": "splunk"
  },
  "data": {
    "status": "success"
  }
}
```

---

## Core fields

### event

Type of event:

- scan.completed
- asset.updated
- enrichment.updated
- finding.updated

---

### timestamp

- ISO 8601 format
- UTC

---

### asset

Present when applicable:

- id
- ip
- hostname

---

### context

Provides metadata:

- source (scan, enrichment, system)
- integration (splunk, syslog, webhook, etc.)

---

### data

Event-specific payload

Examples:

#### Scan event

```json
{
  "status": "completed",
  "duration_seconds": 120
}
```

#### Asset update

```json
{
  "field": "hostname",
  "old": "unknown",
  "new": "server1"
}
```

---

## Delivery behavior

- asynchronous
- non-blocking
- retried on failure (where supported)

---

## Integration-specific notes

### Splunk

- events indexed as JSON
- supports HEC batching

---

### Syslog

- events serialized to structured messages
- field flattening may occur

---

### Webhooks

- raw JSON POST
- supports custom headers

---

### Grafana Loki

- log-style events
- labeled by event type

---

## Design goals

- consistency across integrations
- minimal transformation required downstream
- compatibility with SIEM and observability tools

---

## What to expect

- not all fields are present in every event
- structure remains consistent
- new fields may be added over time

---

See also:
- integrations-data-flow.md
- system-guide.md