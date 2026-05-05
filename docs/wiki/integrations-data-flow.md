# Integrations (Data Flow)

[← Back to Documentation](README.md)

## When to use this

- Use this page when integrating SurveyTrace with external systems.
- This includes both:
  - pulling data into SurveyTrace
  - sending data out to other systems

---

## Overview

SurveyTrace supports two integration models:

```text
Pull:  External system → SurveyTrace
Push:  SurveyTrace → External system
```

These are configured independently and serve different purposes.

---

## Pull integrations

Pull integrations allow external systems to retrieve data from SurveyTrace.

### Authentication

- Uses Bearer tokens
- Each integration consumer should have its own token

---

### Supported pull types

#### Grafana Infinity (dashboard pull)

Used for:

- dashboards
- reporting views

Endpoints:

```text
/api/integrations_dashboard.php
```

Supports:

- trends
- events
- metrics
- compliance

---

#### Prometheus / Grafana metrics

Used for:

- metrics collection
- time-series monitoring

Endpoint:

```text
/api/integrations_metrics.php
```

Auth:

```text
Authorization: Bearer <token>
```

---

#### Splunk scripted input (JSON events)

Used for:

- pulling events into Splunk

Endpoint example:

```text
/api/integrations_events.php?since=...&format=jsonl
```

Auth:

```text
Authorization: Bearer <token>
```

---

## Push integrations

Push integrations send data from SurveyTrace to external systems.

Configured in:

```text
Settings → Integrations
```

---

### Supported push types

#### Generic webhook

- HTTP POST delivery
- customizable endpoint

Optional:

- HMAC signing

---

#### Splunk HEC

- sends events to Splunk
- requires:
  - HEC URL
  - HEC token

---

#### Grafana Loki

- sends log-style events
- used for dashboards and log analysis

---

#### Syslog

- sends events to syslog-compatible systems
- supports central logging and SIEM ingestion

---

## Event model

Events may include:

- scan lifecycle events
- asset updates
- enrichment changes
- risk or finding updates

---

## Integration design

- Pull and push are independent
- Integrations are:
  - non-blocking
  - configurable
  - observable via system health

---

## Tokens and security

- Each consumer should use a separate token
- Tokens can be rotated independently
- Tokens are never exposed via API responses

---

## What to expect

- Pull integrations:
  - external systems request data
- Push integrations:
  - SurveyTrace sends data automatically

---

## Common issues

### No data received (pull)

- invalid token
- wrong endpoint
- missing query parameters

---

### Push not working

- incorrect destination URL
- authentication failure
- endpoint unreachable

---

### Partial data

- depends on configured output type
- verify event payload expectations

---

## Design notes

- Integrations are designed to support:
  - SIEM platforms (Splunk)
  - observability tools (Grafana)
  - automation pipelines (webhooks)
  - logging systems (syslog)

---

See also:
- [Enrichment](enrichment.md)
- [System Guide](system-guide.md)