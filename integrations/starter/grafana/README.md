# SurveyTrace — Grafana Infinity starter

This folder contains an importable **Grafana dashboard** (`surveytrace-infinity-starter.json`) for the [**Infinity**](https://grafana.com/grafana/plugins/yesoreyeram-infinity-datasource/) data source (`yesoreyeram-infinity-datasource`). Panels use **JSON** over HTTP; the starter does **not** embed tokens or `Authorization` headers in the JSON.

## One integration, one datasource token

**Use a single `grafana_infinity_pull` integration** in SurveyTrace **Integrations** (admin): create the row, **Generate / Rotate token**, then configure the **Infinity datasource** (server access) with:

`Authorization: Bearer <your grafana_infinity_pull token>`

**Do not put tokens in dashboard JSON.** Do not commit Bearer headers in the dashboard file. Rotate the token only on that integration row.

### What `grafana_infinity_pull` may call

| Endpoint | Notes |
|----------|--------|
| **`GET /api/integrations_dashboard.php`** | Full bundle **or** raw slices: **`?view=trends`**, **`?view=events`**, **`?view=metrics`**, **`?view=compliance`** (raw JSON only; no `{ "ok": true, … }` wrapper). |
| **`GET /api/integrations_report_summary.php`** | Slim summary JSON. |
| **`GET /api/integrations_events.php?format=json`** | JSON events envelope (**`json_events_pull`** is still the dedicated type for **`format=jsonl`** / heavy event consumers). |
| **`GET /api/integrations_metrics.php?format=json`** | Metrics JSON v1. |

**Not allowed** with this token: **Prometheus text** on **`integrations_metrics.php`** (default `format` without `json`). Use a **`prometheus_pull`** row for scrapes.

Other pull types stay isolated: **`report_summary_pull`** → dashboard + report summary only; **`json_events_pull`** → events only; **`prometheus_pull`** → metrics endpoint only (including Prometheus text).

## Prerequisites

1. Install the **Infinity** plugin.
2. Create an **Infinity** datasource (server access). Under **Allowed hosts / URLs**, add your SurveyTrace origin (scheme + host, **no path**, **no trailing slash**).
3. Set the datasource header **`Authorization: Bearer …`** using the **`grafana_infinity_pull`** token from Integrations.

## Import

1. **Dashboards → Import → Upload JSON** → `surveytrace-infinity-starter.json`.
2. Map template variable **`infinity`** to your Infinity datasource.
3. Set **`surveytrace_base`** to your origin (e.g. `https://surveytrace.example` — no trailing slash).

## Raw `?view=` responses (Infinity-friendly)

These return **only** the slice (array or object), **not** wrapped in SurveyTrace’s usual dashboard envelope:

- **`/api/integrations_dashboard.php?view=trends`** — `trends_summary` array (completed jobs). Each row includes legacy **`timestamp`** plus **`timestamp_iso`** (UTC `2026-05-02T18:18:38Z`) for Infinity time fields; the starter timeseries panels use **`timestamp_iso`**.
- **`/api/integrations_dashboard.php?view=events`** — `recent_events` array (bounded by **`event_hours`** / **`event_limit`**).
- **`/api/integrations_dashboard.php?view=metrics`** — `live_metrics` object (assets, open findings, severity counts, etc.).
- **`/api/integrations_dashboard.php?view=compliance`** — `compliance_snapshot` object.

The starter panels use these URLs so **no `root_selector`** is required against the full bundle.

## Starter panels (summary)

| Area | Panel types | Data source URL pattern |
|------|-------------|-------------------------|
| Headline KPIs | Stat | `…/integrations_dashboard.php?view=metrics` |
| Trends | Time series | `…/integrations_dashboard.php?view=trends&trend_limit=30` |
| Events | Table | `…/integrations_dashboard.php?view=events&event_hours=24&event_limit=40` |
| Severity | Bar gauge | `…/integrations_dashboard.php?view=metrics` |
| Compliance | Table | `…/integrations_dashboard.php?view=compliance` |

If a query fails, use Grafana **Explore** with the same datasource and URL to verify TLS, allowed hosts, and token type.
