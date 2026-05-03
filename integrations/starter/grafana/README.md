# SurveyTrace — Grafana Infinity starter

This folder contains a **starter dashboard JSON** for the community [**Infinity**](https://grafana.com/grafana/plugins/yesoreyeram-infinity-datasource/) data source (plugin id **`yesoreyeram-infinity-datasource`**). Infinity is a **data source**, not a panel type: each panel stays **`stat`**, **`table`**, **`timeseries`**, etc., and points at an Infinity datasource instance.

## Prerequisites

1. Install the **Infinity** plugin on your Grafana stack.
2. Create an **Infinity** datasource (e.g. name `SurveyTrace`, access **Server** so Grafana backend calls SurveyTrace).
3. In the datasource **Allowed hosts / URLs**, add your SurveyTrace origin (scheme + host, no path), e.g. `https://surveytrace.example`.
4. **Recommended:** set a static header on the datasource: **`Authorization`** = **`Bearer <token>`**. Use a **`report_summary_pull`** integration row’s token for **`integrations_dashboard.php`** / **`integrations_report_summary.php`**, and a **`json_events_pull`** row’s token for **`integrations_events.php`** (rotate each row independently under **Integrations**). Pull APIs accept **only** per-integration tokens of the correct type. Do not embed the token in dashboard JSON if you can avoid it.

## Import

1. **Dashboards → Import → Upload JSON** and pick `surveytrace-infinity-starter.json`.
2. Map the **`infinity`** template variable to your Infinity datasource.
3. Set dashboard variables **`surveytrace_base`** (origin only, e.g. `https://surveytrace.example` — **no trailing slash**, or URLs become `https://host//api/...` and may fail) and, if you did **not** configure the Bearer header on the datasource, **`surveytrace_token`**.

## SurveyTrace JSON endpoints (Bearer must match the integration **type** for that URL — see main **`README.md`** → *Integrations (push and pull)*, route table)

| Use | URL (relative to base) |
|-----|-------------------------|
| One-shot bundle (recommended) | **`/api/integrations_dashboard.php`** — `live_metrics`, `trends_summary`, `recent_events`, `compliance_snapshot`, top-level **`scope_id`** / **`scope_name`**. Query: `scope_id`, `trend_limit`, `event_hours`, `event_limit`. |
| Report summary | **`/api/integrations_report_summary.php`** — optional **`scope_id`**. |
| Events | **`/api/integrations_events.php?since=…&format=json`** — JSON envelope; **`flat_scope=0`** disables top-level `scope_id` on each event. |
| Live metrics JSON | **`/api/integrations_metrics.php?format=json`** — fleet-wide live counts + per-scope snapshot rows. |

Auth: **`Authorization: Bearer <token>`** or **`?token=`** (less ideal; appears in logs).

## Notes

- **Prometheus** (`/api/integrations_metrics.php` default) is optional; Infinity can use **`?format=json`** or the **dashboard** bundle directly.
- Session-auth **`reporting.php?action=trends_summary`** is **not** required for this starter.
- If panel queries fail, open **Explore** with the same Infinity datasource, paste the URL, and confirm TLS / allowed hosts / token.
