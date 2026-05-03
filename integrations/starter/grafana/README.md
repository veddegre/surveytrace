# SurveyTrace — Grafana Infinity starter

This folder contains an importable **Grafana dashboard** (`surveytrace-infinity-starter.json`) for the [**Infinity**](https://grafana.com/grafana/plugins/yesoreyeram-infinity-datasource/) data source (`yesoreyeram-infinity-datasource`). Panels use **JSON** over HTTP.

## Security (non-negotiable)

- **No** pull tokens, **no** `st_int_*` strings, and **no** `Authorization` headers in the dashboard JSON.
- **SurveyTrace pull APIs stay authenticated:** there are **no** anonymous integration endpoints. A missing or wrong token returns **401** / **503** JSON from SurveyTrace — fix Grafana before weakening server rules (do not change SurveyTrace auth for Grafana convenience).
- **Do not** store secrets in Grafana dashboard variables (they are easy to leak via export, URL sync, or screenshots). Use **datasource-level** (or Infinity **secure**) settings only.

## Authentication pattern (recommended)

1. Create a **`grafana_infinity_pull`** row in SurveyTrace **Integrations** (admin) and **Generate / Rotate token** once; copy the plaintext only into Grafana (not into git).
2. In Grafana, add or edit an **Infinity** datasource:
   - **Access:** **Server** (default for backend URL queries — required so Grafana’s server attaches auth to panel requests).
   - **Allowed URLs / hosts:** your SurveyTrace origin only, e.g. `https://surveytrace.example` — **no path**, **no trailing slash** (otherwise requests or TLS checks may fail).
   - **Auth for URL / JSON queries:** set **`Authorization`** to **`Bearer <token>`** using the datasource’s **secure** header / custom HTTP header UI (exact labels depend on Infinity version). That header must apply to **all** URL-based JSON queries using this datasource.

3. Import **`surveytrace-infinity-starter.json`**, set dashboard variable **`infinity`** to that datasource, and set **`surveytrace_base`** to the same origin string.

### Dashboard JSON and datasource inheritance

- Each panel sets **`datasource`** once at the **panel** level (`uid: "${infinity}"`). **Query targets do not repeat the datasource** and **do not** set `url_options.headers` — so Grafana applies the **selected Infinity datasource’s** auth and allowed-host rules to every panel URL without per-query overrides that could drop headers.
- **`url_options`** in the starter only contains **`"method": "GET"`** (no empty header maps).

If Infinity still returns **401** from SurveyTrace, Grafana is often **not** attaching the datasource header to backend URL requests — use the section below before changing SurveyTrace.

## Secure fallbacks if “datasource auth” seems ignored

Infinity versions differ slightly; try in order:

1. **Datasource → Authentication / Custom headers (secure)**  
   Ensure **`Authorization: Bearer …`** is stored in a **secure** field (not a plain dashboard query field).

2. **Infinity “global” or shared query configuration** (if your build shows it)  
   Some deployments let you define a reusable URL + auth profile bound to the datasource. Prefer that over duplicating headers per panel.

3. **Separate Infinity datasource per environment**  
   One datasource = one SurveyTrace host + one Bearer — avoids cross-environment confusion.

**Never** put the Bearer string in **`surveytrace_base`**, panel URLs, or dashboard variables.

## One integration, one token type

**Use a `grafana_infinity_pull` integration** for this starter. Configure:

`Authorization: Bearer <your grafana_infinity_pull token>`

on the Infinity datasource as above.

### What `grafana_infinity_pull` may call

| Endpoint | Notes |
|----------|--------|
| **`GET /api/integrations_dashboard.php`** | Full bundle **or** raw slices: **`?view=trends`**, **`?view=events`**, **`?view=metrics`**, **`?view=compliance`**. |
| **`GET /api/integrations_report_summary.php`** | Slim summary JSON. |
| **`GET /api/integrations_events.php?format=json`** | JSON events envelope. |
| **`GET /api/integrations_metrics.php?format=json`** | Metrics JSON v1. |

**Not allowed** with this token: Prometheus **text** on **`integrations_metrics.php`** without **`format=json`**. Use a **`prometheus_pull`** row for scrapes.

Other types stay isolated: **`report_summary_pull`** → dashboard + report summary only; **`json_events_pull`** → events (incl. **`jsonl`**); **`prometheus_pull`** → metrics endpoint (incl. text).

## Prerequisites

1. Install the **Infinity** plugin (Grafana **10+** per Infinity docs).
2. Create the **Infinity** datasource with **server** access, **allowed host**, and **Bearer** as above.
3. Import the dashboard and map **`infinity`** + **`surveytrace_base`**.

## Import

1. **Dashboards → Import → Upload JSON** → `surveytrace-infinity-starter.json`.
2. Choose the **Infinity** datasource for template variable **`infinity`** (this is the only datasource selection the panels rely on).
3. Set **`surveytrace_base`** to your origin (e.g. `https://surveytrace.example` — **no trailing slash**).

## Raw `?view=` responses

- **`…/integrations_dashboard.php?view=trends`** — array of trend rows (`timestamp` + **`timestamp_iso`** for time series).
- **`…/view=events`** — recent events array.
- **`…/view=metrics`** — live metrics object.
- **`…/view=compliance`** — compliance snapshot object.

## Starter panels (summary)

| Area | Panel types | URL pattern |
|------|-------------|-------------|
| Headline KPIs | Stat | `…/integrations_dashboard.php?view=metrics` |
| Trends | Time series | `…/integrations_dashboard.php?view=trends&trend_limit=30` |
| Events | Table | `…/integrations_dashboard.php?view=events&event_hours=24&event_limit=40` |
| Severity | Bar gauge | `…/integrations_dashboard.php?view=metrics` |
| Compliance | Table | `…/integrations_dashboard.php?view=compliance` |

## Troubleshooting **401** from SurveyTrace

1. **Query Inspector** (panel → **Inspect** → **Query**): open the request Grafana sent.  
   - **Headers:** you should see **`Authorization`** present and **redacted** (or masked) when Grafana is attaching it.  
   - If you see **`headers: []`** or no **`Authorization`** at all, Grafana’s Infinity datasource is **not** sending auth on that request — **fix the Infinity datasource / access mode / allowed URL** first. SurveyTrace is correctly rejecting an unauthenticated call.

2. **Explore** with the **same** Infinity datasource and a simple URL:  
   `${surveytrace_base}/api/integrations_dashboard.php?view=metrics`  
   If Explore works but the dashboard does not, the dashboard variable **`infinity`** may point at a **different** datasource instance (one without headers).

3. **HTTPS / host** mismatch: `surveytrace_base` must match the host allowlisted on the datasource (scheme + host, no path).

4. **Wrong token type** (e.g. `report_summary_pull` vs `grafana_infinity_pull`) still returns **401** JSON — rotate the correct integration row.

SurveyTrace **always** requires a valid pull token for these URLs; there is no anonymous read path.
