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

### Dashboard JSON and datasource binding

- **Every panel** and **every Infinity query target** use the same datasource reference: **`{ "type": "yesoreyeram-infinity-datasource", "uid": "${infinity}" }`**. After import, **`${infinity}`** must resolve to the **same** Infinity instance you configured with **Bearer** (not an unconfigured “default” Infinity datasource).
- Targets include **only** `type` + `uid` (variable) — **no** `url_options`, **no** `headers`, **no** `Authorization` in JSON, so Grafana never merges an empty `headers: []` that overrides secure datasource auth.
- Panel URLs stay **absolute** using **`${surveytrace_base}`** (full `https://host/...`). That matches typical Infinity “allowed host + full URL” setups. If your Infinity build supports a **pinned base URL** on the datasource and you prefer **relative** paths (e.g. `/api/integrations_dashboard.php?view=metrics`), you may change panel URLs after import — auth must still come **only** from the datasource, not the dashboard.

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
2. **Critical:** for template variable **`infinity`**, pick the **Infinity datasource that already has** `Authorization: Bearer …` (and allowed host) saved — not a second generic Infinity datasource with no auth.
3. Set **`surveytrace_base`** to the **same** origin you allowlisted on that datasource (e.g. `https://surveytrace.example` — **no trailing slash**).
4. If you previously imported an older starter, **re-import** or **save** the dashboard after mapping **`infinity`**, so panels and targets pick up the variable resolution Grafana expects.

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

## No data (empty panels) when Bearer is already configured

Bearer on the Infinity datasource only applies to requests Grafana actually sends. The starter still needs the **right URL** and the **right datasource variable**; otherwise panels stay empty even though curl to your real host works.

1. **Set `surveytrace_base` on the dashboard** (dropdown at the top after import).  
   It ships with the placeholder **`https://surveytrace.example`**. Every panel URL is `${surveytrace_base}/api/…`. If you do not change it, Grafana requests **surveytrace.example**, not your instance (e.g. **`https://st.vedders.xyz`**). Infinity may block that host, or you get a non-SurveyTrace body — Stat/Table panels then show **No data**.  
   **Fix:** set **`surveytrace_base`** to the **same** origin string as **Allowed hosts** on the datasource (scheme + host, **no** trailing slash, **no** path).

2. **Query Inspector → Query**  
   Check **HTTP status** and the **response body** (or error):  
   - **401** with a small JSON error from SurveyTrace → auth or token type still wrong for that URL (see the **401** section below).  
   - **200** with a normal metrics/trends JSON body but the panel is empty → rare; note the **Executed URL / request URL** and confirm it is your host.

3. **`infinity` variable**  
   Must point at the **same** Infinity datasource where Bearer and allowed hosts are configured (see variable description in the imported JSON).

4. **Integration type**  
   The Bearer value must be a **`grafana_infinity_pull`** token. Other pull types can return **401**, which often surfaces as empty panels rather than a friendly error.

5. **Datasource access mode**  
   Prefer **Server** (default for backend queries). **Browser** access can behave differently with headers and CORS; if you use Browser, confirm in the inspector that requests still succeed.

## Troubleshooting **401** from SurveyTrace (curl works, Grafana does not)

**Symptom:** `curl -H 'Authorization: Bearer …' 'https://host/api/integrations_dashboard.php?view=metrics'` returns **200**, but Grafana panels return **401** and **Query Inspector** shows **`headers: []`** (or no `Authorization`).

**Meaning:** SurveyTrace is fine; **Grafana is not applying the Infinity datasource’s secure headers** on that query. Do **not** change SurveyTrace auth; fix Grafana / datasource binding.

1. **Confirm the panel datasource**  
   In the panel editor → **Query** tab, the datasource dropdown must be the **authenticated** Infinity datasource (the one where you set Bearer). If it shows **“Infinity”** but a **different UID** than the one you configured, the dashboard is hitting an unauthenticated datasource.

2. **Confirm the `infinity` variable**  
   Dashboard **Settings → Variables → `infinity`**: value must be that same datasource. **Re-import** the dashboard or **re-select** the variable after creating the datasource so `${infinity}` resolves correctly.

3. **Query Inspector** (panel → **Inspect** → **Query**)  
   - When auth is applied, request metadata usually shows **`Authorization`** (often **redacted** / masked).  
   - **`headers: []`** means the backend request was built **without** merging datasource auth — revisit Infinity datasource **Server** access, **Allowed URLs**, and **secure** custom headers; check for a second default Infinity datasource with no headers.

4. **Explore sanity check**  
   Open **Explore**, select the **same** Infinity datasource, run a URL query to  
   `${surveytrace_base}/api/integrations_dashboard.php?view=metrics`.  
   If Explore shows headers/auth but the dashboard does not, the dashboard was almost certainly using a **different** datasource before you fixed the variable — **save** the dashboard after correcting **`infinity`**.

5. **HTTPS / host**  
   `surveytrace_base` must match the host allowlisted on the datasource (scheme + host, no path). If you still have the import placeholder **`https://surveytrace.example`**, curl can succeed against your real host while Grafana does not — see **No data** above.

6. **Wrong pull token type** (e.g. wrong integration row) still yields **401** JSON from SurveyTrace — use a **`grafana_infinity_pull`** token for this starter.

SurveyTrace **always** requires a valid pull token for these URLs; there is no anonymous read path.

### `?token=` vs `Authorization: Bearer`

If a request includes **both** a non-empty Bearer token and **`?token=`**, SurveyTrace uses **Bearer first**. Previously **query `token` won**, which could make Grafana look “authenticated” in the datasource while SurveyTrace still saw an old or empty **`?token=`** on the URL and returned **401** — fix URLs or rely on Bearer only.
