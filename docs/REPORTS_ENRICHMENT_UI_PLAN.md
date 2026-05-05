# Reports & Analysis + Enrichment — UI clarity plan

**Status:** Reports **Pass 1** (layout + copy + admin Advanced collapse) **implemented** in `public/index.php` + `public/css/app.css`. Enrichment passes remain planning.  
**Scope:** `public/index.php`, `public/css/app.css` (future passes).  
**Out of scope for this document:** backend/API behavior, `VERSION`, feature removal.

This document audits the **current** UI (as reflected in `public/index.php` around `#t-report` and `#t-enrich`) and proposes a clearer structure, copy, and incremental implementation passes. It does **not** assert that any described improvement is already shipped.

---

## Part 0 — Role / navigation context (audit)

### Reports & Analysis (`#t-report`)

- The tab is visible to **viewers** and **scan editors** (alongside other main nav items).
- **Set baseline** UI (`#report-baseline-set-wrap`) is shown only when `stRoleCanManageScans()` is true **and** the reporting scope filter is **not** “All scopes” (`overviewMode` is false). Viewers never see the setter; scan editors see it in **named scope** or **Unscoped only** modes (`loadReportingTab` logic).
- **`baseline_debug` / `compare_debug`** blocks are visible in the DOM for admins (`stRoleIsAdmin()` toggles `#report-baseline-debug-wrap` and `#report-cmp-debug-wrap`).
- **Create scope** (`#report-scope-create-btn`) is tied to `applyRoleAwareUi` / scope flows — treat as **scan editor or admin** capability in implementation (align with existing `stRoleCanManageScans()` gates on Scopes).
- **Saved report artifacts** table loads for all roles that can open Reports; **Details** on a row requires `stRoleCanManageScans()` (viewer sees “—”).

### Enrichment (`#t-enrich`)

- In **`applyRoleAwareUi`**, the nav item `#nenrich` is **`display:none` unless `stRoleIsAdmin()`**. So today **only admins** open the Enrichment tab in the shell, even though copy references Scan/Schedules for Phase 3b.
- **Zabbix integration configuration** (API URL, token, sync) lives under **Integrations → Zabbix** (`#st-zabbix-card`), not inside `#t-enrich`.
- **Zabbix operator tools** (match review, rules, apply, manual link) live in `#st-zabbix-enrich-tools-wrap`, toggled by JS (`stZabbixApplyEnrichmentPanel`, `loadZabbixEnrichmentPanel`, etc.).

*Planning implication:* Enrichment layout proposals target **admin-first** UX unless product later exposes the tab to `scan_editor`; Reports proposals must explicitly cover **viewer vs scan editor**.

---

## Part 1 — Reports & Analysis audit

### Current structure (high level)

1. **Page title** + long intro (`hint-micro`) mixing snapshot semantics, baseline, drift, and scope rules.
2. **Card: Reporting scope** — selector, Refresh, Create scope, long “How filtering works” explainer + `scan_jobs.scope_id` vs `assets.scope_id`, unscoped warning.
3. **Section: At a glance** — card with another explainer + `#report-at-glance-kpis` + compliance line container.
4. **Section: Snapshot drift** — dense paragraph + `#report-change-since`.
5. **Section: Scan history (snapshots)** — trend explainer + limit selector + `#report-trends-out`.
6. **Region: Analysis & tools** (border-top, slightly faded) — subtitle “Secondary controls…” then:
   - **Baseline** card — status HTML (often very technical: legacy global, named scope, unscoped pool, config ids), validation line, conditional **Set baseline** form, **Admin debug** baseline JSON.
   - **Manual compare** card — two job pickers + Compare + optional admin compare_debug.
   - **Compliance detail** card — job picker + vs-baseline checkbox + Load compliance.
   - **Saved report artifacts** — heading + card (often hidden until loaded; table).

### Problems observed

| Area | Issue |
|------|--------|
| **Information hierarchy** | Automatic summaries (at a glance, drift, trends) sit above tools, but **scope card** and **intro** demand heavy reading before any “success state” is visible. |
| **Language** | “Baseline”, “legacy global”, “unscoped pool”, “effective job”, `phase13_baseline_job_id`, and “All scopes” interact in ways that are **accurate but not scannable**. |
| **Automatic vs manual** | “Analysis & tools” labels the lower region secondary, yet **Baseline** card contains both **read-only status** (automatic/diagnostic) and **Set baseline** (manual), plus **admin debug** — three mental models in one card. |
| **Admin path** | Debug (`baseline_debug`, `compare_debug`) is admin-gated in JS but still **competes visually** with operator baseline text when expanded. |
| **Visual rhythm** | Similar weight: `sth section-top`, `card`, `hint-micro` blocks repeat; **#report-analysis-region** uses opacity/border to separate tools but still feels like “more of the same density”. |
| **Artifacts** | Scheduled report artifacts are **easy to miss** (heading/wrap display logic) and read as an afterthought vs “what do I do first?”. |

### Target structure (preferred model)

Align DOM order and headings with user intent: **context → automatic answers → optional depth → manual tools → advanced**.

#### A. At a glance (start here)

- **Single** short intro line: “Snapshot reporting for **completed scans** in the scope you pick below — not live Dashboard totals.”
- **Reporting scope** card merged into this section **or** immediately under it with a **plain-language** title, e.g. “Which scans am I looking at?”
  - **Plain-language helper** (required): one diagram or bullet trio — **Job scope** (tag when scan was queued → which jobs appear), **Asset scope** (live inventory tag → counts in parentheses only), **Baseline** (frozen reference job for drift/compliance in that bucket). Defer `scan_jobs.scope_id` / SQL names to an **“Advanced / field names”** `<details>`.
- KPI row: latest completed scan identity, asset count, findings summary if present, compliance summary if present (unchanged data; clearer **labels** and fewer parentheticals).

#### B. Snapshot drift

- **One** short paragraph: **Baseline** = “reference completed scan”; **Current** = “latest completed scan in this filter”; drift = automated diff when the product has a valid pair.
- Output area: keep `#report-change-since`; improve **empty / no-baseline** states with friendly copy + link to “Set baseline” or “Pick a named scope” (no API change — copy + layout only).
- Move **long** compatibility rules (unscoped pairing, legacy global) into `<details>` “How automatic drift chooses a prior scan”.

#### C. Trends

- Keep limit control + `#report-trends-out`; heading “Trends” with subline: “Each point = one **finished** job in the current scope filter (last N).”
- Optional: collapse chart/table by default on small viewports only (CSS/media) — decide in Pass 2.

#### D. Manual analysis tools (visually secondary)

- New parent: **“Manual & advanced”** with muted section chrome (e.g. `section` + `report-tools-region` class): lower visual priority than At a glance / Drift.
- **Inside**, ordered:
  1. **Compare two scans** — rename label to e.g. **“Compare any two completed scans”** (avoid sounding like automatic drift). Subtext: “For ad-hoc investigation; does not replace scoped automatic drift.”
  2. **Set / change baseline** — only when `stRoleCanManageScans()` and not “All scopes” (current rule preserved).
  3. **Compliance detail** — “Full rule text for one job” (secondary `tbtn` for Load).
  4. **Saved report artifacts** — same table; move **up** within manual section if schedules are a primary output for editors (optional UX choice in Pass 1).
  5. **Advanced** `<details>`: admin debug triggers, raw JSON toggles, `baseline_debug` / `compare_debug` **only** here (may still be `display:none` for non-admin).

**Rules recap:** Automatic/read-only first; manual below; admin/debug not in the main scan path.

---

## Part 2 — Reports UX decisions (recommendations)

| Topic | Recommendation |
|--------|------------------|
| **Collapsed by default** | **Yes:** “How filtering works” long block → `<details>` under scope card. **Yes:** “How automatic drift chooses…” (long pairing rules). **Yes:** Admin **baseline_debug** / **compare_debug** blocks → nested under **Advanced** (admin-only), collapsed until opened. **Consider:** Baseline **status** card body collapsed when status HTML exceeds N lines (CSS `line-clamp` + expand — Pass 3). |
| **Viewer vs scan_editor** | **Viewer:** scope selector + refresh (read-only), all read-only summaries, trends, manual compare **read** if APIs allow (today compare runs without extra gate — confirm in Pass 1 code review); hide **Set baseline**, **Create scope**, artifact **Details**, compliance **Load** if policy should be viewer-read-only (align with product; current code allows compare for anyone who can call API). **Scan editor / admin:** show baseline setter (non–all-scopes), Create scope, artifact details, compliance load. **Admin:** Advanced debug inside collapsed region. |
| **Scope selector explanation** | Label: **“Report filter (completed jobs)”**; helper: “Jobs are included if they were **queued with** this catalog scope. Parentheses on named scopes show **live assets** tagged with that scope — coverage hint only.” |
| **Baseline unavailable** | Replace internal wording with user-facing tiers: e.g. “**No baseline set** for this scope — pick a completed scan below.” / “**Baseline scan missing or unusable** — choose another completed scan.” Keep one technical sentence in Advanced. |
| **Manual compare label** | **“Compare any two completed scans”** + secondary: “Custom diff; use when automatic drift is not available or you need a specific pair.” |

---

## Part 3 — Enrichment audit

### Current structure (high level)

1. Title + short intro paragraph.
2. **Three overview cards** in `row-wrap`: Network enrichment, Zabbix (`#enrich-zbx-overview-card` + sync + “Open tools”), “More integrations” placeholder.
3. **`scgrid`**: left — **Active sources** + Add source; right — **Available source types** + **How enrichment works** (long `help-line`).
4. **`#st-zabbix-enrich-tools-wrap`** (often hidden): tools head + Expand, freshness banner, intro, panel with Match review, Scope rules (diagnostics nested), Apply actions (identity + scope apply), Manual link/unlink.

### Problems observed

| Area | Issue |
|------|--------|
| **Spacing** | Mixed `mb10` / `mb12` / `mb14`, inline padding on cards (`padding:14px 14px 12px`), `scgrid` asymmetry — **Active sources** feels primary but **Zabbix tools** is a separate full-width card **below** the grid → “bolted on”. |
| **Buttons** | `btnp btn-xs` on “Run sync now” / “Open Zabbix enrichment tools” next to `tbtn` elsewhere; **Refresh match review** uses default `tbtn` without `btn-xs` — inconsistent hierarchy. |
| **Zabbix dominance** | Overview row gives Zabbix **equal card width** to Network even when not configured; tools CTA can appear **before** the user understands configuration lives under Integrations. |
| **Separation of concerns** | **Source configuration** (Integrations) vs **enrichment status** (overview card) vs **operator tools** (panel) is explained in prose but not **visually** chunked. |
| **Diagnostics** | Diagnostics toggle lives **inside** Scope rules section — acceptable but easy to miss; should be under **Advanced** collapsed group. |

### Target structure (preferred model)

#### A. Enrichment overview

- Row of **compact** summary cards (shared card component / tokens): **Network (Phase 3b)**, **Zabbix**, **Other connectors** (placeholders).
- **Zabbix card when not configured / not enabled:** small state only — “Not connected” + `tbtn` **“Configure in Integrations”** (secondary). **No** “Open tools” until integration is enabled **or** user is admin configuring (exact gate mirror existing JS: `stZabbixApplyEnrichmentPanel` / `stEnrichmentRefreshZabbixOverview` — planning only).

#### B. Active sources (configured)

- Same list as today; normalize **card** padding and **+ Add source** as `btnp` primary at bottom or top-right consistent with Scopes patterns.

#### C. Zabbix tools (integrated block)

- **One** contiguous region: title **“Zabbix enrichment”** with substatus line (sync freshness), then **operator tools** in a **2-column grid** on wide screens (Match review | Scope rules) and stack on narrow; **Identity** and **Scope apply** as subsections under Apply with shared `zb-enrich-section` spacing tokens in CSS.
- **Match review | Scope rules | Identity | Diagnostics** — Diagnostics moves to **D** (Advanced).

#### D. Advanced / diagnostics

- `<details>` collapsed by default: diagnostics JSON, technical warnings, optional “raw” toggles mirroring Reports pattern.

### Button / token rules (Enrichment)

- **Primary:** `btnp` / `btnp btn-sm` — Save, Apply selected, Create scope from prereq banner, Run sync (when prominent).
- **Secondary:** `tbtn` / `tbtn btn-sm` / `tbtn btn-xs` — Preview, Refresh, Expand panel.
- **Destructive quiet:** `tbtn--danger-quiet` — Unlink, destructive secondary (align with app-wide table pass).

Remove **ad hoc** `style="..."` margins on Enrichment cards where a shared class (`enrich-section`, `enrich-card`) can define rhythm.

---

## Part 4 — Implementation passes

### Reports Pass 1 — Structure + copy (no API)

- Reorder or re-wrap DOM to match **A → B → C → D**; merge or split cards as needed **without** changing IDs hooked by JS (`report-at-glance-kpis`, `report-change-since`, `report-trends-out`, pickers, etc.) unless each consumer is updated in the same pass.
- Replace top **wall of text** with short intro + `<details>` for scope/job/asset glossary.
- Add semantic wrappers + CSS classes: `report-section`, `report-section--tools`, `report-kpis`, `report-scope-card`.
- **Files:** `public/index.php`, `public/css/app.css`.

### Reports Pass 2 — Collapse + empty states

- Default-collapsed: Advanced blocks, long helpers, admin debug.
- Baseline **unavailable** / **no prior scan** strings: user-tested copy in `loadReportingTab` / drift render paths (JS strings only).
- Artifacts empty/loading rows: align with `tbl-empty` pattern if tables touched.

### Reports Pass 3 — Visual polish

- Trends/compare tables: `tbl-wrap--data` / spacing consistency.
- Optional: KPI grid uses same stat language as Scan Details cards (visual family only).

### Enrichment Pass 1 — Layout + Zabbix when off

- Introduce shared vertical rhythm classes; remove redundant inline padding on overview cards.
- **Zabbix overview:** compact “not configured” path; move full tools panel **below** Active sources inside a **single** visual column or full-width **band** with clear heading.
- Button class normalization per table above.
- **Files:** `public/index.php`, `public/css/app.css` (`.zb-enrich-*` consolidation).

### Enrichment Pass 2 — Operator tools + diagnostics

- Grid layout for Match review / Scope rules; group Apply subsections; move **Diagnostics** to collapsed Advanced.
- “Expand” tools panel: consider default **open** when Zabbix enabled **and** admin opened tab for work (optional — product decision); at minimum preserve aria-controls.

### Enrichment Pass 3 — Source cards + placeholders

- “Available source types” + “How enrichment works” — optional collapse of long doc card; normalize “More integrations” card to same height tokens as others.

---

## Part 5 — Acceptance criteria (post-implementation)

- **Reports:** A first-time user can answer “what is this page?” and “what do I do first?” in **one screenful** without reading SQL field names.
- **Reports:** Automatic summaries (at a glance, drift, trends) are visually **primary**; manual tools and admin debug are **secondary** or hidden until expanded.
- **Reports:** Scope vs asset-tag vs job-scope is explained in **plain language**, with technical names optional.
- **Enrichment:** Spacing and buttons match the rest of the app (`btnp` / `tbtn` / `tbtn--danger-quiet`); no random inline margins for the same concept.
- **Enrichment:** When Zabbix is not configured, the tab does **not** present a full operator surface — **small setup CTA** only.
- **Enrichment:** When Zabbix is configured, tools feel like **one** module (overview → sources → tools), not an appendix.
- **No** backend/API behavior changes unless explicitly approved in a later phase.

---

## Files likely touched (implementation)

| File | Role |
|------|------|
| `public/index.php` | `#t-report` and `#t-enrich` markup, `loadReportingTab` / reporting render strings, Zabbix panel HTML strings, optional `applyRoleAwareUi` tweaks if nav rules change (product decision). |
| `public/css/app.css` | `report-*`, `zb-enrich-*`, shared section/card spacing, details/summary styling for Advanced blocks. |
| `docs/REPORTS_ENRICHMENT_UI_PLAN.md` | This plan; update checkboxes or status when passes complete. |

### Related (likely unchanged in early passes)

- `api/reporting.php`, `api/lib_reporting.php` — **not** required for UI-only passes.
- `docs/UI_CLEANUP_PLAN.md` — may cross-link from this doc after implementation.

---

## Open questions (resolve before or during Pass 1)

1. **Should viewers run Manual compare / Load compliance?** Current client does not obviously gate those buttons by role — confirm intended RBAC and align UI disabled states + tooltips with API enforcement.
2. **Enrichment tab visibility:** Today **admin-only** nav; should **scan_editor** see read-only Enrichment (sources list) without Integrations? Product decision; affects Part 0 and Enrichment Pass 1.
3. **Integrations vs Enrichment split:** Whether to add a **single** deep link banner at top of Enrichment (“Zabbix API token: Integrations → Zabbix”) vs moving a slim read-only status only — **no** API change either way.

---

*Document version: planning draft aligned to repository layout audit (index.php `#t-report` ~757–904, `#t-enrich` ~1207–1352, `applyRoleAwareUi` ~2744–2758, `loadReportingTab` ~14254+).*
