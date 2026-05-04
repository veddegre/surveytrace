# UI cleanup plan (no implementation yet)

This document is a **structured audit and cleanup plan** for the SurveyTrace **single-page UI** (`public/index.php`, `public/css/app.css`). Goals: **clarity**, **consistency**, and **usability** — without changing **backend behavior**, **removing features**, or shipping code in this step.

**Navigation / header redesign (proposal, separate doc):** [`docs/NAV_REDESIGN.md`](NAV_REDESIGN.md) — target shell layout (header, Account menu, collapsible sidebar groups, scan-history redirect), implementation passes, risks, and acceptance criteria. **Not implemented** unless noted elsewhere.

**Host Details panel redesign (proposal, separate doc):** [`docs/HOST_DETAILS_REDESIGN.md`](HOST_DETAILS_REDESIGN.md) — centered wide modal, section/tabs IA, accessibility, implementation passes, risks. **Not implemented** unless noted elsewhere.

**Scope assumption:** Most interactive UI lives in **`public/index.php`** with shared styles in **`public/css/app.css`**. Validation later: grep for remaining native **`window.confirm` / `alert` / `prompt`** (including minified patterns), keyboard flows, and mobile widths.

---

## Principles (apply to every pass)

1. **Same mental model** — If two features both “filter,” they share disclosure, count, reset, and labeling patterns.
2. **Progressive disclosure** — Advanced filters and diagnostics stay behind explicit toggles; defaults stay calm.
3. **One primary action per surface** — Destructive or irreversible actions stay visually and cognitively secondary until confirmed (checkbox + explicit button).
4. **No silent filters** — Anything that changes the list/query should be visible in the filter summary or disclosure label (no “hidden magic”).
5. **Reuse tokens** — Prefer shared CSS utility classes for card padding, table density, and button variants over one-off `style=""` blocks.

---

## 1. Assets view

### Current observations (audit hooks)

- **Filters** — AI filters use a disclosure with **dynamic “(N active)”** on the toggle (`stAssetsAiFiltersDisclosureToggle` path). Zabbix filters use a separate disclosure. **Scope** may use a `<select>` that is **`display:none`** until schema/features allow it — risks feeling like a “hidden” control if shown/hidden without a clear empty state.
- **Bulk actions** — Visibility likely tied to selection state; need explicit audit: when are bulk bars shown, do labels match actions, and does **Clear filters** reset selection expectations?
- **Columns** — **Zbx** column toggled with `hide` class; **scope** vs **hostname** semantics already documented in-page but dense; operators may still confuse **inventory scope** vs **Reports job scope** (copy exists — verify placement and skimmability).
- **Clutter** — Multiple hint blocks (scope vs Zabbix vs reports) may stack; consider collapsible “How filtering works” for returning users.

### Plan items

| ID | Item | Notes |
|----|------|--------|
| A1 | **Unify filter strip layout** | Single horizontal rhythm: search → always-visible essentials → grouped “More filters” (AI | Zabbix | Scope) with identical disclosure chrome. |
| A2 | **Active filter count on every disclosure** | Match AI pattern for Zabbix and Scope: `Label (N active)` when any sub-control applies. |
| A3 | **Unified “Clear” behavior** | One **Clear filters** resets all disclosed panels + search + sort overrides; document in tooltip that scope selection resets too (if applicable). |
| A4 | **Scope control discoverability** | If scope `<select>` stays hidden until migration, show a compact **“Scope filter: not available”** or **“Enable in Scopes”** stub instead of empty space. |
| A5 | **Bulk action bar** | Sticky or high-contrast strip when `>0` selected; consistent verb forms (Set scope / Clear scope / …); ensure disabled reasons visible (tooltip or inline hint). |
| A6 | **Column headers** | Short labels + rich **`title`** / `aria-description`; consider a **legend** popover for Zbx trust fields vs hostname column. |
| A7 | **Reduce duplicate explanations** | Deduplicate long help paragraphs; one canonical “Scope vs reports” expandable section. |

---

## 2. Enrichment (Zabbix) page / tab

### Current observations

- **Cards** — **`#st-zabbix-enrich-tools-wrap`** uses `padding:14px 14px 12px` while **`#st-zabbix-card`** uses default card padding (`card` + `mt12`): likely source of **inconsistent vertical rhythm** (“Zabbix card issue”).
- **Collapse** — **“Zabbix enrichment tools”** panel has **Expand** toggle; Integrations Zabbix card points users to Enrichment — two surfaces with different density and headings.
- **Match review** — Large tables without sticky header / summary row counts may hurt scanability.
- **Diagnostics** — Zabbix cache status / hints belong in an **“Advanced / Diagnostics”** disclosure vs inline with operator workflows.

### Plan items

| ID | Item | Notes |
|----|------|--------|
| E1 | **Normalize card padding** | Apply same `card` padding variables to tools wrap, integration card, and inner sections; remove ad-hoc `style="padding:…"` where possible. |
| E2 | **Collapse pattern parity** | Same button style (`tbtn` vs `btnp`), same **Expand/Collapse** wording, same `aria-expanded` behavior as other panels (e.g. AI filters on Assets). |
| E3 | **Section hierarchy** | H3-style section titles inside tools: **Match review** | **Scope rules** | **Apply plans** | **Manual link** — visual separators and consistent `mb*` spacing scale. |
| E4 | **Match review table UX** | Sticky header, zebra optional, max-height with scroll, **summary row** (“Showing N of M”), empty state illustration. |
| E5 | **Diagnostics drawer** | Move cache-status JSON / debug hints behind **“Diagnostics”** disclosure; keep **Sync** CTA at top-level. |

---

## 3. Filters UX (cross-cutting)

### Target pattern (all: AI, Zabbix, scope)

| Element | Behavior |
|---------|----------|
| **Disclosure** | Button with `aria-expanded`, `aria-controls`; panel `role="region"`; keyboard Enter/Space. |
| **Active count** | Append `(N active)` only when `N>0`; `N` counts applied API params, not “dirty unchecked” UI. |
| **Clear** | Global clear resets; optional per-panel “Reset this group.” |
| **Hidden magic** | Remove implicit filters (e.g. URL params without UI mirror, or select `display:none` without explanation). |

### Plan items

| ID | Item | Notes |
|----|------|--------|
| F1 | **Pattern doc in code comment** | Short block comment above Assets filter helpers describing the contract (for future contributors). |
| F2 | **Parity checklist** | AI ✓ (reference) → bring Zbx + Scope to same checklist before closing Pass 1. |
| F3 | **Reports scope filters** | When touching Reports, apply same disclosure + count pattern for **job scope** filters there (visual family with Assets even if semantics differ). |

---

## 4. Modals

### Plan items

| ID | Item | Notes |
|----|------|--------|
| M1 | **Inventory native dialogs** | Repo-wide search (`confirm`, `alert`, `prompt`); replace with shared modal component pattern (title, body, primary/secondary/destructive). |
| M2 | **Destructive confirm template** | Checkbox **“I understand …”** + enabled **Confirm** button (disabled until checked); used for delete integration, bulk destructive, unlink where irreversible. |
| M3 | **Copy deck pass** | Align titles (“Delete X” vs “Remove X”), body text (consequences), and button order (**Cancel** left, **Confirm** right in LTR). |
| M4 | **Focus trap + return focus** | Accessibility pass on modals opened from tables. |
| M5 | **Host Details wide modal** | Centered host detail surface per **[`docs/HOST_DETAILS_REDESIGN.md`](HOST_DETAILS_REDESIGN.md)**; aligns with M4 (trap, Escape, return focus); reuses existing `openHostPanel` data paths. |

---

## 5. Navigation

**Detailed proposal:** [`docs/NAV_REDESIGN.md`](NAV_REDESIGN.md) (header + Account menu + collapsible sidebar groups + scan redirect + a11y acceptance criteria). The table below stays a **short audit list**; full target layout and pass-by-pass plan live in that file.

### Plan items

| ID | Item | Notes |
|----|------|--------|
| N1 | **Top bar vs sidebar audit** | List every destination from both; mark duplicates; rule: **primary nav in sidebar**; top bar = global (search, user, theme) + **at most one** shortcut per major area if needed. |
| N2 | **Logical grouping** | **Assets** (inventory) · **Scopes** (catalog) · **Enrichment** (sources + Zabbix tools) · **Integrations** (push/pull + Zabbix credentials) · **Reports & Analysis** — confirm sidebar order matches mental model; add sub-labels if tabs are dense. |
| N3 | **Deep links** | Ensure hash/tab routes reflect sidebar selection (bookmarkable). |

---

## 6. Visual consistency

### Plan items

| ID | Item | Notes |
|----|------|--------|
| V1 | **Spacing scale** | Define `mb8` / `mb12` / `mb14` usage rules; remove one-off margins in Zabbix blocks. |
| V2 | **Table styles** | Shared classes for `.st-table-compact` (match review) vs default assets table — align header bg, row hover, border radius. |
| V3 | **Buttons** | **`btnp`** = primary; **`tbtn`** = secondary/neutral; destructive = distinct class (red outline or solid) + only in modals / confirmed rows. |
| V4 | **Cards** | Single `.card` shadow/border/radius from `app.css`; no inline overrides except responsive `min-width` where necessary. |

---

## Incremental delivery passes

Work is sequenced so each pass is **shippable**, **testable**, and **low regression risk**.

### UI Pass 1 — Assets filter parity (highest user impact)

- A1, A2, A3, F2 (Zabbix + Scope disclosure labels + active counts + clear semantics).
- Quick win: A7 shorten duplicate help (no behavior change).

**Exit criteria:** All three filter groups behave identically from a UX contract perspective; QA checklist for “clear + reload” and “disclosure keyboard.”

### UI Pass 2 — Enrichment / Zabbix density

- E1, E2, E3, E5 (card padding, collapse parity, section hierarchy, diagnostics behind disclosure).

**Exit criteria:** Visual diff screenshots before/after; no change to API calls from Enrichment tab.

### UI Pass 3 — Match review readability

- E4 only (table UX: sticky header, scroll, summary).

**Exit criteria:** Usable with 500+ rows without losing context; performance unchanged (client-only).

### UI Pass 4 — Modals and destructive flows

- M1–M4 (native dialog purge + checkbox confirm + copy + a11y).

**Exit criteria:** Zero native `confirm`/`alert`/`prompt` in `public/`; spot-check every modal path.

### UI Pass 5 — Navigation deduplication

- N1–N3, aligned with **[`docs/NAV_REDESIGN.md`](NAV_REDESIGN.md)** (Pass 1–2 minimum: header + Account menu + sidebar groups/collapse; Pass 4 for scan → Scan history).

**Exit criteria:** No duplicate entries to the same panel without intentional “shortcut” labeling; see **Acceptance criteria** in `NAV_REDESIGN.md` for the full nav initiative checklist when implementing that doc.

### UI Pass 6 — Visual tokens + tables

- V1–V4 + A6 (column clarity / legend).

**Exit criteria:** CSS variables or shared classes documented in a short comment at top of `app.css` “Design tokens” block.

### UI Pass 7 — Polish and documentation

- A5 bulk bar, A4 scope discoverability, F3 Reports filter family, README **Assets** / **Enrichment** short “Filtering model” pointer if desired.

**Exit criteria:** Operator-facing README or in-app “?” links updated **without** API changes.

---

## Out of scope (for this plan)

- Backend API changes, new endpoints, or migration changes.
- Removing Zabbix, AI, or scope features.
- **Automatic** scope assignment or new sync semantics.

---

## Success metrics (qualitative)

- New operators can predict **where filters live** and **what Clear does** without reading three paragraphs.
- **Enrichment → Zabbix** and **Integrations → Zabbix** feel like one story (configure vs operate) with **obvious handoff**.
- **Match review** is scannable under load.
- **No** unexplained list changes after navigation (no hidden filters).

---

## References in-repo

- Roadmap track: **UI cleanup and operator workflows** — [`README.md`](../README.md#roadmap) (links this file).
- **Navigation / header redesign (proposal):** [`docs/NAV_REDESIGN.md`](NAV_REDESIGN.md).
- **Host Details panel redesign (proposal):** [`docs/HOST_DETAILS_REDESIGN.md`](HOST_DETAILS_REDESIGN.md).
- Large surface: `public/index.php` (Assets ~L260+, Enrichment ~L1090+, Integrations Zabbix ~L1478+).
- Styles: `public/css/app.css`.
