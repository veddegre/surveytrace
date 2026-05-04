# Host Details panel redesign (proposal)

This document is a **design and implementation proposal** for the **Host Details** surface in SurveyTrace: today a **right-side panel** (`#host-panel`, `#hp-body`, `openHostPanel` / `closeHostPanel` in `public/index.php`). It is **documentation and planning only** — no implementation commitment.

**Status:** Not implemented. Unless a sentence explicitly says *current*, descriptions of layout and behavior refer to the **target** design after future work.

**Related code (audit anchors, today):** `public/index.php` — host panel markup (~L1986+), `openHostPanel` / panel body rendering (~L15543+); styles likely under `.host-panel` / `.host-panel-body` in `public/css/app.css`.

---

## 1. Problem statement

The Host Details view was originally suited to a **narrow right rail**. It has since accumulated substantial content, including:

- Identity and lifecycle  
- Scope (inventory / catalog context)  
- Zabbix enrichment (read-only / links)  
- Detected services  
- Open ports  
- AI host summary  
- CVEs / findings  
- Accepted risk  
- Port history  
- Scan change history  

**Symptoms:** long **vertical stacks**, **cramped** line length, competing blocks without a single reading order, and difficulty scanning at a normal laptop distance. The side-panel pattern **limits width** and encourages endless scroll in a fixed viewport edge.

**Goal:** A **clearer, larger** Host Details experience that preserves **all existing actions** and requires **no backend changes** for the first implementation passes (reuse current APIs and HTML generation paths; only **presentation** and **structure** change).

---

## 2. Preferred direction

### Primary (first passes)

**Evolve** the current panel into a **centered, wide modal** (not a full new route in v1):

- **Max-width** roughly **1100–1300px** (tunable with design tokens).  
- **Responsive height** with **internal scrolling** on the body (header/toolbar may stay visible).  
- **Visual focus** — backdrop dims the rest of the app; attention stays on the host.  
- **Lighter than a full page** — still a modal overlay; faster to ship than routing + new shell.

### Optional later

A **dedicated full-page host detail route** (e.g. `/host/:id` or hash-based `?host=id`) can be evaluated **after** the wide modal proves the information architecture. Not required for Pass 1–2.

---

## 3. Target layout

### 3.1 Modal chrome (header bar)

Sticky or visually pinned **header row** inside the modal (above scrollable content):

| Element | Notes |
|---------|--------|
| **Hostname** (primary) / **IP** (secondary, mono) | Title cluster; loading/error states unchanged semantically. |
| **Type** badge | Category / device type as today. |
| **Lifecycle** badge | Active / stale / retired (or equivalent). |
| **Scope** | Compact label + link or “Change scope” affordance if present today. |
| **Key actions** | **Rescan**, **Edit** (or equivalent), **CVEs** (jump to Vulnerabilities tab/section or scroll target) — **all actions preserved**; grouping in the header reduces hunting in the body. |
| **Close** | Dismiss control; **Escape** also closes (see Accessibility). |

### 3.2 Body: tabs or sections (phased)

**Target information architecture** (labels can match in-app copy):

| Tab / section | Contents |
|---------------|----------|
| **Overview** | Identity table; owner / business unit; criticality / environment; lifecycle / missed scans; MAC, vendor, OS, CPE strings. |
| **Enrichment** | Zabbix block(s); placeholders or patterns for **future enrichment** sources without new backend in pass 1. |
| **Ports & Services** | Detected services; open ports table; **raw banners** behind **collapsed** disclosure (progressive disclosure). |
| **Vulnerabilities** | Open CVEs; accepted risk; **severity filters** — *nice-to-have / Pass 3+* if low cost; otherwise unchanged list UX first. |
| **History** | Port history; scan change history (preserve ordering and actions). |
| **AI Summary** | AI host summary content; **regenerate** action where it exists today. |

**Phasing:**

- **Pass 1:** Single scrollable column with **clear section headings** (`flbl` / `sth` family) and more **whitespace** — **no tab UI yet**.  
- **Pass 2:** **Tabs** or **in-modal anchor nav** (sticky sub-nav) jumping to section ids — reduces “huge vertical stack” perception.

### 3.3 UX goals

- More readable at **normal laptop distance** (comfortable line length, spacing scale).  
- **Fewer** perceived vertical walls of text (tabs/anchors + collapsible raw data).  
- **Clear section headings** and consistent vertical rhythm (`mb*` / card boundaries).  
- **Sticky header** (hostname + badges + key actions) **if practical** without breaking mobile.  
- **Preserve all existing actions** (rescan, edit, scope change, CVE accept/risk, AI regenerate, etc.) — relocate, don’t remove.  
- **No backend changes required** for initial delivery — same payloads, same endpoints; client-only layout and DOM structure.

---

## 4. Accessibility (target)

When implemented, the centered modal should behave like a **dialog**:

| Requirement | Notes |
|-------------|--------|
| **Focus trap** | Tab cycles within modal while open; focus moves to first sensible control or title on open. |
| **Escape** | Closes modal (same as `closeHostPanel()` semantics). |
| **Return focus** | On close, restore focus to the **element that opened** the panel (IP cell, Details button, deep link caller). |
| **`role="dialog"`** | On the modal container; **`aria-modal="true"`** where appropriate. |
| **`aria-labelledby`** | Points at visible modal title (hostname/IP cluster). |
| **Scroll region** | Scrollable body has a name or label if needed for SR users (`aria-label` on scroll container). |

Aligns with broader modal work in [`UI_CLEANUP_PLAN.md`](UI_CLEANUP_PLAN.md) (e.g. M4 focus trap + return focus).

---

## 5. Implementation plan (passes)

| Pass | Scope | Exit notes |
|------|--------|------------|
| **Pass 1** | **Centered wide modal** — Reposition/resize existing `#host-panel` (or equivalent) to centered layout; **max-width** 1100–1300px; backdrop; **internal scroll**; **reuse current data/rendering** for `#hp-body` (move markup wrappers, not API). **Sections stacked** with improved spacing and headings; **no tabs** yet. |
| **Pass 2** | **Tabs or in-modal anchor navigation** — Wire six areas (Overview, Enrichment, Ports & Services, Vulnerabilities, History, AI Summary); keyboard support for tab list if using tabs; deep links can set **hash or query** to section later. |
| **Pass 3** | **Tables and disclosures** — CVE/ports table density, column priorities, **raw banner** collapse pattern shared with other “technical detail” surfaces; optional severity chips/filters for CVEs. |

Further passes (optional): mobile-specific layout, full-page route, URL sync for support handoff.

---

## 6. Risks and mitigations

| Risk | Mitigation |
|------|------------|
| **`openHostPanel` / `closeHostPanel` contract** | Many call sites (Assets, Vulns, Scan history, etc.). Keep **public function names** or thin wrappers; centralize open/close side effects (focus, scroll lock, `aria-hidden` on main). |
| **Mobile / narrow widths** | Below breakpoint, modal becomes **full viewport width** with safe padding; test portrait and small tablets. |
| **Deep links from Scan history** | Any `openHostPanel(assetId, ip)` from job rows must still work; after open, optionally **scroll to section** if Pass 2 adds anchors. |
| **Edit / Rescan inside modal** | May open nested modals or navigate; ensure **z-index stacking** and focus return order (child modal → host modal → opener). |
| **Performance** | Large HTML in `#hp-body` — avoid duplicate reflows; defer non-critical blocks if already partially lazy (preserve behavior). |
| **Device panel parity** | `#device-panel` uses similar `.host-panel` patterns; decide whether to **align visually** in a later pass without merging flows. |

---

## 7. Acceptance criteria (when implemented)

1. Host detail opens as a **centered wide modal** (or clearly documented evolution of the same component) with **max-width** in the 1100–1300px range on desktop.  
2. **All prior actions** remain available (none removed without explicit product decision).  
3. **No new backend endpoints** required for Pass 1–2 (client/layout only).  
4. **Escape** closes; **focus trap** and **return focus** to trigger element verified.  
5. **Readable** section structure: headings + spacing; Pass 2 adds **tabs or anchors** per this doc.  
6. **Regression:** Assets, Vulnerabilities, Scan history, and dashboard entry paths still open the same logical detail.

---

## 8. Out of scope (for this proposal)

- Backend schema or API changes.  
- Removing Zabbix, AI, CVE, or history features.  
- Implementing a **full-page route** in Pass 1 (optional future).  
- Claiming shipped behavior in **`VERSION`** or release notes until work lands.

---

## 9. Cross-links

- Broader UI cleanup and modal patterns: [`docs/UI_CLEANUP_PLAN.md`](UI_CLEANUP_PLAN.md) — **§4 Modals** (M1–M4), principles, and delivery passes.  
- Shell / nav changes (orthogonal): [`docs/NAV_REDESIGN.md`](NAV_REDESIGN.md).  

---

## 10. Files likely touched (when implementing)

| File | Typical changes |
|------|------------------|
| `public/index.php` | `#host-panel` / `#host-panel-bg` structure; `openHostPanel` / `closeHostPanel`; optional tab markup; section ids for anchors. |
| `public/css/app.css` | `.host-panel` layout (position, width, max-width, height), backdrop, internal scroll, responsive breakpoints; tab/anchor chrome. |

No changes to those files are part of **this** documentation-only step.
