# Navigation and header redesign (proposal)

This document is a **design and implementation proposal** for SurveyTrace’s **shell navigation**: top bar (`.bar`), sidebar (`.side`), and related flows (e.g. queueing a scan). It is **documentation only**.

**Status:** Not implemented. Nothing in this file should be read as describing current shipped behavior unless explicitly labeled *current*.

**Primary code surfaces (today):** `public/index.php` (markup for `.bar` / `.side`, `goTab`, `hiNav`, `startScan`, theme/profile helpers) and `public/css/app.css` (layout and button styles).

---

## 1. Current problems

### Header has too many equal-weight actions

The top bar stacks multiple **`tbtn`-style** controls (theme, new scan, access, settings, profile, sign out). Visually they compete at the same weight, so the bar feels **button-dense** and heavy.

### Header duplicates sidebar destinations

**Access control** and **Settings** appear in both the **header** and the **sidebar** (same logical destinations). That duplicates wayfinding and adds noise without adding distinct capability.

### Sidebar is crowded; grouping and collapse are needed

The sidebar lists many destinations under broad labels (**Monitor**, **Control**, **System**) but **all items stay visible** at once. As features grow, vertical scan and cognitive load increase. **Collapsible groups** with remembered open/closed state would reduce crowding while keeping every feature reachable.

### Scan queue should move the user to Scan history

After a successful **queue scan** action, operators typically want to **watch job progress**. Today the client may refresh queue data while leaving the user on **Scan control**; the **target** experience is to land on **Scan history** and, when possible, **highlight or focus** the newly queued (or running) job.

---

## 2. Target layout

### Header

| Zone | Content |
|------|---------|
| **Left** | **SurveyTrace** branding, version/meta, and **global status** (e.g. status pill / connection state). |
| **Right** | **Primary action:** **+ New scan** — visually distinct from secondary chrome (e.g. primary button styling, not the same as neutral toolbar buttons). |
| **Right** | **Account** menu — compact control (e.g. “Account ▾”); opens a menu; **not** a full row of equal-weight `tbtn`s. |

**Remove from the header bar** (relocate, do not delete features):

- Standalone **Theme** control  
- Standalone **Access control**  
- Standalone **Settings**  
- Standalone **My profile** / profile entry as its own top-level button  
- Standalone **Sign out** as its own top-level button  

### Account menu

Anchored popover or panel from the **Account** control. Suggested entries:

| Item | Role |
|------|------|
| **Profile** or **Account** | Opens the existing profile / self-service surface (today: profile modal); naming should align across menu label and modal title. |
| **Theme** | Explicit choices (e.g. **Dark / Light / Auto**) instead of a single ambiguous toggle, preserving current storage / override semantics under the hood. |
| **Settings** | Navigates to the Settings tab. |
| **Access control** | Navigates to the Access control tab; **admin-gated** (hide, disable, or explain — consistent with today’s role checks). |
| **Sign out** | Invokes existing sign-out flow; placed last as a destructive / session-ending action. |

### Sidebar groups and items

**Rules (target):**

- **No duplicate** sidebar rows for the same destination.  
- **Collapsible** groups with **persisted** open/closed state (e.g. `localStorage`).  
- **Active route** expands the **parent group** automatically so the current item is never hidden inside a collapsed section.  
- **Counts / badges** remain on the same items as today (e.g. assets, vulnerabilities, change alerts), attached to the row label.

**Group: Monitor**

- Dashboard  
- Assets  
- Devices  
- Vulnerabilities  

**Group: Operations**

- Scan control  
- Scan history  
- Reports & Analysis  
- Schedules  
- Collectors  

**Group: Organization**

- Scopes  
- Enrichment  
- Integrations  

**Group: Administration**

- Access control  
- Settings  
- System health  
- Audit log  

**Group: Activity**

- Change alerts  

---

## 3. Implementation passes

Work is ordered for **incremental delivery**: each pass should be shippable, testable, and low regression risk. Pass numbers here are **specific to this nav redesign**; they may align with or overlap **UI cleanup plan** passes in [`UI_CLEANUP_PLAN.md`](UI_CLEANUP_PLAN.md) (see cross-links below).

| Pass | Focus |
|------|--------|
| **Pass 1** | **Header slim-down + Account menu** — Implement reduced header; add Account menu with Profile/Account, Theme, Settings, Access control, Sign out; remove duplicated header entries for those destinations. |
| **Pass 2** | **Sidebar grouping and collapse** — Introduce group containers, collapse toggles, persistence, and `hiNav` / active-state compatibility with nested DOM. |
| **Pass 3** | **Visual hierarchy and density** — Smaller sidebar rows, clear primary vs secondary styling in the bar, CSS tokens for nav chrome. |
| **Pass 4** | **Scan redirect** — On successful scan queue (and analogous queue paths where appropriate), navigate to **Scan history**; scroll/highlight/open details for returned **job id** when the table supports it. |
| **Pass 5** | **Accessibility polish** — Account menu keyboard support (`aria-expanded` / `aria-controls`, Escape, focus trap); sidebar group buttons with `aria-expanded`; visible focus and active-route semantics. |
| **Pass 6** | **Cleanup and documentation** — Cross-links, operator-facing notes, any remaining duplicate copy or deep-link cleanup. |

---

## 4. Risks and mitigations

| Risk | Mitigation |
|------|------------|
| **`hiNav` assumes a flat `.ni` list** | After nesting, keep **stable ids** on clickable rows or update `hiNav` to resolve the active node under grouped markup (e.g. query by id + class). |
| **Active item inside a collapsed group** | On tab change and on load, **force-expand** the group containing the active item; optionally scroll the active row into view in the sidebar. |
| **Role-gated admin items** | **Access control** / parts of **Settings** may be admin-only — mirror current behavior: hide menu entries, disable with tooltip, or keep navigation but preserve server-side enforcement and existing toasts. |
| **Keyboard / focus for Account menu** | Treat as a small component: focus trap while open, Escape closes, return focus to launcher; document QA steps (Tab, Shift+Tab, Escape). |
| **Scan redirect expectations** | Some users may want to stay on **Scan control** to queue another job; mitigate with clear feedback (toast + link back) or only redirect from explicit “Queue” success paths. |
| **Batch jobs** | API may return multiple queued jobs; **highlight** the primary `job_id` returned, keep existing batch toasts, and ensure `loadScanHistory` / polling still behave correctly after navigation. |

---

## 5. Acceptance criteria

The following define **done** for the nav redesign initiative (when implemented):

1. **No duplicate primary nav destinations** — Each logical tab/destination has a **single** canonical entry in the primary nav structure (sidebar + agreed header shortcuts).  
2. **Header composition** — Header contains **global status / branding**, **one primary scan action** (**+ New scan**), and the **Account** menu only (no standalone Theme, Settings, Access control, Profile, or Sign out buttons in the bar).  
3. **Sidebar groups** — Groups **collapse and expand**; **open/closed state persists** across reloads (per browser).  
4. **Active item and groups** — The **active** route is clearly marked; its **parent group is expanded** so the active item is visible.  
5. **New scan success** — Successful queue from the primary scan flow **navigates to Scan history** and **surfaces** the new job when job id (or equivalent) is available (scroll/highlight/detail — as implemented in Pass 4).  
6. **Account menu accessibility** — Menu is **keyboard accessible** (open/close, roving focus optional, Escape, visible focus).  

---

## 6. Cross-links

- **UI cleanup plan** (broader UI passes, including navigation audit item N1–N3): [`docs/UI_CLEANUP_PLAN.md`](UI_CLEANUP_PLAN.md) — see **§5 Navigation** and **UI Pass 5 — Navigation deduplication**.  
- **Roadmap** (planning track): [`README.md`](../README.md#roadmap) — **UI cleanup and operator workflows** track.  

When this redesign is implemented, update **UI Pass 5** / roadmap bullets to point at closed PRs or release notes as appropriate.

---

## 7. Out of scope (for this proposal)

- Removing features or tabs.  
- Backend API changes **except** optional future work if a scan-start redirect were ever done server-side (the **target** described here is achievable **client-side** after queue success).  
- Changing **`VERSION`** or claiming a release contains this work until it actually ships.
