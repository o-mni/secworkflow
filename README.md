# ⬡ SecWorkflow

A professional, browser-based checklist and reporting tool for penetration testers and security consultants. Runs entirely client-side — no backend, no accounts, no data leaves your machine.

---

## Features

- **Pentest modules** — Active Directory, Web, API, Network, Cloud, Wireless, Physical
- **Consultant modules** — NIS2, NIST CSF 2.0, DORA, ISO 27001
- **Item detail panel** — per-item status, severity override, notes, evidence, remediation
- **Findings workflow** — promote items to findings, filter by finding flag
- **Filter bar** — filter by status, severity, tag, keyword, or findings-only with live count
- **PDF export** — opens a formatted, print-ready report in a new tab (Print → Save as PDF)
- **Three report types** — Pentest, Compliance, Executive Summary
- **Import / Export** — JSON round-trip to save and resume sessions; per-module Markdown export
- **Project metadata** — project name, client, assessor, dates, classification, scope
- **Storage Mode toggle** — Session Mode (in-memory, default) or Local Mode (persisted to `localStorage`) with explicit confirmation flows
- **Fully offline** — zero external requests in both storage modes

---

## Quick Start

No build step required. Open `index.html` directly in any modern browser, or serve the folder with any static file server:

```bash
# Python
python -m http.server 8080

# Node (npx)
npx serve .
```

Then open `http://localhost:8080`.

---

## Usage

### Workflow

1. Click the **pencil icon** on the project card (top of sidebar) to fill in project metadata — client name, assessor, dates, classification, scope.
2. Select a **module** from the sidebar (Pentest or Consultant tab).
3. Work through checklist items. Click a row to open the **detail panel** and record notes, evidence, and remediation.
4. Mark items as **Vulnerable / Gap** to promote them to findings.
5. Use **Filters** (top bar) to slice the list by status, severity, tag, or keyword.
6. When done, click **Export Report** to configure and export a PDF.

### Keyboard / UI shortcuts

| Action | How |
|---|---|
| Open item detail | Click any checklist row |
| Quick status change | Use the inline dropdown on the row |
| Toggle filter bar | Click **Filters** in the top bar |
| Clear all filters | Click **Clear** inside the filter bar |
| Collapse a group | Click the group header |

### Import / Export (Data menu)

| Option | Description |
|---|---|
| **Import JSON** | Load a previously exported session file |
| **Export JSON** | Save the full session (all modules, all notes) to a JSON file |
| **Export Module MD** | Export the currently open module as Markdown |

### Storage Mode

The **Session / Local** toggle in the top bar controls where your data lives.

| Mode | Storage | Persists on refresh | Persists on restart |
|---|---|---|---|
| **Session** (default) | In-memory only | No | No |
| **Local** | Browser `localStorage` | Yes | Yes |

**Session Mode** is the default. Data is held in memory for the current tab only. Closing or refreshing the tab clears everything. Use this on shared or untrusted devices, or for any engagement where you do not want data left on disk.

**Local Mode** saves all progress to `localStorage` automatically. Data survives refreshes, browser restarts, and OS reboots. Switching to Local Mode requires explicit confirmation and displays a warning about browser sync and prohibited data types.

#### Switching modes

| Action | Trigger |
|---|---|
| Session → Local | Click **Local** in the top bar; confirm in the modal |
| Local → Session | Click **Session**; choose to keep or delete stored local data |
| Delete local data | **Data → Clear local data** (visible in Local Mode only); confirm in the modal |

When Local Mode is active the top bar shows an **amber accent** and the status label reads **Saved on this device**. Session Mode shows **Not saved** in a neutral colour.

---

### PDF Report

Click **Export Report** → choose report type, which modules to include, which statuses to include → **Export PDF**.

A formatted HTML document opens in a new tab. Use your browser's **Print → Save as PDF** (or `Ctrl+P` / `Cmd+P`).

Report types:

| Type | Contents |
|---|---|
| **Pentest** | Cover page, executive summary, risk summary, findings (with evidence/remediation), observations, recommendations table, appendix |
| **Compliance** | Cover page, compliance overview table, gap findings, recommendations, full gap matrix |
| **Executive** | Cover page, domain summary, critical actions, next steps |

---

## Security

SecWorkflow handles confidential professional data. The following measures are layered across the application, transport, and browser levels to minimise risk.

---

### Confidentiality model

| Claim | Accurate? | Notes |
|---|---|---|
| No data transmitted to any server | Yes | `connect-src 'none'` enforced by CSP |
| No analytics or telemetry | Yes | Zero third-party scripts or requests |
| Data stored only on this device | Qualified | True in Session Mode; in Local Mode, browser sync may upload `localStorage` — see Storage Mode section |
| Data is encrypted at rest | No | `localStorage` is plaintext; use Session Mode or export a JSON backup for sensitive sessions |

**Prohibited data types.** Do not record passwords, private keys, API tokens, session cookies, or any cryptographic secret in this tool. It is designed for workflow notes, checklist progress, gap findings, and report drafts — not a secrets vault.

---

### Zero-transmission architecture

All data lives in your browser. There are no accounts, no backend, and no external network requests of any kind:

- No CDN scripts, fonts, or stylesheets
- No analytics or error-reporting integrations
- No service workers
- `connect-src 'none'` in the Content Security Policy prevents any XHR, fetch, or WebSocket from reaching any host — including injected malicious code

---

### Storage Mode

The **Session / Local** toggle in the top bar is the primary privacy control:

- **Session Mode (default)** — `_saveToStorage()` is a no-op; `_loadFromStorage()` never reads from disk; in-memory state starts empty on every load. No data is written anywhere.
- **Local Mode** — `_saveToStorage()` writes to `localStorage` on every state change; `_loadFromStorage()` reads on startup. Mode preference is stored under `secworkflow_storage_mode`.

Switching Session → Local requires an explicit confirmation modal that warns about browser sync and prohibited data types. Switching Local → Session offers the choice to delete or preserve existing stored data. Deleting local data from within the app (Data → Clear local data) removes the `secworkflow_v1` key and resets all in-memory state to defaults without requiring browser developer tools.

---

### XSS prevention

All user-controlled content is HTML-escaped before it touches the DOM:

- **`escHTML()`** — applied to every user string before `innerHTML` insertion in the main application (`app.js`)
- **`_esc()`** — applied to every user field interpolated into generated report HTML (`report.js`), including notes, evidence, remediation, metadata, item titles, tags, and framework references
- All status and severity values are validated against **allowlists** before use
- `textContent` is used wherever HTML rendering is not required

---

### Import validation

Imported JSON files are validated and sanitised field-by-field before merging into application state:

- Files over **5 MB** are rejected before parsing
- The top-level structure is validated; unexpected keys are ignored
- Status values are checked against `VALID_STATUSES`; invalid values default to `not-started`
- Severity values are checked against `VALID_SEVERITIES`; invalid values are set to `null`
- Classification is validated against a fixed allowlist; defaults to `CONFIDENTIAL`
- Date fields are validated against `YYYY-MM-DD` format
- String fields are type-checked and length-capped:
  - Notes: 20 KB
  - Evidence: 100 KB
  - All other strings: 200–5,000 characters depending on field
- Item state keys are length-capped at 200 characters

---

### Export safety

- **JSON export** — exported filenames are sanitised (only `[a-zA-Z0-9_\-. ]` allowed) before use in the `download` attribute, preventing path traversal
- **PDF report** — generated entirely in-browser via `window.open()` + `document.write()`; no content is sent to any server
- **Report HTML** — includes `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, and a Content Security Policy that blocks all external connections in the report tab
- A **confidentiality reminder** is shown in the Export Report modal before every PDF generation

---

### HTTP security headers

Deployed via `_headers` (Cloudflare Pages) or equivalent server configuration:

| Header | Value | Purpose |
|---|---|---|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` | Enforce HTTPS for 2 years |
| `X-Frame-Options` | `DENY` | Prevent clickjacking via framing |
| `X-Content-Type-Options` | `nosniff` | Prevent MIME-type sniffing |
| `X-XSS-Protection` | `1; mode=block` | Legacy browser XSS filter |
| `Referrer-Policy` | `no-referrer` | Strip referrer on all navigation |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()` | Deny sensitive browser APIs |
| `Content-Security-Policy` | See below | Restrict resource loading |
| `Cross-Origin-Opener-Policy` | `same-origin` | Prevent cross-origin window access |
| `Cross-Origin-Resource-Policy` | `same-origin` | Prevent cross-origin resource reads |
| `Cache-Control` | `no-store, no-cache, must-revalidate` | Prevent caching of sensitive data |

**Content Security Policy breakdown:**

```
default-src 'self'                 — resources from same origin only
script-src 'self' 'unsafe-inline'  — local scripts (inline required; no build step)
style-src 'self' 'unsafe-inline'   — local styles
img-src 'self' data: blob:         — local images and generated blobs
font-src 'self'                    — local fonts only
connect-src 'none'                 — block all XHR / fetch / WebSocket to any host
object-src 'none'                  — no plugins
base-uri 'self'                    — prevent base-tag hijacking
form-action 'none'                 — no form submissions off-origin
frame-ancestors 'none'             — no embedding in frames (supersedes X-Frame-Options)
```

> **Note on `unsafe-inline`:** This weakens CSP's XSS protection because the application uses inline scripts and styles. All other mitigations (escaping, import validation, zero external loading) compensate for this. If a build step is ever introduced, switch to nonce-based CSP to eliminate `unsafe-inline`.

### Meta-tag fallback policies

For environments where HTTP headers cannot be set, the following `<meta>` equivalents are embedded in `index.html`:

- `Content-Security-Policy` — supported in most browsers
- `Referrer-Policy: no-referrer`
- `Permissions-Policy`

---

### Threat summary

| Threat | Mitigation | Residual risk |
|---|---|---|
| Stored XSS via notes | `escHTML()` / `_esc()` on all user content | Low |
| DOM XSS via malicious import | Field-by-field sanitisation + allowlists | Low |
| Report XSS | `_esc()` applied to every interpolated field in `report.js` | Low |
| Data exfiltration via injected script | `connect-src 'none'` blocks all outbound requests | Very low |
| Clickjacking | `frame-ancestors 'none'` + `X-Frame-Options: DENY` | Very low |
| Supply chain (CDN compromise) | Zero external dependencies | Very low |
| Browser sync uploading localStorage | Session Mode is the default; Local Mode requires explicit opt-in | Medium (user behaviour) |
| Browser extension access | Out of scope for web apps | High (trust boundary) |
| Physical access / screen sharing | Out of scope | High (user behaviour) |

---

### Deployment notes

If you self-host on a platform other than Cloudflare Pages, configure the headers above in your server.

**Nginx:**
```nginx
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "no-referrer" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'self'; form-action 'none'; frame-ancestors 'none';" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
add_header Cache-Control "no-store, no-cache, must-revalidate" always;
```

**Apache (`.htaccess`):**
```apache
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"
Header always set X-Frame-Options "DENY"
Header always set X-Content-Type-Options "nosniff"
Header always set Referrer-Policy "no-referrer"
Header always set Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'self'; form-action 'none'; frame-ancestors 'none';"
Header always set Cross-Origin-Opener-Policy "same-origin"
Header always set Cross-Origin-Resource-Policy "same-origin"
Header always set Cache-Control "no-store, no-cache, must-revalidate"
```

---

### Residual risks

Even after full hardening, the following risks remain:

- **Browser extensions** with broad permissions can read `localStorage` — use a browser profile without untrusted extensions
- **Browser sync** (Chrome Sync, Firefox Sync) may upload `localStorage` to a cloud account — stay in Session Mode or disable browser sync to avoid this
- **Screen sharing or shoulder surfing** — no code-level mitigation possible
- **Physical access to an unlocked machine** — use Session Mode or clear local data before leaving the device
- **Cloud print services** — when printing a PDF report, disable cloud print or print to a local printer only

---

## Data & Privacy

- **Session Mode (default):** no data is written to disk. Closing or refreshing the tab clears all state.
- **Local Mode:** data is written to `localStorage` under the key `secworkflow_v1` and persists until manually deleted.
- No data is sent to any server at any time, in either mode.
- To delete local data from within the app: **Data → Clear local data** (visible in Local Mode).
- To delete local data via the browser: clear site data in your browser settings, or remove `secworkflow_v1` from `localStorage` in developer tools.
- Export a JSON backup before clearing if you want to preserve your session.
- A privacy notice is shown on first load explaining storage modes and prohibited data types.

---

## Project Structure

```
secworkflow/
├── index.html          # Application shell and all modals
├── _headers            # HTTP security headers (Cloudflare Pages)
├── css/
│   └── style.css       # All UI styles
└── js/
    ├── data.js         # All checklist content (modules, groups, items)
    ├── report.js       # PDF report generator (HTML output)
    └── app.js          # Application logic, state, filters, import/export
```

---

## License

See [LICENSE](LICENSE).
