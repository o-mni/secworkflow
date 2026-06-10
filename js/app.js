'use strict';

/* ════════════════════════════════════════════════════
   CLOCK & SHIFT TIMER
════════════════════════════════════════════════════ */
const shiftStart = Date.now();

function updateClock() {
  const now = new Date();
  const pad = n => String(n).padStart(2, '0');
  document.getElementById('clock-time').textContent =
    `${pad(now.getUTCHours())}:${pad(now.getUTCMinutes())}:${pad(now.getUTCSeconds())}`;

  const elapsed = Math.floor((Date.now() - shiftStart) / 1000);
  const h = Math.floor(elapsed / 3600);
  const m = Math.floor((elapsed % 3600) / 60);
  const s = elapsed % 60;
  document.getElementById('shift-timer').textContent =
    h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${m}:${pad(s)}`;
}
setInterval(updateClock, 1000);
updateClock();

/* ════════════════════════════════════════════════════
   TAB NAVIGATION
════════════════════════════════════════════════════ */
function switchTab(panelName) {
  document.querySelectorAll('.tab-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.panel === panelName);
    b.setAttribute('aria-selected', b.dataset.panel === panelName);
  });
  document.querySelectorAll('.panel').forEach(p => {
    p.classList.toggle('active', p.id === `panel-${panelName}`);
  });
}

document.getElementById('tab-nav').addEventListener('click', e => {
  const btn = e.target.closest('.tab-btn');
  if (btn) switchTab(btn.dataset.panel);
});

/* ════════════════════════════════════════════════════
   ALERT TEMPLATES
════════════════════════════════════════════════════ */
const ALERTS = [
  {
    type: 'Suspicious Login Detected',
    icon: '🔐',
    sev: 'HIGH',
    variants: [
      {
        desc: '47 failed SSH login attempts from 185.220.101.x within 3 minutes, followed by successful authentication as service account "svc-backup".',
        interp: 'Brute-force succeeded. Service accounts shouldn\'t be accessible via SSH — this is likely a compromised credential used by an attacker.',
        actions: [
          'Lock "svc-backup" immediately and revoke all active sessions',
          'Check auth logs for lateral movement from this IP in the past 6 hours',
          'Open IR Playbook: Suspicious Login — initiate full investigation'
        ]
      },
      {
        desc: 'Admin account "jdoe-admin" successfully logged in from 37.48.x.x (RU geolocation) at 03:14 UTC. User is US-based. MFA was not triggered.',
        interp: 'Geo anomaly + no MFA = likely account takeover. The attacker may have stolen credentials and bypassed or downgraded MFA.',
        actions: [
          'Force global sign-out on all sessions and lock the account',
          'Audit for email forwarding rules, OAuth app grants, and added delegates',
          'Contact user via phone (not email) to confirm — then reset credentials + re-enroll MFA'
        ]
      }
    ]
  },
  {
    type: 'Malware Detected on Endpoint',
    icon: '🦠',
    sev: 'CRITICAL',
    variants: [
      {
        desc: 'EDR flagged ransomware behavior on WORKSTATION-042: mass file encryption starting in Documents, shadow copy deletion via vssadmin, ransom note created in 14 directories.',
        interp: 'Active ransomware execution — containment is the only priority right now. Do not reboot. Every second increases the blast radius.',
        actions: [
          'ISOLATE WORKSTATION-042 immediately — network quarantine via EDR or physical cable disconnect',
          'Preserve RAM dump before any further action to capture encryption keys',
          'Verify backups are intact and isolated before declaring an incident scope'
        ]
      },
      {
        desc: 'Cobalt Strike beacon deployed via macro-enabled Word document on SRV-APP01. Process chain: WINWORD.EXE → powershell.exe → rundll32.exe (outbound C2 on port 443 to 194.165.x.x).',
        interp: 'Active C2 implant with interactive access. The attacker is likely already conducting post-exploitation recon. Credential exposure is near-certain.',
        actions: [
          'Network-quarantine SRV-APP01 via EDR — do NOT just reboot',
          'Block 194.165.x.x and its ASN at the firewall perimeter right now',
          'Search all endpoints in the same subnet for the same process chain and beacon hash'
        ]
      }
    ]
  },
  {
    type: 'Phishing Email Reported',
    icon: '🎣',
    sev: 'HIGH',
    variants: [
      {
        desc: '3 users forwarded identical emails impersonating IT Help Desk with a link to "it-helpdesk-corp[.]com" (domain registered 2 days ago). Subject: "URGENT: Your password expires today."',
        interp: 'Targeted credential harvesting. Lookalike domain freshly registered points to a planned attack. Urgency language designed to bypass critical thinking.',
        actions: [
          'Pull and remove the email from all inboxes via admin console now',
          'Block it-helpdesk-corp[.]com at DNS and proxy — check for similar lookalike variants',
          'Identify if anyone clicked — if yes, treat as account compromise and initiate playbook'
        ]
      },
      {
        desc: 'Email impersonating CFO requests urgent $48,000 wire transfer to new vendor. Sender domain registered yesterday. DMARC: FAIL. No reply threading with previous emails.',
        interp: 'Business Email Compromise (BEC) targeting Finance. Urgency + authority impersonation are hallmarks. Financial impact could be immediate.',
        actions: [
          'Alert Finance team immediately — do NOT process the transfer',
          'Call the CFO directly on a known number to verify — never reply to the email',
          'Block sender domain and file abuse report with the email provider'
        ]
      }
    ]
  },
  {
    type: 'Abnormal Outbound Traffic',
    icon: '📡',
    sev: 'CRITICAL',
    variants: [
      {
        desc: 'Periodic HTTPS connections from HOST-WIN-019 to 194.165.x.x every 60 seconds (±3s). Traffic volume: 2–4KB per request. IP matches documented Cobalt Strike C2 infrastructure.',
        interp: 'Classic beacon pattern — consistent interval, small payload. HOST-WIN-019 has an active implant. The attacker has a shell and may be conducting post-exploitation.',
        actions: [
          'Block 194.165.x.x and its entire ASN at the perimeter firewall',
          'Isolate HOST-WIN-019 — preserve memory dump before touching anything',
          'Pivot: search proxy/firewall logs for other hosts that contacted this IP in the past 7 days'
        ]
      },
      {
        desc: 'DNS NXDOMAIN storm from 10.0.14.55: 3,200 failed lookups in 10 minutes to algorithmically generated domains (.com, .net, .org). Matches DGA malware signature pattern.',
        interp: 'Host infected with DGA malware trying to reach C2. No connection has succeeded yet — this is a critical containment window before the implant activates.',
        actions: [
          'Isolate 10.0.14.55 before any C2 connection can be established',
          'Sinkhole DGA domain pattern at internal DNS resolver to monitor without allowing resolution',
          'Full EDR scan and memory forensics on the isolated host'
        ]
      }
    ]
  },
  {
    type: 'Data Exfiltration Suspected',
    icon: '📤',
    sev: 'CRITICAL',
    variants: [
      {
        desc: '4.2GB uploaded to mega.nz from FINANCE-PC-07 between 23:00 and 01:30. DLP alert triggered. User has a scheduled departure in 5 days. HR was notified 2 weeks ago.',
        interp: 'High-confidence insider threat pattern: large after-hours upload, sensitive financial system access, known upcoming departure. Deliberate staging likely.',
        actions: [
          'Preserve forensic image of FINANCE-PC-07 immediately — do NOT alert the user yet',
          'Block mega.nz and personal cloud storage at the proxy — document the restriction',
          'Escalate to HR and legal before any further action — evidence chain is critical here'
        ]
      },
      {
        desc: 'Archive files (.7z, .rar) created in C:\\Temp from \\\\FILESERVER\\Confidential over 2 hours, then synced to personal OneDrive. 8.7GB across 1,240 files.',
        interp: 'Deliberate staging and exfiltration pattern. Selection of the Confidential share shows intentional targeting, not accidental transfer.',
        actions: [
          'Revoke OneDrive sync and disable cloud storage access for this user',
          'Pull exact audit trail of which files were staged and exported',
          'Escalate to legal — scope may trigger breach notification obligations'
        ]
      }
    ]
  },
  {
    type: 'Lateral Movement Detected',
    icon: '↔',
    sev: 'CRITICAL',
    variants: [
      {
        desc: 'WORKSTATION-011 accessed ADMIN$ shares on 12 other workstations within 4 minutes using domain admin "DA-svc". No scheduled admin activity was logged. Source: Sysmon 5145.',
        interp: 'Active lateral movement using a compromised domain admin account. The attacker is using PsExec-style tooling and is spreading rapidly. Blast radius is growing.',
        actions: [
          'Segment network now — block SMB (445) and RDP (3389) between all workstations at switch level',
          'Disable "DA-svc" and reset KRBTGT password twice to invalidate all Kerberos tickets',
          'Treat all 12 target systems as compromised — isolate and investigate each'
        ]
      }
    ]
  },
  {
    type: 'Credential Dumping Detected',
    icon: '🔓',
    sev: 'HIGH',
    variants: [
      {
        desc: 'Sysmon Event 10: lsass.exe accessed by C:\\Users\\Public\\svhost32.exe (not svchost.exe). File hash matches known Mimikatz variant. Occurred 3 minutes ago on DESKTOP-HR-04.',
        interp: 'Active LSASS credential dumping in progress. All domain credentials cached on DESKTOP-HR-04 must be treated as stolen and in attacker hands.',
        actions: [
          'Isolate DESKTOP-HR-04 immediately — all cached credentials are now compromised',
          'Scan all endpoints for svhost32.exe by hash — this is likely not isolated',
          'Begin enterprise-wide privileged credential rotation — start with domain admins and service accounts'
        ]
      }
    ]
  },
  {
    type: 'Web Application Attack',
    icon: '🌐',
    sev: 'MEDIUM',
    variants: [
      {
        desc: 'WAF blocked 340 SQLi probes against /api/search from 45.155.x.x in 2 minutes. Payloads include UNION-based and time-based blind SQLi. All requests blocked.',
        interp: 'Automated SQLi scanner probing the API. WAF is holding for now, but check for bypass attempts and pre-WAF requests that may have succeeded.',
        actions: [
          'Block 45.155.x.x and its ASN at the network perimeter',
          'Review WAF logs for any requests that preceded or bypassed the current rule set',
          'Verify /api/search uses parameterized queries — flag for code review if not confirmed'
        ]
      },
      {
        desc: 'Stored XSS found in user profile "Bio" field: payload exfiltrates document.cookie to external endpoint. Triggered on admin report page load. Two admins viewed the report today.',
        interp: 'Active stored XSS targeting admin sessions. The two admins who viewed the report today may have had their session cookies exfiltrated to the attacker.',
        actions: [
          'Remove the malicious profile and sanitize the bio field server-side immediately',
          'Rotate session tokens for both affected admins right now',
          'Check proxy logs for outbound requests from admin IPs to the exfil endpoint'
        ]
      }
    ]
  },
  {
    type: 'Privileged Account Activity',
    icon: '👑',
    sev: 'MEDIUM',
    variants: [
      {
        desc: 'Domain admin account "Administrator" used interactively on WORKSTATION-023 at 14:32 UTC. Policy prohibits DA accounts from logging into workstations. No change window was open.',
        interp: 'Violation of least-privilege policy — could indicate an attacker using a stolen DA credential, or a sysadmin violating policy. Either scenario needs investigation.',
        actions: [
          'Confirm with the team if a legitimate admin was working on WORKSTATION-023 at that time',
          'If unconfirmed — lock the session, treat as potential compromise, check what was run',
          'Review recent actions of the Administrator account in the past 2 hours'
        ]
      }
    ]
  }
];

/* ════════════════════════════════════════════════════
   ALERT STATE
════════════════════════════════════════════════════ */
let activeAlerts = [];   // { id, sev, createdAt, acked }
let currentSevFilter = 'ALL';
let searchQuery = '';
let lastAlertTime = null;
let relTimeInterval = null;

function rand(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function fmtUtc(d) {
  const p = n => String(n).padStart(2,'0');
  return `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} UTC`;
}

function relTime(ts) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 10)  return 'just now';
  if (s < 60)  return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s/60)}m ago`;
  return `${Math.floor(s/3600)}h ago`;
}

function generateAlert(forceSev) {
  const template = rand(ALERTS);
  const variant  = rand(template.variants);
  const sev      = forceSev || template.sev;
  const now      = new Date();
  const id       = `a-${Date.now()}-${Math.random().toString(36).slice(2,6)}`;

  const card = document.createElement('div');
  card.className = `alert-card sev-${sev}`;
  card.id = id;
  card.dataset.sev = sev;

  card.innerHTML = `
    <div class="alert-inner">
      <div class="alert-top">
        <span class="alert-icon">${template.icon}</span>
        <div class="alert-top-mid">
          <div class="alert-type">${escHtml(template.type)}</div>
          <div class="alert-meta">
            <span class="sev-badge ${sev}">${sev}</span>
            <span class="alert-ts">${fmtUtc(now)}</span>
            <span class="alert-rel" data-ts="${now.getTime()}">just now</span>
          </div>
        </div>
        <div class="alert-btns">
          <button class="btn-ack" data-id="${id}" title="Acknowledge — keeps alert in queue but marks it reviewed">ACK</button>
          <button class="btn-dismiss" data-id="${id}" title="Dismiss alert">✕</button>
        </div>
      </div>
      <div class="alert-desc">${escHtml(variant.desc)}</div>
      <div class="alert-section-label">Assessment</div>
      <div class="alert-interp">${escHtml(variant.interp)}</div>
      <div class="alert-section-label">Immediate Actions</div>
      <ul class="alert-actions-list">
        ${variant.actions.map((a,i) => `
          <li>
            <span class="action-num">${i+1}</span>
            <span>${escHtml(a)}</span>
          </li>`).join('')}
      </ul>
    </div>`;

  activeAlerts.push({ id, sev, createdAt: now.getTime(), acked: false });
  lastAlertTime = now;

  const queue = document.getElementById('alert-queue');
  document.getElementById('empty-state').style.display = 'none';
  queue.insertBefore(card, queue.firstChild);

  applyFilters();
  updateBadge();
  updateSeverityCounts();
  updateStatusBar();
  updateLastAlert();

  startRelTimeUpdates();
}

function simulateIncident() {
  const delays = [0, 350, 700, 1100];
  const sevs = ['CRITICAL', 'CRITICAL', 'HIGH', 'HIGH'];
  delays.forEach((d, i) => setTimeout(() => generateAlert(sevs[i]), d));
}

/* ── ACK ─────────────────────────────────────────────────────────── */
function ackAlert(id) {
  const card = document.getElementById(id);
  if (!card) return;
  const entry = activeAlerts.find(a => a.id === id);
  if (!entry) return;

  if (entry.acked) {
    card.classList.remove('is-acked');
    entry.acked = false;
  } else {
    card.classList.add('is-acked');
    entry.acked = true;
  }
  updateBadge();
  updateStatusBar();
}

/* ── DISMISS ─────────────────────────────────────────────────────── */
function dismissAlert(id) {
  const card = document.getElementById(id);
  if (!card) return;
  card.classList.add('is-dismissed');
  activeAlerts = activeAlerts.filter(a => a.id !== id);
  setTimeout(() => { card.remove(); checkEmpty(); }, 300);
  updateBadge();
  updateSeverityCounts();
  updateStatusBar();
}

function clearAlerts() {
  document.querySelectorAll('.alert-card').forEach(c => c.remove());
  activeAlerts = [];
  updateBadge();
  updateSeverityCounts();
  updateStatusBar();
  checkEmpty();
}

function checkEmpty() {
  const has = document.querySelectorAll('.alert-card').length > 0;
  document.getElementById('empty-state').style.display = has ? 'none' : 'flex';
}

/* ── FILTERS ─────────────────────────────────────────────────────── */
function applyFilters() {
  const q = searchQuery.toLowerCase();
  document.querySelectorAll('.alert-card').forEach(card => {
    const sevMatch = currentSevFilter === 'ALL' || card.dataset.sev === currentSevFilter;
    const textMatch = !q || card.innerText.toLowerCase().includes(q);
    card.dataset.hidden = String(!(sevMatch && textMatch));
    card.style.display = (sevMatch && textMatch) ? '' : 'none';
  });
}

document.getElementById('sev-filters').addEventListener('click', e => {
  const btn = e.target.closest('.sev-filter');
  if (!btn) return;
  document.querySelectorAll('.sev-filter').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  currentSevFilter = btn.dataset.sev;
  applyFilters();
});

document.getElementById('triage-search').addEventListener('input', e => {
  searchQuery = e.target.value.trim();
  applyFilters();
});

/* ── ALERT QUEUE DELEGATION ─────────────────────────────────────── */
document.getElementById('alert-queue').addEventListener('click', e => {
  const ackBtn  = e.target.closest('.btn-ack');
  const disBtn  = e.target.closest('.btn-dismiss');
  if (ackBtn) ackAlert(ackBtn.dataset.id);
  if (disBtn) dismissAlert(disBtn.dataset.id);
});

/* ── GENERATE / SIMULATE ─────────────────────────────────────────── */
document.getElementById('btn-generate').addEventListener('click', () => generateAlert());
document.getElementById('btn-simulate').addEventListener('click', simulateIncident);
document.getElementById('btn-clear').addEventListener('click', clearAlerts);

/* ── BADGE & COUNTS ─────────────────────────────────────────────── */
function updateBadge() {
  const unacked = activeAlerts.filter(a => !a.acked).length;
  const badge = document.getElementById('alert-badge');
  badge.textContent = unacked > 0 ? unacked : '';
}

function updateSeverityCounts() {
  const counts = { ALL: 0, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  activeAlerts.forEach(a => {
    counts.ALL++;
    if (counts[a.sev] !== undefined) counts[a.sev]++;
  });
  Object.entries(counts).forEach(([sev, n]) => {
    const el = document.getElementById(`cnt-${sev}`);
    if (el) el.textContent = n;
  });
}

function updateStatusBar() {
  const total    = activeAlerts.length;
  const critical = activeAlerts.filter(a => a.sev === 'CRITICAL').length;
  const high     = activeAlerts.filter(a => a.sev === 'HIGH').length;
  const medium   = activeAlerts.filter(a => a.sev === 'MEDIUM').length;
  const el = document.getElementById('sb-alert-summary');
  if (total === 0) {
    el.textContent = 'No alerts';
    return;
  }
  const parts = [];
  if (critical) parts.push(`${critical} CRITICAL`);
  if (high)     parts.push(`${high} HIGH`);
  if (medium)   parts.push(`${medium} MEDIUM`);
  const rest = total - critical - high - medium;
  if (rest > 0) parts.push(`${rest} other`);
  el.textContent = parts.join(' · ');
}

function updateLastAlert() {
  const wrap = document.getElementById('last-alert-wrap');
  const el   = document.getElementById('last-alert-time');
  if (!lastAlertTime) { wrap.style.display = 'none'; return; }
  wrap.style.display = 'flex';
  el.textContent = relTime(lastAlertTime.getTime());
}

/* ── RELATIVE TIMESTAMPS ─────────────────────────────────────────── */
function updateRelTimes() {
  document.querySelectorAll('.alert-rel[data-ts]').forEach(el => {
    el.textContent = relTime(parseInt(el.dataset.ts, 10));
  });
  updateLastAlert();
}

function startRelTimeUpdates() {
  if (relTimeInterval) return;
  relTimeInterval = setInterval(updateRelTimes, 30000);
}

/* ════════════════════════════════════════════════════
   IR PLAYBOOKS — ACCORDION
════════════════════════════════════════════════════ */
document.querySelectorAll('.pb-card .pb-header').forEach(h => {
  h.addEventListener('click', () => h.closest('.pb-card').classList.toggle('open'));
});

/* ════════════════════════════════════════════════════
   PENTEST REF — COLLAPSIBLE
════════════════════════════════════════════════════ */
function setRefCard(header, open) {
  const body = header.closest('.ref-card').querySelector('.ref-body');
  const chev = header.querySelector('.ref-chevron');
  header.dataset.open = open ? 'true' : 'false';
  body.style.display  = open ? 'block' : 'none';
  chev.classList.toggle('open', open);
}

document.querySelectorAll('.ref-header').forEach(h => {
  h.addEventListener('click', () => {
    const isOpen = h.dataset.open === 'true';
    setRefCard(h, !isOpen);
  });
});

document.getElementById('btn-expand-all').addEventListener('click', () => {
  document.querySelectorAll('.ref-header').forEach(h => setRefCard(h, true));
});
document.getElementById('btn-collapse-all').addEventListener('click', () => {
  document.querySelectorAll('.ref-header').forEach(h => setRefCard(h, false));
});

/* ════════════════════════════════════════════════════
   THREAT MAP — TACTIC FILTER
════════════════════════════════════════════════════ */
document.getElementById('tactic-filters').addEventListener('click', e => {
  const btn = e.target.closest('.tact-filter');
  if (!btn) return;
  document.querySelectorAll('.tact-filter').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  const tactic = btn.dataset.tactic;
  document.querySelectorAll('#threat-table tbody tr').forEach(row => {
    const match = tactic === 'ALL' || row.dataset.tactic === tactic;
    row.dataset.hidden = String(!match);
    row.style.display = match ? '' : 'none';
  });
});

/* ════════════════════════════════════════════════════
   COPY TO CLIPBOARD
════════════════════════════════════════════════════ */
function showCopyToast() {
  const toast = document.getElementById('copy-toast');
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 1500);
}

document.addEventListener('click', e => {
  const el = e.target.closest('code.copyable');
  if (!el) return;
  const text = el.textContent;
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).then(showCopyToast).catch(() => {});
  } else {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); showCopyToast(); } catch (_) {}
    document.body.removeChild(ta);
  }
});

/* ════════════════════════════════════════════════════
   KEYBOARD SHORTCUTS
════════════════════════════════════════════════════ */
document.addEventListener('keydown', e => {
  const tag = e.target.tagName;
  if (tag === 'INPUT' || tag === 'TEXTAREA') {
    if (e.key === 'Escape') {
      e.target.value = '';
      searchQuery = '';
      applyFilters();
      e.target.blur();
    }
    return;
  }

  if (e.ctrlKey || e.metaKey || e.altKey) return;

  if (e.key === 'n' || e.key === 'N') { generateAlert(); return; }
  if (e.key === 'Escape') {
    searchQuery = '';
    currentSevFilter = 'ALL';
    document.getElementById('triage-search').value = '';
    document.querySelectorAll('.sev-filter').forEach(b => b.classList.remove('active'));
    document.querySelector('.sev-filter[data-sev="ALL"]').classList.add('active');
    applyFilters();
    return;
  }

  const panels = ['triage','playbooks','pentest','threats','logs','grc'];
  const idx = parseInt(e.key) - 1;
  if (idx >= 0 && idx < panels.length) switchTab(panels[idx]);
});

/* ════════════════════════════════════════════════════
   INIT
════════════════════════════════════════════════════ */
// Generate two starter alerts on load so the dashboard isn't empty
setTimeout(() => generateAlert('HIGH'),     300);
setTimeout(() => generateAlert('CRITICAL'), 700);
