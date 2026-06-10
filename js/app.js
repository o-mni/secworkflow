'use strict';

/* ── UTILITIES ───────────────────────────────────────── */
function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function rand(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

/* ── LOCALSTORAGE ────────────────────────────────────── */
const LS = {
  get(k, d=null) { try { const v=localStorage.getItem('cwb_'+k); return v!==null?JSON.parse(v):d; } catch { return d; } },
  set(k, v)      { try { localStorage.setItem('cwb_'+k, JSON.stringify(v)); } catch {} },
  del(k)         { localStorage.removeItem('cwb_'+k); },
  keys()         { return Object.keys(localStorage).filter(k=>k.startsWith('cwb_')); },
  exportAll()    { const d={}; LS.keys().forEach(k=>{ d[k]=localStorage.getItem(k); }); return d; },
  importAll(d)   { Object.entries(d).forEach(([k,v])=>{ if(k.startsWith('cwb_')) localStorage.setItem(k,v); }); },
  clearAll()     { LS.keys().forEach(k=>localStorage.removeItem(k)); },
};

/* ── TOAST ───────────────────────────────────────────── */
let _toastTimer;
function showToast(msg, type='') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show' + (type ? ' '+type : '');
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => { t.className = 'toast'; }, 2000);
}

/* ── DEBOUNCE ────────────────────────────────────────── */
const _timers = {};
function debounceSave(k, fn, ms=700) { clearTimeout(_timers[k]); _timers[k]=setTimeout(fn, ms); }

/* ════════════════════════════════════════════════════
   DATA — CHECKLIST
════════════════════════════════════════════════════ */
const CHECKLIST_ITEMS = [
  'Understand what happened',
  'Validate severity',
  'Identify affected assets',
  'Preserve evidence',
  'Determine containment needs',
  'Escalate if required',
  'Document actions taken',
];

/* ════════════════════════════════════════════════════
   DATA — ALERT TEMPLATES
   Variant fields: sev, title, scenario, meaning,
     firstChecks[], logsToReview[],
     falsePositive, escalationTrigger, docReminder
════════════════════════════════════════════════════ */
const ALERT_TEMPLATES = [
  { type:'Suspicious Login', icon:'🔐', variants:[
    { sev:'CRITICAL', title:'Brute force — successful auth',
      scenario:'47 failed SSH login attempts from 185.220.101.x in 3 minutes, followed by a successful authentication as service account "svc-backup".',
      meaning:'Brute-force likely succeeded. Service accounts should not be SSH-accessible externally. Treat as active compromise until proven otherwise.',
      firstChecks:['Lock "svc-backup" and revoke all active sessions immediately','Block 185.220.101.x at the perimeter firewall','Review every action taken after the successful login'],
      logsToReview:['Windows Security: EventID 4625 (failed), 4624 (success)','SSH: /var/log/auth.log or /var/log/secure','SIEM: correlate source IP across all managed systems'],
      falsePositive:'IT admin was locked out, had their password reset, then authenticated. Confirm with IT and the user before treating as breach.',
      escalationTrigger:'Any unconfirmed successful authentication following brute-force activity.',
      docReminder:'Record source IP, username, timestamp, session duration, and all actions performed after the successful login.' },
    { sev:'HIGH', title:'Impossible travel',
      scenario:'"j.smith-admin" authenticated from London at 08:14 UTC and Singapore at 08:47 UTC — 33 minutes apart. User is normally US-based.',
      meaning:'Impossible travel indicator. Either the account is compromised or a VPN/proxy is being misused. Both require investigation.',
      firstChecks:['Lock the account and revoke all active sessions','Call the user directly — do NOT use email','Audit all actions taken in both session windows'],
      logsToReview:['Azure AD / Okta: sign-in logs with geo, IP, device fingerprint','Conditional access evaluation log','Application activity log during both session windows'],
      falsePositive:'User connected via a VPN with a foreign exit node, or is using a travel proxy. Always confirm directly with the user by phone.',
      escalationTrigger:'User cannot explain the foreign login, or the session accessed sensitive systems.',
      docReminder:'Record both login geolocations, timestamps, device fingerprints, and the user\'s verbal confirmation or denial.' },
  ]},
  { type:'Malware Detected', icon:'🦠', variants:[
    { sev:'CRITICAL', title:'Active ransomware on endpoint',
      scenario:'EDR flagged mass file encryption on WORKSTATION-042. vssadmin.exe deleted shadow copies. Ransom note dropped in 14 directories. Encryption still ongoing.',
      meaning:'Active ransomware. Every second increases blast radius. Containment is the only priority — do NOT reboot.',
      firstChecks:['ISOLATE WORKSTATION-042 immediately — EDR kill switch or physical disconnect','Preserve a memory dump before any other action','Check if network shares are mounted — they may be encrypting simultaneously'],
      logsToReview:['EDR: file modification events and full process tree','Sysmon EventID 11: FileCreate with new file extensions','Windows Event 4688: vssadmin.exe and wbadmin.exe execution'],
      falsePositive:'Backup or compression software can trigger mass file modification alerts. Verify the process name and whether shadow copies were actually deleted.',
      escalationTrigger:'Any confirmed mass encryption event or shadow copy deletion.',
      docReminder:'Record encrypted file count, ransom note paths, full process chain, and all network shares mounted at time of incident.' },
    { sev:'CRITICAL', title:'C2 beacon detected',
      scenario:'Process chain: WINWORD.EXE → powershell.exe → rundll32.exe on SRV-APP01. Periodic HTTPS connections to 194.165.x.x every 60 seconds with ±2s jitter.',
      meaning:'Active C2 implant. Attacker is in post-exploitation phase with likely interactive access. Credential exposure is near-certain.',
      firstChecks:['Network-quarantine SRV-APP01 via EDR — do NOT reboot','Block 194.165.x.x and its ASN at the perimeter firewall','Search all endpoints for the same WINWORD → powershell parent-child chain'],
      logsToReview:['Sysmon EventID 1: WINWORD.EXE and all child processes','Firewall/proxy: all connections to 194.165.x.x','EDR: memory scan for C2 beacon artifacts on SRV-APP01'],
      falsePositive:'Legitimate software with cloud sync or telemetry can produce periodic HTTPS connections. Verify the responsible process and parent chain before acting.',
      escalationTrigger:'Confirmed C2 communication pattern with an anomalous parent process from an Office application.',
      docReminder:'Record the full process tree, C2 IP/domain, connection interval and jitter, and all other hosts found in the lateral search.' },
  ]},
  { type:'Phishing Email', icon:'🎣', variants:[
    { sev:'HIGH', title:'IT impersonation — credential harvest',
      scenario:'3 users forwarded an email impersonating IT Help Desk. Link points to "it-helpdesk-corp.com" (registered 2 days ago). Subject: "URGENT: Your password expires in 1 hour."',
      meaning:'Targeted credential harvesting campaign. Lookalike domain and urgency are classic indicators. Identify total recipient count before deleting.',
      firstChecks:['Pull and delete the email from all inboxes via admin console','Block the domain at DNS and web proxy immediately','Identify any user who clicked — treat as potential credential compromise'],
      logsToReview:['Email gateway: delivery logs, link-click tracking','Proxy/DNS: lookups to the lookalike domain','Auth logs: new logins in the 2-hour window after phishing delivery'],
      falsePositive:'A legitimate IT announcement sent from a new domain. Confirm with IT before bulk-deleting the email from inboxes.',
      escalationTrigger:'Any user who entered credentials on the phishing page — open a Suspicious Login incident.',
      docReminder:'Record sender domain, subject, embedded URLs, total recipient count, who clicked, and any confirmed credential submissions.' },
    { sev:'HIGH', title:'Business Email Compromise',
      scenario:'Email impersonating CFO requests urgent $52,000 wire transfer to a new vendor. Sender domain registered yesterday. DMARC: FAIL. Reply-to differs from sender.',
      meaning:'BEC targeting Finance. Authority impersonation and urgency bypass controls. Impact is immediate if a transfer is processed.',
      firstChecks:['Alert Finance immediately — halt any pending wire transfers','Call the real CFO on a known number — never reply to the email','Block the sender domain and report abuse to the mail provider'],
      logsToReview:['Email gateway: sender reputation, DMARC result, reply-to header analysis','Finance system: pending wire transfers initiated today','Auth logs: check if the CFO account was previously compromised'],
      falsePositive:'A legitimate new vendor request under unusual circumstances. Always verify by phone call — never via the suspicious email chain.',
      escalationTrigger:'Any confirmed or pending wire transfer in response to the request.',
      docReminder:'Preserve the full email with headers, any vendor communication, and the timeline of Finance team awareness.' },
  ]},
  { type:'Abnormal Network Traffic', icon:'📡', variants:[
    { sev:'CRITICAL', title:'Periodic C2 beacon pattern',
      scenario:'HOST-WIN-019 making HTTPS connections to 194.165.x.x every 60 seconds (±3s jitter). Volume: 2–4KB per request. IP matches threat intel C2 infrastructure.',
      meaning:'Classic beacon: consistent interval, jitter, small payload. HOST-WIN-019 almost certainly has an active implant in post-exploitation phase.',
      firstChecks:['Network-isolate HOST-WIN-019 immediately','Block 194.165.x.x at the perimeter firewall','Search proxy/firewall logs for any other hosts contacting this IP in the past 7 days'],
      logsToReview:['Firewall/proxy: all connections to 194.165.x.x with source IPs','EDR: process responsible for the outbound HTTPS connections','Sysmon EventID 3: network connections from HOST-WIN-019'],
      falsePositive:'Scheduled backup, monitoring agent, or antivirus update check can produce periodic HTTPS connections. Verify the responsible process.',
      escalationTrigger:'IP confirmed on threat intel feeds, or responsible process has a suspicious parent chain.',
      docReminder:'Record destination IP, connection interval, bytes per request, and the process responsible.' },
    { sev:'HIGH', title:'DGA malware DNS storm',
      scenario:'10.0.14.55 generated 3,200 NXDOMAIN responses in 10 minutes. Domains are algorithmic — 12–15 random characters, mixed TLDs. No successful resolutions yet.',
      meaning:'DGA-based malware attempting to locate its C2. No connection succeeded yet — this is a containment window before activation.',
      firstChecks:['Isolate 10.0.14.55 before any C2 resolution succeeds','Block the DGA domain pattern at the internal DNS resolver','Full EDR scan on the isolated host immediately'],
      logsToReview:['DNS server: NXDOMAIN responses, client IP 10.0.14.55','EDR: running processes and scheduled tasks on 10.0.14.55','NetFlow: UDP 53 volume from 10.0.14.55'],
      falsePositive:'Misconfigured DNS resolver, typo-heavy application, or a security tool checking domains can generate high NXDOMAIN counts. Verify the generating process.',
      escalationTrigger:'Any successful C2 DNS resolution, or additional hosts showing the same DGA pattern.',
      docReminder:'Record the NXDOMAIN count, domain patterns, time window, and the process responsible on the host.' },
  ]},
  { type:'Data Exfiltration', icon:'📤', variants:[
    { sev:'CRITICAL', title:'Large off-hours upload to personal cloud',
      scenario:'4.2GB uploaded to mega.nz from FINANCE-PC-07 between 23:00–01:30. DLP triggered. User has a confirmed departure date in 7 days.',
      meaning:'High-confidence insider exfiltration. Large off-hours upload from a financial endpoint by a departing employee is a near-certain signal.',
      firstChecks:['Forensic-image FINANCE-PC-07 — do NOT alert the employee','Block personal cloud storage at the web proxy','Escalate to HR and Legal before any further action'],
      logsToReview:['Proxy logs: full upload session to mega.nz (URLs, bytes, timestamps)','DLP: file types, names, sensitivity classification','EDR: file access history, archive creation, USB writes'],
      falsePositive:'Authorized large backup for legitimate work reasons. Verify with manager and Legal before concluding — evidence chain must be preserved.',
      escalationTrigger:'Any confirmed transfer of sensitive data by a user with an active departure date or disciplinary case.',
      docReminder:'Preserve the chain of custody. Record who imaged the device, when, and with which tool.' },
    { sev:'HIGH', title:'Bulk staging and cloud sync',
      scenario:'8.7GB archived from \\\\FILESERVER\\Confidential to C:\\Temp (.7z files), then synced to personal OneDrive. 1,240 files accessed in 2 hours.',
      meaning:'Deliberate staging and exfiltration. Targeting the Confidential share shows intentional selection — not accidental sync.',
      firstChecks:['Revoke OneDrive sync and disable personal cloud sync for this user','Pull the exact audit trail of files staged and transferred','Escalate to Legal — scope may trigger breach notification obligations'],
      logsToReview:['File server access log: files accessed and timestamps','DLP: cloud sync events, bytes transferred, destination account','EDR: archive creation events on the user workstation'],
      falsePositive:'Authorized data migration or user backup activity. Verify destination is an approved location with manager and Legal.',
      escalationTrigger:'Confirmed transfer of Confidential or Restricted files to any unapproved destination.',
      docReminder:'Document every file accessed, archive method, destination account, and total bytes transferred.' },
  ]},
  { type:'Brute Force', icon:'🔨', variants:[
    { sev:'HIGH', title:'SSH brute force on bastion',
      scenario:'840 failed SSH attempts against 10.0.1.5 (public bastion) from 45.155.x.x in 4 minutes. Targeting: root, admin, ubuntu, ec2-user.',
      meaning:'Automated credential scanning. High volume from a single IP. Verify no attempt succeeded and that lockout policy is enforced.',
      firstChecks:['Block 45.155.x.x at the perimeter firewall','Confirm no successful authentication in the attack window','Verify fail2ban or equivalent triggered at the correct threshold'],
      logsToReview:['SSH auth log: /var/log/auth.log — all attempts from 45.155.x.x','Windows Security EventID 4624: any successful login during the window','fail2ban/IPS: confirm the IP was auto-blocked'],
      falsePositive:'An authorized penetration test or vulnerability scan. Confirm with the security team whether a test was scheduled.',
      escalationTrigger:'Any confirmed successful login following the brute-force activity.',
      docReminder:'Record total attempt count, source IP, targeted usernames, time window, and whether lockouts were triggered.' },
    { sev:'HIGH', title:'O365 password spray',
      scenario:'1 failed login attempt against 480 accounts from 91.234.x.x within 6 minutes. Classic low-and-slow spray pattern to avoid lockout.',
      meaning:'Password spray against Microsoft 365. Single attempt per account avoids lockout triggers. High probability of partial success with weak passwords.',
      firstChecks:['Block 91.234.x.x in Conditional Access or Identity Protection','Check for any account with a successful auth from this IP','Force password reset and MFA challenge for any accounts that responded with success'],
      logsToReview:['Azure AD sign-in logs: all attempts from 91.234.x.x','Conditional Access: evaluation results — blocked vs. allowed','SIEM: correlate 480 failed logins in 6 minutes by source IP'],
      falsePositive:'A misconfigured application or monitoring tool retrying auth against many accounts. Verify the IP ownership and business context.',
      escalationTrigger:'Any account that shows a successful authentication from the spray source IP.',
      docReminder:'Record source IP, number of accounts targeted, time window, and any accounts that responded successfully.' },
  ]},
  { type:'Impossible Travel', icon:'✈', variants:[
    { sev:'CRITICAL', title:'Two countries — 9 minutes apart',
      scenario:'"m.jones" authenticated from New York at 14:22 UTC and Romania at 14:31 UTC — 9 minutes apart. No prior logins from Romania for this account.',
      meaning:'Physical impossibility. Almost certainly an active compromise with both the attacker and real user online simultaneously.',
      firstChecks:['Lock the account and revoke all active sessions immediately','Call the user by phone — do NOT use email','Audit every action taken during the Romanian session'],
      logsToReview:['IdP (Okta/Azure AD): sign-in logs — geo, IP, device fingerprint for both sessions','Application logs: every action in each session','Email: check for new forwarding rules or OAuth grants added in the suspicious session'],
      falsePositive:'User connected via a VPN with a Romanian exit node. Always confirm with the user directly by phone before locking the account.',
      escalationTrigger:'User denies the foreign login, or the suspicious session performed any sensitive action.',
      docReminder:'Record both geolocations, timestamps, IPs, device fingerprints, and every action performed in the suspicious session.' },
  ]},
  { type:'Privileged Account Misuse', icon:'👑', variants:[
    { sev:'HIGH', title:'Domain admin interactive logon on workstation',
      scenario:'Domain Administrator logged in interactively to WORKSTATION-023 at 14:32 UTC. Policy prohibits DA interactive logons on workstations. No open change window.',
      meaning:'Either an admin bypassed policy for convenience, or an attacker is using stolen DA credentials. Both require investigation.',
      firstChecks:['Confirm with the team: was a legitimate admin working on this machine at 14:32?','If unconfirmed — treat as potential DA compromise and escalate immediately','Review all commands executed during this session'],
      logsToReview:['Windows Security EventID 4624 (LogonType 2 = interactive)','PowerShell Script Block Logging: commands during the session','Sysmon EventID 1: full process tree under the DA context'],
      falsePositive:'An admin performed urgent work on a workstation outside normal process. Confirm via a change request or direct verbal confirmation from a known admin.',
      escalationTrigger:'The logon cannot be confirmed as legitimate by a known admin within your team.',
      docReminder:'Record the DA account name, workstation hostname, timestamp, LogonType, and all processes executed.' },
    { sev:'MEDIUM', title:'Service account interactive logon',
      scenario:'"svc-monitoring" authenticated interactively on 3 servers in 20 minutes. Configured for unattended service use only — no prior interactive logons in history.',
      meaning:'Service accounts should never be used interactively. May indicate an attacker using a harvested credential for lateral movement.',
      firstChecks:['Verify if scheduled maintenance explains this activity','Check originating IPs for all three sessions','Review commands executed on each server during the session window'],
      logsToReview:['Windows Security EventID 4624: LogonType 2 for svc-monitoring on all 3 servers','PowerShell and CMD history on each affected server','AD audit: recent changes to the svc-monitoring account'],
      falsePositive:'An admin used the service account for a quick maintenance task. Check whether any change request or maintenance window covers this activity.',
      escalationTrigger:'Sessions cannot be attributed to any known maintenance activity or authorized admin.',
      docReminder:'Record the account name, servers accessed, timestamps, originating IPs, and all commands executed.' },
  ]},
];

/* ════════════════════════════════════════════════════
   DATA — IR PLAYBOOKS
════════════════════════════════════════════════════ */
const IR_PLAYBOOKS = [
  { id:'phishing', title:'Phishing Incident', icon:'🎣', severity:'HIGH',
    tags:['Email','Credential Harvest','User Reported'],
    detect:['Email gateway alert or user-reported suspicious email','Verify sender domain — look for lookalike domains','Analyze headers: SPF, DKIM, DMARC alignment results','Check embedded link reputation and domain registration date','Hash any attachment against threat intel feeds','Identify how many users received, opened, or clicked'],
    contain:['Remove the email from all mailboxes via admin console','Block sender domain and all embedded URLs at email gateway and proxy','Reset credentials for any user who entered data on a phishing page','Force MFA re-enrollment if credentials may have been phished','Isolate any endpoint where an attachment was executed'],
    eradicate:['Block all IOCs across all perimeter controls','Scan endpoints that opened attachments for installed artifacts','Audit OAuth app grants, email forwarding rules, and new delegates','Remove any persistence discovered during investigation'],
    recover:['Restore access after credential reset and MFA re-enrollment','Verify no data exfiltration occurred during the compromise window','Confirm email filters are updated with new indicators','Monitor affected accounts for 14+ days'],
    lessons:['Were email filters insufficient? Update detection rules.','Did users report quickly? Reinforce reporting procedure.','How fast were credentials reset? Define an SLA.','Add this scenario to the next phishing simulation.'] },

  { id:'endpoint', title:'Compromised Endpoint', icon:'💻', severity:'CRITICAL',
    tags:['EDR','Malware','Containment'],
    detect:['EDR alert: suspicious process execution, file modification, network beacon','Abnormal parent-child process (e.g. Word spawning PowerShell)','Outbound connection to known malicious C2 infrastructure','User reports system behaving unexpectedly','New scheduled tasks, services, or registry run keys created'],
    contain:['Network-isolate via EDR quarantine — do NOT just reboot','Capture volatile data: processes, connections, loaded modules','Preserve a memory dump before any remediation','Disable the affected user account temporarily','Acquire a disk image for forensic analysis'],
    eradicate:['Re-image from a known-good baseline — do not attempt manual cleaning','Remove all persistence mechanisms on affected and related systems','Reset all credentials that were cached or used on this system','Patch the vulnerability or entry point before bringing back online'],
    recover:['Restore from a verified, pre-infection backup','Re-enroll user with fresh credentials and MFA device','Monitor the restored system closely for 14+ days','Confirm no lateral movement occurred from this endpoint'],
    lessons:['What was the initial infection vector? Patch or block it.','Did EDR alert in time? Review rule coverage.','Is re-imaging faster than attempted cleanup? Update the runbook.','Are backups available and tested?'] },

  { id:'login', title:'Suspicious Login', icon:'🔐', severity:'HIGH',
    tags:['Authentication','Account','Geo-Anomaly'],
    detect:['Login from an unusual geolocation','Impossible travel: same account in two distant locations within minutes','Login outside the user\'s normal hours','Account accessing a sensitive system it rarely uses','Multiple failed attempts followed by a successful authentication'],
    contain:['Lock the account and invalidate all active sessions immediately','Block the source IP at the perimeter firewall','Notify the user via out-of-band channel (phone, not email)','Preserve all authentication logs for the past 30+ days'],
    eradicate:['Force a full password reset','Re-enroll MFA from a verified, trusted device','Audit for persistence: email rules, OAuth grants, new admins','Review every action taken during the suspicious session'],
    recover:['Re-enable account only after direct user verification','Implement conditional access policy for this user type','Monitor account for 14+ days for re-compromise signs'],
    lessons:['Was MFA enforced? Why was it bypassed or absent?','Were geo-anomaly alerts configured? Tune detection rules.','Review detection-to-lockout time against your SLA.','Consider step-up authentication for high-sensitivity resources.'] },

  { id:'malware', title:'Malware Infection', icon:'🦠', severity:'CRITICAL',
    tags:['AV','EDR','Endpoint'],
    detect:['AV/EDR detection — cross-reference with threat intel','Unexpected process spawning, file creation, or registry modification','Network beacon or C2 communication (periodic, small payload)','CPU/memory spike with no operational explanation','New files in startup locations: AppData, Temp, Run registry keys'],
    contain:['Immediately isolate the infected host — EDR quarantine or physical disconnect','Do NOT reboot until memory is preserved','Identify the entry vector: email, web download, USB, lateral movement','Disable admin shares in the affected network segment','Check if the malware has worm/self-propagation capability'],
    eradicate:['Re-image — do not attempt manual cleanup for serious infections','Block all identified IOCs across all security controls','Scan every system on the same subnet for lateral spread','Patch the initial infection vector before restoring'],
    recover:['Restore from a pre-infection backup — verify integrity first','Validate clean state with EDR scan before returning to production','Monitor for 14+ days for re-infection or missed persistence'],
    lessons:['Was the malware blocked or only detected? Review policy.','What was the initial vector? Update filters.','How fast was isolation? Target under 15 minutes from detection.','Were backups accessible and verified clean?'] },

  { id:'lateral', title:'Lateral Movement', icon:'↔', severity:'CRITICAL',
    tags:['SMB','RDP','Credential','Spread'],
    detect:['Unusual SMB or RDP connections between workstations (peer-to-peer)','Pass-the-Hash or Pass-the-Ticket indicators in EDR/Sysmon','Admin share access (C$, ADMIN$) from a non-admin workstation','New local admin accounts appearing on multiple systems simultaneously','Sysmon EventID 3: unexpected connections from non-admin processes'],
    contain:['Segment the affected subnet — block SMB (445) and RDP (3389) between workstations','Disable compromised accounts immediately','Identify all systems the attacker has accessed — treat each as compromised','Reset KRBTGT password twice (60 min apart) to invalidate all Kerberos tickets'],
    eradicate:['Treat all systems in the affected segment as potentially compromised','Remove attacker tools from all systems','Reset all privileged credentials across the environment','Review and harden firewall rules between segments'],
    recover:['Rebuild affected systems from clean images','Restore and monitor all accounts','Validate that network segmentation is enforced and effective'],
    lessons:['Was segmentation blocking lateral SMB/RDP? It should be.','Were privileged accounts used on workstations? Eliminate this.','Was detection fast enough? Review lateral movement detection rules.','Consider host firewall GPO to block workstation-to-workstation SMB.'] },

  { id:'dataleak', title:'Data Leak Suspicion', icon:'📤', severity:'HIGH',
    tags:['DLP','Exfiltration','Insider'],
    detect:['DLP alert: sensitive data transferred to personal or external destination','Unusual outbound volume: large files, bulk uploads, off-hours transfers','Personal cloud storage accessed from corporate endpoint','Email with large attachments to personal or external addresses','Mass file access, staging in Temp, archive creation, USB writes'],
    contain:['Preserve forensic evidence BEFORE any action visible to the user','Block the specific exfiltration channel at the web proxy','Revoke access to sensitive data stores','Do NOT alert the user if insider threat is suspected — escalate to HR and Legal first'],
    eradicate:['Determine full scope: what data, how much, where it went','Revoke all access: email, VPN, workstation, cloud apps','Identify and close the access control gaps that enabled this'],
    recover:['Assess whether breach notification is required','Notify Legal, Compliance, and management of data scope','Implement controls to prevent recurrence (DLP tuning, proxy rules)'],
    lessons:['Were DLP policies tuned to catch this? Update them.','What controls could have limited the blast radius?','Was the off-boarding process followed? Enforce it proactively.','Document chain of custody from the start.'] },

  { id:'ransomware', title:'Ransomware', icon:'🔒', severity:'CRITICAL',
    tags:['Ransomware','Encryption','Critical','Backups'],
    detect:['EDR: mass file modification, shadow copy deletion, ransom note creation','vssadmin.exe or wbadmin.exe deleting backups — treat as maximum urgency','High-volume file renames/rewrites in a very short window','User reports: files have unknown extensions and are inaccessible'],
    contain:['IMMEDIATE: isolate every affected system — unplug network if necessary','Identify patient zero and the full scope of affected systems','Disable admin shares and SMB broadly across the environment','Preserve a memory dump on any running system','Do NOT pay the ransom without executive and legal approval'],
    eradicate:['Re-image all affected systems — no exceptions','Identify and patch the initial entry vector BEFORE restoring','Rotate all credentials across the environment','Scan every system that was online during the incident'],
    recover:['Verify backup integrity BEFORE restoring — confirm backups are not encrypted','Restore from the last known-clean backup','Bring systems back one at a time with enhanced monitoring','Validate data integrity post-restoration before handing back to business'],
    lessons:['Were backups isolated, tested, and immutable? Make this mandatory.','What was the entry vector? Phishing, RDP, unpatched CVE?','Did EDR attempt to block file encryption? Review policy.','When was the last full restore test? Schedule a drill.'] },

  { id:'insider', title:'Insider Threat', icon:'👁', severity:'HIGH',
    tags:['Insider','HR','Evidence','DLP'],
    detect:['DLP: large data staging or transfer near resignation or disciplinary action','Bulk access to sensitive files outside the user\'s normal role','After-hours access to sensitive systems','Personal cloud sync enabled on corporate endpoint'],
    contain:['Preserve forensic evidence FIRST — do not touch the system before imaging','Do NOT alert the employee — coordinate all actions with HR and Legal','Silently restrict additional access where possible','Collect all audit logs: DLP, AD, email, cloud, VPN, badge records'],
    eradicate:['Revoke all access simultaneously on the HR-coordinated action date','Retrieve all corporate devices immediately','Audit all data repositories the individual had access to','File abuse reports with any cloud services where data was uploaded'],
    recover:['Conduct access review across the team — tighten least-privilege assignments','Assess whether data exposure warrants breach notification','Brief leadership with the full scope of data involved'],
    lessons:['Was there a data retention review when departure was flagged? Implement it.','Did access rights exceed what the role required? Conduct regular access reviews.','Were UBA/UEBA tools available to surface the anomaly earlier?','Review the off-boarding checklist — include access revocation timelines.'] },
];

/* ════════════════════════════════════════════════════
   DATA — PENTEST SECTIONS
════════════════════════════════════════════════════ */
const PENTEST_SECTIONS = [
  { title:'Recon Checklist', type:'list', items:[
    'WHOIS, DNS records (A, MX, TXT, CNAME, AAAA), reverse DNS lookups',
    'Shodan / Censys: exposed services, banners, certificates, open ports',
    'Subdomain enumeration: subfinder, amass, dnsx — map the full attack surface',
    'Google dorks: site:target.com, filetype:pdf, inurl:admin, intitle:"login"',
    'LinkedIn / job postings: org chart, usernames, email format, tech stack hints',
    'GitHub / GitLab: hardcoded secrets, internal code, old credentials, config files',
    'Certificate transparency logs: crt.sh for all issued subdomains',
    'Web archive (Wayback Machine): old endpoints, removed pages, past tech choices',
    'Cloud asset discovery: common S3 bucket names (target-backup, target-dev, target-prod)',
    'Email harvesting: theHarvester, Hunter.io for email format discovery',
  ]},
  { title:'Common Ports & Services', type:'table',
    cols:['Port','Service','What to Check'],
    rows:[
      ['21','FTP','Anonymous access? Cleartext credentials. Writable directories?'],
      ['22','SSH','Version (CVEs?). Default or weak credentials. Key-based only?'],
      ['23','Telnet','Should never be open. Cleartext — sniff credentials if present.'],
      ['25 / 587','SMTP','Open relay? User enumeration via VRFY/EXPN.'],
      ['53','DNS','Zone transfer (AXFR)? DNS amplification? Internal DNS exposed?'],
      ['80 / 443','HTTP/HTTPS','Primary web app attack surface. TLS version, cipher strength.'],
      ['389 / 636','LDAP','Anonymous bind? User enumeration. LDAP injection.'],
      ['445','SMB','Null session? EternalBlue (MS17-010)? Open shares? Signing required?'],
      ['1433','MSSQL','SA account enabled? xp_cmdshell available? Remote access from internet?'],
      ['3306','MySQL','Root without password? Remote connections allowed?'],
      ['3389','RDP','BlueKeep (CVE-2019-0708)? Brute force. NLA enforced?'],
      ['5432','PostgreSQL','Default credentials? Remote connections from untrusted IPs?'],
      ['5900','VNC','No password? Weak shared secret? Screen visible?'],
      ['6379','Redis','No authentication? Remote code via CONFIG SET?'],
      ['8080 / 8443','HTTP Alt','Admin consoles, dev servers, internal APIs, reverse proxies.'],
      ['9200','Elasticsearch','No auth? Full data access? Write access (ransomware vector)?'],
      ['27017','MongoDB','No authentication? Guest access to all databases?'],
    ]
  },
  { title:'Web Testing Checklist (OWASP Top 10)', type:'list', items:[
    'A01 Broken Access Control — Test IDOR: change IDs in requests. Forced browsing to /admin, /config. Role escalation via request parameter manipulation.',
    'A02 Cryptographic Failures — HTTPS enforced? HSTS header present? TLS 1.2+ only? Sensitive data returned in cleartext or URLs?',
    'A03 Injection — SQLi (error, blind, time-based, UNION), NoSQLi, LDAP injection, OS command injection, SSTI in template engines.',
    'A04 Insecure Design — Missing rate limiting on login/OTP/API. Price or quantity manipulation. Logic flaws allowing step-skipping in workflows.',
    'A05 Security Misconfiguration — Default credentials, debug mode, verbose error messages with stack traces, CORS wildcard (*), unnecessary HTTP methods.',
    'A06 Vulnerable Components — Identify framework and library versions. Run Nuclei templates. Check JS libraries with Retire.js.',
    'A07 Auth & Session Failures — No lockout (brute force). Session token entropy. Cookie flags: Secure, HttpOnly, SameSite. Session invalidated on logout?',
    'A08 Software Integrity — CDN scripts without SRI? Unvalidated package updates? Secrets in environment variables or CI logs?',
    'A09 Logging Failures — Can you generate an auth event with no log entry? Do errors reveal internal paths or database schema?',
    'A10 SSRF — User-supplied URLs in import/webhook/fetch. Test 127.0.0.1, 169.254.169.254 (AWS metadata), internal subnet addresses.',
  ]},
  { title:'SQL Injection Indicators', type:'list', items:[
    "Single quote: ' — SQL syntax error reveals database type and query structure",
    "Auth bypass: ' OR '1'='1'-- or admin'-- or ' OR 1=1#",
    "Time-based blind (MySQL): ' AND SLEEP(5)-- — observe 5-second delay",
    "Time-based blind (MSSQL): '; WAITFOR DELAY '0:0:5'--",
    "Boolean-based: ' AND 1=1-- (true, normal) vs ' AND 1=2-- (false, different response)",
    "UNION-based: ' UNION SELECT NULL,NULL,NULL-- — increment NULLs until no type error",
    "Error messages: ORA-01756 (Oracle), You have an error in your SQL (MySQL), Unclosed quotation (MSSQL)",
    "SQLMap quick start: sqlmap -u 'http://target/page?id=1' --dbs --batch",
  ]},
  { title:'XSS Indicators', type:'list', items:[
    '<script>alert(document.domain)</script> — basic reflected XSS test',
    '"><script>alert(1)</script> — attribute break-out',
    '"><img src=x onerror=alert(1)> — event handler injection',
    '<svg onload=alert(1)> — SVG vector, often bypasses script-tag filters',
    'javascript:alert(1) in href or action attributes — URL context injection',
    'DOM XSS: check JS for document.write, innerHTML, eval with user-controlled input',
    'Stored XSS: input persists in page after refresh, especially in admin views',
    'Testing: Dalfox — dalfox url target/search?q=XSS',
  ]},
  { title:'Authentication Weaknesses', type:'list', items:[
    'No account lockout: attempt 100 logins — if no lockout, CAPTCHA, or rate limit, brute force is viable',
    'Username enumeration: compare response time and message for valid vs. invalid usernames',
    'Default credentials: admin/admin, admin/password, root/root — plus application-specific defaults',
    'Weak reset tokens: timestamp-based, sequential, or tokens that never expire',
    'Password reset tokens in URL: leak via referrer headers, browser history, and server logs',
    'Session not invalidated on logout: save the token before logout, try it after',
    'Missing cookie flags: Secure (cleartext), HttpOnly (JS access), SameSite (CSRF)',
    'MFA bypass: can MFA be skipped by replaying a request or removing a parameter?',
    'OAuth misconfigurations: missing state (CSRF), open redirect in redirect_uri, token leakage',
  ]},
  { title:'Privilege Escalation (Linux)', type:'list', items:[
    'id && whoami && uname -a — baseline identity and OS version',
    'sudo -l — what can current user run with sudo; look for (ALL) or NOPASSWD',
    'find / -perm -4000 -type f 2>/dev/null — SUID binaries, cross-reference GTFOBins',
    'crontab -l && cat /etc/cron* — check for writable cron scripts',
    'find / -writable -not -path "/proc/*" -type f 2>/dev/null — writable files',
    'NFS no_root_squash: showmount -e target — mount and place a SUID binary',
    'Kernel exploits: uname -r — searchsploit or CVE database check',
  ]},
  { title:'Enumeration (Linux)', type:'list', items:[
    'id && whoami && uname -a — identity, OS, kernel',
    'cat /etc/passwd | grep -v nologin — users with interactive shell',
    'find / -perm -4000 2>/dev/null — SUID files',
    'crontab -l && ls -la /etc/cron* — all scheduled tasks',
    'ss -tulpn — listening ports and services',
    'ps aux — all running processes',
    'find / -name "id_rsa" -readable 2>/dev/null — readable SSH private keys',
    'find / -name "*.conf" -readable 2>/dev/null | head -20 — readable config files',
  ]},
  { title:'Enumeration (Windows)', type:'list', items:[
    'whoami /all — user, all groups, all assigned privileges',
    'net user && net localgroup Administrators — local users and admins',
    'systeminfo — OS version, patch level, hotfixes installed',
    'ipconfig /all && netstat -ano — network config and all connections with PIDs',
    'tasklist /svc — all processes with associated services',
    'reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run — startup entries',
    'dir /s /b C:\\Users\\*.txt *.config *.ini 2>nul — search for credential files',
    'PS: Get-ScheduledTask | Where State -ne Disabled — active scheduled tasks',
  ]},
  { title:'Reporting Reminders', type:'list', items:[
    'Write for two audiences: executive summary (no jargon) and technical detail (full evidence)',
    'Every finding: Title, Severity, Description, Evidence/Screenshot, Impact, Recommendation',
    'Screenshot every finding with a visible timestamp — metadata alone is insufficient',
    'Rate findings consistently: CRITICAL / HIGH / MEDIUM / LOW / INFO with defined criteria',
    'Separate quick wins (patch today) from strategic recommendations (re-architect)',
    'Reference CVE and CWE numbers where applicable',
    'PoC commands must be precise and reproducible — vague descriptions are rejected',
    'Executive summary: pure business-risk language, 1 page max, zero technical jargon',
    'Recommendations must be specific: not "fix SQL injection" but "use parameterized queries in login.php line 47"',
  ]},
];

/* ════════════════════════════════════════════════════
   DATA — INVESTIGATION SECTIONS
════════════════════════════════════════════════════ */
const INV_SECTIONS = [
  { title:'Logs to Check First', type:'table',
    cols:['Log Source','What to Look For','Key Identifiers'],
    rows:[
      ['Authentication','Failed logons, geo anomalies, off-hours logins, MFA bypass, impossible travel','EventID 4624/4625/4648 (Windows), auth.log (Linux), IdP sign-in logs'],
      ['Endpoint / EDR','Suspicious process spawn, LSASS access, new services/tasks, encoded commands, beacons','Sysmon 1/3/7/10/13, EDR process tree and network telemetry'],
      ['Firewall / Network','Blocked outbound to rare IPs, new allow rules, lateral movement on 445/3389','Source IP, dest IP, dest port, action, bytes transferred'],
      ['DNS','High NXDOMAIN rate, DGA-pattern domains, rare TLDs, very long subdomain strings','Query name, response code, client IP, query frequency per client'],
      ['Proxy / Web','Rare external domains, large outbound transfers, off-hours uploads, suspicious user-agents','URL, bytes_out, user-agent, client IP, destination domain age'],
      ['Email','External-to-internal with links/attachments, reply-to mismatch, DMARC FAIL','Sender, recipient, subject, link URLs, attachment hash, DMARC result'],
      ['VPN','Auth from new geolocation, concurrent sessions from different countries','Source IP, geo, user, session start/end, bytes transferred'],
    ]
  },
  { title:'Normal vs. Suspicious', type:'compare',
    rows:[
      { normal:'svchost.exe spawned by services.exe', suspicious:'svchost.exe spawned by cmd.exe or powershell.exe' },
      { normal:'DNS queries to known CDN or cloud providers', suspicious:'DNS queries to random 12-char domains, high NXDOMAIN rate (DGA)' },
      { normal:'RDP session originating from corporate VPN IP', suspicious:'RDP from foreign country IP at 3:00am local time' },
      { normal:'User logs in from their assigned workstation', suspicious:'Same credentials used from 3 countries within 2 hours' },
      { normal:'Scheduled task running notepad.exe at 10:00am', suspicious:'Scheduled task: powershell.exe -NoProfile -enc JABjAGMA...' },
      { normal:'User downloads 20MB of documents during business hours', suspicious:'User downloads 8GB then uploads to personal cloud at 11:00pm' },
      { normal:'LSASS running with normal system-level access', suspicious:'Custom process opening a handle to lsass.exe memory (Sysmon EventID 10)' },
      { normal:'PowerShell running Get-Service with a readable command', suspicious:'powershell.exe -NonInteractive -WindowStyle Hidden -EncodedCommand JAB...' },
    ]
  },
  { title:'Log Filter Cheat Sheet', type:'code', items:[
    { label:'Failed logons (Windows)',          code:'EventID=4625 AND LogonType=3' },
    { label:'Explicit credential logon',         code:'EventID=4648' },
    { label:'Kerberos ticket requests',          code:'EventID=4768 OR EventID=4769' },
    { label:'Process creation (Sysmon)',         code:'EventID=1 AND Image=*powershell.exe*' },
    { label:'LSASS memory access (Sysmon)',      code:'EventID=10 AND TargetImage=*lsass.exe*' },
    { label:'Encoded PowerShell command',        code:'CommandLine=*-EncodedCommand* OR CommandLine=*-enc *' },
    { label:'Base64 payload indicators',         code:'CommandLine=*JAB* OR CommandLine=*TVqQ* OR CommandLine=*SQBF*' },
    { label:'Suspicious parent process',         code:'ParentImage=*WINWORD.EXE* AND Image=*powershell.exe*' },
    { label:'DNS NXDOMAIN storm (Splunk)',        code:'sourcetype=dns answer_type=NXDOMAIN | stats count by src_ip' },
    { label:'Large outbound transfer',           code:'bytes_out > 104857600' },
    { label:'Outbound on suspicious port',       code:'dest_port IN (4444, 1337, 31337, 8888, 6666, 9001)' },
    { label:'Shadow copy deletion',              code:'CommandLine=*vssadmin* AND CommandLine=*delete*' },
    { label:'New service installed',             code:'EventID=7045' },
    { label:'Scheduled task created',            code:'EventID=4698' },
  ]},
  { title:'Investigation Questions', type:'list', items:[
    'Is this normal behavior for this specific user or system? Check the baseline first.',
    'Has this IP address, domain, or file hash been seen before in this environment?',
    'Does the timeline make sense? Are events in a logical sequence with coherent time gaps?',
    'Is there a plausible business justification for this activity?',
    'What is the potential blast radius if this is confirmed malicious?',
    'Have we collected and preserved enough evidence for a formal investigation or legal action?',
    'Should we escalate now, or do we need additional corroborating evidence first?',
    'Is this a single isolated event or part of a broader pattern across multiple systems?',
    'What would have to be true for this to be a false positive? Does that hold up?',
    'If we act on this now and we are wrong, what is the impact on the business?',
    'Who else could have been affected that we have not yet checked?',
    'What attacker objective does this behavior most likely represent in the attack lifecycle?',
  ]},
];

/* ════════════════════════════════════════════════════
   DATA — NIS2
════════════════════════════════════════════════════ */
const NIS2_DATA = {
  summary: 'NIS2 is an EU directive setting baseline cybersecurity requirements for critical and important sector organizations — covering risk management, incident reporting, access control, logging, and supply chain security.',
  mindset: [
    'Incident reporting — Significant incidents must be reported within 24h. Know your org\'s internal escalation path and external reporting obligations.',
    'Risk management — Every alert represents risk. Communicate severity clearly to those who need to act, not just those who want to know.',
    'Access control — Verify who accessed what, when, and why. Least privilege is the baseline, not an aspiration.',
    'Logging & monitoring — Logs must be available, intact, and reviewable. If it\'s not logged, it didn\'t happen.',
    'Business continuity — Know which systems are business-critical. Downtime on these triggers different response priorities and timelines.',
    'Supply chain — Third-party tools, vendors, and integrations are an attack surface. Apply the same scrutiny you apply to internal systems.',
  ],
  incidentThinking: [
    'What happened? Define the event in one clear sentence before escalating.',
    'Who is affected? Which users, systems, services, or data are involved?',
    'Is service impacted? Is something unavailable, degraded, or at imminent risk?',
    'Is data affected? PII, financial, or operational data exposed or accessible to unauthorized parties?',
    'Does this need escalation? When uncertain — yes. Always err toward escalating early.',
    'What evidence exists? Logs, alerts, screenshots, and timelines — collect before acting, not after.',
  ],
  checklist: [
    'Identify all affected systems and their business classification',
    'Preserve relevant logs — prevent rotation or deletion before they are secured',
    'Document the timeline of events as it is understood right now',
    'Escalate internally per your org\'s incident response process',
    'Track all containment and remediation actions taken with timestamps',
    'Support any regulatory reporting requirements if the scope qualifies',
  ],
};

/* ════════════════════════════════════════════════════
   NAVIGATION
════════════════════════════════════════════════════ */
const PAGES = ['dashboard','soc','ir','pentest','investigation','todo','nis2','settings'];

function switchPage(name) {
  if (!PAGES.includes(name)) return;
  document.querySelectorAll('.sb-btn').forEach(b => b.classList.toggle('active', b.dataset.page === name));
  document.querySelectorAll('.page').forEach(p => p.classList.toggle('active', p.id === 'page-' + name));
  LS.set('page', name);
  if (name === 'dashboard') updateDashboard();
}

document.getElementById('sb-nav').addEventListener('click', e => {
  const btn = e.target.closest('.sb-btn');
  if (btn && btn.dataset.page) switchPage(btn.dataset.page);
});

document.addEventListener('click', e => {
  const btn = e.target.closest('[data-goto]');
  if (btn) switchPage(btn.dataset.goto);
});

/* ════════════════════════════════════════════════════
   CLOCK
════════════════════════════════════════════════════ */
function updateClock() {
  const now = new Date();
  const p = n => String(n).padStart(2,'0');
  const utc = `${p(now.getUTCHours())}:${p(now.getUTCMinutes())}:${p(now.getUTCSeconds())} UTC`;
  const clockEl = document.getElementById('sb-clock');
  if (clockEl) clockEl.textContent = utc;
  const dateEl = document.getElementById('dash-date');
  if (dateEl) {
    const opts = { weekday:'long', month:'long', day:'numeric', year:'numeric' };
    dateEl.textContent = now.toLocaleDateString('en-US', opts) + '  ·  ' + utc;
  }
}
setInterval(updateClock, 1000);
updateClock();

/* ════════════════════════════════════════════════════
   SIDEBAR TOGGLE
════════════════════════════════════════════════════ */
document.getElementById('sb-toggle').addEventListener('click', () => {
  const sb = document.getElementById('sidebar');
  const collapsed = sb.classList.toggle('collapsed');
  document.body.classList.toggle('sidebar-collapsed', collapsed);
  const p = document.getElementById('pref-collapsed');
  if (p) p.checked = collapsed;
  const s = LS.get('settings', {}); s.collapsed = collapsed; LS.set('settings', s);
});

/* ════════════════════════════════════════════════════
   DASHBOARD
════════════════════════════════════════════════════ */
function initDashboard() { updateDashboard(); }

function updateDashboard() {
  const todos = LS.get('todos', []);
  const pending = todos.filter(t => !t.done).length;
  const pendingEl = document.getElementById('dash-pending');
  if (pendingEl) pendingEl.textContent = pending;

  const alerts = LS.get('alerts', []);
  const critical = alerts.filter(a => a.sev === 'CRITICAL').length;
  const critEl = document.getElementById('dash-critical');
  if (critEl) { critEl.textContent = critical; critEl.classList.toggle('red', critical > 0); }

  const dla = document.getElementById('dash-last-alert');
  if (dla) {
    if (!alerts.length) {
      dla.innerHTML = '<div class="empty-msg">No scenario yet — use SOC Helper to generate one.</div>';
    } else {
      const a = alerts[0];
      const ts = new Date(a.ts).toLocaleTimeString('en-US',{hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'});
      dla.innerHTML = `
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap">
          <span>${a.icon}</span>
          <span style="font-weight:600;color:var(--text-bright);font-size:13px">${escHtml(a.type)}</span>
          <span class="sev-badge ${a.sev}">${a.sev}</span>
          <span style="font-size:12.5px;color:var(--text)">— ${escHtml(a.title)}</span>
          <span class="alert-ts" style="margin-left:auto">${ts}</span>
        </div>
        <div style="font-size:12.5px;color:var(--text);line-height:1.55">${escHtml(a.scenario)}</div>`;
    }
  }
}

/* ════════════════════════════════════════════════════
   CHECKLIST
════════════════════════════════════════════════════ */
function initChecklist() {
  const states = LS.get('checklist', Array(CHECKLIST_ITEMS.length).fill(false));
  const container = document.getElementById('triage-checklist');

  CHECKLIST_ITEMS.forEach((item, i) => {
    const lbl = document.createElement('label');
    lbl.className = 'check-item' + (states[i] ? ' is-checked' : '');
    lbl.innerHTML = `<span class="check-box"></span><span class="check-label">${escHtml(item)}</span>`;
    lbl.addEventListener('click', () => {
      lbl.classList.toggle('is-checked');
      const s = Array.from(container.querySelectorAll('.check-item')).map(el => el.classList.contains('is-checked'));
      LS.set('checklist', s);
    });
    container.appendChild(lbl);
  });

  document.getElementById('btn-reset-checklist').addEventListener('click', () => {
    container.querySelectorAll('.check-item').forEach(el => el.classList.remove('is-checked'));
    LS.set('checklist', Array(CHECKLIST_ITEMS.length).fill(false));
    showToast('Checklist reset', 'ok');
  });
}

/* ════════════════════════════════════════════════════
   SOC HELPER
════════════════════════════════════════════════════ */
function initSoc() {
  renderAlerts(LS.get('alerts', []));
  document.getElementById('btn-new-alert').addEventListener('click', generateAlert);
  document.getElementById('btn-clear-alerts').addEventListener('click', () => {
    if (!confirm('Clear all scenarios?')) return;
    LS.set('alerts', []); renderAlerts([]); updateDashboard();
  });
  document.getElementById('sev-filters').addEventListener('click', e => {
    const btn = e.target.closest('.sev-filter');
    if (!btn) return;
    document.querySelectorAll('.sev-filter').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    renderAlerts(LS.get('alerts', []));
  });
  document.getElementById('alert-feed').addEventListener('click', e => {
    const dismiss = e.target.closest('.alert-dismiss');
    if (dismiss) {
      const updated = LS.get('alerts', []).filter(a => a.id !== dismiss.dataset.id);
      LS.set('alerts', updated); renderAlerts(updated); updateDashboard(); return;
    }
    const copy = e.target.closest('.alert-copy-btn');
    if (copy) {
      const a = LS.get('alerts', []).find(x => x.id === copy.dataset.id);
      if (a) copyTriageChecklist(a, copy);
    }
  });
}

function generateAlert() {
  const t = rand(ALERT_TEMPLATES);
  const v = rand(t.variants);
  const alert = {
    id: Date.now() + '-' + Math.random().toString(36).slice(2,6),
    type: t.type, icon: t.icon, sev: v.sev, title: v.title,
    scenario: v.scenario, meaning: v.meaning,
    firstChecks: v.firstChecks, logsToReview: v.logsToReview,
    falsePositive: v.falsePositive, escalationTrigger: v.escalationTrigger,
    docReminder: v.docReminder,
    ts: new Date().toISOString(),
  };
  const alerts = LS.get('alerts', []);
  alerts.unshift(alert);
  LS.set('alerts', alerts);
  renderAlerts(alerts);
  updateDashboard();
  showToast(`${alert.sev} scenario generated`, (alert.sev==='CRITICAL'||alert.sev==='HIGH') ? 'err' : 'ok');
}

function renderAlerts(alerts) {
  const filter = document.querySelector('.sev-filter.active')?.dataset.sev || 'ALL';
  const feed = document.getElementById('alert-feed');
  const empty = document.getElementById('alert-empty');
  feed.querySelectorAll('.alert-card').forEach(c => c.remove());
  updateSevCounts(alerts);
  updateTriageBadge(alerts);
  if (!alerts.length) { empty.style.display = ''; return; }
  empty.style.display = 'none';
  (filter === 'ALL' ? alerts : alerts.filter(a => a.sev === filter)).forEach(a => feed.appendChild(buildAlertCard(a)));
}

function buildAlertCard(a) {
  const div = document.createElement('div');
  div.className = 'alert-card';
  div.dataset.sev = a.sev;
  const ts = new Date(a.ts).toLocaleTimeString('en-US',{hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'});
  div.innerHTML = `
    <div class="alert-card-head">
      <div class="alert-card-title-row">
        <span class="alert-icon">${a.icon}</span>
        <span class="alert-type">${escHtml(a.type)}</span>
        <span class="sev-badge ${a.sev}">${a.sev}</span>
        <span class="alert-title-detail">— ${escHtml(a.title)}</span>
        <span class="alert-ts">${ts}</span>
      </div>
      <button class="alert-dismiss" data-id="${a.id}" title="Dismiss">✕</button>
    </div>
    <div class="alert-body">
      <div class="alert-section">
        <div class="alert-section-label">Scenario</div>
        <div class="alert-scenario">${escHtml(a.scenario)}</div>
      </div>
      <div class="alert-section">
        <div class="alert-section-label">Likely Meaning</div>
        <div class="alert-meaning">${escHtml(a.meaning)}</div>
      </div>
      <div class="alert-section">
        <div class="alert-section-label">First Checks</div>
        <ul class="alert-actions-list">${a.firstChecks.map((c,i) =>
          `<li><span class="action-num">${i+1}</span><span>${escHtml(c)}</span></li>`).join('')}</ul>
      </div>
      <div class="alert-section">
        <div class="alert-section-label">Logs to Review</div>
        <ul class="alert-logs-list">${a.logsToReview.map(l=>`<li>${escHtml(l)}</li>`).join('')}</ul>
      </div>
      <div class="alert-meta-row">
        <div class="alert-section">
          <div class="alert-section-label">False Positive?</div>
          <div class="alert-fp">${escHtml(a.falsePositive)}</div>
        </div>
        <div class="alert-section">
          <div class="alert-section-label">Escalate If</div>
          <div class="alert-escalate">${escHtml(a.escalationTrigger)}</div>
        </div>
        <div class="alert-section">
          <div class="alert-section-label">Document</div>
          <div class="alert-doc">${escHtml(a.docReminder)}</div>
        </div>
      </div>
      <button class="alert-copy-btn" data-id="${a.id}">
        <svg width="12" height="12" viewBox="0 0 20 20" fill="currentColor"><path d="M8 3a1 1 0 011-1h2a1 1 0 110 2H9a1 1 0 01-1-1z"/><path d="M6 3a2 2 0 00-2 2v11a2 2 0 002 2h8a2 2 0 002-2V5a2 2 0 00-2-2 3 3 0 01-3 3H9a3 3 0 01-3-3z"/></svg>
        Copy triage checklist
      </button>
    </div>`;
  return div;
}

function copyTriageChecklist(a, btn) {
  const ts = new Date(a.ts).toLocaleString('en-US',{dateStyle:'medium',timeStyle:'short'});
  const lines = [
    'ALERT TRIAGE CHECKLIST',
    '══════════════════════════════════',
    `Scenario : ${a.type} — ${a.title}`,
    `Severity : ${a.sev}`,
    `Generated: ${ts}`,
    '',
    'FIRST CHECKS:',
    ...a.firstChecks.map((c,i) => `[ ] ${i+1}. ${c}`),
    '',
    'LOGS TO REVIEW:',
    ...a.logsToReview.map(l => `[ ] ${l}`),
    '',
    `ESCALATE IF: ${a.escalationTrigger}`,
    '',
    `DOCUMENT: ${a.docReminder}`,
  ].join('\n');

  const resetBtn = () => {
    setTimeout(() => {
      btn.classList.remove('copied');
      btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 20 20" fill="currentColor"><path d="M8 3a1 1 0 011-1h2a1 1 0 110 2H9a1 1 0 01-1-1z"/><path d="M6 3a2 2 0 00-2 2v11a2 2 0 002 2h8a2 2 0 002-2V5a2 2 0 00-2-2 3 3 0 01-3 3H9a3 3 0 01-3-3z"/></svg> Copy triage checklist';
    }, 2500);
  };
  const done = () => { btn.classList.add('copied'); btn.textContent = '✓ Copied'; showToast('Checklist copied', 'ok'); resetBtn(); };
  if (navigator.clipboard) { navigator.clipboard.writeText(lines).then(done).catch(done); }
  else { try { const ta=document.createElement('textarea'); ta.value=lines; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta); done(); } catch {} }
}

function updateSevCounts(alerts) {
  const c = {ALL:alerts.length,CRITICAL:0,HIGH:0,MEDIUM:0,LOW:0};
  alerts.forEach(a => { if(c[a.sev]!==undefined) c[a.sev]++; });
  document.getElementById('cnt-all').textContent      = c.ALL;
  document.getElementById('cnt-critical').textContent = c.CRITICAL;
  document.getElementById('cnt-high').textContent     = c.HIGH;
  document.getElementById('cnt-medium').textContent   = c.MEDIUM;
  document.getElementById('cnt-low').textContent      = c.LOW;
}

function updateTriageBadge(alerts) {
  const n = alerts.filter(a => a.sev === 'CRITICAL').length;
  document.getElementById('triage-badge').textContent = n > 0 ? n : '';
}

/* ════════════════════════════════════════════════════
   IR PLAYBOOKS
════════════════════════════════════════════════════ */
function initIR() {
  const container = document.getElementById('ir-accordion');
  IR_PLAYBOOKS.forEach(pb => {
    const card = document.createElement('div');
    card.className = 'acc-card';
    const ph = name => `
      <div class="pb-phase pb-phase-${name}">
        <div class="pb-phase-hdr">${name.charAt(0).toUpperCase()+name.slice(1)}</div>
        <ul>${pb[name].map(s=>`<li>${escHtml(s)}</li>`).join('')}</ul>
      </div>`;
    card.innerHTML = `
      <div class="acc-header">
        <div class="acc-header-left">
          <span class="acc-icon">${pb.icon}</span>
          <div class="acc-title-block">
            <div class="acc-title">${escHtml(pb.title)}</div>
            <div class="acc-tags">${pb.tags.map(t=>`<span class="acc-tag">${escHtml(t)}</span>`).join('')}</div>
          </div>
        </div>
        <div class="acc-header-right">
          <span class="sev-badge ${pb.severity}">${pb.severity}</span>
          <svg class="acc-chevron" viewBox="0 0 16 16" fill="currentColor"><path d="M7.247 11.14L2.451 5.658C1.885 5.013 2.345 4 3.204 4h9.592a1 1 0 0 1 .753 1.659l-4.796 5.48a1 1 0 0 1-1.506 0z"/></svg>
        </div>
      </div>
      <div class="acc-body">
        <div class="pb-phases">${ph('detect')}${ph('contain')}${ph('eradicate')}${ph('recover')}${ph('lessons')}</div>
      </div>`;
    card.querySelector('.acc-header').addEventListener('click', () => card.classList.toggle('open'));
    container.appendChild(card);
  });
  document.getElementById('btn-ir-expand-all').addEventListener('click', () =>
    document.querySelectorAll('#ir-accordion .acc-card').forEach(c => c.classList.add('open')));
  document.getElementById('btn-ir-collapse-all').addEventListener('click', () =>
    document.querySelectorAll('#ir-accordion .acc-card').forEach(c => c.classList.remove('open')));
}

/* ════════════════════════════════════════════════════
   PENTEST HELPER
════════════════════════════════════════════════════ */
function initPentest() {
  const container = document.getElementById('pentest-list');
  PENTEST_SECTIONS.forEach(sec => container.appendChild(buildRefCard(sec.title, buildRefBody(sec))));
  document.getElementById('btn-pt-expand-all').addEventListener('click', () =>
    document.querySelectorAll('#pentest-list .ref-card').forEach(c => c.classList.add('open')));
  document.getElementById('btn-pt-collapse-all').addEventListener('click', () =>
    document.querySelectorAll('#pentest-list .ref-card').forEach(c => c.classList.remove('open')));
}

/* ════════════════════════════════════════════════════
   INVESTIGATION HELPER
════════════════════════════════════════════════════ */
function initInvestigation() {
  const container = document.getElementById('inv-list');
  INV_SECTIONS.forEach(sec => container.appendChild(buildRefCard(sec.title, buildRefBody(sec), true)));
}

/* ════════════════════════════════════════════════════
   NIS2
════════════════════════════════════════════════════ */
function initNis2() {
  const container = document.getElementById('nis2-container');
  const summ = document.createElement('div');
  summ.className = 'nis2-summary';
  summ.textContent = NIS2_DATA.summary;
  container.appendChild(summ);
  const mindsetHtml = `<ul class="ref-list-items">${NIS2_DATA.mindset.map(i=>`<li>${escHtml(i)}</li>`).join('')}</ul>`;
  container.appendChild(buildRefCard('Key Analyst Mindset', mindsetHtml, true));
  const thinkingHtml = `<ul class="ref-list-items">${NIS2_DATA.incidentThinking.map(i=>`<li>${escHtml(i)}</li>`).join('')}</ul>`;
  container.appendChild(buildRefCard('Incident Thinking Questions', thinkingHtml, true));
  const checkHtml = `<ul class="ref-list-items">${NIS2_DATA.checklist.map(i=>`<li>${escHtml(i)}</li>`).join('')}</ul>`;
  container.appendChild(buildRefCard('Quick Response Checklist', checkHtml, true));
}

/* ── Shared ref card builder ─────────────────────── */
function buildRefCard(title, bodyHtml, startOpen=false) {
  const card = document.createElement('div');
  card.className = 'ref-card' + (startOpen ? ' open' : '');
  card.innerHTML = `
    <div class="ref-header">
      <span class="ref-title">${escHtml(title)}</span>
      <svg class="ref-chevron" viewBox="0 0 16 16" fill="currentColor"><path d="M7.247 11.14L2.451 5.658C1.885 5.013 2.345 4 3.204 4h9.592a1 1 0 0 1 .753 1.659l-4.796 5.48a1 1 0 0 1-1.506 0z"/></svg>
    </div>
    <div class="ref-body">${bodyHtml}</div>`;
  card.querySelector('.ref-header').addEventListener('click', () => card.classList.toggle('open'));
  return card;
}

function buildRefBody(sec) {
  if (sec.type === 'table') {
    return `<table class="ref-table">
      <thead><tr>${sec.cols.map(c=>`<th>${escHtml(c)}</th>`).join('')}</tr></thead>
      <tbody>${sec.rows.map(r=>`<tr>${r.map((c,i)=>`<td class="${i===0?'port-num':''}">${escHtml(c)}</td>`).join('')}</tr>`).join('')}</tbody>
    </table>`;
  }
  if (sec.type === 'compare') {
    return `<table class="compare-table">
      <thead><tr><th class="th-normal">Normal / Benign</th><th class="th-suspicious">Suspicious / Malicious</th></tr></thead>
      <tbody>${sec.rows.map(r=>`<tr><td class="td-normal">${escHtml(r.normal)}</td><td class="td-bad">${escHtml(r.suspicious)}</td></tr>`).join('')}</tbody>
    </table>`;
  }
  if (sec.type === 'code') {
    return `<div class="filter-items">${sec.items.map(item=>
      `<div class="filter-item">
        <div class="filter-label">${escHtml(item.label)}</div>
        <code class="filter-code" data-code="${escHtml(item.code)}">${escHtml(item.code)}</code>
      </div>`).join('')}</div>`;
  }
  return `<ul class="ref-list-items">${sec.items.map(i=>`<li>${escHtml(i)}</li>`).join('')}</ul>`;
}

document.addEventListener('click', e => {
  const code = e.target.closest('.filter-code');
  if (!code) return;
  const text = code.dataset.code || code.textContent.trim();
  const done = () => { code.classList.add('copied'); showToast('Copied', 'ok'); setTimeout(()=>code.classList.remove('copied'), 2000); };
  if (navigator.clipboard) { navigator.clipboard.writeText(text).then(done).catch(done); }
  else { try { const ta=document.createElement('textarea'); ta.value=text; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta); done(); } catch {} }
});

/* ════════════════════════════════════════════════════
   TO-DO (simplified)
════════════════════════════════════════════════════ */
function initTodo() {
  renderTodos();
  const inp = document.getElementById('todo-input');
  inp.addEventListener('keydown', e => { if (e.key === 'Enter') addTodo(); });
  document.getElementById('btn-add-todo').addEventListener('click', addTodo);
  document.getElementById('btn-clear-done').addEventListener('click', () => {
    if (!confirm('Remove all completed tasks?')) return;
    LS.set('todos', LS.get('todos',[]).filter(t=>!t.done));
    renderTodos(); showToast('Completed tasks cleared', 'ok');
  });
}

function addTodo() {
  const inp = document.getElementById('todo-input');
  const text = inp.value.trim();
  if (!text) return;
  const todos = LS.get('todos', []);
  todos.push({
    id: Date.now().toString(),
    text,
    priority: document.getElementById('todo-priority').value,
    done: false,
    createdAt: new Date().toISOString(),
  });
  LS.set('todos', todos);
  inp.value = '';
  renderTodos();
  updateDashboard();
  showToast('Task added', 'ok');
  inp.focus();
}

function sortTodos(arr) {
  const PRI = {high:0, medium:1, low:2};
  return [...arr].sort((a,b) => {
    if (a.done !== b.done) return a.done ? 1 : -1;
    return PRI[a.priority] - PRI[b.priority] || a.createdAt.localeCompare(b.createdAt);
  });
}

function renderTodos() {
  const all = LS.get('todos', []);
  document.getElementById('stat-total').textContent   = all.length;
  document.getElementById('stat-pending').textContent = all.filter(t=>!t.done).length;
  document.getElementById('stat-done').textContent    = all.filter(t=>t.done).length;
  const urgent = all.filter(t=>!t.done&&t.priority==='high').length;
  document.getElementById('todo-badge').textContent = urgent > 0 ? urgent : '';
  const list = document.getElementById('todo-list');
  list.querySelectorAll('.task-item').forEach(el => el.remove());
  document.getElementById('todo-empty').style.display = all.length===0 ? '' : 'none';
  sortTodos(all).forEach(t => list.appendChild(buildTaskItem(t)));
  updateDashboard();
}

function buildTaskItem(todo) {
  const div = document.createElement('div');
  div.className = 'task-item' + (todo.done ? ' done' : '');
  const d = new Date(todo.createdAt);
  const dateStr = d.toLocaleDateString('en-US',{month:'short',day:'numeric'}) + ' ' +
                  d.toLocaleTimeString('en-US',{hour12:false,hour:'2-digit',minute:'2-digit'});
  div.innerHTML = `
    <div class="task-check ${todo.done?'checked':''}" role="checkbox" aria-checked="${todo.done}" tabindex="0"></div>
    <span class="task-priority ${todo.priority}">${todo.priority}</span>
    <span class="task-text">${escHtml(todo.text)}</span>
    <span class="task-date">${dateStr}</span>
    <button class="task-del" title="Delete">✕</button>`;

  const toggle = () => {
    const todos = LS.get('todos',[]);
    const t = todos.find(x=>x.id===todo.id);
    if (t) t.done = !t.done;
    LS.set('todos', todos); renderTodos();
  };
  const check = div.querySelector('.task-check');
  check.addEventListener('click', toggle);
  check.addEventListener('keydown', e => { if(e.key===' '||e.key==='Enter') toggle(); });
  div.querySelector('.task-del').addEventListener('click', () => {
    LS.set('todos', LS.get('todos',[]).filter(t=>t.id!==todo.id)); renderTodos();
  });
  return div;
}

/* ════════════════════════════════════════════════════
   SETTINGS
════════════════════════════════════════════════════ */
function initSettings() {
  const s = LS.get('settings', {compact:false, collapsed:false});
  if (s.compact)   { document.body.classList.add('compact'); document.getElementById('pref-compact').checked = true; }
  if (s.collapsed) { document.getElementById('sidebar').classList.add('collapsed'); document.body.classList.add('sidebar-collapsed'); document.getElementById('pref-collapsed').checked = true; }

  document.getElementById('btn-export-all').addEventListener('click', () => {
    const blob = new Blob([JSON.stringify(LS.exportAll(), null, 2)], {type:'application/json'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
    a.download = 'cyberworkbench-' + new Date().toISOString().slice(0,10) + '.json'; a.click();
    showToast('Data exported', 'ok');
  });

  document.getElementById('import-file').addEventListener('change', e => {
    const file = e.target.files[0]; if (!file) return;
    const reader = new FileReader();
    reader.onload = ev => {
      try {
        const data = JSON.parse(ev.target.result);
        if (!data || typeof data !== 'object') throw new Error();
        LS.importAll(data); showToast('Imported — reloading…', 'ok');
        setTimeout(() => location.reload(), 1200);
      } catch { showToast('Import failed: invalid file', 'err'); }
    };
    reader.readAsText(file); e.target.value = '';
  });

  document.getElementById('btn-reset-all').addEventListener('click', () => {
    if (!confirm('Reset all data? This cannot be undone.')) return;
    LS.clearAll(); showToast('Cleared — reloading…', 'ok');
    setTimeout(() => location.reload(), 1200);
  });

  document.getElementById('pref-compact').addEventListener('change', e => {
    document.body.classList.toggle('compact', e.target.checked);
    const s2 = LS.get('settings',{}); s2.compact = e.target.checked; LS.set('settings', s2);
    showToast('Saved', 'ok');
  });

  document.getElementById('pref-collapsed').addEventListener('change', e => {
    document.getElementById('sidebar').classList.toggle('collapsed', e.target.checked);
    document.body.classList.toggle('sidebar-collapsed', e.target.checked);
    const s2 = LS.get('settings',{}); s2.collapsed = e.target.checked; LS.set('settings', s2);
    showToast('Saved', 'ok');
  });
}

/* ════════════════════════════════════════════════════
   KEYBOARD SHORTCUTS
════════════════════════════════════════════════════ */
document.addEventListener('keydown', e => {
  const tag = document.activeElement?.tagName;
  if (tag==='INPUT'||tag==='TEXTAREA'||tag==='SELECT') return;
  if (e.ctrlKey||e.metaKey||e.altKey) return;
  if (e.key==='n'||e.key==='N') {
    if (document.querySelector('.page.active')?.id==='page-soc') { generateAlert(); return; }
  }
  const idx = parseInt(e.key) - 1;
  if (idx >= 0 && idx < PAGES.length) { e.preventDefault(); switchPage(PAGES[idx]); }
});

/* ════════════════════════════════════════════════════
   INIT
════════════════════════════════════════════════════ */
function init() {
  initSettings();
  switchPage(LS.get('page', 'dashboard'));
  initDashboard();
  initChecklist();
  initSoc();
  initIR();
  initPentest();
  initInvestigation();
  initNis2();
  initTodo();
}

init();
