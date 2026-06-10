'use strict';

/* ════════════════════════════════════════════════════
   UTILITIES
════════════════════════════════════════════════════ */
function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function rand(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

/* ════════════════════════════════════════════════════
   LOCALSTORAGE
════════════════════════════════════════════════════ */
const LS = {
  get(key, def = null) {
    try { const v = localStorage.getItem('cwb_' + key); return v !== null ? JSON.parse(v) : def; }
    catch { return def; }
  },
  set(key, val) { try { localStorage.setItem('cwb_' + key, JSON.stringify(val)); } catch {} },
  del(key) { localStorage.removeItem('cwb_' + key); },
  keys() { return Object.keys(localStorage).filter(k => k.startsWith('cwb_')); },
  exportAll() { const d = {}; LS.keys().forEach(k => { d[k] = localStorage.getItem(k); }); return d; },
  importAll(d) { Object.entries(d).forEach(([k,v]) => { if (k.startsWith('cwb_')) localStorage.setItem(k, v); }); },
  clearAll() { LS.keys().forEach(k => localStorage.removeItem(k)); }
};

/* ════════════════════════════════════════════════════
   TOAST
════════════════════════════════════════════════════ */
let _toastTimer;
function showToast(msg, type = '') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show' + (type ? ' ' + type : '');
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => { t.className = 'toast'; }, 2000);
}

/* ════════════════════════════════════════════════════
   DEBOUNCE SAVE
════════════════════════════════════════════════════ */
const _timers = {};
function debounceSave(key, fn, delay = 700) {
  clearTimeout(_timers[key]);
  _timers[key] = setTimeout(fn, delay);
}

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
════════════════════════════════════════════════════ */
const ALERT_TEMPLATES = [
  {
    type: 'Suspicious Login', icon: '🔐',
    variants: [
      { sev:'CRITICAL', title:'Brute force — successful auth',
        what:'47 failed SSH login attempts from 185.220.101.x within 3 minutes, followed by a successful authentication as service account "svc-backup".',
        interpretation:'Brute-force attack likely succeeded. Service accounts should not be SSH-accessible from the internet. This is a probable active compromise.',
        actions:['Lock "svc-backup" immediately and revoke all active sessions','Block 185.220.101.x and its ASN range at the perimeter firewall','Review exactly what the account accessed after the successful login'],
        logs:['Windows Security: EventID 4625 (failed), 4624 (success)','SSH: /var/log/auth.log or /var/log/secure','SIEM: correlate source IP across all managed systems'],
        escalate:true, escalation:'Yes — active compromise likely. Escalate to IR team immediately.' },
      { sev:'HIGH', title:'Impossible travel login',
        what:'Admin account "j.smith-admin" authenticated from London (08:14 UTC) and then Singapore (08:47 UTC) — 33 minutes apart. User is normally US-based.',
        interpretation:'Impossible travel indicator. The account is either compromised or a VPN/proxy is being abused. Both require immediate investigation.',
        actions:['Lock the account and revoke all active sessions immediately','Contact the user directly via phone — do NOT use email','Audit all actions taken in both sessions before locking'],
        logs:['Azure AD / Okta sign-in logs: geo, IP, device fingerprint','Conditional access evaluation log','Activity audit for the account during both session windows'],
        escalate:true, escalation:'Yes — account takeover high probability. Escalate if user denies logins.' }
    ]
  },
  {
    type: 'Malware Detected', icon: '🦠',
    variants: [
      { sev:'CRITICAL', title:'Active ransomware on workstation',
        what:'EDR flagged mass file encryption on WORKSTATION-042. vssadmin.exe deleted shadow copies. Ransom note dropped in 14 directories. Encryption is ongoing.',
        interpretation:'Active ransomware execution. Every second increases blast radius. Containment is the only priority — do NOT reboot.',
        actions:['ISOLATE WORKSTATION-042 immediately — pull network cable or use EDR kill switch','Preserve memory dump before any further action','Check if any network shares are mounted — they may be encrypting too'],
        logs:['EDR: file modification events and full process tree','Sysmon EventID 11: FileCreate events showing new extensions','Windows Event 4688: vssadmin.exe execution'],
        escalate:true, escalation:'Yes — CRITICAL. Escalate to IR lead and management. Verify backup integrity now.' },
      { sev:'CRITICAL', title:'Cobalt Strike C2 beacon',
        what:'Process chain on SRV-APP01: WINWORD.EXE → powershell.exe → rundll32.exe. Periodic HTTPS connections to 194.165.x.x every 60 seconds (±2s jitter). Matches known C2 infrastructure.',
        interpretation:'Active C2 implant with interactive access. Attacker is conducting post-exploitation. Credential exposure is near-certain.',
        actions:['Network-quarantine SRV-APP01 via EDR — do NOT just reboot','Block 194.165.x.x and its ASN at the perimeter firewall immediately','Search all endpoints for the same WINWORD → powershell process chain'],
        logs:['Sysmon EventID 1: WINWORD.EXE and all child processes','Firewall/proxy: connections to 194.165.x.x','EDR: memory scan for Cobalt Strike beacon artifacts'],
        escalate:true, escalation:'Yes — CRITICAL. Active threat actor with hands-on access. Escalate immediately.' }
    ]
  },
  {
    type: 'Phishing Email', icon: '🎣',
    variants: [
      { sev:'HIGH', title:'IT impersonation — credential harvest',
        what:'3 users forwarded emails impersonating IT Help Desk. Link points to "it-helpdesk-corp.com" (registered 2 days ago). Subject: "URGENT: Your password expires in 1 hour."',
        interpretation:'Targeted credential harvesting. Lookalike domain and urgency language are hallmarks. Likely broader campaign — check total recipient count.',
        actions:['Pull and delete the email from all inboxes via admin console','Block it-helpdesk-corp.com and its hosting IP at DNS and web proxy','Identify any user who clicked — treat as potential credential compromise'],
        logs:['Email gateway: delivery logs, link-click tracking','Proxy/DNS: lookups and GET requests to the lookalike domain','Auth logs: new logins in the 2-hour window after phishing send time'],
        escalate:false, escalation:'Escalate if any user entered credentials — then open a Suspicious Login incident.' },
      { sev:'HIGH', title:'Business Email Compromise (BEC)',
        what:'Email impersonating CFO requests urgent $52,000 wire transfer to a new vendor. Sender domain registered yesterday. DMARC: FAIL. Reply-to address differs from sender.',
        interpretation:'BEC targeting Finance. Authority impersonation and urgency are designed to bypass controls. Financial impact is immediate if a transfer is processed.',
        actions:['Alert Finance team immediately — halt any pending wire transfers','Call the real CFO on a known phone number to confirm — never reply to the email','Block the sender domain and report abuse to the mail provider'],
        logs:['Email gateway: sender reputation, DMARC result, reply-to header analysis','Finance system: pending wire transfers initiated today','Auth logs: check if CFO account was previously compromised'],
        escalate:true, escalation:'Yes — escalate to Finance, CFO, and management. Notify immediately if a transfer was processed.' }
    ]
  },
  {
    type: 'Abnormal Network Traffic', icon: '📡',
    variants: [
      { sev:'CRITICAL', title:'Periodic C2 beacon pattern',
        what:'HOST-WIN-019 making periodic HTTPS connections to 194.165.x.x every 60 seconds (±3s jitter). Volume: 2–4KB per request. IP matches documented malicious C2 infrastructure.',
        interpretation:'Classic beacon pattern: consistent interval with jitter, small payload size. HOST-WIN-019 almost certainly has an active implant. Post-exploitation is likely.',
        actions:['Network-isolate HOST-WIN-019 immediately','Block 194.165.x.x and its ASN at the perimeter firewall','Search firewall/proxy logs for any other hosts contacting this IP over the past 7 days'],
        logs:['Firewall/proxy: all connections to 194.165.x.x with source IPs','EDR: process responsible for the outbound HTTPS connections','Sysmon EventID 3: network connections from HOST-WIN-019'],
        escalate:true, escalation:'Yes — CRITICAL. Active C2 implant. Escalate to IR team immediately.' },
      { sev:'HIGH', title:'DGA malware DNS storm',
        what:'10.0.14.55 generated 3,200 NXDOMAIN responses in 10 minutes. Domains follow an algorithmic pattern (.com/.net/.org, 12–15 random characters). No successful resolutions yet.',
        interpretation:'Host infected with DGA-based malware trying to locate its C2. No connection succeeded yet — this is a containment window before activation.',
        actions:['Isolate 10.0.14.55 before any C2 resolution can succeed','Block the DGA domain pattern at the internal DNS resolver','Full EDR scan and memory forensics on the isolated host'],
        logs:['DNS server: NXDOMAIN responses, client IP 10.0.14.55','EDR: running processes and scheduled tasks on 10.0.14.55','NetFlow: UDP 53 traffic from 10.0.14.55'],
        escalate:false, escalation:'Escalate if C2 connection succeeds or additional hosts are affected.' }
    ]
  },
  {
    type: 'Data Exfiltration Suspected', icon: '📤',
    variants: [
      { sev:'CRITICAL', title:'Large off-hours upload to personal cloud',
        what:'4.2GB uploaded to mega.nz from FINANCE-PC-07 between 23:00 and 01:30. DLP triggered. User has a confirmed departure date in 7 days; HR was informed 2 weeks ago.',
        interpretation:'High-confidence insider threat. Large after-hours upload from a financial endpoint by a departing employee is a strong exfiltration signal.',
        actions:['Forensic-image FINANCE-PC-07 immediately — do NOT alert the employee','Block mega.nz and all personal cloud storage at the web proxy','Escalate to HR and Legal before any further action — evidence chain is critical'],
        logs:['Proxy logs: full upload session to mega.nz (URLs, bytes, timestamps)','DLP alert: file types, names, sensitivity classification','EDR: file access history, archive creation events, USB writes'],
        escalate:true, escalation:'Yes — escalate to HR, Legal, and management. Do not confront the employee without legal guidance.' },
      { sev:'HIGH', title:'Bulk staging and sync to OneDrive',
        what:'8.7GB archived from \\\\FILESERVER\\Confidential to C:\\Temp (.7z files) over 2 hours, then synced to personal OneDrive. 1,240 files accessed.',
        interpretation:'Deliberate staging and exfiltration. Selection of the Confidential share shows intentional targeting — not an accidental sync.',
        actions:['Revoke OneDrive sync access and disable personal cloud sync for this user','Pull exact audit trail of which files were staged and transferred','Escalate to Legal — scope may trigger breach notification obligations'],
        logs:['File server access log: which files were accessed and when','DLP: cloud sync events, bytes transferred, destination account','EDR: archive creation events on user workstation'],
        escalate:true, escalation:'Yes — potential breach. Escalate to Legal and CISO.' }
    ]
  },
  {
    type: 'Brute Force Attempt', icon: '🔨',
    variants: [
      { sev:'HIGH', title:'SSH brute force on bastion host',
        what:'840 failed SSH login attempts against 10.0.1.5 (public-facing bastion) from 45.155.x.x in 4 minutes. Attempting common usernames: root, admin, ubuntu, ec2-user.',
        interpretation:'Automated SSH credential scanning. High volume from a single IP. Verify no attempt succeeded and that lockout policy is enforced.',
        actions:['Block 45.155.x.x at the perimeter firewall immediately','Confirm no successful authentication occurred during the attack window','Verify fail2ban or equivalent is active and triggered correctly'],
        logs:['SSH auth log: /var/log/auth.log — all attempts from 45.155.x.x','Windows Security EventID 4624: any success following the brute-force window','fail2ban: confirm IP was auto-banned and at what threshold'],
        escalate:false, escalation:'Escalate only if any login succeeded. Otherwise block, document, and monitor.' },
      { sev:'HIGH', title:'O365 password spray attack',
        what:'1 failed login attempt against 480 user accounts from 91.234.x.x within 6 minutes. Classic low-and-slow password spray. Attacker likely testing a single common password.',
        interpretation:'Password spray targeting Microsoft 365. Single attempt per account deliberately avoids lockout triggers. High probability of partial success if password policy is weak.',
        actions:['Block 91.234.x.x in Conditional Access or Azure AD Identity Protection','Check for any account with a successful response from this IP','Force password reset and MFA challenge for any accounts that responded with success'],
        logs:['Azure AD sign-in logs: all 480 attempts from 91.234.x.x','Conditional Access: evaluation results — blocked vs. allowed','SIEM: correlate 480 failed logins in 6 minutes by source IP'],
        escalate:true, escalation:'Yes — if any account authenticated. Password spray often precedes account takeover.' }
    ]
  },
  {
    type: 'Impossible Travel', icon: '✈',
    variants: [
      { sev:'CRITICAL', title:'Same account — two countries, 9 minutes apart',
        what:'"m.jones" authenticated from New York at 14:22 UTC and from Romania at 14:31 UTC — 9 minutes apart. Account has never previously authenticated from Romania.',
        interpretation:'Physical impossibility rules out legitimate travel. This is almost certainly an active account compromise where the attacker and real user are both online simultaneously.',
        actions:['Lock the account and revoke all active sessions immediately','Contact the user via phone to confirm — do NOT use email','Audit all actions taken during the Romanian session — full trail required'],
        logs:['IdP (Okta/Azure AD): sign-in logs for m.jones — geo, IP, device','Application logs: every action performed in each session','Email: check for new forwarding rules or OAuth grants added in the Romanian session'],
        escalate:true, escalation:'Yes — confirmed impossible travel from untrusted location. Escalate immediately.' }
    ]
  },
  {
    type: 'Privileged Account Misuse', icon: '👑',
    variants: [
      { sev:'HIGH', title:'Domain admin interactive logon on workstation',
        what:'Domain Administrator account logged in interactively to WORKSTATION-023 at 14:32 UTC. Policy explicitly prohibits DA interactive logons on workstations. No change window open.',
        interpretation:'Policy violation. Either an admin bypassed controls manually, or an attacker is using a stolen Domain Admin credential. Both scenarios require investigation.',
        actions:['Confirm with the team: was a legitimate admin working on WORKSTATION-023 at 14:32?','If unconfirmed — treat as potential DA compromise and escalate immediately','Review all commands executed under the DA account during this session'],
        logs:['Windows Security EventID 4624 (LogonType 2 = interactive)','PowerShell Script Block Logging: commands executed during the session','Sysmon EventID 1: process tree under the DA context during the logon window'],
        escalate:false, escalation:'Escalate immediately if the logon cannot be confirmed as legitimate by a known admin.' },
      { sev:'MEDIUM', title:'Service account used for interactive logon',
        what:'"svc-monitoring" authenticated interactively on three different servers over 20 minutes. This account is configured for unattended service use only and has never had interactive logons before.',
        interpretation:'Service accounts should never be used interactively. This could indicate an attacker using a harvested service account credential to move laterally.',
        actions:['Verify if any scheduled maintenance could explain this activity','Check the originating IPs for the three interactive sessions','Review what was done on each server during the session windows'],
        logs:['Windows Security EventID 4624: LogonType 2 for svc-monitoring','PowerShell and CMD history on the three affected servers','AD audit: recent changes to the svc-monitoring account'],
        escalate:false, escalation:'Escalate if sessions cannot be attributed to a known maintenance activity.' }
    ]
  },
];

/* ════════════════════════════════════════════════════
   DATA — IR PLAYBOOKS
════════════════════════════════════════════════════ */
const IR_PLAYBOOKS = [
  { id:'phishing', title:'Phishing Incident', icon:'🎣', severity:'HIGH',
    tags:['Email','Credential Harvest','User Reported'],
    detect:['Email gateway alert or user-reported suspicious email','Verify sender domain vs expected — look for look-alike domains','Analyze headers: SPF, DKIM, DMARC alignment results','Check embedded link reputation and domain registration date','Hash any attachment against threat intel feeds','Identify how many users received, opened, or clicked'],
    contain:['Remove the email from all mailboxes via admin console','Block sender domain and all embedded URLs at email gateway and proxy','Reset credentials for any user who entered data on a phishing page','Force MFA re-enrollment if credentials may have been phished','Isolate any endpoint where an attachment was opened and executed'],
    eradicate:['Block all IOCs across all perimeter controls','Scan endpoints that opened attachments for installed artifacts','Audit OAuth app grants, email forwarding rules, and added delegates','Remove any persistence discovered during investigation'],
    recover:['Restore access after credential reset and MFA re-enrollment','Verify no data exfiltration occurred during the compromise window','Confirm email filters are updated with new indicators','Monitor affected accounts for 14+ days for anomalous activity'],
    lessons:['Were email filters insufficient? Update detection rules.','Did users report quickly? Reinforce reporting procedure.','How fast were credentials reset? Define an SLA.','Add this scenario to the next phishing simulation campaign.'] },

  { id:'endpoint', title:'Compromised Endpoint', icon:'💻', severity:'CRITICAL',
    tags:['EDR','Malware','Containment'],
    detect:['EDR alert: suspicious process execution, file modification, network beacon','Abnormal parent-child process (e.g. Word spawning PowerShell)','Outbound connection to known malicious C2 infrastructure','User reports system behaving unexpectedly','New scheduled tasks, services, or registry run keys created'],
    contain:['Network-isolate via EDR quarantine — do NOT just reboot','Capture volatile data: processes, connections, loaded modules','Preserve a memory dump before any remediation action','Disable the affected user account temporarily','Identify and preserve a disk image for forensic analysis'],
    eradicate:['Re-image from a known-good baseline — do not attempt manual cleaning','Remove all persistence mechanisms on affected and related systems','Reset all credentials that may have been cached or used from this system','Patch the vulnerability or entry point that caused the compromise'],
    recover:['Restore from a verified, pre-infection backup','Re-enroll user with fresh credentials and MFA device','Monitor the restored system closely for 14+ days','Confirm no lateral movement occurred from this endpoint'],
    lessons:['What was the initial infection vector? Patch or block it.','Did EDR alert in time? Review rule coverage.','Is re-imaging faster than attempted cleanup? Update the runbook.','Are backups available and tested? Confirm schedule.'] },

  { id:'login', title:'Suspicious Login', icon:'🔐', severity:'HIGH',
    tags:['Authentication','Account','Geo-Anomaly'],
    detect:['Login from an unusual or unexpected geolocation','Impossible travel: same account in two distant locations within minutes','Login outside of the user\'s normal hours','Account accessing a sensitive system it rarely uses','Multiple failed attempts followed by a successful authentication','MFA challenge not triggered when it should have been'],
    contain:['Lock the account and invalidate all active sessions immediately','Block the source IP at the perimeter firewall','Notify the user via an out-of-band channel (phone, not email)','Preserve all authentication logs for the past 30+ days'],
    eradicate:['Force a full password reset with a strong random value','Re-enroll MFA from a verified, trusted device','Audit for persistence: email rules, OAuth app grants, added admins','Review every action taken during the suspicious session'],
    recover:['Re-enable account only after direct user verification','Implement conditional access policy for this user type','Monitor account for 14+ days for re-compromise signs'],
    lessons:['Was MFA enforced? Why was it bypassed or absent?','Were geo-anomaly alerts configured? Tune the detection rule.','Review detection-to-lockout time — does it meet your SLA?','Consider step-up authentication for high-sensitivity resources.'] },

  { id:'malware', title:'Malware Infection', icon:'🦠', severity:'CRITICAL',
    tags:['AV','EDR','Endpoint'],
    detect:['AV/EDR detection — cross-reference detection name with threat intel','Unexpected process spawning, file creation, or registry modification','Network beacon or C2 communication (periodic, small payload)','CPU/memory spike with no operational explanation','New files in startup locations: AppData, Temp, Run registry keys'],
    contain:['Immediately isolate the infected host — EDR quarantine or physical disconnect','Do NOT reboot until memory is preserved','Identify the entry vector: email, web download, USB, lateral movement','Disable admin shares (C$, ADMIN$) in the affected network segment','Check if the malware has worm/self-propagation capability'],
    eradicate:['Re-image — do not attempt manual cleanup for serious infections','Block all identified IOCs across all security controls','Scan every system on the same subnet for lateral spread','Remove all persistence mechanisms found','Patch the initial infection vector before bringing systems back online'],
    recover:['Restore from a pre-infection backup — verify backup integrity first','Validate clean state with EDR scan before returning to production','Monitor for 14+ days for re-infection or missed persistence'],
    lessons:['Was the malware blocked or only detected? Review AV enforcement policy.','What was the initial vector? Update filters.','How fast was isolation? Target under 15 minutes from detection.','Were backups accessible and verified clean?'] },

  { id:'lateral', title:'Lateral Movement', icon:'↔', severity:'CRITICAL',
    tags:['SMB','RDP','Credential','Spread'],
    detect:['Unusual SMB or RDP connections between workstations (peer-to-peer, not client-server)','Pass-the-Hash or Pass-the-Ticket indicators in EDR/Sysmon','Admin share access (C$, ADMIN$) from a non-admin workstation','New local admin accounts appearing on multiple systems simultaneously','Sysmon EventID 3: unexpected network connections from non-admin processes'],
    contain:['Segment the affected subnet — block SMB (445) and RDP (3389) between workstations at switch level','Disable compromised accounts immediately','Identify all systems the attacker has accessed — treat each as compromised','Reset KRBTGT password twice (60 minutes apart) to invalidate all Kerberos tickets'],
    eradicate:['Treat all systems in the affected segment as potentially compromised','Remove attacker tools (PsExec artifacts, Mimikatz, implants) from all systems','Reset all privileged credentials across the environment','Review and harden firewall rules between segments'],
    recover:['Rebuild affected systems from clean images','Restore and monitor all accounts','Validate that network segmentation is enforced and effective'],
    lessons:['Was segmentation blocking lateral SMB/RDP? It should be.','Were privileged accounts used on workstations? Eliminate this practice.','Was detection fast enough? Review lateral movement detection rules.','Consider host firewall GPO to block workstation-to-workstation SMB.'] },

  { id:'dataleak', title:'Data Leak Suspicion', icon:'📤', severity:'HIGH',
    tags:['DLP','Exfiltration','Insider'],
    detect:['DLP alert: sensitive data transferred to personal storage or external destination','Unusual outbound volume: large files, bulk uploads, off-hours transfers','Personal cloud storage accessed from corporate endpoints','Email with large attachments to personal or external addresses','Mass file access, staging in Temp folder, archive creation, USB writes'],
    contain:['Preserve forensic evidence BEFORE taking any action visible to the user','Block the specific exfiltration channel at the web proxy','Revoke access to sensitive data stores','Do NOT alert the user if insider threat is suspected — escalate to HR and Legal first'],
    eradicate:['Determine full scope: what data, how much, where it went','Revoke all access: email, VPN, workstation, cloud applications','Identify and close the access control gaps that enabled this'],
    recover:['Assess whether breach notification is required under applicable regulations','Notify Legal, Compliance, and management of full data scope','Implement controls to prevent recurrence (DLP tuning, cloud proxy rules)'],
    lessons:['Were DLP policies tuned to catch this pattern? Update them.','What access controls could have limited the blast radius?','Was the off-boarding process followed? Enforce it proactively.','Document the evidence chain of custody from the start.'] },

  { id:'ransomware', title:'Ransomware', icon:'🔒', severity:'CRITICAL',
    tags:['Ransomware','Encryption','Critical','Backups'],
    detect:['EDR: mass file modification, shadow copy deletion, ransom note creation','vssadmin.exe or wbadmin.exe deleting backups — treat as maximum urgency','Sysmon: high-volume file renames/rewrites in a very short time window','User reports: files have unknown extensions and are inaccessible','CPU spike with high disk I/O across multiple systems simultaneously'],
    contain:['IMMEDIATE: isolate every affected system — unplug network if necessary','Identify patient zero and the full scope of affected systems','Disable admin shares and SMB broadly across the environment','Preserve a memory dump on any running system for encryption key recovery','Do NOT pay the ransom without executive and legal approval'],
    eradicate:['Re-image all affected systems — no exceptions, no partial cleaning','Identify and patch the initial entry vector BEFORE restoring anything','Rotate all credentials across the environment','Scan every system that was online during the incident'],
    recover:['Verify backup integrity BEFORE restoring — confirm backups are not encrypted','Restore from the last known-clean backup','Bring systems online one at a time with enhanced monitoring','Validate data integrity post-restoration before handing back to business'],
    lessons:['Were backups isolated, tested, and immutable? Make this mandatory.','What was the entry vector? Phishing, exposed RDP, unpatched vulnerability?','Did EDR attempt to block file encryption? Review policy.','When was the last full restore test? Schedule a drill.'] },

  { id:'insider', title:'Insider Threat', icon:'👁', severity:'HIGH',
    tags:['Insider','HR','Evidence','DLP'],
    detect:['DLP: large data staging or transfer, especially near resignation or disciplinary action','Unusual bulk access to sensitive files outside the user\'s normal role','After-hours access to sensitive systems','Personal cloud sync enabled on a corporate endpoint','Awareness of upcoming termination, grievance, or investigation — triggers heightened monitoring'],
    contain:['Preserve forensic evidence FIRST — do not touch the suspect\'s system before imaging','Do NOT alert the employee — coordinate all actions with HR and Legal','Silently restrict additional access where possible without raising suspicion','Collect all relevant audit logs: DLP, AD, email, cloud, VPN, badge records'],
    eradicate:['Revoke all access simultaneously on the HR-coordinated action date','Retrieve all corporate devices immediately','Audit all data repositories the individual had access to','File abuse reports with any cloud services where data was uploaded'],
    recover:['Conduct access review across the team — tighten least-privilege assignments','Assess whether data exposure warrants breach notification','Brief leadership with the full scope of data involved'],
    lessons:['Was there a data retention review when departure was flagged? Implement it.','Did access rights exceed what the role required? Conduct regular access reviews.','Were UBA/UEBA tools available to surface the anomalous pattern earlier?','Review the off-boarding checklist — include access revocation timelines.'] },
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
    'LinkedIn / company website: org chart, usernames, email format, tech stack from job postings',
    'GitHub / GitLab: search for hardcoded secrets, internal code, old credentials, config files',
    'Certificate transparency logs: crt.sh for all subdomains across all issued certs',
    'Web archive (Wayback Machine): old endpoints, removed pages, past technology choices',
    'Cloud asset discovery: common S3 bucket names (target-backup, target-dev, target-prod)',
    'Email harvesting: Hunter.io, Phonebook.cz, theHarvester for email format discovery',
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
      ['6379','Redis','No authentication? Remote code via CONFIG SET commands?'],
      ['8080 / 8443','HTTP Alt','Admin consoles, dev servers, internal APIs, reverse proxies.'],
      ['9200','Elasticsearch','No auth? Full data access? Write access (ransomware vector)?'],
      ['27017','MongoDB','No authentication? Guest/anonymous access to all databases?'],
    ]
  },
  { title:'Web Testing Checklist (OWASP Top 10)', type:'list', items:[
    'A01 Broken Access Control — Test IDOR: change IDs in requests. Forced browsing to /admin, /config. Role escalation by modifying request parameters.',
    'A02 Cryptographic Failures — HTTPS enforced? HSTS? TLS 1.2+ only? Sensitive data (passwords, tokens) returned in cleartext responses or URLs?',
    'A03 Injection — SQLi (error-based, blind, time-based, UNION), NoSQLi, LDAP injection, OS command injection in file upload/export functions, SSTI.',
    'A04 Insecure Design — Missing rate limiting on login/OTP/API. Price/quantity manipulation in e-commerce flows. Logic flaws allowing step-skipping.',
    'A05 Security Misconfiguration — Default credentials, debug mode enabled, verbose error messages with stack traces, CORS wildcard (*), unnecessary HTTP methods.',
    'A06 Vulnerable Components — Identify framework and library versions. Run Nuclei templates. Check JS libraries with Retire.js. CVE lookup.',
    'A07 Auth & Session Failures — No lockout (brute force). Session token entropy. Cookie flags: Secure, HttpOnly, SameSite. Session invalidated on logout?',
    'A08 Software Integrity Failures — Unvalidated package updates? CDN scripts without Subresource Integrity (SRI)? Secrets in environment variables or CI logs?',
    'A09 Logging Failures — Can you generate an auth event with no log entry? Do error messages reveal internal paths, credentials, or database schema?',
    'A10 SSRF — User-supplied URLs in import, webhook, or fetch functions. Test 127.0.0.1, 169.254.169.254 (AWS metadata), internal subnet addresses.',
  ]},
  { title:'SQL Injection Indicators', type:'list', items:[
    "Single quote: ' — SQL syntax error in response reveals database type and query structure",
    "Auth bypass: ' OR '1'='1'-- or admin'-- or ' OR 1=1#",
    "Time-based blind (MySQL): ' AND SLEEP(5)-- — observe 5-second delay in response",
    "Time-based blind (MSSQL): '; WAITFOR DELAY '0:0:5'--",
    "Boolean-based: ' AND 1=1-- (true, normal response) vs ' AND 1=2-- (false, different response)",
    "UNION-based: ' UNION SELECT NULL,NULL,NULL-- — increment NULLs until no type error",
    "Error messages to look for: ORA-01756 (Oracle), You have an error in your SQL (MySQL), Unclosed quotation (MSSQL)",
    "SQLMap quick start: sqlmap -u 'http://target/page?id=1' --dbs --batch",
  ]},
  { title:'XSS Indicators', type:'list', items:[
    '<script>alert(document.domain)</script> — basic reflected XSS test',
    '"><script>alert(1)</script> — attribute break-out test',
    '"><img src=x onerror=alert(1)> — event handler injection without script tags',
    '<svg onload=alert(1)> — SVG vector, often bypasses filters that block script tags',
    'javascript:alert(1) in href or action attributes — URL context injection',
    'DOM XSS: check JS source for document.write, innerHTML, eval with user-controlled input',
    'Stored XSS signs: input persists in page after refresh, especially in admin views or reports',
    'Filter bypass techniques: mixed case, HTML entities, Unicode encoding, event handler variants',
    'Testing tool: Dalfox — dalfox url target/search?q=XSS',
  ]},
  { title:'Authentication Weaknesses', type:'list', items:[
    'No account lockout: attempt 100 logins — if no lockout, CAPTCHA, or rate limit, brute force is viable',
    'Username enumeration: compare response time and message for valid vs. invalid usernames',
    'Default credentials: admin/admin, admin/password, root/root, test/test — plus application-specific defaults',
    'Weak reset tokens: timestamp-based, sequential, or tokens that never expire',
    'Password reset tokens in URL: leak via referrer headers, browser history, and server logs',
    'Session not invalidated on logout: save the token before logout, try it after — if it works, it is a bug',
    'Missing cookie flags: Secure (cleartext transmission), HttpOnly (JS access), SameSite (CSRF)',
    'MFA bypass: can MFA be skipped by replaying a request or removing a parameter?',
    'OAuth misconfigurations: state parameter missing (CSRF), open redirect in redirect_uri, token leakage in referrer',
  ]},
  { title:'Privilege Escalation (Linux)', type:'list', items:[
    'id && whoami && hostname && uname -a — baseline identity and OS version',
    'sudo -l — check what current user can run with sudo; look for (ALL) or NOPASSWD entries',
    'find / -perm -4000 -type f 2>/dev/null — SUID binaries, cross-reference with GTFOBins',
    'crontab -l && cat /etc/cron* && ls -la /etc/cron* — check for writable cron scripts',
    'find / -writable -not -path "/proc/*" -type f 2>/dev/null — writable files outside /proc',
    'cat /etc/passwd — look for interactive users with writable home directories',
    'env && cat ~/.bashrc ~/.bash_history — check PATH and command history',
    'ps aux && ss -tulpn — running processes and listening services',
    'NFS no_root_squash: showmount -e target — mount and place a SUID binary',
    'Kernel exploits: uname -r — searchsploit or check against known CVE database',
  ]},
  { title:'Enumeration (Linux)', type:'list', items:[
    'id && whoami && uname -a — identity, OS version, kernel',
    'cat /etc/passwd | grep -v nologin — enumerate users with interactive shell access',
    'find / -perm -4000 2>/dev/null — SUID files',
    'find / -perm -2000 2>/dev/null — SGID files',
    'crontab -l && ls -la /etc/cron* — all scheduled tasks',
    'ss -tulpn || netstat -tulpn — listening ports and services',
    'ps aux — all running processes',
    'ls -la /home/* — other user home directories',
    'cat /etc/hosts && cat /etc/resolv.conf — network and DNS config',
    'find / -name "*.conf" -readable 2>/dev/null | head -20 — readable config files',
    'find / -name "id_rsa" -readable 2>/dev/null — readable SSH private keys',
  ]},
  { title:'Enumeration (Windows)', type:'list', items:[
    'whoami /all — user, all groups, all assigned privileges',
    'net user && net localgroup Administrators — local users and admin group members',
    'systeminfo — OS version, patch level, hotfixes installed',
    'ipconfig /all && netstat -ano — network config and all connections with PIDs',
    'tasklist /svc — all processes with associated services',
    'sc query state= all — full service list',
    'reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run — startup entries',
    'dir /s /b C:\\Users\\*.txt *.config *.ini 2>nul — search for credential files',
    'wmic product get name,version — installed software and versions',
    'net share && net use — shared resources and current connections',
    'PS: Get-ScheduledTask | Where State -ne Disabled — active scheduled tasks',
  ]},
  { title:'Reporting Reminders', type:'list', items:[
    'Write for two audiences: executive summary (no jargon) AND technical detail (full evidence)',
    'Every finding: Title, Severity, Description, Evidence/Screenshot, Impact, Recommendation',
    'Screenshot every finding with a visible timestamp — metadata alone is not sufficient',
    'Rate findings consistently: CRITICAL / HIGH / MEDIUM / LOW / INFO with defined criteria',
    'Separate quick wins (patch this today) from strategic recommendations (re-architect this)',
    'Reference CVE and CWE numbers where applicable — adds credibility and searchability',
    'PoC commands should be precise and reproducible — vague descriptions are rejected',
    'Executive summary: pure business-risk language, 1 page maximum, no technical jargon',
    'Recommendations must be specific: not "fix SQL injection" but "use parameterized queries in login.php line 47"',
    'Include scope confirmation, methodology, limitations, and any out-of-scope findings you noticed',
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
      ['Firewall / Network','Blocked outbound to rare IPs, new allow rules, lateral movement on 445/3389','Source IP, dest IP, dest port, action (allow/deny), bytes transferred'],
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
    { label:'Failed logons (Windows)',         code:'EventID=4625 AND LogonType=3' },
    { label:'Explicit credential logon',        code:'EventID=4648' },
    { label:'Kerberos ticket requests',         code:'EventID=4768 OR EventID=4769' },
    { label:'Process creation (Sysmon)',        code:'EventID=1 AND Image=*powershell.exe*' },
    { label:'LSASS memory access (Sysmon)',     code:'EventID=10 AND TargetImage=*lsass.exe*' },
    { label:'Encoded PowerShell command',       code:'CommandLine=*-EncodedCommand* OR CommandLine=*-enc *' },
    { label:'Base64 payload indicators',        code:'CommandLine=*JAB* OR CommandLine=*TVqQ* OR CommandLine=*SQBF*' },
    { label:'Suspicious parent process',        code:'ParentImage=*WINWORD.EXE* AND Image=*powershell.exe*' },
    { label:'DNS NXDOMAIN storm (Splunk)',       code:'sourcetype=dns answer_type=NXDOMAIN | stats count by src_ip' },
    { label:'Large outbound transfer',          code:'bytes_out > 104857600' },
    { label:'Outbound on suspicious port',      code:'dest_port IN (4444, 1337, 31337, 8888, 6666, 9001)' },
    { label:'Shadow copy deletion',             code:'CommandLine=*vssadmin* AND CommandLine=*delete*' },
    { label:'New service installed',            code:'EventID=7045' },
    { label:'Scheduled task created',           code:'EventID=4698' },
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
    'What would have to be true for this to be a false positive? Does that scenario hold up?',
    'If we act on this now and we are wrong, what is the impact on the business?',
    'Who else could have been affected that we have not yet checked?',
    'What attacker objective does this behavior most likely represent in the attack lifecycle?',
  ]},
];

/* ════════════════════════════════════════════════════
   DATA — GOVERNANCE SECTIONS
════════════════════════════════════════════════════ */
const GOV_SECTIONS = [
  { title:'Risk Formula & Scoring', type:'formula',
    content:'Risk = Likelihood × Impact',
    table:{ cols:['Score','Likelihood','Impact'],
      rows:[
        ['1','Rare (once every 5+ years)','Negligible — no meaningful damage or disruption'],
        ['2','Unlikely (once every 1–5 years)','Minor — limited, quickly recoverable impact'],
        ['3','Possible (once per year)','Moderate — significant disruption or data exposure'],
        ['4','Likely (several times per year)','Major — serious harm, financial or reputational loss'],
        ['5','Almost Certain (monthly or more)','Catastrophic — irreversible damage, regulatory consequences'],
      ]
    },
    risk_matrix:{ ranges:[
      { range:'1–5', level:'LOW', color:'low' },
      { range:'6–12', level:'MEDIUM', color:'medium' },
      { range:'13–19', level:'HIGH', color:'high' },
      { range:'20–25', level:'CRITICAL', color:'critical' },
    ]}
  },
  { title:'Asset Classification', type:'asset', items:[
    { label:'Public',       cls:'public',       desc:'Freely available. Disclosure causes no harm. Examples: marketing website, press releases, public job listings.' },
    { label:'Internal',     cls:'internal',     desc:'Business use only. Limited impact if disclosed externally. Examples: internal wikis, org charts, non-sensitive procedures.' },
    { label:'Confidential', cls:'confidential', desc:'Restricted access. Significant impact if disclosed. Examples: PII, financial records, credentials, client data, incident reports.' },
    { label:'Secret',       cls:'secret',       desc:'Highly restricted. Severe damage if disclosed. Examples: M&A data, cryptographic keys, strategic plans, legal findings.' },
  ]},
  { title:'Audit Reminders', type:'list', items:[
    'Logging: All significant actions must be logged. Logs should be tamper-evident and stored separately from the systems they monitor.',
    'Traceability: Every action must be attributable to an individual account — no shared credentials, no non-repudiable accounts.',
    'Least Privilege: Every user and service account has the minimum access required and nothing more. Review at least quarterly.',
    'Change Tracking: All production changes go through an approved, documented change management process — no ad-hoc changes.',
    'Access Reviews: Periodic review (minimum quarterly) of who has access to what, especially privileged and service accounts.',
    'Separation of Duties: No single person can initiate and approve a sensitive transaction or change without a second reviewer.',
    'Backup Verification: Backups are only as good as the last successful restore test. Untested backups do not count.',
  ]},
  { title:'Documentation Principles', type:'list', items:[
    'Write for the person responding at 3am who has zero context — be specific and assume nothing.',
    'Every finding must include: date, time, exact system hostname, username, and the exact log entry or command.',
    'Describe what you found, not just what you did. The significance of a finding must be stated explicitly.',
    'Assume your notes may be read in a legal or regulatory proceeding — write with that standard in mind.',
    'Chain of custody: document when, who, how, and with what tool evidence was collected.',
    'Use absolute paths, full hostnames, and real UTC timestamps — never relative references like "yesterday" or "the server".',
    'Do not delete old notes even if they turn out to be wrong — annotate and correct them instead.',
    'Screenshots should show timestamps — metadata alone is not legally sufficient in most jurisdictions.',
  ]},
];

/* ════════════════════════════════════════════════════
   NAVIGATION
════════════════════════════════════════════════════ */
const PAGES = ['dashboard','triage','ir','pentest','investigation','notes','todo','governance','settings'];

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
  const utcStr = `${p(now.getUTCHours())}:${p(now.getUTCMinutes())}:${p(now.getUTCSeconds())} UTC`;
  const clockEl = document.getElementById('sb-clock');
  if (clockEl) clockEl.textContent = utcStr;
  const dateEl = document.getElementById('dash-date');
  if (dateEl) {
    const opts = { weekday:'long', month:'long', day:'numeric', year:'numeric' };
    dateEl.textContent = now.toLocaleDateString('en-US', opts) + '  ·  ' + utcStr;
  }
}
setInterval(updateClock, 1000);
updateClock();

/* ════════════════════════════════════════════════════
   SIDEBAR TOGGLE
════════════════════════════════════════════════════ */
document.getElementById('sb-toggle').addEventListener('click', () => {
  const sidebar = document.getElementById('sidebar');
  const collapsed = sidebar.classList.toggle('collapsed');
  document.body.classList.toggle('sidebar-collapsed', collapsed);
  const pref = document.getElementById('pref-collapsed');
  if (pref) pref.checked = collapsed;
  const s = LS.get('settings', {});
  s.collapsed = collapsed;
  LS.set('settings', s);
});

/* ════════════════════════════════════════════════════
   DASHBOARD
════════════════════════════════════════════════════ */
function initDashboard() {
  const focusEl = document.getElementById('today-focus');
  focusEl.value = LS.get('focus', '');
  focusEl.addEventListener('input', () => debounceSave('focus', () => {
    LS.set('focus', focusEl.value);
    showToast('Saved', 'ok');
  }));

  const caseIds = ['case-title','case-severity','case-status','case-date','case-owner'];
  const savedCase = LS.get('case', {});
  caseIds.forEach(id => {
    const el = document.getElementById(id);
    const key = id.replace('case-','');
    if (savedCase[key] !== undefined) el.value = savedCase[key];
    el.addEventListener('input',  saveCase);
    el.addEventListener('change', saveCase);
  });

  function saveCase() {
    const data = {};
    caseIds.forEach(id => { data[id.replace('case-','')] = document.getElementById(id).value; });
    debounceSave('case', () => { LS.set('case', data); showToast('Saved', 'ok'); });
  }

  updateDashboard();
}

function updateDashboard() {
  const todos = LS.get('todos', []);
  const pending = todos.filter(t => !t.done)
    .sort((a,b) => ({high:0,medium:1,low:2}[a.priority] - {high:0,medium:1,low:2}[b.priority]));
  const dtl = document.getElementById('dash-task-list');
  if (dtl) {
    if (pending.length === 0) {
      dtl.innerHTML = '<div class="empty-msg">No pending tasks.</div>';
    } else {
      dtl.innerHTML = pending.slice(0,5).map(t =>
        `<div class="mini-task">
          <span class="mini-task-priority task-priority ${t.priority}">${t.priority}</span>
          <span>${escHtml(t.text)}</span>
          ${t.due ? `<span class="task-due" style="margin-left:auto">${t.due}</span>` : ''}
        </div>`).join('') +
        (pending.length > 5 ? `<div class="empty-msg" style="margin-top:4px">+${pending.length-5} more…</div>` : '');
    }
  }

  const alerts = LS.get('alerts', []);
  const dla = document.getElementById('dash-last-alert');
  if (dla) {
    if (alerts.length === 0) {
      dla.innerHTML = '<div class="empty-msg">No alerts generated yet.</div>';
    } else {
      const a = alerts[0];
      const ts = new Date(a.ts).toLocaleTimeString('en-US',{hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'});
      dla.innerHTML = `
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap">
          <span>${a.icon}</span>
          <span style="font-weight:600;color:var(--text-bright);font-size:13px">${escHtml(a.type)}</span>
          <span class="sev-badge ${a.sev}">${a.sev}</span>
          <span class="alert-ts" style="margin-left:auto">${ts}</span>
        </div>
        <div style="font-size:12.5px;color:var(--text);line-height:1.5">${escHtml(a.what)}</div>`;
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
   SOC TRIAGE
════════════════════════════════════════════════════ */
function initTriage() {
  renderAlerts(LS.get('alerts', []));

  document.getElementById('btn-new-alert').addEventListener('click', generateAlert);
  document.getElementById('btn-clear-alerts').addEventListener('click', () => {
    if (!confirm('Clear all alerts? This cannot be undone.')) return;
    LS.set('alerts', []);
    renderAlerts([]);
    updateDashboard();
  });

  document.getElementById('sev-filters').addEventListener('click', e => {
    const btn = e.target.closest('.sev-filter');
    if (!btn) return;
    document.querySelectorAll('.sev-filter').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    renderAlerts(LS.get('alerts', []));
  });

  document.getElementById('alert-feed').addEventListener('click', e => {
    const btn = e.target.closest('.alert-dismiss');
    if (!btn) return;
    const updated = LS.get('alerts', []).filter(a => a.id !== btn.dataset.id);
    LS.set('alerts', updated);
    renderAlerts(updated);
    updateDashboard();
  });
}

function generateAlert() {
  const template = rand(ALERT_TEMPLATES);
  const variant  = rand(template.variants);
  const alert = {
    id: Date.now() + '-' + Math.random().toString(36).slice(2,6),
    type: template.type, icon: template.icon,
    sev: variant.sev, title: variant.title,
    what: variant.what, interpretation: variant.interpretation,
    actions: variant.actions, logs: variant.logs,
    escalate: variant.escalate, escalation: variant.escalation,
    ts: new Date().toISOString()
  };
  const alerts = LS.get('alerts', []);
  alerts.unshift(alert);
  LS.set('alerts', alerts);
  renderAlerts(alerts);
  updateDashboard();
  showToast(`${alert.sev} alert generated`, (alert.sev === 'CRITICAL' || alert.sev === 'HIGH') ? 'err' : 'ok');
}

function renderAlerts(alerts) {
  const filter = document.querySelector('.sev-filter.active')?.dataset.sev || 'ALL';
  const feed = document.getElementById('alert-feed');
  const empty = document.getElementById('alert-empty');
  feed.querySelectorAll('.alert-card').forEach(c => c.remove());
  updateSevCounts(alerts);
  updateTriageBadge(alerts);
  if (alerts.length === 0) { empty.style.display = ''; return; }
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
        <div class="alert-section-label">What happened</div>
        <div class="alert-what">${escHtml(a.what)}</div>
      </div>
      <div class="alert-section">
        <div class="alert-section-label">Initial interpretation</div>
        <div class="alert-interpretation">${escHtml(a.interpretation)}</div>
      </div>
      <div class="alert-section">
        <div class="alert-section-label">First 3 actions</div>
        <ul class="alert-actions-list">${a.actions.map((ac,i) =>
          `<li><span class="action-num">${i+1}</span><span>${escHtml(ac)}</span></li>`).join('')}</ul>
      </div>
      <div class="alert-section">
        <div class="alert-section-label">Logs to check</div>
        <ul class="alert-logs-list">${a.logs.map(l => `<li>${escHtml(l)}</li>`).join('')}</ul>
      </div>
      <div class="alert-section">
        <div class="alert-section-label">Escalation</div>
        <div class="alert-escalate ${a.escalate ? 'yes' : 'no'}">${a.escalate ? '⚠ ' : '✓ '}${escHtml(a.escalation)}</div>
      </div>
    </div>`;
  return div;
}

function updateSevCounts(alerts) {
  const c = {ALL:alerts.length, CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0};
  alerts.forEach(a => { if (c[a.sev] !== undefined) c[a.sev]++; });
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
    const ph = phase => `
      <div class="pb-phase pb-phase-${phase}">
        <div class="pb-phase-hdr">${phase.charAt(0).toUpperCase() + phase.slice(1)}</div>
        <ul>${pb[phase].map(s => `<li>${escHtml(s)}</li>`).join('')}</ul>
      </div>`;
    card.innerHTML = `
      <div class="acc-header">
        <div class="acc-header-left">
          <span class="acc-icon">${pb.icon}</span>
          <div class="acc-title-block">
            <div class="acc-title">${escHtml(pb.title)}</div>
            <div class="acc-tags">${pb.tags.map(t => `<span class="acc-tag">${escHtml(t)}</span>`).join('')}</div>
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
   GOVERNANCE
════════════════════════════════════════════════════ */
function initGovernance() {
  const container = document.getElementById('gov-list');
  GOV_SECTIONS.forEach(sec => {
    let body = '';
    if (sec.type === 'formula') {
      body = `<div class="risk-formula-block">${escHtml(sec.content)}</div>
        <table class="ref-table">
          <thead><tr>${sec.table.cols.map(c=>`<th>${escHtml(c)}</th>`).join('')}</tr></thead>
          <tbody>${sec.table.rows.map(r=>`<tr>${r.map(c=>`<td>${escHtml(c)}</td>`).join('')}</tr>`).join('')}</tbody>
        </table>
        <div class="risk-matrix" style="margin-top:12px">
          ${sec.risk_matrix.ranges.map(r=>`<span class="risk-band ${r.color}">${escHtml(r.range)}: ${escHtml(r.level)}</span>`).join('')}
        </div>`;
    } else if (sec.type === 'asset') {
      body = `<div class="asset-items">${sec.items.map(item =>
        `<div class="asset-item">
          <span class="asset-label ${item.cls}">${escHtml(item.label)}</span>
          <span class="asset-desc">${escHtml(item.desc)}</span>
        </div>`).join('')}</div>`;
    } else {
      body = `<ul class="ref-list-items">${sec.items.map(i=>`<li>${escHtml(i)}</li>`).join('')}</ul>`;
    }
    container.appendChild(buildRefCard(sec.title, body, true));
  });
}

/* ── Shared ref card builder ──────────────────────────────── */
function buildRefCard(title, bodyHtml, startOpen = false) {
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
  const onCopied = () => { code.classList.add('copied'); showToast('Copied', 'ok'); setTimeout(() => code.classList.remove('copied'), 2000); };
  if (navigator.clipboard) { navigator.clipboard.writeText(text).then(onCopied).catch(onCopied); }
  else { try { const ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta); onCopied(); } catch {} }
});

/* ════════════════════════════════════════════════════
   NOTES
════════════════════════════════════════════════════ */
function initNotes() {
  const titleEl = document.getElementById('notes-title');
  const bodyEl  = document.getElementById('notes-body');
  titleEl.value = LS.get('notes_title', '');
  bodyEl.value  = LS.get('notes_body', '');
  titleEl.addEventListener('input', () => debounceSave('notes_title', () => { LS.set('notes_title', titleEl.value); showToast('Saved', 'ok'); }));
  bodyEl.addEventListener('input',  () => debounceSave('notes_body',  () => { LS.set('notes_body',  bodyEl.value);  showToast('Saved', 'ok'); }));

  ['ips','domains','hashes','users','hosts'].forEach(f => {
    const el = document.getElementById('ioc-' + f);
    el.value = LS.get('ioc_' + f, '');
    el.addEventListener('input', () => debounceSave('ioc_' + f, () => { LS.set('ioc_' + f, el.value); showToast('Saved', 'ok'); }));
  });

  renderTimeline();
  renderEvidence();

  document.getElementById('btn-add-timeline-entry').addEventListener('click', () => {
    document.getElementById('timeline-add-form').style.display = '';
    document.getElementById('timeline-entry-text').focus();
  });
  document.getElementById('btn-timeline-cancel').addEventListener('click', () => {
    document.getElementById('timeline-add-form').style.display = 'none';
    document.getElementById('timeline-entry-text').value = '';
  });
  document.getElementById('btn-timeline-submit').addEventListener('click', submitTimeline);
  document.getElementById('timeline-entry-text').addEventListener('keydown', e => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) submitTimeline();
  });

  document.getElementById('btn-add-evidence').addEventListener('click', () => {
    document.getElementById('evidence-add-form').style.display = '';
    document.getElementById('ev-source').focus();
  });
  document.getElementById('btn-ev-cancel').addEventListener('click', () => {
    document.getElementById('evidence-add-form').style.display = 'none';
    document.getElementById('ev-source').value = '';
    document.getElementById('ev-notes').value = '';
  });
  document.getElementById('btn-ev-submit').addEventListener('click', submitEvidence);

  document.getElementById('btn-export-notes').addEventListener('click', exportNotes);
  document.getElementById('btn-clear-notes').addEventListener('click', () => {
    if (!confirm('Clear all notes, timeline, IoCs, and evidence? This cannot be undone.')) return;
    ['notes_title','notes_body','timeline','evidence','ioc_ips','ioc_domains','ioc_hashes','ioc_users','ioc_hosts'].forEach(k => LS.del(k));
    titleEl.value = ''; bodyEl.value = '';
    ['ips','domains','hashes','users','hosts'].forEach(f => { document.getElementById('ioc-'+f).value = ''; });
    renderTimeline(); renderEvidence();
    showToast('Notes cleared', 'ok');
  });
}

function submitTimeline() {
  const text = document.getElementById('timeline-entry-text').value.trim();
  if (!text) return;
  const entries = LS.get('timeline', []);
  entries.push({ id: Date.now().toString(), ts: new Date().toISOString(), text });
  LS.set('timeline', entries);
  renderTimeline();
  document.getElementById('timeline-entry-text').value = '';
  document.getElementById('timeline-add-form').style.display = 'none';
  showToast('Entry added', 'ok');
}

function renderTimeline() {
  const entries = LS.get('timeline', []);
  const list = document.getElementById('timeline-list');
  if (entries.length === 0) {
    list.innerHTML = '<div class="empty-msg">No entries yet. Add entries to track the investigation progression.</div>';
    return;
  }
  list.innerHTML = '';
  [...entries].reverse().forEach(entry => {
    const div = document.createElement('div');
    div.className = 'timeline-entry';
    const d = new Date(entry.ts);
    const ts = d.toLocaleDateString('en-US',{month:'short',day:'numeric'}) + ' ' +
               d.toLocaleTimeString('en-US',{hour12:false,hour:'2-digit',minute:'2-digit'});
    div.innerHTML = `<span class="tl-ts">${ts}</span><span class="tl-text">${escHtml(entry.text)}</span><button class="tl-del" data-id="${entry.id}" title="Delete">✕</button>`;
    div.querySelector('.tl-del').addEventListener('click', () => {
      LS.set('timeline', LS.get('timeline',[]).filter(e => e.id !== entry.id));
      renderTimeline();
    });
    list.appendChild(div);
  });
}

function submitEvidence() {
  const source = document.getElementById('ev-source').value.trim();
  const notes  = document.getElementById('ev-notes').value.trim();
  if (!source) return;
  const ev = LS.get('evidence', []);
  ev.push({ id: Date.now().toString(), source, notes, ts: new Date().toISOString() });
  LS.set('evidence', ev);
  renderEvidence();
  document.getElementById('ev-source').value = '';
  document.getElementById('ev-notes').value = '';
  document.getElementById('evidence-add-form').style.display = 'none';
  showToast('Evidence added', 'ok');
}

function renderEvidence() {
  const ev = LS.get('evidence', []);
  const list = document.getElementById('evidence-list');
  if (ev.length === 0) { list.innerHTML = '<div class="empty-msg">No evidence entries yet.</div>'; return; }
  list.innerHTML = '';
  ev.forEach(item => {
    const div = document.createElement('div');
    div.className = 'evidence-item';
    const ts = new Date(item.ts).toLocaleDateString('en-US',{month:'short',day:'numeric'}) + ' ' +
               new Date(item.ts).toLocaleTimeString('en-US',{hour12:false,hour:'2-digit',minute:'2-digit'});
    div.innerHTML = `<div class="ev-source">${escHtml(item.source)}</div>${item.notes ? `<div class="ev-notes">${escHtml(item.notes)}</div>` : ''}<div class="ev-ts">${ts}</div><button class="ev-del" data-id="${item.id}" title="Delete">✕</button>`;
    div.querySelector('.ev-del').addEventListener('click', () => {
      LS.set('evidence', LS.get('evidence',[]).filter(e => e.id !== item.id));
      renderEvidence();
    });
    list.appendChild(div);
  });
}

function exportNotes() {
  const lines = [];
  const L = s => lines.push(s);
  L('═══════════════════════════════════════════════════');
  L('ANALYST NOTES EXPORT');
  L('Exported: ' + new Date().toISOString());
  L('═══════════════════════════════════════════════════\n');
  const title = LS.get('notes_title','');
  if (title) L('CASE: ' + title + '\n');
  const body = LS.get('notes_body','');
  if (body) { L('─── INVESTIGATION NOTES ───'); L(body); L(''); }
  const timeline = LS.get('timeline',[]);
  if (timeline.length) {
    L('─── INVESTIGATION TIMELINE ───');
    timeline.forEach(e => L(`[${new Date(e.ts).toISOString().replace('T',' ').slice(0,19)} UTC] ${e.text}`));
    L('');
  }
  const fields = {ips:'IP Addresses',domains:'Domains',hashes:'Hashes',users:'Usernames',hosts:'Hostnames'};
  if (Object.keys(fields).some(f => LS.get('ioc_'+f,'').trim())) {
    L('─── INDICATORS OF COMPROMISE ───');
    Object.entries(fields).forEach(([f,label]) => {
      const v = LS.get('ioc_'+f,'').trim();
      if (v) { L(label + ':'); v.split('\n').forEach(x => L('  '+x)); L(''); }
    });
  }
  const evidence = LS.get('evidence',[]);
  if (evidence.length) {
    L('─── EVIDENCE TRACKER ───');
    evidence.forEach(e => {
      L(`[${new Date(e.ts).toISOString().replace('T',' ').slice(0,19)} UTC] SOURCE: ${e.source}`);
      if (e.notes) L('NOTES: ' + e.notes);
      L('');
    });
  }
  const blob = new Blob([lines.join('\n')], {type:'text/plain'});
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
  a.download = 'analyst-notes-' + new Date().toISOString().slice(0,10) + '.txt'; a.click();
  showToast('Notes exported', 'ok');
}

/* ════════════════════════════════════════════════════
   TO-DO
════════════════════════════════════════════════════ */
let todoSort   = 'priority';
let todoFilter = 'all';
const PRI = {high:0, medium:1, low:2};

function initTodo() {
  todoSort   = LS.get('todo_sort',   'priority');
  todoFilter = LS.get('todo_filter', 'all');
  document.querySelectorAll('.tc-btn[data-sort]').forEach(b => b.classList.toggle('active', b.dataset.sort === todoSort));
  document.querySelectorAll('.tc-btn[data-filter]').forEach(b => b.classList.toggle('active', b.dataset.filter === todoFilter));
  renderTodos();

  const inp = document.getElementById('todo-input');
  inp.addEventListener('keydown', e => { if (e.key === 'Enter') addTodo(); });
  document.getElementById('btn-add-todo').addEventListener('click', addTodo);

  document.querySelectorAll('.tc-btn[data-sort]').forEach(btn => btn.addEventListener('click', () => {
    document.querySelectorAll('.tc-btn[data-sort]').forEach(b => b.classList.remove('active'));
    btn.classList.add('active'); todoSort = btn.dataset.sort; LS.set('todo_sort', todoSort); renderTodos();
  }));
  document.querySelectorAll('.tc-btn[data-filter]').forEach(btn => btn.addEventListener('click', () => {
    document.querySelectorAll('.tc-btn[data-filter]').forEach(b => b.classList.remove('active'));
    btn.classList.add('active'); todoFilter = btn.dataset.filter; LS.set('todo_filter', todoFilter); renderTodos();
  }));

  document.getElementById('btn-clear-done').addEventListener('click', () => {
    if (!confirm('Remove all completed tasks?')) return;
    LS.set('todos', LS.get('todos',[]).filter(t => !t.done));
    renderTodos(); showToast('Completed tasks cleared', 'ok');
  });
}

function addTodo() {
  const inp = document.getElementById('todo-input');
  const text = inp.value.trim(); if (!text) return;
  const todos = LS.get('todos', []);
  todos.push({ id: Date.now().toString(), text, priority: document.getElementById('todo-priority').value,
    due: document.getElementById('todo-due').value, done: false, createdAt: new Date().toISOString() });
  LS.set('todos', todos);
  inp.value = ''; document.getElementById('todo-due').value = '';
  renderTodos(); updateDashboard(); showToast('Task added', 'ok'); inp.focus();
}

function sortTodos(arr) {
  const s = [...arr];
  if (todoSort === 'priority') s.sort((a,b) => (PRI[a.priority]-PRI[b.priority]) || a.createdAt.localeCompare(b.createdAt));
  else if (todoSort === 'due') s.sort((a,b) => { if(!a.due&&!b.due) return 0; if(!a.due) return 1; if(!b.due) return -1; return a.due.localeCompare(b.due); });
  else s.sort((a,b) => a.createdAt.localeCompare(b.createdAt));
  return s;
}

function renderTodos() {
  const all = LS.get('todos', []);
  document.getElementById('stat-total').textContent   = all.length;
  document.getElementById('stat-pending').textContent = all.filter(t=>!t.done).length;
  document.getElementById('stat-done').textContent    = all.filter(t=>t.done).length;
  const urgent = all.filter(t => !t.done && t.priority === 'high').length;
  document.getElementById('todo-badge').textContent = urgent > 0 ? urgent : '';
  const filtered = todoFilter === 'pending' ? all.filter(t=>!t.done) : todoFilter === 'done' ? all.filter(t=>t.done) : all;
  const sorted = sortTodos(filtered);
  const list = document.getElementById('todo-list');
  list.querySelectorAll('.task-item').forEach(el => el.remove());
  document.getElementById('todo-empty').style.display = sorted.length === 0 ? '' : 'none';
  sorted.forEach(t => list.appendChild(buildTaskItem(t)));
  updateDashboard();
}

function buildTaskItem(todo) {
  const div = document.createElement('div');
  div.className = 'task-item' + (todo.done ? ' done' : '');
  const today = new Date().toISOString().slice(0,10);
  const overdue = todo.due && !todo.done && todo.due < today;
  div.innerHTML = `
    <div class="task-check ${todo.done?'checked':''}" role="checkbox" aria-checked="${todo.done}" tabindex="0"></div>
    <div class="task-body">
      <div class="task-text">${escHtml(todo.text)}</div>
      <div class="task-meta">
        <span class="task-priority ${todo.priority}">${todo.priority}</span>
        ${todo.due ? `<span class="task-due ${overdue?'overdue':''}">Due: ${todo.due}</span>` : ''}
      </div>
    </div>
    <div class="task-actions">
      <button class="task-btn edit" title="Edit">✎</button>
      <button class="task-btn del" title="Delete">✕</button>
    </div>`;

  const toggle = () => {
    const todos = LS.get('todos',[]);
    const t = todos.find(x=>x.id===todo.id);
    if (t) t.done = !t.done;
    LS.set('todos', todos); renderTodos();
  };
  const check = div.querySelector('.task-check');
  check.addEventListener('click', toggle);
  check.addEventListener('keydown', e => { if (e.key===' '||e.key==='Enter') toggle(); });

  div.querySelector('.task-btn.del').addEventListener('click', () => {
    if (!confirm('Delete this task?')) return;
    LS.set('todos', LS.get('todos',[]).filter(t=>t.id!==todo.id)); renderTodos();
  });

  div.querySelector('.task-btn.edit').addEventListener('click', () => {
    if (div.querySelector('.task-edit-form')) return;
    const body = div.querySelector('.task-body');
    const ef = document.createElement('div'); ef.className = 'task-edit-form';
    ef.innerHTML = `<input type="text" value="${escHtml(todo.text)}" /><button class="btn-primary btn-sm">Save</button><button class="btn-ghost btn-sm">Cancel</button>`;
    body.appendChild(ef);
    const inp = ef.querySelector('input'); inp.focus(); inp.select();
    const save = () => {
      const v = inp.value.trim(); if (!v) return;
      const todos = LS.get('todos',[]); const t = todos.find(t=>t.id===todo.id);
      if (t) t.text = v; LS.set('todos', todos); renderTodos(); showToast('Task updated', 'ok');
    };
    ef.querySelector('.btn-primary').addEventListener('click', save);
    ef.querySelector('.btn-ghost').addEventListener('click', () => ef.remove());
    inp.addEventListener('keydown', e => { if(e.key==='Enter') save(); if(e.key==='Escape') ef.remove(); });
  });

  return div;
}

/* ════════════════════════════════════════════════════
   SETTINGS
════════════════════════════════════════════════════ */
function initSettings() {
  const s = LS.get('settings', {compact:false, collapsed:false});
  if (s.compact)   { document.body.classList.add('compact');          document.getElementById('pref-compact').checked = true; }
  if (s.collapsed) { document.getElementById('sidebar').classList.add('collapsed'); document.body.classList.add('sidebar-collapsed'); document.getElementById('pref-collapsed').checked = true; }

  document.getElementById('btn-export-all').addEventListener('click', () => {
    const blob = new Blob([JSON.stringify(LS.exportAll(), null, 2)], {type:'application/json'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
    a.download = 'cyberworkbench-backup-' + new Date().toISOString().slice(0,10) + '.json'; a.click();
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
    if (!confirm('Reset everything? All notes, tasks, cases, and alerts will be permanently deleted. This cannot be undone.')) return;
    LS.clearAll(); showToast('Cleared — reloading…', 'ok');
    setTimeout(() => location.reload(), 1200);
  });

  document.getElementById('pref-compact').addEventListener('change', e => {
    document.body.classList.toggle('compact', e.target.checked);
    const s2 = LS.get('settings',{}); s2.compact = e.target.checked; LS.set('settings', s2);
    showToast('Preference saved', 'ok');
  });

  document.getElementById('pref-collapsed').addEventListener('change', e => {
    document.getElementById('sidebar').classList.toggle('collapsed', e.target.checked);
    document.body.classList.toggle('sidebar-collapsed', e.target.checked);
    const s2 = LS.get('settings',{}); s2.collapsed = e.target.checked; LS.set('settings', s2);
    showToast('Preference saved', 'ok');
  });
}

/* ════════════════════════════════════════════════════
   KEYBOARD SHORTCUTS
════════════════════════════════════════════════════ */
document.addEventListener('keydown', e => {
  const tag = document.activeElement?.tagName;
  if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
  if (e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.key === 'n' || e.key === 'N') {
    if (document.querySelector('.page.active')?.id === 'page-triage') { generateAlert(); return; }
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
  initTriage();
  initIR();
  initPentest();
  initInvestigation();
  initNotes();
  initTodo();
  initGovernance();
}

init();
