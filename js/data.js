// ── SecWorkflow Data Layer ───────────────────────────────────────────────────
// All module definitions. Item states are stored separately in localStorage.
// Schema: Module > Group > Item (static definition)
// ─────────────────────────────────────────────────────────────────────────────

// Pentest statuses (default)
const STATUSES = [
  { value: 'not-started',    label: 'Not Started',              color: '#6b7280' },
  { value: 'in-progress',    label: 'In Progress',              color: '#3b82f6' },
  { value: 'not-vulnerable', label: 'Not Vulnerable / Compliant', color: '#10b981' },
  { value: 'vulnerable',     label: 'Vulnerable / Gap',         color: '#ef4444' },
  { value: 'not-in-scope',   label: 'Not in Scope',             color: '#9ca3af' },
  { value: 'cannot-verify',  label: 'Cannot Verify',            color: '#f59e0b' },
];

// Consultant-specific statuses (independent from pentest)
const CONSULTANT_STATUSES = [
  { value: 'not-assessed',        label: 'Not Assessed',        color: '#6b7280' },
  { value: 'in-progress',         label: 'In Progress',         color: '#3b82f6' },
  { value: 'compliant',           label: 'Compliant',           color: '#10b981' },
  { value: 'partially-compliant', label: 'Partially Compliant', color: '#f59e0b' },
  { value: 'not-compliant',       label: 'Not Compliant',       color: '#ef4444' },
  { value: 'not-applicable',      label: 'Not Applicable',      color: '#9ca3af' },
];

const SEVERITIES = ['critical','high','medium','low','info'];

// ─────────────────────────────────────────────────────────────────────────────
// PENTEST MODULES
// ─────────────────────────────────────────────────────────────────────────────

const MODULE_ACTIVE_DIRECTORY = {
  id: 'active-directory',
  name: 'Active Directory',
  type: 'pentest',
  icon: '🏢',
  description: 'Comprehensive AD/Windows domain penetration test — enumeration through domain compromise.',
  groups: [
    {
      id: 'ad-enum',
      name: 'Enumeration & Reconnaissance',
      items: [
        { id:'ad-enum-001', title:'LDAP anonymous bind', description:'Test for unauthenticated LDAP bind allowing enumeration of domain users, computers, groups, and policies. Tools: ldapsearch, windapsearch, ldapdomaindump.', severity:'medium', tags:['ldap','enumeration','unauthenticated'], frameworks:['MITRE:T1018','CIS-AD-1'], remediation:'Disable anonymous LDAP access. Enforce LDAP signing and channel binding (KB4520412). Set RestrictAnonymous = 2.' },
        { id:'ad-enum-002', title:'Domain user enumeration via RPC', description:'Enumerate all domain users, their attributes, password policies, and account flags via MS-RPC null sessions or authenticated LDAP. Tools: enum4linux-ng, rpcclient, BloodHound.', severity:'medium', tags:['rpc','enumeration','users'], frameworks:['MITRE:T1087.002'], remediation:'Restrict anonymous enumeration via RPC. Set RestrictAnonymousSAM = 1 and RestrictAnonymous = 1. Disable null sessions.' },
        { id:'ad-enum-003', title:'BloodHound/SharpHound collection', description:'Run SharpHound (or BloodHound CE collector) with All collection method to map AD attack paths. Identify shortest paths to Domain Admin. Analyse Kerberoastable, ASREPRoastable, unconstrained delegation, and DCSync paths.', severity:'info', tags:['bloodhound','enumeration','attack-paths'], frameworks:['MITRE:T1069.002'], remediation:'Remediate specific attack paths identified. Enforce least privilege. Tier administrative accounts.' },
        { id:'ad-enum-004', title:'AS-REP roastable account identification', description:'Enumerate accounts with "Do not require Kerberos preauthentication" flag set (UserAccountControl: 0x400000). These yield TGTs crackable offline without authentication. Tool: GetNPUsers.py, Rubeus asreproast.', severity:'high', tags:['kerberos','asrep-roast','enumeration'], frameworks:['MITRE:T1558.004'], remediation:'Enable Kerberos pre-authentication on all accounts. Audit with: Get-ADUser -Filter * -Properties DoesNotRequirePreAuth | Where-Object {$_.DoesNotRequirePreAuth}' },
        { id:'ad-enum-005', title:'Kerberoastable account identification', description:'Enumerate all accounts with ServicePrincipalNames (SPNs) set, particularly those not computer accounts. These yield TGS tickets crackable offline. Prioritise accounts in privileged groups. Tool: GetUserSPNs.py, Rubeus kerberoast.', severity:'high', tags:['kerberos','kerberoast','spn','enumeration'], frameworks:['MITRE:T1558.003'], remediation:'Audit SPNs. Remove unnecessary SPNs. Set managed service accounts (gMSA) which use 120-char random passwords. Enable AES encryption for Kerberos.' },
        { id:'ad-enum-006', title:'Unconstrained delegation hosts', description:'Identify computers (and users) with unconstrained delegation enabled (TrustedForDelegation = True). When a privileged user authenticates to such a host, their TGT is cached and extractable. Tool: PowerView, ldapdomaindump, BloodHound.', severity:'critical', tags:['delegation','unconstrained','kerberos'], frameworks:['MITRE:T1558'], remediation:'Remove unconstrained delegation from all non-DC systems. Replace with constrained or resource-based constrained delegation.' },
        { id:'ad-enum-007', title:'Constrained delegation configuration review', description:'Enumerate all accounts with constrained delegation (msDS-AllowedToDelegateTo populated) and identify those with protocol transition (TrustedToAuthForDelegation). S4U2Self abuse possible without user interaction.', severity:'high', tags:['delegation','constrained','s4u'], frameworks:['MITRE:T1558'], remediation:'Audit constrained delegation configurations. Use resource-based constrained delegation (RBCD) where possible. Review service-to-service delegation requirements.' },
        { id:'ad-enum-008', title:'AdminSDHolder protected objects', description:'Enumerate all objects under AdminSDHolder protection (adminCount=1). These objects have stricter ACL inheritance disabled and are used as persistence targets. Unexpected objects with adminCount=1 may indicate prior compromise.', severity:'medium', tags:['adminsdholder','enumeration','persistence'], frameworks:['MITRE:T1078.002'], remediation:'Audit all objects with adminCount=1. Remove stale admin accounts. Ensure SDProp runs every 60 minutes.' },
        { id:'ad-enum-009', title:'Domain trust enumeration', description:'Map all inbound, outbound, and bidirectional domain/forest trusts. Identify transitivity, trust attributes (e.g. SID filtering disabled), and cross-forest authentication paths. Tool: nltest, Get-DomainTrust, BloodHound.', severity:'high', tags:['trusts','forest','enumeration'], frameworks:['MITRE:T1482'], remediation:'Audit all trusts. Enable SID filtering on external trusts. Disable TGT delegation across trusts unless required. Remove stale trusts.' },
        { id:'ad-enum-010', title:'LAPS deployment status', description:'Check whether LAPS (Local Administrator Password Solution) or Windows LAPS is deployed on workstations and servers. Non-LAPS systems share a common local admin password enabling lateral movement. Tool: Check ms-Mcs-AdmPwd attribute, LAPSToolkit.', severity:'high', tags:['laps','local-admin','enumeration'], frameworks:['CIS-AD-5','MITRE:T1078.003'], remediation:'Deploy Microsoft LAPS or Windows LAPS to all workstations and member servers. Store passwords in AD with appropriate ACLs.' },
        { id:'ad-enum-011', title:'Fine-grained password policy enumeration', description:'Enumerate Password Settings Objects (PSOs) / fine-grained password policies. Identify if privileged accounts have weaker policies, or if service accounts have exemptions from lockout policies enabling brute-force.', severity:'medium', tags:['password-policy','pso','enumeration'], frameworks:['CIS-AD-2'], remediation:'Review all PSOs. Ensure privileged accounts have stronger password requirements. Enforce lockout on all accounts including service accounts.' },
        { id:'ad-enum-012', title:'GPO enumeration and SYSVOL review', description:'Enumerate all Group Policy Objects, their permissions, linked OUs, and content. Review SYSVOL share for GPP password files (Groups.xml, Services.xml), logon scripts containing credentials, and world-writable scripts.', severity:'high', tags:['gpo','sysvol','enumeration','credentials'], frameworks:['MITRE:T1552.006','CIS-AD-6'], remediation:'Remove all GPP password entries (MS14-025). Restrict GPO write permissions. Audit SYSVOL content. Restrict write access to logon scripts.' },
        { id:'ad-enum-013', title:'Resource-based constrained delegation (RBCD) candidates', description:'Identify computer accounts where authenticated users have write permissions to msDS-AllowedToActOnBehalfOfOtherIdentity attribute. This allows RBCD attacks if an attacker can create machine accounts. Tool: BloodHound, PowerView.', severity:'high', tags:['rbcd','delegation','acl'], frameworks:['MITRE:T1558'], remediation:'Restrict who can write msDS-AllowedToActOnBehalfOfOtherIdentity. Lower MachineAccountQuota from default 10 to 0 unless required. Use Protected Users group.' },
        { id:'ad-enum-014', title:'MachineAccountQuota check', description:'Check ms-DS-MachineAccountQuota attribute on domain. Default is 10, meaning any authenticated user can create machine accounts. Attackers leverage this for RBCD and other attacks.', severity:'medium', tags:['machineaccountquota','rbcd','configuration'], frameworks:['MITRE:T1136.002'], remediation:'Set MachineAccountQuota to 0. Use dedicated accounts for computer object creation. Manage computer account creation via delegated rights.' },
        { id:'ad-enum-015', title:'Sensitive group membership enumeration', description:'Enumerate members of privileged groups: Domain Admins, Enterprise Admins, Schema Admins, Group Policy Creator Owners, Account Operators, Backup Operators, Print Operators, Server Operators, DnsAdmins. Identify stale and service accounts.', severity:'medium', tags:['privileged-groups','enumeration'], frameworks:['MITRE:T1069.002','CIS-AD-3'], remediation:'Enforce least privilege. Remove stale members. Document all privileged group memberships. Use tiered administration model.' },
      ]
    },
    {
      id: 'ad-kerb',
      name: 'Kerberos Attacks',
      items: [
        { id:'ad-kerb-001', title:'AS-REP Roasting', description:'Request TGTs for accounts without Kerberos pre-auth and crack offline. Even a single cracked account can enable lateral movement. Use hashcat mode 18200. Target high-value accounts in privileged groups.', severity:'high', tags:['kerberos','asrep-roast','offline-crack'], frameworks:['MITRE:T1558.004'], remediation:'Enable pre-authentication on all accounts. Enforce strong passwords (20+ chars) on service accounts. Monitor for unusual TGT requests (Event 4768, KDC_ERR_PREAUTH_FAILED from unknown sources).' },
        { id:'ad-kerb-002', title:'Kerberoasting', description:'Request TGS tickets for SPN-bearing service accounts as any authenticated domain user. Crack offline using hashcat mode 13100 (RC4) or 19700 (AES). Target accounts with high privileges and weak/guessable passwords.', severity:'high', tags:['kerberos','kerberoast','offline-crack','spn'], frameworks:['MITRE:T1558.003'], remediation:'Use gMSA for service accounts (120-char random passwords). Enforce AES-only Kerberos. Audit SPNs. Monitor Event 4769 with ticket encryption type 0x17 (RC4).' },
        { id:'ad-kerb-003', title:'Pass-the-Ticket (PTT)', description:'Inject Kerberos TGT or TGS tickets into current session using Rubeus or Mimikatz. Access resources authenticated as the ticket owner without knowing their password. Useful after AS-REP roast, unconstrained delegation capture, or LSASS dump.', severity:'critical', tags:['kerberos','ptt','lateral-movement'], frameworks:['MITRE:T1550.003'], remediation:'Enforce AES encryption. Limit session lifespan. Deploy Credential Guard. Monitor for ticket anomalies (Event 4769, 4770). Use Protected Users security group.' },
        { id:'ad-kerb-004', title:'Overpass-the-Hash (OPtH)', description:'Convert an NTLM hash to a Kerberos TGT using Rubeus (asktgt /rc4: or /aes256:). Allows Kerberos-only authentication to evade NTLM-restricted environments. Requires NTLM hash from LSASS dump or DCSync.', severity:'critical', tags:['kerberos','opth','lateral-movement','ntlm'], frameworks:['MITRE:T1550.002'], remediation:'Deploy Credential Guard to prevent NTLM hash extraction. Enforce Protected Users group. Monitor for TGT requests with RC4 encryption from non-DC hosts.' },
        { id:'ad-kerb-005', title:'Golden Ticket attack', description:'Forge a valid TGT using the krbtgt account NTLM hash. Valid for 10 years by default. Persists across password resets until krbtgt password is changed TWICE. Enables DCSync, lateral movement, and persistent DA access.', severity:'critical', tags:['golden-ticket','kerberos','persistence','krbtgt'], frameworks:['MITRE:T1558.001'], remediation:'Change krbtgt password TWICE with delay. Monitor Event 4769 for tickets longer than Kerberos maximum ticket age. Detect anomalous PAC-less tickets. Reset after any domain compromise.' },
        { id:'ad-kerb-006', title:'Silver Ticket attack', description:'Forge a TGS for a specific service using the service account hash without contacting the KDC. CIFS, HOST, LDAP, HTTP tickets provide access to specific services silently (no DC events generated).', severity:'critical', tags:['silver-ticket','kerberos','persistence'], frameworks:['MITRE:T1558.002'], remediation:'Enable PAC validation on all services. Enforce 128-bit AES service tickets. Rotate service account credentials. Monitor for tickets that bypass KDC.' },
        { id:'ad-kerb-007', title:'Unconstrained delegation TGT capture', description:'On a host with unconstrained delegation, execute SpoolSample, PetitPotam, or PrinterBug to coerce DC to authenticate, capture its TGT via Rubeus monitor, then DCSync or PTT to access all domain resources.', severity:'critical', tags:['unconstrained-delegation','tgt-capture','coerce','dcsync'], frameworks:['MITRE:T1558','MITRE:T1187'], remediation:'Remove unconstrained delegation from non-DC hosts. Block SMB coercion paths from non-admin systems. Enable MS-RPRN firewall rules. Deploy EPA on all NTLM services.' },
        { id:'ad-kerb-008', title:'Constrained delegation S4U2Proxy abuse', description:'Accounts with constrained delegation (TrustedToAuthForDelegation + msDS-AllowedToDelegateTo) can use S4U2Self to get a service ticket on behalf of any user, then S4U2Proxy to delegate to configured targets. Attack chain from any DA-adjacent account.', severity:'high', tags:['s4u2proxy','constrained-delegation','kerberos'], frameworks:['MITRE:T1558'], remediation:'Audit constrained delegation configurations. Avoid protocol transition. Prefer RBCD with explicit trust. Remove unnecessary delegation configurations.' },
        { id:'ad-kerb-009', title:'RBCD exploitation', description:'If write access to msDS-AllowedToActOnBehalfOfOtherIdentity exists, configure RBCD to allow a controlled machine account to delegate as any user to the target. Combine with S4U2Self to impersonate DA to target service.', severity:'critical', tags:['rbcd','delegation','privilege-escalation'], frameworks:['MITRE:T1558'], remediation:'Restrict write permissions on computer objects. Set MachineAccountQuota to 0. Monitor msDS-AllowedToActOnBehalfOfOtherIdentity modifications (Event 5136).' },
      ]
    },
    {
      id: 'ad-cred',
      name: 'Credential Attacks',
      items: [
        { id:'ad-cred-001', title:'NTLM relay (SMB→LDAP)', description:'Using Responder + ntlmrelayx, capture NTLMv1/v2 hashes from LLMNR/NBT-NS/mDNS poisoning and relay to LDAP/LDAPS to create computer accounts, modify DACL, or perform DCSync. Critical in environments without SMB signing.', severity:'critical', tags:['ntlm-relay','responder','llmnr','ldap'], frameworks:['MITRE:T1557.001'], remediation:'Enable SMB signing on all hosts (mandatory). Disable LLMNR and NBT-NS via GPO. Enable LDAP signing and channel binding. Deploy EPA.' },
        { id:'ad-cred-002', title:'IPv6 DNS takeover (mitm6)', description:'Exploit Windows default IPv6 preference over IPv4 using mitm6 to respond as DHCPv6/DNS server. Capture authentication attempts from systems querying the rogue DNS. Relay to LDAP for account creation or DA compromise.', severity:'critical', tags:['ipv6','mitm6','dns','ntlm-relay'], frameworks:['MITRE:T1557'], remediation:'Disable IPv6 where not required (GPO). Block DHCPv6 at network level. Enable LDAP signing and channel binding. Implement 802.1X authentication.' },
        { id:'ad-cred-003', title:'LSASS credential extraction', description:'Dump credentials from LSASS memory using Mimikatz sekurlsa::logonpasswords, procdump, nanodump, or direct API calls. Yields NTLM hashes, Kerberos tickets, WDigest plaintext (legacy). Requires local admin/SYSTEM.', severity:'critical', tags:['lsass','credential-dump','mimikatz'], frameworks:['MITRE:T1003.001'], remediation:'Enable Credential Guard (VBS). Enable PPL for LSASS. Disable WDigest. Deploy EDR with LSASS access monitoring. Enable Event 10 (lsass access) in Sysmon.' },
        { id:'ad-cred-004', title:'DCSync attack', description:'Using DS-Replication-Get-Changes-All rights, replicate all domain credentials including krbtgt hash via mimikatz lsadump::dcsync. Requires DomainController, Domain Admin, or explicitly delegated replication rights.', severity:'critical', tags:['dcsync','replication','credential-dump','krbtgt'], frameworks:['MITRE:T1003.006'], remediation:'Restrict DS-Replication rights to DCs only (audit Event 4662 with GUIDs 1131f6ad, 1131f6aa, 89e95b76). Monitor for non-DC replication requests.' },
        { id:'ad-cred-005', title:'NTDS.dit offline extraction', description:'Extract ntds.dit via Volume Shadow Copy (vssadmin) or ntdsutil IFM, copy with SYSTEM hive, and parse offline with impacket secretsdump.py. Full domain credential dump without LSASS interaction.', severity:'critical', tags:['ntds','vss','credential-dump'], frameworks:['MITRE:T1003.003'], remediation:'Restrict access to VSS operations. Monitor Event 7036 (VSS service). Implement JEA for administrative tasks. Monitor ntdsutil and vssadmin usage.' },
        { id:'ad-cred-006', title:'GPP password extraction (MS14-025)', description:'Search SYSVOL for Groups.xml, Services.xml, Scheduledtasks.xml, Datasources.xml containing cpassword fields (AES-256 encrypted with published key). Tool: Get-GPPPassword, CrackMapExec gpp_password.', severity:'high', tags:['gpp','sysvol','ms14-025','credentials'], frameworks:['MITRE:T1552.006'], remediation:'Apply MS14-025 (prevents creating new GPP passwords). Remove all existing cpassword entries from SYSVOL. Rotate all credentials exposed via GPP.' },
        { id:'ad-cred-007', title:'Pass-the-Hash (PtH)', description:'Use NTLM hash directly for authentication to SMB, WMI, DCOM, RDP (restricted admin mode) without cracking. Tool: impacket suite, CrackMapExec, Rubeus. Particularly effective with shared local admin hash across endpoints.', severity:'critical', tags:['pth','ntlm','lateral-movement'], frameworks:['MITRE:T1550.002'], remediation:'Deploy Credential Guard. Disable NTLM authentication where possible. Enforce Protected Users group for privileged accounts. Deploy LAPS to prevent hash reuse.' },
        { id:'ad-cred-008', title:'Credential spraying', description:'Test commonly used passwords (Welcome1!, Company2024!, Autumn2024!) against domain accounts using kerbrute or CME. One password per ~30 mins to evade lockout. Check badpwdcount in LDAP to calibrate timing.', severity:'high', tags:['password-spray','brute-force','authentication'], frameworks:['MITRE:T1110.003'], remediation:'Enforce account lockout policies (threshold ≤5). Deploy MFA. Monitor Event 4625 (failed logon) with pattern detection. Implement fine-grained policies for privileged accounts.' },
        { id:'ad-cred-009', title:'SAM database extraction (local accounts)', description:'Extract local account hashes from SAM registry hive (requires SYSTEM). Offline crack with hashcat. Particularly valuable if local admin password is reused across multiple hosts.', severity:'high', tags:['sam','local-accounts','credential-dump'], frameworks:['MITRE:T1003.002'], remediation:'Deploy LAPS. Restrict local admin rights. Monitor registry access to HKLM\\SAM. Enable Sysmon Event 13 for registry manipulation.' },
        { id:'ad-cred-010', title:'DPAPI master key extraction', description:'Extract DPAPI master keys to decrypt browser credentials, RDP saved passwords, Windows vault credentials. Use Mimikatz dpapi::masterkey or impacket dpapi.py. Requires user or domain backup key.', severity:'high', tags:['dpapi','credentials','browser'], frameworks:['MITRE:T1555.003'], remediation:'Monitor domain DPAPI backup key requests (Event 4692). Use dedicated service accounts instead of user accounts for sensitive operations.' },
      ]
    },
    {
      id: 'ad-acl',
      name: 'ACL / ACE Abuse',
      items: [
        { id:'ad-acl-001', title:'GenericAll privilege escalation', description:'Identify objects where current user or controlled groups have GenericAll. On users: change password without knowing current. On groups: add members. On computers: configure RBCD. On GPOs: modify policy for privileged users. Tool: BloodHound, PowerView.', severity:'critical', tags:['acl','genericall','privilege-escalation'], frameworks:['MITRE:T1222'], remediation:'Audit all AD ACLs with BloodHound or PingCastle. Remove over-permissive ACEs. Enable AD audit logging for DACL changes (Event 4662, 5136).' },
        { id:'ad-acl-002', title:'WriteDACL abuse', description:'WriteDACL on an object allows modification of its DACL. An attacker can grant themselves GenericAll on that object. Target: domain object for DCSync rights, group for membership control, GPO for policy modification.', severity:'critical', tags:['acl','writedacl','privilege-escalation'], frameworks:['MITRE:T1222'], remediation:'Audit WriteDACL permissions on all sensitive objects. Use Protected Users group. Restrict DACL modification to Domain Admins.' },
        { id:'ad-acl-003', title:'WriteOwner abuse', description:'WriteOwner permits changing object ownership to self, then granting own account GenericAll via DACL modification. Chain: WriteOwner → set as owner → WriteDACL → GenericAll. Common on cross-domain or service account objects.', severity:'critical', tags:['acl','writeowner','privilege-escalation'], frameworks:['MITRE:T1222'], remediation:'Audit object ownership. Remove WriteOwner from non-privileged accounts on sensitive objects. Monitor ownership changes (Event 4657).' },
        { id:'ad-acl-004', title:'ForceChangePassword abuse', description:'ForceChangePassword (User-Force-Change-Password extended right) allows resetting a user\'s password without knowing the current password. Exploited to reset DA account passwords. Tool: Set-DomainUserPassword (PowerView), net user.', severity:'high', tags:['acl','forcechangepassword','privilege-escalation'], frameworks:['MITRE:T1098'], remediation:'Audit ForceChangePassword ACEs on privileged accounts. Remove unnecessary delegated password reset rights. Alert on password resets for DA accounts.' },
        { id:'ad-acl-005', title:'GenericWrite targeted Kerberoasting', description:'GenericWrite on a user object allows setting arbitrary SPNs, making the account Kerberoastable on demand. Set SPN → request TGS → crack offline → remove SPN. Tool: Set-DomainObject (PowerView), Rubeus kerberoast.', severity:'high', tags:['acl','genericwrite','kerberoast','targeted'], frameworks:['MITRE:T1558.003'], remediation:'Remove GenericWrite from non-privileged accounts on user objects. Enable AES-only Kerberos. Monitor SPN creation events.' },
        { id:'ad-acl-006', title:'AddSelf / AddMember to privileged groups', description:'Accounts with AddMember or AddSelf rights can add users to privileged groups (Domain Admins, etc.). Enumerate with BloodHound "Shortest Paths to DA" including group membership modification edges.', severity:'critical', tags:['acl','addmember','privilege-escalation','groups'], frameworks:['MITRE:T1098.001'], remediation:'Restrict AddMember rights to Domain Admins. Monitor group membership changes (Event 4728, 4732, 4756). Implement change management for privileged group membership.' },
        { id:'ad-acl-007', title:'DCSync rights on non-DC accounts', description:'DS-Replication-Get-Changes + DS-Replication-Get-Changes-All rights on the domain NC root allow any account to replicate all AD objects including credential data. Identify non-DC accounts with these rights.', severity:'critical', tags:['dcsync','replication','acl'], frameworks:['MITRE:T1003.006'], remediation:'Remove DS-Replication rights from non-DC accounts. Audit with: (Get-Acl "AD:\\DC=domain,DC=com").Access where ObjectType matches replication GUIDs.' },
        { id:'ad-acl-008', title:'AdminSDHolder DACL modification', description:'AdminSDHolder is the template DACL applied to all protected objects every 60 min by SDProp. Adding a backdoor ACE to AdminSDHolder grants persistent rights to all DA, EA, and other protected objects.', severity:'critical', tags:['adminsdholder','persistence','acl'], frameworks:['MITRE:T1078.002'], remediation:'Monitor AdminSDHolder ACL modifications (Event 5136). Alert on any non-standard ACE additions. Schedule regular audits of AdminSDHolder DACL.' },
      ]
    },
    {
      id: 'ad-cs',
      name: 'AD Certificate Services (AD CS)',
      items: [
        { id:'ad-cs-001', title:'AD CS enumeration', description:'Enumerate AD CS configuration: Certificate Authorities, published templates, enrollment permissions, and CA settings. Tools: Certify.exe, certipy, ADCSPwn. Identify templates with EKUs enabling authentication.', severity:'info', tags:['adcs','enumeration','pki'], frameworks:['MITRE:T1649'], remediation:'Audit CA configurations and published templates. Review enrollment permissions. Remove unused templates.' },
        { id:'ad-cs-002', title:'ESC1 — SAN specification in enrollment', description:'Template allows enrollee to supply a Subject Alternative Name (SAN). Combined with Client Authentication EKU, allows forging certificates as any domain user including DA. Requires enrollment rights on template. Tool: Certify /vulnerable, certipy find.', severity:'critical', tags:['adcs','esc1','san','certificate'], frameworks:['MITRE:T1649'], remediation:'Disable "Supply in the request" in template Subject Name configuration. Enable Manager Approval for sensitive templates. Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag.' },
        { id:'ad-cs-003', title:'ESC2 — Any Purpose or SubCA templates', description:'Template with Any Purpose EKU or no EKU (SubCA) with enrollment rights allows generating certificates usable for authentication, code signing, or any other purpose. Tool: Certify, certipy.', severity:'critical', tags:['adcs','esc2','certificate'], frameworks:['MITRE:T1649'], remediation:'Remove Any Purpose EKU from templates. Require Manager Approval. Restrict enrollment permissions to specific groups.' },
        { id:'ad-cs-004', title:'ESC4 — Vulnerable template ACLs', description:'Low-privileged users have WriteDACL/GenericAll/WriteProperty over certificate templates. Attacker modifies template to enable SAN specification (ESC1 pattern). Tool: Certify /vulnerable, certipy.', severity:'critical', tags:['adcs','esc4','acl','certificate'], frameworks:['MITRE:T1649','MITRE:T1222'], remediation:'Restrict template modification rights to CA Admins. Audit template ACLs. Monitor Event 4899 (certificate template modification).' },
        { id:'ad-cs-005', title:'ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 CA flag', description:'CA configured with EDITF_ATTRIBUTESUBJECTALTNAME2 flag allows any template with Client Auth EKU to accept SAN in request, regardless of template settings. Affects all enrolled templates on that CA. Tool: Certify, certutil.', severity:'critical', tags:['adcs','esc6','san','ca-flag'], frameworks:['MITRE:T1649'], remediation:'Remove EDITF_ATTRIBUTESUBJECTALTNAME2 flag: certutil -config CA -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2. Restart CertSvc.' },
        { id:'ad-cs-006', title:'ESC8 — NTLM relay to AD CS HTTP enrollment', description:'AD CS Web Enrollment (certsrv) accepts NTLM authentication. Relay coerced NTLM from DC or privileged host to request a domain controller certificate, then use it for DCSync via PKINIT. PetitPotam + ntlmrelayx + certipy.', severity:'critical', tags:['adcs','esc8','ntlm-relay','certsrv'], frameworks:['MITRE:T1649','MITRE:T1557'], remediation:'Enable Extended Protection for Authentication (EPA) on CES/CEP/certsrv. Enforce HTTPS. Disable NTLM on IIS. Block SMB coercion from DC (MS-RPRN, MS-EFSR firewall rules).' },
        { id:'ad-cs-007', title:'PKINIT certificate-based authentication', description:'If AD CS issues certificates with Smart Card Logon EKU, test certificate-based authentication pathways. Verify certificate revocation. Test if old/stolen certificates remain valid. Extract private keys from cert stores.', severity:'high', tags:['adcs','pkinit','certificate-auth'], frameworks:['MITRE:T1550.001'], remediation:'Enforce CRL/OCSP checking. Implement short-lived certificate lifetimes. Monitor PKINIT authentication events (Event 4768 with Certificate Info).' },
      ]
    },
    {
      id: 'ad-esc',
      name: 'Domain Escalation & Known Vulnerabilities',
      items: [
        { id:'ad-esc-001', title:'ZeroLogon (CVE-2020-1472)', description:'Netlogon protocol vulnerability allowing unauthenticated attacker to reset DC machine account password and gain domain admin access. Test for patch status. Tool: zerologon_tester.py, netexec zerologon.', severity:'critical', tags:['zerologon','cve-2020-1472','unauthenticated'], frameworks:['MITRE:T1210','CVE:2020-1472'], remediation:'Apply MS20-040 patch immediately. Enforce Netlogon secure channel. Enable Event 5829 monitoring.' },
        { id:'ad-esc-002', title:'NoPac / Sam Account Name Spoofing (CVE-2021-42278/42287)', description:'sAMAccountName of machine account can be set to match DC name (without trailing $). Request TGT as "DC", rename back, request TGS using S4U2Self as DA. Full domain compromise without any privilege. Tool: noPac.py.', severity:'critical', tags:['nopac','sam-spoofing','cve-2021-42278'], frameworks:['MITRE:T1078.002','CVE:2021-42278'], remediation:'Apply November 2021 patches (KB5008380, KB5008102, KB5008380). Restrict MachineAccountQuota to 0.' },
        { id:'ad-esc-003', title:'PrintNightmare (CVE-2021-1675 / CVE-2021-34527)', description:'Unauthenticated (or authenticated) RCE via Windows Print Spooler. Check if Print Spooler service is running on DCs and servers. Tool: cube0x0/CVE-2021-1675, impacket addcomputer.', severity:'critical', tags:['printnightmare','print-spooler','rce','cve-2021-1675'], frameworks:['MITRE:T1210','CVE:2021-34527'], remediation:'Disable Print Spooler on DCs (mandatory). Apply patches. If required, restrict who can install print drivers via GPO (RestrictDriverInstallationToAdministrators = 1).' },
        { id:'ad-esc-004', title:'PetitPotam (MS-EFSR) coercion', description:'Unauthenticated (patched) or authenticated NTLM coercion via MS-EFSR (Encrypting File System Remote Protocol). Forces target to authenticate to attacker-controlled host. Chain with NTLM relay to LDAP or AD CS ESC8.', severity:'high', tags:['petitpotam','ms-efsr','ntlm-coercion'], frameworks:['MITRE:T1187'], remediation:'Apply MS21-085 patch. Block EFS-RPC at firewall. Enable EPA on all NTLM-accepting services. Disable NTLM where possible.' },
        { id:'ad-esc-005', title:'DnsAdmins privilege escalation', description:'Members of DnsAdmins group can load arbitrary DLL into DNS Server service via dnscmd /serverlevelplugindll. DNS service runs as SYSTEM on DCs. Provides code execution at SYSTEM level on domain controllers.', severity:'critical', tags:['dnsadmins','dll-injection','privilege-escalation'], frameworks:['MITRE:T1574.002'], remediation:'Remove unnecessary accounts from DnsAdmins. Restrict who can modify DNS server plugin DLL path. Monitor dnscmd.exe execution.' },
        { id:'ad-esc-006', title:'SCCM / MECM attack paths', description:'Identify SCCM/MECM deployment. Test for credential harvesting via PXE boot (unencrypted), hierarchy takeover via site server compromise, NAA credential exposure, and admin privilege escalation via deployment configuration.', severity:'high', tags:['sccm','mecm','configmgr'], frameworks:['MITRE:T1557'], remediation:'Encrypt PXE passwords. Remove NAA accounts from Distribution Points. Restrict SCCM admin access. Apply SCCM security guidance.' },
      ]
    },
    {
      id: 'ad-trust',
      name: 'Trust & Cross-Forest Attacks',
      items: [
        { id:'ad-trust-001', title:'Cross-forest Kerberoasting', description:'If forest trust exists, Kerberoast service accounts across the trust boundary. SPNs in trusted domains are requestable from the trusting domain. Tool: GetUserSPNs.py -target-domain.', severity:'high', tags:['trust','kerberoast','cross-forest'], frameworks:['MITRE:T1558.003'], remediation:'Enable SID filtering on all external/forest trusts. Audit cross-forest delegation. Remove unnecessary forest trusts.' },
        { id:'ad-trust-002', title:'SID history injection', description:'If SID filtering is disabled on a trust, inject privileged SIDs (e.g., Domain Admins of trusted forest) into SID history of user account in trusting domain. Grants access as injected SID. Requires compromise of child domain krbtgt.', severity:'critical', tags:['trust','sid-history','privilege-escalation'], frameworks:['MITRE:T1134.005'], remediation:'Enable SID filtering on ALL trusts (Quarantine mode). Remove SID history from all accounts unless required for migrations.' },
        { id:'ad-trust-003', title:'Child-to-parent domain escalation', description:'With control of a child domain, forge inter-realm TGT with Enterprise Admins SID in PAC. Compromise parent domain via SID history injection in golden/diamond ticket across parent-child trust. Tool: Mimikatz, Rubeus.', severity:'critical', tags:['trust','child-domain','enterprise-admins'], frameworks:['MITRE:T1558.001'], remediation:'Treat all child domains as fully trusted. Maintain SID filtering even on parent-child trusts (not default). Isolate sensitive resources in separate forests.' },
      ]
    },
    {
      id: 'ad-pers',
      name: 'Persistence Mechanisms',
      items: [
        { id:'ad-pers-001', title:'Golden Ticket persistence', description:'After obtaining krbtgt hash, forge golden tickets for offline persistence. Valid for 10 years. Survives password resets of all other accounts (requires krbtgt reset TWICE). Store krbtgt hash as engagement artifact.', severity:'critical', tags:['golden-ticket','persistence','krbtgt'], frameworks:['MITRE:T1558.001'], remediation:'Change krbtgt password twice with 10-hour delay. Monitor for tickets with anomalous validity periods. Implement Microsoft Defender Credential Guard.' },
        { id:'ad-pers-002', title:'AdminSDHolder backdoor', description:'Modify AdminSDHolder object DACL to include backdoor user with GenericAll. Every 60 min SDProp propagates this ACE to all protected objects (DA, EA, etc.), providing persistent DA-level rights through ACE not ACL membership.', severity:'critical', tags:['adminsdholder','persistence','backdoor'], frameworks:['MITRE:T1078.002'], remediation:'Monitor Event 5136 on AdminSDHolder CN. Alert on any DACL modification. Restore AdminSDHolder DACL from known-good baseline.' },
        { id:'ad-pers-003', title:'DCShadow attack', description:'Register a rogue domain controller to replicate malicious changes (SID history injection, AdminSDHolder modification, schema changes) without detection by standard logging. Requires DA-level rights to perform.', severity:'critical', tags:['dcshadow','replication','persistence','stealth'], frameworks:['MITRE:T1484.002'], remediation:'Monitor for new DC registration events. Alert on unexpected replication partners. Detect DCShadow-specific WMI event registration.' },
        { id:'ad-pers-004', title:'Skeleton Key malware', description:'Patch LSASS on all DCs to accept a master password alongside legitimate credentials. Provides persistent DA access. Requires DA rights to install. Does not survive reboots unless continuously re-patched.', severity:'critical', tags:['skeleton-key','persistence','lsass'], frameworks:['MITRE:T1556.001'], remediation:'Deploy EDR with LSASS monitoring. Enable Credential Guard. Monitor unusual LSASS patch patterns. Reboot all DCs to clear in-memory patches.' },
        { id:'ad-pers-005', title:'DSRM account abuse', description:'Each DC has a local DSRM Administrator account for Directory Services Restore Mode. If the DSRM password is known and DSRMAdminLogonBehavior = 2 is set, the DSRM account can be used for remote authentication. Check registry value.', severity:'high', tags:['dsrm','persistence','local-admin'], frameworks:['MITRE:T1098'], remediation:'Set DSRMAdminLogonBehavior = 0 (default). Randomise and vault DSRM passwords. Monitor DSRM logon events.' },
      ]
    },
  ]
};

// ─────────────────────────────────────────────────────────────────────────────

const MODULE_WINDOWS = {
  id: 'windows',
  name: 'Windows',
  type: 'pentest',
  icon: '🪟',
  description: 'Local Windows privilege escalation, credential access, and host-based misconfigurations.',
  groups: [
    {
      id: 'win-lpe',
      name: 'Local Privilege Escalation',
      items: [
        { id:'win-lpe-001', title:'Unquoted service path', description:'Identify services with unquoted binary paths containing spaces. Windows will attempt to execute intermediate paths first (e.g., C:\\Program Files\\App\\service.exe → C:\\Program.exe). Requires write access to intermediate path.', severity:'high', tags:['service','unquoted-path','lpe'], frameworks:['MITRE:T1574.009'], remediation:'Quote all service binary paths. Audit: Get-WmiObject Win32_Service | Where-Object {$_.PathName -notmatch \'"\'}. Restrict write access to program directories.' },
        { id:'win-lpe-002', title:'Weak service binary permissions', description:'Identify services where low-privileged users have write access to the service binary or containing directory. Replace binary with malicious payload that executes as SYSTEM. Tool: PowerUp, accesschk.exe, PrivescCheck.', severity:'high', tags:['service','weak-permissions','lpe'], frameworks:['MITRE:T1574.010'], remediation:'Apply correct ACLs on all service binaries and directories. No non-admin write access to Program Files, Windows, or service directories.' },
        { id:'win-lpe-003', title:'Weak service registry permissions', description:'If low-privileged user has write access to HKLM\\SYSTEM\\CurrentControlSet\\Services\\<svc>, modify ImagePath to execute arbitrary binary. Tool: accesschk.exe /kvuqsw hklm\\System\\CurrentControlSet\\Services.', severity:'high', tags:['service','registry','lpe'], frameworks:['MITRE:T1574.011'], remediation:'Restrict registry write permissions on service keys to SYSTEM and Administrators only.' },
        { id:'win-lpe-004', title:'AlwaysInstallElevated', description:'If AlwaysInstallElevated is enabled in both HKCU and HKLM, any MSI file executes as SYSTEM regardless of user privilege. Generate malicious MSI with msfvenom. Tool: PowerUp, PrivescCheck.', severity:'high', tags:['alwaysinstallelevated','msi','lpe'], frameworks:['MITRE:T1548'], remediation:'Disable AlwaysInstallElevated in HKCU and HKLM via GPO. Audit: reg query HKCU\\Software\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated.' },
        { id:'win-lpe-005', title:'Scheduled task misconfiguration', description:'Identify scheduled tasks running as SYSTEM where low-privileged users have write access to the task binary, containing folder, or the task definition itself. Tool: PrivescCheck, PowerUp, schtasks /query /fo LIST /v.', severity:'high', tags:['scheduled-task','lpe'], frameworks:['MITRE:T1053.005'], remediation:'Audit task binary permissions and task definition ACLs. Restrict modification rights to Administrators.' },
        { id:'win-lpe-006', title:'DLL hijacking in privileged paths', description:'Identify processes running as SYSTEM or elevated user that load DLLs from user-writable directories. Use Procmon to identify missing DLL loads (NAME NOT FOUND). Drop malicious DLL in search path.', severity:'high', tags:['dll-hijacking','lpe'], frameworks:['MITRE:T1574.001'], remediation:'Enable SafeDllSearchMode. Restrict user write access to application directories. Use CIS Benchmarks for application directory permissions.' },
        { id:'win-lpe-007', title:'Token impersonation (SeImpersonatePrivilege)', description:'If SeImpersonatePrivilege is held (common for service accounts, IIS AppPools), use Potato attacks (GodPotato, SweetPotato, PrintSpoofer) to impersonate SYSTEM token and execute code as SYSTEM.', severity:'critical', tags:['token-impersonation','seimpersonateprivilege','potato','lpe'], frameworks:['MITRE:T1134'], remediation:'Restrict SeImpersonatePrivilege to only necessary service accounts. Enforce Credential Guard. Implement application allowlisting to prevent potato binaries.' },
        { id:'win-lpe-008', title:'UAC bypass techniques', description:'Test applicable UAC bypass techniques for the environment\'s UAC level: fodhelper, eventvwr, cmstp, DiskCleanup, CMSTPLUA COM interface, WSReset. Most effective at UAC level 2 (Default). Tool: UACME project.', severity:'medium', tags:['uac-bypass','lpe'], frameworks:['MITRE:T1548.002'], remediation:'Set UAC to highest level. Deploy application allowlisting. Enforce least privilege so standard users don\'t need elevation.' },
        { id:'win-lpe-009', title:'Stored credentials (cmdkey, Credential Manager)', description:'Enumerate stored credentials via cmdkey /list, Windows Credential Manager, .rdg files, VNC configs, Putty sessions, browser saved passwords. Tool: Seatbelt, WinPeas, LaZagne.', severity:'high', tags:['stored-credentials','credential-access'], frameworks:['MITRE:T1555'], remediation:'Enforce credential hygiene policies. Clear stored credentials. Use password managers with MFA. Monitor credential access via Event 5379.' },
        { id:'win-lpe-010', title:'Windows Subsystem for Linux (WSL) abuse', description:'If WSL is enabled, check for credential files, history files (.bash_history), SSH keys, and configuration files accessible from the Linux subsystem. WSL can bypass Windows security controls in some configurations.', severity:'medium', tags:['wsl','linux-subsystem'], frameworks:['MITRE:T1202'], remediation:'Disable WSL where not required. Apply GPO restrictions. Monitor WSL execution.' },
      ]
    },
    {
      id: 'win-config',
      name: 'Security Configuration Review',
      items: [
        { id:'win-cfg-001', title:'PowerShell script block logging', description:'Verify Script Block Logging, Module Logging, and Transcription are enabled and forwarded to SIEM. Test if constrained language mode is enforced. Check AMSI bypass resistance.', severity:'medium', tags:['powershell','logging','amsi'], frameworks:['MITRE:T1059.001','CIS-W-13'], remediation:'Enable PS Script Block Logging (Event 4104). Enable Module Logging. Enable AMSI. Enforce Constrained Language Mode via AppLocker or WDAC.' },
        { id:'win-cfg-002', title:'Windows Defender / EDR coverage', description:'Verify Windows Defender is enabled, up to date, and not in passive mode. Check for tamper protection. Identify gaps in EDR coverage. Test basic bypass techniques (AMSI bypass, obfuscation) to verify detection capability.', severity:'high', tags:['defender','edr','antivirus'], frameworks:['CIS-W-8'], remediation:'Enforce Defender tamper protection. Enable cloud protection. Integrate with SIEM. Validate EDR alerting regularly.' },
        { id:'win-cfg-003', title:'SMB signing and version', description:'Verify SMBv1 is disabled across all endpoints. Verify SMB signing is required (not just enabled). Test with CrackMapExec: cme smb targets --gen-relay-list nosigning.txt.', severity:'high', tags:['smb','smb-signing','smbv1','network'], frameworks:['CIS-W-9','MITRE:T1557.001'], remediation:'Disable SMBv1 via GPO. Enforce SMB signing (RequireSecuritySignature = 1). Block SMB (445/139) at network perimeter.' },
        { id:'win-cfg-004', title:'NTLM authentication restrictions', description:'Audit NTLM usage. Test for NTLMv1 acceptance (susceptible to relay and offline crack). Check if NTLM is restricted (Network Security: Restrict NTLM GPO). Evaluate feasibility of NTLM deprecation.', severity:'medium', tags:['ntlm','authentication','ntlmv1'], frameworks:['CIS-W-10'], remediation:'Disable NTLMv1. Audit NTLM usage via Event 8001/8002/8003/8004. Move to Kerberos where possible. Enable NTLM audit mode before restriction.' },
        { id:'win-cfg-005', title:'RDP security configuration', description:'Test RDP security: NLA enforcement, CredSSP version, RDP port change, certificate validity, idle session timeout, restricted admin mode, Remote Credential Guard support. Check for BlueKeep/DejaBlue exposure.', severity:'medium', tags:['rdp','nla','credssp'], frameworks:['CIS-W-18'], remediation:'Enforce NLA (NetworkLevelAuthentication = 1). Use valid TLS certificate. Restrict RDP access to jump hosts. Monitor Event 4624 logon type 10.' },
        { id:'win-cfg-006', title:'AppLocker / WDAC policy evaluation', description:'Enumerate AppLocker or Windows Defender Application Control (WDAC) policies. Test for bypasses using LOLBins (mshta, wscript, cscript, msiexec, regsvr32, installutil). Identify writable paths in allowed rules.', severity:'medium', tags:['applocker','wdac','application-control','lolbin'], frameworks:['MITRE:T1218'], remediation:'Implement WDAC in audit mode first, then enforcement. Block known LOLBin abuse paths. Default deny with explicit allowlist.' },
      ]
    },
  ]
};

// ─────────────────────────────────────────────────────────────────────────────

const MODULE_WEB_APP = {
  id: 'web-application',
  name: 'Web Application',
  type: 'pentest',
  icon: '🌐',
  description: 'OWASP WSTG-aligned web application penetration test covering authentication through business logic.',
  groups: [
    {
      id: 'web-recon',
      name: 'Information Gathering (WSTG-INFO)',
      items: [
        { id:'web-info-001', title:'Web server fingerprinting', description:'Identify web server type/version via response headers (Server, X-Powered-By, X-AspNet-Version), error pages, and response timing. Check for default pages, backup files (.bak, .old, ~), and directory listings.', severity:'low', tags:['fingerprinting','recon','headers'], frameworks:['OWASP:WSTG-INFO-02'], remediation:'Remove version-disclosing headers. Suppress default error pages. Disable directory listing. Remove backup files from webroot.' },
        { id:'web-info-002', title:'Application entry-point mapping', description:'Map all application entry points: parameters, hidden fields, HTTP headers used as input, cookies, REST endpoints, WebSockets, GraphQL endpoints, file upload endpoints, and API calls via JS analysis (linkfinder, getJS).', severity:'info', tags:['mapping','entry-points','recon'], frameworks:['OWASP:WSTG-INFO-06'], remediation:'This is a discovery step; apply appropriate controls per finding type.' },
        { id:'web-info-003', title:'Authentication mechanism identification', description:'Identify all authentication mechanisms: login forms, HTTP Basic/Digest, SSO (SAML, OIDC), API keys, JWT, certificate-based. Map login, registration, password reset, and account recovery flows.', severity:'info', tags:['authentication','recon'], frameworks:['OWASP:WSTG-ATHN-01'], remediation:'Ensure all authentication mechanisms are consistently hardened.' },
        { id:'web-info-004', title:'JavaScript analysis for sensitive data', description:'Extract and analyse all JavaScript files for: hardcoded API keys, credentials, JWT secrets, internal API endpoints, developer comments, debug flags, and hidden functionality. Tools: LinkFinder, JSParser, truffleHog.', severity:'medium', tags:['javascript','hardcoded-secrets','recon'], frameworks:['OWASP:WSTG-INFO-05'], remediation:'Remove sensitive data from JS. Use environment variables. Strip source maps from production. Implement Content Security Policy.' },
      ]
    },
    {
      id: 'web-config',
      name: 'Configuration & Deployment (WSTG-CONF)',
      items: [
        { id:'web-conf-001', title:'HTTP security headers', description:'Test for missing or misconfigured security headers: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, HSTS (max-age, includeSubDomains, preload), Referrer-Policy, Permissions-Policy. Tool: securityheaders.com logic, curl.', severity:'medium', tags:['headers','csp','hsts','clickjacking'], frameworks:['OWASP:WSTG-CONF-12'], remediation:'Implement all security headers via web server config or middleware. CSP should restrict inline scripts. HSTS min-age: 31536000.' },
        { id:'web-conf-002', title:'TLS/SSL configuration', description:'Test SSL/TLS configuration: deprecated protocols (SSLv2/3, TLS 1.0/1.1), weak ciphers (RC4, DES, EXPORT, NULL), certificate validity/chain, mixed content, HSTS, certificate transparency. Tool: testssl.sh, sslyze.', severity:'high', tags:['tls','ssl','cipher-suites','certificates'], frameworks:['OWASP:WSTG-CRYP-01'], remediation:'Disable TLS 1.0/1.1. Disable weak ciphers. Configure HSTS. Use certificates from trusted CA with 2048+ bit keys. Enable OCSP stapling.' },
        { id:'web-conf-003', title:'Sensitive file and path discovery', description:'Enumerate sensitive files: /.git/, /.svn/, /.env, /wp-config.php, /web.config, /phpinfo.php, /actuator/, /console, /swagger-ui.html, /.DS_Store, /backup/. Tool: feroxbuster, ffuf with SecLists.', severity:'high', tags:['file-discovery','sensitive-files','path-traversal'], frameworks:['OWASP:WSTG-CONF-04'], remediation:'Remove all non-production files from webroot. Restrict access to administrative interfaces. Review .gitignore to prevent committing secrets.' },
        { id:'web-conf-004', title:'HTTP methods allowed', description:'Test for dangerous HTTP methods enabled: PUT, DELETE, PATCH on non-API endpoints, TRACE (XST), CONNECT. Test WebDAV if present. Verify OPTIONS response.', severity:'medium', tags:['http-methods','webdav','trace'], frameworks:['OWASP:WSTG-CONF-06'], remediation:'Disable unused HTTP methods at web server level. Explicitly allowlist required methods per endpoint.' },
        { id:'web-conf-005', title:'CORS policy review', description:'Test CORS configuration: reflected Origin header without validation, null origin acceptance, credentials with wildcard, overly permissive Access-Control-Allow-Origin. Tool: CORS misconfiguration checker, Burp Suite.', severity:'high', tags:['cors','api','headers'], frameworks:['OWASP:WSTG-CONF-07'], remediation:'Implement strict CORS allowlist. Never reflect Origin without validation. Never combine credentials=true with wildcard. Validate Origin against whitelist.' },
      ]
    },
    {
      id: 'web-auth',
      name: 'Authentication (WSTG-ATHN)',
      items: [
        { id:'web-auth-001', title:'Default and weak credentials', description:'Test application and administrative interfaces for default credentials (admin/admin, admin/password, etc.). Test for weak password policies (minimum length, complexity). Use vendor default credential databases.', severity:'high', tags:['default-credentials','authentication','brute-force'], frameworks:['OWASP:WSTG-ATHN-02'], remediation:'Enforce strong password policies. Force password change on first login. Implement account lockout. Remove all default credentials.' },
        { id:'web-auth-002', title:'Username enumeration', description:'Identify username enumeration via: different error messages for valid vs invalid usernames, response timing differences, account lockout behaviour differences, password reset messages. Automated tool: ffuf with timing analysis.', severity:'medium', tags:['username-enumeration','authentication'], frameworks:['OWASP:WSTG-ATHN-04'], remediation:'Return generic error messages for all auth failures. Use consistent timing (constant-time comparison). Implement rate limiting regardless of validity.' },
        { id:'web-auth-003', title:'Brute force and lockout policy', description:'Test account lockout: threshold, lockout duration, lockout bypass via case variation or IP rotation. Test for missing lockout on: login, password reset, 2FA code entry, API key submission.', severity:'high', tags:['brute-force','lockout','authentication'], frameworks:['OWASP:WSTG-ATHN-03'], remediation:'Implement lockout after 5 failures. CAPTCHA after 3 failures. Notify user on lockout. Use progressive delays (exponential backoff).' },
        { id:'web-auth-004', title:'Multi-factor authentication bypass', description:'Test MFA implementation: replay of OTP codes, brute force of 6-digit codes, MFA bypass via direct URL access after step 1, fallback mechanism abuse, SIM swapping vectors (SMS-based MFA), CSRF on MFA enable/disable.', severity:'critical', tags:['mfa','2fa','otp','bypass'], frameworks:['OWASP:WSTG-ATHN-06'], remediation:'Enforce MFA state on server-side per request. Time-bound OTPs (30s window). Rate limit OTP attempts. Use hardware token or TOTP app over SMS.' },
        { id:'web-auth-005', title:'Password reset mechanism', description:'Test password reset: predictable tokens (timestamp-based, sequential), token reuse, token expiry, host header injection in reset emails, no rate limiting, reset poisoning via email parameter manipulation.', severity:'high', tags:['password-reset','token','authentication'], frameworks:['OWASP:WSTG-ATHN-09'], remediation:'Cryptographically random tokens (128+ bits). Single use, expire in 15 minutes. Invalidate on use. Verify Host header on email generation. Rate limit requests.' },
        { id:'web-auth-006', title:'JWT security testing', description:'Test JWT: algorithm confusion (RS256→HS256 using public key as secret, alg:none), weak secret cracking (hashcat -a 0 -m 16500), key confusion with JWKS, kid path traversal/injection, missing signature validation.', severity:'critical', tags:['jwt','authentication','token','algorithm-confusion'], frameworks:['OWASP:WSTG-ATHN'], remediation:'Enforce specific algorithm (RS256/ES256). Validate all claims. Use libraries, not custom implementations. Rotate signing keys. Verify signature server-side.' },
      ]
    },
    {
      id: 'web-authz',
      name: 'Authorization (WSTG-ATHZ)',
      items: [
        { id:'web-authz-001', title:'Broken object-level authorization (BOLA/IDOR)', description:'Test all resource identifiers (numeric IDs, GUIDs, filenames, hashes) for horizontal privilege escalation. Substitute own resource ID with another user\'s. Test all CRUD operations. Use two test accounts and Burp Autorize extension.', severity:'critical', tags:['idor','bola','authorization','horizontal-escalation'], frameworks:['OWASP:WSTG-ATHZ-01','OWASP:API1'], remediation:'Enforce object-level authorization checks per user session on every request. Never rely on obscurity (GUIDs). Indirect object references.' },
        { id:'web-authz-002', title:'Vertical privilege escalation', description:'Test for vertical privilege escalation: access admin functions as regular user, force-browse to admin URLs, modify role/group parameters, tamper with privilege-indicating cookies or tokens, test function-level authorization.', severity:'critical', tags:['vertical-escalation','authorization','privilege'], frameworks:['OWASP:WSTG-ATHZ-02'], remediation:'Enforce role-based access control server-side. Never trust client-supplied role or permission claims. Implement allowlist of authorized functions per role.' },
        { id:'web-authz-003', title:'Path traversal', description:'Test for path traversal in file serving endpoints, file download/upload, template inclusion, PDF generation. Payloads: ../../../etc/passwd, ..\\..\\..\\Windows\\win.ini, URL-encoded variants, double encoding.', severity:'high', tags:['path-traversal','lfi','file-access'], frameworks:['OWASP:WSTG-ATHZ-01'], remediation:'Canonicalize paths and validate against a safe base directory. Never concatenate user input into file paths. Use allowlist of permitted filenames.' },
        { id:'web-authz-004', title:'Mass assignment / parameter pollution', description:'Test for unintended field assignment in REST APIs: add extra fields to POST/PUT body (role:admin, isAdmin:true, verified:true). Test HTTP parameter pollution (duplicate parameters). Tool: Arjun for parameter discovery.', severity:'high', tags:['mass-assignment','parameter-pollution','api'], frameworks:['OWASP:API6'], remediation:'Use DTOs/input models with explicit field binding. Deny-by-default for model binding. Never auto-bind all request fields to domain objects.' },
      ]
    },
    {
      id: 'web-input',
      name: 'Input Validation (WSTG-INPV)',
      items: [
        { id:'web-inpv-001', title:'SQL injection', description:'Test all input parameters for SQL injection: error-based, blind boolean, time-based blind, out-of-band, second-order injection. Include: GET/POST params, headers, cookies, JSON/XML body, path segments. Tool: sqlmap, manual payloads.', severity:'critical', tags:['sqli','sql-injection','injection'], frameworks:['OWASP:WSTG-INPV-05','OWASP:A03'], remediation:'Parameterised queries / prepared statements everywhere. ORM with no raw SQL. Input validation as defense-in-depth. WAF. Principle of least privilege on DB accounts.' },
        { id:'web-inpv-002', title:'Cross-Site Scripting (XSS)', description:'Test for reflected, stored, and DOM-based XSS across all input/output points. Include: URL parameters, form fields, HTTP headers (User-Agent, Referer), JSON responses, JavaScript contexts (eval, innerHTML, href, setTimeout). Tool: Burp Suite, XSStrike.', severity:'high', tags:['xss','cross-site-scripting','injection'], frameworks:['OWASP:WSTG-INPV-01','OWASP:A03'], remediation:'Context-aware output encoding. Strict Content Security Policy. X-Content-Type-Options. HttpOnly cookies. DOM-based XSS: avoid dangerous sinks, use textContent over innerHTML.' },
        { id:'web-inpv-003', title:'XML External Entity (XXE)', description:'Test XML parsers for XXE: standard file read (file:///etc/passwd), SSRF via HTTP entity, blind XXE via out-of-band (DNS/HTTP), XInclude, SVG/DOCX/XLSX file upload vectors. Tool: Burp Suite, XXEinjector.', severity:'high', tags:['xxe','xml','ssrf','injection'], frameworks:['OWASP:WSTG-INPV-07','OWASP:A05'], remediation:'Disable external entity processing in XML parser. Use JSON where possible. Apply OWASP XXE prevention cheatsheet specific to your parser library.' },
        { id:'web-inpv-004', title:'Server-Side Request Forgery (SSRF)', description:'Test parameters that cause server-side HTTP requests: URL parameters, webhook URLs, image fetch, PDF generators, document importers, DNS rebinding. Test for: internal service access, cloud metadata (169.254.169.254), localhost services.', severity:'critical', tags:['ssrf','server-side','request-forgery'], frameworks:['OWASP:WSTG-INPV-19','OWASP:A10'], remediation:'Allowlist permitted domains/IPs for server-side requests. Disable redirects or validate final destination. Block access to metadata endpoints via IMDSv2. Deploy SSRF firewall rules.' },
        { id:'web-inpv-005', title:'Command injection (OS injection)', description:'Test parameters processed by OS commands: file operations, ping/traceroute tools, image processing (ImageMagick), archive extraction, document conversion. Payloads: ;id, |id, `id`, $(id), %0aid. Tool: commix.', severity:'critical', tags:['command-injection','os-injection','rce'], frameworks:['OWASP:WSTG-INPV-12'], remediation:'Never pass user input to shell commands. Use language APIs instead of shell. Parameterize all system calls. Run web process with minimal OS privileges.' },
        { id:'web-inpv-006', title:'SSTI — Server-side template injection', description:'Test template engines (Jinja2, Twig, Freemarker, Velocity, Pebble, Smarty, Handlebars) for injection: {{7*7}}, ${7*7}, <%= 7*7 %>. Escalate to RCE via template object access. Tool: tplmap.', severity:'critical', tags:['ssti','template-injection','rce'], frameworks:['OWASP:WSTG-INPV'], remediation:'Sandbox template rendering. Do not concatenate user input into templates. Use logic-less templates where possible. Upgrade to latest template engine version.' },
        { id:'web-inpv-007', title:'File upload security', description:'Test file upload: executable file upload (PHP, JSP, ASP, ASPX), MIME type bypass, double extension bypass, null byte injection, archive containing symlinks/path traversal (.zip slip), image with embedded code (polyglots), SVG XSS.', severity:'critical', tags:['file-upload','rce','webshell'], frameworks:['OWASP:WSTG-BUSL-08'], remediation:'Allowlist file types by content (magic bytes), not extension. Rename uploaded files. Store outside webroot. Disable execution in upload directory. Scan with AV.' },
        { id:'web-inpv-008', title:'HTTP request smuggling', description:'Test for HTTP request smuggling via CL.TE or TE.CL desynchronisation. Identify frontend/backend proxy split. Use Burp HTTP Request Smuggler. Can bypass security controls, hijack requests, or exploit cache poisoning.', severity:'high', tags:['request-smuggling','http','desync'], frameworks:['OWASP:WSTG-INPV'], remediation:'Normalise Transfer-Encoding before forwarding. Disable support for ambiguous requests. Use HTTP/2. Keep frontend and backend on same parsing implementation.' },
      ]
    },
    {
      id: 'web-session',
      name: 'Session Management (WSTG-SESS)',
      items: [
        { id:'web-sess-001', title:'Session token analysis', description:'Analyse session tokens for: predictability (sequential IDs, timestamp-based, low entropy), length (< 128 bits), transmission over HTTP, storage in localStorage vs HttpOnly cookie, token rotation on privilege change.', severity:'high', tags:['session','token','cookie','entropy'], frameworks:['OWASP:WSTG-SESS-01'], remediation:'Cryptographically random session IDs (128+ bits). HttpOnly + Secure + SameSite=Strict cookies. Rotate session ID on login/privilege change. Invalidate on logout.' },
        { id:'web-sess-002', title:'Cross-Site Request Forgery (CSRF)', description:'Test for CSRF on state-changing actions: missing CSRF token, predictable token, token not validated server-side, missing SameSite attribute, CORS bypass enabling CSRF, JSON CSRF via text/plain content-type.', severity:'high', tags:['csrf','cross-site-request-forgery','session'], frameworks:['OWASP:WSTG-SESS-05'], remediation:'Synchronizer token pattern. SameSite=Strict/Lax on session cookies. Verify Origin/Referer for state-changing requests. Double submit cookie pattern.' },
        { id:'web-sess-003', title:'Session fixation', description:'Test if application accepts session IDs provided before authentication and maintains same ID post-login. Set session ID in URL/cookie before login, then authenticate, verify same ID is used.', severity:'medium', tags:['session-fixation','authentication'], frameworks:['OWASP:WSTG-SESS-03'], remediation:'Always generate new session ID after successful authentication. Invalidate pre-authentication session. Do not accept session IDs from URL parameters.' },
      ]
    },
    {
      id: 'web-biz',
      name: 'Business Logic (WSTG-BUSL)',
      items: [
        { id:'web-busl-001', title:'Business logic bypass', description:'Test for bypassing business rules: negative quantities in shopping cart, skipping payment steps, modifying prices in hidden fields, applying discounts repeatedly, coupon code abuse, race conditions in inventory/balance checks.', severity:'high', tags:['business-logic','price-manipulation'], frameworks:['OWASP:WSTG-BUSL-01'], remediation:'Enforce all business rules server-side. Validate all states in workflow transitions. Implement idempotency for financial operations.' },
        { id:'web-busl-002', title:'Race conditions (TOCTOU)', description:'Test for race conditions: concurrent discount code redemption, concurrent withdrawal exceeding balance, concurrent account registration with same email, file upload concurrent processing. Tool: Turbo Intruder (Burp), goroutine race tool.', severity:'high', tags:['race-condition','toctou','concurrency'], frameworks:['OWASP:WSTG-BUSL-09'], remediation:'Implement optimistic/pessimistic locking. Use atomic database operations. Idempotency keys for financial transactions. Mutex for shared resources.' },
      ]
    },
  ]
};

// ─────────────────────────────────────────────────────────────────────────────

const MODULE_API = {
  id: 'api-security',
  name: 'API Security',
  type: 'pentest',
  icon: '⚡',
  description: 'API security testing aligned with OWASP API Security Top 10 and REST/GraphQL/gRPC specifics.',
  groups: [
    {
      id: 'api-auth',
      name: 'Authentication & Authorization',
      items: [
        { id:'api-auth-001', title:'API key and token exposure', description:'Search for API keys/tokens in: response headers, URL parameters, public Git repos, error messages, Swagger/OpenAPI spec, JavaScript bundles. Test for key rotation mechanism and revocation capability.', severity:'high', tags:['api-key','token','secrets'], frameworks:['OWASP:API2'], remediation:'API keys in Authorization header only. Implement key rotation and revocation. Use short-lived tokens. Scan repos for secrets (gitleaks, truffleHog).' },
        { id:'api-auth-002', title:'BOLA (Broken Object Level Authorization)', description:'Test every API endpoint for BOLA: enumerate resources by incrementing IDs, substitute other user\'s object IDs, test all HTTP methods (GET, PUT, DELETE, PATCH) per resource. Automate with two test accounts + Burp Autorize.', severity:'critical', tags:['bola','idor','api','authorization'], frameworks:['OWASP:API1'], remediation:'Enforce authorization at data layer per user session on every resource operation. Use UUIDs not sequential IDs. Implement centralised authorization module.' },
        { id:'api-auth-003', title:'Broken function level authorization', description:'Test for access to administrative/privileged API functions as standard user: admin endpoints (/admin, /internal, /manage), HTTP method upgrade (GET→DELETE), functionality exposed but not shown in UI.', severity:'critical', tags:['function-level-auth','api','privilege'], frameworks:['OWASP:API5'], remediation:'Inventory all API endpoints. Enforce RBAC on every function. Do not rely on obscurity. Test all HTTP methods per endpoint.' },
        { id:'api-auth-004', title:'JWT attacks on APIs', description:'Test JWT in API authentication: algorithm confusion (RS256→HS256), weak HMAC secret cracking, missing exp validation, kid injection (SQL/path traversal), jwks_uri manipulation, none algorithm acceptance.', severity:'critical', tags:['jwt','api','authentication'], frameworks:['OWASP:API2'], remediation:'Enforce algorithm. Validate all standard claims (exp, aud, iss). Use library for JWT handling. Rotate keys. Monitor for invalid signatures.' },
      ]
    },
    {
      id: 'api-input',
      name: 'Input Validation & Injection',
      items: [
        { id:'api-inj-001', title:'NoSQL injection', description:'Test APIs backed by MongoDB/CouchDB/Elasticsearch for NoSQL injection: operator injection ($gt, $ne, $regex, $where), authentication bypass ({username:{$gt:""}, password:{$gt:""}}), JSON injection. Tool: NoSQLMap.', severity:'high', tags:['nosql-injection','mongodb','injection'], frameworks:['OWASP:API3'], remediation:'Validate and sanitize all inputs. Use parameterized queries for NoSQL. Disable $where operator. Use ORM/ODM validation schemas.' },
        { id:'api-inj-002', title:'GraphQL-specific attacks', description:'Test GraphQL: introspection enabled (enumerate all types, queries, mutations), batch query DoS (unlimited query nesting), IDOR via GraphQL, injection in queries, alias override, __typename information disclosure.', severity:'high', tags:['graphql','introspection','injection'], frameworks:['OWASP:API3'], remediation:'Disable introspection in production. Implement query depth limits. Implement query cost analysis. Field-level authorization on all resolvers.' },
        { id:'api-inj-003', title:'Mass assignment via API', description:'Test for mass assignment: send extra fields in API request body (role, admin, verified, balance). Use verbose response comparison to identify bindable fields. Test all POST/PUT/PATCH endpoints.', severity:'high', tags:['mass-assignment','api'], frameworks:['OWASP:API6'], remediation:'Use explicit input validation schemas (JSON Schema). Allowlist permitted fields. Never auto-map request body to domain objects.' },
      ]
    },
    {
      id: 'api-ops',
      name: 'Rate Limiting & Operational',
      items: [
        { id:'api-ops-001', title:'Rate limiting and throttling', description:'Test API rate limiting: missing rate limits on auth endpoints, missing rate limits on resource-intensive endpoints, rate limit bypass (IP rotation, header manipulation, method switching, parameter variation).', severity:'high', tags:['rate-limiting','dos','api'], frameworks:['OWASP:API4'], remediation:'Implement rate limiting per user, per IP, and globally. Rate limit all authentication endpoints. Return 429 with Retry-After header.' },
        { id:'api-ops-002', title:'Excessive data exposure', description:'Check API responses for data over-fetching: sensitive fields returned but not displayed in UI (SSN, passwords, tokens, internal IDs, other users\' data). Compare API response to UI rendered data.', severity:'high', tags:['data-exposure','api','over-fetching'], frameworks:['OWASP:API3'], remediation:'Return only fields required by client. Use response DTOs. Never return raw DB models. Implement field-level filtering.' },
        { id:'api-ops-003', title:'API versioning and deprecated endpoints', description:'Identify deprecated/legacy API versions (v1, v2 while v3 is current). Test if old versions have weaker security controls. Map all version prefixes via enumeration and JS analysis.', severity:'medium', tags:['api-versioning','legacy','deprecated'], frameworks:['OWASP:API9'], remediation:'Maintain security controls across all API versions. Decommission old versions. Redirect to current version. Monitor usage of deprecated endpoints.' },
      ]
    },
  ]
};

// ─────────────────────────────────────────────────────────────────────────────

const MODULE_NETWORK_INTERNAL = {
  id: 'internal-network',
  name: 'Internal Network (L2/L3)',
  type: 'pentest',
  icon: '🔌',
  description: 'Layer 2 and internal network infrastructure security testing.',
  groups: [
    {
      id: 'net-l2',
      name: 'Layer 2 Attacks',
      items: [
        { id:'net-l2-001', title:'VLAN hopping (switch spoofing / double tagging)', description:'Test for VLAN hopping: switch spoofing via DTP negotiation (send DTP frames to trunk mode), double 802.1Q tagging to reach native VLAN. Tool: Yersinia, scapy. Identify native VLAN configuration.', severity:'high', tags:['vlan','l2','switch','dtp'], frameworks:['MITRE:T1599'], remediation:'Disable DTP on all access ports (switchport nonegotiate). Change native VLAN from VLAN 1. Prune VLANs from trunks. Enable port security.' },
        { id:'net-l2-002', title:'ARP spoofing / ARP poisoning', description:'Poison ARP cache of target and gateway to perform MITM. Capture credentials from HTTP, SMTP, FTP, Telnet sessions. Tool: arpspoof, ettercap, Bettercap. Evaluate if dynamic ARP inspection (DAI) is enabled.', severity:'high', tags:['arp-spoofing','mitm','l2'], frameworks:['MITRE:T1557.002'], remediation:'Enable Dynamic ARP Inspection (DAI) on all VLANs. Enable DHCP snooping as prerequisite. Use static ARP entries for critical hosts. Deploy 802.1X.' },
        { id:'net-l2-003', title:'DHCP starvation and rogue DHCP', description:'Exhaust DHCP pool by sending spoofed DHCPDISCOVER with random MACs (Yersinia, dhcpstarv). Then configure rogue DHCP server with attacker-controlled gateway/DNS. Enables DNS poisoning and network traffic capture.', severity:'high', tags:['dhcp','rogue-server','l2'], frameworks:['MITRE:T1557'], remediation:'Enable DHCP snooping. Port security limiting MACs per port. DHCP rate limiting. Deploy 802.1X NAC.' },
        { id:'net-l2-004', title:'STP (Spanning Tree) manipulation', description:'Send superior STP BPDUs to become root bridge, redirecting all L2 traffic through attacker. Tool: Yersinia. Test if BPDU guard and root guard are configured on access ports.', severity:'high', tags:['stp','spanning-tree','l2','root-bridge'], frameworks:['MITRE:T1557'], remediation:'Enable BPDU Guard on all access ports. Enable Root Guard on uplinks. Enable portfast only on end-device ports. Deploy RSTP.' },
      ]
    },
    {
      id: 'net-l3',
      name: 'Layer 3 & Services',
      items: [
        { id:'net-l3-001', title:'Internal DNS poisoning', description:'Test for DNS cache poisoning on internal resolver. Test for DNS zone transfer (AXFR) availability. Enumerate internal DNS records. Test for DNS-over-HTTP/HTTPS bypass. Tool: dig, dnsrecon, Bettercap dns.spoof.', severity:'high', tags:['dns','dns-poisoning','zone-transfer'], frameworks:['MITRE:T1557.003'], remediation:'Disable AXFR from non-authoritative sources. Implement DNSSEC. Deploy DNS response rate limiting. Restrict recursive DNS to authoritative sources.' },
        { id:'net-l3-002', title:'Network service enumeration', description:'Enumerate all internal services: identify hosts via ping sweep, port scan (nmap), service version detection, OS fingerprinting. Map internal subnets. Identify out-of-support systems (Windows XP/2003/2008, end-of-life Linux).', severity:'info', tags:['enumeration','nmap','service-discovery'], frameworks:['MITRE:T1046'], remediation:'Maintain asset inventory. Restrict network access via firewalls/VLANs. Decommission EOL systems. Implement network access control.' },
        { id:'net-l3-003', title:'Cleartext protocol capture', description:'Capture network traffic to identify cleartext authentication or sensitive data transmission: Telnet, FTP, HTTP, SMTP, POP3, IMAP, LDAP, NFS, rsh. Tool: Wireshark, tcpdump, Bettercap sniffer.', severity:'high', tags:['cleartext','sniffing','protocols'], frameworks:['MITRE:T1040'], remediation:'Mandate encrypted protocols (SSH, SFTP/FTPS, HTTPS, SMTPS, LDAPS). Disable cleartext alternatives. Deploy MACsec for L2 encryption in sensitive segments.' },
        { id:'net-l3-004', title:'Unauthenticated network service access', description:'Identify critical services accessible without authentication: databases (MongoDB, Redis, Elasticsearch, CouchDB default install), admin panels, SNMP v1/v2 with default community strings, Jenkins without auth, Kibana.', severity:'critical', tags:['unauthenticated','database','service-exposure'], frameworks:['MITRE:T1190'], remediation:'Require authentication on all services. Bind services to required interfaces only. Firewall databases from direct user access. Change all default community strings.' },
        { id:'net-l3-005', title:'SNMP enumeration and default strings', description:'Test SNMP v1/v2c for default community strings (public, private, community, manager). Enumerate via SNMP: system info, interface details, routing table, user accounts on some devices. Tool: snmpwalk, onesixtyone.', severity:'high', tags:['snmp','default-strings','enumeration'], frameworks:['MITRE:T1201'], remediation:'Disable SNMPv1/v2c where possible. Migrate to SNMPv3 with authentication and encryption. Change all default community strings. ACL SNMP access to monitoring systems only.' },
      ]
    },
  ]
};

// ─────────────────────────────────────────────────────────────────────────────

const MODULE_EXTERNAL = {
  id: 'external-network',
  name: 'External Network',
  type: 'pentest',
  icon: '🌍',
  description: 'External attack surface assessment — perimeter, public exposure, and internet-facing exploitation.',
  groups: [
    {
      id: 'ext-recon',
      name: 'Reconnaissance',
      items: [
        { id:'ext-rec-001', title:'OSINT and attack surface mapping', description:'Map external attack surface: subdomain enumeration (amass, subfinder, crt.sh), ASN/IP range identification (bgp.he.net, whois), email harvesting (theHarvester), breach data (HIBP, DeHashed), public code repos (GitHub dorking), Shodan/Censys exposure.', severity:'info', tags:['osint','recon','subdomains','shodan'], frameworks:['MITRE:T1589','MITRE:T1596'], remediation:'Monitor public exposure of internal assets. Implement DMARC/DKIM/SPF. Remove sensitive data from public code repos. Use Shodan alerts for exposed services.' },
        { id:'ext-rec-002', title:'DNS security configuration', description:'Test: DNSSEC deployment, zone transfer from external, DNS wildcard records, SPF/DKIM/DMARC configuration, dangling DNS records (subdomain takeover candidates), MX record security.', severity:'medium', tags:['dns','dnssec','spf','dmarc','subdomain-takeover'], frameworks:['MITRE:T1584.002'], remediation:'Implement DMARC (p=reject). SPF with -all. DKIM for all sending domains. DNSSEC. Audit all DNS records for dangling CNAMEs.' },
        { id:'ext-rec-003', title:'Subdomain takeover', description:'Identify subdomains pointing to unclaimed third-party services (GitHub Pages, Heroku, Azure, S3 buckets, Fastly, Zendesk). Verify CNAME chain termination. Tool: subjack, nuclei subdomain-takeover templates.', severity:'high', tags:['subdomain-takeover','dns','cname'], frameworks:['MITRE:T1584.001'], remediation:'Audit all DNS records. Remove CNAME entries for decommissioned services. Implement DNS management process for decommissioning.' },
      ]
    },
    {
      id: 'ext-vuln',
      name: 'Vulnerability Assessment',
      items: [
        { id:'ext-vuln-001', title:'Public-facing vulnerability scanning', description:'Comprehensive vulnerability scan of all external IPs and domains: authenticated scan where possible, service version fingerprinting, CVE correlation. Tool: Nessus/OpenVAS, Nuclei with CVE templates. Validate findings manually.', severity:'info', tags:['vulnerability-scan','cve','external'], frameworks:['MITRE:T1595'], remediation:'Patch critical/high findings within SLA. Implement virtual patching via WAF where required. Reduce attack surface by closing unnecessary ports.' },
        { id:'ext-vuln-002', title:'Web application firewall (WAF) detection and bypass', description:'Detect WAF presence and vendor (wafw00f). Test basic WAF bypass techniques: encoding variations, case manipulation, whitespace injection, HTTP header injection. Evaluate WAF effectiveness against OWASP Top 10.', severity:'medium', tags:['waf','bypass','external'], frameworks:[], remediation:'Ensure WAF is in blocking mode. Tune WAF rules to application. Implement WAF bypass monitoring. Do not rely solely on WAF for injection protection.' },
        { id:'ext-vuln-003', title:'Email security (phishing attack surface)', description:'Test email security controls: SPF strictness (-all vs ~all), DMARC policy (p=none vs p=quarantine/reject), DKIM signature validation, email spoofing potential, open relay test, MTA-STS deployment.', severity:'high', tags:['email','spf','dmarc','phishing'], frameworks:['MITRE:T1566'], remediation:'Enforce DMARC p=reject. SPF -all. DKIM on all sending domains. MTA-STS. Anti-spoofing rules in email gateway.' },
        { id:'ext-vuln-004', title:'VPN and remote access security', description:'Identify VPN gateway vendor/version (Pulse, Fortinet, Citrix, GlobalProtect, SonicWall). Test for known CVEs (CVE-2019-11510, CVE-2018-13379, CVE-2022-42475). Check certificate, MFA enforcement, split tunneling configuration.', severity:'critical', tags:['vpn','remote-access','cve'], frameworks:['MITRE:T1133'], remediation:'Patch VPN appliances immediately when CVEs are published. Enforce MFA. Monitor for authentication anomalies. Restrict split tunneling.' },
      ]
    },
  ]
};

// ─────────────────────────────────────────────────────────────────────────────

const MODULE_WIRELESS = {
  id: 'wireless',
  name: 'Wireless',
  type: 'pentest',
  icon: '📡',
  description: 'Wireless network security assessment covering encryption, authentication, and client attacks.',
  groups: [
    {
      id: 'wifi-enc',
      name: 'Encryption & Authentication',
      items: [
        { id:'wifi-enc-001', title:'WPA2/WPA3 handshake capture and offline crack', description:'Capture 4-way handshake by deauthenticating a client (aireplay-ng). Crack PSK offline with hashcat (mode 22000) using wordlist + rules. Test for PMKID capture (no client deauth needed). Identify WPA3 SAE deployment.', severity:'high', tags:['wpa2','handshake','offline-crack','wifi'], frameworks:['MITRE:T1040'], remediation:'Use WPA3 where possible. Strong passphrase (20+ chars, random). Enterprise authentication (802.1X). Disable WPS.' },
        { id:'wifi-enc-002', title:'WEP and WPA-TKIP detection', description:'Identify any networks still using WEP or WPA-TKIP (deprecated, cryptographically broken). WEP can be cracked in minutes. TKIP subject to BEAST and other attacks.', severity:'critical', tags:['wep','tkip','deprecated','wifi'], frameworks:[], remediation:'Immediately upgrade to WPA2-CCMP or WPA3. Decommission any WEP/TKIP-only devices. Replace legacy hardware.' },
        { id:'wifi-enc-003', title:'WPS vulnerability testing', description:'Test for WPS PIN brute force (Reaver, Bully) and PixieDust attack against WPS implementations with weak random number generation. Check if WPS is enabled on access points.', severity:'high', tags:['wps','wifi','brute-force'], frameworks:[], remediation:'Disable WPS on all access points. If required, use WPS Push Button only (not PIN).' },
        { id:'wifi-enc-004', title:'802.1X EAP security (enterprise WiFi)', description:'Identify EAP method used (EAP-PEAP, EAP-TLS, EAP-TTLS, EAP-MD5). Test for: improper certificate validation enabling hostapd-wpe attack, PEAP MSCHAPv2 credential capture, inner method downgrade. Tool: hostapd-wpe, EAPHammer.', severity:'high', tags:['802.1x','eap','peap','enterprise-wifi'], frameworks:[], remediation:'Enforce EAP-TLS (certificate-based). If using PEAP, enforce server certificate validation on all clients. Distribute trusted CA to all endpoints via MDM.' },
      ]
    },
    {
      id: 'wifi-client',
      name: 'Client & Rogue AP Attacks',
      items: [
        { id:'wifi-cli-001', title:'Evil Twin / Rogue AP attack', description:'Deploy rogue AP with same SSID as corporate network. Enable deauth to force clients to connect. Capture credentials or perform MITM. Tool: hostapd-wpe, EAPHammer, airbase-ng. Evaluate client detection capability.', severity:'critical', tags:['evil-twin','rogue-ap','mitm','wifi'], frameworks:['MITRE:T1557'], remediation:'Deploy wireless intrusion detection/prevention (WIDS/WIPS). 802.1X with certificate validation prevents credential harvesting. Educate users on certificate warnings.' },
        { id:'wifi-cli-002', title:'Karma / PMKID attack', description:'Respond to all probe requests (KARMA) to capture association attempts from clients looking for previously connected networks. Combined with PMKID for passive capture without client interaction.', severity:'high', tags:['karma','probe-request','wifi','client'], frameworks:['MITRE:T1040'], remediation:'Use randomised probe requests (modern OS default). Configure clients to only connect to known networks. Use 802.1X which prevents KARMA capture.' },
        { id:'wifi-cli-003', title:'Deauthentication attack (DoS)', description:'Send spoofed IEEE 802.11 deauthentication frames to disassociate clients from legitimate AP. Management frames are unprotected in WPA2. WPA3 adds Management Frame Protection (MFP/PMF). Test for PMF enforcement.', severity:'medium', tags:['deauth','dos','management-frames','wifi'], frameworks:['MITRE:T1498'], remediation:'Enable Protected Management Frames (PMF/802.11w). Use WPA3 which mandates PMF. Detect deauth floods with WIDS.' },
      ]
    },
  ]
};

// ─────────────────────────────────────────────────────────────────────────────

const MODULE_PHYSICAL = {
  id: 'physical-security',
  name: 'Physical Security',
  type: 'pentest',
  icon: '🔒',
  description: 'Physical security assessment — access controls, social engineering, and device security.',
  groups: [
    {
      id: 'phys-access',
      name: 'Physical Access Controls',
      items: [
        { id:'phys-acc-001', title:'Perimeter access control evaluation', description:'Assess physical perimeter: fence security, gate controls, guard coverage, CCTV blind spots, tailgating opportunities, mantrap effectiveness, visitor management, delivery bay access. Attempt access without authorization.', severity:'high', tags:['physical','access-control','perimeter'], frameworks:['ISO27001:A.11.1'], remediation:'Implement two-person integrity for sensitive areas. Mantrap with anti-tailgate sensors. 24/7 CCTV coverage with alerting. Sign-in register for all visitors.' },
        { id:'phys-acc-002', title:'Badge cloning and access card security', description:'Test RFID/NFC badge security: identify card technology (125kHz HID, MIFARE Classic, iCLASS), attempt credential cloning (Proxmark3, Flipper Zero), test replay attacks, test MIFARE Classic encryption (CRYPTO-1 weakness).', severity:'critical', tags:['rfid','badge-cloning','access-card'], frameworks:['ISO27001:A.11.1'], remediation:'Upgrade to MIFARE DESFire EV3 or SEOS. Implement PIN+card (two-factor). Add visual verification for high-security areas. Deploy OSDP instead of Wiegand.' },
        { id:'phys-acc-003', title:'Lock and door security', description:'Test physical lock security: lock picking (pin tumbler, wafer), bypass techniques (loid, shimming, under-door tools), electromagnetic lock failure mode (fail-safe vs fail-secure), door frame integrity, REX sensor bypass.', severity:'high', tags:['lock-picking','physical','door-security'], frameworks:['ISO27001:A.11.1'], remediation:'High-security locks (Abloy Protect2, Medeco). Door sensors for forced entry. Video verification for critical access events. Regular door frame and closer inspection.' },
        { id:'phys-acc-004', title:'Sensitive area access (server room, DC, comms)', description:'Assess access controls to server rooms, data centres, communications rooms, and wiring closets: who has access (audit logs), whether access is logged and reviewed, whether unescorted access is permitted, cable management exposure.', severity:'critical', tags:['server-room','data-center','physical'], frameworks:['ISO27001:A.11.1','DORA'], remediation:'Biometric + card for server rooms. All access logged and reviewed. Escort policy for non-IT staff. Cage locks for individual server racks.' },
      ]
    },
    {
      id: 'phys-se',
      name: 'Social Engineering',
      items: [
        { id:'phys-se-001', title:'Tailgating and impersonation', description:'Attempt to gain physical access by tailgating legitimate employees, impersonating IT support, delivery personnel, or cleaning staff. Test if employees challenge unfamiliar individuals in secure areas.', severity:'high', tags:['social-engineering','tailgating','impersonation'], frameworks:['MITRE:T1200'], remediation:'Security awareness training for challenging unknown persons. "Challenge culture" programme. Visitor badges clearly distinguishable. Escort policy enforcement.' },
        { id:'phys-se-002', title:'Dumpster diving and information disclosure', description:'Inspect disposed materials for: printed documents with sensitive data, storage media (USB, HDD), labels revealing system info, network diagrams, personnel lists. Test shredding and secure disposal processes.', severity:'medium', tags:['dumpster-diving','information-disclosure','physical'], frameworks:['ISO27001:A.11.2'], remediation:'Cross-cut shredding for all printed documents. Certified media destruction for storage devices. Clear desk policy. Destruction audit trail.' },
      ]
    },
    {
      id: 'phys-device',
      name: 'Device & Media Security',
      items: [
        { id:'phys-dev-001', title:'Rogue device deployment (dropbox / implant)', description:'Test if network access is physically available in unsecured locations (lobby, conference rooms, under desks). Attempt connection of rogue device (LAN Turtle, Bash Bunny, Pi). Test 802.1X enforcement on wired ports.', severity:'critical', tags:['rogue-device','dropbox','network-access','802.1x'], frameworks:['MITRE:T1200'], remediation:'Deploy 802.1X NAC on all wired ports. Disable unused switch ports. Lock patch panels. Monitor for new MAC addresses on network.' },
        { id:'phys-dev-002', title:'Unattended workstation access', description:'Test if unattended workstations auto-lock after defined timeout. Test if screen lock can be bypassed. Check for password-protected BIOS. Test USB boot capability. Test HDD encryption deployment (BitLocker, LUKS).', severity:'high', tags:['workstation','screen-lock','encryption','physical'], frameworks:['CIS-W-5'], remediation:'Auto-lock after 5 minutes via GPO. BIOS password. Disable USB boot. BitLocker with TPM+PIN on all laptops. Disable direct memory access ports (Thunderbolt).' },
        { id:'phys-dev-003', title:'Clean desk policy compliance', description:'Assess compliance with clean desk policy: documents left unattended, unattended logged-in sessions, physical keys left at desk, passwords written down, portable media left out.', severity:'medium', tags:['clean-desk','policy','physical'], frameworks:['ISO27001:A.11.2'], remediation:'Enforce clean desk policy via written policy and regular walkthroughs. Locked drawers/cabinets for sensitive documents. Document destruction near workstations.' },
      ]
    },
  ]
};

// ─────────────────────────────────────────────────────────────────────────────

const MODULE_CLOUD = {
  id: 'cloud-security',
  name: 'Cloud Security',
  type: 'pentest',
  icon: '☁️',
  description: 'Cloud security assessment — IAM, storage, network, and compute misconfigurations (AWS/Azure/GCP).',
  groups: [
    {
      id: 'cloud-iam',
      name: 'Identity & Access Management',
      items: [
        { id:'cloud-iam-001', title:'IAM privilege escalation paths', description:'Enumerate IAM policies and identify privilege escalation paths: PassRole + CreateFunction, AttachUserPolicy, CreatePolicyVersion, UpdateAssumeRolePolicy, iam:* on self, ec2:RunInstances with IAM instance profile. Tool: Pacu, PMapper.', severity:'critical', tags:['iam','privilege-escalation','cloud','aws'], frameworks:['MITRE:T1078.004'], remediation:'Enforce least privilege IAM. Use AWS IAM Access Analyzer. Remove dangerous permission combinations. Require MFA for sensitive operations.' },
        { id:'cloud-iam-002', title:'Cloud metadata service (IMDS) exposure', description:'Test for SSRF leading to EC2/Azure/GCP metadata service access. AWS: http://169.254.169.254/latest/. Test if IMDSv1 is disabled (IMDSv2 requires PUT with TTL header). Check for overly permissive instance roles.', severity:'critical', tags:['imds','metadata','ssrf','cloud'], frameworks:['MITRE:T1552.005'], remediation:'Enforce IMDSv2 on all EC2 instances. Restrict instance role permissions. Block metadata access at WAF if application has SSRF risk.' },
        { id:'cloud-iam-003', title:'Service account and API key exposure', description:'Search for exposed cloud credentials: GitHub repos, CI/CD logs, Lambda environment variables, S3 bucket contents, EC2 user-data scripts, AMI snapshots, container images. Tool: truffleHog, gitleaks, Prowler.', severity:'critical', tags:['api-key','secrets','cloud','exposure'], frameworks:['MITRE:T1552.001'], remediation:'Rotate all exposed credentials immediately. Use IAM roles for service-to-service auth. Implement secrets manager (AWS Secrets Manager, Azure Key Vault). Scan repos for secrets.' },
      ]
    },
    {
      id: 'cloud-storage',
      name: 'Storage & Data',
      items: [
        { id:'cloud-stor-001', title:'Public S3 bucket / blob storage enumeration', description:'Enumerate S3 buckets/Azure blobs/GCS buckets for: public read access, public write access, authenticated-user accessible, misconfigured ACLs. Tools: S3Scanner, cloud_enum, BucketFinder. Check bucket policy and ACLs.', severity:'critical', tags:['s3','blob-storage','public-access','cloud'], frameworks:['MITRE:T1530'], remediation:'Block public access at account/organization level (S3 Block Public Access). Audit bucket policies. Enable S3 server access logging. Use AWS Config rules for bucket compliance.' },
        { id:'cloud-stor-002', title:'Cloud snapshot and backup exposure', description:'Check for publicly accessible EBS snapshots, RDS snapshots, and AMIs. Attackers can mount snapshots to extract data. Tool: Pacu snapshot enumeration, AWS CLI describe-snapshots with --owner-id.', severity:'high', tags:['snapshots','backup','cloud','exposure'], frameworks:['MITRE:T1530'], remediation:'Restrict snapshot permissions to specific accounts. Encrypt all snapshots. Audit snapshot sharing settings. Automated compliance rules.' },
      ]
    },
    {
      id: 'cloud-net',
      name: 'Network & Compute',
      items: [
        { id:'cloud-net-001', title:'Security group overly permissive rules', description:'Identify security groups with 0.0.0.0/0 source on: SSH (22), RDP (3389), database ports (3306, 5432, 1433, 27017), admin panels, internal services. Test if instances are reachable from internet.', severity:'high', tags:['security-groups','firewall','cloud','exposure'], frameworks:['CIS-AWS-4'], remediation:'Restrict security groups to required source IPs. Implement jump host / Systems Manager Session Manager. Regular security group audit. Use AWS Config rules.' },
        { id:'cloud-net-002', title:'CloudTrail / audit logging configuration', description:'Verify CloudTrail (AWS) or equivalent audit logging: all regions enabled, management and data events logged, log integrity validation enabled, logs stored securely (encrypted, cross-account), real-time alerting on sensitive actions.', severity:'high', tags:['cloudtrail','logging','cloud','audit'], frameworks:['CIS-AWS-2','MITRE:T1562.008'], remediation:'Enable CloudTrail in all regions with S3 log file validation. Send to SIEM. Alert on root account usage, IAM changes, and security group modifications.' },
        { id:'cloud-net-003', title:'Container and Kubernetes security', description:'If Kubernetes/EKS/AKS/GKE deployed: test for unauthenticated API server access, RBAC misconfigurations, privileged containers, hostPath mounts, service account token exposure, container escape techniques.', severity:'high', tags:['kubernetes','containers','eks','rbac'], frameworks:['MITRE:T1610'], remediation:'Restrict Kubernetes API access. Implement RBAC least privilege. Use Pod Security Standards (restricted). Run containers as non-root. Scan images for vulnerabilities.' },
      ]
    },
  ]
};

// ─────────────────────────────────────────────────────────────────────────────
// CONSULTANT MODULES
// ─────────────────────────────────────────────────────────────────────────────

const MODULE_NIS2 = {
  id: 'nis2',
  name: 'NIS2 Directive',
  type: 'consultant',
  icon: '🇪🇺',
  description: 'Structured assessment against NIS2 Directive (EU 2022/2555) requirements applicable to essential and important entities.',
  groups: [
    {
      id: 'nis2-gov',
      name: 'Governance & Management Body',
      items: [
        { id:'nis2-gov-001', title:'Management body approval of cybersecurity measures', description:'Verify that the management body (board/C-suite) formally approves, oversees, and can be held accountable for cybersecurity risk management measures as required under NIS2 Art. 20(1). Document evidence of approval and oversight.', severity:'high', tags:['governance','nis2','management'], frameworks:['NIS2:Art.20'], remediation:'Establish formal board-level cybersecurity oversight. Create board cybersecurity committee. Document approval of risk management policies. Schedule quarterly cybersecurity reporting to board.' },
        { id:'nis2-gov-002', title:'Cybersecurity training for management body', description:'Verify that members of the management body receive regular cybersecurity training to maintain sufficient knowledge and skills for governance responsibilities (NIS2 Art. 20(2)).', severity:'medium', tags:['training','governance','management','nis2'], frameworks:['NIS2:Art.20'], remediation:'Implement mandatory cybersecurity awareness training for board members. Annual training on cybersecurity risks, obligations, and incident reporting. Document attendance.' },
        { id:'nis2-gov-003', title:'Cybersecurity policy documentation', description:'Verify existence of documented, approved, and maintained cybersecurity policies covering all NIS2-required domains. Policies should be reviewed at least annually and after significant incidents.', severity:'high', tags:['policy','governance','nis2'], frameworks:['NIS2:Art.21'], remediation:'Develop/update comprehensive cybersecurity policy suite. Assign policy ownership. Implement review cycle. Communicate policies to all staff.' },
        { id:'nis2-gov-004', title:'Cybersecurity roles and responsibilities', description:'Verify clear assignment of cybersecurity responsibilities (CISO or equivalent), reporting lines, and authority. Verify CISO has sufficient independence, resources, and access to management body.', severity:'medium', tags:['roles','ciso','governance','nis2'], frameworks:['NIS2:Art.21'], remediation:'Appoint CISO with defined mandate. Document responsibilities in RACI matrix. Ensure CISO reports directly to board or CEO. Provide adequate budget and staffing.' },
      ]
    },
    {
      id: 'nis2-risk',
      name: 'Risk Management (Art. 21)',
      items: [
        { id:'nis2-risk-001', title:'Cybersecurity risk management framework', description:'Assess maturity of cybersecurity risk management framework: risk identification methodology, risk assessment frequency, risk appetite definition, risk treatment plans, risk register maintenance, residual risk acceptance process.', severity:'high', tags:['risk-management','framework','nis2'], frameworks:['NIS2:Art.21.1'], remediation:'Implement formal risk management process (aligned with ISO 31000 or NIST SP 800-30). Quarterly risk register review. Document risk acceptance decisions.' },
        { id:'nis2-risk-002', title:'Asset management and classification', description:'Verify existence of comprehensive asset inventory covering hardware, software, data, and cloud assets. Verify assets are classified by criticality/sensitivity. Assess coverage of asset discovery processes.', severity:'high', tags:['asset-management','inventory','classification','nis2'], frameworks:['NIS2:Art.21.2'], remediation:'Implement automated asset discovery. Classify all assets by criticality. Assign data custodians. Integrate with CMDB. Review quarterly.' },
        { id:'nis2-risk-003', title:'Vulnerability management programme', description:'Assess vulnerability management maturity: scanning coverage and frequency, patch management SLAs per severity, vulnerability prioritisation (CVSS + context), exception process, treatment tracking. Verify critical patches applied within defined SLA.', severity:'high', tags:['vulnerability-management','patching','nis2'], frameworks:['NIS2:Art.21.2.e'], remediation:'Deploy automated vulnerability scanning (weekly minimum). Define patch SLAs: Critical <48h, High <7d, Medium <30d. Implement patch management tooling. Monthly reporting to management.' },
        { id:'nis2-risk-004', title:'Cryptography and encryption controls', description:'Assess use of encryption for data at rest and in transit for sensitive/critical systems. Verify key management procedures: key generation, storage (HSM), rotation, revocation, escrow. Review cryptographic algorithms used (no deprecated algorithms: MD5, SHA-1, DES, RC4).', severity:'high', tags:['encryption','cryptography','key-management','nis2'], frameworks:['NIS2:Art.21.2.h'], remediation:'Implement data classification-driven encryption policy. Enforce TLS 1.2/1.3. Encrypt all sensitive data at rest (AES-256). Use HSM for critical key storage. Crypto agility roadmap.' },
        { id:'nis2-risk-005', title:'Multi-factor authentication deployment', description:'Verify MFA deployment scope and coverage: all remote access, all privileged access, all cloud access. Review MFA methods used (resistance to phishing: FIDO2, hardware tokens preferred over SMS). Identify gaps in MFA coverage.', severity:'critical', tags:['mfa','authentication','access-control','nis2'], frameworks:['NIS2:Art.21.2.j'], remediation:'Mandate phishing-resistant MFA (FIDO2/WebAuthn) for all privileged users. MFA for all remote access. Phase out SMS-based MFA. Deploy conditional access policies.' },
      ]
    },
    {
      id: 'nis2-incident',
      name: 'Incident Handling (Art. 23)',
      items: [
        { id:'nis2-inc-001', title:'Incident management process', description:'Assess incident management process maturity: incident classification scheme, escalation procedures, response playbooks for common incident types, documentation requirements, post-incident review process.', severity:'critical', tags:['incident-response','process','nis2'], frameworks:['NIS2:Art.23'], remediation:'Develop IRP covering detection, triage, containment, eradication, recovery, lessons learned. Define incident severity classification. Test plan via tabletop exercises.' },
        { id:'nis2-inc-002', title:'NIS2 incident reporting process (Art. 23)', description:'Verify NIS2-compliant incident reporting process: Early warning within 24h, Incident notification within 72h, Final report within 1 month. Identify CSIRT/NCA notification chain. Verify reporting templates and responsible personnel.', severity:'critical', tags:['incident-reporting','csirt','nis2','notification'], frameworks:['NIS2:Art.23'], remediation:'Document reporting procedures with clear timelines. Identify CSIRT contact details for your Member State. Define who authorises notifications. Conduct reporting drill.' },
        { id:'nis2-inc-003', title:'Detection and monitoring capability', description:'Assess detection capability: SIEM coverage, EDR deployment, network monitoring, log collection and retention (minimum 12 months recommended), alerting rules, SOC coverage hours (24/7 vs business hours), mean time to detect (MTTD) metrics.', severity:'high', tags:['detection','siem','monitoring','nis2'], frameworks:['NIS2:Art.21.2.b'], remediation:'Deploy centralised SIEM with 12-month log retention. EDR on all endpoints. Network traffic analysis. Define detection use cases aligned with MITRE ATT&CK. Measure and improve MTTD.' },
      ]
    },
    {
      id: 'nis2-bcp',
      name: 'Business Continuity (Art. 21)',
      items: [
        { id:'nis2-bcp-001', title:'Business continuity and disaster recovery planning', description:'Assess BCP/DRP maturity: formal BCP/DRP documentation, defined RTO/RPO per critical system, tested recovery procedures, backup verification, alternative site arrangements, communication plans during crisis.', severity:'high', tags:['bcp','drp','continuity','nis2'], frameworks:['NIS2:Art.21.2.c'], remediation:'Document BCP/DRP for all critical services. Define and test RTO/RPO. Conduct annual DR test. Verify backup restoration. Establish crisis communication chain.' },
        { id:'nis2-bcp-002', title:'Backup and recovery testing', description:'Verify backup processes: scope (all critical data), frequency (daily minimum), retention (aligned with RTO/RPO), offsite/cloud storage, encryption, integrity checking (regular restore tests), air-gapped backups for ransomware resistance.', severity:'high', tags:['backup','recovery','ransomware','nis2'], frameworks:['NIS2:Art.21.2.c'], remediation:'Implement 3-2-1 backup strategy. Test restores monthly. Air-gapped backups for critical systems. Encrypt all backups. Document and verify RTO/RPO achievement.' },
        { id:'nis2-bcp-003', title:'Crisis management capability', description:'Assess crisis management: defined crisis team (IT, legal, communications, exec), crisis communication templates, customer/regulator notification procedures, media response plan, regulatory engagement process.', severity:'medium', tags:['crisis-management','communication','nis2'], frameworks:['NIS2:Art.21.2.c'], remediation:'Establish crisis management team with defined roles. Crisis communication playbook. Pre-approved messaging templates. Quarterly crisis simulation.' },
      ]
    },
    {
      id: 'nis2-supply',
      name: 'Supply Chain Security (Art. 21)',
      items: [
        { id:'nis2-sup-001', title:'Third-party and supply chain risk management', description:'Assess TPCRM programme: supplier security assessment process, security requirements in contracts, ongoing monitoring of critical suppliers, software supply chain controls, exit strategy for critical dependencies.', severity:'high', tags:['supply-chain','third-party','tpcrm','nis2'], frameworks:['NIS2:Art.21.2.d'], remediation:'Implement supplier risk classification. Security assessment for critical suppliers. Contractual security requirements (right-to-audit). Annual supplier review. Software BOM requirements.' },
        { id:'nis2-sup-002', title:'Software and hardware supply chain controls', description:'Verify controls for software supply chain: software composition analysis (SCA) for open source dependencies, SBOM generation and review, developer code signing, trusted software repositories, firmware integrity verification.', severity:'high', tags:['sbom','software-supply-chain','sca','nis2'], frameworks:['NIS2:Art.21.2.d'], remediation:'Implement SCA in CI/CD pipeline. Generate and maintain SBOM. Require vendor SBOM. Monitor for open source vulnerabilities (Dependabot, Snyk).' },
      ]
    },
    {
      id: 'nis2-access',
      name: 'Access Control & HR Security',
      items: [
        { id:'nis2-acc-001', title:'Access control policy and implementation', description:'Assess access control: least privilege enforcement, role-based access control (RBAC), privilege review frequency (quarterly minimum for privileged access), joiners/movers/leavers process (access removed within 24h of departure), generic/shared account usage.', severity:'high', tags:['access-control','rbac','least-privilege','nis2'], frameworks:['NIS2:Art.21.2.i'], remediation:'Implement RBAC across all systems. Quarterly access reviews. Automate JML process via HR system integration. Disable accounts same day as departure. Eliminate shared accounts.' },
        { id:'nis2-acc-002', title:'Privileged access management (PAM)', description:'Assess PAM programme: identification of all privileged accounts, just-in-time (JIT) privileged access, privileged session recording, vault for privileged credentials, use of dedicated admin workstations.', severity:'critical', tags:['pam','privileged-access','nis2'], frameworks:['NIS2:Art.21.2.i'], remediation:'Deploy PAM tooling (CyberArk, Delinea, BeyondTrust). Vault all privileged credentials. JIT provisioning for admin access. Session recording for all privileged sessions. Dedicated admin workstations.' },
      ]
    },
  ]
};

// ─────────────────────────────────────────────────────────────────────────────

const MODULE_NIST_CSF = {
  id: 'nist-csf',
  name: 'NIST CSF 2.0',
  type: 'consultant',
  icon: '🇺🇸',
  description: 'Assessment aligned with NIST Cybersecurity Framework 2.0 — all 6 Functions (GV, ID, PR, DE, RS, RC).',
  groups: [
    {
      id: 'csf-govern',
      name: 'GV — Govern',
      items: [
        { id:'csf-gv-001', title:'GV.OC: Organisational context and mission', description:'Verify the organisation understands its cybersecurity obligations, stakeholder expectations, regulatory requirements, and how they relate to mission objectives. Document legal, regulatory, and contractual requirements.', severity:'medium', tags:['nist-csf','govern','context'], frameworks:['NIST-CSF:GV.OC'], remediation:'Conduct stakeholder analysis. Document regulatory landscape. Align cybersecurity strategy with business objectives. Review annually.' },
        { id:'csf-gv-002', title:'GV.RM: Risk management strategy', description:'Assess whether a documented risk management strategy exists with defined risk appetite, risk tolerance thresholds, and integration of cybersecurity risk into enterprise risk management (ERM).', severity:'high', tags:['nist-csf','govern','risk-management'], frameworks:['NIST-CSF:GV.RM'], remediation:'Document risk appetite statements. Integrate cyber risk into ERM. Define risk tolerance thresholds per asset class. Quarterly risk reporting.' },
        { id:'csf-gv-003', title:'GV.SC: Cybersecurity supply chain risk management', description:'Assess TPCRM integration into overall risk management strategy. Verify supplier security requirements, due diligence processes, and ongoing monitoring for critical suppliers.', severity:'high', tags:['nist-csf','govern','supply-chain'], frameworks:['NIST-CSF:GV.SC'], remediation:'Develop supplier security policy. Tier suppliers by criticality. Due diligence pre-onboarding. Contractual security requirements. Annual assessments for critical suppliers.' },
        { id:'csf-gv-004', title:'GV.PO: Policy establishment', description:'Verify cybersecurity policies exist, are reviewed regularly, are communicated to all relevant parties, and are enforced. Assess coverage across all security domains.', severity:'medium', tags:['nist-csf','govern','policy'], frameworks:['NIST-CSF:GV.PO'], remediation:'Policy library covering all security domains. Annual review cycle. Evidence of communication and acknowledgement. Policy exception process.' },
        { id:'csf-gv-005', title:'GV.RR: Roles and responsibilities', description:'Verify cybersecurity roles and responsibilities are defined, assigned, and understood by individuals. Verify accountability for cybersecurity outcomes at management body level.', severity:'medium', tags:['nist-csf','govern','roles'], frameworks:['NIST-CSF:GV.RR'], remediation:'RACI matrix for cybersecurity functions. CISO designation with clear mandate. Board-level accountability. Include cyber responsibilities in job descriptions.' },
      ]
    },
    {
      id: 'csf-identify',
      name: 'ID — Identify',
      items: [
        { id:'csf-id-001', title:'ID.AM: Asset management completeness', description:'Assess asset inventory completeness and accuracy: hardware assets, software assets, data assets, cloud services, OT assets (if applicable). Evaluate automated discovery vs manual inventory. Assess classification and owner assignment.', severity:'high', tags:['nist-csf','identify','asset-management'], frameworks:['NIST-CSF:ID.AM'], remediation:'Deploy automated asset discovery (e.g., Axonius, ServiceNow ITAM). Assign owners to all assets. Classify by criticality and sensitivity. Verify quarterly.' },
        { id:'csf-id-002', title:'ID.RA: Risk assessment process', description:'Assess formal risk assessment process: threat identification methodology, vulnerability identification sources, likelihood and impact scoring, risk prioritisation, risk register maintenance, frequency of assessments.', severity:'high', tags:['nist-csf','identify','risk-assessment'], frameworks:['NIST-CSF:ID.RA'], remediation:'Formal risk assessment methodology (NIST SP 800-30, ISO 31000). Annual full assessment. Event-triggered reassessments. Maintain live risk register.' },
        { id:'csf-id-003', title:'ID.IM: Improvement process', description:'Verify lessons learned from incidents, assessments, and exercises are used to improve the cybersecurity programme. Assess metrics and KPIs tracked and reported.', severity:'medium', tags:['nist-csf','identify','improvement'], frameworks:['NIST-CSF:ID.IM'], remediation:'Post-incident review process. Formal lessons-learned tracking. Cybersecurity KPI dashboard. Annual programme effectiveness review.' },
      ]
    },
    {
      id: 'csf-protect',
      name: 'PR — Protect',
      items: [
        { id:'csf-pr-001', title:'PR.AA: Identity management and access control', description:'Assess identity lifecycle management: provisioning, review, and deprovisioning. MFA deployment. Privileged access controls. Service account management. Directory service security.', severity:'high', tags:['nist-csf','protect','identity','access-control'], frameworks:['NIST-CSF:PR.AA'], remediation:'Identity governance tooling. Automated JML. MFA for all users. PAM for privileged accounts. Quarterly access reviews. Zero-trust architecture roadmap.' },
        { id:'csf-pr-002', title:'PR.AT: Awareness and training programme', description:'Assess security awareness programme: training frequency, coverage, content relevance, phishing simulation, role-specific training for high-risk roles (IT, finance, HR, executive), effectiveness measurement.', severity:'medium', tags:['nist-csf','protect','training','awareness'], frameworks:['NIST-CSF:PR.AT'], remediation:'Annual training mandatory for all staff. Quarterly phishing simulations. Role-based training for high-risk roles. Track completion rates. Measure click rates in phishing sims.' },
        { id:'csf-pr-003', title:'PR.DS: Data protection controls', description:'Assess data protection: DLP tooling (content inspection, endpoint DLP, email DLP), data classification enforcement, encryption at rest and in transit, data retention and disposal procedures, backup security.', severity:'high', tags:['nist-csf','protect','data-protection','dlp'], frameworks:['NIST-CSF:PR.DS'], remediation:'Implement DLP solution. Enforce data classification labels. Encrypt sensitive data in transit and at rest. Secure data disposal procedures. DSAR process for GDPR.' },
        { id:'csf-pr-004', title:'PR.PS: Platform security (hardening)', description:'Assess system hardening maturity: CIS Benchmark compliance for critical systems, patch management effectiveness, configuration management (drift detection), endpoint protection, removable media controls.', severity:'high', tags:['nist-csf','protect','hardening','configuration'], frameworks:['NIST-CSF:PR.PS'], remediation:'Apply CIS Benchmarks. Automate hardening via DSC/Ansible/Chef. Configuration drift detection. Monthly compliance scanning. Baseline configuration management.' },
        { id:'csf-pr-005', title:'PR.IR: Technology infrastructure resilience', description:'Assess resilience controls: redundancy for critical systems, network segmentation, high availability configurations, DR site capabilities, backup coverage and testing.', severity:'high', tags:['nist-csf','protect','resilience','redundancy'], frameworks:['NIST-CSF:PR.IR'], remediation:'N+1 redundancy for critical components. Network segmentation (DMZ, production separation). Documented HA architecture. Annual DR test.' },
      ]
    },
    {
      id: 'csf-detect',
      name: 'DE — Detect',
      items: [
        { id:'csf-de-001', title:'DE.CM: Continuous monitoring capability', description:'Assess continuous monitoring: log collection coverage (endpoints, network, cloud, applications), SIEM with correlation rules, EDR deployment, network traffic analysis, cloud security posture monitoring, threat intelligence integration.', severity:'high', tags:['nist-csf','detect','monitoring','siem'], frameworks:['NIST-CSF:DE.CM'], remediation:'Centralised SIEM with 90-day+ retention. EDR on all endpoints. Network monitoring (IDS/NTA). Cloud CSPM. MITRE ATT&CK-aligned detection coverage assessment.' },
        { id:'csf-de-002', title:'DE.AE: Adverse event analysis', description:'Assess capability to correlate events into incidents: alert triage process, SOC maturity (staffing, SLAs, playbooks), threat intelligence contextualisation, false positive rate management, escalation procedures.', severity:'high', tags:['nist-csf','detect','analysis','soc'], frameworks:['NIST-CSF:DE.AE'], remediation:'Define alert SLAs (triage within 15min for critical). Document triage playbooks per alert type. SOAR for automation. Threat intel feeds. Measure and optimise false positive rates.' },
      ]
    },
    {
      id: 'csf-respond',
      name: 'RS — Respond',
      items: [
        { id:'csf-rs-001', title:'RS.MA: Incident management process', description:'Assess incident response process maturity: IRP documentation, severity classification, response playbooks, cross-functional coordination (IT, legal, communications, exec), external support (retainer, CERT), evidence preservation procedures.', severity:'critical', tags:['nist-csf','respond','incident-response'], frameworks:['NIST-CSF:RS.MA'], remediation:'Document comprehensive IRP. Define severity matrix. Create playbooks for top 10 incident scenarios. IR retainer with specialist firm. Annual tabletop exercise.' },
        { id:'csf-rs-002', title:'RS.CO: Communication during incidents', description:'Assess internal and external communication during incidents: notification chain, management reporting templates, regulatory notification procedures (NIS2 72h), customer notification playbook, media handling, legal review process.', severity:'high', tags:['nist-csf','respond','communication','notification'], frameworks:['NIST-CSF:RS.CO'], remediation:'Communication matrix per incident severity. Pre-approved notification templates. Legal review of external communications. Regulatory notification runbook.' },
        { id:'csf-rs-003', title:'RS.AN: Incident analysis capability', description:'Assess forensic and analysis capabilities: evidence collection procedures, chain of custody, forensic tools, log retention adequacy, ability to reconstruct timeline, external forensics support.', severity:'high', tags:['nist-csf','respond','forensics','analysis'], frameworks:['NIST-CSF:RS.AN'], remediation:'Forensic acquisition tools and procedures. Chain of custody documentation. Forensic retainer. Minimum 12-month log retention. Memory forensics capability.' },
      ]
    },
    {
      id: 'csf-recover',
      name: 'RC — Recover',
      items: [
        { id:'csf-rc-001', title:'RC.RP: Recovery plan execution', description:'Assess recovery planning: documented recovery plans per critical service, recovery prioritisation, tested procedures (RPO/RTO validation), communication during recovery, stakeholder updates.', severity:'high', tags:['nist-csf','recover','recovery-plan'], frameworks:['NIST-CSF:RC.RP'], remediation:'Document recovery playbooks per critical system. Define recovery order priority. Test recovery procedures annually. Communicate clearly during recovery. Post-incident review.' },
        { id:'csf-rc-002', title:'RC.CO: Recovery communication and lessons learned', description:'Assess post-recovery processes: lessons-learned documentation, corrective action tracking, communication of recovery completion to stakeholders, integration of improvements back into security programme.', severity:'medium', tags:['nist-csf','recover','lessons-learned'], frameworks:['NIST-CSF:RC.CO'], remediation:'Mandatory post-incident review for all major incidents. Track corrective actions to closure. Update playbooks based on lessons. Annual programme improvement cycle.' },
      ]
    },
  ]
};

// ─────────────────────────────────────────────────────────────────────────────

const MODULE_DORA = {
  id: 'dora',
  name: 'DORA',
  type: 'consultant',
  icon: '🏦',
  description: 'Digital Operational Resilience Act (EU 2022/2554) assessment for financial entities.',
  groups: [
    {
      id: 'dora-ict-risk',
      name: 'ICT Risk Management (Art. 5-16)',
      items: [
        { id:'dora-risk-001', title:'ICT risk management framework', description:'Assess ICT risk management framework: framework documentation, ICT risk appetite, ICT risk assessment methodology, integration with overall ERM, management body approval and oversight, annual review process.', severity:'critical', tags:['dora','ict-risk','framework'], frameworks:['DORA:Art.6'], remediation:'Document comprehensive ICT risk management framework. Board-approved ICT risk appetite statement. Annual ICT risk assessment. Integrate ICT risk into ERM reporting.' },
        { id:'dora-risk-002', title:'ICT asset classification and management', description:'Verify ICT asset inventory covering hardware, software, data, and third-party services. Assets classified by criticality. Mapping of critical ICT assets to business functions. Documentation of dependencies and single points of failure.', severity:'high', tags:['dora','asset-management','classification'], frameworks:['DORA:Art.8'], remediation:'Maintain comprehensive ICT asset register. Classify by criticality (critical, important, standard). Map to business functions. Identify and remediate single points of failure.' },
        { id:'dora-risk-003', title:'Threat and vulnerability management', description:'Assess proactive threat and vulnerability management: threat intelligence consumption, vulnerability scanning programme, penetration testing programme (TLPT for significant entities), patch management SLAs.', severity:'high', tags:['dora','vulnerability-management','threat-intel'], frameworks:['DORA:Art.10'], remediation:'Implement threat intelligence programme. Automated vulnerability scanning with defined SLAs. Annual penetration testing. Threat-led penetration testing (TLPT) if applicable.' },
        { id:'dora-risk-004', title:'Data and ICT system security controls', description:'Assess security controls for ICT systems: access control (need-to-know, least privilege), encryption policy, network segmentation, change management controls, configuration management, secure development practices.', severity:'high', tags:['dora','security-controls','access-control'], frameworks:['DORA:Art.9'], remediation:'Document security control framework. Verify encryption for sensitive data. Review network segmentation design. Implement formal change management process for ICT systems.' },
        { id:'dora-risk-005', title:'ICT change management', description:'Assess ICT change management process: formal change management process, testing requirements before production deployment, rollback procedures, emergency change process, change advisory board (CAB), documentation and approval.', severity:'high', tags:['dora','change-management','ict'], frameworks:['DORA:Art.9'], remediation:'Formal change management process (ITIL-aligned). Mandatory testing and approval for production changes. Rollback plans for all changes. Emergency change procedure with retrospective approval.' },
        { id:'dora-risk-006', title:'Concentration risk and technology dependencies', description:'Identify and assess concentration risks from technology providers (single cloud provider, critical software vendor), assess alternatives and exit strategies, evaluate impact of provider failure.', severity:'high', tags:['dora','concentration-risk','third-party'], frameworks:['DORA:Art.30'], remediation:'Map critical technology dependencies. Assess concentration risk for each critical provider. Develop exit strategies. Multi-cloud/multi-vendor strategy for critical functions where feasible.' },
      ]
    },
    {
      id: 'dora-incident',
      name: 'ICT Incident Management & Reporting (Art. 17-23)',
      items: [
        { id:'dora-inc-001', title:'ICT incident management process', description:'Assess ICT-related incident management: incident classification criteria (major incident thresholds), escalation procedures, roles and responsibilities during incident, communication plan, evidence preservation.', severity:'critical', tags:['dora','incident-management','ict'], frameworks:['DORA:Art.17'], remediation:'Document ICT incident management process. Define major incident thresholds aligned with DORA criteria. Assign clear roles. Test via tabletop exercises annually.' },
        { id:'dora-inc-002', title:'DORA major incident reporting (Art. 19)', description:'Verify DORA-compliant major incident reporting capability: Initial notification to competent authority within 4 hours, Intermediate report within 72 hours, Final report within 1 month. Identify reporting chain and template readiness.', severity:'critical', tags:['dora','incident-reporting','regulatory'], frameworks:['DORA:Art.19'], remediation:'Document reporting procedures. Pre-approved notification templates for initial (4h), intermediate (72h), and final (1 month) reports. Train responsible staff. Conduct mock reporting exercise.' },
        { id:'dora-inc-003', title:'Major incident classification criteria', description:'Verify criteria for classifying major ICT incidents align with DORA RTS: client impact, service duration, geographic spread, data loss, critical services affected, reputation impact, business impact thresholds.', severity:'high', tags:['dora','classification','major-incident'], frameworks:['DORA:Art.18'], remediation:'Define major incident criteria per DORA Art. 18 and Commission RTS. Document classification decision tree. Assign classification authority. Train SOC and management.' },
        { id:'dora-inc-004', title:'Post-incident review process', description:'Assess root cause analysis and post-incident review process for major ICT incidents. Verify lessons learned are captured, corrective actions assigned and tracked, improvements integrated into risk management.', severity:'medium', tags:['dora','post-incident','root-cause'], frameworks:['DORA:Art.17'], remediation:'Mandate post-incident review for all major incidents. 5-Whys or fishbone RCA methodology. Corrective action tracking to closure. Update ICT risk assessment and controls.' },
      ]
    },
    {
      id: 'dora-resilience',
      name: 'Digital Operational Resilience Testing (Art. 24-27)',
      items: [
        { id:'dora-test-001', title:'Resilience testing programme', description:'Assess resilience testing programme: vulnerability assessments, scenario-based testing, penetration testing coverage and frequency. Verify testing covers critical ICT systems and functions. Review last testing cycle results.', severity:'high', tags:['dora','resilience-testing','penetration-testing'], frameworks:['DORA:Art.24'], remediation:'Annual penetration testing of all critical ICT systems. Vulnerability assessment after major changes. Scenario-based testing (ransomware, DDoS, cloud provider failure). Test remediation tracking.' },
        { id:'dora-test-002', title:'Threat-led penetration testing (TLPT) readiness', description:'For significant financial entities, assess TLPT programme maturity: TIBER-EU alignment, scope definition (critical functions), intelligence gathering phase, red team testing, blue team involvement, competent authority coordination.', severity:'high', tags:['dora','tlpt','tiber-eu','red-team'], frameworks:['DORA:Art.26'], remediation:'Engage TIBER-EU accredited test provider. Define critical functions in scope with competent authority. Conduct full TLPT cycle: intelligence, red team, purple team, reporting. Remediate findings.' },
        { id:'dora-test-003', title:'BCP/DRP testing and exercises', description:'Assess frequency and depth of BCP/DR testing: full failover tests, partial tests, tabletop exercises, recovery time achievement against documented RTO/RPO, staff familiarity with recovery procedures.', severity:'high', tags:['dora','bcp','drp','testing'], frameworks:['DORA:Art.11'], remediation:'Annual full BCP/DRP test. Quarterly tabletop exercises. Validate RTO/RPO achievement. Staff training on recovery procedures. Document and remediate test gaps.' },
      ]
    },
    {
      id: 'dora-tpcrm',
      name: 'Third-Party ICT Risk (Art. 28-44)',
      items: [
        { id:'dora-tp-001', title:'ICT third-party provider register', description:'Verify maintained register of all ICT third-party service providers (TPPs). Register should include: provider name, services provided, criticality classification, contractual arrangements, risk assessments.', severity:'critical', tags:['dora','third-party','register','tpp'], frameworks:['DORA:Art.28'], remediation:'Maintain comprehensive ICT TPP register. Classify providers by criticality. Document all contractual arrangements. Report critical TPPs to competent authority as required.' },
        { id:'dora-tp-002', title:'DORA-compliant contractual arrangements', description:'Verify ICT provider contracts include DORA-required clauses: service description and SLAs, data security requirements, access and audit rights, incident notification obligations, business continuity provisions, exit strategy.', severity:'high', tags:['dora','contracts','third-party','sla'], frameworks:['DORA:Art.30'], remediation:'Review all critical ICT provider contracts for DORA Art.30 compliance. Update contracts to include mandatory clauses. Define SLAs for critical services. Negotiate audit rights.' },
        { id:'dora-tp-003', title:'Critical ICT provider oversight', description:'Assess ongoing oversight of critical ICT providers: monitoring of SLA performance, security assessment results, incident notification fulfilment, right-to-audit exercise, concentration risk management, exit planning.', severity:'high', tags:['dora','oversight','critical-provider','monitoring'], frameworks:['DORA:Art.28'], remediation:'Define oversight programme for critical ICT providers. Annual security assessments. SLA monitoring dashboard. Escalation process for SLA breaches. Exercise audit rights periodically.' },
        { id:'dora-tp-004', title:'ICT provider exit strategy and portability', description:'Assess exit strategies for critical ICT providers: documented exit plans, data portability requirements in contracts, transition support provisions, alternative provider identification, exit testing (where practical).', severity:'high', tags:['dora','exit-strategy','portability','concentration-risk'], frameworks:['DORA:Art.28'], remediation:'Document exit strategies for top 5 critical ICT providers. Verify data portability in contracts. Identify fallback providers. Test exit procedure (tabletop) annually.' },
      ]
    },
    {
      id: 'dora-gov',
      name: 'Governance & Accountability',
      items: [
        { id:'dora-gov-001', title:'Management body ICT risk oversight', description:'Verify management body actively oversees ICT risk management: regular ICT risk reporting to board, board approval of ICT risk policies, board members with ICT risk expertise, board accountability for DORA compliance.', severity:'critical', tags:['dora','governance','board','accountability'], frameworks:['DORA:Art.5'], remediation:'Quarterly ICT risk reporting to board. Board cybersecurity training. Dedicated board agenda item for ICT resilience. Document board decisions on ICT risk.' },
        { id:'dora-gov-002', title:'DORA compliance programme', description:'Assess overall DORA compliance programme: gap assessment completion, remediation roadmap, designated DORA programme owner, integration with ERM, regulatory engagement (competent authority relationship).', severity:'high', tags:['dora','compliance','programme'], frameworks:['DORA:Art.5'], remediation:'Complete formal DORA gap assessment. Prioritised remediation roadmap with owners and dates. Designated DORA compliance owner. Regular compliance status reporting.' },
      ]
    },
  ]
};

// ─────────────────────────────────────────────────────────────────────────────

const MODULE_ISO27001 = {
  id: 'iso27001',
  name: 'ISO 27001 (Light)',
  type: 'consultant',
  icon: '📋',
  description: 'Lightweight ISO 27001:2022 gap assessment covering key Annex A controls and ISMS requirements.',
  groups: [
    {
      id: 'iso-isms',
      name: 'ISMS Requirements (Clauses 4-10)',
      items: [
        { id:'iso-isms-001', title:'ISMS scope and context', description:'Verify documented ISMS scope, internal/external context analysis, interested parties and their requirements, leadership commitment, and information security policy signed by senior management.', severity:'high', tags:['iso27001','isms','scope'], frameworks:['ISO27001:Clause 4,5'], remediation:'Define and document ISMS scope. Context analysis (PESTLE/SWOT). Stakeholder analysis. Formally approved IS policy. Management review process.' },
        { id:'iso-isms-002', title:'Information security risk assessment and treatment', description:'Verify documented risk assessment methodology, risk register with likelihood/impact scores, risk treatment plans, Statement of Applicability (SoA) with justifications for included/excluded controls, residual risk acceptance.', severity:'high', tags:['iso27001','risk-assessment','soa'], frameworks:['ISO27001:Clause 6'], remediation:'Formal RA methodology. Annual risk assessment. Statement of Applicability with justifications. Risk treatment plan with owners and dates. Management acceptance of residual risks.' },
        { id:'iso-isms-003', title:'Internal audit programme', description:'Verify internal audit programme: audit schedule covering all ISMS scope, qualified auditors (internal or external), documented audit reports, nonconformity tracking, management review of results.', severity:'medium', tags:['iso27001','audit','internal-audit'], frameworks:['ISO27001:Clause 9'], remediation:'Annual internal audit covering all ISMS scope. Qualified auditors independent of audited area. Track and remediate nonconformities. Report to management review.' },
        { id:'iso-isms-004', title:'Management review', description:'Verify regular management review of ISMS: documented review meeting, inputs (audit results, incident trends, risk status, objective progress), outputs (improvement decisions), and records maintained.', severity:'medium', tags:['iso27001','management-review'], frameworks:['ISO27001:Clause 9'], remediation:'Formal annual management review (minimum). Document agenda, inputs, outputs, and action items. Track improvement actions to completion.' },
      ]
    },
    {
      id: 'iso-controls',
      name: 'Key Annex A Controls',
      items: [
        { id:'iso-ann-001', title:'A.5 — Information security policies', description:'Verify comprehensive policy suite: IS policy, acceptable use, access control, cryptography, incident management, physical security, supplier security, data classification. All reviewed in last 12 months and communicated to staff.', severity:'medium', tags:['iso27001','policy','annex-a'], frameworks:['ISO27001:A.5'], remediation:'Policy library for all key domains. Annual review with version control. Staff acknowledgement of key policies. Policy exception process.' },
        { id:'iso-ann-002', title:'A.8 — Asset management', description:'Verify asset inventory (hardware, software, data, cloud), data classification scheme, asset labelling, acceptable use of assets, media handling, secure disposal procedures.', severity:'high', tags:['iso27001','asset-management','classification'], frameworks:['ISO27001:A.8'], remediation:'Comprehensive asset inventory. Data classification scheme (Public, Internal, Confidential, Restricted). Secure media disposal with certificates. Data labelling.' },
        { id:'iso-ann-003', title:'A.8 — Access control (ISO 27001:2022)', description:'Verify access control policy, privileged access management, least privilege enforcement, user provisioning/deprovisioning process, password policy, MFA for privileged/remote access, access reviews.', severity:'high', tags:['iso27001','access-control','least-privilege'], frameworks:['ISO27001:A.8.2,A.8.3'], remediation:'Documented access control policy. Formal provisioning/deprovisioning process. Quarterly privileged access reviews. MFA for all remote and privileged access.' },
        { id:'iso-ann-004', title:'A.8 — Cryptography controls', description:'Verify cryptographic controls policy: encryption requirements by data classification, approved algorithms (AES-256, RSA-2048+, TLS 1.2+), key management procedures, prohibited algorithms list.', severity:'high', tags:['iso27001','cryptography','encryption'], frameworks:['ISO27001:A.8.24'], remediation:'Cryptography policy with approved/prohibited algorithm list. Encryption mandated for sensitive data. Key management procedure. Annual crypto review for algorithm agility.' },
        { id:'iso-ann-005', title:'A.7 — Physical and environmental security', description:'Verify physical security controls: secure areas, equipment protection, clean desk, clear screen, secure disposal of equipment and media, physical access logging and review.', severity:'medium', tags:['iso27001','physical-security','environmental'], frameworks:['ISO27001:A.7'], remediation:'Physical access control for sensitive areas. Equipment siting to reduce risk. Secure disposal policy. Clean desk policy. UPS and environmental controls for data centre.' },
        { id:'iso-ann-006', title:'A.8 — Operations security (logging and monitoring)', description:'Verify logging and monitoring: log collection scope (servers, network, endpoints, applications), log retention (minimum 12 months), log protection (tamper-evident), SIEM use, monitoring of privileged user activity.', severity:'high', tags:['iso27001','logging','monitoring','siem'], frameworks:['ISO27001:A.8.15,A.8.16'], remediation:'Centralised log management. 12-month retention. Privileged user activity monitoring. Defined monitoring use cases. SIEM with alerting on key events.' },
        { id:'iso-ann-007', title:'A.6 — Supplier security', description:'Verify supplier security policy: due diligence for new suppliers, security requirements in contracts, ongoing monitoring, right to audit, ICT supply chain security controls, offboarding process.', severity:'high', tags:['iso27001','supplier','third-party'], frameworks:['ISO27001:A.6.6,A.5.19-5.22'], remediation:'Supplier security policy. Risk-based due diligence process. Security clauses in all contracts. Annual supplier review for critical suppliers. Formal offboarding.' },
        { id:'iso-ann-008', title:'A.5 — Incident management', description:'Verify incident management process: incident reporting mechanism (all staff), incident classification, response procedures, evidence preservation, regulatory notification process, post-incident review, lessons-learned integration.', severity:'high', tags:['iso27001','incident-management'], frameworks:['ISO27001:A.5.24-5.28'], remediation:'Document IRP with classification criteria. All-staff incident reporting channel. Regular IRP testing. Post-incident review for significant events. Regulatory notification procedure.' },
        { id:'iso-ann-009', title:'A.8 — Vulnerability management', description:'Verify vulnerability management: asset scanning coverage and frequency, patch management SLAs, penetration testing programme, vulnerability tracking, risk-based remediation prioritisation.', severity:'high', tags:['iso27001','vulnerability-management','patching'], frameworks:['ISO27001:A.8.8'], remediation:'Regular automated vulnerability scanning. Patch SLAs per severity. Annual penetration test. Vulnerability tracking to remediation. Supplier vulnerability notification process.' },
      ]
    },
  ]
};

// ─────────────────────────────────────────────────────────────────────────────
// RECON MODULE
// ─────────────────────────────────────────────────────────────────────────────

const MODULE_RECON = {
  id: 'recon',
  name: 'Reconnaissance',
  type: 'pentest',
  icon: '🔭',
  description: 'Pre-engagement scanning, enumeration, and initial footprinting. Map the attack surface before active exploitation.',
  groups: [
    {
      id: 'recon-osint',
      name: 'OSINT & Passive Recon',
      items: [
        { id:'recon-001', title:'Domain & subdomain enumeration', description:'Enumerate subdomains via certificate transparency logs (crt.sh, Censys), DNS brute-force (dnsrecon, amass), and passive sources (Shodan, SecurityTrails). Identify forgotten or dev subdomains exposed to the internet.', severity:'medium', tags:['osint','dns','subdomain'], frameworks:['MITRE:T1590.001'], remediation:'Review and remove unused subdomains. Ensure dev/staging environments are not publicly accessible. Monitor certificate transparency logs.' },
        { id:'recon-002', title:'Exposed credentials in public repositories', description:'Search GitHub, GitLab, and code repositories for leaked API keys, passwords, connection strings, and secrets using tools like truffleHog, gitleaks, or GitHub search operators.', severity:'critical', tags:['osint','credentials','github'], frameworks:['MITRE:T1552.001'], remediation:'Rotate any exposed credentials immediately. Implement git-secrets or pre-commit hooks. Enable GitHub secret scanning.' },
        { id:'recon-003', title:'WHOIS and ASN intelligence', description:'Collect WHOIS records, ASN assignments, IP ranges, and organisational data. Identify IP space owned by the target. Cross-reference with BGP data for full IP inventory.', severity:'info', tags:['osint','whois','asn'], frameworks:['MITRE:T1590'], remediation:'Minimise public registration data. Use privacy-protected WHOIS registrations.' },
        { id:'recon-004', title:'Employee & organisational OSINT', description:'Enumerate employees via LinkedIn, Hunter.io, and OSINT tools. Build username/email format list for credential spraying. Identify key personnel for social engineering or phishing simulation.', severity:'medium', tags:['osint','social-engineering','email'], frameworks:['MITRE:T1591.004'], remediation:'Train employees on OSINT risks. Minimise information published in job postings and org charts.' },
        { id:'recon-005', title:'Technology fingerprinting', description:'Identify technologies, frameworks, CMS, CDN, WAF, load balancer, mail providers, and cloud platforms from passive sources: Wappalyzer, Shodan, BuiltWith, HTTP response headers.', severity:'info', tags:['osint','fingerprinting','technology'], frameworks:['MITRE:T1592'], remediation:'Suppress verbose server headers. Use generic error pages. Deploy WAF to obscure backend technology.' },
      ],
    },
    {
      id: 'recon-scanning',
      name: 'Active Scanning',
      items: [
        { id:'recon-006', title:'Port and service scanning', description:'Perform full TCP/UDP port scan using Nmap (-sS -sU -p-). Identify open ports, running services, and versions. Prioritise unusual ports and services exposed externally.', severity:'medium', tags:['scanning','nmap','ports'], frameworks:['MITRE:T1046'], remediation:'Close unnecessary ports. Implement host-based and network firewalls. Document and justify all externally accessible services.' },
        { id:'recon-007', title:'Service version and banner grabbing', description:'Identify exact versions of exposed services via banner grabbing (netcat, nmap -sV). Cross-reference with CVE databases to identify unpatched vulnerabilities in exposed services.', severity:'medium', tags:['scanning','banner-grab','versions'], frameworks:['MITRE:T1046'], remediation:'Suppress version banners in service configurations. Patch all exposed services to latest stable versions.' },
        { id:'recon-008', title:'Web application discovery', description:'Discover web applications on non-standard ports. Run directory/file brute-force (feroxbuster, ffuf, dirsearch) using wordlists. Identify admin panels, API endpoints, backup files, and development artifacts.', severity:'medium', tags:['scanning','web','discovery'], frameworks:['MITRE:T1595.003'], remediation:'Remove or protect admin interfaces. Implement allowlist-based routing. Delete backup and development files from production.' },
        { id:'recon-009', title:'SSL/TLS configuration analysis', description:'Analyse TLS configuration using sslyze, testssl.sh. Identify weak cipher suites, expired certificates, missing HSTS, vulnerable TLS versions (SSLv3, TLS 1.0/1.1), and certificate validity.', severity:'medium', tags:['scanning','ssl','tls'], frameworks:['MITRE:T1040'], remediation:'Enforce TLS 1.2+. Disable weak cipher suites. Enable HSTS with long max-age. Automate certificate renewal.' },
        { id:'recon-010', title:'DNS zone transfer attempt', description:'Attempt AXFR/IXFR zone transfers from authoritative nameservers. A successful transfer reveals the entire DNS zone contents including internal hostnames and IP addresses.', severity:'high', tags:['scanning','dns','zone-transfer'], frameworks:['MITRE:T1590.002'], remediation:'Restrict zone transfers to authorised secondary nameservers only. Configure ACLs on DNS server.' },
      ],
    },
    {
      id: 'recon-enum',
      name: 'Initial Enumeration',
      items: [
        { id:'recon-011', title:'Network topology mapping', description:'Map the network topology from discovered hosts. Identify routers, firewalls, load balancers, and network segmentation. Use traceroute, ping sweeps, and ARP scanning (if internal).', severity:'info', tags:['enumeration','network','topology'], frameworks:['MITRE:T1018'], remediation:'Implement network segmentation. Restrict ICMP and traceroute responses at perimeter.' },
        { id:'recon-012', title:'Email security (SPF/DKIM/DMARC)', description:'Check SPF, DKIM, and DMARC records for all discovered domains. Identify missing or permissive policies that allow email spoofing. Test with external email spoofing simulation.', severity:'high', tags:['enumeration','email','spf','dmarc'], frameworks:['MITRE:T1566'], remediation:'Implement strict SPF (v=spf1 ... -all). Deploy DKIM signing. Set DMARC to p=reject with rua reporting.' },
        { id:'recon-013', title:'Cloud asset discovery', description:'Identify cloud storage buckets (S3, Azure Blob, GCS), serverless functions, and cloud-hosted services. Check for publicly accessible or misconfigured cloud resources using cloudbrute, GrayhatWarfare.', severity:'high', tags:['enumeration','cloud','s3','azure'], frameworks:['MITRE:T1530'], remediation:'Enforce bucket ACLs. Disable public access at organisation policy level. Enable cloud audit logging.' },
        { id:'recon-014', title:'Initial findings summary', description:'Document all discovered assets, services, technologies, and potential attack vectors before active exploitation begins. Create scope-in and scope-out lists based on findings.', severity:'info', tags:['enumeration','documentation','scope'], frameworks:[], remediation:'Maintain accurate asset inventory. Conduct regular attack surface reviews.' },
      ],
    },
  ],
};

// ─────────────────────────────────────────────────────────────────────────────
// MODULE REGISTRY
// ─────────────────────────────────────────────────────────────────────────────

const ALL_MODULES = [
  MODULE_RECON,
  MODULE_ACTIVE_DIRECTORY,
  MODULE_WINDOWS,
  MODULE_WEB_APP,
  MODULE_API,
  MODULE_NETWORK_INTERNAL,
  MODULE_EXTERNAL,
  MODULE_WIRELESS,
  MODULE_PHYSICAL,
  MODULE_CLOUD,
  MODULE_NIS2,
  MODULE_NIST_CSF,
  MODULE_DORA,
  MODULE_ISO27001,
];

const MODULES_BY_TYPE = {
  pentest: ALL_MODULES.filter(m => m.type === 'pentest'),
  consultant: ALL_MODULES.filter(m => m.type === 'consultant'),
};

const MODULE_MAP = Object.fromEntries(ALL_MODULES.map(m => [m.id, m]));

// Helper: get all items in a module
function getModuleItems(module) {
  return module.groups.flatMap(g => g.items.map(i => ({ ...i, groupId: g.id, groupName: g.name })));
}

// Helper: get all unique tags across all modules
function getAllTags() {
  const tags = new Set();
  ALL_MODULES.forEach(m => m.groups.forEach(g => g.items.forEach(i => i.tags.forEach(t => tags.add(t)))));
  return [...tags].sort();
}
