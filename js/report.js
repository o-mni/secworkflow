// ── Report Generator ─────────────────────────────────────────────────────────

class ReportGenerator {
  constructor(app) {
    this.app = app;
  }

  // ── Entry point ────────────────────────────────────────────────────────────

  generatePDF(options = {}) {
    const {
      type = 'pentest',
      includedModuleIds = [],
      includeStatuses = ['vulnerable', 'in-progress', 'cannot-verify', 'not-compliant', 'partially-compliant'],
      findingsOnly = false,
    } = options;

    const state = this.app.state;
    const meta = state.metadata;

    const moduleReports = [];
    for (const modId of includedModuleIds) {
      const module = MODULE_MAP[modId];
      if (!module) continue;

      const items = getModuleItems(module);
      // Auto-filter: only include items that have meaningful data
      const filtered = items.filter(item => {
        const ist = state.itemStates[item.id] || {};
        const status = ist.status || 'not-started';
        // Exclude out-of-scope items
        if (ist.outOfScope) return false;
        // Include if status matches OR if the item has notes/findings regardless of status
        const statusMatch = includeStatuses.includes(status);
        const hasData = ist.note || ist.evidence || ist.isFinding;
        if (findingsOnly) return (ist.isFinding || (ist.note && statusMatch));
        return statusMatch || (hasData && status !== 'not-started' && status !== 'not-assessed');
      });

      if (filtered.length === 0) continue;
      const progress = this.app.getModuleProgress(module);
      moduleReports.push({ module, items: filtered, progress });
    }

    let body, title;
    if (type === 'executive') {
      title = `Executive Summary — ${meta.projectName || 'Security Assessment'}`;
      body = this._buildExecutiveBody(meta, moduleReports);
    } else if (type === 'consultant') {
      title = `Compliance Assessment — ${meta.projectName || 'Assessment'}`;
      body = this._buildConsultantBody(meta, moduleReports);
    } else {
      title = `Penetration Test Report — ${meta.projectName || 'Assessment'}`;
      body = this._buildPentestBody(meta, moduleReports);
    }

    const html = this._buildHTMLShell(title, meta, body);
    const win = window.open('', '_blank');
    if (!win) {
      alert('Please allow pop-ups for this page to generate the PDF report.');
      return;
    }
    win.document.write(html);
    win.document.close();
  }

  // ── HTML shell with embedded styles ────────────────────────────────────────

  _buildHTMLShell(title, meta, body) {
    const classifColorMap = {
      'CONFIDENTIAL': '#dc2626',
      'TLP:RED':      '#dc2626',
      'TLP:AMBER':    '#d97706',
      'TLP:GREEN':    '#059669',
      'INTERNAL':     '#2563eb',
    };
    const classifColor = classifColorMap[meta.classification] || '#dc2626';
    const accent = '#3b4ef8';

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate" />
<meta name="referrer" content="no-referrer" />
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data: blob:; connect-src 'none'; object-src 'none'; form-action 'none'; frame-ancestors 'none';" />
<title>${this._esc(title)}</title>
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, Helvetica, sans-serif;
  font-size: 10.5pt; color: #1e1e2e; line-height: 1.65; background: #fff;
  padding: 0 6mm;
}

/* ── Cover ── */
.cover { display: flex; flex-direction: column; min-height: 100vh; page-break-after: always; break-after: page; }
.cover-accent { height: 8px; background: ${accent}; flex-shrink: 0; }
.cover-body { flex: 1; display: flex; flex-direction: column; justify-content: center; padding: 48pt 52pt; }
.cover-wordmark { font-size: 11pt; font-weight: 700; color: ${accent}; letter-spacing: -.3px; margin-bottom: 36pt; }
.cover-report-type { font-size: 8pt; font-weight: 700; letter-spacing: 2px; text-transform: uppercase; color: ${accent}; margin-bottom: 10pt; }
.cover-title { font-size: 26pt; font-weight: 800; color: #0a0a18; line-height: 1.15; letter-spacing: -.5pt; margin-bottom: 8pt; }
.cover-client { font-size: 13pt; color: #666; margin-bottom: 40pt; }
.cover-divider { height: 1px; background: #e5e7eb; margin-bottom: 24pt; }
.cover-meta { display: grid; grid-template-columns: 110pt 1fr; row-gap: 9pt; column-gap: 16pt; }
.cover-meta-key { font-size: 8pt; color: #999; text-transform: uppercase; letter-spacing: .6px; font-weight: 600; padding-top: 1pt; }
.cover-meta-val { font-size: 9.5pt; color: #1e1e2e; font-weight: 500; }
.cover-footer { display: flex; justify-content: space-between; align-items: center; padding: 12pt 52pt; border-top: 1px solid #e5e7eb; flex-shrink: 0; }
.cover-classif { font-size: 7.5pt; font-weight: 800; letter-spacing: 2px; color: ${classifColor}; text-transform: uppercase; }
.cover-generated { font-size: 7.5pt; color: #ccc; }

/* ── Section headings ── */
.page-break { page-break-before: always; break-before: page; }
.section { margin-bottom: 30pt; }

h1.sec-title {
  font-size: 16pt; font-weight: 800; color: #0a0a18; letter-spacing: -.3pt;
  padding-bottom: 8pt; border-bottom: 2.5px solid ${accent}; margin-bottom: 20pt;
}
h2.sub-title { font-size: 12pt; font-weight: 700; color: #1e1e2e; margin-top: 20pt; margin-bottom: 10pt; }
h3.sub-sub { font-size: 10.5pt; font-weight: 700; color: #1e1e2e; margin-bottom: 7pt; margin-top: 14pt; }

p { margin-bottom: 8pt; font-size: 10pt; }
ul, ol { margin-left: 16pt; margin-bottom: 8pt; }
li { margin-bottom: 3pt; font-size: 10pt; }

/* ── Tables ── */
table { width: 100%; border-collapse: collapse; margin-bottom: 14pt; font-size: 9pt; }
thead tr { background: #f4f5ff; }
th { text-align: left; padding: 7pt 10pt; font-size: 8pt; font-weight: 700; color: #555; text-transform: uppercase; letter-spacing: .4px; border-bottom: 2px solid #e5e7eb; white-space: nowrap; }
td { padding: 7pt 10pt; border-bottom: 1px solid #f0f2f5; vertical-align: top; }
tr:last-child td { border-bottom: none; }

/* ── Risk summary cards ── */
.risk-row { display: flex; gap: 10pt; margin-bottom: 18pt; }
.risk-card { flex: 1; text-align: center; padding: 12pt 8pt; border-radius: 7px; border: 1px solid #e5e7eb; }
.risk-count { font-size: 22pt; font-weight: 800; line-height: 1; margin-bottom: 3pt; }
.risk-label { font-size: 7.5pt; font-weight: 700; text-transform: uppercase; letter-spacing: .6px; color: #888; }
.rc-critical .risk-count { color: #dc2626; }
.rc-high .risk-count { color: #ea580c; }
.rc-medium .risk-count { color: #d97706; }
.rc-low .risk-count { color: #2563eb; }
.rc-info .risk-count { color: #6b7280; }

/* ── Module group headers ── */
.mod-header { display: flex; align-items: center; gap: 8pt; padding: 7pt 12pt; background: #f4f5ff; border-radius: 6px; margin-bottom: 10pt; border-left: 3px solid ${accent}; }
.mod-icon { font-size: 13pt; }
.mod-name { font-size: 10.5pt; font-weight: 700; color: #0a0a18; }

/* ── Finding cards ── */
.finding-card { border: 1px solid #e5e7eb; border-radius: 8px; margin-bottom: 14pt; page-break-inside: avoid; }
.finding-header { display: flex; align-items: center; gap: 10pt; padding: 9pt 14pt; background: #f9f9ff; border-bottom: 1px solid #e5e7eb; border-radius: 8px 8px 0 0; }
.finding-num { font-size: 8pt; font-weight: 700; color: ${accent}; flex-shrink: 0; }
.finding-name { font-size: 10pt; font-weight: 700; color: #0a0a18; flex: 1; }
.finding-body { padding: 12pt 14pt; display: flex; flex-direction: column; gap: 9pt; }
.fld { display: flex; flex-direction: column; gap: 2pt; }
.fld-label { font-size: 7.5pt; font-weight: 700; color: #aaa; text-transform: uppercase; letter-spacing: .5px; }
.fld-value { font-size: 9.5pt; color: #1e1e2e; line-height: 1.55; }
.fld-value.mono {
  font-family: 'Cascadia Code', 'Fira Code', Consolas, 'Courier New', monospace; font-size: 8.5pt;
  background: #f4f5f7; padding: 7pt 10pt; border-radius: 4px; white-space: pre-wrap;
  word-break: break-all; color: #2d3748; border: 1px solid #e8eaed;
}
.fld-row { display: flex; gap: 16pt; flex-wrap: wrap; }
.fld-row .fld { flex: 1; min-width: 80pt; }

/* ── Observations list ── */
.obs-list { border: 1px solid #e5e7eb; border-radius: 6px; overflow: hidden; margin-bottom: 10pt; }
.obs-item { display: flex; align-items: flex-start; gap: 10pt; padding: 8pt 12pt; border-bottom: 1px solid #f0f2f5; }
.obs-item:last-child { border-bottom: none; }
.obs-main { flex: 1; }
.obs-title { font-size: 9.5pt; font-weight: 600; color: #1e1e2e; }
.obs-note { font-size: 9pt; color: #666; margin-top: 2pt; }

/* ── Badges ── */
.badge { display: inline-block; padding: 1.5pt 6pt; border-radius: 3px; font-size: 8pt; font-weight: 700; letter-spacing: .3px; text-transform: uppercase; white-space: nowrap; }
.b-critical      { background: #fee2e2; color: #dc2626; }
.b-high          { background: #ffedd5; color: #ea580c; }
.b-medium        { background: #fef9c3; color: #d97706; }
.b-low           { background: #dbeafe; color: #2563eb; }
.b-info          { background: #f3f4f6; color: #6b7280; }
.b-vulnerable    { background: #fee2e2; color: #dc2626; }
.b-in-progress   { background: #dbeafe; color: #1d4ed8; }
.b-cannot-verify { background: #fef9c3; color: #92400e; }
.b-not-vulnerable{ background: #dcfce7; color: #166534; }
.b-not-started   { background: #f3f4f6; color: #4b5563; }
.b-not-in-scope  { background: #f3f4f6; color: #9ca3af; }

/* ── Empty state ── */
.no-findings { text-align: center; padding: 28pt; color: #aaa; font-size: 10pt; background: #fafafa; border-radius: 8px; border: 1px solid #e5e7eb; }

/* ── Page header / footer (printed) ── */
@page {
  size: A4;
  margin: 22mm 20mm 28mm 20mm;
  @bottom-left { content: "${this._esc(meta.projectName || 'Security Assessment')} — ${this._esc(meta.classification || 'CONFIDENTIAL')}"; font-size: 7.5pt; color: #aaa; font-family: sans-serif; }
  @bottom-right { content: "Page " counter(page) " of " counter(pages); font-size: 7.5pt; color: #aaa; font-family: sans-serif; }
  @top-right { content: "⬡ SecWorkflow"; font-size: 7.5pt; color: #4c73f8; font-family: sans-serif; font-weight: bold; }
}

@media print {
  body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .page-break { page-break-before: always; }
  .finding-card { page-break-inside: avoid; }
  .cover { page-break-after: always; }
  .obs-list { page-break-inside: avoid; }
}
</style>
</head>
<body>
${body}
<script>
setTimeout(function() { window.print(); }, 450);
</script>
</body>
</html>`;
  }

  // ── Pentest report body ────────────────────────────────────────────────────

  _buildPentestBody(meta, moduleReports) {
    const now = new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'long', year: 'numeric' });
    const findings = this._collectFindings(moduleReports);
    const sevCounts = this._countBySeverity(findings);
    const version = meta.version || '1.0';

    let h = '';

    // Cover
    h += `<div class="cover">
  <div class="cover-accent"></div>
  <div class="cover-body">
    <div class="cover-wordmark">⬡ SecWorkflow</div>
    <div class="cover-report-type">Penetration Test Report</div>
    <h1 class="cover-title">${this._esc(meta.projectName || 'Security Assessment')}</h1>
    <div class="cover-client">${this._esc(meta.client || '')}</div>
    <div class="cover-divider"></div>
    <div class="cover-meta">
      <div class="cover-meta-key">Client</div><div class="cover-meta-val">${this._esc(meta.client || '—')}</div>
      <div class="cover-meta-key">Assessor(s)</div><div class="cover-meta-val">${this._esc(meta.assessor || '—')}</div>
      <div class="cover-meta-key">Test Period</div><div class="cover-meta-val">${this._esc(meta.startDate || '—')} – ${this._esc(meta.endDate || '—')}</div>
      <div class="cover-meta-key">Report Date</div><div class="cover-meta-val">${now}</div>
      <div class="cover-meta-key">Version</div><div class="cover-meta-val">${this._esc(version)}</div>
      <div class="cover-meta-key">Classification</div><div class="cover-meta-val">${this._esc(meta.classification || 'CONFIDENTIAL')}</div>
    </div>
  </div>
  <div class="cover-footer">
    <div class="cover-classif">${this._esc(meta.classification || 'CONFIDENTIAL')}</div>
    <div class="cover-generated">Generated ${now}</div>
  </div>
</div>`;

    // Executive Summary
    h += `<div class="section page-break">
<h1 class="sec-title">Executive Summary</h1>
<p>This report presents the results of a penetration test conducted against <strong>${this._esc(meta.client || 'the client')}</strong>. The assessment covered <strong>${moduleReports.length} module(s)</strong> with a total of <strong>${findings.length} vulnerability/vulnerabilities identified</strong>.</p>
<h2 class="sub-title">Risk Summary</h2>
<div class="risk-row">`;
    for (const [sev, cls] of [['critical','rc-critical'],['high','rc-high'],['medium','rc-medium'],['low','rc-low'],['info','rc-info']]) {
      h += `<div class="risk-card ${cls}"><div class="risk-count">${sevCounts[sev]||0}</div><div class="risk-label">${sev}</div></div>`;
    }
    h += `</div>`;

    if (meta.scope) h += `<h2 class="sub-title">Scope</h2><p>${this._esc(meta.scope).replace(/\n/g,'<br>')}</p>`;
    if (meta.exclusions) h += `<h2 class="sub-title">Exclusions</h2><p>${this._esc(meta.exclusions).replace(/\n/g,'<br>')}</p>`;

    h += `<h2 class="sub-title">Methodology</h2>
<p>Testing was conducted using industry-standard methodologies including PTES, OWASP WSTG, and MITRE ATT&CK. Evidence was collected through a combination of automated tools and manual testing techniques.</p>
</div>`;

    // Findings
    h += `<div class="section page-break"><h1 class="sec-title">Findings</h1>`;
    let findingNum = 1;
    let anyFindings = false;

    for (const { module, items } of moduleReports) {
      const vulnItems = items.filter(i => (this.app.state.itemStates[i.id]||{}).status === 'vulnerable');
      if (vulnItems.length === 0) continue;
      anyFindings = true;

      h += `<div class="mod-header"><span class="mod-icon">${module.icon}</span><span class="mod-name">${this._esc(module.name)}</span></div>`;

      for (const item of vulnItems) {
        const ist = this.app.state.itemStates[item.id] || {};
        const sev = ist.severityOverride || item.severity || 'medium';
        h += `<div class="finding-card">
<div class="finding-header">
  <span class="finding-num">F${String(findingNum).padStart(3,'0')}</span>
  <span class="finding-name">${this._esc(item.title)}</span>
  <span class="badge b-${sev}">${sev}</span>
</div>
<div class="finding-body">
  <div class="fld-row">
    <div class="fld"><div class="fld-label">Status</div><div class="fld-value"><span class="badge b-vulnerable">Vulnerable</span></div></div>
    ${item.tags?.length ? `<div class="fld"><div class="fld-label">Tags</div><div class="fld-value">${item.tags.map(t=>this._esc(t)).join(', ')}</div></div>` : ''}
    ${item.frameworks?.length ? `<div class="fld"><div class="fld-label">References</div><div class="fld-value">${item.frameworks.map(f=>this._esc(f)).join(', ')}</div></div>` : ''}
  </div>
  <div class="fld"><div class="fld-label">Description</div><div class="fld-value">${this._esc(item.description)}</div></div>
  ${ist.note ? `<div class="fld"><div class="fld-label">Observation</div><div class="fld-value">${this._esc(ist.note).replace(/\n/g,'<br>')}</div></div>` : ''}
  ${ist.evidence ? `<div class="fld"><div class="fld-label">Evidence</div><div class="fld-value mono">${this._esc(ist.evidence)}</div></div>` : ''}
  ${(ist.remediation||item.remediation) ? `<div class="fld"><div class="fld-label">Remediation</div><div class="fld-value">${this._esc(ist.remediation||item.remediation).replace(/\n/g,'<br>')}</div></div>` : ''}
</div>
</div>`;
        findingNum++;
      }
    }

    if (!anyFindings) h += `<div class="no-findings">No vulnerabilities were identified in the selected scope.</div>`;
    h += `</div>`;

    // Observations
    const obsModules = moduleReports.filter(({ items }) =>
      items.some(i => { const s=(this.app.state.itemStates[i.id]||{}).status; return s==='in-progress'||s==='cannot-verify'; })
    );
    if (obsModules.length) {
      h += `<div class="section page-break"><h1 class="sec-title">Observations</h1>`;
      for (const { module, items } of obsModules) {
        const obs = items.filter(i => { const s=(this.app.state.itemStates[i.id]||{}).status; return s==='in-progress'||s==='cannot-verify'; });
        h += `<div class="mod-header"><span class="mod-icon">${module.icon}</span><span class="mod-name">${this._esc(module.name)}</span></div>`;
        h += `<div class="obs-list">`;
        for (const item of obs) {
          const ist = this.app.state.itemStates[item.id]||{};
          const lbl = ist.status==='cannot-verify' ? 'Cannot Verify' : 'In Progress';
          h += `<div class="obs-item"><div class="obs-main"><div class="obs-title">${this._esc(item.title)}</div>${ist.note?`<div class="obs-note">${this._esc(ist.note)}</div>`:''}</div><span class="badge b-${ist.status}">${lbl}</span></div>`;
        }
        h += `</div>`;
      }
      h += `</div>`;
    }

    return h;
  }

  // ── Consultant / Compliance report body ───────────────────────────────────

  _buildConsultantBody(meta, moduleReports) {
    const now = new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'long', year: 'numeric' });
    const version = meta.version || '1.0';

    let h = '';

    // Cover
    h += `<div class="cover">
  <div class="cover-accent"></div>
  <div class="cover-body">
    <div class="cover-wordmark">⬡ SecWorkflow</div>
    <div class="cover-report-type">Cybersecurity Compliance Assessment</div>
    <h1 class="cover-title">${this._esc(meta.projectName || 'Compliance Assessment')}</h1>
    <div class="cover-client">${this._esc(meta.client || '')}</div>
    <div class="cover-divider"></div>
    <div class="cover-meta">
      <div class="cover-meta-key">Client</div><div class="cover-meta-val">${this._esc(meta.client || '—')}</div>
      <div class="cover-meta-key">Assessor(s)</div><div class="cover-meta-val">${this._esc(meta.assessor || '—')}</div>
      <div class="cover-meta-key">Period</div><div class="cover-meta-val">${this._esc(meta.startDate || '—')} – ${this._esc(meta.endDate || '—')}</div>
      <div class="cover-meta-key">Report Date</div><div class="cover-meta-val">${now}</div>
      <div class="cover-meta-key">Version</div><div class="cover-meta-val">${this._esc(version)}</div>
      <div class="cover-meta-key">Classification</div><div class="cover-meta-val">${this._esc(meta.classification || 'CONFIDENTIAL')}</div>
    </div>
  </div>
  <div class="cover-footer">
    <div class="cover-classif">${this._esc(meta.classification || 'CONFIDENTIAL')}</div>
    <div class="cover-generated">Generated ${now}</div>
  </div>
</div>`;

    // Executive summary
    h += `<div class="section page-break"><h1 class="sec-title">Executive Summary</h1>
<p>This report presents the findings of a cybersecurity compliance assessment for <strong>${this._esc(meta.client || 'the organisation')}</strong>. It identifies control gaps, areas of compliance, and prioritised remediation recommendations.</p>
<h2 class="sub-title">Compliance Overview</h2>
<table><thead><tr><th>Framework / Domain</th><th>Total Controls</th><th>Compliant</th><th>Gap / Partial</th><th>Not Assessed</th></tr></thead><tbody>`;
    for (const { module, progress } of moduleReports) {
      const notAssessed = progress.notStarted + progress.inProgress;
      h += `<tr><td>${module.icon} ${this._esc(module.name)}</td><td>${progress.total}</td><td>${progress.compliant}</td><td>${progress.vulnerable}</td><td>${notAssessed}</td></tr>`;
    }
    h += `</tbody></table>`;
    if (meta.scope) h += `<h2 class="sub-title">Scope</h2><p>${this._esc(meta.scope).replace(/\n/g,'<br>')}</p>`;
    h += `<h2 class="sub-title">Methodology</h2>
<p>The assessment was conducted through document review, stakeholder interviews, and technical evidence review. Controls were rated as: <strong>Compliant</strong>, <strong>Gap Identified</strong>, <strong>In Progress</strong>, or <strong>Cannot Verify</strong>.</p>
</div>`;

    // Findings (gaps)
    h += `<div class="section page-break"><h1 class="sec-title">Findings and Gaps</h1>`;
    let anyGaps = false;
    const negativeStatuses = ['not-compliant', 'vulnerable'];
    const partialStatuses  = ['partially-compliant', 'in-progress', 'cannot-verify'];

    for (const { module, items } of moduleReports) {
      const gaps = items.filter(i => {
        const s=(this.app.state.itemStates[i.id]||{}).status;
        return negativeStatuses.includes(s) || partialStatuses.includes(s);
      });
      if (!gaps.length) continue;
      anyGaps = true;

      h += `<div class="mod-header"><span class="mod-icon">${module.icon}</span><span class="mod-name">${this._esc(module.name)}</span></div>`;

      const gapItems = gaps.filter(i => negativeStatuses.includes((this.app.state.itemStates[i.id]||{}).status));
      if (gapItems.length) {
        h += `<h3 class="sub-sub">Non-Compliant Controls</h3>`;
        for (const item of gapItems) {
          const ist = this.app.state.itemStates[item.id]||{};
          h += `<div class="finding-card">
<div class="finding-header"><span class="finding-name">${this._esc(item.title)}</span><span class="badge b-not-compliant">Non-Compliant</span></div>
<div class="finding-body">
  ${item.frameworks?.length ? `<div class="fld"><div class="fld-label">Framework References</div><div class="fld-value">${item.frameworks.map(f=>this._esc(f)).join(', ')}</div></div>` : ''}
  <div class="fld"><div class="fld-label">Description</div><div class="fld-value">${this._esc(item.description)}</div></div>
  ${ist.note ? `<div class="fld"><div class="fld-label">Assessment Notes</div><div class="fld-value">${this._esc(ist.note).replace(/\n/g,'<br>')}</div></div>` : ''}
</div></div>`;
        }
      }

      const partialItems = gaps.filter(i => partialStatuses.includes((this.app.state.itemStates[i.id]||{}).status));
      if (partialItems.length) {
        h += `<h3 class="sub-sub">Partially Implemented / Unverified</h3><div class="obs-list">`;
        for (const item of partialItems) {
          const ist = this.app.state.itemStates[item.id]||{};
          const s = ist.status || 'in-progress';
          const lbl = s === 'partially-compliant' ? 'Partial' : s === 'cannot-verify' ? 'Unverified' : 'In Progress';
          h += `<div class="obs-item"><div class="obs-main"><div class="obs-title">${this._esc(item.title)}</div>${ist.note?`<div class="obs-note">${this._esc(ist.note)}</div>`:''}</div><span class="badge b-${s}">${lbl}</span></div>`;
        }
        h += `</div>`;
      }
    }
    if (!anyGaps) h += `<div class="no-findings">No gaps or issues identified in the selected scope.</div>`;
    h += `</div>`;

    return h;
  }

  // ── Executive summary body ────────────────────────────────────────────────

  _buildExecutiveBody(meta, moduleReports) {
    const now = new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'long', year: 'numeric' });
    const totalVuln = this._countByStatus(moduleReports, 'vulnerable');
    const totalItems = moduleReports.reduce((s, { items }) => s + items.length, 0);
    const version = meta.version || '1.0';

    let h = '';

    // Cover
    h += `<div class="cover">
  <div class="cover-accent"></div>
  <div class="cover-body">
    <div class="cover-wordmark">⬡ SecWorkflow</div>
    <div class="cover-report-type">Executive Summary</div>
    <h1 class="cover-title">${this._esc(meta.projectName || 'Security Assessment')}</h1>
    <div class="cover-client">${this._esc(meta.client || '')}</div>
    <div class="cover-divider"></div>
    <div class="cover-meta">
      <div class="cover-meta-key">Client</div><div class="cover-meta-val">${this._esc(meta.client || '—')}</div>
      <div class="cover-meta-key">Assessor(s)</div><div class="cover-meta-val">${this._esc(meta.assessor || '—')}</div>
      <div class="cover-meta-key">Date</div><div class="cover-meta-val">${now}</div>
      <div class="cover-meta-key">Version</div><div class="cover-meta-val">${this._esc(version)}</div>
      <div class="cover-meta-key">Classification</div><div class="cover-meta-val">${this._esc(meta.classification || 'CONFIDENTIAL')}</div>
    </div>
  </div>
  <div class="cover-footer">
    <div class="cover-classif">${this._esc(meta.classification || 'CONFIDENTIAL')}</div>
    <div class="cover-generated">Generated ${now}</div>
  </div>
</div>`;

    h += `<div class="section page-break"><h1 class="sec-title">Overview</h1>
<p>A security assessment was conducted for <strong>${this._esc(meta.client || 'the organisation')}</strong> covering <strong>${moduleReports.length} domain(s)</strong>. Of <strong>${totalItems} checks evaluated</strong>, <strong>${totalVuln} gap(s) or vulnerabilities</strong> were identified requiring remediation.</p>
<h2 class="sub-title">Domain Summary</h2>
<table><thead><tr><th>Domain</th><th>Total Checks</th><th>Issues Found</th><th>Compliant</th><th>Risk Level</th></tr></thead><tbody>`;

    for (const { module, items, progress } of moduleReports) {
      const issues = items.filter(i => (this.app.state.itemStates[i.id]||{}).status==='vulnerable').length;
      const pct = progress.total > 0 ? Math.round((progress.compliant / progress.total) * 100) : 0;
      const riskBadge = issues === 0
        ? '<span class="badge b-not-vulnerable">Low</span>'
        : issues > 5
          ? '<span class="badge b-critical">High</span>'
          : '<span class="badge b-medium">Medium</span>';
      h += `<tr><td>${module.icon} ${this._esc(module.name)}</td><td>${progress.total}</td><td>${issues}</td><td>${pct}%</td><td>${riskBadge}</td></tr>`;
    }
    h += `</tbody></table>`;

    const criticalItems = moduleReports.flatMap(({ module, items }) =>
      items.filter(i => {
        const ist = this.app.state.itemStates[i.id]||{};
        const sev = ist.severityOverride || i.severity;
        return ist.status==='vulnerable' && (sev==='critical'||sev==='high');
      }).map(i => ({ item: i, module, sev: (this.app.state.itemStates[i.id]||{}).severityOverride || i.severity }))
    );

    h += `<h2 class="sub-title">Critical Actions Required</h2>`;
    if (criticalItems.length) {
      h += `<table><thead><tr><th>#</th><th>Finding</th><th>Domain</th><th>Severity</th></tr></thead><tbody>`;
      criticalItems.forEach(({ item, module, sev }, i) => {
        h += `<tr><td>${i+1}</td><td>${this._esc(item.title)}</td><td>${this._esc(module.name)}</td><td><span class="badge b-${sev}">${sev}</span></td></tr>`;
      });
      h += `</tbody></table>`;
    } else {
      h += `<p style="color:#059669;font-weight:600">✓ No critical or high severity items identified.</p>`;
    }

    h += `<h2 class="sub-title">Next Steps</h2>
<ol>
  <li>Review this report with the security and IT leadership teams</li>
  <li>Prioritise remediation of critical and high findings</li>
  <li>Define ownership and target dates for all remediation actions</li>
  <li>Schedule a follow-up assessment to verify remediation effectiveness</li>
  <li>Update the organisational risk register with all identified risks</li>
</ol>
</div>`;

    return h;
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  _esc(str) {
    if (str == null) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;');
  }

  _collectFindings(moduleReports) {
    return moduleReports.flatMap(({ module, items }) =>
      items.filter(i => (this.app.state.itemStates[i.id]||{}).status==='vulnerable').map(i => ({ item: i, module }))
    );
  }

  _countByStatus(moduleReports, status) {
    return moduleReports.reduce((sum, { items }) =>
      sum + items.filter(i => (this.app.state.itemStates[i.id]||{}).status===status).length, 0);
  }

  _countBySeverity(findings) {
    const counts = {};
    for (const { item } of findings) {
      const sev = (this.app.state.itemStates[item.id]||{}).severityOverride || item.severity || 'info';
      counts[sev] = (counts[sev] || 0) + 1;
    }
    return counts;
  }
}
