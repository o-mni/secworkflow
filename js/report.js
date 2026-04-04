// ── Report Generator ─────────────────────────────────────────────────────────

class ReportGenerator {
  constructor(app) {
    this.app = app;
  }

  // ── Entry point ────────────────────────────────────────────────────────────

  generate(options = {}) {
    const {
      type = 'pentest',
      includedModuleIds = [],
      includeStatuses = ['vulnerable', 'in-progress', 'cannot-verify'],
      findingsOnly = false,
    } = options;

    const state = this.app.state;
    const meta = state.metadata;

    // Collect findings per module
    const moduleReports = [];

    for (const modId of includedModuleIds) {
      const module = MODULE_MAP[modId];
      if (!module) continue;

      const items = getModuleItems(module);
      const filtered = items.filter(item => {
        const ist = state.itemStates[item.id] || {};
        const status = ist.status || 'not-started';
        if (!includeStatuses.includes(status)) return false;
        if (findingsOnly && !ist.isFinding && !ist.note) return false;
        return true;
      });

      if (filtered.length === 0) continue;

      const progress = this.app.getModuleProgress(module);
      moduleReports.push({ module, items: filtered, progress });
    }

    if (type === 'executive') return this._generateExecutive(meta, moduleReports);
    if (type === 'consultant') return this._generateConsultant(meta, moduleReports);
    return this._generatePentest(meta, moduleReports);
  }

  // ── Pentest report ─────────────────────────────────────────────────────────

  _generatePentest(meta, moduleReports) {
    const now = new Date().toISOString().slice(0, 10);
    const findings = this._collectFindings(moduleReports, 'pentest');
    const vulnCount = this._countByStatus(moduleReports, 'vulnerable');
    const sevCounts = this._countBySeverity(findings);

    let md = '';
    md += `# Penetration Test Report\n\n`;
    md += `| Field | Value |\n|---|---|\n`;
    md += `| Project | ${meta.projectName || 'Untitled'} |\n`;
    md += `| Client | ${meta.client || '—'} |\n`;
    md += `| Assessor(s) | ${meta.assessor || '—'} |\n`;
    md += `| Classification | ${meta.classification || 'CONFIDENTIAL'} |\n`;
    md += `| Test Period | ${meta.startDate || '—'} to ${meta.endDate || '—'} |\n`;
    md += `| Report Date | ${now} |\n\n`;

    md += `---\n\n## Executive Summary\n\n`;
    md += `This report presents the results of a penetration test conducted against ${meta.client || 'the client'} environment. `;
    md += `The assessment covered ${moduleReports.length} module(s) with a total of **${vulnCount} vulnerabilities identified**.\n\n`;

    md += `### Risk Summary\n\n`;
    md += `| Severity | Count |\n|---|---|\n`;
    for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
      if (sevCounts[sev]) md += `| ${sev.charAt(0).toUpperCase() + sev.slice(1)} | ${sevCounts[sev]} |\n`;
    }
    md += `\n`;

    if (meta.scope) {
      md += `## Scope\n\n${meta.scope}\n\n`;
    }
    if (meta.exclusions) {
      md += `## Exclusions\n\n${meta.exclusions}\n\n`;
    }

    md += `## Methodology\n\n`;
    md += `Testing was conducted using industry-standard methodologies including PTES, OWASP WSTG, and MITRE ATT&CK framework. `;
    md += `Evidence was collected using a combination of automated tools and manual testing techniques.\n\n`;
    md += `---\n\n## Findings\n\n`;

    let findingNum = 1;
    for (const { module, items } of moduleReports) {
      const vulnItems = items.filter(i => {
        const s = (this.app.state.itemStates[i.id] || {}).status;
        return s === 'vulnerable';
      });
      if (vulnItems.length === 0) continue;

      md += `### ${module.icon} ${module.name}\n\n`;

      for (const item of vulnItems) {
        const ist = this.app.state.itemStates[item.id] || {};
        const sev = ist.severityOverride || item.severity || 'medium';
        md += `#### [F${String(findingNum).padStart(3,'0')}] ${item.title}\n\n`;
        md += `**Severity:** ${sev.toUpperCase()}  \n`;
        md += `**Status:** Vulnerable  \n`;
        if (item.tags?.length) md += `**Tags:** ${item.tags.join(', ')}  \n`;
        if (item.frameworks?.length) md += `**References:** ${item.frameworks.join(', ')}  \n`;
        md += `\n**Description**\n\n${item.description}\n\n`;
        if (ist.note) md += `**Observation / Evidence**\n\n${ist.note}\n\n`;
        if (ist.evidence) md += `**Evidence**\n\n\`\`\`\n${ist.evidence}\n\`\`\`\n\n`;
        const rem = ist.remediation || item.remediation;
        if (rem) md += `**Remediation**\n\n${rem}\n\n`;
        md += `---\n\n`;
        findingNum++;
      }
    }

    // In-progress and cannot-verify
    md += `## Observations (In Progress / Cannot Verify)\n\n`;
    let obsCount = 0;
    for (const { module, items } of moduleReports) {
      const obsItems = items.filter(i => {
        const s = (this.app.state.itemStates[i.id] || {}).status;
        return s === 'in-progress' || s === 'cannot-verify';
      });
      if (obsItems.length === 0) continue;
      md += `### ${module.name}\n\n`;
      for (const item of obsItems) {
        const ist = this.app.state.itemStates[item.id] || {};
        md += `- **${item.title}** (${ist.status || 'in-progress'})`;
        if (ist.note) md += `: ${ist.note}`;
        md += `\n`;
        obsCount++;
      }
      md += `\n`;
    }
    if (obsCount === 0) md += `_No observations in this category._\n\n`;

    md += `## Recommendations\n\n`;
    md += `The following prioritised recommendations address the identified vulnerabilities:\n\n`;
    let recNum = 1;
    const allVuln = moduleReports.flatMap(({ module, items }) =>
      items
        .filter(i => (this.app.state.itemStates[i.id] || {}).status === 'vulnerable')
        .map(i => ({ item: i, module }))
    ).sort((a, b) => {
      const order = { critical:0, high:1, medium:2, low:3, info:4 };
      const sa = (this.app.state.itemStates[a.item.id] || {}).severityOverride || a.item.severity || 'medium';
      const sb = (this.app.state.itemStates[b.item.id] || {}).severityOverride || b.item.severity || 'medium';
      return (order[sa] ?? 5) - (order[sb] ?? 5);
    });

    for (const { item, module } of allVuln) {
      const ist = this.app.state.itemStates[item.id] || {};
      const rem = ist.remediation || item.remediation;
      if (rem) {
        md += `${recNum}. **[${module.name}] ${item.title}** — ${rem}\n`;
        recNum++;
      }
    }

    md += `\n## Appendix: Module Coverage\n\n`;
    md += `| Module | Total | Vulnerable | In Progress | Compliant | Not in Scope |\n|---|---|---|---|---|---|\n`;
    for (const { module, progress } of moduleReports) {
      md += `| ${module.name} | ${progress.total} | ${progress.vulnerable} | ${progress.inProgress} | ${progress.compliant} | ${progress.notInScope} |\n`;
    }
    md += `\n`;

    return md;
  }

  // ── Consultant / Compliance report ────────────────────────────────────────

  _generateConsultant(meta, moduleReports) {
    const now = new Date().toISOString().slice(0, 10);
    let md = '';
    md += `# Cybersecurity Compliance Assessment Report\n\n`;
    md += `| Field | Value |\n|---|---|\n`;
    md += `| Project | ${meta.projectName || 'Untitled'} |\n`;
    md += `| Client | ${meta.client || '—'} |\n`;
    md += `| Assessor(s) | ${meta.assessor || '—'} |\n`;
    md += `| Classification | ${meta.classification || 'CONFIDENTIAL'} |\n`;
    md += `| Assessment Period | ${meta.startDate || '—'} to ${meta.endDate || '—'} |\n`;
    md += `| Report Date | ${now} |\n\n`;

    md += `---\n\n## Executive Summary\n\n`;
    md += `This report presents the findings of a cybersecurity compliance assessment against the selected frameworks. `;
    md += `The assessment identifies gaps, areas of compliance, and prioritised remediation recommendations.\n\n`;

    md += `### Compliance Overview\n\n`;
    md += `| Framework | Total Controls | Compliant | Gap / Partial | Not Assessed |\n|---|---|---|---|---|\n`;
    for (const { module, progress } of moduleReports) {
      const notAssessed = progress.notStarted + progress.inProgress;
      md += `| ${module.name} | ${progress.total} | ${progress.compliant} | ${progress.vulnerable} | ${notAssessed} |\n`;
    }
    md += `\n`;

    if (meta.scope) md += `## Scope\n\n${meta.scope}\n\n`;

    md += `## Methodology\n\n`;
    md += `The assessment was conducted through document review, interviews with key stakeholders, and technical evidence review. `;
    md += `Controls were evaluated against the selected framework requirements and rated as: `;
    md += `**Compliant**, **Gap Identified**, **In Progress** (partially implemented), or **Cannot Verify** (insufficient evidence).\n\n`;

    md += `---\n\n## Key Findings and Gaps\n\n`;

    for (const { module, items } of moduleReports) {
      const gaps = items.filter(i => {
        const s = (this.app.state.itemStates[i.id] || {}).status;
        return s === 'vulnerable' || s === 'in-progress' || s === 'cannot-verify';
      });
      if (gaps.length === 0) continue;

      md += `### ${module.icon} ${module.name}\n\n`;

      const byStatus = {
        vulnerable: gaps.filter(i => (this.app.state.itemStates[i.id]||{}).status === 'vulnerable'),
        'in-progress': gaps.filter(i => (this.app.state.itemStates[i.id]||{}).status === 'in-progress'),
        'cannot-verify': gaps.filter(i => (this.app.state.itemStates[i.id]||{}).status === 'cannot-verify'),
      };

      if (byStatus.vulnerable.length) {
        md += `#### Gaps Identified\n\n`;
        for (const item of byStatus.vulnerable) {
          const ist = this.app.state.itemStates[item.id] || {};
          md += `**${item.title}**\n\n`;
          md += `*Frameworks:* ${item.frameworks?.join(', ') || '—'}  \n`;
          md += `*Description:* ${item.description}\n\n`;
          if (ist.note) md += `*Assessment Notes:* ${ist.note}\n\n`;
          const rem = ist.remediation || item.remediation;
          if (rem) md += `*Recommended Action:* ${rem}\n\n`;
          md += `---\n\n`;
        }
      }

      if (byStatus['in-progress'].length) {
        md += `#### Partially Implemented\n\n`;
        for (const item of byStatus['in-progress']) {
          const ist = this.app.state.itemStates[item.id] || {};
          md += `- **${item.title}**`;
          if (ist.note) md += `: ${ist.note}`;
          md += `\n`;
        }
        md += `\n`;
      }

      if (byStatus['cannot-verify'].length) {
        md += `#### Cannot Verify (insufficient evidence)\n\n`;
        for (const item of byStatus['cannot-verify']) {
          md += `- ${item.title}\n`;
        }
        md += `\n`;
      }
    }

    md += `## Prioritised Recommendations\n\n`;
    md += `The following recommendations are prioritised by criticality:\n\n`;
    let recNum = 1;
    for (const { module, items } of moduleReports) {
      const critItems = items.filter(i => (this.app.state.itemStates[i.id]||{}).status === 'vulnerable');
      for (const item of critItems) {
        const ist = this.app.state.itemStates[item.id] || {};
        const rem = ist.remediation || item.remediation;
        if (rem) {
          md += `${recNum}. **[${module.name}] ${item.title}** — ${rem}\n`;
          recNum++;
        }
      }
    }

    md += `\n## Compliance Gap Matrix\n\n`;
    md += `| # | Control | Framework | Status | Note |\n|---|---|---|---|---|\n`;
    let rowNum = 1;
    for (const { module, items } of moduleReports) {
      for (const item of items) {
        const ist = this.app.state.itemStates[item.id] || {};
        const status = ist.status || 'not-started';
        const statusLabel = STATUSES.find(s => s.value === status)?.label || status;
        md += `| ${rowNum} | ${item.title} | ${item.frameworks?.join(', ') || '—'} | ${statusLabel} | ${ist.note || ''} |\n`;
        rowNum++;
      }
    }
    md += `\n`;

    return md;
  }

  // ── Executive summary ─────────────────────────────────────────────────────

  _generateExecutive(meta, moduleReports) {
    const now = new Date().toISOString().slice(0, 10);
    const totalVuln = this._countByStatus(moduleReports, 'vulnerable');
    const totalItems = moduleReports.reduce((s, { items }) => s + items.length, 0);

    let md = `# Executive Summary\n\n`;
    md += `**${meta.projectName || 'Security Assessment'} — ${meta.client || 'Client'}**  \n`;
    md += `Date: ${now} | Assessor: ${meta.assessor || '—'} | Classification: ${meta.classification || 'CONFIDENTIAL'}\n\n`;

    md += `## Overview\n\n`;
    md += `A security assessment was conducted covering **${moduleReports.length} domain(s)**. `;
    md += `Of **${totalItems} controls/checks evaluated**, **${totalVuln} gaps or vulnerabilities** were identified requiring remediation.\n\n`;

    md += `## Domain Summary\n\n`;
    md += `| Domain | Assessed | Issues | Status |\n|---|---|---|---|\n`;
    for (const { module, items, progress } of moduleReports) {
      const issues = items.filter(i => (this.app.state.itemStates[i.id]||{}).status === 'vulnerable').length;
      const pct = progress.total > 0 ? Math.round((progress.compliant / progress.total) * 100) : 0;
      const statusEmoji = issues > 0 ? (issues > 5 ? '🔴' : '🟠') : '🟢';
      md += `| ${module.icon} ${module.name} | ${progress.total} | ${issues} | ${statusEmoji} ${pct}% compliant |\n`;
    }
    md += `\n`;

    md += `## Critical Actions Required\n\n`;
    let actionNum = 1;
    for (const { module, items } of moduleReports) {
      for (const item of items) {
        const ist = this.app.state.itemStates[item.id] || {};
        const sev = ist.severityOverride || item.severity;
        if (ist.status === 'vulnerable' && (sev === 'critical' || sev === 'high')) {
          md += `${actionNum}. **${item.title}** (${module.name}) — Severity: ${sev?.toUpperCase()}\n`;
          actionNum++;
        }
      }
    }
    if (actionNum === 1) md += `_No critical or high severity items identified._\n`;
    md += `\n`;

    md += `## Next Steps\n\n`;
    md += `1. Review this report with the security and IT leadership teams\n`;
    md += `2. Prioritise remediation of critical and high findings\n`;
    md += `3. Define ownership and target dates for all remediation actions\n`;
    md += `4. Schedule follow-up assessment to verify remediation\n`;
    md += `5. Update risk register with identified risks\n\n`;

    return md;
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  _collectFindings(moduleReports, type) {
    return moduleReports.flatMap(({ module, items }) =>
      items
        .filter(i => (this.app.state.itemStates[i.id]||{}).status === 'vulnerable')
        .map(i => ({ item: i, module }))
    );
  }

  _countByStatus(moduleReports, status) {
    return moduleReports.reduce((sum, { items }) =>
      sum + items.filter(i => (this.app.state.itemStates[i.id]||{}).status === status).length, 0);
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
