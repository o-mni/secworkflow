// ── Report Generator ─────────────────────────────────────────────────────────

class ReportGenerator {
  constructor(app) {
    this.app = app;
  }

  // ── Entry point ────────────────────────────────────────────────────────────

  _buildModuleReports(options) {
    const { type = 'pentest', includedModuleIds = [] } = options;
    const state = this.app.state;
    const meta = state.metadata;
    const moduleReports = [];

    for (const modId of includedModuleIds) {
      const module = MODULE_MAP[modId];
      if (!module) continue;
      const items = getModuleItems(module);
      const filtered = items.filter(item => {
        const ist = state.itemStates[item.id] || {};
        if (ist.outOfScope) return false;
        if (item._custom) return true;
        const status = ist.status || 'not-started';
        if (status === 'not-started' || status === 'not-assessed' || status === 'not-in-scope') {
          const hasNotes = Array.isArray(ist.notes) && ist.notes.length > 0;
          return hasNotes || !!ist.evidence || !!ist.isFinding;
        }
        return true;
      });
      if (filtered.length === 0) continue;
      moduleReports.push({ module, items: filtered, progress: this.app.getModuleProgress(module) });
    }
    return { type, meta, moduleReports };
  }

  generateHTML(options = {}) {
    const { type, meta, moduleReports } = this._buildModuleReports(options);
    const html = this._buildInteractiveHTML(type, meta, moduleReports);
    const slug = (meta.projectName || 'report').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    const date = new Date().toISOString().slice(0, 10);
    const filename = `${slug}_${date}.html`;
    const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  }

  _buildInteractiveHTML(type, meta, moduleReports) {
    const e = (s) => this._esc(s);
    const now = new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'long', year: 'numeric' });
    const isConsultant = type === 'consultant';

    // ── collect all items with their data ──────────────────────────────
    const allItems = [];
    let findingCounter = 0;
    for (const { module, items } of moduleReports) {
      for (const item of items) {
        const ist = this.app.state.itemStates[item.id] || {};
        const status = ist.status || (isConsultant ? 'not-assessed' : 'not-started');
        const sev = ist.severityOverride || item.severity || 'info';
        const isVuln = status === 'vulnerable' || status === 'not-compliant';
        if (isVuln) findingCounter++;
        allItems.push({ item, ist, module, status, sev, isVuln, fNum: isVuln ? findingCounter : null });
      }
    }

    // ── severity counts ────────────────────────────────────────────────
    const sevCounts = { critical:0, high:0, medium:0, low:0, info:0 };
    for (const { isVuln, sev } of allItems) {
      if (isVuln && sevCounts[sev] !== undefined) sevCounts[sev]++;
    }
    const totalVuln = Object.values(sevCounts).reduce((a,b)=>a+b,0);

    // ── status counts ──────────────────────────────────────────────────
    const statusCounts = {};
    for (const { status } of allItems) statusCounts[status] = (statusCounts[status]||0)+1;

    // ── donut SVG ──────────────────────────────────────────────────────
    const donutColors = { critical:'#ef4444', high:'#f97316', medium:'#eab308', low:'#3b82f6', info:'#6b7280' };
    const donutTotal = totalVuln || 1;
    let donutSvg = '', offset = 0;
    const r = 54, circ = 2 * Math.PI * r;
    for (const [sev, color] of Object.entries(donutColors)) {
      const pct = (sevCounts[sev]||0) / donutTotal;
      if (pct === 0) continue;
      const dash = pct * circ;
      donutSvg += `<circle cx="64" cy="64" r="${r}" fill="none" stroke="${color}" stroke-width="14" stroke-dasharray="${dash.toFixed(2)} ${(circ-dash).toFixed(2)}" stroke-dashoffset="${(-offset * circ).toFixed(2)}" transform="rotate(-90 64 64)"/>`;
      offset += pct;
    }
    if (totalVuln === 0) donutSvg = `<circle cx="64" cy="64" r="${r}" fill="none" stroke="#1e2535" stroke-width="14"/>`;

    // ── module progress bars data ──────────────────────────────────────
    const modProgressHTML = moduleReports.map(({ module, items, progress }) => {
      const vulnCount = items.filter(i => { const s=(this.app.state.itemStates[i.id]||{}).status; return s==='vulnerable'||s==='not-compliant'; }).length;
      const doneCount = items.filter(i => { const s=(this.app.state.itemStates[i.id]||{}).status; return s&&s!=='not-started'&&s!=='not-assessed'; }).length;
      const pct = items.length > 0 ? Math.round((doneCount/items.length)*100) : 0;
      return `<div class="mod-prog-row" data-mod-id="${e(module.id)}">
  <div class="mod-prog-icon">${e(module.icon)}</div>
  <div class="mod-prog-body">
    <div class="mod-prog-top"><span class="mod-prog-name">${e(module.name)}</span><span class="mod-prog-stats">${vulnCount > 0 ? `<span class="pill pill-vuln">${vulnCount} issue${vulnCount!==1?'s':''}</span>` : ''}<span class="pill pill-pct">${pct}%</span></span></div>
    <div class="mod-prog-bar"><div class="mod-prog-fill" style="width:${pct}%;background:${vulnCount>0?'#ef4444':'#4c73f8'}"></div></div>
  </div>
</div>`;
    }).join('');

    // ── nav items ──────────────────────────────────────────────────────
    const navItems = [
      { id:'sec-overview', label:'Overview', icon:'◈' },
      { id:'sec-findings', label:`Findings (${totalVuln})`, icon:'⚠' },
      { id:'sec-observations', label:'Observations', icon:'◉' },
    ];
    if (moduleReports.some(r => r.module.id === 'custom-checks')) {
      navItems.push({ id:'sec-custom', label:'Custom Checks', icon:'✦' });
    }
    const navHTML = navItems.map(n =>
      `<a class="nav-link" href="#${n.id}"><span class="nav-icon">${n.icon}</span>${n.label}</a>`
    ).join('');

    const modNavHTML = moduleReports.filter(r=>r.module.id!=='custom-checks').map(({ module }) =>
      `<a class="nav-link nav-link-mod" href="#mod-${e(module.id)}" data-mod="${e(module.id)}"><span class="nav-icon">${e(module.icon)}</span>${e(module.name)}</a>`
    ).join('');

    // ── classification colors ──────────────────────────────────────────
    const classifColors = { 'CONFIDENTIAL':'#ef4444','TLP:RED':'#ef4444','TLP:AMBER':'#f97316','TLP:GREEN':'#22c55e','INTERNAL':'#3b82f6' };
    const classifColor = classifColors[meta.classification] || '#ef4444';

    // ── build finding cards ────────────────────────────────────────────
    const buildCard = ({ item, ist, module, status, sev, isVuln, fNum }) => {
      const statusLabels = {
        'vulnerable':'Vulnerable','not-compliant':'Non-Compliant','in-progress':'In Progress',
        'cannot-verify':'Cannot Verify','not-vulnerable':'Not Vulnerable','not-started':'Not Started',
        'partially-compliant':'Partial','compliant':'Compliant','not-assessed':'Not Assessed',
      };
      const statusColors = {
        'vulnerable':'#ef4444','not-compliant':'#ef4444','in-progress':'#3b82f6',
        'cannot-verify':'#eab308','not-vulnerable':'#22c55e','not-started':'#6b7280',
        'partially-compliant':'#f97316','compliant':'#22c55e','not-assessed':'#6b7280',
      };
      const sevColors = { critical:'#ef4444', high:'#f97316', medium:'#eab308', low:'#3b82f6', info:'#6b7280' };
      const sl = statusLabels[status] || status;
      const sc = statusColors[status] || '#6b7280';
      const sevc = sevColors[sev] || '#6b7280';
      const notesHTML = (ist.notes||[]).length > 0
        ? `<div class="card-field"><div class="card-field-label">Notes</div><div class="card-field-notes">${(ist.notes||[]).map(n=>`<div class="note-row"><span class="note-ts">${e(this._formatNoteTs(n.ts))}</span><span class="note-txt">${e(n.text).replace(/\n/g,'<br>')}</span></div>`).join('')}</div></div>`
        : '';
      const evidHTML = ist.evidence
        ? `<div class="card-field"><div class="card-field-label">Evidence</div><pre class="card-evidence">${e(ist.evidence)}</pre></div>` : '';
      const cvesHTML = (ist.cves||[]).length > 0
        ? `<div class="card-field"><div class="card-field-label">CVEs</div><div class="card-field-value">${(ist.cves||[]).map(c=>`<span class="cve-chip">${e(c)}</span>`).join('')}</div></div>` : '';
      const tagsHTML = item.tags?.length
        ? `<div class="card-field"><div class="card-field-label">Tags</div><div class="card-field-value">${item.tags.map(t=>`<span class="tag-chip">${e(t)}</span>`).join('')}</div></div>` : '';
      const fwHTML = item.frameworks?.length
        ? `<div class="card-field"><div class="card-field-label">References</div><div class="card-field-value fld-refs">${item.frameworks.map(f=>e(f)).join(' · ')}</div></div>` : '';
      return `<div class="card" data-status="${e(status)}" data-sev="${e(sev)}" data-mod="${e(module.id)}" data-search="${e((item.title+' '+(item.description||'')+' '+(ist.notes||[]).map(n=>n.text).join(' ')).toLowerCase())}">
  <div class="card-header" onclick="this.parentElement.classList.toggle('open')">
    <div class="card-header-left">
      ${fNum ? `<span class="card-fnum">F${String(fNum).padStart(3,'0')}</span>` : ''}
      <span class="card-icon">${e(module.icon)}</span>
      <span class="card-title">${e(item.title)}</span>
    </div>
    <div class="card-header-right">
      <span class="chip" style="background:${sc}22;color:${sc};border:1px solid ${sc}44">${sl}</span>
      ${item.severity ? `<span class="chip chip-sev" style="background:${sevc}22;color:${sevc};border:1px solid ${sevc}44">${e(sev)}</span>` : ''}
      <span class="card-mod-label">${e(module.name)}</span>
      <span class="card-chevron">›</span>
    </div>
  </div>
  <div class="card-body">
    ${item.description ? `<div class="card-field"><div class="card-field-label">Description</div><div class="card-field-value">${e(item.description)}</div></div>` : ''}
    ${tagsHTML}${fwHTML}${notesHTML}${evidHTML}${cvesHTML}
  </div>
</div>`;
    };

    // ── sections ───────────────────────────────────────────────────────
    const findingItems = allItems.filter(x => x.isVuln);
    const obsItems = allItems.filter(x => !x.isVuln && !x.item._custom);
    const customItems = allItems.filter(x => x.item._custom);

    const findingsSection = findingItems.length
      ? findingItems.map(buildCard).join('\n')
      : `<div class="empty-state"><div class="empty-icon">✓</div><div class="empty-title">No vulnerabilities found</div><div class="empty-sub">No items were marked as vulnerable in the selected scope.</div></div>`;

    // Group observations by module
    const obsGrouped = {};
    for (const x of obsItems) {
      const key = x.module.id;
      if (!obsGrouped[key]) obsGrouped[key] = { module: x.module, items: [] };
      obsGrouped[key].items.push(x);
    }
    const obsSection = Object.values(obsGrouped).length
      ? Object.values(obsGrouped).map(({ module, items }) =>
          `<div id="mod-${e(module.id)}" class="mod-anchor"></div>` +
          items.map(buildCard).join('\n')
        ).join('\n')
      : `<div class="empty-state"><div class="empty-icon">◉</div><div class="empty-title">No observations</div><div class="empty-sub">All assessed items were either vulnerable or not touched.</div></div>`;

    const customSection = customItems.length
      ? customItems.map(buildCard).join('\n')
      : '';

    // ── title ──────────────────────────────────────────────────────────
    const reportTypeLabel = isConsultant ? 'Compliance Assessment' : 'Penetration Test Report';
    const titleStr = `${meta.projectName || 'Security Assessment'} — ${reportTypeLabel}`;

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data: blob:; connect-src 'none'; object-src 'none';">
<title>${e(titleStr)}</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0b0d14;--bg2:#0f1118;--bg3:#151722;--bg4:#1a1d2e;
  --border:#1e2235;--border2:#252a3d;
  --text:#e2e6f3;--text2:#8b91aa;--text3:#5a6080;
  --accent:#4c73f8;--accent2:#3a5fdf;
  --red:#ef4444;--orange:#f97316;--yellow:#eab308;--blue:#3b82f6;--gray:#6b7280;--green:#22c55e;
  --sidebar-w:240px;--topbar-h:56px;
  --font:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
  --mono:'Cascadia Code','Fira Code',Consolas,monospace;
  --radius:10px;--radius-sm:6px;
}
html{scroll-behavior:smooth}
body{font-family:var(--font);background:var(--bg);color:var(--text);min-height:100vh;display:flex;flex-direction:column}

/* ── TOPBAR ── */
.topbar{position:fixed;top:0;left:0;right:0;height:var(--topbar-h);background:var(--bg2);border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 20px 0 calc(var(--sidebar-w) + 20px);z-index:100;gap:16px}
.topbar-title{font-size:13px;font-weight:700;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:1}
.topbar-meta{display:flex;align-items:center;gap:10px;flex-shrink:0}
.classif-badge{font-size:10px;font-weight:800;letter-spacing:1.5px;padding:3px 10px;border-radius:4px;background:${classifColor}22;color:${classifColor};border:1px solid ${classifColor}44;text-transform:uppercase}
.topbar-date{font-size:11px;color:var(--text3)}
.btn-print{display:inline-flex;align-items:center;gap:6px;padding:6px 14px;border-radius:var(--radius-sm);border:1px solid var(--border2);background:var(--bg4);color:var(--text2);font-size:11px;font-weight:600;cursor:pointer;transition:all .15s;white-space:nowrap}
.btn-print:hover{border-color:var(--accent);color:var(--accent);background:#4c73f808}
.btn-print svg{flex-shrink:0}

/* ── SIDEBAR ── */
.sidebar{position:fixed;top:0;left:0;bottom:0;width:var(--sidebar-w);background:var(--bg2);border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:110;overflow:hidden}
.sidebar-brand{display:flex;align-items:center;gap:10px;padding:0 16px;height:var(--topbar-h);border-bottom:1px solid var(--border);flex-shrink:0}
.sidebar-brand-mark{font-size:18px;color:var(--accent)}
.sidebar-brand-name{font-size:12px;font-weight:800;color:var(--text);letter-spacing:-.2px}
.sidebar-brand-sub{font-size:9px;color:var(--text3);margin-top:1px}
.sidebar-scroll{flex:1;overflow-y:auto;padding:12px 8px}
.sidebar-scroll::-webkit-scrollbar{width:4px}
.sidebar-scroll::-webkit-scrollbar-track{background:transparent}
.sidebar-scroll::-webkit-scrollbar-thumb{background:var(--border2);border-radius:4px}
.nav-section-label{font-size:9px;font-weight:700;color:var(--text3);letter-spacing:1.5px;text-transform:uppercase;padding:10px 10px 4px}
.nav-link{display:flex;align-items:center;gap:8px;padding:7px 10px;border-radius:var(--radius-sm);color:var(--text2);font-size:12px;font-weight:500;text-decoration:none;transition:all .12s;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.nav-link:hover{background:var(--bg4);color:var(--text)}
.nav-link.active{background:var(--accent)18;color:var(--accent);font-weight:600}
.nav-icon{font-size:12px;flex-shrink:0;width:16px;text-align:center}
.nav-link-mod{font-size:11px;padding:5px 10px}
.nav-divider{height:1px;background:var(--border);margin:8px 4px}

/* ── MAIN ── */
.main{margin-left:var(--sidebar-w);padding-top:var(--topbar-h)}
.content{max-width:960px;margin:0 auto;padding:32px 24px 80px}

/* ── SEARCH + FILTERS ── */
.toolbar{display:flex;align-items:center;gap:10px;margin-bottom:24px;flex-wrap:wrap}
.search-wrap{position:relative;flex:1;min-width:200px}
.search-wrap svg{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--text3);pointer-events:none}
.search-input{width:100%;background:var(--bg3);border:1px solid var(--border2);border-radius:var(--radius-sm);padding:8px 12px 8px 34px;color:var(--text);font-size:12px;outline:none;transition:border .15s}
.search-input::placeholder{color:var(--text3)}
.search-input:focus{border-color:var(--accent)}
.filter-group{display:flex;gap:6px;flex-wrap:wrap}
.filter-btn{padding:5px 12px;border-radius:var(--radius-sm);border:1px solid var(--border2);background:var(--bg3);color:var(--text2);font-size:11px;font-weight:600;cursor:pointer;transition:all .12s}
.filter-btn:hover{border-color:var(--accent);color:var(--accent)}
.filter-btn.active{background:var(--accent);border-color:var(--accent);color:#fff}
.filter-btn[data-sev="critical"].active{background:var(--red);border-color:var(--red)}
.filter-btn[data-sev="high"].active{background:var(--orange);border-color:var(--orange)}
.filter-btn[data-sev="medium"].active{background:var(--yellow);border-color:var(--yellow);color:#000}
.filter-btn[data-sev="low"].active{background:var(--blue);border-color:var(--blue)}
.results-count{font-size:11px;color:var(--text3);white-space:nowrap}

/* ── SECTION HEADERS ── */
.section-anchor{display:block;height:var(--topbar-h);margin-top:calc(-1 * var(--topbar-h));visibility:hidden;pointer-events:none}
.mod-anchor{display:block;height:var(--topbar-h);margin-top:calc(-1 * var(--topbar-h));visibility:hidden;pointer-events:none}
.sec-header{display:flex;align-items:center;gap:12px;margin-bottom:20px;margin-top:40px}
.sec-header:first-of-type{margin-top:0}
.sec-icon{font-size:18px}
.sec-title{font-size:20px;font-weight:800;color:var(--text);letter-spacing:-.3px}
.sec-count{font-size:12px;color:var(--text3);background:var(--bg4);border:1px solid var(--border2);padding:2px 10px;border-radius:20px}

/* ── OVERVIEW CARDS ── */
.overview-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:32px}
.overview-card{background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius);padding:20px}
.overview-card-title{font-size:11px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:1px;margin-bottom:14px}
.meta-grid{display:grid;grid-template-columns:auto 1fr;gap:6px 16px;font-size:12px}
.meta-key{color:var(--text3);font-weight:600;white-space:nowrap}
.meta-val{color:var(--text)}
.sev-row{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px}
.sev-card{flex:1;min-width:70px;text-align:center;padding:12px 8px;border-radius:var(--radius-sm);border:1px solid var(--border2);background:var(--bg4)}
.sev-num{font-size:24px;font-weight:800;line-height:1;margin-bottom:2px}
.sev-lbl{font-size:9px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;color:var(--text3)}
.sev-card.sev-critical .sev-num{color:var(--red)}
.sev-card.sev-high .sev-num{color:var(--orange)}
.sev-card.sev-medium .sev-num{color:var(--yellow)}
.sev-card.sev-low .sev-num{color:var(--blue)}
.sev-card.sev-info .sev-num{color:var(--gray)}
.donut-wrap{display:flex;align-items:center;gap:20px;margin-bottom:16px}
.donut-center{position:relative;flex-shrink:0}
.donut-label{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;pointer-events:none}
.donut-total{font-size:22px;font-weight:800;color:var(--text);line-height:1}
.donut-sub{font-size:9px;color:var(--text3);font-weight:600;text-transform:uppercase;letter-spacing:.5px}
.donut-legend{display:flex;flex-direction:column;gap:5px}
.legend-row{display:flex;align-items:center;gap:7px;font-size:11px;color:var(--text2)}
.legend-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.legend-val{font-weight:700;color:var(--text);margin-left:auto;min-width:16px;text-align:right}
.overview-full{grid-column:1/-1}
.mod-prog-row{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.mod-prog-icon{font-size:16px;width:24px;text-align:center;flex-shrink:0}
.mod-prog-body{flex:1}
.mod-prog-top{display:flex;align-items:center;justify-content:space-between;margin-bottom:4px}
.mod-prog-name{font-size:11px;color:var(--text);font-weight:600}
.mod-prog-stats{display:flex;gap:5px;align-items:center}
.pill{font-size:9px;font-weight:700;padding:2px 7px;border-radius:10px;letter-spacing:.3px}
.pill-vuln{background:var(--red)22;color:var(--red)}
.pill-pct{background:var(--bg4);color:var(--text3)}
.mod-prog-bar{height:4px;background:var(--bg4);border-radius:4px;overflow:hidden}
.mod-prog-fill{height:100%;border-radius:4px;transition:width .4s}

/* ── CARDS ── */
.card{background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:10px;transition:border-color .15s;overflow:hidden}
.card:hover{border-color:var(--border2)}
.card.open{border-color:var(--accent)66}
.card-header{display:flex;align-items:center;justify-content:space-between;padding:13px 16px;cursor:pointer;gap:10px;user-select:none}
.card-header-left{display:flex;align-items:center;gap:8px;min-width:0;flex:1}
.card-fnum{font-size:10px;font-weight:800;color:var(--accent);background:var(--accent)18;padding:2px 7px;border-radius:4px;flex-shrink:0;font-family:var(--mono)}
.card-icon{font-size:14px;flex-shrink:0}
.card-title{font-size:13px;font-weight:600;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.card-header-right{display:flex;align-items:center;gap:6px;flex-shrink:0}
.chip{font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;white-space:nowrap;letter-spacing:.3px}
.card-mod-label{font-size:10px;color:var(--text3);white-space:nowrap;display:none}
.card-chevron{color:var(--text3);font-size:16px;transition:transform .2s;line-height:1}
.card.open .card-chevron{transform:rotate(90deg)}
.card-body{display:none;padding:0 16px 16px;border-top:1px solid var(--border)}
.card.open .card-body{display:block}
.card-field{margin-top:14px}
.card-field-label{font-size:10px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:.8px;margin-bottom:5px}
.card-field-value{font-size:12px;color:var(--text2);line-height:1.6}
.fld-refs{color:var(--text3);font-size:11px}
.card-evidence{font-family:var(--mono);font-size:11px;color:#a5b4fc;background:var(--bg4);border:1px solid var(--border2);border-radius:var(--radius-sm);padding:12px;white-space:pre-wrap;word-break:break-all;line-height:1.6;margin-top:4px}
.card-field-notes{display:flex;flex-direction:column;gap:8px;margin-top:4px}
.note-row{display:flex;flex-direction:column;gap:2px;padding:8px 12px;background:var(--bg4);border-radius:var(--radius-sm);border-left:2px solid var(--accent)66}
.note-ts{font-size:10px;color:var(--text3);font-weight:600}
.note-txt{font-size:12px;color:var(--text2);line-height:1.55}
.cve-chip{display:inline-block;font-family:var(--mono);font-size:10px;background:#312e81;color:#a5b4fc;border:1px solid #4338ca66;padding:2px 8px;border-radius:4px;margin:2px}
.tag-chip{display:inline-block;font-size:10px;background:var(--bg4);color:var(--text2);border:1px solid var(--border2);padding:2px 8px;border-radius:4px;margin:2px}

/* ── EMPTY STATE ── */
.empty-state{text-align:center;padding:48px 24px;background:var(--bg3);border:1px solid var(--border);border-radius:var(--radius)}
.empty-icon{font-size:36px;margin-bottom:10px}
.empty-title{font-size:15px;font-weight:700;color:var(--text);margin-bottom:6px}
.empty-sub{font-size:12px;color:var(--text3)}

/* ── HIDDEN ── */
.hidden{display:none!important}

/* ── PRINT ── */
@media print{
  .sidebar,.topbar,.toolbar,.btn-print{display:none!important}
  .main{margin-left:0;padding-top:0}
  .card-body{display:block!important}
  .card-chevron{display:none}
  body{background:#fff;color:#000}
  .card{background:#fff;border:1px solid #ddd;break-inside:avoid}
  .card-evidence{background:#f5f5f5;color:#333}
  .note-row{background:#f5f5f5}
}
</style>
</head>
<body>

<!-- SIDEBAR -->
<nav class="sidebar">
  <div class="sidebar-brand">
    <div class="sidebar-brand-mark">⬡</div>
    <div><div class="sidebar-brand-name">SecWorkflow</div><div class="sidebar-brand-sub">${e(reportTypeLabel)}</div></div>
  </div>
  <div class="sidebar-scroll">
    <div class="nav-section-label">Report</div>
    ${navHTML}
    ${modNavHTML ? `<div class="nav-divider"></div><div class="nav-section-label">Modules</div>${modNavHTML}` : ''}
  </div>
</nav>

<!-- TOPBAR -->
<header class="topbar">
  <div class="topbar-title">${e(meta.projectName || 'Security Assessment')} — ${e(meta.client || '')}</div>
  <div class="topbar-meta">
    <span class="topbar-date">${now}</span>
    <span class="classif-badge">${e(meta.classification || 'CONFIDENTIAL')}</span>
    <button class="btn-print" onclick="window.print()">
      <svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor"><path d="M2.5 8a.5.5 0 1 0 0-1 .5.5 0 0 0 0 1z"/><path d="M5 1a2 2 0 0 0-2 2v2H2a2 2 0 0 0-2 2v3a2 2 0 0 0 2 2h1v1a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2v-1h1a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-1V3a2 2 0 0 0-2-2H5zM4 3a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2H4V3zm1 5a2 2 0 0 0-2 2v1H2a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1h-1v-1a2 2 0 0 0-2-2H5zm7 2v3a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1z"/></svg>
      Print / Save PDF
    </button>
  </div>
</header>

<!-- MAIN -->
<main class="main">
<div class="content">

  <!-- OVERVIEW -->
  <span id="sec-overview" class="section-anchor"></span>
  <div class="sec-header">
    <span class="sec-icon">◈</span>
    <span class="sec-title">Overview</span>
  </div>

  <div class="overview-grid">
    <div class="overview-card">
      <div class="overview-card-title">Engagement Details</div>
      <div class="meta-grid">
        <span class="meta-key">Client</span><span class="meta-val">${e(meta.client||'—')}</span>
        <span class="meta-key">Assessor(s)</span><span class="meta-val">${e(meta.assessor||'—')}</span>
        <span class="meta-key">Period</span><span class="meta-val">${e(meta.startDate||'—')} – ${e(meta.endDate||'—')}</span>
        <span class="meta-key">Version</span><span class="meta-val">${e(meta.version||'1.0')}</span>
        <span class="meta-key">Generated</span><span class="meta-val">${now}</span>
        ${meta.scope ? `<span class="meta-key">Scope</span><span class="meta-val">${e(meta.scope).replace(/\n/g,'<br>')}</span>` : ''}
      </div>
    </div>
    <div class="overview-card">
      <div class="overview-card-title">Risk Distribution</div>
      <div class="donut-wrap">
        <div class="donut-center">
          <svg width="128" height="128" viewBox="0 0 128 128">${donutSvg}</svg>
          <div class="donut-label"><div class="donut-total">${totalVuln}</div><div class="donut-sub">issues</div></div>
        </div>
        <div class="donut-legend">
          ${[['critical','#ef4444'],['high','#f97316'],['medium','#eab308'],['low','#3b82f6'],['info','#6b7280']].map(([s,c])=>
            `<div class="legend-row"><div class="legend-dot" style="background:${c}"></div>${s}<span class="legend-val">${sevCounts[s]||0}</span></div>`
          ).join('')}
        </div>
      </div>
      <div class="sev-row">
        ${[['critical','#ef4444'],['high','#f97316'],['medium','#eab308'],['low','#3b82f6'],['info','#6b7280']].map(([s,c])=>
          `<div class="sev-card sev-${s}"><div class="sev-num">${sevCounts[s]||0}</div><div class="sev-lbl">${s}</div></div>`
        ).join('')}
      </div>
    </div>
    <div class="overview-card overview-full">
      <div class="overview-card-title">Module Coverage</div>
      ${modProgressHTML}
    </div>
  </div>

  <!-- FINDINGS -->
  <span id="sec-findings" class="section-anchor"></span>
  <div class="sec-header">
    <span class="sec-icon">⚠</span>
    <span class="sec-title">Findings</span>
    <span class="sec-count">${findingItems.length}</span>
  </div>

  <div class="toolbar" id="findings-toolbar">
    <div class="search-wrap">
      <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001c.03.04.062.078.098.115l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85a1.007 1.007 0 0 0-.115-.1zM12 6.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0z"/></svg>
      <input class="search-input" id="findings-search" placeholder="Search findings…" oninput="filterCards('findings')" autocomplete="off">
    </div>
    <div class="filter-group" id="findings-sev-filters">
      <button class="filter-btn active" data-sev="all" onclick="setSevFilter('findings','all',this)">All</button>
      <button class="filter-btn" data-sev="critical" onclick="setSevFilter('findings','critical',this)">Critical</button>
      <button class="filter-btn" data-sev="high" onclick="setSevFilter('findings','high',this)">High</button>
      <button class="filter-btn" data-sev="medium" onclick="setSevFilter('findings','medium',this)">Medium</button>
      <button class="filter-btn" data-sev="low" onclick="setSevFilter('findings','low',this)">Low</button>
    </div>
    <span class="results-count" id="findings-count"></span>
  </div>
  <div id="findings-list">${findingsSection}</div>

  <!-- OBSERVATIONS -->
  <span id="sec-observations" class="section-anchor"></span>
  <div class="sec-header">
    <span class="sec-icon">◉</span>
    <span class="sec-title">Observations</span>
    <span class="sec-count">${obsItems.length}</span>
  </div>

  <div class="toolbar" id="obs-toolbar">
    <div class="search-wrap">
      <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor"><path d="M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001c.03.04.062.078.098.115l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85a1.007 1.007 0 0 0-.115-.1zM12 6.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0z"/></svg>
      <input class="search-input" id="obs-search" placeholder="Search observations…" oninput="filterCards('obs')" autocomplete="off">
    </div>
    <div class="filter-group" id="obs-status-filters">
      <button class="filter-btn active" data-status="all" onclick="setStatusFilter('obs','all',this)">All</button>
      <button class="filter-btn" data-status="in-progress" onclick="setStatusFilter('obs','in-progress',this)">In Progress</button>
      <button class="filter-btn" data-status="not-vulnerable" onclick="setStatusFilter('obs','not-vulnerable',this)">Not Vulnerable</button>
      <button class="filter-btn" data-status="cannot-verify" onclick="setStatusFilter('obs','cannot-verify',this)">Cannot Verify</button>
    </div>
    <span class="results-count" id="obs-count"></span>
  </div>
  <div id="obs-list">${obsSection}</div>

  ${customItems.length ? `
  <!-- CUSTOM CHECKS -->
  <span id="sec-custom" class="section-anchor"></span>
  <div class="sec-header">
    <span class="sec-icon">✦</span>
    <span class="sec-title">Custom Checks</span>
    <span class="sec-count">${customItems.length}</span>
  </div>
  <div id="custom-list">${customSection}</div>
  ` : ''}

</div>
</main>

<script>
// ── filter state ──────────────────────────────────────────────────────
const state = { findings: { sev: 'all', q: '' }, obs: { status: 'all', q: '' } };

function filterCards(section) {
  const listId = section === 'findings' ? 'findings-list' : 'obs-list';
  const list = document.getElementById(listId);
  if (!list) return;
  const cards = list.querySelectorAll('.card');
  const q = (document.getElementById(section + '-search')?.value || '').toLowerCase().trim();
  const sevFilter = state[section].sev || 'all';
  const statusFilter = state[section].status || 'all';
  let visible = 0;
  cards.forEach(card => {
    const searchText = card.dataset.search || '';
    const matchQ = !q || searchText.includes(q);
    const matchSev = sevFilter === 'all' || card.dataset.sev === sevFilter;
    const matchStatus = statusFilter === 'all' || card.dataset.status === statusFilter;
    const show = matchQ && matchSev && matchStatus;
    card.classList.toggle('hidden', !show);
    if (show) visible++;
  });
  const countEl = document.getElementById(section + '-count');
  if (countEl) countEl.textContent = visible === cards.length ? '' : visible + ' of ' + cards.length + ' shown';
}

function setSevFilter(section, sev, btn) {
  state[section].sev = sev;
  btn.closest('.filter-group').querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  filterCards(section);
}

function setStatusFilter(section, status, btn) {
  state[section].status = status;
  btn.closest('.filter-group').querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  filterCards(section);
}

// ── active nav on scroll ──────────────────────────────────────────────
(function() {
  const links = document.querySelectorAll('.nav-link');
  const anchors = Array.from(document.querySelectorAll('.section-anchor, .mod-anchor'));
  function onScroll() {
    const scrollY = window.scrollY + 80;
    let current = null;
    for (const a of anchors) {
      if (a.offsetTop <= scrollY) current = a.id;
    }
    links.forEach(l => {
      const href = l.getAttribute('href');
      l.classList.toggle('active', href === '#' + current);
    });
  }
  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();
})();

// ── keyboard shortcut: / to focus search ─────────────────────────────
document.addEventListener('keydown', e => {
  if (e.key === '/' && document.activeElement.tagName !== 'INPUT') {
    e.preventDefault();
    document.getElementById('findings-search')?.focus();
  }
});
</script>
</body>
</html>`;
  }

  generatePDF(options = {}) {
    const { type, meta, moduleReports } = this._buildModuleReports(options);
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
.b-not-compliant { background: #fee2e2; color: #dc2626; }
.b-not-started   { background: #f3f4f6; color: #4b5563; }
.b-not-in-scope  { background: #f3f4f6; color: #9ca3af; }
.b-cve           { background: #ede9fe; color: #6d28d9; font-family: 'Cascadia Code', Consolas, monospace; letter-spacing: .2px; }
.note-report-entry { padding: 4pt 0; border-bottom: 1px solid #f0f2f5; }
.note-report-entry:last-child { border-bottom: none; }
.note-report-ts { display: block; font-size: 7.5pt; color: #aaa; font-weight: 600; margin-bottom: 2pt; }

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
    // Risk summary counts: vulnerable built-in items + ALL custom items (user defined their severity explicitly)
    const customItems = moduleReports.flatMap(({ module, items }) =>
      items.filter(i => i._custom && !findings.some(f => f.item.id === i.id)).map(i => ({ item: i, module }))
    );
    const sevCounts = this._countBySeverity([...findings, ...customItems]);
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
    const totalRisks = findings.length + customItems.length;
    const customCount = customItems.length;
    h += `<div class="section page-break">
<h1 class="sec-title">Executive Summary</h1>
<p>This report presents the results of a penetration test conducted against <strong>${this._esc(meta.client || 'the client')}</strong>. The assessment covered <strong>${moduleReports.length} module(s)</strong> with <strong>${findings.length} confirmed vulnerability/vulnerabilities</strong>${customCount > 0 ? ` and <strong>${customCount} custom check${customCount !== 1 ? 's' : ''}</strong> defined for this engagement` : ''}.</p>
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
  ${(ist.notes||[]).length > 0 ? `<div class="fld"><div class="fld-label">Notes</div><div class="fld-value">${(ist.notes||[]).map(e=>`<div class="note-report-entry"><span class="note-report-ts">${this._esc(this._formatNoteTs(e.ts))}</span>${this._esc(e.text).replace(/\n/g,'<br>')}</div>`).join('')}</div></div>` : ''}
  ${ist.evidence ? `<div class="fld"><div class="fld-label">Evidence</div><div class="fld-value mono">${this._esc(ist.evidence)}</div></div>` : ''}
  ${(ist.cves||[]).length > 0 ? `<div class="fld"><div class="fld-label">CVEs</div><div class="fld-value">${(ist.cves||[]).map(c=>`<span class="badge b-cve">${this._esc(c)}</span>`).join(' ')}</div></div>` : ''}
</div>
</div>`;
        findingNum++;
      }
    }

    if (!anyFindings) h += `<div class="no-findings">No vulnerabilities were identified in the selected scope.</div>`;
    h += `</div>`;

    // Custom Checks — dedicated section showing every user-created check regardless of status
    const customReport = moduleReports.find(r => r.module.id === 'custom-checks');
    if (customReport && customReport.items.length > 0) {
      h += `<div class="section page-break"><h1 class="sec-title">Custom Checks</h1>
<p>The following checks were defined manually for this engagement.</p>`;

      // Group items by their groupName
      const byGroup = {};
      for (const item of customReport.items) {
        const grp = item.groupName || 'Custom Checks';
        if (!byGroup[grp]) byGroup[grp] = [];
        byGroup[grp].push(item);
      }

      for (const [groupName, groupItems] of Object.entries(byGroup)) {
        h += `<h2 class="sub-title">${this._esc(groupName)}</h2>`;
        for (const item of groupItems) {
          const ist = this.app.state.itemStates[item.id] || {};
          const sev = ist.severityOverride || item.severity || 'medium';
          const status = ist.status || 'not-started';
          const statusLabel = {
            'not-started': 'Not Started', 'in-progress': 'In Progress',
            'vulnerable': 'Vulnerable', 'not-vulnerable': 'Not Vulnerable',
            'not-in-scope': 'Not in Scope', 'cannot-verify': 'Cannot Verify',
          }[status] || status;

          h += `<div class="finding-card">
<div class="finding-header">
  <span class="finding-name">${this._esc(item.title)}</span>
  <span class="badge b-${sev}">${sev}</span>
  <span class="badge b-${status}" style="margin-left:4pt">${this._esc(statusLabel)}</span>
</div>
<div class="finding-body">`;
          if (item.description) h += `<div class="fld"><div class="fld-label">Description</div><div class="fld-value">${this._esc(item.description).replace(/\n/g,'<br>')}</div></div>`;
          if (item.tags?.length) h += `<div class="fld"><div class="fld-label">Tags</div><div class="fld-value">${item.tags.map(t=>this._esc(t)).join(', ')}</div></div>`;
          if ((ist.notes||[]).length > 0) h += `<div class="fld"><div class="fld-label">Notes</div><div class="fld-value">${ist.notes.map(e=>`<div class="note-report-entry"><span class="note-report-ts">${this._esc(this._formatNoteTs(e.ts))}</span>${this._esc(e.text).replace(/\n/g,'<br>')}</div>`).join('')}</div></div>`;
          if (ist.evidence) h += `<div class="fld"><div class="fld-label">Evidence</div><div class="fld-value mono">${this._esc(ist.evidence)}</div></div>`;
          if ((ist.cves||[]).length > 0) h += `<div class="fld"><div class="fld-label">CVEs</div><div class="fld-value">${ist.cves.map(c=>`<span class="badge b-cve">${this._esc(c)}</span>`).join(' ')}</div></div>`;
          h += `</div></div>`;
        }
      }
      h += `</div>`;
    }

    // Observations — all touched items that are not vulnerable and not custom
    const obsStatuses = new Set(['not-vulnerable', 'in-progress', 'cannot-verify', 'not-started']);
    const statusLabel = {
      'not-vulnerable': 'Not Vulnerable', 'in-progress': 'In Progress',
      'cannot-verify': 'Cannot Verify', 'not-started': 'Not Started',
    };
    const obsModules = moduleReports.filter(({ items }) =>
      items.some(i => {
        if (i._custom) return false;
        const s = (this.app.state.itemStates[i.id]||{}).status || 'not-started';
        return obsStatuses.has(s);
      })
    );
    if (obsModules.length) {
      h += `<div class="section page-break"><h1 class="sec-title">Observations</h1>`;
      for (const { module, items } of obsModules) {
        const obs = items.filter(i => {
          if (i._custom) return false;
          const s = (this.app.state.itemStates[i.id]||{}).status || 'not-started';
          return obsStatuses.has(s);
        });
        if (!obs.length) continue;
        h += `<div class="mod-header"><span class="mod-icon">${module.icon}</span><span class="mod-name">${this._esc(module.name)}</span></div>`;
        for (const item of obs) {
          const ist = this.app.state.itemStates[item.id]||{};
          const s = ist.status || 'not-started';
          const lbl = statusLabel[s] || s;
          const sev = ist.severityOverride || item.severity || 'info';
          h += `<div class="finding-card">
<div class="finding-header">
  <span class="finding-name">${this._esc(item.title)}</span>
  <span class="badge b-${s}">${lbl}</span>
  ${item.severity ? `<span class="badge b-${sev}" style="margin-left:4pt">${sev}</span>` : ''}
</div>
<div class="finding-body">
  ${item.description ? `<div class="fld"><div class="fld-label">Description</div><div class="fld-value">${this._esc(item.description)}</div></div>` : ''}
  ${item.tags?.length ? `<div class="fld"><div class="fld-label">Tags</div><div class="fld-value">${item.tags.map(t=>this._esc(t)).join(', ')}</div></div>` : ''}
  ${(ist.notes||[]).length > 0 ? `<div class="fld"><div class="fld-label">Notes</div><div class="fld-value">${(ist.notes||[]).map(e=>`<div class="note-report-entry"><span class="note-report-ts">${this._esc(this._formatNoteTs(e.ts))}</span>${this._esc(e.text).replace(/\n/g,'<br>')}</div>`).join('')}</div></div>` : ''}
  ${ist.evidence ? `<div class="fld"><div class="fld-label">Evidence</div><div class="fld-value mono">${this._esc(ist.evidence)}</div></div>` : ''}
  ${(ist.cves||[]).length > 0 ? `<div class="fld"><div class="fld-label">CVEs</div><div class="fld-value">${(ist.cves||[]).map(c=>`<span class="badge b-cve">${this._esc(c)}</span>`).join(' ')}</div></div>` : ''}
</div>
</div>`;
        }
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
  ${(ist.notes||[]).length>0 ? `<div class="fld"><div class="fld-label">Assessment Notes</div><div class="fld-value">${(ist.notes||[]).map(e=>`<div class="note-report-entry"><span class="note-report-ts">${this._esc(this._formatNoteTs(e.ts))}</span>${this._esc(e.text).replace(/\n/g,'<br>')}</div>`).join('')}</div></div>` : ''}
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
          h += `<div class="obs-item"><div class="obs-main"><div class="obs-title">${this._esc(item.title)}</div>${(ist.notes||[]).length>0?`<div class="obs-note">${this._esc(ist.notes[ist.notes.length-1].text)}</div>`:''}</div><span class="badge b-${s}">${lbl}</span></div>`;
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

  _formatNoteTs(isoStr) {
    if (!isoStr) return '';
    try {
      const d = new Date(isoStr);
      const date = d.toLocaleDateString([], { day: '2-digit', month: '2-digit', year: 'numeric' });
      const time = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      return `${date} ${time}`;
    } catch (_) { return ''; }
  }

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
