// ── SecWorkflow Application ───────────────────────────────────────────────────

const STORAGE_KEY = 'secworkflow_v1';
const STATUS_LABELS = Object.fromEntries(STATUSES.map(s => [s.value, s.label]));
const STATUS_COLORS = Object.fromEntries(STATUSES.map(s => [s.value, s.color]));

class SecWorkflowApp {
  constructor() {
    this.state = {
      currentModuleId: null,
      currentType: 'pentest',
      metadata: {
        projectName: 'Untitled Project',
        client: 'Client',
        assessor: '',
        classification: 'CONFIDENTIAL',
        startDate: '',
        endDate: '',
        scope: '',
        exclusions: '',
        version: '1.0',
      },
      itemStates: {},
      filters: { status: 'all', severity: 'all', tag: 'all', search: '', findingsOnly: false },
      filterBarOpen: false,
    };
    this.panelItemId = null;
    this.reportGen = new ReportGenerator(this);
    this._loadFromStorage();
    this._init();
  }

  // ── Initialisation ─────────────────────────────────────────────────────────

  _init() {
    this._renderSidebar();
    this._populateTagFilter();
    this._bindStaticEvents();
    this._syncMetaToUI();

    if (this.state.currentModuleId) {
      this._loadModule(this.state.currentModuleId);
    }
  }

  _bindStaticEvents() {
    // Sidebar type tabs
    document.querySelectorAll('.sidebar-tab').forEach(btn => {
      btn.addEventListener('click', () => {
        this.state.currentType = btn.dataset.type;
        document.querySelectorAll('.sidebar-tab').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        this._renderSidebar();
        this._saveToStorage();
      });
    });

    // Top bar buttons
    document.getElementById('btn-filter-toggle').addEventListener('click', () => this._toggleFilterBar());
    document.getElementById('btn-import').addEventListener('click', () => document.getElementById('import-file-input').click());
    document.getElementById('import-file-input').addEventListener('change', e => this._importJSON(e));
    document.getElementById('btn-export-json').addEventListener('click', () => this._exportJSON());
    document.getElementById('btn-export-md').addEventListener('click', () => this._exportMarkdown());
    document.getElementById('btn-report').addEventListener('click', () => this._openReportModal());
    document.getElementById('btn-project-meta').addEventListener('click', () => this._openMetaModal());

    // Data dropdown toggle
    const dataMenuWrap = document.getElementById('data-menu-wrap');
    document.getElementById('btn-data-menu').addEventListener('click', (e) => {
      e.stopPropagation();
      dataMenuWrap.classList.toggle('open');
    });
    document.addEventListener('click', () => dataMenuWrap.classList.remove('open'));

    // Classification picker
    document.getElementById('classification-picker').addEventListener('click', (e) => {
      const btn = e.target.closest('.classif-btn');
      if (!btn) return;
      document.querySelectorAll('.classif-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('meta-classification').value = btn.dataset.value;
    });

    // Report type card active state
    document.getElementById('report-type-cards').addEventListener('change', (e) => {
      if (e.target.name === 'report-type') {
        document.querySelectorAll('.report-type-card').forEach(c => c.classList.remove('active'));
        e.target.closest('.report-type-card').classList.add('active');
      }
    });

    // Filters
    document.getElementById('filter-status').addEventListener('change', e => { this.state.filters.status = e.target.value; this._applyFilters(); });
    document.getElementById('filter-severity').addEventListener('change', e => { this.state.filters.severity = e.target.value; this._applyFilters(); });
    document.getElementById('filter-tag').addEventListener('change', e => { this.state.filters.tag = e.target.value; this._applyFilters(); });
    document.getElementById('filter-search').addEventListener('input', e => { this.state.filters.search = e.target.value; this._applyFilters(); });
    document.getElementById('filter-findings-only').addEventListener('change', e => { this.state.filters.findingsOnly = e.target.checked; this._applyFilters(); });
    document.getElementById('btn-filter-clear').addEventListener('click', () => this._clearFilters());

    // Modals
    document.querySelectorAll('.modal-close, [data-modal]').forEach(el => {
      el.addEventListener('click', () => {
        const modalId = el.dataset.modal || el.closest('.modal')?.id;
        if (modalId) document.getElementById(modalId).style.display = 'none';
      });
    });
    document.querySelectorAll('.modal-overlay').forEach(overlay => {
      overlay.addEventListener('click', e => {
        if (e.target === overlay) overlay.style.display = 'none';
      });
    });

    // Meta modal
    document.getElementById('btn-save-meta').addEventListener('click', () => this._saveMetaModal());

    // Project name / client inline edit
    document.getElementById('project-name-display').addEventListener('blur', e => {
      this.state.metadata.projectName = e.target.textContent.trim() || 'Untitled Project';
      this._saveToStorage();
    });
    document.getElementById('project-client-display').addEventListener('blur', e => {
      this.state.metadata.client = e.target.textContent.trim() || 'Client';
      this._saveToStorage();
    });

    // Panel
    document.getElementById('panel-close').addEventListener('click', () => this._closePanel());
    document.getElementById('panel-close-btn').addEventListener('click', () => this._closePanel());
    document.getElementById('panel-save-btn').addEventListener('click', () => this._savePanelItem());
    document.getElementById('panel-overlay').addEventListener('click', () => this._closePanel());

    // Report modal
    document.getElementById('btn-generate-report').addEventListener('click', () => this._generateReport());
  }

  // ── Storage ────────────────────────────────────────────────────────────────

  _saveToStorage() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify({
        metadata: this.state.metadata,
        itemStates: this.state.itemStates,
        currentModuleId: this.state.currentModuleId,
        currentType: this.state.currentType,
      }));
    } catch (_) { /* storage full */ }
  }

  _loadFromStorage() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return;
      const saved = JSON.parse(raw);
      if (saved.metadata) this.state.metadata = { ...this.state.metadata, ...saved.metadata };
      if (saved.itemStates) this.state.itemStates = saved.itemStates;
      if (saved.currentModuleId) this.state.currentModuleId = saved.currentModuleId;
      if (saved.currentType) this.state.currentType = saved.currentType;
    } catch (_) { /* ignore */ }
  }

  // ── Sidebar ────────────────────────────────────────────────────────────────

  _renderSidebar() {
    const nav = document.getElementById('sidebar-nav');
    const modules = MODULES_BY_TYPE[this.state.currentType] || [];

    // Sync tab active state
    document.querySelectorAll('.sidebar-tab').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.type === this.state.currentType);
    });

    nav.innerHTML = '';
    for (const mod of modules) {
      const progress = this.getModuleProgress(mod);
      const item = document.createElement('div');
      item.className = `nav-item${mod.id === this.state.currentModuleId ? ' active' : ''}`;
      item.dataset.moduleId = mod.id;

      let badge = '';
      if (progress.vulnerable > 0) {
        badge = `<span class="nav-item-badge">${progress.vulnerable} vuln</span>`;
      } else if (progress.inProgress > 0) {
        badge = `<span class="nav-item-badge badge-warn">${progress.inProgress}</span>`;
      } else if (progress.total > 0 && progress.compliant === progress.total) {
        badge = `<span class="nav-item-badge badge-ok">✓</span>`;
      }

      item.innerHTML = `
        <span class="nav-item-icon">${mod.icon}</span>
        <span class="nav-item-label">${mod.name}</span>
        ${badge}
      `;
      item.addEventListener('click', () => this._loadModule(mod.id));
      nav.appendChild(item);
    }
  }

  // ── Module Loading ─────────────────────────────────────────────────────────

  _loadModule(moduleId) {
    const module = MODULE_MAP[moduleId];
    if (!module) return;

    this.state.currentModuleId = moduleId;
    this._saveToStorage();

    // Update breadcrumb
    document.getElementById('breadcrumb-text').textContent = `${module.icon} ${module.name}`;

    // Show/hide screens
    document.getElementById('welcome-screen').style.display = 'none';
    document.getElementById('checklist-container').style.display = 'block';

    // Update sidebar active state
    document.querySelectorAll('.nav-item').forEach(el => {
      el.classList.toggle('active', el.dataset.moduleId === moduleId);
    });

    this._renderModule(module);
    this._updateProgress(module);
  }

  _renderModule(module) {
    const header = document.getElementById('module-header');
    const groups = document.getElementById('checklist-groups');

    // Header
    const progress = this.getModuleProgress(module);
    header.innerHTML = `
      <div class="module-header-top">
        <div class="module-header-icon">${module.icon}</div>
        <div class="module-header-info">
          <h2>${module.name}</h2>
          <p>${module.description}</p>
        </div>
      </div>
      <div class="module-header-stats">
        <div class="stat-pill"><span class="stat-pill-dot" style="background:${STATUS_COLORS['vulnerable']}"></span>${progress.vulnerable} Vulnerable</div>
        <div class="stat-pill"><span class="stat-pill-dot" style="background:${STATUS_COLORS['in-progress']}"></span>${progress.inProgress} In Progress</div>
        <div class="stat-pill"><span class="stat-pill-dot" style="background:${STATUS_COLORS['not-vulnerable']}"></span>${progress.compliant} Compliant</div>
        <div class="stat-pill"><span class="stat-pill-dot" style="background:${STATUS_COLORS['not-started']}"></span>${progress.notStarted} Not Started</div>
        <div class="stat-pill"><span class="stat-pill-dot" style="background:${STATUS_COLORS['cannot-verify']}"></span>${progress.cannotVerify} Cannot Verify</div>
      </div>
    `;

    // Groups
    groups.innerHTML = '';
    for (const group of module.groups) {
      groups.appendChild(this._renderGroup(group));
    }

    this._applyFilters();
  }

  _renderGroup(group) {
    const container = document.createElement('div');
    container.className = 'checklist-group';
    container.dataset.groupId = group.id;

    const completedCount = group.items.filter(i => {
      const s = (this.state.itemStates[i.id] || {}).status || 'not-started';
      return s !== 'not-started';
    }).length;
    const pct = group.items.length > 0 ? (completedCount / group.items.length) * 100 : 0;

    const header = document.createElement('div');
    header.className = 'group-header';
    header.innerHTML = `
      <span class="group-header-title">${group.name}</span>
      <span class="group-header-count">${completedCount}/${group.items.length}</span>
      <span class="group-chevron">▾</span>
    `;

    const progressBar = document.createElement('div');
    progressBar.className = 'group-progress';
    progressBar.innerHTML = `<div class="group-progress-fill" style="width:${pct}%"></div>`;

    const itemsContainer = document.createElement('div');
    itemsContainer.className = 'group-items';
    itemsContainer.dataset.groupId = group.id;

    for (const item of group.items) {
      itemsContainer.appendChild(this._renderItem(item));
    }

    header.addEventListener('click', () => {
      header.classList.toggle('collapsed');
      itemsContainer.classList.toggle('collapsed');
    });

    container.appendChild(header);
    container.appendChild(progressBar);
    container.appendChild(itemsContainer);
    return container;
  }

  _renderItem(item) {
    const ist = this.state.itemStates[item.id] || {};
    const status = ist.status || 'not-started';
    const sev = ist.severityOverride || item.severity;

    const el = document.createElement('div');
    el.className = `checklist-item${ist.isFinding ? ' is-finding' : ''}`;
    el.dataset.itemId = item.id;
    el.dataset.status = status;
    el.dataset.severity = sev || '';
    el.dataset.tags = (item.tags || []).join(',');
    el.dataset.isFinding = ist.isFinding ? '1' : '0';

    const statusSelect = this._buildStatusSelect(item.id, status);
    const sevBadge = sev ? `<span class="sev-badge sev-${sev}">${sev.toUpperCase()}</span>` : '';
    const tagBadges = (item.tags || []).slice(0, 4).map(t => `<span class="badge badge-tag">${t}</span>`).join('');
    const findingBadge = ist.isFinding ? `<span class="badge badge-finding">Finding</span>` : '';
    const notePreview = ist.note ? `<div class="item-note-preview">📝 ${ist.note}</div>` : '';

    el.innerHTML = `
      <div class="item-status-col">
        <div class="status-dot status-${status}"></div>
      </div>
      <div class="item-body">
        <div class="item-title-row">
          <span class="item-title">${item.title}</span>
          ${sevBadge}${findingBadge}
        </div>
        <div class="item-tags">${tagBadges}</div>
        <div class="item-desc">${item.description.slice(0, 120)}${item.description.length > 120 ? '…' : ''}</div>
        ${notePreview}
      </div>
      <div class="item-actions" onclick="event.stopPropagation()">
        ${statusSelect}
      </div>
    `;

    // Open panel on row click
    el.addEventListener('click', (e) => {
      if (e.target.closest('.item-actions')) return;
      this._openPanel(item);
    });

    return el;
  }

  _buildStatusSelect(itemId, currentStatus) {
    // Returns an HTML string. Changes handled via event delegation on #checklist-groups.
    const options = STATUSES.map(s =>
      `<option value="${s.value}"${s.value === currentStatus ? ' selected' : ''}>${s.label}</option>`
    ).join('');
    return `<select class="item-status-select ss-${currentStatus}" data-item-id="${itemId}">${options}</select>`;
  }

  // ── Item State ────────────────────────────────────────────────────────────

  _updateItemState(itemId, field, value) {
    if (!this.state.itemStates[itemId]) {
      this.state.itemStates[itemId] = { status: 'not-started', note: '', evidence: '', remediation: '', severityOverride: null, isFinding: false };
    }
    this.state.itemStates[itemId][field] = value;
    this.state.itemStates[itemId].updatedAt = new Date().toISOString();
    this._saveToStorage();
  }

  // ── Panel ─────────────────────────────────────────────────────────────────

  _openPanel(item) {
    this.panelItemId = item.id;
    const ist = this.state.itemStates[item.id] || {};

    document.getElementById('panel-title').textContent = item.title;
    document.getElementById('panel-description').textContent = item.description;

    // Status
    const statusSel = document.getElementById('panel-status');
    statusSel.innerHTML = STATUSES.map(s =>
      `<option value="${s.value}"${(ist.status || 'not-started') === s.value ? ' selected' : ''}>${s.label}</option>`
    ).join('');
    statusSel.className = `status-select panel-status ss-${ist.status || 'not-started'}`;
    statusSel.addEventListener('change', (e) => {
      statusSel.className = `status-select panel-status ss-${e.target.value}`;
    });

    // Severity override
    const sevSel = document.getElementById('panel-severity');
    sevSel.value = ist.severityOverride || '';

    // Text fields
    document.getElementById('panel-notes').value = ist.note || '';
    document.getElementById('panel-evidence').value = ist.evidence || '';
    document.getElementById('panel-remediation').value = ist.remediation || '';
    document.getElementById('panel-default-remediation').textContent = item.remediation || 'No default remediation specified.';

    // Finding checkbox
    document.getElementById('panel-is-finding').checked = ist.isFinding || false;

    // Tags
    const tagsEl = document.getElementById('panel-tags');
    tagsEl.innerHTML = (item.tags || []).map(t => `<span class="badge badge-tag">${t}</span>`).join('') || '<span class="text-muted text-small">None</span>';

    // Frameworks
    const fwEl = document.getElementById('panel-frameworks');
    fwEl.innerHTML = (item.frameworks || []).map(f => `<span class="badge badge-framework">${f}</span>`).join('') || '<span class="text-muted text-small">None</span>';

    // Show panel
    document.getElementById('panel-overlay').style.display = 'block';
    document.getElementById('item-panel').style.display = 'flex';
  }

  _closePanel() {
    document.getElementById('panel-overlay').style.display = 'none';
    document.getElementById('item-panel').style.display = 'none';
    this.panelItemId = null;
  }

  _savePanelItem() {
    if (!this.panelItemId) return;
    const id = this.panelItemId;

    const status = document.getElementById('panel-status').value;
    const severityOverride = document.getElementById('panel-severity').value || null;
    const note = document.getElementById('panel-notes').value.trim();
    const evidence = document.getElementById('panel-evidence').value.trim();
    const remediation = document.getElementById('panel-remediation').value.trim();
    const isFinding = document.getElementById('panel-is-finding').checked;

    this._updateItemState(id, 'status', status);
    this._updateItemState(id, 'severityOverride', severityOverride);
    this._updateItemState(id, 'note', note);
    this._updateItemState(id, 'evidence', evidence);
    this._updateItemState(id, 'remediation', remediation);
    this._updateItemState(id, 'isFinding', isFinding);

    // Update the row in the DOM
    const row = document.querySelector(`.checklist-item[data-item-id="${id}"]`);
    if (row) {
      row.dataset.status = status;
      row.dataset.isFinding = isFinding ? '1' : '0';
      row.classList.toggle('is-finding', isFinding);

      const dot = row.querySelector('.status-dot');
      if (dot) dot.className = `status-dot status-${status}`;

      const sel = row.querySelector('.item-status-select');
      if (sel) {
        sel.value = status;
        sel.className = `item-status-select ss-${status}`;
      }

      const notePreview = row.querySelector('.item-note-preview');
      if (note) {
        if (notePreview) notePreview.textContent = `📝 ${note}`;
        else {
          const nb = document.createElement('div');
          nb.className = 'item-note-preview';
          nb.textContent = `📝 ${note}`;
          row.querySelector('.item-body').appendChild(nb);
        }
      } else if (notePreview) notePreview.remove();
    }

    this._updateProgress(MODULE_MAP[this.state.currentModuleId]);
    this._renderSidebar();
    this._closePanel();
    this._showToast('Item saved', 'success');
  }

  // ── Progress ──────────────────────────────────────────────────────────────

  getModuleProgress(module) {
    const counts = { total: 0, notStarted: 0, inProgress: 0, compliant: 0, vulnerable: 0, notInScope: 0, cannotVerify: 0 };
    for (const group of module.groups) {
      for (const item of group.items) {
        counts.total++;
        const status = (this.state.itemStates[item.id] || {}).status || 'not-started';
        if (status === 'not-started') counts.notStarted++;
        else if (status === 'in-progress') counts.inProgress++;
        else if (status === 'not-vulnerable') counts.compliant++;
        else if (status === 'vulnerable') counts.vulnerable++;
        else if (status === 'not-in-scope') counts.notInScope++;
        else if (status === 'cannot-verify') counts.cannotVerify++;
      }
    }
    return counts;
  }

  _updateProgress(module) {
    if (!module) return;
    const progress = this.getModuleProgress(module);
    const progressEl = document.getElementById('sidebar-progress');
    const fill = document.getElementById('progress-bar-fill');
    const fraction = document.getElementById('progress-fraction');
    const stats = document.getElementById('progress-stats');

    progressEl.style.display = 'block';
    const assessed = progress.total - progress.notStarted;
    const pct = progress.total > 0 ? (assessed / progress.total) * 100 : 0;
    fill.style.width = `${pct}%`;
    fraction.textContent = `${assessed}/${progress.total}`;

    stats.innerHTML = [
      { label: 'Vuln', count: progress.vulnerable, color: STATUS_COLORS['vulnerable'] },
      { label: 'OK', count: progress.compliant, color: STATUS_COLORS['not-vulnerable'] },
      { label: 'WIP', count: progress.inProgress, color: STATUS_COLORS['in-progress'] },
      { label: '?', count: progress.cannotVerify, color: STATUS_COLORS['cannot-verify'] },
    ].filter(s => s.count > 0).map(s =>
      `<div class="progress-stat"><div class="progress-stat-dot" style="background:${s.color}"></div>${s.count} ${s.label}</div>`
    ).join('');

    // Update module header stats
    const headerStats = document.querySelector('.module-header-stats');
    if (headerStats) {
      const pills = headerStats.querySelectorAll('.stat-pill');
      const values = [progress.vulnerable, progress.inProgress, progress.compliant, progress.notStarted, progress.cannotVerify];
      pills.forEach((pill, i) => {
        const text = pill.textContent.trim().split(' ');
        if (values[i] !== undefined) {
          pill.childNodes[pill.childNodes.length - 1].textContent = ` ${text[text.length - 1]}`;
          pill.innerHTML = `<span class="stat-pill-dot" style="background:${pill.querySelector('.stat-pill-dot').style.background}"></span>${values[i]} ${text[text.length - 1]}`;
        }
      });
    }
  }

  // ── Filters ───────────────────────────────────────────────────────────────

  _populateTagFilter() {
    const sel = document.getElementById('filter-tag');
    const tags = getAllTags();
    tags.forEach(tag => {
      const opt = document.createElement('option');
      opt.value = tag;
      opt.textContent = tag;
      sel.appendChild(opt);
    });
  }

  _applyFilters() {
    const { status, severity, tag, search, findingsOnly } = this.state.filters;
    const rows = document.querySelectorAll('.checklist-item');
    const searchLower = search.toLowerCase();

    let visible = 0;
    const total = rows.length;

    rows.forEach(row => {
      let show = true;
      const rowStatus = row.dataset.status;
      const rowSeverity = row.dataset.severity;
      const rowTags = row.dataset.tags || '';
      const rowFinding = row.dataset.isFinding === '1';
      const rowTitle = row.querySelector('.item-title')?.textContent?.toLowerCase() || '';
      const rowDesc = row.querySelector('.item-desc')?.textContent?.toLowerCase() || '';

      if (status !== 'all' && rowStatus !== status) show = false;
      if (severity !== 'all' && rowSeverity !== severity) show = false;
      if (tag !== 'all' && !rowTags.split(',').includes(tag)) show = false;
      if (searchLower && !rowTitle.includes(searchLower) && !rowDesc.includes(searchLower)) show = false;
      if (findingsOnly && !rowFinding) show = false;

      row.classList.toggle('filtered-out', !show);
      if (show) visible++;
    });

    // Hide groups with no visible items
    document.querySelectorAll('.checklist-group').forEach(group => {
      const hasVisible = group.querySelectorAll('.checklist-item:not(.filtered-out)').length > 0;
      group.style.display = hasVisible ? '' : 'none';
    });

    // Update result count
    const countEl = document.getElementById('filter-count');
    if (countEl && total > 0) {
      countEl.textContent = visible === total ? `${total} items` : `${visible} / ${total} items`;
    }

    // Empty state
    const groups = document.getElementById('checklist-groups');
    if (groups) {
      let emptyEl = document.getElementById('filter-empty-msg');
      if (visible === 0 && total > 0) {
        if (!emptyEl) {
          emptyEl = document.createElement('div');
          emptyEl.id = 'filter-empty-msg';
          emptyEl.className = 'filter-empty-state';
          emptyEl.innerHTML = '<p><strong>No items match the current filters.</strong></p><p>Try adjusting or clearing the filters above.</p>';
          groups.parentNode.insertBefore(emptyEl, groups.nextSibling);
        }
        emptyEl.style.display = '';
      } else if (emptyEl) {
        emptyEl.style.display = 'none';
      }
    }

    this._updateFilterBadge();
  }

  _updateFilterBadge() {
    const { status, severity, tag, search, findingsOnly } = this.state.filters;
    let count = 0;
    if (status !== 'all') count++;
    if (severity !== 'all') count++;
    if (tag !== 'all') count++;
    if (search) count++;
    if (findingsOnly) count++;

    const badge = document.getElementById('filter-active-badge');
    if (badge) {
      badge.textContent = count;
      badge.style.display = count > 0 ? 'inline-flex' : 'none';
    }

    // Visual active state on inputs
    const statusSel = document.getElementById('filter-status');
    if (statusSel) statusSel.classList.toggle('filter-active', status !== 'all');
    const sevSel = document.getElementById('filter-severity');
    if (sevSel) sevSel.classList.toggle('filter-active', severity !== 'all');
    const tagSel = document.getElementById('filter-tag');
    if (tagSel) tagSel.classList.toggle('filter-active', tag !== 'all');
    const searchIn = document.getElementById('filter-search');
    if (searchIn) searchIn.classList.toggle('filter-active', !!search);
    const findingsChk = document.getElementById('filter-findings-only');
    if (findingsChk) findingsChk.parentElement?.classList.toggle('filter-active-label', findingsOnly);

    // Clear button visibility
    const clearBtn = document.getElementById('btn-filter-clear');
    if (clearBtn) clearBtn.style.visibility = count > 0 ? 'visible' : 'hidden';
  }

  _clearFilters() {
    this.state.filters = { status: 'all', severity: 'all', tag: 'all', search: '', findingsOnly: false };
    document.getElementById('filter-status').value = 'all';
    document.getElementById('filter-severity').value = 'all';
    document.getElementById('filter-tag').value = 'all';
    document.getElementById('filter-search').value = '';
    document.getElementById('filter-findings-only').checked = false;
    this._applyFilters();
  }

  _toggleFilterBar() {
    this.state.filterBarOpen = !this.state.filterBarOpen;
    document.getElementById('filter-bar').classList.toggle('open', this.state.filterBarOpen);
    document.querySelector('.layout').classList.toggle('filter-open', this.state.filterBarOpen);
    document.getElementById('btn-filter-toggle').classList.toggle('active', this.state.filterBarOpen);
  }

  // ── Metadata modal ────────────────────────────────────────────────────────

  _openMetaModal() {
    const m = this.state.metadata;
    document.getElementById('meta-project-name').value = m.projectName || '';
    document.getElementById('meta-client').value = m.client || '';
    document.getElementById('meta-assessor').value = m.assessor || '';
    document.getElementById('meta-version').value = m.version || '1.0';
    document.getElementById('meta-start-date').value = m.startDate || '';
    document.getElementById('meta-end-date').value = m.endDate || '';
    document.getElementById('meta-scope').value = m.scope || '';
    document.getElementById('meta-exclusions').value = m.exclusions || '';

    // Sync classification picker buttons
    const classifVal = m.classification || 'CONFIDENTIAL';
    document.getElementById('meta-classification').value = classifVal;
    document.querySelectorAll('.classif-btn').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.value === classifVal);
    });

    document.getElementById('modal-project').style.display = 'flex';
  }

  _saveMetaModal() {
    this.state.metadata = {
      projectName: document.getElementById('meta-project-name').value.trim() || 'Untitled Project',
      client: document.getElementById('meta-client').value.trim() || 'Client',
      assessor: document.getElementById('meta-assessor').value.trim(),
      classification: document.getElementById('meta-classification').value,
      version: document.getElementById('meta-version').value.trim() || '1.0',
      startDate: document.getElementById('meta-start-date').value,
      endDate: document.getElementById('meta-end-date').value,
      scope: document.getElementById('meta-scope').value.trim(),
      exclusions: document.getElementById('meta-exclusions').value.trim(),
    };
    this._syncMetaToUI();
    this._saveToStorage();
    document.getElementById('modal-project').style.display = 'none';
    this._showToast('Project metadata saved', 'success');
  }

  _syncMetaToUI() {
    document.getElementById('project-name-display').textContent = this.state.metadata.projectName;
    document.getElementById('project-client-display').textContent = this.state.metadata.client;
  }

  // ── Report modal ──────────────────────────────────────────────────────────

  _openReportModal() {
    const container = document.getElementById('report-module-checkboxes');
    container.innerHTML = '';
    for (const mod of ALL_MODULES) {
      const label = document.createElement('label');
      label.className = 'cb-label';
      label.innerHTML = `<input type="checkbox" class="report-module-cb" value="${mod.id}" checked /> ${mod.icon} ${mod.name}`;
      container.appendChild(label);
    }
    // Reset type cards to first option
    document.querySelectorAll('.report-type-card').forEach((c, i) => c.classList.toggle('active', i === 0));
    const firstRadio = document.querySelector('[name="report-type"]');
    if (firstRadio) firstRadio.checked = true;

    document.getElementById('modal-report').style.display = 'flex';
  }

  _generateReport() {
    const typeEl = document.querySelector('[name="report-type"]:checked');
    const type = typeEl ? typeEl.value : 'pentest';
    const includedModuleIds = [...document.querySelectorAll('.report-module-cb:checked')].map(el => el.value);
    const includeStatuses = [...document.querySelectorAll('.report-status-filter:checked')].map(el => el.value);
    const findingsOnly = document.getElementById('report-findings-only').checked;

    if (includedModuleIds.length === 0) {
      this._showToast('Select at least one module', 'info');
      return;
    }

    document.getElementById('modal-report').style.display = 'none';
    this.reportGen.generatePDF({ type, includedModuleIds, includeStatuses, findingsOnly });
    this._showToast('Opening PDF report…', 'success');
  }

  // ── Import / Export ────────────────────────────────────────────────────────

  _exportJSON() {
    const data = {
      version: 1,
      exportedAt: new Date().toISOString(),
      metadata: this.state.metadata,
      itemStates: this.state.itemStates,
    };
    const name = (this.state.metadata.projectName || 'secworkflow').replace(/\s+/g, '_').toLowerCase();
    this._downloadFile(`${name}_${new Date().toISOString().slice(0,10)}.json`, JSON.stringify(data, null, 2), 'application/json');
    this._showToast('Exported JSON', 'success');
  }

  _importJSON(event) {
    const file = event.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const data = JSON.parse(e.target.result);
        if (data.metadata) this.state.metadata = { ...this.state.metadata, ...data.metadata };
        if (data.itemStates) this.state.itemStates = { ...this.state.itemStates, ...data.itemStates };
        this._syncMetaToUI();
        this._saveToStorage();
        if (this.state.currentModuleId) this._loadModule(this.state.currentModuleId);
        this._renderSidebar();
        this._showToast('Data imported successfully', 'success');
      } catch (_) {
        this._showToast('Invalid JSON file', 'error');
      }
    };
    reader.readAsText(file);
    event.target.value = '';
  }

  _exportMarkdown() {
    if (!this.state.currentModuleId) { this._showToast('Load a module first', 'info'); return; }
    const module = MODULE_MAP[this.state.currentModuleId];
    const progress = this.getModuleProgress(module);
    let md = `# ${module.icon} ${module.name} — Checklist Export\n\n`;
    md += `**Project:** ${this.state.metadata.projectName}  \n`;
    md += `**Client:** ${this.state.metadata.client}  \n`;
    md += `**Date:** ${new Date().toISOString().slice(0, 10)}\n\n`;
    md += `**Progress:** ${progress.total - progress.notStarted}/${progress.total} assessed, ${progress.vulnerable} vulnerable\n\n`;

    for (const group of module.groups) {
      md += `## ${group.name}\n\n`;
      for (const item of group.items) {
        const ist = this.state.itemStates[item.id] || {};
        const status = ist.status || 'not-started';
        const statusLabel = STATUS_LABELS[status] || status;
        const sev = ist.severityOverride || item.severity;

        md += `### ${item.title}\n\n`;
        md += `**Status:** ${statusLabel}`;
        if (sev) md += ` | **Severity:** ${sev.toUpperCase()}`;
        if (ist.isFinding) md += ` | 🔍 **Finding**`;
        md += `\n\n`;
        md += `${item.description}\n\n`;
        if (ist.note) md += `**Notes:** ${ist.note}\n\n`;
        if (ist.evidence) md += `**Evidence:**\n\`\`\`\n${ist.evidence}\n\`\`\`\n\n`;
        const rem = ist.remediation || item.remediation;
        if (rem) md += `**Remediation:** ${rem}\n\n`;
        if (item.tags?.length) md += `**Tags:** ${item.tags.join(', ')}\n\n`;
        if (item.frameworks?.length) md += `**Frameworks:** ${item.frameworks.join(', ')}\n\n`;
        md += `---\n\n`;
      }
    }

    const name = `${module.name.replace(/\s+/g,'_').toLowerCase()}_checklist`;
    this._downloadFile(`${name}.md`, md, 'text/markdown');
    this._showToast('Exported Markdown', 'success');
  }

  // ── Utilities ─────────────────────────────────────────────────────────────

  _downloadFile(filename, content, type) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
  }

  _showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => { toast.style.opacity = '0'; toast.style.transition = 'opacity .3s'; }, 2500);
    setTimeout(() => toast.remove(), 2900);
  }
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  window.app = new SecWorkflowApp();

  // Delegated change handler for inline status selects
  document.getElementById('checklist-groups').addEventListener('change', (e) => {
    if (!e.target.matches('.item-status-select')) return;
    const itemId = e.target.dataset.itemId;
    const row = e.target.closest('.checklist-item');
    const newStatus = e.target.value;
    if (!itemId) return;
    window.app._updateItemState(itemId, 'status', newStatus);
    e.target.className = `item-status-select ss-${newStatus}`;
    if (row) {
      row.dataset.status = newStatus;
      const dot = row.querySelector('.status-dot');
      if (dot) dot.className = `status-dot status-${newStatus}`;
    }
    window.app._updateProgress(MODULE_MAP[window.app.state.currentModuleId]);
    window.app._renderSidebar();
  });
});
