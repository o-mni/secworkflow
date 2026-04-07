// ── SecWorkflow Application ───────────────────────────────────────────────────

// ── Security utilities ────────────────────────────────────────────────────────

/** HTML-escape a value before inserting into innerHTML. */
function escHTML(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

const VALID_STATUSES = new Set([
  // Pentest statuses
  'not-started','in-progress','not-vulnerable','vulnerable','not-in-scope','cannot-verify',
  // Consultant statuses
  'not-assessed','compliant','partially-compliant','not-compliant','not-applicable',
]);
const VALID_SEVERITIES = new Set(['critical','high','medium','low','info']);

/** Sanitise and validate a single item-state record from untrusted input (e.g. imported JSON). */
function sanitiseItemState(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  return {
    status:           VALID_STATUSES.has(raw.status)   ? raw.status           : 'not-started',
    severityOverride: VALID_SEVERITIES.has(raw.severityOverride) ? raw.severityOverride : null,
    note:             typeof raw.note        === 'string' ? raw.note.slice(0, 20000)        : '',
    evidence:         typeof raw.evidence    === 'string' ? raw.evidence.slice(0, 100000)   : '',
    remediation:      typeof raw.remediation === 'string' ? raw.remediation.slice(0, 20000) : '',
    isFinding:        Boolean(raw.isFinding),
    outOfScope:       Boolean(raw.outOfScope),
    updatedAt:        typeof raw.updatedAt   === 'string' ? raw.updatedAt                   : '',
  };
}

/** Sanitise project metadata from untrusted input. */
function sanitiseMetadata(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
  const str = (v, max = 500) => (typeof v === 'string' ? v.slice(0, max) : '');
  const VALID_CLASSIFS = new Set(['CONFIDENTIAL','TLP:RED','TLP:AMBER','TLP:GREEN','INTERNAL']);
  return {
    projectName:    str(raw.projectName, 200)  || 'Untitled Project',
    client:         str(raw.client, 200)        || 'Client',
    assessor:       str(raw.assessor, 300),
    classification: VALID_CLASSIFS.has(raw.classification) ? raw.classification : 'CONFIDENTIAL',
    version:        str(raw.version, 20)        || '1.0',
    startDate:      /^\d{4}-\d{2}-\d{2}$/.test(raw.startDate) ? raw.startDate : '',
    endDate:        /^\d{4}-\d{2}-\d{2}$/.test(raw.endDate)   ? raw.endDate   : '',
    scope:          str(raw.scope, 5000),
    exclusions:     str(raw.exclusions, 5000),
  };
}

// ─────────────────────────────────────────────────────────────────────────────

const STORAGE_KEY      = 'secworkflow_v1';
const STORAGE_MODE_KEY = 'secworkflow_storage_mode'; // 'session' | 'local' (local is default)
const WELCOMED_KEY     = 'secworkflow_welcomed';

// Build combined label/color maps from both status sets
const ALL_STATUSES_COMBINED = [...STATUSES, ...CONSULTANT_STATUSES.filter(s => !STATUSES.find(p => p.value === s.value))];
const STATUS_LABELS = Object.fromEntries(ALL_STATUSES_COMBINED.map(s => [s.value, s.label]));
const STATUS_COLORS = Object.fromEntries(ALL_STATUSES_COMBINED.map(s => [s.value, s.color]));

class SecWorkflowApp {
  constructor() {
    // Default storage mode is 'local' — only fall back to session if explicitly set
    const savedMode = localStorage.getItem(STORAGE_MODE_KEY);
    const initialMode = savedMode === 'session' ? 'session' : 'local';

    this.state = {
      currentModuleId: null,
      currentType: 'pentest',
      modeSelected: false,         // true once user has picked pentest or consultant
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
      collapseStates: {},           // persists group collapse/expand per module
      sortOrder: 'default',         // 'default' | 'severity' | 'status' | 'findings'
      filters: { status: 'all', severity: 'all', tag: 'all', search: '', findingsOnly: false },
      filterBarOpen: false,
      storageMode: initialMode,
    };
    this.panelItemId = null;
    this._sessionDirty = false;          // true when unsaved work exists in Session Mode
    this._pendingImportFile = null;      // staged file waiting for import confirmation
    this._moduleCompleteToasted = false; // prevents repeat completion toasts per module
    this._panelDirty = false;            // true when panel has unsaved edits
    this.reportGen = new ReportGenerator(this);
    this._loadFromStorage();
    this._init();
  }

  // Returns the appropriate status list for the current assessment type
  _getStatusesForType() {
    return this.state.currentType === 'consultant' ? CONSULTANT_STATUSES : STATUSES;
  }

  // ── Initialisation ─────────────────────────────────────────────────────────

  _init() {
    this._renderSidebar();
    this._populateTagFilter();
    this._populateFilterStatuses();
    this._bindStaticEvents();
    this._syncMetaToUI();

    // If a mode was previously selected and a module loaded, restore it
    if (this.state.modeSelected && this.state.currentModuleId) {
      this._activateMode(this.state.currentType, false);
      this._loadModule(this.state.currentModuleId);
    } else if (this.state.modeSelected) {
      this._activateMode(this.state.currentType, false);
      // Show welcome screen still (no module selected)
      this._showWelcomeScreen();
    } else {
      this._showWelcomeScreen();
    }
    this._syncStorageModeUI();
    this._syncSidebarModeBar();
    this._updateDocTitle();
    this._checkFirstRun();
  }

  _showWelcomeScreen() {
    document.getElementById('welcome-screen').style.display = '';
    document.getElementById('checklist-container').style.display = 'none';
  }

  _bindStaticEvents() {
    // Mode selector: "Change" button in sidebar returns to welcome screen
    document.getElementById('btn-change-mode')?.addEventListener('click', () => {
      this.state.modeSelected = false;
      this.state.currentModuleId = null;
      this._saveToStorage();
      this._showWelcomeScreen();
      this._syncSidebarModeBar();
    });

    // Sort order in sidebar
    document.getElementById('sort-select')?.addEventListener('change', (e) => {
      this.state.sortOrder = e.target.value;
      if (this.state.currentModuleId) {
        this._renderModule(MODULE_MAP[this.state.currentModuleId]);
      }
    });

    // Top bar buttons
    document.getElementById('btn-filter-toggle').addEventListener('click', () => this._toggleFilterBar());
    document.getElementById('btn-import').addEventListener('click', () => document.getElementById('import-file-input').click());
    document.getElementById('btn-confirm-import').addEventListener('click', () => this._doImport());
    document.getElementById('import-file-input').addEventListener('change', e => this._stageImport(e));
    document.getElementById('btn-export-json').addEventListener('click', () => this._exportJSON());
    document.getElementById('btn-export-md').addEventListener('click', () => this._exportMarkdown());
    document.getElementById('btn-report').addEventListener('click', () => this._openReportModal());
    document.getElementById('btn-project-meta').addEventListener('click', () => this._openMetaModal());

    // Prominent Delete Local Data button
    document.getElementById('btn-delete-data')?.addEventListener('click', () => this._requestClearLocalData());

    // Welcome screen "Export Report" button
    document.getElementById('btn-report-welcome')?.addEventListener('click', () => this._openReportModal());

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
      this._updateDocTitle();
    });
    document.getElementById('project-client-display').addEventListener('blur', e => {
      this.state.metadata.client = e.target.textContent.trim() || 'Client';
      this._saveToStorage();
    });

    // Panel
    document.getElementById('panel-close').addEventListener('click', () => this._closePanel(true));
    document.getElementById('panel-close-btn').addEventListener('click', () => this._closePanel());
    document.getElementById('panel-save-btn').addEventListener('click', () => this._savePanelItem());
    document.getElementById('panel-overlay').addEventListener('click', () => this._closePanel(true));

    // Mark panel dirty on any change (used to warn on close without saving)
    ['panel-status', 'panel-severity', 'panel-notes', 'panel-evidence', 'panel-remediation', 'panel-is-finding', 'panel-out-of-scope'].forEach(id => {
      const el = document.getElementById(id);
      if (el) {
        el.addEventListener('input',  () => { this._panelDirty = true; });
        el.addEventListener('change', () => { this._panelDirty = true; });
      }
    });

    // Prevent newlines in contenteditable project fields
    ['project-name-display', 'project-client-display'].forEach(id => {
      document.getElementById(id)?.addEventListener('keydown', e => {
        if (e.key === 'Enter') { e.preventDefault(); e.target.blur(); }
      });
    });

    // Report modal
    document.getElementById('btn-generate-report').addEventListener('click', () => this._generateReport());

    // Storage mode toggle
    document.getElementById('smt-session').addEventListener('click', () => {
      if (this.state.storageMode !== 'session') this._requestSwitchToSession();
    });
    document.getElementById('smt-local').addEventListener('click', () => {
      if (this.state.storageMode !== 'local') this._requestSwitchToLocal();
    });
    document.getElementById('btn-confirm-to-local').addEventListener('click', () => this._confirmSwitchToLocal());
    document.getElementById('btn-confirm-to-session-keep').addEventListener('click', () => this._confirmSwitchToSession(false));
    document.getElementById('btn-confirm-to-session-clear').addEventListener('click', () => this._confirmSwitchToSession(true));
    document.getElementById('btn-confirm-clear-data').addEventListener('click', () => this._confirmClearLocalData());

    // Warn before unload when unsaved work exists in Session Mode
    window.addEventListener('beforeunload', (e) => {
      if (this.state.storageMode === 'session' && this._sessionDirty) {
        e.preventDefault();
        e.returnValue = ''; // required for Chrome; shows browser-native dialog
      }
    });

    // Welcome mode card click → activate mode and load first module
    document.querySelectorAll('.welcome-mode-card[data-action]').forEach(card => {
      const activate = () => {
        const action = card.dataset.action;
        if (action === 'report') { this._openReportModal(); return; }
        this._activateMode(action, true);
      };
      card.addEventListener('click', activate);
      card.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); activate(); } });
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
      const inInput = ['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName);

      // Ctrl+/ — open filter bar and focus search
      if ((e.ctrlKey || e.metaKey) && e.key === '/') {
        e.preventDefault();
        if (!this.state.filterBarOpen) this._toggleFilterBar();
        setTimeout(() => document.getElementById('filter-search').focus(), 50);
        return;
      }

      // Escape — close filter bar
      if (e.key === 'Escape' && this.state.filterBarOpen) {
        this._toggleFilterBar();
        return;
      }

      // N — jump to next not-started item (when not typing)
      if (e.key === 'n' && !e.ctrlKey && !e.metaKey && !inInput) {
        e.preventDefault();
        const next = document.querySelector('.checklist-item[data-status="not-started"]:not(.filtered-out)');
        if (next) {
          next.scrollIntoView({ behavior: 'smooth', block: 'center' });
          next.classList.add('highlight-pulse');
          setTimeout(() => next.classList.remove('highlight-pulse'), 900);
        } else {
          this._showToast('No unchecked items remaining', 'info');
        }
      }
    });

    // Privacy notice dismiss
    document.getElementById('btn-privacy-dismiss').addEventListener('click', () => this._dismissPrivacyNotice());
  }

  // ── Storage ────────────────────────────────────────────────────────────────

  _saveToStorage() {
    if (this.state.storageMode !== 'local') return; // Session Mode: no writes
    try {
      const now = new Date().toISOString();
      localStorage.setItem(STORAGE_KEY, JSON.stringify({
        version: 1,
        metadata: this.state.metadata,
        itemStates: this.state.itemStates,
        collapseStates: this.state.collapseStates,
        currentModuleId: this.state.currentModuleId,
        currentType: this.state.currentType,
        modeSelected: this.state.modeSelected,
        savedAt: now,
      }));
      // Live-update timestamps in topbar and sidebar
      const timeStr = new Date(now).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      const savedAtEl = document.querySelector('.smt-saved-at');
      if (savedAtEl) savedAtEl.textContent = ` · ${timeStr}`;
      const projectSavedAt = document.getElementById('project-saved-at');
      if (projectSavedAt && projectSavedAt.style.display !== 'none') {
        projectSavedAt.textContent = `Last saved ${timeStr}`;
      }
    } catch (_) { /* storage full */ }
  }

  _loadFromStorage() {
    if (this.state.storageMode !== 'local') return; // Session Mode: start fresh
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return;
      const saved = JSON.parse(raw);
      if (saved.metadata) this.state.metadata = { ...this.state.metadata, ...saved.metadata };
      if (saved.itemStates) this.state.itemStates = saved.itemStates;
      if (saved.collapseStates) this.state.collapseStates = saved.collapseStates;
      if (saved.currentModuleId) this.state.currentModuleId = saved.currentModuleId;
      if (saved.currentType) this.state.currentType = saved.currentType;
      if (saved.modeSelected) this.state.modeSelected = saved.modeSelected;
    } catch (_) { /* ignore */ }
  }

  // ── Storage mode switching ─────────────────────────────────────────────────

  _requestSwitchToLocal() {
    document.getElementById('modal-to-local').style.display = 'flex';
  }

  _confirmSwitchToLocal() {
    document.getElementById('modal-to-local').style.display = 'none';
    this.state.storageMode = 'local';
    this._sessionDirty = false; // data is now being persisted
    localStorage.setItem(STORAGE_MODE_KEY, 'local');
    this._saveToStorage(); // Persist current in-memory state immediately
    this._syncStorageModeUI();
    this._showToast('Local Mode enabled — data saved on this device', 'info');
  }

  _requestSwitchToSession() {
    document.getElementById('modal-to-session').style.display = 'flex';
  }

  _confirmSwitchToSession(clearData) {
    document.getElementById('modal-to-session').style.display = 'none';
    this.state.storageMode = 'session';
    localStorage.setItem(STORAGE_MODE_KEY, 'session'); // explicitly mark session (local is default)
    if (clearData) {
      localStorage.removeItem(STORAGE_KEY);
      this._showToast('Session Mode — local data deleted', 'info');
    } else {
      this._showToast('Session Mode — local data preserved but no longer updated', 'info');
    }
    this._syncStorageModeUI();
  }

  _requestClearLocalData() {
    document.getElementById('modal-clear-data').style.display = 'flex';
  }

  _confirmClearLocalData() {
    document.getElementById('modal-clear-data').style.display = 'none';
    localStorage.removeItem(STORAGE_KEY);
    // Reset in-memory state to defaults
    this.state.metadata = {
      projectName: 'Untitled Project', client: 'Client', assessor: '',
      classification: 'CONFIDENTIAL', startDate: '', endDate: '',
      scope: '', exclusions: '', version: '1.0',
    };
    this.state.itemStates = {};
    this.state.collapseStates = {};
    this.state.currentModuleId = null;
    this.state.currentType = 'pentest';
    this.state.modeSelected = false;
    this._syncMetaToUI();
    this._renderSidebar();
    this._syncSidebarModeBar();
    this._syncStorageModeUI();
    this._updateDocTitle();
    this._showWelcomeScreen();
    this._closePanel(true);
    this._showToast('All local data cleared — app reset to defaults', 'success');
  }

  _syncStorageModeUI() {
    const isLocal = this.state.storageMode === 'local';
    const hasLocalData = !!localStorage.getItem(STORAGE_KEY);

    // Segmented control active state
    document.getElementById('smt-session').classList.toggle('active', !isLocal);
    document.getElementById('smt-local').classList.toggle('active', isLocal);

    // Status label + optional saved-at timestamp
    const statusEl = document.getElementById('smt-status');
    if (isLocal) {
      const savedAt = this._getLocalSavedAt();
      statusEl.innerHTML = `Saved on this device${savedAt ? `<span class="smt-saved-at"> · ${savedAt}</span>` : ''}`;
    } else {
      statusEl.textContent = 'Session only — not saved locally';
    }

    // Topbar visual accent for Local Mode
    document.querySelector('.topbar').classList.toggle('topbar-local-mode', isLocal);

    // Prominent Delete Local Data button — visible when there's local data
    const deleteBtn = document.getElementById('btn-delete-data');
    if (deleteBtn) {
      deleteBtn.style.display = (isLocal && hasLocalData) ? '' : 'none';
    }

    // Sidebar project card: show last-saved timestamp in Local Mode
    const projectSavedAt = document.getElementById('project-saved-at');
    if (projectSavedAt) {
      if (isLocal && hasLocalData) {
        const savedAt = this._getLocalSavedAt();
        projectSavedAt.textContent = savedAt ? `Last saved ${savedAt}` : 'Saved on this device';
        projectSavedAt.style.display = '';
      } else {
        projectSavedAt.style.display = 'none';
      }
    }
  }

  _getLocalSavedAt() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return null;
      const saved = JSON.parse(raw);
      if (saved.savedAt) {
        return new Date(saved.savedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      }
    } catch (_) {}
    return null;
  }

  // ── Document title ────────────────────────────────────────────────────────

  _updateDocTitle() {
    const projectName = this.state.metadata.projectName;
    const hasProject = projectName && projectName !== 'Untitled Project';
    const mod = this.state.currentModuleId ? MODULE_MAP[this.state.currentModuleId] : null;

    let title;
    if (hasProject && mod) {
      title = `${projectName} | ${mod.name} | SecWorkflow`;
    } else if (hasProject) {
      title = `${projectName} | SecWorkflow`;
    } else if (mod) {
      title = `SecWorkflow | ${mod.name}`;
    } else {
      title = 'SecWorkflow';
    }
    document.title = title;
  }

  _checkFirstRun() {
    if (localStorage.getItem(WELCOMED_KEY)) return;
    document.getElementById('modal-privacy').style.display = 'flex';
  }

  _dismissPrivacyNotice() {
    localStorage.setItem(WELCOMED_KEY, '1');
    document.getElementById('modal-privacy').style.display = 'none';
  }

  // ── Mode activation ────────────────────────────────────────────────────────

  _activateMode(type, loadFirst = true) {
    this.state.currentType = type;
    this.state.modeSelected = true;
    this._populateFilterStatuses();
    this._renderSidebar();
    this._syncSidebarModeBar();
    this._saveToStorage();

    if (loadFirst) {
      const mods = MODULES_BY_TYPE[type] || [];
      if (mods.length > 0) this._loadModule(mods[0].id);
    }
  }

  _syncSidebarModeBar() {
    const bar = document.getElementById('sidebar-mode-bar');
    const sortBar = document.getElementById('sidebar-sort-bar');
    if (!bar) return;

    if (this.state.modeSelected) {
      bar.style.display = '';
      if (sortBar) sortBar.style.display = '';
      const icons = { pentest: '🔴', consultant: '📊' };
      const labels = { pentest: 'Pentest Mode', consultant: 'Consultant Mode' };
      document.getElementById('smb-mode-icon').textContent = icons[this.state.currentType] || '';
      document.getElementById('smb-mode-text').textContent = labels[this.state.currentType] || '';
    } else {
      bar.style.display = 'none';
      if (sortBar) sortBar.style.display = 'none';
    }
  }

  // ── Populate filter status dropdown based on current mode ──────────────────

  _populateFilterStatuses() {
    const sel = document.getElementById('filter-status');
    if (!sel) return;
    const statuses = this._getStatusesForType();
    sel.innerHTML = '<option value="all">All</option>' +
      statuses.map(s => `<option value="${s.value}">${s.label}</option>`).join('');
    // Reset filter if current value isn't valid for this mode
    if (this.state.filters.status !== 'all' && !statuses.find(s => s.value === this.state.filters.status)) {
      this.state.filters.status = 'all';
    }
    sel.value = this.state.filters.status;
  }

  // ── Sidebar ────────────────────────────────────────────────────────────────

  _renderSidebar() {
    const nav = document.getElementById('sidebar-nav');
    const modules = MODULES_BY_TYPE[this.state.currentType] || [];

    // Sync hidden tabs for any legacy code references
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

    // Update breadcrumb (with type prefix) and browser tab title
    const typeLabel = this.state.currentType === 'pentest' ? 'Pentest' : 'Consultant';
    document.getElementById('breadcrumb-text').textContent = `${typeLabel} / ${module.icon} ${module.name}`;
    this._updateDocTitle();
    this._moduleCompleteToasted = false;

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
    const isConsultant = this.state.currentType === 'consultant';

    // Header
    const progress = this.getModuleProgress(module);
    const negativeColor = isConsultant ? STATUS_COLORS['not-compliant'] || STATUS_COLORS['vulnerable'] : STATUS_COLORS['vulnerable'];
    const positiveColor = isConsultant ? STATUS_COLORS['compliant'] || STATUS_COLORS['not-vulnerable'] : STATUS_COLORS['not-vulnerable'];
    const negativeLabel = isConsultant ? 'Non-Compliant' : 'Vulnerable';
    const positiveLabel = isConsultant ? 'Compliant' : 'Compliant';

    header.innerHTML = `
      <div class="module-header-top">
        <div class="module-header-icon">${module.icon}</div>
        <div class="module-header-info">
          <h2>${module.name}</h2>
          <p>${module.description}</p>
        </div>
      </div>
      <div class="module-header-stats">
        <div class="stat-pill"><span class="stat-pill-dot" style="background:${negativeColor}"></span>${progress.vulnerable} ${negativeLabel}</div>
        <div class="stat-pill"><span class="stat-pill-dot" style="background:${STATUS_COLORS['in-progress']}"></span>${progress.inProgress} In Progress</div>
        <div class="stat-pill"><span class="stat-pill-dot" style="background:${positiveColor}"></span>${progress.compliant} ${positiveLabel}</div>
        <div class="stat-pill"><span class="stat-pill-dot" style="background:${STATUS_COLORS['not-started']}"></span>${progress.notStarted} Not Started</div>
        <div class="stat-pill"><span class="stat-pill-dot" style="background:${STATUS_COLORS['cannot-verify']}"></span>${progress.cannotVerify} Unverified</div>
      </div>
    `;

    // Groups
    groups.innerHTML = '';

    // First-time tip (dismissible)
    const tipDismissed = localStorage.getItem('sw_tip_dismissed') === '1';
    const allPristine = module.groups.every(g =>
      g.items.every(i => !this.state.itemStates[i.id] || ['not-started','not-assessed'].includes(this.state.itemStates[i.id].status))
    );
    if (allPristine && !tipDismissed) {
      const tip = document.createElement('div');
      tip.className = 'module-first-tip';
      tip.innerHTML = `<span class="module-first-tip-icon">💡</span><span class="module-first-tip-text"> Click any row to open the detail panel — add notes, evidence, and set status. Use the chips on the right for a quick status change.</span><button class="module-first-tip-close" title="Dismiss" aria-label="Dismiss hint">✕</button>`;
      tip.querySelector('.module-first-tip-close').addEventListener('click', () => {
        localStorage.setItem('sw_tip_dismissed', '1');
        tip.remove();
      });
      groups.appendChild(tip);
    }

    for (const group of module.groups) {
      groups.appendChild(this._renderGroup(group));
    }

    this._applyFilters();
  }

  _renderGroup(group) {
    const container = document.createElement('div');
    container.className = 'checklist-group';
    container.dataset.groupId = group.id;

    const isConsultant = this.state.currentType === 'consultant';
    const notStartedVal = isConsultant ? 'not-assessed' : 'not-started';
    const negativeVal   = isConsultant ? 'not-compliant' : 'vulnerable';
    const positiveVal   = isConsultant ? 'compliant' : 'not-vulnerable';

    let completedCount = 0, negCount = 0, posCount = 0;
    for (const i of group.items) {
      const s = (this.state.itemStates[i.id] || {}).status || notStartedVal;
      if (s !== notStartedVal && s !== 'not-started') completedCount++;
      if (s === negativeVal || s === 'vulnerable') negCount++;
      else if (s === positiveVal || s === 'not-vulnerable') posCount++;
    }
    const pct = group.items.length > 0 ? (completedCount / group.items.length) * 100 : 0;

    const groupStatBits = [
      negCount > 0 ? `<span class="group-stat"><span class="group-stat-dot" style="background:${STATUS_COLORS[negativeVal]||STATUS_COLORS['vulnerable']}"></span>${negCount} ${isConsultant ? 'gaps' : 'vuln'}</span>` : '',
      posCount > 0 ? `<span class="group-stat"><span class="group-stat-dot" style="background:${STATUS_COLORS[positiveVal]||STATUS_COLORS['not-vulnerable']}"></span>${posCount} ok</span>` : '',
    ].filter(Boolean).join('');

    // Sort items based on current sort order
    let items = [...group.items];
    const sortOrder = { critical:0, high:1, medium:2, low:3, info:4 };
    const statusOrder = { 'vulnerable':0, 'not-compliant':0, 'in-progress':1, 'cannot-verify':2, 'partially-compliant':2, 'not-started':3, 'not-assessed':3, 'not-in-scope':4, 'not-applicable':4, 'not-vulnerable':5, 'compliant':5 };
    if (this.state.sortOrder === 'severity') {
      items.sort((a, b) => {
        const sa = (this.state.itemStates[a.id]||{}).severityOverride || a.severity || 'info';
        const sb = (this.state.itemStates[b.id]||{}).severityOverride || b.severity || 'info';
        return (sortOrder[sa]??5) - (sortOrder[sb]??5);
      });
    } else if (this.state.sortOrder === 'status') {
      items.sort((a, b) => {
        const sa = (this.state.itemStates[a.id]||{}).status || notStartedVal;
        const sb = (this.state.itemStates[b.id]||{}).status || notStartedVal;
        return (statusOrder[sa]??9) - (statusOrder[sb]??9);
      });
    } else if (this.state.sortOrder === 'findings') {
      items.sort((a, b) => {
        const fa = (this.state.itemStates[a.id]||{}).isFinding ? 0 : 1;
        const fb = (this.state.itemStates[b.id]||{}).isFinding ? 0 : 1;
        return fa - fb;
      });
    }

    const header = document.createElement('div');
    // Restore collapse state
    const isCollapsed = !!this.state.collapseStates[group.id];
    header.className = `group-header${isCollapsed ? ' collapsed' : ''}`;
    header.innerHTML = `
      <span class="group-header-title">${group.name}</span>
      ${groupStatBits ? `<span class="group-stat-row">${groupStatBits}</span>` : ''}
      <span class="group-header-count">${completedCount}/${group.items.length}</span>
      <span class="group-chevron">▾</span>
    `;

    const progressBar = document.createElement('div');
    progressBar.className = 'group-progress';
    progressBar.innerHTML = `<div class="group-progress-fill" style="width:${pct}%"></div>`;

    const itemsContainer = document.createElement('div');
    itemsContainer.className = `group-items${isCollapsed ? ' collapsed' : ''}`;
    itemsContainer.dataset.groupId = group.id;

    for (const item of items) {
      itemsContainer.appendChild(this._renderItem(item));
    }

    header.addEventListener('click', () => {
      const nowCollapsed = header.classList.toggle('collapsed');
      itemsContainer.classList.toggle('collapsed', nowCollapsed);
      // Persist collapse state
      this.state.collapseStates[group.id] = nowCollapsed;
      this._saveToStorage();
    });

    container.appendChild(header);
    container.appendChild(progressBar);
    container.appendChild(itemsContainer);
    return container;
  }

  _renderItem(item) {
    const ist = this.state.itemStates[item.id] || {};
    const isConsultant = this.state.currentType === 'consultant';
    const defaultStatus = isConsultant ? 'not-assessed' : 'not-started';
    const status = ist.status || defaultStatus;
    const sev = ist.severityOverride || item.severity;
    const outOfScope = ist.outOfScope || false;

    const el = document.createElement('div');
    let classes = 'checklist-item';
    if (ist.isFinding) classes += ' is-finding';
    if (outOfScope) classes += ' is-out-of-scope';
    el.className = classes;
    el.dataset.itemId = item.id;
    el.dataset.status = status;
    el.dataset.severity = sev || '';
    el.dataset.tags = (item.tags || []).join(',');
    el.dataset.isFinding = ist.isFinding ? '1' : '0';

    const statusChips = this._buildStatusChips(item.id, status);
    const sevBadge = sev ? `<span class="sev-badge sev-${sev}">${sev.toUpperCase()}</span>` : '';
    const tagBadges = (item.tags || []).slice(0, 3).map(t => `<span class="badge badge-tag">${escHTML(t)}</span>`).join('');
    const findingBadge = ist.isFinding ? `<span class="badge badge-finding">Finding</span>` : '';
    const scopeBadge = outOfScope ? `<span class="badge badge-out-of-scope">Out of scope</span>` : '';
    const notePreview = ist.note ? `<div class="item-note-preview">📝 ${escHTML(ist.note.slice(0, 100))}${ist.note.length > 100 ? '…' : ''}</div>` : '';

    el.innerHTML = `
      <div class="item-status-col">
        <div class="status-dot status-${status}"></div>
      </div>
      <div class="item-body">
        <div class="item-title-row">
          <span class="item-title">${escHTML(item.title)}</span>
          ${sevBadge}${findingBadge}${scopeBadge}
        </div>
        <div class="item-tags">${tagBadges}</div>
        <div class="item-desc">${escHTML(item.description.slice(0, 120))}${item.description.length > 120 ? '…' : ''}</div>
        ${notePreview}
      </div>
      <div class="item-actions">
        ${statusChips}
      </div>
    `;

    // Open panel on row click
    el.addEventListener('click', (e) => {
      if (e.target.closest('.item-actions')) return;
      this._openPanel(item);
    });

    return el;
  }

  _buildStatusChips(itemId, currentStatus) {
    const statuses = this._getStatusesForType();
    const chips = statuses.map(s => {
      const isActive = s.value === currentStatus;
      return `<button class="status-chip chip-${s.value}${isActive ? ' active-chip' : ''}" data-item-id="${itemId}" data-status="${s.value}" title="${escHTML(s.label)}">${escHTML(s.label)}</button>`;
    }).join('');
    return `<div class="item-status-chips">${chips}</div>`;
  }

  // ── Item State ────────────────────────────────────────────────────────────

  _updateItemState(itemId, field, value) {
    if (!this.state.itemStates[itemId]) {
      const defaultStatus = this.state.currentType === 'consultant' ? 'not-assessed' : 'not-started';
      this.state.itemStates[itemId] = { status: defaultStatus, note: '', evidence: '', remediation: '', severityOverride: null, isFinding: false, outOfScope: false };
    }
    this.state.itemStates[itemId][field] = value;
    this.state.itemStates[itemId].updatedAt = new Date().toISOString();
    if (this.state.storageMode === 'session') this._sessionDirty = true;
    this._saveToStorage();
  }

  // ── Panel ─────────────────────────────────────────────────────────────────

  _openPanel(item) {
    this.panelItemId = item.id;
    const ist = this.state.itemStates[item.id] || {};
    const isConsultant = this.state.currentType === 'consultant';
    const defaultStatus = isConsultant ? 'not-assessed' : 'not-started';

    document.getElementById('panel-title').textContent = item.title;
    document.getElementById('panel-description').textContent = item.description;

    // Note timestamp
    const noteTs = document.getElementById('panel-note-ts');
    if (noteTs && ist.updatedAt) {
      try {
        const d = new Date(ist.updatedAt);
        noteTs.textContent = `Last edited ${d.toLocaleDateString()} ${d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
      } catch (_) { noteTs.textContent = ''; }
    } else if (noteTs) {
      noteTs.textContent = '';
    }

    // Status — use context-appropriate status list
    const statuses = this._getStatusesForType();
    const currentStatus = ist.status || defaultStatus;
    const statusSel = document.getElementById('panel-status');
    statusSel.innerHTML = statuses.map(s =>
      `<option value="${s.value}"${currentStatus === s.value ? ' selected' : ''}>${s.label}</option>`
    ).join('');
    statusSel.className = `status-select panel-status ss-${currentStatus}`;
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

    // Out of scope checkbox
    const outOfScopeEl = document.getElementById('panel-out-of-scope');
    if (outOfScopeEl) outOfScopeEl.checked = ist.outOfScope || false;

    // Tags
    const tagsEl = document.getElementById('panel-tags');
    tagsEl.innerHTML = (item.tags || []).map(t => `<span class="badge badge-tag">${t}</span>`).join('') || '<span class="text-muted text-small">None</span>';

    // Frameworks
    const fwEl = document.getElementById('panel-frameworks');
    fwEl.innerHTML = (item.frameworks || []).map(f => `<span class="badge badge-framework">${f}</span>`).join('') || '<span class="text-muted text-small">None</span>';

    // Show panel
    this._panelDirty = false;
    document.getElementById('panel-overlay').style.display = 'block';
    document.getElementById('item-panel').style.display = 'flex';
  }

  _closePanel(force = false) {
    if (!force && this._panelDirty) {
      // Two-step confirm: first click turns button red, second click closes
      const btn = document.getElementById('panel-close-btn');
      if (!btn.dataset.confirmPending) {
        btn.dataset.confirmPending = '1';
        btn.textContent = 'Discard changes?';
        btn.classList.add('panel-close-btn-warn');
        setTimeout(() => {
          delete btn.dataset.confirmPending;
          btn.textContent = 'Close';
          btn.classList.remove('panel-close-btn-warn');
        }, 3000);
        return;
      }
      delete btn.dataset.confirmPending;
      btn.textContent = 'Close';
      btn.classList.remove('panel-close-btn-warn');
    }
    this._panelDirty = false;
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
    const outOfScope = document.getElementById('panel-out-of-scope')?.checked || false;

    this._updateItemState(id, 'status', status);
    this._updateItemState(id, 'severityOverride', severityOverride);
    this._updateItemState(id, 'note', note);
    this._updateItemState(id, 'evidence', evidence);
    this._updateItemState(id, 'remediation', remediation);
    this._updateItemState(id, 'isFinding', isFinding);
    this._updateItemState(id, 'outOfScope', outOfScope);

    // Update the row in the DOM
    const row = document.querySelector(`.checklist-item[data-item-id="${id}"]`);
    if (row) {
      row.dataset.status = status;
      row.dataset.isFinding = isFinding ? '1' : '0';
      row.classList.toggle('is-finding', isFinding);
      row.classList.toggle('is-out-of-scope', outOfScope);

      const dot = row.querySelector('.status-dot');
      if (dot) dot.className = `status-dot status-${status}`;

      // Update chips
      const chipsEl = row.querySelector('.item-status-chips');
      if (chipsEl) {
        chipsEl.querySelectorAll('.status-chip').forEach(chip => {
          chip.classList.toggle('active-chip', chip.dataset.status === status);
        });
      }

      const notePreview = row.querySelector('.item-note-preview');
      if (note) {
        const previewText = `📝 ${note.slice(0, 100)}${note.length > 100 ? '…' : ''}`;
        if (notePreview) notePreview.textContent = previewText;
        else {
          const nb = document.createElement('div');
          nb.className = 'item-note-preview';
          nb.textContent = previewText;
          row.querySelector('.item-body').appendChild(nb);
        }
      } else if (notePreview) notePreview.remove();
    }

    this._panelDirty = false;
    this._updateProgress(MODULE_MAP[this.state.currentModuleId]);
    this._renderSidebar();
    this._closePanel(true);
    this._showToast('Item saved', 'success');
  }

  // ── Progress ──────────────────────────────────────────────────────────────

  getModuleProgress(module) {
    const isConsultant = module.type === 'consultant';
    const counts = { total: 0, notStarted: 0, inProgress: 0, compliant: 0, vulnerable: 0, notInScope: 0, cannotVerify: 0 };
    for (const group of module.groups) {
      for (const item of group.items) {
        counts.total++;
        const status = (this.state.itemStates[item.id] || {}).status || (isConsultant ? 'not-assessed' : 'not-started');
        if (status === 'not-started' || status === 'not-assessed') counts.notStarted++;
        else if (status === 'in-progress') counts.inProgress++;
        else if (status === 'not-vulnerable' || status === 'compliant') counts.compliant++;
        else if (status === 'vulnerable' || status === 'not-compliant') counts.vulnerable++;
        else if (status === 'not-in-scope' || status === 'not-applicable') counts.notInScope++;
        else if (status === 'cannot-verify' || status === 'partially-compliant') counts.cannotVerify++;
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
    fraction.textContent = `${assessed}/${progress.total}`;

    // Stacked colour segments: vulnerable / compliant / in-progress / cannot-verify
    const segments = [
      { count: progress.vulnerable,   color: STATUS_COLORS['vulnerable']    },
      { count: progress.compliant,    color: STATUS_COLORS['not-vulnerable'] },
      { count: progress.inProgress,   color: STATUS_COLORS['in-progress']   },
      { count: progress.cannotVerify, color: STATUS_COLORS['cannot-verify'] },
      { count: progress.notInScope,   color: STATUS_COLORS['not-in-scope']  },
    ].filter(s => s.count > 0);
    fill.style.cssText = `width:${pct}%;height:100%;display:flex;background:none;border-radius:2px;transition:width .35s ease;overflow:hidden;`;
    fill.innerHTML = segments.map(s =>
      `<div style="flex:${s.count};background:${s.color};"></div>`
    ).join('');

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

    // Module completion celebration (toast once per module load)
    if (progress.notStarted === 0 && progress.total > 0 && !this._moduleCompleteToasted) {
      this._moduleCompleteToasted = true;
      const f = progress.vulnerable;
      this._showToast(
        f > 0 ? `All items assessed — ${f} finding${f !== 1 ? 's' : ''} flagged` : 'All items assessed — no findings',
        'success'
      );
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
    this._updateDocTitle();
    document.getElementById('modal-project').style.display = 'none';
    this._showToast('Project metadata saved', 'success');
  }

  _syncMetaToUI() {
    const m = this.state.metadata;

    // Inline-editable fields (contenteditable)
    document.getElementById('project-name-display').textContent = m.projectName;
    document.getElementById('project-client-display').textContent = m.client;

    // Classification badge
    const classifEl = document.getElementById('project-classification-display');
    if (classifEl) {
      classifEl.textContent = m.classification || 'CONFIDENTIAL';
      classifEl.dataset.value = m.classification || 'CONFIDENTIAL';
    }

    // Date range
    const datesEl = document.getElementById('project-dates-display');
    if (datesEl) {
      if (m.startDate || m.endDate) {
        const fmt = d => d
          ? new Date(d + 'T12:00:00').toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' })
          : '?';
        datesEl.textContent = `${fmt(m.startDate)} – ${fmt(m.endDate)}`;
      } else {
        datesEl.textContent = '';
      }
    }
  }

  // ── Report modal ──────────────────────────────────────────────────────────

  _openReportModal() {
    const container = document.getElementById('report-module-checkboxes');
    container.innerHTML = '';
    // Show only modules relevant to current type (or all if no mode selected)
    const modsToShow = this.state.modeSelected
      ? (MODULES_BY_TYPE[this.state.currentType] || ALL_MODULES)
      : ALL_MODULES;
    for (const mod of modsToShow) {
      const label = document.createElement('label');
      label.className = 'cb-label';
      label.innerHTML = `<input type="checkbox" class="report-module-cb" value="${mod.id}" checked /> ${mod.icon} ${escHTML(mod.name)}`;
      container.appendChild(label);
    }
    // Auto-select report type based on mode
    const reportType = this.state.currentType === 'consultant' ? 'consultant' : 'pentest';
    document.querySelectorAll('[name="report-type"]').forEach(radio => {
      radio.checked = radio.value === reportType;
    });
    document.querySelectorAll('.report-type-card').forEach(c => {
      const radio = c.querySelector('input[name="report-type"]');
      c.classList.toggle('active', radio?.checked || false);
    });

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
      appVersion: '1.0',
      metadata: this.state.metadata,
      itemStates: this.state.itemStates,
    };
    const safeName = (this.state.metadata.projectName || 'secworkflow')
      .replace(/[^a-zA-Z0-9_\-. ]/g, '_').replace(/\s+/g, '_').slice(0, 80).toLowerCase();
    this._downloadFile(`${safeName}_${new Date().toISOString().slice(0,10)}.json`, JSON.stringify(data, null, 2), 'application/json');
    this._sessionDirty = false; // user has a backup now
    this._showToast('Exported JSON', 'success');
  }

  // Stage the file and show confirmation modal before overwriting
  _stageImport(event) {
    const file = event.target.files[0];
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) {
      this._showToast('File too large (max 5 MB)', 'error');
      event.target.value = '';
      return;
    }
    this._pendingImportFile = file;
    event.target.value = '';
    document.getElementById('modal-import-confirm').style.display = 'flex';
  }

  _doImport() {
    document.getElementById('modal-import-confirm').style.display = 'none';
    const file = this._pendingImportFile;
    this._pendingImportFile = null;
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const data = JSON.parse(e.target.result);
        if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Invalid structure');

        if (data.metadata) {
          this.state.metadata = { ...this.state.metadata, ...sanitiseMetadata(data.metadata) };
        }

        if (data.itemStates && typeof data.itemStates === 'object' && !Array.isArray(data.itemStates)) {
          for (const [key, val] of Object.entries(data.itemStates)) {
            if (typeof key === 'string' && key.length <= 200) {
              this.state.itemStates[key] = sanitiseItemState(val);
            }
          }
        }

        this._syncMetaToUI();
        this._saveToStorage();
        this._sessionDirty = false;
        this._updateDocTitle();
        if (this.state.currentModuleId) this._loadModule(this.state.currentModuleId);
        this._renderSidebar();
        this._showToast('Data imported successfully', 'success');
      } catch (_) {
        this._showToast('Invalid or malformed JSON file', 'error');
      }
    };
    reader.readAsText(file);
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
    toast.title = 'Click to dismiss';
    toast.style.cursor = 'pointer';
    container.appendChild(toast);

    const dismiss = () => {
      toast.style.opacity = '0';
      toast.style.transition = 'opacity .15s';
      setTimeout(() => toast.remove(), 180);
    };
    toast.addEventListener('click', dismiss);
    setTimeout(dismiss, 3000);
  }
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  window.app = new SecWorkflowApp();

  // Delegated click handler for status chips
  document.getElementById('checklist-groups').addEventListener('click', (e) => {
    const chip = e.target.closest('.status-chip');
    if (!chip) return;
    e.stopPropagation();

    const itemId = chip.dataset.itemId;
    const newStatus = chip.dataset.status;
    const row = chip.closest('.checklist-item');
    if (!itemId || !newStatus) return;

    window.app._updateItemState(itemId, 'status', newStatus);

    // Update all chips in this row
    const chips = chip.closest('.item-status-chips');
    if (chips) chips.querySelectorAll('.status-chip').forEach(c => {
      c.classList.toggle('active-chip', c.dataset.status === newStatus);
    });

    if (row) {
      row.dataset.status = newStatus;
      const dot = row.querySelector('.status-dot');
      if (dot) dot.className = `status-dot status-${newStatus}`;
    }

    window.app._updateProgress(MODULE_MAP[window.app.state.currentModuleId]);
    window.app._renderSidebar();
  });
});
