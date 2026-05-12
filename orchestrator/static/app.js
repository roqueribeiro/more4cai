/* CAI dashboard — Alpine.js components.
 *
 * Dois componentes:
 *   - dashboard()  — index.html (4 abas, polling 3s, charts)
 *   - cockpit()    — cockpit.html (1 scan, SSE phase + logs)
 */

const POLL_MS = 3000;
const TOKEN_KEY = 'cai_app_token';

// -------------------- helpers globais --------------------

function fmtTime(iso) {
  if (!iso) return '-';
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    const now = new Date();
    if (d.toDateString() === now.toDateString()) {
      return d.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' });
    }
    return d.toLocaleString('pt-BR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
  } catch { return iso; }
}

function nowFmt() {
  return new Date().toLocaleTimeString('pt-BR');
}

function stateColor(state) {
  return {
    'pending':  'bg-muted/20 text-muted',
    'running':  'bg-accent/20 text-accent',
    'done':     'bg-ok/20 text-ok',
    'failed':   'bg-down/20 text-down',
    'canceled': 'bg-warn/20 text-warn',
  }[state] || 'bg-muted/20 text-muted';
}

function sevColor(sev) {
  return {
    'critical': 'bg-down/30 text-down',
    'high':     'bg-warn/30 text-warn',
    'medium':   'bg-accent/30 text-accent',
    'low':      'bg-ok/30 text-ok',
    'info':     'bg-muted/30 text-muted',
  }[sev] || 'bg-muted/20 text-muted';
}

function logLevelColor(lvl) {
  return {
    'debug':   'text-muted',
    'info':    'text-accent',
    'warning': 'text-warn',
    'error':   'text-down',
    'critical':'text-down',
  }[lvl] || 'text-slate-400';
}

function logRest(l) {
  // Mostra os campos extras (sem level/event/timestamp/_received_at)
  const { level, event, timestamp, _received_at, ...rest } = l;
  return Object.keys(rest).length ? JSON.stringify(rest) : '';
}

function logKey(l) {
  // chave pra Alpine não duplicar em re-render
  return `${l.timestamp || ''}-${l.event || ''}-${Math.random()}`;
}

// -------------------- Dashboard component --------------------

function dashboard() {
  return {
    activeTab: 'dashboard',
    tabs: [
      { id: 'dashboard', icon: '◉', label: 'Dashboard', subtitle: 'Visão geral da stack e atividade', badge: null },
      { id: 'scans',     icon: '⚡', label: 'Scans',     subtitle: 'Pentests executados',                badge: null },
      { id: 'ai',        icon: '✦', label: 'AI Calls',  subtitle: 'Chamadas LLM (litellm)',             badge: null },
      { id: 'logs',      icon: '⌗', label: 'Logs',       subtitle: 'Stream de eventos do orchestrator',  badge: null },
    ],
    token: '',
    health: { components: [], overall: 'ok' },
    overallStatus: 'ok',
    version: '',
    scans: [],
    aiRuns: [],
    aiStats: {},
    logs: [],
    sseConnected: false,
    sseSource: null,
    logFilter: '',
    pollTimer: null,
    chartModels: null,
    chartSeverity: null,

    init() {
      this.token = localStorage.getItem(TOKEN_KEY) || '';
      this.refresh();
      this.pollTimer = setInterval(() => this.refresh(), POLL_MS);
      this.connectSSE();
    },

    saveToken() {
      localStorage.setItem(TOKEN_KEY, this.token);
      this.refresh();
      this.disconnectSSE();
      this.connectSSE();
    },

    async refresh() {
      await Promise.all([
        this.loadHealth(),
        this.loadScans(),
        this.loadAIRuns(),
        this.loadAIStats(),
        this.loadVersion(),
      ]);
      this.renderCharts();
    },

    async fetchJson(path) {
      try {
        const r = await fetch(path, { headers: { 'X-API-Token': this.token } });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return await r.json();
      } catch (e) {
        console.warn('fetch failed', path, e.message);
        return null;
      }
    },

    async loadHealth() {
      const data = await this.fetchJson('/health/full');
      if (data) {
        this.health = data;
        this.overallStatus = data.overall;
      } else {
        this.overallStatus = 'down';
      }
    },

    async loadVersion() {
      const data = await this.fetchJson('/health');
      if (data) this.version = data.version;
    },

    async loadScans() {
      const data = await this.fetchJson('/ui/api/scans?limit=50');
      if (data) this.scans = data;
    },

    async loadAIRuns() {
      const data = await this.fetchJson('/ui/api/ai-runs?limit=100');
      if (data) this.aiRuns = data;
    },

    async loadAIStats() {
      const data = await this.fetchJson('/ui/api/ai-runs/stats');
      if (data) this.aiStats = data;
    },

    renderCharts() {
      // Models doughnut
      const ctxM = document.getElementById('chartModels');
      if (ctxM && this.aiStats.by_model) {
        const labels = this.aiStats.by_model.map(m => m.model.split('/').pop());
        const counts = this.aiStats.by_model.map(m => m.count);
        if (this.chartModels) this.chartModels.destroy();
        this.chartModels = new Chart(ctxM, {
          type: 'doughnut',
          data: { labels, datasets: [{
            data: counts,
            backgroundColor: ['#3b82f6', '#8b5cf6', '#10b981', '#f59e0b', '#ef4444', '#64748b'],
            borderColor: '#111a2c', borderWidth: 2,
          }] },
          options: { plugins: { legend: { position: 'right', labels: { color: '#cbd5e1', font: { size: 11 } } } } }
        });
      }

      // Severity stacked bar (10 últimos scans)
      const ctxS = document.getElementById('chartSeverity');
      if (ctxS && this.scans.length) {
        const last = this.scans.slice(0, 10).reverse();
        const labels = last.map(s => s.id.slice(0, 6));
        const sevs = ['critical', 'high', 'medium', 'low', 'info'];
        const colors = { critical: '#ef4444', high: '#f59e0b', medium: '#3b82f6', low: '#10b981', info: '#64748b' };
        const datasets = sevs.map(sev => ({
          label: sev,
          data: last.map(s => s.severity_counts[sev] || 0),
          backgroundColor: colors[sev],
        }));
        if (this.chartSeverity) this.chartSeverity.destroy();
        this.chartSeverity = new Chart(ctxS, {
          type: 'bar',
          data: { labels, datasets },
          options: {
            responsive: true,
            scales: {
              x: { stacked: true, ticks: { color: '#64748b', font: { size: 10 } }, grid: { color: '#1e293b' } },
              y: { stacked: true, ticks: { color: '#64748b', font: { size: 10 } }, grid: { color: '#1e293b' } }
            },
            plugins: { legend: { labels: { color: '#cbd5e1', font: { size: 11 } } } }
          }
        });
      }
    },

    connectSSE() {
      if (!this.token) return;
      // EventSource não tem header customizado — usa query token
      const url = `/ui/api/events?token=${encodeURIComponent(this.token)}`;
      this.sseSource = new EventSource(url);
      this.sseSource.addEventListener('open', () => { this.sseConnected = true; });
      this.sseSource.addEventListener('error', () => { this.sseConnected = false; });
      this.sseSource.addEventListener('log', (e) => {
        try {
          const data = JSON.parse(e.data);
          data._key = logKey(data);
          this.logs.push(data);
          if (this.logs.length > 500) this.logs = this.logs.slice(-500);
        } catch {}
      });
    },

    disconnectSSE() {
      if (this.sseSource) { this.sseSource.close(); this.sseSource = null; this.sseConnected = false; }
    },

    logsFiltered() {
      if (!this.logFilter) return this.logs.slice(-200);
      const f = this.logFilter.toLowerCase();
      return this.logs.filter(l =>
        (l.event || '').toLowerCase().includes(f) ||
        (l.level || '').toLowerCase().includes(f) ||
        JSON.stringify(l).toLowerCase().includes(f)
      ).slice(-200);
    },

    nowFmt, fmtTime, stateColor, sevColor, logLevelColor, logRest,
  };
}

// -------------------- Cockpit component --------------------

function cockpit() {
  return {
    scanId: '',
    token: '',
    scan: null,
    findings: [],
    logs: [],
    sseConnected: false,
    sseSource: null,
    pollTimer: null,
    phaseProgress: null,
    phases: [
      { key: 'queued',          label: 'queued' },
      { key: 'nmap_running',    label: 'nmap' },
      { key: 'zap_running',     label: 'zap' },
      { key: 'dedup',           label: 'dedup' },
      { key: 'ai_triage',       label: 'triage' },
      { key: 'persisting',      label: 'persist' },
      { key: 'reporting',       label: 'report' },
      { key: 'done',            label: 'done' },
    ],

    init() {
      const params = new URLSearchParams(location.search);
      this.scanId = params.get('scan_id') || '';
      this.token = params.get('token') || localStorage.getItem(TOKEN_KEY) || '';
      if (!this.scanId) { document.body.innerText = 'Faltou ?scan_id=...'; return; }
      this.refresh();
      this.pollTimer = setInterval(() => this.refresh(), POLL_MS);
      this.connectSSE();
    },

    async fetchJson(path) {
      try {
        const r = await fetch(path, { headers: { 'X-API-Token': this.token } });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return await r.json();
      } catch (e) {
        console.warn('fetch failed', path, e.message);
        return null;
      }
    },

    async refresh() {
      const [scan, findings] = await Promise.all([
        this.fetchJson(`/ui/api/scans/${this.scanId}`),
        this.fetchJson(`/ui/api/findings?scan_id=${this.scanId}&limit=200`),
      ]);
      if (scan) {
        this.scan = scan;
        this.phaseProgress = scan.phase_progress;
      }
      if (findings) {
        // ordena por severity rank (critical primeiro)
        const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        this.findings = findings.sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9));
      }
    },

    connectSSE() {
      if (!this.token) return;
      const url = `/ui/api/events?token=${encodeURIComponent(this.token)}&scan_id=${encodeURIComponent(this.scanId)}`;
      this.sseSource = new EventSource(url);
      this.sseSource.addEventListener('open', () => { this.sseConnected = true; });
      this.sseSource.addEventListener('error', () => { this.sseConnected = false; });
      this.sseSource.addEventListener('log', (e) => {
        try {
          const data = JSON.parse(e.data);
          data._key = logKey(data);
          this.logs.push(data);
          if (this.logs.length > 500) this.logs = this.logs.slice(-500);
        } catch {}
      });
      this.sseSource.addEventListener('phase', (e) => {
        try {
          const data = JSON.parse(e.data);
          if (data.scan_id === this.scanId) {
            // forçar refresh de scan pra ver o phase update
            this.phaseProgress = data.progress;
            this.refresh();
          }
        } catch {}
      });
    },

    elapsed() {
      if (!this.scan?.started_at) return '';
      const start = new Date(this.scan.started_at).getTime();
      const end = this.scan.finished_at ? new Date(this.scan.finished_at).getTime() : Date.now();
      const sec = Math.floor((end - start) / 1000);
      const m = Math.floor(sec / 60), s = sec % 60;
      return m > 0 ? `${m}m ${s}s` : `${s}s`;
    },

    phaseStatus(key) {
      const cur = this.scan?.current_phase;
      if (!cur) return 'pending';
      // ordem das fases pra inferir "passou já"
      const order = this.phases.map(p => p.key);
      const idxCur = order.indexOf(cur === 'failed' ? 'done' : cur);
      const idxKey = order.indexOf(key);
      // mapeia zap_spider/passive/active -> zap_running pra UI
      const norm = (cur === 'zap_spider' || cur === 'zap_passive' || cur === 'zap_active') ? 'zap_running' : cur;
      if (norm === key) return this.scan.state === 'failed' ? 'failed' : 'running';
      if (idxKey < idxCur) return 'done';
      return 'pending';
    },

    phaseStyle(key) {
      const st = this.phaseStatus(key);
      return {
        'done':    'bg-ok/20 text-ok ring-1 ring-ok/40',
        'running': 'bg-accent/30 text-accent ring-2 ring-accent animate-pulse',
        'failed':  'bg-down/30 text-down ring-2 ring-down',
        'pending': 'bg-panel border border-border text-muted',
      }[st];
    },

    phaseIcon(key) {
      const st = this.phaseStatus(key);
      return { done: '✓', running: '⚡', failed: '✗', pending: '○' }[st];
    },

    sevColor, stateColor, logLevelColor, logRest, fmtTime,
  };
}
