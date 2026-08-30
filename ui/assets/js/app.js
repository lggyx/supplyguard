// SupplyGuard console — vanilla ES module + Alpine component (no build step).
// Design tokens live in app.css; this module wires data + SSE + the chart.

function consoleComponent() {
  return {
    view: 'overview',
    connState: 'on',
    connLabel: 'SSE 已连接',
    busy: false,
    scanPath: 'fixtures/demo-app',
    summary: null,
    recent: [],
    detail: null,
    timelineSession: '',
    timelineSteps: [],
    auditEntries: [],
    auditVerification: null,
    chart: null,
    es: null,
    retry: 0,

    get title() {
      return {
        overview: '总览 Overview',
        scans: '扫描详情 Scan Detail',
        timeline: '裁决时间线 Timeline',
        audit: '审计链 Audit Chain',
      }[this.view];
    },

    async init() {
      await this.refreshAll();
      this.connectSse();
      this.$watch('view', (v) => { if (v === 'overview') this.renderChart(); });
    },

    show(view) {
      this.view = view;
      if (view === 'overview') this.renderChart();
      if (view === 'audit') this.refreshAudit();
    },

    async api(path, options) {
      const response = await fetch(path, options);
      const text = await response.text();
      let body = {};
      try { body = text ? JSON.parse(text) : {}; } catch { body = {}; }
      if (!response.ok) throw new Error(body?.error?.code || String(response.status));
      return body;
    },

    async refreshAll() {
      await Promise.all([this.refreshOverview(), this.refreshAudit()]);
    },

    async refreshOverview() {
      try {
        this.summary = await this.api('/api/overview');
        this.recent = this.summary.recent_sessions || [];
        this.renderChart();
      } catch { this.markError(); }
    },

    async refreshAudit() {
      try {
        const data = await this.api('/api/audit');
        this.auditEntries = data.entries || [];
        this.auditVerification = data.verification;
      } catch { this.markError(); }
    },

    async loadDetail(id) {
      try { this.detail = await this.api('/api/scans/' + id); }
      catch { this.markError(); }
    },

    async loadTimeline() {
      if (!this.timelineSession) return;
      try {
        const data = await this.api('/api/scans/' + this.timelineSession + '/timeline');
        this.timelineSteps = (data.steps || []).map((s) => ({
          state: s.state,
          time: new Date(Number(s.timestamp)).toLocaleTimeString(),
        }));
      } catch { this.markError(); }
    },

    async triggerScan() {
      this.busy = true;
      try {
        await this.api('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ path: this.scanPath, include_dev: false }),
        });
        this.show('overview');
      } catch { this.markError(); }
      this.busy = false;
    },

    async triggerDemoGuard() {
      this.busy = true;
      try {
        await this.api('/api/guard', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ path: 'fixtures/diffs/add_lodos_v3.diff' }),
        });
      } catch { this.markError(); }
      this.busy = false;
    },

    connectSse() {
      if (this.es) this.es.close();
      this.es = new EventSource('/api/events');
      this.es.onopen = () => { this.connState = 'on'; this.connLabel = 'SSE 已连接'; this.retry = 0; };
      this.es.onerror = () => {
        this.connState = 'off';
        this.connLabel = '连接断开';
        // Exponential backoff, capped at 5s (PROMPT 6.1.4).
        const delay = Math.min(5000, 500 * 2 ** this.retry);
        this.retry += 1;
        setTimeout(() => this.connectSse(), delay);
      };
      const refreshOn = (handler) => (event) => {
        handler(JSON.parse(event.data || '{}'));
        clearTimeout(this._debounce);
        this._debounce = setTimeout(() => this.refreshAll(), 150);
      };
      this.es.addEventListener('scan_progress', refreshOn(() => {}));
      this.es.addEventListener('guard_verdict', refreshOn(() => {}));
      this.es.addEventListener('scan_completed', refreshOn(() => {}));
      this.es.addEventListener('audit_appended', refreshOn(() => {}));
    },

    markError() {
      this.connLabel = '数据加载失败（可重试）';
    },

    riskCards() {
      const s = this.summary || {};
      return [
        { label: 'critical', value: s.critical || 0, cls: 'critical' },
        { label: 'high', value: s.high || 0, cls: 'high' },
        { label: 'medium', value: s.medium || 0, cls: 'medium' },
        { label: 'low', value: s.low || 0, cls: 'low' },
        { label: 'sessions', value: s.total_sessions || 0, cls: '' },
      ];
    },

    riskCls(level) { return level || ''; },
    verdictCls(verdict) { return verdict || ''; },

    renderChart() {
      const el = document.getElementById('chart-risk');
      if (!el || typeof echarts === 'undefined') return;
      if (!this.chart) {
        this.chart = echarts.init(el, null, { renderer: 'canvas' });
        window.addEventListener('resize', () => this.chart && this.chart.resize());
      }
      const s = this.summary || {};
      const tokens = getComputedStyle(document.documentElement);
      const color = (name) => tokens.getPropertyValue(name).trim() || '#4f8cff';
      this.chart.setOption({
        backgroundColor: 'transparent',
        textStyle: { color: color('--text-2'), fontFamily: 'inherit' },
        tooltip: { trigger: 'item' },
        series: [{
          type: 'pie',
          radius: ['52%', '78%'],
          itemStyle: { borderColor: color('--bg-1'), borderWidth: 2, borderRadius: 6 },
          label: { color: color('--text-2') },
          data: [
            { name: 'critical', value: s.critical || 0, itemStyle: { color: color('--critical') } },
            { name: 'high', value: s.high || 0, itemStyle: { color: color('--danger') } },
            { name: 'medium', value: s.medium || 0, itemStyle: { color: color('--warn') } },
            { name: 'low', value: s.low || 0, itemStyle: { color: color('--ok') } },
          ].filter((d) => d.value > 0),
        }],
      });
    },
  };
}

// Register the Alpine component before Alpine boots (script is type=module,
// Alpine is deferred classic — module executes first).
document.addEventListener('alpine:init', () => {
  window.Alpine.data('console', consoleComponent);
});
window.consoleComponent = consoleComponent;
