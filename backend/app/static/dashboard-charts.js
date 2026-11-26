const CHART_PALETTE = ['#2F7BFF', '#22D3EE', '#A78BFA', '#FACC15', '#F97316', '#22C55E'];

function chartColorFor(name, index) {
  const key = String(name).toUpperCase();
  if (key.includes('REPLAY')) return '#EF4444';
  if (key.includes('FREQ') || key.includes('FLOOD')) return '#F97316';
  if (key.includes('NORMAL')) return '#22C55E';
  return CHART_PALETTE[index % CHART_PALETTE.length];
}

/* Event types: colored donut */
function renderBarChart(targetId, values) {
  const target = $(targetId);
  target.replaceChildren();
  const entries = Object.entries(values || {}).sort((a, b) => b[1] - a[1]);
  if (!entries.length) {
    target.innerHTML = '<div class="timeline-empty">No event type data in available reports.</div>';
    return;
  }
  const total = entries.reduce((sum, [, count]) => sum + count, 0);
  let angle = 0;
  const stops = entries.map(([name, count], i) => {
    const start = angle;
    angle += (count / total) * 360;
    return `${chartColorFor(name, i)} ${start}deg ${angle}deg`;
  });
  const wrap = document.createElement('div');
  wrap.className = 'donut-wrap';
  const donut = document.createElement('div');
  donut.className = 'donut';
  donut.style.background = `conic-gradient(${stops.join(',')})`;
  donut.innerHTML = `<div class="donut-center"><strong>${total}</strong><span>total records</span></div>`;
  const legend = document.createElement('ul');
  legend.className = 'donut-legend';
  entries.forEach(([name, count], i) => {
    const li = document.createElement('li');
    li.innerHTML = `<i style="background:${chartColorFor(name, i)}"></i><span>${escapeHtml(name)}</span><span class="pct">${Math.round(count / total * 100)}%</span><strong>${count}</strong>`;
    legend.append(li);
  });
  wrap.append(donut, legend);
  target.append(wrap);
}

/* Risk levels: vertical colored columns */
function renderRiskChart(values) {
  const target = $('risk-chart');
  target.replaceChildren();
  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
  const counts = order.map((name) => values?.[name] || 0);
  const total = counts.reduce((sum, count) => sum + count, 0);
  if (!total) {
    target.innerHTML = '<p class="risk-empty">Risk levels are not available in the current report records.</p>';
    return;
  }
  const maximum = Math.max(...counts, 1);
  const columns = document.createElement('div');
  columns.className = 'risk-columns';
  order.forEach((name, i) => {
    const count = counts[i];
    const pct = Math.round(count / total * 100);
    const col = document.createElement('div');
    col.className = 'risk-col';
    const label = name.charAt(0) + name.slice(1).toLowerCase();
    col.innerHTML = `<span class="risk-col-count">${count}</span>
      <div class="risk-col-track"><div class="risk-col-bar ${name.toLowerCase()}" style="height:${count ? Math.max(6, count / maximum * 100) : 0}%"></div></div>
      <span class="risk-col-label">${label}</span><small>${pct}%</small>`;
    columns.append(col);
  });
  target.append(columns);
}

/* Trend: SVG line chart, only with real dated history */
function renderTimeline(historyAvailable) {
  const target = $('timeline-chart');
  target.replaceChildren();
  if (!historyAvailable) {
    target.innerHTML = '<div class="timeline-empty">Historical event storage is not available. Trend analysis is not derived from a single report.</div>';
    $('timeline-meta').textContent = 'History unavailable';
    return;
  }
  const dated = events.map((event) => ({ date: new Date(event.timestamp) })).filter(({ date }) => !Number.isNaN(date.getTime()));
  if (!dated.length) {
    target.innerHTML = '<div class="timeline-empty">No event timestamps are available for a time series.</div>';
    $('timeline-meta').textContent = 'No timestamps';
    return;
  }
  const counts = new Map();
  dated.forEach(({ date }) => {
    const key = date.toISOString().slice(0, 10);
    counts.set(key, (counts.get(key) || 0) + 1);
  });
  const points = [...counts.entries()].sort(([a], [b]) => a.localeCompare(b)).slice(-12);
  $('timeline-meta').textContent = `${dated.length} dated record${dated.length === 1 ? '' : 's'}`;
  if (points.length < 2) {
    target.innerHTML = `<div class="timeline-empty">Only one day of records (${escapeHtml(points[0][0])}). A trend needs at least two days.</div>`;
    return;
  }
  const W = 640, H = 200, padL = 36, padR = 16, padT = 16, padB = 28;
  const max = Math.max(...points.map(([, count]) => count), 1);
  const x = (i) => padL + (i / (points.length - 1)) * (W - padL - padR);
  const y = (count) => padT + (1 - count / max) * (H - padT - padB);
  const line = points.map(([, count], i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(count).toFixed(1)}`).join(' ');
  const area = `${line} L${x(points.length - 1).toFixed(1)},${H - padB} L${x(0).toFixed(1)},${H - padB} Z`;
  const dots = points.map(([date, count], i) =>
    `<circle cx="${x(i).toFixed(1)}" cy="${y(count).toFixed(1)}" r="4" class="trend-dot"><title>${escapeHtml(date)}: ${count} event${count === 1 ? '' : 's'}</title></circle>`).join('');
  const labels = points.map(([date], i) =>
    `<text x="${x(i).toFixed(1)}" y="${H - 8}" text-anchor="middle" class="trend-label">${escapeHtml(date.slice(5))}</text>`).join('');
  target.innerHTML = `<svg viewBox="0 0 ${W} ${H}" class="trend-svg" role="img" aria-label="Events per day">
    <defs><linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#22D3EE" stop-opacity=".35"/><stop offset="100%" stop-color="#22D3EE" stop-opacity="0"/></linearGradient></defs>
    <line x1="${padL}" y1="${H - padB}" x2="${W - padR}" y2="${H - padB}" class="trend-axis"/>
    <text x="${padL - 8}" y="${padT + 4}" text-anchor="end" class="trend-label">${max}</text>
    <text x="${padL - 8}" y="${H - padB}" text-anchor="end" class="trend-label">0</text>
    <path d="${area}" fill="url(#trendFill)"/>
    <path d="${line}" class="trend-line" fill="none"/>
    ${dots}${labels}
  </svg>`;
}

const VIEWS = ['overview', 'traffic', 'threats', 'workflow', 'diagnostics', 'report'];
function showView() {
  const id = location.hash.slice(1);
  const view = VIEWS.includes(id) ? id : 'overview';
  document.body.dataset.view = view;
  activateNavigation(view);
  window.scrollTo({ top: 0 });
  document.querySelector('.content')?.scrollTo({ top: 0 });
}
window.addEventListener('hashchange', showView);
showView();

const _setAgentPanels = setAgentPanels;
setAgentPanels = function (record) {
  _setAgentPanels(record);
  enhancePages(record);
};

function enhancePages(record) {
  const meta = document.querySelector('.diagnostic-meta');
  if (meta) {
    let card = $('confidence-card');
    if (!card) {
      card = document.createElement('div');
      card.id = 'confidence-card';
      card.className = 'confidence-card';
      card.innerHTML = '<div class="confidence-ring"><span id="confidence-value"></span></div><div><strong>Assessment confidence</strong><small>Value reported by the diagnostic agent. It is not a measured accuracy.</small></div>';
      meta.before(card);
    }
    const c = record?.diagnostic?.confidence;
    card.hidden = c == null;
    if (c != null) {
      card.querySelector('.confidence-ring').style.setProperty('--pct', Math.round(c * 100));
      $('confidence-value').textContent = `${Math.round(c * 100)}%`;
    }
  }

  const toolbar = document.querySelector('#traffic .event-toolbar');
  if (toolbar) {
    let strip = $('traffic-summary');
    if (!strip) {
      strip = document.createElement('div');
      strip.id = 'traffic-summary';
      strip.className = 'traffic-summary';
      toolbar.before(strip);
    }
    const flagged = events.filter((e) => e.anomaly === true).length;
    const rates = events.map((e) => e.observed_rate).filter(Number.isFinite);
    const topRate = rates.length ? `${Math.max(...rates)} msg/s` : 'Not recorded';
    const ids = new Set(events.map((e) => e.can_id).filter(Boolean)).size;
    strip.innerHTML = [
      ['Events in report', events.length, '#2F7BFF'],
      ['Anomalies flagged', flagged, '#EF4444'],
      ['CAN IDs involved', ids, '#A78BFA'],
      ['Highest observed rate', topRate, '#22D3EE'],
    ].map(([label, value, color]) =>
      `<div class="mini-stat" style="--kpi:${color}"><span>${label}</span><strong>${escapeHtml(value)}</strong></div>`).join('');
  }
}

function renderAgentCards(record) {
  const panel = document.querySelector('.workflow-panel');
  if (!panel) return;
  let grid = $('agent-cards');
  if (!grid) {
    grid = document.createElement('div');
    grid.id = 'agent-cards';
    grid.className = 'agent-cards';
    panel.prepend(grid);
  }
  const trace = record?.agent_trace || [];
  const find = (key) => trace.find((t) => String(t.agent || '').toLowerCase().includes(key));
  const sec = record?.security;
  const diag = record?.diagnostic;
  const agents = [
    { key: 'security', name: 'Security Agent', color: '#2F7BFF',
      role: 'Interprets the detector evidence and assesses risk, using retrieved knowledge. Primary LLM with a local fallback.',
      facts: [['Risk level', sec?.risk_level], ['Classification', record?.attack_type], ['Assessment', sec?.summary]] },
    { key: 'diagnostic', name: 'Diagnostic Agent', color: '#22D3EE',
      role: 'Produces structured diagnostic findings and records what remains unknown.',
      facts: [['Method', diag?.analysis_method],
              ['Confidence', diag?.confidence == null ? null : `${Math.round(diag.confidence * 100)}%`],
              ['Root cause', diag?.root_cause_confirmed == null ? null : (diag.root_cause_confirmed ? 'Confirmed' : 'Not confirmed')]] },
    { key: 'report', name: 'Report Agent', color: '#A78BFA',
      role: 'Generates the Markdown security report from the available findings.',
      facts: [['Report entries', $('report-record-count')?.textContent],
              ['Freshness', $('report-freshness')?.textContent]] },
  ];
  grid.replaceChildren();
  agents.forEach((agent, i) => {
    const entry = find(agent.key);
    const status = entry?.status || 'Not recorded';
    const duration = Number.isFinite(entry?.duration_ms) ? `${entry.duration_ms.toFixed(1)} ms` : 'Not recorded';
    const facts = [...agent.facts, ['Duration', duration]].map(([label, value]) =>
      `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value == null || value === '' ? 'Not recorded' : value)}</dd></div>`).join('');
    const card = document.createElement('article');
    card.className = 'agent-card';
    card.style.setProperty('--agent', agent.color);
    card.innerHTML = `<header><span class="agent-step">${i + 1}</span><h3>${agent.name}</h3>
      <span class="status-badge ${entry?.status || 'neutral'}">${escapeHtml(status)}</span></header>
      <p class="agent-role">${agent.role}</p><dl class="agent-facts">${facts}</dl>`;
    grid.append(card);
  });
}

const _setAgentPanelsCards = setAgentPanels;
setAgentPanels = function (record) {
  _setAgentPanelsCards(record);
  renderAgentCards(record);
};

const reportCountNode = $('report-record-count');
if (reportCountNode) {
  new MutationObserver(() => renderAgentCards(latestRecord))
    .observe(reportCountNode, { childList: true, characterData: true, subtree: true });
}

function updateKpiCards() {
  const framesValue = $('stat-frames');
  const alertsValue = $('stat-active-alerts');
  if (!framesValue || !alertsValue) return;

  const counts = events.map((e) => e.message_count).filter(Number.isFinite);
  const framesCard = framesValue.closest('.stat-card');
  framesCard.classList.remove('stat-unavailable');
  framesCard.querySelector('.stat-card-head span').textContent = 'Frames in detections';
  framesValue.textContent = counts.length ? counts.reduce((a, b) => a + b, 0) : 'Not recorded';
  framesCard.querySelector('.stat-foot').textContent = 'Counted by detectors, not total bus traffic';

  const alertsCard = alertsValue.closest('.stat-card');
  alertsCard.classList.remove('stat-unavailable');
  alertsCard.querySelector('.stat-card-head span').textContent = 'High-risk events';
  alertsValue.textContent = events.filter((e) => ['HIGH', 'CRITICAL'].includes(e.security?.risk_level)).length;
  alertsCard.querySelector('.stat-foot').textContent = 'Assessed risk HIGH or CRITICAL';
}

const kpiFooter = $('footer-updated');
if (kpiFooter) {
  new MutationObserver(updateKpiCards)
    .observe(kpiFooter, { childList: true, characterData: true, subtree: true });
}