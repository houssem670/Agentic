const $ = (id) => document.getElementById(id);
let events = [];
let latestRecord = null;
let sortKey = 'timestamp';
let sortDirection = 'desc';
let currentPage = 1;
const PAGE_SIZE = 10;
const THEME_STORAGE_KEY = 'autosentinel-ai-theme';
const SIDEBAR_STORAGE_KEY = 'can-security-sidebar-collapsed';
let hasSidebarPreference = false;

function setTheme(theme, persist = true) {
  const dark = theme === 'dark';
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
  const toggle = $('theme-toggle');
  toggle.setAttribute('aria-pressed', String(dark));
  toggle.setAttribute('aria-label', `Switch to ${dark ? 'light' : 'dark'} theme`);
  toggle.title = `Switch to ${dark ? 'light' : 'dark'} theme`;
  toggle.querySelector('svg').innerHTML = dark
    ? '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.93 4.93l1.41 1.41m11.32 11.32 1.41 1.41M2 12h2m16 0h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/>'
    : '<path d="M20.5 15.5A8.5 8.5 0 0 1 8.5 3.5 8.5 8.5 0 1 0 20.5 15.5Z"/>';
  document.querySelector('meta[name="theme-color"]').content = dark ? '#0B1120' : '#F5F7FA';
  if (persist) {
    try { localStorage.setItem(THEME_STORAGE_KEY, dark ? 'dark' : 'light'); } catch {}
  }
}

function setSidebarCollapsed(collapsed, persist = true) {
  document.body.classList.toggle('sidebar-collapsed', collapsed);
  document.body.classList.toggle('sidebar-expanded', !collapsed && matchMedia('(max-width: 1023px)').matches);
  const toggle = $('sidebar-toggle');
  toggle.setAttribute('aria-expanded', String(!collapsed));
  toggle.setAttribute('aria-label', `${collapsed ? 'Expand' : 'Collapse'} sidebar`);
  toggle.title = `${collapsed ? 'Expand' : 'Collapse'} sidebar`;
  const label = toggle.querySelector('span');
  if (label) label.textContent = `${collapsed ? 'Expand' : 'Collapse'} sidebar`;
  if (persist) {
    hasSidebarPreference = true;
    try { localStorage.setItem(SIDEBAR_STORAGE_KEY, String(collapsed)); } catch {}
  }
}

function updateFilterStates() {
  document.querySelectorAll('.filters select, .filters input').forEach((control) => {
    control.classList.toggle('filter-active', Boolean(control.value));
  });
}

const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const formatDate = (value, withTime = true) => {
  if (!value) return 'Not available';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, withTime ? {dateStyle:'medium',timeStyle:'short',timeZone:'UTC'} : {month:'short',day:'numeric',timeZone:'UTC'}).format(date) + (withTime ? ' UTC' : '');
};
const shortValue = (value, fallback = 'Not recorded') => value && value !== 'Unknown' ? value : fallback;
const showList = (id, items) => {
  const list = $(id);
  list.replaceChildren();
  if (!items?.length) {
    const empty = document.createElement('li');
    empty.className = 'list-empty';
    empty.textContent = 'Not recorded';
    list.append(empty);
    return;
  }
  items.forEach((item) => { const li = document.createElement('li'); li.textContent = item; list.append(li); });
};
const riskClass = (risk) => String(risk || 'unknown').toLowerCase();
const provenanceDisplay = (provenance) => ({
  LIVE_CAPTURE: ['Live CAN capture', 'live'],
  SYNTHETIC_TEST_FIXTURE: ['Synthetic test data', 'synthetic'],
  MIXED: ['Mixed report sources', 'mixed'],
  UNSPECIFIED: ['Source not verified', 'unspecified'],
}[provenance] || ['Source not verified', 'unspecified']);

function renderBarChart(targetId, values) {
  const target = $(targetId);
  target.replaceChildren();
  const entries = Object.entries(values || {}).sort((a, b) => b[1] - a[1]);
  if (!entries.length) {
    target.innerHTML = '<div class="timeline-empty">No event type data in available reports.</div>';
    return;
  }
  const palette = ['#2F7BFF', '#22D3EE', '#22C55E', '#FACC15', '#F97316', '#A78BFA'];
  const total = entries.reduce((sum, [, count]) => sum + count, 0);
  let angle = 0;
  const stops = entries.map(([, count], i) => {
    const start = angle;
    angle += (count / total) * 360;
    return `${palette[i % palette.length]} ${start}deg ${angle}deg`;
  });
  const wrap = document.createElement('div');
  wrap.className = 'donut-wrap';
  const donut = document.createElement('div');
  donut.className = 'donut';
  donut.style.background = `conic-gradient(${stops.join(',')})`;
  donut.innerHTML = `<div class="donut-center"><strong>${total}</strong><span>total records</span></div>`;
  const legend = document.createElement('ul');
  legend.className = 'donut-legend';
  entries.forEach(([label, count], i) => {
    const li = document.createElement('li');
    li.innerHTML = `<i style="background:${palette[i % palette.length]}"></i><span>${escapeHtml(label)}</span><span class="pct">${Math.round(count / total * 100)}%</span><strong>${count}</strong>`;
    legend.append(li);
  });
  wrap.append(donut, legend);
  target.append(wrap);
}

function renderRiskChart(values) {
  const target = $('risk-chart');
  target.replaceChildren();
  const order = ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'];
  const entries = order.filter((name) => values?.[name]).map((name) => [name, values[name]]);
  const total = entries.reduce((sum, [, count]) => sum + count, 0);
  if (!total) {
    target.innerHTML = '<p class="risk-empty">Risk levels are not available in the current report records.</p>';
    return;
  }
  const maximum = Math.max(...entries.map(([, count]) => count), 1);
  entries.forEach(([name,count]) => {
    const row = document.createElement('div');
    row.className = 'risk-row';
    const label = document.createElement('span');
    label.className = 'risk-label';
    label.textContent = name;
    const track = document.createElement('span');
    track.className = 'risk-track';
    const fill = document.createElement('span');
    fill.className = `risk-fill ${name.toLowerCase()}`;
    fill.style.width = `${count / maximum * 100}%`;
    track.append(fill);
    const value = document.createElement('strong');
    value.className = 'risk-value';
    value.textContent = count;
    row.append(label, track, value);
    target.append(row);
  });
}

function renderTimeline(historyAvailable) {
  const target = $('timeline-chart');
  target.replaceChildren();
  if (!historyAvailable) {
    target.innerHTML = '<div class="timeline-empty">Historical event storage is not available. Trend analysis is not derived from a single report.</div>';
    $('timeline-meta').textContent = 'History unavailable';
    return;
  }
  const dated = events.map((event) => ({date:new Date(event.timestamp), event})).filter(({date}) => !Number.isNaN(date.getTime()));
  if (!dated.length) {
    target.innerHTML = '<div class="timeline-empty">No event timestamps are available for a time series.</div>';
    $('timeline-meta').textContent = 'No timestamps';
    return;
  }
  const counts = new Map();
  dated.forEach(({date}) => { const key = date.toISOString().slice(0,10); counts.set(key,(counts.get(key)||0)+1); });
  const points = [...counts.entries()].sort(([a],[b]) => a.localeCompare(b)).slice(-12);
  const max = Math.max(...points.map(([,count]) => count),1);
  points.forEach(([date,count]) => {
    const bar = document.createElement('div'); bar.className = 'timeline-bar';
    bar.style.height = `${Math.max(8,count/max*100)}%`; bar.title = `${date}: ${count} event${count === 1 ? '' : 's'}`;
    bar.innerHTML = `<span>${escapeHtml(date.slice(5))}</span>`;
    target.append(bar);
  });
  $('timeline-meta').textContent = `${dated.length} dated record${dated.length === 1 ? '' : 's'}`;
}

function filteredEvents() {
  const type = $('type-filter').value;
  const risk = $('risk-filter').value;
  const date = $('date-filter').value;
  const search = $('search-filter').value.trim().toLowerCase();
  return events.filter((event) => {
    const haystack = [event.event_id,event.scenario_id,event.timestamp,event.can_id,event.detection_rule,event.event_type,event.attack_type,event.data_provenance,event.evidence?.join(' '),event.security?.summary].join(' ').toLowerCase();
    return (!type || (event.attack_type || event.event_type) === type)
      && (!risk || event.security?.risk_level === risk)
      && (!date || (event.timestamp && event.timestamp.slice(0,10) >= date))
      && (!search || haystack.includes(search));
  });
}

function classificationFor(event) {
  if (event.anomaly !== true) return event.anomaly === false ? 'No anomaly flagged' : 'Status not recorded';
  return event.attack_type === 'REPLAY_SUSPECTED' ? 'Replay suspicion' : 'Anomaly detected';
}

function updateSortControls() {
  document.querySelectorAll('.sort-button').forEach((button) => {
    const active = button.dataset.sort === sortKey;
    button.setAttribute('aria-pressed', String(active));
    button.querySelector('span').textContent = active ? (sortDirection === 'asc' ? '↑' : '↓') : '↕';
    button.closest('th').setAttribute('aria-sort', active ? (sortDirection === 'asc' ? 'ascending' : 'descending') : 'none');
  });
}

function renderEvents() {
  const body = $('event-rows'); body.replaceChildren();
  const filtered = filteredEvents();
  const riskRank = {UNKNOWN:0,LOW:1,MEDIUM:2,HIGH:3,CRITICAL:4};
  const valueFor = (event) => {
    if (sortKey === 'timestamp') return Date.parse(event.timestamp || '') || 0;
    if (sortKey === 'attack_type') return event.attack_type || event.event_type || '';
    if (sortKey === 'message_count') return event.message_count ?? -1;
    if (sortKey === 'risk_level') return riskRank[event.security?.risk_level] ?? -1;
    return event[sortKey] || '';
  };
  filtered.sort((left, right) => {
    const leftValue = valueFor(left);
    const rightValue = valueFor(right);
    const order = typeof leftValue === 'number' && typeof rightValue === 'number'
      ? leftValue - rightValue
      : String(leftValue).localeCompare(String(rightValue), undefined, {numeric:true,sensitivity:'base'});
    return order * (sortDirection === 'asc' ? 1 : -1);
  });
  const pageCount = Math.ceil(filtered.length / PAGE_SIZE);
  currentPage = Math.min(currentPage, Math.max(pageCount, 1));
  const start = (currentPage - 1) * PAGE_SIZE;
  const visibleEvents = filtered.slice(start, start + PAGE_SIZE);
  $('events-pagination').hidden = filtered.length <= PAGE_SIZE;
  $('page-summary').textContent = filtered.length
    ? `Showing ${start + 1}-${Math.min(start + PAGE_SIZE, filtered.length)} of ${filtered.length} events`
    : 'Showing 0 events';
  $('previous-page').disabled = currentPage <= 1;
  $('next-page').disabled = currentPage >= pageCount;
  updateSortControls();
  $('event-count').textContent = filtered.length;
  $('events-empty').classList.toggle('hidden', events.length !== 0);
  $('events-filtered').classList.toggle('hidden', events.length === 0 || filtered.length !== 0);
  updateFilterStates();
  visibleEvents.forEach((event) => {
    const row = document.createElement('tr');
    const observed = event.message_count == null ? 'Not recorded' : `${event.message_count} frames${event.observed_rate == null ? '' : ` / ${event.observed_rate} msg/s`}`;
    const evidence = event.evidence?.[0] || event.security?.summary || 'No detector evidence recorded';
    const classification = classificationFor(event);
    const classificationStyle = classification === 'Replay suspicion' ? 'suspicion' : event.anomaly === true ? 'anomaly' : 'normal';
    row.innerHTML = `<td><div class="event-id">${escapeHtml(event.event_id)}</div><div class="event-time">${escapeHtml(formatDate(event.timestamp))}</div></td><td class="can-id">${escapeHtml(shortValue(event.can_id))}</td><td class="rule-cell">${escapeHtml(shortValue(event.detection_rule))}</td><td class="classification-cell"><span class="classification-pill ${classificationStyle}">${escapeHtml(classification)}</span><small>${escapeHtml(shortValue(event.attack_type || event.event_type))}</small></td><td class="rate-cell">${escapeHtml(observed)}</td><td><span class="risk-badge ${riskClass(event.security?.risk_level)}">${escapeHtml(event.security?.risk_level || 'Not recorded')}</span></td><td class="evidence-cell" title="${escapeHtml(evidence)}">${escapeHtml(evidence)}</td>`;
    row.addEventListener('click', () => openEvent(event));
    row.addEventListener('keydown', (keyEvent) => {
      if (keyEvent.key === 'Enter' || keyEvent.key === ' ') {
        keyEvent.preventDefault();
        openEvent(event);
      }
    });
    row.tabIndex = 0; row.setAttribute('aria-label', `Open security event ${event.event_id}`);
    body.append(row);
  });
}

function fillFilter(selectId, values, label) {
  const select = $(selectId); const current = select.value;
  select.replaceChildren(new Option(label,''));
  [...values].sort().forEach((value) => select.add(new Option(value,value)));
  if ([...select.options].some((option) => option.value === current)) select.value = current;
}

function setAgentPanels(record) {
  const security = record?.security;
  const diagnostic = record?.diagnostic;
  $('security-risk').textContent = security?.risk_level || 'Not recorded';
  $('security-risk').className = `risk-badge ${riskClass(security?.risk_level)}`;
  $('security-summary').textContent = security?.summary || 'No security assessment is available in the latest report.';
  showList('security-evidence', security?.observed_facts?.length ? security.observed_facts : record?.evidence);
  showList('security-unknowns', security?.unknowns);
  showList('security-recommendations', security?.investigation_steps);
  $('diagnostic-summary').textContent = diagnostic?.summary || 'No diagnostic findings are available in the latest report.';
  $('diagnostic-method').textContent = shortValue(diagnostic?.analysis_method);
  $('diagnostic-confidence').textContent = diagnostic?.confidence == null ? 'Not available' : `${Math.round(diagnostic.confidence * 100)}%`;
  $('root-cause').textContent = diagnostic?.root_cause_confirmed == null ? 'Root cause: not recorded' : `Root cause: ${diagnostic.root_cause_confirmed ? 'confirmed' : 'not confirmed'}`;
  showList('diagnostic-unknowns', diagnostic?.unknowns);
  showList('diagnostic-checks', diagnostic?.recommended_checks);
  renderAgentTrace(record?.agent_trace || []);
  const errors = record?.execution_errors || [];
  $('execution-errors').textContent = errors.length ? `Recorded execution errors: ${errors.join(' · ')}` : '';
  $('execution-errors').classList.toggle('hidden', errors.length === 0);
}

function renderAgentTrace(trace) {
  const target = $('workflow-trace');
  target.replaceChildren();
  const hasTrace = Array.isArray(trace) && trace.length > 0;
  $('workflow-empty').classList.toggle('hidden', hasTrace);
  const failed = trace.some((entry) => entry.status === 'failed');
  const fallback = trace.some((entry) => entry.status === 'fallback');
  const workflowState = $('workflow-state');
  workflowState.textContent = !hasTrace
    ? 'Trace unavailable'
    : failed ? 'Execution error recorded' : fallback ? 'Fallback recorded' : 'All stages recorded';
  workflowState.className = `status-badge ${!hasTrace ? 'neutral' : failed ? 'failed' : fallback ? 'fallback' : 'completed'}`;
  document.querySelectorAll('.workflow-node').forEach((node) => {
  const name = node.textContent.split('\n')[0].trim().toLowerCase().split(' ')[0];
  const match = trace.find((entry) => String(entry.agent || '').toLowerCase().includes(name));
  node.dataset.state = match?.status || '';
  node.querySelector('small')?.remove();
  if (match) node.insertAdjacentHTML('beforeend', `<small>${escapeHtml(match.status)}</small>`);
  });
  trace.forEach((entry) => {
    const item = document.createElement('li');
    item.className = 'trace-row';
    const agent = document.createElement('span');
    agent.className = 'trace-agent';
    agent.textContent = entry.agent || 'Unknown stage';
    const status = document.createElement('span');
    status.className = `status-badge ${entry.status || 'neutral'}`;
    status.textContent = entry.status || 'Not recorded';
    const duration = document.createElement('span');
    duration.className = 'trace-duration';
    duration.textContent = Number.isFinite(entry.duration_ms)
      ? `${entry.duration_ms.toFixed(3)} ms`
      : 'Duration not recorded';
    const error = document.createElement('span');
    error.className = 'trace-error';
    error.textContent = entry.error_type ? `Error type: ${entry.error_type}` : 'No error recorded';
    item.append(agent, status, duration, error);
    target.append(item);
  });
}

function openEvent(event) {
  const details = [
    ['Event ID',event.event_id],['Scenario ID',event.scenario_id],['Data provenance',event.data_provenance],['Event timestamp',event.timestamp],['CAN ID',event.can_id],['CAN interface',event.channel],['Detection rule',event.detection_rule],['Detector label',event.attack_type],['Event type',event.event_type],['Message count',event.message_count],['Observation duration (s)',event.window_seconds],['Observed rate (messages/s)',event.observed_rate],['Detector threshold',event.threshold],['Anomaly flagged',event.anomaly],['Assessed risk',event.security?.risk_level],['Diagnostic method',event.diagnostic?.analysis_method],['Root cause confirmed',event.diagnostic?.root_cause_confirmed]
  ];
  const content = $('dialog-content'); content.replaceChildren();
  const classification = document.createElement('div');
  classification.className = `classification-banner ${event.anomaly === true ? 'detected' : 'unconfirmed'}`;
  classification.innerHTML = `<strong>${escapeHtml(classificationFor(event))}</strong><span>Detection evidence does not confirm malicious activity or an attack.</span>`;
  content.append(classification);
  const section = document.createElement('section'); section.className = 'dialog-section';
  const dl = document.createElement('dl');
  details.forEach(([label,value]) => {if (value == null || value === '') return; const div=document.createElement('div'); div.innerHTML=`<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd>`; dl.append(div);});
  section.append(dl); content.append(section);
  [['Detector evidence',event.evidence],['Security summary',[event.security?.summary,event.security?.interpretation].filter(Boolean)],['Security uncertainties',event.security?.unknowns],['Investigation steps',event.security?.investigation_steps],['Diagnostic findings',[event.diagnostic?.summary].filter(Boolean)],['Diagnostic unknowns',event.diagnostic?.unknowns],['Recommended diagnostic checks',event.diagnostic?.recommended_checks]].forEach(([title,items]) => {
    if (!items?.length) return;
    const block=document.createElement('section'); block.className='dialog-section';
    const heading=document.createElement('h3'); heading.textContent=title; block.append(heading);
    const ul=document.createElement('ul'); items.forEach((item)=>{const li=document.createElement('li');li.textContent=item;ul.append(li);}); block.append(ul); content.append(block);
  });
  $('dialog-title').textContent = event.event_id || 'Security event';
  $('event-dialog').showModal();
}



function renderRecentEvents() {
  const list = $('recent-events');
  list.replaceChildren();
  if (!events.length) {
    list.innerHTML = '<li class="list-empty">No events recorded.</li>';
    return;
  }
  events.slice(0, 5).forEach((event) => {
    const li = document.createElement('li');
    const risk = event.security?.risk_level || 'Not recorded';
    const rate = event.observed_rate == null ? 'rate not recorded' : `${event.observed_rate} msg/s`;
    li.innerHTML = `<span class="risk-badge ${riskClass(event.security?.risk_level)}">${escapeHtml(risk)}</span>
      <div><strong>${escapeHtml(classificationFor(event))}</strong>
      <small>${escapeHtml(shortValue(event.can_id))} · ${escapeHtml(formatDate(event.timestamp))} · ${escapeHtml(rate)}</small></div>`;
    li.tabIndex = 0;
    li.addEventListener('click', () => openEvent(event));
    li.addEventListener('keydown', (e) => { if (e.key === 'Enter') openEvent(event); });
    list.append(li);
  });
}

function renderSystemStatus(health, report) {
  const rows = [
    ['Backend API', health.status === 'ok' ? ['OK', 'ok'] : ['Unavailable', 'bad']],
    ['Report file', report.available ? ['Found', 'ok'] : ['Missing', 'bad']],
    ['Report parser', health.invalid_report_blocks ? [`${health.invalid_report_blocks} malformed`, 'warn'] : ['No errors', 'ok']],
    ['Event history', health.history_available === true ? ['Available', 'ok'] : ['Not persisted', 'warn']],
  ];
  const list = $('system-status');
  list.replaceChildren();
  rows.forEach(([name, [label, state]]) => {
    const li = document.createElement('li');
    li.innerHTML = `<span>${escapeHtml(name)}</span><span class="sys-pill ${state}">${escapeHtml(label)}</span>`;
    list.append(li);
  });
}
async function refreshDashboard() {
  $('connection-label').textContent = 'Refreshing local data';
  $('global-error').classList.add('hidden');
  $('report-loading').classList.remove('hidden');
  $('report-empty').classList.add('hidden');
  const initialLoad = $('stat-events').textContent === '—';
  $('overview').setAttribute('aria-busy', String(initialLoad));
  $('events-loading').classList.toggle('hidden', !initialLoad);
  try {
    const [summaryResponse, eventsResponse, reportResponse, healthResponse] = await Promise.all([
      fetch('/api/summary'), fetch('/api/events'), fetch('/api/reports/latest'), fetch('/api/health')
    ]);
    if (![summaryResponse,eventsResponse,reportResponse,healthResponse].every((response) => response.ok)) throw new Error('The local dashboard API returned an error.');
    const [summary, eventPayload, report, health] = await Promise.all([summaryResponse.json(),eventsResponse.json(),reportResponse.json(),healthResponse.json()]);
    events = (eventPayload.events || []).sort((left, right) => (Date.parse(right.timestamp || '') || 0) - (Date.parse(left.timestamp || '') || 0));
    latestRecord = events[0] || null;
    $('stat-events').textContent = summary.total_security_events;
    $('stat-anomalies').textContent = events.filter((event) => event.anomaly === true).length;
    $('stat-frames').textContent = 'Not recorded';
    $('stat-active-alerts').textContent = 'Not tracked';
    $('scope-note').textContent = summary.statistics_scope;
    $('latest-summary').textContent = latestRecord?.security?.summary || 'No security assessment is recorded for the latest event.';
    const summarySource = provenanceDisplay(summary.data_provenance || 'UNSPECIFIED')[0];
    $('summary-provenance').textContent = summarySource;
    $('analysis-timestamp').textContent = formatDate(summary.latest_analysis_timestamp);
    $('last-analysis').textContent = formatDate(summary.latest_analysis_timestamp);
    $('event-type-total').textContent = `${events.length} record${events.length === 1 ? '' : 's'}`;
    renderBarChart('type-chart',summary.event_types);
    renderRiskChart(summary.risk_levels);
    renderTimeline(summary.history_available === true);
    fillFilter('type-filter',new Set(events.map((event)=>event.attack_type || event.event_type).filter(Boolean)),'All event types');
    fillFilter('risk-filter',new Set(events.map((event)=>event.security?.risk_level).filter(Boolean)),'All risk levels');
    renderEvents();
    $('overview').setAttribute('aria-busy', 'false');
    $('events-loading').classList.add('hidden');
    setAgentPanels(latestRecord);
    renderRecentEvents();
    renderSystemStatus(health, report);
    const freshness = report.freshness?.state || 'unknown';
    const [provenanceLabel, provenanceClass] = provenanceDisplay(
      report.data_provenance || health.data_provenance || 'UNSPECIFIED'
    );
    const provenanceBadge = $('data-provenance');
    provenanceBadge.textContent = provenanceLabel;
    provenanceBadge.className = `provenance-badge ${provenanceClass}`;
    provenanceBadge.title = provenanceClass === 'live'
      ? 'The report records were marked as generated from a CAN capture.'
      : provenanceClass === 'synthetic'
        ? 'Synthetic fixture data; this is not evidence of a live CAN capture.'
        : 'The source of the report records is not verified as a live capture.';
      $('rail-provenance').textContent = provenanceLabel;
    const freshnessBadge = $('report-freshness');
    freshnessBadge.className = `freshness-badge ${freshness}`;
    const ageHours = report.freshness?.age_hours;
    freshnessBadge.textContent = freshness === 'stale'
      ? `STALE · ${ageHours >= 24 ? `${Math.floor(ageHours / 24)}d old` : `${ageHours}h old`}`
      : freshness === 'current' ? 'CURRENT · within 24h' : 'FRESHNESS UNKNOWN';
    freshnessBadge.title = freshness === 'stale'
      ? `Report age: approximately ${ageHours} hours since generation.`
      : freshness === 'current' ? 'Report generated within the last 24 hours.' : 'Report generation time is unavailable.';
    const topFreshnessBadge = $('top-report-freshness');
    topFreshnessBadge.className = `freshness-badge ${freshness} top-report-freshness`;
    topFreshnessBadge.textContent = freshness === 'stale'
      ? `Stale · ${ageHours >= 24 ? `${Math.floor(ageHours / 24)}d` : `${ageHours}h`}`
      : freshness === 'current' ? 'Fresh' : 'Freshness unknown';
    topFreshnessBadge.title = freshnessBadge.title;
    $('report-status').textContent = !report.available ? 'No report' : freshness === 'stale' ? 'Stale report' : freshness === 'current' ? 'Report available' : 'Age unknown';
    $('report-status').className = `status-badge ${freshness === 'stale' ? 'status-stale' : freshness === 'current' ? 'status-current' : ''} ${!report.available ? 'status-missing' : ''}`;
    $('report-record-count').textContent = report.record_count;
    $('report-meta').textContent = report.available ? `Last available generation: ${formatDate(report.generated_at)} · ${report.record_count} report record${report.record_count === 1 ? '' : 's'}` : 'No report is currently available.';
    $('report-loading').classList.add('hidden');
    $('report-empty').classList.toggle('hidden',report.available);
    $('report-content').classList.toggle('hidden',!report.available);
    $('report-content').innerHTML = report.available ? report.html : '';
    $('report-download').disabled = !report.available;
    const apiHealthy = health.status === 'ok';
    $('health-indicator').className = `health-indicator ${apiHealthy ? 'healthy' : 'failed'}`;
    $('connection-label').textContent = apiHealthy ? 'Backend online' : 'Backend unavailable';
    $('footer-updated').textContent = `Refreshed ${new Intl.DateTimeFormat(undefined,{timeStyle:'short'}).format(new Date())}`;
    if (health.invalid_report_blocks) $('global-error').textContent = `${health.invalid_report_blocks} malformed report block${health.invalid_report_blocks === 1 ? '' : 's'} omitted from statistics.`;
    $('global-error').classList.toggle('hidden',!health.invalid_report_blocks);
  } catch (error) {
    $('connection-label').textContent = 'Local data unavailable';
    $('health-indicator').className = 'health-indicator failed';
    $('data-provenance').textContent = 'Source unverified';
    $('data-provenance').className = 'provenance-badge unspecified';
    $('rail-provenance').textContent = 'Source unverified';
    $('top-report-freshness').className = 'freshness-badge unknown';
    $('top-report-freshness').textContent = 'Freshness unavailable';
    $('overview').setAttribute('aria-busy', 'false');
    $('events-loading').classList.add('hidden');
    $('report-loading').classList.add('hidden');
    $('global-error').textContent = `${error.message} Confirm the Flask dashboard is running and refresh.`;
    $('global-error').classList.remove('hidden');
  }
}

['type-filter','risk-filter','date-filter','search-filter'].forEach((id) => $(id).addEventListener(id === 'search-filter' ? 'input' : 'change',() => { currentPage = 1; renderEvents(); }));
['previous-page','next-page'].forEach((id) => $(id).addEventListener('click',() => {
  currentPage += id === 'next-page' ? 1 : -1;
  renderEvents();
}));
['refresh-button','report-refresh'].forEach((id) => $(id).addEventListener('click',refreshDashboard));
['report-download'].forEach((id) => $(id).addEventListener('click',()=>{window.location.assign('/api/reports/latest/download');}));
$('dialog-close').addEventListener('click',()=>$('event-dialog').close());
$('theme-toggle').addEventListener('click',() => setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'));
$('sidebar-toggle').addEventListener('click',() => {
  const tablet = matchMedia('(max-width: 1023px)').matches;
  const collapsed = tablet
    ? !document.body.classList.contains('sidebar-expanded')
    : document.body.classList.contains('sidebar-collapsed');
  setSidebarCollapsed(!collapsed);
});
$('dialog-report')?.addEventListener('click',()=>{$('event-dialog').close();$('report').scrollIntoView({behavior:'smooth'});});
$('event-dialog').addEventListener('click',(event)=>{if(event.target === $('event-dialog')) $('event-dialog').close();});
document.querySelectorAll('.sort-button').forEach((button) => button.addEventListener('click',() => {
  const nextKey = button.dataset.sort;
  sortDirection = nextKey === sortKey ? (sortDirection === 'asc' ? 'desc' : 'asc') : (nextKey === 'timestamp' ? 'desc' : 'asc');
  sortKey = nextKey;
  currentPage = 1;
  renderEvents();
}));
const navigationLabels = {
  overview: 'Overview',
  traffic: 'CAN Traffic',
  threats: 'Threat Detection',
  workflow: 'AI Agents',
  diagnostics: 'Diagnostics',
  report: 'Reports',
};
const navigationHeadings = {
  overview: 'Security operations',
  traffic: 'CAN traffic & threat events',
  threats: 'Threat assessment',
  workflow: 'AI agent workflow',
  diagnostics: 'Diagnostic findings',
  report: 'Latest security report',
};
function activateNavigation(id) {
  document.querySelectorAll('[data-nav]').forEach((link) => {
    const active = link.dataset.nav === id;
    link.classList.toggle('active', active);
    if (active) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  });
  const label = navigationLabels[id] || navigationLabels.overview;
  $('breadcrumb-current').textContent = label;
  $('page-heading').textContent = navigationHeadings[id] || navigationHeadings.overview;
}
activateNavigation('overview');
document.querySelectorAll('[data-nav]').forEach((link) => link.addEventListener('click', () => activateNavigation(link.dataset.nav)));
let storedTheme = 'dark';
let storedSidebar = null;
try {
  storedTheme = localStorage.getItem(THEME_STORAGE_KEY) || 'dark';
  storedSidebar = localStorage.getItem(SIDEBAR_STORAGE_KEY);
} catch {}
hasSidebarPreference = storedSidebar !== null;
setTheme(storedTheme, false);
const sidebarBreakpoint = matchMedia('(max-width: 1023px)');
setSidebarCollapsed(storedSidebar === 'true' || (storedSidebar === null && sidebarBreakpoint.matches), false);
sidebarBreakpoint.addEventListener('change', (event) => {
  if (!hasSidebarPreference) setSidebarCollapsed(event.matches, false);
});
window.addEventListener('resize', () => {
  if (!hasSidebarPreference) setSidebarCollapsed(sidebarBreakpoint.matches, false);
});
if ('IntersectionObserver' in window) {
  const navObserver = new IntersectionObserver((entries) => {
    const visible = entries.filter((entry) => entry.isIntersecting).sort((left,right) => left.boundingClientRect.top - right.boundingClientRect.top)[0];
    if (!visible) return;
    activateNavigation(visible.target.id);
  },{rootMargin:'-15% 0px -70% 0px'});
  document.querySelectorAll('[data-nav]').forEach((link) => {
    const target = document.getElementById(link.dataset.nav);
    if (target) navObserver.observe(target);
  });
}
refreshDashboard();