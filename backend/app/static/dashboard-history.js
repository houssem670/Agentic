/* Load AFTER dashboard.js and dashboard-charts.js (all with defer).
   Adds the "Report archive" list to the Reports page. Real data only. */

function riskBadge(level) {
  const name = level || 'Not recorded';
  return `<span class="risk-badge ${riskClass(level)}">${escapeHtml(name)}</span>`;
}

function renderReportArchive(panel, reports) {
  if (!reports.length) {
    panel.innerHTML = '<p class="archive-empty">No report has been archived yet.</p>';
    return;
  }
  const rows = reports.map((report) => `
    <tr data-report-id="${escapeHtml(report.id)}">
      <td>${escapeHtml(formatDate(report.generated_at))}</td>
      <td>${escapeHtml(report.file_name)}</td>
      <td>${report.record_count}</td>
      <td>${riskBadge(report.highest_risk)}</td>
      <td>${escapeHtml(provenanceDisplay(report.data_provenance)[0])}</td>
      <td class="archive-actions">
        <button type="button" class="button button-secondary" data-open="${escapeHtml(report.id)}">Open</button>
        <button type="button" class="button button-secondary" data-download="${escapeHtml(report.id)}">Download</button>
      </td>
    </tr>`).join('');
  panel.innerHTML = `
    <div class="archive-head">
      <div><p class="eyebrow">REPORT ARCHIVE</p><h3>All reports <span class="count-pill">${reports.length}</span></h3></div>
      <span class="panel-meta">Newest first</span>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th scope="col">Generated</th><th scope="col">File</th><th scope="col">Records</th><th scope="col">Highest risk</th><th scope="col">Source</th><th scope="col">Actions</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
  panel.querySelectorAll('[data-open]').forEach((button) =>
    button.addEventListener('click', () => openArchivedReport(button.dataset.open)));
  panel.querySelectorAll('[data-download]').forEach((button) =>
    button.addEventListener('click', () => {
      window.location.assign(`/api/report/download?id=${encodeURIComponent(button.dataset.download)}`);
    }));
}

async function openArchivedReport(id) {
  try {
    const response = await fetch(`/api/report?id=${encodeURIComponent(id)}`);
    if (!response.ok) throw new Error('This report could not be loaded.');
    const report = await response.json();
    $('report-content').innerHTML = report.html;
    $('report-content').classList.remove('hidden');
    $('report-empty').classList.add('hidden');
    $('report-meta').textContent = `Viewing archived report: ${formatDate(report.generated_at)} · ${report.record_count} record${report.record_count === 1 ? '' : 's'}`;
    document.querySelectorAll('#report-archive tr[data-report-id]').forEach((row) =>
      row.classList.toggle('active-row', row.dataset.reportId === id));
    $('report-content').scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (error) {
    $('global-error').textContent = error.message;
    $('global-error').classList.remove('hidden');
  }
}

async function loadReportArchive() {
  if (!$('report')) return;
  let panel = $('report-archive');
  if (!panel) {
    panel = document.createElement('div');
    panel.id = 'report-archive';
    panel.className = 'report-archive';
    $('report-loading').before(panel);
  }
  try {
    const response = await fetch('/api/reports');
    if (!response.ok) throw new Error('The report list is unavailable.');
    const payload = await response.json();
    renderReportArchive(panel, payload.reports || []);
  } catch (error) {
    panel.innerHTML = `<p class="archive-empty">${escapeHtml(error.message)}</p>`;
  }
}

const footerStamp = $('footer-updated');
if (footerStamp) {
  new MutationObserver(loadReportArchive)
    .observe(footerStamp, { childList: true, characterData: true, subtree: true });
}
loadReportArchive();