/* Load AFTER dashboard.js (and the other dashboard scripts).
   Restructures the rendered report into cards. Uses only the report's own content. */
(function () {
  const box = document.getElementById('report-content');
  if (!box) return;

  const COLORS = ['#6366F1', '#22D3EE', '#A78BFA', '#F59E0B', '#22C55E', '#EF4444', '#38BDF8'];
  const CHIPS = [
    ['Classification', ['Threat classification', 'Detector attack label']],
    ['Risk', ['Assessed risk level'], 'risk'],
    ['Detection rule', ['Detection rule']],
    ['CAN ID', ['CAN ID']],
    ['Observed rate', ['Observed rate']],
    ['Threshold', ['Detector threshold']],
    ['Confidence', ['Assessment confidence']],
    ['Source', ['Data provenance']],
  ];

  const clean = (text) => String(text || '').replace(/\s+/g, ' ').trim();

  function tableValues(root) {
    const values = {};
    root.querySelectorAll('table tr').forEach((row) => {
      const cells = row.querySelectorAll('td');
      if (cells.length >= 2) values[clean(cells[0].textContent)] = clean(cells[1].textContent);
    });
    return values;
  }

  function buildChips(values) {
    const items = CHIPS.map(([label, keys, kind]) => {
      const key = keys.find((k) => values[k]);
      if (!key) return '';
      const value = values[key];
      const shown = kind === 'risk'
        ? `<span class="risk-badge ${String(value).toLowerCase()}">${escapeHtml(value)}</span>`
        : `<strong>${escapeHtml(value)}</strong>`;
      return `<div class="report-chip"><span>${label}</span>${shown}</div>`;
    }).join('');
    const wrap = document.createElement('div');
    wrap.className = 'report-chips';
    wrap.innerHTML = items;
    return wrap;
  }

  function buildSection(section, docIndex, index) {
    const match = section.title.match(/^(\d+)\.\s*(.*)$/);
    const number = match ? match[1] : String(index + 1);
    const name = match ? match[2] : section.title;
    const details = document.createElement('details');
    details.className = 'report-section';
    details.open = true;
    details.id = `report-section-${docIndex}-${index}`;
    details.style.setProperty('--c', COLORS[index % COLORS.length]);
    const summary = document.createElement('summary');
    summary.innerHTML = `<span class="rs-num">${escapeHtml(number)}</span><span class="rs-title">${escapeHtml(name)}</span>`;
    const body = document.createElement('div');
    body.className = 'rs-body';
    section.nodes.forEach((node) => body.append(node));
    body.querySelectorAll('table').forEach((table) => {
      const holder = document.createElement('div');
      holder.className = 'table-wrap';
      table.replaceWith(holder);
      holder.append(table);
    });
    details.append(summary, body);
    return { details, name, number };
  }

  function build() {
    if (box.querySelector(':scope > .report-doc')) return;
    const nodes = Array.from(box.children);
    if (!nodes.length) return;

    const docs = [];
    let current = null;
    const startDoc = (title) => {
      current = { title, intro: [], sections: [] };
      docs.push(current);
    };
    nodes.forEach((node) => {
      if (node.tagName === 'H1') { startDoc(clean(node.textContent)); return; }
      if (node.tagName === 'HR') return;
      if (!current) startDoc('Security report');
      if (node.tagName === 'H2') {
        current.sections.push({ title: clean(node.textContent), nodes: [] });
        return;
      }
      (current.sections.length ? current.sections[current.sections.length - 1].nodes : current.intro).push(node);
    });
    if (!docs.length) return;

    const elements = docs.map((doc, docIndex) => {
      const article = document.createElement('article');
      article.className = 'report-doc';

      const probe = document.createElement('div');
      doc.sections.forEach((s) => s.nodes.forEach((n) => probe.append(n.cloneNode(true))));
      const intro = clean(doc.intro.map((n) => n.textContent).join(' '));

      const head = document.createElement('header');
      head.className = 'report-doc-head';
      head.innerHTML = `<h3>${escapeHtml(doc.title)}</h3>${intro ? `<p>${escapeHtml(intro)}</p>` : ''}`;
      article.append(head, buildChips(tableValues(probe)));

      const built = doc.sections.map((section, index) => buildSection(section, docIndex, index));

      const toc = document.createElement('nav');
      toc.className = 'report-toc';
      toc.setAttribute('aria-label', 'Report sections');
      built.forEach(({ details, name, number }) => {
        const link = document.createElement('button');
        link.type = 'button';
        link.textContent = `${number}. ${name}`;
        link.addEventListener('click', () => {
          details.open = true;
          details.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });
        toc.append(link);
      });
      const toggle = document.createElement('button');
      toggle.type = 'button';
      toggle.className = 'toc-toggle';
      toggle.textContent = 'Collapse all';
      toggle.addEventListener('click', () => {
        const open = toggle.textContent === 'Expand all';
        built.forEach(({ details }) => { details.open = open; });
        toggle.textContent = open ? 'Collapse all' : 'Expand all';
      });
      toc.append(toggle);

      article.append(toc);
      built.forEach(({ details }) => article.append(details));
      return article;
    });

    box.replaceChildren(...elements);
  }

  new MutationObserver(build).observe(box, { childList: true });
  build();
})();