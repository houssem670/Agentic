/* Load AFTER dashboard.js. Adds a button that cycles through the color palettes. */
(function () {
  const PALETTES = ['indigo', 'teal', 'graphite'];
  const KEY = 'canSentinelPalette';

  function apply(name) {
    if (name === 'indigo') document.documentElement.removeAttribute('data-palette');
    else document.documentElement.dataset.palette = name;
  }

  let current = 'indigo';
  try {
    const saved = localStorage.getItem(KEY);
    if (PALETTES.includes(saved)) current = saved;
  } catch {}
  apply(current);

  const actions = document.querySelector('.top-actions');
  if (!actions) return;
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'icon-button palette-button';
  button.innerHTML = '<span class="swatch" aria-hidden="true"></span>';
  const label = () => {
    button.title = `Color palette: ${current} (click to change)`;
    button.setAttribute('aria-label', button.title);
  };
  label();
  button.addEventListener('click', () => {
    current = PALETTES[(PALETTES.indexOf(current) + 1) % PALETTES.length];
    apply(current);
    label();
    try { localStorage.setItem(KEY, current); } catch {}
  });
  actions.append(button);
})();