// Client-side filtering for the security-checks explorer and the check-page rail.
// Every card/row is server-rendered; this only toggles visibility, so the page
// is fully usable without JavaScript.
(function () {
  const root = document.querySelector('[data-checks-root]');
  if (!root) return;

  const search = root.querySelector('[data-filter-search]');
  const sevInputs = [...root.querySelectorAll('[data-filter-sev]')];
  const catInputs = [...root.querySelectorAll('[data-filter-cat]')];
  const items = [...root.querySelectorAll('[data-check]')];
  const groups = [...root.querySelectorAll('[data-check-group]')];
  const countEl = root.querySelector('[data-check-count]');
  const emptyEls = [...root.querySelectorAll('[data-check-empty]')];
  const clearBtns = [...document.querySelectorAll('[data-filter-clear]')];
  const syncUrl = root.hasAttribute('data-sync-url');

  const checked = (inputs) => new Set(inputs.filter((i) => i.checked).map((i) => i.value));

  function apply() {
    const terms = (search?.value || '').trim().toLowerCase().split(/\s+/).filter(Boolean);
    const sevs = checked(sevInputs);
    const cats = checked(catInputs);
    let shown = 0;

    for (const item of items) {
      const text = item.dataset.text || '';
      const visible =
        (sevs.size === 0 || sevs.has(item.dataset.severity)) &&
        (cats.size === 0 || cats.has(item.dataset.category)) &&
        terms.every((t) => text.includes(t));
      item.hidden = !visible;
      if (visible) shown += 1;
    }

    for (const group of groups) {
      const visibleInGroup = group.querySelectorAll('[data-check]:not([hidden])').length;
      group.hidden = visibleInGroup === 0;
      const groupCount = group.querySelector('[data-group-count]');
      if (groupCount) groupCount.textContent = visibleInGroup;
    }

    if (countEl) countEl.textContent = shown;
    emptyEls.forEach((el) => { el.hidden = shown !== 0; });
    const active = terms.length > 0 || sevs.size > 0 || cats.size > 0;
    clearBtns.forEach((btn) => {
      if (btn.closest('[data-check-empty]')) return;
      btn.hidden = !active;
    });

    if (syncUrl) {
      const params = new URLSearchParams();
      if (search?.value.trim()) params.set('q', search.value.trim());
      if (sevs.size) params.set('severity', [...sevs].join(','));
      if (cats.size) params.set('category', [...cats].join(','));
      const query = params.toString();
      history.replaceState(null, '', query ? `?${query}${location.hash}` : location.pathname + location.hash);
    }
  }

  function restoreFromUrl() {
    if (!syncUrl) return;
    const params = new URLSearchParams(location.search);
    if (search && params.get('q')) search.value = params.get('q');
    const sevs = new Set((params.get('severity') || '').split(',').filter(Boolean));
    const cats = new Set((params.get('category') || '').split(',').filter(Boolean));
    sevInputs.forEach((i) => { i.checked = sevs.has(i.value); });
    catInputs.forEach((i) => { i.checked = cats.has(i.value); });
  }

  function clear() {
    if (search) search.value = '';
    [...sevInputs, ...catInputs].forEach((i) => { i.checked = false; });
    apply();
    search?.focus();
  }

  search?.addEventListener('input', apply);
  search?.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      search.value = '';
      apply();
    }
  });
  [...sevInputs, ...catInputs].forEach((i) => i.addEventListener('change', apply));
  clearBtns.forEach((btn) => btn.addEventListener('click', clear));

  // Keep the current check visible in the rail.
  // Scroll only the rail's own list, never the page.
  const current = root.querySelector('.ck-rail-item.is-current');
  const list = current?.closest('.ck-rail-inner');
  if (current && list) {
    const center = () => { list.scrollTop = current.offsetTop - list.clientHeight / 2; };
    if (document.readyState === 'complete') requestAnimationFrame(center);
    else window.addEventListener('load', () => requestAnimationFrame(center), { once: true });
  }

  restoreFromUrl();
  apply();
})();
