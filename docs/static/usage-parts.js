// Usage page: the cards at the top show one part of the page at a time.
// Without this script every part stays visible and the cards are plain
// anchor links, so the page works the same with JavaScript off.
document.addEventListener('DOMContentLoaded', () => {
  const nav = document.querySelector('.as-parts');
  const content = nav && nav.closest('.content');
  if (!content) return;

  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
  const cards = [...nav.querySelectorAll('[data-part]')];

  // The theme puts a heading's anchor id on an element inside it.
  const anchorOf = (heading) => heading.id || heading.querySelector('[id]')?.id || '';

  // What sits between the cards and the first part (the demo video) is an
  // overview: it shows with "Everything" and steps aside for a single part.
  const intro = document.createElement('div');
  intro.className = 'as-part-intro';
  nav.after(intro);
  for (let el = intro.nextElementSibling; el && el.tagName !== 'H2'; el = intro.nextElementSibling) {
    intro.append(el);
  }

  // Wrap each h2 and everything up to the next h2 in a section.
  const sections = new Map();
  let current = null;
  [...content.children].forEach((el) => {
    const id = el.tagName === 'H2' ? anchorOf(el) : '';
    if (id) {
      current = document.createElement('section');
      current.className = 'as-part-section';
      current.dataset.part = id;
      el.before(current);
      sections.set(id, current);
    }
    if (current) current.append(el);
  });

  const reveal = (els) => {
    if (reduceMotion.matches) return;
    els.forEach((el) => el.animate(
      [{ opacity: 0, transform: 'translateY(6px)' }, { opacity: 1, transform: 'none' }],
      { duration: 220, easing: 'cubic-bezier(0.23, 1, 0.32, 1)' },
    ));
  };

  let active = 'all';
  const select = (part, { animate = true } = {}) => {
    if (part !== 'all' && !sections.has(part)) part = 'all';
    const changed = part !== active;
    active = part;
    cards.forEach((card) => {
      const on = card.dataset.part === part;
      card.classList.toggle('is-active', on);
      if (on) card.setAttribute('aria-current', 'true');
      else card.removeAttribute('aria-current');
    });
    intro.hidden = part !== 'all';
    const shown = [];
    sections.forEach((section, id) => {
      const visible = part === 'all' || id === part;
      // until-found keeps hidden parts searchable with find-in-page.
      if (visible) section.removeAttribute('hidden');
      else section.setAttribute('hidden', 'until-found');
      if (visible) shown.push(section);
    });
    if (changed && animate) reveal(part === 'all' ? [] : shown);
  };

  // Keep the cards in view when switching parts from further down the page.
  const scrollToCards = () => {
    const top = nav.getBoundingClientRect().top;
    if (top < 0) nav.scrollIntoView({ behavior: reduceMotion.matches ? 'auto' : 'smooth', block: 'start' });
  };

  const partOf = (el) => el && el.closest('.as-part-section')?.dataset.part;

  // A hash names a part or something inside one: show that part and go there.
  const followHash = () => {
    const id = decodeURIComponent(location.hash.slice(1));
    const target = id && document.getElementById(id);
    if (!target) return;
    const part = sections.has(id) ? id : partOf(target);
    if (!part) return;
    select(part, { animate: false });
    requestAnimationFrame(() => target.scrollIntoView({ block: 'start' }));
  };

  cards.forEach((card) => card.addEventListener('click', (event) => {
    event.preventDefault();
    const part = card.dataset.part;
    select(part);
    history.replaceState(null, '', part === 'all' ? location.pathname : `#${part}`);
    scrollToCards();
  }));

  sections.forEach((section) => section.addEventListener('beforematch', () => {
    select(section.dataset.part, { animate: false });
  }));

  window.addEventListener('hashchange', followHash);
  select('all', { animate: false });
  followHash();
  // The browser's own jump to the fragment runs after this script, against
  // the layout where every part was still showing; redo ours once loaded.
  if (location.hash) {
    if (document.readyState === 'complete') requestAnimationFrame(followHash);
    else window.addEventListener('load', () => requestAnimationFrame(followHash), { once: true });
  }
});
