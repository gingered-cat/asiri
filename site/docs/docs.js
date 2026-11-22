const copyButton = document.querySelector('#copy-page');
const source = document.querySelector('#markdown-source');
const status = document.querySelector('#copy-status');
copyButton.hidden = false;

// Read the published Markdown, not innerText: code fences and links must survive.
async function copyPage() {
  if (copyButton.disabled) return;
  copyButton.disabled = true;
  status.textContent = 'reading markdown…';
  try {
    const response = await fetch(source.href);
    if (!response.ok) throw new Error('Markdown request failed');
    const markdown = await response.text();
    await navigator.clipboard.writeText(markdown);
    status.textContent = 'copied. ready for your agent.';
  } catch {
    status.textContent = 'could not copy. open raw .md and copy it there.';
  } finally {
    copyButton.disabled = false;
  }
}
copyButton.addEventListener('click', copyPage);

// Mobile has the same native trees, collapsed initially to keep the article first.
// They settle closed for a frame with transitions off, so the load shows no slide.
if (matchMedia('(max-width: 760px)').matches) {
  document.body.classList.add('settling');
  document.querySelector('.nav-root').open = false;
  document.querySelector('.reading-guide > details').open = false;
  requestAnimationFrame(() => requestAnimationFrame(() => document.body.classList.remove('settling')));
}

const guideLinks = [...document.querySelectorAll('.reading-guide a')];
const headings = guideLinks.map(link => document.getElementById(decodeURIComponent(link.hash.slice(1))));
let scrollQueued = false;
const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
const guide = document.querySelector('.reading-guide');

// A hairline that grows with reading progress. CSS scroll timelines drive it
// where supported; otherwise (and under reduced motion) the scroll handler does.
const progress = document.createElement('div');
progress.className = 'read-progress';
progress.setAttribute('aria-hidden', 'true');
document.body.prepend(progress);
const cssProgress = !reduced && CSS.supports('animation-timeline: scroll()');
if (cssProgress) progress.classList.add('css-driven');
function updateProgress() {
  const max = document.documentElement.scrollHeight - innerHeight;
  progress.hidden = max < 200; // nothing to track on a short page
  if (!cssProgress) progress.style.setProperty('--read', max > 0 ? Math.min(1, scrollY / max) : 0);
}

// The guide's tint glides to the new entry instead of jumping: the new entry's
// ::before starts where the old tint is drawn and settles into place. Transform
// only, and measured before anything is written.
const motion = getComputedStyle(document.documentElement);
const ease = motion.getPropertyValue('--docs-ease').trim() || 'ease-out';
const reveal = parseFloat(motion.getPropertyValue('--docs-reveal')) || 240;
const fast = parseFloat(motion.getPropertyValue('--docs-fast')) || 160;
const glides = !reduced && typeof KeyframeEffect === 'function' && 'pseudoElement' in KeyframeEffect.prototype;
if (glides) guide.classList.add('glides');
let tint;
function box(link) {
  if (!(link.checkVisibility?.() ?? true)) return null; // inside a closed branch
  const rect = link.getBoundingClientRect();
  return rect.width && rect.height ? rect : null;
}
function drawn(link) { // where the tint is on screen, mid-glide included
  const rect = box(link);
  if (!rect) return null;
  const m = new DOMMatrixReadOnly(getComputedStyle(link, '::before').transform);
  return { x: rect.left + m.e, y: rect.top + m.f, w: rect.width * m.a, h: rect.height * m.d };
}
function glide(link, from, to) {
  tint?.cancel();
  tint = from
    ? link.animate([
      { transform: `translate(${from.x - to.left}px, ${from.y - to.top}px) scale(${from.w / to.width}, ${from.h / to.height})` },
      { transform: 'none' },
    ], { duration: reveal, easing: ease, pseudoElement: '::before' })
    : link.animate([{ opacity: 0 }, { opacity: 1 }], { duration: fast, easing: 'ease-out', pseudoElement: '::before' });
}

let lastActive = -1;
function markSection() {
  let active = 0;
  headings.forEach((heading, i) => {
    if (heading.getBoundingClientRect().top <= 120) active = i;
  });
  const to = glides && lastActive >= 0 && active !== lastActive ? box(guideLinks[active]) : null;
  const from = to && drawn(guideLinks[lastActive]);
  guideLinks.forEach((link, i) => {
    if (i === active) link.setAttribute('aria-current', 'location');
    else link.removeAttribute('aria-current');
  });
  if (to) glide(guideLinks[active], from, to);
  // Keep the current entry in view when the guide is taller than the screen.
  if (active !== lastActive && guideLinks[active] && guide.scrollHeight > guide.clientHeight) {
    guideLinks[active].scrollIntoView({ block: 'nearest', behavior: reduced ? 'auto' : 'smooth' });
  }
  lastActive = active;
  updateProgress();
  scrollQueued = false;
}

// Each section's rule is drawn in red as it arrives on screen, and again
// whenever it comes back after leaving.
if (!reduced) {
  const arrive = new IntersectionObserver((entries) => {
    for (const e of entries) e.target.classList.toggle('arrived', e.isIntersecting);
  }, { rootMargin: '0px 0px -20% 0px' });
  document.querySelectorAll('.prose h2').forEach((h) => arrive.observe(h));
}
addEventListener('resize', updateProgress, { passive: true });
addEventListener('scroll', () => {
  if (!scrollQueued) {
    scrollQueued = true;
    requestAnimationFrame(markSection);
  }
}, { passive: true });
markSection();

const dialog = document.querySelector('#commands');
const trigger = document.querySelector('#command-trigger');
const list = document.querySelector('#command-list');
const search = document.querySelector('#command-search');
const searchLabel = document.querySelector('.search-label');
const empty = document.querySelector('#command-empty');
const path = document.querySelector('#command-path');
const title = document.querySelector('#command-title');
const docs = [...document.querySelectorAll('[data-doc-link]')].map(link => ({
  key: link.dataset.key, label: link.textContent, href: link.href,
}));
const index = [...document.querySelectorAll('#search-index a')].map(link => ({
  label: link.textContent, href: link.href,
}));
let mode = 'root';
let returnFocus;
let items = [];

function close() { dialog.hidden = true; }
function navigate(href) { close(); location.assign(href); }
const root = [
  { key: 'g', label: 'go to a page', run: () => render('go') },
  { key: 'c', label: 'copy page as markdown', run: () => { close(); copyPage(); } },
  { key: '/', label: 'find a page or section', run: () => render('search') },
  { key: 'm', label: 'open raw markdown', run: () => navigate(source.href) },
];

function render(nextMode) {
  mode = nextMode;
  search.hidden = searchLabel.hidden = mode !== 'search';
  title.textContent = mode === 'go' ? 'go to a page' : mode === 'search' ? 'find in the guide' : 'commands';
  path.textContent = mode === 'go' ? 'space → g' : mode === 'search' ? '⌘ / ctrl + k' : 'space';
  if (mode === 'search') search.value = '';
  updateList();
  if (mode === 'search') search.focus();
  else list.querySelector('button')?.focus();
}

function updateList() {
  items = mode === 'root' ? root : mode === 'go'
    ? docs.map(page => ({ ...page, run: () => navigate(page.href) }))
    : index.filter(page => search.value.trim().toLowerCase().split(/\s+/).every(word => page.label.toLowerCase().includes(word)))
      .map(page => ({ ...page, run: () => navigate(page.href) }));
  list.replaceChildren();
  items.forEach((item, i) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.dataset.index = i;
    if (item.key) {
      const key = document.createElement('kbd');
      key.textContent = item.key;
      button.append(key);
    }
    const label = document.createElement('span');
    label.textContent = item.label;
    button.append(label);
    button.addEventListener('click', item.run);
    list.append(button);
  });
  empty.hidden = items.length !== 0;
}

function open(nextMode = 'root') {
  if (dialog.hidden) {
    returnFocus = document.activeElement;
    dialog.hidden = false;
    trigger.setAttribute('aria-expanded', 'true');
  }
  render(nextMode);
}
trigger.hidden = false;
trigger.setAttribute('aria-expanded', 'false');
trigger.addEventListener('click', () => open());
document.querySelector('#command-close').addEventListener('click', shut);
search.addEventListener('input', updateList);
function shut() {
  close();
  trigger.setAttribute('aria-expanded', 'false');
  (returnFocus instanceof HTMLElement ? returnFocus : trigger).focus({ preventScroll: true });
}
document.addEventListener('pointerdown', event => {
  if (dialog.hidden || dialog.contains(event.target) || trigger.contains(event.target)) return;
  shut();
});

document.addEventListener('keydown', event => {
  const editing = event.target instanceof Element && event.target.closest('input, textarea, select, [contenteditable="true"]');
  if (!dialog.hidden && event.key === 'Escape') {
    event.preventDefault();
    if (mode === 'root') shut();
    else render('root');
    return;
  }
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
    event.preventDefault();
    open('search');
    return;
  }
  if (event.metaKey || event.ctrlKey || event.altKey || event.isComposing) return;
  if (!dialog.hidden && event.key === 'Tab') {
    const controls = [...dialog.querySelectorAll('button, input')].filter(el => !el.hidden);
    const edge = event.shiftKey ? controls[0] : controls.at(-1);
    if (document.activeElement === edge) {
      event.preventDefault();
      (event.shiftKey ? controls.at(-1) : controls[0]).focus();
    }
    return;
  }
  if (dialog.hidden) {
    // Space remains native on links, buttons and disclosures; never steal typing.
    const interactive = event.target instanceof Element && event.target.closest('a, button, summary');
    if (event.key === ' ' && !event.repeat && !editing && !interactive && !getSelection()?.toString()) {
      event.preventDefault();
      open();
    }
    return;
  }
  const buttons = [...list.querySelectorAll('button')];
  const current = buttons.indexOf(document.activeElement);
  if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
    event.preventDefault();
    const next = event.key === 'ArrowDown' ? (current + 1) % buttons.length : (current <= 0 ? buttons.length - 1 : current - 1);
    buttons[next]?.focus();
  } else if (event.key === 'Enter' && document.activeElement === search) {
    event.preventDefault();
    items[0]?.run();
  } else if (!editing && event.key === 'Backspace' && mode !== 'root') {
    event.preventDefault();
    render('root');
  } else if (!editing && mode !== 'search') {
    const item = items.find(item => item.key === event.key.toLowerCase());
    if (item) {
      event.preventDefault();
      item.run();
    }
  }
});

// Star count beside github in the header (shared cache with the home page).
(async () => {
  let n = null;
  try {
    const hit = JSON.parse(sessionStorage.getItem('asiri:stars') || 'null');
    if (hit && Date.now() - hit.at < 600000) n = hit.n;
    else {
      const r = await fetch('https://api.github.com/repos/gingered-cat/asiri', { headers: { Accept: 'application/vnd.github+json' } });
      n = r.ok ? (await r.json()).stargazers_count : null;
      if (Number.isInteger(n)) sessionStorage.setItem('asiri:stars', JSON.stringify({ n, at: Date.now() }));
    }
  } catch { n = null; }
  if (!Number.isInteger(n)) return;
  for (const el of document.querySelectorAll('[data-gh-stars]')) {
    el.textContent = n.toLocaleString('en');
    el.closest('a')?.setAttribute('aria-label', `github, ${n} star${n === 1 ? '' : 's'}`);
    el.hidden = false;
  }
})();
