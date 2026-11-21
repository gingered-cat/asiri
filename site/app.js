// Motion on asiri.run, after Kit Langton's published explainer-motion rules:
// quiet holds, one event at a time, short eased transitions, a red flash that
// starts instantly and fades slowly, and glyphs that change in place without
// moving the layout. Everything runs on requestAnimationFrame timestamps,
// pauses off screen, and becomes still under prefers-reduced-motion.

const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
if (!reduced) document.documentElement.classList.add("js");

const POOL = "@#%&*+=-:.";

// Run start/stop as el enters and leaves the viewport (and the tab hides).
function whenVisible(el, start, stop) {
  let onScreen = false;
  const update = () => (onScreen && !document.hidden ? start() : stop());
  new IntersectionObserver(([e]) => { onScreen = e.isIntersecting; update(); }, { threshold: 0.1 }).observe(el);
  document.addEventListener("visibilitychange", update);
}

// A loop driven by frame timestamps: fn(elapsedMs) each frame while running.
function clock(fn) {
  let raf = 0, last = null, t = 0;
  const tick = (now) => {
    if (last !== null) t += Math.min(now - last, 100); // don't jump after a pause
    last = now;
    fn(t);
    raf = requestAnimationFrame(tick);
  };
  return {
    start() { if (!raf) { last = null; raf = requestAnimationFrame(tick); } },
    stop() { cancelAnimationFrame(raf); raf = 0; },
  };
}

// Change text in place: matching glyphs stay, changed ones scramble briefly
// and settle left to right, so the width never jumps.
function decode(el, to, { from = el.textContent, stagger = 26, spin = 160 } = {}) {
  cancelAnimationFrame(el._decode);
  if (reduced) { el.textContent = to; return; }
  const len = Math.max(from.length, to.length);
  const t0 = performance.now();
  const step = (now) => {
    const t = now - t0;
    let out = "", done = true;
    for (let i = 0; i < len; i++) {
      const a = from[i] ?? " ", b = to[i] ?? "";
      if (a === b || t >= i * stagger + spin) { out += b; continue; }
      done = false;
      out += t < i * stagger ? a : POOL[(Math.floor(t / 50) + i * 7) % POOL.length];
    }
    el.textContent = out;
    if (!done) el._decode = requestAnimationFrame(step);
  };
  el._decode = requestAnimationFrame(step);
}

// Deterministic randomness, so the star layout is the same on every visit.
function seeded(seed) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let x = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    x = (x + Math.imul(x ^ (x >>> 7), 61 | x)) ^ x;
    return ((x ^ (x >>> 14)) >>> 0) / 4294967296;
  };
}

// ---- copy prompt ----
const copy = document.getElementById("copy");
copy.addEventListener("click", async () => {
  const text = document.getElementById(copy.dataset.copy).textContent.replace(/^>\s*/, "");
  let label = "copied";
  try { await navigator.clipboard.writeText(text); } catch { label = "select it"; }
  decode(copy, label);
  clearTimeout(copy._reset);
  copy._reset = setTimeout(() => decode(copy, "copy prompt"), 1600);
});

// ---- the demo: one request, the lock opens for one grant, then closes ----
const lock = document.getElementById("lock");
const SHACKLE = {
  closed: ["             ", "    ╭───╮    ", "    │   │    ", "  ┌─┴───┴─┐  "],
  lifted: ["    ╭───╮    ", "    │   │    ", "    │   │    ", "  ┌─┴───┴─┐  "],
  open:   ["    ╭───╮    ", "    │   │    ", "    │   ╵    ", "  ┌─┴─────┐  "],
};
function drawLock(state) {
  lock.innerHTML = [
    ...SHACKLE[state],
    '  │   <span class="k">•</span>   │  ',
    '  │   <span class="k">┃</span>   │  ',
    "  └───────┘  ",
  ].join("\n");
}
// The one red event: instant attack, long decay (the CSS transition only runs on the way out).
function flash(el, ms = 120) {
  el.classList.add("lit");
  setTimeout(() => el.classList.remove("lit"), ms);
}
drawLock("closed");

const lines = [...document.querySelectorAll("#log li")];
const scrubbed = document.getElementById("scrubbed");
const PLACEHOLDER = scrubbed.textContent;
const fakeSecret = () => Array.from(PLACEHOLDER, (_, i) => POOL[(i * 5 + 3) % POOL.length]).join("");

if (!reduced) {
  const show = (i) => lines[i].classList.add("shown");
  const events = [
    [300, () => show(0)],
    [1200, () => show(1)],
    [2300, () => { show(2); flash(lines[2]); }],
    [2450, () => drawLock("lifted")],
    [2540, () => { drawLock("open"); flash(lock); }],
    [3300, () => show(3)],
    [4100, () => drawLock("lifted")], // closing is quicker than opening
    [4160, () => drawLock("closed")],
    [4700, () => {
      scrubbed.textContent = fakeSecret();
      show(4);
      decode(scrubbed, PLACEHOLDER, { stagger: 18, spin: 220 });
    }],
    [8600, () => lines.forEach((l) => l.classList.add("leaving"))],
    [8900, () => lines.forEach((l) => l.classList.remove("shown", "leaving"))],
  ];
  const PERIOD = 9600;
  let next = 0, lap = 0;
  const demo = clock((t) => {
    const at = t - lap * PERIOD;
    while (next < events.length && events[next][0] <= at) events[next++][1]();
    if (at >= PERIOD) { lap++; next = 0; }
  });
  whenVisible(lock, demo.start, demo.stop);
}

// ---- star count beside github in the navbar ----
// Cached for ten minutes so moving between pages doesn't spend the API's rate limit.
async function githubStars() {
  try {
    const hit = JSON.parse(sessionStorage.getItem("asiri:stars") || "null");
    if (hit && Date.now() - hit.at < 600000) return hit.n;
    const r = await fetch("https://api.github.com/repos/gingered-cat/asiri", { headers: { Accept: "application/vnd.github+json" } });
    const n = r.ok ? (await r.json()).stargazers_count : null;
    if (Number.isInteger(n)) sessionStorage.setItem("asiri:stars", JSON.stringify({ n, at: Date.now() }));
    return Number.isInteger(n) ? n : null;
  } catch { return null; }
}
githubStars().then((n) => {
  if (n === null) return;
  for (const el of document.querySelectorAll("[data-gh-stars]")) {
    el.textContent = n.toLocaleString("en");
    el.closest("a")?.setAttribute("aria-label", `github, ${n} star${n === 1 ? "" : "s"}`);
    el.hidden = false;
  }
});

// ---- sections settle in the first time they scroll into view ----
if (!reduced) {
  const io = new IntersectionObserver((entries) => {
    for (const e of entries) if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); }
  }, { threshold: 0.15 });
  document.querySelectorAll("main > section").forEach((section) => {
    [...section.querySelectorAll(":scope > h2, :scope > p, :scope > pre, .row, .actions")]
      .forEach((el, i) => { el.classList.add("reveal"); el.style.setProperty("--i", Math.min(i, 8)); });
    io.observe(section);
  });
}
