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

// ---- the GitHub mark: still, with a few stars twinkling around it ----
const gh = document.getElementById("gh");
if (gh) {
  const art = gh.textContent.split("\n");
  const W = 40, H = art.length + 2, ox = 6, oy = 1;
  const sky = Array.from({ length: H }, (_, y) =>
    Array.from({ length: W }, (_, x) => (art[y - oy] || "")[x - ox] || " "));
  // each row's span of the mark, so stars stay out of its hollow middle too
  const span = sky.map((row) => {
    const xs = row.map((c, x) => (c !== " " ? x : -1)).filter((x) => x >= 0);
    return xs.length ? [xs[0], xs[xs.length - 1]] : null;
  });
  const near = (x, y) => {
    for (let dy = -1; dy <= 1; dy++) {
      const s = span[y + dy];
      if (s && x >= s[0] - 2 && x <= s[1] + 2) return true;
    }
    return false;
  };
  const free = [];
  for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) if (!near(x, y)) free.push([x, y]);
  const rand = seeded(7420);
  const stars = [];
  while (stars.length < 14 && free.length) {
    const [x, y] = free[Math.floor(rand() * free.length)];
    stars.push({ x, y, born: -1 });
    for (let j = free.length - 1; j >= 0; j--) // keep stars apart
      if (Math.abs(free[j][0] - x) <= 2 && Math.abs(free[j][1] - y) <= 1) free.splice(j, 1);
  }
  const TWINKLE = ["+", "*", "*", "+", "."]; // ~12 fps: one twinkle lasts ~400 ms
  const FRAME = 83;
  const esc = (c) => (c === "<" ? "&lt;" : c === "&" ? "&amp;" : c);
  const render = (frame) => {
    const cells = sky.map((row) => row.map(esc));
    for (const s of stars) {
      const k = s.born < 0 ? -1 : frame - s.born;
      cells[s.y][s.x] = k >= 0 && k < TWINKLE.length
        ? `<span class="on">${TWINKLE[k]}</span>`
        : '<span class="dim">.</span>';
    }
    gh.innerHTML = cells.map((row) => row.join("").replace(/\s+$/, "")).join("\n");
  };
  render(0);
  if (!reduced) {
    let shown = -1;
    const sparkle = clock((t) => {
      const frame = Math.floor(t / FRAME);
      if (frame === shown) return; // only redraw on a new frame
      shown = frame;
      const active = stars.filter((s) => s.born >= 0 && frame - s.born < TWINKLE.length).length;
      if (active < 3 && rand() < 0.12) { // start a new twinkle now and then, never more than three
        const idle = stars.filter((s) => s.born < 0 || frame - s.born >= TWINKLE.length + 6);
        if (idle.length) idle[Math.floor(rand() * idle.length)].born = frame;
      }
      render(frame);
    });
    whenVisible(gh, sparkle.start, sparkle.stop);
  }
}

// ---- live star count: digits roll into place ----
const starN = document.getElementById("star-n");
if (starN) {
  fetch("https://api.github.com/repos/gingered-cat/asiri", { headers: { Accept: "application/vnd.github+json" } })
    .then((r) => (r.ok ? r.json() : null))
    .then((r) => {
      const n = r && r.stargazers_count;
      if (!Number.isInteger(n)) return;
      if (n === 0) return decode(starN, "be the first star");
      const label = n === 1 ? " star" : " stars";
      if (reduced) { starN.textContent = n.toLocaleString("en") + label; return; }
      const digits = [...n.toLocaleString("en")];
      starN.setAttribute("aria-label", n + label);
      starN.innerHTML = digits.map((d, i) => /\d/.test(d)
        ? `<span class="digit" aria-hidden="true"><span class="wheel" style="--i:${i}">0\n1\n2\n3\n4\n5\n6\n7\n8\n9</span></span>`
        : `<span aria-hidden="true">${d}</span>`).join("") + `<span aria-hidden="true">${label}</span>`;
      requestAnimationFrame(() => requestAnimationFrame(() => {
        starN.querySelectorAll(".wheel").forEach((w, i) => w.style.setProperty("--d", digits.filter((d) => /\d/.test(d))[i]));
      }));
    })
    .catch(() => {});
}

// ---- sections settle in the first time they scroll into view ----
if (!reduced) {
  const io = new IntersectionObserver((entries) => {
    for (const e of entries) if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); }
  }, { threshold: 0.15 });
  document.querySelectorAll("main > section").forEach((section) => {
    [...section.querySelectorAll(":scope > h2, :scope > p, :scope > pre, .row, .actions, .sky, .star-text")]
      .forEach((el, i) => { el.classList.add("reveal"); el.style.setProperty("--i", Math.min(i, 8)); });
    io.observe(section);
  });
}
