// copy prompt
const copy = document.getElementById("copy");
copy.addEventListener("click", async () => {
  const text = document.getElementById(copy.dataset.copy).textContent.replace(/^>\s*/, "");
  try {
    await navigator.clipboard.writeText(text);
    copy.textContent = "copied";
  } catch {
    copy.textContent = "select and copy";
  }
  setTimeout(() => (copy.textContent = "copy prompt"), 1600);
});

// the demo: the lock opens for one grant, then closes again
const lock = document.getElementById("lock");
const lines = [...document.querySelectorAll("#log li")];
const shackle = {
  closed: ["             ", "    ╭───╮    ", "    │   │    ", "  ┌─┴───┴─┐  "],
  open:   ["    ╭───╮    ", "    │   │    ", "    │   ╵    ", "  ┌─┴─────┐  "],
};
function draw(open) {
  const hole = open ? '<span class="on">•</span>' : "•";
  const slot = open ? '<span class="on">┃</span>' : "┃";
  lock.innerHTML = [
    ...shackle[open ? "open" : "closed"],
    `  │   ${hole}   │  `,
    `  │   ${slot}   │  `,
    "  └───────┘  ",
  ].join("\n");
}
draw(false);

if (!matchMedia("(prefers-reduced-motion: reduce)").matches) {
  document.documentElement.classList.add("js");
  const show = (i) => lines[i].classList.add("shown");
  const steps = [
    [300, () => show(0)],
    [1300, () => show(1)],
    [2500, () => show(2)],
    [2700, () => draw(true)],
    [3400, () => show(3)],
    [4300, () => draw(false)],
    [4900, () => show(4)],
    [9000, () => lines.forEach((l) => l.classList.remove("shown"))],
  ];
  const loop = () => {
    for (const [at, fn] of steps) setTimeout(fn, at);
    setTimeout(loop, 9800);
  };
  loop();
}

// the github mark, with ascii stars twinkling in the sky around it
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
  const stars = [];
  for (let i = 0; i < 18 && free.length; i++) {
    const [x, y] = free[Math.floor(Math.random() * free.length)];
    stars.push({ x, y, phase: Math.floor(Math.random() * 24) });
    // keep stars apart: no neighbours within two columns or one row
    for (let j = free.length - 1; j >= 0; j--)
      if (Math.abs(free[j][0] - x) <= 2 && Math.abs(free[j][1] - y) <= 1) free.splice(j, 1);
  }
  const twinkle = [".", "+", "*", "+", ".", " ", " ", " ", " ", " ", " ", " "];
  const esc = (c) => (c === "<" ? "&lt;" : c === "&" ? "&amp;" : c);
  const render = (t) => {
    const cells = sky.map((row) => row.map(esc));
    for (const s of stars) {
      const c = t < 0 ? ".+*"[s.phase % 3] : twinkle[(t + s.phase) % twinkle.length];
      if (c !== " ") cells[s.y][s.x] = `<span class="on">${c}</span>`;
    }
    gh.innerHTML = cells.map((row) => row.join("").replace(/\s+$/, "")).join("\n");
  };
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) {
    render(-1);
  } else {
    let t = 0;
    render(t);
    setInterval(() => render(++t), 180);
  }
}

// live star count
const starN = document.getElementById("star-n");
if (starN) {
  fetch("https://api.github.com/repos/gingered-cat/asiri", { headers: { Accept: "application/vnd.github+json" } })
    .then((r) => (r.ok ? r.json() : null))
    .then((r) => {
      const n = r && r.stargazers_count;
      if (!Number.isInteger(n)) return;
      starN.textContent = n === 0 ? "be the first star" : n === 1 ? "1 star" : `${n.toLocaleString("en")} stars`;
    })
    .catch(() => {});
}
