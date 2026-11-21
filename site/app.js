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
