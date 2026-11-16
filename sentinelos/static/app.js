// SentinelOS dashboard helpers: API calls, animated SVG charts, formatting,
// theme switching and small UI effects (count-up numbers, sliding tabs, 3D tilt).
const CSRF = document.querySelector('meta[name="csrf"]')?.content || "";
const ROLE = document.querySelector('meta[name="role"]')?.content || "viewer";
const SERVER_HOST = document.querySelector('meta[name="host"]')?.content || "";
// Colours come from the theme (CSS variables), so charts follow light/dark mode.
const RISK_COLORS = { LOW: "var(--low)", MEDIUM: "var(--medium)", HIGH: "var(--high)", CRITICAL: "var(--critical)" };
const SERIES_COLORS = ["var(--s1)", "var(--s2)", "var(--s3)", "var(--s4)", "var(--s5)", "var(--s6)"];
const LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
const SVGNS = "http://www.w3.org/2000/svg";
const REDUCED = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

async function api(url, options = {}) {
  const res = await fetch(url, {
    ...options,
    headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF, ...(options.headers || {}) },
  });
  if (res.status === 401) { location.href = "/login"; return null; }
  return res.json();
}

// Run `fn` now and every `ms` milliseconds (the dashboard is live).
function poll(fn, ms = 3000) {
  const tick = async () => { try { await fn(); } catch (e) { console.error(e); } };
  tick();
  return setInterval(tick, ms);
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
const badge = (level) => `<span class="badge b-${esc(level)}">${esc(level)}</span>`;
const timeOf = (t) => new Date(t * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const seriesColor = (i) => SERIES_COLORS[i % SERIES_COLORS.length];
const worstLevel = (levels) => levels.slice().sort((a, b) => LEVELS.indexOf(b) - LEVELS.indexOf(a))[0] || "LOW";

// Resolve a CSS colour such as "var(--high)" to a real colour (needed by <canvas>).
const _colorCache = new Map();
function cssColor(value) {
  if (!String(value).startsWith("var(")) return value;
  if (!_colorCache.has(value)) {
    const name = value.slice(4, -1).trim();
    _colorCache.set(value, getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#888");
  }
  return _colorCache.get(value);
}

function svgEl(tag, attrs = {}, parent) {
  const el = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  if (parent) parent.appendChild(el);
  return el;
}

/* ------------------------------------------------------------------ theme */
// id -> [name, preview colours: background, accent, accent-2]
const THEMES = {
  light: ["Light", "#f6f8fc", "#0891b2", "#7c3aed"],
  dark: ["Cyber", "#060a13", "#22d3ee", "#8b5cf6"],
  matrix: ["Matrix", "#010a04", "#22ff78", "#00c2a8"],
  synthwave: ["Synthwave", "#0c0220", "#ff3ec8", "#ffa62b"],
};
const currentTheme = () => THEMES[document.documentElement.dataset.theme] ? document.documentElement.dataset.theme : "light";
// cycle through the themes (keyboard "t", login page)
function toggleTheme() {
  const ids = Object.keys(THEMES);
  setTheme(ids[(ids.indexOf(currentTheme()) + 1) % ids.length]);
}
function setTheme(next) {
  const root = document.documentElement;
  if (next === currentTheme()) return;
  const apply = () => {
    root.dataset.theme = next;
    try { localStorage.setItem("theme", next); } catch (e) {}
    _colorCache.clear();
    window.dispatchEvent(new Event("themechange"));
  };
  // A circle that grows out of the button (Chrome/Edge); plain switch elsewhere.
  const btn = document.querySelector("#theme-btn, .theme-dots")?.getBoundingClientRect();
  if (document.startViewTransition && !REDUCED && btn) {
    root.style.setProperty("--vt-x", `${btn.left + btn.width / 2}px`);
    root.style.setProperty("--vt-y", `${btn.top + btn.height / 2}px`);
    root.classList.add("theme-vt");
    document.startViewTransition(apply).finished.finally(() => root.classList.remove("theme-vt"));
  } else apply();
}

/* ------------------------------------------------------- number animation */
// Smoothly count a number element from its last value to `value`.
function countTo(el, value, { decimals = 0, suffix = "", prefix = "" } = {}) {
  if (!el) return;
  const to = Number(value) || 0;
  const from = el._value ?? 0;
  const fmt = v => prefix + v.toFixed(decimals) + suffix;
  el.classList.add("ready");   // removes the loading skeleton
  if (el._value !== undefined && el._value !== to) {
    el.classList.remove("bump"); void el.offsetWidth; el.classList.add("bump");
  }
  el._value = to;
  cancelAnimationFrame(el._raf);
  if (REDUCED || from === to) { el.textContent = fmt(to); return; }
  const start = performance.now(), dur = 900;
  const step = now => {
    const k = Math.min(1, (now - start) / dur), e = 1 - Math.pow(1 - k, 3);
    el.textContent = fmt(from + (to - from) * e);
    if (k < 1) el._raf = requestAnimationFrame(step);
  };
  el._raf = requestAnimationFrame(step);
}

/* ------------------------------------------------------------ line chart */
let _uid = 0;
// Line chart. series = [{name, color, points: [{t, v}]}], values 0..max.
// Draws itself in with an animation the first time, then updates quietly.
// Hover shows a crosshair with the values at that moment.
function lineChart(container, series, { max = 100, height = 220, unit = "%" } = {}) {
  const width = Math.max(container.clientWidth, 280);
  const pad = { l: 40, r: 14, t: 12, b: 26 };
  const all = series.flatMap(s => s.points);
  const first = !container.dataset.drawn;
  container.classList.add("chart-host");
  container.innerHTML = "";
  if (!all.length) { container.innerHTML = '<div class="empty">Waiting for data...</div>'; return; }
  container.dataset.drawn = "1";
  const t0 = Math.min(...all.map(p => p.t)), t1 = Math.max(...all.map(p => p.t), t0 + 1);
  const x = t => pad.l + (t - t0) / (t1 - t0) * (width - pad.l - pad.r);
  const y = v => pad.t + (1 - Math.min(v, max) / max) * (height - pad.t - pad.b);
  const svg = svgEl("svg", { width, height, viewBox: `0 0 ${width} ${height}`, class: "chart-svg" }, container);
  const defs = svgEl("defs", {}, svg);
  for (let i = 0; i <= 4; i++) {
    const v = max * i / 4;
    svgEl("line", { x1: pad.l, x2: width - pad.r, y1: y(v), y2: y(v), class: "grid-line", "stroke-dasharray": i ? "3 5" : "" }, svg);
    svgEl("text", { x: pad.l - 8, y: y(v) + 4, "text-anchor": "end" }, svg).textContent = Math.round(v) + unit;
  }
  svgEl("text", { x: pad.l, y: height - 6 }, svg).textContent = timeOf(t0);
  svgEl("text", { x: width - pad.r, y: height - 6, "text-anchor": "end" }, svg).textContent = timeOf(t1);
  series.forEach(s => {
    if (!s.points.length) return;
    const id = `g${++_uid}`;
    const grad = svgEl("linearGradient", { id, x1: 0, y1: 0, x2: 0, y2: 1 }, defs);
    svgEl("stop", { offset: "0%", style: `stop-color:${s.color};stop-opacity:.32` }, grad);
    svgEl("stop", { offset: "100%", style: `stop-color:${s.color};stop-opacity:0` }, grad);
    // smooth curve through the points
    const pts = s.points.map(p => [x(p.t), y(p.v)]);
    let d = `M${pts[0][0].toFixed(1)},${pts[0][1].toFixed(1)}`;
    for (let i = 1; i < pts.length; i++) {
      const [ax, ay] = pts[i - 1], [bx, by] = pts[i], mx = (ax + bx) / 2;
      d += `C${mx.toFixed(1)},${ay.toFixed(1)} ${mx.toFixed(1)},${by.toFixed(1)} ${bx.toFixed(1)},${by.toFixed(1)}`;
    }
    const area = `${d}L${pts.at(-1)[0]},${y(0)}L${pts[0][0]},${y(0)}Z`;
    svgEl("path", { d: area, fill: `url(#${id})`, class: first ? "area-in" : "" }, svg);
    svgEl("path", { d, fill: "none", style: `stroke:${s.color}`, "stroke-width": 2.4, "stroke-linejoin": "round",
      "stroke-linecap": "round", pathLength: 1, class: first ? "draw" : "", "stroke-dasharray": first ? "" : "none" }, svg);
    const [lx, ly] = pts.at(-1);
    svgEl("circle", { cx: lx, cy: ly, r: 4, style: `fill:${s.color}`, class: "end-dot" }, svg);
    svgEl("circle", { cx: lx, cy: ly, r: 4, style: `fill:${s.color}`, stroke: "var(--panel-solid)", "stroke-width": 2 }, svg);
  });
  // hover crosshair + tooltip
  const cross = svgEl("line", { y1: pad.t, y2: height - pad.b, class: "grid-line", "stroke-width": 1.5, visibility: "hidden" }, svg);
  const dots = series.map(s => svgEl("circle", { r: 5, style: `fill:${s.color}`, stroke: "var(--panel-solid)", "stroke-width": 2, visibility: "hidden" }, svg));
  const tip = document.createElement("div");
  tip.className = "chart-tip";
  container.appendChild(tip);
  const hit = svgEl("rect", { x: pad.l, y: 0, width: width - pad.l - pad.r, height, fill: "transparent" }, svg);
  const show = (mx) => {
    const t = t0 + (mx - pad.l) / (width - pad.l - pad.r) * (t1 - t0);
    const rows = [];
    series.forEach((s, i) => {
      if (!s.points.length) return;
      const p = s.points.reduce((a, b) => Math.abs(b.t - t) < Math.abs(a.t - t) ? b : a);
      dots[i].setAttribute("cx", x(p.t)); dots[i].setAttribute("cy", y(p.v)); dots[i].setAttribute("visibility", "visible");
      rows.push(`<div><i style="display:inline-block;width:8px;height:8px;border-radius:2px;margin-right:6px;background:${s.color}"></i>${esc(s.name)} <b>${Math.round(p.v)}${unit}</b></div>`);
      if (i === 0) { cross.setAttribute("x1", x(p.t)); cross.setAttribute("x2", x(p.t)); }
    });
    cross.setAttribute("visibility", "visible");
    tip.innerHTML = `<div class="muted small">${timeOf(t)}</div>${rows.join("")}`;
    tip.style.left = `${Math.min(Math.max(mx, 70), width - 70)}px`;
    tip.style.top = `${pad.t + 10}px`;
    tip.style.transform = "translate(-50%, 0)";
    tip.classList.add("show");
  };
  hit.addEventListener("pointermove", e => { container._hoverX = e.offsetX; show(e.offsetX); });
  hit.addEventListener("pointerleave", () => {
    container._hoverX = null; tip.classList.remove("show");
    cross.setAttribute("visibility", "hidden"); dots.forEach(d => d.setAttribute("visibility", "hidden"));
  });
  if (container._hoverX) show(container._hoverX);   // keep the tooltip through live updates
  const legend = document.createElement("div");
  legend.className = "legend";
  legend.innerHTML = series.map(s =>
    `<span><i style="background:${s.color}"></i>${esc(s.name)} <b>${s.points.length ? Math.round(s.points.at(-1).v) + unit : ""}</b></span>`).join("");
  container.appendChild(legend);
}

/* ------------------------------------------------------------ donut chart */
// Donut chart. items = [{label, value, color}]. Segments glide to new sizes.
function donutChart(container, items, centerLabel = "") {
  const total = items.reduce((a, b) => a + b.value, 0);
  const size = 180, r = 66, stroke = 20, c = 2 * Math.PI * r;
  let svg = container.querySelector("svg.donut");
  if (!svg || svg.dataset.n !== String(items.length)) {
    container.innerHTML = "";
    const wrap = document.createElement("div");
    wrap.className = "donut-wrap";
    svg = svgEl("svg", { width: size, height: size, viewBox: `0 0 ${size} ${size}`, class: "donut" }, wrap);
    svg.dataset.n = items.length;
    svgEl("circle", { cx: size / 2, cy: size / 2, r, fill: "none", style: "stroke:var(--panel-3)", "stroke-width": stroke }, svg);
    items.forEach(it => svgEl("circle", {
      cx: size / 2, cy: size / 2, r, fill: "none", style: `stroke:${it.color}`, "stroke-width": stroke, "stroke-linecap": "butt",
      "stroke-dasharray": `0 ${c}`, "stroke-dashoffset": 0, transform: `rotate(-90 ${size / 2} ${size / 2})`, class: "donut-seg",
    }, svg));
    svgEl("text", { x: size / 2, y: size / 2 + 4, "text-anchor": "middle", class: "donut-total" }, svg);
    svgEl("text", { x: size / 2, y: size / 2 + 24, "text-anchor": "middle" }, svg).textContent = centerLabel;
    const legend = document.createElement("div");
    legend.className = "donut-legend";
    wrap.appendChild(legend);
    container.appendChild(wrap);
    void svg.getBoundingClientRect();  // start from 0 so the first draw animates
  }
  let offset = 0;
  const gap = items.filter(i => i.value).length > 1 ? 3 : 0;
  svg.querySelectorAll(".donut-seg").forEach((seg, i) => {
    const len = total ? items[i].value / total * c : 0;
    seg.setAttribute("stroke-dasharray", `${Math.max(len - gap, 0)} ${c}`);
    seg.setAttribute("stroke-dashoffset", -offset);
    offset += len;
  });
  const totalEl = svg.querySelector(".donut-total");
  countTo(totalEl, total);
  container.querySelector(".donut-legend").innerHTML = items.map(it =>
    `<div class="legend" style="margin:8px 0"><span><i style="background:${it.color}"></i>${esc(it.label)}: <b>${it.value}</b>
      <span class="muted">${total ? Math.round(it.value / total * 100) : 0}%</span></span></div>`).join("");
}

/* -------------------------------------------------------- horizontal bars */
// Horizontal bars. items = [{label, value, color}]. Bars are reused between
// updates so they grow/shrink smoothly instead of flashing.
function barList(container, items) {
  if (!items.length) { container.innerHTML = '<div class="empty">No data yet</div>'; return; }
  container.querySelector(".empty")?.remove();
  const max = Math.max(...items.map(i => i.value), 1);
  const existing = new Map([...container.querySelectorAll(".hbar")].map(r => [r.dataset.label, r]));
  items.forEach((it, idx) => {
    let row = existing.get(it.label);
    if (!row) {
      row = document.createElement("div");
      row.className = "hbar reveal";
      row.style.setProperty("--i", idx);
      row.dataset.label = it.label;
      row.innerHTML = `<span class="trunc" title="${esc(it.label)}">${esc(it.label)}</span>
        <div class="track"><div class="fill"></div></div><b></b>`;
    }
    existing.delete(it.label);
    container.appendChild(row);  // keeps rows in the new order
    const fill = row.querySelector(".fill");
    fill.style.background = `linear-gradient(90deg, ${it.color}, color-mix(in srgb, ${it.color} 55%, transparent))`;
    requestAnimationFrame(() => { fill.style.width = `${it.value / max * 100}%`; });
    countTo(row.querySelector("b"), it.value);
  });
  existing.forEach(r => r.remove());
}

/* ------------------------------------------------------------- sparkline */
// Tiny line without axes, for endpoint cards.
function sparkline(container, values, color) {
  const w = Math.max(container.clientWidth, 120), h = 46;
  container.innerHTML = "";
  if (values.length < 2) return;
  const svg = svgEl("svg", { width: w, height: h, class: "chart-svg" }, container);
  const id = `sp${++_uid}`;
  const grad = svgEl("linearGradient", { id, x1: 0, y1: 0, x2: 0, y2: 1 }, svgEl("defs", {}, svg));
  svgEl("stop", { offset: "0%", style: `stop-color:${color};stop-opacity:.35` }, grad);
  svgEl("stop", { offset: "100%", style: `stop-color:${color};stop-opacity:0` }, grad);
  const x = i => i / (values.length - 1) * (w - 4) + 2;
  const yy = v => h - 3 - Math.min(v, 100) / 100 * (h - 8);
  const d = values.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${yy(v).toFixed(1)}`).join("");
  svgEl("path", { d: `${d}L${x(values.length - 1)},${h}L${x(0)},${h}Z`, fill: `url(#${id})` }, svg);
  svgEl("path", { d, fill: "none", style: `stroke:${color}`, "stroke-width": 2, "stroke-linejoin": "round" }, svg);
  svgEl("circle", { cx: x(values.length - 1), cy: yy(values.at(-1)), r: 3, style: `fill:${color}`, class: "end-dot" }, svg);
}

/* -------------------------------------------------------------- ring gauge */
// Circular percentage gauge used on endpoint cards. Animates between values.
function ringGauge(el, pct, color, label) {
  const r = 32, c = 2 * Math.PI * r;
  if (!el.querySelector("svg")) {
    el.innerHTML = `<svg viewBox="0 0 78 78"><circle class="track-c" cx="39" cy="39" r="${r}"/>
      <circle class="val-c" cx="39" cy="39" r="${r}" stroke-dasharray="${c}" stroke-dashoffset="${c}"/></svg>
      <div class="ring-txt"><div><b></b><span>${esc(label)}</span></div></div>`;
    void el.offsetWidth;
  }
  const val = el.querySelector(".val-c");
  val.style.stroke = color;
  requestAnimationFrame(() => val.setAttribute("stroke-dashoffset", c * (1 - Math.min(pct, 100) / 100)));
  countTo(el.querySelector("b"), pct, { suffix: "%" });
}

/* ------------------------------------------------------------- tables */
// Click a <th data-key> to sort. Returns a function that sorts rows.
function sortable(table, state, onChange) {
  const ths = table.querySelectorAll("th[data-key]");
  const mark = () => ths.forEach(th => {
    th.classList.toggle("sorted", th.dataset.key === state.key);
    th.classList.toggle("asc", th.dataset.key === state.key && state.dir > 0);
  });
  ths.forEach(th => th.addEventListener("click", () => {
    state.dir = state.key === th.dataset.key ? -state.dir : -1;
    state.key = th.dataset.key;
    mark();
    onChange();
  }));
  mark();
  return rows => !state.key ? rows : [...rows].sort((a, b) => {
    const va = a[state.key], vb = b[state.key];
    return (typeof va === "number" ? va - vb : String(va).localeCompare(String(vb))) * state.dir;
  });
}

// Fill a <tbody>; rows slide in only the first time (live updates stay calm).
function fillRows(tbody, html) {
  const first = !tbody.dataset.filled;
  tbody.innerHTML = html;
  if (first && tbody.rows.length) {
    tbody.dataset.filled = "1";
    [...tbody.rows].forEach((r, i) => r.style.setProperty("--r", i));
    tbody.classList.add("enter");
    setTimeout(() => tbody.classList.remove("enter"), 1400);
  }
}

/* ------------------------------------------------------------- modal/toast */
function showModal(title, obj) {
  const modal = document.getElementById("modal");
  const rows = Object.entries(obj).map(([k, v]) =>
    `<div>${esc(k)}</div><div class="mono">${esc(typeof v === "object" ? JSON.stringify(v, null, 1) : v)}</div>`).join("");
  modal.querySelector(".box").innerHTML =
    `<div class="topbar"><h1>${esc(title)}</h1><button class="btn ghost sm" onclick="closeModal()">Close</button></div>
     <div class="kv">${rows}</div>`;
  modal.classList.add("show");
}
function closeModal() { document.getElementById("modal").classList.remove("show"); }
document.addEventListener("keydown", e => { if (e.key === "Escape") closeModal(); });

function toast(alert) {
  const box = document.createElement("div");
  box.className = `toast ${alert.severity}`;
  box.innerHTML = `<div style="display:flex;justify-content:space-between;gap:8px"><b>${esc(alert.severity)} RISK</b>
    <span class="muted small">${esc(alert.endpoint)}</span></div>
    <div>${esc(alert.alert_type)} · ${esc(alert.process)} (PID ${esc(alert.pid)})</div>
    <div class="muted small">${esc(alert.reasons)}</div><div class="bar"></div>`;
  box.onclick = () => location.href = "/alerts";
  document.getElementById("toasts").appendChild(box);
  chime(alert.severity === "CRITICAL");
  setTimeout(() => { box.classList.add("out"); setTimeout(() => box.remove(), 400); }, 12000);
}

// Pop up new HIGH/CRITICAL alerts on every page.
let lastAlertId = null;
async function watchAlerts() {
  const data = await api("/api/alerts");
  if (!data) return;
  const alerts = data.alerts;
  const newest = alerts.length ? alerts[0].id : 0;
  if (lastAlertId !== null) {
    alerts.filter(a => a.id > lastAlertId && ["HIGH", "CRITICAL"].includes(a.severity))
      .slice(0, 4).forEach(toast);
  }
  lastAlertId = newest;
  recentAlerts = alerts.slice(0, 25);
  updateBell();
  const counter = document.getElementById("nav-alerts");
  const fresh = alerts.filter(a => a.status === "NEW").length;
  if (counter && counter.textContent !== String(fresh || "")) {
    counter.textContent = fresh ? fresh : "";
    counter.classList.remove("bump"); void counter.offsetWidth; counter.classList.add("bump");
  }
}

/* ------------------------------------------------------------- UI effects */
// Segmented tabs: a highlight slides under the active button.
function initTabs(tabs) {
  if (tabs._ink) return;
  const ink = document.createElement("span");
  ink.className = "tab-ink";
  tabs.prepend(ink);
  tabs._ink = ink;
  const move = () => {
    const active = tabs.querySelector("button.active");
    if (!active || !active.offsetWidth) { ink.style.height = "0"; return; }
    ink.style.width = `${active.offsetWidth}px`;
    ink.style.height = `${active.offsetHeight}px`;
    ink.style.transform = `translate(${active.offsetLeft}px, ${active.offsetTop - 4}px)`;
  };
  new MutationObserver(move).observe(tabs, { subtree: true, attributes: true, attributeFilter: ["class"] });
  new ResizeObserver(move).observe(tabs);
  move();
}

// Cards marked .tilt lean towards the mouse in 3D (event delegation, so it
// also works for cards that are re-drawn by live updates).
let tilted = null;
document.addEventListener("pointermove", e => {
  if (REDUCED || e.pointerType !== "mouse") return;
  const card = e.target.closest?.(".tilt");
  if (tilted && tilted !== card) { tilted.style.transform = ""; tilted = null; }
  if (!card) return;
  tilted = card;
  const r = card.getBoundingClientRect();
  const px = (e.clientX - r.left) / r.width, py = (e.clientY - r.top) / r.height;
  card.style.transform = `perspective(900px) rotateX(${(0.5 - py) * 7}deg) rotateY(${(px - 0.5) * 9}deg) translateY(-3px)`;
  card.style.setProperty("--mx", `${px * 100}%`);
  card.style.setProperty("--my", `${py * 100}%`);
  if (!card.querySelector(":scope > .shine")) card.insertAdjacentHTML("beforeend", '<span class="shine"></span>');
});
document.addEventListener("pointerleave", () => { if (tilted) tilted.style.transform = ""; });

/* ------------------------------------------------------------ alert sound */
// A short two-tone chime made with Web Audio (no sound files). Off by default.
let audioCtx = null;
const soundOn = () => { try { return localStorage.getItem("sound") === "on"; } catch (e) { return false; } };
function setSound(on) {
  try { localStorage.setItem("sound", on ? "on" : "off"); } catch (e) {}
  document.querySelectorAll("[data-sound]").forEach(b => b.classList.toggle("on-btn", on));
  if (on) chime(false, true);
}
function chime(critical = false, force = false) {
  if (!force && !soundOn()) return;
  try {
    audioCtx = audioCtx || new (window.AudioContext || window.webkitAudioContext)();
    (critical ? [988, 740, 988, 740] : [740, 988]).forEach((f, i) => {
      const o = audioCtx.createOscillator(), g = audioCtx.createGain(), t = audioCtx.currentTime + i * 0.15;
      o.type = "triangle"; o.frequency.value = f;
      g.gain.setValueAtTime(0.0001, t); g.gain.exponentialRampToValueAtTime(0.16, t + 0.02); g.gain.exponentialRampToValueAtTime(0.0001, t + 0.14);
      o.connect(g).connect(audioCtx.destination); o.start(t); o.stop(t + 0.15);
    });
  } catch (e) {}
}

/* ------------------------------------------------------------ small icons */
const ICON_PATHS = {
  overview: '<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>',
  laptop: '<rect x="4" y="4" width="16" height="11" rx="2"/><path d="M2 20h20"/>',
  alert: '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/>',
  activity: '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
  users: '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/>',
  globe: '<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15 15 0 0 1 0 20 15 15 0 0 1 0-20z"/>',
  palette: '<circle cx="13.5" cy="6.5" r="1.5"/><circle cx="17.5" cy="10.5" r="1.5"/><circle cx="8.5" cy="7.5" r="1.5"/><circle cx="6.5" cy="12.5" r="1.5"/><path d="M12 2a10 10 0 0 0 0 20c1 0 1.6-.8 1.6-1.7 0-.4-.2-.8-.4-1.1-.3-.3-.4-.7-.4-1.1 0-.9.8-1.7 1.7-1.7H16a6 6 0 0 0 6-6C22 6 17.5 2 12 2z"/>',
  bell: '<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.9 1.9 0 0 0 3.4 0"/>',
  sound: '<path d="M11 5 6 9H2v6h4l5 4z"/><path d="M15.5 8.5a5 5 0 0 1 0 7M19 5a10 10 0 0 1 0 14"/>',
  expand: '<path d="M8 3H5a2 2 0 0 0-2 2v3M21 8V5a2 2 0 0 0-2-2h-3M3 16v3a2 2 0 0 0 2 2h3M16 21h3a2 2 0 0 0 2-2v-3"/>',
  download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5M12 15V3"/>',
  keyboard: '<rect x="2" y="5" width="20" height="14" rx="2"/><path d="M6 9h.01M10 9h.01M14 9h.01M18 9h.01M7 15h10"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5M21 12H9"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>',
  zap: '<path d="M13 2 3 14h9l-1 8 10-12h-9z"/>',
};
const svgI = (n) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${ICON_PATHS[n] || ""}</svg>`;

/* ------------------------------------------------------------ theme picker */
function openThemePicker(anchor) {
  let pop = document.getElementById("theme-pop");
  if (!pop) {
    pop = document.createElement("div");
    pop.id = "theme-pop";
    pop.className = "theme-pop";
    pop.innerHTML = '<div class="pop-title">Choose a theme</div>' + Object.entries(THEMES).map(([id, [name, bg, a, b]]) =>
      `<button class="swatch" data-theme-id="${id}" type="button"><div class="pv" style="background:${bg}">
        <i style="background:${a}"></i><i style="background:linear-gradient(90deg,${a},${b})"></i><i style="background:${b}"></i></div>
        <span>${name}</span></button>`).join("");
    pop.addEventListener("click", e => {
      const sw = e.target.closest(".swatch");
      if (sw) { setTheme(sw.dataset.themeId); markSwatches(); }
    });
    document.body.appendChild(pop);
    document.addEventListener("pointerdown", e => {
      if (pop.classList.contains("show") && !pop.contains(e.target) && !e.target.closest("#theme-btn")) pop.classList.remove("show");
    });
  }
  const markSwatches = () => pop.querySelectorAll(".swatch").forEach(s => s.classList.toggle("active", s.dataset.themeId === currentTheme()));
  markSwatches();
  const r = (anchor || document.body).getBoundingClientRect();
  pop.style.left = `${Math.max(8, Math.min(r.left, innerWidth - 270))}px`;
  if (r.top > 320) { pop.style.top = ""; pop.style.bottom = `${innerHeight - r.top + 8}px`; }
  else { pop.style.bottom = ""; pop.style.top = `${r.bottom + 8}px`; }
  pop.classList.toggle("show");
}

/* ------------------------------------------------------------ backdrop fx */
// A soft light follows the mouse; the Matrix theme adds falling "digital rain".
function initBackdrop() {
  const bd = document.querySelector(".backdrop");
  if (!bd) return;
  const spot = document.createElement("span");
  spot.className = "spot";
  bd.appendChild(spot);
  let raf = 0;
  document.addEventListener("pointermove", e => {
    if (raf || REDUCED) return;
    raf = requestAnimationFrame(() => { raf = 0; spot.style.setProperty("--cx", `${e.clientX}px`); spot.style.setProperty("--cy", `${e.clientY}px`); });
  });
  let rain = null;
  const sync = () => {
    if (currentTheme() === "matrix" && !REDUCED) { if (!rain) rain = startRain(bd); }
    else if (rain) { rain(); rain = null; }
  };
  window.addEventListener("themechange", sync);
  sync();
}
function startRain(bd) {
  const c = document.createElement("canvas");
  c.className = "rain";
  bd.appendChild(c);
  const ctx = c.getContext("2d"), glyphs = "01アイウエオカキクケコサシスセソタチツテトナニヌネノ<>/{}[]#$%=+*0123456789ABCDEF";
  const size = 16;
  let drops = [], timer;
  const resize = () => { c.width = innerWidth; c.height = innerHeight; drops = Array.from({ length: Math.ceil(c.width / size) }, () => Math.random() * -50); };
  resize();
  addEventListener("resize", resize);
  timer = setInterval(() => {
    if (document.hidden) return;
    ctx.fillStyle = "rgba(1, 10, 4, 0.14)";
    ctx.fillRect(0, 0, c.width, c.height);
    ctx.font = `${size}px monospace`;
    drops.forEach((y, i) => {
      ctx.fillStyle = Math.random() > .975 ? "#d8ffe6" : "#22ff78";
      ctx.fillText(glyphs[(Math.random() * glyphs.length) | 0], i * size, y * size);
      drops[i] = y * size > c.height && Math.random() > .975 ? 0 : y + 1;
    });
  }, 55);
  return () => { clearInterval(timer); removeEventListener("resize", resize); c.remove(); };
}

/* ------------------------------------------------------------ fullscreen */
function toggleFullscreen() {
  if (document.fullscreenElement) document.exitFullscreen?.();
  else document.documentElement.requestFullscreen?.().catch(() => {});
}

/* ------------------------------------------------------------ notifications */
let recentAlerts = [];
const lastSeen = () => { try { return +localStorage.getItem("seenAlert") || 0; } catch (e) { return 0; } };
function updateBell() {
  const n = recentAlerts.filter(a => a.id > lastSeen()).length;
  document.querySelectorAll(".bell-count").forEach(b => b.textContent = n ? (n > 9 ? "9+" : n) : "");
}
function ago(ts) {
  const s = Math.max(0, (Date.now() - new Date(ts.replace(" ", "T")).getTime()) / 1000);
  return s < 60 ? "just now" : s < 3600 ? `${Math.round(s / 60)} min ago` : s < 86400 ? `${Math.round(s / 3600)} h ago` : ts.slice(0, 10);
}
function openDrawer() {
  let drawer = document.getElementById("drawer");
  if (!drawer) {
    document.body.insertAdjacentHTML("beforeend", `<div class="scrim" id="scrim"></div><aside class="drawer" id="drawer" aria-label="Notifications">
      <div class="drawer-head"><div><h3>Notifications</h3><div class="muted small">Latest alerts from every laptop you can see</div></div>
      <button class="btn ghost sm" type="button" onclick="closeDrawer()">Close</button></div><div class="drawer-list" id="drawer-list"></div></aside>`);
    drawer = document.getElementById("drawer");
    document.getElementById("scrim").onclick = closeDrawer;
  }
  const seen = lastSeen();
  document.getElementById("drawer-list").innerHTML = recentAlerts.map((a, i) => `
    <a class="note ${a.id > seen ? "unread" : ""}" style="--i:${i}" href="/alerts">
      <div style="display:flex;gap:8px;align-items:center">${badge(a.severity)}<b style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(a.alert_type)}</b></div>
      <div style="margin-top:6px">${esc(a.process)} <span class="muted">on</span> ${esc(a.endpoint)}</div>
      <div class="t">${esc(ago(a.timestamp))} · ${esc(a.reasons)}</div></a>`).join("")
    || '<div class="empty">No alerts yet. All quiet.</div>';
  drawer.classList.add("show");
  document.getElementById("scrim").classList.add("show");
  try { localStorage.setItem("seenAlert", recentAlerts.length ? recentAlerts[0].id : seen); } catch (e) {}
  updateBell();
}
function closeDrawer() {
  document.getElementById("drawer")?.classList.remove("show");
  document.getElementById("scrim")?.classList.remove("show");
}

/* ------------------------------------------------------------ command palette */
// Ctrl+K / Cmd+K / "/" : jump to any page, laptop or action by typing.
let palItems = [], palActive = 0;
function paletteItems() {
  const go = url => () => { location.href = url; };
  const items = [
    ["Pages", "Overview", "overview", go("/"), "g o"], ["Pages", "Endpoints", "laptop", go("/endpoints"), "g e"],
    ["Pages", "Alerts", "alert", go("/alerts"), "g a"], ["Pages", "Activity Log", "activity", go("/activity"), "g l"],
    ["Pages", "War Room (3D command centre)", "globe", go("/warroom"), "g w"],
  ];
  if (ROLE === "admin") items.push(["Pages", "Users", "users", go("/users"), "g u"]);
  Object.entries(THEMES).forEach(([id, [name]]) => items.push(["Theme", `Theme: ${name}`, "palette", () => setTheme(id), id === currentTheme() ? "current" : ""]));
  items.push(
    ["Actions", "Notifications", "bell", openDrawer, "n"],
    ["Actions", `Alert sound: turn ${soundOn() ? "off" : "on"}`, "sound", () => setSound(!soundOn()), ""],
    ["Actions", "Full screen on / off", "expand", toggleFullscreen, "f"],
    ["Actions", "Export alerts (CSV)", "download", go("/export/alerts.csv"), ""],
    ["Actions", "Export activity log (CSV)", "download", go("/export/events.csv"), ""],
    ["Actions", "Keyboard shortcuts", "keyboard", showHelp, "?"],
    ["Actions", "Log out", "logout", go("/logout"), ""]);
  return items.map(([group, label, icon, run, hint]) => ({ group, label, icon, run, hint }));
}
function fuzzy(q, text) {   // every typed letter must appear in order; returns score + matched positions
  if (!q) return { score: 0, hits: [] };
  const t = text.toLowerCase(); let i = 0, score = 0, last = -2; const hits = [];
  for (const ch of q.toLowerCase()) {
    i = t.indexOf(ch, i);
    if (i < 0) return null;
    score += i === last + 1 ? 3 : 1; if (i === 0 || t[i - 1] === " ") score += 2;
    hits.push(i); last = i; i++;
  }
  return { score, hits };
}
function openPalette() {
  let pal = document.getElementById("palette");
  if (!pal) {
    document.body.insertAdjacentHTML("beforeend", `<div class="palette" id="palette"><div class="pal-box" role="dialog" aria-label="Command palette">
      <div class="pal-in">${svgI("search")}<input id="pal-q" placeholder="Search pages, laptops, actions..." autocomplete="off"><kbd>Esc</kbd></div>
      <div class="pal-list" id="pal-list"></div>
      <div class="pal-foot"><span><kbd>↑</kbd><kbd>↓</kbd>move</span><span><kbd>Enter</kbd>open</span><span><kbd>Esc</kbd>close</span></div></div></div>`);
    pal = document.getElementById("palette");
    pal.addEventListener("pointerdown", e => { if (e.target === pal) closePalette(); });
    const q = document.getElementById("pal-q");
    q.addEventListener("input", () => { palActive = 0; renderPalette(); });
    q.addEventListener("keydown", e => {
      const n = document.querySelectorAll(".pal-item").length;
      if (e.key === "ArrowDown") { palActive = (palActive + 1) % Math.max(n, 1); renderPalette(); e.preventDefault(); }
      if (e.key === "ArrowUp") { palActive = (palActive - 1 + n) % Math.max(n, 1); renderPalette(); e.preventDefault(); }
      if (e.key === "Enter") { runPalette(palActive); e.preventDefault(); }
    });
  }
  palItems = paletteItems();
  palActive = 0;
  document.getElementById("pal-q").value = "";
  renderPalette();
  pal.classList.add("show");
  const q = document.getElementById("pal-q");
  [0, 60, 250].forEach(ms => setTimeout(() => { if (document.activeElement !== q) q.focus(); }, ms));
  api("/api/endpoints").then(d => {   // laptops become searchable too
    if (!d) return;
    palItems = palItems.filter(i => i.group !== "Laptops").concat(d.endpoints.map(e => ({ group: "Laptops", label: e.hostname,
      icon: "laptop", hint: e.online ? e.threat_level : "offline", run: () => { location.href = `/endpoint/${encodeURIComponent(e.hostname)}`; } })));
    renderPalette();
  });
}
function closePalette() { document.getElementById("palette")?.classList.remove("show"); }
let palShown = [];
function renderPalette() {
  const q = document.getElementById("pal-q").value.trim();
  palShown = palItems.map(it => ({ it, m: fuzzy(q, it.label) })).filter(x => x.m)
    .sort((a, b) => (q ? b.m.score - a.m.score : 0));
  if (!q) {   // keep groups in order when nothing is typed
    const order = ["Pages", "Laptops", "Actions", "Theme"];
    palShown.sort((a, b) => order.indexOf(a.it.group) - order.indexOf(b.it.group));
  }
  let html = "", group = null;
  palShown.forEach(({ it, m }, i) => {
    if (it.group !== group && !q) { group = it.group; html += `<div class="pal-group">${group}</div>`; }
    const label = [...it.label].map((ch, k) => m.hits.includes(k) ? `<mark>${esc(ch)}</mark>` : esc(ch)).join("");
    html += `<div class="pal-item ${i === palActive ? "active" : ""}" data-i="${i}">${svgI(it.icon)}<span>${label}</span><span class="hint">${esc(it.hint || "")}</span></div>`;
  });
  const list = document.getElementById("pal-list");
  list.innerHTML = html || '<div class="empty">Nothing found</div>';
  list.querySelectorAll(".pal-item").forEach(el => {
    el.addEventListener("click", () => runPalette(+el.dataset.i));
    el.addEventListener("pointermove", () => { if (palActive !== +el.dataset.i) { palActive = +el.dataset.i; list.querySelectorAll(".pal-item").forEach(x => x.classList.toggle("active", x === el)); } });
  });
  list.querySelector(".pal-item.active")?.scrollIntoView({ block: "nearest" });
}
function runPalette(i) {
  const pick = palShown[i];
  if (!pick) return;
  closePalette();
  pick.it.run();
}

/* ------------------------------------------------------------ keyboard */
function showHelp() {
  const k = (keys, what) => `<div>${keys.split(" ").map(x => `<kbd>${x}</kbd>`).join("")}</div><div>${what}</div>`;
  document.querySelector("#modal .box").innerHTML = `<div class="topbar"><h1>Keyboard shortcuts</h1>
    <button class="btn ghost sm" onclick="closeModal()">Close</button></div><div class="keys">
    ${k("Ctrl K", "Command palette (also <kbd>/</kbd>)")}${k("g o", "Go to Overview")}${k("g e", "Go to Endpoints")}
    ${k("g a", "Go to Alerts")}${k("g l", "Go to Activity Log")}${k("g w", "Open the 3D War Room")}
    ${ROLE === "admin" ? k("g u", "Go to Users") : ""}${k("t", "Next theme")}${k("n", "Notifications")}
    ${k("f", "Full screen")}${k("?", "This help")}${k("Esc", "Close any window")}</div>`;
  document.getElementById("modal").classList.add("show");
}
let gKey = 0;
document.addEventListener("keydown", e => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k" && document.querySelector(".layout, .wr")) { e.preventDefault(); openPalette(); return; }
  if (e.key === "Escape") { closePalette(); closeDrawer(); document.getElementById("theme-pop")?.classList.remove("show"); return; }
  const typing = e.target.closest?.("input, textarea, select, [contenteditable]");
  if (typing || e.ctrlKey || e.metaKey || e.altKey || !document.querySelector(".layout, .wr")) return;
  const key = e.key.toLowerCase();
  if (Date.now() - gKey < 1200) {
    gKey = 0;
    const to = { o: "/", e: "/endpoints", a: "/alerts", l: "/activity", w: "/warroom", u: ROLE === "admin" ? "/users" : null }[key];
    if (to) location.href = to;
    return;
  }
  if (key === "g") gKey = Date.now();
  else if (key === "/") { e.preventDefault(); openPalette(); }
  else if (key === "?") showHelp();
  else if (key === "t") toggleTheme();
  else if (key === "n") openDrawer();
  else if (key === "f") toggleFullscreen();
});

/* ------------------------------------------------------------ typewriter */
// Types HTML text into an element (tags are inserted whole). A new call cancels the old one.
function typeText(el, html, speed = 11) {
  const token = (el._typing || 0) + 1;
  el._typing = token;
  if (REDUCED) { el.innerHTML = html; return; }
  const parts = html.match(/<[^>]+>|&[a-z#0-9]+;|[\s\S]/g) || [];
  let i = 0, out = "";
  el.classList.add("caret");
  const step = () => {
    if (el._typing !== token) return;
    for (let n = 0; n < 2 && i < parts.length; n++) out += parts[i++];
    while (i < parts.length && parts[i].startsWith("<")) out += parts[i++];
    el.innerHTML = out;
    if (i < parts.length) setTimeout(step, speed);
    else setTimeout(() => el._typing === token && el.classList.remove("caret"), 1800);
  };
  step();
}

/* ------------------------------------------------------------ boot sequence */
// Plays once right after login: the EDR "powers up". Click or press a key to skip.
function runBoot() {
  let flag = null;
  try { flag = sessionStorage.getItem("boot"); sessionStorage.removeItem("boot"); } catch (e) {}
  if (flag !== "1" || REDUCED) return;
  const logo = document.querySelector(".brand .logo")?.innerHTML || "";
  const boot = document.createElement("div");
  boot.id = "boot";
  boot.innerHTML = `<div class="boot-core"><div class="boot-rings"><i></i><i></i><i></i><div class="logo">${logo}</div></div>
    <div class="boot-title">SENTINELOS</div><div class="boot-sub">Endpoint Detection &amp; Response</div>
    <div class="boot-log" id="boot-log"></div><div class="boot-bar"><div id="boot-bar"></div></div></div>
    <div class="boot-skip">Click or press any key to skip</div>`;
  document.body.appendChild(boot);
  const lines = ["Secure session established · CSRF token bound", "Process monitor online · psutil",
    "File integrity watcher armed · watchdog + SHA-256", "Network monitor online · suspicious ports + IoC list",
    "Risk engine loaded · MITRE ATT&amp;CK mapping", "Dashboard ready"];
  let done = false;
  const finish = () => {
    if (done) return; done = true;
    boot.classList.add("out");
    setTimeout(() => boot.remove(), 800);
  };
  lines.forEach((l, i) => setTimeout(() => {
    if (done) return;
    document.getElementById("boot-log").insertAdjacentHTML("beforeend", `<div class="reveal"><span class="ok">[ OK ]</span> ${l}</div>`);
    document.getElementById("boot-bar").style.width = `${(i + 1) / lines.length * 100}%`;
  }, 350 + i * 300));
  setTimeout(finish, 350 + lines.length * 300 + 500);
  boot.addEventListener("click", finish);
  document.addEventListener("keydown", finish, { once: true });
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".tabs").forEach(initTabs);
  document.querySelectorAll(".reveal").forEach((el, i) => { if (!el.style.getPropertyValue("--i")) el.style.setProperty("--i", i); });
  document.querySelectorAll("[data-sound]").forEach(b => b.classList.toggle("on-btn", soundOn()));
  initBackdrop();
  if (document.querySelector(".layout")) runBoot();
  if (document.querySelector(".layout, .wr")) poll(watchAlerts, 4000);
});
