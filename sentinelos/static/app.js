// SentinelOS dashboard helpers: API calls, small SVG charts, formatting.
const CSRF = document.querySelector('meta[name="csrf"]')?.content || "";
const ROLE = document.querySelector('meta[name="role"]')?.content || "viewer";
const SERVER_HOST = document.querySelector('meta[name="host"]')?.content || "";
const RISK_COLORS = { LOW: "#22c55e", MEDIUM: "#f59e0b", HIGH: "#ef4444", CRITICAL: "#a855f7" };
const SERIES_COLORS = ["#4f8cff", "#22c55e", "#f59e0b", "#e879f9", "#38bdf8", "#f472b6"];
const SVGNS = "http://www.w3.org/2000/svg";

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

function svgEl(tag, attrs = {}, parent) {
  const el = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  if (parent) parent.appendChild(el);
  return el;
}

// Line chart. series = [{name, color, points: [{t, v}]}], values 0..max
function lineChart(container, series, { max = 100, height = 220, unit = "%" } = {}) {
  const width = Math.max(container.clientWidth, 280);
  const pad = { l: 36, r: 10, t: 10, b: 24 };
  const all = series.flatMap(s => s.points);
  container.innerHTML = "";
  if (!all.length) { container.innerHTML = '<div class="empty">Waiting for data...</div>'; return; }
  const t0 = Math.min(...all.map(p => p.t)), t1 = Math.max(...all.map(p => p.t), t0 + 1);
  const x = t => pad.l + (t - t0) / (t1 - t0) * (width - pad.l - pad.r);
  const y = v => pad.t + (1 - Math.min(v, max) / max) * (height - pad.t - pad.b);
  const svg = svgEl("svg", { width, height, viewBox: `0 0 ${width} ${height}` }, container);
  for (let i = 0; i <= 4; i++) {
    const v = max * i / 4;
    svgEl("line", { x1: pad.l, x2: width - pad.r, y1: y(v), y2: y(v), stroke: "#24304d" }, svg);
    svgEl("text", { x: pad.l - 6, y: y(v) + 4, "text-anchor": "end" }, svg).textContent = Math.round(v) + unit;
  }
  svgEl("text", { x: pad.l, y: height - 6 }, svg).textContent = timeOf(t0);
  svgEl("text", { x: width - pad.r, y: height - 6, "text-anchor": "end" }, svg).textContent = timeOf(t1);
  series.forEach(s => {
    if (!s.points.length) return;
    const d = s.points.map((p, i) => `${i ? "L" : "M"}${x(p.t).toFixed(1)},${y(p.v).toFixed(1)}`).join("");
    const area = `${d}L${x(s.points.at(-1).t)},${y(0)}L${x(s.points[0].t)},${y(0)}Z`;
    svgEl("path", { d: area, fill: s.color, opacity: 0.08 }, svg);
    svgEl("path", { d, fill: "none", stroke: s.color, "stroke-width": 2.2, "stroke-linejoin": "round" }, svg);
    const last = s.points.at(-1);
    svgEl("circle", { cx: x(last.t), cy: y(last.v), r: 3.5, fill: s.color }, svg);
  });
  const legend = document.createElement("div");
  legend.className = "legend";
  legend.innerHTML = series.map(s =>
    `<span><i style="background:${s.color}"></i>${esc(s.name)} ${s.points.length ? Math.round(s.points.at(-1).v) + unit : ""}</span>`).join("");
  container.appendChild(legend);
}

// Donut chart. items = [{label, value, color}]
function donutChart(container, items, centerLabel = "") {
  const total = items.reduce((a, b) => a + b.value, 0);
  const size = 170, r = 64, stroke = 22, c = 2 * Math.PI * r;
  container.innerHTML = "";
  const wrap = document.createElement("div");
  wrap.className = "donut-wrap";
  const svg = svgEl("svg", { width: size, height: size, viewBox: `0 0 ${size} ${size}` }, wrap);
  svgEl("circle", { cx: size / 2, cy: size / 2, r, fill: "none", stroke: "#18223a", "stroke-width": stroke }, svg);
  let offset = 0;
  items.forEach(it => {
    if (!it.value) return;
    const len = it.value / total * c;
    svgEl("circle", {
      cx: size / 2, cy: size / 2, r, fill: "none", stroke: it.color, "stroke-width": stroke,
      "stroke-dasharray": `${len} ${c - len}`, "stroke-dashoffset": -offset,
      transform: `rotate(-90 ${size / 2} ${size / 2})`,
    }, svg);
    offset += len;
  });
  const t1 = svgEl("text", { x: size / 2, y: size / 2 + 2, "text-anchor": "middle", style: "font-size:24px;font-weight:700;fill:#e6ebf5" }, svg);
  t1.textContent = total;
  const t2 = svgEl("text", { x: size / 2, y: size / 2 + 20, "text-anchor": "middle" }, svg);
  t2.textContent = centerLabel;
  const legend = document.createElement("div");
  legend.innerHTML = items.map(it =>
    `<div class="legend" style="margin:6px 0"><span><i style="background:${it.color}"></i>${esc(it.label)}: <b style="color:#e6ebf5">${it.value}</b></span></div>`).join("");
  wrap.appendChild(legend);
  container.appendChild(wrap);
}

// Horizontal bars. items = [{label, value, color}]
function barList(container, items) {
  if (!items.length) { container.innerHTML = '<div class="empty">No data yet</div>'; return; }
  const max = Math.max(...items.map(i => i.value), 1);
  container.innerHTML = items.map(i => `
    <div class="hbar"><span class="trunc">${esc(i.label)}</span>
      <div class="track"><div class="fill" style="width:${i.value / max * 100}%;background:${i.color}"></div></div>
      <b>${i.value}</b></div>`).join("");
}

// Tiny line without axes, for endpoint cards.
function sparkline(container, values, color) {
  const w = Math.max(container.clientWidth, 120), h = 40;
  container.innerHTML = "";
  if (values.length < 2) return;
  const svg = svgEl("svg", { width: w, height: h }, container);
  const x = i => i / (values.length - 1) * w;
  const y = v => h - 2 - Math.min(v, 100) / 100 * (h - 4);
  const d = values.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join("");
  svgEl("path", { d: `${d}L${w},${h}L0,${h}Z`, fill: color, opacity: 0.12 }, svg);
  svgEl("path", { d, fill: "none", stroke: color, "stroke-width": 2 }, svg);
}

// Click a <th data-key> to sort. Returns a function that sorts rows.
function sortable(table, state, onChange) {
  table.querySelectorAll("th[data-key]").forEach(th => th.addEventListener("click", () => {
    state.dir = state.key === th.dataset.key ? -state.dir : -1;
    state.key = th.dataset.key;
    onChange();
  }));
  return rows => !state.key ? rows : [...rows].sort((a, b) => {
    const va = a[state.key], vb = b[state.key];
    return (typeof va === "number" ? va - vb : String(va).localeCompare(String(vb))) * state.dir;
  });
}

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

function toast(alert) {
  const box = document.createElement("div");
  box.className = `toast ${alert.severity}`;
  box.innerHTML = `<div style="display:flex;justify-content:space-between"><b>${esc(alert.severity)} RISK</b>
    <span class="muted small">${esc(alert.endpoint)}</span></div>
    <div>${esc(alert.alert_type)} · ${esc(alert.process)} (PID ${esc(alert.pid)})</div>
    <div class="muted small">${esc(alert.reasons)}</div>`;
  box.onclick = () => location.href = "/alerts";
  document.getElementById("toasts").appendChild(box);
  setTimeout(() => box.remove(), 12000);
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
  const counter = document.getElementById("nav-alerts");
  const fresh = alerts.filter(a => a.status === "NEW").length;
  if (counter) counter.textContent = fresh ? fresh : "";
}
document.addEventListener("DOMContentLoaded", () => poll(watchAlerts, 4000));
