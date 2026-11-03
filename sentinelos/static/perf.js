// SentinelOS Overview: Windows Task Manager style "Performance" view.
// Left: one tile per resource (CPU, Memory, Disk, each network adapter, ...).
// Right: details of the tile you clicked (big 60-second graph + numbers).
// Uses helpers from app.js (esc, svgEl, donutChart, barList, RISK_COLORS, SERVER_HOST).
const Perf = (() => {
  const WINDOW = 60;                                   // seconds shown on the big graph
  const COLORS = { cpu: "#4F7A8A", mem: "#8A6A8F", disk: "#6F8559", net: "#C2762B", sec: "#985D1D" };
  const LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
  const CHART_TITLES = { risk: "Risk levels", types: "Alerts by type", eps: "Alerts by laptop" };
  let data = null, host = null, sel = "cpu";

  try {
    host = localStorage.getItem("overviewHost");
    sel = localStorage.getItem("overviewTile") || "cpu";
  } catch (e) { /* storage blocked: use defaults */ }

  // ---------- formatting ----------
  const num = v => (v === null || v === undefined || v === "" || !Number.isFinite(+v)) ? null : +v;
  const pad = n => String(n).padStart(2, "0");
  const dash = "—";
  function fmtBytes(b) {
    b = num(b); if (b === null) return dash;
    const units = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    while (b >= 1024 && i < units.length - 1) { b /= 1024; i++; }
    return `${i ? b.toFixed(1) : Math.round(b)} ${units[i]}`;
  }
  const fmtDisk = bps => num(bps) === null ? dash : `${fmtBytes(bps)}/s`;
  function fmtBits(Bps) {                              // network speeds are shown in bits, like Task Manager
    Bps = num(Bps); if (Bps === null) return dash;
    const bits = Bps * 8;
    if (bits >= 1e9) return `${(bits / 1e9).toFixed(1)} Gbps`;
    if (bits >= 1e6) return `${(bits / 1e6).toFixed(1)} Mbps`;
    return `${Math.round(bits / 1e3)} Kbps`;
  }
  const fmtGHz = mhz => num(mhz) === null ? dash : `${(mhz / 1000).toFixed(2)} GHz`;
  function fmtUptime(sec) {                            // days:hh:mm:ss
    sec = num(sec); if (sec === null) return dash;
    return `${Math.floor(sec / 86400)}:${pad(Math.floor(sec % 86400 / 3600))}:${pad(Math.floor(sec % 3600 / 60))}:${pad(Math.floor(sec % 60))}`;
  }
  const pct = (v, d = 0) => num(v) === null ? dash : `${(+v).toFixed(d)}%`;
  const show = v => (v === null || v === undefined || v === "") ? dash : esc(v);

  // Smallest "nice" scale (1-2-5 steps) that fits `value`; `floor` is the lowest scale.
  function niceMax(value, floor) {
    for (let base = floor; ; base *= 10)
      for (const step of [1, 2, 5]) if (base * step >= value) return base * step;
  }
  const maxOf = (series, key = "v") => Math.max(0, ...series.flatMap(s => s.points.map(p => p[key])));

  // ---------- drawing ----------
  // Draws one line + filled area into an <svg>. Newest point is at the right edge.
  function drawSeries(svg, s, { w, h, t0, max }) {
    const pts = s.points.filter(p => p.v !== null && p.t >= t0 - 15);
    if (!pts.length) return;
    const x = t => (t - t0) / WINDOW * w;
    const y = v => (h - 1) - Math.min(Math.max(v, 0), max) / max * (h - 2);
    const d = pts.map((p, i) => `${i ? "L" : "M"}${x(p.t).toFixed(1)},${y(p.v).toFixed(1)}`).join("");
    if (s.fill !== false)
      svgEl("path", { d: `${d}L${x(pts.at(-1).t).toFixed(1)},${h}L${x(pts[0].t).toFixed(1)},${h}Z`,
        fill: s.color, opacity: 0.22 }, svg);
    const line = svgEl("path", { d, fill: "none", stroke: s.color, "stroke-width": 1.6,
      "stroke-linejoin": "round" }, svg);
    if (s.dashed) line.setAttribute("stroke-dasharray", "5 3");
  }

  // Big graph with a scrolling grid. series = [{color, points:[{t,v}], dashed?}]
  function bigGraph(box, series, { max = 100, height = 300, color }) {
    box.innerHTML = "";
    box.style.setProperty("--c", color);
    const w = Math.max(box.clientWidth, 280), h = height;
    const svg = svgEl("svg", { width: w, height: h, viewBox: `0 0 ${w} ${h}` }, box);
    const tEnd = Math.max(0, ...series.flatMap(s => s.points.map(p => p.t)));
    const t0 = tEnd - WINDOW, step = WINDOW / 10;
    const grid = { stroke: color, "stroke-opacity": 0.2 };
    for (let i = 1; i < 10; i++) svgEl("line", { x1: 0, x2: w, y1: h * i / 10, y2: h * i / 10, ...grid }, svg);
    if (tEnd) for (let t = Math.ceil(t0 / step) * step; t < tEnd; t += step)
      svgEl("line", { x1: (t - t0) / WINDOW * w, x2: (t - t0) / WINDOW * w, y1: 0, y2: h, ...grid }, svg);
    series.forEach(s => drawSeries(svg, s, { w, h, t0, max }));
    if (!tEnd) svgEl("text", { x: w / 2, y: h / 2, "text-anchor": "middle" }, svg).textContent = "Waiting for data...";
  }

  // Small graph shown inside a tile.
  function miniGraph(box, series, { max = 100, color }) {
    const w = 72, h = 46;
    box.style.setProperty("--c", color);
    const svg = svgEl("svg", { width: w, height: h, viewBox: `0 0 ${w} ${h}` }, box);
    const tEnd = Math.max(0, ...series.flatMap(s => s.points.map(p => p.t)));
    series.forEach(s => drawSeries(svg, s, { w, h, t0: tEnd - WINDOW, max }));
  }

  // ---------- data for one laptop ----------
  const pts = (e, fn) => e.history.map(p => ({ t: p.t, v: num(fn(p)) }));
  const nicPoints = (e, name, i) => e.history.filter(p => p.net && p.net[name])
    .map(p => ({ t: p.t, v: num(p.net[name][i]) }));
  const latest = (e, key) => { const p = e.history.at(-1); return p ? p[key] : undefined; };

  function tilesFor(e, d) {
    const s = e.system || {}, tiles = [];
    const ramPct = num(s.ram_used_percent);
    tiles.push({ id: "cpu", title: "CPU", color: COLORS.cpu, max: 100,
      sub: `${pct(s.cpu_percent)} ${fmtGHz(s.cpu_mhz) === dash ? "" : fmtGHz(s.cpu_mhz)}`,
      series: [{ color: COLORS.cpu, points: pts(e, p => p.cpu) }] });
    tiles.push({ id: "mem", title: "Memory", color: COLORS.mem, max: 100,
      sub: num(s.ram_total) ? `${fmtBytes(s.ram_used)}/${fmtBytes(s.ram_total)} (${pct(ramPct)})` : pct(ramPct),
      series: [{ color: COLORS.mem, points: pts(e, p => p.ram) }] });

    if (s.disk_io) {
      const drives = (s.drives || []).map(x => x.mount).join(" ");
      const diskSeries = [{ color: COLORS.disk, points: pts(e, p => p.disk_active) }];
      tiles.push({ id: "disk", title: `Disk ${drives ? "(" + drives + ")" : ""}`, color: COLORS.disk, max: 100,
        sub: pct(latest(e, "disk_active")), series: diskSeries });
    } else {
      tiles.push({ id: "disk", title: "Disk", color: COLORS.disk, sub: "Not reported", series: [], max: 100 });
    }

    const nics = Object.keys(s.net || {});
    nics.forEach(name => {
      const both = e.history.filter(p => p.net && p.net[name]).map(p => ({ t: p.t, v: p.net[name][0] + p.net[name][1] }));
      const top = niceMax(maxOf([{ points: both }]), 12500);
      const last = (e.history.at(-1) || {}).net;
      const rate = last && last[name] ? last[name] : [null, null];
      tiles.push({ id: "net:" + name, title: name, color: COLORS.net, max: top,
        sub: `S: ${fmtBits(rate[0])} R: ${fmtBits(rate[1])}`,
        series: [{ color: COLORS.net, points: both }] });
    });
    if (!nics.length)
      tiles.push({ id: "net:", title: "Network", color: COLORS.net, sub: "Not reported", series: [], max: 100 });

    const high = d.risk.HIGH + d.risk.CRITICAL;
    tiles.push({ id: "risk", title: "Risk levels", icon: "🎯", color: COLORS.sec, sub: `${high} high / critical`, divider: true });
    tiles.push({ id: "types", title: "Alerts by type", icon: "🚨", color: COLORS.sec, sub: `${d.alert_total} alerts, ${d.new_alerts} new` });
    if (d.endpoints.length > 1)
      tiles.push({ id: "eps", title: "Alerts by laptop", icon: "💻", color: COLORS.sec, sub: `${Object.keys(d.by_endpoint).length} laptops with alerts` });
    return tiles;
  }

  // ---------- detail panels ----------
  const stat = (label, value, big = true) =>
    `<div class="pv-stat ${big ? "big" : ""}"><span>${esc(label)}</span><b>${value}</b></div>`;
  const kv = rows => `<table class="pv-kv">${rows.map(([k, v]) => `<tr><td>${esc(k)}</td><td>${v}</td></tr>`).join("")}</table>`;
  const axis = (left, right) => `<div class="pv-axis"><span>${left}</span><span>${right}</span></div>`;
  const head = (title, right = "") => `<div class="pv-head"><h2>${esc(title)}</h2><div>${right}</div></div>`;
  const note = text => `<div class="empty">${text}</div>`;
  const OLD_AGENT = "This laptop's agent does not report disk or network data. " +
    "Rebuild the agent package (python build_agent.py) and run the new version on that laptop.";

  function cpuPanel(e) {
    const s = e.system || {}, graphs = [];
    const html = head("CPU", esc(s.cpu_model || "")) + axis("% Utilization", "100%") +
      `<div class="pv-graph" id="pv-g0"></div>` + axis(`${WINDOW} seconds`, "0") +
      `<div class="pv-stats"><div>
         <div class="pv-row">${stat("Utilization", pct(s.cpu_percent))}${stat("Speed", fmtGHz(s.cpu_mhz))}</div>
         <div class="pv-row">${stat("Processes", show(s.process_count ?? e.process_count))}${stat("Threads", show(e.threads))}${stat("Handles", show(e.handles))}</div>
         ${stat("Up time", fmtUptime(s.uptime_sec), false)}
       </div>${kv([["Base speed:", fmtGHz(s.cpu_base_mhz)], ["Cores:", show(s.cpu_physical)],
         ["Logical processors:", show(s.cpu_cores)], ["Virtualization:", show(s.virtualization)]])}</div>`;
    graphs.push(["pv-g0", [{ color: COLORS.cpu, points: pts(e, p => p.cpu) }], { max: 100, color: COLORS.cpu }]);
    return { html, graphs };
  }

  function memPanel(e) {
    const s = e.system || {}, total = num(s.ram_total), used = num(s.ram_used);
    const usedPct = total && used !== null ? used / total * 100 : num(s.ram_used_percent) || 0;
    const html = head("Memory", total ? fmtBytes(total) : "") + axis("Memory usage", total ? fmtBytes(total) : "100%") +
      `<div class="pv-graph" id="pv-g0"></div>` + axis(`${WINDOW} seconds`, "0") +
      `<div class="pv-label">Memory composition</div>
       <div class="pv-bar" style="--c:${COLORS.mem}"><div style="width:${usedPct.toFixed(1)}%"></div></div>
       <div class="pv-stats"><div>
         <div class="pv-row">${stat("In use", fmtBytes(s.ram_used))}${stat("Available", fmtBytes(s.ram_available))}</div>
         <div class="pv-row">${stat("Usage", pct(usedPct), false)}${stat("Total", fmtBytes(s.ram_total), false)}</div>
       </div>${kv([["Cached:", fmtBytes(s.ram_cached)],
         ["Page file / swap:", num(s.swap_total) ? `${fmtBytes(s.swap_used)} / ${fmtBytes(s.swap_total)}` : dash]])}</div>`;
    return { html, graphs: [["pv-g0", [{ color: COLORS.mem, points: pts(e, p => p.ram) }], { max: 100, color: COLORS.mem }]] };
  }

  function diskPanel(e) {
    const s = e.system || {};
    if (!s.disk_io) return { html: head("Disk") + note(OLD_AGENT), graphs: [] };
    const read = pts(e, p => p.disk_read), write = pts(e, p => p.disk_write);
    const top = niceMax(maxOf([{ points: read }, { points: write }]), 1e5);
    const drives = (s.drives || []).map(dv => {
      const used = dv.total ? dv.used / dv.total * 100 : 0;
      return `<tr><td>${esc(dv.mount)}</td><td><div class="pv-bar thin" style="--c:${COLORS.disk}"><div style="width:${used.toFixed(0)}%"></div></div></td>
        <td>${fmtBytes(dv.used)} of ${fmtBytes(dv.total)}</td></tr>`;
    }).join("");
    const html = head("Disk", esc((s.drives || []).map(x => x.mount).join(" "))) + axis("Active time", "100%") +
      `<div class="pv-graph" id="pv-g0"></div>` + axis(`${WINDOW} seconds`, "0") +
      axis("Disk transfer rate", fmtDisk(top)) + `<div class="pv-graph" id="pv-g1"></div>` + axis(`${WINDOW} seconds`, "0") +
      `<div class="pv-stats"><div><div class="pv-row">${stat("Active time", pct(latest(e, "disk_active")))}</div>
         <div class="pv-row">${stat("Read speed", fmtDisk(latest(e, "disk_read")))}${stat("Write speed", fmtDisk(latest(e, "disk_write")))}</div></div>
         <table class="pv-kv drives">${drives || `<tr><td>${dash}</td></tr>`}</table></div>`;
    return { html, graphs: [
      ["pv-g0", [{ color: COLORS.disk, points: pts(e, p => p.disk_active) }], { max: 100, height: 150, color: COLORS.disk }],
      ["pv-g1", [{ color: COLORS.disk, points: read }, { color: COLORS.disk, points: write, dashed: true, fill: false }],
        { max: top, height: 150, color: COLORS.disk }]] };
  }

  function netPanel(e, name) {
    const s = e.system || {}, nic = (s.net || {})[name];
    if (!nic) return { html: head("Network") + note(s.net ? "That network adapter is no longer active." : OLD_AGENT), graphs: [] };
    const recv = nicPoints(e, name, 1), sent = nicPoints(e, name, 0);
    const top = niceMax(maxOf([{ points: recv }, { points: sent }]), 12500);
    const last = (e.history.at(-1) || {}).net, rate = last && last[name] ? last[name] : [null, null];
    const html = head(name, nic.speed ? `Up, ${nic.speed} Mbps` : "Up") + axis("Throughput", fmtBits(top)) +
      `<div class="pv-graph" id="pv-g0"></div>` + axis(`${WINDOW} seconds`, "0") +
      `<div class="pv-stats"><div><div class="pv-row">${stat("Send", fmtBits(rate[0]))}${stat("Receive", fmtBits(rate[1]))}</div></div>
         ${kv([["Adapter name:", esc(name)], ["Link speed:", nic.speed ? `${nic.speed} Mbps` : dash],
           ["Total sent:", fmtBytes(nic.sent)], ["Total received:", fmtBytes(nic.recv)]])}</div>`;
    return { html, graphs: [["pv-g0", [{ color: COLORS.net, points: recv }, { color: COLORS.net, points: sent, dashed: true, fill: false }],
      { max: top, color: COLORS.net }]] };
  }

  function chartPanel(id, d) {
    const bars = (counts, offset) => Object.entries(counts).sort((a, b) => b[1] - a[1])
      .map(([k, v], i) => ({ label: k, value: v, color: seriesColor(i + offset) }));
    const draw = box => {
      if (id === "risk") donutChart(box, LEVELS.map(l => ({ label: l, value: d.risk[l], color: RISK_COLORS[l] })), "processes");
      if (id === "types") barList(box, bars(d.by_type, 2));
      if (id === "eps") barList(box, bars(d.by_endpoint, 0));
    };
    return { html: head(CHART_TITLES[id], "All visible laptops") + `<div id="pv-chart" class="pv-chart"></div>`, graphs: [], after: () => draw(document.getElementById("pv-chart")) };
  }

  // ---------- page ----------
  function save() { try { localStorage.setItem("overviewHost", host || ""); localStorage.setItem("overviewTile", sel); } catch (e) {} }

  // The picker and the tiles are updated in place (not rebuilt) every few seconds, so an
  // open dropdown stays open and a click is never lost because the button was replaced.
  function renderList(eps, tiles) {
    const pick = document.getElementById("pf-pick"), box = document.getElementById("pf-tiles");
    const pickSig = host + "|" + eps.map(x => x.hostname + x.online).join(",");
    if (pick.dataset.sig !== pickSig) {
      pick.dataset.sig = pickSig;
      pick.innerHTML = eps.length > 1
        ? `<select id="pf-host" aria-label="Laptop">${eps.map(x => `<option value="${esc(x.hostname)}" ${x.hostname === host ? "selected" : ""}>${x.online ? "● " : "○ "}${esc(x.hostname)}</option>`).join("")}</select>`
        : `<div class="pf-one">💻 ${esc(host)}</div>`;
    }
    const sig = tiles.map(t => t.id + (t.divider ? "!" : "")).join("|");
    if (box.dataset.sig !== sig) {
      box.dataset.sig = sig;
      box.innerHTML = tiles.map(t => `${t.divider ? '<div class="pf-sep">Security</div>' : ""}
        <button class="tile" data-id="${esc(t.id)}"><div class="mini"></div>
          <div class="tt"><b></b><small></small></div></button>`).join("");
    }
    const buttons = box.querySelectorAll(".tile");
    tiles.forEach((t, i) => {
      const btn = buttons[i], mini = btn.querySelector(".mini");
      btn.classList.toggle("active", t.id === sel);
      btn.setAttribute("aria-pressed", t.id === sel);
      btn.style.setProperty("--c", t.color);
      btn.querySelector("b").textContent = t.title;
      btn.querySelector("small").textContent = t.sub || "";
      mini.innerHTML = t.icon ? `<span>${t.icon}</span>` : "";
      if (t.series && t.series.length) miniGraph(mini, t.series, { max: t.max, color: t.color });
    });
  }

  function render() {
    if (!data) return;
    const eps = data.endpoints, panel = document.getElementById("pf-panel");
    if (!eps.length) {
      document.getElementById("pf-pick").innerHTML = document.getElementById("pf-tiles").innerHTML = "";
      document.getElementById("pf-pick").dataset.sig = document.getElementById("pf-tiles").dataset.sig = "";
      panel.innerHTML = note("No laptops are reporting yet.");
      return;
    }
    if (!eps.some(e => e.hostname === host))
      host = (eps.find(e => e.hostname === SERVER_HOST) || eps.find(e => e.online) || eps[0]).hostname;
    const e = eps.find(x => x.hostname === host);
    const tiles = tilesFor(e, data);
    if (!tiles.some(t => t.id === sel)) sel = "cpu";
    renderList(eps, tiles);

    const view = sel === "cpu" ? cpuPanel(e) : sel === "mem" ? memPanel(e) : sel === "disk" ? diskPanel(e)
      : sel.startsWith("net:") ? netPanel(e, sel.slice(4)) : chartPanel(sel, data);
    const offline = e.online ? "" : `<div class="pv-offline">⚠ ${esc(e.hostname)} is offline. Showing the last data it sent.</div>`;
    panel.innerHTML = offline + view.html;
    view.graphs.forEach(([id, series, opts]) => bigGraph(document.getElementById(id), series, { height: 300, ...opts }));
    if (view.after) view.after();
  }

  document.addEventListener("click", ev => {
    const btn = ev.target.closest("#pf-tiles .tile");
    if (!btn) return;
    sel = btn.dataset.id; save(); render();
  });
  document.addEventListener("change", ev => {
    if (ev.target.id === "pf-host") { host = ev.target.value; save(); render(); }
  });
  let resizeTimer;
  window.addEventListener("resize", () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(render, 150); });

  return { update(d) { data = d; render(); } };
})();
