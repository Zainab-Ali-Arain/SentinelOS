// Scene3D: a tiny dependency-free 3D renderer on <canvas> for the dashboard.
// No WebGL library is downloaded, so the 3D views also work on an offline LAN.
//
//   const scene = new Scene3D(hostDiv, { tooltip: n => "<b>..</b>", onClick: n => ... });
//   scene.set(nodes, edges);
//
// node = { id, x, y, z, r, color, label?, alpha?, pulse?, showLabel?, data?,
//          orbit?: { parent, radius, speed, phase, tilt } }   (colour may be "var(--x)")
// edge = { a, b, color?, width?, flow?, curve? }
// Drag to rotate, wheel / pinch to zoom, hover for details, click a node.
(function () {
  const REDUCED = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function resolve(color) {
    if (typeof cssColor === "function") return cssColor(color);
    if (!String(color).startsWith("var(")) return color;
    return getComputedStyle(document.documentElement).getPropertyValue(color.slice(4, -1).trim()).trim() || "#888";
  }
  function rgba(color, a) {
    const c = resolve(color);
    if (c.startsWith("#")) {
      const h = c.length === 4 ? c.slice(1).split("").map(x => x + x).join("") : c.slice(1, 7);
      const n = parseInt(h, 16);
      return `rgba(${n >> 16 & 255},${n >> 8 & 255},${n & 255},${a})`;
    }
    const m = c.match(/[\d.]+/g);
    return m ? `rgba(${m[0]},${m[1]},${m[2]},${a})` : c;
  }
  const ICONS = {
    plus: '<path d="M12 5v14M5 12h14"/>', minus: '<path d="M5 12h14"/>',
    reset: '<path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5"/>',
    spin: '<path d="M21 12a9 9 0 1 1-6.2-8.6"/><path d="M21 3v6h-6"/>',
  };
  const svgIcon = p => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">${p}</svg>`;

  class Scene3D {
    constructor(host, opts = {}) {
      this.host = host;
      this.o = Object.assign({
        autoRotate: true, spin: 0.0022, distance: 760, fov: 620, yaw: 0.6, pitch: -0.42,
        floorY: null, floorRings: 5, floorStep: 80, sphere: null, interactive: true, hud: true,
        hint: "Drag to rotate · scroll to zoom", tooltip: null, onClick: null, fit: 1,
      }, opts);
      this.yaw = this.o.yaw; this.pitch = this.o.pitch; this.zoom = 1;
      this.vy = 0; this.vp = 0; this.spinning = this.o.autoRotate && !REDUCED; this.idleAt = 0;
      this.nodes = new Map(); this.edges = []; this.proj = []; this.hover = null;
      this.sprites = new Map(); this.t = 0; this.visible = true; this.pointers = new Map();
      this.fx = []; this.goal = null;

      this.canvas = document.createElement("canvas");
      host.appendChild(this.canvas);
      this.ctx = this.canvas.getContext("2d");
      if (this.o.interactive) {
        this.tip = document.createElement("div");
        this.tip.className = "tip3d";
        host.appendChild(this.tip);
        this._bind();
      }
      if (this.o.hud) this._hud();
      this._resize();
      new ResizeObserver(() => this._resize()).observe(host);
      new IntersectionObserver(es => { this.visible = es[0].isIntersecting; }).observe(host);
      window.addEventListener("themechange", () => this.sprites.clear());
      this._loop = this._loop.bind(this);
      requestAnimationFrame(this._loop);
    }

    /* ---------------------------------------------------------------- data */
    set(nodes, edges = []) {
      const now = performance.now(), seen = new Set();
      nodes.forEach(n => {
        seen.add(n.id);
        const old = this.nodes.get(n.id);
        const parent = n.orbit ? this.nodes.get(n.orbit.parent) : null;
        const start = old || {
          x: parent ? parent.x : (n.from?.x ?? 0), y: parent ? parent.y : (n.from?.y ?? 0),
          z: parent ? parent.z : (n.from?.z ?? 0), born: now,
        };
        this.nodes.set(n.id, Object.assign(start, n, {
          tx: n.x ?? 0, ty: n.y ?? 0, tz: n.z ?? 0, x: start.x, y: start.y, z: start.z, born: start.born, dying: 0,
        }));
      });
      this.nodes.forEach((n, id) => { if (!seen.has(id) && !n.dying) n.dying = now; });
      this.edges = edges;
    }

    resetView() { this.yaw = this.o.yaw; this.pitch = this.o.pitch; this.zoom = 1; this.vy = this.vp = 0; this.goal = null; }

    /* ------------------------------------------------------------- effects */
    // A comet flies in from deep space and hits the node; then a shockwave.
    strike(nodeId, color = "var(--high)", { onImpact, duration = 1600 } = {}) {
      const n = this.nodes.get(nodeId);
      if (!n) return;
      const len = Math.hypot(n.x, n.y, n.z) || 1, side = Math.random() - .5;
      const start = { x: n.x / len * 950 + side * 600, y: 520 + Math.random() * 200, z: n.z / len * 950 - side * 400 };
      this.fx.push({ kind: "comet", node: n, start, color, t0: performance.now(), dur: REDUCED ? 1 : duration, onImpact });
    }
    burst(node, color = "var(--high)") {
      this.fx.push({ kind: "burst", node, color, t0: performance.now(), dur: 1500 });
    }
    // Turn the camera so this node faces the viewer.
    focus(nodeId) {
      const n = this.nodes.get(nodeId);
      if (!n) return;
      const flat = Math.hypot(n.tx, n.tz) || 1;
      this.goal = { yaw: Math.atan2(-n.tx, -n.tz), pitch: Math.max(-1.2, Math.min(1.2, Math.atan2(-n.ty, flat))) };
      this.vy = this.vp = 0; this.idleAt = performance.now() + 6000;
    }

    _drawFx(now) {
      const ctx = this.ctx;
      this.fx = this.fx.filter(f => {
        const q = (now - f.t0) / f.dur, n = f.node;
        if (f.kind === "comet") {
          const end = { x: n.x, y: n.y, z: n.z };
          const lift = 1 + 260 / (Math.hypot(end.x, end.y, end.z) || 1);
          const mid = { x: (f.start.x + end.x) / 2 * lift, y: (f.start.y + end.y) / 2 + 120, z: (f.start.z + end.z) / 2 * lift };
          const at = u => {
            const a = (1 - u) * (1 - u), b = 2 * (1 - u) * u, c = u * u;
            return this._project(a * f.start.x + b * mid.x + c * end.x, a * f.start.y + b * mid.y + c * end.y, a * f.start.z + b * mid.z + c * end.z);
          };
          const u = Math.min(1, Math.pow(Math.max(q, 0), 1.35));
          // tail: segments that get thinner and fainter
          let prev = at(u);
          for (let k = 1; k <= 22; k++) {
            const uk = Math.max(0, u - k * 0.016), p = at(uk);
            ctx.strokeStyle = rgba(f.color, (1 - k / 22) * .9);
            ctx.lineWidth = Math.max(.5, (1 - k / 22) * 5 * Math.max(prev.s, .5));
            ctx.beginPath(); ctx.moveTo(prev.sx, prev.sy); ctx.lineTo(p.sx, p.sy); ctx.stroke();
            prev = p;
            if (uk === 0) break;
          }
          const head = at(u), hr = 26 * Math.max(head.s, .5);
          ctx.drawImage(this._sprite(f.color), head.sx - hr, head.sy - hr, hr * 2, hr * 2);
          ctx.fillStyle = rgba("#ffffff", .95);
          ctx.beginPath(); ctx.arc(head.sx, head.sy, 2.6 * Math.max(head.s, .6), 0, Math.PI * 2); ctx.fill();
          if (q >= 1) { this.burst(n, f.color); if (f.onImpact) f.onImpact(n); return false; }
          return true;
        }
        // burst: flash + three expanding shock rings
        const p = n._p;
        if (!p || q >= 1) return q < 1;
        if (q < .35) {
          const fr = (p.r + 70 * p.s) * (1 - q / .35 * .4);
          ctx.globalAlpha = 1 - q / .35;
          ctx.drawImage(this._sprite(f.color), p.sx - fr, p.sy - fr, fr * 2, fr * 2);
          ctx.globalAlpha = 1;
        }
        [0, .14, .28].forEach(d => {
          const qq = (q - d) / (1 - d);
          if (qq <= 0) return;
          ctx.strokeStyle = rgba(f.color, (1 - qq) * .9);
          ctx.lineWidth = 3 * (1 - qq) + .5;
          ctx.beginPath(); ctx.ellipse(p.sx, p.sy, p.r + qq * 150 * p.s, (p.r + qq * 150 * p.s) * .55, 0, 0, Math.PI * 2); ctx.stroke();
        });
        return true;
      });
    }

    /* ------------------------------------------------------------- helpers */
    _resize() {
      const r = this.host.getBoundingClientRect();
      this.w = Math.max(r.width, 10); this.h = Math.max(r.height, 10);
      this.dpr = Math.min(window.devicePixelRatio || 1, 2);
      this.canvas.width = this.w * this.dpr; this.canvas.height = this.h * this.dpr;
      this.ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
      // fit the scene to the box: smaller boxes zoom out a little
      this.scaleFit = Math.min(1, Math.min(this.w, this.h * 1.5) / 760) * this.o.fit;
    }

    _project(x, y, z) {
      const cy = Math.cos(this.yaw), sy = Math.sin(this.yaw), cp = Math.cos(this.pitch), sp = Math.sin(this.pitch);
      const x1 = x * cy - z * sy, z1 = x * sy + z * cy;           // around Y
      const y2 = y * cp - z1 * sp, z2 = y * sp + z1 * cp;          // around X
      const dist = this.o.distance / this.zoom;
      const s = this.o.fov / Math.max(dist + z2, 40) * this.scaleFit;
      return { sx: this.w / 2 + x1 * s, sy: this.h / 2 - y2 * s, s, z: z2 };
    }

    _sprite(color) {
      const key = resolve(color);
      if (!this.sprites.has(key)) {
        const c = document.createElement("canvas"); c.width = c.height = 64;
        const g = c.getContext("2d"), grad = g.createRadialGradient(32, 32, 0, 32, 32, 32);
        grad.addColorStop(0, rgba(color, .55)); grad.addColorStop(.35, rgba(color, .22)); grad.addColorStop(1, rgba(color, 0));
        g.fillStyle = grad; g.fillRect(0, 0, 64, 64);
        this.sprites.set(key, c);
      }
      return this.sprites.get(key);
    }

    /* --------------------------------------------------------- interaction */
    _bind() {
      const h = this.host;
      h.addEventListener("pointerdown", e => {
        if (e.target.closest(".hud")) return;
        h.setPointerCapture(e.pointerId);
        this.pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
        this.drag = { x: e.clientX, y: e.clientY, moved: 0 };
        this.vy = this.vp = 0; this.idleAt = performance.now(); this.goal = null;
        h.classList.add("dragging");
      });
      h.addEventListener("pointermove", e => {
        const rect = h.getBoundingClientRect();
        this.mouse = { x: e.clientX - rect.left, y: e.clientY - rect.top };
        if (!this.pointers.has(e.pointerId)) return;
        const prev = this.pointers.get(e.pointerId);
        this.pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
        if (this.pointers.size === 2) {                     // pinch to zoom
          const [a, b] = [...this.pointers.values()];
          const d = Math.hypot(a.x - b.x, a.y - b.y);
          if (this.pinch) this.zoom = Math.min(3, Math.max(.45, this.zoom * d / this.pinch));
          this.pinch = d; return;
        }
        const dx = e.clientX - prev.x, dy = e.clientY - prev.y;
        this.drag.moved += Math.abs(dx) + Math.abs(dy);
        this.yaw += dx * 0.008; this.pitch = Math.max(-1.45, Math.min(1.45, this.pitch + dy * 0.006));
        this.vy = dx * 0.008; this.vp = dy * 0.006; this.idleAt = performance.now();
      });
      const up = e => {
        this.pointers.delete(e.pointerId); this.pinch = null;
        if (this.pointers.size) return;
        h.classList.remove("dragging");
        if (this.drag && this.drag.moved < 6 && this.hover && this.o.onClick) this.o.onClick(this.hover);
        this.drag = null;
      };
      h.addEventListener("pointerup", up);
      h.addEventListener("pointercancel", up);
      h.addEventListener("pointerleave", () => { this.mouse = null; });
      h.addEventListener("wheel", e => {
        e.preventDefault();
        this.zoom = Math.min(3, Math.max(.45, this.zoom * Math.exp(-e.deltaY * 0.0012)));
        this.idleAt = performance.now();
      }, { passive: false });
      h.addEventListener("dblclick", () => this.resetView());
    }

    _hud() {
      const hud = document.createElement("div");
      hud.className = "hud";
      const btn = (icon, title, fn) => {
        const b = document.createElement("button");
        b.type = "button"; b.title = title; b.innerHTML = svgIcon(ICONS[icon]);
        b.addEventListener("click", e => { e.stopPropagation(); fn(b); });
        hud.appendChild(b); return b;
      };
      btn("plus", "Zoom in", () => { this.zoom = Math.min(3, this.zoom * 1.25); });
      btn("minus", "Zoom out", () => { this.zoom = Math.max(.45, this.zoom / 1.25); });
      btn("reset", "Reset view", () => this.resetView());
      const s = btn("spin", "Auto-rotate on/off", b => { this.spinning = !this.spinning; b.classList.toggle("on-btn", this.spinning); });
      s.classList.toggle("on-btn", this.spinning);
      this.host.appendChild(hud);
      if (this.o.hint) {
        const hint = document.createElement("div");
        hint.className = "hint3d"; hint.textContent = this.o.hint;
        this.host.appendChild(hint);
      }
    }

    /* ----------------------------------------------------------- rendering */
    _loop(now) {
      requestAnimationFrame(this._loop);
      if (!this.visible || document.hidden || !this.host.getClientRects().length) return;
      const dt = Math.min(now - (this._last || now), 50); this._last = now; this.t += dt;
      // motion: inertia after a drag, then gentle auto-rotation
      if (this.goal && !this.drag) {   // glide to a focused node (shortest way round)
        let dy = this.goal.yaw - this.yaw;
        dy = Math.atan2(Math.sin(dy), Math.cos(dy));
        this.yaw += dy * 0.06; this.pitch += (this.goal.pitch - this.pitch) * 0.06;
        if (Math.abs(dy) < .002 && Math.abs(this.goal.pitch - this.pitch) < .002) this.goal = null;
      } else if (!this.drag) {
        this.yaw += this.vy; this.pitch = Math.max(-1.45, Math.min(1.45, this.pitch + this.vp));
        this.vy *= 0.94; this.vp *= 0.9;
        if (this.spinning && now - this.idleAt > 2500) this.yaw += this.o.spin * dt / 16;
      }
      this._step(now);
      this._draw(now);
    }

    _step(now) {
      // ease every node towards its target; orbiting nodes circle their parent
      this.nodes.forEach((n, id) => {
        if (n.dying && now - n.dying > 500) { this.nodes.delete(id); return; }
        if (n.orbit) {
          const p = this.nodes.get(n.orbit.parent);
          if (p) {
            const a = n.orbit.phase + this.t * 0.001 * n.orbit.speed * (REDUCED ? 0 : 1), R = n.orbit.radius, tl = n.orbit.tilt;
            const lx = Math.cos(a) * R, lz = Math.sin(a) * R;
            n.tx = p.x + lx; n.ty = p.y + lz * Math.sin(tl); n.tz = p.z + lz * Math.cos(tl);
          }
        }
        const k = n.orbit ? 0.25 : 0.075;
        n.x += (n.tx - n.x) * k; n.y += (n.ty - n.y) * k; n.z += (n.tz - n.z) * k;
      });
    }

    _draw(now) {
      const ctx = this.ctx, W = this.w, H = this.h;
      ctx.clearRect(0, 0, W, H);
      const line = resolve("var(--line-2)"), text = resolve("var(--text)"), muted = resolve("var(--muted)"), bg = resolve("var(--bg)");

      // guides: floor rings and/or a wireframe sphere
      ctx.lineWidth = 1;
      if (this.o.floorY !== null) {
        for (let i = 1; i <= this.o.floorRings; i++) {
          this._ring(0, this.o.floorY, 0, i * this.o.floorStep, "y", rgba(line, .5 - i * 0.06), i === this.o.floorRings ? [4, 6] : null);
        }
        for (let a = 0; a < 12; a++) {   // spokes
          const ang = a / 12 * Math.PI * 2, R = this.o.floorRings * this.o.floorStep;
          const p1 = this._project(Math.cos(ang) * this.o.floorStep, this.o.floorY, Math.sin(ang) * this.o.floorStep);
          const p2 = this._project(Math.cos(ang) * R, this.o.floorY, Math.sin(ang) * R);
          ctx.strokeStyle = rgba(line, .16); ctx.beginPath(); ctx.moveTo(p1.sx, p1.sy); ctx.lineTo(p2.sx, p2.sy); ctx.stroke();
        }
      }
      if (this.o.sphere) {
        const R = this.o.sphere;
        for (let i = 1; i < 6; i++) {
          const lat = -Math.PI / 2 + i * Math.PI / 6;
          this._ring(0, Math.sin(lat) * R, 0, Math.cos(lat) * R, "y", rgba(line, .28));
        }
        for (let i = 0; i < 6; i++) this._ring(0, 0, 0, R, "m" + i * Math.PI / 6, rgba(line, .22));
      }

      // project nodes
      const proj = [];
      let zmin = Infinity, zmax = -Infinity;
      this.nodes.forEach(n => {
        const p = this._project(n.x, n.y, n.z);
        const grow = Math.min(1, (now - n.born) / 650), ease = 1 - Math.pow(1 - grow, 3);
        const fade = n.dying ? Math.max(0, 1 - (now - n.dying) / 500) : 1;
        p.n = n; p.k = ease * fade; p.r = Math.max(1.2, n.r * p.s) * (0.2 + 0.8 * ease) * (n === this.hover ? 1.35 : 1);
        zmin = Math.min(zmin, p.z); zmax = Math.max(zmax, p.z);
        proj.push(p); n._p = p;
      });
      const fog = z => 0.35 + 0.65 * (1 - (z - zmin) / Math.max(zmax - zmin, 1));

      // edges
      this.edges.forEach((e, i) => {
        const A = this.nodes.get(e.a), B = this.nodes.get(e.b);
        if (!A || !B || !A._p || !B._p) return;
        const a = A._p, b = B._p, hot = this.hover && (this.hover === A || this.hover === B);
        const al = Math.min(a.k, b.k) * fog((a.z + b.z) / 2) * (e.alpha ?? .55) * (this.hover && !hot ? .45 : 1);
        ctx.strokeStyle = rgba(e.color || line, hot ? .95 : al);
        ctx.lineWidth = (e.width || 1) * (hot ? 1.8 : 1);
        ctx.beginPath(); ctx.moveTo(a.sx, a.sy);
        let cx, cy;
        if (e.curve) {   // arc lifted away from the centre (globe arcs)
          const m = { x: (A.x + B.x) / 2, y: (A.y + B.y) / 2, z: (A.z + B.z) / 2 };
          const len = Math.hypot(m.x, m.y, m.z) || 1, lift = (len + e.curve) / len;
          const pm = this._project(m.x * lift, m.y * lift, m.z * lift);
          cx = 2 * pm.sx - (a.sx + b.sx) / 2; cy = 2 * pm.sy - (a.sy + b.sy) / 2;
          ctx.quadraticCurveTo(cx, cy, b.sx, b.sy);
        } else ctx.lineTo(b.sx, b.sy);
        ctx.stroke();
        if (e.flow && !REDUCED) {   // a data packet travelling along the edge
          const u = ((this.t * 0.00035 * (e.speed || 1)) + i * 0.37) % 1;
          let px, py;
          if (e.curve) { px = (1 - u) ** 2 * a.sx + 2 * (1 - u) * u * cx + u * u * b.sx; py = (1 - u) ** 2 * a.sy + 2 * (1 - u) * u * cy + u * u * b.sy; }
          else { px = a.sx + (b.sx - a.sx) * u; py = a.sy + (b.sy - a.sy) * u; }
          const sr = 9 * Math.max(a.s, .4);
          ctx.globalAlpha = al * 1.6;
          ctx.drawImage(this._sprite(e.color || "var(--accent)"), px - sr, py - sr, sr * 2, sr * 2);
          ctx.globalAlpha = 1;
          ctx.fillStyle = rgba(e.color || "var(--accent)", Math.min(1, al * 2));
          ctx.beginPath(); ctx.arc(px, py, 1.8, 0, Math.PI * 2); ctx.fill();
        }
      });

      // nodes, far to near
      proj.sort((a, b) => b.z - a.z);
      ctx.textAlign = "center";
      proj.forEach(p => {
        const n = p.n, f = fog(p.z), a = (n.alpha ?? 1) * p.k * f;
        if (a <= 0.01) return;
        const gr = p.r * (n.glow ?? 3.2);
        ctx.globalAlpha = a;
        ctx.drawImage(this._sprite(n.color), p.sx - gr, p.sy - gr, gr * 2, gr * 2);
        if (n.pulse && !REDUCED) {   // expanding ring = needs attention
          const ph = ((this.t / 1400) + (n.phase || 0)) % 1;
          ctx.strokeStyle = rgba(n.color, (1 - ph) * .8);
          ctx.lineWidth = 1.5;
          ctx.beginPath(); ctx.arc(p.sx, p.sy, p.r * (1.2 + ph * 2.6), 0, Math.PI * 2); ctx.stroke();
        }
        if (p.r > 3.5) {   // shaded sphere for bigger nodes, flat dot for tiny ones (faster)
          const g = ctx.createRadialGradient(p.sx - p.r * .35, p.sy - p.r * .35, p.r * .1, p.sx, p.sy, p.r);
          g.addColorStop(0, rgba("#ffffff", .9)); g.addColorStop(.25, rgba(n.color, 1)); g.addColorStop(1, rgba(n.color, .85));
          ctx.fillStyle = g;
        } else ctx.fillStyle = rgba(n.color, 1);
        ctx.beginPath(); ctx.arc(p.sx, p.sy, p.r, 0, Math.PI * 2); ctx.fill();
        if (n === this.hover) {
          ctx.strokeStyle = rgba(text, .9); ctx.lineWidth = 1.5;
          ctx.beginPath(); ctx.arc(p.sx, p.sy, p.r + 4, 0, Math.PI * 2); ctx.stroke();
        }
        if (n.label && (n.showLabel || n === this.hover)) {
          // text with a halo in the page colour so it stays readable over lines and dots
          ctx.globalAlpha = Math.min(1, a * 1.3);
          ctx.lineJoin = "round"; ctx.lineWidth = 4; ctx.strokeStyle = rgba(bg, .85);
          ctx.font = `${n.labelWeight || 650} ${n.labelSize || 12}px Inter, "Segoe UI", system-ui, sans-serif`;
          ctx.strokeText(n.label, p.sx, p.sy + p.r + 15);
          ctx.fillStyle = n.labelColor ? resolve(n.labelColor) : text;
          ctx.fillText(n.label, p.sx, p.sy + p.r + 15);
          if (n.sub) {
            ctx.font = `500 10.5px Inter, "Segoe UI", system-ui, sans-serif`;
            ctx.strokeText(n.sub, p.sx, p.sy + p.r + 28);
            ctx.fillStyle = muted; ctx.fillText(n.sub, p.sx, p.sy + p.r + 28);
          }
        }
        ctx.globalAlpha = 1;
      });
      this.proj = proj;
      this._drawFx(now);
      this._hoverPick();
    }

    _ring(cx, cy, cz, R, axis, stroke, dash) {
      const ctx = this.ctx, steps = 72;
      ctx.strokeStyle = stroke; ctx.setLineDash(dash || []);
      ctx.beginPath();
      for (let i = 0; i <= steps; i++) {
        const a = i / steps * Math.PI * 2;
        let x, y, z;
        if (axis === "y") { x = cx + Math.cos(a) * R; y = cy; z = cz + Math.sin(a) * R; }
        else { const m = parseFloat(axis.slice(1)); const u = Math.cos(a) * R; x = u * Math.cos(m); z = u * Math.sin(m); y = Math.sin(a) * R; }
        const p = this._project(x, y, z);
        i ? ctx.lineTo(p.sx, p.sy) : ctx.moveTo(p.sx, p.sy);
      }
      ctx.stroke(); ctx.setLineDash([]);
    }

    _hoverPick() {
      if (!this.o.interactive) return;
      let best = null;
      if (this.mouse && !(this.drag && this.drag.moved > 5)) {
        let bd = Infinity;
        for (const p of this.proj) {   // nearest node under the mouse (front-most wins ties)
          if (p.k < .5 || p.n.noHover) continue;
          const d = Math.hypot(p.sx - this.mouse.x, p.sy - this.mouse.y);
          if (d < Math.max(p.r + 5, 9) && d <= bd) { bd = d; best = p.n; }
        }
      }
      if (best !== this.hover) {
        this.hover = best;
        this.host.style.cursor = best && this.o.onClick ? "pointer" : "";
        if (best && this.o.tooltip) this.tip.innerHTML = this.o.tooltip(best);
        this.tip.classList.toggle("show", !!(best && this.o.tooltip));
      }
      if (best && best._p) {
        const tw = this.tip.offsetWidth, th = this.tip.offsetHeight;
        let x = best._p.sx + 16, y = best._p.sy - th / 2;
        if (x + tw > this.w - 8) x = best._p.sx - tw - 16;
        this.tip.style.left = `${Math.max(8, x)}px`;
        this.tip.style.top = `${Math.max(8, Math.min(this.h - th - 8, y))}px`;
      }
    }
  }

  // Evenly spread points on a sphere (for the login globe).
  Scene3D.fibonacci = (count, R) => Array.from({ length: count }, (_, i) => {
    const y = 1 - (i / (count - 1)) * 2, r = Math.sqrt(1 - y * y), th = i * Math.PI * (3 - Math.sqrt(5));
    return { x: Math.cos(th) * r * R, y: y * R, z: Math.sin(th) * r * R };
  });

  window.Scene3D = Scene3D;
})();
