// Неоновый график скорости: canvas, без сторонних библиотек.
// Точки — {t, vu, vd, du, dd} (байт/с), окно — 5 минут.
(function () {
  const SERIES = [
    { key: "vd", name: "VPN ↓", color: "#22d3ee", group: "vpn" },
    { key: "vu", name: "VPN ↑", color: "#7dd3fc", group: "vpn" },
    { key: "dd", name: "Напрямую ↓", color: "#a78bfa", group: "direct" },
    { key: "du", name: "Напрямую ↑", color: "#f0abfc", group: "direct" },
  ];
  const WINDOW = 300 * 1000;

  function fmtRate(v) { return window.fmtBytes(v) + "/с"; }

  class NeonChart {
    constructor(canvas, tip) {
      this.c = canvas; this.tip = tip; this.data = []; this.mode = "both"; this.hover = null;
      this.ctx = canvas.getContext("2d");
      new ResizeObserver(() => this.draw()).observe(canvas.parentElement);
      canvas.addEventListener("mousemove", (e) => { this.hover = e.offsetX; this.draw(); });
      canvas.addEventListener("mouseleave", () => { this.hover = null; this.tip.style.display = "none"; this.draw(); });
    }
    set(points) { this.data = (points || []).slice(-300); this.draw(); }
    push(p) { this.data.push(p); if (this.data.length > 300) this.data.shift(); this.draw(); }
    setMode(m) { this.mode = m; this.draw(); }
    series() { return SERIES.filter((s) => this.mode === "both" || s.group === this.mode); }

    draw() {
      const c = this.c, dpr = window.devicePixelRatio || 1;
      const w = c.parentElement.clientWidth, h = c.parentElement.clientHeight;
      if (!w || !h) return;
      if (c.width !== Math.round(w * dpr) || c.height !== Math.round(h * dpr)) { c.width = Math.round(w * dpr); c.height = Math.round(h * dpr); }
      const g = this.ctx; g.setTransform(dpr, 0, 0, dpr, 0, 0); g.clearRect(0, 0, w, h);
      const pad = { l: 70, r: 14, t: 14, b: 26 };
      const now = this.data.length ? this.data[this.data.length - 1].t : Date.now();
      const t0 = now - WINDOW;
      const ser = this.series();
      let max = 1024;
      for (const p of this.data) for (const s of ser) max = Math.max(max, p[s.key] || 0);
      max = niceMax(max * 1.15);
      const X = (t) => pad.l + ((t - t0) / WINDOW) * (w - pad.l - pad.r);
      const Y = (v) => h - pad.b - (v / max) * (h - pad.t - pad.b);

      // сетка
      g.font = "11px JBMono, Consolas, monospace"; g.textBaseline = "middle";
      for (let i = 0; i <= 4; i++) {
        const v = (max / 4) * i, y = Y(v);
        g.strokeStyle = i === 0 ? "rgba(56,189,248,.22)" : "rgba(56,189,248,.08)";
        g.setLineDash(i === 0 ? [] : [3, 5]); g.beginPath(); g.moveTo(pad.l, y); g.lineTo(w - pad.r, y); g.stroke();
        g.fillStyle = "rgba(169,189,211,.6)"; g.textAlign = "right"; g.fillText(fmtRate(v), pad.l - 8, y);
      }
      g.setLineDash([]); g.textAlign = "center";
      for (let m = 0; m <= 5; m++) {
        const x = X(t0 + m * 60000);
        g.fillStyle = "rgba(111,134,160,.8)"; g.fillText(m === 5 ? "сейчас" : `−${5 - m} мин`, x, h - 10);
      }
      if (this.data.length < 2) {
        g.fillStyle = "rgba(111,134,160,.7)"; g.font = "13px Golos, sans-serif";
        g.fillText("Данные появятся после подключения", w / 2, h / 2); return;
      }
      // линии с градиентной заливкой и свечением
      for (const s of ser.slice().reverse()) {
        const pts = this.data.filter((p) => p.t >= t0).map((p) => [X(p.t), Y(p[s.key] || 0)]);
        if (pts.length < 2) continue;
        const grad = g.createLinearGradient(0, pad.t, 0, h - pad.b);
        grad.addColorStop(0, hexA(s.color, 0.28)); grad.addColorStop(1, hexA(s.color, 0));
        g.beginPath(); smooth(g, pts); g.lineTo(pts[pts.length - 1][0], Y(0)); g.lineTo(pts[0][0], Y(0)); g.closePath();
        g.fillStyle = grad; g.fill();
        g.save(); g.shadowColor = s.color; g.shadowBlur = 12; g.strokeStyle = s.color; g.lineWidth = 2;
        g.beginPath(); smooth(g, pts); g.stroke(); g.restore();
      }
      // подсказка
      if (this.hover != null && this.hover > pad.l) {
        const t = t0 + ((this.hover - pad.l) / (w - pad.l - pad.r)) * WINDOW;
        let best = null; for (const p of this.data) if (!best || Math.abs(p.t - t) < Math.abs(best.t - t)) best = p;
        if (best) {
          const x = X(best.t);
          g.strokeStyle = "rgba(231,243,255,.35)"; g.beginPath(); g.moveTo(x, pad.t); g.lineTo(x, h - pad.b); g.stroke();
          for (const s of ser) { g.fillStyle = s.color; g.beginPath(); g.arc(x, Y(best[s.key] || 0), 3.5, 0, 7); g.fill(); }
          const rows = [window.el("div", { style: "color:#6f86a0" }, new Date(best.t).toLocaleTimeString("ru-RU"))];
          for (const s of ser) rows.push(window.el("div", {}, window.el("span", { style: `color:${s.color}` }, "● "), `${s.name}: ${fmtRate(best[s.key] || 0)}`));
          this.tip.replaceChildren(...rows);
          this.tip.style.display = "block";
          const tw = this.tip.offsetWidth;
          this.tip.style.left = (x + tw + 20 > w ? x - tw - 12 : x + 12) + "px"; this.tip.style.top = pad.t + 4 + "px";
        }
      }
    }
  }

  function smooth(g, pts) {
    g.moveTo(pts[0][0], pts[0][1]);
    for (let i = 1; i < pts.length; i++) {
      const [x0, y0] = pts[i - 1], [x1, y1] = pts[i], mx = (x0 + x1) / 2;
      g.bezierCurveTo(mx, y0, mx, y1, x1, y1);
    }
  }
  function niceMax(v) {
    const p = Math.pow(1024, Math.floor(Math.log(v) / Math.log(1024)));
    const n = v / p; const steps = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024];
    return (steps.find((s) => s >= n) || 1024) * p;
  }
  function hexA(hex, a) {
    const n = parseInt(hex.slice(1), 16);
    return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`;
  }
  window.NeonChart = NeonChart;
})();
