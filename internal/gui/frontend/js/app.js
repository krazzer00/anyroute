// AnyRoute — интерфейс. Все обращения к Go асинхронные: окно не ждёт службу.
"use strict";

// ---------- утилиты ----------
const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat()) if (k != null && k !== false) n.append(k instanceof Node ? k : String(k));
  return n;
}
window.el = el;
function fmtBytes(v) {
  v = Math.max(0, v || 0);
  const u = ["Б", "КБ", "МБ", "ГБ", "ТБ"]; let i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (i === 0 ? Math.round(v) : v.toFixed(v < 10 ? 1 : 0)) + " " + u[i];
}
window.fmtBytes = fmtBytes;
function fmtDur(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  return [Math.floor(s / 3600), Math.floor((s % 3600) / 60), s % 60].map((x) => String(x).padStart(2, "0")).join(":");
}
function errText(e) { return typeof e === "string" ? e : (e && e.message) || String(e); }
function toast(text, kind) {
  const t = el("div", { class: "toast " + (kind || "") }, text);
  $("#toasts").append(t);
  setTimeout(() => t.remove(), kind === "error" ? 7000 : 4000);
}
const debounce = (f, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => f(...a), ms); }; };

const go = () => window.go.gui.App;
const S = { servers: [], profiles: [], settings: {}, status: { state: "idle" }, serviceUp: true, sel: null, logs: [], lastSeq: 0, update: null, totals: { vu: 0, vd: 0, du: 0, dd: 0 } };

// ---------- модальные окна ----------
const modal = {
  open(id) { $(id).classList.add("show"); const f = $(id).querySelector("input:not([type=checkbox]),textarea"); if (f) setTimeout(() => f.focus(), 50); },
  close(id) { $(id).classList.remove("show"); },
};
document.addEventListener("click", (e) => { if (e.target.matches("[data-close]")) e.target.closest(".modal-back").classList.remove("show"); });
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") { const m = $$(".modal-back.show").pop(); if (m && m.id !== "m2fa") m.classList.remove("show"); }
});

// ---------- окно ----------
const App = window.App = {
  win: {
    min: () => go().WindowMinimise(),
    hide: () => go().WindowHide(),
    toggleMax: () => { go().WindowToggleMaximise(); setTimeout(syncMax, 120); },
  },
};
function syncMax() {
  const max = window.outerWidth >= screen.availWidth - 2 && window.outerHeight >= screen.availHeight - 2;
  document.body.classList.toggle("maximized", max);
  go().WindowShape();
}
window.addEventListener("resize", debounce(syncMax, 120));

// ---------- серверы ----------
function selServer() { return S.servers.find((s) => s.id === S.sel) || null; }
function renderServers() {
  const ul = $("#servers"); ul.replaceChildren();
  if (!S.servers.length) { ul.append(el("li", { class: "empty-hint" }, "Серверов пока нет. Нажмите «+», чтобы добавить первый.")); return; }
  S.servers.forEach((s, i) => {
    const active = S.status.serverId === s.id && S.status.state !== "idle";
    let dot = "";
    if (active) dot = S.status.state === "connected" ? "connected" : "busy";
    const li = el("li", { class: "server" + (s.id === S.sel ? " sel" : ""), style: `--i:${i}`, title: "Двойной щелчок — изменить" },
      el("div", { class: "name" }, el("span", { class: "dot " + dot }), s.name),
      el("div", { class: "host" }, s.host + (s.group ? "  ·  " + s.group : "")),
      el("div", { class: "badges" },
        el("span", { class: "badge" + (s.hasPassword ? " on" : "") }, s.hasPassword ? "ПАРОЛЬ" : "БЕЗ ПАРОЛЯ"),
        s.hasTotp ? el("span", { class: "badge on" }, "TOTP") : null,
        el("span", { class: "badge" }, profileName(s.routingProfileId))));
    li.addEventListener("click", () => { S.sel = s.id; renderServers(); renderHero(); });
    li.addEventListener("dblclick", () => openServer(s));
    ul.append(li);
  });
}
function profileName(id) { const p = S.profiles.find((x) => x.id === id) || S.profiles.find((x) => x.id === "default"); return p ? p.name : "Default"; }

async function refreshServers() { S.servers = await go().Servers(); if (!selServer() && S.servers.length) S.sel = S.servers[0].id; renderServers(); renderHero(); }

// форма сервера
let editing = null;
function fillProfileSelect(sel, value) {
  sel.replaceChildren(...S.profiles.map((p) => el("option", { value: p.id }, p.name)));
  sel.value = value || "default";
}
function openServer(s) {
  editing = s || null;
  $("#mServerTitle").textContent = s ? "Сервер «" + s.name + "»" : "Новый сервер";
  $("#sName").value = s ? s.name : "";
  $("#sHost").value = s ? s.host : "";
  const g = $("#sGroup"); g.replaceChildren(el("option", { value: "" }, "По умолчанию сервера"));
  if (s && s.group) g.append(el("option", { value: s.group }, s.group));
  g.value = s ? s.group : "";
  $("#sUser").value = s ? s.username : "";
  $("#sPass").value = ""; $("#sPass").placeholder = s && s.hasPassword ? "сохранён — оставьте пустым" : "••••••";
  $("#sSavePass").checked = s ? s.savePassword : true;
  $("#sTotp").value = ""; $("#totpPreview").textContent = "";
  $("#sTotp").placeholder = s && s.hasTotp ? "сохранён — оставьте пустым или введите новый" : "Base32 из QR-кода или ссылка otpauth://";
  $("#totpState").textContent = s && s.hasTotp ? "TOTP-секрет сохранён: код подставляется автоматически. Чтобы убрать — введите «-»." : "Если указать — код второго фактора будет подставляться сам. Без секрета код вводится вручную.";
  fillProfileSelect($("#sProfile"), s ? s.routingProfileId : "default");
  $("#sInsecure").checked = s ? !!s.insecureTls : false;
  $("#btnDeleteServer").classList.toggle("hidden", !s);
  modal.open("#mServer");
}
$("#btnAddServer").onclick = () => openServer(null);
$("#btnFetchGroups").onclick = async () => {
  const b = $("#btnFetchGroups"); b.disabled = true; b.textContent = "Запрос…";
  try {
    const r = await go().FetchGroups($("#sHost").value, $("#sInsecure").checked);
    const g = $("#sGroup"), cur = g.value;
    g.replaceChildren(el("option", { value: "" }, "По умолчанию сервера" + (r.default ? ` (${r.default})` : "")), ...r.groups.map((x) => el("option", { value: x }, x)));
    g.value = r.groups.includes(cur) ? cur : "";
    toast(`Сервер предлагает групп: ${r.groups.length}`, "ok");
  } catch (e) { toast(errText(e), "error"); }
  b.disabled = false; b.textContent = "↻ С сервера";
};
$("#sTotp").addEventListener("input", debounce(async () => {
  const v = $("#sTotp").value.trim();
  if (!v || v === "-") { $("#totpPreview").textContent = ""; return; }
  try { $("#totpPreview").textContent = await go().TOTPPreview(v); } catch (e) { $("#totpPreview").textContent = "✕"; }
}, 300));
$("#btnSaveServer").onclick = async () => {
  const totp = $("#sTotp").value.trim();
  const form = {
    server: Object.assign({}, editing || {}, {
      id: editing ? editing.id : "", name: $("#sName").value, host: $("#sHost").value, group: $("#sGroup").value,
      username: $("#sUser").value, savePassword: $("#sSavePass").checked, routingProfileId: $("#sProfile").value, insecureTls: $("#sInsecure").checked,
    }),
    password: $("#sPass").value, totpSecret: totp === "-" ? "" : totp, clearTotp: totp === "-",
  };
  try { const sv = await go().SaveServer(form); S.sel = sv.id; modal.close("#mServer"); await refreshServers(); toast("Сервер сохранён", "ok"); }
  catch (e) { toast(errText(e), "error"); }
};
$("#btnDeleteServer").onclick = async () => {
  if (!editing || !confirm(`Удалить сервер «${editing.name}» и сохранённые для него пароль и TOTP-секрет?`)) return;
  await go().DeleteServer(editing.id); modal.close("#mServer"); S.sel = null; await refreshServers();
};

// ---------- подключение ----------
const busyStates = ["connecting", "auth", "2fa", "disconnecting"];
async function connect(serverId, password, remember) {
  try { await go().Connect(serverId, password || "", !!remember); }
  catch (e) {
    const m = errText(e);
    if (m.includes("NEED_PASSWORD")) { openPassword(serverId); return; }
    toast(m, "error");
  }
}
$("#ringBtn").onclick = async () => {
  const st = S.status.state;
  if (st === "idle") {
    const s = selServer(); if (!s) { openServer(null); return; }
    await connect(s.id);
  } else {
    try { await go().Disconnect(); } catch (e) { toast(errText(e), "error"); }
  }
};
let passFor = null;
function openPassword(id) {
  passFor = id; const s = S.servers.find((x) => x.id === id);
  $("#passFor").textContent = s ? `${s.username} @ ${s.host}` : ""; $("#pPass").value = ""; modal.open("#mPass");
}
$("#btnPassOk").onclick = async () => { modal.close("#mPass"); await connect(passFor, $("#pPass").value, $("#pRemember").checked); await refreshServers(); };
$("#pPass").addEventListener("keydown", (e) => { if (e.key === "Enter") $("#btnPassOk").click(); });

// 2FA
let shownSeq = 0, totpWait = null;
function handleChallenge(st) {
  if (st.state !== "2fa" || !st.challenge) { modal.close("#m2fa"); clearTimeout(totpWait); return; }
  const ch = st.challenge; if (ch.seq === shownSeq) return;
  const srv = S.servers.find((x) => x.id === st.serverId);
  const show = () => {
    if (S.status.state !== "2fa" || !S.status.challenge || S.status.challenge.seq !== ch.seq) return;
    shownSeq = ch.seq;
    const m = $("#chMsg"); m.textContent = ch.message + (ch.label ? ` (${ch.label})` : "");
    m.classList.toggle("retry", !!ch.retry);
    if (ch.retry) m.textContent = "Сервер не принял код. " + m.textContent;
    $("#chCode").value = ""; modal.open("#m2fa");
  };
  clearTimeout(totpWait);
  // При сохранённом TOTP-секрете код отправляется сам; окно — только если не сработало.
  if (srv && srv.hasTotp && !ch.retry) totpWait = setTimeout(show, 6000); else show();
}
$("#btn2faOk").onclick = async () => {
  const c = $("#chCode").value.trim(); if (!c) return;
  try { await go().Submit2FA(c); modal.close("#m2fa"); } catch (e) { toast(errText(e), "error"); }
};
$("#chCode").addEventListener("keydown", (e) => { if (e.key === "Enter") $("#btn2faOk").click(); });
$("#btn2faCancel").onclick = async () => { modal.close("#m2fa"); await go().Disconnect(); };

// ---------- главный блок ----------
const STATE_TEXT = { idle: "Отключено", connecting: "Подключение", auth: "Вход", "2fa": "Нужен код", connected: "Подключено", disconnecting: "Отключение" };
function renderHero() {
  const st = S.status, hero = $("#hero");
  const busy = busyStates.includes(st.state), err = st.state === "idle" && st.error;
  hero.className = "hero " + (st.state === "connected" ? "state-connected" : busy ? "state-busy" : err ? "state-error" : "");
  $("#stateText").textContent = err ? "Ошибка" : STATE_TEXT[st.state] || st.state;
  const s = (st.state !== "idle" && S.servers.find((x) => x.id === st.serverId)) || selServer();
  const t = $("#serverTitle"); t.replaceChildren();
  if (s) t.append(el("b", {}, s.name), "  ", el("span", { class: "mono" }, s.host + (s.group ? " · " + s.group : "")));
  else t.append("Добавьте сервер слева, чтобы подключиться");
  if (busy && st.step) t.append(el("div", { style: "margin-top:4px;color:var(--warn)" }, st.step));
  $("#timer").classList.toggle("hidden", st.state !== "connected");
  $("#transport").classList.toggle("hidden", st.state !== "connected");
  $("#transport").textContent = st.dtls ? "DTLS" : "TLS";
  // профиль
  const ps = $("#profileSelect"); fillProfileSelect(ps, s ? s.routingProfileId : "default"); ps.disabled = !s;
  // параметры
  const chips = $("#chips"); chips.replaceChildren();
  if (st.state === "connected") {
    const add = (k, v, title) => chips.append(el("div", { class: "chip", title: title || v }, el("div", { class: "k" }, k), el("div", { class: "v" }, v)));
    const nets = st.splitInclude || [], zones = st.splitDns || [];
    add("Адрес в VPN", st.address || "—", `TUN AnyRoute: ${st.tunPrefix || "—"}`);
    add("Шлюз", st.gateway || "—");
    add("DNS", (st.dns || []).join(", ") || "—", "DNS-зоны VPN: " + (zones.join(", ") || "нет"));
    add("Маршруты", `${nets.length} сетей · ${st.hostRoutes || 0} хостов`, "Сети сервера:\n" + (nets.join("\n") || "нет") + "\n\nHost-маршруты — адреса доменов из списка VPN");
  }
  const en = $("#errNotice"); en.textContent = err ? st.error : ""; en.classList.toggle("show", !!err);
  const wn = $("#warnNotice"); const w = st.state === "connected" ? (st.warnings || []) : [];
  wn.textContent = w.length > 1 ? `${w[0]} (и ещё ${w.length - 1})` : (w[0] || ""); wn.title = w.join("\n"); wn.classList.toggle("show", w.length > 0);
}
setInterval(() => { if (S.status.state === "connected" && S.status.since) $("#timer").textContent = fmtDur(Date.now() - new Date(S.status.since)); }, 1000);
function onStatus(st) {
  const prev = S.status.state; S.status = st || { state: "idle" };
  if (prev !== "connected" && S.status.state === "connected") { S.totals = { vu: 0, vd: 0, du: 0, dd: 0 }; toast("VPN подключён", "ok"); }
  renderHero(); renderServers(); handleChallenge(S.status);
}
$("#profileSelect").onchange = async (e) => {
  const s = (S.status.state !== "idle" && S.servers.find((x) => x.id === S.status.serverId)) || selServer(); if (!s) return;
  try { await go().UseProfile(s.id, e.target.value); await refreshServers(); toast(`Профиль «${profileName(e.target.value)}»` + (S.status.state === "connected" ? " применён без переподключения" : " выбран"), "ok"); }
  catch (err) { toast(errText(err), "error"); }
};

// ---------- журнал ----------
const LV = { debug: "DEBUG", info: "INFO", ok: "OK", warn: "WARN", error: "ERROR" };
let logLevel = "all", logQuery = "";
function logMatch(e) {
  if (logLevel === "warn" && e.level !== "warn") return false;
  if (logLevel === "error" && e.level !== "error") return false;
  if (logLevel === "info" && !["info", "ok"].includes(e.level)) return false;
  if (logLevel === "debug" && e.level !== "debug") return false;
  return !logQuery || (e.message + " " + e.source).toLowerCase().includes(logQuery);
}
function logRow(e) {
  const d = new Date(e.time);
  return el("div", { class: "log " + e.level }, el("span", { class: "t" }, d.toLocaleTimeString("ru-RU")), el("span", { class: "lv" }, LV[e.level] || e.level), el("span", { class: "src" }, e.source), el("span", { class: "msg" }, e.message));
}
function addLogs(list) {
  const box = $("#logs"); const frag = document.createDocumentFragment();
  for (const e of list) { if (e.seq && e.seq <= S.lastSeq) continue; if (e.seq) S.lastSeq = e.seq; S.logs.push(e); if (logMatch(e)) frag.append(logRow(e)); }
  if (S.logs.length > 5000) { S.logs.splice(0, S.logs.length - 5000); while (box.childElementCount > 5000) box.firstChild.remove(); }
  box.append(frag);
  if ($("#logFollow").checked) box.scrollTop = box.scrollHeight;
}
function rerenderLogs() { const box = $("#logs"); box.replaceChildren(...S.logs.filter(logMatch).map(logRow)); box.scrollTop = box.scrollHeight; }
$$("#logLevels button").forEach((b) => b.onclick = () => { $$("#logLevels button").forEach((x) => x.classList.toggle("on", x === b)); logLevel = b.dataset.lv; rerenderLogs(); });
$("#logSearch").addEventListener("input", debounce((e) => { logQuery = e.target.value.toLowerCase(); rerenderLogs(); }, 150));
$("#btnClearLogs").onclick = () => { S.logs = []; $("#logs").replaceChildren(); };
$("#btnCopyLogs").onclick = async () => {
  const text = S.logs.filter(logMatch).map((e) => `${e.time} [${LV[e.level]}] ${e.source}: ${e.message}`).join("\n");
  try { await navigator.clipboard.writeText(text); toast("Журнал скопирован", "ok"); } catch (e) { toast("Не удалось скопировать", "error"); }
};

// ---------- приложения ----------
let appFilter = "all", appQuery = "", expanded = new Set();
const PALETTE = ["#22d3ee", "#a78bfa", "#34f5c5", "#f5a524", "#7dd3fc", "#f0abfc", "#facc15", "#60a5fa"];
function color(name) { let h = 0; for (const c of name) h = (h * 31 + c.charCodeAt(0)) >>> 0; return PALETTE[h % PALETTE.length]; }
async function refreshApps() {
  if (!$("#panel-apps").classList.contains("active") && S.status.state !== "connected") return;
  let conns = [];
  try { conns = (await go().Connections()) || []; } catch (e) { conns = []; }
  const showClosed = $("#appClosed").checked;
  const groups = new Map();
  for (const c of conns) {
    if (!showClosed && c.closed) continue;
    if (appFilter !== "all" && c.outbound !== appFilter) continue;
    const name = c.process || "система";
    if (appQuery && !(name + " " + c.domain + " " + c.dest).toLowerCase().includes(appQuery)) continue;
    const g = groups.get(name) || { name, path: c.path, conns: [], up: 0, down: 0, outs: new Set() };
    g.conns.push(c); g.up += c.up; g.down += c.down; g.outs.add(c.outbound); groups.set(name, g);
  }
  const list = [...groups.values()].sort((a, b) => (b.up + b.down) - (a.up + a.down));
  $("#appsCount").textContent = list.length ? String(list.length) : "";
  const body = $("#appsBody"); body.replaceChildren();
  for (const g of list) {
    const tr = el("tr", { class: "proc", title: g.path || "" },
      el("td", {}, el("div", { class: "pname" }, el("span", { class: "avatar", style: `background:${color(g.name)}` }, g.name.slice(0, 2).toUpperCase()), g.name)),
      el("td", { class: "num", style: "text-align:left" }, String(g.conns.length)),
      el("td", {}, [...g.outs].map((o) => el("span", { class: "out " + o }, o === "vpn" ? "VPN" : o === "direct" ? "НАПРЯМУЮ" : "БЛОК"))),
      el("td", { class: "num" }, fmtBytes(g.up)), el("td", { class: "num" }, fmtBytes(g.down)));
    tr.onclick = () => { expanded.has(g.name) ? expanded.delete(g.name) : expanded.add(g.name); refreshApps(); };
    body.append(tr);
    if (expanded.has(g.name)) for (const c of g.conns) {
      body.append(el("tr", { class: "sub" + (c.closed ? " closed" : "") },
        el("td", {}, (c.network || "").toUpperCase()), el("td", { colspan: "1" }, c.domain || "—"),
        el("td", {}, el("span", { class: "out " + c.outbound }, c.outbound), c.dest),
        el("td", { class: "num" }, fmtBytes(c.up)), el("td", { class: "num" }, fmtBytes(c.down))));
    }
  }
  $("#appsEmpty").classList.toggle("hidden", list.length > 0);
}
setInterval(refreshApps, 1500);
$$("#appFilter button").forEach((b) => b.onclick = () => { $$("#appFilter button").forEach((x) => x.classList.toggle("on", x === b)); appFilter = b.dataset.f; refreshApps(); });
$("#appSearch").addEventListener("input", debounce((e) => { appQuery = e.target.value.toLowerCase(); refreshApps(); }, 150));
$("#appClosed").onchange = refreshApps;

// ---------- график ----------
const chart = new NeonChart($("#chart"), $("#chartTip"));
$$("#chartMode button").forEach((b) => b.onclick = () => { $$("#chartMode button").forEach((x) => x.classList.toggle("on", x === b)); chart.setMode(b.dataset.m); });
function onSample(s) {
  chart.push(s);
  for (const k of ["vu", "vd", "du", "dd"]) { S.totals[k] += s[k] || 0; }
  $("#spVd").textContent = fmtBytes(s.vd) + "/с"; $("#spVu").textContent = fmtBytes(s.vu) + "/с";
  $("#spDd").textContent = fmtBytes(s.dd) + "/с"; $("#spDu").textContent = fmtBytes(s.du) + "/с";
  $("#totVd").textContent = "всего " + fmtBytes(S.totals.vd); $("#totVu").textContent = "всего " + fmtBytes(S.totals.vu);
  $("#totDd").textContent = "всего " + fmtBytes(S.totals.dd); $("#totDu").textContent = "всего " + fmtBytes(S.totals.du);
}

// ---------- вкладки ----------
$$(".tab").forEach((t) => t.onclick = () => {
  $$(".tab").forEach((x) => x.classList.toggle("active", x === t));
  $$(".panel").forEach((p) => p.classList.toggle("active", p.id === "panel-" + t.dataset.tab));
  if (t.dataset.tab === "chart") chart.draw();
  if (t.dataset.tab === "apps") refreshApps();
});

// ---------- профили маршрутизации ----------
let pfSel = null;
function renderProfList() {
  $("#profList").replaceChildren(...S.profiles.map((p) => {
    const d = el("div", { class: "prof-item" + (p.id === pfSel?.id ? " sel" : "") }, p.name);
    d.onclick = () => loadProfile(p); return d;
  }));
}
function loadProfile(p) {
  pfSel = Object.assign({}, p);
  $("#pfName").value = p.name; $("#pfDefault").value = p.defaultOutbound || "direct";
  $("#pfServer").checked = !!p.serverRoutesToVpn; $("#pfLan").checked = !!p.lanDirect;
  $("#pfVpn").value = p.vpn || ""; $("#pfDirect").value = p.direct || ""; $("#pfBlock").value = p.block || "";
  showRuleErrors({}); $("#btnDelProfile").disabled = p.id === "default"; renderProfList();
}
function showRuleErrors(errs) {
  for (const [k, id] of [["vpn", "Vpn"], ["direct", "Direct"], ["block", "Block"]]) {
    const list = errs[k] || [];
    $("#err" + id).textContent = list.map((e) => `строка ${e.line}: ${e.error}`).join("\n");
    $("#pf" + id).closest(".list-box").classList.toggle("bad", list.length > 0);
  }
}
function openProfiles(id) {
  const cur = S.profiles.find((p) => p.id === id) || S.profiles[0];
  loadProfile(cur || { id: "", name: "Новый профиль", defaultOutbound: "direct", serverRoutesToVpn: true, lanDirect: true });
  modal.open("#mProfiles");
}
$("#btnProfiles").onclick = () => openProfiles(selServer()?.routingProfileId);
$("#btnEditProfile").onclick = () => openProfiles($("#profileSelect").value);
$("#btnHelp").onclick = () => $("#help").classList.toggle("show");
$("#btnNewProfile").onclick = () => loadProfile({ id: "", name: "Новый профиль", defaultOutbound: "direct", serverRoutesToVpn: true, lanDirect: true, vpn: "", direct: "", block: "" });
$("#btnDupProfile").onclick = () => { if (pfSel) loadProfile(Object.assign({}, pfSel, { id: "", name: pfSel.name + " (копия)" })); };
$("#btnSaveProfile").onclick = async () => {
  const p = Object.assign({}, pfSel, { name: $("#pfName").value, defaultOutbound: $("#pfDefault").value, serverRoutesToVpn: $("#pfServer").checked,
    lanDirect: $("#pfLan").checked, vpn: $("#pfVpn").value, direct: $("#pfDirect").value, block: $("#pfBlock").value });
  try {
    const r = await go().SaveProfile(p);
    if (r.ruleErrors) { showRuleErrors(r.ruleErrors); toast("В правилах есть ошибки — исправьте подсвеченные строки", "error"); return; }
    showRuleErrors({}); S.profiles = await go().Profiles(); loadProfile(r.profile); renderHero(); renderServers();
    toast(S.status.state === "connected" && S.status.profileId === r.profile.id ? "Профиль сохранён и применён" : "Профиль сохранён", "ok");
  } catch (e) { toast(errText(e), "error"); }
};
$("#btnDelProfile").onclick = async () => {
  if (!pfSel || !pfSel.id || pfSel.id === "default" || !confirm(`Удалить профиль «${pfSel.name}»?`)) return;
  try { await go().DeleteProfile(pfSel.id); S.profiles = await go().Profiles(); loadProfile(S.profiles[0]); await refreshServers(); } catch (e) { toast(errText(e), "error"); }
};

// ---------- настройки и обновления ----------
$("#btnSettings").onclick = () => {
  const s = S.settings;
  $("#stAutostart").checked = !!s.autostart; $("#stUpdates").checked = !!s.checkUpdates; $("#stEffects").checked = s.effects !== false;
  $("#stDisconnect").checked = s.disconnectOnExit !== false; $("#stLevel").value = s.logLevel || "info"; $("#updState").textContent = "";
  modal.open("#mSettings");
};
$("#btnSaveSettings").onclick = async () => {
  const s = Object.assign({}, S.settings, { autostart: $("#stAutostart").checked, checkUpdates: $("#stUpdates").checked, effects: $("#stEffects").checked,
    disconnectOnExit: $("#stDisconnect").checked, logLevel: $("#stLevel").value });
  try { await go().SaveSettings(s); S.settings = s; modal.close("#mSettings"); toast("Настройки сохранены", "ok"); } catch (e) { toast(errText(e), "error"); }
};
$("#btnQuit").onclick = () => go().Quit(S.settings.disconnectOnExit !== false);
$("#btnCheckUpdate").onclick = async () => {
  $("#updState").textContent = "проверка…";
  const u = await go().CheckUpdate();
  if (u.error) $("#updState").textContent = u.error;
  else if (u.available) { $("#updState").textContent = "доступна " + u.version; showUpdateBar(u); }
  else $("#updState").textContent = "установлена последняя версия";
};
function showUpdateBar(u) { S.update = u; $("#updateText").textContent = `Доступна версия ${u.version} (у вас ${S.version})`; $("#updateBar").classList.add("show"); }
function openUpdate() { if (!S.update) return; $("#updTitle").textContent = "AnyRoute " + S.update.version; $("#updNotes").textContent = S.update.notes || "Без описания изменений"; modal.open("#mUpdate"); }
$("#btnUpdateNotes").onclick = openUpdate;
$("#btnUpdateNow").onclick = openUpdate;
$("#btnUpdateGo").onclick = async () => {
  try { await go().ApplyUpdate(S.update.version); modal.close("#mUpdate"); toast("Загрузка обновления… Ход — в журнале", "info"); } catch (e) { toast(errText(e), "error"); }
};
$("#svcRestart").onclick = async () => { toast("Перезапуск службы…"); try { await go().RestartService(); } catch (e) { toast(errText(e), "error"); } };
function onService(up) { S.serviceUp = up; $("#svcPill").classList.toggle("show", !up); if (up) loadLogs(); }
async function loadLogs() { try { addLogs((await go().Logs(S.lastSeq)) || []); } catch (e) { /* служба недоступна */ } }

// ---------- старт ----------
(async function init() {
  const b = await go().Init();
  S.version = b.version; $("#version").textContent = b.version;
  S.servers = b.servers || []; S.profiles = b.profiles || []; S.settings = b.settings || {};
  if (S.settings.effects === false) document.body.classList.add("no-effects");
  S.sel = (S.servers.find((s) => s.id === S.settings.lastServerId) || S.servers[0] || {}).id || null;
  onService(b.serviceUp); onStatus(b.status); addLogs(b.logs || []); chart.set(b.samples || []);
  const on = window.runtime.EventsOn;
  on("status", onStatus);
  on("log", (e) => addLogs([e]));
  on("sample", onSample);
  on("service", onService);
  on("toast", (t) => toast(t.text, t.kind));
  on("updateAvailable", showUpdateBar);
  on("showUpdate", openUpdate);
  on("update", (u) => { if (u && u.state === "error") toast("Обновление не установлено: " + u.error, "error"); if (u && u.state === "installing") toast("Устанавливается обновление, AnyRoute перезапустится", "info"); });
  on("connectFailed", (d) => { if (String(d.error).includes("NEED_PASSWORD")) openPassword(d.serverId); else toast(d.error, "error"); });
  on("profileChanged", () => refreshServers());
  syncMax();
})();
