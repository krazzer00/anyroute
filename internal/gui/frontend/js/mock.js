// Заглушка бэкенда для предпросмотра интерфейса в обычном браузере.
// В приложении (WebView2) не активируется: там есть window.chrome.webview.
(function () {
  if (window.chrome && window.chrome.webview) return;
  const listeners = {};
  const emit = (n, d) => (listeners[n] || []).forEach((f) => f(d));
  let seq = 0, status = { state: "idle", version: "0.1.0", hostRoutes: 0, dtls: false };
  const log = (level, source, message) => emit("log", { seq: ++seq, time: new Date().toISOString(), level, source, message });
  const servers = [
    { id: "a1", name: "Офис", host: "vpn.example.com", group: "Remote Access", username: "ivan", savePassword: true, routingProfileId: "default", hasPassword: true, hasTotp: true },
    { id: "b2", name: "Стенд", host: "vpn2.example.com:8443", group: "", username: "ivan", savePassword: false, routingProfileId: "work", hasPassword: false, hasTotp: false },
  ];
  const profiles = [
    { id: "default", name: "Default", defaultOutbound: "direct", serverRoutesToVpn: true, lanDirect: true, vpn: "", direct: "# Например:\n# processName:Telegram.exe\n", block: "" },
    { id: "work", name: "Работа", defaultOutbound: "direct", serverRoutesToVpn: true, lanDirect: true, vpn: "domain:googleapis.com\nprocessName:chrome.exe", direct: "processName:Telegram.exe\nprocessName:OVRServer_x64.exe", block: "domain:ads.example" },
  ];
  const set = (patch) => { status = Object.assign({}, status, patch); emit("status", status); };
  let timer = null;
  const App = {
    Init: async () => ({ version: "0.1.0", servers, profiles, settings: { checkUpdates: true, logLevel: "info", effects: true, disconnectOnExit: true, lastServerId: "a1" }, status, serviceUp: true, logs: [], samples: [] }),
    Servers: async () => servers, Profiles: async () => profiles,
    SaveServer: async (f) => { const s = Object.assign({ id: f.server.id || "n" + Date.now() }, f.server, { hasPassword: !!f.password, hasTotp: !!f.totpSecret }); const i = servers.findIndex((x) => x.id === s.id); if (i >= 0) servers[i] = s; else servers.push(s); return s; },
    DeleteServer: async (id) => { const i = servers.findIndex((x) => x.id === id); if (i >= 0) servers.splice(i, 1); },
    TOTPPreview: async () => "482915",
    FetchGroups: async () => ({ groups: ["Remote Access", "Remote Access MFA", "Partners"], default: "Remote Access" }),
    SaveProfile: async (p) => { if (/300\./.test(p.vpn)) return { ruleErrors: { vpn: [{ line: 2, text: "ip:300.1.1.1", error: "некорректный адрес или подсеть" }] } }; p.id = p.id || "p" + Date.now(); const i = profiles.findIndex((x) => x.id === p.id); if (i >= 0) profiles[i] = p; else profiles.push(p); return { profile: p }; },
    DeleteProfile: async () => {}, UseProfile: async () => {},
    Connect: async (id, pw) => {
      const s = servers.find((x) => x.id === id);
      if (!s.hasPassword && !pw) throw "NEED_PASSWORD";
      set({ state: "connecting", serverId: id, serverName: s.name, host: s.host, step: "Подключение к " + s.host + "…", error: "" });
      log("info", "core", "Подключение к " + s.host + "…");
      setTimeout(() => { set({ state: "auth", step: "Аутентификация…" }); log("info", "core", "Аутентификация…"); }, 600);
      setTimeout(() => { set({ state: "2fa", challenge: { message: "Введите OTP-код", seq: 1 } }); log("info", "core", "сервер запросил второй фактор: Введите OTP-код"); }, 1300);
    },
    Submit2FA: async () => {
      set({ state: "auth", challenge: null, step: "Проверка кода…" });
      setTimeout(() => {
        set({ state: "connected", since: new Date().toISOString(), address: "10.20.30.41/24", gateway: "203.0.113.10", dns: ["10.0.0.53", "10.0.0.54"], splitInclude: ["10.0.0.0/8", "172.20.0.0/16"], splitDns: ["corp.example"], tunPrefix: "172.29.254.1/30", dtls: true, hostRoutes: 3, warnings: ["правила keyword:/regexp: в списке VPN работают только для трафика, уже попавшего в туннель"] });
        log("ok", "core", "подключено к Офис (профиль «Работа»)");
        timer = setInterval(() => emit("sample", { t: Date.now(), vd: Math.random() * 900e3, vu: Math.random() * 120e3, dd: Math.random() * 300e3, du: Math.random() * 40e3 }), 1000);
      }, 700);
    },
    Disconnect: async () => { clearInterval(timer); set({ state: "disconnecting", step: "Отключение…" }); setTimeout(() => { set({ state: "idle", error: "" }); log("info", "core", "отключено"); }, 600); },
    Connections: async () => status.state !== "connected" ? [] : [
      { id: "1", process: "chrome.exe", pid: 4120, network: "tcp", dest: "10.1.2.3:443", domain: "jira.corp.example", outbound: "vpn", up: 120e3, down: 4.2e6, start: Date.now() - 50e3 },
      { id: "2", process: "chrome.exe", pid: 4120, network: "tcp", dest: "142.250.1.1:443", domain: "storage.googleapis.com", outbound: "vpn", up: 20e3, down: 900e3, start: Date.now() - 20e3 },
      { id: "3", process: "Telegram.exe", pid: 812, network: "tcp", dest: "10.9.9.9:443", domain: "", outbound: "direct", up: 3e3, down: 12e3, start: Date.now() - 9e3 },
      { id: "4", process: "svchost.exe", pid: 1300, network: "udp", dest: "10.0.0.53:53", domain: "", outbound: "vpn", up: 400, down: 900, start: Date.now() - 5e3, closed: true },
    ],
    Logs: async () => [], Settings: async () => ({}), SaveSettings: async () => {}, RestartService: async () => {}, ServiceUp: async () => true,
    WindowMinimise() {}, WindowToggleMaximise() {}, WindowHide() {}, WindowShape() {}, Quit() {},
    CheckUpdate: async () => ({ available: true, version: "0.2.0", current: "0.1.0", notes: "• Переключение профилей быстрее\n• Исправления DTLS" }),
    ApplyUpdate: async () => {},
  };
  window.go = { gui: { App } };
  window.runtime = { EventsOn: (n, f) => { (listeners[n] = listeners[n] || []).push(f); } };
  setTimeout(() => { log("info", "service", "служба AnyRoute 0.1.0 готова"); log("warn", "cleanup", "найдены оставшиеся после сбоя правила DNS (2) — удаляю"); log("ok", "cleanup", "оставшиеся правила DNS удалены"); emit("updateAvailable", { available: true, version: "0.2.0", notes: "• Переключение профилей быстрее" }); }, 400);
})();
