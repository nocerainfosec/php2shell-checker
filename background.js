// Service worker: coleta passivamente cabeçalhos e indícios de PHP por aba e por host.
import {
  extractPhpVersion, assess, STATUS, STATUS_INFO, RULES_VERSION, matchIocHost, matchIocFiles, IOC_SOURCE,
  parsePhpinfo, sapiFromHeaders, statusLabel,
} from "./lib/php-rules.js";
import { msg, render, t, detectLang } from "./lib/i18n.js";

const MAX_HOSTS_PER_TAB = 40;
const MAX_HISTORY = 1000;
const PROBE_WINDOW_MS = 60000;
const REDIRECT_CHAIN_MS = 5000;
const DEEP_TIMEOUT_MS = 8000;
const DEEP_MAX_BYTES = 400000;
const EXT_ORIGIN = chrome.runtime.getURL("").replace(/\/$/, "");

// Cookies que indicam PHP ou um framework/CMS em PHP.
const COOKIE_HINTS = [
  [/^PHPSESSID$/i, "PHP"],
  [/^laravel_session$/i, "Laravel"],
  [/^ci_session$/i, "CodeIgniter"],
  [/^CAKEPHP$/i, "CakePHP"],
  [/^(wordpress_|wp-settings|wordpress_logged_in)/i, "WordPress"],
  [/^S?SESS[0-9a-f]{32}$/i, "Drupal"],
  [/^PrestaShop-/i, "PrestaShop"],
  [/^(frontend|adminhtml|mage-cache-sessid)$/i, "Magento"],
  [/^symfony$|^sf_redirect$/i, "Symfony"],
  [/^MOODLEID_|^MoodleSession/i, "Moodle"],
  [/^zbx_session$/i, "Zabbix"],
  [/^phpMyAdmin|^pma_/i, "phpMyAdmin"],
  [/^roundcube_sessid$/i, "Roundcube"],
  [/^GLPI_/i, "GLPI"],
  [/^WHMCS/i, "WHMCS"],
];

// Cabeçalhos que indicam PHP mesmo sem a versão.
const HEADER_HINTS = [
  [/^x-pingback$/i, () => "WordPress (X-Pingback / xmlrpc.php)"],
  [/^x-generator$/i, (v) => (/drupal|wordpress|joomla|typo3/i.test(v) ? msg("ind.generator", { v }) : null)],
  [/^x-drupal-(cache|dynamic-cache)$/i, () => "Drupal"],
  [/^x-magento-/i, () => "Magento"],
  [/^x-powered-cms$/i, (v) => `CMS: ${v}`],
  [/^link$/i, (v) => (/wp-json|api\.w\.org/i.test(v) ? "WordPress (REST API, Link header)" : null)],
];

// ---------- Idioma ----------

let lang = detectLang(chrome.i18n.getUILanguage());
chrome.storage.local.get("lang").then(({ lang: saved }) => {
  if (saved) lang = saved;
});
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.lang) {
    lang = changes.lang.newValue || detectLang(chrome.i18n.getUILanguage());
    for (const tabId of tabs.keys()) updateBadge(tabId);
  }
});

// ---------- Estado por aba (memória + storage.session) ----------

const tabs = new Map();
let loaded = null;

function loadState() {
  if (!loaded) {
    loaded = chrome.storage.session.get(null).then((all) => {
      for (const [k, v] of Object.entries(all)) if (k.startsWith("tab:")) tabs.set(+k.slice(4), v);
    });
  }
  return loaded;
}

const saveTimers = new Map();
function scheduleSave(tabId) {
  clearTimeout(saveTimers.get(tabId));
  saveTimers.set(
    tabId,
    setTimeout(() => {
      saveTimers.delete(tabId);
      const t = tabs.get(tabId);
      if (t) chrome.storage.session.set({ [`tab:${tabId}`]: t });
      else chrome.storage.session.remove(`tab:${tabId}`);
      updateBadge(tabId);
      recordHistory(tabId);
    }, 300)
  );
}

function resetTab(tabId, url) {
  tabs.set(tabId, { url, topHost: safeHost(url), hosts: {}, updated: Date.now() });
  scheduleSave(tabId);
}

function hostEntry(tab, hostname) {
  if (!tab.hosts[hostname]) {
    if (Object.keys(tab.hosts).length >= MAX_HOSTS_PER_TAB) return null;
    tab.hosts[hostname] = { versions: [], indicators: [], sapi: [], headers: {}, phpinfo: null };
    const ioc = matchIocHost(hostname);
    if (ioc) addIndicator(tab.hosts[hostname], "ioc", msg("ind.iocHost", { label: msg(ioc) }), IOC_SOURCE);
  }
  return tab.hosts[hostname];
}

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

function addVersion(h, v, source) {
  if (!h.versions.some((x) => x.full === v.full)) h.versions.push({ ...v, source });
}

function addIndicator(h, kind, value, source) {
  if (!h.indicators.some((x) => x.kind === kind && same(x.value, value))) h.indicators.push({ kind, value, source });
}

function addSapi(h, hint) {
  if (!h.sapi.some((x) => same(x, hint))) h.sapi.push(hint);
}

function safeHost(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

// Aplica um phpinfo() lido (pela página ou pela checagem profunda) ao host.
function applyPhpinfo(h, info, source) {
  if (!info) return;
  h.phpinfo = info;
  const v = extractPhpVersion(info.versionText);
  if (v) addVersion(h, v, `phpinfo(): ${info.versionText}`);
  addIndicator(h, "alert", msg("ind.phpinfoPublic"), source);
  if (info.sapi) addSapi(h, msg("sapi.phpinfo", { v: info.sapi }));
  if (info.uploadProgress) {
    const off = /^(off|0|no)$/i.test(info.uploadProgress);
    addIndicator(h, off ? "mitigation" : "info", msg(off ? "ind.uploadProgressOff" : "ind.uploadProgressOn"), source);
  }
}

// ---------- Coleta de cabeçalhos ----------

const probes = new Map(); // tabId -> { until, label }

function probeFor(details) {
  if (details.tabId >= 0) return { tabId: details.tabId };
  if (details.initiator !== EXT_ORIGIN) return null;
  const now = Date.now();
  for (const [tabId, p] of probes) if (p.until > now) return { tabId, label: p.label };
  return null;
}

function processHeaders(tabId, details, probeLabel) {
  let tab = tabs.get(tabId);
  if (!tab) {
    if (details.type !== "main_frame") return;
    resetTab(tabId, details.url);
    tab = tabs.get(tabId);
  }
  const hostname = safeHost(details.url);
  const h = hostEntry(tab, hostname);
  if (!h) return;

  const path = new URL(details.url).pathname;
  const src = msg(probeLabel || (details.type === "main_frame" ? "src.page" : "src.resource"), { path });
  let touched = false;

  for (const { name, value = "" } of details.responseHeaders || []) {
    const n = name.toLowerCase();

    if (n === "x-powered-by" || n === "server") {
      h.headers[n] = value;
      const v = extractPhpVersion(value);
      if (v) addVersion(h, v, `${name}: ${value}`);
      else if (n === "x-powered-by") addIndicator(h, "header", `X-Powered-By: ${value}`, src);
      touched = true;
      continue;
    }

    if (n === "set-cookie") {
      const cookieName = value.split("=")[0].trim();
      for (const [re, label] of COOKIE_HINTS) {
        if (re.test(cookieName)) {
          addIndicator(h, "cookie", msg("ind.cookie", { name: cookieName, label }), src);
          touched = true;
        }
      }
      if (/^PHPSESSID$/i.test(cookieName)) {
        const val = value.split(";")[0].slice(cookieName.length + 1);
        if (val.length > 128) addIndicator(h, "alert", msg("ind.bigSess", { n: val.length }), src);
      }
      continue;
    }

    for (const [re, fn] of HEADER_HINTS) {
      if (re.test(n)) {
        const label = fn(value);
        if (label) {
          addIndicator(h, "header", label, src);
          touched = true;
        }
      }
    }
  }

  if (/\.php\d?$/i.test(path) && details.statusCode < 400) {
    addIndicator(h, "url", msg("ind.phpUrl", { path: path.slice(0, 80) }), src);
    touched = true;
  }

  for (const hint of sapiFromHeaders(h.headers.server, h.headers["x-powered-by"])) addSapi(h, hint);

  if (touched || details.type === "main_frame") {
    tab.updated = Date.now();
    scheduleSave(tabId);
  }
}

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    const probe = probeFor(details);
    if (!probe) return;
    const { tabId } = probe;
    loadState().then(() => {
      if (details.type === "main_frame" && details.tabId >= 0) {
        // Nova navegação zera o estado; respostas seguidas (cadeia de redirects) são somadas.
        const t = tabs.get(tabId);
        const now = Date.now();
        if (!t || now - (t.mainAt || 0) > REDIRECT_CHAIN_MS) resetTab(tabId, details.url);
        const cur = tabs.get(tabId);
        cur.mainAt = now;
        cur.url = details.url;
        cur.topHost = safeHost(details.url);
      }
      processHeaders(tabId, details, probe.label);
    });
  },
  { urls: ["http://*/*", "https://*/*"] },
  ["responseHeaders", "extraHeaders"]
);

// ---------- Mensagens (content script e popup) ----------

chrome.runtime.onMessage.addListener((m, sender, sendResponse) => {
  (async () => {
    await loadState();

    if (m.type === "hints" && sender.tab) {
      const tabId = sender.tab.id;
      if (!tabs.has(tabId)) resetTab(tabId, sender.url);
      const tab = tabs.get(tabId);
      const h = hostEntry(tab, safeHost(sender.url));
      if (!h) return sendResponse({});
      const src = msg("src.content");
      for (const i of m.indicators || []) addIndicator(h, i.kind, i.value, src);
      applyPhpinfo(h, parsePhpinfo(m.phpinfoHtml), src);
      // Diretório aberto: compara os nomes listados com os arquivos dos toolkits de ataque.
      for (const hit of matchIocFiles(m.listing || [])) {
        addIndicator(h, "ioc", msg("ind.iocFile", { file: hit.file, label: msg(hit.label) }), IOC_SOURCE);
      }
      scheduleSave(tabId);
      return sendResponse({});
    }

    if (m.type === "getTab") return sendResponse(buildReport(m.tabId));

    if (m.type === "recheck") return sendResponse(await recheck(m.tabId));

    if (m.type === "deepCheck") return sendResponse(await deepCheck(m.tabId));

    if (m.type === "getHistory") {
      const { history = {} } = await chrome.storage.local.get("history");
      return sendResponse(Object.values(history).sort((a, b) => b.lastSeen - a.lastSeen));
    }

    if (m.type === "clearHistory") {
      await chrome.storage.local.remove("history");
      return sendResponse({});
    }
  })();
  return true;
});

const hasIoc = (h) => h.indicators.some((i) => i.kind === "ioc");

function buildReport(tabId) {
  const tab = tabs.get(tabId);
  if (!tab) return { tab: null, rulesVersion: RULES_VERSION };
  const hosts = Object.entries(tab.hosts)
    .map(([hostname, h]) => ({ hostname, ...h, verdict: assess(h) }))
    .filter((h) => h.hostname === tab.topHost || h.verdict.status !== STATUS.NOT_DETECTED || hasIoc(h))
    .sort((a, b) => {
      if (a.hostname === tab.topHost) return -1;
      if (b.hostname === tab.topHost) return 1;
      return STATUS_INFO[b.verdict.status].severity - STATUS_INFO[a.verdict.status].severity;
    });
  return { tab: { url: tab.url, topHost: tab.topHost, updated: tab.updated }, hosts, rulesVersion: RULES_VERSION };
}

async function tabOrigin(tabId) {
  let tab = tabs.get(tabId);
  if (!tab) {
    const t = await chrome.tabs.get(tabId);
    resetTab(tabId, t.url);
    tab = tabs.get(tabId);
  }
  let url;
  try {
    url = new URL(tab.url);
  } catch {
    return { error: msg("ui.invalidUrl") };
  }
  if (!/^https?:$/.test(url.protocol)) return { error: msg("ui.httpOnly") };
  return { tab, url };
}

async function get(url, readBody) {
  const r = await fetch(url, {
    cache: "no-store",
    credentials: "omit",
    redirect: "follow",
    signal: AbortSignal.timeout(DEEP_TIMEOUT_MS),
  });
  let body = "";
  if (readBody) body = (await r.text()).slice(0, DEEP_MAX_BYTES);
  return { r, body };
}

// Fallback caso o webRequest não tenha atribuído a resposta à aba.
function readFetchHeaders(tab, r, fallbackUrl) {
  const h = hostEntry(tab, safeHost(r.url || fallbackUrl));
  if (!h) return null;
  for (const n of ["x-powered-by", "server"]) {
    const val = r.headers.get(n);
    if (val) {
      h.headers[n] = val;
      const v = extractPhpVersion(val);
      if (v) addVersion(h, v, `${n}: ${val}`);
    }
  }
  for (const hint of sapiFromHeaders(h.headers.server, h.headers["x-powered-by"])) addSapi(h, hint);
  return h;
}

// Re-checagem: GETs comuns ao próprio site, sem payload de exploração e sem cookies.
async function recheck(tabId) {
  const { tab, url, error } = await tabOrigin(tabId);
  if (error) return { ok: false, error };
  probes.set(tabId, { until: Date.now() + PROBE_WINDOW_MS, label: "src.recheck" });
  const results = [];
  for (const path of ["/", "/index.php"]) {
    try {
      const { r } = await get(url.origin + path, false);
      results.push(`${path} → HTTP ${r.status}`);
      readFetchHeaders(tab, r, url.origin);
    } catch (e) {
      results.push(`${path} → ${e.name}`);
    }
  }
  probes.delete(tabId);
  tab.updated = Date.now();
  scheduleSave(tabId);
  return { ok: true, results };
}

// Checagem profunda (opt-in): só GETs a caminhos públicos conhecidos, sem payload.
// phpinfo exposto, status do PHP-FPM, Apache server-status, .php inexistente e easter egg (PHP < 5.5).
const PHPINFO_PATHS = ["/phpinfo.php", "/info.php", "/test.php", "/i.php", "/php.php", "/pi.php", "/php_info.php", "/_profiler/phpinfo"];
const FPM_STATUS_PATHS = ["/fpm-status", "/status", "/php-status", "/php-fpm-status"];
const LOGO_GUID = "PHPE9568F34-D428-11d2-A769-00AA001ACF42";

async function deepCheck(tabId) {
  const { tab, url, error } = await tabOrigin(tabId);
  if (error) return { ok: false, error };
  const origin = url.origin;
  const h = hostEntry(tab, url.hostname);
  if (!h) return { ok: false, error: msg("ui.invalidUrl") };
  probes.set(tabId, { until: Date.now() + PROBE_WINDOW_MS, label: "src.deep" });
  let requests = 0;
  const before = h.indicators.length + h.sapi.length + h.versions.length;
  const src = (path) => msg("src.deep", { path });

  const tryGet = async (path, readBody = true) => {
    requests++;
    try {
      const res = await get(origin + path, readBody);
      readFetchHeaders(tab, res.r, origin);
      return res;
    } catch {
      return null;
    }
  };
  const isHtml200 = (res) => res && res.r.ok && !res.r.redirected;

  for (const path of PHPINFO_PATHS) {
    const res = await tryGet(path);
    if (isHtml200(res)) {
      const info = parsePhpinfo(res.body);
      if (info) {
        applyPhpinfo(h, info, src(path));
        break;
      }
    }
  }

  for (const path of FPM_STATUS_PATHS) {
    const res = await tryGet(path);
    if (isHtml200(res) && /pool:\s*\S+/i.test(res.body) && /process manager:/i.test(res.body)) {
      const pool = /pool:\s*(\S+)/i.exec(res.body)[1];
      addIndicator(h, "alert", msg("ind.fpmStatus", { path, pool }), src(path));
      addSapi(h, msg("sapi.fpm"));
      break;
    }
  }

  const ss = await tryGet("/server-status");
  if (isHtml200(ss) && /Apache Server Status/i.test(ss.body)) {
    addIndicator(h, "alert", msg("ind.serverStatus", { path: "/server-status" }), src("/server-status"));
    const sv = /Server Version:\s*([^<\n]+)/i.exec(ss.body);
    if (sv) {
      const v = extractPhpVersion(sv[1]);
      if (v) {
        addVersion(h, v, `server-status: ${sv[1].trim()}`);
        addSapi(h, msg("sapi.modphp"));
      }
    }
  }

  // .php inexistente: a resposta do handler revela como o PHP está ligado ao servidor web.
  const missing = `/php2shell-check-${Math.random().toString(36).slice(2, 10)}.php`;
  const nf = await tryGet(missing);
  if (nf) {
    const body = nf.body.trim();
    if (/^File not found\.?$/i.test(body)) {
      addIndicator(h, "info", msg("ind.fpm404"), src(missing));
      addSapi(h, msg("sapi.fpm"));
    } else if (/^No input file specified\.?$/i.test(body)) {
      addIndicator(h, "info", msg("ind.noInput"), src(missing));
    }
  }

  // Easter egg do logo: só PHP < 5.5 com expose_php=On responde com uma imagem.
  const eggPath = /\.php$/i.test(url.pathname) ? url.pathname : "/";
  const egg = await tryGet(`${eggPath}?=${LOGO_GUID}`, false);
  if (egg && egg.r.ok && /^image\//i.test(egg.r.headers.get("content-type") || "")) {
    addIndicator(h, "alert", msg("ind.easterEgg"), src(eggPath));
  }

  probes.delete(tabId);
  tab.updated = Date.now();
  scheduleSave(tabId);
  const after = h.indicators.length + h.sapi.length + h.versions.length;
  return { ok: true, requests, findings: after - before };
}

// ---------- Badge e histórico ----------

function updateBadge(tabId) {
  const tab = tabs.get(tabId);
  if (!tab) return;
  const top = tab.hosts[tab.topHost];
  const verdict = top ? assess(top) : null;
  let text = "";
  let color = "#5f6368";
  if (verdict && verdict.status !== STATUS.NOT_DETECTED) {
    const v = verdict.version;
    text = v ? `${v.major}.${v.minor}` : "PHP";
    color = STATUS_INFO[verdict.status].badge;
  }
  const ioc = top && hasIoc(top);
  if (ioc) {
    text = "IOC";
    color = "#a50e0e";
  }
  const title = ioc
    ? t(lang, "ui.badgeIoc")
    : verdict
      ? `PHP2Shell: ${render(lang, statusLabel(verdict.status))}`
      : "PHP2Shell Version Checker";
  chrome.action.setBadgeText({ tabId, text }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ tabId, color }).catch(() => {});
  chrome.action.setTitle({ tabId, title }).catch(() => {});
}

let historyChain = Promise.resolve();
function recordHistory(tabId) {
  const tab = tabs.get(tabId);
  if (!tab) return;
  historyChain = historyChain.then(async () => {
    const { history = {} } = await chrome.storage.local.get("history");
    for (const [hostname, h] of Object.entries(tab.hosts)) {
      const verdict = assess(h);
      const ioc = h.indicators.filter((i) => i.kind === "ioc").map((i) => i.value);
      if (verdict.status === STATUS.NOT_DETECTED && !ioc.length) continue;
      history[hostname] = {
        host: hostname,
        status: verdict.status,
        version: verdict.version ? verdict.version.full : "",
        evidence: verdict.version ? verdict.version.source : (h.indicators[0] || {}).value || "",
        sapi: h.sapi,
        xPoweredBy: h.headers["x-powered-by"] || "",
        server: h.headers["server"] || "",
        ioc,
        lastSeen: Date.now(),
      };
    }
    const entries = Object.values(history).sort((a, b) => b.lastSeen - a.lastSeen).slice(0, MAX_HISTORY);
    await chrome.storage.local.set({ history: Object.fromEntries(entries.map((e) => [e.host, e])) });
  });
}

// A versão 1.0 gravava o histórico com textos fixos em português. Converte essas entradas para dados
// neutros (cabeçalho bruto e mensagens traduzíveis) para que o histórico e o CSV sigam o idioma escolhido.
async function migrateHistory() {
  const { history } = await chrome.storage.local.get("history");
  if (!history) return;
  let changed = false;
  for (const e of Object.values(history)) {
    if (!("label" in e) && typeof e.ioc !== "string") continue;
    delete e.label;
    if (typeof e.evidence === "string") e.evidence = e.xPoweredBy || e.server || "";
    if (typeof e.ioc === "string") e.ioc = e.ioc ? [msg("ui.ioc.title")] : [];
    if (!e.sapi) e.sapi = [];
    changed = true;
  }
  if (changed) await chrome.storage.local.set({ history });
}
chrome.runtime.onInstalled.addListener(() => {
  historyChain = historyChain.then(migrateHistory);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabs.delete(tabId);
  chrome.storage.session.remove(`tab:${tabId}`);
});

loadState();
