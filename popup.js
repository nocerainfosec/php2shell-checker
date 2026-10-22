import { STATUS_INFO, statusLabel, CODE_VERSION } from "./lib/php-rules.js";
import { t, render, detectLang, LANGS } from "./lib/i18n.js";

const $ = (id) => document.getElementById(id);
let currentTabId = null;
let lastReport = null;
let lang = detectLang(chrome.i18n.getUILanguage());
let deepArmed = false;

const send = (m) => chrome.runtime.sendMessage(m);
const tr = (key, params) => t(lang, key, params);
const R = (x) => render(lang, x);

function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "style") Object.assign(n.style, v);
    else n.setAttribute(k, v);
  }
  for (const c of children) if (c != null) n.append(c);
  return n;
}

function pill(status) {
  return el("span", { class: "pill", style: { background: STATUS_INFO[status].badge } }, R(statusLabel(status)));
}

function applyStaticText() {
  document.documentElement.lang = lang === "pt" ? "pt-BR" : "en";
  for (const n of document.querySelectorAll("[data-i18n]")) n.textContent = tr(n.dataset.i18n);
  for (const n of document.querySelectorAll("[data-i18n-title]")) n.title = tr(n.dataset.i18nTitle);
  $("lang").textContent = lang === "pt" ? "EN" : "PT";
}

// ---------- Aba "Site" ----------

// Consultas em serviços de terceiros: abrem o host no serviço, sem enviar tráfego ao site.
function lookups(host) {
  const q = encodeURIComponent(host);
  return [
    ["Shodan", `https://www.shodan.io/search?query=hostname%3A${q}`],
    ["Censys", `https://search.censys.io/search?resource=hosts&q=${q}`],
    ["SOCRadar", "https://socradar.io/free-tools/php2shell-checker"],
    ["Brandefense", "https://atlas.brandefense.io/php-vulnerability-check"],
    ["securetheweb.org", "https://securetheweb.org/"],
  ];
}

async function renderSite() {
  const report = await send({ type: "getTab", tabId: currentTabId });
  lastReport = report;
  // Arquivos novos no disco com o service worker antigo ainda rodando (ex.: depois de um git pull).
  $("stale").hidden = report.codeVersion === CODE_VERSION;
  $("rules").textContent = tr("ui.rules", { d: report.rulesVersion });

  if (!report.tab || !report.hosts.length) {
    $("host").textContent = "";
    $("status").textContent = tr("ui.noData");
    $("version").textContent = "";
    $("title").textContent = tr("ui.noData.title");
    $("detail").textContent = tr("ui.noData.detail");
    for (const id of ["ioc", "sapi-wrap", "evidence-wrap", "actions-wrap", "others-wrap", "lookups-wrap"]) $(id).hidden = true;
    return;
  }

  const [top, ...others] = report.hosts;
  const v = top.verdict;

  $("host").textContent = top.hostname;
  const iocs = top.indicators.filter((i) => i.kind === "ioc");
  $("ioc").hidden = !iocs.length;
  $("ioc").replaceChildren(tr("ui.ioc.title"), el("small", {}, tr("ui.ioc.detail")));
  $("verdict").style.setProperty("--accent", STATUS_INFO[v.status].color);
  $("status").textContent = R(statusLabel(v.status));
  $("version").textContent = v.version ? `PHP ${v.version.full}` : "";
  $("title").textContent = R(v.title);
  $("detail").textContent = R(v.detail);

  $("sapi").replaceChildren(...top.sapi.map((s) => el("li", {}, R(s))));
  $("sapi-wrap").hidden = !top.sapi.length;

  const ev = $("evidence");
  ev.replaceChildren();
  for (const ver of top.versions) {
    ev.append(el("li", {}, el("code", {}, ver.source), el("span", { class: "src" }, tr("src.versionRead", { v: ver.full }))));
  }
  for (const i of top.indicators) {
    const cls = { alert: "alert", ioc: "alert", mitigation: "ok" }[i.kind];
    ev.append(el("li", {}, el("span", cls ? { class: cls } : {}, R(i.value)), el("span", { class: "src" }, R(i.source))));
  }
  if (!top.versions.length) {
    for (const [k, val] of Object.entries(top.headers)) {
      ev.append(el("li", {}, el("code", {}, `${k}: ${val}`), el("span", { class: "src" }, tr("src.headerNoVersion"))));
    }
  }
  $("evidence-wrap").hidden = !ev.children.length;

  $("actions").replaceChildren(...v.actions.map((a) => el("li", {}, R(a))));
  $("actions-wrap").hidden = !v.actions.length;

  $("others").replaceChildren(
    ...others.map((h) =>
      el(
        "li",
        {},
        el("strong", {}, h.hostname), " ", pill(h.verdict.status),
        el("span", { class: "src" }, h.verdict.version ? h.verdict.version.source : R(h.verdict.title))
      )
    )
  );
  $("others-wrap").hidden = !others.length;

  $("lookups").replaceChildren(
    ...lookups(top.hostname).map(([name, href]) => el("a", { href, target: "_blank", rel: "noopener" }, name))
  );
  $("lookups-wrap").hidden = false;
}

function reportText(r) {
  const lines = [`# ${tr("r.title")}`, ``];
  lines.push(`URL: ${r.tab.url}`, `${tr("r.date")}: ${new Date(r.tab.updated).toLocaleString(lang === "pt" ? "pt-BR" : "en-US")}`, ``);
  for (const h of r.hosts) {
    const v = h.verdict;
    lines.push(`## ${h.hostname}`);
    lines.push(`${tr("ui.status")}: ${R(statusLabel(v.status))}`);
    if (v.version) lines.push(`${tr("r.announced")}: PHP ${v.version.full}`);
    lines.push(`${tr("r.analysis")}: ${R(v.title)}. ${R(v.detail)}`);
    if (h.sapi.length) lines.push(`SAPI: ${h.sapi.map(R).join("; ")}`);
    const ev = [...h.versions.map((x) => x.source), ...h.indicators.map((i) => `${R(i.value)} [${R(i.source)}]`)];
    if (ev.length) lines.push(`${tr("r.evidence")}:`, ...ev.map((e) => `- ${e}`));
    if (v.actions.length) lines.push(`${tr("r.actions")}:`, ...v.actions.map((a) => `- ${R(a)}`));
    lines.push(``);
  }
  lines.push(tr("r.note"), ``, `PHP2Shell Version Checker · NoceraInfoSec® · https://nocerainfosec.com.br · https://github.com/nocerainfosec`);
  return lines.join("\n");
}

$("copy").addEventListener("click", async () => {
  if (!lastReport || !lastReport.tab) return ($("msg").textContent = tr("ui.nothingToCopy"));
  await navigator.clipboard.writeText(reportText(lastReport));
  $("msg").textContent = tr("ui.copied");
});

$("recheck").addEventListener("click", async () => {
  const btn = $("recheck");
  btn.disabled = true;
  $("msg").textContent = tr("ui.sending");
  const res = await send({ type: "recheck", tabId: currentTabId });
  btn.disabled = false;
  $("msg").textContent = res.ok ? res.results.join(" · ") : R(res.error);
  setTimeout(renderSite, 400);
});

// Checagem profunda pede um segundo clique: ela envia requisições a caminhos sensíveis.
$("deep").addEventListener("click", async () => {
  const btn = $("deep");
  if (!deepArmed) {
    deepArmed = true;
    btn.textContent = tr("ui.deep.confirm");
    btn.classList.add("armed");
    $("msg").textContent = tr("ui.deep.warn");
    return;
  }
  deepArmed = false;
  btn.classList.remove("armed");
  btn.textContent = tr("ui.deep");
  btn.disabled = true;
  $("msg").textContent = tr("ui.deep.running");
  const res = await send({ type: "deepCheck", tabId: currentTabId });
  btn.disabled = false;
  $("msg").textContent = res.ok ? tr("ui.deep.done", { n: res.findings, m: res.requests }) : R(res.error);
  setTimeout(renderSite, 400);
});

// ---------- Aba "Histórico" ----------

async function renderHistory() {
  const rows = await send({ type: "getHistory" });
  $("history").replaceChildren(
    ...rows.map((r) =>
      el(
        "tr",
        { title: R(r.evidence) },
        el("td", {}, r.host),
        el("td", {}, r.version || "?"),
        el("td", {}, r.ioc && r.ioc.length ? el("span", { class: "pill", style: { background: "#a50e0e" } }, "IOC") : pill(r.status))
      )
    )
  );
  $("history-empty").hidden = rows.length > 0;
  return rows;
}

const csvCell = (s) => `"${String(s ?? "").replace(/"/g, '""')}"`;

$("export").addEventListener("click", async () => {
  const rows = await renderHistory();
  const header = ["host", "version", "status", "evidence", "sapi", "x_powered_by", "server", "ioc", "last_seen"];
  const list = (x) => (Array.isArray(x) ? x.map(R).join(" | ") : R(x));
  const csv = [header.join(",")]
    .concat(
      rows.map((r) =>
        [
          r.host, r.version, R(statusLabel(r.status)), R(r.evidence), list(r.sapi), r.xPoweredBy, r.server, list(r.ioc),
          new Date(r.lastSeen).toISOString(),
        ].map(csvCell).join(",")
      )
    )
    .join("\n");
  const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  const a = el("a", { href: url, download: `php2shell-inventory-${new Date().toISOString().slice(0, 10)}.csv` });
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

$("clear").addEventListener("click", async () => {
  await send({ type: "clearHistory" });
  renderHistory();
});

for (const tab of document.querySelectorAll(".tab")) {
  tab.addEventListener("click", () => {
    for (const x of document.querySelectorAll(".tab")) x.classList.toggle("active", x === tab);
    $("view-site").hidden = tab.dataset.view !== "site";
    $("view-history").hidden = tab.dataset.view !== "history";
    if (tab.dataset.view === "history") renderHistory();
  });
}

$("reload-ext").addEventListener("click", () => chrome.runtime.reload());

$("lang").addEventListener("click", async () => {
  lang = LANGS[(LANGS.indexOf(lang) + 1) % LANGS.length];
  await chrome.storage.local.set({ lang });
  applyStaticText();
  renderSite();
  if (!$("view-history").hidden) renderHistory();
});

// popup.html?tab=<id> permite abrir o relatório de uma aba específica (útil para testes).
const tabParam = new URLSearchParams(location.search).get("tab");
const { lang: saved } = await chrome.storage.local.get("lang");
if (saved) lang = saved;
applyStaticText();
const [tab] = tabParam ? [{ id: +tabParam }] : await chrome.tabs.query({ active: true, currentWindow: true });
currentTabId = tab.id;
renderSite();
