// QA das regras com um export do Shodan (JSON por linha, .json ou .json.gz).
// Roda as mesmas funções da extensão em cada banner HTTP e resume onde as regras acertam, falham ou não cobrem.
// Uso: node tools/shodan-qa.mjs <arquivo.json.gz> [--limit N] [--json saida.json] [--include-honeypots]
// Banners marcados como honeypot pelo Shodan são ignorados por padrão: eles imitam dezenas de produtos de uma vez.
import { createReadStream, writeFileSync } from "node:fs";
import { createGunzip } from "node:zlib";
import { createInterface } from "node:readline";
import {
  analyzeHeaders, assess, classifyVersion, extractPhpVersion, parsePhpinfo, sapiFromHeaders, matchIocHost, matchIocFiles,
  versionsFromSignatures, parseDevDashboard,
} from "../lib/php-rules.js";
import { render } from "../lib/i18n.js";

const args = process.argv.slice(2);
const file = args.find((a) => !a.startsWith("--"));
const limit = args.includes("--limit") ? +args[args.indexOf("--limit") + 1] : Infinity;
const jsonOut = args.includes("--json") ? args[args.indexOf("--json") + 1] : null;
const includeHoneypots = args.includes("--include-honeypots");
if (!file) {
  console.error("uso: node tools/shodan-qa.mjs <arquivo.json.gz> [--limit N] [--json saida.json]");
  process.exit(1);
}

// Contador com limite de chaves, para não estourar memória com valores únicos.
class Counter {
  constructor(max = 5000) {
    this.m = new Map();
    this.max = max;
    this.dropped = 0;
  }
  add(k, n = 1) {
    if (this.m.has(k) || this.m.size < this.max) this.m.set(k, (this.m.get(k) || 0) + n);
    else this.dropped++;
  }
  top(n = 20) {
    return [...this.m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n);
  }
}

// Guarda poucos exemplos por categoria.
class Samples {
  constructor(per = 5) {
    this.m = new Map();
    this.per = per;
  }
  add(k, v) {
    const list = this.m.get(k) || [];
    if (list.length < this.per) list.push(v);
    this.m.set(k, list);
  }
}

const stats = {
  lines: 0,
  badJson: 0,
  http: 0,
  honeypots: 0,
  fromSignature: 0,
  withPhpVersion: 0,
  phpNoVersion: 0,
  errors: 0,
  cpePhp: 0,
  cpeAgree: 0,
  cpeDisagree: 0,
  phpinfoPages: 0,
  phpinfoParsed: 0,
  phpinfoHardLimit: 0,
  openDirs: 0,
};
const status = new Counter();
const versions = new Counter();
const versionStatus = new Map();
const genericCheckSuffix = new Counter();
const phpHeaderNoVersion = new Counter();
const xpbNonPhpWithPhpCookie = new Counter();
const xpbNonPhpFlagged = new Counter();
const xpbNonPhpIgnored = new Counter();
const sapi = new Counter();
const phpinfoSapi = new Counter();
const uploadProgress = new Counter();
const cpeMismatch = new Counter();
const iocHosts = new Counter();
const devDashboards = new Counter();
const iocFiles = new Counter();
const errorSamples = new Samples(5);
const phpinfoFailures = new Samples(5);

// Banner HTTP cru do Shodan -> lista de cabeçalhos { name, value }.
function parseRawHeaders(data) {
  const head = data.split(/\r?\n\r?\n/, 1)[0];
  const lines = head.split(/\r?\n/);
  if (!/^HTTP\/\d/.test(lines[0] || "")) return null;
  const out = [];
  for (const line of lines.slice(1)) {
    const i = line.indexOf(":");
    if (i > 0) out.push({ name: line.slice(0, i).trim(), value: line.slice(i + 1).trim() });
  }
  return out;
}

const PHP_COOKIE = /^(PHPSESSID|laravel_session|ci_session|CAKEPHP|wordpress_|wp-settings)/i;

function processRecord(r) {
  const headers = typeof r.data === "string" ? parseRawHeaders(r.data) : null;
  if (!headers) return;
  if (!includeHoneypots && (r.tags || []).includes("honeypot")) {
    stats.honeypots++;
    return;
  }
  stats.http++;

  const found = analyzeHeaders(headers);
  const host = { versions: found.versions.map((x) => ({ ...x.v, source: x.source })), indicators: [...found.indicators], phpinfo: null };

  // Assinatura do Apache no corpo, como o content script lê do elemento <address>.
  const html0 = r.http && typeof r.http.html === "string" ? r.http.html : "";
  const sigs = [...html0.matchAll(/<address>([^<]*PHP\/\d[^<]*)<\/address>/gi)].map((m) => m[1]);
  const sigVersions = versionsFromSignatures(sigs);
  if (sigVersions.length && !host.versions.length) stats.fromSignature++;
  for (const { v, source } of sigVersions) host.versions.push({ ...v, source });

  // Painel de desenvolvimento exposto (WampServer, Laragon...), como o content script lê do título e do texto.
  const dash = parseDevDashboard((r.http && r.http.title) || "", html0.replace(/<[^>]+>/g, " ").replace(/&nbsp;/g, " "));
  if (dash) {
    devDashboards.add(`${dash.name} ${dash.versions.join(",") || "(sem versão)"}${dash.modphp ? " mod_php" : ""}`);
    host.indicators.push({ kind: "alert", value: dash.name });
    for (const text of host.versions.length ? [] : dash.versions) {
      const v = extractPhpVersion(text);
      if (v) host.versions.push({ ...v, source: dash.name });
    }
  }

  const ioc = matchIocHost(r.ip_str || "");
  if (ioc) {
    iocHosts.add(`${r.ip_str} (${ioc})`);
    host.indicators.push({ kind: "ioc", value: ioc });
  }

  // phpinfo() exposto no corpo capturado pelo Shodan.
  const html = r.http && typeof r.http.html === "string" ? r.http.html : "";
  if (/phpinfo\(\)/i.test(html) && /PHP Version/i.test(html)) {
    stats.phpinfoPages++;
    const info = parsePhpinfo(html);
    if (info && info.versionText) {
      stats.phpinfoParsed++;
      host.phpinfo = info;
      const v = extractPhpVersion(info.versionText);
      if (v) host.versions.push({ ...v, source: "phpinfo" });
      phpinfoSapi.add(info.sapi || "(sem Server API)");
      uploadProgress.add(info.uploadProgress || "(ausente)");
      if (info.hardLimit) stats.phpinfoHardLimit++;
    } else {
      phpinfoFailures.add("parse", `${r.ip_str}:${r.port} ${html.slice(0, 200).replace(/\s+/g, " ")}`);
    }
  }

  // Diretório aberto com arquivos de toolkit.
  const title = (r.http && r.http.title) || "";
  if (/^(Index of |Directory listing for )/i.test(title)) {
    stats.openDirs++;
    const names = [...html.matchAll(/href="([^"?#]+)"/gi)].map((m) => m[1].replace(/\/$/, "").split("/").pop());
    for (const hit of matchIocFiles(names)) iocFiles.add(`${hit.file} @ ${r.ip_str}:${r.port}`);
  }

  const verdict = assess(host);
  status.add(verdict.status);
  if (host.versions.length) stats.withPhpVersion++;
  else if (verdict.status === "no_version") stats.phpNoVersion++;

  for (const v of host.versions) {
    versions.add(v.full);
    if (!versionStatus.has(v.full)) versionStatus.set(v.full, classifyVersion(v));
    const c = versionStatus.get(v.full);
    // Pacote de distro sem regra específica: candidatos a entrar em DISTRO_FIXED.
    if (c.status === "check" && v.suffix) genericCheckSuffix.add(v.suffix.replace(/\d+/g, "N"));
  }

  const xpb = found.headers["x-powered-by"] || "";
  const server = found.headers.server || "";
  for (const h of sapiFromHeaders(server, xpb)) sapi.add(render("en", h));

  // Cabeçalhos que mencionam PHP mas de onde nenhuma versão foi lida (lacunas do parser).
  for (const val of [xpb, server]) {
    if (/php/i.test(val) && !extractPhpVersion(val)) phpHeaderNoVersion.add(val.slice(0, 80));
  }

  // X-Powered-By sem PHP: quais viram indício de PHP e quais são ignorados.
  if (xpb && !/php/i.test(xpb)) {
    const flagged = found.indicators.some((i) => typeof i.value === "string" && i.value.startsWith("X-Powered-By"));
    (flagged ? xpbNonPhpFlagged : xpbNonPhpIgnored).add(xpb.slice(0, 60));
    if (headers.some((h) => /^set-cookie$/i.test(h.name) && PHP_COOKIE.test(h.value))) xpbNonPhpWithPhpCookie.add(xpb.slice(0, 60));
  }

  // Concordância com o CPE do PHP que o próprio Shodan atribuiu.
  const cpe = (r.cpe23 || []).find((c) => /^cpe:2\.3:a:php:php:/.test(c));
  if (cpe) {
    stats.cpePhp++;
    const cpeVer = cpe.split(":")[5];
    const ours = host.versions.map((v) => `${v.major}.${v.minor}.${v.patch ?? ""}`.replace(/\.$/, ""));
    if (ours.includes(cpeVer)) stats.cpeAgree++;
    else {
      stats.cpeDisagree++;
      cpeMismatch.add(`cpe=${cpeVer} ours=${ours.join("|") || "-"} xpb=${xpb.slice(0, 40)} server=${server.slice(0, 40)}`);
    }
  }
}

const started = Date.now();
const input = createReadStream(file);
const stream = file.endsWith(".gz") ? input.pipe(createGunzip()) : input;
const rl = createInterface({ input: stream, crlfDelay: Infinity });

for await (const line of rl) {
  if (!line) continue;
  stats.lines++;
  let r;
  try {
    r = JSON.parse(line);
  } catch {
    stats.badJson++;
    continue;
  }
  try {
    processRecord(r);
  } catch (e) {
    stats.errors++;
    errorSamples.add(e.message, `${r.ip_str}:${r.port}`);
  }
  if (stats.lines >= limit) break;
  if (stats.lines % 100000 === 0) console.error(`${stats.lines} linhas, ${((Date.now() - started) / 1000).toFixed(0)}s`);
}

const pct = (a, b) => (b ? `${((100 * a) / b).toFixed(1)}%` : "-");
const table = (title, rows) => {
  console.log(`\n## ${title}`);
  if (!rows.length) console.log("(nenhum)");
  for (const [k, n] of rows) console.log(`${String(n).padStart(8)}  ${k}`);
};

console.log(`# QA Shodan: ${file}`);
console.log(`linhas ${stats.lines}, JSON inválido ${stats.badJson}, banners HTTP ${stats.http}, honeypots ignorados ${stats.honeypots}, erros ${stats.errors}`);
console.log(`versão só pela assinatura do Apache no corpo: ${stats.fromSignature}`);
console.log(`com versão do PHP ${stats.withPhpVersion} (${pct(stats.withPhpVersion, stats.http)}), PHP sem versão ${stats.phpNoVersion}`);
console.log(`CPE do PHP no Shodan: ${stats.cpePhp}, concorda ${stats.cpeAgree} (${pct(stats.cpeAgree, stats.cpePhp)}), discorda ${stats.cpeDisagree}`);
console.log(`phpinfo(): ${stats.phpinfoPages} páginas, ${stats.phpinfoParsed} lidas, ${stats.phpinfoHardLimit} com memory_hard_limit_percent`);
console.log(`diretórios abertos: ${stats.openDirs}; tempo ${((Date.now() - started) / 1000).toFixed(0)}s`);
table("Vereditos", status.top(10));
table("Versões mais vistas (com veredito)", versions.top(40).map(([v, n]) => [`${v}  -> ${versionStatus.get(v).status}`, n]));
table("Sufixos de distro sem regra específica (status check)", genericCheckSuffix.top(25));
table("Cabeçalhos com PHP sem versão lida", phpHeaderNoVersion.top(20));
table("Discordâncias com o CPE do Shodan", cpeMismatch.top(20));
table("SAPI pelos cabeçalhos", sapi.top(10));
table("phpinfo: Server API", phpinfoSapi.top(10));
table("phpinfo: session.upload_progress.enabled", uploadProgress.top(5));
table("X-Powered-By sem PHP marcado como PHP", xpbNonPhpFlagged.top(15));
table("X-Powered-By sem PHP ignorado", xpbNonPhpIgnored.top(15));
table("X-Powered-By sem PHP junto com cookie de PHP (candidatos a PHP_PRODUCTS)", xpbNonPhpWithPhpCookie.top(15));
table("Painéis de desenvolvimento expostos", devDashboards.top(15));
table("Hosts de IOC", iocHosts.top(20));
table("Arquivos de IOC em diretórios abertos", iocFiles.top(20));
if (errorSamples.m.size) console.log("\n## Erros\n", Object.fromEntries(errorSamples.m));
if (phpinfoFailures.m.size) console.log("\n## phpinfo não lido\n", Object.fromEntries(phpinfoFailures.m));

if (jsonOut) {
  writeFileSync(
    jsonOut,
    JSON.stringify({ stats, status: status.top(20), versions: versions.top(200), genericCheckSuffix: genericCheckSuffix.top(100), cpeMismatch: cpeMismatch.top(100) }, null, 2)
  );
}
