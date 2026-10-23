// Testes das regras de classificação e das traduções. Rodar com: node --test tests/*.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  extractPhpVersion, classifyVersion, dpkgCompare, assess, parsePhpinfo, matchIocHost, matchIocFiles, sapiFromHeaders,
} from "../lib/php-rules.js";
import { t, render } from "../lib/i18n.js";

const status = (header) => classifyVersion(extractPhpVersion(header)).status;

test("versões upstream por branch", () => {
  assert.equal(status("PHP/8.5.11"), "vulnerable");
  assert.equal(status("PHP/8.5.12"), "patched");
  assert.equal(status("PHP/8.4.26"), "vulnerable");
  assert.equal(status("PHP/8.4.27"), "patched");
  assert.equal(status("PHP/8.3.35"), "vulnerable");
  assert.equal(status("PHP/8.3.36"), "patched");
  assert.equal(status("PHP/8.2.34"), "vulnerable");
  assert.equal(status("PHP/8.2.35"), "patched");
  assert.equal(status("PHP/9.0.1"), "patched");
  assert.equal(status("PHP/8.3"), "check");
});

test("builds RC não têm a correção", () => {
  assert.equal(status("PHP/8.4.27RC1"), "vulnerable");
  assert.equal(status("PHP/8.5.12RC1"), "vulnerable");
});

test("branches EOL e backports de fornecedor", () => {
  assert.equal(status("PHP/5.6.40"), "eol");
  assert.equal(status("PHP/7.4.30"), "eol");
  assert.equal(status("PHP/7.4.33"), "check");
  assert.equal(status("PHP/8.0.30"), "check");
  assert.equal(status("PHP/8.1.34"), "check");
});

test("pacotes de distribuição", () => {
  assert.equal(status("PHP/8.1.2-1ubuntu2.14"), "vulnerable");
  assert.equal(status("PHP/8.1.2-1ubuntu2.28"), "backport");
  assert.equal(status("PHP/8.3.6-0ubuntu0.24.04.12"), "vulnerable");
  assert.equal(status("PHP/8.3.6-0ubuntu0.24.04.13"), "backport");
  assert.equal(status("PHP/8.5.4-0ubuntu1.5"), "backport");
  assert.equal(status("PHP/8.5.9-0ubuntu2.1"), "backport");
  assert.equal(status("PHP/7.4.3-4ubuntu2.29+esm4"), "vulnerable");
  assert.equal(status("PHP/7.4.3-4ubuntu2.29+esm5"), "backport");
  assert.equal(status("PHP/8.2.20-1~deb12u1"), "vulnerable");
  assert.equal(status("PHP/8.4.27-1~deb13u1"), "patched");
  assert.equal(status("PHP/7.4.33-30+ubuntu22.04.1+deb.sury.org+1"), "vulnerable");
  assert.equal(status("PHP/7.4.33-31+ubuntu22.04.1+deb.sury.org+1"), "check");
  assert.equal(status("PHP/8.2.13.el9"), "check");
});

test("extração de versão em formatos comuns", () => {
  assert.equal(extractPhpVersion("Apache/2.4.52 (Ubuntu) PHP/8.0.30").full, "8.0.30");
  assert.equal(extractPhpVersion("PHP Version 8.3.6").full, "8.3.6");
  assert.equal(extractPhpVersion("nginx"), null);
});

test("comparação dpkg", () => {
  assert.ok(dpkgCompare("8.4.27-1~deb13u1", "8.4.27-1") < 0);
  assert.ok(dpkgCompare("8.1.2-1ubuntu2.9", "8.1.2-1ubuntu2.28") < 0);
  assert.equal(dpkgCompare("1.0-1", "1.0-1"), 0);
});

test("phpinfo com memory_hard_limit_percent confirma a correção", () => {
  const html =
    '<title>PHP 8.3.35 - phpinfo()</title><h1 class="p">PHP Version 8.3.35</h1>' +
    '<tr><td class="e">Server API </td><td class="v">FPM/FastCGI </td></tr>' +
    '<tr><td class="e">memory_hard_limit_percent</td><td class="v">200</td><td class="v">200</td></tr>' +
    '<tr><td class="e">session.upload_progress.enabled</td><td class="v">Off</td><td class="v">On</td></tr>';
  const info = parsePhpinfo(html);
  assert.equal(info.sapi, "FPM/FastCGI");
  assert.equal(info.uploadProgress, "Off");
  assert.equal(info.hardLimit, true);
  const v = extractPhpVersion(info.versionText);
  assert.equal(assess({ versions: [v], indicators: [], phpinfo: info }).status, "backport");
  assert.equal(parsePhpinfo("<html>hello</html>"), null);
});

test("avaliação sem versão", () => {
  assert.equal(assess({ versions: [], indicators: [{ kind: "cookie", value: "x" }] }).status, "no_version");
  assert.equal(assess({ versions: [], indicators: [{ kind: "ioc", value: "x" }] }).status, "not_detected");
  assert.equal(assess({}).status, "not_detected");
});

test("SAPI pelos cabeçalhos", () => {
  assert.equal(sapiFromHeaders("Apache/2.4.58 (Ubuntu) PHP/8.3.6", "")[0].k, "sapi.modphp");
  assert.equal(sapiFromHeaders("nginx/1.24.0", "PHP/8.3.35")[0].k, "sapi.nginx");
  assert.equal(sapiFromHeaders("nginx/1.24.0", "").length, 0);
});

test("IOCs da Hunt.io", () => {
  assert.equal(matchIocHost("206.188.197.105"), "ioc.toolkitDir");
  assert.equal(matchIocHost("45.198.224.9"), "ioc.scannerNet");
  assert.equal(matchIocHost("a.godofthunder.st"), "ioc.c2");
  assert.equal(matchIocHost("example.com"), null);
  assert.equal(matchIocFiles(["shell.php", "index.html"]).length, 0);
  assert.equal(matchIocFiles(["aslr_exploit.py", "shell.php"]).length, 2);
});

test("toda chave usada no código existe no dicionário, em inglês e português", () => {
  const files = ["background.js", "content.js", "popup.js", "popup.html", "lib/php-rules.js"];
  const src = files.map((f) => readFileSync(new URL(`../${f}`, import.meta.url), "utf8")).join("\n");
  const keys = new Set([
    ...[...src.matchAll(/(?:msg|tr)\(\s*"([a-zA-Z]+\.[a-zA-Z.]+)"/g)].map((m) => m[1]),
    ...[...src.matchAll(/t\(lang, "([a-zA-Z]+\.[a-zA-Z.]+)"/g)].map((m) => m[1]),
    ...[...src.matchAll(/data-i18n(?:-title)?="([^"]+)"/g)].map((m) => m[1]),
    ...[...src.matchAll(/"(ioc\.[a-zA-Z]+)"/g)].map((m) => m[1]),
  ]);
  assert.ok(keys.size > 50);
  for (const k of keys) {
    assert.notEqual(t("en", k), k, `chave sem tradução: ${k}`);
    assert.notEqual(t("pt", k), k, `chave sem tradução: ${k}`);
  }
  const r = classifyVersion(extractPhpVersion("PHP/7.4.33"));
  assert.doesNotMatch(render("pt", r.detail), /\{\w+\}/);
});

// Casos reais encontrados no QA com dados do Shodan (tools/shodan-qa.mjs).
import { analyzeHeaders, distroRelease } from "../lib/php-rules.js";

test("QA Shodan: builds rotuladas, Dotdeb e releases de distro", () => {
  assert.equal(status("PHP/7.4.33-php2shell-fix"), "check");
  assert.equal(status("PHP/5.3.10-1ubuntu3.48+php2shell2"), "check");
  assert.equal(status("PHP/5.3.24-1~dotdeb.0"), "eol");
  assert.equal(status("PHP/5.2.9-0.dotdeb.2"), "eol");
  assert.equal(status("PHP/7.4.3-4ubuntu2.24"), "vulnerable");
  assert.equal(distroRelease("5.5.9", "-1ubuntu4.21"), "Ubuntu 14.04");
  assert.equal(distroRelease("7.0.33", "-0ubuntu0.16.04.16"), "Ubuntu 16.04");
  assert.equal(distroRelease("5.6.20", "-0+deb8u1"), "Debian 8");
  assert.equal(distroRelease("5.6.40", "-57+ubuntu18.04.1+deb.sury.org+1"), "Sury (Ubuntu 18.04)");
});

test("QA Shodan: cabeçalhos com PHP sem versão e X-Powered-By de outras stacks", () => {
  const verdict = (name, value) => assess({ versions: [], indicators: analyzeHeaders([{ name, value }]).indicators }).status;
  assert.equal(verdict("X-Powered-By", "php"), "no_version");
  assert.equal(verdict("X-Powered-By", "ThinkPHP"), "no_version");
  assert.equal(verdict("X-Powered-By", "Fat-Free Framework"), "no_version");
  assert.equal(verdict("Server", "thttpd/2.25b PHP/20030920"), "no_version");
  assert.equal(verdict("X-Powered-By", "Express"), "not_detected");
  assert.equal(verdict("X-Powered-By", "Next.js"), "not_detected");
  assert.equal(verdict("X-Powered-By", "ASP.NET"), "not_detected");
  assert.equal(sapiFromHeaders("", "FrankenPHP Caddy")[0].k, "sapi.caddy");
});

// Sinais aprendidos com o Shodan, confirmados em hosts reais (fora dos honeypots).
import { versionsFromSignatures } from "../lib/php-rules.js";

test("QA Shodan: novos sinais de cabeçalho e cookie", () => {
  const kinds = (hdrs) => analyzeHeaders(hdrs).indicators.map((i) => i.kind);
  assert.deepEqual(kinds([{ name: "phpdebugbar-id", value: "01M5J" }]), ["alert"]);
  assert.deepEqual(kinds([{ name: "X-PHP-PID", value: "4720" }]), ["header"]);
  assert.deepEqual(kinds([{ name: "X-PHP-Response-Code", value: "403" }]), ["header"]);
  assert.deepEqual(kinds([{ name: "Set-Cookie", value: "oc_sessionPassphrase=x" }]), ["cookie"]);
  const laravel = analyzeHeaders([
    { name: "Set-Cookie", value: "XSRF-TOKEN=a; path=/" },
    { name: "Set-Cookie", value: "subs_session=b; path=/; httponly" },
  ]).indicators;
  assert.equal(laravel.length, 1);
  assert.equal(laravel[0].value.p.label, "Laravel");
  // Só um dos dois não basta.
  assert.equal(analyzeHeaders([{ name: "Set-Cookie", value: "XSRF-TOKEN=a" }]).indicators.length, 0);
  assert.equal(analyzeHeaders([{ name: "Set-Cookie", value: "csrftoken=a" }]).indicators.length, 0);
});

test("QA Shodan: versão pela assinatura do Apache", () => {
  const [s] = versionsFromSignatures(["Apache/2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.2.18 mod_fcgid/2.3.10-dev Server at x Port 80"]);
  assert.equal(s.v.full, "7.2.18");
  assert.match(s.source, /^Apache signature:/);
  assert.equal(versionsFromSignatures(["Apache/2.4.39 Server at x Port 80"]).length, 0);
});

import { parseDevDashboard } from "../lib/php-rules.js";

test("QA Shodan: painéis WampServer e Laragon expostos", () => {
  const wamp = parseDevDashboard("Accueil WAMPSERVER", "Apache/2.4.54 (Win64) PHP/8.0.26 - Port 80 PHP 8.0.26 -> Apache module PHP 8.0.26 -> CLI - FCGI PHP 7.4.33 used for CLI");
  assert.deepEqual(wamp, { name: "WampServer", versions: ["PHP 8.0.26"], modphp: true });
  const laragon = parseDevDashboard("Laragon", "Apache/2.4.66 (Win64) OpenSSL/3.0.18 PHP/8.3.30 PHP version: 8.3.30 phpinfo()");
  assert.deepEqual(laragon, { name: "Laragon", versions: ["PHP 8.3.30"], modphp: false });
  assert.equal(parseDevDashboard("Welcome", "PHP version: 8.3.30"), null);
});

import { fingerprintSession, isPhpSessionCacheLimiter } from "../lib/php-rules.js";

test("fingerprint do PHPSESSID: teto de versão pelo formato do ID", () => {
  // IDs reais de 26 chars no alfabeto 0-9a-v exigem session.hash_bits_per_character=5 (removido no 7.1).
  assert.equal(fingerprintSession("og1ritgauld215rh2j3u61lhgu").range, "<=7.0");
  assert.equal(fingerprintSession("h3rc1m1ipmqmcsvng86pharkq4").range, "<=7.0");
  // 32 hex é o padrão nas duas eras -> sem sinal.
  assert.equal(fingerprintSession("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"), null);
  // Alfabeto de 6 bits (maiúsculas, vírgula, hífen) num comprimento não-legado -> >= 7.1.
  assert.equal(fingerprintSession("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345,-abcdef").range, ">=7.1");
  // Underscore não existe no alfabeto nativo do PHP.
  assert.equal(fingerprintSession("wJ9x_Abc123XYZ_wJ9x_Abc123XYZ_01"), null);
});

test("fingerprint do PHPSESSID vira veredito EOL inferido", () => {
  const { indicators } = analyzeHeaders([{ name: "Set-Cookie", value: "PHPSESSID=og1ritgauld215rh2j3u61lhgu; path=/; secure; HttpOnly" }]);
  assert.ok(indicators.some((i) => i.kind === "session"));
  const verdict = assess({ versions: [], indicators });
  assert.equal(verdict.status, "eol");
  assert.equal(verdict.badge, "≤7.0");
  // Um ID >= 7.1 não baixa para EOL: segue como PHP sem versão.
  const modern = analyzeHeaders([{ name: "Set-Cookie", value: "PHPSESSID=ABCDEFGHIJKLMNOPQRSTUVWXYZ012345,-abcdef; path=/" }]).indicators;
  assert.equal(assess({ versions: [], indicators: modern }).status, "no_version");
});

test("cabeçalhos de cache-limiter de sessão do PHP", () => {
  assert.equal(isPhpSessionCacheLimiter("Thu, 19 Nov 1981 08:52:00 GMT", "no-store, no-cache, must-revalidate", "no-cache"), true);
  assert.equal(isPhpSessionCacheLimiter("Wed, 21 Oct 2026 00:00:00 GMT", "no-store, no-cache, must-revalidate", "no-cache"), false);
  const { indicators } = analyzeHeaders([
    { name: "Expires", value: "Thu, 19 Nov 1981 08:52:00 GMT" },
    { name: "Cache-Control", value: "no-store, no-cache, must-revalidate, post-check=0, pre-check=0" },
    { name: "Pragma", value: "no-cache" },
  ]);
  assert.ok(indicators.some((i) => i.kind === "header" && i.value.k === "ind.cacheLimiter"));
  assert.equal(assess({ versions: [], indicators }).status, "no_version");
});

test("QA Shodan: WampServer antigo e XAMPP", () => {
  assert.deepEqual(parseDevDashboard("WAMPSERVER Homepage", "Apache Version : 2.2.11 PHP Version : 5.3.0 Loaded Extensions").versions, ["PHP 5.3.0"]);
  assert.deepEqual(parseDevDashboard("Welcome to XAMPP", "Apache + MariaDB + PHP + Perl Welcome to XAMPP for Windows 8.2.12 You have").versions, ["PHP 8.2.12"]);
  assert.deepEqual(parseDevDashboard("XAMPP 5.6.3", "").versions, ["PHP 5.6.3"]);
  // XAMPP 1.x tem numeração própria, não é a versão do PHP.
  assert.deepEqual(parseDevDashboard("XAMPP 1.8.1", "").versions, []);
});
