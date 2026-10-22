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
