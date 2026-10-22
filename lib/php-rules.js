// Regras de classificação do PHP2Shell (CVE-2026-109618 / CVE-2026-109619).
// Fontes: guia técnico da NoceraInfoSec® v1.0 (Tabelas 5, 6 e 7), Hunt.io, Brandefense, ComputingForGeeks,
// Aikido e watchTowr (todos de 21-22/10/2026). Atualize este arquivo quando sairem novos boletins.
// Todo texto sai como mensagem { k, p } (ver lib/i18n.js).
import { msg } from "./i18n.js";

export const RULES_VERSION = "2026-10-22";

// Primeira versão com patch por branch suportado.
export const FIXED = {
  "8.5": "8.5.12",
  "8.4": "8.4.27",
  "8.3": "8.3.36",
  "8.2": "8.2.35",
};

// Branches acima do maior listado foram lançados depois do patch.
const NEWEST_KNOWN_BRANCH = [8, 5];

// Pacotes de distribuição corrigidos por backport (versão dpkg, que o Debian/Ubuntu expõe no X-Powered-By).
export const DISTRO_FIXED = [
  { distro: "Ubuntu 26.10", branch: "8.5", match: /0ubuntu2\./i, pkg: "8.5.9-0ubuntu2.1", ref: "USN-8948-1" },
  { distro: "Ubuntu 26.04", branch: "8.5", match: /0ubuntu1\./i, pkg: "8.5.4-0ubuntu1.5", ref: "USN-8948-1" },
  { distro: "Ubuntu 24.04", branch: "8.3", match: /ubuntu0\.24\.04/i, pkg: "8.3.6-0ubuntu0.24.04.13", ref: "USN-8948-1" },
  { distro: "Ubuntu 22.04", branch: "8.1", match: /ubuntu2(\.|$)/i, pkg: "8.1.2-1ubuntu2.28", ref: "USN-8948-1" },
  { distro: "Ubuntu 20.04 ESM", branch: "7.4", match: /ubuntu2(\.|$)/i, pkg: "7.4.3-4ubuntu2.29+esm5", ref: "USN-8948-2" },
  { distro: "Debian 13", branch: "8.4", match: /deb13u/i, pkg: "8.4.27-1~deb13u1", ref: "DSA-6574-1" },
  { distro: "Debian 12", branch: "8.2", match: /deb12u/i, pkg: "8.2.35-1~deb12u1", ref: "DSA-6574-1 / DLA-4848-1" },
];

// Revisões do repositório Sury reportadas com o patch (relato não oficial).
export const SURY_FIXED = {
  "5.6": "5.6.40-104", "7.0": "7.0.33-92", "7.1": "7.1.33-80", "7.2": "7.2.34-66",
  "7.3": "7.3.33-35", "7.4": "7.4.33-31", "8.0": "8.0.30-25", "8.1": "8.1.34-9",
  "8.2": "8.2.35-1", "8.3": "8.3.36-1", "8.4": "8.4.27-1", "8.5": "8.5.12-1",
};

// Últimas releases de branches EOL para as quais fornecedores publicaram builds corrigidas
// que continuam anunciando o mesmo número (ComputingForGeeks, Brandefense e Aikido, 22/10/2026).
export const VENDOR_BACKPORTS = {
  "7.4.33": ["RHEL 8 php:7.4 (7.4.33-8)", "Remi 7.4.33-31", "cPanel ea-php74", "CloudLinux alt-php74", "Aikido php:7.4.33-fpm"],
  "8.0.30": ["RHEL 9 (8.0.30-8.el9_8.1)", "AlmaLinux 8.0.30-8.el9_8.alma.1", "Remi 8.0.30-21", "cPanel ea-php80", "CloudLinux alt-php80"],
  "8.1.34": ["Remi 8.1.34-6", "cPanel ea-php81", "CloudLinux alt-php81"],
  "8.1.32": ["AlmaLinux 8.1.32-1"],
  "7.3.33": ["Aikido php:7.3.33-fpm"],
};

// Imagens corrigidas da Aikido mantêm a tag da versão anterior ao patch.
export const AIKIDO_SAME_TAG = new Set(["8.5.11", "8.4.26", "8.3.35", "8.2.34"]);

export const STATUS = {
  VULNERABLE: "vulnerable",     // versão anunciada sem patch
  EOL: "eol",                   // 8.1 ou anterior, sem release oficial
  CHECK: "check",               // depende de backport: confirmar no servidor
  BACKPORT: "backport",         // pacote de distro corrigido conhecido
  PATCHED: "patched",           // versão anunciada >= versão com patch
  NO_VERSION: "no_version",     // há indício de PHP mas a versão não é exposta
  NOT_DETECTED: "not_detected", // nenhum indício de PHP
};

export const STATUS_INFO = {
  vulnerable:   { severity: 5, color: "#d93025", badge: "#d93025" },
  eol:          { severity: 5, color: "#a50e0e", badge: "#a50e0e" },
  check:        { severity: 4, color: "#e37400", badge: "#e37400" },
  no_version:   { severity: 3, color: "#b06000", badge: "#5f6368" },
  backport:     { severity: 2, color: "#188038", badge: "#188038" },
  patched:      { severity: 1, color: "#188038", badge: "#188038" },
  not_detected: { severity: 0, color: "#5f6368", badge: "#5f6368" },
};

export const statusLabel = (status) => msg(`status.${status}`);

// Extrai a primeira versão do PHP de um texto (X-Powered-By, Server, phpinfo, etc.).
// Ex.: "PHP/8.1.2-1ubuntu2.14", "Apache/2.4.52 (Ubuntu) PHP/8.3.6", "PHP Version 8.4.27RC1".
export function extractPhpVersion(text) {
  if (!text) return null;
  const m = /PHP(?:\/|\s+Version\s+|\s+)v?(\d+)\.(\d+)(?:\.(\d+))?([0-9A-Za-z.+~:_-]*)/i.exec(text);
  if (!m) return null;
  return {
    raw: m[0],
    major: +m[1],
    minor: +m[2],
    patch: m[3] === undefined ? null : +m[3],
    suffix: m[4] || "",
    full: `${m[1]}.${m[2]}${m[3] !== undefined ? "." + m[3] : ""}${m[4] || ""}`,
  };
}

function cmpTriple(a, b) {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

const triple = (s) => s.split(".").map(Number);

// Comparação de versões no estilo dpkg (epoch:upstream-revision, com "~" < "").
export function dpkgCompare(a, b) {
  const order = (c) => {
    if (c === "~") return -1;
    if (/\d/.test(c)) return 0;
    if (!c) return 0;
    if (/[A-Za-z]/.test(c)) return c.charCodeAt(0);
    return c.charCodeAt(0) + 256;
  };
  const cmpPart = (x, y) => {
    let i = 0, j = 0;
    while (i < x.length || j < y.length) {
      let diff = 0;
      while ((i < x.length && !/\d/.test(x[i])) || (j < y.length && !/\d/.test(y[j]))) {
        const ox = order(x[i] || ""), oy = order(y[j] || "");
        if (ox !== oy) return ox - oy;
        i++; j++;
      }
      while (x[i] === "0") i++;
      while (y[j] === "0") j++;
      while (i < x.length && /\d/.test(x[i]) && j < y.length && /\d/.test(y[j])) {
        if (!diff) diff = x.charCodeAt(i) - y.charCodeAt(j);
        i++; j++;
      }
      if (i < x.length && /\d/.test(x[i])) return 1;
      if (j < y.length && /\d/.test(y[j])) return -1;
      if (diff) return diff;
    }
    return 0;
  };
  const split = (v) => {
    const e = v.indexOf(":");
    const epoch = e >= 0 ? +v.slice(0, e) : 0;
    const rest = e >= 0 ? v.slice(e + 1) : v;
    const d = rest.lastIndexOf("-");
    return [epoch, d >= 0 ? rest.slice(0, d) : rest, d >= 0 ? rest.slice(d + 1) : "0"];
  };
  const [ea, ua, ra] = split(a);
  const [eb, ub, rb] = split(b);
  return ea - eb || cmpPart(ua, ub) || cmpPart(ra, rb);
}

const DISTRO_HINT = /(ubuntu|deb\d*u?|debian|\.el\d|el\d|amzn|fc\d|suse|sury|alpine|\+b\d|remi)/i;
const PRERELEASE = /^(RC|alpha|beta|dev)/i;

// Classifica uma versão anunciada. Retorna { status, title, detail[], actions[] }.
export function classifyVersion(v) {
  const branch = `${v.major}.${v.minor}`;
  const suffix = v.suffix;
  const base = `${v.major}.${v.minor}.${v.patch ?? 0}`;
  const pkg = `${base}${suffix}`;
  const fixed = FIXED[branch];
  const backportNote = msg("note.backport");

  if (v.patch === null && fixed) {
    // Só "PHP/8.3" (sem patch): não dá para concluir dentro de branches suportados.
    return {
      status: STATUS.CHECK,
      title: msg("v.noPatch.title", { branch }),
      detail: [msg("v.noPatch.detail", { branch, fixed })],
      actions: [msg("act.confirmServer")],
    };
  }

  const isNewerBranch =
    v.major > NEWEST_KNOWN_BRANCH[0] ||
    (v.major === NEWEST_KNOWN_BRANCH[0] && v.minor > NEWEST_KNOWN_BRANCH[1]);
  if (isNewerBranch) {
    return {
      status: STATUS.PATCHED,
      title: msg("v.newer.title", { v: v.full }),
      detail: [msg("v.newer.detail")],
      actions: [msg("act.confirmCritical")],
    };
  }

  // Builds de pré-release (8.4.27RC1, 8.5.12RC1) NÃO contêm a correção.
  if (PRERELEASE.test(suffix)) {
    return {
      status: STATUS.VULNERABLE,
      title: msg("v.pre.title", { v: v.full }),
      detail: [msg("v.pre.detail")],
      actions: [msg("act.upgradeStable", { fixed: fixed || "8.2.35+" })],
    };
  }

  if (fixed && cmpTriple([v.major, v.minor, v.patch], triple(fixed)) >= 0) {
    return {
      status: STATUS.PATCHED,
      title: msg("v.patched.title", { v: v.full }),
      detail: [msg("v.patched.detail", { fixed })],
      actions: [msg("act.confirmRestart")],
    };
  }

  // Abaixo da versão corrigida, ou branch sem suporte. Verificar backports conhecidos.
  if (/sury/i.test(suffix)) {
    const ref = SURY_FIXED[branch];
    const debVer = pkg.replace(/\+.*$/, "");
    if (ref && dpkgCompare(debVer, ref) >= 0) {
      return {
        status: STATUS.CHECK,
        title: msg("v.suryOk.title", { v: v.full }),
        detail: [msg("v.suryOk.detail", { ref })],
        actions: [msg("act.suryChangelog", { branch })],
      };
    }
    if (ref) {
      return {
        status: STATUS.VULNERABLE,
        title: msg("v.suryOld.title", { v: v.full }),
        detail: [msg("v.suryOld.detail", { ref })],
        actions: [msg("act.suryUpdate", { branch })],
      };
    }
  }

  for (const d of DISTRO_FIXED) {
    if (d.branch === branch && d.match.test(suffix)) {
      if (dpkgCompare(pkg, d.pkg) >= 0) {
        return {
          status: STATUS.BACKPORT,
          title: msg("v.distroOk.title", { v: v.full, distro: d.distro }),
          detail: [msg("v.distroOk.detail", { pkg: d.pkg, ref: d.ref })],
          actions: [msg("act.restartAfterPkg")],
        };
      }
      return {
        status: STATUS.VULNERABLE,
        title: msg("v.distroOld.title", { v: v.full, distro: d.distro }),
        detail: [msg("v.distroOld.detail", { pkg: d.pkg, ref: d.ref })],
        actions: [msg("act.distroUpdate", { pkg: d.pkg })],
      };
    }
  }

  if (DISTRO_HINT.test(suffix)) {
    return {
      status: STATUS.CHECK,
      title: msg(fixed ? "v.distroCheck.title" : "v.distroCheck.titleEol", { v: v.full }),
      detail: [msg("v.distroCheck.detail")],
      actions: [msg("act.confirmPkg"), msg("act.ifNoBackport")],
    };
  }

  // Número "puro" que fornecedores mantêm em builds corrigidas (RHEL, Remi, cPanel, CloudLinux, Aikido).
  if (!suffix && VENDOR_BACKPORTS[base]) {
    return {
      status: STATUS.CHECK,
      title: msg("v.vendorLast.title", { v: base, branch }),
      detail: [msg("v.vendorLast.detail", { v: base, branch, vendors: VENDOR_BACKPORTS[base].join(", ") })],
      actions: [msg("act.confirmPkg"), msg("act.migrate")],
    };
  }

  if (!fixed) {
    return {
      status: STATUS.EOL,
      title: msg("v.eol.title", { v: v.full }),
      detail: [msg("v.eol.detail"), backportNote],
      actions: [msg("act.migrate"), msg("act.confirmBeforeClose")],
    };
  }

  const detail = [msg("v.vuln.detail", { branch, fixed }), backportNote];
  if (!suffix && AIKIDO_SAME_TAG.has(base)) detail.push(msg("note.aikido", { v: base }));
  return {
    status: STATUS.VULNERABLE,
    title: msg("v.vuln.title", { v: v.full }),
    detail,
    actions: [msg("act.upgrade", { fixed }), msg("act.stopgap"), msg("act.confirmBeforeClose")],
  };
}

// Lê a tabela de um phpinfo() (HTML). Funciona em string, sem DOM, para rodar no service worker.
export function parsePhpinfo(html) {
  if (!html || !/phpinfo\(\)|<h1 class="p">PHP Version/i.test(html)) return null;
  const cell = (name) => {
    const re = new RegExp(`<td class="e">\\s*${name.replace(/\./g, "\\.")}\\s*</td>\\s*<td class="v">\\s*(.*?)\\s*</td>`, "i");
    const m = re.exec(html);
    return m ? m[1].replace(/<[^>]+>/g, "").trim() : null;
  };
  const h1 = /<h1 class="p">\s*(PHP Version [^<]+)<\/h1>/i.exec(html);
  const title = /<title>\s*(PHP [^<]*?)\s*-\s*phpinfo\(\)/i.exec(html);
  return {
    versionText: h1 ? h1[1] : title ? title[1] : null,
    sapi: cell("Server API"),
    uploadProgress: cell("session.upload_progress.enabled"),
    memoryLimit: cell("memory_limit"),
    hardLimit: cell("memory_hard_limit_percent") !== null,
    exposePhp: cell("expose_php"),
  };
}

// Combina as evidências de um host em um veredito.
export function assess(host) {
  const versions = host.versions || [];
  if (versions.length) {
    // Usa a versão com maior severidade (pior caso) quando o host anuncia mais de uma.
    let worst = null;
    for (const v of versions) {
      const c = { ...classifyVersion(v), version: v };
      if (!worst || STATUS_INFO[c.status].severity > STATUS_INFO[worst.status].severity) worst = c;
    }
    // memory_hard_limit_percent só existe em builds com a correção (ComputingForGeeks).
    if (host.phpinfo && host.phpinfo.hardLimit && worst.status !== STATUS.PATCHED) {
      return {
        status: STATUS.BACKPORT,
        title: msg("v.phpinfoFixed.title", { v: worst.version.full }),
        detail: [msg("v.phpinfoFixed.detail")],
        actions: [msg("act.removePhpinfo"), msg("act.confirmRestart")],
        version: worst.version,
      };
    }
    return worst;
  }
  if ((host.indicators || []).some((i) => i.kind !== "ioc")) {
    return {
      status: STATUS.NO_VERSION,
      title: msg("a.noVersion.title"),
      detail: [msg("a.noVersion.detail")],
      actions: [msg("act.confirmHosting")],
    };
  }
  return {
    status: STATUS.NOT_DETECTED,
    title: msg("a.none.title"),
    detail: [msg("a.none.detail")],
    actions: [],
  };
}

// Pistas de SAPI a partir dos cabeçalhos. O PHP classifica Apache + mod_php como o cenário de maior risco.
export function sapiFromHeaders(server = "", xpb = "") {
  const hints = [];
  const hasPhp = /PHP/i.test(xpb) || /PHP/i.test(server);
  if (/Apache/i.test(server) && /PHP\//i.test(server)) hints.push(msg("sapi.modphp"));
  if (/LiteSpeed/i.test(server)) hints.push(msg("sapi.litespeed"));
  if (/Caddy|FrankenPHP/i.test(server) && hasPhp) hints.push(msg("sapi.caddy"));
  if (/nginx|openresty/i.test(server) && hasPhp) hints.push(msg("sapi.nginx"));
  return hints;
}

// ---------- Infraestrutura de ataque do PHP2Shell ----------
// Fonte: Hunt.io, "Hunting Leaked PHP2Shell RCE Across Open Directories" (22/10/2026).
// Serve para o analista que abre diretórios abertos de atacantes no navegador.

export const IOC_SOURCE = "Hunt.io (2026-10-22)";

export const IOC_IPS = {
  "85.11.167.243": "ioc.scanner",
  "92.118.112.100": "ioc.payload",
  "89.32.41.16": "ioc.botnet",
  "89.32.41.50": "ioc.botnet",
  "45.198.224.88": "ioc.botnet",
  "91.90.123.25": "ioc.research",
  "102.210.149.166": "ioc.staging",
  "122.10.110.72": "ioc.staging",
  "122.10.17.49": "ioc.staging",
  "58.221.60.160": "ioc.probeDir",
  "206.188.197.105": "ioc.toolkitDir",
  "41.223.30.7": "ioc.staging",
  "157.230.117.70": "ioc.staging",
  "104.219.251.31": "ioc.shellDir",
  "107.150.31.151": "ioc.staging",
  "217.160.132.82": "ioc.staging",
  "47.100.125.108": "ioc.staging",
  "54.169.109.7": "ioc.staging",
  "139.162.165.136": "ioc.staging",
};

// 45.198.224.0/24 (AS215925, VPSVAULT): rede de scanner.
export const IOC_PREFIXES = [["45.198.224.", "ioc.scannerNet"]];

export const IOC_DOMAINS = [
  ["botlesscucks.st", "ioc.c2"],
  ["godofthunder.st", "ioc.c2"],
  ["gettingheadfromduckysmom.st", "ioc.c2"],
  ["maste.mangsud.org", "ioc.shellSrc"],
];

// Arquivos vistos nos diretórios abertos dos atacantes.
export const IOC_FILES = [
  [/^aslr_exploit\.py$/i, "ioc.toolkit"],
  [/^deep_probe\.py$/i, "ioc.toolkit"],
  [/^c2\.py$/i, "ioc.toolkit"],
  [/^probe_rfc1867\.py$/i, "ioc.probe"],
  [/^verify_fixation\.py$/i, "ioc.probe"],
  [/^autologin_fd\.php$/i, "ioc.webshell"],
  [/^tebaran_/i, "ioc.deployer"],
  [/php2shell|109618|109619/i, "ioc.named"],
];

// Retorna a chave do rótulo do IOC ou null.
export function matchIocHost(hostname) {
  if (IOC_IPS[hostname]) return IOC_IPS[hostname];
  for (const [prefix, label] of IOC_PREFIXES) if (hostname.startsWith(prefix)) return label;
  for (const [domain, label] of IOC_DOMAINS) if (hostname === domain || hostname.endsWith("." + domain)) return label;
  return null;
}

// shell.php só conta junto com outro arquivo do toolkit, por ser um nome genérico.
export function matchIocFiles(names) {
  const hits = [];
  for (const name of names) {
    for (const [re, label] of IOC_FILES) {
      if (re.test(name)) {
        hits.push({ file: name, label });
        break;
      }
    }
  }
  if (hits.length && names.some((n) => /^shell\.php$/i.test(n))) hits.push({ file: "shell.php", label: "ioc.webshell" });
  return hits;
}
