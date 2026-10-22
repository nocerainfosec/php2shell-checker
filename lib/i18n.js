// Mensagens da extensão em inglês e português. Regras e coletores produzem { k, p } (chave + parâmetros);
// a tradução só acontece na hora de exibir, então trocar o idioma não exige recoletar nada.

export const LANGS = ["en", "pt"];

const M = {
  // ---------- Status ----------
  "status.vulnerable": { en: "VULNERABLE", pt: "VULNERÁVEL" },
  "status.eol": { en: "UNSUPPORTED (EOL)", pt: "SEM SUPORTE (EOL)" },
  "status.check": { en: "CONFIRM BACKPORT", pt: "CONFIRMAR BACKPORT" },
  "status.no_version": { en: "PHP, NO VERSION", pt: "PHP SEM VERSÃO" },
  "status.backport": { en: "BACKPORT APPLIED", pt: "BACKPORT APLICADO" },
  "status.patched": { en: "PATCHED VERSION", pt: "VERSÃO COM PATCH" },
  "status.not_detected": { en: "PHP NOT DETECTED", pt: "PHP NÃO DETECTADO" },

  // ---------- Vereditos por versão ----------
  "v.noPatch.title": { en: "PHP {branch} announced without a patch number", pt: "PHP {branch} anunciado sem número de patch" },
  "v.noPatch.detail": {
    en: "Branch {branch} is fixed from {fixed}, but the server does not announce the patch level.",
    pt: "O branch {branch} tem correção a partir de {fixed}, mas o servidor não informa o patch.",
  },
  "v.newer.title": { en: "PHP {v}: branch newer than the fix", pt: "PHP {v}: branch posterior ao patch" },
  "v.newer.detail": {
    en: "Branch released after 21 Oct 2026, presumed to include the fix.",
    pt: "Branch lançado depois de 21/10/2026, presume-se que já inclui a correção.",
  },
  "v.pre.title": { en: "PHP {v}: pre-release build", pt: "PHP {v}: build de pré-release" },
  "v.pre.detail": {
    en: "RC/beta builds (e.g. 8.4.27RC1, 8.5.12RC1) do not contain the PHP2Shell fix.",
    pt: "Builds RC/beta (ex.: 8.4.27RC1, 8.5.12RC1) não contêm a correção do PHP2Shell.",
  },
  "v.patched.title": { en: "PHP {v}: patched release", pt: "PHP {v}: versão com patch publicado" },
  "v.patched.detail": {
    en: "Equal to or above {fixed}. The announced version does not prove the running workers were restarted.",
    pt: "Igual ou superior a {fixed}. A versão anunciada não prova que o processo em execução foi reiniciado.",
  },
  "v.suryOk.title": { en: "PHP {v}: Sury package with reported backport", pt: "PHP {v}: pacote Sury com backport reportado" },
  "v.suryOk.detail": {
    en: "Revision >= {ref}. Unofficial report, confirm in the repository changelog.",
    pt: "Revisão >= {ref}. Relato não oficial, a confirmar no changelog do repositório.",
  },
  "v.suryOld.title": { en: "PHP {v}: Sury package before the backport", pt: "PHP {v}: pacote Sury anterior ao backport" },
  "v.suryOld.detail": {
    en: "Revision older than {ref}, the first one reported with the fix.",
    pt: "Revisão anterior a {ref}, a primeira reportada com o patch.",
  },
  "v.distroOk.title": { en: "PHP {v}: fixed {distro} package", pt: "PHP {v}: pacote {distro} corrigido" },
  "v.distroOk.detail": {
    en: "Package >= {pkg} ({ref}). Fixed by distribution backport.",
    pt: "Pacote >= {pkg} ({ref}). Correção aplicada por backport da distribuição.",
  },
  "v.distroOld.title": { en: "PHP {v}: {distro} package without the backport", pt: "PHP {v}: pacote {distro} sem o backport" },
  "v.distroOld.detail": { en: "Package older than {pkg} ({ref}).", pt: "Pacote anterior a {pkg} ({ref})." },
  "v.distroCheck.title": { en: "PHP {v}: distribution package", pt: "PHP {v}: pacote de distribuição" },
  "v.distroCheck.titleEol": {
    en: "PHP {v}: distribution package (unsupported branch)",
    pt: "PHP {v}: pacote de distribuição (branch sem suporte)",
  },
  "v.distroCheck.detail": {
    en: "The base version is older than the fixed one, but distributions backport the fix without changing the upstream number. Check the vendor advisory.",
    pt: "A versão base é anterior à corrigida, mas distribuições aplicam o patch por backport sem mudar o número upstream. Consultar o boletim do fornecedor.",
  },
  "v.vendorLast.title": {
    en: "PHP {v}: last {branch} release, vendor backports exist",
    pt: "PHP {v}: última release do {branch}, há backports de fornecedores",
  },
  "v.vendorLast.detail": {
    en: "Branch {branch} has no official fix, but these vendors ship fixed builds that still report {v}: {vendors}.",
    pt: "O branch {branch} não tem correção oficial, mas estes fornecedores publicam builds corrigidas que continuam anunciando {v}: {vendors}.",
  },
  "v.distroNamed.title": { en: "PHP {v}: {distro} package", pt: "PHP {v}: pacote {distro}" },
  "v.distroNamed.titleEol": {
    en: "PHP {v}: {distro} package (unsupported branch)",
    pt: "PHP {v}: pacote {distro} (branch sem suporte)",
  },
  "v.customFix.title": {
    en: "PHP {v}: custom build labelled as a PHP2Shell fix",
    pt: "PHP {v}: build própria rotulada como correção do PHP2Shell",
  },
  "v.customFix.detail": {
    en: "The version string says the fix was applied, but this is a label set by whoever built it, not a vendor release.",
    pt: "A versão diz que a correção foi aplicada, mas é um rótulo de quem compilou, não uma release de fornecedor.",
  },
  "note.dotdeb": {
    en: "The Dotdeb repository was discontinued, so no backport is expected for this build.",
    pt: "O repositório Dotdeb foi descontinuado, então não há backport esperado para esta build.",
  },
  "v.eol.title": { en: "PHP {v}: unsupported branch", pt: "PHP {v}: branch fora de suporte" },
  "v.eol.detail": {
    en: "PHP 8.1 and older have no official release with the fix. Treat as vulnerable.",
    pt: "PHP 8.1 e anteriores não têm release oficial com a correção. Tratar como vulnerável.",
  },
  "v.vuln.title": { en: "PHP {v}: below the patched release", pt: "PHP {v}: abaixo da versão com patch" },
  "v.vuln.detail": { en: "Branch {branch} is only fixed from {fixed}.", pt: "O branch {branch} só é corrigido a partir de {fixed}." },
  "v.phpinfoFixed.title": {
    en: "PHP {v}: fixed build confirmed by phpinfo()",
    pt: "PHP {v}: build corrigida confirmada pelo phpinfo()",
  },
  "v.phpinfoFixed.detail": {
    en: "The memory_hard_limit_percent directive only exists in builds with the PHP2Shell fix.",
    pt: "A diretiva memory_hard_limit_percent só existe em builds com a correção do PHP2Shell.",
  },
  "note.backport": {
    en: "The version is only what the server announces: backport repos (Sury, ppa:ondrej) fix it without changing the number.",
    pt: "A versão é só o que o servidor anuncia: repositórios de backport (Sury, ppa:ondrej) corrigem sem mudar o número.",
  },
  "note.aikido": {
    en: "Aikido's patched Docker images keep the tag {v} while including the fix.",
    pt: "As imagens Docker corrigidas da Aikido mantêm a tag {v} e já incluem a correção.",
  },

  // ---------- Ações ----------
  "act.confirmServer": {
    en: "Confirm the version and package on the server (php -v, php-fpm -v, dpkg/rpm).",
    pt: "Confirmar versão e pacote no servidor (php -v, php-fpm -v, dpkg/rpm).",
  },
  "act.confirmCritical": { en: "Confirm the version on the server if the asset is critical.", pt: "Confirmar a versão no servidor se o ativo for crítico." },
  "act.upgradeStable": {
    en: "Upgrade to the stable release {fixed} and restart the workers.",
    pt: "Atualizar para a release estável {fixed} e reiniciar os workers.",
  },
  "act.confirmRestart": {
    en: "Confirm on the server that the workers were restarted with the fixed version.",
    pt: "Confirmar no servidor que os workers foram reiniciados com a versão corrigida.",
  },
  "act.suryChangelog": {
    en: "Check the Sury package changelog on the server (apt changelog php{branch}).",
    pt: "Conferir o changelog do pacote Sury no servidor (apt changelog php{branch}).",
  },
  "act.suryUpdate": {
    en: "Update the php{branch} package from the Sury repository and restart the workers.",
    pt: "Atualizar o pacote php{branch} do repositório Sury e reiniciar os workers.",
  },
  "act.restartAfterPkg": {
    en: "Confirm PHP-FPM/Apache was restarted after the package update.",
    pt: "Confirmar que o PHP-FPM/Apache foi reiniciado após a atualização do pacote.",
  },
  "act.distroUpdate": { en: "Update to {pkg} or later and restart the workers.", pt: "Atualizar para {pkg} ou superior e reiniciar os workers." },
  "act.confirmPkg": {
    en: "Confirm the installed package (dpkg -l 'php*' / rpm -qa 'php*') and the distro advisory.",
    pt: "Confirmar o pacote instalado (dpkg -l 'php*' / rpm -qa 'php*') e o boletim da distro.",
  },
  "act.ifNoBackport": {
    en: "If there is no backport: upgrade, apply stopgaps/WAF or take it offline.",
    pt: "Se não houver backport: atualizar, aplicar paliativos/WAF ou retirar do ar.",
  },
  "act.migrate": {
    en: "Migrate to a supported branch, get an LTS vendor backport, or isolate/take the service offline.",
    pt: "Migrar para branch suportado, obter backport de fornecedor LTS ou isolar/retirar o serviço.",
  },
  "act.upgrade": { en: "Upgrade to {fixed} or later and restart the workers.", pt: "Atualizar para {fixed} ou superior e reiniciar os workers." },
  "act.stopgap": {
    en: "If that is not possible today: config stopgaps (session.upload_progress.enabled=0), WAF and access allowlist.",
    pt: "Se não for possível hoje: paliativos de configuração (session.upload_progress.enabled=0), WAF e allowlist de acesso.",
  },
  "act.confirmBeforeClose": {
    en: "Confirm the installed package on the server (dpkg -l 'php*' / apt changelog) before closing the finding.",
    pt: "Confirmar o pacote instalado no servidor (dpkg -l 'php*' / apt changelog) antes de fechar o achado.",
  },
  "act.confirmHosting": {
    en: "Confirm the version on the server or with the hosting provider.",
    pt: "Confirmar a versão no servidor ou junto ao provedor de hospedagem.",
  },
  "act.removePhpinfo": {
    en: "Remove the public phpinfo() page: it gives attackers the exact version and configuration.",
    pt: "Remover a página phpinfo() pública: ela entrega a versão e a configuração exatas ao atacante.",
  },
  "act.restrictFpmStatus": {
    en: "Restrict the PHP-FPM status page to trusted IPs.",
    pt: "Restringir a página de status do PHP-FPM a IPs confiáveis.",
  },

  // ---------- Avaliação sem versão ----------
  "a.noVersion.title": { en: "PHP detected, version not exposed", pt: "PHP detectado, versão não exposta" },
  "a.noVersion.detail": {
    en: "There are signs of PHP, but the server does not announce the version (expose_php=Off or header removed). Good practice, but it does not prove the asset is fixed.",
    pt: "Há indícios de PHP, mas o servidor não anuncia a versão (expose_php=Off ou cabeçalho removido). Isso é boa prática, mas não prova que o ativo está corrigido.",
  },
  "a.none.title": { en: "No sign of PHP", pt: "Nenhum indício de PHP" },
  "a.none.detail": {
    en: "No PHP header, cookie or artifact was seen. Does not rule out PHP behind a CDN/proxy.",
    pt: "Nenhum cabeçalho, cookie ou artefato de PHP foi observado. Não exclui PHP atrás de CDN/proxy.",
  },

  // ---------- Indicadores ----------
  "ind.cookie": { en: "Cookie {name} ({label})", pt: "Cookie {name} ({label})" },
  "ind.bigSess": {
    en: "Abnormally large PHPSESSID ({n} chars), a PHP2Shell attack sign",
    pt: "PHPSESSID anormalmente grande ({n} chars), sinal de ataque PHP2Shell",
  },
  "ind.phpUrl": { en: ".php resource served ({path})", pt: "Recurso .php servido ({path})" },
  "ind.generator": { en: "Generator: {v}", pt: "Gerador: {v}" },
  "ind.debugbar": {
    en: "PHP DebugBar enabled in production: it leaks queries, requests and variables",
    pt: "PHP DebugBar ativo em produção: vaza consultas, requisições e variáveis",
  },
  "ind.devDashboard": {
    en: "{name} development dashboard exposed to the internet: it lists installed versions and tools",
    pt: "Painel de desenvolvimento {name} exposto na internet: lista versões e ferramentas instaladas",
  },
  "ind.phpinfoPublic": { en: "phpinfo() publicly reachable", pt: "phpinfo() acessível publicamente" },
  "ind.phpLinks": { en: "{n} link(s)/form(s) to .php (e.g. {sample})", pt: "{n} link(s)/form(s) para .php (ex.: {sample})" },
  "ind.phpError": {
    en: "PHP error message shown on the page (display_errors=On)",
    pt: "Mensagem de erro do PHP exibida na página (display_errors=On)",
  },
  "ind.iocHost": { en: "Known PHP2Shell infrastructure: {label}", pt: "Infraestrutura conhecida do PHP2Shell: {label}" },
  "ind.iocFile": { en: "Attack file in open directory: {file} ({label})", pt: "Arquivo de ataque no diretório aberto: {file} ({label})" },
  "ind.fpmStatus": {
    en: "PHP-FPM status page exposed at {path} (pool {pool})",
    pt: "Página de status do PHP-FPM exposta em {path} (pool {pool})",
  },
  "ind.serverStatus": { en: "Apache server-status exposed at {path}", pt: "Apache server-status exposto em {path}" },
  "ind.fpm404": {
    en: "Missing .php returns \"File not found.\": nginx + PHP-FPM",
    pt: "Arquivo .php inexistente retorna \"File not found.\": nginx + PHP-FPM",
  },
  "ind.noInput": {
    en: "Missing .php returns \"No input file specified.\": PHP via FastCGI/CGI",
    pt: "Arquivo .php inexistente retorna \"No input file specified.\": PHP via FastCGI/CGI",
  },
  "ind.easterEgg": {
    en: "PHP logo easter egg answered: PHP older than 5.5 (EOL)",
    pt: "Easter egg do logo do PHP respondeu: PHP anterior ao 5.5 (EOL)",
  },
  "ind.uploadProgressOff": {
    en: "Stopgap active: session.upload_progress.enabled = Off",
    pt: "Paliativo ativo: session.upload_progress.enabled = Off",
  },
  "ind.uploadProgressOn": {
    en: "session.upload_progress.enabled = On (exploited path, default)",
    pt: "session.upload_progress.enabled = On (caminho explorado, padrão)",
  },

  // ---------- SAPI ----------
  "sapi.modphp": {
    en: "Apache mod_php (PHP in the Apache banner): the setup PHP rates as highest risk",
    pt: "Apache mod_php (PHP no banner do Apache): a configuração que o PHP classifica como de maior risco",
  },
  "sapi.litespeed": { en: "LiteSpeed (lsphp), affected SAPI", pt: "LiteSpeed (lsphp), SAPI afetada" },
  "sapi.caddy": { en: "Caddy + PHP: probably FrankenPHP, affected SAPI", pt: "Caddy + PHP: provavelmente FrankenPHP, SAPI afetada" },
  "sapi.nginx": { en: "nginx + PHP: probably PHP-FPM", pt: "nginx + PHP: provavelmente PHP-FPM" },
  "sapi.phpinfo": { en: "Server API (phpinfo): {v}", pt: "Server API (phpinfo): {v}" },
  "sapi.fpm": { en: "PHP-FPM confirmed", pt: "PHP-FPM confirmado" },

  // ---------- Rótulos de IOC ----------
  "ioc.scanner": { en: "PHP2Shell scanner", pt: "Scanner PHP2Shell" },
  "ioc.scannerNet": { en: "PHP2Shell scanner network (AS215925)", pt: "Rede de scanner PHP2Shell (AS215925)" },
  "ioc.payload": { en: "Payload host", pt: "Host de payload" },
  "ioc.botnet": { en: "Botnet binary host", pt: "Host de binário de botnet" },
  "ioc.research": { en: "Likely research checker (php2shell-verify/1.0)", pt: "Provável checker de pesquisa (php2shell-verify/1.0)" },
  "ioc.staging": { en: "Staging/operator", pt: "Staging/operador" },
  "ioc.probeDir": { en: "Open directory with probes (probe_rfc1867.py)", pt: "Diretório aberto com probes (probe_rfc1867.py)" },
  "ioc.toolkitDir": { en: "Open directory with mass-exploitation toolkit", pt: "Diretório aberto com toolkit de exploração em massa" },
  "ioc.shellDir": { en: "Open directory with webshell (shell.php)", pt: "Diretório aberto com webshell (shell.php)" },
  "ioc.c2": { en: "Botnet C2", pt: "C2 de botnet" },
  "ioc.shellSrc": { en: "shell.php source", pt: "Origem do shell.php" },
  "ioc.toolkit": { en: "Mass-exploitation toolkit", pt: "Toolkit de exploração em massa" },
  "ioc.probe": { en: "PHP2Shell probe", pt: "Probe PHP2Shell" },
  "ioc.webshell": { en: "Webshell/payload", pt: "Webshell/payload" },
  "ioc.deployer": { en: "CMS deployer (tebaran_*)", pt: "Deployer de CMS (tebaran_*)" },
  "ioc.named": { en: "File named after PHP2Shell", pt: "Arquivo com nome do PHP2Shell" },

  // ---------- Fontes ----------
  "src.page": { en: "Page {path}", pt: "Página {path}" },
  "src.resource": { en: "Resource {path}", pt: "Recurso {path}" },
  "src.recheck": { en: "Re-check {path}", pt: "Re-checagem {path}" },
  "src.deep": { en: "Deep check {path}", pt: "Checagem profunda {path}" },
  "src.content": { en: "Page content", pt: "Conteúdo da página" },
  "src.headerNoVersion": { en: "Header without a PHP version", pt: "Cabeçalho sem versão do PHP" },
  "src.versionRead": { en: "Version read: {v}", pt: "Versão lida: {v}" },

  // ---------- Popup ----------
  "ui.site": { en: "Site", pt: "Site" },
  "ui.history": { en: "History", pt: "Histórico" },
  "ui.loading": { en: "Loading…", pt: "Carregando…" },
  "ui.noData": { en: "NO DATA", pt: "SEM DADOS" },
  "ui.noData.title": { en: "The extension has not seen this page load yet.", pt: "A extensão ainda não viu esta página carregar." },
  "ui.noData.detail": { en: "Reload the page (F5) or click Re-check.", pt: "Recarregue a página (F5) ou clique em Re-checar." },
  "ui.evidence": { en: "Evidence", pt: "Evidências" },
  "ui.sapi": { en: "Server setup (SAPI)", pt: "Configuração do servidor (SAPI)" },
  "ui.todo": { en: "What to do", pt: "O que fazer" },
  "ui.others": { en: "Other hosts loaded by the page", pt: "Outros hosts carregados pela página" },
  "ui.lookups": { en: "Look up without touching the site", pt: "Consultar sem tocar no site" },
  "ui.recheck": { en: "Re-check", pt: "Re-checar" },
  "ui.recheck.tip": {
    en: "Sends a plain GET to / and /index.php, without cookies or payload",
    pt: "Envia GET comum para / e /index.php, sem cookies e sem payload",
  },
  "ui.deep": { en: "Deep check", pt: "Checagem profunda" },
  "ui.deep.confirm": { en: "Confirm deep check", pt: "Confirmar checagem" },
  "ui.deep.warn": {
    en: "Sends ~15 GETs to known paths (phpinfo, FPM status, server-status, missing .php, easter egg). No exploit, but it can show up in the WAF. Only on authorized assets. Click again to confirm.",
    pt: "Envia ~15 GETs a caminhos conhecidos (phpinfo, status do FPM, server-status, .php inexistente, easter egg). Sem exploit, mas pode aparecer no WAF. Só em ativos autorizados. Clique de novo para confirmar.",
  },
  "ui.deep.running": { en: "Running deep check…", pt: "Executando checagem profunda…" },
  "ui.deep.done": { en: "Deep check: {n} finding(s) in {m} requests.", pt: "Checagem profunda: {n} achado(s) em {m} requisições." },
  "ui.copy": { en: "Copy report", pt: "Copiar relatório" },
  "ui.copied": { en: "Report copied.", pt: "Relatório copiado." },
  "ui.nothingToCopy": { en: "Nothing to copy yet.", pt: "Nada para copiar ainda." },
  "ui.sending": { en: "Sending GET to / and /index.php…", pt: "Enviando GET para / e /index.php…" },
  "ui.export": { en: "Export CSV", pt: "Exportar CSV" },
  "ui.clear": { en: "Clear", pt: "Limpar" },
  "ui.host": { en: "Host", pt: "Host" },
  "ui.version": { en: "Version", pt: "Versão" },
  "ui.status": { en: "Status", pt: "Status" },
  "ui.historyEmpty": { en: "No host with PHP seen yet.", pt: "Nenhum host com PHP visto ainda." },
  "ui.footer": {
    en: "Passive check. Only the version and package installed on the server are conclusive.",
    pt: "Verificação passiva. Só a versão e o pacote instalados no servidor são conclusivos.",
  },
  "ui.rules": { en: "Rules from {d}.", pt: "Regras de {d}." },
  "ui.ioc.title": { en: "PHP2Shell attack infrastructure", pt: "Infraestrutura de ataque do PHP2Shell" },
  "ui.ioc.detail": {
    en: "Do not interact with the host: record the evidence and forward it to CTI/blocking.",
    pt: "Não interaja com o host: registre a evidência e encaminhe para CTI/bloqueio.",
  },
  "ui.stale.title": { en: "The extension was updated", pt: "A extensão foi atualizada" },
  "ui.stale.detail": {
    en: "Chrome is still running the previous version in the background, so results can be outdated or mixed. Reload the extension, then reload the page.",
    pt: "O Chrome ainda roda a versão anterior em segundo plano, então os resultados podem estar desatualizados ou misturados. Recarregue a extensão e depois a página.",
  },
  "ui.stale.button": { en: "Reload extension", pt: "Recarregar extensão" },
  "ui.source": { en: "Source code", pt: "Código-fonte" },
  "ui.invalidUrl": { en: "Invalid URL", pt: "URL inválida" },
  "ui.httpOnly": { en: "Only http/https pages", pt: "Somente páginas http/https" },
  "ui.badgeIoc": { en: "PHP2Shell: known attack infrastructure", pt: "PHP2Shell: infraestrutura de ataque conhecida" },

  // ---------- Relatório ----------
  "r.title": { en: "PHP2Shell (CVE-2026-109618 / CVE-2026-109619) - passive check", pt: "PHP2Shell (CVE-2026-109618 / CVE-2026-109619) - verificação passiva" },
  "r.date": { en: "Date", pt: "Data" },
  "r.announced": { en: "Announced version", pt: "Versão anunciada" },
  "r.analysis": { en: "Analysis", pt: "Análise" },
  "r.evidence": { en: "Evidence", pt: "Evidências" },
  "r.actions": { en: "Actions", pt: "Ações" },
  "r.note": {
    en: "Note: passive check from headers and content. Distribution backports do not change the upstream number; the definitive confirmation is the version and package installed on the server.",
    pt: "Observação: verificação passiva por cabeçalhos e conteúdo. Backport de distribuição não muda o número upstream; a confirmação definitiva é a versão e o pacote instalados no servidor.",
  },
};

export function detectLang(uiLang) {
  return /^pt/i.test(uiLang || "") ? "pt" : "en";
}

export function t(lang, key, params = {}) {
  const entry = M[key];
  if (!entry) return key;
  return (entry[lang] || entry.en).replace(/\{(\w+)\}/g, (_, name) => {
    const v = params[name];
    return v == null ? "" : typeof v === "object" && v.k ? t(lang, v.k, v.p) : String(v);
  });
}

// Renderiza texto que pode ser string pura, uma mensagem { k, p } ou uma lista delas.
export function render(lang, x) {
  if (x == null) return "";
  if (typeof x === "string") return x;
  if (Array.isArray(x)) return x.map((y) => render(lang, y)).filter(Boolean).join(" ");
  return t(lang, x.k, x.p);
}

export const msg = (k, p) => (p ? { k, p } : { k });
