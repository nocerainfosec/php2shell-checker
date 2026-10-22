// Content script: lê apenas o DOM já carregado em busca de indícios de PHP. Não faz requisições.
// Os textos vão como chaves de mensagem { k, p } e são traduzidos no popup (lib/i18n.js).
(() => {
  const indicators = [];
  const add = (kind, value) => indicators.push({ kind, value });
  const msg = (k, p) => (p ? { k, p } : { k });
  const isListing = /^(Index of |Directory listing for )/i.test(document.title);

  // Página phpinfo() exposta: o background extrai versão, SAPI e diretivas do HTML.
  let phpinfoHtml = null;
  const h1 = document.querySelector("h1.p");
  if (/phpinfo\(\)/i.test(document.title) || (h1 && /PHP Version/i.test(h1.textContent))) {
    phpinfoHtml = document.documentElement.outerHTML.slice(0, 400000);
  }

  // Meta generator de CMS em PHP.
  const generator = document.querySelector('meta[name="generator" i]');
  if (generator) {
    const g = generator.content || "";
    if (/wordpress|drupal|joomla|typo3|magento|prestashop|opencart|moodle|mediawiki|concrete|craft cms|october|grav|processwire|roadiz|spip|limesurvey|vbulletin|vbadvanced|discuz|matomo|piwik|dokuwiki|phpbb|xenforo|modx|silverstripe|pimcore|shopware|codecharge/i.test(g)) {
      add("dom", msg("ind.generator", { v: g.slice(0, 80) }));
    } else if (/elementor|all in one seo|aioseo|wpbakery|layerslider|slider revolution|site kit by google|wpml|yoast|woocommerce/i.test(g)) {
      // Plugins do WordPress também se anunciam no generator.
      add("dom", msg("ind.generator", { v: `WordPress plugin: ${g.slice(0, 60)}` }));
    }
  }

  // Caminhos típicos de CMS/frameworks PHP em recursos da própria página.
  const html = document.documentElement.innerHTML.slice(0, 500000);
  const PATHS = [
    [/\/wp-(content|includes)\//i, "WordPress (wp-content/wp-includes)"],
    [/\/sites\/(default|all)\/(files|modules|themes)\//i, "Drupal (sites/default)"],
    [/\/media\/(jui|system)\/|\/components\/com_/i, "Joomla"],
    [/\/static\/version\d+\/|\/skin\/frontend\//i, "Magento"],
    [/\/typo3(conf|temp)\//i, "TYPO3"],
    [/\/catalog\/view\/theme\//i, "OpenCart"],
    [/\/bundles\/[a-z]+\//i, "Symfony (bundles)"],
    [/\/vendor\/livewire\/|livewire\.js/i, "Laravel Livewire"],
  ];
  if (!isListing) for (const [re, label] of PATHS) if (re.test(html)) add("dom", label);

  // Links e formulários para scripts .php no mesmo host.
  let phpLinks = 0;
  let sample = "";
  for (const el of document.querySelectorAll("a[href], form[action], script[src], link[href], iframe[src]")) {
    const raw = el.getAttribute("href") || el.getAttribute("action") || el.getAttribute("src");
    if (!raw) continue;
    let u;
    try {
      u = new URL(raw, location.href);
    } catch {
      continue;
    }
    if (u.hostname === location.hostname && /\.php\d?$/i.test(u.pathname)) {
      phpLinks++;
      if (!sample) sample = u.pathname;
    }
  }
  // Em listagem de diretório, um .php listado é só um arquivo, não PHP em execução.
  if (phpLinks && !isListing) add("dom", msg("ind.phpLinks", { n: phpLinks, sample: sample.slice(0, 60) }));

  // Cookies acessíveis ao JavaScript (os HttpOnly vêm pelos cabeçalhos).
  for (const c of document.cookie.split(";")) {
    const name = c.split("=")[0].trim();
    if (/^(PHPSESSID|laravel_session|ci_session|CAKEPHP)$/i.test(name)) {
      add("cookie", msg("ind.cookie", { name, label: "document.cookie" }));
    }
  }

  // Mensagens de erro do PHP renderizadas na página (vazam caminho e às vezes versão).
  const body = (document.body && document.body.innerText.slice(0, 200000)) || "";
  if (/(Fatal error|Warning|Parse error|Notice|Deprecated):\s.+? in \S+ on line \d+/i.test(body)) {
    add("alert", msg("ind.phpError"));
  }

  // Listagem de diretório aberto (Apache/nginx autoindex, python http.server): envia os nomes
  // para o background comparar com os arquivos dos toolkits do PHP2Shell.
  let listing = [];
  if (isListing) {
    listing = [...document.querySelectorAll("a[href]")]
      .map((a) => {
        const href = (a.getAttribute("href") || "").split(/[?#]/)[0].replace(/\/$/, "");
        const name = href.split("/").pop();
        try {
          return decodeURIComponent(name);
        } catch {
          return name;
        }
      })
      .filter(Boolean)
      .slice(0, 2000);
  }

  // Painel de stack de desenvolvimento (WampServer, Laragon, XAMPP, MAMP): o background lê as versões do texto.
  let dashboard = null;
  if (/WAMPSERVER|Laragon|XAMPP|\bMAMP\b/i.test(document.title) && document.body) {
    dashboard = { title: document.title, text: document.body.innerText.slice(0, 50000) };
  }

  // Assinatura do Apache (<address>) em páginas de erro e listagens, que pode trazer "PHP/x.y.z".
  const signatures = [...document.querySelectorAll("address")]
    .map((a) => a.textContent)
    .filter((s) => /PHP\/\d/i.test(s))
    .slice(0, 5);

  if (indicators.length || listing.length || phpinfoHtml || signatures.length || dashboard) {
    chrome.runtime.sendMessage({ type: "hints", indicators, listing, phpinfoHtml, signatures, dashboard }).catch(() => {});
  }
})();
