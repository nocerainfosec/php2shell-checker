# Changelog

All notable changes to PHP2Shell Version Checker. Dates are ISO (YYYY-MM-DD).

## 1.4.0 — 2026-10-23

New detection techniques for **hardened hosts that hide the version** (`expose_php=Off`, stripped
`Server`, WAF in front) — the case where 1.3.0 could only say "PHP, no version". Everything added is
passive or an opt-in GET, with no exploit traffic, consistent with the existing design.

### Added

- **Session-ID format fingerprint (passive).** The native `PHPSESSID` value is a direct function of
  PHP's session INI. PHP ≤ 7.0 built the ID from `session.hash_function` +
  `session.hash_bits_per_character`; both directives were **removed in PHP 7.1**. So a 26-char `0-9a-v`
  ID (and the other legacy length/alphabet pairs) is strong evidence of **PHP ≤ 7.0**, even when no
  version is announced. The badge now shows an inferred `≤7.0` ceiling in EOL red instead of a grey
  "no version". *Why it matters:* on legacy hosts that is the difference between "unknown" and
  "unsupported, act now" — the extension's core mission. Clearly marked as inferred, not proof
  (a ≥ 7.1 host deliberately tuned to the old format could mimic it).
- **Session cache-limiter header signature (passive).** PHP emits
  `Expires: Thu, 19 Nov 1981 08:52:00 GMT` + `Cache-Control: no-store, no-cache, must-revalidate` +
  `Pragma: no-cache` on every session-starting response (the date is hardcoded in php-src). This now
  proves PHP is behind the response even when `X-Powered-By` is gone **and** the session cookie was
  renamed.
- **php-cgi argument banners in Deep check (opt-in).** `/index.php?-v`, `?-s`, `?-i`
  (the CVE-2012-1823 detection class). On modern mod_php/FPM the app just answers normally — zero noise.
  On an old `php-cgi` SAPI, `?-v` returns the **exact version** and `?-s` dumping PHP source raises a
  **source-disclosure** finding. These are detection probes only; the dangerous `-d`/`auto_prepend_file`
  variants are deliberately **not** sent.
- **phpinfo() under the front-controller prefix (opt-in).** Apps served from a subdirectory (e.g.
  `/saude/`) bury `phpinfo` one level down; Deep check now also probes the known paths under the first
  path segment of the current URL, not just the web root.
- **PHP Credits easter egg (opt-in).** Complements the existing logo probe to catch PHP < 5.5 whose
  logo GUID is disabled but whose credits page still renders.
- **WAF / deny-list oracle (opt-in).** A name WAFs commonly block (`composer.json` → 403) versus a random
  name (→ 404) reveals a deny-list in front — which also **explains why deep checks come back empty** on
  hardened hosts.
- **Wayback one-click lookup.** A new link opens `web.archive.org` for the host, to recover historical
  `X-Powered-By` from when `expose_php` was still on. Like the other lookups, it just opens the service
  in a new tab — nothing is sent automatically.

### Changed

- Rules date bumped to `2026-10-23`; `CODE_VERSION` to `1.4.0`.
- Deep check now sends ~25 GETs (was ~15); the confirmation warning lists the new probe groups.

### Notes

All new logic ships with unit tests (`node --test tests/*.test.mjs`, now 20 suites) and was re-run
against the 10,000-record Shodan QA sample with 0 crashes and no regression (98.4% version read,
99.9% CPE agreement on hosts Shodan also versioned).

## 1.3.0 — 2026-10-22

- New detection signals learned from a 10,000-record Shodan sample: Apache `<address>` signature,
  Laravel `XSRF-TOKEN` + `*_session`, Nextcloud/Cacti/OpenEMR/Kimai cookies, `X-PHP-PID` /
  `X-PHP-Response-Code`, PHP DebugBar header, CMS generators, exposed dev dashboards
  (WampServer/Laragon/XAMPP/MAMP), `X-Powered-By: php` with no version, FrankenPHP.
- Fixes from QA: Dotdeb no longer misread as Debian; custom `php2shell-fix` builds get their own verdict;
  stale dashboard versions no longer override headers.
- Stale service-worker detection (`CODE_VERSION`) with a reload banner; old history entries migrated.
- English/Portuguese interface; website and GitHub links.

## 1.0.0 — 2026-10-22

- Initial release: passive PHP version detection, PHP2Shell (CVE-2026-109618 / CVE-2026-109619) verdict,
  distro/vendor backport rules, SAPI inference, phpinfo parsing, opt-in deep check, Hunt.io IOCs,
  per-host history and CSV export.
