=== SudoWP Radar ===
Contributors: sudowp
Tags: security, abilities-api, audit, scanner, permissions
Requires at least: 6.9
Tested up to: 6.9
Requires PHP: 8.1
Stable tag: 1.0.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Security auditor for the WordPress 6.9+ Abilities API. Scans every registered ability for permission misconfigurations, input schema gaps, REST exposure risks, and namespace collisions.

== Description ==

SudoWP Radar is a runtime security auditor for the WordPress 6.9 Abilities API. It scans every registered ability across all active plugins and themes, applying a rule engine that detects the vulnerability patterns most likely to be exploited in production.

**What it audits:**

* **Open and weak permissions** -- abilities with no permission_callback, or one that allows any authenticated user through.
* **Missing or loose input schemas** -- abilities that accept unconstrained string inputs, creating potential injection vectors for path traversal, SSRF, and similar attacks.
* **REST overexposure** -- abilities marked show_in_rest with no or open permission control, accessible to unauthenticated callers.
* **Orphaned callbacks** -- execute_callbacks that reference functions no longer loaded, often left behind by deactivated plugins.
* **Namespace collisions** -- duplicate ability names where the last registration silently overwrites the first, potentially downgrading the permission model.

**How it works:**

SudoWP Radar reads the live WP_Abilities_Registry after all plugins and themes have loaded. It applies static rules to each ability and returns a structured findings report with severity ratings (Critical, High, Medium, Low) and actionable remediation guidance. A risk score from 0-100 summarises the overall exposure of the site.

**Security model:**

* Requires the `radar_run_audit` capability (granted to site administrators by default).
* All audit requests are nonce-gated. No public-facing endpoints.
* Audit findings are stored in user meta, not global options.
* Rate-limited to one audit per 30 seconds per user.

**Premium features (via SudoWP Pro):**

* SudoWP Vulnerability Dataset matching -- cross-references registered abilities against a curated database of known-vulnerable ability patterns, with CVE references, CVSS scores, and patch guidance.
* Scheduled audits with email alerts.
* Multi-site dashboard aggregation.
* PDF and CSV report export.

SudoWP Radar is a complement to static analysis tools. It audits the live, runtime state of your site -- what is actually registered and executing -- not just what is declared in code.

== Installation ==

1. Upload the `sudowp-radar` directory to `/wp-content/plugins/`.
2. Activate the plugin through the Plugins screen in WordPress.
3. Navigate to Radar in the admin menu.
4. Click "Run Audit" to scan your site's registered abilities.

WordPress 6.9 or higher is required. The plugin will display an admin notice and deactivate gracefully on older versions.

== Frequently Asked Questions ==

= Does this plugin modify my site? =

No. SudoWP Radar is a read-only auditor. It reads the Abilities registry and reports findings. It does not modify any registered abilities, alter plugin settings, or write to the database (other than storing the last audit report in your own user meta).

= What does a "Critical" finding mean? =

Critical findings are abilities that any authenticated (or in some cases unauthenticated) user can execute. These represent the highest risk and should be addressed before lower severity findings.

= Will this slow down my site? =

The audit runs on demand only, triggered by clicking the "Run Audit" button on the admin page. It does not run automatically and has no effect on front-end performance.

= Is there a REST API? =

SudoWP Radar registers a `sudowp-radar/audit` ability via the WP Abilities API, allowing MCP-connected AI agents to trigger audits programmatically. REST exposure is disabled by default (`show_in_rest: false`).

= What PHP version is required? =

PHP 8.1 or higher. The plugin uses constructor property promotion, readonly properties, and named arguments.

== Changelog ==

= 1.0.0 =
* Initial release.
* Scans abilities for open/weak permissions, missing input schemas, REST overexposure, orphaned callbacks, and namespace collisions.
* Admin page with Run Audit button and severity-sorted findings list.
* Risk score from 0-100.
* Premium dataset stub with four extension filters.
* Registers `sudowp-radar/audit` ability for MCP agent access.

== Upgrade Notice ==

= 1.0.0 =
Initial release.
