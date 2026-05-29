=== SudoWP Radar ===
Contributors: sudowp, thewebcitizen
Tags: security, abilities-api, audit, scanner, permissions
Requires at least: 6.9
Tested up to: 7.0
Requires PHP: 8.1
Stable tag: 1.3.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Security auditor for the WordPress Abilities API. Scans registered abilities for permission, schema, and exposure risks.

== Description ==

WordPress 7.0 introduced a new AI attack surface. Every plugin that registers
an ability on your site declares a structured entry point for AI agents and MCP
tools. SudoWP Radar audits that surface at runtime, flagging misconfigurations
before they become incidents.

It sits between reactive CVE scanners (which wait for a vulnerability to be
disclosed) and developer-side static analysis tools (which run before deployment).
Radar audits what is actually registered and executing on your live site, right now.

= What it audits =

**Core ability rules (WP 6.9+)**

* Open and weak permissions -- abilities with no permission_callback, or one that
  passes any authenticated user through regardless of role.
* Missing or loose input schemas -- abilities that accept unconstrained string
  inputs on fields like path, file, url, redirect, or slug. Common injection
  vector for path traversal and SSRF.
* REST overexposure -- abilities marked show_in_rest with no or open permission
  control, reachable by unauthenticated callers.
* Orphaned callbacks -- execute_callbacks referencing functions no longer loaded,
  typically left behind by deactivated plugins.
* Namespace collisions -- duplicate ability names where the last registration
  silently overwrites the first, potentially downgrading the permission model.

**AI agent rules (WP 7.0+)**

* AI prompt filter bypass (HIGH) -- a plugin has disabled the sitewide AI prompt
  prevention gate. Any AI agent connected to your site bypasses this control.
* AI REST overexposure (CRITICAL/HIGH) -- REST endpoints that invoke the AI client
  with no or weak permission checks. Directly exploitable by unauthenticated callers.
* AI missing version gate (MEDIUM) -- plugins calling the WP 7.0 AI client without
  a compatibility check, causing fatal errors on sites not yet running 7.0.
* Hosting-injected ability (HIGH) -- an ability registered by a plugin auto-installed
  by your hosting provider, without explicit site administrator consent, with REST
  exposure enabled. Requires premium vendor slug list via the SudoWP dataset.
* Connector key in database (HIGH) -- an AI provider API key (OpenAI, Anthropic,
  Google, or similar) is stored as plaintext in your WordPress database via the
  WP 7.0 Connectors API. Any SQL injection or object cache exposure on your site
  leaks this key directly. The fix is to define it as an environment variable or
  PHP constant instead.

= Why this matters now =

WordPress 7.0 ships with native AI agent integration. Plugins can now register
abilities that AI agents call directly, expose AI endpoints over REST, and connect
to external AI providers via the Connectors API. Each of these is a new attack
surface that existing security scanners do not cover -- they match known CVEs,
they do not audit AI agent architecture.

Some hosting providers have begun auto-installing AI agent plugins on customer
sites without explicit consent. If one of those plugins registers abilities with
REST exposure, or stores an AI provider key in your database, Radar flags it.

= How it works =

Radar reads the live abilities registry after all plugins and themes have loaded.
It applies its rule engine to each registered ability and returns a findings report
with severity ratings (CRITICAL, HIGH, MEDIUM, LOW) and specific remediation
guidance per finding. A risk score from 0-100 summarises the overall exposure.

The audit runs on demand. It does not affect front-end performance.

= Security model =

* Requires the radar_run_audit capability (administrators by default).
* All requests are nonce-gated. No public-facing endpoints.
* Findings are stored in user meta, not global options.
* Rate-limited to one audit per 30 seconds per user.

= Free vs premium =

The free plugin is a fully functional standalone auditor. An optional premium
add-on (SudoWP Pro) extends it with vulnerability dataset matching (CVE references,
CVSS scores, patch guidance), the hosting-injected vendor slug list, scheduled
audits with email alerts, multi-site dashboard aggregation, and report export.

None of the premium features are required to run the core audit.

== Installation ==

1. Upload the `sudowp-radar` directory to `/wp-content/plugins/`.
2. Activate the plugin through the Plugins screen in WordPress.
3. Navigate to Radar in the admin menu.
4. Click "Run Audit" to scan your site's registered abilities.

WordPress 6.9 or higher is required. The plugin will display an admin notice and deactivate gracefully on older versions.

== FAQ ==

= Do I need WordPress 7.0 to use this plugin? =

No. The core audit rules work on WordPress 6.9 and higher. The five AI agent rules
(AI prompt filter bypass, AI REST overexposure, AI missing version gate,
hosting-injected ability, connector key in database) are silently skipped on sites
running below 7.0 -- no errors, no noise. If you are running 7.0, those rules
activate automatically.

= What is the WordPress Abilities API? =

The Abilities API, introduced in WordPress 6.9, is the layer that allows AI agents
and MCP tools to interact with your site programmatically. Plugins register named
abilities with permission callbacks and input schemas. When an AI agent connects
to your site, it can call these abilities directly. A misconfigured ability is a
direct entry point -- not a theoretical risk.

= A plugin was auto-installed on my site by my hosting provider. Should I be concerned? =

Possibly. Some hosting providers auto-install AI agent plugins on customer sites
without explicit consent. If that plugin registers abilities with REST exposure, or
stores an AI provider key in your database, it expands your AI attack surface
without your knowledge. Run a Radar audit to check. The hosting-injected ability
rule (premium) and connector key in database rule (free) are designed to catch
exactly this scenario.

= What does the "Connector key in database" finding mean? =

WordPress 7.0 introduces a Connectors API that lets plugins register AI provider
integrations (OpenAI, Anthropic, Google, and others). If the API key for one of
these connectors was entered through the WordPress admin UI rather than defined as
an environment variable or PHP constant, it is stored as plaintext in your database.
Any SQL injection vulnerability or object cache exposure on your site would expose
that key directly. The finding tells you which connector is affected and how to
move the key to a safer location.

= What does a "Critical" finding mean? =

A Critical finding is an ability or endpoint that any user -- in some cases an
unauthenticated visitor -- can call directly. This is the highest severity level
and should be addressed before anything else.

= Does this plugin modify my site? =

No. Radar is a read-only auditor. It reads the Abilities registry and reports
findings. It does not modify any registered abilities, alter plugin settings, or
write to the database other than storing the last audit report in your own user meta.

= Will this slow down my site? =

No. The audit runs on demand only, triggered by clicking Run Audit in the admin.
It does not run automatically and has no effect on front-end performance.

= Is there a REST API? =

Radar registers a sudowp-radar/audit ability via the WP Abilities API, allowing
MCP-connected AI agents to trigger audits programmatically. REST exposure is
disabled by default -- the ability is only reachable by MCP agents with the
appropriate permission, not by unauthenticated REST callers.

= What PHP version is required? =

PHP 8.1 or higher.

== External Services ==

When an API key is configured, SudoWP Radar connects to the SudoWP vulnerability
dataset API (api.sudowp.com) to retrieve patch availability information for
registered WordPress abilities.

No data is transmitted without an API key being explicitly entered by the site
administrator. When no key is present, the plugin makes zero external network
requests.

Data sent to the API: the ability name being looked up and your API key.
No personal data, no site URL, no user data is transmitted.

API key registration: https://sudowp.com/get-api-key/
Terms of service: https://sudowp.com/tos/
Privacy policy: https://sudowp.com/privacy-policy/

== Changelog ==

= 1.3.0 =
* Added HOSTING_INJECTED_ABILITY rule (HIGH): detects abilities registered by hosting-injected plugins with REST exposure, without explicit admin consent
* Added CONNECTOR_KEY_IN_DB rule (HIGH): detects AI connector API keys stored as plaintext in the WordPress database via the WP 7.0 Connectors API
* New premium filter radar_hosting_vendor_slugs for dataset-delivered vendor list
* Tested up to WordPress 7.0

= 1.2.0 =
* Added optional SudoWP vulnerability dataset integration
* Dataset lookup adds patch availability and remediation links to matching audit findings
* API key settings field added to Radar Settings -- dataset is disabled when no key is present
* Free tier: 100 lookups per day. Paid tier: unlimited.
* Key registration: https://sudowp.com/get-api-key/
* All plugin code remains fully open source -- the dataset is an external service
* Added External Services disclosure per WordPress.org guidelines

= 1.1.0 =
* Feature: Summary block added to sudowp-radar/audit ability response for AI agents (total_findings, by_severity, highest_severity, audit_timestamp, abilities_scanned, recommended_action).
* Feature: Remediation hints added to all Finding objects with actionable one-line guidance.
* Feature: AI prompt filter bypass rule (HIGH) -- detects wp_ai_client_prevent_prompt callbacks that unconditionally return false. WP 7.0+ only.
* Feature: AI REST overexposure rule (CRITICAL/HIGH) -- detects REST endpoints calling wp_ai_client_prompt() with weak or missing permission checks. WP 7.0+ only.
* Feature: AI missing version gate rule (MEDIUM) -- detects plugins calling wp_ai_client_prompt() without a function_exists guard. WP 7.0+ only.
* Security: Rate limiting added to ability execute callback (30-second cooldown per user).
* Note: All WP 7.0 rules are silently skipped on WP 6.9 sites -- zero noise, zero errors.

= 1.0.1 =
* Security: Added filter output validation to ensure only Finding instances are processed.
* Hardening: Prefixed all constants from RADAR_* to SUDOWP_RADAR_* to prevent namespace collisions.

= 1.0.0 =
* Initial release.
* Scans abilities for open/weak permissions, missing input schemas, REST overexposure, MCP overexposure, orphaned callbacks, and namespace collisions.
* Admin page with Run Audit button and severity-sorted findings list.
* Risk score from 0-100.
* Premium dataset stub with four extension filters.
* Registers `sudowp-radar/audit` ability for MCP agent access.

== Upgrade Notice ==

= 1.3.0 =
Adds two new WP 7.0 security rules: HOSTING_INJECTED_ABILITY (HIGH) and CONNECTOR_KEY_IN_DB (HIGH). Both rules are silently skipped on WP < 7.0.

= 1.2.0 =
Adds optional SudoWP vulnerability dataset integration with API key settings field. Core audit is fully functional without a key.

= 1.1.0 =
Adds AI agent summary block, remediation hints on all findings, rate limiting on ability callback, and three new WP 7.0 AI Client surface rules.

= 1.0.0 =
Initial release.
