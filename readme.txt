=== SudoWP Radar ===
Contributors: sudowp, thewebcitizen
Tags: security, abilities-api, audit, scanner, permissions
Requires at least: 6.9
Tested up to: 6.9
Requires PHP: 8.1
Stable tag: 1.2.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Security auditor for the WordPress Abilities API. Scans registered abilities for permission, schema, and exposure risks.

== Description ==

SudoWP Radar is a runtime security auditor for the WordPress 6.9 Abilities API. It scans every registered ability across all active plugins and themes, applying a rule engine that detects the vulnerability patterns most likely to be exploited in production.

**What it audits:**

* **Open and weak permissions** -- abilities with no permission_callback, or one that allows any authenticated user through.
* **Missing or loose input schemas** -- abilities that accept unconstrained string inputs, creating potential injection vectors for path traversal, SSRF, and similar attacks.
* **REST overexposure** -- abilities marked show_in_rest with no or open permission control, accessible to unauthenticated callers.
* **MCP overexposure** -- abilities marked meta.mcp.public = true with a weak or null permission callback are directly callable by any connected AI agent. Flagged as CRITICAL.
* **Orphaned callbacks** -- execute_callbacks that reference functions no longer loaded, often left behind by deactivated plugins.
* **Namespace collisions** -- duplicate ability names where the last registration silently overwrites the first, potentially downgrading the permission model.
* **AI prompt filter bypass** (WP 7.0+) -- callbacks on wp_ai_client_prevent_prompt that unconditionally return false, disabling the AI prompt prevention gate sitewide. Flagged as HIGH.
* **AI REST overexposure** (WP 7.0+) -- REST endpoints that call wp_ai_client_prompt() with no or weak permission callbacks. Flagged as CRITICAL or HIGH.
* **AI missing version gate** (WP 7.0+) -- plugins that call wp_ai_client_prompt() without a function_exists compatibility check, causing fatal errors on WP < 7.0. Flagged as MEDIUM.

**How it works:**

SudoWP Radar reads the live abilities registry after all plugins and themes have loaded. It applies static rules to each ability and returns a structured findings report with severity ratings (Critical, High, Medium, Low) and actionable remediation guidance. A risk score from 0-100 summarises the overall exposure of the site.

**Security model:**

* Requires the `radar_run_audit` capability (granted to site administrators by default).
* All audit requests are nonce-gated. No public-facing endpoints.
* Audit findings are stored in user meta, not global options.
* Rate-limited to one audit per 30 seconds per user.

**Optional premium extension (SudoWP Pro):**

The free plugin is a fully functional standalone security auditor. An optional premium add-on extends it with SudoWP Vulnerability Dataset matching (CVE references, CVSS scores, patch guidance), scheduled audits with email alerts, multi-site dashboard aggregation, and report export. None of these are required to use the core auditing features.

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

SudoWP Radar registers a `sudowp-radar/audit` ability via the WP Abilities API, allowing MCP-connected AI agents to trigger audits programmatically. REST exposure is disabled by default.

= What PHP version is required? =

PHP 8.1 or higher. The plugin uses constructor property promotion, readonly properties, and named arguments.

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

= 1.2.0 =
Adds optional SudoWP vulnerability dataset integration with API key settings field. Core audit is fully functional without a key.

= 1.1.0 =
Adds AI agent summary block, remediation hints on all findings, rate limiting on ability callback, and three new WP 7.0 AI Client surface rules.

= 1.0.0 =
Initial release.

== Premium Extension Filters ==

SudoWP Radar exposes four WordPress filters so a premium plugin can extend
the audit engine without modifying core plugin files.

= radar_dataset_enabled =

Controls whether dataset lookups run during an audit. Return true to activate.

  Parameters:
    $enabled (bool) -- default false.
  Returns:
    bool

  Example:

    add_filter( 'radar_dataset_enabled', function ( bool $enabled ): bool {
        return true; // Enable dataset lookups.
    } );

= radar_dataset_findings =

Inject Finding objects from a vulnerability dataset for a specific ability.
Called once per ability during an audit. Non-Finding return values are stripped.

  Parameters:
    $findings (array)  -- current Finding[] for this ability, default [].
    $ability  (array)  -- ability data array from Scanner (name, meta, callbacks, etc.).
  Returns:
    Finding[]

  Note: register with accepted_args=2 to receive both parameters.

  Example:

    add_filter(
        'radar_dataset_findings',
        function ( array $findings, array $ability ): array {
            if ( str_starts_with( $ability['name'], 'my-plugin/' ) ) {
                $findings[] = new \SudoWP\Radar\Finding(
                    ability_name:   $ability['name'],
                    severity:       \SudoWP\Radar\Finding::SEVERITY_CRITICAL,
                    vuln_class:     \SudoWP\Radar\Finding::VULN_DATASET_MATCH,
                    message:        'Known vulnerable ability pattern detected (CVE-2026-1234).',
                    recommendation: 'Update my-plugin to version 2.1.0 or later.',
                    is_premium:     true,
                );
            }
            return $findings;
        },
        10,
        2
    );

= radar_dataset_status =

Override the dataset status array displayed in the admin UI.

  Parameters:
    $status (array) -- default status with keys:
      enabled       (bool)        -- false in free version.
      label         (string)      -- UI display string.
      last_updated  (string|null) -- ISO 8601 date or null.
      total_entries (int)         -- 0 in free version.
  Returns:
    array (same shape as input)

  Example:

    add_filter( 'radar_dataset_status', function ( array $status ): array {
        return [
            'enabled'       => true,
            'label'         => 'SudoWP Vulnerability Dataset: Connected. 4,821 entries.',
            'last_updated'  => '2026-03-08',
            'total_entries' => 4821,
        ];
    } );

= radar_audit_findings =

Modify the complete findings array after all rules and dataset lookups have run.
Use this to add cross-ability findings, re-score existing findings, or suppress
false positives. Called once per full audit run.

  Parameters:
    $findings  (array) -- complete Finding[] from the full audit.
    $abilities (array) -- all ability data arrays scanned during this audit.
  Returns:
    Finding[]

  Note: register with accepted_args=2 to receive both parameters.

  Example:

    add_filter(
        'radar_audit_findings',
        function ( array $findings, array $abilities ): array {
            // Example: promote medium findings to high for a high-risk site.
            return array_map( function ( $finding ) {
                if ( $finding->severity === \SudoWP\Radar\Finding::SEVERITY_MEDIUM ) {
                    return new \SudoWP\Radar\Finding(
                        ability_name:   $finding->ability_name,
                        severity:       \SudoWP\Radar\Finding::SEVERITY_HIGH,
                        vuln_class:     $finding->vuln_class,
                        message:        $finding->message,
                        recommendation: $finding->recommendation,
                        context:        $finding->context,
                        is_premium:     $finding->is_premium,
                    );
                }
                return $finding;
            }, $findings );
        },
        10,
        2
    );
