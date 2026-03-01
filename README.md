# SudoWP Radar

A WordPress security scanner built for the **WordPress 6.9 Abilities API**.

Every plugin that registers abilities on a WP 6.9+ site declares a structured attack surface. SudoWP Radar audits that surface at runtime, flagging misconfigurations before they become CVEs.

---

## What It Does

WordPress 6.9 introduced the Abilities API -- a standardized registry that lets plugins, themes, and AI agents expose discrete units of functionality with defined inputs, outputs, and permission checks. It is the foundation of WordPress MCP integration.

Every registered ability is a potential entry point. SudoWP Radar inspects each one at runtime and reports:

- Abilities with no permission check or a weak one (`__return_true`, `read`, `exist`)
- Abilities exposed to the REST API or MCP without adequate access control
- Input schemas that accept unconstrained strings on sensitive fields (`path`, `file`, `url`, `redirect`, `source`, `target`, `slug`)
- Duplicate ability registrations that could silently downgrade permissions

Results are displayed in the WordPress admin with a severity-sorted findings list and a 0-100 risk score.

---

## Why It Exists

Wordfence and Patchstack are reactive -- they match against known CVEs. Neither audits the Abilities API because it is new and because their approach requires a known vulnerability to match against.

SudoWP Radar is proactive. It audits the architecture of what is registered on your site right now, before a CVE exists.

[Abilities Scout](https://github.com/laxmariappan/abilities-scout) by Lax Mariappan covers pre-registration static analysis for developers. SudoWP Radar covers post-registration runtime auditing for site owners, agencies, and security consultants. The two tools complement each other.

---

## Requirements

- WordPress 6.9 or higher
- PHP 8.1 or higher
- No other dependencies

---

## Installation

1. Download the plugin ZIP from the [releases page](https://github.com/Sudo-WP/sudowp-radar/releases).
2. In your WordPress admin, go to Plugins > Add New > Upload Plugin.
3. Upload the ZIP and activate.
4. Navigate to **Radar** in the admin menu.
5. Click **Run Audit**.

---

## Vulnerability Rules

| Rule | Severity | Description |
|------|----------|-------------|
| Open Permission | CRITICAL | `permission_callback` is `__return_true` or equivalent |
| Weak Permission | HIGH | Uses a low capability: `read`, `exist`, `level_0` |
| No Input Schema | MEDIUM | Ability accepts input but declares no `input_schema` |
| Loose Input Schema | HIGH | `input_schema` contains unconstrained string on a sensitive field name |
| REST Overexposure | CRITICAL | `show_in_rest: true` with no or weak permission callback |
| Orphaned Callback | HIGH | `execute_callback` references a non-callable function |
| Namespace Collision | HIGH | Two abilities registered with the same name |

---

## MCP Integration

SudoWP Radar registers its own ability (`sudowp-radar/audit`) so an AI agent connected to your WordPress site via MCP can trigger a full security audit natively.

The ability is REST-disabled by default. It requires the custom `radar_run_audit` capability.

---

## Premium Extension

The free plugin ships four WordPress filters that allow a premium layer to extend audit results without modifying core code:

| Filter | Purpose |
|--------|---------|
| `radar_dataset_enabled` | Return `true` to activate SudoWP vulnerability dataset lookups |
| `radar_dataset_findings` | Inject findings from the dataset (CVE references, CVSS scores, patch links) |
| `radar_dataset_status` | Inject dataset metadata for admin UI display |
| `radar_audit_findings` | Modify the full findings array post-audit |

---

## Security Design

- Custom capability `radar_run_audit` on every access-gated surface. Never tied directly to a role.
- All audit results stored in user meta, not global options.
- Rate limiting via 30-second transient per user on all AJAX endpoints.
- No public AJAX endpoints. No `wp_ajax_nopriv_` hooks.
- All output escaped with `esc_html()`, `esc_attr()`, `esc_url()`, or `wp_kses()`.
- All input sanitized with the most specific WP sanitization function available.
- Zero external dependencies. Zero external HTTP calls.
- Clean uninstall: all user meta and transients removed on plugin deletion.

---

## Compatibility Notes

Tested against WordPress 6.9.1 and PHP 8.3. The Abilities API is not available below WP 6.9 -- the plugin will display an admin notice and deactivate gracefully on older installs.

WP 6.9 validates both `execute_callback` and `permission_callback` as callable at registration time, which makes Rules 6 (orphaned callback) and 7 (namespace collision) unreachable via normal API usage in the current WordPress version. Both rules are retained as defensive code for future API changes.

---

## About SudoWP

SudoWP closes the security gap in the WordPress ecosystem by providing security-hardened plugin forks and auditing tools that address vulnerabilities before slow vendor patch cycles put sites at risk.

[sudowp.com](https://sudowp.com)
