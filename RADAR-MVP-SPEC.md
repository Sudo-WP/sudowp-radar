# SudoWP Radar  — MVP Plugin Spec
> For use with Claude Code. Drop into your local repo root and run.

---

## Plugin Identity

| Field | Value |
|---|---|
| Plugin Name | SudoWP Radar |
| Plugin Slug | `sudowp-radar` |
| Text Domain | `sudowp-radar` |
| Namespace | `SudoWP\Radar` |
| Minimum WP | 6.9 |
| Minimum PHP | 8.1 |
| License | GPL-2.0-or-later |
| Author | SudoWP |
| Author URI | https://sudowp.com |

---

## Directory Structure

```
sudowp-radar/
├── sudowp-radar.php      # Main plugin file (bootstrap only)
├── uninstall.php                        # Cleanup on uninstall
├── readme.txt                           # WordPress.org readme
├── includes/
│   ├── class-radar-loader.php             # Hook registration
│   ├── class-radar-auditor.php            # Core audit engine
│   ├── class-radar-scanner.php            # Registry scanner (reads WP_Abilities_Registry)
│   ├── class-radar-rule-engine.php        # Static rule evaluator
│   ├── class-radar-finding.php            # Finding data model
│   ├── class-radar-report.php             # Report aggregator and renderer
│   ├── class-radar-ajax.php               # AJAX handlers (admin-only, nonce-gated)
│   ├── class-radar-capabilities.php       # Custom WP capability registration
│   ├── class-radar-dataset.php            # SudoWP vulnerability dataset stub (premium hook)
│   ├── class-radar-abilities.php          # Registers ASA's own WP Abilities API entries
│   └── class-radar-admin.php             # Admin menu, settings page, report UI
├── assets/
│   ├── css/
│   │   └── radar-admin.css
│   └── js/
│       └── radar-admin.js
└── languages/
    └── sudowp-radar.pot
```

---

## Main Plugin File

**File:** `sudowp-radar.php`

```php
<?php
/**
 * Plugin Name: SudoWP Radar
 * Plugin URI:  https://sudowp.com/sudowp-radar
 * Description: Security auditor for the WordPress 6.9+ Abilities API. Scans every registered ability for permission misconfigurations, input schema gaps, REST exposure risks, and namespace collisions.
 * Version:     1.0.0
 * Author:      SudoWP
 * Author URI:  https://sudowp.com
 * License:     GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: sudowp-radar
 * Domain Path: /languages
 * Requires at least: 6.9
 * Requires PHP:  8.1
 *
 * @package SudoWP\Radar
 */

declare( strict_types=1 );

namespace SudoWP\Radar;

// Prevent direct access.
defined( 'ABSPATH' ) || exit;

// Bail early if WP Abilities API is not available.
if ( ! function_exists( 'wp_get_abilities_registry' ) ) {
    add_action( 'admin_notices', function () {
        echo '<div class="notice notice-error"><p>' .
            esc_html__( 'SudoWP Radar requires WordPress 6.9 or higher with the Abilities API enabled.', 'sudowp-radar' ) .
            '</p></div>';
    } );
    return;
}

// Constants.
define( 'RADAR_VERSION',     '1.0.0' );
define( 'RADAR_PLUGIN_FILE', __FILE__ );
define( 'RADAR_PLUGIN_DIR',  plugin_dir_path( __FILE__ ) );
define( 'RADAR_PLUGIN_URL',  plugin_dir_url( __FILE__ ) );
define( 'RADAR_TEXT_DOMAIN', 'sudowp-radar' );

// Autoloader.
spl_autoload_register( function ( string $class ): void {
    $prefix = 'SudoWP\Radar\';
    if ( ! str_starts_with( $class, $prefix ) ) {
        return;
    }
    $relative = substr( $class, strlen( $prefix ) );
    $file     = RADAR_PLUGIN_DIR . 'includes/class-' . strtolower( str_replace( '_', '-', $relative ) ) . '.php';
    if ( file_exists( $file ) ) {
        require_once $file;
    }
} );

// Bootstrap.
add_action( 'plugins_loaded', function (): void {
    $loader = new Loader();
    $loader->init();
} );
```

---

## Core Classes

### `class-radar-loader.php`

Registers all hooks. Nothing else runs unless the current user has the `radar_run_audit` capability.

```php
<?php
declare( strict_types=1 );

namespace SudoWP\Radar;

defined( 'ABSPATH' ) || exit;

class Loader {

    public function init(): void {
        load_plugin_textdomain( RADAR_TEXT_DOMAIN, false, dirname( plugin_basename( RADAR_PLUGIN_FILE ) ) . '/languages' );

        ( new Capabilities() )->register();
        ( new Admin() )->init();
        ( new Ajax() )->init();
        ( new Abilities() )->init();   // Registers ASA's own WP Abilities API entries.
    }
}
```

---

### `class-radar-capabilities.php`

Defines a custom capability so the audit is never tied to a generic role.

```php
<?php
declare( strict_types=1 );

namespace SudoWP\Radar;

defined( 'ABSPATH' ) || exit;

class Capabilities {

    /**
     * Custom capability required to run audits.
     * Granted to administrators by default via option; never hardcoded to a role.
     */
    const RUN_AUDIT = 'radar_run_audit';

    public function register(): void {
        // Grant to super admin on multisite.
        add_filter( 'user_has_cap', [ $this, 'grant_to_admin' ], 10, 3 );
    }

    public function grant_to_admin( array $allcaps, array $caps, array $args ): array {
        if ( in_array( self::RUN_AUDIT, $caps, true ) && isset( $allcaps['manage_options'] ) && $allcaps['manage_options'] ) {
            $allcaps[ self::RUN_AUDIT ] = true;
        }
        return $allcaps;
    }
}
```

---

### `class-radar-finding.php`

Immutable data object for a single audit finding.

```php
<?php
declare( strict_types=1 );

namespace SudoWP\Radar;

defined( 'ABSPATH' ) || exit;

class Finding {

    const SEVERITY_CRITICAL = 'critical';
    const SEVERITY_HIGH     = 'high';
    const SEVERITY_MEDIUM   = 'medium';
    const SEVERITY_LOW      = 'low';
    const SEVERITY_INFO     = 'info';

    const VULN_OPEN_PERMISSION     = 'open-permission';
    const VULN_WEAK_PERMISSION     = 'weak-permission';
    const VULN_NO_INPUT_SCHEMA     = 'no-input-schema';
    const VULN_LOOSE_INPUT_SCHEMA  = 'loose-input-schema';
    const VULN_REST_OVEREXPOSURE   = 'rest-overexposure';
    const VULN_NAMESPACE_COLLISION = 'namespace-collision';
    const VULN_ORPHANED_CALLBACK   = 'orphaned-callback';
    const VULN_DATASET_MATCH       = 'dataset-match';  // Premium: SudoWP vulnerability dataset.

    public function __construct(
        public readonly string $ability_name,
        public readonly string $severity,
        public readonly string $vuln_class,
        public readonly string $message,
        public readonly string $recommendation,
        public readonly array  $context = [],       // Extra data: file, line, callback name, etc.
        public readonly bool   $is_premium = false, // True for findings from SudoWP dataset.
    ) {}

    public function to_array(): array {
        return [
            'ability_name'    => $this->ability_name,
            'severity'        => $this->severity,
            'vuln_class'      => $this->vuln_class,
            'message'         => $this->message,
            'recommendation'  => $this->recommendation,
            'context'         => $this->context,
            'is_premium'      => $this->is_premium,
        ];
    }
}
```

---

### `class-radar-scanner.php`

Reads the live `WP_Abilities_Registry` and returns raw ability data for the rule engine.

```php
<?php
declare( strict_types=1 );

namespace SudoWP\Radar;

defined( 'ABSPATH' ) || exit;

class Scanner {

    /**
     * Returns an array of ability data arrays from the live registry.
     * Only callable by users with radar_run_audit capability.
     */
    public function get_registered_abilities(): array {
        if ( ! current_user_can( Capabilities::RUN_AUDIT ) ) {
            return [];
        }

        $registry  = wp_get_abilities_registry();
        $abilities = [];

        // WP_Abilities_Registry exposes abilities via get_all() or equivalent.
        // Adjust method name if the API changes before WP 6.9 final.
        if ( method_exists( $registry, 'get_all' ) ) {
            foreach ( $registry->get_all() as $ability ) {
                $abilities[] = $this->extract_ability_data( $ability );
            }
        }

        return $abilities;
    }

    /**
     * Extracts serializable data from a WP_Ability instance.
     */
    private function extract_ability_data( \WP_Ability $ability ): array {
        return [
            'name'                => $ability->name,
            'label'               => $ability->label ?? '',
            'description'         => $ability->description ?? '',
            'category'            => $ability->category ?? '',
            'input_schema'        => $ability->input_schema ?? [],
            'output_schema'       => $ability->output_schema ?? [],
            'execute_callback'    => $ability->execute_callback ?? null,
            'permission_callback' => $ability->permission_callback ?? null,
            'meta'                => $ability->meta ?? [],
            'namespace'           => strstr( $ability->name, '/', true ),
        ];
    }
}
```

---

### `class-radar-rule-engine.php`

Static rule evaluator. Each rule is a self-contained method returning zero or more `Finding` objects.
Add new rules here as new vulnerability classes are discovered.

```php
<?php
declare( strict_types=1 );

namespace SudoWP\Radar;

defined( 'ABSPATH' ) || exit;

class Rule_Engine {

    /**
     * Runs all static rules against a single ability data array.
     *
     * @param array $ability   Ability data from Scanner.
     * @param array $all       All abilities data (for cross-ability rules like collision detection).
     * @return Finding[]
     */
    public function evaluate( array $ability, array $all = [] ): array {
        $findings = [];

        $findings = array_merge( $findings, $this->rule_permission_callback( $ability ) );
        $findings = array_merge( $findings, $this->rule_input_schema( $ability ) );
        $findings = array_merge( $findings, $this->rule_rest_exposure( $ability ) );
        $findings = array_merge( $findings, $this->rule_orphaned_callback( $ability ) );
        $findings = array_merge( $findings, $this->rule_namespace_collision( $ability, $all ) );

        return $findings;
    }

    // -------------------------------------------------------------------------
    // Rule: Permission Callback
    // -------------------------------------------------------------------------

    private function rule_permission_callback( array $a ): array {
        $findings = [];
        $cb       = $a['permission_callback'];
        $name     = $a['name'];

        // No permission callback at all.
        if ( null === $cb ) {
            $findings[] = new Finding(
                ability_name:   $name,
                severity:       Finding::SEVERITY_CRITICAL,
                vuln_class:     Finding::VULN_OPEN_PERMISSION,
                message:        sprintf( __( 'Ability "%s" has no permission_callback. Any request can execute it.', 'sudowp-radar' ), esc_html( $name ) ),
                recommendation: __( 'Add a permission_callback that calls current_user_can() with an appropriate capability.', 'sudowp-radar' ),
                context:        [ 'callback' => null ],
            );
            return $findings;
        }

        // Callback is __return_true — fully open.
        if ( is_string( $cb ) && '__return_true' === $cb ) {
            $findings[] = new Finding(
                ability_name:   $name,
                severity:       Finding::SEVERITY_CRITICAL,
                vuln_class:     Finding::VULN_OPEN_PERMISSION,
                message:        sprintf( __( 'Ability "%s" uses __return_true as its permission_callback. It is publicly executable.', 'sudowp-radar' ), esc_html( $name ) ),
                recommendation: __( 'Replace __return_true with a proper capability check.', 'sudowp-radar' ),
                context:        [ 'callback' => '__return_true' ],
            );
            return $findings;
        }

        // Detect known weak capabilities via reflection on the callback source.
        $weak_caps = [ 'read', 'exist', 'level_0' ];
        if ( is_callable( $cb ) ) {
            try {
                $ref  = is_array( $cb )
                    ? new \ReflectionMethod( $cb[0], $cb[1] )
                    : new \ReflectionFunction( \Closure::fromCallable( $cb ) );
                $src  = $this->get_function_source( $ref );
                foreach ( $weak_caps as $cap ) {
                    if ( str_contains( $src, "'{$cap}'" ) || str_contains( $src, "\"{$cap}\"" ) ) {
                        $findings[] = new Finding(
                            ability_name:   $name,
                            severity:       Finding::SEVERITY_HIGH,
                            vuln_class:     Finding::VULN_WEAK_PERMISSION,
                            message:        sprintf( __( 'Ability "%s" uses the "%s" capability which may be too permissive.', 'sudowp-radar' ), esc_html( $name ), esc_html( $cap ) ),
                            recommendation: __( 'Use a more restrictive capability such as manage_options, edit_posts, or a custom capability.', 'sudowp-radar' ),
                            context:        [ 'detected_cap' => $cap ],
                        );
                        break;
                    }
                }
            } catch ( \ReflectionException ) {
                // Cannot inspect; skip weak cap detection for this ability.
            }
        }

        return $findings;
    }

    // -------------------------------------------------------------------------
    // Rule: Input Schema
    // -------------------------------------------------------------------------

    private function rule_input_schema( array $a ): array {
        $findings = [];
        $name     = $a['name'];
        $schema   = $a['input_schema'];

        if ( empty( $schema ) ) {
            $findings[] = new Finding(
                ability_name:   $name,
                severity:       Finding::SEVERITY_MEDIUM,
                vuln_class:     Finding::VULN_NO_INPUT_SCHEMA,
                message:        sprintf( __( 'Ability "%s" has no input_schema. Inputs are unvalidated.', 'sudowp-radar' ), esc_html( $name ) ),
                recommendation: __( 'Define an input_schema with typed properties and format constraints. Use "format: uri" for URLs, "pattern" for slugs, and enum for fixed values.', 'sudowp-radar' ),
            );
            return $findings;
        }

        // Check for unconstrained string properties that could be path/URL injection vectors.
        $risky_patterns = [ 'path', 'file', 'url', 'redirect', 'source', 'target', 'slug' ];
        $properties     = $schema['properties'] ?? [];

        foreach ( $properties as $prop_name => $prop_def ) {
            if ( ( $prop_def['type'] ?? '' ) !== 'string' ) {
                continue;
            }
            $has_format  = isset( $prop_def['format'] );
            $has_pattern = isset( $prop_def['pattern'] );
            $has_enum    = isset( $prop_def['enum'] );

            foreach ( $risky_patterns as $pattern ) {
                if ( str_contains( strtolower( $prop_name ), $pattern ) && ! $has_format && ! $has_pattern && ! $has_enum ) {
                    $findings[] = new Finding(
                        ability_name:   $name,
                        severity:       Finding::SEVERITY_HIGH,
                        vuln_class:     Finding::VULN_LOOSE_INPUT_SCHEMA,
                        message:        sprintf(
                            __( 'Ability "%s" has a string property "%s" with no format, pattern, or enum constraint. This may allow injection.', 'sudowp-radar' ),
                            esc_html( $name ),
                            esc_html( $prop_name )
                        ),
                        recommendation: __( 'Add a format (e.g. "uri", "date-time"), a regex pattern, or restrict to an enum to prevent directory traversal or SSRF.', 'sudowp-radar' ),
                        context:        [ 'property' => $prop_name ],
                    );
                    break;
                }
            }
        }

        return $findings;
    }

    // -------------------------------------------------------------------------
    // Rule: REST Exposure vs Permission Level
    // -------------------------------------------------------------------------

    private function rule_rest_exposure( array $a ): array {
        $findings     = [];
        $name         = $a['name'];
        $show_in_rest = $a['meta']['show_in_rest'] ?? false;
        $cb           = $a['permission_callback'];

        if ( ! $show_in_rest ) {
            return $findings;
        }

        // REST-exposed with no or open permission = critical.
        if ( null === $cb || ( is_string( $cb ) && '__return_true' === $cb ) ) {
            $findings[] = new Finding(
                ability_name:   $name,
                severity:       Finding::SEVERITY_CRITICAL,
                vuln_class:     Finding::VULN_REST_OVEREXPOSURE,
                message:        sprintf( __( 'Ability "%s" is exposed via REST and has no or open permission_callback. Unauthenticated callers can execute it.', 'sudowp-radar' ), esc_html( $name ) ),
                recommendation: __( 'Restrict REST-exposed abilities to at minimum is_user_logged_in() and preferably a specific capability like edit_posts.', 'sudowp-radar' ),
            );
        }

        return $findings;
    }

    // -------------------------------------------------------------------------
    // Rule: Orphaned Callback
    // -------------------------------------------------------------------------

    private function rule_orphaned_callback( array $a ): array {
        $findings = [];
        $name     = $a['name'];
        $cb       = $a['execute_callback'];

        if ( null === $cb ) {
            return $findings;
        }

        $exists = is_callable( $cb ) || ( is_string( $cb ) && function_exists( $cb ) );

        if ( ! $exists ) {
            $findings[] = new Finding(
                ability_name:   $name,
                severity:       Finding::SEVERITY_HIGH,
                vuln_class:     Finding::VULN_ORPHANED_CALLBACK,
                message:        sprintf( __( 'Ability "%s" references a non-existent or non-callable execute_callback. The ability is broken and may indicate a deactivated plugin left registrations behind.', 'sudowp-radar' ), esc_html( $name ) ),
                recommendation: __( 'Verify the plugin registering this ability is active, or unregister the orphaned ability.', 'sudowp-radar' ),
                context:        [ 'callback' => is_string( $cb ) ? $cb : 'closure/array' ],
            );
        }

        return $findings;
    }

    // -------------------------------------------------------------------------
    // Rule: Namespace Collision
    // -------------------------------------------------------------------------

    private function rule_namespace_collision( array $a, array $all ): array {
        $findings  = [];
        $name      = $a['name'];
        $namespace = $a['namespace'];

        $namespace_map = [];
        foreach ( $all as $other ) {
            $ns = $other['namespace'];
            if ( ! isset( $namespace_map[ $ns ] ) ) {
                $namespace_map[ $ns ] = [];
            }
            $namespace_map[ $ns ][] = $other['name'];
        }

        // Collision = two different abilities sharing exact name (last registration wins in WP).
        $same_name = array_filter( $all, fn( $other ) => $other['name'] === $name );
        if ( count( $same_name ) > 1 ) {
            $findings[] = new Finding(
                ability_name:   $name,
                severity:       Finding::SEVERITY_HIGH,
                vuln_class:     Finding::VULN_NAMESPACE_COLLISION,
                message:        sprintf( __( 'Ability "%s" is registered more than once. The last registration overwrites earlier ones, potentially downgrading permissions.', 'sudowp-radar' ), esc_html( $name ) ),
                recommendation: __( 'Ensure each ability has a unique, plugin-namespaced name. Review all plugins registering abilities under this namespace.', 'sudowp-radar' ),
                context:        [ 'collision_count' => count( $same_name ) ],
            );
        }

        return $findings;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private function get_function_source( \ReflectionFunctionAbstract $ref ): string {
        $file  = $ref->getFileName();
        $start = $ref->getStartLine() - 1;
        $end   = $ref->getEndLine();

        if ( ! $file || ! is_readable( $file ) ) {
            return '';
        }

        $lines = array_slice( file( $file ), $start, $end - $start );
        return implode( '', $lines );
    }
}
```

---

### `class-radar-dataset.php`

SudoWP vulnerability dataset integration. Stubbed for MVP — wired to the filter system so premium code can plug in without touching core audit logic.

```php
<?php
declare( strict_types=1 );

namespace SudoWP\Radar;

defined( 'ABSPATH' ) || exit;

/**
 * SudoWP Vulnerability Dataset
 *
 * MVP: This class is a stub. The filter `radar_dataset_findings` allows a premium
 * add-on or SudoWP Hub to inject dataset-matched findings without modifying
 * core plugin files.
 *
 * Premium workflow (future):
 *   1. SudoWP dataset API returns known-vulnerable ability patterns (by namespace,
 *      callback signature, or schema fingerprint).
 *   2. Dataset_Premium class (loaded by SudoWP Hub) hooks into `radar_dataset_findings`
 *      and returns matched findings with CVE references, CVSS scores, and patch links.
 *   3. Core auditor displays them as Finding::VULN_DATASET_MATCH with is_premium = true.
 */
class Dataset {

    const FILTER_FINDINGS = 'radar_dataset_findings';
    const FILTER_ENABLED  = 'radar_dataset_enabled';

    /**
     * Returns whether dataset lookups are enabled (premium feature).
     */
    public static function is_enabled(): bool {
        return (bool) apply_filters( self::FILTER_ENABLED, false );
    }

    /**
     * Returns dataset-matched findings for a given ability.
     * Returns empty array in free version; premium code hooks in via filter.
     *
     * @param array $ability Ability data from Scanner.
     * @return Finding[]
     */
    public static function get_findings( array $ability ): array {
        $findings = apply_filters( self::FILTER_FINDINGS, [], $ability );

        // Validate that whatever premium code returns are actual Finding objects.
        return array_filter( $findings, fn( $f ) => $f instanceof Finding );
    }

    /**
     * Returns a summary of the dataset status for display in the admin UI.
     */
    public static function get_status(): array {
        return apply_filters( 'radar_dataset_status', [
            'enabled'       => false,
            'label'         => __( 'SudoWP Vulnerability Dataset: Not connected. Upgrade to SudoWP Pro.', 'sudowp-radar' ),
            'last_updated'  => null,
            'total_entries' => 0,
        ] );
    }
}
```

---

### `class-radar-auditor.php`

Orchestrator — runs scanner, rule engine, and dataset stub; returns a complete report.

```php
<?php
declare( strict_types=1 );

namespace SudoWP\Radar;

defined( 'ABSPATH' ) || exit;

class Auditor {

    public function __construct(
        private readonly Scanner     $scanner,
        private readonly Rule_Engine $rule_engine,
    ) {}

    /**
     * Runs a full audit and returns a Report object.
     * Access-gated — silently returns empty report if capability missing.
     */
    public function run(): Report {
        if ( ! current_user_can( Capabilities::RUN_AUDIT ) ) {
            return new Report( [], [] );
        }

        $abilities = $this->scanner->get_registered_abilities();
        $findings  = [];

        foreach ( $abilities as $ability ) {
            // Static rule engine findings.
            $rule_findings = $this->rule_engine->evaluate( $ability, $abilities );
            $findings      = array_merge( $findings, $rule_findings );

            // SudoWP dataset findings (no-op in free version; premium hooks in via filter).
            if ( Dataset::is_enabled() ) {
                $dataset_findings = Dataset::get_findings( $ability );
                $findings         = array_merge( $findings, $dataset_findings );
            }
        }

        // Allow third-party or premium code to add/modify findings.
        $findings = apply_filters( 'radar_audit_findings', $findings, $abilities );

        return new Report( $findings, $abilities );
    }
}
```

---

### `class-radar-report.php`

Aggregates findings and provides rendering helpers.

```php
<?php
declare( strict_types=1 );

namespace SudoWP\Radar;

defined( 'ABSPATH' ) || exit;

class Report {

    public function __construct(
        private readonly array $findings,  // Finding[]
        private readonly array $abilities, // Raw ability data arrays.
    ) {}

    public function get_findings(): array {
        return $this->findings;
    }

    public function get_findings_by_severity( string $severity ): array {
        return array_filter( $this->findings, fn( $f ) => $f->severity === $severity );
    }

    public function get_total_abilities(): int {
        return count( $this->abilities );
    }

    public function get_risk_score(): int {
        $weights = [
            Finding::SEVERITY_CRITICAL => 40,
            Finding::SEVERITY_HIGH     => 20,
            Finding::SEVERITY_MEDIUM   => 8,
            Finding::SEVERITY_LOW      => 2,
            Finding::SEVERITY_INFO     => 0,
        ];

        $score = 0;
        foreach ( $this->findings as $f ) {
            $score += $weights[ $f->severity ] ?? 0;
        }

        return min( $score, 100 );
    }

    public function get_summary(): array {
        return [
            'total_abilities' => $this->get_total_abilities(),
            'total_findings'  => count( $this->findings ),
            'critical'        => count( $this->get_findings_by_severity( Finding::SEVERITY_CRITICAL ) ),
            'high'            => count( $this->get_findings_by_severity( Finding::SEVERITY_HIGH ) ),
            'medium'          => count( $this->get_findings_by_severity( Finding::SEVERITY_MEDIUM ) ),
            'low'             => count( $this->get_findings_by_severity( Finding::SEVERITY_LOW ) ),
            'risk_score'      => $this->get_risk_score(),
        ];
    }

    /**
     * Returns findings as a JSON-serializable array.
     * Used by the REST-exposed ASA ability and AJAX handler.
     */
    public function to_array(): array {
        return [
            'summary'  => $this->get_summary(),
            'findings' => array_map( fn( $f ) => $f->to_array(), $this->findings ),
        ];
    }
}
```

---

### `class-radar-ajax.php`

All AJAX endpoints are admin-only and nonce-gated. No public AJAX.

```php
<?php
declare( strict_types=1 );

namespace SudoWP\Radar;

defined( 'ABSPATH' ) || exit;

class Ajax {

    const NONCE_ACTION = 'radar_run_audit_nonce';

    public function init(): void {
        add_action( 'wp_ajax_radar_run_audit', [ $this, 'handle_run_audit' ] );
        // Deliberately NOT registering wp_ajax_nopriv_ — no unauthenticated access.
    }

    public function handle_run_audit(): void {
        // 1. Nonce verification.
        if ( ! check_ajax_referer( self::NONCE_ACTION, 'nonce', false ) ) {
            wp_send_json_error( [ 'message' => __( 'Invalid nonce.', 'sudowp-radar' ) ], 403 );
        }

        // 2. Capability check.
        if ( ! current_user_can( Capabilities::RUN_AUDIT ) ) {
            wp_send_json_error( [ 'message' => __( 'Insufficient permissions.', 'sudowp-radar' ) ], 403 );
        }

        // 3. Rate limiting: prevent flooding. One audit per 30 seconds per user.
        $transient_key = 'radar_last_audit_' . get_current_user_id();
        if ( get_transient( $transient_key ) ) {
            wp_send_json_error( [ 'message' => __( 'Please wait before running another audit.', 'sudowp-radar' ) ], 429 );
        }
        set_transient( $transient_key, true, 30 );

        // 4. Run audit.
        $auditor = new Auditor( new Scanner(), new Rule_Engine() );
        $report  = $auditor->run();

        // 5. Store last report in a user-scoped option (not a global option).
        update_user_meta( get_current_user_id(), '_radar_last_report', $report->to_array() );

        wp_send_json_success( $report->to_array() );
    }
}
```

---

### `class-radar-abilities.php`

ASA registers its own abilities via the WP Abilities API.
This means an MCP-connected AI agent can call `sudowp-radar/audit` directly.

```php
<?php
declare( strict_types=1 );

namespace SudoWP\Radar;

defined( 'ABSPATH' ) || exit;

class Abilities {

    public function init(): void {
        add_action( 'wp_abilities_api_init', [ $this, 'register' ] );
    }

    public function register(): void {
        // Ability: run a full site audit and return structured findings.
        wp_register_ability(
            'sudowp-radar/audit',
            [
                'label'       => __( 'Run Security Radar Scan', 'sudowp-radar' ),
                'description' => __( 'Audits all registered WordPress Abilities for security misconfigurations. Returns a structured findings report.', 'sudowp-radar' ),
                'category'    => 'security',
                'input_schema' => [
                    'type'       => 'object',
                    'properties' => [],
                ],
                'output_schema' => [
                    'type'       => 'object',
                    'properties' => [
                        'summary'  => [ 'type' => 'object' ],
                        'findings' => [ 'type' => 'array' ],
                    ],
                ],
                'execute_callback'    => [ $this, 'execute_audit' ],
                'permission_callback' => fn() => current_user_can( Capabilities::RUN_AUDIT ),
                'meta'                => [ 'show_in_rest' => false ], // Not REST-exposed by default.
            ]
        );
    }

    public function execute_audit(): array {
        if ( ! current_user_can( Capabilities::RUN_AUDIT ) ) {
            return [ 'error' => 'Insufficient permissions.' ];
        }

        $auditor = new Auditor( new Scanner(), new Rule_Engine() );
        return $auditor->run()->to_array();
    }
}
```

---

### `class-radar-admin.php`

Registers the admin menu and settings page. Enqueues assets with versioned URLs.

```php
<?php
declare( strict_types=1 );

namespace SudoWP\Radar;

defined( 'ABSPATH' ) || exit;

class Admin {

    public function init(): void {
        add_action( 'admin_menu', [ $this, 'register_menu' ] );
        add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_assets' ] );
    }

    public function register_menu(): void {
        add_menu_page(
            __( 'SudoWP Radar', 'sudowp-radar' ),
            __( 'Radar', 'sudowp-radar' ),
            Capabilities::RUN_AUDIT,
            'sudowp-radar',
            [ $this, 'render_page' ],
            'dashicons-shield',
            81
        );
    }

    public function enqueue_assets( string $hook ): void {
        if ( 'toplevel_page_sudowp-radar' !== $hook ) {
            return;
        }

        wp_enqueue_style(
            'radar-admin',
            RADAR_PLUGIN_URL . 'assets/css/radar-admin.css',
            [],
            RADAR_VERSION
        );

        wp_enqueue_script(
            'radar-admin',
            RADAR_PLUGIN_URL . 'assets/js/radar-admin.js',
            [ 'jquery' ],
            RADAR_VERSION,
            true
        );

        // Localize only what JS needs — never leak sensitive data.
        wp_localize_script( 'radar-admin', 'SudoWPRadar', [
            'ajax_url'       => admin_url( 'admin-ajax.php' ),
            'nonce'          => wp_create_nonce( Ajax::NONCE_ACTION ),
            'dataset_status' => Dataset::get_status(),
            'strings'        => [
                'run_audit'    => __( 'Run Audit', 'sudowp-radar' ),
                'running'      => __( 'Scanning...', 'sudowp-radar' ),
                'no_findings'  => __( 'No issues found. All abilities look clean.', 'sudowp-radar' ),
                'error'        => __( 'Audit failed. Please try again.', 'sudowp-radar' ),
            ],
        ] );
    }

    public function render_page(): void {
        if ( ! current_user_can( Capabilities::RUN_AUDIT ) ) {
            wp_die( esc_html__( 'You do not have permission to access this page.', 'sudowp-radar' ) );
        }

        $last_report   = get_user_meta( get_current_user_id(), '_radar_last_report', true );
        $dataset_status = Dataset::get_status();
        ?>
        <div class="wrap radar-wrap">
            <h1><?php esc_html_e( 'SudoWP Radar', 'sudowp-radar' ); ?></h1>

            <div class="radar-dataset-status <?php echo $dataset_status['enabled'] ? 'radar-premium' : 'radar-free'; ?>">
                <?php echo esc_html( $dataset_status['label'] ); ?>
            </div>

            <button id="radar-run-audit" class="button button-primary">
                <?php esc_html_e( 'Run Audit', 'sudowp-radar' ); ?>
            </button>

            <div id="radar-results">
                <?php if ( $last_report ) : ?>
                    <p class="radar-cached-notice"><?php esc_html_e( 'Showing last audit results.', 'sudowp-radar' ); ?></p>
                    <!-- JS will re-render from cached data on page load -->
                <?php endif; ?>
            </div>
        </div>
        <?php
    }
}
```

---

## Security Checklist (Baked In from Day One)

This checklist maps to OWASP Top 10 and WordPress security guidelines. Every item is addressed in the MVP code above.

| # | Requirement | Where Implemented |
|---|---|---|
| 1 | No direct file access | `defined('ABSPATH') \|\| exit` in every file |
| 2 | Capability checks on every user action | `Capabilities::RUN_AUDIT` checked in AJAX, admin page, scanner, abilities |
| 3 | Nonce verification on all AJAX | `check_ajax_referer()` before any processing in `Ajax::handle_run_audit()` |
| 4 | No public AJAX endpoints | Only `wp_ajax_` registered, never `wp_ajax_nopriv_` |
| 5 | Output escaping | All admin output uses `esc_html()`, `esc_attr()` |
| 6 | No raw SQL | No `$wpdb` queries in MVP; only WP API calls |
| 7 | No user data in global options | Last report stored in user meta (`update_user_meta`), not `update_option` |
| 8 | Rate limiting on audit runs | 30-second transient per user in `Ajax::handle_run_audit()` |
| 9 | No execute/eval of scanned code | Scanner uses `wp_get_abilities_registry()` and reflection only |
| 10 | REST ability not exposed by default | `show_in_rest => false` on `sudowp-radar/audit` |
| 11 | Custom capability (not tied to role) | `radar_run_audit` granted to `manage_options` holders via filter |
| 12 | Asset versioning | All enqueued with `RADAR_VERSION` |
| 13 | Minimal JS data exposure | `wp_localize_script` passes only nonce + UI strings, never findings |
| 14 | PHP 8.1+ strict types | `declare(strict_types=1)` in all files |
| 15 | Clean uninstall | `uninstall.php` must delete all user meta and options |

---

## `uninstall.php`

```php
<?php
defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

// Remove last report from all users.
delete_metadata( 'user', 0, '_radar_last_report', '', true );

// Remove rate-limiting transients.
global $wpdb;
$wpdb->query(
    $wpdb->prepare(
        "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s",
        $wpdb->esc_like( '_transient_radar_last_audit_' ) . '%'
    )
);
```

---

## Premium Extension Points (Documented for Future Dev)

The free MVP wires in these hooks so the premium layer never requires core edits:

| Hook | Type | Purpose |
|---|---|---|
| `radar_dataset_enabled` | filter | Return `true` to activate dataset lookups |
| `radar_dataset_findings` | filter | Inject `Finding[]` from SudoWP vulnerability dataset |
| `radar_dataset_status` | filter | Inject dataset metadata for admin UI display |
| `radar_audit_findings` | filter | Modify full findings array post-audit (add, remove, re-score) |

**Premium tier roadmap built on these hooks:**
- Scheduled audits via WP Cron + email alerts
- SudoWP vulnerability database matching (CVE references, CVSS scores, patch links)
- Multi-site dashboard aggregation
- PDF/CSV report export
- White-label mode for agencies

---

## `.gitignore`

Create this file in the repo root before the first commit.

```
# Dependencies
node_modules/

# OS files
.DS_Store
Thumbs.db

# Logs and temp files
*.log
*.orig
*.bak

# Environment and credentials
.env
.env.*

# Build artifacts
/vendor/
*.zip

# IDE files
.idea/
.vscode/
*.sublime-project
*.sublime-workspace
```

---

## Claude Code Instructions

When you receive this file, build the plugin as follows:

1. Create the directory structure exactly as specified above.
2. Implement each file from the code blocks. Do not merge files or rename classes. All class files use the `class-radar-` prefix, not `class-asa-`.
3. Create `assets/css/radar-admin.css` and `assets/js/radar-admin.js` as minimal stubs — just enough for the Run Audit button to trigger the AJAX call and render findings as a severity-sorted list.
4. Create `languages/sudowp-radar.pot` as an empty pot file with correct headers.
5. Create `readme.txt` following WordPress.org plugin readme format with the plugin description from the pitch document.
6. Create `.gitignore` as specified in the section above.
7. Run a PHP lint pass (`php -l`) on every `.php` file before finishing.
8. Verify no `error_log()`, `var_dump()`, or `print_r()` calls exist in any file.
9. Do not add Composer or any external dependencies. This plugin must be zero-dependency.
10. Run the GitHub Sync and Health Check Routine from `HANDOFF.md` after all files are built. Report the full sync output. Do not end the session until SYNC OK is confirmed.

---

## GitHub Sync and Health Check Routine

See `HANDOFF.md` for the full routine. Summary for reference:

```bash
cd ~/plugins/sudowp-radar

# Stage and commit
git add -A
git commit -m "M[N]: [description]"

# Push
git push origin main

# Health check
git fetch origin
git diff HEAD origin/main          # must be empty
git rev-parse HEAD                 # must match origin/main
git rev-parse origin/main

LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)
[ "$LOCAL" = "$REMOTE" ] && echo "SYNC OK" || echo "SYNC FAIL"
```

Never force push. If push is rejected, stop and report to G. before proceeding.

---

*Built by SudoWP — https://sudowp.com*
