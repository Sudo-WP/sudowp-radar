<?php
declare( strict_types=1 );

namespace SudoWP\Radar;

defined( 'ABSPATH' ) || exit;

class Rule_Engine {

	/**
	 * Runs all static rules against a single ability data array.
	 *
	 * @param array $ability  Ability data from Scanner.
	 * @param array $all      All abilities data (for cross-ability rules like collision detection).
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
				message:        sprintf(
					/* translators: %s: ability name */
					__( 'Ability "%s" has no permission_callback. Any request can execute it.', 'sudowp-radar' ),
					esc_html( $name )
				),
				recommendation: __( 'Add a permission_callback that calls current_user_can() with an appropriate capability.', 'sudowp-radar' ),
				context:        [ 'callback' => null ],
			);
			return $findings;
		}

		// Callback is __return_true -- fully open.
		if ( is_string( $cb ) && '__return_true' === $cb ) {
			$findings[] = new Finding(
				ability_name:   $name,
				severity:       Finding::SEVERITY_CRITICAL,
				vuln_class:     Finding::VULN_OPEN_PERMISSION,
				message:        sprintf(
					/* translators: %s: ability name */
					__( 'Ability "%s" uses __return_true as its permission_callback. It is publicly executable.', 'sudowp-radar' ),
					esc_html( $name )
				),
				recommendation: __( 'Replace __return_true with a proper capability check.', 'sudowp-radar' ),
				context:        [ 'callback' => '__return_true' ],
			);
			return $findings;
		}

		// Detect known weak capabilities via reflection on the callback source.
		$weak_caps = [ 'read', 'exist', 'level_0' ];
		if ( is_callable( $cb ) ) {
			try {
				$ref = is_array( $cb )
					? new \ReflectionMethod( $cb[0], $cb[1] )
					: new \ReflectionFunction( \Closure::fromCallable( $cb ) );
				$src = $this->get_function_source( $ref );
				foreach ( $weak_caps as $cap ) {
					if ( str_contains( $src, "'{$cap}'" ) || str_contains( $src, "\"{$cap}\"" ) ) {
						$findings[] = new Finding(
							ability_name:   $name,
							severity:       Finding::SEVERITY_HIGH,
							vuln_class:     Finding::VULN_WEAK_PERMISSION,
							message:        sprintf(
								/* translators: 1: ability name, 2: capability name */
								__( 'Ability "%1$s" uses the "%2$s" capability which may be too permissive.', 'sudowp-radar' ),
								esc_html( $name ),
								esc_html( $cap )
							),
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
				message:        sprintf(
					/* translators: %s: ability name */
					__( 'Ability "%s" has no input_schema. Inputs are unvalidated.', 'sudowp-radar' ),
					esc_html( $name )
				),
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
							/* translators: 1: ability name, 2: property name */
							__( 'Ability "%1$s" has a string property "%2$s" with no format, pattern, or enum constraint. This may allow injection.', 'sudowp-radar' ),
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
				message:        sprintf(
					/* translators: %s: ability name */
					__( 'Ability "%s" is exposed via REST and has no or open permission_callback. Unauthenticated callers can execute it.', 'sudowp-radar' ),
					esc_html( $name )
				),
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
				message:        sprintf(
					/* translators: %s: ability name */
					__( 'Ability "%s" references a non-existent or non-callable execute_callback. The ability is broken and may indicate a deactivated plugin left registrations behind.', 'sudowp-radar' ),
					esc_html( $name )
				),
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
		$findings = [];
		$name     = $a['name'];

		// Collision = two different abilities sharing the exact same name.
		$same_name = array_filter( $all, fn( $other ) => $other['name'] === $name );
		if ( count( $same_name ) > 1 ) {
			$findings[] = new Finding(
				ability_name:   $name,
				severity:       Finding::SEVERITY_HIGH,
				vuln_class:     Finding::VULN_NAMESPACE_COLLISION,
				message:        sprintf(
					/* translators: %s: ability name */
					__( 'Ability "%s" is registered more than once. The last registration overwrites earlier ones, potentially downgrading permissions.', 'sudowp-radar' ),
					esc_html( $name )
				),
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
