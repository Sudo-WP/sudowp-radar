<?php
declare( strict_types=1 );

namespace SudoWP\Radar;

defined( 'ABSPATH' ) || exit;

class Rule_Engine {

	const AI_PREVENT_FILTER_BYPASS = 'ai-prevent-filter-bypass';
	const AI_REST_OVEREXPOSURE     = 'ai-rest-overexposure';
	const AI_MISSING_VERSION_GATE  = 'ai-missing-version-gate';

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
		$findings = array_merge( $findings, $this->rule_mcp_exposure( $ability ) );
		$findings = array_merge( $findings, $this->rule_orphaned_callback( $ability ) );
		$findings = array_merge( $findings, $this->rule_namespace_collision( $ability, $all ) );

		return $findings;
	}

	/**
	 * Runs AI Client surface rules (WP 7.0+).
	 * Silently returns empty array on WP < 7.0 where wp_ai_client_prompt does not exist.
	 *
	 * @return Finding[]
	 */
	public function evaluate_ai_client_surface(): array {
		if ( ! function_exists( 'wp_ai_client_prompt' ) ) {
			return [];
		}

		$findings = [];

		$findings = array_merge( $findings, $this->rule_ai_prevent_filter_bypass() );
		$findings = array_merge( $findings, $this->rule_ai_rest_overexposure() );
		$findings = array_merge( $findings, $this->rule_ai_missing_version_gate() );

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
		// Note: WP 6.9 requires a callable permission_callback at registration time.
		// This branch is defensive code for future API changes or bypassed registration paths.
		if ( null === $cb ) {
			$finding = new Finding(
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
			$finding->set_remediation_hint(
				__( 'Replace the permission callback with a capability check such as current_user_can(\'manage_options\') or a stricter custom capability.', 'sudowp-radar' )
			);
			$findings[] = $finding;
			return $findings;
		}

		// Callback is __return_true -- fully open.
		if ( is_string( $cb ) && '__return_true' === $cb ) {
			$finding = new Finding(
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
			$finding->set_remediation_hint(
				__( 'Replace the permission callback with a capability check such as current_user_can(\'manage_options\') or a stricter custom capability.', 'sudowp-radar' )
			);
			$findings[] = $finding;
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
						$finding = new Finding(
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
						$finding->set_remediation_hint(
							__( 'Replace the weak capability check with manage_options or a custom capability scoped to the intended audience for this ability.', 'sudowp-radar' )
						);
						$findings[] = $finding;
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
			$finding = new Finding(
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
			$finding->set_remediation_hint(
				__( 'Register an input_schema for this ability that validates all accepted parameters before the execute callback is called.', 'sudowp-radar' )
			);
			$findings[] = $finding;
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
					$finding = new Finding(
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
					$finding->set_remediation_hint(
						__( 'Add explicit type and maxLength constraints to the input schema for this parameter to prevent arbitrary input from reaching the execute callback.', 'sudowp-radar' )
					);
					$findings[] = $finding;
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
			$finding = new Finding(
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
			$finding->set_remediation_hint(
				__( 'Remove show_in_rest: true or add a permission callback that restricts REST access to the intended audience.', 'sudowp-radar' )
			);
			$findings[] = $finding;
		}

		return $findings;
	}

	// -------------------------------------------------------------------------
	// Rule: MCP Exposure vs Permission Level
	// -------------------------------------------------------------------------

	private function rule_mcp_exposure( array $a ): array {
		$findings   = [];
		$name       = $a['name'];
		$mcp_public = $a['meta']['mcp.public'] ?? false;
		$cb         = $a['permission_callback'];

		if ( ! $mcp_public ) {
			return $findings;
		}

		// MCP-public with no or open permission = critical.
		// Any connected AI agent can execute this ability without authentication.
		if ( null === $cb || ( is_string( $cb ) && '__return_true' === $cb ) ) {
			$finding = new Finding(
				ability_name:   $name,
				severity:       Finding::SEVERITY_CRITICAL,
				vuln_class:     Finding::VULN_MCP_OVEREXPOSURE,
				message:        sprintf(
					/* translators: %s: ability name */
					__( 'Ability "%s" is exposed via MCP and has no or open permission_callback. Any connected AI agent can execute it without authentication.', 'sudowp-radar' ),
					esc_html( $name )
				),
				recommendation: __( 'Restrict MCP-public abilities with a specific capability check. Never use __return_true or null permission_callback on an MCP-public ability.', 'sudowp-radar' ),
			);
			$finding->set_remediation_hint(
				__( 'Set meta.mcp.public to false or add a permission callback that requires authentication before this ability can be called by an AI agent.', 'sudowp-radar' )
			);
			$findings[] = $finding;
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

		// Note: WP 6.9 validates execute_callback is callable at registration time (WP_Ability::prepare_properties()).
		// An ability in the live registry will always have a callable execute_callback.
		// This rule is defensive code for future API changes, manual registry manipulation,
		// or non-standard registration paths that bypass WP_Ability validation.
		if ( null === $cb ) {
			return $findings;
		}

		$exists = is_callable( $cb ) || ( is_string( $cb ) && function_exists( $cb ) );

		if ( ! $exists ) {
			$finding = new Finding(
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
			$finding->set_remediation_hint(
				__( 'Remove the ability registration or restore the missing execute callback function -- a registered ability with no callable handler is dead attack surface.', 'sudowp-radar' )
			);
			$findings[] = $finding;
		}

		return $findings;
	}

	// -------------------------------------------------------------------------
	// Rule: Namespace Collision
	// -------------------------------------------------------------------------

	private function rule_namespace_collision( array $a, array $all ): array {
		$findings = [];
		$name     = $a['name'];

		// Note: WP 6.9 rejects duplicate ability registrations -- the registry does NOT overwrite
		// existing entries. Two abilities cannot share the same name via normal WP API usage.
		// This rule is defensive code for future API changes or non-standard registration paths.
		// Collision = two different abilities sharing the exact same name.
		$same_name = array_filter( $all, fn( $other ) => $other['name'] === $name );
		if ( count( $same_name ) > 1 ) {
			$finding = new Finding(
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
			$finding->set_remediation_hint(
				__( 'Rename the ability to a unique namespace to prevent a later registration from silently overriding its permission callback.', 'sudowp-radar' )
			);
			$findings[] = $finding;
		}

		return $findings;
	}

	// -------------------------------------------------------------------------
	// Rule: AI Prevent Filter Bypass (WP 7.0+)
	// -------------------------------------------------------------------------

	private function rule_ai_prevent_filter_bypass(): array {
		$findings = [];

		$hooks = $GLOBALS['wp_filter']['wp_ai_client_prevent_prompt'] ?? null;
		if ( ! $hooks ) {
			return $findings;
		}

		// WP_Hook stores callbacks keyed by priority.
		$callbacks = [];
		if ( $hooks instanceof \WP_Hook ) {
			$callbacks = $hooks->callbacks;
		} elseif ( is_array( $hooks ) ) {
			$callbacks = $hooks;
		}

		foreach ( $callbacks as $priority => $hooks_at_priority ) {
			foreach ( $hooks_at_priority as $hook_id => $hook_data ) {
				$cb = $hook_data['function'] ?? null;
				if ( ! $cb || ! is_callable( $cb ) ) {
					continue;
				}

				$cb_name = $this->get_callback_identifier( $cb );

				try {
					$ref = $this->get_reflection_for_callback( $cb );
					if ( ! $ref ) {
						continue;
					}
					$src = $this->get_function_source( $ref );
					if ( $this->is_unconditional_return_false( $src ) ) {
						$finding = new Finding(
							ability_name:   $cb_name,
							severity:       Finding::SEVERITY_HIGH,
							vuln_class:     Finding::VULN_AI_PREVENT_FILTER_BYPASS,
							message:        __( 'A filter hook on wp_ai_client_prevent_prompt unconditionally returns false, disabling the AI prompt prevention gate for all prompts on this site.', 'sudowp-radar' ),
							recommendation: __( 'Review the wp_ai_client_prevent_prompt filter callback and ensure it applies conditional logic.', 'sudowp-radar' ),
							context:        [ 'callback' => $cb_name, 'priority' => $priority ],
						);
						$finding->set_remediation_hint(
							__( 'Review the wp_ai_client_prevent_prompt filter callback and ensure it returns false only under specific, intentional conditions rather than unconditionally.', 'sudowp-radar' )
						);
						$findings[] = $finding;
					}
				} catch ( \ReflectionException ) {
					// Cannot inspect callback source; skip.
				}
			}
		}

		return $findings;
	}

	// -------------------------------------------------------------------------
	// Rule: AI REST Overexposure (WP 7.0+)
	// -------------------------------------------------------------------------

	private function rule_ai_rest_overexposure(): array {
		$findings = [];

		if ( ! function_exists( 'rest_get_server' ) ) {
			return $findings;
		}

		$server = rest_get_server();
		$routes = $server->get_routes();

		foreach ( $routes as $route => $handlers ) {
			foreach ( $handlers as $handler ) {
				$callback = $handler['callback'] ?? null;
				if ( ! $callback || ! is_callable( $callback ) ) {
					continue;
				}

				// Check if the route callback calls wp_ai_client_prompt.
				try {
					$ref = $this->get_reflection_for_callback( $callback );
					if ( ! $ref ) {
						continue;
					}
					$src = $this->get_function_source( $ref );
					if ( ! str_contains( $src, 'wp_ai_client_prompt' ) ) {
						continue;
					}
				} catch ( \ReflectionException ) {
					continue;
				}

				// Route calls wp_ai_client_prompt -- inspect its permission_callback.
				$perm_cb  = $handler['permission_callback'] ?? null;
				$severity = null;

				if ( null === $perm_cb || ( is_string( $perm_cb ) && '__return_true' === $perm_cb ) ) {
					$severity = Finding::SEVERITY_CRITICAL;
				} elseif ( is_callable( $perm_cb ) ) {
					try {
						$perm_ref = $this->get_reflection_for_callback( $perm_cb );
						if ( $perm_ref ) {
							$perm_src  = $this->get_function_source( $perm_ref );
							$weak_caps = [ 'read', 'exist', 'level_0' ];
							foreach ( $weak_caps as $cap ) {
								if ( str_contains( $perm_src, "'{$cap}'" ) || str_contains( $perm_src, "\"{$cap}\"" ) ) {
									$severity = Finding::SEVERITY_HIGH;
									break;
								}
							}
						}
					} catch ( \ReflectionException ) {
						// Cannot inspect; skip.
					}
				}

				if ( $severity ) {
					$finding = new Finding(
						ability_name:   $route,
						severity:       $severity,
						vuln_class:     Finding::VULN_AI_REST_OVEREXPOSURE,
						message:        __( 'A REST endpoint that calls wp_ai_client_prompt() has no or insufficient permission check, allowing unauthenticated or low-privilege users to trigger AI prompt execution.', 'sudowp-radar' ),
						recommendation: __( 'Add a permission_callback to this REST route that requires at minimum manage_options or a custom capability.', 'sudowp-radar' ),
						context:        [ 'route' => $route ],
					);
					$finding->set_remediation_hint(
						__( 'Add a permission_callback to this REST route that requires at minimum manage_options or a custom capability before allowing AI prompt execution.', 'sudowp-radar' )
					);
					$findings[] = $finding;
				}
			}
		}

		return $findings;
	}

	// -------------------------------------------------------------------------
	// Rule: AI Missing Version Gate (WP 7.0+)
	// -------------------------------------------------------------------------

	private function rule_ai_missing_version_gate(): array {
		$findings = [];

		if ( ! function_exists( 'get_option' ) ) {
			return $findings;
		}

		$active_plugins = get_option( 'active_plugins', [] );
		if ( ! is_array( $active_plugins ) ) {
			return $findings;
		}

		$plugin_dir = defined( 'WP_PLUGIN_DIR' ) ? WP_PLUGIN_DIR : ABSPATH . 'wp-content/plugins';

		foreach ( $active_plugins as $plugin_file ) {
			$full_path = $plugin_dir . '/' . $plugin_file;
			if ( ! is_readable( $full_path ) ) {
				continue;
			}

			$contents = file_get_contents( $full_path );
			if ( false === $contents ) {
				continue;
			}

			// Skip files that do not call wp_ai_client_prompt at all.
			if ( ! str_contains( $contents, 'wp_ai_client_prompt(' ) && ! str_contains( $contents, 'wp_ai_client_prompt (' ) ) {
				continue;
			}

			// Check if there is a function_exists guard or is_supported_ call.
			$has_guard = str_contains( $contents, "function_exists( 'wp_ai_client_prompt'" )
				|| str_contains( $contents, 'function_exists( "wp_ai_client_prompt"' )
				|| str_contains( $contents, "function_exists('wp_ai_client_prompt'" )
				|| str_contains( $contents, 'function_exists("wp_ai_client_prompt"' )
				|| str_contains( $contents, 'is_supported_' );

			if ( ! $has_guard ) {
				$finding = new Finding(
					ability_name:   $plugin_file,
					severity:       Finding::SEVERITY_MEDIUM,
					vuln_class:     Finding::VULN_AI_MISSING_VERSION_GATE,
					message:        __( 'This plugin calls wp_ai_client_prompt() without a version compatibility check, causing fatal errors on WordPress versions below 7.0.', 'sudowp-radar' ),
					recommendation: __( 'Wrap calls to wp_ai_client_prompt() in a function_exists check or use is_supported_for_text_generation() before rendering any AI-powered UI.', 'sudowp-radar' ),
					context:        [ 'plugin_file' => $plugin_file ],
				);
				$finding->set_remediation_hint(
					__( 'Wrap calls to wp_ai_client_prompt() in a function_exists( \'wp_ai_client_prompt\' ) check or use is_supported_for_text_generation() before rendering any AI-powered UI.', 'sudowp-radar' )
				);
				$findings[] = $finding;
			}
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

	/**
	 * Returns a human-readable identifier for a callback.
	 */
	private function get_callback_identifier( mixed $cb ): string {
		if ( is_string( $cb ) ) {
			return $cb;
		}
		if ( is_array( $cb ) && count( $cb ) === 2 ) {
			$class = is_object( $cb[0] ) ? get_class( $cb[0] ) : (string) $cb[0];
			return $class . '::' . $cb[1];
		}
		if ( $cb instanceof \Closure ) {
			return '{closure}';
		}
		return '{unknown}';
	}

	/**
	 * Returns a ReflectionFunctionAbstract for a callback, or null if not resolvable.
	 */
	private function get_reflection_for_callback( mixed $cb ): ?\ReflectionFunctionAbstract {
		if ( is_array( $cb ) && count( $cb ) === 2 ) {
			return new \ReflectionMethod( $cb[0], $cb[1] );
		}
		if ( is_string( $cb ) && function_exists( $cb ) ) {
			return new \ReflectionFunction( $cb );
		}
		if ( $cb instanceof \Closure ) {
			return new \ReflectionFunction( $cb );
		}
		if ( is_callable( $cb ) ) {
			return new \ReflectionFunction( \Closure::fromCallable( $cb ) );
		}
		return null;
	}

	/**
	 * Checks if a function source unconditionally returns false with no conditional logic.
	 * Looks for patterns like: return false; with no if/switch/ternary.
	 */
	private function is_unconditional_return_false( string $src ): bool {
		if ( ! str_contains( $src, 'return false' ) && ! str_contains( $src, 'return FALSE' ) ) {
			return false;
		}

		// If the source contains conditional keywords, the return is not unconditional.
		$conditional_keywords = [ 'if ', 'if(', 'switch', 'match(', 'match (' , '?' ];
		foreach ( $conditional_keywords as $keyword ) {
			if ( str_contains( $src, $keyword ) ) {
				return false;
			}
		}

		return true;
	}
}
