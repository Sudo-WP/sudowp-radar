<?php
declare( strict_types=1 );

namespace SudoWP\Radar;

defined( 'ABSPATH' ) || exit;

class Scanner {

	/**
	 * Returns an array of ability data arrays from the live registry.
	 * Only callable by users with radar_run_audit capability.
	 *
	 * API notes (verified against WP 6.9 source):
	 *   - wp_get_abilities() returns WP_Ability[] from the singleton registry.
	 *   - WP_Ability properties are protected; getters are used for all fields.
	 *   - execute_callback and permission_callback have no public getters;
	 *     ReflectionProperty is used to read them for security audit purposes.
	 */
	public function get_registered_abilities(): array {
		if ( ! current_user_can( Capabilities::RUN_AUDIT ) ) {
			return [];
		}

		if ( ! function_exists( 'wp_get_abilities' ) ) {
			return [];
		}

		$abilities = [];

		foreach ( wp_get_abilities() as $ability ) {
			if ( $ability instanceof \WP_Ability ) {
				$abilities[] = $this->extract_ability_data( $ability );
			}
		}

		return $abilities;
	}

	/**
	 * Extracts serializable data from a WP_Ability instance.
	 *
	 * WP_Ability exposes name, label, description, category, input_schema,
	 * output_schema, and meta via public getter methods. The execute_callback
	 * and permission_callback properties are protected with no public accessor,
	 * so ReflectionProperty is used to read them. This is intentional: the
	 * scanner is a security audit tool that must inspect callback configuration.
	 */
	private function extract_ability_data( \WP_Ability $ability ): array {
		$permission_callback = null;
		$execute_callback    = null;

		try {
			$perm_prop = new \ReflectionProperty( \WP_Ability::class, 'permission_callback' );
			$perm_prop->setAccessible( true );
			$permission_callback = $perm_prop->getValue( $ability );

			$exec_prop = new \ReflectionProperty( \WP_Ability::class, 'execute_callback' );
			$exec_prop->setAccessible( true );
			$execute_callback = $exec_prop->getValue( $ability );
		} catch ( \ReflectionException ) {
			// Properties inaccessible; callbacks remain null for rule evaluation.
		}

		$name = $ability->get_name();

		return [
			'name'                => $name,
			'label'               => $ability->get_label(),
			'description'         => $ability->get_description(),
			'category'            => $ability->get_category() ?? '',
			'input_schema'        => $ability->get_input_schema() ?? [],
			'output_schema'       => $ability->get_output_schema() ?? [],
			'execute_callback'    => $execute_callback,
			'permission_callback' => $permission_callback,
			'meta'                => $ability->get_meta() ?? [],
			'namespace'           => strstr( $name, '/', true ),
		];
	}
}
