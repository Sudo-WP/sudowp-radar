<?php
declare( strict_types=1 );

namespace SudoWP\Radar;

defined( 'ABSPATH' ) || exit;

class Abilities {

	public function init(): void {
		// Register the 'security' category before any abilities in it are registered.
		// wp_abilities_api_categories_init fires before wp_abilities_api_init.
		add_action( 'wp_abilities_api_categories_init', [ $this, 'register_category' ] );
		add_action( 'wp_abilities_api_init', [ $this, 'register' ] );
	}

	public function register_category(): void {
		wp_register_ability_category(
			'security',
			[
				'label'       => __( 'Security', 'sudowp-radar' ),
				'description' => __( 'Abilities related to site security auditing and monitoring.', 'sudowp-radar' ),
			]
		);
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
			return [ 'error' => __( 'Insufficient permissions.', 'sudowp-radar' ) ];
		}

		$auditor = new Auditor( new Scanner(), new Rule_Engine() );
		return $auditor->run()->to_array();
	}
}
