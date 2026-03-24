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

	public function execute_audit(): array|\WP_Error {
		if ( ! current_user_can( Capabilities::RUN_AUDIT ) ) {
			return [ 'error' => __( 'Insufficient permissions.', 'sudowp-radar' ) ];
		}

		// Rate limiting -- same transient pattern as AJAX handler.
		$user_id       = get_current_user_id();
		$transient_key = 'radar_last_audit_' . $user_id;

		if ( get_transient( $transient_key ) ) {
			return new \WP_Error(
				'rate_limited',
				__( 'Rate limit exceeded. Please wait 30 seconds between audit requests.', 'sudowp-radar' )
			);
		}

		set_transient( $transient_key, time(), 30 );

		$auditor = new Auditor( new Scanner(), new Rule_Engine() );
		$report  = $auditor->run();
		$data    = $report->to_array();

		// Build agent-oriented summary block.
		$findings = $report->get_findings();

		$by_severity = [
			'critical' => 0,
			'high'     => 0,
			'medium'   => 0,
			'low'      => 0,
			'info'     => 0,
		];
		foreach ( $findings as $f ) {
			if ( isset( $by_severity[ $f->severity ] ) ) {
				++$by_severity[ $f->severity ];
			}
		}

		$severity_order = [ 'critical', 'high', 'medium', 'low', 'info' ];
		$highest        = 'none';
		foreach ( $severity_order as $level ) {
			if ( $by_severity[ $level ] > 0 ) {
				$highest = $level;
				break;
			}
		}

		if ( $by_severity['critical'] > 0 || $by_severity['high'] > 0 ) {
			$recommended_action = 'immediate_review';
		} elseif ( $by_severity['medium'] > 0 ) {
			$recommended_action = 'scheduled_review';
		} else {
			$recommended_action = 'no_action_required';
		}

		$data['summary'] = [
			'total_findings'     => count( $findings ),
			'by_severity'        => $by_severity,
			'highest_severity'   => $highest,
			'audit_timestamp'    => ( new \DateTimeImmutable( 'now', new \DateTimeZone( 'UTC' ) ) )->format( \DateTimeInterface::ATOM ),
			'abilities_scanned'  => $report->get_total_abilities(),
			'recommended_action' => $recommended_action,
		];

		return $data;
	}
}
