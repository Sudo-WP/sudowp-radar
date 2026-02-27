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
	 * Access-gated -- silently returns empty report if capability missing.
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
