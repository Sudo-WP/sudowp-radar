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
	 * Used by the AJAX handler and the registered ability callback.
	 */
	public function to_array(): array {
		return [
			'summary'  => $this->get_summary(),
			'findings' => array_map( fn( $f ) => $f->to_array(), $this->findings ),
		];
	}
}
