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
	const VULN_DATASET_MATCH       = 'dataset-match'; // Premium: SudoWP vulnerability dataset.

	public function __construct(
		public readonly string $ability_name,
		public readonly string $severity,
		public readonly string $vuln_class,
		public readonly string $message,
		public readonly string $recommendation,
		public readonly array  $context = [],      // Extra data: file, line, callback name, etc.
		public readonly bool   $is_premium = false, // True for findings from SudoWP dataset.
	) {}

	public function to_array(): array {
		return [
			'ability_name'   => $this->ability_name,
			'severity'       => $this->severity,
			'vuln_class'     => $this->vuln_class,
			'message'        => $this->message,
			'recommendation' => $this->recommendation,
			'context'        => $this->context,
			'is_premium'     => $this->is_premium,
		];
	}
}
