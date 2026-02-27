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
		return apply_filters(
			'radar_dataset_status',
			[
				'enabled'       => false,
				'label'         => __( 'SudoWP Vulnerability Dataset: Not connected. Upgrade to SudoWP Pro.', 'sudowp-radar' ),
				'last_updated'  => null,
				'total_entries' => 0,
			]
		);
	}
}
