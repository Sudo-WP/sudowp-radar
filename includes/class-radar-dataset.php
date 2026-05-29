<?php
declare( strict_types=1 );

namespace SudoWP\Radar;

defined( 'ABSPATH' ) || exit;

/**
 * SudoWP Vulnerability Dataset
 *
 * Wires Dataset_Client into the four premium extension filters so that
 * an API key is the only prerequisite for dataset lookups. External
 * premium code can still hook the same filters to augment or override
 * the built-in Dataset_Client behaviour.
 *
 * Premium filter contract:
 *   radar_dataset_enabled        -- return bool
 *   radar_dataset_findings       -- return Finding[] (non-Finding values stripped)
 *   radar_dataset_status         -- return status array
 *   radar_audit_findings         -- return Finding[] (called once per full audit)
 *   radar_hosting_vendor_slugs   -- return string[] of ability namespace slugs to flag as
 *                                   hosting-injected (M10: HOSTING_INJECTED_ABILITY rule).
 *                                   Default: [] (free tier emits no findings without this list).
 */
class Dataset {

	const FILTER_FINDINGS = 'radar_dataset_findings';
	const FILTER_ENABLED  = 'radar_dataset_enabled';

	/**
	 * Returns whether dataset lookups are enabled.
	 * True when an API key is configured; overrideable via filter.
	 */
	public static function is_enabled(): bool {
		return (bool) apply_filters( 'radar_dataset_enabled', '' !== get_option( 'sudowp_radar_api_key', '' ) );
	}

	/**
	 * Returns dataset-matched findings for a given ability.
	 * Calls Dataset_Client when enabled; premium code can inject more via filter.
	 *
	 * @param array $ability Ability data from Scanner.
	 * @return Finding[]
	 */
	public static function get_findings( array $ability ): array {
		$ability_name = $ability['name'] ?? '';
		$base         = ( self::is_enabled() && '' !== $ability_name )
			? Dataset_Client::get_findings( $ability_name )
			: [];

		$findings = apply_filters( 'radar_dataset_findings', $base, $ability );

		// Validate that whatever code returns are actual Finding objects.
		return array_filter( $findings, fn( $f ) => $f instanceof Finding );
	}

	/**
	 * Returns a summary of the dataset status for display in the admin UI.
	 * Includes both the new client keys (connected, tier, usage_today, daily_limit)
	 * and the legacy keys (enabled, label, last_updated, total_entries) for
	 * backward compatibility with any external premium code using this method.
	 */
	public static function get_status(): array {
		$api_key = get_option( 'sudowp_radar_api_key', '' );

		if ( '' === $api_key ) {
			return apply_filters(
				'radar_dataset_status',
				[
					'enabled'       => false,
					'label'         => __( 'Vulnerability dataset: not active.', 'sudowp-radar' ),
					'last_updated'  => null,
					'total_entries' => 0,
					'connected'     => false,
					'tier'          => '',
					'usage_today'   => 0,
					'daily_limit'   => 0,
				]
			);
		}

		$client = Dataset_Client::get_status();
		$label  = $client['connected']
			? sprintf(
				/* translators: 1: tier name, 2: usage count, 3: daily limit */
				__( 'Connected -- %1$s tier (%2$d / %3$d lookups today)', 'sudowp-radar' ),
				$client['tier'],
				$client['usage_today'],
				$client['daily_limit']
			)
			: __( 'Could not connect to dataset API. Check your key.', 'sudowp-radar' );

		return apply_filters(
			'radar_dataset_status',
			array_merge(
				$client,
				[
					'enabled'       => $client['connected'],
					'label'         => $label,
					'last_updated'  => null,
					'total_entries' => 0,
				]
			)
		);
	}
}
