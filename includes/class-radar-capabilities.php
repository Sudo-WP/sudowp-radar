<?php
declare( strict_types=1 );

namespace SudoWP\Radar;

defined( 'ABSPATH' ) || exit;

class Capabilities {

	/**
	 * Custom capability required to run audits.
	 * Granted to administrators by default via filter; never hardcoded to a role.
	 */
	const RUN_AUDIT = 'radar_run_audit';

	public function register(): void {
		// Grant to any user who has manage_options (site administrators).
		add_filter( 'user_has_cap', [ $this, 'grant_to_admin' ], 10, 3 );
	}

	public function grant_to_admin( array $allcaps, array $caps, array $args ): array {
		if ( in_array( self::RUN_AUDIT, $caps, true ) && isset( $allcaps['manage_options'] ) && $allcaps['manage_options'] ) {
			$allcaps[ self::RUN_AUDIT ] = true;
		}
		return $allcaps;
	}
}
