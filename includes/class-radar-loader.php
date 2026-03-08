<?php
declare( strict_types=1 );

namespace SudoWP\Radar;

defined( 'ABSPATH' ) || exit;

class Loader {

	public function init(): void {
		( new Capabilities() )->register();
		( new Admin() )->init();
		( new Ajax() )->init();
		( new Abilities() )->init(); // Registers the plugin's own WP Abilities API entries.
	}
}
