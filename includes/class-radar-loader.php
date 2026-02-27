<?php
declare( strict_types=1 );

namespace SudoWP\Radar;

defined( 'ABSPATH' ) || exit;

class Loader {

	public function init(): void {
		load_plugin_textdomain( RADAR_TEXT_DOMAIN, false, dirname( plugin_basename( RADAR_PLUGIN_FILE ) ) . '/languages' );

		( new Capabilities() )->register();
		( new Admin() )->init();
		( new Ajax() )->init();
		( new Abilities() )->init(); // Registers the plugin's own WP Abilities API entries.
	}
}
