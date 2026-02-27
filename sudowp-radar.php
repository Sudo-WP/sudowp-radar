<?php
/**
 * Plugin Name: SudoWP Radar
 * Plugin URI:  https://sudowp.com/sudowp-radar
 * Description: Security auditor for the WordPress 6.9+ Abilities API. Scans every registered ability for permission misconfigurations, input schema gaps, REST exposure risks, and namespace collisions.
 * Version:     1.0.0
 * Author:      SudoWP
 * Author URI:  https://sudowp.com
 * License:     GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: sudowp-radar
 * Domain Path: /languages
 * Requires at least: 6.9
 * Requires PHP:  8.1
 *
 * @package SudoWP\Radar
 */

declare( strict_types=1 );

namespace SudoWP\Radar;

// Prevent direct access.
defined( 'ABSPATH' ) || exit;

// Bail early if WP Abilities API is not available.
if ( ! function_exists( 'wp_register_ability' ) ) {
	add_action(
		'admin_notices',
		function () {
			echo '<div class="notice notice-error"><p>' .
				esc_html__( 'SudoWP Radar requires WordPress 6.9 or higher with the Abilities API enabled.', 'sudowp-radar' ) .
				'</p></div>';
		}
	);
	return;
}

// Constants.
define( 'RADAR_VERSION',     '1.0.0' );
define( 'RADAR_PLUGIN_FILE', __FILE__ );
define( 'RADAR_PLUGIN_DIR',  plugin_dir_path( __FILE__ ) );
define( 'RADAR_PLUGIN_URL',  plugin_dir_url( __FILE__ ) );
define( 'RADAR_TEXT_DOMAIN', 'sudowp-radar' );

// Autoloader.
// Note: namespace separator is backslash; double-escaped in single-quoted string.
spl_autoload_register(
	function ( string $class ): void {
		$prefix = 'SudoWP\\Radar\\';
		if ( ! str_starts_with( $class, $prefix ) ) {
			return;
		}
		$relative = substr( $class, strlen( $prefix ) );
		$file     = RADAR_PLUGIN_DIR . 'includes/class-radar-' . strtolower( str_replace( '_', '-', $relative ) ) . '.php';
		if ( file_exists( $file ) ) {
			require_once $file;
		}
	}
);

// Bootstrap.
add_action(
	'plugins_loaded',
	function (): void {
		$loader = new Loader();
		$loader->init();
	}
);
