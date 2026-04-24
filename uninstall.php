<?php
declare( strict_types=1 );

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

// Remove last report from all users.
delete_metadata( 'user', 0, '_radar_last_report', '', true );

// Remove API key option.
delete_option( 'sudowp_radar_api_key' );

global $wpdb;

// Remove rate-limiting transients.
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Uninstall routine. Caching a delete query on uninstall is not appropriate.
$wpdb->query(
	$wpdb->prepare(
		"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s",
		$wpdb->esc_like( '_transient_radar_last_audit_' ) . '%'
	)
);

// Remove dataset cache transients.
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Uninstall routine.
$wpdb->query(
	"DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_sudowp\_radar\_ds\_%' OR option_name LIKE '\_transient\_timeout\_sudowp\_radar\_ds\_%'"
);
