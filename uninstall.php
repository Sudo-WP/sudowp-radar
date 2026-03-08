<?php
declare( strict_types=1 );

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

// Remove last report from all users.
delete_metadata( 'user', 0, '_radar_last_report', '', true );

// Remove rate-limiting transients.
global $wpdb;
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Uninstall routine. Caching a delete query on uninstall is not appropriate.
$wpdb->query(
	$wpdb->prepare(
		"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s",
		$wpdb->esc_like( '_transient_radar_last_audit_' ) . '%'
	)
);
