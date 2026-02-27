<?php
defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

// Remove last report from all users.
delete_metadata( 'user', 0, '_radar_last_report', '', true );

// Remove rate-limiting transients.
global $wpdb;
$wpdb->query(
	$wpdb->prepare(
		"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s",
		$wpdb->esc_like( '_transient_radar_last_audit_' ) . '%'
	)
);
