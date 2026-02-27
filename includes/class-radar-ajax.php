<?php
declare( strict_types=1 );

namespace SudoWP\Radar;

defined( 'ABSPATH' ) || exit;

class Ajax {

	const NONCE_ACTION = 'radar_run_audit_nonce';

	public function init(): void {
		add_action( 'wp_ajax_radar_run_audit', [ $this, 'handle_run_audit' ] );
		// Deliberately NOT registering wp_ajax_nopriv_ -- no unauthenticated access.
	}

	public function handle_run_audit(): void {
		// 1. Nonce verification.
		if ( ! check_ajax_referer( self::NONCE_ACTION, 'nonce', false ) ) {
			wp_send_json_error( [ 'message' => __( 'Invalid nonce.', 'sudowp-radar' ) ], 403 );
		}

		// 2. Capability check.
		if ( ! current_user_can( Capabilities::RUN_AUDIT ) ) {
			wp_send_json_error( [ 'message' => __( 'Insufficient permissions.', 'sudowp-radar' ) ], 403 );
		}

		// 3. Rate limiting: prevent flooding. One audit per 30 seconds per user.
		$transient_key = 'radar_last_audit_' . get_current_user_id();
		if ( get_transient( $transient_key ) ) {
			wp_send_json_error( [ 'message' => __( 'Please wait before running another audit.', 'sudowp-radar' ) ], 429 );
		}
		set_transient( $transient_key, true, 30 );

		// 4. Run audit.
		$auditor = new Auditor( new Scanner(), new Rule_Engine() );
		$report  = $auditor->run();

		// 5. Store last report in a user-scoped meta (not a global option).
		update_user_meta( get_current_user_id(), '_radar_last_report', $report->to_array() );

		wp_send_json_success( $report->to_array() );
	}
}
