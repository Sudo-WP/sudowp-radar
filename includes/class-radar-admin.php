<?php
declare( strict_types=1 );

namespace SudoWP\Radar;

defined( 'ABSPATH' ) || exit;

class Admin {

	public function init(): void {
		add_action( 'admin_menu', [ $this, 'register_menu' ] );
		add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_assets' ] );
	}

	public function register_menu(): void {
		add_menu_page(
			__( 'SudoWP Radar', 'sudowp-radar' ),
			__( 'Radar', 'sudowp-radar' ),
			Capabilities::RUN_AUDIT,
			'sudowp-radar',
			[ $this, 'render_page' ],
			'dashicons-shield',
			81
		);
	}

	public function enqueue_assets( string $hook ): void {
		if ( 'toplevel_page_sudowp-radar' !== $hook ) {
			return;
		}

		wp_enqueue_style(
			'radar-admin',
			RADAR_PLUGIN_URL . 'assets/css/radar-admin.css',
			[],
			RADAR_VERSION
		);

		wp_enqueue_script(
			'radar-admin',
			RADAR_PLUGIN_URL . 'assets/js/radar-admin.js',
			[ 'jquery' ],
			RADAR_VERSION,
			true
		);

		// Fetch last report so JS can render it on page load without a separate AJAX call.
		$last_report = get_user_meta( get_current_user_id(), '_radar_last_report', true );

		// Localize only what JS needs -- never leak sensitive data.
		wp_localize_script(
			'radar-admin',
			'SudoWPRadar',
			[
				'ajax_url'       => admin_url( 'admin-ajax.php' ),
				'nonce'          => wp_create_nonce( Ajax::NONCE_ACTION ),
				'dataset_status' => Dataset::get_status(),
				'last_report'    => $last_report ?: null,
				'strings'        => [
					'run_audit'    => __( 'Run Audit', 'sudowp-radar' ),
					'running'      => __( 'Scanning...', 'sudowp-radar' ),
					'no_findings'  => __( 'No issues found. All abilities look clean.', 'sudowp-radar' ),
					'error'        => __( 'Audit failed. Please try again.', 'sudowp-radar' ),
					'rate_limited' => __( 'Please wait 30 seconds before running another audit.', 'sudowp-radar' ),
					'no_permission' => __( 'You do not have permission to run this audit.', 'sudowp-radar' ),
				],
			]
		);
	}

	public function render_page(): void {
		if ( ! current_user_can( Capabilities::RUN_AUDIT ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'sudowp-radar' ) );
		}

		$last_report    = get_user_meta( get_current_user_id(), '_radar_last_report', true );
		$dataset_status = Dataset::get_status();
		$status_class   = esc_attr( $dataset_status['enabled'] ? 'radar-premium' : 'radar-free' );
		?>
		<div class="wrap radar-wrap">
			<h1><?php esc_html_e( 'SudoWP Radar', 'sudowp-radar' ); ?></h1>

			<div class="radar-dataset-status <?php echo $status_class; ?>">
				<?php echo esc_html( $dataset_status['label'] ); ?>
			</div>

			<button id="radar-run-audit" class="button button-primary">
				<?php esc_html_e( 'Run Audit', 'sudowp-radar' ); ?>
			</button>

			<div id="radar-results">
				<?php if ( $last_report ) : ?>
					<p class="radar-cached-notice"><?php esc_html_e( 'Showing last audit results.', 'sudowp-radar' ); ?></p>
					<!-- JS will re-render from cached data on page load -->
				<?php endif; ?>
			</div>
		</div>
		<?php
	}
}
