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
			SUDOWP_RADAR_PLUGIN_URL . 'assets/css/radar-admin.css',
			[],
			SUDOWP_RADAR_VERSION
		);

		wp_enqueue_script(
			'radar-admin',
			SUDOWP_RADAR_PLUGIN_URL . 'assets/js/radar-admin.js',
			[ 'jquery' ],
			SUDOWP_RADAR_VERSION,
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
					'run_audit'     => __( 'Run Audit', 'sudowp-radar' ),
					'running'       => __( 'Scanning...', 'sudowp-radar' ),
					'no_findings'   => __( 'No issues found. All abilities look clean.', 'sudowp-radar' ),
					'error'         => __( 'Audit failed. Please try again.', 'sudowp-radar' ),
					'rate_limited'  => __( 'Please wait 30 seconds before running another audit.', 'sudowp-radar' ),
					'no_permission' => __( 'You do not have permission to run this audit.', 'sudowp-radar' ),
				],
			]
		);
	}

	public function render_page(): void {
		if ( ! current_user_can( Capabilities::RUN_AUDIT ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'sudowp-radar' ) );
		}

		$saved = false;
		if ( isset( $_POST['sudowp_radar_settings_nonce'] ) ) {
			check_admin_referer( 'sudowp_radar_save_settings', 'sudowp_radar_settings_nonce' );
			if ( isset( $_POST['sudowp_radar_api_key'] ) ) {
				update_option( 'sudowp_radar_api_key', sanitize_text_field( wp_unslash( $_POST['sudowp_radar_api_key'] ) ) );
				delete_transient( 'sudowp_radar_ds_status' );
				$saved = true;
			}
		}

		$last_report    = get_user_meta( get_current_user_id(), '_radar_last_report', true );
		$dataset_status = Dataset::get_status();
		$status_class   = $dataset_status['enabled'] ? 'radar-premium' : 'radar-free';
		?>
		<div class="wrap radar-wrap">
			<h1><?php esc_html_e( 'SudoWP Radar', 'sudowp-radar' ); ?></h1>

			<?php if ( $saved ) : ?>
			<div class="notice notice-success is-dismissible">
				<p><?php esc_html_e( 'Settings saved.', 'sudowp-radar' ); ?></p>
			</div>
			<?php endif; ?>

			<div class="radar-dataset-status <?php echo esc_attr( $status_class ); ?>">
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

			<?php $this->render_dataset_section( $dataset_status ); ?>
		</div>
		<?php
	}

	private function render_dataset_section( array $dataset_status ): void {
		$api_key = get_option( 'sudowp_radar_api_key', '' );
		?>
		<hr>
		<form method="post" action="">
			<?php wp_nonce_field( 'sudowp_radar_save_settings', 'sudowp_radar_settings_nonce' ); ?>
			<h2><?php esc_html_e( 'Dataset API', 'sudowp-radar' ); ?></h2>
			<table class="form-table" role="presentation">
				<tbody>
					<tr>
						<th scope="row">
							<label for="sudowp_radar_api_key">
								<?php esc_html_e( 'Dataset API Key', 'sudowp-radar' ); ?>
							</label>
						</th>
						<td>
							<input
								type="password"
								id="sudowp_radar_api_key"
								name="sudowp_radar_api_key"
								value="<?php echo esc_attr( $api_key ); ?>"
								class="regular-text"
								autocomplete="off"
							>
							<button type="button" class="button sudowp-toggle-key" data-target="sudowp_radar_api_key">
								<?php esc_html_e( 'Show', 'sudowp-radar' ); ?>
							</button>
							<p class="description">
								<?php esc_html_e( 'Enter your SudoWP Dataset API key to enable vulnerability dataset lookups.', 'sudowp-radar' ); ?>
								<?php if ( '' === $api_key ) : ?>
								<a href="https://sudowp.com/get-api-key/" target="_blank" rel="noopener">
									<?php esc_html_e( 'Get a free API key', 'sudowp-radar' ); ?>
								</a>
								<?php endif; ?>
							</p>
							<p class="description">
								<?php
								if ( '' === $api_key ) {
									esc_html_e( 'Dataset lookups disabled.', 'sudowp-radar' );
									echo ' <a href="' . esc_url( 'https://sudowp.com/get-api-key/' ) . '" target="_blank" rel="noopener">'
										. esc_html__( 'Get a free API key', 'sudowp-radar' )
										. '</a>';
								} elseif ( ! empty( $dataset_status['connected'] ) ) {
									echo esc_html(
										sprintf(
											/* translators: 1: tier name, 2: usage count, 3: daily limit */
											__( 'Connected -- %1$s tier (%2$d / %3$d lookups today)', 'sudowp-radar' ),
											$dataset_status['tier'],
											$dataset_status['usage_today'],
											$dataset_status['daily_limit']
										)
									);
								} else {
									esc_html_e( 'Could not connect to dataset API. Check your key.', 'sudowp-radar' );
								}
								?>
							</p>
						</td>
					</tr>
				</tbody>
			</table>
			<?php submit_button( __( 'Save Settings', 'sudowp-radar' ) ); ?>
		</form>
		<script>
		( function () {
			var btns = document.querySelectorAll( '.sudowp-toggle-key' );
			btns.forEach( function ( btn ) {
				btn.addEventListener( 'click', function () {
					var target = document.getElementById( btn.getAttribute( 'data-target' ) );
					if ( ! target ) {
						return;
					}
					if ( target.type === 'password' ) {
						target.type = 'text';
						btn.textContent = <?php echo wp_json_encode( __( 'Hide', 'sudowp-radar' ) ); ?>;
					} else {
						target.type = 'password';
						btn.textContent = <?php echo wp_json_encode( __( 'Show', 'sudowp-radar' ) ); ?>;
					}
				} );
			} );
		}() );
		</script>
		<?php
	}
}
