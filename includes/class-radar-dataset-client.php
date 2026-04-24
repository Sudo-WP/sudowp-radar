<?php
declare( strict_types=1 );

namespace SudoWP\Radar;

defined( 'ABSPATH' ) || exit;

class Dataset_Client {

	private const API_BASE  = 'https://api.sudowp.com';
	private const CACHE_TTL = 43200; // 12 hours
	private const TIMEOUT   = 5;

	public static function get_findings( string $ability_name ): array {
		$cache_key = 'sudowp_radar_ds_' . md5( $ability_name );
		$cached    = get_transient( $cache_key );

		if ( false !== $cached ) {
			return $cached;
		}

		$api_key = get_option( 'sudowp_radar_api_key', '' );
		if ( '' === $api_key ) {
			return [];
		}

		$response = wp_remote_post(
			self::API_BASE . '/v1/lookup',
			[
				'headers' => [ 'Content-Type' => 'application/json' ],
				'body'    => wp_json_encode( [
					'ability_name' => $ability_name,
					'api_key'      => $api_key,
				] ),
				'timeout' => self::TIMEOUT,
			]
		);

		if ( is_wp_error( $response ) || wp_remote_retrieve_response_code( $response ) !== 200 ) {
			return [];
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( ! isset( $body['found'] ) || ! $body['found'] || empty( $body['findings'] ) ) {
			set_transient( $cache_key, [], self::CACHE_TTL );
			return [];
		}

		$findings = [];
		foreach ( $body['findings'] as $item ) {
			if ( empty( $item['severity'] ) || empty( $item['vuln_class'] ) ) {
				continue;
			}
			$finding = new Finding(
				ability_name:   $ability_name,
				severity:       strtolower( $item['severity'] ),
				vuln_class:     $item['vuln_class'],
				message:        $item['message'] ?? __( 'Dataset vulnerability match.', 'sudowp-radar' ),
				recommendation: $item['patch_url'] ?? '',
				is_premium:     true,
			);
			if ( ! empty( $item['remediation_hint'] ) ) {
				$finding->set_remediation_hint( $item['remediation_hint'] );
			}
			$findings[] = $finding;
		}

		set_transient( $cache_key, $findings, self::CACHE_TTL );
		return $findings;
	}

	public static function get_status(): array {
		$cache_key = 'sudowp_radar_ds_status';
		$cached    = get_transient( $cache_key );

		if ( false !== $cached ) {
			return $cached;
		}

		$api_key = get_option( 'sudowp_radar_api_key', '' );
		if ( '' === $api_key ) {
			return [ 'connected' => false, 'tier' => '', 'usage_today' => 0, 'daily_limit' => 0 ];
		}

		$response = wp_remote_post(
			self::API_BASE . '/v1/status',
			[
				'headers' => [ 'Content-Type' => 'application/json' ],
				'body'    => wp_json_encode( [ 'api_key' => $api_key ] ),
				'timeout' => self::TIMEOUT,
			]
		);

		if ( is_wp_error( $response ) || wp_remote_retrieve_response_code( $response ) !== 200 ) {
			$status = [ 'connected' => false, 'tier' => '', 'usage_today' => 0, 'daily_limit' => 0 ];
			set_transient( $cache_key, $status, 3600 );
			return $status;
		}

		$body   = json_decode( wp_remote_retrieve_body( $response ), true );
		$status = [
			'connected'   => (bool) ( $body['connected'] ?? false ),
			'tier'        => sanitize_text_field( $body['tier'] ?? '' ),
			'usage_today' => absint( $body['usage_today'] ?? 0 ),
			'daily_limit' => absint( $body['daily_limit'] ?? 0 ),
		];

		set_transient( $cache_key, $status, 3600 );
		return $status;
	}
}
