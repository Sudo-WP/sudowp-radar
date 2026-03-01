/**
 * SudoWP Radar -- Admin JavaScript
 *
 * Triggers the AJAX audit call, renders findings sorted by severity,
 * and displays the summary risk score.
 */
( function ( $, config ) {
	'use strict';

	var severityOrder = [ 'critical', 'high', 'medium', 'low', 'info' ];

	/**
	 * Returns a numeric sort weight for a severity string (lower = more severe).
	 */
	function severityWeight( severity ) {
		var idx = severityOrder.indexOf( severity );
		return idx === -1 ? 99 : idx;
	}

	/**
	 * Escapes HTML special characters to prevent XSS when building markup.
	 */
	function esc( text ) {
		return $( '<span>' ).text( String( text ) ).html();
	}

	/**
	 * Returns the CSS score class based on numeric risk score.
	 */
	function scoreClass( score ) {
		if ( score >= 60 ) {
			return 'score-high';
		}
		if ( score >= 25 ) {
			return 'score-medium';
		}
		return 'score-low';
	}

	/**
	 * Renders the full report (summary + findings list) into #radar-results.
	 */
	function renderReport( data ) {
		var $results = $( '#radar-results' );
		$results.empty();

		var summary  = data.summary  || {};
		var findings = data.findings || [];

		// Sort findings by severity (critical first).
		findings.sort( function ( a, b ) {
			return severityWeight( a.severity ) - severityWeight( b.severity );
		} );

		// Risk score.
		var score     = parseInt( summary.risk_score, 10 ) || 0;
		var scoreHtml =
			'<div class="radar-risk-score">' +
				'<span class="radar-risk-score__label">Risk Score</span>' +
				'<span class="radar-risk-score__value ' + esc( scoreClass( score ) ) + '">' + esc( score ) + '/100</span>' +
				'<span class="radar-risk-score__label">' +
					esc( summary.total_abilities || 0 ) + ' abilities scanned &bull; ' +
					esc( summary.total_findings  || 0 ) + ' issues found' +
				'</span>' +
			'</div>';

		// Summary counts by severity.
		var severities = [ 'critical', 'high', 'medium', 'low' ];
		var summaryHtml = '<div class="radar-summary">';
		severities.forEach( function ( sev ) {
			var count = parseInt( summary[ sev ], 10 ) || 0;
			summaryHtml +=
				'<div class="radar-summary__item radar-summary__item--' + esc( sev ) + '">' +
					'<span class="radar-summary__count">' + esc( count ) + '</span>' +
					esc( sev.charAt( 0 ).toUpperCase() + sev.slice( 1 ) ) +
				'</div>';
		} );
		summaryHtml += '</div>';

		$results.append( scoreHtml + summaryHtml );

		// Findings list.
		if ( findings.length === 0 ) {
			$results.append(
				'<div class="radar-no-findings">' + esc( config.strings.no_findings ) + '</div>'
			);
			return;
		}

		var listHtml = '<ul class="radar-findings">';
		findings.forEach( function ( f ) {
			listHtml +=
				'<li class="radar-finding radar-finding--' + esc( f.severity ) + '">' +
					'<div class="radar-finding__header">' +
						'<span class="radar-badge radar-badge--' + esc( f.severity ) + '">' + esc( f.severity ) + '</span>' +
						'<span class="radar-finding__name">' + esc( f.ability_name ) + '</span>' +
						'<span class="radar-finding__vuln-class">' + esc( f.vuln_class ) + '</span>' +
					'</div>' +
					'<p class="radar-finding__message">' + esc( f.message ) + '</p>' +
					'<p class="radar-finding__recommendation">' + esc( f.recommendation ) + '</p>' +
				'</li>';
		} );
		listHtml += '</ul>';

		$results.append( listHtml );
	}

	/**
	 * Shows an error message in #radar-results.
	 */
	function showError( msg ) {
		$( '#radar-results' ).empty().append(
			'<div class="notice notice-error inline"><p>' + esc( msg ) + '</p></div>'
		);
	}

	/**
	 * Runs the audit via AJAX.
	 */
	function runAudit() {
		var $btn     = $( '#radar-run-audit' );
		var $results = $( '#radar-results' );

		$btn.prop( 'disabled', true ).text( config.strings.running );
		$results.empty().append(
			'<div class="radar-loading"><span class="spinner is-active" style="float:none;margin:0"></span> ' +
			esc( config.strings.running ) + '</div>'
		);

		$.ajax( {
			url:      config.ajax_url,
			type:     'POST',
			dataType: 'json',
			data: {
				action: 'radar_run_audit',
				nonce:  config.nonce
			},
			success: function ( response ) {
				if ( response && response.success && response.data ) {
					renderReport( response.data );
				} else {
					var msg = ( response && response.data && response.data.message )
						? response.data.message
						: config.strings.error;
					showError( msg );
				}
			},
			error: function ( xhr ) {
				if ( xhr.status === 429 ) {
					showError( config.strings.rate_limited );
				} else if ( xhr.status === 403 ) {
					showError( config.strings.no_permission );
				} else {
					showError( config.strings.error );
				}
			},
			complete: function () {
				$btn.prop( 'disabled', false ).text( config.strings.run_audit );
			}
		} );
	}

	// Bind events and render any cached report on DOM ready.
	$( function () {
		$( '#radar-run-audit' ).on( 'click', function ( e ) {
			e.preventDefault();
			runAudit();
		} );

		// Render the last cached report immediately on page load if available.
		if ( config.last_report && config.last_report.summary ) {
			renderReport( config.last_report );
		}
	} );

} ( jQuery, window.SudoWPRadar || {} ) );
