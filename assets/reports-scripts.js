/**
 * Saurity Reports Dashboard Scripts
 *
 * @package Saurity
 */

/* global ajaxurl, saurityReports, Chart */

jQuery( document ).ready( function ( $ ) {
	'use strict';

	// Generate report button.
	$( '#generate-report-btn, #generate-first-report' ).on( 'click', function () {
		var $btn         = $( this );
		var originalText = $btn.text();

		$btn.prop( 'disabled', true ).text( 'Generating\u2026' );
		$( '#report-status' ).show().text( 'Generating report\u2026' ).css( 'color', '#2196F3' );

		$.ajax( {
			url:  ajaxurl,
			type: 'POST',
			data: {
				action: 'saurity_generate_report',
				nonce:  saurityReports.generateNonce
			},
			success: function ( response ) {
				if ( response.success ) {
					$( '#report-status' ).text( 'Report generated successfully!' ).css( 'color', '#46b450' );
					setTimeout( function () {
						window.location.reload();
					}, 1000 );
				} else {
					$( '#report-status' ).text( 'Error: ' + response.data ).css( 'color', '#dc3232' );
					$btn.prop( 'disabled', false ).text( originalText );
				}
			},
			error: function () {
				$( '#report-status' ).text( 'Error generating report' ).css( 'color', '#dc3232' );
				$btn.prop( 'disabled', false ).text( originalText );
			}
		} );
	} );

	// Export menu toggle.
	$( '#export-menu-btn' ).on( 'click', function ( e ) {
		e.stopPropagation();
		$( '#export-menu' ).toggle();
	} );

	// Close export menu when clicking outside.
	$( document ).on( 'click', function () {
		$( '#export-menu' ).hide();
	} );

	// Export as PDF.
	$( '#export-pdf-btn' ).on( 'click', function ( e ) {
		e.preventDefault();
		$( '#export-menu' ).hide();

		var reportId  = new URLSearchParams( window.location.search ).get( 'report_id' ) || '';
		var exportUrl = ajaxurl + '?action=saurity_export_pdf&report_id=' + reportId + '&nonce=' + saurityReports.exportNonce;

		$( '#report-status' ).show().text( 'Generating PDF\u2026' ).css( 'color', '#2196F3' );
		window.open( exportUrl, '_blank' );

		setTimeout( function () {
			$( '#report-status' ).hide();
		}, 2000 );
	} );

	// Export as CSV.
	$( '#export-csv-btn' ).on( 'click', function ( e ) {
		e.preventDefault();
		$( '#export-menu' ).hide();

		var reportId  = new URLSearchParams( window.location.search ).get( 'report_id' ) || '';
		var exportUrl = ajaxurl + '?action=saurity_export_csv&report_id=' + reportId + '&nonce=' + saurityReports.exportNonce;

		$( '#report-status' ).show().text( 'Generating CSV\u2026' ).css( 'color', '#2196F3' );
		window.location.href = exportUrl;

		setTimeout( function () {
			$( '#report-status' ).hide();
		}, 2000 );
	} );

	// Render charts if report data is available.
	if ( saurityReports.reportData ) {
		var reportData = saurityReports.reportData;

		// Event Types doughnut chart.
		var eventTypesCtx = document.getElementById( 'eventTypesChart' );
		if ( eventTypesCtx ) {
			new Chart( eventTypesCtx, {
				type: 'doughnut',
				data: {
					labels:   [ 'Info', 'Warning', 'Error', 'Critical' ],
					datasets: [ {
						data: [
							reportData.event_counts.info,
							reportData.event_counts.warning,
							reportData.event_counts.error,
							reportData.event_counts.critical
						],
						backgroundColor: [ '#2196F3', '#ff9800', '#f44336', '#9c27b0' ]
					} ]
				},
				options: {
					responsive: true,
					plugins: { legend: { position: 'bottom' } }
				}
			} );
		}

		// Daily Trend line chart.
		var dailyTrendCtx = document.getElementById( 'dailyTrendChart' );
		if ( dailyTrendCtx && reportData.daily_stats ) {
			var labels = reportData.daily_stats.map( function ( stat ) {
				return new Date( stat.date ).toLocaleDateString( 'en-US', { month: 'short', day: 'numeric' } );
			} );

			new Chart( dailyTrendCtx, {
				type: 'line',
				data: {
					labels:   labels,
					datasets: [
						{
							label:           'Total Events',
							data:            reportData.daily_stats.map( function ( stat ) { return stat.total; } ),
							borderColor:     '#2196F3',
							backgroundColor: 'rgba(33, 150, 243, 0.1)',
							tension:         0.4
						},
						{
							label:           'Warnings',
							data:            reportData.daily_stats.map( function ( stat ) { return stat.warnings; } ),
							borderColor:     '#ff9800',
							backgroundColor: 'rgba(255, 152, 0, 0.1)',
							tension:         0.4
						},
						{
							label:           'Errors',
							data:            reportData.daily_stats.map( function ( stat ) { return stat.errors; } ),
							borderColor:     '#f44336',
							backgroundColor: 'rgba(244, 67, 54, 0.1)',
							tension:         0.4
						}
					]
				},
				options: {
					responsive: true,
					plugins: { legend: { position: 'bottom' } },
					scales:  { y: { beginAtZero: true } }
				}
			} );
		}
	}
} );