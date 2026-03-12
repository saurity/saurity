/**
 * Saurity Shield Admin Scripts
 *
 * @package Saurity
 */

/* global ajaxurl, saurityFeedsData, saurityCloudflare */

( function ( $ ) {
	'use strict';

	/**
	 * IP Management: Toggle all checkboxes in a list.
	 *
	 * @param {string} listType - 'allowlist' or 'blocklist'
	 */
	window.toggleAllCheckboxes = function ( listType ) {
		var checkAll  = document.getElementById( listType + '-check-all' );
		var checkboxes = document.querySelectorAll( '.' + listType + '-checkbox' );
		checkboxes.forEach( function ( cb ) {
			cb.checked = checkAll.checked;
		} );
		window.updateBulkBar( listType );
	};

	/**
	 * IP Management: Update the bulk action bar visibility and count.
	 *
	 * @param {string} listType - 'allowlist' or 'blocklist'
	 */
	window.updateBulkBar = function ( listType ) {
		var checkboxes = document.querySelectorAll( '.' + listType + '-checkbox:checked' );
		var count      = checkboxes.length;
		var bulkBar    = document.getElementById( listType + '-bulk-bar' );
		var countSpan  = document.getElementById( listType + '-selected-count' );

		if ( count > 0 ) {
			bulkBar.style.display = 'flex';
			countSpan.textContent = count;
		} else {
			bulkBar.style.display = 'none';
		}
	};

	$( document ).ready( function () {

		// Bug Report: Copy system info to clipboard.
		$( '#copy-system-info' ).on( 'click', function () {
			var text     = $( '#system-info-text' ).text();
			var $btn     = $( '#copy-system-info' );
			var original = $btn.text();
			navigator.clipboard.writeText( text ).then( function () {
				$btn.text( '\u2705 Copied!' );
				setTimeout( function () { $btn.text( original ); }, 2000 );
			} );
		} );

		// Bug Report: Copy bug report template to clipboard.
		$( '#copy-bug-template' ).on( 'click', function () {
			var text     = $( '#bug-template-text' ).text();
			var $btn     = $( '#copy-bug-template' );
			var original = $btn.text();
			navigator.clipboard.writeText( text ).then( function () {
				$btn.text( '\u2705 Copied!' );
				setTimeout( function () { $btn.text( original ); }, 2000 );
			} );
		} );

		// Bug Report: Copy feature request template to clipboard.
		$( '#copy-feature-template' ).on( 'click', function () {
			var text     = $( '#feature-template-text' ).text();
			var $btn     = $( '#copy-feature-template' );
			var original = $btn.text();
			navigator.clipboard.writeText( text ).then( function () {
				$btn.text( '\u2705 Copied!' );
				setTimeout( function () { $btn.text( original ); }, 2000 );
			} );
		} );

		// Threat Feeds Updater — only active when saurityFeedsData is localised.
		if ( typeof saurityFeedsData !== 'undefined' ) {
			$( '#saurity-start-feed-update' ).on( 'click', function () {
				var $button      = $( this );
				var $progress    = $( '#saurity-feed-progress' );
				var $current     = $( '#saurity-feed-current' );
				var $progressBar = $( '#saurity-feed-progress-bar' );
				var $results     = $( '#saurity-feed-results' );

				// Collect selected feeds.
				var enabledFeeds = [];
				$( 'input[name="saurity_threat_feeds_builtin[]"]:checked' ).each( function () {
					enabledFeeds.push( $( this ).val() );
				} );

				if ( 0 === enabledFeeds.length ) {
					window.alert( 'Please enable at least one threat feed before updating.' );
					return;
				}

				$button.prop( 'disabled', true ).text( '\u23F3 Updating\u2026' );
				$progress.show();
				$results.empty().hide();

				var totalFeeds  = enabledFeeds.length;
				var currentFeed = 0;
				var results     = [];

				var feedNames = {
					emerging_threats: 'Emerging Threats',
					spamhaus:         'Spamhaus DROP',
					blocklist_de:     'Blocklist.de'
				};

				function processNextFeed() {
					if ( currentFeed >= enabledFeeds.length ) {
						$button.prop( 'disabled', false ).text( '\uD83D\uDD04 Start Update' );
						$progress.hide();
						$current.text( 'Preparing\u2026' );
						$progressBar.css( 'width', '0%' );

						var html = '<div style="margin-top:15px;padding:15px;background:#f8f9fa;border-radius:4px;">';
						html    += '<h4 style="margin:0 0 10px 0;">\u2705 Update Complete</h4>';
						html    += '<ul style="margin:0;font-size:13px;line-height:1.8;">';

						results.forEach( function ( result ) {
							var icon  = result.success ? '\u2705' : '\u274C';
							var color = result.success ? '#28a745' : '#dc3232';
							html     += '<li style="color:' + color + ';">' + icon + ' <strong>' + result.feed + ':</strong> ' + result.message + '</li>';
						} );

						html += '</ul></div>';
						$results.html( html ).show();

						setTimeout( function () { window.location.reload(); }, 3000 );
						return;
					}

					var feedId   = enabledFeeds[ currentFeed ];
					var feedName = feedNames[ feedId ] || feedId;

					$current.text( 'Updating ' + feedName + '\u2026 (' + ( currentFeed + 1 ) + '/' + totalFeeds + ')' );
					$progressBar.css( 'width', ( ( currentFeed / totalFeeds ) * 100 ) + '%' );

					$.ajax( {
						url:  ajaxurl,
						type: 'POST',
						data: {
							action:  'saurity_update_feeds_ajax',
							nonce:   saurityFeedsData.nonce,
							feed_id: feedId
						},
						success: function ( response ) {
							if ( response.success ) {
								results.push( {
									success: true,
									feed:    feedName,
									message: response.data.message + ' (' + response.data.total_ips + ' IPs)'
								} );
							} else {
								results.push( {
									success: false,
									feed:    feedName,
									message: response.data.message || 'Unknown error'
								} );
							}
						},
						error: function ( xhr, status, error ) {
							results.push( {
								success: false,
								feed:    feedName,
								message: 'Network error: ' + error
							} );
						},
						complete: function () {
							currentFeed++;
							$progressBar.css( 'width', ( ( currentFeed / totalFeeds ) * 100 ) + '%' );
							setTimeout( processNextFeed, 500 );
						}
					} );
				}

				processNextFeed();
			} );
		}

		// Cloudflare integration buttons — only active when plugin is configured.
		if ( typeof saurityCloudflare !== 'undefined' ) {

			$( '#saurity-cf-test-connection' ).on( 'click', function () {
				var $btn    = $( this );
				var $status = $( '#saurity-cf-status' );

				$btn.prop( 'disabled', true ).text( '\u23F3 Testing\u2026' );
				$status.html( '<span style="color:#666;">Connecting to Cloudflare API\u2026</span>' );

				$.ajax( {
					url:  ajaxurl,
					type: 'POST',
					data: { action: 'saurity_cloudflare_test', nonce: saurityCloudflare.nonce },
					success: function ( r ) {
						$status.html( r.success
							? '<span style="color:#28a745;">\u2705 ' + r.data.message + '</span>'
							: '<span style="color:#dc3232;">\u274C ' + r.data.message + '</span>'
						);
					},
					error: function () {
						$status.html( '<span style="color:#dc3232;">\u274C Network error</span>' );
					},
					complete: function () {
						$btn.prop( 'disabled', false ).text( '\uD83D\uDD17 Test Connection' );
					}
				} );
			} );

			$( '#saurity-cf-manual-sync' ).on( 'click', function () {
				var $btn    = $( this );
				var $status = $( '#saurity-cf-status' );

				$btn.prop( 'disabled', true ).text( '\u23F3 Syncing\u2026' );
				$status.html( '<span style="color:#666;">Syncing with Cloudflare\u2026</span>' );

				$.ajax( {
					url:  ajaxurl,
					type: 'POST',
					data: { action: 'saurity_cloudflare_sync', nonce: saurityCloudflare.nonce },
					success: function ( r ) {
						if ( r.success ) {
							$status.html( '<span style="color:#28a745;">\u2705 ' + r.data.message + '</span>' );
							setTimeout( function () { location.reload(); }, 2000 );
						} else {
							$status.html( '<span style="color:#dc3232;">\u274C ' + r.data.message + '</span>' );
						}
					},
					error: function () {
						$status.html( '<span style="color:#dc3232;">\u274C Network error</span>' );
					},
					complete: function () {
						$btn.prop( 'disabled', false ).text( '\uD83D\uDD04 Sync Now' );
					}
				} );
			} );

		}

	} );

} )( jQuery );