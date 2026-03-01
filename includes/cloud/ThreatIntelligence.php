<?php
/**
 * Threat Intelligence Feeds
 *
 * Manages importing and updating threat intelligence feeds
 * OPTIMIZED: Uses batched processing to prevent resource exhaustion
 *
 * @package Saurity
 */

namespace Saurity\Cloud;

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * ThreatIntelligence class - manages threat feeds and automatic IP blocking
 */
class ThreatIntelligence {

    /**
     * Logger instance
     *
     * @var \Saurity\ActivityLogger
     */
    private $logger;

    /**
     * Batch size for processing IPs
     *
     * @var int
     */
    private $batch_size = 300;

    /**
     * Maximum IPs to process per feed (prevents memory exhaustion)
     *
     * @var int
     */
    private $max_ips_per_feed = 10000;

    /**
     * Built-in threat feeds
     *
     * @var array
     */
    private $builtin_feeds = [
        'emerging_threats' => [
            'name' => 'Emerging Threats',
            'url' => 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
            'format' => 'text',
            'description' => 'Known compromised hosts',
        ],
        'spamhaus' => [
            'name' => 'Spamhaus DROP',
            'url' => 'https://www.spamhaus.org/drop/drop.txt',
            'format' => 'text',
            'description' => 'Don\'t Route Or Peer list',
        ],
        'blocklist_de' => [
            'name' => 'Blocklist.de',
            'url' => 'https://lists.blocklist.de/lists/all.txt',
            'format' => 'text',
            'description' => 'SSH, mail, Apache attackers',
        ],
    ];

    /**
     * Constructor
     *
     * @param \Saurity\ActivityLogger $logger Logger instance.
     */
    public function __construct( $logger ) {
        $this->logger = $logger;
    }

    /**
     * Update all enabled feeds
     *
     * @return array Result with counts.
     */
    public function update_all_feeds() {
        $enabled_feeds = get_option( 'saurity_threat_feeds_builtin', [] );
        $custom_feeds = get_option( 'saurity_threat_feeds_custom', [] );

        $total_added = 0;
        $total_removed = 0;

        // Update built-in feeds
        foreach ( $enabled_feeds as $feed_id ) {
            if ( isset( $this->builtin_feeds[ $feed_id ] ) ) {
                $result = $this->update_feed(
                    $feed_id,
                    $this->builtin_feeds[ $feed_id ]['url'],
                    $this->builtin_feeds[ $feed_id ]['format']
                );

                if ( $result['success'] ) {
                    $total_added += $result['added'];
                    $total_removed += $result['removed'];
                }
            }
        }

        // Update custom feeds
        foreach ( $custom_feeds as $feed ) {
            if ( ! empty( $feed['enabled'] ) && ! empty( $feed['url'] ) ) {
                $result = $this->update_feed(
                    $feed['id'],
                    $feed['url'],
                    $feed['format'] ?? 'text'
                );

                if ( $result['success'] ) {
                    $total_added += $result['added'];
                    $total_removed += $result['removed'];
                }
            }
        }

        // Remove old IPs
        $removed = $this->cleanup_old_ips();
        $total_removed += $removed;

        return [
            'added' => $total_added,
            'removed' => $total_removed,
        ];
    }

    /**
     * Update a single feed (public method for AJAX)
     *
     * @param string $feed_id Feed identifier.
     * @param string $url Feed URL.
     * @param string $format Feed format (text, csv, json).
     * @return array Result.
     */
    public function update_single_feed( $feed_id, $url, $format ) {
        return $this->update_feed( $feed_id, $url, $format );
    }

    /**
     * Update a single feed - OPTIMIZED for memory efficiency
     * ENHANCED: Comprehensive error handling with try-catch
     *
     * @param string $feed_id Feed identifier.
     * @param string $url Feed URL.
     * @param string $format Feed format (text, csv, json).
     * @return array Result.
     */
    private function update_feed( $feed_id, $url, $format ) {
        try {
            $this->logger->log( 'info', "Updating threat feed: {$feed_id}" );

            // Validate URL
            if ( empty( $url ) || ! filter_var( $url, FILTER_VALIDATE_URL ) ) {
                throw new \Exception( "Invalid feed URL: {$url}" );
            }

            // Check if URL is HTTPS (security requirement)
            if ( strpos( $url, 'https://' ) !== 0 && strpos( $url, 'http://' ) !== 0 ) {
                throw new \Exception( "Feed URL must use HTTP or HTTPS protocol" );
            }

            // Download feed with error handling
            $response = wp_remote_get(
                $url,
                [
                    'timeout' => 60,
                    'user-agent' => 'Saurity-Security-Plugin/1.0',
                    'stream' => false,
                    'sslverify' => true, // Verify SSL certificates
                ]
            );

            // Handle WordPress HTTP errors
            if ( is_wp_error( $response ) ) {
                $error_message = $response->get_error_message();
                $error_code = $response->get_error_code();
                
                // Provide helpful error messages
                $friendly_error = $this->get_friendly_http_error( $error_code, $error_message );
                
                $this->logger->log( 'error', "Failed to download feed {$feed_id}: {$friendly_error}" );
                return [
                    'success' => false,
                    'error' => $friendly_error,
                    'added' => 0,
                ];
            }

            // Check HTTP status code
            $status_code = wp_remote_retrieve_response_code( $response );
            
            if ( $status_code === 0 ) {
                throw new \Exception( 'Network error: Could not connect to feed server' );
            }

            if ( $status_code >= 400 && $status_code < 500 ) {
                throw new \Exception( "Feed server returned client error (HTTP {$status_code}). URL may be invalid or access denied." );
            }

            if ( $status_code >= 500 ) {
                throw new \Exception( "Feed server error (HTTP {$status_code}). Try again later." );
            }

            if ( $status_code !== 200 ) {
                throw new \Exception( "Unexpected response (HTTP {$status_code})" );
            }

            $body = wp_remote_retrieve_body( $response );

            if ( empty( $body ) ) {
                throw new \Exception( 'Empty response from feed server' );
            }

            // Check response size
            $body_size = strlen( $body );
            $max_size = 10 * 1024 * 1024; // 10MB limit
            
            if ( $body_size > $max_size ) {
                throw new \Exception( "Feed too large ({$body_size} bytes). Maximum allowed: {$max_size} bytes." );
            }

            // Parse feed in memory-efficient way
            $ips = $this->parse_feed_streaming( $body, $format );
            
            // Free memory from raw body
            unset( $body );
            unset( $response );

            if ( empty( $ips ) ) {
                throw new \Exception( 'No valid IPs found in feed. Check feed format and URL.' );
            }

            // Limit IPs to prevent memory exhaustion
            $total_ips = count( $ips );
            if ( $total_ips > $this->max_ips_per_feed ) {
                $ips = array_slice( $ips, 0, $this->max_ips_per_feed );
                $this->logger->log( 
                    'warning', 
                    "Feed {$feed_id}: Truncated from {$total_ips} to {$this->max_ips_per_feed} IPs"
                );
            }

            // Store feed metadata
            $this->update_feed_metadata( $feed_id, count( $ips ) );

            // Auto-block IPs if enabled - USE BATCH PROCESSING
            $auto_block_enabled = get_option( 'saurity_threat_feeds_auto_block', true );
            $blocked_count = 0;
            
            if ( $auto_block_enabled ) {
                try {
                    $feed_name = $this->builtin_feeds[ $feed_id ]['name'] ?? $feed_id;
                    $blocked_count = $this->bulk_add_to_blocklist( $ips, "Threat Feed: {$feed_name}" );
                } catch ( \Exception $e ) {
                    $this->logger->log( 'error', "Failed to add IPs to blocklist: " . $e->getMessage() );
                    // Don't fail the whole operation if blocklist update fails
                }
            }

            $this->logger->log(
                'info',
                "Feed {$feed_id} updated: " . count( $ips ) . " IPs processed" . 
                ( $auto_block_enabled ? ", {$blocked_count} added to blocklist" : " (auto-block disabled)" )
            );

            return [
                'success' => true,
                'added' => $blocked_count,
                'total_ips' => count( $ips ),
                'removed' => 0,
            ];

        } catch ( \Exception $e ) {
            $this->logger->log( 'error', "Feed {$feed_id} update failed: " . $e->getMessage() );
            
            return [
                'success' => false,
                'error' => $e->getMessage(),
                'added' => 0,
            ];
        }
    }

    /**
     * Get friendly error message for HTTP errors
     *
     * @param string $error_code Error code.
     * @param string $error_message Original error message.
     * @return string Friendly error message.
     */
    private function get_friendly_http_error( $error_code, $error_message ) {
        $common_errors = [
            'http_request_failed' => 'Network connection failed. Check your server can reach external URLs.',
            'http_request_not_executed' => 'Request was not executed. Server may be blocking outbound connections.',
            'ssl_certificate_error' => 'SSL certificate verification failed. Feed server may have invalid certificate.',
            'operation_timedout' => 'Connection timed out. Feed server may be slow or unreachable.',
            'couldnt_connect' => 'Could not connect to feed server. Check if URL is correct.',
            'couldnt_resolve_host' => 'Could not resolve hostname. Check if URL is correct.',
        ];

        // Check for common error patterns
        foreach ( $common_errors as $pattern => $friendly ) {
            if ( stripos( $error_code, $pattern ) !== false || stripos( $error_message, $pattern ) !== false ) {
                return $friendly;
            }
        }

        // Check for timeout
        if ( stripos( $error_message, 'timeout' ) !== false || stripos( $error_message, 'timed out' ) !== false ) {
            return 'Connection timed out. Feed server may be slow or unreachable.';
        }

        // Check for SSL errors
        if ( stripos( $error_message, 'ssl' ) !== false || stripos( $error_message, 'certificate' ) !== false ) {
            return 'SSL/TLS error. Feed server may have certificate issues.';
        }

        // Check for DNS errors
        if ( stripos( $error_message, 'resolve' ) !== false || stripos( $error_message, 'dns' ) !== false ) {
            return 'DNS resolution failed. Check if feed URL is correct.';
        }

        // Return original message if no match
        return $error_message;
    }

    /**
     * Parse feed content in a memory-efficient way
     *
     * @param string $content Feed content.
     * @param string $format Format type.
     * @return array List of IP addresses.
     */
    private function parse_feed_streaming( $content, $format ) {
        $ips = [];
        $count = 0;

        // Process line by line to save memory
        $lines = explode( "\n", $content );
        
        foreach ( $lines as $line ) {
            $line = trim( $line );
            
            // Skip comments and empty lines
            if ( empty( $line ) || $line[0] === '#' || $line[0] === ';' ) {
                continue;
            }

            // Extract IP based on format
            $ip = null;
            
            if ( $format === 'csv' ) {
                $data = str_getcsv( $line );
                $ip = ! empty( $data[0] ) ? trim( $data[0] ) : null;
            } else {
                // For text format, take first word (handles "IP ; comment" formats)
                $parts = preg_split( '/[\s;,]+/', $line, 2 );
                $ip = ! empty( $parts[0] ) ? trim( $parts[0] ) : null;
            }

            // Validate IP
            if ( $ip && $this->validate_ip_or_cidr( $ip ) ) {
                $ips[] = $ip;
                $count++;
                
                // Stop if we hit the limit
                if ( $count >= $this->max_ips_per_feed ) {
                    break;
                }
            }
        }

        // Free memory
        unset( $lines );

        return array_unique( $ips );
    }

    /**
     * Bulk add IPs to blocklist - OPTIMIZED
     * Uses direct database operations instead of individual API calls
     *
     * @param array  $ips Array of IP addresses.
     * @param string $reason Block reason.
     * @return int Number of IPs added.
     */
    private function bulk_add_to_blocklist( $ips, $reason ) {
        $added_count = 0;
        
        // Get current blocklist
        $current_blocklist = get_option( 'saurity_ip_blocklist', [] );
        if ( ! is_array( $current_blocklist ) ) {
            $current_blocklist = [];
        }

        // Get current allowlist to exclude
        $allowlist = get_option( 'saurity_ip_allowlist', [] );
        if ( ! is_array( $allowlist ) ) {
            $allowlist = [];
        }
        
        // Create lookup arrays for fast checking
        $existing_ips = [];
        foreach ( $current_blocklist as $entry ) {
            if ( is_array( $entry ) && isset( $entry['ip'] ) ) {
                $existing_ips[ $entry['ip'] ] = true;
            } elseif ( is_string( $entry ) ) {
                $existing_ips[ $entry ] = true;
            }
        }

        $allowlisted_ips = [];
        foreach ( $allowlist as $entry ) {
            if ( is_array( $entry ) && isset( $entry['ip'] ) ) {
                $allowlisted_ips[ $entry['ip'] ] = true;
            } elseif ( is_string( $entry ) ) {
                $allowlisted_ips[ $entry ] = true;
            }
        }

        // Process IPs in batches
        $batch = [];
        $current_time = current_time( 'mysql' );
        
        foreach ( $ips as $ip ) {
            // Skip if already in blocklist or allowlist
            if ( isset( $existing_ips[ $ip ] ) || isset( $allowlisted_ips[ $ip ] ) ) {
                continue;
            }

            // Add to batch
            $batch[] = [
                'ip' => $ip,
                'reason' => $reason,
                'added' => $current_time,
                'added_by' => 'threat_feed',
            ];
            $added_count++;
            
            // Mark as existing to prevent duplicates within batch
            $existing_ips[ $ip ] = true;

            // Process batch when it reaches the limit
            if ( count( $batch ) >= $this->batch_size ) {
                $current_blocklist = array_merge( $current_blocklist, $batch );
                $batch = [];
                
                // Save periodically to prevent memory buildup
                if ( count( $current_blocklist ) % 1000 === 0 ) {
                    update_option( 'saurity_ip_blocklist', $current_blocklist, false );
                }
            }
        }

        // Add remaining batch
        if ( ! empty( $batch ) ) {
            $current_blocklist = array_merge( $current_blocklist, $batch );
        }

        // Final save (use autoload=false for large lists)
        update_option( 'saurity_ip_blocklist', $current_blocklist, false );

        return $added_count;
    }

    /**
     * Validate IP address or CIDR range
     *
     * @param string $ip IP or CIDR.
     * @return bool
     */
    private function validate_ip_or_cidr( $ip ) {
        // Check if it's a CIDR range
        if ( strpos( $ip, '/' ) !== false ) {
            list( $network, $prefix ) = explode( '/', $ip );
            
            if ( ! filter_var( $network, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
                return false;
            }
            
            $prefix = intval( $prefix );
            return $prefix >= 0 && $prefix <= 32;
        }
        
        // Check if it's a valid IP
        return filter_var( $ip, FILTER_VALIDATE_IP ) !== false;
    }

    /**
     * Update feed metadata (without storing individual IPs)
     *
     * @param string $feed_id Feed identifier.
     * @param int    $total_ips Total IPs in feed.
     */
    private function update_feed_metadata( $feed_id, $total_ips ) {
        global $wpdb;
        $table = $wpdb->prefix . 'saurity_threat_feeds';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Direct DB required for threat feeds, data changes frequently
        $feed = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM {$wpdb->prefix}saurity_threat_feeds WHERE feed_id = %s",
                $feed_id
            )
        );

        if ( $feed ) {
            
            $wpdb->update( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Direct DB required for threat feeds
                $table,
                [
                    'total_ips' => $total_ips,
                    'last_updated' => current_time( 'mysql' ),
                ],
                [ 'feed_id' => $feed_id ]
            );
        } else {
            
            $wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Direct DB required for threat feeds
                $table,
                [
                    'feed_id' => $feed_id,
                    'total_ips' => $total_ips,
                    'last_updated' => current_time( 'mysql' ),
                    'created_at' => current_time( 'mysql' ),
                ]
            );
        }
    }

    /**
     * Cleanup old IPs based on max age setting
     *
     * @return int Number of IPs removed.
     */
    private function cleanup_old_ips() {
        $max_age = (int) get_option( 'saurity_threat_feeds_max_age', 30 );
        
        if ( $max_age <= 0 ) {
            return 0; // Disabled
        }

        global $wpdb;
        $table = $wpdb->prefix . 'saurity_threat_feeds';

        $cutoff_date = gmdate( 'Y-m-d H:i:s', strtotime( "-{$max_age} days" ) );

        // Just delete old feed records (don't try to remove individual IPs)
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Direct DB required for cleanup
        $deleted = $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$wpdb->prefix}saurity_threat_feeds WHERE last_updated < %s",
                $cutoff_date
            )
        );

        if ( $deleted > 0 ) {
            $this->logger->log( 'info', "Cleaned up {$deleted} old threat feed records" );
        }

        return $deleted;
    }

    /**
     * Get built-in feeds
     *
     * @return array
     */
    public function get_builtin_feeds() {
        return $this->builtin_feeds;
    }

    /**
     * Get feed statistics
     *
     * @return array Statistics.
     */
    public function get_statistics() {
        global $wpdb;
        $table = $wpdb->prefix . 'saurity_threat_feeds';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Statistics data changes frequently, caching would provide stale security data
        $feeds = $wpdb->get_results(
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is safe, uses $wpdb->prefix
            "SELECT feed_id, total_ips, last_updated FROM {$wpdb->prefix}saurity_threat_feeds"
        );

        $stats = [
            'total_feeds' => count( $feeds ),
            'total_ips' => 0,
            'feeds' => [],
        ];

        foreach ( $feeds as $feed ) {
            $stats['total_ips'] += (int) $feed->total_ips;
            
            $feed_info = [
                'id' => $feed->feed_id,
                'name' => $this->builtin_feeds[ $feed->feed_id ]['name'] ?? $feed->feed_id,
                'total_ips' => (int) $feed->total_ips,
                'last_updated' => $feed->last_updated,
            ];

            $stats['feeds'][] = $feed_info;
        }

        return $stats;
    }
}