<?php
/**
 * Activity Logger
 *
 * @package Saurity
 */

namespace Saurity;

/**
 * ActivityLogger class - human-readable logging with DoS protection
 */
class ActivityLogger {

    /**
     * Cache directory for throttling
     *
     * @var string
     */
    private $cache_dir;

    /**
     * Table existence cache (check once per request)
     *
     * @var bool|null
     */
    private static $table_exists_cache = null;

    /**
     * Constructor
     */
    public function __construct() {
        // Use same cache directory as Firewall/RateLimiter
        $this->cache_dir = sys_get_temp_dir() . '/saurity_firewall';
        if ( ! file_exists( $this->cache_dir ) ) {
            @mkdir( $this->cache_dir, 0755, true );
        }
    }

    /**
     * Log an event with throttling to prevent database DoS
     *
     * @param string $type Event type (info, warning, error, critical).
     * @param string $message Human-readable message.
     * @param array  $context Additional context (ip, username, etc.).
     */
    public function log( $type, $message, $context = [] ) {
        // Check if logging is enabled
        if ( ! $this->is_logging_enabled() ) {
            return;
        }

        $ip_address = $context['ip'] ?? $this->get_client_ip();

        // THROTTLING: Prevent same IP from logging same event too frequently
        // This protects database during attacks (10,000 req/s would = 10,000 DB writes)
        if ( ! $this->should_log( $type, $message, $ip_address ) ) {
            return; // Skip this log entry (duplicate within throttle window)
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'saurity_logs';

        // Check table existence (cached per request, not per log call)
        if ( ! $this->table_exists_cached( $table_name ) ) {
            return;
        }

        $user_login = $context['username'] ?? ( is_user_logged_in() ? wp_get_current_user()->user_login : null );

        // Use WordPress timezone for logging (already in local time)
        $timestamp = current_time( 'mysql' );

        $wpdb->insert(
            $table_name,
            [
                'event_type' => sanitize_text_field( $type ),
                'message' => sanitize_textarea_field( $message ),
                'ip_address' => $ip_address,
                'user_login' => $user_login,
                'created_at' => $timestamp,
            ],
            [ '%s', '%s', '%s', '%s', '%s' ]
        );

        // Clear dashboard cache occasionally (5% chance to avoid constant DB writes)
        // Transient expires naturally anyway, so this is just for freshness
        if ( rand( 1, 20 ) === 1 ) {
            delete_transient( 'saurity_dashboard_data' );
        }

        // Schedule cleanup (doesn't run immediately)
        $this->schedule_cleanup();
    }

    /**
     * Get paginated logs
     *
     * @param int    $page Current page number (1-based).
     * @param int    $per_page Number of logs per page.
     * @param string $type Filter by event type (optional).
     * @param string $search Search term (optional).
     * @return array Array with 'logs' and 'total' keys.
     */
    public function get_logs_paginated( $page = 1, $per_page = 50, $type = '', $search = '' ) {
        global $wpdb;

        $table_name = $wpdb->prefix . 'saurity_logs';

        if ( ! $this->table_exists( $table_name ) ) {
            return [ 'logs' => [], 'total' => 0 ];
        }

        $page = max( 1, absint( $page ) );
        $per_page = absint( $per_page );
        $offset = ( $page - 1 ) * $per_page;

        // Build WHERE clause
        $where_conditions = [];
        
        if ( ! empty( $type ) ) {
            $where_conditions[] = $wpdb->prepare( 'event_type = %s', $type );
        }

        if ( ! empty( $search ) ) {
            $search_term = '%' . $wpdb->esc_like( $search ) . '%';
            $where_conditions[] = $wpdb->prepare(
                '(message LIKE %s OR ip_address LIKE %s OR user_login LIKE %s)',
                $search_term,
                $search_term,
                $search_term
            );
        }

        $where = '';
        if ( ! empty( $where_conditions ) ) {
            $where = ' WHERE ' . implode( ' AND ', $where_conditions );
        }

        // Get total count
        $total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table_name" . $where );

        // Get paginated results
        $sql = "SELECT * FROM $table_name" . $where . " ORDER BY created_at DESC LIMIT $per_page OFFSET $offset";
        $results = $wpdb->get_results( $sql, ARRAY_A );

        // Timestamps are already in WordPress timezone (from current_time)
        // No conversion needed for display

        return [
            'logs' => $results ?: [],
            'total' => $total,
        ];
    }

    /**
     * Get recent logs (legacy method for backwards compatibility)
     *
     * @param int    $limit Number of logs to retrieve.
     * @param string $type Filter by event type (optional).
     * @return array
     */
    public function get_logs( $limit = 100, $type = '' ) {
        $result = $this->get_logs_paginated( 1, $limit, $type );
        return $result['logs'];
    }

    /**
     * Get log counts by type
     *
     * @return array Associative array of event_type => count.
     */
    public function get_log_counts() {
        global $wpdb;

        $table_name = $wpdb->prefix . 'saurity_logs';

        if ( ! $this->table_exists( $table_name ) ) {
            return [];
        }

        $results = $wpdb->get_results(
            "SELECT event_type, COUNT(*) as count FROM $table_name GROUP BY event_type",
            ARRAY_A
        );

        $counts = [
            'all' => 0,
            'info' => 0,
            'warning' => 0,
            'error' => 0,
            'critical' => 0,
        ];

        foreach ( $results as $row ) {
            $counts['all'] += $row['count'];
            $counts[ $row['event_type'] ] = $row['count'];
        }

        return $counts;
    }

    /**
     * Get client IP address securely
     * 
     * SECURITY: Always uses REMOTE_ADDR by default to prevent IP spoofing.
     * Only trusts proxy headers if SAURITY_BEHIND_PROXY constant is defined.
     * 
     * This ensures accurate forensic logs - if attacker sends fake headers,
     * we log their REAL IP, not the spoofed one.
     *
     * @return string
     */
    private function get_client_ip() {
        // Default to REMOTE_ADDR (cannot be spoofed by client)
        $ip = isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';

        // Only check proxy headers if explicitly configured
        // This prevents IP spoofing in logs during forensic analysis
        if ( defined( 'SAURITY_BEHIND_PROXY' ) && SAURITY_BEHIND_PROXY ) {
            $headers = [
                'HTTP_CF_CONNECTING_IP', // Cloudflare
                'HTTP_X_FORWARDED_FOR',  // Standard reverse proxy
                'HTTP_X_REAL_IP',        // Nginx
            ];

            foreach ( $headers as $header ) {
                if ( ! empty( $_SERVER[ $header ] ) ) {
                    $ip_value = sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) );
                    
                    // Handle X-Forwarded-For with multiple IPs
                    if ( strpos( $ip_value, ',' ) !== false ) {
                        $ips = array_map( 'trim', explode( ',', $ip_value ) );
                        $ip = $ips[0];
                    } else {
                        $ip = $ip_value;
                    }
                    break;
                }
            }
        }

        // Validate and return
        return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '0.0.0.0';
    }

    /**
     * Check if logging is enabled
     *
     * @return bool
     */
    private function is_logging_enabled() {
        return (bool) get_option( 'saurity_enable_logging', true );
    }

    /**
     * Check if table exists (cached per request)
     *
     * @param string $table_name Table name.
     * @return bool
     */
    private function table_exists_cached( $table_name ) {
        // Check once per request, cache result
        if ( null !== self::$table_exists_cache ) {
            return self::$table_exists_cache;
        }

        global $wpdb;
        $query = $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name );
        self::$table_exists_cache = (bool) $wpdb->get_var( $query );

        return self::$table_exists_cache;
    }

    /**
     * Check if table exists (legacy method for backwards compatibility)
     *
     * @param string $table_name Table name.
     * @return bool
     */
    private function table_exists( $table_name ) {
        return $this->table_exists_cached( $table_name );
    }

    /**
     * Throttling: Should this event be logged?
     * Prevents same IP from flooding database with identical log entries
     * EXCEPTION: Login events are NEVER throttled for security auditing
     *
     * @param string $type Event type.
     * @param string $message Message.
     * @param string $ip IP address.
     * @return bool True if should log, false if throttled.
     */
    private function should_log( $type, $message, $ip ) {
        // NEVER throttle login events - we need every attempt logged for security
        if ( strpos( $message, 'login' ) !== false || strpos( $message, 'Login' ) !== false ) {
            return true; // Always log login events
        }

        // Create unique key for this event type + message + IP
        $event_key = md5( $type . $message . $ip );
        $file = $this->cache_dir . '/log_' . $event_key;

        // If file exists and is recent (within 10 seconds), skip logging
        if ( file_exists( $file ) && ( time() - filemtime( $file ) < 10 ) ) {
            return false; // Throttled (same event within 10 seconds)
        }

        // Create/update throttle file
        file_put_contents( $file, '1', LOCK_EX );
        return true; // Allow logging
    }

    /**
     * Schedule cleanup (doesn't run immediately)
     */
    private function schedule_cleanup() {
        // Schedule daily cron if not already scheduled
        if ( ! wp_next_scheduled( 'saurity_daily_cleanup' ) ) {
            wp_schedule_event( time(), 'daily', 'saurity_daily_cleanup' );
        }
    }

    /**
     * Run daily cleanup (batched for performance)
     */
    public function run_daily_cleanup() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'saurity_logs';
        
        if ( ! $this->table_exists( $table_name ) ) {
            return;
        }
        
        // Get configurable retention period (default 15 days)
        $retention_days = absint( get_option( 'saurity_log_retention_days', 15 ) );
        $retention_days = max( 1, min( 365, $retention_days ) ); // Ensure within valid range
        
        // Delete in batches to prevent table locking
        $batch_size = 1000;
        $cutoff_date = date( 'Y-m-d H:i:s', strtotime( "-{$retention_days} days" ) );
        
        do {
            $deleted = $wpdb->query(
                $wpdb->prepare(
                    "DELETE FROM $table_name WHERE created_at < %s LIMIT %d",
                    $cutoff_date,
                    $batch_size
                )
            );
            
            // Small delay between batches to prevent load spike
            if ( $deleted > 0 ) {
                usleep( 100000 ); // 0.1 second
            }
        } while ( $deleted === $batch_size );
        
        // Log cleanup completion
        $this->log( 'info', 'Daily log cleanup completed' );
    }

    /**
     * Clear all logs
     */
    public function clear_logs() {
        global $wpdb;

        $table_name = $wpdb->prefix . 'saurity_logs';
        $wpdb->query( "TRUNCATE TABLE $table_name" );
    }

    /**
     * Hook WordPress events for comprehensive logging
     * 
     * NOTE: Login/logout events are handled by LoginGateway (has more context)
     */
    public function hook_wordpress_events() {
        // User authentication events (logout only - login handled by LoginGateway)
        add_action( 'wp_logout', [ $this, 'log_user_logout' ] );
        
        // Post/Page events
        add_action( 'transition_post_status', [ $this, 'log_post_status_change' ], 10, 3 );
        add_action( 'before_delete_post', [ $this, 'log_post_delete' ] );
        
        // User management events
        add_action( 'user_register', [ $this, 'log_user_register' ] );
        add_action( 'delete_user', [ $this, 'log_user_delete' ] );
        add_action( 'profile_update', [ $this, 'log_profile_update' ], 10, 2 );
        
        // Plugin/Theme events
        add_action( 'activated_plugin', [ $this, 'log_plugin_activated' ] );
        add_action( 'deactivated_plugin', [ $this, 'log_plugin_deactivated' ] );
        add_action( 'switch_theme', [ $this, 'log_theme_switch' ], 10, 3 );
        
        // Settings changes
        add_action( 'updated_option', [ $this, 'log_option_update' ], 10, 3 );
        
        // Daily cleanup cron
        add_action( 'saurity_daily_cleanup', [ $this, 'run_daily_cleanup' ] );
    }

    /**
     * Log user logout
     */
    public function log_user_logout() {
        $current_user = wp_get_current_user();
        if ( $current_user->user_login ) {
            $this->log( 'info', sprintf( 'User "%s" logged out', $current_user->user_login ) );
        }
    }

    /**
     * Log post status changes
     */
    public function log_post_status_change( $new_status, $old_status, $post ) {
        if ( $new_status === $old_status ) {
            return;
        }

        $post_type = get_post_type_object( $post->post_type );
        $post_type_name = $post_type ? $post_type->labels->singular_name : $post->post_type;

        if ( $new_status === 'publish' && $old_status !== 'publish' ) {
            $this->log( 'info', sprintf( '%s "%s" published (ID: %d)', $post_type_name, $post->post_title, $post->ID ) );
        } elseif ( $old_status === 'publish' && $new_status !== 'publish' ) {
            $this->log( 'info', sprintf( '%s "%s" unpublished (ID: %d)', $post_type_name, $post->post_title, $post->ID ) );
        } else {
            $this->log( 'info', sprintf( '%s "%s" status changed from %s to %s (ID: %d)', $post_type_name, $post->post_title, $old_status, $new_status, $post->ID ) );
        }
    }

    /**
     * Log post deletion
     */
    public function log_post_delete( $post_id ) {
        $post = get_post( $post_id );
        if ( $post ) {
            $post_type = get_post_type_object( $post->post_type );
            $post_type_name = $post_type ? $post_type->labels->singular_name : $post->post_type;
            $this->log( 'warning', sprintf( '%s "%s" deleted (ID: %d)', $post_type_name, $post->post_title, $post_id ) );
        }
    }

    /**
     * Log user registration
     */
    public function log_user_register( $user_id ) {
        $user = get_userdata( $user_id );
        if ( $user ) {
            $this->log( 'info', sprintf( 'New user registered: "%s" (ID: %d)', $user->user_login, $user_id ) );
        }
    }

    /**
     * Log user deletion
     */
    public function log_user_delete( $user_id ) {
        $user = get_userdata( $user_id );
        if ( $user ) {
            $this->log( 'warning', sprintf( 'User deleted: "%s" (ID: %d)', $user->user_login, $user_id ) );
        }
    }

    /**
     * Log profile updates
     */
    public function log_profile_update( $user_id, $old_user_data ) {
        $user = get_userdata( $user_id );
        if ( $user ) {
            $this->log( 'info', sprintf( 'Profile updated for user "%s" (ID: %d)', $user->user_login, $user_id ) );
        }
    }

    /**
     * Log plugin activation
     */
    public function log_plugin_activated( $plugin ) {
        $this->log( 'info', sprintf( 'Plugin activated: %s', $plugin ) );
    }

    /**
     * Log plugin deactivation
     */
    public function log_plugin_deactivated( $plugin ) {
        $this->log( 'info', sprintf( 'Plugin deactivated: %s', $plugin ) );
    }

    /**
     * Log theme switch
     */
    public function log_theme_switch( $new_name, $new_theme, $old_theme ) {
        $this->log( 'info', sprintf( 'Theme changed from "%s" to "%s"', $old_theme->get( 'Name' ), $new_name ) );
    }

    /**
     * Log option updates (selective logging)
     */
    public function log_option_update( $option, $old_value, $value ) {
        // Only log specific important options to avoid spam
        $monitored_options = [
            'blogname',
            'blogdescription',
            'siteurl',
            'home',
            'admin_email',
            'users_can_register',
            'default_role',
            'permalink_structure',
        ];

        if ( in_array( $option, $monitored_options, true ) ) {
            $this->log( 'info', sprintf( 'Site setting updated: %s', $option ) );
        }
    }
}
