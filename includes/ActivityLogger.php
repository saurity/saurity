<?php
/**
 * Activity Logger
 *
 * @package Saurity
 */

namespace Saurity;

/**
 * ActivityLogger class - human-readable logging
 */
class ActivityLogger {

    /**
     * Log an event
     *
     * @param string $type Event type (info, warning, error, critical).
     * @param string $message Human-readable message.
     * @param array  $context Additional context (ip, username, etc.).
     */
    public function log( $type, $message, $context = [] ) {
        global $wpdb;

        $table_name = $wpdb->prefix . 'saurity_logs';

        // Defensive: ensure table exists
        if ( ! $this->table_exists( $table_name ) ) {
            return;
        }

        $ip_address = $context['ip'] ?? $this->get_client_ip();
        $user_login = $context['username'] ?? ( is_user_logged_in() ? wp_get_current_user()->user_login : null );

        // Use WordPress timezone for logging
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

        // Auto-cleanup old logs (keep last 1000 entries)
        $this->cleanup_old_logs( $table_name );
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

        // Convert UTC timestamps to local time for display
        if ( ! empty( $results ) ) {
            foreach ( $results as &$log ) {
                if ( ! empty( $log['created_at'] ) ) {
                    // Convert from UTC to local timezone
                    $utc_time = strtotime( $log['created_at'] . ' UTC' );
                    $log['created_at'] = date_i18n( 'Y-m-d H:i:s', $utc_time );
                }
            }
        }

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
     * Get client IP address
     *
     * @return string
     */
    private function get_client_ip() {
        // Check for proxy headers (common in shared hosting)
        $headers = [
            'HTTP_CF_CONNECTING_IP', // Cloudflare
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'REMOTE_ADDR',
        ];

        foreach ( $headers as $header ) {
            if ( ! empty( $_SERVER[ $header ] ) ) {
                $ip = sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) );
                
                // Handle X-Forwarded-For with multiple IPs
                if ( strpos( $ip, ',' ) !== false ) {
                    $ips = array_map( 'trim', explode( ',', $ip ) );
                    $ip = $ips[0];
                }

                // Basic IPv4/IPv6 validation
                if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
                    return $ip;
                }
            }
        }

        return '0.0.0.0';
    }

    /**
     * Check if table exists
     *
     * @param string $table_name Table name.
     * @return bool
     */
    private function table_exists( $table_name ) {
        global $wpdb;

        $query = $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name );
        return (bool) $wpdb->get_var( $query );
    }

    /**
     * Cleanup old logs
     *
     * Delete logs older than 15 days
     *
     * @param string $table_name Table name.
     */
    private function cleanup_old_logs( $table_name ) {
        global $wpdb;

        // Only run cleanup 1% of the time to reduce overhead
        if ( wp_rand( 1, 100 ) > 1 ) {
            return;
        }

        // Delete logs older than 15 days
        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM $table_name WHERE created_at < %s",
                date( 'Y-m-d H:i:s', strtotime( '-15 days' ) )
            )
        );
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
     */
    public function hook_wordpress_events() {
        // User authentication events
        add_action( 'wp_login', [ $this, 'log_user_login' ], 10, 2 );
        add_action( 'wp_logout', [ $this, 'log_user_logout' ] );
        add_action( 'wp_login_failed', [ $this, 'log_login_failed' ] );
        
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
    }

    /**
     * Log user login
     */
    public function log_user_login( $user_login, $user ) {
        $this->log( 'info', sprintf( 'User "%s" logged in successfully', $user_login ) );
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
     * Log failed login
     */
    public function log_login_failed( $username ) {
        $this->log( 'warning', sprintf( 'Failed login attempt for username "%s"', $username ) );
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
