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

        $wpdb->insert(
            $table_name,
            [
                'event_type' => sanitize_text_field( $type ),
                'message' => sanitize_textarea_field( $message ),
                'ip_address' => $ip_address,
                'user_login' => $user_login,
            ],
            [ '%s', '%s', '%s', '%s' ]
        );

        // Auto-cleanup old logs (keep last 1000 entries)
        $this->cleanup_old_logs( $table_name );
    }

    /**
     * Get recent logs
     *
     * @param int    $limit Number of logs to retrieve.
     * @param string $type Filter by event type (optional).
     * @return array
     */
    public function get_logs( $limit = 100, $type = '' ) {
        global $wpdb;

        $table_name = $wpdb->prefix . 'saurity_logs';

        if ( ! $this->table_exists( $table_name ) ) {
            return [];
        }

        $limit = absint( $limit );
        $sql = "SELECT * FROM $table_name";

        if ( ! empty( $type ) ) {
            $sql .= $wpdb->prepare( ' WHERE event_type = %s', $type );
        }

        $sql .= " ORDER BY created_at DESC LIMIT $limit";

        $results = $wpdb->get_results( $sql, ARRAY_A );

        return $results ?: [];
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
     * Keep only the last 1000 entries
     *
     * @param string $table_name Table name.
     */
    private function cleanup_old_logs( $table_name ) {
        global $wpdb;

        // Only run cleanup 1% of the time to reduce overhead
        if ( wp_rand( 1, 100 ) > 1 ) {
            return;
        }

        $wpdb->query(
            "DELETE FROM $table_name 
            WHERE id NOT IN (
                SELECT id FROM (
                    SELECT id FROM $table_name 
                    ORDER BY created_at DESC 
                    LIMIT 1000
                ) as keep_logs
            )"
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
}