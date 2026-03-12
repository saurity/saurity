<?php
/**
 * Plugin Installation and Uninstallation
 *
 * @package Saurity
 */

namespace Saurity;

/**
 * Installer class
 */
class Installer {

    /**
     * Run on plugin activation
     */
    public static function activate() {
        global $wpdb;

        $charset_collate = $wpdb->get_charset_collate();
        $table_name = $wpdb->prefix . 'saurity_logs';

        // Create logs table
        $sql = "CREATE TABLE IF NOT EXISTS $table_name (
            id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            event_type varchar(50) NOT NULL,
            message text NOT NULL,
            ip_address varchar(45) DEFAULT NULL,
            user_login varchar(60) DEFAULT NULL,
            context longtext,
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY  (id),
            KEY event_type (event_type),
            KEY ip_address (ip_address),
            KEY created_at (created_at)
        ) $charset_collate;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta( $sql );

        // Create reports table
        $reports_table = $wpdb->prefix . 'saurity_reports';
        $sql_reports = "CREATE TABLE IF NOT EXISTS $reports_table (
            id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            report_type varchar(50) NOT NULL DEFAULT 'weekly',
            start_date datetime NOT NULL,
            end_date datetime NOT NULL,
            report_data longtext NOT NULL,
            security_score int(3) NOT NULL DEFAULT 0,
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY  (id),
            KEY report_type (report_type),
            KEY start_date (start_date),
            KEY created_at (created_at)
        ) $charset_collate;";

        dbDelta( $sql_reports );

        // Create cloud cache table
        // Note: cache_key reduced to 191 chars to fit utf8mb4 index limit (191 * 4 bytes = 764 bytes < 1000)
        $cloud_cache_table = $wpdb->prefix . 'saurity_cloud_cache';
        $sql_cloud_cache = "CREATE TABLE IF NOT EXISTS $cloud_cache_table (
            id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            cache_key varchar(191) NOT NULL,
            cache_type varchar(50) NOT NULL,
            cache_data longtext,
            expires_at datetime NOT NULL,
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY  (id),
            KEY idx_key_type (cache_key, cache_type),
            KEY idx_expires (expires_at)
        ) $charset_collate;";

        dbDelta( $sql_cloud_cache );

        // Create threat feeds table
        $threat_feeds_table = $wpdb->prefix . 'saurity_threat_feeds';
        $sql_threat_feeds = "CREATE TABLE IF NOT EXISTS $threat_feeds_table (
            id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            feed_id varchar(100) NOT NULL,
            feed_ips longtext,
            total_ips int(11) NOT NULL DEFAULT 0,
            last_updated datetime,
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY  (id),
            UNIQUE KEY feed_id (feed_id),
            KEY last_updated (last_updated)
        ) $charset_collate;";

        dbDelta( $sql_threat_feeds );

        // Set default options
        self::set_default_options();

        // Log activation
        $logger = new ActivityLogger();
        $logger->log( 'info', 'Saurity Shield plugin activated' );
    }

    /**
     * Set default plugin options
     */
    private static function set_default_options() {
        $defaults = [
            'saurity_rate_limit_attempts' => 5,
            'saurity_rate_limit_window' => 600, // 10 minutes in seconds
            'saurity_hard_block_attempts' => 20,
            'saurity_hard_block_duration' => 3600, // 1 hour in seconds
            'saurity_progressive_delay' => 2, // seconds per failed attempt
            'saurity_kill_switch' => 0,
            'saurity_emergency_bypass_key' => wp_generate_password( 32, false ),
            'saurity_version' => SAURITY_VERSION,
        ];

        foreach ( $defaults as $key => $value ) {
            if ( false === get_option( $key ) ) {
                add_option( $key, $value );
            }
        }
    }

    /**
     * Run on plugin deactivation
     */
    public static function deactivate() {
        // Clear all transients
        self::clear_transients();

        // Log deactivation
        $logger = new ActivityLogger();
        $logger->log( 'info', 'Saurity plugin deactivated' );
    }

    /**
     * Run on plugin uninstall - Complete cleanup
     * 
     * This method removes ALL plugin data when the plugin is deleted:
     * - Database tables (logs, reports, cache, threat feeds)
     * - All plugin options
     * - File-based rate limiting data
     * - Transients and cached data
     * - Scheduled cron jobs
     * 
     * GDPR Compliance: All personal data (IP addresses, usernames in logs) is deleted.
     */
    public static function uninstall() {
        global $wpdb;

        // ==========================================
        // 1. DROP ALL DATABASE TABLES
        // ==========================================
        $tables = [
            $wpdb->prefix . 'saurity_logs',
            $wpdb->prefix . 'saurity_reports',
            $wpdb->prefix . 'saurity_cloud_cache',
            $wpdb->prefix . 'saurity_threat_feeds',
        ];

        foreach ( $tables as $table ) {
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Table name safe, schema change required for uninstall
            $wpdb->query( "DROP TABLE IF EXISTS {$table}" );
        }

        // ==========================================
        // 2. DELETE ALL PLUGIN OPTIONS
        // ==========================================
        $options = [
            // Core settings
            'saurity_version',
            'saurity_kill_switch',
            'saurity_kill_switch_reason',
            'saurity_kill_switch_activated_at',
            'saurity_emergency_bypass_key',
            'saurity_last_cron_check',
            
            // Feature toggles
            'saurity_enable_rate_limiting',
            'saurity_enable_firewall',
            'saurity_enable_logging',
            'saurity_enable_ip_management',
            'saurity_email_notifications',
            
            // Rate limiting settings
            'saurity_rate_limit_attempts',
            'saurity_rate_limit_window',
            'saurity_hard_block_attempts',
            'saurity_hard_block_duration',
            'saurity_progressive_delay',
            
            // POST flood protection
            'saurity_enable_post_flood',
            'saurity_post_flood_device_limit',
            'saurity_post_flood_ip_limit',
            'saurity_post_flood_window',
            
            // XML-RPC protection
            'saurity_enable_xmlrpc_protection',
            'saurity_xmlrpc_limit',
            'saurity_xmlrpc_window',
            
            // Comment rate limiting
            'saurity_enable_comment_rate_limiting',
            'saurity_comment_rate_limit',
            'saurity_comment_rate_window',
            
            // Request throttling
            'saurity_enable_request_throttle',
            'saurity_request_throttle_limit',
            'saurity_request_throttle_window',
            
            // Advanced security
            'saurity_enable_tarpitting',
            'saurity_tarpit_delay',
            'saurity_enable_subnet_blocking',
            'saurity_subnet_failure_threshold',
            'saurity_enable_honeypot',
            'saurity_enable_timing_check',
            'saurity_min_form_time',
            
            // Email settings
            'saurity_notification_email',
            'saurity_email_reports',
            
            // Logging settings
            'saurity_log_retention_days',
            
            // IP Management (ALLOWLIST & BLOCKLIST)
            'saurity_ip_allowlist',
            'saurity_ip_allowlist_meta',
            'saurity_ip_blocklist',
            'saurity_ip_blocklist_meta',
            
            // Cloudflare integration
            'saurity_cloudflare_enabled',
            'saurity_cloudflare_api_token',
            'saurity_cloudflare_zone_id',
            'saurity_cloudflare_sync_blocklist',
            'saurity_cloudflare_import_events',
            'saurity_cloudflare_last_sync',
            
            // Threat intelligence
            'saurity_threat_feeds_enabled',
            'saurity_threat_feeds_builtin',
            'saurity_threat_feeds_custom',
            'saurity_threat_feeds_update_interval',
            'saurity_threat_feeds_auto_block',
            'saurity_threat_feeds_max_age',
            
            // GeoIP settings
            'saurity_geoip_enabled',
            'saurity_geoip_provider',
            'saurity_geoip_license_key',
            'saurity_geoip_mode',
            'saurity_geoip_blocked_countries',
            'saurity_geoip_allowed_countries',
            'saurity_geoip_show_flags',
            
            // Bypass session tracking
            'saurity_bypass_sessions',
        ];

        foreach ( $options as $option ) {
            delete_option( $option );
        }

        // Also delete any options that might have been created dynamically
        // (options starting with saurity_)
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Direct DB required for cleanup
        $wpdb->query(
            "DELETE FROM {$wpdb->options} 
            WHERE option_name LIKE 'saurity_%'"
        );

        // ==========================================
        // 3. DELETE FILE-BASED RATE LIMITING DATA
        // ==========================================
        self::delete_rate_limit_files();

        // ==========================================
        // 4. CLEAR ALL TRANSIENTS
        // ==========================================
        self::clear_transients();
        
        // ==========================================
        // 5. CLEAR SCHEDULED CRON JOBS
        // ==========================================
        self::clear_cron_jobs();

        // ==========================================
        // 6. DELETE UPLOADS DIRECTORY (GeoIP databases, etc.)
        // ==========================================
        self::delete_uploads_directory();
    }

    /**
     * Clear all Saurity transients
     */
    private static function clear_transients() {
        global $wpdb;

        // Delete all transients starting with 'saurity_'
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Direct DB required for cleanup
        $wpdb->query(
            "DELETE FROM {$wpdb->options} 
            WHERE option_name LIKE '_transient_saurity_%' 
            OR option_name LIKE '_transient_timeout_saurity_%'"
        );
    }

    /**
     * Clear all scheduled cron jobs
     */
    private static function clear_cron_jobs() {
        // List of all Saurity cron hooks
        $cron_hooks = [
            'saurity_cleanup_logs',
            'saurity_daily_cleanup',
            'saurity_cleanup_cloud_cache',
            'saurity_cleanup_old_reports',
            'saurity_update_threat_feeds',
            'saurity_sync_cloudflare',
            'saurity_update_geoip_database',
            'saurity_generate_weekly_report',
        ];

        // Unschedule all cron jobs
        foreach ( $cron_hooks as $hook ) {
            $timestamp = wp_next_scheduled( $hook );
            if ( $timestamp ) {
                wp_unschedule_event( $timestamp, $hook );
            }
            
            // Also clear all scheduled events for this hook (in case there are multiple)
            wp_clear_scheduled_hook( $hook );
        }
    }

    /**
     * Delete file-based rate limiting data
     * 
     * Rate limiter uses file-based counters in wp-content/uploads/saurity/
     * for better performance. These must be deleted on uninstall.
     */
    private static function delete_rate_limit_files() {
        $upload_dir = wp_upload_dir();
        $saurity_dir = $upload_dir['basedir'] . '/saurity';

        // Delete rate limit counter files
        $rate_limit_dir = $saurity_dir . '/rate-limits';
        if ( is_dir( $rate_limit_dir ) ) {
            self::recursive_delete( $rate_limit_dir );
        }

        // Delete any other temp files
        $temp_dir = $saurity_dir . '/temp';
        if ( is_dir( $temp_dir ) ) {
            self::recursive_delete( $temp_dir );
        }
    }

    /**
     * Delete the Saurity uploads directory
     * 
     * Contains GeoIP databases, rate limit files, and other cached data.
     */
    private static function delete_uploads_directory() {
        $upload_dir = wp_upload_dir();
        $saurity_dir = $upload_dir['basedir'] . '/saurity';

        if ( is_dir( $saurity_dir ) ) {
            self::recursive_delete( $saurity_dir );
        }
    }

    /**
     * Recursively delete a directory and its contents using WP_Filesystem
     *
     * @param string $dir Directory path.
     * @return bool Success.
     */
    private static function recursive_delete( $dir ) {
        if ( ! is_dir( $dir ) ) {
            return false;
        }

        // Security check: Only delete within uploads directory
        $upload_dir = wp_upload_dir();
        if ( strpos( realpath( $dir ), realpath( $upload_dir['basedir'] ) ) !== 0 ) {
            return false; // Refuse to delete outside uploads
        }

        // Use WP_Filesystem for recursive directory deletion
        global $wp_filesystem;
        if ( empty( $wp_filesystem ) ) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
            WP_Filesystem();
        }

        // WP_Filesystem::delete with recursive=true handles the entire directory
        return $wp_filesystem->delete( $dir, true );
    }
}
