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
            created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY  (id),
            KEY event_type (event_type),
            KEY ip_address (ip_address),
            KEY created_at (created_at)
        ) $charset_collate;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta( $sql );

        // Set default options
        self::set_default_options();

        // Log activation
        $logger = new ActivityLogger();
        $logger->log( 'info', 'SAURITY plugin activated' );
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
        $logger->log( 'info', 'SAURITY plugin deactivated' );
    }

    /**
     * Run on plugin uninstall
     */
    public static function uninstall() {
        global $wpdb;

        // Drop logs table
        $table_name = $wpdb->prefix . 'saurity_logs';
        $wpdb->query( "DROP TABLE IF EXISTS $table_name" );

        // Delete all options
        $options = [
            'saurity_rate_limit_attempts',
            'saurity_rate_limit_window',
            'saurity_hard_block_attempts',
            'saurity_hard_block_duration',
            'saurity_progressive_delay',
            'saurity_kill_switch',
            'saurity_emergency_bypass_key',
            'saurity_version',
        ];

        foreach ( $options as $option ) {
            delete_option( $option );
        }

        // Clear all transients
        self::clear_transients();
    }

    /**
     * Clear all Saurity transients
     */
    private static function clear_transients() {
        global $wpdb;

        // Delete all transients starting with 'saurity_'
        $wpdb->query(
            "DELETE FROM {$wpdb->options} 
            WHERE option_name LIKE '_transient_saurity_%' 
            OR option_name LIKE '_transient_timeout_saurity_%'"
        );
    }
}