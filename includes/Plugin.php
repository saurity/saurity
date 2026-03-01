<?php
/**
 * Main Plugin Class
 *
 * @package Saurity
 */

namespace Saurity;

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Plugin core class - singleton pattern
 */
class Plugin {

    /**
     * Single instance
     *
     * @var Plugin|null
     */
    private static $instance = null;

    /**
     * Components
     *
     * @var array
     */
    private $components = [];

    /**
     * Get singleton instance
     *
     * @return Plugin
     */
    public static function get_instance() {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Private constructor (singleton)
     */
    private function __construct() {
        // Singleton pattern
    }

    /**
     * Initialize plugin
     */
    public function init() {
        // Initialize kill switch first (always needed)
        $kill_switch = new KillSwitch();
        
        // Initialize logger (conditional based on user preference)
        $logger = new ActivityLogger();
        $this->components['logger'] = $logger;
        
        // Initialize email notifier (must work even when kill switch is on)
        $this->components['email_notifier'] = new EmailNotifier( $logger );
        $this->components['email_notifier']->hook();
        
        // Initialize admin interface (always needed for settings access)
        if ( is_admin() ) {
            $this->components['admin'] = new Admin( $logger, $kill_switch );
            $this->components['admin']->hook();
        }

        // Check if kill switch is active
        if ( $kill_switch->is_active() ) {
            // All enforcement disabled - skip security components
            // But email notifier remains active for kill switch/bypass alerts
            
            // Initialize dashboard widget (always available)
            $this->components['dashboard_widget'] = new DashboardWidget( $logger, $kill_switch );
            $this->components['dashboard_widget']->hook();
            
            return;
        }

        // Feature toggles - check user preferences
        $enable_rate_limiting = (bool) get_option( 'saurity_enable_rate_limiting', true );
        $enable_firewall = (bool) get_option( 'saurity_enable_firewall', true );
        $enable_logging = (bool) get_option( 'saurity_enable_logging', true );
        $enable_ip_management = (bool) get_option( 'saurity_enable_ip_management', true );

        // Initialize IP Manager if enabled
        if ( $enable_ip_management ) {
            $this->components['ip_manager'] = new IPManager( $logger );
        }

        // Initialize Rate Limiting & Login Protection if enabled
        if ( $enable_rate_limiting ) {
            $this->components['rate_limiter'] = new RateLimiter( $logger );
            $this->components['login_gateway'] = new LoginGateway( $this->components['rate_limiter'], $logger );
            $this->components['login_gateway']->hook();
        }

        // Initialize Firewall if enabled
        if ( $enable_firewall ) {
            $this->components['firewall'] = new Firewall( $logger );
            $this->components['firewall']->hook();
        }

        // Initialize Warning Display (works with both rate limiting and firewall)
        if ( $enable_rate_limiting || $enable_firewall ) {
            $this->components['warning_display'] = new WarningDisplay();
            $this->components['warning_display']->hook();
        }

        // Hook WordPress events for activity logging if enabled
        if ( $enable_logging ) {
            $logger->hook_wordpress_events();
        }
        
        // Initialize dashboard widget (always available for admins)
        $this->components['dashboard_widget'] = new DashboardWidget( $logger, $kill_switch );
        $this->components['dashboard_widget']->hook();

        // Initialize Security Reports (always available for admins)
        if ( is_admin() ) {
            $this->components['security_reports'] = new SecurityReports( $logger );
            $this->components['security_reports']->hook();

            $this->components['reports_dashboard'] = new ReportsDashboard( $this->components['security_reports'] );
            $this->components['reports_dashboard']->hook();
        }

        // Initialize Privacy Policy integration (GDPR compliance)
        $this->components['privacy_policy'] = new PrivacyPolicy( $logger );
        $this->components['privacy_policy']->hook();

        // Initialize Cloud Integration (optional features)
        $enable_cloud = get_option( 'saurity_cloudflare_enabled', false ) ||
                       get_option( 'saurity_threat_feeds_enabled', false ) ||
                       get_option( 'saurity_geoip_enabled', false );

        if ( $enable_cloud ) {
            $this->components['cloud_integration'] = new CloudIntegration( $logger );
            $this->components['cloud_integration']->hook();
        }

        // Register lightweight cron hooks (actual work is done by CloudIntegration)
        $this->register_cron_hooks();
    }

    /**
     * Get component
     *
     * @param string $name Component name.
     * @return mixed|null
     */
    public function get_component( $name ) {
        return $this->components[ $name ] ?? null;
    }

    /**
     * Register cron hooks for scheduled tasks
     * 
     * NOTE: We use standard WordPress cron instead of inline execution.
     * This avoids memory issues by running heavy tasks in separate requests.
     * 
     * If your host doesn't support WP-Cron properly, set up a real cron job:
     * wget -q -O /dev/null https://yoursite.com/wp-cron.php?doing_wp_cron > /dev/null 2>&1
     */
    private function register_cron_hooks() {
        // Only register the lightweight daily cleanup hook here
        // Other cron hooks are registered by CloudIntegration when enabled
        add_action( 'saurity_daily_cleanup', [ $this, 'run_daily_cleanup' ] );
        
        // Schedule daily cleanup if not already scheduled
        if ( ! wp_next_scheduled( 'saurity_daily_cleanup' ) ) {
            wp_schedule_event( time() + 3600, 'daily', 'saurity_daily_cleanup' );
        }
    }

    /**
     * Run daily cleanup tasks (lightweight)
     * 
     * This only handles quick cleanup operations.
     * Heavy operations like threat feeds are handled separately.
     */
    public function run_daily_cleanup() {
        try {
            // Clean up old logs
            $logger = $this->get_component( 'logger' );
            if ( $logger ) {
                $retention_days = (int) get_option( 'saurity_log_retention_days', 15 );
                $logger->cleanup_old_logs( $retention_days );
            }

            // Clean up expired transients
            $this->cleanup_transients();

        } catch ( \Exception $e ) {
            // Silently fail - cleanup errors should not break the site. Error is intentionally not logged.
            unset( $e );
        }
    }

    /**
     * Cleanup expired Saurity transients
     */
    private function cleanup_transients() {
        global $wpdb;
        
        // Delete expired transients with saurity_ prefix
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Direct DB required for transient cleanup
        $wpdb->query(
            "DELETE a, b FROM {$wpdb->options} a, {$wpdb->options} b
            WHERE a.option_name LIKE '_transient_saurity_%'
            AND b.option_name LIKE '_transient_timeout_saurity_%'
            AND SUBSTRING(a.option_name, 12) = SUBSTRING(b.option_name, 20)
            AND b.option_value < UNIX_TIMESTAMP()"
        );
    }
}
