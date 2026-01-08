<?php
/**
 * Main Plugin Class
 *
 * @package Saurity
 */

namespace Saurity;

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
}
