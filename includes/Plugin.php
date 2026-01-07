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
        // Check if kill switch is active
        $kill_switch = new KillSwitch();
        if ( $kill_switch->is_active() ) {
            // All enforcement disabled
            $this->log_kill_switch_active();
            return;
        }

        // Initialize core components
        $this->components['logger'] = new ActivityLogger();
        $this->components['rate_limiter'] = new RateLimiter( $this->components['logger'] );
        $this->components['login_gateway'] = new LoginGateway( $this->components['rate_limiter'], $this->components['logger'] );
        $this->components['firewall'] = new Firewall( $this->components['logger'] );

        // Initialize admin interface
        if ( is_admin() ) {
            $this->components['admin'] = new Admin( $this->components['logger'], $kill_switch );
        }

        // Hook components
        foreach ( $this->components as $component ) {
            if ( method_exists( $component, 'hook' ) ) {
                $component->hook();
            }
        }
    }

    /**
     * Log kill switch activation
     */
    private function log_kill_switch_active() {
        $logger = new ActivityLogger();
        $logger->log( 'info', 'Kill switch is active - all enforcement disabled' );
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