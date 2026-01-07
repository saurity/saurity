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
        // Initialize kill switch and logger first (always needed)
        $kill_switch = new KillSwitch();
        $logger = new ActivityLogger();
        
        // Initialize admin interface (always needed for settings access)
        if ( is_admin() ) {
            $this->components['admin'] = new Admin( $logger, $kill_switch );
            $this->components['admin']->hook();
        }

        // Check if kill switch is active
        if ( $kill_switch->is_active() ) {
            // All enforcement disabled - skip security components
            return;
        }

        // Initialize security components only if kill switch is off
        $this->components['logger'] = $logger;
        $this->components['rate_limiter'] = new RateLimiter( $logger );
        $this->components['login_gateway'] = new LoginGateway( $this->components['rate_limiter'], $logger );
        $this->components['firewall'] = new Firewall( $logger );

        // Hook security components
        foreach ( [ 'rate_limiter', 'login_gateway', 'firewall' ] as $component_name ) {
            if ( isset( $this->components[ $component_name ] ) && method_exists( $this->components[ $component_name ], 'hook' ) ) {
                $this->components[ $component_name ]->hook();
            }
        }

        // Hook WordPress events for comprehensive activity logging
        $logger->hook_wordpress_events();
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
