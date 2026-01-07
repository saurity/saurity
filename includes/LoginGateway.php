<?php
/**
 * Login Gateway - Protects wp-login.php and wp-admin
 *
 * @package Saurity
 */

namespace Saurity;

/**
 * LoginGateway class - intercepts and protects login attempts
 */
class LoginGateway {

    /**
     * Rate limiter instance
     *
     * @var RateLimiter
     */
    private $rate_limiter;

    /**
     * Logger instance
     *
     * @var ActivityLogger
     */
    private $logger;

    /**
     * Client IP
     *
     * @var string
     */
    private $client_ip;

    /**
     * Constructor
     *
     * @param RateLimiter    $rate_limiter Rate limiter instance.
     * @param ActivityLogger $logger Logger instance.
     */
    public function __construct( RateLimiter $rate_limiter, ActivityLogger $logger ) {
        $this->rate_limiter = $rate_limiter;
        $this->logger = $logger;
        $this->client_ip = $this->get_client_ip();
    }

    /**
     * Hook into WordPress
     */
    public function hook() {
        // Early check before authentication
        add_action( 'init', [ $this, 'check_access' ], 1 );
        
        // Monitor login attempts
        add_action( 'wp_login', [ $this, 'on_login_success' ], 10, 2 );
        add_action( 'wp_login_failed', [ $this, 'on_login_failure' ], 10, 2 );
    }

    /**
     * Check if access should be allowed
     */
    public function check_access() {
        // Only check on login page or admin access
        if ( ! $this->is_protected_area() ) {
            return;
        }

        // Allow if already logged in and accessing admin
        if ( is_user_logged_in() && is_admin() ) {
            return;
        }

        // Check rate limit
        $check = $this->rate_limiter->check( $this->client_ip );

        if ( $check['limited'] ) {
            if ( $check['action'] === 'block' ) {
                $this->block_request();
            } elseif ( $check['action'] === 'delay' ) {
                $this->rate_limiter->apply_delay( $check['delay'] );
            }
        }
    }

    /**
     * Handle successful login
     *
     * @param string   $user_login Username.
     * @param \WP_User $user User object.
     */
    public function on_login_success( $user_login, $user ) {
        // Reset rate limit on successful login
        $this->rate_limiter->reset( $this->client_ip, $user_login );

        $this->logger->log(
            'info',
            "Successful login for user '$user_login'",
            [ 'ip' => $this->client_ip, 'username' => $user_login ]
        );

        // Reset admin failure tracking
        $kill_switch = new KillSwitch();
        $kill_switch->reset_admin_failures();
    }

    /**
     * Handle failed login
     *
     * @param string    $username Username or email.
     * @param \WP_Error $error Error object.
     */
    public function on_login_failure( $username, $error = null ) {
        // Record the failure
        $this->rate_limiter->record_failure( $this->client_ip, $username );

        // Check if this is an admin account
        $user = get_user_by( 'login', $username );
        if ( ! $user ) {
            $user = get_user_by( 'email', $username );
        }

        $is_admin = false;
        if ( $user && user_can( $user, 'manage_options' ) ) {
            $is_admin = true;
            
            // Track admin failures for kill switch
            $kill_switch = new KillSwitch();
            $kill_switch->track_admin_failure();
        }

        // Check current status
        $check = $this->rate_limiter->check( $this->client_ip, $username );

        $message = "Failed login for user '$username'";
        
        if ( $check['limited'] ) {
            if ( $check['action'] === 'block' ) {
                $message .= ' (hard blocked)';
                $log_type = 'error';
            } elseif ( $check['action'] === 'delay' ) {
                $message .= ' (throttled)';
                $log_type = 'warning';
            } else {
                $log_type = 'info';
            }
        } else {
            $log_type = 'info';
        }

        $this->logger->log(
            $log_type,
            $message,
            [ 'ip' => $this->client_ip, 'username' => $username ]
        );
    }

    /**
     * Check if current request is to protected area
     *
     * @return bool
     */
    private function is_protected_area() {
        global $pagenow;

        // Check if wp-login.php
        if ( $pagenow === 'wp-login.php' ) {
            return true;
        }

        // Check if trying to access wp-admin without being logged in
        if ( is_admin() && ! is_user_logged_in() ) {
            return true;
        }

        return false;
    }

    /**
     * Block the request (return 404)
     */
    private function block_request() {
        // Silent fail - return 404 instead of obvious block message
        status_header( 404 );
        nocache_headers();
        
        // Load 404 template if available
        if ( file_exists( get_404_template() ) ) {
            include get_404_template();
        } else {
            // Fallback minimal 404
            echo '<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>';
        }
        
        exit;
    }

    /**
     * Get client IP address
     *
     * @return string
     */
    private function get_client_ip() {
        $headers = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'REMOTE_ADDR',
        ];

        foreach ( $headers as $header ) {
            if ( ! empty( $_SERVER[ $header ] ) ) {
                $ip = sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) );
                
                if ( strpos( $ip, ',' ) !== false ) {
                    $ips = array_map( 'trim', explode( ',', $ip ) );
                    $ip = $ips[0];
                }

                if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
                    return $ip;
                }
            }
        }

        return '0.0.0.0';
    }
}