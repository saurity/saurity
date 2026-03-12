<?php
/**
 * Login Gateway
 *
 * @package Saurity
 */

namespace Saurity;

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

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
        // Early check for blocked IPs
        add_action( 'init', [ $this, 'check_ip_blocklist' ], 1 );

        // Check access before protected areas
        add_action( 'init', [ $this, 'check_access' ], 2 );

        // Enqueue login-page warning styles
        add_action( 'login_enqueue_scripts', [ $this, 'enqueue_login_styles' ] );

        // Display warning on login page if approaching limit
        add_action( 'login_header', [ $this, 'display_login_warning' ] );

        // Add honeypot and timing fields to login form
        add_action( 'login_form', [ $this, 'add_bot_detection_fields' ] );

        // Monitor login attempts
        add_action( 'wp_login', [ $this, 'on_login_success' ], 10, 2 );
        add_action( 'wp_login_failed', [ $this, 'on_login_failure' ], 10, 2 );
    }

    /**
     * Enqueue warning styles on the login page
     */
    public function enqueue_login_styles() {
        $css = '
            .saurity-login-warning {
                padding: 15px;
                margin: 0 0 20px 0;
                border-radius: 4px;
                border: 1px solid;
                border-left-width: 4px;
            }
            .saurity-login-warning--hard {
                background: #fff3cd;
                border-color: #ffc107;
                border-left-color: #ff5722;
            }
            .saurity-login-warning--hard strong { color: #721c24; font-size: 15px; }
            .saurity-login-warning--hard p { margin: 8px 0 0 0; color: #721c24; font-size: 13px; line-height: 1.5; }
            .saurity-login-warning--hard .saurity-remaining { background: #ff5722; }
            .saurity-login-warning--soft {
                background: #fff3e0;
                border-color: #ff9800;
                border-left-color: #ff9800;
            }
            .saurity-login-warning--soft strong { color: #856404; font-size: 15px; }
            .saurity-login-warning--soft p { margin: 8px 0 0 0; color: #856404; font-size: 13px; line-height: 1.5; }
            .saurity-login-warning--soft .saurity-remaining { background: #ff9800; }
            .saurity-login-warning .warning-icon { font-size: 20px; margin-right: 10px; vertical-align: middle; }
            .saurity-remaining {
                display: inline-block;
                color: white;
                padding: 3px 8px;
                border-radius: 3px;
                font-weight: bold;
                font-size: 14px;
            }
        ';
        wp_add_inline_style( 'login', $css );
    }
    
    /**
     * Add honeypot and timing check fields to login form
     */
    public function add_bot_detection_fields() {
        // Get Firewall instance to generate token
        $plugin = \Saurity\Plugin::get_instance();
        $firewall = $plugin->get_component( 'firewall' );
        
        if ( ! $firewall ) {
            return;
        }
        
        // Generate timing token
        $timing_token = $firewall->generate_form_token();
        
        ?>
        <!-- Honeypot Field (hidden, bots will fill it) -->
        <input type="text" 
               name="website_url_check" 
               value="" 
               autocomplete="off" 
               tabindex="-1"
               style="position: absolute !important; left: -9999px !important; width: 1px !important; height: 1px !important; opacity: 0 !important; pointer-events: none !important;" 
               aria-hidden="true" />
        
        <!-- Timing Token (encrypted timestamp for bot detection) -->
        <input type="hidden" 
               name="saurity_form_time" 
               value="<?php echo esc_attr( $timing_token ); ?>" />
        <?php
    }
    
    /**
     * Display warning notice on login page if user is approaching rate limit
     */
    public function display_login_warning() {
        // Check if warning flag is set (soft limit warning)
        $soft_warning_key = 'saurity_login_warning_' . md5( $this->client_ip );
        $soft_warning = get_transient( $soft_warning_key );
        
        // Check if approaching hard block (critical warning)
        $hard_warning_key = 'saurity_rate_warning_' . md5( $this->client_ip );
        $hard_warning = get_transient( $hard_warning_key );
        
        if ( $hard_warning ) {
            // CRITICAL: Approaching hard block
            ?>
            <div class="saurity-login-warning saurity-login-warning--hard">
                <span class="warning-icon">⚠️</span>
                <strong>CRITICAL: Approaching Account Lock</strong>
                <p>
                    You have <span class="saurity-remaining"><?php echo esc_html( $hard_warning['remaining'] ); ?> attempts remaining</span> 
                    before your IP is temporarily blocked for 1 hour.
                </p>
                <p style="margin-top: 10px;">
                    <strong>Important:</strong> If you've forgotten your password, use the "Lost your password?" link below 
                    instead of guessing. Continued failed attempts will result in automatic blocking.
                </p>
            </div>
            <?php
            // Keep the warning for next attempt
        } elseif ( $soft_warning ) {
            // WARNING: Approaching soft limit (rate limiting will start)
            ?>
            <div class="saurity-login-warning saurity-login-warning--soft">
                <span class="warning-icon">⚠️</span>
                <strong>Login Attempt Warning</strong>
                <p>
                    You have <span class="saurity-remaining"><?php echo esc_html( $soft_warning['remaining'] ); ?> attempts remaining</span> 
                    before rate limiting is applied (increasing delays between attempts).
                </p>
                <p style="margin-top: 10px;">
                    💡 <strong>Tip:</strong> Double-check your username and password carefully. 
                    If you've forgotten your password, click "Lost your password?" below.
                </p>
            </div>
            <?php
            // Keep the warning for next attempt
        }
    }

    /**
     * Check if current IP is permanently blocked
     */
    public function check_ip_blocklist() {
        $plugin = \Saurity\Plugin::get_instance();
        $ip_manager = $plugin->get_component( 'ip_manager' );
        
        if ( ! $ip_manager ) {
            return;
        }

        $ip = $this->get_client_ip();

        // Check permanent blocklist
        if ( $ip_manager->is_blocked( $ip ) ) {
            wp_die(
                '<h1>Access Denied</h1><p>Your IP address has been permanently blocked.</p>',
                'Access Denied',
                [ 'response' => 403 ]
            );
        }
    }

    /**
     * Check access to protected areas
     */
    public function check_access() {
        // Skip if not protected area
        if ( ! $this->is_protected_area() ) {
            return;
        }

        // Allow if already logged in and accessing admin
        if ( is_user_logged_in() && is_admin() ) {
            return;
        }

        // Check allowlist (trusted IPs bypass all security)
        $plugin = \Saurity\Plugin::get_instance();
        $ip_manager = $plugin->get_component( 'ip_manager' );
        
        if ( $ip_manager && $ip_manager->is_allowed( $this->client_ip ) ) {
            return; // Allowlisted IPs bypass rate limiting
        }

        // Check rate limit
        $check = $this->rate_limiter->check( $this->client_ip );

        if ( $check['limited'] ) {
            // Use new enforce() method instead of apply_delay()
            // enforce() returns 429 and exits immediately (no sleep)
            $this->rate_limiter->enforce( $check );
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
            
            // Track admin failures for monitoring (does NOT auto-disable)
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
                $message .= ' (rate limited)';
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
            [ 'ip' => $this->client_ip, 'username' => $username, 'is_admin' => $is_admin ]
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
