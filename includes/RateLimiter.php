<?php
/**
 * Rate Limiter
 *
 * @package Saurity
 */

namespace Saurity;

/**
 * RateLimiter class - Handles ALL frequency/velocity checks
 * Extends SecurityComponent for thread-safe operations
 */
class RateLimiter extends SecurityComponent {

    /**
     * Constructor
     *
     * @param ActivityLogger $logger Logger instance.
     */
    public function __construct( ActivityLogger $logger ) {
        // Use 'rl_' prefix to isolate RateLimiter files from other components
        parent::__construct( $logger, 'rl_' );
    }

    /**
     * Hook into WordPress
     */
    public function hook() {
        // Hook is handled by LoginGateway for login rate limiting
        // This class is called directly by Firewall and LoginGateway
    }

    /**
     * Check if IP or username is rate limited (Login attempts)
     *
     * @param string $ip IP address.
     * @param string $username Username (optional).
     * @return array ['limited' => bool, 'action' => string, 'delay' => int, 'warning' => bool, 'remaining' => int]
     */
    public function check( $ip, $username = '' ) {
        // Run garbage collector
        $this->garbage_collector();

        // 0. Check Subnet Block (Anti-Botnet) - Check FIRST
        if ( $this->is_subnet_blocked( $ip ) ) {
            $subnet = substr( $ip, 0, strrpos( $ip, '.' ) );
            $this->logger->log( 'warning', "IP $ip blocked (subnet $subnet.0/24 is blocked)", [ 'ip' => $ip, 'subnet' => $subnet ] );
            
            return [
                'limited' => true,
                'action'  => 'block',
                'delay'   => 3600,
                'warning' => false,
                'remaining' => 0,
            ];
        }

        // 1. Check Hard Block (File check, fast)
        if ( $this->is_hard_blocked( $ip ) ) {
            return [
                'limited' => true,
                'action'  => 'block',
                'delay'   => 3600, // 1 hour default
                'warning' => false,
                'remaining' => 0,
            ];
        }

        // 2. Get Attempt Counts (Thread-safe read from base class)
        $ip_attempts       = $this->read_count( $ip, 'login_ip', 600 );
        $username_attempts = $username ? $this->read_count( $username, 'login_username', 600 ) : 0;

        // Use WordPress options for limits, but allow fallback defaults
        $max_attempts         = (int) get_option( 'saurity_rate_limit_attempts', 5 );
        $hard_block_threshold = (int) get_option( 'saurity_hard_block_attempts', 20 );

        // Use the higher count of the two
        $total_attempts = max( $ip_attempts, $username_attempts );

        // 3. Trigger Hard Block if threshold met
        if ( $total_attempts >= $hard_block_threshold ) {
            $this->set_hard_block( $ip );
            
            $this->logger->log( 'error', "IP $ip hard blocked after $total_attempts attempts", [ 'ip' => $ip ] );

            // Trigger action for email notifications, etc.
            do_action( 'saurity_critical_event', 'IP Hard Blocked', [
                'ip' => $ip,
                'username' => $username,
                'count' => $total_attempts,
            ] );

            return [ 
                'limited' => true, 
                'action' => 'block', 
                'delay' => 3600,
                'warning' => false,
                'remaining' => 0,
            ];
        }

        // 3.5. WARNING ZONE - Approaching hard block (80% of threshold)
        $warning_threshold = max( 1, (int)( $hard_block_threshold * 0.8 ) );
        if ( $total_attempts >= $warning_threshold && $total_attempts < $hard_block_threshold ) {
            // Set warning flag
            set_transient( 'saurity_rate_warning_' . md5( $ip ), [
                'attempts' => $total_attempts,
                'threshold' => $hard_block_threshold,
                'remaining' => $hard_block_threshold - $total_attempts,
            ], 300 );
        }

        // 4. Soft Limit Reached?
        if ( $total_attempts >= $max_attempts ) {
            // Calculate backoff: 2^attempts (2s, 4s, 8s, 16s...)
            $excess = $total_attempts - $max_attempts + 1;
            $delay  = min( 2 * pow( 2, min( $excess, 5 ) ), 60 );
            
            return [
                'limited' => true,
                'action'  => 'delay',
                'delay'   => $delay,
                'warning' => ( $total_attempts >= $warning_threshold ),
                'remaining' => $hard_block_threshold - $total_attempts,
            ];
        }

        // 4.5. WARNING ZONE - Approaching soft limit (80% of limit)
        $soft_warning_threshold = max( 1, (int)( $max_attempts * 0.8 ) );
        if ( $total_attempts >= $soft_warning_threshold && $total_attempts < $max_attempts ) {
            set_transient( 'saurity_login_warning_' . md5( $ip ), [
                'attempts' => $total_attempts,
                'threshold' => $max_attempts,
                'remaining' => $max_attempts - $total_attempts,
            ], 300 );
        }

        return [ 
            'limited' => false, 
            'action' => 'allow', 
            'delay' => 0,
            'warning' => ( $total_attempts >= $soft_warning_threshold ),
            'remaining' => $max_attempts - $total_attempts,
        ];
    }

    /**
     * Record a failed login attempt (Increment counters)
     * Also tracks subnet failures for anti-botnet protection
     *
     * @param string $ip IP address.
     * @param string $username Username (optional).
     */
    public function record_failure( $ip, $username = '' ) {
        // Uses thread-safe get_hit_count from base class
        $this->get_hit_count( $ip, 'login_ip', 600 );
        if ( ! empty( $username ) ) {
            $this->get_hit_count( $username, 'login_username', 600 );
        }
        
        // Track subnet failures for anti-botnet protection
        $this->record_subnet_failure( $ip );
    }
    
    /**
     * Record subnet failure (Anti-Botnet)
     * PROBLEM: Attackers own IP ranges, switch IPs when blocked
     * SOLUTION: Track failures by Class C subnet (/24), block entire range
     *
     * @param string $ip IP address.
     */
    private function record_subnet_failure( $ip ) {
        // Check if subnet blocking is enabled
        if ( ! get_option( 'saurity_enable_subnet_blocking', false ) ) {
            return;
        }
        
        // Extract subnet (first 3 octets - Class C)
        // Example: 192.168.1.50 → 192.168.1
        $subnet = substr( $ip, 0, strrpos( $ip, '.' ) );
        
        if ( empty( $subnet ) ) {
            return;
        }
        
        // Track failures for this subnet (10 minute window)
        $count = $this->get_hit_count( $subnet, 'subnet_failures', 600 );
        
        // Get configurable threshold (default: 30 failures)
        $threshold = (int) get_option( 'saurity_subnet_failure_threshold', 30 );
        
        // If threshold exceeded, trigger subnet-wide hard block
        if ( $count >= $threshold ) {
            $this->set_subnet_block( $subnet );
            
            $this->logger->log( 
                'critical', 
                "Subnet $subnet.0/24 blocked after $count failures (botnet detected)", 
                [ 'subnet' => $subnet, 'count' => $count ]
            );
            
            // Trigger action for email notifications
            do_action( 'saurity_critical_event', 'Subnet Blocked (Botnet)', [
                'subnet' => $subnet . '.0/24',
                'failures' => $count,
                'threshold' => $threshold,
            ] );
        }
    }
    
    /**
     * Check if IP's subnet is blocked
     *
     * @param string $ip IP address.
     * @return bool True if subnet is blocked.
     */
    private function is_subnet_blocked( $ip ) {
        // Check if subnet blocking is enabled
        if ( ! get_option( 'saurity_enable_subnet_blocking', false ) ) {
            return false;
        }
        
        // Extract subnet
        $subnet = substr( $ip, 0, strrpos( $ip, '.' ) );
        
        if ( empty( $subnet ) ) {
            return false;
        }
        
        // Check for subnet block flag (1 hour duration)
        $value = $this->read_flag( $subnet, 'subnet_block', 3600 );
        return ( false !== $value );
    }
    
    /**
     * Set subnet block flag
     *
     * @param string $subnet Subnet (first 3 octets).
     */
    private function set_subnet_block( $subnet ) {
        $this->set_flag( $subnet, 'subnet_block', '1' );
    }

    /**
     * Reset counters (Login Success)
     *
     * @param string $ip IP address.
     * @param string $username Username (optional).
     */
    public function reset( $ip, $username = '' ) {
        $this->clear_file( $ip, 'login_ip' );
        if ( ! empty( $username ) ) {
            $this->clear_file( $username, 'login_username' );
        }
        $this->remove_hard_block( $ip );
    }

    /**
     * Check for XML-RPC abuse (MOVED FROM FIREWALL)
     * SEPARATION OF CONCERNS: RateLimiter handles ALL frequency checks
     * Now uses configurable settings from admin UI
     *
     * @return bool True if abuse detected.
     */
    public function is_xmlrpc_abuse() {
        // Master switch: If rate limiting is disabled globally, skip all checks
        if ( ! get_option( 'saurity_enable_rate_limiting', true ) ) {
            return false;
        }
        
        // Check if XML-RPC protection is enabled
        if ( ! get_option( 'saurity_enable_xmlrpc_protection', true ) ) {
            return false;
        }
        
        if ( ! defined( 'XMLRPC_REQUEST' ) || ! XMLRPC_REQUEST ) {
            return false;
        }

        // Get configurable settings
        $limit = (int) get_option( 'saurity_xmlrpc_limit', 10 );
        $window = (int) get_option( 'saurity_xmlrpc_window', 60 );
        
        $count = $this->get_hit_count( $this->client_ip, 'xmlrpc', $window );
        
        // Block if limit exceeded
        return $count > $limit;
    }

    /**
     * Check for POST flood (MOVED FROM FIREWALL)
     * SEPARATION OF CONCERNS: RateLimiter handles ALL frequency checks
     * Uses Two-Tier system for NAT/School safety
     * Now uses configurable settings from admin UI
     *
     * @return bool True if flood detected.
     */
    public function is_post_flood() {
        // Master switch: If rate limiting is disabled globally, skip all checks
        if ( ! get_option( 'saurity_enable_rate_limiting', true ) ) {
            return false;
        }
        
        // Check if POST flood protection is enabled
        if ( ! get_option( 'saurity_enable_post_flood', true ) ) {
            return false;
        }
        
        if ( $_SERVER['REQUEST_METHOD'] !== 'POST' ) {
            return false;
        }

        // 1. Always allow logged-in users
        if ( is_user_logged_in() ) {
            return false;
        }

        // Detect Login Page - Skip POST flood check (handled by check() method)
        $is_login = ( 
            strpos( $_SERVER['REQUEST_URI'], 'wp-login.php' ) !== false ||
            strpos( $_SERVER['REQUEST_URI'], 'xmlrpc.php' ) !== false ||
            isset( $_POST['log'] )
        );

        if ( $is_login ) {
            return false;
        }

        // Get configurable settings
        $device_limit = (int) get_option( 'saurity_post_flood_device_limit', 20 );
        $ip_limit = (int) get_option( 'saurity_post_flood_ip_limit', 200 );
        $window = (int) get_option( 'saurity_post_flood_window', 60 );

        // --- DEFINE IDENTIFIERS ---
        
        // Tier 1 ID: The Specific Device (IP + User Agent)
        $user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? $_SERVER['HTTP_USER_AGENT'] : '';
        $device_id  = $this->client_ip . $user_agent;

        // Tier 2 ID: The Building (IP Only)
        $office_id  = $this->client_ip;

        // --- LOGIC: GENERAL POST (Comments, Forms) ---
        
        // Rule 1: Stop a spam bot on a specific computer
        // Limit: Configurable posts per window per DEVICE
        $count_device = $this->get_hit_count( $device_id, 'post_device', $window );
        
        // Warning at 80%
        $device_warning_threshold = (int)( $device_limit * 0.8 );
        if ( $count_device >= $device_warning_threshold && $count_device < $device_limit ) {
            set_transient( 'saurity_post_warning_' . md5( $this->client_ip ), [
                'count' => $count_device,
                'limit' => $device_limit,
            ], $window );
        }
        
        if ( $count_device > $device_limit ) {
            return true;
        }

        // Rule 2: Allow the office to work
        // Limit: Configurable posts per window for the BUILDING
        $count_office = $this->get_hit_count( $office_id, 'post_ip', $window );
        if ( $count_office > $ip_limit ) {
            return true;
        }

        return false;
    }

    /**
     * Check for comment spam frequency (MOVED FROM FIREWALL)
     * SEPARATION OF CONCERNS: RateLimiter handles ALL frequency checks
     * Now uses configurable settings from admin UI
     *
     * @return array ['limited' => bool, 'count' => int, 'warning' => bool]
     */
    public function check_comment_rate() {
        // Master switch: If rate limiting is disabled globally, skip all checks
        if ( ! get_option( 'saurity_enable_rate_limiting', true ) ) {
            return [ 'limited' => false, 'count' => 0, 'warning' => false ];
        }
        
        // Check if comment rate limiting is enabled
        if ( ! get_option( 'saurity_enable_comment_rate_limiting', true ) ) {
            return [ 'limited' => false, 'count' => 0, 'warning' => false ];
        }
        
        // Skip for logged-in users
        if ( is_user_logged_in() ) {
            return [ 'limited' => false, 'count' => 0, 'warning' => false ];
        }

        // Get configurable settings
        $limit = (int) get_option( 'saurity_comment_rate_limit', 3 );
        $window = (int) get_option( 'saurity_comment_rate_window', 300 );

        // Check for rapid comments from same IP (thread-safe tracking)
        $count = $this->get_hit_count( $this->client_ip, 'comment', $window );

        // Warning at limit - 1 (one before blocking)
        $warning_threshold = max( 1, $limit - 1 );
        $warning = ( $count === $warning_threshold );
        
        if ( $warning ) {
            $this->logger->log(
                'info',
                'Comment rate warning: User approaching limit',
                [ 'ip' => $this->client_ip, 'count' => $count, 'limit' => $limit ]
            );
            
            // Store warning for display after redirect
            set_transient( 'saurity_comment_warning_' . md5( $this->client_ip ), true, $window );
        }

        // Block at limit exceeded
        $limited = ( $count > $limit );
        
        if ( $limited ) {
            $this->logger->log(
                'warning',
                'Comment spam blocked: Too many comments in short time',
                [ 'ip' => $this->client_ip, 'count' => $count, 'limit' => $limit ]
            );
        }

        return [
            'limited' => $limited,
            'count' => $count,
            'warning' => $warning,
        ];
    }

    /**
     * Check for general request flood (DoS Protection)
     * Limits ALL requests (GET, POST, etc.) to prevent scrapers and DoS
     * Uses high default limits to avoid false positives
     *
     * @return bool True if flood detected.
     */
    public function is_general_request_flood() {
        // Master switch: If rate limiting is disabled globally, skip all checks
        if ( ! get_option( 'saurity_enable_rate_limiting', true ) ) {
            return false;
        }
        
        // Check if general request throttling is enabled
        if ( ! get_option( 'saurity_enable_request_throttle', false ) ) {
            return false;
        }
        
        // Always allow logged-in users
        if ( is_user_logged_in() ) {
            return false;
        }
        
        // Skip for admin and ajax requests
        if ( is_admin() || ( defined( 'DOING_AJAX' ) && DOING_AJAX ) ) {
            return false;
        }

        // Get configurable settings (high defaults to avoid false positives)
        $limit = (int) get_option( 'saurity_request_throttle_limit', 120 );
        $window = (int) get_option( 'saurity_request_throttle_window', 60 );

        // Track all requests from this IP
        $count = $this->get_hit_count( $this->client_ip, 'general_request', $window );
        
        // Block if limit exceeded
        return $count > $limit;
    }

    /**
     * Enforce the limit (Exit with 429 response)
     * AUDIT: Logs the block action with delay duration for auditing
     *
     * @param array $result Result from check().
     */
    public function enforce( $result ) {
        if ( ! $result['limited'] ) {
            return;
        }

        // AUDIT: Log the rate limit enforcement with delay duration
        $this->logger->log(
            'warning',
            $result['action'] === 'block' ? 'IP Hard Blocked' : 'Rate Limit Exceeded',
            [
                'ip' => $this->client_ip,
                'delay' => $result['delay'], // Important for audit trail
                'action' => $result['action'],
            ]
        );

        // Send 429 Too Many Requests
        status_header( 429 );
        header( 'Retry-After: ' . $result['delay'] );
        nocache_headers();
        
        // Determine message based on action
        if ( $result['action'] === 'block' ) {
            $title = 'Temporarily Blocked';
            $reason = 'Too many failed login attempts';
            $user_message = 'Your IP address has been temporarily blocked due to too many failed login attempts. This is an automatic security measure to protect against brute force attacks.';
            
            // Get configured hard block duration (default 600 seconds = 10 minutes)
            $configured_duration = (int) get_option( 'saurity_hard_block_duration', 3600 );
            
            // Format wait time nicely
            if ( $configured_duration >= 3600 ) {
                $hours = ceil( $configured_duration / 3600 );
                $wait_time_text = $hours . ( $hours === 1 ? ' hour' : ' hours' );
            } elseif ( $configured_duration >= 60 ) {
                $minutes = ceil( $configured_duration / 60 );
                $wait_time_text = $minutes . ( $minutes === 1 ? ' minute' : ' minutes' );
            } else {
                $wait_time_text = $configured_duration . ' seconds';
            }
            
            $additional_info = [
                [
                    'title' => '⏱️ Please Wait',
                    'text' => 'You can try again after the waiting period expires. This temporary restriction helps protect the site from automated attacks.',
                ],
                [
                    'html' => '<div class="wait-time">Max Wait Time: ' . esc_html( $wait_time_text ) . '</div>',
                ],
                [
                    'title' => 'What happened?',
                    'list' => [
                        'Too many failed login attempts were detected',
                        'Your IP was automatically blocked',
                        'If you forgot your password, wait for the block to expire',
                    ],
                ],
            ];
        } else {
            $title = 'Rate Limit Exceeded';
            $reason = 'Too many requests';
            $user_message = 'You\'re sending too many login requests too quickly. Please wait before trying again to help us maintain security for all users.';
             // Get configured hard block duration (default 600 seconds = 10 minutes)
            $configured_duration = (int) get_option( 'saurity_rate_limit_window', 600 );
            
            // Format wait time nicely
            if ( $configured_duration >= 3600 ) {
                $hours = ceil( $configured_duration / 3600 );
                $wait_time_text = $hours . ( $hours === 1 ? ' hour' : ' hours' );
            } elseif ( $configured_duration >= 60 ) {
                $minutes = ceil( $configured_duration / 60 );
                $wait_time_text = $minutes . ( $minutes === 1 ? ' minute' : ' minutes' );
            } else {
                $wait_time_text = $configured_duration . ' seconds';
            }
            
            $additional_info = [
                [
                    'title' => '⏱️ Please Wait',
                    'text' => 'You can try again after the waiting period expires. This temporary restriction helps protect the site from automated attacks.',
                ],
                [
                    'html' => '<div class="wait-time">Max Wait Time: ' . esc_html( $wait_time_text ) . '</div>',
                ],
                [
                    'title' => 'Tips:',
                    'list' => [
                        'Double-check your username and password',
                        'Use the "Forgot Password" link if needed',
                        'Contact support if you continue having issues',
                    ],
                ],
            ];
        }
        
        // DRY: Use centralized rendering from SecurityComponent
        $this->render_block_page( $title, $reason, $user_message, '⏱️', '#ff9800', $additional_info );
    }

    /* -----------------------------------------------------------------
       PRIVATE HELPERS
       ----------------------------------------------------------------- */

    /**
     * Check if IP is hard blocked
     *
     * @param string $ip IP address.
     * @return bool
     */
    private function is_hard_blocked( $ip ) {
        $value = $this->read_flag( $ip, 'block', 3600 );
        return ( false !== $value );
    }

    /**
     * Set hard block for IP
     *
     * @param string $ip IP address.
     */
    private function set_hard_block( $ip ) {
        $this->set_flag( $ip, 'block', '1' );
    }

    /**
     * Remove hard block for IP
     *
     * @param string $ip IP address.
     */
    private function remove_hard_block( $ip ) {
        $this->clear_file( $ip, 'block' );
    }
}