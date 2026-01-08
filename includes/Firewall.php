<?php
/**
 * Lightweight Firewall
 *
 * @package Saurity
 */

namespace Saurity;

/**
 * Firewall class - CONTENT INSPECTION ONLY
 * Extends SecurityComponent for thread-safe operations
 * ALL frequency/velocity checks delegated to RateLimiter
 */
class Firewall extends SecurityComponent {

    /**
     * RateLimiter instance
     *
     * @var RateLimiter
     */
    private $rate_limiter;

    /**
     * Constructor
     *
     * @param ActivityLogger $logger Logger instance.
     */
    public function __construct( ActivityLogger $logger ) {
        // Use 'fw_' prefix to isolate Firewall files from other components
        parent::__construct( $logger, 'fw_' );
        
        // Initialize RateLimiter for frequency checks
        $this->rate_limiter = new RateLimiter( $logger );
    }

    /**
     * Hook into WordPress
     */
    public function hook() {
        add_action( 'init', [ $this, 'check_request' ], 0 );
        add_filter( 'preprocess_comment', [ $this, 'check_comment_spam' ], 1 );
        add_action( 'comment_form_before', [ $this, 'display_comment_warning' ] );
        add_action( 'comment_form', [ $this, 'add_comment_bot_detection_fields' ] );
    }
    
    /**
     * Add honeypot and timing fields to comment form
     */
    public function add_comment_bot_detection_fields() {
        // Skip for logged-in users
        if ( is_user_logged_in() ) {
            return;
        }
        
        // Generate timing token
        $timing_token = $this->generate_form_token();
        
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
     * Display warning notice on comment form if user is approaching rate limit
     */
    public function display_comment_warning() {
        // Only show for non-logged-in users
        if ( is_user_logged_in() ) {
            return;
        }

        // Check if warning flag is set
        $warning_key = 'saurity_comment_warning_' . md5( $this->client_ip );
        $has_warning = get_transient( $warning_key );

        if ( $has_warning ) {
            // Get configured limits for accurate messaging
            $limit = (int) get_option( 'saurity_comment_rate_limit', 3 );
            $window = (int) get_option( 'saurity_comment_rate_window', 300 );
            $window_minutes = ceil( $window / 60 );
            
            ?>
            <div style="background: #fff3cd; border: 1px solid #ffc107; border-left: 4px solid #ff9800; padding: 15px; margin-bottom: 20px; border-radius: 4px;">
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span style="font-size: 24px;">⚠️</span>
                    <div>
                        <strong style="color: #856404; font-size: 16px;">Rate Limit Warning</strong>
                        <p style="margin: 5px 0 0 0; color: #856404; font-size: 14px;">
                            You're approaching the comment rate limit (<?php echo esc_html( $limit ); ?> comments per <?php echo esc_html( $window_minutes ); ?> minutes). 
                            <strong>Your next comment may be blocked.</strong>
                        </p>
                        <p style="margin: 8px 0 0 0; color: #856404; font-size: 13px;">
                            💡 <strong>Tip:</strong> <a href="<?php echo esc_url( wp_login_url( get_permalink() ) ); ?>" style="color: #667eea; text-decoration: underline;">Login to your account</a> to bypass this limit and comment freely.
                        </p>
                    </div>
                </div>
            </div>
            <?php
            // Clear the warning after displaying it once
            delete_transient( $warning_key );
        }
    }

    /**
     * Check incoming request
     */
    public function check_request() {
        // Run garbage collector (component-specific, no collisions)
        $this->garbage_collector();

        // Get IPManager instance (unified allow/block lists)
        $plugin = \Saurity\Plugin::get_instance();
        $ip_manager = $plugin->get_component( 'ip_manager' );

        // Priority 1: Check IPManager permanent blocklist (Admin UI)
        if ( $ip_manager && $ip_manager->is_blocked( $this->client_ip ) ) {
            $this->block( 'IP address permanently blocked' );
        }

        // Priority 2: Check IPManager allowlist (Admin UI)
        if ( $ip_manager && $ip_manager->is_allowed( $this->client_ip ) ) {
            return; // Bypass all firewall checks
        }

        // Priority 3: Check filter-based whitelist (wp-config.php)
        if ( $this->is_whitelisted() ) {
            return;
        }

        // Priority 4: Check Honeypot (100% bot detection, zero false positives)
        if ( $this->check_honeypot() ) {
            $this->block( 'Bot detected (honeypot field filled)' );
        }

        // Priority 5: Check Form Timing (humans take time to type)
        if ( $this->check_form_timing() ) {
            $this->block( 'Bot detected (form submitted too quickly)' );
        }

        // Early exit: Skip heavy scanning for trusted users
        if ( current_user_can( 'manage_options' ) || current_user_can( 'edit_posts' ) ) {
            // SEPARATION OF CONCERNS: Delegate frequency checks to RateLimiter
            if ( $this->rate_limiter->is_xmlrpc_abuse() ) {
                $this->block( 'XML-RPC abuse detected' );
            }
            if ( $this->rate_limiter->is_post_flood() ) {
                $this->block( 'POST flood detected' );
            }
            return; // Skip content inspection for trusted users
        }

        // SEPARATION OF CONCERNS: All frequency/velocity checks delegated to RateLimiter
        
        // General request throttling (DoS Protection) - Check FIRST
        if ( $this->rate_limiter->is_general_request_flood() ) {
            $this->block( 'Too many requests - DoS protection triggered' );
        }
        
        if ( $this->rate_limiter->is_xmlrpc_abuse() ) {
            $this->block( 'XML-RPC abuse detected' );
        }

        if ( $this->rate_limiter->is_post_flood() ) {
            $this->block( 'POST flood detected' );
        }

        // CONTENT INSPECTION (Firewall's core responsibility)
        if ( $this->is_sensitive_path() ) {
            $this->block( 'Access to sensitive path blocked' );
        }

        if ( $this->is_method_abuse() ) {
            $this->block( 'HTTP method abuse detected' );
        }

        if ( $this->is_malicious_user_agent() ) {
            $this->block( 'Malicious user agent detected' );
        }

        if ( $this->is_suspicious_referer() ) {
            $this->block( 'Suspicious referer detected' );
        }

        if ( $this->has_sql_injection() ) {
            $this->block( 'SQL injection attempt detected' );
        }

        if ( $this->has_xss_attempt() ) {
            $this->block( 'XSS attempt detected' );
        }
    }

    /**
     * Check for sensitive path access (CONTENT INSPECTION)
     *
     * @return bool
     */
    private function is_sensitive_path() {
        $request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';

        if ( empty( $request_uri ) ) {
            return false;
        }

        $blocked_paths = [
            '/.env',
            '/.git',
            '/config.php',
            '/configuration.php',
            '/phpmyadmin',
            '/admin/config.php',
            '/.aws/',
            '/.ssh/',
        ];

        foreach ( $blocked_paths as $path ) {
            if ( strpos( $request_uri, $path ) !== false ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check for HTTP method abuse (CONTENT INSPECTION)
     *
     * @return bool
     */
    private function is_method_abuse() {
        $method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : 'GET';

        $allowed_methods = [ 'GET', 'POST', 'HEAD', 'OPTIONS' ];
        
        if ( ! in_array( $method, $allowed_methods, true ) ) {
            return true;
        }

        // Block POST to static file endpoints
        if ( $method === 'POST' ) {
            $request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
            
            $static_extensions = [ '.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf' ];
            
            foreach ( $static_extensions as $ext ) {
                if ( substr( $request_uri, -strlen( $ext ) ) === $ext ) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check honeypot field (Zero False-Positive Bot Detection)
     * PROBLEM: CAPTCHAs annoy humans
     * SOLUTION: Hidden field that humans can't see, but bots fill out
     *
     * @return bool True if bot detected.
     */
    private function check_honeypot() {
        // Check if honeypot is enabled
        if ( ! get_option( 'saurity_enable_honeypot', true ) ) {
            return false;
        }
        
        // Only check POST requests
        if ( $_SERVER['REQUEST_METHOD'] !== 'POST' ) {
            return false;
        }
        
        // Skip for logged-in users
        if ( is_user_logged_in() ) {
            return false;
        }
        
        // Check if honeypot field is filled (100% bot detection)
        // Field name: website_url_check (sounds legitimate to bots)
        if ( ! empty( $_POST['website_url_check'] ) ) {
            $this->logger->log(
                'warning',
                'Bot detected via honeypot field',
                [ 'ip' => $this->client_ip, 'value' => substr( $_POST['website_url_check'], 0, 50 ) ]
            );
            return true;
        }
        
        return false;
    }
    
    /**
     * Check form submission timing (Human Verification)
     * PROBLEM: Bots submit forms instantly
     * SOLUTION: Timestamp in hidden field, humans need time to type
     *
     * @return bool True if bot detected (submitted too fast).
     */
    private function check_form_timing() {
        // Check if timing check is enabled
        if ( ! get_option( 'saurity_enable_timing_check', true ) ) {
            return false;
        }
        
        // Only check POST requests
        if ( $_SERVER['REQUEST_METHOD'] !== 'POST' ) {
            return false;
        }
        
        // Skip for logged-in users
        if ( is_user_logged_in() ) {
            return false;
        }
        
        // Check if timing token exists
        if ( empty( $_POST['saurity_form_time'] ) ) {
            return false; // No token = don't check (form might not have it)
        }
        
        // Decrypt and validate token
        $token = sanitize_text_field( $_POST['saurity_form_time'] );
        $timestamp = $this->decrypt_timestamp( $token );
        
        if ( false === $timestamp ) {
            return false; // Invalid token, don't penalize
        }
        
        // Calculate how long it took to submit form
        $elapsed = time() - $timestamp;
        
        // Get configurable minimum time (default: 2 seconds)
        $min_time = (int) get_option( 'saurity_min_form_time', 2 );
        
        // If submitted too quickly, it's a bot
        if ( $elapsed < $min_time ) {
            $this->logger->log(
                'warning',
                "Bot detected via timing check (submitted in {$elapsed}s, minimum: {$min_time}s)",
                [ 'ip' => $this->client_ip, 'elapsed' => $elapsed ]
            );
            return true;
        }
        
        return false;
    }
    
    /**
     * Generate encrypted timestamp token for form timing checks
     *
     * @return string Encrypted token.
     */
    public function generate_form_token() {
        $timestamp = time();
        // Simple encryption using WordPress salts
        $key = wp_salt( 'nonce' );
        return base64_encode( $timestamp . '|' . hash_hmac( 'sha256', $timestamp, $key ) );
    }
    
    /**
     * Decrypt and validate timestamp token
     *
     * @param string $token Encrypted token.
     * @return int|false Timestamp or false if invalid.
     */
    private function decrypt_timestamp( $token ) {
        $decoded = base64_decode( $token, true );
        
        if ( false === $decoded ) {
            return false;
        }
        
        $parts = explode( '|', $decoded );
        
        if ( count( $parts ) !== 2 ) {
            return false;
        }
        
        list( $timestamp, $hash ) = $parts;
        
        // Validate hash
        $key = wp_salt( 'nonce' );
        $expected_hash = hash_hmac( 'sha256', $timestamp, $key );
        
        if ( ! hash_equals( $expected_hash, $hash ) ) {
            return false;
        }
        
        // Validate timestamp is reasonable (not older than 1 hour, not in future)
        $timestamp = (int) $timestamp;
        if ( $timestamp > time() || ( time() - $timestamp ) > 3600 ) {
            return false;
        }
        
        return $timestamp;
    }

    /**
     * Check if IP is whitelisted
     *
     * @return bool
     */
    private function is_whitelisted() {
        $whitelist = apply_filters( 'saurity_firewall_whitelist', [
            '127.0.0.1',
            '::1',
        ] );

        return in_array( $this->client_ip, $whitelist, true );
    }

    /**
     * Check for malicious user agents (CONTENT INSPECTION)
     *
     * @return bool
     */
    private function is_malicious_user_agent() {
        $user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? strtolower( $_SERVER['HTTP_USER_AGENT'] ) : '';

        if ( empty( $user_agent ) ) {
            return false;
        }

        $bad_bots = [
            'masscan',
            'nikto',
            'sqlmap',
            'acunetix',
            'nessus',
            'openvas',
            'metis',
            'libwww-perl',
            'python-requests',
            'wget',
            'curl',
            'java/',
            'go-http-client',
            'scrapy',
            'nmap',
            'havij',
            'zmeu',
            'dirbuster',
            'email',
            'harvest',
            'extract',
            'grab',
            'miner',
        ];

        foreach ( $bad_bots as $bot ) {
            if ( strpos( $user_agent, $bot ) !== false ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check for suspicious referers (CONTENT INSPECTION)
     *
     * @return bool
     */
    private function is_suspicious_referer() {
        if ( $_SERVER['REQUEST_METHOD'] !== 'POST' ) {
            return false;
        }

        if ( is_user_logged_in() || is_admin() ) {
            return false;
        }

        $referer = isset( $_SERVER['HTTP_REFERER'] ) ? strtolower( $_SERVER['HTTP_REFERER'] ) : '';
        $host = isset( $_SERVER['HTTP_HOST'] ) ? strtolower( $_SERVER['HTTP_HOST'] ) : '';

        if ( empty( $referer ) ) {
            return false;
        }

        // Check if referer is from same domain
        if ( strpos( $referer, $host ) === false ) {
            $allowed_external = [
                'paypal.com',
                'stripe.com',
                'google.com',
                'facebook.com',
                'twitter.com',
            ];

            $is_allowed = false;
            foreach ( $allowed_external as $allowed ) {
                if ( strpos( $referer, $allowed ) !== false ) {
                    $is_allowed = true;
                    break;
                }
            }

            if ( ! $is_allowed ) {
                return true;
            }
        }

        // Check for spam referers
        $spam_referers = [
            'get-free-traffic',
            'free-share-buttons',
            'social-buttons',
            'buy-cheap',
            'get-more-visitors',
            'poker',
            'casino',
            'viagra',
            'cialis',
        ];

        foreach ( $spam_referers as $spam ) {
            if ( strpos( $referer, $spam ) !== false ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check for SQL injection attempts (CONTENT INSPECTION)
     * SECURITY: Checks both raw and decoded values to catch double-encoding attacks
     *
     * @return bool
     */
    private function has_sql_injection() {
        $check_values = [];

        if ( ! empty( $_GET ) ) {
            $check_values = array_merge( $check_values, $_GET );
        }

        if ( ! empty( $_POST ) && ! isset( $_POST['comment'] ) && ! isset( $_POST['content'] ) ) {
            $check_values = array_merge( $check_values, $_POST );
        }

        if ( isset( $_SERVER['REQUEST_URI'] ) ) {
            $check_values[] = $_SERVER['REQUEST_URI'];
        }

        if ( isset( $_SERVER['QUERY_STRING'] ) ) {
            $check_values[] = $_SERVER['QUERY_STRING'];
        }

        $sql_pattern = '/\b(union[\s\+]+select|insert[\s\+]+into|delete[\s\+]+from|drop[\s\+]+table|update.+set.+where|exec[\s\+]+(s|x)p\w+|benchmark\s*\(|sleep\s*\(|waitfor\s+delay|load_file\s*\(|into\s+outfile)\b/i';
        $hex_pattern = '/\b0x[0-9a-f]{2,}\b/i';
        $boolean_pattern = '/(\bor\b|\band\b)\s+[\d\'\"]+\s*=\s*[\d\'\"]+/i';

        foreach ( $check_values as $value ) {
            if ( ! is_string( $value ) ) {
                continue;
            }

            // SECURITY: Check both raw value and decoded value to catch double-encoding
            // Example: %2527 decodes to %27 (which is '), catches sophisticated attacks
            $test_values = [ $value ];
            
            // Decode up to 3 times to catch multiple encoding layers
            $decoded = $value;
            for ( $i = 0; $i < 3; $i++ ) {
                $prev = $decoded;
                $decoded = urldecode( $decoded );
                if ( $decoded === $prev ) {
                    break; // No more decoding possible
                }
                $test_values[] = $decoded;
            }

            // Check all encoding layers
            foreach ( $test_values as $test_value ) {
                if ( preg_match( $sql_pattern, $test_value ) ) {
                    return true;
                }

                if ( preg_match( $hex_pattern, $test_value ) ) {
                    return true;
                }

                if ( preg_match( $boolean_pattern, $test_value ) ) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check for XSS attempts (CONTENT INSPECTION)
     * SECURITY: Checks both raw and decoded values to catch double-encoding attacks
     *
     * @return bool
     */
    private function has_xss_attempt() {
        $check_values = [];

        if ( ! empty( $_GET ) ) {
            $check_values = array_merge( $check_values, $_GET );
        }

        if ( ! empty( $_POST ) && ! isset( $_POST['comment'] ) && ! isset( $_POST['content'] ) ) {
            $check_values = array_merge( $check_values, $_POST );
        }

        if ( isset( $_SERVER['REQUEST_URI'] ) ) {
            $check_values[] = $_SERVER['REQUEST_URI'];
        }

        if ( isset( $_SERVER['QUERY_STRING'] ) ) {
            $check_values[] = $_SERVER['QUERY_STRING'];
        }

        $xss_pattern = '/<(script|iframe|embed|object)[^>]*>|javascript:|vbscript:|on\w+\s*=|eval\s*\(|expression\s*\(|document\.(cookie|write)|window\.location/i';

        foreach ( $check_values as $value ) {
            if ( ! is_string( $value ) ) {
                continue;
            }

            // SECURITY: Check multiple encoding layers
            $test_values = [ $value ];
            
            $decoded = $value;
            for ( $i = 0; $i < 3; $i++ ) {
                $prev = $decoded;
                $decoded = urldecode( $decoded );
                if ( $decoded === $prev ) {
                    break;
                }
                $test_values[] = $decoded;
            }

            foreach ( $test_values as $test_value ) {
                if ( preg_match( $xss_pattern, $test_value ) ) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check comment for spam (CONTENT INSPECTION + delegates rate check to RateLimiter)
     *
     * @param array $comment_data Comment data.
     * @return array
     */
    public function check_comment_spam( $comment_data ) {
        // Skip for logged-in users
        if ( is_user_logged_in() ) {
            return $comment_data;
        }

        $comment_content = isset( $comment_data['comment_content'] ) ? $comment_data['comment_content'] : '';
        $comment_author = isset( $comment_data['comment_author'] ) ? $comment_data['comment_author'] : '';
        $comment_author_email = isset( $comment_data['comment_author_email'] ) ? $comment_data['comment_author_email'] : '';
        $comment_author_url = isset( $comment_data['comment_author_url'] ) ? $comment_data['comment_author_url'] : '';

        // SEPARATION OF CONCERNS: Delegate rate limiting to RateLimiter
        $rate_check = $this->rate_limiter->check_comment_rate();
        
        if ( $rate_check['warning'] ) {
            add_filter( 'pre_comment_approved', function( $approved ) {
                set_transient( 'saurity_comment_warning_' . md5( $this->client_ip ), true, 300 );
                return $approved;
            }, 99 );
        }
        
        if ( $rate_check['limited'] ) {
            wp_die( 'Comment rejected: Too many comments in 5 minutes. You must login to continue commenting.' );
        }

        // CONTENT INSPECTION: Check comment content
        $link_count = substr_count( strtolower( $comment_content ), 'http' );
        if ( $link_count > 3 ) {
            $this->logger->log(
                'warning',
                'Comment spam blocked: Excessive links',
                [ 'ip' => $this->client_ip, 'links' => $link_count ]
            );
            wp_die( 'Comment rejected: Too many links.' );
        }

        // Check for spam keywords
        $spam_keywords = [
            'viagra',
            'cialis',
            'casino',
            'poker',
            'lottery',
            'get rich',
            'make money fast',
            'work from home',
            'buy now',
            'click here',
            'limited offer',
            'buy cheap',
            'discount',
            'free money',
            'earn cash',
        ];

        $comment_lower = strtolower( $comment_content . ' ' . $comment_author . ' ' . $comment_author_url );
        
        foreach ( $spam_keywords as $keyword ) {
            if ( strpos( $comment_lower, $keyword ) !== false ) {
                $this->logger->log(
                    'warning',
                    'Comment spam blocked: Spam keyword detected',
                    [ 'ip' => $this->client_ip, 'keyword' => $keyword ]
                );
                wp_die( 'Comment rejected: Spam detected.' );
            }
        }

        // Check for excessive capitalization
        $caps_count = preg_match_all( '/[A-Z]/', $comment_content, $matches );
        $total_chars = strlen( preg_replace( '/\s/', '', $comment_content ) );
        
        if ( $total_chars > 10 && $caps_count > ( $total_chars * 0.5 ) ) {
            $this->logger->log(
                'warning',
                'Comment spam blocked: Excessive capitalization',
                [ 'ip' => $this->client_ip ]
            );
            wp_die( 'Comment rejected: Excessive capitalization.' );
        }

        // Check for temporary email services
        if ( ! empty( $comment_author_email ) ) {
            $temp_email_domains = [
                'tempmail.com',
                'throwaway.email',
                '10minutemail.com',
                'guerrillamail.com',
                'mailinator.com',
                'maildrop.cc',
            ];

            foreach ( $temp_email_domains as $domain ) {
                if ( strpos( $comment_author_email, $domain ) !== false ) {
                    $this->logger->log(
                        'warning',
                        'Comment spam blocked: Temporary email detected',
                        [ 'ip' => $this->client_ip, 'email' => $comment_author_email ]
                    );
                    wp_die( 'Comment rejected: Please use a permanent email address.' );
                }
            }
        }

        return $comment_data;
    }

    /**
     * Block the request
     * DRY: Uses centralized rendering from SecurityComponent
     *
     * @param string $reason Reason for blocking.
     */
    private function block( $reason ) {
        $this->logger->log(
            'warning',
            $reason,
            [ 'ip' => $this->client_ip ]
        );

        status_header( 403 );
        nocache_headers();
        
        $user_message = $this->get_user_friendly_message( $reason );
        
        // Determine additional info based on reason type
        $additional_info = [];
        
        if ( strpos( $reason, 'IP address permanently blocked' ) !== false ) {
            $additional_info[] = [
                'title' => '🔒 IP Address Blocked',
                'text' => 'Your IP address has been permanently blocked by the site administrator. If you believe this is an error, please contact the site owner.',
            ];
        } elseif ( strpos( $reason, 'SQL injection' ) !== false || strpos( $reason, 'XSS' ) !== false ) {
            $additional_info[] = [
                'title' => '⚠️ Malicious Activity Detected',
                'text' => 'The security system detected potentially harmful content in your request. If you\'re a legitimate user, please ensure you\'re not using special characters or scripts in form submissions.',
            ];
        } elseif ( strpos( $reason, 'POST flood' ) !== false || strpos( $reason, 'Rate limit' ) !== false ) {
            $additional_info[] = [
                'title' => '⏱️ Too Many Requests',
                'text' => 'You\'re sending too many requests too quickly. Please wait a few minutes before trying again.',
            ];
        } else {
            $additional_info[] = [
                'title' => '🔍 Security Check Failed',
                'text' => 'Your request triggered our security protection. This could be due to suspicious patterns or automated behavior.',
            ];
        }
        
        // DRY: Use centralized rendering from SecurityComponent
        $this->render_block_page( 'Access Denied', $reason, $user_message, '🛡️', '#dc3545', $additional_info );
    }

    /**
     * Get user-friendly message based on block reason
     *
     * @param string $reason Technical block reason.
     * @return string User-friendly message.
     */
    private function get_user_friendly_message( $reason ) {
        $messages = [
            'SQL injection attempt detected' => 'Your request contained patterns commonly used in SQL injection attacks. This is a serious security violation.',
            'XSS attempt detected' => 'Your request contained cross-site scripting (XSS) patterns that could harm other users.',
            'XML-RPC abuse detected' => 'Too many XML-RPC requests detected. This endpoint is being protected from automated attacks.',
            'POST flood detected' => 'You\'re submitting forms or making POST requests too quickly. Please slow down and try again in a few minutes.',
            'Access to sensitive path blocked' => 'You attempted to access a protected file or directory that should not be publicly accessible.',
            'HTTP method abuse detected' => 'Your request used an HTTP method that\'s not allowed for this resource.',
            'Malicious user agent detected' => 'Your browser or tool has been identified as commonly used for malicious purposes.',
            'Suspicious referer detected' => 'Your request came from a suspicious source. Cross-site request forgery protection is active.',
            'IP address permanently blocked' => 'Your IP address has been blocked by the site administrator due to previous security violations.',
        ];

        return isset( $messages[ $reason ] ) ? $messages[ $reason ] : 'Your request was blocked by our security system to protect this website and its users.';
    }
}             
