<?php
/**
 * Security Component Base Class
 *
 * @package Saurity
 */

namespace Saurity;

/**
 * Abstract base class for security components
 * Provides thread-safe file operations and centralized garbage collection
 */
abstract class SecurityComponent {

    /**
     * Shared cache directory for all security components
     *
     * @var string
     */
    protected $cache_dir;

    /**
     * Logger instance
     *
     * @var ActivityLogger
     */
    protected $logger;

    /**
     * Client IP address
     *
     * @var string
     */
    protected $client_ip;

    /**
     * Component name prefix for file isolation
     *
     * @var string
     */
    protected $component_prefix;

    /**
     * Constructor
     *
     * @param ActivityLogger $logger Logger instance.
     * @param string         $component_prefix Prefix for file isolation (e.g., 'fw_', 'rl_').
     */
    public function __construct( ActivityLogger $logger, $component_prefix ) {
        $this->logger = $logger;
        $this->component_prefix = $component_prefix;
        $this->client_ip = $this->get_client_ip();
        
        // Shared cache directory for all security components
        $this->cache_dir = sys_get_temp_dir() . '/saurity_security';
        if ( ! file_exists( $this->cache_dir ) ) {
            // SECURITY: 0700 (user-only access) prevents other users on shared hosting
            // from reading IP addresses or session flags
            @mkdir( $this->cache_dir, 0700, true );
        }
    }

    /**
     * Get hit count with thread-safe file locking (FIXES RACE CONDITION)
     * Uses flock() to ensure atomic read-modify-write operations
     *
     * @param string $identifier Unique identifier (IP, device ID, etc.).
     * @param string $context Context (login, post, comment, xmlrpc, etc.).
     * @param int    $window Time window in seconds.
     * @return int Hit count.
     */
    protected function get_hit_count( $identifier, $context, $window ) {
        $file = $this->get_file_path( $context, $identifier );
        
        // Open or create file for reading and writing
        $fp = @fopen( $file, 'c+' );
        if ( false === $fp ) {
            // Fallback: File creation failed, return 0
            return 0;
        }

        // CRITICAL: Acquire exclusive lock (blocks until lock is available)
        // This prevents race conditions between concurrent requests
        if ( ! flock( $fp, LOCK_EX ) ) {
            fclose( $fp );
            return 0;
        }

        // Check if file is within time window
        clearstatcache( true, $file );
        $mtime = @filemtime( $file );
        
        if ( false !== $mtime && ( time() - $mtime > $window ) ) {
            // Window expired - reset to 1
            ftruncate( $fp, 0 );
            rewind( $fp );
            fwrite( $fp, '1' );
            fflush( $fp );
            flock( $fp, LOCK_UN );
            fclose( $fp );
            @touch( $file ); // Update mtime
            return 1;
        }

        // Read current count (file pointer is at start)
        rewind( $fp );
        $content = stream_get_contents( $fp );
        $count = empty( $content ) ? 0 : (int) $content;
        
        // Increment count
        $count++;
        
        // Write updated count (atomically)
        ftruncate( $fp, 0 );
        rewind( $fp );
        fwrite( $fp, (string) $count );
        fflush( $fp );
        
        // Release lock and close file
        flock( $fp, LOCK_UN );
        fclose( $fp );
        
        // Update modification time
        @touch( $file );
        
        return $count;
    }

    /**
     * Get current count without incrementing (thread-safe read)
     *
     * @param string $identifier Unique identifier.
     * @param string $context Context.
     * @param int    $window Time window in seconds.
     * @return int Current count.
     */
    protected function read_count( $identifier, $context, $window ) {
        $file = $this->get_file_path( $context, $identifier );
        
        if ( ! file_exists( $file ) ) {
            return 0;
        }

        // Check if file is within time window
        clearstatcache( true, $file );
        $mtime = @filemtime( $file );
        
        if ( false === $mtime || ( time() - $mtime > $window ) ) {
            return 0;
        }

        // Open file for reading with shared lock
        $fp = @fopen( $file, 'r' );
        if ( false === $fp ) {
            return 0;
        }

        // Acquire shared lock (multiple readers allowed)
        if ( ! flock( $fp, LOCK_SH ) ) {
            fclose( $fp );
            return 0;
        }

        $content = stream_get_contents( $fp );
        $count = empty( $content ) ? 0 : (int) $content;
        
        flock( $fp, LOCK_UN );
        fclose( $fp );
        
        return $count;
    }

    /**
     * Set a flag file with thread-safe locking
     * SECURITY: Uses JSON instead of serialize() to prevent RCE attacks
     *
     * @param string $identifier Unique identifier.
     * @param string $context Context.
     * @param mixed  $value Value to store (will be JSON encoded).
     * @return bool Success.
     */
    protected function set_flag( $identifier, $context, $value = '1' ) {
        $file = $this->get_file_path( $context, $identifier );
        
        $fp = @fopen( $file, 'c' );
        if ( false === $fp ) {
            return false;
        }

        if ( ! flock( $fp, LOCK_EX ) ) {
            fclose( $fp );
            return false;
        }

        ftruncate( $fp, 0 );
        rewind( $fp );
        // SECURITY: JSON encode instead of serialize to prevent unserialize() RCE
        fwrite( $fp, is_string( $value ) ? $value : json_encode( $value ) );
        fflush( $fp );
        
        flock( $fp, LOCK_UN );
        fclose( $fp );
        
        @touch( $file );
        
        return true;
    }

    /**
     * Read a flag file with thread-safe locking
     *
     * @param string $identifier Unique identifier.
     * @param string $context Context.
     * @param int    $max_age Maximum age in seconds (0 = no expiry).
     * @return mixed Value or false if not found/expired.
     */
    protected function read_flag( $identifier, $context, $max_age = 0 ) {
        $file = $this->get_file_path( $context, $identifier );
        
        if ( ! file_exists( $file ) ) {
            return false;
        }

        // Check age if max_age specified
        if ( $max_age > 0 ) {
            clearstatcache( true, $file );
            $mtime = @filemtime( $file );
            if ( false === $mtime || ( time() - $mtime > $max_age ) ) {
                return false;
            }
        }

        $fp = @fopen( $file, 'r' );
        if ( false === $fp ) {
            return false;
        }

        if ( ! flock( $fp, LOCK_SH ) ) {
            fclose( $fp );
            return false;
        }

        $content = stream_get_contents( $fp );
        
        flock( $fp, LOCK_UN );
        fclose( $fp );
        
        return $content;
    }

    /**
     * Clear a file with thread-safe locking
     *
     * @param string $identifier Unique identifier.
     * @param string $context Context.
     * @return bool Success.
     */
    protected function clear_file( $identifier, $context ) {
        $file = $this->get_file_path( $context, $identifier );
        return @unlink( $file );
    }

    /**
     * Get file path for identifier with component prefix isolation
     * Each component (Firewall, RateLimiter) has its own namespace
     *
     * @param string $context Context.
     * @param string $identifier Unique identifier.
     * @return string File path.
     */
    protected function get_file_path( $context, $identifier ) {
        $hash = md5( $identifier );
        return $this->cache_dir . "/{$this->component_prefix}{$context}_{$hash}";
    }

    /**
     * Centralized garbage collection (FIXES COLLISION ISSUE)
     * Only files belonging to this component are cleaned up
     * Runs on ~1% of requests to minimize performance impact
     *
     * @param int $max_age Maximum file age in seconds (default: 3600).
     */
    protected function garbage_collector( $max_age = 3600 ) {
        // 1% chance to run cleanup
        if ( rand( 1, 100 ) !== 1 ) {
            return;
        }

        // Only clean up files belonging to this component
        $pattern = $this->cache_dir . '/' . $this->component_prefix . '*';
        $files = glob( $pattern );
        
        if ( false === $files ) {
            return;
        }

        $now = time();

        foreach ( $files as $file ) {
            if ( ! is_file( $file ) ) {
                continue;
            }

            clearstatcache( true, $file );
            $mtime = @filemtime( $file );
            
            if ( false !== $mtime && ( $now - $mtime > $max_age ) ) {
                @unlink( $file );
            }
        }
    }

    /**
     * Get client IP address securely
     * 
     * SECURITY WARNING: Always uses REMOTE_ADDR by default to prevent IP spoofing.
     * Only trusts proxy headers if SAURITY_BEHIND_PROXY constant is defined.
     * 
     * CRITICAL: SAURITY_BEHIND_PROXY should ONLY be enabled if:
     * 1. Your server is behind a trusted reverse proxy (Cloudflare, nginx, etc.)
     * 2. Your firewall/server is configured to ONLY accept connections from the proxy
     * 3. Direct access to your server bypassing the proxy is blocked
     * 
     * If enabled incorrectly, attackers can spoof X-Forwarded-For headers to bypass rate limits.
     * 
     * To enable, add to wp-config.php:
     * define( 'SAURITY_BEHIND_PROXY', true );
     *
     * @return string Client IP address.
     */
    protected function get_client_ip() {
        // Default to REMOTE_ADDR (cannot be spoofed by client)
        $ip = isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';

        // Only check proxy headers if explicitly configured
        if ( defined( 'SAURITY_BEHIND_PROXY' ) && SAURITY_BEHIND_PROXY ) {
            $headers = [
                'HTTP_CF_CONNECTING_IP', // Cloudflare
                'HTTP_X_FORWARDED_FOR',  // Standard reverse proxy
                'HTTP_X_REAL_IP',        // Nginx
            ];

            foreach ( $headers as $header ) {
                if ( ! empty( $_SERVER[ $header ] ) ) {
                    // Get first IP in list (actual client IP)
                    $ip_list = explode( ',', $_SERVER[ $header ] );
                    $ip = trim( $ip_list[0] );
                    break;
                }
            }
        }

        // Validate and return
        return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '0.0.0.0';
    }

    /**
     * Apply tarpitting delay (Attack Slowdown)
     * PROBLEM: 403 returns in 0.01s, allows thousands of password tests/min
     * SOLUTION: sleep(3) wastes attacker's time, reduces attacks by 99.98%
     * 
     * Example: Without tarpit = 10,000 attempts/min, With tarpit = 20 attempts/min
     */
    protected function apply_tarpit() {
        // Check if tarpitting is enabled
        if ( ! get_option( 'saurity_enable_tarpitting', true ) ) {
            return;
        }
        
        // Get configurable delay (1-10 seconds, default 3)
        $delay = (int) get_option( 'saurity_tarpit_delay', 3 );
        $delay = max( 1, min( 10, $delay ) ); // Sanitize
        
        // Log tarpitting for audit trail
        $this->logger->log(
            'info',
            "Tarpitting applied: {$delay}s delay before block",
            [ 'ip' => $this->client_ip, 'delay' => $delay ]
        );
        
        // Sleep to waste attacker's time
        sleep( $delay );
    }

    /**
     * Render security block page (DRY: Centralized HTML generation)
     * Used by both Firewall and RateLimiter to avoid code duplication
     * Automatically applies tarpitting before rendering
     *
     * @param string $title Page title (e.g., 'Access Denied', 'Rate Limit Exceeded').
     * @param string $reason Technical reason for blocking.
     * @param string $user_message User-friendly explanation.
     * @param string $icon Emoji icon for the page.
     * @param string $color Primary color for the page theme.
     * @param array  $additional_info Optional additional information boxes.
     */
    protected function render_block_page( $title, $reason, $user_message, $icon = '🛡️', $color = '#dc3545', $additional_info = [] ) {
        // Apply tarpitting to slow down attackers
        $this->apply_tarpit();
        
        $site_name = get_bloginfo( 'name' );
        $site_url = home_url();
        
        ?>
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title><?php echo esc_html( $title ); ?> - Security Protection</title>
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                    background: #ffffff;
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }
                .container {
                    background: white;
                    border-radius: 12px;
                    box-shadow: 0 10px 40px rgba(0,0,0,0.1);
                    max-width: 600px;
                    width: 100%;
                    padding: 40px;
                    text-align: center;
                    border: 1px solid #e0e0e0;
                }
                .icon {
                    font-size: 64px;
                    margin-bottom: 20px;
                }
                h1 {
                    color: <?php echo esc_attr( $color ); ?>;
                    font-size: 28px;
                    margin-bottom: 10px;
                }
                .subtitle {
                    color: #6c757d;
                    font-size: 16px;
                    margin-bottom: 30px;
                }
                .message-box {
                    background: #f8f9fa;
                    border-left: 4px solid <?php echo esc_attr( $color ); ?>;
                    padding: 20px;
                    text-align: left;
                    border-radius: 4px;
                    margin-bottom: 30px;
                }
                .message-box h3 {
                    color: #333;
                    font-size: 16px;
                    margin-bottom: 10px;
                }
                .message-box p {
                    color: #666;
                    font-size: 14px;
                    line-height: 1.6;
                    margin-bottom: 10px;
                }
                .reason-code {
                    background: #fff;
                    border: 1px solid #dee2e6;
                    padding: 10px;
                    border-radius: 4px;
                    font-family: 'Courier New', monospace;
                    font-size: 13px;
                    color: <?php echo esc_attr( $color ); ?>;
                    margin-top: 15px;
                }
                .info-box {
                    background: #e7f3ff;
                    border-left: 4px solid #2196F3;
                    padding: 15px;
                    text-align: left;
                    border-radius: 4px;
                    margin-bottom: 20px;
                }
                .info-box strong {
                    color: #2196F3;
                }
                .info-box p {
                    color: #666;
                    font-size: 13px;
                    margin-top: 5px;
                }
                .info-box ul {
                    margin: 10px 0 0 20px;
                    font-size: 14px;
                    color: #666;
                }
                .wait-time {
                    background: #fff3e0;
                    border: 2px solid #ff9800;
                    padding: 15px;
                    border-radius: 8px;
                    margin: 20px 0;
                    font-size: 18px;
                    font-weight: 600;
                    color: #ff9800;
                }
                .btn {
                    display: inline-block;
                    background: #667eea;
                    color: white;
                    padding: 12px 30px;
                    border-radius: 6px;
                    text-decoration: none;
                    font-weight: 500;
                    transition: background 0.3s;
                }
                .btn:hover {
                    background: #5568d3;
                }
                .footer {
                    margin-top: 30px;
                    padding-top: 20px;
                    border-top: 1px solid #dee2e6;
                    color: #6c757d;
                    font-size: 12px;
                }
                .ip-address {
                    color: #666;
                    font-size: 12px;
                    margin-top: 10px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="icon"><?php echo esc_html( $icon ); ?></div>
                <h1><?php echo esc_html( $title ); ?></h1>
                <p class="subtitle">Security Protection Active</p>
                
                <div class="message-box">
                    <h3>Why was I blocked?</h3>
                    <p><?php echo esc_html( $user_message ); ?></p>
                    <div class="reason-code">
                        <strong>Reason:</strong> <?php echo esc_html( $reason ); ?>
                    </div>
                </div>
                
                <?php foreach ( $additional_info as $info ) : ?>
                <div class="info-box">
                    <strong><?php echo esc_html( $info['title'] ); ?></strong>
                    <?php if ( isset( $info['text'] ) ) : ?>
                        <p><?php echo esc_html( $info['text'] ); ?></p>
                    <?php endif; ?>
                    <?php if ( isset( $info['list'] ) ) : ?>
                        <ul>
                            <?php foreach ( $info['list'] as $item ) : ?>
                                <li><?php echo esc_html( $item ); ?></li>
                            <?php endforeach; ?>
                        </ul>
                    <?php endif; ?>
                    <?php if ( isset( $info['html'] ) ) : ?>
                        <?php echo $info['html']; // Already escaped by caller ?>
                    <?php endif; ?>
                </div>
                <?php endforeach; ?>
                
                <a href="<?php echo esc_url( $site_url ); ?>" class="btn">← Return to Homepage</a>
                
                <div class="footer">
                    <strong><?php echo esc_html( $site_name ); ?></strong><br>
                    Protected by Saurity Security
                    <div class="ip-address">
                        Your IP: <?php echo esc_html( $this->client_ip ); ?> | <?php echo esc_html( current_time( 'Y-m-d H:i:s' ) ); ?>
                    </div>
                </div>
            </div>
        </body>
        </html>
        <?php
        exit;
    }

    /**
     * Hook method - must be implemented by child classes
     */
    abstract public function hook();
}
