<?php
/**
 * Kill Switch - Emergency Disable
 *
 * @package Saurity
 */

namespace Saurity;

/**
 * KillSwitch class - disables all enforcement
 */
class KillSwitch {

    /**
     * Check if kill switch is active
     *
     * @return bool
     */
    public function is_active() {
        // Option-based kill switch (manual toggle in admin)
        if ( get_option( 'saurity_kill_switch', 0 ) ) {
            return true;
        }

        // Emergency bypass via session (15 minutes)
        if ( $this->check_emergency_bypass() ) {
            return true;
        }

        return false;
    }

    /**
     * Activate kill switch (manual only)
     *
     * @param string $reason Reason for activation.
     */
    public function activate( $reason = '' ) {
        update_option( 'saurity_kill_switch', 1 );

        $logger = new ActivityLogger();
        $message = 'Kill switch activated: ' . ( $reason ?: 'Manual activation' );
        $logger->log( 'critical', $message );

        // Trigger email notification
        do_action( 'saurity_critical_event', 'Kill Switch Activated', [
            'message' => $message,
        ] );
    }

    /**
     * Deactivate kill switch
     */
    public function deactivate() {
        update_option( 'saurity_kill_switch', 0 );

        $logger = new ActivityLogger();
        $logger->log( 'info', 'Kill switch deactivated - enforcement resumed' );
    }

    /**
     * Check emergency bypass (session-based, allows multiple page loads)
     * Works for 15 minutes to allow admin navigation
     *
     * @return bool
     */
    private function check_emergency_bypass() {
        // Start session if not already started
        if ( ! session_id() ) {
            @session_start();
        }

        // Handle manual bypass termination
        if ( isset( $_GET['saurity_end_bypass'] ) ) {
            unset( $_SESSION['saurity_bypass_active'] );
            unset( $_SESSION['saurity_bypass_expires'] );
            unset( $_SESSION['saurity_bypass_ip'] );
            unset( $_SESSION['saurity_bypass_logged'] );
            
            // Log the manual termination
            $logger = new ActivityLogger();
            $logger->log( 'info', 'Emergency bypass session ended manually' );
            
            return false;
        }

        // Check if active bypass session exists
        if ( isset( $_SESSION['saurity_bypass_active'] ) && $_SESSION['saurity_bypass_expires'] > time() ) {
            // Verify IP hasn't changed (security measure)
            if ( isset( $_SESSION['saurity_bypass_ip'] ) && $_SESSION['saurity_bypass_ip'] === $this->get_client_ip() ) {
                // Show admin notice about active bypass
                add_action( 'admin_notices', [ $this, 'show_bypass_notice' ] );
                return true;
            }
            
            // IP changed - invalidate session
            unset( $_SESSION['saurity_bypass_active'] );
            unset( $_SESSION['saurity_bypass_expires'] );
            unset( $_SESSION['saurity_bypass_ip'] );
            return false;
        }

        // Check if new bypass URL was used
        if ( ! isset( $_GET['saurity_bypass'] ) ) {
            return false;
        }

        $provided_key = sanitize_text_field( wp_unslash( $_GET['saurity_bypass'] ) );
        $stored_key = get_option( 'saurity_emergency_bypass_key', '' );

        if ( empty( $stored_key ) || empty( $provided_key ) ) {
            return false;
        }

        // Constant-time comparison to prevent timing attacks
        if ( hash_equals( $stored_key, $provided_key ) ) {
            // Create bypass session (10 minutes)
            $_SESSION['saurity_bypass_active'] = true;
            $_SESSION['saurity_bypass_expires'] = time() + ( 10 * 60 ); // 10 minutes
            $_SESSION['saurity_bypass_ip'] = $this->get_client_ip();
            
            // Show admin notice
            add_action( 'admin_notices', [ $this, 'show_bypass_notice' ] );
            
            // Schedule bypass logging for after init
            add_action( 'init', [ $this, 'log_bypass_usage' ], 999 );
            
            // Temporarily disable security
            return true;
        }

        return false;
    }

    /**
     * Log emergency bypass usage
     */
    public function log_bypass_usage() {
        // Only log once per session
        if ( ! session_id() ) {
            @session_start();
        }
        
        if ( isset( $_SESSION['saurity_bypass_logged'] ) ) {
            return;
        }
        $_SESSION['saurity_bypass_logged'] = true;

        $logger = new ActivityLogger();
        
        // Get client IP (secure method)
        $ip = $this->get_client_ip();
        
        $logger->log( 'warning', 'Emergency bypass session started - security bypassed for 10 minutes', [
            'ip' => $ip,
        ] );

        // Trigger email notification with IP context
        do_action( 'saurity_security_alert', 'Emergency Bypass Activated', [
            'message' => 'Emergency bypass URL was used to temporarily disable security for 10 minutes.',
            'ip' => $ip,
            'duration' => '10 minutes',
        ] );
    }

    /**
     * Show bypass notice in admin
     */
    public function show_bypass_notice() {
        // Calculate remaining time
        if ( ! session_id() ) {
            @session_start();
        }
        
        $remaining_seconds = 0;
        if ( isset( $_SESSION['saurity_bypass_expires'] ) ) {
            $remaining_seconds = max( 0, $_SESSION['saurity_bypass_expires'] - time() );
        }
        
        $remaining_minutes = ceil( $remaining_seconds / 60 );
        
        ?>
        <div class="notice notice-warning" style="border-left: 4px solid #ff9800;">
            <p>
                <strong>⚠️ Emergency Bypass Active (<?php echo esc_html( $remaining_minutes ); ?> minutes remaining)</strong><br>
                Security is temporarily bypassed to allow you to navigate and make changes. This session expires automatically.<br>
                <a href="<?php echo esc_url( admin_url( 'admin.php?page=saurity' ) ); ?>" class="button button-primary">
                    Go to Saurity Settings
                </a>
                <a href="<?php echo esc_url( add_query_arg( 'saurity_end_bypass', '1' ) ); ?>" class="button" 
                   onclick="return confirm('End bypass session and re-enable security?');">
                    End Bypass Now
                </a>
            </p>
        </div>
        <?php
    }

    /**
     * Track admin login failures (for logging purposes only)
     * Does NOT trigger auto-disable
     */
    public function track_admin_failure() {
        // Just increment counter for monitoring
        // Does NOT trigger auto-disable anymore
        $failures = (int) get_transient( 'saurity_admin_failures' );
        $failures++;

        set_transient( 'saurity_admin_failures', $failures, 300 ); // 5 minutes
        
        // Log if threshold reached (for admin awareness)
        if ( $failures === 10 ) {
            $logger = new ActivityLogger();
            $logger->log( 'warning', 'Multiple admin login failures detected (10 in 5 minutes)', [
                'note' => 'Use emergency bypass URL if you are locked out',
            ] );
        }
    }

    /**
     * Reset admin failure tracking
     */
    public function reset_admin_failures() {
        delete_transient( 'saurity_admin_failures' );
    }

    /**
     * Get client IP address securely
     * Uses same secure logic as Firewall
     *
     * @return string
     */
    private function get_client_ip() {
        // Default to REMOTE_ADDR (cannot be spoofed by client)
        $ip = isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';

        // Only check proxy headers if explicitly configured
        // This prevents IP spoofing attacks
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
}