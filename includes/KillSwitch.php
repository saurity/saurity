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
        // Option-based kill switch
        if ( get_option( 'saurity_kill_switch', 0 ) ) {
            return true;
        }

        // Emergency bypass via query parameter
        if ( $this->check_emergency_bypass() ) {
            return true;
        }

        // Auto-disable detection (prevents lockout loops)
        if ( $this->should_auto_disable() ) {
            $this->activate( 'Auto-disabled due to repeated lockout pattern' );
            return true;
        }

        return false;
    }

    /**
     * Activate kill switch
     *
     * @param string $reason Reason for activation.
     */
    public function activate( $reason = '' ) {
        update_option( 'saurity_kill_switch', 1 );

        $logger = new ActivityLogger();
        $logger->log( 'critical', 'Kill switch activated: ' . ( $reason ?: 'Manual activation' ) );
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
     * Check emergency bypass query parameter
     *
     * @return bool
     */
    private function check_emergency_bypass() {
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
            // Log bypass usage for security audit
            $this->log_bypass_usage();
            
            // Show admin notice
            add_action( 'admin_notices', [ $this, 'show_bypass_notice' ] );
            
            // Temporarily disable for this request only
            return true;
        }

        return false;
    }

    /**
     * Log emergency bypass usage
     */
    private function log_bypass_usage() {
        // Only log once per request
        static $logged = false;
        if ( $logged ) {
            return;
        }
        $logged = true;

        $logger = new ActivityLogger();
        $logger->log( 'warning', 'Emergency bypass URL used - security bypassed for this request only' );
    }

    /**
     * Show bypass notice in admin
     */
    public function show_bypass_notice() {
        ?>
        <div class="notice notice-warning">
            <p>
                <strong>⚠️ Emergency Bypass Active</strong><br>
                Security is bypassed for this page load only. This does NOT permanently disable protection.<br>
                <a href="<?php echo esc_url( admin_url( 'admin.php?page=saurity' ) ); ?>" class="button button-primary">
                    Go to Saurity Settings
                </a>
            </p>
        </div>
        <?php
    }

    /**
     * Check if auto-disable should trigger
     *
     * Prevents admin lockout scenarios
     *
     * @return bool
     */
    private function should_auto_disable() {
        // Check for rapid failed admin attempts pattern
        $admin_failures = get_transient( 'saurity_admin_failures' );
        
        if ( false === $admin_failures ) {
            return false;
        }

        // If more than 10 admin failures in 5 minutes, auto-disable
        // This prevents accidental admin lockout
        if ( $admin_failures > 10 ) {
            return true;
        }

        return false;
    }

    /**
     * Track potential admin lockout
     *
     * Called when admin user is rate-limited
     */
    public function track_admin_failure() {
        $failures = (int) get_transient( 'saurity_admin_failures' );
        $failures++;

        set_transient( 'saurity_admin_failures', $failures, 300 ); // 5 minutes
    }

    /**
     * Reset admin failure tracking
     */
    public function reset_admin_failures() {
        delete_transient( 'saurity_admin_failures' );
    }
}