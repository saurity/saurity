<?php
/**
 * Admin Interface
 *
 * @package Saurity
 */

namespace Saurity;

/**
 * Admin class - simple settings and logs interface
 */
class Admin {

    /**
     * Logger instance
     *
     * @var ActivityLogger
     */
    private $logger;

    /**
     * Kill switch instance
     *
     * @var KillSwitch
     */
    private $kill_switch;

    /**
     * Constructor
     *
     * @param ActivityLogger $logger Logger instance.
     * @param KillSwitch     $kill_switch Kill switch instance.
     */
    public function __construct( ActivityLogger $logger, KillSwitch $kill_switch ) {
        $this->logger = $logger;
        $this->kill_switch = $kill_switch;
    }

    /**
     * Hook into WordPress
     */
    public function hook() {
        add_action( 'admin_menu', [ $this, 'add_menu' ] );
        add_action( 'admin_init', [ $this, 'register_settings' ] );
        add_action( 'admin_post_saurity_clear_logs', [ $this, 'handle_clear_logs' ] );
        add_action( 'admin_post_saurity_toggle_kill_switch', [ $this, 'handle_kill_switch_toggle' ] );
    }

    /**
     * Add admin menu
     */
    public function add_menu() {
        add_options_page(
            'SAURITY Settings',
            'SAURITY',
            'manage_options',
            'saurity',
            [ $this, 'render_page' ]
        );
    }

    /**
     * Register settings
     */
    public function register_settings() {
        register_setting( 'saurity_settings', 'saurity_rate_limit_attempts' );
        register_setting( 'saurity_settings', 'saurity_rate_limit_window' );
        register_setting( 'saurity_settings', 'saurity_hard_block_attempts' );
        register_setting( 'saurity_settings', 'saurity_hard_block_duration' );
        register_setting( 'saurity_settings', 'saurity_progressive_delay' );
    }

    /**
     * Render admin page
     */
    public function render_page() {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        $kill_switch_active = $this->kill_switch->is_active();
        $bypass_key = get_option( 'saurity_emergency_bypass_key', '' );
        $logs = $this->logger->get_logs( 50 );

        ?>
        <div class="wrap">
            <h1>SAURITY v<?php echo esc_html( SAURITY_VERSION ); ?></h1>
            <p>Minimal viable security foundation. No nonsense.</p>

            <?php if ( $kill_switch_active ) : ?>
                <div class="notice notice-warning">
                    <p><strong>⚠️ Kill Switch Active</strong> - All enforcement is disabled.</p>
                </div>
            <?php endif; ?>

            <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 20px; margin-top: 20px;">
                
                <!-- Settings Column -->
                <div>
                    <h2>Settings</h2>
                    <form method="post" action="options.php">
                        <?php settings_fields( 'saurity_settings' ); ?>
                        <table class="form-table">
                            <tr>
                                <th>Rate Limit Attempts</th>
                                <td>
                                    <input type="number" name="saurity_rate_limit_attempts" 
                                           value="<?php echo esc_attr( get_option( 'saurity_rate_limit_attempts', 5 ) ); ?>" 
                                           min="1" max="20" />
                                    <p class="description">Failed attempts before throttling (default: 5)</p>
                                </td>
                            </tr>
                            <tr>
                                <th>Rate Limit Window</th>
                                <td>
                                    <input type="number" name="saurity_rate_limit_window" 
                                           value="<?php echo esc_attr( get_option( 'saurity_rate_limit_window', 600 ) ); ?>" 
                                           min="60" max="3600" />
                                    <p class="description">Time window in seconds (default: 600 = 10 minutes)</p>
                                </td>
                            </tr>
                            <tr>
                                <th>Hard Block Threshold</th>
                                <td>
                                    <input type="number" name="saurity_hard_block_attempts" 
                                           value="<?php echo esc_attr( get_option( 'saurity_hard_block_attempts', 20 ) ); ?>" 
                                           min="10" max="100" />
                                    <p class="description">Failed attempts before hard block (default: 20)</p>
                                </td>
                            </tr>
                            <tr>
                                <th>Hard Block Duration</th>
                                <td>
                                    <input type="number" name="saurity_hard_block_duration" 
                                           value="<?php echo esc_attr( get_option( 'saurity_hard_block_duration', 3600 ) ); ?>" 
                                           min="300" max="86400" />
                                    <p class="description">Block duration in seconds (default: 3600 = 1 hour)</p>
                                </td>
                            </tr>
                            <tr>
                                <th>Progressive Delay</th>
                                <td>
                                    <input type="number" name="saurity_progressive_delay" 
                                           value="<?php echo esc_attr( get_option( 'saurity_progressive_delay', 2 ) ); ?>" 
                                           min="1" max="10" />
                                    <p class="description">Base delay in seconds (default: 2, exponential backoff applied)</p>
                                </td>
                            </tr>
                        </table>
                        <?php submit_button(); ?>
                    </form>

                    <hr>

                    <h2>Activity Log</h2>
                    <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
                        <input type="hidden" name="action" value="saurity_clear_logs" />
                        <?php wp_nonce_field( 'saurity_clear_logs' ); ?>
                        <button type="submit" class="button" onclick="return confirm('Clear all logs?');">Clear Logs</button>
                    </form>

                    <div style="margin-top: 15px; max-height: 400px; overflow-y: auto; border: 1px solid #ddd; padding: 10px; background: #f9f9f9; font-family: monospace; font-size: 12px;">
                        <?php if ( empty( $logs ) ) : ?>
                            <p>No activity logged yet.</p>
                        <?php else : ?>
                            <?php foreach ( $logs as $log ) : ?>
                                <div style="margin-bottom: 8px; padding: 5px; background: white; border-left: 3px solid <?php echo esc_attr( $this->get_log_color( $log['event_type'] ) ); ?>;">
                                    <strong><?php echo esc_html( $log['created_at'] ); ?></strong>
                                    [<?php echo esc_html( strtoupper( $log['event_type'] ) ); ?>]
                                    <?php echo esc_html( $log['message'] ); ?>
                                    <?php if ( $log['ip_address'] ) : ?>
                                        <span style="color: #666;">(IP: <?php echo esc_html( $log['ip_address'] ); ?>)</span>
                                    <?php endif; ?>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Recovery Column -->
                <div>
                    <h2>Recovery & Safety</h2>
                    
                    <div style="padding: 15px; background: #fff3cd; border: 1px solid #ffc107; margin-bottom: 20px;">
                        <h3 style="margin-top: 0;">🔴 Kill Switch</h3>
                        <p>Immediately disable all enforcement.</p>
                        <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
                            <input type="hidden" name="action" value="saurity_toggle_kill_switch" />
                            <?php wp_nonce_field( 'saurity_kill_switch' ); ?>
                            <?php if ( $kill_switch_active ) : ?>
                                <button type="submit" class="button button-primary">Enable Protection</button>
                            <?php else : ?>
                                <button type="submit" class="button" onclick="return confirm('Disable all protection?');">Activate Kill Switch</button>
                            <?php endif; ?>
                        </form>
                    </div>

                    <div style="padding: 15px; background: #f0f0f0; border: 1px solid #ddd;">
                        <h3 style="margin-top: 0;">🔑 Emergency Bypass</h3>
                        <p>Use this URL to bypass all protection:</p>
                        <input type="text" readonly 
                               value="<?php echo esc_url( site_url( '/?saurity_bypass=' . $bypass_key ) ); ?>" 
                               style="width: 100%; font-size: 11px; padding: 5px;" 
                               onclick="this.select();" />
                        <p style="font-size: 11px; color: #666;">Keep this URL secret. Valid until plugin settings are reset.</p>
                    </div>

                    <div style="padding: 15px; background: #fff; border: 1px solid #ddd; margin-top: 20px;">
                        <h3 style="margin-top: 0;">📋 Manual Disable</h3>
                        <p style="font-size: 12px;">If locked out, disable via file:</p>
                        <code style="display: block; padding: 10px; background: #f5f5f5; font-size: 11px; word-wrap: break-word;">
                            wp-content/plugins/saurity/saurity.php
                        </code>
                        <p style="font-size: 11px; color: #666;">Rename or delete the plugin folder to disable.</p>
                    </div>

                    <div style="padding: 15px; background: #e7f3ff; border: 1px solid #2196F3; margin-top: 20px;">
                        <h3 style="margin-top: 0;">ℹ️ Version Info</h3>
                        <p style="font-size: 12px; margin: 0;"><strong>Version:</strong> <?php echo esc_html( SAURITY_VERSION ); ?></p>
                        <p style="font-size: 12px; margin: 5px 0 0 0;"><strong>Status:</strong> MVP (Minimal Viable Product)</p>
                    </div>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Get color for log type
     *
     * @param string $type Log type.
     * @return string
     */
    private function get_log_color( $type ) {
        $colors = [
            'info' => '#2196F3',
            'warning' => '#ff9800',
            'error' => '#f44336',
            'critical' => '#9c27b0',
        ];

        return $colors[ $type ] ?? '#666';
    }

    /**
     * Handle clear logs action
     */
    public function handle_clear_logs() {
        check_admin_referer( 'saurity_clear_logs' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Unauthorized' );
        }

        $this->logger->clear_logs();
        $this->logger->log( 'info', 'Activity logs cleared by admin' );

        wp_safe_redirect( admin_url( 'options-general.php?page=saurity' ) );
        exit;
    }

    /**
     * Handle kill switch toggle
     */
    public function handle_kill_switch_toggle() {
        check_admin_referer( 'saurity_kill_switch' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Unauthorized' );
        }

        if ( $this->kill_switch->is_active() ) {
            $this->kill_switch->deactivate();
        } else {
            $this->kill_switch->activate( 'Manual activation by admin' );
        }

        wp_safe_redirect( admin_url( 'options-general.php?page=saurity' ) );
        exit;
    }
}