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
        add_action( 'admin_notices', [ $this, 'display_admin_notices' ] );
        add_action( 'admin_bar_menu', [ $this, 'add_admin_bar_indicator' ], 100 );
        add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_admin_styles' ] );
    }

    /**
     * Add admin menu
     */
    public function add_menu() {
        add_menu_page(
            'Saurity Security',
            'Saurity',
            'manage_options',
            'saurity',
            [ $this, 'render_page' ],
            'dashicons-shield',
            30
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

        ?>
        <div class="wrap">
            <h1>🛡️ Saurity v<?php echo esc_html( SAURITY_VERSION ); ?></h1>
            <p>Minimal viable security foundation. No nonsense.</p>

            <?php if ( $kill_switch_active ) : ?>
                <div class="notice notice-warning is-dismissible" style="padding: 15px; display: flex; align-items: center; gap: 15px;">
                    <span style="font-size: 24px;">⚠️</span>
                    <div style="flex: 1;">
                        <strong>Kill Switch Active</strong><br>
                        <span>All security enforcement is currently disabled. Your site is vulnerable.</span>
                    </div>
                    <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin: 0;">
                        <input type="hidden" name="action" value="saurity_toggle_kill_switch" />
                        <?php wp_nonce_field( 'saurity_kill_switch' ); ?>
                        <button type="submit" class="button button-primary button-large">
                            Enable Protection Now
                        </button>
                    </form>
                </div>
            <?php else : ?>
                <div class="notice notice-success" style="padding: 12px;">
                    <p style="margin: 0;"><strong>✓ Protection Active</strong> - Your site is being monitored and protected.</p>
                </div>
            <?php endif; ?>

            <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 20px; margin-top: 20px;">
                
                <!-- Settings Column -->
                <div>
                    <h2>Settings</h2>
                    <form method="post" action="options.php">
                        <?php settings_fields( 'saurity_settings' ); ?>
                        <style>
                            .saurity-setting-label {
                                display: inline-flex;
                                align-items: center;
                                gap: 8px;
                            }
                            .saurity-info-icon {
                                display: inline-flex;
                                align-items: center;
                                justify-content: center;
                                width: 18px;
                                height: 18px;
                                border-radius: 50%;
                                background: #2196F3;
                                color: white;
                                font-size: 12px;
                                font-weight: bold;
                                cursor: help;
                                position: relative;
                            }
                            .saurity-tooltip {
                                visibility: hidden;
                                opacity: 0;
                                position: absolute;
                                z-index: 1000;
                                bottom: 125%;
                                left: 50%;
                                transform: translateX(-50%);
                                width: 280px;
                                background-color: #333;
                                color: #fff;
                                text-align: left;
                                padding: 12px;
                                border-radius: 6px;
                                font-size: 13px;
                                font-weight: normal;
                                line-height: 1.5;
                                transition: opacity 0.3s;
                                box-shadow: 0 2px 8px rgba(0,0,0,0.2);
                            }
                            .saurity-tooltip::after {
                                content: "";
                                position: absolute;
                                top: 100%;
                                left: 50%;
                                margin-left: -5px;
                                border-width: 5px;
                                border-style: solid;
                                border-color: #333 transparent transparent transparent;
                            }
                            .saurity-info-icon:hover .saurity-tooltip {
                                visibility: visible;
                                opacity: 1;
                            }
                        </style>
                        <table class="form-table">
                            <tr>
                                <th>
                                    <span class="saurity-setting-label">
                                        Rate Limit Attempts
                                        <span class="saurity-info-icon">
                                            i
                                            <span class="saurity-tooltip">
                                                <strong>What it does:</strong> Sets how many failed login attempts are allowed before throttling begins.<br><br>
                                                <strong>Example:</strong> With 5 attempts, after the 5th failed login, delays start increasing exponentially.<br><br>
                                                <strong>Recommended:</strong> 5-10 for most sites
                                            </span>
                                        </span>
                                    </span>
                                </th>
                                <td>
                                    <input type="number" name="saurity_rate_limit_attempts" 
                                           value="<?php echo esc_attr( get_option( 'saurity_rate_limit_attempts', 5 ) ); ?>" 
                                           min="1" max="20" />
                                    <p class="description">Failed attempts before throttling (default: 5)</p>
                                </td>
                            </tr>
                            <tr>
                                <th>
                                    <span class="saurity-setting-label">
                                        Rate Limit Window
                                        <span class="saurity-info-icon">
                                            i
                                            <span class="saurity-tooltip">
                                                <strong>What it does:</strong> The time period (in seconds) during which failed attempts are counted.<br><br>
                                                <strong>Example:</strong> 600 seconds (10 minutes) means if someone fails 5 times in 10 minutes, they'll be throttled.<br><br>
                                                <strong>Recommended:</strong> 600-900 seconds (10-15 minutes)
                                            </span>
                                        </span>
                                    </span>
                                </th>
                                <td>
                                    <input type="number" name="saurity_rate_limit_window" 
                                           value="<?php echo esc_attr( get_option( 'saurity_rate_limit_window', 600 ) ); ?>" 
                                           min="60" max="3600" />
                                    <p class="description">Time window in seconds (default: 600 = 10 minutes)</p>
                                </td>
                            </tr>
                            <tr>
                                <th>
                                    <span class="saurity-setting-label">
                                        Hard Block Threshold
                                        <span class="saurity-info-icon">
                                            i
                                            <span class="saurity-tooltip">
                                                <strong>What it does:</strong> After this many failed attempts, the IP is completely blocked for a set duration.<br><br>
                                                <strong>Example:</strong> With 20 attempts, after 20 failures, the IP cannot access the site at all.<br><br>
                                                <strong>Recommended:</strong> 15-25 for security vs. usability balance
                                            </span>
                                        </span>
                                    </span>
                                </th>
                                <td>
                                    <input type="number" name="saurity_hard_block_attempts" 
                                           value="<?php echo esc_attr( get_option( 'saurity_hard_block_attempts', 20 ) ); ?>" 
                                           min="10" max="100" />
                                    <p class="description">Failed attempts before hard block (default: 20)</p>
                                </td>
                            </tr>
                            <tr>
                                <th>
                                    <span class="saurity-setting-label">
                                        Hard Block Duration
                                        <span class="saurity-info-icon">
                                            i
                                            <span class="saurity-tooltip">
                                                <strong>What it does:</strong> How long (in seconds) an IP stays blocked after hitting the hard block threshold.<br><br>
                                                <strong>Example:</strong> 3600 seconds = 1 hour of complete blocking.<br><br>
                                                <strong>Recommended:</strong> 3600-7200 seconds (1-2 hours)
                                            </span>
                                        </span>
                                    </span>
                                </th>
                                <td>
                                    <input type="number" name="saurity_hard_block_duration" 
                                           value="<?php echo esc_attr( get_option( 'saurity_hard_block_duration', 3600 ) ); ?>" 
                                           min="300" max="86400" />
                                    <p class="description">Block duration in seconds (default: 3600 = 1 hour)</p>
                                </td>
                            </tr>
                            <tr>
                                <th>
                                    <span class="saurity-setting-label">
                                        Progressive Delay
                                        <span class="saurity-info-icon">
                                            i
                                            <span class="saurity-tooltip">
                                                <strong>What it does:</strong> Base delay time that grows exponentially with each failed attempt.<br><br>
                                                <strong>How it works:</strong> 2 seconds = 1st fail: 2s, 2nd: 4s, 3rd: 8s, 4th: 16s delay, etc.<br><br>
                                                <strong>Recommended:</strong> 2-3 seconds for good balance
                                            </span>
                                        </span>
                                    </span>
                                </th>
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

                    <?php $this->render_activity_log(); ?>
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
                        <h3 style="margin-top: 0;">🔑 Emergency Bypass URL</h3>
                        <p><strong>What it does:</strong> Temporarily bypasses security for ONE page load only.</p>
                        <p style="font-size: 12px; margin: 10px 0;">
                            <strong>Use case:</strong> If you're locked out and can't login, use this URL to access your site once and disable the kill switch.
                        </p>
                        <input type="text" readonly 
                               value="<?php echo esc_url( site_url( '/?saurity_bypass=' . $bypass_key ) ); ?>" 
                               style="width: 100%; font-size: 11px; padding: 5px; margin: 10px 0;" 
                               onclick="this.select();" />
                        <p style="font-size: 11px; color: #d63638; margin: 0;">
                            <strong>⚠️ Important:</strong> This does NOT permanently disable security. It only works for one request. 
                            Keep this URL secret and safe.
                        </p>
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
     * Render activity log with pagination and filters
     */
    private function render_activity_log() {
        // Get current filter, page, and search
        $current_filter = isset( $_GET['log_type'] ) ? sanitize_text_field( $_GET['log_type'] ) : '';
        $current_page = isset( $_GET['log_page'] ) ? max( 1, absint( $_GET['log_page'] ) ) : 1;
        $search_term = isset( $_GET['log_search'] ) ? sanitize_text_field( $_GET['log_search'] ) : '';
        $per_page = 25;

        // Get log counts and paginated logs
        $counts = $this->logger->get_log_counts();
        $result = $this->logger->get_logs_paginated( $current_page, $per_page, $current_filter, $search_term );
        $logs = $result['logs'];
        $total = $result['total'];
        $total_pages = ceil( $total / $per_page );

        ?>
        <h2>Activity Log</h2>
        
        <!-- Search Bar -->
        <div style="margin-bottom: 15px;">
            <form method="get" action="" style="display: flex; gap: 10px; align-items: center;">
                <input type="hidden" name="page" value="saurity" />
                <?php if ( $current_filter ) : ?>
                    <input type="hidden" name="log_type" value="<?php echo esc_attr( $current_filter ); ?>" />
                <?php endif; ?>
                <input type="text" 
                       name="log_search" 
                       value="<?php echo esc_attr( $search_term ); ?>" 
                       placeholder="Search logs (message, IP, username)..." 
                       style="flex: 1; max-width: 400px;" />
                <button type="submit" class="button">Search</button>
                <?php if ( $search_term ) : ?>
                    <a href="<?php echo esc_url( remove_query_arg( [ 'log_search', 'log_page' ] ) ); ?>" 
                       class="button">Clear Search</a>
                <?php endif; ?>
            </form>
            <?php if ( $search_term ) : ?>
                <p style="margin: 8px 0 0 0; font-size: 13px; color: #666;">
                    Searching for: <strong>"<?php echo esc_html( $search_term ); ?>"</strong> 
                    (<?php echo esc_html( $total ); ?> results)
                </p>
            <?php endif; ?>
        </div>

        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
            <!-- Filter Tabs -->
            <div class="nav-tab-wrapper">
                <a href="<?php echo esc_url( add_query_arg( [ 'log_page' => 1 ], remove_query_arg( 'log_type' ) ) ); ?>" 
                   class="nav-tab <?php echo empty( $current_filter ) ? 'nav-tab-active' : ''; ?>">
                    All (<?php echo esc_html( $counts['all'] ); ?>)
                </a>
                <a href="<?php echo esc_url( add_query_arg( [ 'log_type' => 'info', 'log_page' => 1 ] ) ); ?>" 
                   class="nav-tab <?php echo $current_filter === 'info' ? 'nav-tab-active' : ''; ?>">
                    Info (<?php echo esc_html( $counts['info'] ); ?>)
                </a>
                <a href="<?php echo esc_url( add_query_arg( [ 'log_type' => 'warning', 'log_page' => 1 ] ) ); ?>" 
                   class="nav-tab <?php echo $current_filter === 'warning' ? 'nav-tab-active' : ''; ?>">
                    Warning (<?php echo esc_html( $counts['warning'] ); ?>)
                </a>
                <a href="<?php echo esc_url( add_query_arg( [ 'log_type' => 'error', 'log_page' => 1 ] ) ); ?>" 
                   class="nav-tab <?php echo $current_filter === 'error' ? 'nav-tab-active' : ''; ?>">
                    Error (<?php echo esc_html( $counts['error'] ); ?>)
                </a>
                <a href="<?php echo esc_url( add_query_arg( [ 'log_type' => 'critical', 'log_page' => 1 ] ) ); ?>" 
                   class="nav-tab <?php echo $current_filter === 'critical' ? 'nav-tab-active' : ''; ?>">
                    Critical (<?php echo esc_html( $counts['critical'] ); ?>)
                </a>
            </div>

            <!-- Clear Logs Button -->
            <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin: 0;">
                <input type="hidden" name="action" value="saurity_clear_logs" />
                <?php wp_nonce_field( 'saurity_clear_logs' ); ?>
                <button type="submit" class="button" onclick="return confirm('Clear all logs?');">Clear Logs</button>
            </form>
        </div>

        <!-- Log Entries -->
        <div style="border: 1px solid #ddd; background: #f9f9f9;">
            <?php if ( empty( $logs ) ) : ?>
                <div style="padding: 20px; text-align: center; color: #666;">
                    No activity logged yet.
                </div>
            <?php else : ?>
                <?php foreach ( $logs as $log ) : ?>
                    <div style="padding: 12px; background: white; border-bottom: 1px solid #ddd; border-left: 3px solid <?php echo esc_attr( $this->get_log_color( $log['event_type'] ) ); ?>;">
                        <div style="display: flex; justify-content: space-between; align-items: start; gap: 15px;">
                            <div style="flex: 1;">
                                <div style="margin-bottom: 5px;">
                                    <span style="font-weight: 600; color: <?php echo esc_attr( $this->get_log_color( $log['event_type'] ) ); ?>;">
                                        [<?php echo esc_html( strtoupper( $log['event_type'] ) ); ?>]
                                    </span>
                                    <span style="color: #666; font-size: 13px;">
                                        <?php echo esc_html( $log['created_at'] ); ?>
                                    </span>
                                </div>
                                <div style="font-size: 14px;">
                                    <?php echo esc_html( $log['message'] ); ?>
                                </div>
                                <?php if ( $log['ip_address'] || $log['user_login'] ) : ?>
                                    <div style="font-size: 12px; color: #666; margin-top: 5px;">
                                        <?php if ( $log['user_login'] ) : ?>
                                            <span>User: <?php echo esc_html( $log['user_login'] ); ?></span>
                                        <?php endif; ?>
                                        <?php if ( $log['ip_address'] ) : ?>
                                            <span><?php echo $log['user_login'] ? ' | ' : ''; ?>IP: <?php echo esc_html( $log['ip_address'] ); ?></span>
                                        <?php endif; ?>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <!-- Pagination -->
        <?php if ( $total_pages > 1 ) : ?>
            <div style="margin-top: 15px; text-align: center;">
                <?php
                $page_links = paginate_links( [
                    'base' => add_query_arg( 'log_page', '%#%' ),
                    'format' => '',
                    'current' => $current_page,
                    'total' => $total_pages,
                    'prev_text' => '« Previous',
                    'next_text' => 'Next »',
                    'type' => 'plain',
                ] );

                if ( $page_links ) {
                    echo '<div class="tablenav"><div class="tablenav-pages">' . $page_links . '</div></div>';
                }
                ?>
            </div>
        <?php endif; ?>

        <p style="margin-top: 15px; font-size: 12px; color: #666;">
            <strong>Note:</strong> Logs older than 15 days are automatically deleted. 
            Showing <?php echo esc_html( count( $logs ) ); ?> of <?php echo esc_html( $total ); ?> total entries.
        </p>
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

        wp_safe_redirect( admin_url( 'admin.php?page=saurity' ) );
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
            add_settings_error(
                'saurity_messages',
                'saurity_message',
                'Protection enabled successfully. Your site is now being monitored.',
                'success'
            );
        } else {
            $this->kill_switch->activate( 'Manual activation by admin' );
            add_settings_error(
                'saurity_messages',
                'saurity_message',
                'Kill switch activated. All security enforcement is disabled.',
                'warning'
            );
        }

        set_transient( 'saurity_admin_notice', get_settings_errors( 'saurity_messages' ), 30 );
        wp_safe_redirect( admin_url( 'admin.php?page=saurity' ) );
        exit;
    }

    /**
     * Display admin notices
     */
    public function display_admin_notices() {
        $notices = get_transient( 'saurity_admin_notice' );
        
        if ( $notices ) {
            foreach ( $notices as $notice ) {
                $type = $notice['type'] === 'success' ? 'notice-success' : 'notice-warning';
                printf(
                    '<div class="notice %s is-dismissible"><p>%s</p></div>',
                    esc_attr( $type ),
                    esc_html( $notice['message'] )
                );
            }
            delete_transient( 'saurity_admin_notice' );
        }
    }

    /**
     * Add admin bar indicator when kill switch is active
     *
     * @param object $wp_admin_bar WordPress admin bar object.
     */
    public function add_admin_bar_indicator( $wp_admin_bar ) {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        if ( $this->kill_switch->is_active() ) {
            $wp_admin_bar->add_node( [
                'id'    => 'saurity-kill-switch',
                'title' => '<span class="saurity-kill-switch-indicator">⚠️ Saurity: Protection Disabled</span>',
                'href'  => admin_url( 'admin.php?page=saurity' ),
                'meta'  => [
                    'class' => 'saurity-kill-switch-warning',
                ],
            ] );
        } else {
            $wp_admin_bar->add_node( [
                'id'    => 'saurity-status',
                'title' => '<span class="saurity-status-indicator">🛡️ Saurity: Active</span>',
                'href'  => admin_url( 'admin.php?page=saurity' ),
                'meta'  => [
                    'class' => 'saurity-status-active',
                ],
            ] );
        }
    }

    /**
     * Enqueue admin styles
     */
    public function enqueue_admin_styles() {
        wp_add_inline_style( 'admin-bar', '
            #wpadminbar .saurity-kill-switch-warning {
                background-color: #dc3232 !important;
            }
            #wpadminbar .saurity-kill-switch-warning:hover {
                background-color: #a00 !important;
            }
            #wpadminbar .saurity-kill-switch-indicator {
                color: #fff !important;
                font-weight: bold;
            }
            #wpadminbar .saurity-status-active {
                background-color: #46b450 !important;
            }
            #wpadminbar .saurity-status-active:hover {
                background-color: #2ea44f !important;
            }
            #wpadminbar .saurity-status-indicator {
                color: #fff !important;
            }
        ' );
    }
}