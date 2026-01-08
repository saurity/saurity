<?php
/**
 * Admin Interface
 *
 * @package Saurity
 */

namespace Saurity;

/**
 * Admin class - tabbed interface for better navigation
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
     * IP Manager instance
     *
     * @var IPManager
     */
    private $ip_manager;

    /**
     * Constructor
     *
     * @param ActivityLogger $logger Logger instance.
     * @param KillSwitch     $kill_switch Kill switch instance.
     */
    public function __construct( ActivityLogger $logger, KillSwitch $kill_switch ) {
        $this->logger = $logger;
        $this->kill_switch = $kill_switch;
        $this->ip_manager = new IPManager( $logger );
    }

    /**
     * Hook into WordPress
     */
    public function hook() {
        add_action( 'admin_menu', [ $this, 'add_menu' ] );
        add_action( 'admin_init', [ $this, 'register_settings' ] );
        add_action( 'admin_post_saurity_clear_logs', [ $this, 'handle_clear_logs' ] );
        add_action( 'admin_post_saurity_toggle_kill_switch', [ $this, 'handle_kill_switch_toggle' ] );
        add_action( 'admin_post_saurity_test_email', [ $this, 'handle_test_email' ] );
        add_action( 'admin_post_saurity_export_csv', [ $this, 'handle_export_csv' ] );
        add_action( 'admin_post_saurity_add_to_allowlist', [ $this, 'handle_add_to_allowlist' ] );
        add_action( 'admin_post_saurity_remove_from_allowlist', [ $this, 'handle_remove_from_allowlist' ] );
        add_action( 'admin_post_saurity_add_to_blocklist', [ $this, 'handle_add_to_blocklist' ] );
        add_action( 'admin_post_saurity_remove_from_blocklist', [ $this, 'handle_remove_from_blocklist' ] );
        add_action( 'admin_post_saurity_rotate_bypass_key', [ $this, 'handle_rotate_bypass_key' ] );
        add_action( 'admin_post_saurity_export_allowlist', [ $this, 'handle_export_allowlist' ] );
        add_action( 'admin_post_saurity_export_blocklist', [ $this, 'handle_export_blocklist' ] );
        add_action( 'admin_post_saurity_import_allowlist', [ $this, 'handle_import_allowlist' ] );
        add_action( 'admin_post_saurity_import_blocklist', [ $this, 'handle_import_blocklist' ] );
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
        // Feature toggles - simple boolean handling
        register_setting( 'saurity_settings', 'saurity_enable_rate_limiting', [
            'type' => 'boolean',
            'default' => true,
        ] );
        
        register_setting( 'saurity_settings', 'saurity_enable_firewall', [
            'type' => 'boolean',
            'default' => true,
        ] );
        
        register_setting( 'saurity_settings', 'saurity_enable_logging', [
            'type' => 'boolean',
            'default' => true,
        ] );
        
        register_setting( 'saurity_settings', 'saurity_enable_ip_management', [
            'type' => 'boolean',
            'default' => true,
        ] );
        
        register_setting( 'saurity_settings', 'saurity_rate_limit_attempts', [
            'type' => 'integer',
            'sanitize_callback' => function( $value ) {
                $value = absint( $value );
                return max( 1, min( 20, $value ) );
            },
            'default' => 5,
        ] );
        
        register_setting( 'saurity_settings', 'saurity_rate_limit_window', [
            'type' => 'integer',
            'sanitize_callback' => function( $value ) {
                $value = absint( $value );
                return max( 60, min( 3600, $value ) );
            },
            'default' => 600,
        ] );
        
        register_setting( 'saurity_settings', 'saurity_hard_block_attempts', [
            'type' => 'integer',
            'sanitize_callback' => function( $value ) {
                $value = absint( $value );
                return max( 10, min( 100, $value ) );
            },
            'default' => 20,
        ] );
        
        register_setting( 'saurity_settings', 'saurity_hard_block_duration', [
            'type' => 'integer',
            'sanitize_callback' => function( $value ) {
                $value = absint( $value );
                return max( 300, min( 86400, $value ) );
            },
            'default' => 3600,
        ] );
        
        register_setting( 'saurity_settings', 'saurity_progressive_delay', [
            'type' => 'integer',
            'sanitize_callback' => function( $value ) {
                $value = absint( $value );
                return max( 1, min( 10, $value ) );
            },
            'default' => 2,
        ] );
        
        // POST Flood Settings
        register_setting( 'saurity_settings', 'saurity_enable_post_flood', [
            'type' => 'boolean',
            'default' => true,
        ] );
        
        register_setting( 'saurity_settings', 'saurity_post_flood_device_limit', [
            'type' => 'integer',
            'sanitize_callback' => function( $value ) {
                $value = absint( $value );
                return max( 5, min( 100, $value ) );
            },
            'default' => 20,
        ] );
        
        register_setting( 'saurity_settings', 'saurity_post_flood_ip_limit', [
            'type' => 'integer',
            'sanitize_callback' => function( $value ) {
                $value = absint( $value );
                return max( 50, min( 1000, $value ) );
            },
            'default' => 200,
        ] );
        
        register_setting( 'saurity_settings', 'saurity_post_flood_window', [
            'type' => 'integer',
            'sanitize_callback' => function( $value ) {
                $value = absint( $value );
                return max( 30, min( 300, $value ) );
            },
            'default' => 60,
        ] );
        
        // XML-RPC Settings
        register_setting( 'saurity_settings', 'saurity_enable_xmlrpc_protection', [
            'type' => 'boolean',
            'default' => true,
        ] );
        
        register_setting( 'saurity_settings', 'saurity_xmlrpc_limit', [
            'type' => 'integer',
            'sanitize_callback' => function( $value ) {
                $value = absint( $value );
                return max( 1, min( 50, $value ) );
            },
            'default' => 10,
        ] );
        
        register_setting( 'saurity_settings', 'saurity_xmlrpc_window', [
            'type' => 'integer',
            'sanitize_callback' => function( $value ) {
                $value = absint( $value );
                return max( 30, min( 300, $value ) );
            },
            'default' => 60,
        ] );
        
        // Comment Rate Limiting Settings
        register_setting( 'saurity_settings', 'saurity_enable_comment_rate_limiting', [
            'type' => 'boolean',
            'default' => true,
        ] );
        
        register_setting( 'saurity_settings', 'saurity_comment_rate_limit', [
            'type' => 'integer',
            'sanitize_callback' => function( $value ) {
                $value = absint( $value );
                return max( 1, min( 20, $value ) );
            },
            'default' => 3,
        ] );
        
        register_setting( 'saurity_settings', 'saurity_comment_rate_window', [
            'type' => 'integer',
            'sanitize_callback' => function( $value ) {
                $value = absint( $value );
                return max( 60, min( 1800, $value ) );
            },
            'default' => 300,
        ] );
        
        // General Request Throttling (DoS Protection)
        register_setting( 'saurity_settings', 'saurity_enable_request_throttle', [
            'type' => 'boolean',
            'default' => false, // Disabled by default
        ] );
        
        register_setting( 'saurity_settings', 'saurity_request_throttle_limit', [
            'type' => 'integer',
            'sanitize_callback' => function( $value ) {
                $value = absint( $value );
                return max( 60, min( 300, $value ) );
            },
            'default' => 120, // High default to avoid false positives
        ] );
        
        register_setting( 'saurity_settings', 'saurity_request_throttle_window', [
            'type' => 'integer',
            'sanitize_callback' => function( $value ) {
                $value = absint( $value );
                return max( 30, min( 120, $value ) );
            },
            'default' => 60,
        ] );
        
        // Advanced Security Features
        register_setting( 'saurity_settings', 'saurity_enable_subnet_blocking', [
            'type' => 'boolean',
            'default' => false,
        ] );
        
        register_setting( 'saurity_settings', 'saurity_subnet_failure_threshold', [
            'type' => 'integer',
            'sanitize_callback' => function( $value ) {
                $value = absint( $value );
                return max( 10, min( 100, $value ) );
            },
            'default' => 30,
        ] );
        
        register_setting( 'saurity_settings', 'saurity_enable_tarpitting', [
            'type' => 'boolean',
            'default' => true, // Enabled by default for better security
        ] );
        
        register_setting( 'saurity_settings', 'saurity_tarpit_delay', [
            'type' => 'integer',
            'sanitize_callback' => function( $value ) {
                $value = absint( $value );
                return max( 1, min( 10, $value ) );
            },
            'default' => 3,
        ] );
        
        register_setting( 'saurity_settings', 'saurity_enable_honeypot', [
            'type' => 'boolean',
            'default' => true, // Enabled by default - zero false positives
        ] );
        
        register_setting( 'saurity_settings', 'saurity_enable_timing_check', [
            'type' => 'boolean',
            'default' => true, // Enabled by default
        ] );
        
        register_setting( 'saurity_settings', 'saurity_min_form_time', [
            'type' => 'integer',
            'sanitize_callback' => function( $value ) {
                $value = absint( $value );
                return max( 1, min( 10, $value ) );
            },
            'default' => 2,
        ] );
        
        register_setting( 'saurity_settings', 'saurity_email_notifications', [
            'type' => 'boolean',
            'default' => true,
        ] );
        
        register_setting( 'saurity_settings', 'saurity_notification_email', [
            'type' => 'string',
            'sanitize_callback' => function( $value ) {
                if ( empty( $value ) ) {
                    return get_option( 'admin_email' );
                }
                $email = sanitize_email( $value );
                return is_email( $email ) ? $email : get_option( 'admin_email' );
            },
            'default' => '',
        ] );
        
        register_setting( 'saurity_settings', 'saurity_log_retention_days', [
            'type' => 'integer',
            'sanitize_callback' => function( $value ) {
                $value = absint( $value );
                return max( 1, min( 365, $value ) );
            },
            'default' => 15,
        ] );
    }

    /**
     * Render admin page with tabs
     */
    public function render_page() {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        $current_tab = isset( $_GET['tab'] ) ? sanitize_text_field( $_GET['tab'] ) : 'dashboard';
        $kill_switch_active = $this->kill_switch->is_active();

        ?>
        <div class="wrap">
            <h1>Saurity Security v<?php echo esc_html( SAURITY_VERSION ); ?></h1>

            <?php if ( $kill_switch_active ) : ?>
                <div class="notice notice-warning" style="padding: 15px; display: flex; align-items: center; gap: 15px; border-left: 4px solid #ff9800;">
                    <div style="flex: 1;">
                        <strong>Kill Switch Active</strong> - All security enforcement is disabled.
                    </div>
                    <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin: 0;">
                        <input type="hidden" name="action" value="saurity_toggle_kill_switch" />
                        <?php wp_nonce_field( 'saurity_kill_switch' ); ?>
                        <button type="submit" class="button button-primary">Enable Protection</button>
                    </form>
                </div>
            <?php endif; ?>

            <!-- Tab Navigation -->
            <h2 class="nav-tab-wrapper">
                <a href="?page=saurity&tab=dashboard" class="nav-tab <?php echo $current_tab === 'dashboard' ? 'nav-tab-active' : ''; ?>">
                    Dashboard
                </a>
                <a href="?page=saurity&tab=settings" class="nav-tab <?php echo $current_tab === 'settings' ? 'nav-tab-active' : ''; ?>">
                    Settings
                </a>
                <a href="?page=saurity&tab=logs" class="nav-tab <?php echo $current_tab === 'logs' ? 'nav-tab-active' : ''; ?>">
                    Activity Log
                </a>
                <a href="?page=saurity&tab=recovery" class="nav-tab <?php echo $current_tab === 'recovery' ? 'nav-tab-active' : ''; ?>">
                    Recovery
                </a>
                <a href="?page=saurity&tab=ip-management" class="nav-tab <?php echo $current_tab === 'ip-management' ? 'nav-tab-active' : ''; ?>">
                    IP Management
                </a>
            </h2>

            <!-- Tab Content -->
            <div class="tab-content" style="margin-top: 20px;">
                <?php
                switch ( $current_tab ) {
                    case 'settings':
                        $this->render_all_settings();
                        break;
                    case 'logs':
                        $this->render_activity_log();
                        break;
                    case 'recovery':
                        $this->render_recovery_tab();
                        break;
                    case 'ip-management':
                        $this->render_ip_management();
                        break;
                    case 'dashboard':
                    default:
                        $this->render_dashboard();
                        break;
                }
                ?>
            </div>
        </div>
        <?php
    }

    /**
     * Render dashboard tab
     */
    private function render_dashboard() {
        $kill_switch_active = $this->kill_switch->is_active();
        
        // Cache dashboard data for 5 minutes to improve performance
        $cache_key = 'saurity_dashboard_data';
        $dashboard_data = get_transient( $cache_key );
        
        if ( false === $dashboard_data ) {
            $dashboard_data = [
                'counts' => $this->logger->get_log_counts(),
                'recent_logs' => $this->logger->get_logs( 10 ),
            ];
            set_transient( $cache_key, $dashboard_data, 300 );
        }
        
        $counts = $dashboard_data['counts'];
        $recent_logs = $dashboard_data['recent_logs'];
        ?>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px;">
            <!-- Status Card -->
            <div style="background: <?php echo $kill_switch_active ? '#fff3cd' : '#d4edda'; ?>; padding: 20px; border-radius: 8px; border: 1px solid <?php echo $kill_switch_active ? '#ffc107' : '#28a745'; ?>; border-left: 4px solid <?php echo $kill_switch_active ? '#ff9800' : '#28a745'; ?>;">
                <h3 style="margin: 0 0 10px 0; color: #333; font-size: 14px; text-transform: uppercase; letter-spacing: 0.5px;">Protection Status</h3>
                <p style="font-size: 18px; margin: 0; font-weight: 600;">
                    <?php echo $kill_switch_active ? 'Disabled' : 'Active'; ?>
                </p>
            </div>

            <!-- Total Events -->
            <div style="background: #e7f3ff; padding: 20px; border-radius: 8px; border: 1px solid #2196F3; border-left: 4px solid #2196F3;">
                <h3 style="margin: 0 0 10px 0; color: #333; font-size: 14px; text-transform: uppercase; letter-spacing: 0.5px;">Total Events</h3>
                <p style="font-size: 32px; margin: 0; font-weight: 600; color: #2196F3;">
                    <?php echo esc_html( $counts['all'] ); ?>
                </p>
            </div>

            <!-- Warnings -->
            <div style="background: #fff3cd; padding: 20px; border-radius: 8px; border: 1px solid #ffc107; border-left: 4px solid #ff9800;">
                <h3 style="margin: 0 0 10px 0; color: #333; font-size: 14px; text-transform: uppercase; letter-spacing: 0.5px;">Warnings</h3>
                <p style="font-size: 32px; margin: 0; font-weight: 600; color: #ff9800;">
                    <?php echo esc_html( $counts['warning'] ); ?>
                </p>
            </div>

            <!-- Critical/Errors -->
            <div style="background: #f8d7da; padding: 20px; border-radius: 8px; border: 1px solid #f44336; border-left: 4px solid #dc3232;">
                <h3 style="margin: 0 0 10px 0; color: #333; font-size: 14px; text-transform: uppercase; letter-spacing: 0.5px;">Critical/Errors</h3>
                <p style="font-size: 32px; margin: 0; font-weight: 600; color: #dc3232;">
                    <?php echo esc_html( $counts['critical'] + $counts['error'] ); ?>
                </p>
            </div>
        </div>

        <!-- Plugin Showcase Card -->
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 12px; margin-bottom: 30px; color: white; box-shadow: 0 10px 30px rgba(102, 126, 234, 0.3);">
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 30px; align-items: center;">
                <div>
                    <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 15px;">
                        <span style="font-size: 48px;">🛡️</span>
                        <div>
                            <h2 style="margin: 0; color: white; font-size: 28px;">Saurity Security</h2>
                            <p style="margin: 5px 0 0 0; opacity: 0.9; font-size: 14px;">Enterprise-Grade Protection for WordPress</p>
                        </div>
                    </div>
                    <p style="margin: 20px 0; line-height: 1.8; opacity: 0.95;">
                        Protect your WordPress site with intelligent rate limiting, advanced firewall rules, 
                        IP management, and real-time activity logging. Built for performance and reliability.
                    </p>
                    <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                        <a href="?page=saurity&tab=settings" class="button button-secondary" style="background: rgba(255,255,255,0.2); border: 1px solid rgba(255,255,255,0.3); color: white; text-shadow: none;">
                            ⚙️ Configure Settings
                        </a>
                        <a href="?page=saurity&tab=ip-management" class="button button-secondary" style="background: rgba(255,255,255,0.2); border: 1px solid rgba(255,255,255,0.3); color: white; text-shadow: none;">
                            🔒 Manage IPs
                        </a>
                        <a href="?page=saurity&tab=recovery" class="button button-secondary" style="background: rgba(255,255,255,0.2); border: 1px solid rgba(255,255,255,0.3); color: white; text-shadow: none;">
                            🆘 Recovery Options
                        </a>
                    </div>
                </div>
                <div style="background: rgba(255,255,255,0.1); padding: 25px; border-radius: 8px; backdrop-filter: blur(10px);">
                    <h3 style="margin: 0 0 15px 0; color: white; font-size: 18px;">🎯 Key Features</h3>
                    <ul style="margin: 0; padding: 0; list-style: none; line-height: 2;">
                        <li style="display: flex; align-items: center; gap: 10px;">
                            <span style="background: rgba(255,255,255,0.2); width: 24px; height: 24px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; flex-shrink: 0;">✓</span>
                            <span>Fully Configurable Rate Limiting (All Optional)</span>
                        </li>
                        <li style="display: flex; align-items: center; gap: 10px;">
                            <span style="background: rgba(255,255,255,0.2); width: 24px; height: 24px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; flex-shrink: 0;">✓</span>
                            <span>Login, POST, XML-RPC & Comment Protection</span>
                        </li>
                        <li style="display: flex; align-items: center; gap: 10px;">
                            <span style="background: rgba(255,255,255,0.2); width: 24px; height: 24px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; flex-shrink: 0;">✓</span>
                            <span>Two-Tier System (NAT/Office Safe)</span>
                        </li>
                        <li style="display: flex; align-items: center; gap: 10px;">
                            <span style="background: rgba(255,255,255,0.2); width: 24px; height: 24px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; flex-shrink: 0;">✓</span>
                            <span>Advanced Firewall (SQLi, XSS Detection)</span>
                        </li>
                        <li style="display: flex; align-items: center; gap: 10px;">
                            <span style="background: rgba(255,255,255,0.2); width: 24px; height: 24px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; flex-shrink: 0;">✓</span>
                            <span>IP Allowlist & Blocklist (CIDR Support)</span>
                        </li>
                        <li style="display: flex; align-items: center; gap: 10px;">
                            <span style="background: rgba(255,255,255,0.2); width: 24px; height: 24px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; flex-shrink: 0;">✓</span>
                            <span>Real-Time Activity Logging & Alerts</span>
                        </li>
                        <li style="display: flex; align-items: center; gap: 10px;">
                            <span style="background: rgba(255,255,255,0.2); width: 24px; height: 24px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; flex-shrink: 0;">✓</span>
                            <span>Emergency Recovery & Kill Switch</span>
                        </li>
                    </ul>
                </div>
            </div>
        </div>

        <h2>Recent Activity</h2>
        <?php
        if ( empty( $recent_logs ) ) {
            echo '<p style="color: #666;">No recent activity.</p>';
        } else {
            echo '<div style="border: 1px solid #ddd; background: #f9f9f9;">';
            foreach ( $recent_logs as $log ) {
                ?>
                <div style="padding: 12px; background: white; border-bottom: 1px solid #ddd; border-left: 3px solid <?php echo esc_attr( $this->get_log_color( $log['event_type'] ) ); ?>;">
                    <div style="font-weight: 600; color: <?php echo esc_attr( $this->get_log_color( $log['event_type'] ) ); ?>; margin-bottom: 5px;">
                        [<?php echo esc_html( strtoupper( $log['event_type'] ) ); ?>] 
                        <span style="color: #666; font-weight: normal; font-size: 13px;"><?php echo esc_html( $log['created_at'] ); ?></span>
                    </div>
                    <div><?php echo esc_html( $log['message'] ); ?></div>
                </div>
                <?php
            }
            echo '</div>';
        }
        ?>
        <p style="margin-top: 15px;">
            <a href="?page=saurity&tab=logs" class="button button-primary">View Full Activity Log →</a>
        </p>
        <?php
    }

    /**
     * Render all settings in one tab
     */
    private function render_all_settings() {
        ?>
        <form method="post" action="options.php">
            <?php settings_fields( 'saurity_settings' ); ?>
            <?php $this->render_tooltip_styles(); ?>
            
            <h2>Feature Modules</h2>
            <p style="margin-bottom: 20px; color: #666;">
                Enable or disable individual security features based on your needs. 
                All features work independently - you can use logging without rate limiting, or firewall without login protection.
            </p>
            
            <table class="form-table">
                <tr>
                    <th>
                        <span class="saurity-setting-label">
                            Rate Limiting (Master Switch)
                            <?php $this->render_info_icon( 'MASTER SWITCH: Disabling this turns OFF all rate limiting features (Login, POST Flood, XML-RPC, Comments). If enabled, you can then individually control each rate limit type in their respective sections below.' ); ?>
                        </span>
                    </th>
                    <td>
                        <label>
                            <input type="checkbox" name="saurity_enable_rate_limiting" value="1" 
                                   <?php checked( get_option( 'saurity_enable_rate_limiting', true ) ); ?> />
                            <strong>Enable All Rate Limiting</strong>
                        </label>
                        <p class="description">
                            Master switch for ALL rate limits (Login, POST, XML-RPC, Comments)
                        </p>
                    </td>
                </tr>
                <tr>
                    <th>
                        <span class="saurity-setting-label">
                            Firewall Protection
                            <?php $this->render_info_icon( 'Content inspection engine: Blocks SQL injection, XSS attacks, malicious user agents, sensitive file access, and dangerous HTTP methods. Does NOT handle rate limiting - that\'s managed by separate rate limit features below.' ); ?>
                        </span>
                    </th>
                    <td>
                        <label>
                            <input type="checkbox" name="saurity_enable_firewall" value="1" 
                                   <?php checked( get_option( 'saurity_enable_firewall', true ) ); ?> />
                            <strong>Enable Firewall</strong>
                        </label>
                        <p class="description">
                            Content inspection: SQLi, XSS, malicious patterns, sensitive paths
                        </p>
                    </td>
                </tr>
                <tr>
                    <th>
                        <span class="saurity-setting-label">
                            Activity Logging
                            <?php $this->render_info_icon( 'Records security events, user logins, failed attempts, and system changes. Can be used independently for monitoring only.' ); ?>
                        </span>
                    </th>
                    <td>
                        <label>
                            <input type="checkbox" name="saurity_enable_logging" value="1" 
                                   <?php checked( get_option( 'saurity_enable_logging', true ) ); ?> />
                            <strong>Enable Activity Logging</strong>
                        </label>
                        <p class="description">
                            Records all security events and user activity (15-day retention)
                        </p>
                    </td>
                </tr>
                <tr>
                    <th>
                        <span class="saurity-setting-label">
                            IP Management (Allowlist/Blocklist)
                            <?php $this->render_info_icon( 'Manually manage trusted and blocked IP addresses. Works with other features when enabled.' ); ?>
                        </span>
                    </th>
                    <td>
                        <label>
                            <input type="checkbox" name="saurity_enable_ip_management" value="1" 
                                   <?php checked( get_option( 'saurity_enable_ip_management', true ) ); ?> />
                            <strong>Enable IP Management</strong>
                        </label>
                        <p class="description">
                            Allowlist and blocklist functionality
                        </p>
                    </td>
                </tr>
                <tr>
                    <th>
                        <span class="saurity-setting-label">
                            Email Notifications
                            <?php $this->render_info_icon( 'Sends email alerts when critical security events occur: Hard blocks, kill switch changes, bypass URL usage. Rate-limited to prevent spam (max 1 email per event type every 15 minutes)' ); ?>
                        </span>
                    </th>
                    <td>
                        <label>
                            <input type="checkbox" name="saurity_email_notifications" value="1" 
                                   <?php checked( get_option( 'saurity_email_notifications', true ) ); ?> />
                            <strong>Enable Email Notifications</strong>
                        </label>
                        <p class="description">
                            Send alerts for critical security events
                        </p>
                    </td>
                </tr>
            </table>

            <div style="background: #f0f0f0; padding: 15px; border-radius: 4px; margin: 20px 0;">
                <?php submit_button( 'Save Feature Settings', 'primary', 'submit', false ); ?>
                <p class="description" style="margin: 10px 0 0 0;">
                    Save your feature module choices before continuing to other sections.
                </p>
            </div>

            <hr style="margin: 30px 0;">

            <h2>Activity Log Settings</h2>
            <p style="margin-bottom: 15px; color: #666;">
                Configure how long activity logs are retained before automatic cleanup.
            </p>
            <table class="form-table">
                <tr>
                    <th>
                        <span class="saurity-setting-label">
                            Log Retention Period
                            <?php $this->render_info_icon( 'How many days to keep activity logs before automatic deletion. Logs older than this will be deleted during daily cleanup. Recommended: 15-30 days for most sites, 90+ days for compliance requirements.' ); ?>
                        </span>
                    </th>
                    <td>
                        <input type="number" name="saurity_log_retention_days" 
                               value="<?php echo esc_attr( get_option( 'saurity_log_retention_days', 15 ) ); ?>" 
                               min="1" max="365" />
                        <p class="description">Days to keep logs (1-365, default: 15 days)</p>
                        
                        <?php
                        $retention_days = get_option( 'saurity_log_retention_days', 15 );
                        $disk_estimate = ceil( $retention_days / 15 * 1 ); // Rough estimate: 1MB per 15 days
                        ?>
                        <p class="description" style="color: #666; margin-top: 5px;">
                            <strong>Current setting:</strong> <?php echo esc_html( $retention_days ); ?> days<br>
                            <strong>Estimated disk usage:</strong> ~<?php echo esc_html( $disk_estimate ); ?>MB for <?php echo esc_html( $retention_days ); ?> days of logs
                        </p>
                    </td>
                </tr>
            </table>

            <div style="background: #f0f0f0; padding: 15px; border-radius: 4px; margin: 20px 0;">
                <?php submit_button( 'Save Log Settings', 'primary', 'submit', false ); ?>
                <p class="description" style="margin: 10px 0 0 0;">
                    Changes take effect during next automatic cleanup (runs daily).
                </p>
            </div>

            <hr style="margin: 30px 0;">

            <h2>Email Notification Settings</h2>
            <p style="margin-bottom: 15px; color: #666;">
                Configure email address for security alerts. <strong>Remember to save before testing!</strong>
            </p>
            <table class="form-table">
                <tr>
                    <th>
                        <span class="saurity-setting-label">
                            Notification Email
                            <?php $this->render_info_icon( 'The email address that receives security alerts. Default: Uses your WordPress admin email if not specified. Tip: Use a dedicated security monitoring email' ); ?>
                        </span>
                    </th>
                    <td>
                        <input type="email" name="saurity_notification_email" 
                               value="<?php echo esc_attr( get_option( 'saurity_notification_email', get_option( 'admin_email' ) ) ); ?>" 
                               class="regular-text" 
                               placeholder="<?php echo esc_attr( get_option( 'admin_email' ) ); ?>" />
                        <p class="description">Leave blank to use admin email (<?php echo esc_html( get_option( 'admin_email' ) ); ?>)</p>
                        
                        <!-- Save button right after email field -->
                        <div style="margin-top: 10px;">
                            <?php submit_button( 'Save Email Settings', 'primary', 'submit', false ); ?>
                            <p class="description" style="margin: 5px 0 0 0;">
                                <strong>Important:</strong> Save your email address before sending a test email!
                            </p>
                        </div>
                    </td>
                </tr>
                <tr>
                    <th>Test Notifications</th>
                    <td>
                        <a href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=saurity_test_email' ), 'saurity_test' ); ?>" 
                           class="button button-secondary">
                            Send Test Email
                        </a>
                        <p class="description">Click "Save Email Settings" above before testing</p>
                        
                        <?php
                        // Check if an SMTP plugin is active
                        $smtp_plugins = [
                            'wp-mail-smtp/wp_mail_smtp.php' => 'WP Mail SMTP',
                            'easy-wp-smtp/easy-wp-smtp.php' => 'Easy WP SMTP',
                            'post-smtp/postman-smtp.php' => 'Post SMTP',
                            'wp-ses/wp-ses.php' => 'WP SES',
                        ];
                        
                        $active_smtp = [];
                        foreach ( $smtp_plugins as $plugin_file => $plugin_name ) {
                            if ( is_plugin_active( $plugin_file ) ) {
                                $active_smtp[] = $plugin_name;
                            }
                        }
                        
                        if ( empty( $active_smtp ) ) :
                        ?>
                            <div style="margin-top: 10px; padding: 10px; background: #fff3cd; border-left: 4px solid #ffc107;">
                                <strong>Email Delivery Tip:</strong><br>
                                Many WordPress sites can't send emails reliably. If you don't receive test emails:<br>
                                <ol style="margin: 5px 0 0 20px; font-size: 13px;">
                                    <li>Install <strong>WP Mail SMTP</strong> or <strong>Easy WP SMTP</strong> plugin</li>
                                    <li>Configure with Gmail, SendGrid, or your email provider</li>
                                    <li>Test again - emails should work reliably</li>
                                </ol>
                            </div>
                        <?php else : ?>
                            <div style="margin-top: 10px; padding: 10px; background: #d4edda; border-left: 4px solid #28a745;">
                                <strong>SMTP Plugin Detected:</strong> <?php echo esc_html( implode( ', ', $active_smtp ) ); ?><br>
                                <span style="font-size: 13px;">Email delivery should be reliable.</span>
                            </div>
                        <?php endif; ?>
                    </td>
                </tr>
            </table>

            <hr style="margin: 30px 0;">

            <h2>Login Rate Limiting Configuration</h2>
            <p style="margin-bottom: 15px;">
                <?php if ( ! get_option( 'saurity_enable_rate_limiting', true ) ) : ?>
                    <span style="background: #f8d7da; padding: 8px 12px; border-radius: 4px; border-left: 4px solid #dc3232; display: inline-block;">
                        <strong>Note:</strong> Rate limiting is currently disabled. These settings will have no effect.
                    </span>
                <?php endif; ?>
            </p>
            <table class="form-table">
                <tr>
                    <th>
                        <span class="saurity-setting-label">
                            Rate Limit Attempts
                            <?php $this->render_info_icon( 'Sets how many failed login attempts are allowed before throttling begins. Example: With 5 attempts, after the 5th failed login, delays start increasing exponentially. Recommended: 5-10 for most sites' ); ?>
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
                            <?php $this->render_info_icon( 'The time period (in seconds) during which failed attempts are counted. Example: 600 seconds (10 minutes) means if someone fails 5 times in 10 minutes, they\'ll be throttled. Recommended: 600-900 seconds' ); ?>
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
                            <?php $this->render_info_icon( 'After this many failed attempts, the IP is completely blocked for a set duration. Example: With 20 attempts, after 20 failures, the IP cannot access the site at all. Recommended: 15-25' ); ?>
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
                            <?php $this->render_info_icon( 'How long (in seconds) an IP stays blocked after hitting the hard block threshold. Example: 3600 seconds = 1 hour of complete blocking. Recommended: 3600-7200 seconds' ); ?>
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
                            <?php $this->render_info_icon( 'Base delay time that grows exponentially with each failed attempt. How it works: 2 seconds = 1st fail: 2s, 2nd: 4s, 3rd: 8s, 4th: 16s delay, etc. Recommended: 2-3 seconds' ); ?>
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

            <div style="background: #f0f0f0; padding: 15px; border-radius: 4px; margin: 20px 0;">
                <?php submit_button( 'Save Login Rate Limiting', 'primary', 'submit', false ); ?>
            </div>

            <hr style="margin: 30px 0;">

            <h2>POST Flood Protection</h2>
            <p style="margin-bottom: 15px; color: #666;">
                Protects against form spam and POST request floods using a two-tier system (device + IP).
            </p>
            <table class="form-table">
                <tr>
                    <th>
                        <span class="saurity-setting-label">
                            Enable POST Flood Protection
                            <?php $this->render_info_icon( 'Protects against rapid form submissions and POST floods. Uses two-tier system: limits per device (IP+UA) and per IP (for NAT/office safety). Logged-in users bypass these limits.' ); ?>
                        </span>
                    </th>
                    <td>
                        <label>
                            <input type="checkbox" name="saurity_enable_post_flood" value="1" 
                                   <?php checked( get_option( 'saurity_enable_post_flood', true ) ); ?> />
                            <strong>Enable POST Flood Protection</strong>
                        </label>
                    </td>
                </tr>
                <tr>
                    <th>
                        <span class="saurity-setting-label">
                            Device Limit (Tier 1)
                            <?php $this->render_info_icon( 'POST requests per minute from a specific device (IP + User Agent combination). Stops spam bots on individual computers. Recommended: 20-30' ); ?>
                        </span>
                    </th>
                    <td>
                        <input type="number" name="saurity_post_flood_device_limit" 
                               value="<?php echo esc_attr( get_option( 'saurity_post_flood_device_limit', 20 ) ); ?>" 
                               min="5" max="100" />
                        <p class="description">Requests per minute per device (default: 20)</p>
                    </td>
                </tr>
                <tr>
                    <th>
                        <span class="saurity-setting-label">
                            IP Limit (Tier 2)
                            <?php $this->render_info_icon( 'POST requests per minute from an IP address (all devices). Allows offices/schools with shared IPs to function. Must be higher than device limit. Recommended: 150-250' ); ?>
                        </span>
                    </th>
                    <td>
                        <input type="number" name="saurity_post_flood_ip_limit" 
                               value="<?php echo esc_attr( get_option( 'saurity_post_flood_ip_limit', 200 ) ); ?>" 
                               min="50" max="1000" />
                        <p class="description">Requests per minute per IP (default: 200)</p>
                    </td>
                </tr>
                <tr>
                    <th>
                        <span class="saurity-setting-label">
                            Time Window
                            <?php $this->render_info_icon( 'Time period for counting POST requests. 60 seconds is optimal for catching floods without false positives. Recommended: 60-120 seconds' ); ?>
                        </span>
                    </th>
                    <td>
                        <input type="number" name="saurity_post_flood_window" 
                               value="<?php echo esc_attr( get_option( 'saurity_post_flood_window', 60 ) ); ?>" 
                               min="30" max="300" />
                        <p class="description">Window in seconds (default: 60)</p>
                    </td>
                </tr>
            </table>

            <div style="background: #f0f0f0; padding: 15px; border-radius: 4px; margin: 20px 0;">
                <?php submit_button( 'Save POST Flood Settings', 'primary', 'submit', false ); ?>
            </div>

            <hr style="margin: 30px 0;">

            <h2>XML-RPC Protection</h2>
            <p style="margin-bottom: 15px; color: #666;">
                Protects the xmlrpc.php endpoint from brute force and DDoS attacks.
            </p>
            <table class="form-table">
                <tr>
                    <th>
                        <span class="saurity-setting-label">
                            Enable XML-RPC Protection
                            <?php $this->render_info_icon( 'Limits XML-RPC requests to prevent brute force attacks. Most sites don\'t use XML-RPC. If you use Jetpack or mobile apps that require XML-RPC, adjust the limit accordingly.' ); ?>
                        </span>
                    </th>
                    <td>
                        <label>
                            <input type="checkbox" name="saurity_enable_xmlrpc_protection" value="1" 
                                   <?php checked( get_option( 'saurity_enable_xmlrpc_protection', true ) ); ?> />
                            <strong>Enable XML-RPC Protection</strong>
                        </label>
                        <p class="description">Block excessive XML-RPC requests</p>
                    </td>
                </tr>
                <tr>
                    <th>
                        <span class="saurity-setting-label">
                            XML-RPC Request Limit
                            <?php $this->render_info_icon( 'Maximum XML-RPC requests per minute from a single IP. 10 is generous for legitimate use. If using Jetpack, increase to 20-30. Recommended: 10 for most sites, 20+ if using XML-RPC actively' ); ?>
                        </span>
                    </th>
                    <td>
                        <input type="number" name="saurity_xmlrpc_limit" 
                               value="<?php echo esc_attr( get_option( 'saurity_xmlrpc_limit', 10 ) ); ?>" 
                               min="1" max="50" />
                        <p class="description">Requests per minute (default: 10)</p>
                    </td>
                </tr>
                <tr>
                    <th>
                        <span class="saurity-setting-label">
                            Time Window
                            <?php $this->render_info_icon( 'Time period for counting XML-RPC requests. 60 seconds is standard. Recommended: 60 seconds' ); ?>
                        </span>
                    </th>
                    <td>
                        <input type="number" name="saurity_xmlrpc_window" 
                               value="<?php echo esc_attr( get_option( 'saurity_xmlrpc_window', 60 ) ); ?>" 
                               min="30" max="300" />
                        <p class="description">Window in seconds (default: 60)</p>
                    </td>
                </tr>
            </table>

            <div style="background: #f0f0f0; padding: 15px; border-radius: 4px; margin: 20px 0;">
                <?php submit_button( 'Save XML-RPC Settings', 'primary', 'submit', false ); ?>
            </div>

            <hr style="margin: 30px 0;">

            <h2>Comment Rate Limiting</h2>
            <p style="margin-bottom: 15px; color: #666;">
                Prevents comment spam by limiting how many comments anonymous users can post.
            </p>
            <table class="form-table">
                <tr>
                    <th>
                        <span class="saurity-setting-label">
                            Enable Comment Rate Limiting
                            <?php $this->render_info_icon( 'Limits how many comments anonymous users can post in a time window. Logged-in users automatically bypass this limit. Prevents spam floods.' ); ?>
                        </span>
                    </th>
                    <td>
                        <label>
                            <input type="checkbox" name="saurity_enable_comment_rate_limiting" value="1" 
                                   <?php checked( get_option( 'saurity_enable_comment_rate_limiting', true ) ); ?> />
                            <strong>Enable Comment Rate Limiting</strong>
                        </label>
                        <p class="description">Limit anonymous comment submissions</p>
                    </td>
                </tr>
                <tr>
                    <th>
                        <span class="saurity-setting-label">
                            Comment Limit
                            <?php $this->render_info_icon( 'Maximum comments allowed from an anonymous user in the time window. Users get a warning at 2 comments and are blocked at 3+. Logged-in users bypass this. Recommended: 3-5' ); ?>
                        </span>
                    </th>
                    <td>
                        <input type="number" name="saurity_comment_rate_limit" 
                               value="<?php echo esc_attr( get_option( 'saurity_comment_rate_limit', 3 ) ); ?>" 
                               min="1" max="20" />
                        <p class="description">Comments allowed in time window (default: 3)</p>
                    </td>
                </tr>
                <tr>
                    <th>
                        <span class="saurity-setting-label">
                            Time Window
                            <?php $this->render_info_icon( 'Time period for counting comments. 300 seconds (5 minutes) is optimal for catching spam without blocking legitimate users. Recommended: 300-600 seconds' ); ?>
                        </span>
                    </th>
                    <td>
                        <input type="number" name="saurity_comment_rate_window" 
                               value="<?php echo esc_attr( get_option( 'saurity_comment_rate_window', 300 ) ); ?>" 
                               min="60" max="1800" />
                        <p class="description">Window in seconds (default: 300 = 5 minutes)</p>
                    </td>
                </tr>
            </table>

            <div style="background: #f0f0f0; padding: 15px; border-radius: 4px; margin: 20px 0;">
                <?php submit_button( 'Save Comment Rate Limiting', 'primary', 'submit', false ); ?>
            </div>

            <hr style="margin: 40px 0; border: none; border-top: 2px solid #667eea;">

            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 8px; margin-bottom: 30px; color: white;">
                <h2 style="margin: 0 0 10px 0; color: white; font-size: 24px;">🚀 Advanced Security Features</h2>
                <p style="margin: 0; opacity: 0.95; font-size: 14px;">
                    Enterprise-grade protection mechanisms that make attacks extremely expensive and time-consuming for attackers.
                </p>
            </div>

            <h3 style="color: #667eea; margin-top: 0;">General Request Throttling (DoS Protection)</h3>
            <p style="margin-bottom: 15px; color: #666;">
                Protects against web scrapers and DoS attacks by limiting ALL requests from anonymous users.
            </p>
            <table class="form-table">
                <tr>
                    <th>
                        <span class="saurity-setting-label">
                            Enable Request Throttling
                            <?php $this->render_info_icon( 'Limits ALL requests (GET/POST) from anonymous IPs. Stops scrapers and simple DoS attacks. HIGH limits prevent false positives. Logged-in users bypass. Use only if under attack. Recommended: Keep disabled unless needed.' ); ?>
                        </span>
                    </th>
                    <td>
                        <label>
                            <input type="checkbox" name="saurity_enable_request_throttle" value="1" 
                                   <?php checked( get_option( 'saurity_enable_request_throttle', false ) ); ?> />
                            <strong>Enable General Request Throttling</strong>
                        </label>
                        <p class="description" style="color: #d63301;">
                            <strong>Advanced feature</strong> - Disabled by default to avoid false positives
                        </p>
                    </td>
                </tr>
                <tr>
                    <th>
                        <span class="saurity-setting-label">
                            Request Limit
                            <?php $this->render_info_icon( 'Maximum requests per minute from an anonymous IP. 120 = 2 requests/second. Even fast users won\'t exceed this. Lower if under heavy attack. Recommended: 120-180 for normal sites, 60-90 if under active attack' ); ?>
                        </span>
                    </th>
                    <td>
                        <input type="number" name="saurity_request_throttle_limit" 
                               value="<?php echo esc_attr( get_option( 'saurity_request_throttle_limit', 120 ) ); ?>" 
                               min="60" max="300" />
                        <p class="description">Requests per minute (default: 120 = 2 requests/second)</p>
                        <p class="description" style="color: #666; margin-top: 5px;">
                            <strong>Reference:</strong> 120/min = 2/sec, 180/min = 3/sec, 60/min = 1/sec
                        </p>
                    </td>
                </tr>
                <tr>
                    <th>
                        <span class="saurity-setting-label">
                            Time Window
                            <?php $this->render_info_icon( 'Time period for counting requests. 60 seconds is standard for per-minute limiting. Recommended: 60 seconds' ); ?>
                        </span>
                    </th>
                    <td>
                        <input type="number" name="saurity_request_throttle_window" 
                               value="<?php echo esc_attr( get_option( 'saurity_request_throttle_window', 60 ) ); ?>" 
                               min="30" max="120" />
                        <p class="description">Window in seconds (default: 60)</p>
                    </td>
                </tr>
            </table>

            <h3 style="color: #667eea; margin-top: 30px;">Tarpitting (Attack Slowdown)</h3>
            <p style="margin-bottom: 15px; color: #666;">
                Adds delay before blocking to slow down attacks.
            </p>
            <table class="form-table">
                <tr>
                    <th>
                        <span class="saurity-setting-label">
                            Enable Tarpitting
                            <?php $this->render_info_icon( 'Adds a configurable delay (sleep) before showing block pages. This wastes attacker\'s time and resources. Legitimate users rarely see blocks. Highly recommended - enabled by default. Impact: 10k attempts/min → 20 attempts/min with 3s delay' ); ?>
                        </span>
                    </th>
                    <td>
                        <label>
                            <input type="checkbox" name="saurity_enable_tarpitting" value="1" 
                                   <?php checked( get_option( 'saurity_enable_tarpitting', true ) ); ?> />
                            <strong>Enable Tarpitting</strong>
                        </label>
                        <p class="description" style="color: #28a745;">
                            <strong>Recommended:</strong> Keep enabled for maximum security
                        </p>
                    </td>
                </tr>
                <tr>
                    <th>
                        <span class="saurity-setting-label">
                            Tarpit Delay
                            <?php $this->render_info_icon( 'How long (in seconds) to delay before showing block page. 3 seconds wastes attacker time without significantly impacting user experience (they\'re being blocked anyway). Recommended: 3-5 seconds for best balance' ); ?>
                        </span>
                    </th>
                    <td>
                        <input type="number" name="saurity_tarpit_delay" 
                               value="<?php echo esc_attr( get_option( 'saurity_tarpit_delay', 3 ) ); ?>" 
                               min="1" max="10" />
                        <p class="description">Delay in seconds (default: 3)</p>
                        <p class="description" style="color: #666; margin-top: 5px;">
                            <strong>Impact:</strong> 1s = 60 attempts/min, 3s = 20 attempts/min, 5s = 12 attempts/min, 10s = 6 attempts/min
                        </p>
                    </td>
                </tr>
            </table>

            <h3 style="color: #667eea; margin-top: 30px;">Subnet Blocking (Anti-Botnet)</h3>
            <p style="margin-bottom: 15px; color: #666;">
                Blocks entire IP ranges when failures exceed threshold.
            </p>
            <table class="form-table">
                <tr>
                    <th>
                        <span class="saurity-setting-label">
                            Enable Subnet Blocking
                            <?php $this->render_info_icon( 'Tracks login failures by subnet (first 3 IP octets). When a subnet exceeds the failure threshold, the entire /24 range (256 IPs) is blocked. Defeats botnets that rotate IPs. Disabled by default to avoid blocking shared hosting.' ); ?>
                        </span>
                    </th>
                    <td>
                        <label>
                            <input type="checkbox" name="saurity_enable_subnet_blocking" value="1" 
                                   <?php checked( get_option( 'saurity_enable_subnet_blocking', false ) ); ?> />
                            <strong>Enable Subnet Blocking</strong>
                        </label>
                        <p class="description" style="color: #666;">
                            <strong>Advanced feature</strong> - Only enable if experiencing botnet attacks
                        </p>
                    </td>
                </tr>
                <tr>
                    <th>
                        <span class="saurity-setting-label">
                            Subnet Failure Threshold
                            <?php $this->render_info_icon( 'How many login failures from a subnet before blocking the entire /24 range. Higher = fewer false positives. Example: 30 failures from different IPs in 192.168.1.x = block entire 192.168.1.0/24. Recommended: 30-50' ); ?>
                        </span>
                    </th>
                    <td>
                        <input type="number" name="saurity_subnet_failure_threshold" 
                               value="<?php echo esc_attr( get_option( 'saurity_subnet_failure_threshold', 30 ) ); ?>" 
                               min="10" max="100" />
                        <p class="description">Failures before subnet block (default: 30)</p>
                        <p class="description" style="color: #666; margin-top: 5px;">
                            <strong>Examples:</strong> 20 = Aggressive, 30 = Balanced (recommended), 50 = Conservative
                        </p>
                    </td>
                </tr>
            </table>

            <h3 style="color: #667eea; margin-top: 30px;">Advanced Bot Detection</h3>
            <p style="margin-bottom: 15px; color: #666;">
                Honeypot fields and timing analysis for zero false-positive bot detection.
            </p>
            <table class="form-table">
                <tr>
                    <th>
                        <span class="saurity-setting-label">
                            Enable Honeypot Detection
                            <?php $this->render_info_icon( 'Adds hidden field to login form. Invisible to humans (CSS: display:none), but bots fill it out. 100% accurate bot detection with ZERO false positives. Highly recommended - enabled by default. No impact on legitimate users.' ); ?>
                        </span>
                    </th>
                    <td>
                        <label>
                            <input type="checkbox" name="saurity_enable_honeypot" value="1" 
                                   <?php checked( get_option( 'saurity_enable_honeypot', true ) ); ?> />
                            <strong>Enable Honeypot</strong>
                        </label>
                        <p class="description" style="color: #28a745;">
                            <strong>Recommended:</strong> Zero false positives, catches all form-filling bots
                        </p>
                    </td>
                </tr>
                <tr>
                    <th>
                        <span class="saurity-setting-label">
                            Enable Timing Check
                            <?php $this->render_info_icon( 'Measures how long it takes to submit login form. Humans need 2+ seconds to type. Bots submit instantly. Encrypted timestamp prevents manipulation. Logged-in users bypass. Recommended: Keep enabled.' ); ?>
                        </span>
                    </th>
                    <td>
                        <label>
                            <input type="checkbox" name="saurity_enable_timing_check" value="1" 
                                   <?php checked( get_option( 'saurity_enable_timing_check', true ) ); ?> />
                            <strong>Enable Timing Check</strong>
                        </label>
                        <p class="description" style="color: #28a745;">
                            <strong>Recommended:</strong> Catches bots that submit forms instantly
                        </p>
                    </td>
                </tr>
                <tr>
                    <th>
                        <span class="saurity-setting-label">
                            Minimum Form Time
                            <?php $this->render_info_icon( 'Minimum seconds required to submit form. Even fast typers need 2+ seconds for username+password. Lower increases false positives. Recommended: 2-3 seconds for best balance' ); ?>
                        </span>
                    </th>
                    <td>
                        <input type="number" name="saurity_min_form_time" 
                               value="<?php echo esc_attr( get_option( 'saurity_min_form_time', 2 ) ); ?>" 
                               min="1" max="10" />
                        <p class="description">Minimum seconds (default: 2)</p>
                        <p class="description" style="color: #666; margin-top: 5px;">
                            <strong>Examples:</strong> 1s = Very aggressive, 2s = Balanced (recommended), 3-4s = Conservative
                        </p>
                    </td>
                </tr>
            </table>

            <div style="background: #f0f0f0; padding: 15px; border-radius: 4px; margin: 20px 0;">
                <?php submit_button( 'Save Advanced Security', 'primary', 'submit', false ); ?>
                <p class="description" style="margin: 10px 0 0 0; color: #666;">
                    <strong>Note:</strong> These features work silently in the background. Legitimate users won't notice any difference.
                </p>
            </div>
        </form>
        <?php
    }

    /**
     * Render recovery tab
     */
    private function render_recovery_tab() {
        $bypass_key = get_option( 'saurity_emergency_bypass_key', '' );
        $kill_switch_active = $this->kill_switch->is_active();
        ?>
        
        <!-- Kill Switch Card (Full Width) -->
        <div style="padding: 20px; background: #fff3cd; border: 1px solid #ffc107; border-radius: 8px; border-left: 4px solid #ff9800; margin-bottom: 20px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h3 style="margin: 0 0 10px 0; color: #333; font-size: 18px; text-transform: uppercase; letter-spacing: 0.5px;">⚠️ Kill Switch</h3>
                    <p style="margin: 0; font-size: 14px;">Immediately disable all security enforcement site-wide.</p>
                </div>
                <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin: 0;">
                    <input type="hidden" name="action" value="saurity_toggle_kill_switch" />
                    <?php wp_nonce_field( 'saurity_kill_switch' ); ?>
                    <?php if ( $kill_switch_active ) : ?>
                        <button type="submit" class="button button-primary button-large">✓ Enable Protection</button>
                    <?php else : ?>
                        <button type="submit" class="button button-large" onclick="return confirm('Disable all protection?');">Activate Kill Switch</button>
                    <?php endif; ?>
                </form>
            </div>
        </div>

        <!-- Emergency Bypass & Manual Disable (Equal Height Cards) -->
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; align-items: stretch;">
            
            <!-- Emergency Bypass -->
            <div style="padding: 20px; background: #f0f0f0; border: 1px solid #ddd; border-radius: 8px; border-left: 4px solid #666; display: flex; flex-direction: column;">
                <div style="margin-bottom: 15px;">
                    <h3 style="margin: 0 0 10px 0; color: #333; font-size: 16px; text-transform: uppercase; letter-spacing: 0.5px;">🔗 Emergency Bypass</h3>
                    <p style="margin: 0; font-size: 13px; color: #666;">10-minute session for admin tasks</p>
                </div>
                
                <div style="flex: 1; display: flex; flex-direction: column; gap: 12px;">
                    <button type="button" id="saurity-reveal-btn" class="button button-secondary" 
                            onclick="document.getElementById('saurity-bypass-url').style.display='block'; document.getElementById('saurity-copy-btn').style.display='inline-block'; document.getElementById('saurity-hide-btn').style.display='inline-block'; this.style.display='none';" 
                            style="width: 100%;">
                        🔓 Reveal Bypass URL
                    </button>
                    
                    <div id="saurity-bypass-url" style="display:none;">
                        <input type="text" readonly 
                               value="<?php echo esc_url( site_url( '/?saurity_bypass=' . $bypass_key ) ); ?>" 
                               style="width: 100%; font-size: 11px; padding: 8px; margin-bottom: 8px; font-family: monospace;" 
                               onclick="this.select();" 
                               id="saurity-bypass-input" />
                        
                        <div style="display: flex; gap: 8px; margin-bottom: 12px;">
                            <button type="button" id="saurity-copy-btn" class="button button-small" 
                                    onclick="document.getElementById('saurity-bypass-input').select(); document.execCommand('copy'); this.textContent='✓ Copied!';" 
                                    style="flex: 1;">
                                📋 Copy
                            </button>
                            <button type="button" id="saurity-hide-btn" class="button button-small" 
                                    onclick="document.getElementById('saurity-bypass-url').style.display='none'; document.getElementById('saurity-reveal-btn').style.display='inline-block';" 
                                    style="flex: 1;">
                                👁️ Hide
                            </button>
                        </div>
                    </div>
                    
                    <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top: auto;">
                        <input type="hidden" name="action" value="saurity_rotate_bypass_key" />
                        <?php wp_nonce_field( 'saurity_rotate_bypass' ); ?>
                        <button type="submit" class="button button-small" style="width: 100%;"
                                onclick="return confirm('Rotate bypass URL? The old URL will stop working immediately.');">
                            🔄 Rotate URL
                        </button>
                    </form>
                </div>
                
                <p style="font-size: 10px; color: #999; margin: 12px 0 0 0; text-align: center; padding-top: 12px; border-top: 1px solid #ddd;">
                    IP-locked • Keep secret • Email alerts sent
                </p>
            </div>

            <!-- Manual Disable -->
            <div style="padding: 20px; background: #fff; border: 1px solid #ddd; border-radius: 8px; border-left: 4px solid #999; display: flex; flex-direction: column;">
                <div style="margin-bottom: 15px;">
                    <h3 style="margin: 0 0 10px 0; color: #333; font-size: 16px; text-transform: uppercase; letter-spacing: 0.5px;">📁 Manual Disable</h3>
                    <p style="margin: 0; font-size: 13px; color: #666;">File system access required</p>
                </div>
                
                <div style="flex: 1; display: flex; flex-direction: column; gap: 12px;">
                    <div style="background: #f8f9fa; padding: 15px; border-radius: 4px; border: 1px solid #ddd;">
                        <p style="margin: 0 0 8px 0; font-size: 12px; font-weight: 600;">Plugin Location:</p>
                        <code style="display: block; padding: 8px; background: #fff; font-size: 11px; word-wrap: break-word; border: 1px solid #ddd; border-radius: 3px;">
                            wp-content/plugins/saurity/
                        </code>
                    </div>
                </div>
                
                <p style="font-size: 10px; color: #999; margin: 12px 0 0 0; text-align: center; padding-top: 12px; border-top: 1px solid #ddd;">
                    Last resort • FTP/File Manager needed
                </p>
            </div>

        </div>
        
        <div style="margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 8px; border-left: 4px solid #2196F3;">
            <h4 style="margin: 0 0 10px 0; color: #333;">💡 Recovery Options Priority</h4>
            <ol style="margin: 0; padding-left: 20px; font-size: 13px; line-height: 1.8;">
                <li><strong>Kill Switch</strong> - Use if you have admin access</li>
                <li><strong>Bypass URL</strong> - Use if blocked but can access URL</li>
                <li><strong>Manual Disable</strong> - Use if completely locked out (requires file access)</li>
            </ol>
        </div>
        <?php
    }

    /**
     * Render activity log tab
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
        <!-- Search Bar -->
        <div style="margin-bottom: 15px;">
            <form method="get" action="" style="display: flex; gap: 10px; align-items: center;">
                <input type="hidden" name="page" value="saurity" />
                <input type="hidden" name="tab" value="logs" />
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
                    <a href="<?php echo esc_url( admin_url( 'admin.php?page=saurity&tab=logs' ) ); ?>" 
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
                <a href="<?php echo esc_url( admin_url( 'admin.php?page=saurity&tab=logs&log_page=1' ) ); ?>" 
                   class="nav-tab <?php echo empty( $current_filter ) ? 'nav-tab-active' : ''; ?>">
                    All (<?php echo esc_html( $counts['all'] ); ?>)
                </a>
                <a href="<?php echo esc_url( add_query_arg( [ 'page' => 'saurity', 'tab' => 'logs', 'log_type' => 'info', 'log_page' => 1 ], admin_url( 'admin.php' ) ) ); ?>" 
                   class="nav-tab <?php echo $current_filter === 'info' ? 'nav-tab-active' : ''; ?>">
                    Info (<?php echo esc_html( $counts['info'] ); ?>)
                </a>
                <a href="<?php echo esc_url( add_query_arg( [ 'page' => 'saurity', 'tab' => 'logs', 'log_type' => 'warning', 'log_page' => 1 ], admin_url( 'admin.php' ) ) ); ?>" 
                   class="nav-tab <?php echo $current_filter === 'warning' ? 'nav-tab-active' : ''; ?>">
                    Warning (<?php echo esc_html( $counts['warning'] ); ?>)
                </a>
                <a href="<?php echo esc_url( add_query_arg( [ 'page' => 'saurity', 'tab' => 'logs', 'log_type' => 'error', 'log_page' => 1 ], admin_url( 'admin.php' ) ) ); ?>" 
                   class="nav-tab <?php echo $current_filter === 'error' ? 'nav-tab-active' : ''; ?>">
                    Error (<?php echo esc_html( $counts['error'] ); ?>)
                </a>
                <a href="<?php echo esc_url( add_query_arg( [ 'page' => 'saurity', 'tab' => 'logs', 'log_type' => 'critical', 'log_page' => 1 ], admin_url( 'admin.php' ) ) ); ?>" 
                   class="nav-tab <?php echo $current_filter === 'critical' ? 'nav-tab-active' : ''; ?>">
                    Critical (<?php echo esc_html( $counts['critical'] ); ?>)
                </a>
            </div>

            <!-- Action Buttons -->
            <div style="display: flex; gap: 10px;">
                <a href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=saurity_export_csv' ), 'saurity_export' ); ?>" 
                   class="button">
                    Export to CSV
                </a>
                <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin: 0;">
                    <input type="hidden" name="action" value="saurity_clear_logs" />
                    <?php wp_nonce_field( 'saurity_clear_logs' ); ?>
                    <button type="submit" class="button" onclick="return confirm('Clear all logs?');">Clear Logs</button>
                </form>
            </div>
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
                        <div>
                            <span style="font-weight: 600; color: <?php echo esc_attr( $this->get_log_color( $log['event_type'] ) ); ?>;">
                                [<?php echo esc_html( strtoupper( $log['event_type'] ) ); ?>]
                            </span>
                            <span style="color: #666; font-size: 13px;">
                                <?php echo esc_html( $log['created_at'] ); ?>
                            </span>
                        </div>
                        <div style="font-size: 14px; margin-top: 5px;">
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
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <!-- Pagination -->
        <?php if ( $total_pages > 1 ) : ?>
            <div style="margin-top: 15px; text-align: center;">
                <?php
                $base_url = add_query_arg( [ 'page' => 'saurity', 'tab' => 'logs' ], admin_url( 'admin.php' ) );
                if ( $current_filter ) {
                    $base_url = add_query_arg( 'log_type', $current_filter, $base_url );
                }
                if ( $search_term ) {
                    $base_url = add_query_arg( 'log_search', $search_term, $base_url );
                }

                $page_links = paginate_links( [
                    'base' => add_query_arg( 'log_page', '%#%', $base_url ),
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
            <?php $retention_days = get_option( 'saurity_log_retention_days', 15 ); ?>
            <strong>Note:</strong> Logs older than <?php echo esc_html( $retention_days ); ?> days are automatically deleted. 
            Showing <?php echo esc_html( count( $logs ) ); ?> of <?php echo esc_html( $total ); ?> total entries.
            <a href="?page=saurity&tab=settings" style="margin-left: 10px;">Change retention period →</a>
        </p>
        <?php
    }

    /**
     * Render tooltip styles
     */
    private function render_tooltip_styles() {
        ?>
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
        <?php
    }

    /**
     * Render info icon with tooltip
     *
     * @param string $tooltip_text Tooltip text.
     */
    private function render_info_icon( $tooltip_text ) {
        ?>
        <span class="saurity-info-icon">
            i
            <span class="saurity-tooltip"><?php echo esc_html( $tooltip_text ); ?></span>
        </span>
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
        
        // Clear dashboard cache
        delete_transient( 'saurity_dashboard_data' );

        wp_safe_redirect( admin_url( 'admin.php?page=saurity&tab=logs' ) );
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
                'title' => '<span class="saurity-kill-switch-indicator">Saurity: Protection Disabled</span>',
                'href'  => admin_url( 'admin.php?page=saurity' ),
                'meta'  => [
                    'class' => 'saurity-kill-switch-warning',
                ],
            ] );
        } else {
            $wp_admin_bar->add_node( [
                'id'    => 'saurity-status',
                'title' => '<span class="saurity-status-indicator">Saurity: Active</span>',
                'href'  => admin_url( 'admin.php?page=saurity' ),
                'meta'  => [
                    'class' => 'saurity-status-active',
                ],
            ] );
        }
    }

    /**
     * Enqueue admin styles
     *
     * @param string $hook Current admin page hook.
     */
    public function enqueue_admin_styles( $hook ) {
        // Enqueue main admin CSS file (for Saurity admin pages)
        if ( strpos( $hook, 'saurity' ) !== false ) {
            wp_enqueue_style(
                'saurity-admin',
                plugins_url( 'assets/admin-styles.css', dirname( __FILE__ ) ),
                [],
                SAURITY_VERSION
            );
        }

        // Admin bar indicator styles (always loaded)
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

    /**
     * Handle test email
     */
    public function handle_test_email() {
        check_admin_referer( 'saurity_test' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Unauthorized' );
        }

        // Get email notifier from plugin
        $plugin = \Saurity\Plugin::get_instance();
        $email_notifier = $plugin->get_component( 'email_notifier' );

        if ( $email_notifier ) {
            // Capture wp_mail errors
            $mail_error = '';
            add_action( 'wp_mail_failed', function( $error ) use ( &$mail_error ) {
                $mail_error = $error->get_error_message();
            } );

            $result = $email_notifier->send_test_email();

            if ( $result && empty( $mail_error ) ) {
                add_settings_error(
                    'saurity_messages',
                    'saurity_message',
                    'Test email sent successfully! Check your inbox (and spam folder).',
                    'success'
                );
            } else {
                $error_msg = 'Failed to send test email.';
                if ( ! empty( $mail_error ) ) {
                    $error_msg .= ' Error: ' . $mail_error;
                } else {
                    $error_msg .= ' WordPress mail function returned false. This usually means your server cannot send emails. Please configure SMTP in Easy WP SMTP plugin.';
                }
                
                add_settings_error(
                    'saurity_messages',
                    'saurity_message',
                    $error_msg,
                    'error'
                );
            }
        } else {
            add_settings_error(
                'saurity_messages',
                'saurity_message',
                'Email notifier not available.',
                'error'
            );
        }

        set_transient( 'saurity_admin_notice', get_settings_errors( 'saurity_messages' ), 30 );
        wp_safe_redirect( admin_url( 'admin.php?page=saurity&tab=settings' ) );
        exit;
    }

    /**
     * Handle CSV export with memory-efficient streaming
     * Exports logs in batches to prevent memory exhaustion
     */
    public function handle_export_csv() {
        check_admin_referer( 'saurity_export' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Unauthorized' );
        }

        // Stream output directly, don't buffer
        header( 'Content-Type: text/csv; charset=utf-8' );
        header( 'Content-Disposition: attachment; filename="saurity-logs-' . date( 'Y-m-d' ) . '.csv"' );
        header( 'Pragma: no-cache' );
        header( 'Expires: 0' );

        $output = fopen( 'php://output', 'w' );

        // Add BOM for Excel UTF-8 compatibility
        fprintf( $output, chr(0xEF).chr(0xBB).chr(0xBF) );

        // CSV headers
        fputcsv( $output, [ 'Date/Time', 'Type', 'Message', 'IP Address', 'Username' ] );

        // Stream logs in batches of 500 to prevent memory exhaustion
        $batch_size = 500;
        $page = 1;
        
        do {
            $result = $this->logger->get_logs_paginated( $page, $batch_size );
            $logs = $result['logs'];
            
            // Write batch to CSV
            foreach ( $logs as $log ) {
                fputcsv( $output, [
                    $log['created_at'],
                    strtoupper( $log['event_type'] ),
                    $log['message'],
                    $log['ip_address'] ?? '',
                    $log['user_login'] ?? '',
                ] );
            }
            
            // Flush output buffer to send data immediately
            flush();
            
            $page++;
            
            // Continue while we have a full batch (indicates more records)
        } while ( count( $logs ) === $batch_size );

        fclose( $output );
        exit;
    }

    /**
     * Render IP management tab
     */
    private function render_ip_management() {
        $current_ip = $this->ip_manager->get_current_ip();
        $allowlist = $this->ip_manager->get_allowlist();
        $blocklist = $this->ip_manager->get_blocklist();
        $allowlist_meta = $this->ip_manager->get_allowlist_metadata();
        $blocklist_meta = $this->ip_manager->get_blocklist_metadata();
        ?>
        
        <!-- Current IP Display -->
        <div style="background: #e7f3ff; padding: 15px; border-radius: 8px; border: 1px solid #2196F3; border-left: 4px solid #2196F3; margin-bottom: 20px;">
            <strong>Your Current IP:</strong> 
            <code style="font-size: 16px; background: white; padding: 5px 10px; border-radius: 3px; margin-left: 10px;"><?php echo esc_html( $current_ip ); ?></code>
            <p style="margin: 10px 0 0 0; font-size: 13px;">
                Use this IP to add yourself to the allowlist if needed.
            </p>
        </div>

        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(450px, 1fr)); gap: 20px;">
            
            <!-- Allowlist Section -->
            <div>
                <h2>Allowlist (Trusted IPs)</h2>
                <p>IPs and CIDR ranges in the allowlist bypass all security checks and rate limiting.</p>
                
                <!-- Import/Export Buttons -->
                <div style="margin-bottom: 15px; display: flex; gap: 10px;">
                    <a href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=saurity_export_allowlist' ), 'saurity_export' ); ?>" 
                       class="button">
                        <span class="dashicons dashicons-download" style="vertical-align: middle;"></span> Export
                    </a>
                    <button type="button" class="button" onclick="document.getElementById('import-allowlist-file').click();">
                        <span class="dashicons dashicons-upload" style="vertical-align: middle;"></span> Import CSV
                    </button>
                    <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" 
                          enctype="multipart/form-data" id="import-allowlist-form" style="display: none;">
                        <input type="hidden" name="action" value="saurity_import_allowlist" />
                        <?php wp_nonce_field( 'saurity_import' ); ?>
                        <input type="file" name="csv_file" id="import-allowlist-file" accept=".csv" 
                               onchange="if(confirm('Import IPs from CSV? This will add new entries to your allowlist.')) { this.form.submit(); }" />
                    </form>
                </div>
                
                <!-- Add to Allowlist Form -->
                <div style="background: #d4edda; padding: 15px; border-radius: 8px; border-left: 4px solid #28a745; margin-bottom: 15px;">
                    <h4 style="margin-top: 0;">Add IP or CIDR Range</h4>
                    <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
                        <input type="hidden" name="action" value="saurity_add_to_allowlist" />
                        <?php wp_nonce_field( 'saurity_ip_action' ); ?>
                        <div style="display: grid; gap: 10px;">
                            <input type="text" name="ip" placeholder="IP Address or CIDR (e.g., 192.168.1.1 or 10.0.0.0/24)" 
                                   required style="padding: 8px;" />
                            <input type="text" name="note" placeholder="Note (optional)" 
                                   style="padding: 8px;" />
                            <button type="submit" class="button button-primary">Add to Allowlist</button>
                        </div>
                        <p style="margin: 10px 0 0 0; font-size: 12px; color: #666;">
                            <strong>Examples:</strong> Single IP: <code>192.168.1.100</code> | CIDR Range: <code>10.0.0.0/8</code>, <code>172.16.0.0/12</code>, <code>192.168.0.0/16</code>
                        </p>
                    </form>
                </div>

                <!-- Allowlist Table -->
                <?php if ( empty( $allowlist ) ) : ?>
                    <p style="color: #666; font-style: italic;">No IPs in allowlist.</p>
                <?php else : ?>
                    <table class="wp-list-table widefat fixed striped">
                        <thead>
                            <tr>
                                <th style="width: 30%;">IP Address</th>
                                <th style="width: 32%;">Note</th>
                                <th style="width: 25%;">Added</th>
                                <th style="width: 13%;">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ( $allowlist as $ip ) : ?>
                                <?php $meta = $allowlist_meta[ $ip ] ?? []; ?>
                                <tr>
                                    <td><code><?php echo esc_html( $ip ); ?></code></td>
                                    <td><?php echo esc_html( $meta['note'] ?? '-' ); ?></td>
                                    <td style="font-size: 12px;"><?php echo esc_html( $meta['added'] ?? '-' ); ?></td>
                                    <td>
                                        <a href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=saurity_remove_from_allowlist&ip=' . urlencode( $ip ) ), 'saurity_ip_action' ); ?>" 
                                           class="button button-small" 
                                           onclick="return confirm('Remove <?php echo esc_js( $ip ); ?> from allowlist?');">
                                            Remove
                                        </a>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>

            <!-- Blocklist Section -->
            <div>
                <h2>Blocklist (Permanently Blocked)</h2>
                <p>IPs and CIDR ranges in the blocklist are permanently blocked from accessing the site.</p>
                
                <!-- Import/Export Buttons -->
                <div style="margin-bottom: 15px; display: flex; gap: 10px;">
                    <a href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=saurity_export_blocklist' ), 'saurity_export' ); ?>" 
                       class="button">
                        <span class="dashicons dashicons-download" style="vertical-align: middle;"></span> Export
                    </a>
                    <button type="button" class="button" onclick="document.getElementById('import-blocklist-file').click();">
                        <span class="dashicons dashicons-upload" style="vertical-align: middle;"></span> Import CSV
                    </button>
                    <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" 
                          enctype="multipart/form-data" id="import-blocklist-form" style="display: none;">
                        <input type="hidden" name="action" value="saurity_import_blocklist" />
                        <?php wp_nonce_field( 'saurity_import' ); ?>
                        <input type="file" name="csv_file" id="import-blocklist-file" accept=".csv" 
                               onchange="if(confirm('Import IPs from CSV? This will add new entries to your blocklist.')) { this.form.submit(); }" />
                    </form>
                </div>
                
                <!-- Add to Blocklist Form -->
                <div style="background: #f8d7da; padding: 15px; border-radius: 8px; border-left: 4px solid #dc3232; margin-bottom: 15px;">
                    <h4 style="margin-top: 0;">Add IP or CIDR Range</h4>
                    <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
                        <input type="hidden" name="action" value="saurity_add_to_blocklist" />
                        <?php wp_nonce_field( 'saurity_ip_action' ); ?>
                        <div style="display: grid; gap: 10px;">
                            <input type="text" name="ip" placeholder="IP Address or CIDR (e.g., 192.168.1.1 or 192.168.1.0/24)" 
                                   required style="padding: 8px;" />
                            <input type="text" name="reason" placeholder="Reason (optional)" 
                                   style="padding: 8px;" />
                            <button type="submit" class="button button-primary">Add to Blocklist</button>
                        </div>
                        <p style="margin: 10px 0 0 0; font-size: 12px; color: #666;">
                            <strong>Examples:</strong> Single IP: <code>203.0.113.5</code> | CIDR Range: <code>203.0.113.0/24</code> (blocks 256 IPs)
                        </p>
                    </form>
                </div>

                <!-- Blocklist Table -->
                <?php if ( empty( $blocklist ) ) : ?>
                    <p style="color: #666; font-style: italic;">No IPs in blocklist.</p>
                <?php else : ?>
                    <table class="wp-list-table widefat fixed striped">
                        <thead>
                            <tr>
                                <th style="width: 30%;">IP Address</th>
                                <th style="width: 32%;">Reason</th>
                                <th style="width: 25%;">Added</th>
                                <th style="width: 13%;">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ( $blocklist as $ip ) : ?>
                                <?php $meta = $blocklist_meta[ $ip ] ?? []; ?>
                                <tr>
                                    <td><code><?php echo esc_html( $ip ); ?></code></td>
                                    <td><?php echo esc_html( $meta['reason'] ?? '-' ); ?></td>
                                    <td style="font-size: 12px;"><?php echo esc_html( $meta['added'] ?? '-' ); ?></td>
                                    <td>
                                        <a href="<?php echo wp_nonce_url( admin_url( 'admin-post.php?action=saurity_remove_from_blocklist&ip=' . urlencode( $ip ) ), 'saurity_ip_action' ); ?>" 
                                           class="button button-small" 
                                           onclick="return confirm('Unblock <?php echo esc_js( $ip ); ?>?');">
                                            Unblock
                                        </a>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>

        </div>
        <?php
    }

    /**
     * Handle add to allowlist
     */
    public function handle_add_to_allowlist() {
        check_admin_referer( 'saurity_ip_action' );
        
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Unauthorized' );
        }

        $ip = isset( $_POST['ip'] ) ? sanitize_text_field( $_POST['ip'] ) : '';
        $note = isset( $_POST['note'] ) ? sanitize_text_field( $_POST['note'] ) : '';

        $result = $this->ip_manager->add_to_allowlist( $ip, $note );

        if ( true === $result ) {
            add_settings_error(
                'saurity_messages',
                'saurity_message',
                "IP {$ip} added to allowlist successfully.",
                'success'
            );
        } else {
            // Handle specific error messages
            $error_messages = [
                'invalid_ip' => "Invalid IP address or CIDR format: {$ip}",
                'already_in_allowlist' => "IP {$ip} is already in the allowlist.",
                'already_in_blocklist' => "Cannot add IP {$ip} to allowlist - it's already in the blocklist. Remove it from blocklist first.",
            ];
            
            $message = isset( $error_messages[ $result ] ) ? $error_messages[ $result ] : "Failed to add IP {$ip} to allowlist.";
            
            add_settings_error(
                'saurity_messages',
                'saurity_message',
                $message,
                'error'
            );
        }

        set_transient( 'saurity_admin_notice', get_settings_errors( 'saurity_messages' ), 30 );
        wp_safe_redirect( admin_url( 'admin.php?page=saurity&tab=ip-management' ) );
        exit;
    }

    /**
     * Handle remove from allowlist
     */
    public function handle_remove_from_allowlist() {
        check_admin_referer( 'saurity_ip_action' );
        
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Unauthorized' );
        }

        $ip = isset( $_GET['ip'] ) ? sanitize_text_field( $_GET['ip'] ) : '';

        if ( $this->ip_manager->remove_from_allowlist( $ip ) ) {
            add_settings_error(
                'saurity_messages',
                'saurity_message',
                "IP {$ip} removed from allowlist.",
                'success'
            );
        } else {
            add_settings_error(
                'saurity_messages',
                'saurity_message',
                "Failed to remove IP {$ip} from allowlist.",
                'error'
            );
        }

        set_transient( 'saurity_admin_notice', get_settings_errors( 'saurity_messages' ), 30 );
        wp_safe_redirect( admin_url( 'admin.php?page=saurity&tab=ip-management' ) );
        exit;
    }

    /**
     * Handle add to blocklist
     */
    public function handle_add_to_blocklist() {
        check_admin_referer( 'saurity_ip_action' );
        
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Unauthorized' );
        }

        $ip = isset( $_POST['ip'] ) ? sanitize_text_field( $_POST['ip'] ) : '';
        $reason = isset( $_POST['reason'] ) ? sanitize_text_field( $_POST['reason'] ) : '';

        $result = $this->ip_manager->add_to_blocklist( $ip, $reason );

        if ( true === $result ) {
            add_settings_error(
                'saurity_messages',
                'saurity_message',
                "IP {$ip} added to blocklist successfully.",
                'success'
            );
        } else {
            // Handle specific error messages
            $error_messages = [
                'invalid_ip' => "Invalid IP address or CIDR format: {$ip}",
                'already_in_blocklist' => "IP {$ip} is already in the blocklist.",
                'already_in_allowlist' => "Cannot add IP {$ip} to blocklist - it's already in the allowlist (trusted IPs). Remove it from allowlist first.",
            ];
            
            $message = isset( $error_messages[ $result ] ) ? $error_messages[ $result ] : "Failed to add IP {$ip} to blocklist.";
            
            add_settings_error(
                'saurity_messages',
                'saurity_message',
                $message,
                'error'
            );
        }

        set_transient( 'saurity_admin_notice', get_settings_errors( 'saurity_messages' ), 30 );
        wp_safe_redirect( admin_url( 'admin.php?page=saurity&tab=ip-management' ) );
        exit;
    }

    /**
     * Handle remove from blocklist
     */
    public function handle_remove_from_blocklist() {
        check_admin_referer( 'saurity_ip_action' );
        
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Unauthorized' );
        }

        $ip = isset( $_GET['ip'] ) ? sanitize_text_field( $_GET['ip'] ) : '';

        if ( $this->ip_manager->remove_from_blocklist( $ip ) ) {
            add_settings_error(
                'saurity_messages',
                'saurity_message',
                "IP {$ip} unblocked successfully.",
                'success'
            );
        } else {
            add_settings_error(
                'saurity_messages',
                'saurity_message',
                "Failed to unblock IP {$ip}.",
                'error'
            );
        }

        set_transient( 'saurity_admin_notice', get_settings_errors( 'saurity_messages' ), 30 );
        wp_safe_redirect( admin_url( 'admin.php?page=saurity&tab=ip-management' ) );
        exit;
    }

    /**
     * Handle rotate bypass key
     */
    public function handle_rotate_bypass_key() {
        check_admin_referer( 'saurity_rotate_bypass' );
        
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Unauthorized' );
        }

        // Generate new bypass key
        $new_key = wp_generate_password( 32, false );
        update_option( 'saurity_emergency_bypass_key', $new_key );

        // Log the rotation
        $this->logger->log( 'warning', 'Emergency bypass URL was rotated by admin' );

        add_settings_error(
            'saurity_messages',
            'saurity_message',
            'Bypass URL rotated successfully. The old URL is now invalid.',
            'success'
        );

        set_transient( 'saurity_admin_notice', get_settings_errors( 'saurity_messages' ), 30 );
        wp_safe_redirect( admin_url( 'admin.php?page=saurity&tab=recovery' ) );
        exit;
    }

    /**
     * Handle export allowlist
     */
    public function handle_export_allowlist() {
        check_admin_referer( 'saurity_export' );
        
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Unauthorized' );
        }

        $csv_content = $this->ip_manager->export_allowlist_csv();

        header( 'Content-Type: text/csv; charset=utf-8' );
        header( 'Content-Disposition: attachment; filename="saurity-allowlist-' . date( 'Y-m-d' ) . '.csv"' );
        header( 'Pragma: no-cache' );
        header( 'Expires: 0' );

        echo $csv_content;
        exit;
    }

    /**
     * Handle export blocklist
     */
    public function handle_export_blocklist() {
        check_admin_referer( 'saurity_export' );
        
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Unauthorized' );
        }

        $csv_content = $this->ip_manager->export_blocklist_csv();

        header( 'Content-Type: text/csv; charset=utf-8' );
        header( 'Content-Disposition: attachment; filename="saurity-blocklist-' . date( 'Y-m-d' ) . '.csv"' );
        header( 'Pragma: no-cache' );
        header( 'Expires: 0' );

        echo $csv_content;
        exit;
    }

    /**
     * Handle import allowlist
     */
    public function handle_import_allowlist() {
        check_admin_referer( 'saurity_import' );
        
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Unauthorized' );
        }

        if ( empty( $_FILES['csv_file']['tmp_name'] ) ) {
            add_settings_error(
                'saurity_messages',
                'saurity_message',
                'No file uploaded.',
                'error'
            );
        } else {
            $csv_content = file_get_contents( $_FILES['csv_file']['tmp_name'] );
            $result = $this->ip_manager->import_allowlist_csv( $csv_content );

            if ( $result['success'] > 0 ) {
                $message = "Successfully imported {$result['success']} IP(s) to allowlist.";
                if ( ! empty( $result['errors'] ) ) {
                    $message .= ' ' . count( $result['errors'] ) . ' errors occurred.';
                }
                add_settings_error(
                    'saurity_messages',
                    'saurity_message',
                    $message,
                    'success'
                );
            } else {
                add_settings_error(
                    'saurity_messages',
                    'saurity_message',
                    'Failed to import IPs. Check CSV format.',
                    'error'
                );
            }
        }

        set_transient( 'saurity_admin_notice', get_settings_errors( 'saurity_messages' ), 30 );
        wp_safe_redirect( admin_url( 'admin.php?page=saurity&tab=ip-management' ) );
        exit;
    }

    /**
     * Handle import blocklist
     */
    public function handle_import_blocklist() {
        check_admin_referer( 'saurity_import' );
        
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Unauthorized' );
        }

        if ( empty( $_FILES['csv_file']['tmp_name'] ) ) {
            add_settings_error(
                'saurity_messages',
                'saurity_message',
                'No file uploaded.',
                'error'
            );
        } else {
            $csv_content = file_get_contents( $_FILES['csv_file']['tmp_name'] );
            $result = $this->ip_manager->import_blocklist_csv( $csv_content );

            if ( $result['success'] > 0 ) {
                $message = "Successfully imported {$result['success']} IP(s) to blocklist.";
                if ( ! empty( $result['errors'] ) ) {
                    $message .= ' ' . count( $result['errors'] ) . ' errors occurred.';
                }
                add_settings_error(
                    'saurity_messages',
                    'saurity_message',
                    $message,
                    'success'
                );
            } else {
                add_settings_error(
                    'saurity_messages',
                    'saurity_message',
                    'Failed to import IPs. Check CSV format.',
                    'error'
                );
            }
        }

        set_transient( 'saurity_admin_notice', get_settings_errors( 'saurity_messages' ), 30 );
        wp_safe_redirect( admin_url( 'admin.php?page=saurity&tab=ip-management' ) );
        exit;
    }
}
