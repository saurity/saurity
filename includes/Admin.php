<?php
/**
 * Admin Dashboard
 *
 * @package Saurity
 */

namespace Saurity;
// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

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
        add_action( 'admin_post_saurity_update_threat_feeds', [ $this, 'handle_update_threat_feeds' ] );
        add_action( 'wp_ajax_saurity_update_feeds_ajax', [ $this, 'ajax_update_threat_feeds' ] );
        add_action( 'admin_post_saurity_bulk_ip_action', [ $this, 'handle_bulk_ip_action' ] );
        add_action( 'wp_ajax_saurity_bulk_ip_action', [ $this, 'ajax_bulk_ip_action' ] );
        // DISABLED: Cloudflare integration commented out
        // add_action( 'wp_ajax_saurity_cloudflare_test', [ $this, 'ajax_cloudflare_test' ] );
        // add_action( 'wp_ajax_saurity_cloudflare_sync', [ $this, 'ajax_cloudflare_sync' ] );
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

        // Cloud Services Settings
        register_setting( 'saurity_cloud_settings', 'saurity_cloudflare_enabled', [
            'type' => 'boolean',
            'sanitize_callback' => 'rest_sanitize_boolean',
            'default' => false,
        ] );
        register_setting( 'saurity_cloud_settings', 'saurity_cloudflare_api_token', [
            'type' => 'string',
            'sanitize_callback' => 'sanitize_text_field',
            'default' => '',
        ] );
        register_setting( 'saurity_cloud_settings', 'saurity_cloudflare_zone_id', [
            'type' => 'string',
            'sanitize_callback' => 'sanitize_text_field',
            'default' => '',
        ] );
        register_setting( 'saurity_cloud_settings', 'saurity_cloudflare_sync_blocklist', [
            'type' => 'boolean',
            'sanitize_callback' => 'rest_sanitize_boolean',
            'default' => true,
        ] );
        register_setting( 'saurity_cloud_settings', 'saurity_cloudflare_import_events', [
            'type' => 'boolean',
            'sanitize_callback' => 'rest_sanitize_boolean',
            'default' => true,
        ] );
        register_setting( 'saurity_cloud_settings', 'saurity_threat_feeds_enabled', [
            'type' => 'boolean',
            'sanitize_callback' => 'rest_sanitize_boolean',
            'default' => false,
        ] );
        register_setting( 'saurity_cloud_settings', 'saurity_threat_feeds_builtin', [
            'type' => 'array',
            'sanitize_callback' => function( $value ) {
                if ( ! is_array( $value ) ) {
                    return [];
                }
                return array_map( 'sanitize_text_field', $value );
            },
            'default' => [],
        ] );
        register_setting( 'saurity_cloud_settings', 'saurity_threat_feeds_update_interval', [
            'type' => 'string',
            'sanitize_callback' => function( $value ) {
                $valid = [ 'hourly', 'twicedaily', 'daily' ];
                return in_array( $value, $valid, true ) ? $value : 'daily';
            },
            'default' => 'daily',
        ] );
        register_setting( 'saurity_cloud_settings', 'saurity_threat_feeds_auto_block', [
            'type' => 'boolean',
            'sanitize_callback' => 'rest_sanitize_boolean',
            'default' => true,
        ] );
        register_setting( 'saurity_cloud_settings', 'saurity_threat_feeds_max_age', [
            'type' => 'integer',
            'sanitize_callback' => function( $value ) {
                $value = absint( $value );
                return max( 7, min( 90, $value ) );
            },
            'default' => 30,
        ] );
        register_setting( 'saurity_cloud_settings', 'saurity_geoip_enabled', [
            'type' => 'boolean',
            'sanitize_callback' => 'rest_sanitize_boolean',
            'default' => false,
        ] );
        register_setting( 'saurity_cloud_settings', 'saurity_geoip_provider', [
            'type' => 'string',
            'sanitize_callback' => function( $value ) {
                $valid = [ 'maxmind', 'ipapi' ];
                return in_array( $value, $valid, true ) ? $value : 'maxmind';
            },
            'default' => 'maxmind',
        ] );
        register_setting( 'saurity_cloud_settings', 'saurity_geoip_license_key', [
            'type' => 'string',
            'sanitize_callback' => 'sanitize_text_field',
            'default' => '',
        ] );
        register_setting( 'saurity_cloud_settings', 'saurity_geoip_mode', [
            'type' => 'string',
            'sanitize_callback' => function( $value ) {
                $valid = [ 'blocklist', 'allowlist' ];
                return in_array( $value, $valid, true ) ? $value : 'blocklist';
            },
            'default' => 'blocklist',
        ] );
        register_setting( 'saurity_cloud_settings', 'saurity_geoip_blocked_countries', [
            'type' => 'array',
            'sanitize_callback' => function( $value ) {
                if ( ! is_array( $value ) ) {
                    return [];
                }
                return array_map( 'sanitize_text_field', $value );
            },
            'default' => [],
        ] );
        register_setting( 'saurity_cloud_settings', 'saurity_geoip_show_flags', [
            'type' => 'boolean',
            'sanitize_callback' => 'rest_sanitize_boolean',
            'default' => true,
        ] );
    }

    /**
     * Render admin page with tabs
     */
    public function render_page() {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- This is a tab navigation, not a form submission
        $current_tab = isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : 'dashboard';
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
                <a href="?page=saurity&tab=cloud-services" class="nav-tab <?php echo $current_tab === 'cloud-services' ? 'nav-tab-active' : ''; ?>">
                    Cloud Services
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
                    case 'cloud-services':
                        $this->render_cloud_services();
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
        <!-- Stats Cards -->
        <div class="saurity-stats-grid">
            <div class="saurity-stat-card <?php echo $kill_switch_active ? 'warning' : 'success'; ?>">
                <div class="saurity-stat-label">Protection Status</div>
                <div class="saurity-stat-value"><?php echo $kill_switch_active ? 'Disabled' : 'Active'; ?></div>
            </div>
            <div class="saurity-stat-card info">
                <div class="saurity-stat-label">Total Events</div>
                <div class="saurity-stat-value"><?php echo esc_html( $counts['all'] ); ?></div>
            </div>
            <div class="saurity-stat-card warning">
                <div class="saurity-stat-label">Warnings</div>
                <div class="saurity-stat-value"><?php echo esc_html( $counts['warning'] ); ?></div>
            </div>
            <div class="saurity-stat-card danger">
                <div class="saurity-stat-label">Critical/Errors</div>
                <div class="saurity-stat-value"><?php echo esc_html( $counts['critical'] + $counts['error'] ); ?></div>
            </div>
        </div>

        <!-- Quick Actions -->
        <div class="saurity-quick-actions-bar">
            <a href="?page=saurity&tab=settings" class="saurity-action-btn">Configure Settings</a>
            <a href="?page=saurity&tab=ip-management" class="saurity-action-btn">Manage IPs</a>
            <a href="?page=saurity&tab=recovery" class="saurity-action-btn">Recovery Options</a>
            <a href="?page=saurity&tab=cloud-services" class="saurity-action-btn">Cloud Services</a>
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
     * Render all settings in one tab - Modern UI
     */
    private function render_all_settings() {
        // Get current settings for feature cards
        $rate_limiting = get_option( 'saurity_enable_rate_limiting', true );
        $firewall = get_option( 'saurity_enable_firewall', true );
        $logging = get_option( 'saurity_enable_logging', true );
        $ip_management = get_option( 'saurity_enable_ip_management', true );
        $email_notifications = get_option( 'saurity_email_notifications', true );
        
        // Calculate security score
        $enabled_features = array_sum( [ (int) $rate_limiting, (int) $firewall, (int) $logging, (int) $ip_management, (int) $email_notifications ] );
        $security_score = min( 100, $enabled_features * 20 );
        $score_class = $security_score >= 80 ? '' : ( $security_score >= 60 ? 'warning' : 'danger' );
        
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- This is for UI state, not form processing
        $section_open = isset( $_GET['section'] ) && $_GET['section'] === 'login';
        ?>
        
        <form method="post" action="options.php" id="saurity-settings-form">
            <?php settings_fields( 'saurity_settings' ); ?>

            <!-- Security Score Banner -->
            <div class="saurity-security-score">
                <div class="saurity-score-circle"><?php echo esc_html( $security_score ); ?></div>
                <div class="saurity-score-info">
                    <h3>🛡️ Security Score</h3>
                    <p><?php echo esc_html( $enabled_features ); ?> of 5 core features enabled</p>
                    <div class="saurity-score-bar">
                        <div class="saurity-score-fill <?php echo esc_attr( $score_class ); ?>" style="width: <?php echo esc_attr( $security_score ); ?>%;"></div>
                    </div>
                </div>
            </div>

            <!-- Feature Cards Grid -->
            <h2 style="margin-bottom: 15px;">⚡ Core Security Features</h2>
            <p style="color: #666; margin-bottom: 20px;">Toggle features on/off with one click. Changes save automatically.</p>
            
            <div class="saurity-features-grid">
                <!-- Rate Limiting Card -->
                <div class="saurity-feature-card <?php echo $rate_limiting ? 'enabled' : 'disabled'; ?>">
                    <div class="saurity-feature-header">
                        <div class="saurity-feature-title">
                            <span class="saurity-feature-icon">🚦</span>
                            Rate Limiting
                        </div>
                        <label class="saurity-toggle">
                            <input type="checkbox" name="saurity_enable_rate_limiting" value="1" 
                                   <?php checked( $rate_limiting ); ?> />
                            <span class="saurity-toggle-slider"></span>
                        </label>
                    </div>
                    <p class="saurity-feature-desc">
                        Blocks brute force attacks by limiting login attempts, POST requests, XML-RPC, and comments.
                    </p>
                </div>

                <!-- Firewall Card -->
                <div class="saurity-feature-card <?php echo $firewall ? 'enabled' : 'disabled'; ?>">
                    <div class="saurity-feature-header">
                        <div class="saurity-feature-title">
                            <span class="saurity-feature-icon">🔥</span>
                            Firewall
                        </div>
                        <label class="saurity-toggle">
                            <input type="checkbox" name="saurity_enable_firewall" value="1" 
                                   <?php checked( $firewall ); ?> />
                            <span class="saurity-toggle-slider"></span>
                        </label>
                    </div>
                    <p class="saurity-feature-desc">
                        Blocks SQL injection, XSS attacks, malicious bots, and sensitive file access.
                    </p>
                </div>

                <!-- Activity Logging Card -->
                <div class="saurity-feature-card <?php echo $logging ? 'enabled' : 'disabled'; ?>">
                    <div class="saurity-feature-header">
                        <div class="saurity-feature-title">
                            <span class="saurity-feature-icon">📋</span>
                            Activity Logging
                        </div>
                        <label class="saurity-toggle">
                            <input type="checkbox" name="saurity_enable_logging" value="1" 
                                   <?php checked( $logging ); ?> />
                            <span class="saurity-toggle-slider"></span>
                        </label>
                    </div>
                    <p class="saurity-feature-desc">
                        Records all security events, login attempts, and system changes for forensic analysis.
                    </p>
                </div>

                <!-- IP Management Card -->
                <div class="saurity-feature-card <?php echo $ip_management ? 'enabled' : 'disabled'; ?>">
                    <div class="saurity-feature-header">
                        <div class="saurity-feature-title">
                            <span class="saurity-feature-icon">🔒</span>
                            IP Management
                        </div>
                        <label class="saurity-toggle">
                            <input type="checkbox" name="saurity_enable_ip_management" value="1" 
                                   <?php checked( $ip_management ); ?> />
                            <span class="saurity-toggle-slider"></span>
                        </label>
                    </div>
                    <p class="saurity-feature-desc">
                        Manually allowlist trusted IPs or blocklist malicious ones with CIDR support.
                    </p>
                </div>

                <!-- Email Notifications Card -->
                <div class="saurity-feature-card <?php echo $email_notifications ? 'enabled' : 'disabled'; ?>">
                    <div class="saurity-feature-header">
                        <div class="saurity-feature-title">
                            <span class="saurity-feature-icon">📧</span>
                            Email Alerts
                        </div>
                        <label class="saurity-toggle">
                            <input type="checkbox" name="saurity_email_notifications" value="1" 
                                   <?php checked( $email_notifications ); ?> />
                            <span class="saurity-toggle-slider"></span>
                        </label>
                    </div>
                    <p class="saurity-feature-desc">
                        Get notified when critical security events occur: hard blocks, kill switch, and more.
                    </p>
                </div>
            </div>

            <div style="margin: 25px 0;">
                <?php submit_button( 'Save All Settings', 'primary large', 'submit', false ); ?>
            </div>

            <!-- Collapsible Sections -->
            <h2 style="margin: 30px 0 15px 0;">⚙️ Detailed Configuration</h2>
            <p style="color: #666; margin-bottom: 20px;">Click on each section to expand and configure advanced settings.</p>

            <!-- Login Rate Limiting Section -->
            <div class="saurity-section <?php echo $section_open ? 'open' : ''; ?>" id="section-login">
                <div class="saurity-section-header" onclick="this.parentElement.classList.toggle('open')">
                    <div class="saurity-section-title">
                        <span class="saurity-section-icon">🔐</span>
                        Login Protection
                    </div>
                    <div class="saurity-section-status">
                        <span class="saurity-section-badge <?php echo $rate_limiting ? 'enabled' : 'disabled'; ?>">
                            <?php echo $rate_limiting ? 'Active' : 'Disabled'; ?>
                        </span>
                        <span class="saurity-section-arrow">▼</span>
                    </div>
                </div>
                <div class="saurity-section-content">
                    <p style="margin-bottom: 20px; color: #666;">
                        Configure how many failed login attempts are allowed before throttling and blocking.
                    </p>
                    
                    <div class="saurity-setting-row">
                        <div class="saurity-setting-info">
                            <div class="saurity-setting-name">Attempts Before Throttle</div>
                            <div class="saurity-setting-desc">Failed attempts before progressive delays begin</div>
                        </div>
                        <div class="saurity-setting-control">
                            <input type="number" name="saurity_rate_limit_attempts" 
                                   value="<?php echo esc_attr( get_option( 'saurity_rate_limit_attempts', 5 ) ); ?>" 
                                   min="1" max="20" style="width: 70px;" />
                            <span class="saurity-unit">attempts</span>
                        </div>
                    </div>

                    <div class="saurity-setting-row">
                        <div class="saurity-setting-info">
                            <div class="saurity-setting-name">Time Window</div>
                            <div class="saurity-setting-desc">Period during which attempts are counted</div>
                        </div>
                        <div class="saurity-setting-control">
                            <input type="number" name="saurity_rate_limit_window" 
                                   value="<?php echo esc_attr( get_option( 'saurity_rate_limit_window', 600 ) ); ?>" 
                                   min="60" max="3600" style="width: 80px;" />
                            <span class="saurity-unit">seconds</span>
                        </div>
                    </div>

                    <div class="saurity-setting-row">
                        <div class="saurity-setting-info">
                            <div class="saurity-setting-name">Hard Block After</div>
                            <div class="saurity-setting-desc">Complete block after this many failures</div>
                        </div>
                        <div class="saurity-setting-control">
                            <input type="number" name="saurity_hard_block_attempts" 
                                   value="<?php echo esc_attr( get_option( 'saurity_hard_block_attempts', 20 ) ); ?>" 
                                   min="10" max="100" style="width: 70px;" />
                            <span class="saurity-unit">attempts</span>
                        </div>
                    </div>

                    <div class="saurity-setting-row">
                        <div class="saurity-setting-info">
                            <div class="saurity-setting-name">Block Duration</div>
                            <div class="saurity-setting-desc">How long an IP stays blocked</div>
                        </div>
                        <div class="saurity-setting-control">
                            <input type="number" name="saurity_hard_block_duration" 
                                   value="<?php echo esc_attr( get_option( 'saurity_hard_block_duration', 3600 ) ); ?>" 
                                   min="300" max="86400" style="width: 80px;" />
                            <span class="saurity-unit">seconds</span>
                        </div>
                    </div>

                    <div class="saurity-setting-row">
                        <div class="saurity-setting-info">
                            <div class="saurity-setting-name">Progressive Delay</div>
                            <div class="saurity-setting-desc">Base delay that doubles with each failed attempt</div>
                        </div>
                        <div class="saurity-setting-control">
                            <input type="number" name="saurity_progressive_delay" 
                                   value="<?php echo esc_attr( get_option( 'saurity_progressive_delay', 2 ) ); ?>" 
                                   min="1" max="10" style="width: 60px;" />
                            <span class="saurity-unit">seconds</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- POST Flood Section -->
            <div class="saurity-section" id="section-post">
                <div class="saurity-section-header" onclick="this.parentElement.classList.toggle('open')">
                    <div class="saurity-section-title">
                        <span class="saurity-section-icon">📝</span>
                        POST Flood Protection
                    </div>
                    <div class="saurity-section-status">
                        <span class="saurity-section-badge <?php echo get_option( 'saurity_enable_post_flood', true ) ? 'enabled' : 'disabled'; ?>">
                            <?php echo get_option( 'saurity_enable_post_flood', true ) ? 'Active' : 'Disabled'; ?>
                        </span>
                        <span class="saurity-section-arrow">▼</span>
                    </div>
                </div>
                <div class="saurity-section-content">
                    <div class="saurity-setting-row">
                        <div class="saurity-setting-info">
                            <div class="saurity-setting-name">Enable POST Flood Protection</div>
                            <div class="saurity-setting-desc">Prevents form spam and POST floods (two-tier system)</div>
                        </div>
                        <div class="saurity-setting-control">
                            <label class="saurity-toggle">
                                <input type="checkbox" name="saurity_enable_post_flood" value="1" 
                                       <?php checked( get_option( 'saurity_enable_post_flood', true ) ); ?> />
                                <span class="saurity-toggle-slider"></span>
                            </label>
                        </div>
                    </div>

                    <div class="saurity-setting-row">
                        <div class="saurity-setting-info">
                            <div class="saurity-setting-name">Device Limit (Tier 1)</div>
                            <div class="saurity-setting-desc">POSTs per minute from single device (IP+UA)</div>
                        </div>
                        <div class="saurity-setting-control">
                            <input type="number" name="saurity_post_flood_device_limit" 
                                   value="<?php echo esc_attr( get_option( 'saurity_post_flood_device_limit', 20 ) ); ?>" 
                                   min="5" max="100" style="width: 70px;" />
                            <span class="saurity-unit">/min</span>
                        </div>
                    </div>

                    <div class="saurity-setting-row">
                        <div class="saurity-setting-info">
                            <div class="saurity-setting-name">IP Limit (Tier 2)</div>
                            <div class="saurity-setting-desc">POSTs per minute from single IP (NAT-safe)</div>
                        </div>
                        <div class="saurity-setting-control">
                            <input type="number" name="saurity_post_flood_ip_limit" 
                                   value="<?php echo esc_attr( get_option( 'saurity_post_flood_ip_limit', 200 ) ); ?>" 
                                   min="50" max="1000" style="width: 80px;" />
                            <span class="saurity-unit">/min</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- XML-RPC Section -->
            <div class="saurity-section" id="section-xmlrpc">
                <div class="saurity-section-header" onclick="this.parentElement.classList.toggle('open')">
                    <div class="saurity-section-title">
                        <span class="saurity-section-icon">📡</span>
                        XML-RPC Protection
                    </div>
                    <div class="saurity-section-status">
                        <span class="saurity-section-badge <?php echo get_option( 'saurity_enable_xmlrpc_protection', true ) ? 'enabled' : 'disabled'; ?>">
                            <?php echo get_option( 'saurity_enable_xmlrpc_protection', true ) ? 'Active' : 'Disabled'; ?>
                        </span>
                        <span class="saurity-section-arrow">▼</span>
                    </div>
                </div>
                <div class="saurity-section-content">
                    <div class="saurity-setting-row">
                        <div class="saurity-setting-info">
                            <div class="saurity-setting-name">Enable XML-RPC Protection</div>
                            <div class="saurity-setting-desc">Rate limit xmlrpc.php requests</div>
                        </div>
                        <div class="saurity-setting-control">
                            <label class="saurity-toggle">
                                <input type="checkbox" name="saurity_enable_xmlrpc_protection" value="1" 
                                       <?php checked( get_option( 'saurity_enable_xmlrpc_protection', true ) ); ?> />
                                <span class="saurity-toggle-slider"></span>
                            </label>
                        </div>
                    </div>

                    <div class="saurity-setting-row">
                        <div class="saurity-setting-info">
                            <div class="saurity-setting-name">Request Limit</div>
                            <div class="saurity-setting-desc">XML-RPC requests allowed per minute</div>
                        </div>
                        <div class="saurity-setting-control">
                            <input type="number" name="saurity_xmlrpc_limit" 
                                   value="<?php echo esc_attr( get_option( 'saurity_xmlrpc_limit', 10 ) ); ?>" 
                                   min="1" max="50" style="width: 70px;" />
                            <span class="saurity-unit">/min</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Comment Protection Section -->
            <div class="saurity-section" id="section-comments">
                <div class="saurity-section-header" onclick="this.parentElement.classList.toggle('open')">
                    <div class="saurity-section-title">
                        <span class="saurity-section-icon">💬</span>
                        Comment Rate Limiting
                    </div>
                    <div class="saurity-section-status">
                        <span class="saurity-section-badge <?php echo get_option( 'saurity_enable_comment_rate_limiting', true ) ? 'enabled' : 'disabled'; ?>">
                            <?php echo get_option( 'saurity_enable_comment_rate_limiting', true ) ? 'Active' : 'Disabled'; ?>
                        </span>
                        <span class="saurity-section-arrow">▼</span>
                    </div>
                </div>
                <div class="saurity-section-content">
                    <div class="saurity-setting-row">
                        <div class="saurity-setting-info">
                            <div class="saurity-setting-name">Enable Comment Rate Limiting</div>
                            <div class="saurity-setting-desc">Prevents comment spam (logged-in users bypass)</div>
                        </div>
                        <div class="saurity-setting-control">
                            <label class="saurity-toggle">
                                <input type="checkbox" name="saurity_enable_comment_rate_limiting" value="1" 
                                       <?php checked( get_option( 'saurity_enable_comment_rate_limiting', true ) ); ?> />
                                <span class="saurity-toggle-slider"></span>
                            </label>
                        </div>
                    </div>

                    <div class="saurity-setting-row">
                        <div class="saurity-setting-info">
                            <div class="saurity-setting-name">Comment Limit</div>
                            <div class="saurity-setting-desc">Comments allowed per time window</div>
                        </div>
                        <div class="saurity-setting-control">
                            <input type="number" name="saurity_comment_rate_limit" 
                                   value="<?php echo esc_attr( get_option( 'saurity_comment_rate_limit', 3 ) ); ?>" 
                                   min="1" max="20" style="width: 60px;" />
                        </div>
                    </div>

                    <div class="saurity-setting-row">
                        <div class="saurity-setting-info">
                            <div class="saurity-setting-name">Time Window</div>
                            <div class="saurity-setting-desc">Period for counting comments</div>
                        </div>
                        <div class="saurity-setting-control">
                            <input type="number" name="saurity_comment_rate_window" 
                                   value="<?php echo esc_attr( get_option( 'saurity_comment_rate_window', 300 ) ); ?>" 
                                   min="60" max="1800" style="width: 80px;" />
                            <span class="saurity-unit">seconds</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Advanced Bot Detection Section -->
            <div class="saurity-section" id="section-bot-detection">
                <div class="saurity-section-header" onclick="this.parentElement.classList.toggle('open')">
                    <div class="saurity-section-title">
                        <span class="saurity-section-icon">🤖</span>
                        Advanced Bot Detection
                    </div>
                    <div class="saurity-section-status">
                        <span class="saurity-section-badge enabled">Active</span>
                        <span class="saurity-section-arrow">▼</span>
                    </div>
                </div>
                <div class="saurity-section-content">
                    <div class="saurity-setting-row">
                        <div class="saurity-setting-info">
                            <div class="saurity-setting-name">🍯 Honeypot Detection</div>
                            <div class="saurity-setting-desc">Hidden field that catches bots (zero false positives)</div>
                        </div>
                        <div class="saurity-setting-control">
                            <label class="saurity-toggle">
                                <input type="checkbox" name="saurity_enable_honeypot" value="1" 
                                       <?php checked( get_option( 'saurity_enable_honeypot', true ) ); ?> />
                                <span class="saurity-toggle-slider"></span>
                            </label>
                        </div>
                    </div>

                    <div class="saurity-setting-row">
                        <div class="saurity-setting-info">
                            <div class="saurity-setting-name">⏱️ Timing Check</div>
                            <div class="saurity-setting-desc">Blocks instant form submissions (humans need 2+ seconds)</div>
                        </div>
                        <div class="saurity-setting-control">
                            <label class="saurity-toggle">
                                <input type="checkbox" name="saurity_enable_timing_check" value="1" 
                                       <?php checked( get_option( 'saurity_enable_timing_check', true ) ); ?> />
                                <span class="saurity-toggle-slider"></span>
                            </label>
                        </div>
                    </div>

                    <div class="saurity-setting-row">
                        <div class="saurity-setting-info">
                            <div class="saurity-setting-name">Min Form Time</div>
                            <div class="saurity-setting-desc">Minimum seconds to submit login form</div>
                        </div>
                        <div class="saurity-setting-control">
                            <input type="number" name="saurity_min_form_time" 
                                   value="<?php echo esc_attr( get_option( 'saurity_min_form_time', 2 ) ); ?>" 
                                   min="1" max="10" style="width: 60px;" />
                            <span class="saurity-unit">seconds</span>
                        </div>
                    </div>

                    <div class="saurity-setting-row">
                        <div class="saurity-setting-info">
                            <div class="saurity-setting-name">🐢 Tarpitting (Attack Slowdown)</div>
                            <div class="saurity-setting-desc">Adds delay before blocking to waste attacker time</div>
                        </div>
                        <div class="saurity-setting-control">
                            <label class="saurity-toggle">
                                <input type="checkbox" name="saurity_enable_tarpitting" value="1" 
                                       <?php checked( get_option( 'saurity_enable_tarpitting', true ) ); ?> />
                                <span class="saurity-toggle-slider"></span>
                            </label>
                        </div>
                    </div>

                    <div class="saurity-setting-row">
                        <div class="saurity-setting-info">
                            <div class="saurity-setting-name">Tarpit Delay</div>
                            <div class="saurity-setting-desc">Seconds to delay before showing block page</div>
                        </div>
                        <div class="saurity-setting-control">
                            <input type="number" name="saurity_tarpit_delay" 
                                   value="<?php echo esc_attr( get_option( 'saurity_tarpit_delay', 3 ) ); ?>" 
                                   min="1" max="10" style="width: 60px;" />
                            <span class="saurity-unit">seconds</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Advanced Security Section -->
            <div class="saurity-section" id="section-advanced">
                <div class="saurity-section-header" onclick="this.parentElement.classList.toggle('open')">
                    <div class="saurity-section-title">
                        <span class="saurity-section-icon">⚠️</span>
                        Advanced Security (Use with caution)
                    </div>
                    <div class="saurity-section-status">
                        <span class="saurity-section-arrow">▼</span>
                    </div>
                </div>
                <div class="saurity-section-content">
                    <div style="background: #fff3cd; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #ffc107;">
                        <strong>⚠️ Warning:</strong> These features can cause false positives. Only enable if needed.
                    </div>

                    <div class="saurity-setting-row">
                        <div class="saurity-setting-info">
                            <div class="saurity-setting-name">🌐 General Request Throttling</div>
                            <div class="saurity-setting-desc">Limit ALL requests from anonymous IPs (DoS protection)</div>
                        </div>
                        <div class="saurity-setting-control">
                            <label class="saurity-toggle">
                                <input type="checkbox" name="saurity_enable_request_throttle" value="1" 
                                       <?php checked( get_option( 'saurity_enable_request_throttle', false ) ); ?> />
                                <span class="saurity-toggle-slider"></span>
                            </label>
                        </div>
                    </div>

                    <div class="saurity-setting-row">
                        <div class="saurity-setting-info">
                            <div class="saurity-setting-name">Request Limit</div>
                            <div class="saurity-setting-desc">Max requests per minute per IP</div>
                        </div>
                        <div class="saurity-setting-control">
                            <input type="number" name="saurity_request_throttle_limit" 
                                   value="<?php echo esc_attr( get_option( 'saurity_request_throttle_limit', 120 ) ); ?>" 
                                   min="60" max="300" style="width: 80px;" />
                            <span class="saurity-unit">/min</span>
                        </div>
                    </div>

                    <div class="saurity-setting-row">
                        <div class="saurity-setting-info">
                            <div class="saurity-setting-name">🔗 Subnet Blocking (Anti-Botnet)</div>
                            <div class="saurity-setting-desc">Block entire /24 ranges when failures exceed threshold</div>
                        </div>
                        <div class="saurity-setting-control">
                            <label class="saurity-toggle">
                                <input type="checkbox" name="saurity_enable_subnet_blocking" value="1" 
                                       <?php checked( get_option( 'saurity_enable_subnet_blocking', false ) ); ?> />
                                <span class="saurity-toggle-slider"></span>
                            </label>
                        </div>
                    </div>

                    <div class="saurity-setting-row">
                        <div class="saurity-setting-info">
                            <div class="saurity-setting-name">Subnet Threshold</div>
                            <div class="saurity-setting-desc">Failures before blocking entire subnet</div>
                        </div>
                        <div class="saurity-setting-control">
                            <input type="number" name="saurity_subnet_failure_threshold" 
                                   value="<?php echo esc_attr( get_option( 'saurity_subnet_failure_threshold', 30 ) ); ?>" 
                                   min="10" max="100" style="width: 70px;" />
                            <span class="saurity-unit">failures</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Logging & Email Section -->
            <div class="saurity-section open" id="section-logging">
                <div class="saurity-section-header" onclick="this.parentElement.classList.toggle('open')">
                    <div class="saurity-section-title">
                        <span class="saurity-section-icon">📧</span>
                        Logging & Email Settings
                    </div>
                    <div class="saurity-section-status">
                        <span class="saurity-section-arrow">▼</span>
                    </div>
                </div>
                <div class="saurity-section-content">
                    <div class="saurity-setting-row">
                        <div class="saurity-setting-info">
                            <div class="saurity-setting-name">Log Retention</div>
                            <div class="saurity-setting-desc">Days to keep activity logs before auto-cleanup</div>
                        </div>
                        <div class="saurity-setting-control">
                            <input type="number" name="saurity_log_retention_days" 
                                   value="<?php echo esc_attr( get_option( 'saurity_log_retention_days', 15 ) ); ?>" 
                                   min="1" max="365" style="width: 70px;" />
                            <span class="saurity-unit">days</span>
                        </div>
                    </div>

                    <div class="saurity-setting-row">
                        <div class="saurity-setting-info">
                            <div class="saurity-setting-name">Notification Email</div>
                            <div class="saurity-setting-desc">Email for security alerts (leave blank for admin email)</div>
                        </div>
                        <div class="saurity-setting-control">
                            <input type="email" name="saurity_notification_email" 
                                   value="<?php echo esc_attr( get_option( 'saurity_notification_email', '' ) ); ?>" 
                                   placeholder="<?php echo esc_attr( get_option( 'admin_email' ) ); ?>"
                                   style="width: 200px;" />
                        </div>
                    </div>

                    <div class="saurity-setting-row">
                        <div class="saurity-setting-info">
                            <div class="saurity-setting-name">Test Email</div>
                            <div class="saurity-setting-desc">Send a test email to verify delivery</div>
                        </div>
                        <div class="saurity-setting-control">
                            <a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=saurity_test_email' ), 'saurity_test' ) ); ?>" 
                               class="button">
                                Send Test Email
                            </a>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Save Bar -->
            <div style="margin-top: 30px; padding: 20px; background: #f8f9fa; border-radius: 8px; border: 1px solid #e0e0e0;">
                <?php submit_button( 'Save All Settings', 'primary large', 'submit', false ); ?>
                <span style="margin-left: 15px; color: #666;">All changes are saved when you click this button.</span>
            </div>
        </form>

        <style>
            /* Ensure sections start collapsed except specified */
            .saurity-section:not(.open) .saurity-section-content { display: none; }
            .saurity-section.open .saurity-section-content { display: block; }
            .saurity-section.open .saurity-section-arrow { transform: rotate(180deg); }
        </style>
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
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- These are pagination/filter parameters, not form submissions
        $current_filter = isset( $_GET['log_type'] ) ? sanitize_text_field( wp_unslash( $_GET['log_type'] ) ) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $current_page = isset( $_GET['log_page'] ) ? max( 1, absint( $_GET['log_page'] ) ) : 1;
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $search_term = isset( $_GET['log_search'] ) ? sanitize_text_field( wp_unslash( $_GET['log_search'] ) ) : '';
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
                <a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=saurity_export_csv' ), 'saurity_export' ) ); ?>" 
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
                    echo '<div class="tablenav"><div class="tablenav-pages">' . wp_kses_post( $page_links ) . '</div></div>';
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
     * Get country flag emoji
     *
     * @param string $code ISO country code.
     * @return string Flag emoji.
     */
    private function get_country_flag( $code ) {
        if ( strlen( $code ) !== 2 ) {
            return '🏳️';
        }

        $code = strtoupper( $code );
        
        // Convert letters to regional indicator symbols
        $flag = mb_chr( 0x1F1E6 + ord( $code[0] ) - ord( 'A' ) ) .
                mb_chr( 0x1F1E6 + ord( $code[1] ) - ord( 'A' ) );

        return $flag;
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
        header( 'Content-Disposition: attachment; filename="saurity-logs-' . gmdate( 'Y-m-d' ) . '.csv"' );
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

        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Closing php://output stream
        fclose( $output );
        exit;
    }

    /**
     * Render IP management tab - Modern UI with pagination, search, and bulk actions
     */
    private function render_ip_management() {
        $current_ip = $this->ip_manager->get_current_ip();
        $stats = $this->ip_manager->get_statistics();
        
        // Get URL parameters for both lists
        // phpcs:disable WordPress.Security.NonceVerification.Recommended -- These are pagination/filter parameters, not form submissions
        $allowlist_page = isset( $_GET['allowlist_page'] ) ? max( 1, absint( $_GET['allowlist_page'] ) ) : 1;
        $blocklist_page = isset( $_GET['blocklist_page'] ) ? max( 1, absint( $_GET['blocklist_page'] ) ) : 1;
        $allowlist_search = isset( $_GET['allowlist_search'] ) ? sanitize_text_field( wp_unslash( $_GET['allowlist_search'] ) ) : '';
        $blocklist_search = isset( $_GET['blocklist_search'] ) ? sanitize_text_field( wp_unslash( $_GET['blocklist_search'] ) ) : '';
        $allowlist_sort = isset( $_GET['allowlist_sort'] ) ? sanitize_text_field( wp_unslash( $_GET['allowlist_sort'] ) ) : 'added';
        $blocklist_sort = isset( $_GET['blocklist_sort'] ) ? sanitize_text_field( wp_unslash( $_GET['blocklist_sort'] ) ) : 'added';
        $allowlist_order = isset( $_GET['allowlist_order'] ) && $_GET['allowlist_order'] === 'asc' ? 'asc' : 'desc';
        $blocklist_order = isset( $_GET['blocklist_order'] ) && $_GET['blocklist_order'] === 'asc' ? 'asc' : 'desc';
        // phpcs:enable WordPress.Security.NonceVerification.Recommended
        $per_page = 15;
        
        // Get paginated data
        $allowlist_data = $this->ip_manager->get_allowlist_paginated( $allowlist_page, $per_page, $allowlist_search, $allowlist_sort, $allowlist_order );
        $blocklist_data = $this->ip_manager->get_blocklist_paginated( $blocklist_page, $per_page, $blocklist_search, $blocklist_sort, $blocklist_order );
        
        ?>
        
        <!-- Current IP Banner -->
        <div class="saurity-current-ip-banner">
            <div class="saurity-current-ip-info">
                <span class="saurity-current-ip-label">Your Current IP:</span>
                <code class="saurity-current-ip-value"><?php echo esc_html( $current_ip ); ?></code>
            </div>
            <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="saurity-current-ip-form">
                <input type="hidden" name="action" value="saurity_add_to_allowlist" />
                <input type="hidden" name="ip" value="<?php echo esc_attr( $current_ip ); ?>" />
                <input type="hidden" name="note" value="Auto-added from admin panel" />
                <?php wp_nonce_field( 'saurity_ip_action' ); ?>
                <button type="submit" class="button button-primary">Allowlist My IP</button>
            </form>
        </div>

        <!-- Statistics Cards -->
        <div class="saurity-ip-stats-grid">
            <div class="saurity-ip-stat-card saurity-ip-stat-success">
                <div class="saurity-ip-stat-content">
                    <div class="saurity-ip-stat-value"><?php echo esc_html( $stats['allowlist_total'] ); ?></div>
                    <div class="saurity-ip-stat-label">Allowlisted</div>
                    <div class="saurity-ip-stat-sub">
                        <?php echo esc_html( $stats['allowlist_single'] ); ?> IPs, <?php echo esc_html( $stats['allowlist_cidr'] ); ?> CIDR
                    </div>
                </div>
            </div>
            
            <div class="saurity-ip-stat-card saurity-ip-stat-danger">
                <div class="saurity-ip-stat-content">
                    <div class="saurity-ip-stat-value"><?php echo esc_html( $stats['blocklist_total'] ); ?></div>
                    <div class="saurity-ip-stat-label">Blocklisted</div>
                    <div class="saurity-ip-stat-sub">
                        <?php echo esc_html( $stats['blocklist_single'] ); ?> IPs, <?php echo esc_html( $stats['blocklist_cidr'] ); ?> CIDR
                    </div>
                </div>
            </div>
            
            <div class="saurity-ip-stat-card saurity-ip-stat-warning">
                <div class="saurity-ip-stat-content">
                    <div class="saurity-ip-stat-value"><?php echo esc_html( $stats['recent_blocklist'] ); ?></div>
                    <div class="saurity-ip-stat-label">Blocked (7 days)</div>
                    <div class="saurity-ip-stat-sub">
                        +<?php echo esc_html( $stats['recent_allowlist'] ); ?> allowlisted
                    </div>
                </div>
            </div>
        </div>

        <!-- Two Column Layout -->
        <div class="saurity-ip-columns">
            
            <!-- Allowlist Section -->
            <div class="saurity-ip-section saurity-ip-section-allowlist">
                <div class="saurity-ip-section-header">
                    <div class="saurity-ip-section-title">
                        <span class="saurity-ip-section-icon">✅</span>
                        <div>
                            <h2>Allowlist (Trusted IPs)</h2>
                            <p>Bypass all security checks and rate limiting</p>
                        </div>
                    </div>
                    <div class="saurity-ip-section-actions">
                        <a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=saurity_export_allowlist' ), 'saurity_export' ) ); ?>" 
                           class="button button-small" title="Export to CSV">
                            📥 Export
                        </a>
                        <button type="button" class="button button-small" onclick="document.getElementById('import-allowlist-file').click();" title="Import from CSV">
                            📤 Import
                        </button>
                        <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" 
                              enctype="multipart/form-data" style="display: none;">
                            <input type="hidden" name="action" value="saurity_import_allowlist" />
                            <?php wp_nonce_field( 'saurity_import' ); ?>
                            <input type="file" name="csv_file" id="import-allowlist-file" accept=".csv" 
                                   onchange="if(confirm('Import IPs from CSV?')) { this.form.submit(); }" />
                        </form>
                    </div>
                </div>
                
                <!-- Add Form -->
                <div class="saurity-ip-add-form saurity-ip-add-form-allowlist">
                    <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
                        <input type="hidden" name="action" value="saurity_add_to_allowlist" />
                        <?php wp_nonce_field( 'saurity_ip_action' ); ?>
                        <div class="saurity-ip-add-row">
                            <input type="text" name="ip" placeholder="IP or CIDR (e.g., 192.168.1.1 or 10.0.0.0/24)" required />
                            <input type="text" name="note" placeholder="Note (optional)" />
                            <button type="submit" class="button button-primary">➕ Add</button>
                        </div>
                    </form>
                </div>
                
                <!-- Search & Filter -->
                <div class="saurity-ip-toolbar">
                    <form method="get" class="saurity-ip-search-form">
                        <input type="hidden" name="page" value="saurity" />
                        <input type="hidden" name="tab" value="ip-management" />
                        <?php if ( $blocklist_search ) : ?>
                            <input type="hidden" name="blocklist_search" value="<?php echo esc_attr( $blocklist_search ); ?>" />
                        <?php endif; ?>
                        <input type="text" name="allowlist_search" value="<?php echo esc_attr( $allowlist_search ); ?>" 
                               placeholder="Search IPs or notes..." />
                        <button type="submit" class="button">🔍</button>
                        <?php if ( $allowlist_search ) : ?>
                            <a href="<?php echo esc_url( remove_query_arg( 'allowlist_search' ) ); ?>" class="button">✕</a>
                        <?php endif; ?>
                    </form>
                    
                    <div class="saurity-ip-sort">
                        <span>Sort:</span>
                        <?php
                        $sort_options = [ 'added' => 'Date', 'ip' => 'IP', 'note' => 'Note' ];
                        foreach ( $sort_options as $sort_key => $sort_label ) :
                            $is_active = $allowlist_sort === $sort_key;
                            $new_order = $is_active && $allowlist_order === 'desc' ? 'asc' : 'desc';
                            $sort_url = add_query_arg( [ 'allowlist_sort' => $sort_key, 'allowlist_order' => $new_order ] );
                        ?>
                            <a href="<?php echo esc_url( $sort_url ); ?>" 
                               class="saurity-ip-sort-btn <?php echo $is_active ? 'active' : ''; ?>">
                                <?php echo esc_html( $sort_label ); ?>
                                <?php if ( $is_active ) echo $allowlist_order === 'asc' ? '↑' : '↓'; ?>
                            </a>
                        <?php endforeach; ?>
                    </div>
                </div>
                
                <!-- Bulk Actions Form -->
                <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" id="allowlist-bulk-form">
                    <input type="hidden" name="action" value="saurity_bulk_ip_action" />
                    <input type="hidden" name="list_type" value="allowlist" />
                    <?php wp_nonce_field( 'saurity_bulk_ip' ); ?>
                    
                    <!-- Table -->
                    <div class="saurity-ip-table-container">
                        <?php if ( empty( $allowlist_data['items'] ) ) : ?>
                            <div class="saurity-ip-empty">
                                <span class="saurity-ip-empty-icon">📋</span>
                                <p><?php echo $allowlist_search ? 'No IPs match your search.' : 'No IPs in allowlist yet.'; ?></p>
                            </div>
                        <?php else : ?>
                            <!-- Bulk Actions Bar -->
                            <div class="saurity-ip-bulk-bar" id="allowlist-bulk-bar" style="display: none;">
                                <span class="saurity-ip-bulk-count">
                                    <strong id="allowlist-selected-count">0</strong> selected
                                </span>
                                <select name="bulk_action" class="saurity-ip-bulk-select">
                                    <option value="">Bulk Actions</option>
                                    <option value="remove">🗑️ Remove Selected</option>
                                    <option value="move_to_blocklist">➡️ Move to Blocklist</option>
                                </select>
                                <button type="submit" class="button button-small" onclick="return confirm('Apply action to selected IPs?');">Apply</button>
                            </div>
                            
                            <table class="saurity-ip-table">
                                <thead>
                                    <tr>
                                        <th class="saurity-ip-check-col">
                                            <input type="checkbox" id="allowlist-check-all" onclick="toggleAllCheckboxes('allowlist')" />
                                        </th>
                                        <th>IP / CIDR</th>
                                        <th>Note</th>
                                        <th>Added</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ( $allowlist_data['items'] as $item ) : ?>
                                        <tr>
                                            <td class="saurity-ip-check-col">
                                                <input type="checkbox" name="selected_ips[]" value="<?php echo esc_attr( $item['ip'] ); ?>" 
                                                       class="allowlist-checkbox" onchange="updateBulkBar('allowlist')" />
                                            </td>
                                            <td>
                                                <code class="saurity-ip-code"><?php echo esc_html( $item['ip'] ); ?></code>
                                                <?php if ( strpos( $item['ip'], '/' ) !== false ) : ?>
                                                    <span class="saurity-ip-badge saurity-ip-badge-cidr">CIDR</span>
                                                <?php endif; ?>
                                            </td>
                                            <td class="saurity-ip-note"><?php echo esc_html( $item['note'] ?: '-' ); ?></td>
                                            <td class="saurity-ip-date">
                                                <?php echo esc_html( $item['added'] ? gmdate( 'M j, Y', strtotime( $item['added'] ) ) : '-' ); ?>
                                                <?php if ( $item['added_by'] ) : ?>
                                                    <span class="saurity-ip-by">by <?php echo esc_html( $item['added_by'] ); ?></span>
                                                <?php endif; ?>
                                            </td>
                                            <td class="saurity-ip-actions">
                                                <a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=saurity_remove_from_allowlist&ip=' . urlencode( $item['ip'] ) ), 'saurity_ip_action' ) ); ?>" 
                                                   class="saurity-ip-action-btn saurity-ip-action-remove" 
                                                   title="Remove"
                                                   onclick="return confirm('Remove <?php echo esc_js( $item['ip'] ); ?>?');">
                                                    🗑️
                                                </a>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        <?php endif; ?>
                    </div>
                </form>
                
                <!-- Pagination -->
                <?php if ( $allowlist_data['pages'] > 1 ) : ?>
                    <div class="saurity-ip-pagination">
                        <?php
                        $base_url = add_query_arg( [ 'page' => 'saurity', 'tab' => 'ip-management' ], admin_url( 'admin.php' ) );
                        if ( $allowlist_search ) $base_url = add_query_arg( 'allowlist_search', $allowlist_search, $base_url );
                        if ( $allowlist_sort !== 'added' ) $base_url = add_query_arg( 'allowlist_sort', $allowlist_sort, $base_url );
                        if ( $allowlist_order !== 'desc' ) $base_url = add_query_arg( 'allowlist_order', $allowlist_order, $base_url );
                        
                        echo wp_kses_post( paginate_links( [
                            'base' => add_query_arg( 'allowlist_page', '%#%', $base_url ),
                            'format' => '',
                            'current' => $allowlist_page,
                            'total' => $allowlist_data['pages'],
                            'prev_text' => '«',
                            'next_text' => '»',
                        ] ) );
                        ?>
                        <span class="saurity-ip-pagination-info">
                            Page <?php echo esc_html( $allowlist_page ); ?> of <?php echo esc_html( $allowlist_data['pages'] ); ?>
                            (<?php echo esc_html( $allowlist_data['total'] ); ?> total)
                        </span>
                    </div>
                <?php endif; ?>
            </div>

            <!-- Blocklist Section -->
            <div class="saurity-ip-section saurity-ip-section-blocklist">
                <div class="saurity-ip-section-header">
                    <div class="saurity-ip-section-title">
                        <span class="saurity-ip-section-icon">🚫</span>
                        <div>
                            <h2>Blocklist (Permanently Blocked)</h2>
                            <p>Blocked from accessing the entire site</p>
                        </div>
                    </div>
                    <div class="saurity-ip-section-actions">
                        <a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=saurity_export_blocklist' ), 'saurity_export' ) ); ?>" 
                           class="button button-small" title="Export to CSV">
                            📥 Export
                        </a>
                        <button type="button" class="button button-small" onclick="document.getElementById('import-blocklist-file').click();" title="Import from CSV">
                            📤 Import
                        </button>
                        <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" 
                              enctype="multipart/form-data" style="display: none;">
                            <input type="hidden" name="action" value="saurity_import_blocklist" />
                            <?php wp_nonce_field( 'saurity_import' ); ?>
                            <input type="file" name="csv_file" id="import-blocklist-file" accept=".csv" 
                                   onchange="if(confirm('Import IPs from CSV?')) { this.form.submit(); }" />
                        </form>
                    </div>
                </div>
                
                <!-- Add Form -->
                <div class="saurity-ip-add-form saurity-ip-add-form-blocklist">
                    <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
                        <input type="hidden" name="action" value="saurity_add_to_blocklist" />
                        <?php wp_nonce_field( 'saurity_ip_action' ); ?>
                        <div class="saurity-ip-add-row">
                            <input type="text" name="ip" placeholder="IP or CIDR (e.g., 203.0.113.5 or 203.0.113.0/24)" required />
                            <input type="text" name="reason" placeholder="Reason (optional)" />
                            <button type="submit" class="button button-primary">➕ Block</button>
                        </div>
                    </form>
                </div>
                
                <!-- Search & Filter -->
                <div class="saurity-ip-toolbar">
                    <form method="get" class="saurity-ip-search-form">
                        <input type="hidden" name="page" value="saurity" />
                        <input type="hidden" name="tab" value="ip-management" />
                        <?php if ( $allowlist_search ) : ?>
                            <input type="hidden" name="allowlist_search" value="<?php echo esc_attr( $allowlist_search ); ?>" />
                        <?php endif; ?>
                        <input type="text" name="blocklist_search" value="<?php echo esc_attr( $blocklist_search ); ?>" 
                               placeholder="Search IPs or reasons..." />
                        <button type="submit" class="button">🔍</button>
                        <?php if ( $blocklist_search ) : ?>
                            <a href="<?php echo esc_url( remove_query_arg( 'blocklist_search' ) ); ?>" class="button">✕</a>
                        <?php endif; ?>
                    </form>
                    
                    <div class="saurity-ip-sort">
                        <span>Sort:</span>
                        <?php
                        $sort_options = [ 'added' => 'Date', 'ip' => 'IP', 'reason' => 'Reason' ];
                        foreach ( $sort_options as $sort_key => $sort_label ) :
                            $is_active = $blocklist_sort === $sort_key;
                            $new_order = $is_active && $blocklist_order === 'desc' ? 'asc' : 'desc';
                            $sort_url = add_query_arg( [ 'blocklist_sort' => $sort_key, 'blocklist_order' => $new_order ] );
                        ?>
                            <a href="<?php echo esc_url( $sort_url ); ?>" 
                               class="saurity-ip-sort-btn <?php echo $is_active ? 'active' : ''; ?>">
                                <?php echo esc_html( $sort_label ); ?>
                                <?php if ( $is_active ) echo $blocklist_order === 'asc' ? '↑' : '↓'; ?>
                            </a>
                        <?php endforeach; ?>
                    </div>
                </div>
                
                <!-- Bulk Actions Form -->
                <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" id="blocklist-bulk-form">
                    <input type="hidden" name="action" value="saurity_bulk_ip_action" />
                    <input type="hidden" name="list_type" value="blocklist" />
                    <?php wp_nonce_field( 'saurity_bulk_ip' ); ?>
                    
                    <!-- Table -->
                    <div class="saurity-ip-table-container">
                        <?php if ( empty( $blocklist_data['items'] ) ) : ?>
                            <div class="saurity-ip-empty">
                                <span class="saurity-ip-empty-icon">🛡️</span>
                                <p><?php echo $blocklist_search ? 'No IPs match your search.' : 'No IPs blocked yet. Good news!'; ?></p>
                            </div>
                        <?php else : ?>
                            <!-- Bulk Actions Bar -->
                            <div class="saurity-ip-bulk-bar" id="blocklist-bulk-bar" style="display: none;">
                                <span class="saurity-ip-bulk-count">
                                    <strong id="blocklist-selected-count">0</strong> selected
                                </span>
                                <select name="bulk_action" class="saurity-ip-bulk-select">
                                    <option value="">Bulk Actions</option>
                                    <option value="remove">🗑️ Unblock Selected</option>
                                    <option value="move_to_allowlist">➡️ Move to Allowlist</option>
                                </select>
                                <button type="submit" class="button button-small" onclick="return confirm('Apply action to selected IPs?');">Apply</button>
                            </div>
                            
                            <table class="saurity-ip-table">
                                <thead>
                                    <tr>
                                        <th class="saurity-ip-check-col">
                                            <input type="checkbox" id="blocklist-check-all" onclick="toggleAllCheckboxes('blocklist')" />
                                        </th>
                                        <th>IP / CIDR</th>
                                        <th>Reason</th>
                                        <th>Added</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ( $blocklist_data['items'] as $item ) : ?>
                                        <tr>
                                            <td class="saurity-ip-check-col">
                                                <input type="checkbox" name="selected_ips[]" value="<?php echo esc_attr( $item['ip'] ); ?>" 
                                                       class="blocklist-checkbox" onchange="updateBulkBar('blocklist')" />
                                            </td>
                                            <td>
                                                <code class="saurity-ip-code"><?php echo esc_html( $item['ip'] ); ?></code>
                                                <?php if ( strpos( $item['ip'], '/' ) !== false ) : ?>
                                                    <span class="saurity-ip-badge saurity-ip-badge-cidr">CIDR</span>
                                                <?php endif; ?>
                                            </td>
                                            <td class="saurity-ip-note"><?php echo esc_html( $item['reason'] ?: '-' ); ?></td>
                                            <td class="saurity-ip-date">
                                                <?php echo esc_html( $item['added'] ? gmdate( 'M j, Y', strtotime( $item['added'] ) ) : '-' ); ?>
                                                <?php if ( $item['added_by'] ) : ?>
                                                    <span class="saurity-ip-by">by <?php echo esc_html( $item['added_by'] ); ?></span>
                                                <?php endif; ?>
                                            </td>
                                            <td class="saurity-ip-actions">
                                                <a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=saurity_remove_from_blocklist&ip=' . urlencode( $item['ip'] ) ), 'saurity_ip_action' ) ); ?>"
                                                   class="saurity-ip-action-btn saurity-ip-action-unblock" 
                                                   title="Unblock"
                                                   onclick="return confirm('Unblock <?php echo esc_js( $item['ip'] ); ?>?');">
                                                    ✅
                                                </a>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        <?php endif; ?>
                    </div>
                </form>
                
                <!-- Pagination -->
                <?php if ( $blocklist_data['pages'] > 1 ) : ?>
                    <div class="saurity-ip-pagination">
                        <?php
                        $base_url = add_query_arg( [ 'page' => 'saurity', 'tab' => 'ip-management' ], admin_url( 'admin.php' ) );
                        if ( $blocklist_search ) $base_url = add_query_arg( 'blocklist_search', $blocklist_search, $base_url );
                        if ( $blocklist_sort !== 'added' ) $base_url = add_query_arg( 'blocklist_sort', $blocklist_sort, $base_url );
                        if ( $blocklist_order !== 'desc' ) $base_url = add_query_arg( 'blocklist_order', $blocklist_order, $base_url );
                        
                        echo wp_kses_post( paginate_links( [
                            'base' => add_query_arg( 'blocklist_page', '%#%', $base_url ),
                            'format' => '',
                            'current' => $blocklist_page,
                            'total' => $blocklist_data['pages'],
                            'prev_text' => '«',
                            'next_text' => '»',
                        ] ) );
                        ?>
                        <span class="saurity-ip-pagination-info">
                            Page <?php echo esc_html( $blocklist_page ); ?> of <?php echo esc_html( $blocklist_data['pages'] ); ?>
                            (<?php echo esc_html( $blocklist_data['total'] ); ?> total)
                        </span>
                    </div>
                <?php endif; ?>
            </div>
        </div>
        
        <!-- Tips Section -->
        <div class="saurity-ip-tips">
            <h4>💡 Quick Tips</h4>
            <ul>
                <li><strong>CIDR Notation:</strong> Use <code>/24</code> to block 256 IPs (e.g., <code>192.168.1.0/24</code>), or <code>/16</code> for 65,536 IPs</li>
                <li><strong>Allowlist Priority:</strong> Allowlisted IPs bypass ALL security checks including rate limiting and firewall rules</li>
                <li><strong>Bulk Actions:</strong> Select multiple IPs using checkboxes, then use the dropdown to remove or move them</li>
                <li><strong>Import/Export:</strong> CSV format: <code>IP,Note/Reason,Date,AddedBy</code> (first row is header)</li>
            </ul>
        </div>
        
        <script type="text/javascript">
        function toggleAllCheckboxes(listType) {
            var checkAll = document.getElementById(listType + '-check-all');
            var checkboxes = document.querySelectorAll('.' + listType + '-checkbox');
            checkboxes.forEach(function(cb) {
                cb.checked = checkAll.checked;
            });
            updateBulkBar(listType);
        }
        
        function updateBulkBar(listType) {
            var checkboxes = document.querySelectorAll('.' + listType + '-checkbox:checked');
            var count = checkboxes.length;
            var bulkBar = document.getElementById(listType + '-bulk-bar');
            var countSpan = document.getElementById(listType + '-selected-count');
            
            if (count > 0) {
                bulkBar.style.display = 'flex';
                countSpan.textContent = count;
            } else {
                bulkBar.style.display = 'none';
            }
        }
        </script>
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

        $ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
        $note = isset( $_POST['note'] ) ? sanitize_text_field( wp_unslash( $_POST['note'] ) ) : '';

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

        $ip = isset( $_GET['ip'] ) ? sanitize_text_field( wp_unslash( $_GET['ip'] ) ) : '';

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

        $ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
        $reason = isset( $_POST['reason'] ) ? sanitize_text_field( wp_unslash( $_POST['reason'] ) ) : '';

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

        $ip = isset( $_GET['ip'] ) ? sanitize_text_field( wp_unslash( $_GET['ip'] ) ) : '';

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
        header( 'Content-Disposition: attachment; filename="saurity-allowlist-' . gmdate( 'Y-m-d' ) . '.csv"' );
        header( 'Pragma: no-cache' );
        header( 'Expires: 0' );

        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV content must not be escaped
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
        header( 'Content-Disposition: attachment; filename="saurity-blocklist-' . gmdate( 'Y-m-d' ) . '.csv"' );
        header( 'Pragma: no-cache' );
        header( 'Expires: 0' );

        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CSV content must not be escaped
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

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- tmp_name is a server-generated path, cannot be sanitized
        if ( empty( $_FILES['csv_file']['tmp_name'] ) ) {
            add_settings_error(
                'saurity_messages',
                'saurity_message',
                'No file uploaded.',
                'error'
            );
        } else {
            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading uploaded file content
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
     * AJAX handler for threat feed updates
     */
    public function ajax_update_threat_feeds() {
        check_ajax_referer( 'saurity_feeds_ajax', 'nonce' );
        
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( [ 'message' => 'Unauthorized' ] );
        }

        $feed_id = isset( $_POST['feed_id'] ) ? sanitize_text_field( wp_unslash( $_POST['feed_id'] ) ) : '';
        
        if ( empty( $feed_id ) ) {
            wp_send_json_error( [ 'message' => 'No feed ID provided' ] );
        }

        $plugin = \Saurity\Plugin::get_instance();
        $cloud_integration = $plugin->get_component( 'cloud_integration' );

        if ( ! $cloud_integration ) {
            wp_send_json_error( [ 'message' => 'Cloud integration not available' ] );
        }

        $threat_intel = $cloud_integration->get_threat_intel();
        
        if ( ! $threat_intel ) {
            wp_send_json_error( [ 'message' => 'Threat intelligence not available' ] );
        }

        // Update the specific feed
        $builtin_feeds = $threat_intel->get_builtin_feeds();
        
        if ( ! isset( $builtin_feeds[ $feed_id ] ) ) {
            wp_send_json_error( [ 'message' => 'Invalid feed ID' ] );
        }

        $feed_info = $builtin_feeds[ $feed_id ];
        $result = $threat_intel->update_single_feed( $feed_id, $feed_info['url'], $feed_info['format'] );

        if ( $result['success'] ) {
            wp_send_json_success( [
                'message' => "Feed {$feed_info['name']} updated successfully",
                'feed_id' => $feed_id,
                'total_ips' => $result['added'],
            ] );
        } else {
            wp_send_json_error( [
                'message' => "Failed to update feed: " . $result['error'],
                'feed_id' => $feed_id,
            ] );
        }
    }

    /**
     * Handle manual threat feed update (now redirects to AJAX version)
     */
    public function handle_update_threat_feeds() {
        check_admin_referer( 'saurity_update_feeds' );
        
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Unauthorized' );
        }

        // Just redirect back - the actual update will happen via AJAX
        add_settings_error(
            'saurity_messages',
            'saurity_message',
            'Click the "Start Update" button below to begin updating threat feeds.',
            'info'
        );

        set_transient( 'saurity_admin_notice', get_settings_errors( 'saurity_messages' ), 30 );
        wp_safe_redirect( admin_url( 'admin.php?page=saurity&tab=cloud-services' ) );
        exit;
    }

    /**
     * Handle bulk IP actions
     */
    public function handle_bulk_ip_action() {
        check_admin_referer( 'saurity_bulk_ip' );
        
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Unauthorized' );
        }

        $list_type = isset( $_POST['list_type'] ) ? sanitize_text_field( wp_unslash( $_POST['list_type'] ) ) : '';
        $bulk_action = isset( $_POST['bulk_action'] ) ? sanitize_text_field( wp_unslash( $_POST['bulk_action'] ) ) : '';
        $selected_ips = isset( $_POST['selected_ips'] ) ? array_map( 'sanitize_text_field', wp_unslash( $_POST['selected_ips'] ) ) : [];

        if ( empty( $bulk_action ) || empty( $selected_ips ) ) {
            add_settings_error(
                'saurity_messages',
                'saurity_message',
                'Please select IPs and an action.',
                'error'
            );
            set_transient( 'saurity_admin_notice', get_settings_errors( 'saurity_messages' ), 30 );
            wp_safe_redirect( admin_url( 'admin.php?page=saurity&tab=ip-management' ) );
            exit;
        }

        $count = 0;
        $action_label = '';

        if ( $list_type === 'allowlist' ) {
            if ( $bulk_action === 'remove' ) {
                $count = $this->ip_manager->bulk_remove_from_allowlist( $selected_ips );
                $action_label = 'removed from allowlist';
            } elseif ( $bulk_action === 'move_to_blocklist' ) {
                $count = $this->ip_manager->bulk_move_to_blocklist( $selected_ips );
                $action_label = 'moved to blocklist';
            }
        } elseif ( $list_type === 'blocklist' ) {
            if ( $bulk_action === 'remove' ) {
                $count = $this->ip_manager->bulk_remove_from_blocklist( $selected_ips );
                $action_label = 'unblocked';
            } elseif ( $bulk_action === 'move_to_allowlist' ) {
                $count = $this->ip_manager->bulk_move_to_allowlist( $selected_ips );
                $action_label = 'moved to allowlist';
            }
        }

        if ( $count > 0 ) {
            add_settings_error(
                'saurity_messages',
                'saurity_message',
                "{$count} IP(s) {$action_label} successfully.",
                'success'
            );
        } else {
            add_settings_error(
                'saurity_messages',
                'saurity_message',
                'No IPs were modified.',
                'warning'
            );
        }

        set_transient( 'saurity_admin_notice', get_settings_errors( 'saurity_messages' ), 30 );
        wp_safe_redirect( admin_url( 'admin.php?page=saurity&tab=ip-management' ) );
        exit;
    }

    /**
     * AJAX handler for bulk IP actions
     */
    public function ajax_bulk_ip_action() {
        check_ajax_referer( 'saurity_bulk_ip', '_wpnonce' );
        
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( [ 'message' => 'Unauthorized' ] );
        }

        $list_type = isset( $_POST['list_type'] ) ? sanitize_text_field( wp_unslash( $_POST['list_type'] ) ) : '';
        $bulk_action = isset( $_POST['bulk_action'] ) ? sanitize_text_field( wp_unslash( $_POST['bulk_action'] ) ) : '';
        $selected_ips = isset( $_POST['selected_ips'] ) ? array_map( 'sanitize_text_field', wp_unslash( $_POST['selected_ips'] ) ) : [];

        if ( empty( $bulk_action ) || empty( $selected_ips ) ) {
            wp_send_json_error( [ 'message' => 'Please select IPs and an action.' ] );
        }

        $count = 0;

        if ( $list_type === 'allowlist' ) {
            if ( $bulk_action === 'remove' ) {
                $count = $this->ip_manager->bulk_remove_from_allowlist( $selected_ips );
            } elseif ( $bulk_action === 'move_to_blocklist' ) {
                $count = $this->ip_manager->bulk_move_to_blocklist( $selected_ips );
            }
        } elseif ( $list_type === 'blocklist' ) {
            if ( $bulk_action === 'remove' ) {
                $count = $this->ip_manager->bulk_remove_from_blocklist( $selected_ips );
            } elseif ( $bulk_action === 'move_to_allowlist' ) {
                $count = $this->ip_manager->bulk_move_to_allowlist( $selected_ips );
            }
        }

        wp_send_json_success( [
            'message' => "{$count} IP(s) processed successfully.",
            'count' => $count,
        ] );
    }

    /**
     * Handle import blocklist
     */
    public function handle_import_blocklist() {
        check_admin_referer( 'saurity_import' );
        
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Unauthorized' );
        }

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- tmp_name is a server-generated path, cannot be sanitized
        if ( empty( $_FILES['csv_file']['tmp_name'] ) ) {
            add_settings_error(
                'saurity_messages',
                'saurity_message',
                'No file uploaded.',
                'error'
            );
        } else {
            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading uploaded file content
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

    /**
     * AJAX handler for Cloudflare connection test
     */
    public function ajax_cloudflare_test() {
        check_ajax_referer( 'saurity_cloudflare_ajax', 'nonce' );
        
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( [ 'message' => 'Unauthorized' ] );
        }

        // Check if cloud integration is available
        $plugin = \Saurity\Plugin::get_instance();
        $cloud_integration = $plugin->get_component( 'cloud_integration' );

        if ( ! $cloud_integration ) {
            // Create Cloudflare API instance directly for testing
            $cloudflare = new \Saurity\Cloud\CloudflareAPI( $this->logger );
        } else {
            $cloudflare = $cloud_integration->get_cloudflare();
        }

        if ( ! $cloudflare ) {
            $cloudflare = new \Saurity\Cloud\CloudflareAPI( $this->logger );
        }

        $result = $cloudflare->test_connection();

        if ( $result['success'] ) {
            wp_send_json_success( [
                'message' => $result['message'],
                'zone_name' => $result['zone_name'] ?? 'Unknown',
            ] );
        } else {
            wp_send_json_error( [ 'message' => $result['message'] ] );
        }
    }

    /**
     * AJAX handler for manual Cloudflare sync
     */
    public function ajax_cloudflare_sync() {
        check_ajax_referer( 'saurity_cloudflare_ajax', 'nonce' );
        
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( [ 'message' => 'Unauthorized' ] );
        }

        // Check if cloud integration is available
        $plugin = \Saurity\Plugin::get_instance();
        $cloud_integration = $plugin->get_component( 'cloud_integration' );

        if ( ! $cloud_integration ) {
            // Create Cloudflare API instance directly for syncing
            $cloudflare = new \Saurity\Cloud\CloudflareAPI( $this->logger );
        } else {
            $cloudflare = $cloud_integration->get_cloudflare();
        }

        if ( ! $cloudflare ) {
            $cloudflare = new \Saurity\Cloud\CloudflareAPI( $this->logger );
        }

        $result = $cloudflare->sync();

        if ( $result['success'] ) {
            $message = 'Sync completed successfully!';
            if ( isset( $result['pushed'] ) && $result['pushed'] > 0 ) {
                $message .= " Pushed {$result['pushed']} IP(s) to Cloudflare.";
            }
            if ( isset( $result['imported'] ) && $result['imported'] > 0 ) {
                $message .= " Imported {$result['imported']} event(s).";
            }
            if ( ( ! isset( $result['pushed'] ) || $result['pushed'] == 0 ) && 
                 ( ! isset( $result['imported'] ) || $result['imported'] == 0 ) ) {
                $message .= ' No new items to sync.';
            }
            
            wp_send_json_success( [
                'message' => $message,
                'pushed' => $result['pushed'] ?? 0,
                'imported' => $result['imported'] ?? 0,
            ] );
        } else {
            wp_send_json_error( [ 'message' => $result['error'] ?? 'Sync failed' ] );
        }
    }

    /**
     * Render cloud services tab
     */
    private function render_cloud_services() {
        $plugin = \Saurity\Plugin::get_instance();
        $cloud_integration = $plugin->get_component( 'cloud_integration' );
        
        ?>
        <div style="margin-bottom: 20px; padding: 15px; background: #e7f3ff; border-radius: 8px; border-left: 4px solid #2196F3;">
            <h3 style="margin: 0 0 10px 0;">☁️ Cloud Services Integration</h3>
            <p style="margin: 0; font-size: 14px;">
                Connect Saurity with external services for enhanced protection. All integrations are optional and work independently.
            </p>
        </div>

        <form method="post" action="options.php">
            <?php settings_fields( 'saurity_cloud_settings' ); ?>
            <?php $this->render_tooltip_styles(); ?>

            <!-- Cloudflare Section - DISABLED -->
            <div style="background: #f5f5f5; padding: 20px; border: 1px solid #ddd; border-radius: 8px; border-left: 4px solid #999; margin-bottom: 20px; opacity: 0.6;">
                <h2 style="margin-top: 0; color: #999;">🔶 Cloudflare Integration (Coming Soon)</h2>
                <p style="color: #999; margin-bottom: 20px;">
                    Cloudflare integration is temporarily disabled. This feature requires a Cloudflare Pro plan for full functionality.
                </p>
                
                <!--
                <p style="color: #666; margin-bottom: 20px;">
                    Sync your WordPress blocklist with Cloudflare's edge firewall for enhanced protection.
                </p>
                -->

                <!-- Cloudflare UI commented out
                <table class="form-table">
                    <tr>
                        <th>
                            <span class="saurity-setting-label">
                                Enable Cloudflare
                                <?php $this->render_info_icon( 'Enables two-way sync between WordPress and Cloudflare. Blocked IPs are automatically added to Cloudflare firewall, and Cloudflare security events are imported into activity logs.' ); ?>
                            </span>
                        </th>
                        <td>
                            <label>
                                <input type="checkbox" name="saurity_cloudflare_enabled" value="1" 
                                       <?php checked( get_option( 'saurity_cloudflare_enabled', false ) ); ?> />
                                <strong>Enable Cloudflare Integration</strong>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th>API Token</th>
                        <td>
                            <input type="password" name="saurity_cloudflare_api_token" 
                                   value="<?php echo esc_attr( get_option( 'saurity_cloudflare_api_token', '' ) ); ?>" 
                                   class="regular-text" 
                                   placeholder="Enter Cloudflare API token" />
                            <p class="description">
                                Create an API token at <a href="https://dash.cloudflare.com/profile/api-tokens" target="_blank">Cloudflare Dashboard</a> 
                                with "Zone.Firewall Services" permissions
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th>Zone ID</th>
                        <td>
                            <input type="text" name="saurity_cloudflare_zone_id" 
                                   value="<?php echo esc_attr( get_option( 'saurity_cloudflare_zone_id', '' ) ); ?>" 
                                   class="regular-text" 
                                   placeholder="Your Cloudflare Zone ID" />
                            <p class="description">
                                Find your Zone ID in Cloudflare Dashboard → Overview → API section (right sidebar)
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th>Sync Options</th>
                        <td>
                            <label style="display: block; margin-bottom: 10px;">
                                <input type="checkbox" name="saurity_cloudflare_sync_blocklist" value="1" 
                                       <?php checked( get_option( 'saurity_cloudflare_sync_blocklist', true ) ); ?> />
                                Auto-sync Blocklist (Hourly)
                            </label>
                            <label>
                                <input type="checkbox" name="saurity_cloudflare_import_events" value="1" 
                                       <?php checked( get_option( 'saurity_cloudflare_import_events', true ) ); ?> />
                                Import Cloudflare Security Events
                            </label>
                            <p class="description">
                                Imports Cloudflare firewall events into activity log for unified monitoring
                            </p>
                        </td>
                    </tr>
                </table>
                -->

                <!-- Cloudflare buttons commented out
                <div style="background: #f0f0f0; padding: 15px; border-radius: 4px; display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
                    <?php /* submit_button( 'Save Cloudflare Settings', 'primary', 'submit', false ); */ ?>
                    <?php if ( get_option( 'saurity_cloudflare_enabled', false ) && get_option( 'saurity_cloudflare_api_token', '' ) ) : ?>
                        <button type="button" id="saurity-cf-test-connection" class="button button-secondary">
                            🔗 Test Connection
                        </button>
                        <button type="button" id="saurity-cf-manual-sync" class="button button-secondary">
                            🔄 Sync Now
                        </button>
                        <span id="saurity-cf-status" style="margin-left: 10px; font-size: 13px;"></span>
                    <?php endif; ?>
                </div>

                <?php if ( get_option( 'saurity_cloudflare_enabled', false ) && get_option( 'saurity_cloudflare_api_token', '' ) ) : ?>
                <script type="text/javascript">
                jQuery(document).ready(function($) {
                    // Test Connection button
                    $('#saurity-cf-test-connection').on('click', function() {
                        var $button = $(this);
                        var $status = $('#saurity-cf-status');
                        
                        $button.prop('disabled', true).text('⏳ Testing...');
                        $status.html('<span style="color: #666;">Connecting to Cloudflare API...</span>');
                        
                        $.ajax({
                            url: ajaxurl,
                            type: 'POST',
                            data: {
                                action: 'saurity_cloudflare_test',
                                nonce: '<?php echo esc_js( wp_create_nonce( 'saurity_cloudflare_ajax' ) ); ?>'
                            },
                            success: function(response) {
                                if (response.success) {
                                    $status.html('<span style="color: #28a745;">✅ ' + response.data.message + '</span>');
                                } else {
                                    $status.html('<span style="color: #dc3232;">❌ ' + response.data.message + '</span>');
                                }
                            },
                            error: function() {
                                $status.html('<span style="color: #dc3232;">❌ Network error</span>');
                            },
                            complete: function() {
                                $button.prop('disabled', false).text('🔗 Test Connection');
                            }
                        });
                    });
                    
                    // Manual Sync button
                    $('#saurity-cf-manual-sync').on('click', function() {
                        var $button = $(this);
                        var $status = $('#saurity-cf-status');
                        
                        $button.prop('disabled', true).text('⏳ Syncing...');
                        $status.html('<span style="color: #666;">Syncing with Cloudflare...</span>');
                        
                        $.ajax({
                            url: ajaxurl,
                            type: 'POST',
                            data: {
                                action: 'saurity_cloudflare_sync',
                                nonce: '<?php echo esc_js( wp_create_nonce( 'saurity_cloudflare_ajax' ) ); ?>'
                            },
                            success: function(response) {
                                if (response.success) {
                                    $status.html('<span style="color: #28a745;">✅ ' + response.data.message + '</span>');
                                    // Reload after 2 seconds to show updated stats
                                    setTimeout(function() {
                                        location.reload();
                                    }, 2000);
                                } else {
                                    $status.html('<span style="color: #dc3232;">❌ ' + response.data.message + '</span>');
                                }
                            },
                            error: function() {
                                $status.html('<span style="color: #dc3232;">❌ Network error</span>');
                            },
                            complete: function() {
                                $button.prop('disabled', false).text('🔄 Sync Now');
                            }
                        });
                    });
                });
                </script>
                <?php endif; ?>

                <?php /* Cloudflare stats commented out
                if ( $cloud_integration && get_option( 'saurity_cloudflare_enabled', false ) ) : ?>
                    <?php
                    $cloudflare = $cloud_integration->get_cloudflare();
                    if ( $cloudflare ) {
                        $cf_stats = $cloudflare->get_statistics();
                    ?>
                    <div style="margin-top: 15px; padding: 15px; background: #f8f9fa; border-radius: 4px;">
                        <h4 style="margin: 0 0 10px 0;">Status</h4>
                        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; font-size: 13px;">
                            <div>
                                <strong>Blocked IPs:</strong> <?php echo esc_html( $cf_stats['blocked_ips'] ); ?>
                            </div>
                            <div>
                                <strong>Events (24h):</strong> <?php echo esc_html( $cf_stats['events_24h'] ); ?>
                            </div>
                            <div>
                                <strong>Last Sync:</strong> <?php echo esc_html( $cf_stats['last_sync'] ); ?>
                            </div>
                        </div>
                    </div>
                    <?php } ?>
                <?php endif;
                */ ?>
                -->
            </div>

            <!-- Threat Intelligence Section -->
            <div style="background: #fff; padding: 20px; border: 1px solid #ddd; border-radius: 8px; border-left: 4px solid #9c27b0; margin-bottom: 20px;">
                <h2 style="margin-top: 0; color: #9c27b0;">🛡️ Threat Intelligence Feeds</h2>
                <p style="color: #666; margin-bottom: 20px;">
                    Automatically import and block IPs from trusted threat intelligence sources.
                </p>

                <table class="form-table">
                    <tr>
                        <th>
                            <span class="saurity-setting-label">
                                Enable Threat Feeds
                                <?php $this->render_info_icon( 'Automatically downloads and imports malicious IP lists from trusted sources. IPs are added to your blocklist and removed when they age out or are no longer in feeds.' ); ?>
                            </span>
                        </th>
                        <td>
                            <label>
                                <input type="checkbox" name="saurity_threat_feeds_enabled" value="1" 
                                       <?php checked( get_option( 'saurity_threat_feeds_enabled', false ) ); ?> />
                                <strong>Enable Threat Feed Integration</strong>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th>Built-in Feeds</th>
                        <td>
                            <?php
                            $enabled_feeds = get_option( 'saurity_threat_feeds_builtin', [] );
                            // Ensure $enabled_feeds is always an array (WordPress may return empty string)
                            if ( ! is_array( $enabled_feeds ) ) {
                                $enabled_feeds = [];
                            }
                            $builtin_feeds = [
                                'emerging_threats' => 'Emerging Threats (Known compromised hosts)',
                                'spamhaus' => 'Spamhaus DROP (Don\'t Route Or Peer)',
                                'blocklist_de' => 'Blocklist.de (SSH, mail, Apache attackers)',
                            ];
                            
                            foreach ( $builtin_feeds as $feed_id => $feed_name ) :
                            ?>
                                <label style="display: block; margin-bottom: 8px;">
                                    <input type="checkbox" name="saurity_threat_feeds_builtin[]" value="<?php echo esc_attr( $feed_id ); ?>" 
                                           <?php checked( in_array( $feed_id, $enabled_feeds, true ) ); ?> />
                                    <?php echo esc_html( $feed_name ); ?>
                                </label>
                            <?php endforeach; ?>
                            <p class="description">
                                Free threat intelligence sources (updated daily)
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th>Update Interval</th>
                        <td>
                            <select name="saurity_threat_feeds_update_interval">
                                <option value="hourly" <?php selected( get_option( 'saurity_threat_feeds_update_interval', 'daily' ), 'hourly' ); ?>>Hourly</option>
                                <option value="twicedaily" <?php selected( get_option( 'saurity_threat_feeds_update_interval', 'daily' ), 'twicedaily' ); ?>>Twice Daily</option>
                                <option value="daily" <?php selected( get_option( 'saurity_threat_feeds_update_interval', 'daily' ), 'daily' ); ?>>Daily (Recommended)</option>
                            </select>
                            <p class="description">How often to check for feed updates</p>
                        </td>
                    </tr>
                    <tr>
                        <th>Auto-Block IPs</th>
                        <td>
                            <label>
                                <input type="checkbox" name="saurity_threat_feeds_auto_block" value="1" 
                                       <?php checked( get_option( 'saurity_threat_feeds_auto_block', true ) ); ?> />
                                Automatically add feed IPs to blocklist
                            </label>
                            <p class="description">
                                If disabled, feeds are imported but not enforced
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th>Max Age</th>
                        <td>
                            <input type="number" name="saurity_threat_feeds_max_age" 
                                   value="<?php echo esc_attr( get_option( 'saurity_threat_feeds_max_age', 30 ) ); ?>" 
                                   min="7" max="90" />
                            <p class="description">Remove IPs not updated in X days (default: 30)</p>
                        </td>
                    </tr>
                </table>

                <div style="background: #f0f0f0; padding: 15px; border-radius: 4px; display: flex; gap: 10px; align-items: center;">
                    <?php submit_button( 'Save Threat Intelligence Settings', 'primary', 'submit', false ); ?>
                    <?php if ( get_option( 'saurity_threat_feeds_enabled', false ) ) : ?>
                        <button type="button" id="saurity-start-feed-update" class="button button-secondary">
                            🔄 Start Update
                        </button>
                        <div id="saurity-feed-progress" style="display: none; flex: 1; margin-left: 15px;">
                            <div style="font-size: 13px; color: #666; margin-bottom: 5px;">
                                <strong>Progress:</strong> <span id="saurity-feed-current">Preparing...</span>
                            </div>
                            <div style="background: #e0e0e0; border-radius: 3px; overflow: hidden; height: 20px;">
                                <div id="saurity-feed-progress-bar" style="background: #2196F3; height: 100%; width: 0%; transition: width 0.3s;"></div>
                            </div>
                        </div>
                        <div id="saurity-feed-results" style="display: none;">
                            <!-- Results will be inserted here -->
                        </div>
                    <?php endif; ?>
                </div>

                <?php if ( get_option( 'saurity_threat_feeds_enabled', false ) ) : ?>
                    <script type="text/javascript">
                    jQuery(document).ready(function($) {
                        $('#saurity-start-feed-update').on('click', function() {
                            var $button = $(this);
                            var $progress = $('#saurity-feed-progress');
                            var $current = $('#saurity-feed-current');
                            var $progressBar = $('#saurity-feed-progress-bar');
                            var $results = $('#saurity-feed-results');
                            
                            // Get enabled feeds
                            var enabledFeeds = [];
                            $('input[name="saurity_threat_feeds_builtin[]"]:checked').each(function() {
                                enabledFeeds.push($(this).val());
                            });
                            
                            if (enabledFeeds.length === 0) {
                                alert('Please enable at least one threat feed before updating.');
                                return;
                            }
                            
                            // Disable button and show progress
                            $button.prop('disabled', true).text('⏳ Updating...');
                            $progress.show();
                            $results.empty().hide();
                            
                            var totalFeeds = enabledFeeds.length;
                            var currentFeed = 0;
                            var results = [];
                            
                            // Feed name mapping
                            var feedNames = {
                                'emerging_threats': 'Emerging Threats',
                                'spamhaus': 'Spamhaus DROP',
                                'blocklist_de': 'Blocklist.de'
                            };
                            
                            // Process feeds one by one
                            function processNextFeed() {
                                if (currentFeed >= enabledFeeds.length) {
                                    // All done
                                    $button.prop('disabled', false).text('🔄 Start Update');
                                    $progress.hide();
                                    $current.text('Preparing...');
                                    $progressBar.css('width', '0%');
                                    
                                    // Show results
                                    var html = '<div style="margin-top: 15px; padding: 15px; background: #f8f9fa; border-radius: 4px;">';
                                    html += '<h4 style="margin: 0 0 10px 0;">✅ Update Complete</h4>';
                                    html += '<ul style="margin: 0; font-size: 13px; line-height: 1.8;">';
                                    
                                    results.forEach(function(result) {
                                        var icon = result.success ? '✅' : '❌';
                                        var color = result.success ? '#28a745' : '#dc3232';
                                        html += '<li style="color: ' + color + ';">';
                                        html += icon + ' <strong>' + result.feed + ':</strong> ' + result.message;
                                        html += '</li>';
                                    });
                                    
                                    html += '</ul></div>';
                                    $results.html(html).show();
                                    
                                    // Reload the page after 3 seconds to refresh statistics
                                    setTimeout(function() {
                                        location.reload();
                                    }, 3000);
                                    
                                    return;
                                }
                                
                                var feedId = enabledFeeds[currentFeed];
                                var feedName = feedNames[feedId] || feedId;
                                
                                // Update progress
                                $current.text('Updating ' + feedName + '... (' + (currentFeed + 1) + '/' + totalFeeds + ')');
                                $progressBar.css('width', ((currentFeed / totalFeeds) * 100) + '%');
                                
                                // Make AJAX request
                                $.ajax({
                                    url: ajaxurl,
                                    type: 'POST',
                                    data: {
                                        action: 'saurity_update_feeds_ajax',
                                nonce: '<?php echo esc_js( wp_create_nonce( 'saurity_feeds_ajax' ) ); ?>',
                                        feed_id: feedId
                                    },
                                    success: function(response) {
                                        if (response.success) {
                                            results.push({
                                                success: true,
                                                feed: feedName,
                                                message: response.data.message + ' (' + response.data.total_ips + ' IPs)'
                                            });
                                        } else {
                                            results.push({
                                                success: false,
                                                feed: feedName,
                                                message: response.data.message || 'Unknown error'
                                            });
                                        }
                                    },
                                    error: function(xhr, status, error) {
                                        results.push({
                                            success: false,
                                            feed: feedName,
                                            message: 'Network error: ' + error
                                        });
                                    },
                                    complete: function() {
                                        currentFeed++;
                                        // Update progress bar to show completion
                                        $progressBar.css('width', ((currentFeed / totalFeeds) * 100) + '%');
                                        
                                        // Process next feed after a short delay
                                        setTimeout(processNextFeed, 500);
                                    }
                                });
                            }
                            
                            // Start processing
                            processNextFeed();
                        });
                    });
                    </script>
                <?php endif; ?>

                <?php if ( $cloud_integration && get_option( 'saurity_threat_feeds_enabled', false ) ) : ?>
                    <?php
                    $threat_intel = $cloud_integration->get_threat_intel();
                    if ( $threat_intel ) {
                        $ti_stats = $threat_intel->get_statistics();
                    ?>
                    <div style="margin-top: 15px; padding: 15px; background: #f8f9fa; border-radius: 4px;">
                        <h4 style="margin: 0 0 10px 0;">Feed Status</h4>
                        <p style="margin: 0; font-size: 13px;">
                            <strong>Total Feeds:</strong> <?php echo esc_html( $ti_stats['total_feeds'] ); ?> | 
                            <strong>Total IPs:</strong> <?php echo esc_html( $ti_stats['total_ips'] ); ?>
                        </p>
                        <?php if ( ! empty( $ti_stats['feeds'] ) ) : ?>
                            <ul style="margin: 10px 0 0 0; font-size: 12px;">
                                <?php foreach ( $ti_stats['feeds'] as $feed ) : ?>
                                    <li>
                                        <strong><?php echo esc_html( $feed['name'] ); ?>:</strong> 
                                        <?php echo esc_html( $feed['total_ips'] ); ?> IPs 
                                        (Updated: <?php echo esc_html( $feed['last_updated'] ); ?>)
                                    </li>
                                <?php endforeach; ?>
                            </ul>
                        <?php endif; ?>
                    </div>
                    <?php } ?>
                <?php endif; ?>
            </div>

            <!-- GeoIP Section -->
            <div style="background: #fff; padding: 20px; border: 1px solid #ddd; border-radius: 8px; border-left: 4px solid #4caf50; margin-bottom: 20px;">
                <h2 style="margin-top: 0; color: #4caf50;">🌍 Country-Based Blocking & Analytics</h2>
                <p style="color: #666; margin-bottom: 20px;">
                    Block or allow specific countries and visualize attacks geographically.
                </p>

                <table class="form-table">
                    <tr>
                        <th>
                            <span class="saurity-setting-label">
                                Enable GeoIP
                                <?php $this->render_info_icon( 'Enables country detection for all requests. Shows country flags in logs and allows geographic blocking. Uses MaxMind GeoLite2 (local) or IP-API.com (fallback).' ); ?>
                            </span>
                        </th>
                        <td>
                            <label>
                                <input type="checkbox" name="saurity_geoip_enabled" value="1" 
                                       <?php checked( get_option( 'saurity_geoip_enabled', false ) ); ?> />
                                <strong>Enable GeoIP Protection</strong>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th>Provider</th>
                        <td>
                            <select name="saurity_geoip_provider">
                                <option value="maxmind" <?php selected( get_option( 'saurity_geoip_provider', 'maxmind' ), 'maxmind' ); ?>>
                                    MaxMind GeoLite2 (Local, 95% accuracy)
                                </option>
                                <option value="ipapi" <?php selected( get_option( 'saurity_geoip_provider', 'maxmind' ), 'ipapi' ); ?>>
                                    IP-API.com (Free API, 90% accuracy)
                                </option>
                            </select>
                            <p class="description">
                                MaxMind requires free license key and database download
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th>MaxMind License Key</th>
                        <td>
                            <input type="text" name="saurity_geoip_license_key" 
                                   value="<?php echo esc_attr( get_option( 'saurity_geoip_license_key', '' ) ); ?>" 
                                   class="regular-text" 
                                   placeholder="Optional - for MaxMind provider" />
                            <p class="description">
                                Get free license at <a href="https://www.maxmind.com/en/geolite2/signup" target="_blank">MaxMind</a> 
                                (required for MaxMind provider only)
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th>Blocking Mode</th>
                        <td>
                            <label style="display: block; margin-bottom: 10px;">
                                <input type="radio" name="saurity_geoip_mode" value="blocklist" 
                                       <?php checked( get_option( 'saurity_geoip_mode', 'blocklist' ), 'blocklist' ); ?> />
                                Blocklist Mode (Block specific countries)
                            </label>
                            <label>
                                <input type="radio" name="saurity_geoip_mode" value="allowlist" 
                                       <?php checked( get_option( 'saurity_geoip_mode', 'blocklist' ), 'allowlist' ); ?> />
                                Allowlist Mode (Allow only specific countries)
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th>Country Selection</th>
                        <td>
                            <?php
                            $blocked_countries = get_option( 'saurity_geoip_blocked_countries', [] );
                            // Ensure $blocked_countries is always an array
                            if ( ! is_array( $blocked_countries ) ) {
                                $blocked_countries = [];
                            }
                            
                            // High-risk countries for quick selection
                            $high_risk_countries = [
                                'CN' => 'China',
                                'RU' => 'Russia',
                                'KP' => 'North Korea',
                                'IR' => 'Iran',
                            ];
                            
                            // Full country list
                            $all_countries = [
                                'AF' => 'Afghanistan', 'AL' => 'Albania', 'DZ' => 'Algeria', 'AS' => 'American Samoa',
                                'AD' => 'Andorra', 'AO' => 'Angola', 'AG' => 'Antigua and Barbuda', 'AR' => 'Argentina',
                                'AM' => 'Armenia', 'AW' => 'Aruba', 'AU' => 'Australia', 'AT' => 'Austria',
                                'AZ' => 'Azerbaijan', 'BS' => 'Bahamas', 'BH' => 'Bahrain', 'BD' => 'Bangladesh',
                                'BB' => 'Barbados', 'BY' => 'Belarus', 'BE' => 'Belgium', 'BZ' => 'Belize',
                                'BJ' => 'Benin', 'BM' => 'Bermuda', 'BT' => 'Bhutan', 'BO' => 'Bolivia',
                                'BA' => 'Bosnia and Herzegovina', 'BW' => 'Botswana', 'BR' => 'Brazil', 'BN' => 'Brunei',
                                'BG' => 'Bulgaria', 'BF' => 'Burkina Faso', 'BI' => 'Burundi', 'KH' => 'Cambodia',
                                'CM' => 'Cameroon', 'CA' => 'Canada', 'CV' => 'Cape Verde', 'KY' => 'Cayman Islands',
                                'CF' => 'Central African Republic', 'TD' => 'Chad', 'CL' => 'Chile', 'CN' => 'China',
                                'CO' => 'Colombia', 'KM' => 'Comoros', 'CG' => 'Congo', 'CD' => 'Congo (DRC)',
                                'CR' => 'Costa Rica', 'CI' => 'Côte d\'Ivoire', 'HR' => 'Croatia', 'CU' => 'Cuba',
                                'CY' => 'Cyprus', 'CZ' => 'Czech Republic', 'DK' => 'Denmark', 'DJ' => 'Djibouti',
                                'DM' => 'Dominica', 'DO' => 'Dominican Republic', 'EC' => 'Ecuador', 'EG' => 'Egypt',
                                'SV' => 'El Salvador', 'GQ' => 'Equatorial Guinea', 'ER' => 'Eritrea', 'EE' => 'Estonia',
                                'ET' => 'Ethiopia', 'FJ' => 'Fiji', 'FI' => 'Finland', 'FR' => 'France',
                                'GA' => 'Gabon', 'GM' => 'Gambia', 'GE' => 'Georgia', 'DE' => 'Germany',
                                'GH' => 'Ghana', 'GR' => 'Greece', 'GD' => 'Grenada', 'GT' => 'Guatemala',
                                'GN' => 'Guinea', 'GW' => 'Guinea-Bissau', 'GY' => 'Guyana', 'HT' => 'Haiti',
                                'HN' => 'Honduras', 'HK' => 'Hong Kong', 'HU' => 'Hungary', 'IS' => 'Iceland',
                                'IN' => 'India', 'ID' => 'Indonesia', 'IR' => 'Iran', 'IQ' => 'Iraq',
                                'IE' => 'Ireland', 'IL' => 'Israel', 'IT' => 'Italy', 'JM' => 'Jamaica',
                                'JP' => 'Japan', 'JO' => 'Jordan', 'KZ' => 'Kazakhstan', 'KE' => 'Kenya',
                                'KI' => 'Kiribati', 'KP' => 'North Korea', 'KR' => 'South Korea', 'KW' => 'Kuwait',
                                'KG' => 'Kyrgyzstan', 'LA' => 'Laos', 'LV' => 'Latvia', 'LB' => 'Lebanon',
                                'LS' => 'Lesotho', 'LR' => 'Liberia', 'LY' => 'Libya', 'LI' => 'Liechtenstein',
                                'LT' => 'Lithuania', 'LU' => 'Luxembourg', 'MK' => 'Macedonia', 'MG' => 'Madagascar',
                                'MW' => 'Malawi', 'MY' => 'Malaysia', 'MV' => 'Maldives', 'ML' => 'Mali',
                                'MT' => 'Malta', 'MH' => 'Marshall Islands', 'MR' => 'Mauritania', 'MU' => 'Mauritius',
                                'MX' => 'Mexico', 'FM' => 'Micronesia', 'MD' => 'Moldova', 'MC' => 'Monaco',
                                'MN' => 'Mongolia', 'ME' => 'Montenegro', 'MA' => 'Morocco', 'MZ' => 'Mozambique',
                                'MM' => 'Myanmar', 'NA' => 'Namibia', 'NR' => 'Nauru', 'NP' => 'Nepal',
                                'NL' => 'Netherlands', 'NZ' => 'New Zealand', 'NI' => 'Nicaragua', 'NE' => 'Niger',
                                'NG' => 'Nigeria', 'NO' => 'Norway', 'OM' => 'Oman', 'PK' => 'Pakistan',
                                'PW' => 'Palau', 'PS' => 'Palestine', 'PA' => 'Panama', 'PG' => 'Papua New Guinea',
                                'PY' => 'Paraguay', 'PE' => 'Peru', 'PH' => 'Philippines', 'PL' => 'Poland',
                                'PT' => 'Portugal', 'QA' => 'Qatar', 'RO' => 'Romania', 'RU' => 'Russia',
                                'RW' => 'Rwanda', 'KN' => 'Saint Kitts and Nevis', 'LC' => 'Saint Lucia',
                                'VC' => 'Saint Vincent', 'WS' => 'Samoa', 'SM' => 'San Marino', 'ST' => 'São Tomé',
                                'SA' => 'Saudi Arabia', 'SN' => 'Senegal', 'RS' => 'Serbia', 'SC' => 'Seychelles',
                                'SL' => 'Sierra Leone', 'SG' => 'Singapore', 'SK' => 'Slovakia', 'SI' => 'Slovenia',
                                'SB' => 'Solomon Islands', 'SO' => 'Somalia', 'ZA' => 'South Africa', 'SS' => 'South Sudan',
                                'ES' => 'Spain', 'LK' => 'Sri Lanka', 'SD' => 'Sudan', 'SR' => 'Suriname',
                                'SZ' => 'Swaziland', 'SE' => 'Sweden', 'CH' => 'Switzerland', 'SY' => 'Syria',
                                'TW' => 'Taiwan', 'TJ' => 'Tajikistan', 'TZ' => 'Tanzania', 'TH' => 'Thailand',
                                'TL' => 'Timor-Leste', 'TG' => 'Togo', 'TO' => 'Tonga', 'TT' => 'Trinidad and Tobago',
                                'TN' => 'Tunisia', 'TR' => 'Turkey', 'TM' => 'Turkmenistan', 'TV' => 'Tuvalu',
                                'UG' => 'Uganda', 'UA' => 'Ukraine', 'AE' => 'United Arab Emirates', 'GB' => 'United Kingdom',
                                'US' => 'United States', 'UY' => 'Uruguay', 'UZ' => 'Uzbekistan', 'VU' => 'Vanuatu',
                                'VA' => 'Vatican City', 'VE' => 'Venezuela', 'VN' => 'Vietnam', 'YE' => 'Yemen',
                                'ZM' => 'Zambia', 'ZW' => 'Zimbabwe',
                            ];
                            ?>
                            
                            <!-- Quick Select High-Risk -->
                            <div style="margin-bottom: 15px; padding: 10px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 4px;">
                                <strong style="display: block; margin-bottom: 8px;">⚠️ Quick Select High-Risk Countries:</strong>
                                <div style="display: flex; flex-wrap: wrap; gap: 10px;">
                                    <?php foreach ( $high_risk_countries as $code => $name ) : ?>
                                        <label style="display: inline-flex; align-items: center; gap: 5px; padding: 5px 10px; background: white; border: 1px solid #ddd; border-radius: 3px; cursor: pointer;">
                                            <input type="checkbox" name="saurity_geoip_blocked_countries[]" value="<?php echo esc_attr( $code ); ?>" 
                                                   <?php checked( in_array( $code, $blocked_countries, true ) ); ?> />
                                            <span><?php echo esc_html( $this->get_country_flag( $code ) . ' ' . $name ); ?></span>
                                        </label>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                            
                            <!-- Full Country Selector -->
                            <div style="margin-top: 15px;">
                                <strong style="display: block; margin-bottom: 8px;">🌍 All Countries (Select Multiple):</strong>
                                <select name="saurity_geoip_blocked_countries[]" multiple size="10" style="width: 100%; max-width: 600px;">
                                    <?php foreach ( $all_countries as $code => $name ) : ?>
                                        <option value="<?php echo esc_attr( $code ); ?>" <?php selected( in_array( $code, $blocked_countries, true ) ); ?>>
                                            <?php echo esc_html( $this->get_country_flag( $code ) . ' ' . $name ); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                                <p class="description" style="margin-top: 8px;">
                                    Hold Ctrl (Windows) or Cmd (Mac) to select multiple countries. Use blocklist mode to block selected countries, or allowlist mode to allow only selected countries.
                                </p>
                            </div>
                        </td>
                    </tr>
                    <tr>
                        <th>Display Options</th>
                        <td>
                            <label>
                                <input type="checkbox" name="saurity_geoip_show_flags" value="1" 
                                       <?php checked( get_option( 'saurity_geoip_show_flags', true ) ); ?> />
                                Show country flags in activity log
                            </label>
                        </td>
                    </tr>
                </table>

                <div style="background: #f0f0f0; padding: 15px; border-radius: 4px;">
                    <?php submit_button( 'Save GeoIP Settings', 'primary', 'submit', false ); ?>
                </div>

                <?php if ( $cloud_integration && get_option( 'saurity_geoip_enabled', false ) ) : ?>
                    <?php
                    $geoip = $cloud_integration->get_geoip();
                    if ( $geoip ) {
                        $geo_stats = $geoip->get_statistics( 7 );
                    ?>
                    <div style="margin-top: 15px; padding: 15px; background: #f8f9fa; border-radius: 4px;">
                        <h4 style="margin: 0 0 10px 0;">Geographic Statistics (Last 7 Days)</h4>
                        <p style="margin: 0; font-size: 13px;">
                            <strong>Total Attacks:</strong> <?php echo esc_html( $geo_stats['total_attacks'] ); ?> | 
                            <strong>Unique Countries:</strong> <?php echo esc_html( $geo_stats['unique_countries'] ); ?>
                        </p>
                        <?php if ( ! empty( $geo_stats['top_countries'] ) ) : ?>
                            <h5 style="margin: 15px 0 10px 0;">Top Attacking Countries:</h5>
                            <ul style="margin: 0; font-size: 12px;">
                                <?php foreach ( array_slice( $geo_stats['top_countries'], 0, 5 ) as $country ) : ?>
                                    <li>
                                        <?php echo esc_html( $country['flag'] ); ?> 
                                        <strong><?php echo esc_html( $country['name'] ); ?>:</strong> 
                                        <?php echo esc_html( $country['count'] ); ?> attacks
                                    </li>
                                <?php endforeach; ?>
                            </ul>
                        <?php endif; ?>
                    </div>
                    <?php } ?>
                <?php endif; ?>
            </div>

            <div style="margin-top: 20px; padding: 15px; background: #fff3cd; border-radius: 8px; border-left: 4px solid #ffc107;">
                <h4 style="margin: 0 0 10px 0;">💡 Setup Tips</h4>
                <ul style="margin: 0; padding-left: 20px; font-size: 13px; line-height: 1.8;">
                    <!-- <li><strong>Cloudflare:</strong> Best for sites already using Cloudflare. Blocks attacks at the edge before they hit your server.</li> -->
                    <li><strong>Threat Feeds:</strong> Provides proactive blocking based on global threat intelligence. Updates daily.</li>
                    <li><strong>GeoIP:</strong> Useful for sites that only serve specific regions. Shows where attacks originate.</li>
                    <li><strong>Performance:</strong> All features use aggressive caching to minimize overhead (&lt;10ms).</li>
                    <li><strong>Privacy:</strong> GeoIP MaxMind runs locally (no external calls). IP-API is used as fallback.</li>
                </ul>
            </div>
        </form>
        <?php
    }
}
