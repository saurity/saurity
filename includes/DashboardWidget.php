<?php
/**
 * Dashboard Widget
 *
 * @package Saurity
 */

namespace Saurity;
// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * DashboardWidget class - displays security overview on wp-admin dashboard
 */
class DashboardWidget {

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
        add_action( 'wp_dashboard_setup', [ $this, 'add_dashboard_widget' ] );
        add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_widget_styles' ] );
    }

    /**
     * Enqueue dashboard widget styles
     *
     * @param string $hook Current admin page hook.
     */
    public function enqueue_widget_styles( $hook ) {
        if ( 'index.php' !== $hook ) {
            return;
        }

        $css = '
            .saurity-widget { font-size: 13px; }
            .saurity-status { display: flex; align-items: flex-start; gap: 8px; padding: 10px 12px;
                border-radius: 4px; margin-bottom: 12px; font-size: 13px; }
            .saurity-status.active { background: #d4edda; color: #155724; }
            .saurity-status.inactive { background: #f8d7da; color: #721c24; }
            .saurity-stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; margin-bottom: 14px; }
            .saurity-stat { text-align: center; padding: 8px; border-radius: 6px; background: #f0f0f1; }
            .saurity-stat-value { display: block; font-size: 22px; font-weight: 700; color: #2196F3; }
            .saurity-stat-label { display: block; font-size: 11px; color: #666; margin-top: 2px; }
            .saurity-recent-log { padding: 6px 8px; border-left: 3px solid #ccc;
                margin-bottom: 4px; background: #f9f9f9; font-size: 12px; }
            .saurity-recent-log.info { border-left-color: #2196F3; }
            .saurity-recent-log.warning { border-left-color: #ff9800; }
            .saurity-recent-log.error { border-left-color: #f44336; }
            .saurity-recent-log.critical { border-left-color: #9c27b0; }
            .saurity-log-time { font-size: 11px; color: #999; margin-top: 2px; }
            .saurity-widget-footer { margin-top: 12px; }
        ';

        wp_register_style( 'saurity-widget', false, [], SAURITY_VERSION );
        wp_enqueue_style( 'saurity-widget' );
        wp_add_inline_style( 'saurity-widget', $css );
    }

    /**
     * Add dashboard widget
     */
    public function add_dashboard_widget() {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        wp_add_dashboard_widget(
            'saurity_security_widget',
            '🛡️ Saurity Shield Status',
            [ $this, 'render_widget' ]
        );
    }

    /**
     * Render dashboard widget
     */
    public function render_widget() {
        $kill_switch_active = $this->kill_switch->is_active();
        $recent_logs = $this->logger->get_logs( 5 );
        $log_counts = $this->logger->get_log_counts();
        
        // Get statistics
        $stats = $this->get_statistics();

        ?>
        <div class="saurity-widget">
            <!-- Status Banner -->
            <div class="saurity-status <?php echo $kill_switch_active ? 'inactive' : 'active'; ?>">
                <?php if ( $kill_switch_active ) : ?>
                    <strong>⚠️ Protection Disabled</strong>
                    <p style="margin: 5px 0 0 0; opacity: 0.9;">Kill switch is active - all security enforcement is disabled.</p>
                <?php else : ?>
                    <strong>✓ Protection Active</strong>
                    <p style="margin: 5px 0 0 0; opacity: 0.9;">Your site is being monitored and protected.</p>
                <?php endif; ?>
            </div>

            <!-- Statistics -->
            <div class="saurity-stats">
                <div class="saurity-stat">
                    <span class="saurity-stat-value"><?php echo esc_html( $log_counts['all'] ); ?></span>
                    <span class="saurity-stat-label">Total Events</span>
                </div>
                <div class="saurity-stat">
                    <span class="saurity-stat-value" style="color: #ff9800;">
                        <?php echo esc_html( $log_counts['warning'] ); ?>
                    </span>
                    <span class="saurity-stat-label">Warnings</span>
                </div>
                <div class="saurity-stat">
                    <span class="saurity-stat-value" style="color: #dc3232;">
                        <?php echo esc_html( $log_counts['critical'] + $log_counts['error'] ); ?>
                    </span>
                    <span class="saurity-stat-label">Critical/Errors</span>
                </div>
            </div>

            <!-- 24 Hour Stats -->
            <div style="margin-bottom: 15px;">
                <strong>Last 24 Hours:</strong>
                <ul style="margin: 8px 0; padding-left: 20px; font-size: 13px;">
                    <li>Failed Logins: <strong><?php echo esc_html( $stats['failed_logins'] ); ?></strong></li>
                    <li>Successful Logins: <strong><?php echo esc_html( $stats['successful_logins'] ); ?></strong></li>
                    <li>Blocked IPs: <strong><?php echo esc_html( $stats['blocked_ips'] ); ?></strong></li>
                </ul>
            </div>

            <!-- Recent Activity -->
            <div>
                <strong>Recent Activity:</strong>
                <?php if ( empty( $recent_logs ) ) : ?>
                    <p style="color: #666; font-size: 12px; margin-top: 8px;">No recent activity.</p>
                <?php else : ?>
                    <div style="margin-top: 8px;">
                        <?php foreach ( $recent_logs as $log ) : ?>
                            <div class="saurity-recent-log <?php echo esc_attr( $log['event_type'] ); ?>">
                                <div><?php echo esc_html( $log['message'] ); ?></div>
                                <div class="saurity-log-time"><?php echo esc_html( $log['created_at'] ); ?></div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>

            <!-- Footer -->
            <div class="saurity-widget-footer">
                <a href="<?php echo esc_url( admin_url( 'admin.php?page=saurity' ) ); ?>" class="button button-primary">
                    View Full Activity Log
                </a>
            </div>
        </div>
        <?php
    }

    /**
     * Get statistics for last 24 hours
     *
     * @return array
     */
    private function get_statistics() {
        global $wpdb;

        $table_name = $wpdb->prefix . 'saurity_logs';
        $since = gmdate( 'Y-m-d H:i:s', strtotime( '-24 hours' ) );

        $stats = [
            'failed_logins' => 0,
            'successful_logins' => 0,
            'blocked_ips' => 0,
        ];

        // Failed logins
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Direct DB required for statistics
        $stats['failed_logins'] = (int) $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$wpdb->prefix}saurity_logs 
                WHERE created_at >= %s 
                AND message LIKE %s",
                $since,
                '%Failed login%'
            )
        );

        // Successful logins
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Direct DB required for statistics
        $stats['successful_logins'] = (int) $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$wpdb->prefix}saurity_logs 
                WHERE created_at >= %s 
                AND message LIKE %s",
                $since,
                '%logged in successfully%'
            )
        );

        // Blocked IPs
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Direct DB required for statistics
        $stats['blocked_ips'] = (int) $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$wpdb->prefix}saurity_logs 
                WHERE created_at >= %s 
                AND message LIKE %s",
                $since,
                '%hard blocked%'
            )
        );

        return $stats;
    }
}