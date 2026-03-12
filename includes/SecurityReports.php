<?php
/**
 * Security Reports
 *
 * @package Saurity
 */

namespace Saurity;

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * SecurityReports class - generates and manages weekly security reports
 */
class SecurityReports {

    /**
     * Logger instance
     *
     * @var ActivityLogger
     */
    private $logger;

    /**
     * Constructor
     *
     * @param ActivityLogger $logger Logger instance.
     */
    public function __construct( ActivityLogger $logger ) {
        $this->logger = $logger;
    }

    /**
     * Hook into WordPress
     */
    public function hook() {
        // Add custom cron schedule for weekly reports
        add_filter( 'cron_schedules', [ $this, 'add_weekly_cron_schedule' ] );
        
        // Schedule weekly report generation
        add_action( 'saurity_generate_weekly_report', [ $this, 'generate_weekly_report' ] );
        
        // Initialize weekly cron if not scheduled
        if ( ! wp_next_scheduled( 'saurity_generate_weekly_report' ) ) {
            wp_schedule_event( time(), 'weekly', 'saurity_generate_weekly_report' );
        }
        
        // Schedule cleanup of old reports
        add_action( 'saurity_cleanup_old_reports', [ $this, 'cleanup_old_reports' ] );
        
        if ( ! wp_next_scheduled( 'saurity_cleanup_old_reports' ) ) {
            wp_schedule_event( time(), 'daily', 'saurity_cleanup_old_reports' );
        }
    }

    /**
     * Add weekly cron schedule
     *
     * @param array $schedules Existing schedules.
     * @return array Modified schedules.
     */
    public function add_weekly_cron_schedule( $schedules ) {
        if ( ! isset( $schedules['weekly'] ) ) {
            $schedules['weekly'] = [
                'interval' => 604800, // 7 days in seconds
                'display'  => __( 'Once Weekly', 'saurity-shield' ),
            ];
        }
        return $schedules;
    }

    /**
     * Generate weekly security report
     *
     * @param string $start_date Optional start date (Y-m-d format).
     * @param string $end_date Optional end date (Y-m-d format).
     * @return int|false Report ID on success, false on failure.
     */
    public function generate_weekly_report( $start_date = null, $end_date = null ) {
        global $wpdb;

        // Default to last 7 days if no dates provided
        if ( null === $start_date || null === $end_date ) {
            $end_date = current_time( 'Y-m-d' );
            $start_date = gmdate( 'Y-m-d', strtotime( '-7 days', strtotime( $end_date ) ) );
        }

        $start_datetime = $start_date . ' 00:00:00';
        $end_datetime = $end_date . ' 23:59:59';

        // Generate report data
        $report_data = $this->collect_report_data( $start_datetime, $end_datetime );

        // Calculate security score
        $security_score = $this->calculate_security_score( $report_data );

        // Store report in database
        $table_name = $wpdb->prefix . 'saurity_reports';
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Direct DB required for report storage
        $result = $wpdb->insert(
            $table_name,
            [
                'report_type' => 'weekly',
                'start_date' => $start_datetime,
                'end_date' => $end_datetime,
                'report_data' => wp_json_encode( $report_data ),
                'security_score' => $security_score,
                'created_at' => current_time( 'mysql' ),
            ],
            [ '%s', '%s', '%s', '%s', '%d', '%s' ]
        );

        if ( $result ) {
            $report_id = $wpdb->insert_id;
            
            // Log report generation
            $this->logger->log( 'info', sprintf(
                'Weekly security report generated (ID: %d) for period %s to %s',
                $report_id,
                $start_date,
                $end_date
            ) );

            // Send email notification if enabled
            if ( get_option( 'saurity_email_reports', false ) ) {
                $this->send_report_email( $report_id, $report_data, $security_score );
            }

            return $report_id;
        }

        return false;
    }

    /**
     * Collect report data for the specified period
     *
     * @param string $start_datetime Start datetime.
     * @param string $end_datetime End datetime.
     * @return array Report data.
     */
    /**
     * Collect report data (Fix for missing metrics)
     */
    /**
     * Collect report data (Fixed & Optimized)
     *
     * @param string $start_datetime Start datetime.
     * @param string $end_datetime End datetime.
     * @return array Report data.
     */
    private function collect_report_data( $start_datetime, $end_datetime ) {
        global $wpdb;

        // Use LIKE patterns with proper preparation - static patterns don't need esc_like
        $like_failed_login = '%Failed login%';
        $like_successful_login = '%Successful login%';
        $like_logged_in = '%logged in successfully%';
        $like_hard_blocked = '%hard blocked%';
        $like_perm_blocked = '%permanently blocked%';
        $like_rate_limited = '%rate limited%';
        $like_rate_limit = '%Rate limit%';
        $like_sql_injection = '%SQL injection%';
        $like_xss = '%XSS%';
        $like_xmlrpc = '%XML-RPC%';
        $like_post_flood = '%POST flood%';
        $like_sensitive_path = '%sensitive path%';
        $like_malicious_user = '%Malicious user%';
        $like_bad_bot = '%Bad bot%';
        $like_cloudflare = '%Cloudflare%';
        $like_cf_firewall = '%Cloudflare firewall%';
        $like_cf_push = '%Cloudflare push%';
        $like_cf_sync = '%Cloudflare sync%';
        $like_syncing_cf = '%Syncing with Cloudflare%';
        $like_threat_feed = '%threat feed%';
        $like_threat_intel = '%threat intelligence%';
        $like_updating_feed = '%Updating threat feed%';
        $like_geoip = '%GeoIP%';
        $like_maxmind = '%MaxMind%';
        $like_ipapi = '%IP-API%';
        $like_geoip_updated = '%GeoIP database updated%';

        // 1. Single Pass Aggregation Query
        // Instead of running 14 separate queries, we count everything in one go.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Direct DB required for reports
        $stats = $wpdb->get_row( $wpdb->prepare( "
            SELECT 
                COUNT(*) as total,
                
                -- Summary Metrics (Fixed patterns to match actual log messages)
                SUM(CASE WHEN message LIKE %s THEN 1 ELSE 0 END) as failed_logins,
                SUM(CASE WHEN message LIKE %s OR message LIKE %s THEN 1 ELSE 0 END) as successful_logins,
                SUM(CASE WHEN message LIKE %s OR message LIKE %s THEN 1 ELSE 0 END) as blocked_ips,
                SUM(CASE WHEN message LIKE %s OR message LIKE %s THEN 1 ELSE 0 END) as rate_limited,
                
                -- Firewall / Attack Vector Metrics
                SUM(CASE WHEN message LIKE %s THEN 1 ELSE 0 END) as sql_injection,
                SUM(CASE WHEN message LIKE %s THEN 1 ELSE 0 END) as xss,
                SUM(CASE WHEN message LIKE %s THEN 1 ELSE 0 END) as xmlrpc,
                SUM(CASE WHEN message LIKE %s THEN 1 ELSE 0 END) as post_flood,
                SUM(CASE WHEN message LIKE %s THEN 1 ELSE 0 END) as sensitive_paths,
                SUM(CASE WHEN message LIKE %s OR message LIKE %s THEN 1 ELSE 0 END) as bad_bots,
                
                -- Cloud Services Metrics (extracted from logs)
                SUM(CASE WHEN message LIKE %s THEN 1 ELSE 0 END) as cloudflare_events,
                SUM(CASE WHEN message LIKE %s OR message LIKE %s THEN 1 ELSE 0 END) as cloudflare_blocks,
                SUM(CASE WHEN message LIKE %s OR message LIKE %s THEN 1 ELSE 0 END) as cloudflare_syncs,
                SUM(CASE WHEN message LIKE %s OR message LIKE %s THEN 1 ELSE 0 END) as threat_feed_events,
                SUM(CASE WHEN message LIKE %s THEN 1 ELSE 0 END) as threat_feed_updates,
                SUM(CASE WHEN message LIKE %s OR message LIKE %s OR message LIKE %s THEN 1 ELSE 0 END) as geoip_events,
                SUM(CASE WHEN message LIKE %s THEN 1 ELSE 0 END) as geoip_updates,
                
                -- Severity Counts
                SUM(CASE WHEN event_type = 'critical' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN event_type = 'error' THEN 1 ELSE 0 END) as error,
                SUM(CASE WHEN event_type = 'warning' THEN 1 ELSE 0 END) as warning

            FROM {$wpdb->prefix}saurity_logs 
            WHERE created_at BETWEEN %s AND %s
        ",
            // Summary placeholders
            $like_failed_login,
            $like_successful_login, $like_logged_in,
            $like_hard_blocked, $like_perm_blocked,
            $like_rate_limited, $like_rate_limit,
            // Attack vector placeholders
            $like_sql_injection,
            $like_xss,
            $like_xmlrpc,
            $like_post_flood,
            $like_sensitive_path,
            $like_malicious_user, $like_bad_bot,
            // Cloud services placeholders
            $like_cloudflare,
            $like_cf_firewall, $like_cf_push,
            $like_cf_sync, $like_syncing_cf,
            $like_threat_feed, $like_threat_intel,
            $like_updating_feed,
            $like_geoip, $like_maxmind, $like_ipapi,
            $like_geoip_updated,
            // Date range
            $start_datetime, $end_datetime
        ), ARRAY_A );

        // Calculate total firewall blocks (sum of specific vectors + generic blocks)
        $firewall_blocks = (int)$stats['sql_injection'] + (int)$stats['xss'] + (int)$stats['xmlrpc'] + 
                           (int)$stats['post_flood'] + (int)$stats['sensitive_paths'] + (int)$stats['bad_bots'];

        // 2. Top Attackers (Requires separate query for grouping)
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Direct DB required for reports
        $top_attackers = $wpdb->get_results( $wpdb->prepare(
            "SELECT ip_address, COUNT(*) as count 
             FROM {$wpdb->prefix}saurity_logs 
             WHERE created_at BETWEEN %s AND %s 
             AND event_type IN ('warning', 'error', 'critical')
             AND ip_address IS NOT NULL
             GROUP BY ip_address 
             ORDER BY count DESC 
             LIMIT 10",
            $start_datetime,
            $end_datetime
        ), ARRAY_A );

        // 3. Top Users (Requires separate query)
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Direct DB required for reports
        $top_users = $wpdb->get_results( $wpdb->prepare(
            "SELECT user_login, COUNT(*) as count 
             FROM {$wpdb->prefix}saurity_logs 
             WHERE created_at BETWEEN %s AND %s 
             AND user_login IS NOT NULL AND user_login != ''
             GROUP BY user_login 
             ORDER BY count DESC 
             LIMIT 10",
            $start_datetime,
            $end_datetime
        ), ARRAY_A );

        // 4. Daily Stats (Requires separate query)
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Direct DB required for reports
        $daily_stats = $wpdb->get_results( $wpdb->prepare(
            "SELECT DATE(created_at) as date, 
            COUNT(*) as total,
            SUM(CASE WHEN event_type = 'warning' THEN 1 ELSE 0 END) as warnings,
            SUM(CASE WHEN event_type = 'error' THEN 1 ELSE 0 END) as errors,
            SUM(CASE WHEN event_type = 'critical' THEN 1 ELSE 0 END) as critical
            FROM {$wpdb->prefix}saurity_logs 
            WHERE created_at BETWEEN %s AND %s 
            GROUP BY DATE(created_at)
            ORDER BY date ASC",
            $start_datetime,
            $end_datetime
        ), ARRAY_A );

        // Collect Cloud Services data (with proper error handling)
        $cloud_services = $this->collect_cloud_services_data( $start_datetime, $end_datetime );

        // Return formatted data structure
        return [
            'period' => [
                'start' => $start_datetime,
                'end' => $end_datetime,
            ],
            'summary' => [
                'total_events'      => (int)$stats['total'],
                'failed_logins'     => (int)$stats['failed_logins'],
                'successful_logins' => (int)$stats['successful_logins'],
                'blocked_ips'       => (int)$stats['blocked_ips'],
                'rate_limited'      => (int)$stats['rate_limited'],
                'firewall_blocks'   => $firewall_blocks,
                // Ensure permanent_blocks exists for dashboard compatibility
                'permanent_blocks'  => (int)$stats['blocked_ips'], 
            ],
            'attack_vectors' => [
                'sql_injection'   => (int)$stats['sql_injection'],
                'xss'             => (int)$stats['xss'],
                'xmlrpc_abuse'    => (int)$stats['xmlrpc'],
                'post_flood'      => (int)$stats['post_flood'],
                'sensitive_paths' => (int)$stats['sensitive_paths'],
                'bad_bots'        => (int)$stats['bad_bots'],
            ],
            'event_counts' => [
                'info'     => (int)($stats['total'] - $stats['warning'] - $stats['error'] - $stats['critical']),
                'warning'  => (int)$stats['warning'],
                'error'    => (int)$stats['error'],
                'critical' => (int)$stats['critical'],
            ],
            'top_attackers' => $top_attackers,
            'top_users'     => $top_users,
            'daily_stats'   => $daily_stats,
            'cloud_services' => $cloud_services,
        ];
    }

    /**
     * Collect Cloud Services data for the report
     * Combines live statistics with log-based event counts
     * Handles cases where features are disabled gracefully
     *
     * @param string $start_datetime Start datetime.
     * @param string $end_datetime End datetime.
     * @return array Cloud services data.
     */
    private function collect_cloud_services_data( $start_datetime, $end_datetime ) {
        global $wpdb;

        // Define LIKE patterns as variables for placeholders
        $like_cloudflare = '%Cloudflare%';
        $like_added_cf = '%added to Cloudflare firewall%';
        $like_cf_push = '%Cloudflare push%';
        $like_cf_sync = '%Cloudflare sync%';
        $like_syncing_cf = '%Syncing with Cloudflare%';
        $like_cf_api = '%Cloudflare API%';
        $like_threat_feed = '%threat feed%';
        $like_threat_intel = '%threat intelligence%';
        $like_updating_feed = '%Updating threat feed%';
        $like_geoip = '%GeoIP%';
        $like_maxmind = '%MaxMind%';
        $like_ipapi = '%IP-API%';
        $like_geoip_updated = '%GeoIP database updated%';
        $like_access_denied = '%Access denied from your country%';

        // Get log-based statistics for the period
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Direct DB required for reports
        $log_stats = $wpdb->get_row( $wpdb->prepare( "
            SELECT 
                -- Cloudflare log events
                SUM(CASE WHEN message LIKE %s THEN 1 ELSE 0 END) as cloudflare_events,
                SUM(CASE WHEN message LIKE %s OR message LIKE %s THEN 1 ELSE 0 END) as cloudflare_blocks,
                SUM(CASE WHEN message LIKE %s OR message LIKE %s THEN 1 ELSE 0 END) as cloudflare_syncs,
                SUM(CASE WHEN message LIKE %s AND event_type = 'error' THEN 1 ELSE 0 END) as cloudflare_errors,
                
                -- Threat Intelligence log events
                SUM(CASE WHEN message LIKE %s OR message LIKE %s THEN 1 ELSE 0 END) as threat_feed_events,
                SUM(CASE WHEN message LIKE %s THEN 1 ELSE 0 END) as threat_feed_updates,
                SUM(CASE WHEN message LIKE %s AND event_type = 'error' THEN 1 ELSE 0 END) as threat_feed_errors,
                
                -- GeoIP log events  
                SUM(CASE WHEN message LIKE %s OR message LIKE %s OR message LIKE %s THEN 1 ELSE 0 END) as geoip_events,
                SUM(CASE WHEN message LIKE %s THEN 1 ELSE 0 END) as geoip_updates,
                SUM(CASE WHEN (message LIKE %s OR message LIKE %s) AND event_type = 'error' THEN 1 ELSE 0 END) as geoip_errors,
                
                -- Country-based blocks (directly from Firewall block messages)
                SUM(CASE WHEN message LIKE %s THEN 1 ELSE 0 END) as geo_blocks
                
            FROM {$wpdb->prefix}saurity_logs 
            WHERE created_at BETWEEN %s AND %s
        ",
            // Cloudflare placeholders
            $like_cloudflare,
            $like_added_cf, $like_cf_push,
            $like_cf_sync, $like_syncing_cf,
            $like_cf_api,
            // Threat feed placeholders
            $like_threat_feed, $like_threat_intel,
            $like_updating_feed,
            $like_threat_feed,
            // GeoIP placeholders
            $like_geoip, $like_maxmind, $like_ipapi,
            $like_geoip_updated,
            $like_maxmind, $like_ipapi,
            // Geo blocks placeholder
            $like_access_denied,
            // Date range
            $start_datetime, $end_datetime
        ), ARRAY_A );

        $data = [
            'cloudflare' => [
                'enabled' => false,
                'blocked_ips' => 0,
                'events_imported' => 0,
                'last_sync' => 'Never',
                'log_events' => (int)($log_stats['cloudflare_events'] ?? 0),
                'log_blocks' => (int)($log_stats['cloudflare_blocks'] ?? 0),
                'log_syncs' => (int)($log_stats['cloudflare_syncs'] ?? 0),
                'log_errors' => (int)($log_stats['cloudflare_errors'] ?? 0),
            ],
            'threat_feeds' => [
                'enabled' => false,
                'total_feeds' => 0,
                'total_ips' => 0,
                'feeds' => [],
                'log_events' => (int)($log_stats['threat_feed_events'] ?? 0),
                'log_updates' => (int)($log_stats['threat_feed_updates'] ?? 0),
                'log_errors' => (int)($log_stats['threat_feed_errors'] ?? 0),
            ],
            'geoip' => [
                'enabled' => false,
                'blocked_countries' => [],
                'top_countries' => [],
                'total_blocks' => 0,
                'log_events' => (int)($log_stats['geoip_events'] ?? 0),
                'log_updates' => (int)($log_stats['geoip_updates'] ?? 0),
                'log_errors' => (int)($log_stats['geoip_errors'] ?? 0),
                'geo_blocks' => (int)($log_stats['geo_blocks'] ?? 0),
            ],
        ];

        try {
            $plugin = \Saurity\Plugin::get_instance();
            $cloud_integration = $plugin->get_component( 'cloud_integration' );

            // Cloudflare Integration (live stats + log stats)
            if ( get_option( 'saurity_cloudflare_enabled', false ) ) {
                $data['cloudflare']['enabled'] = true;
                
                if ( $cloud_integration ) {
                    $cloudflare = $cloud_integration->get_cloudflare();
                    if ( $cloudflare ) {
                        try {
                            $cf_stats = $cloudflare->get_statistics();
                            $data['cloudflare']['blocked_ips'] = $cf_stats['blocked_ips'] ?? 0;
                            $data['cloudflare']['events_imported'] = $cf_stats['events_24h'] ?? 0;
                            $data['cloudflare']['last_sync'] = $cf_stats['last_sync'] ?? 'Never';
                        } catch ( \Exception $e ) {
                            // Silently handle errors - log stats still available
                        }
                    }
                }
            }

            // Threat Intelligence Feeds (live stats + log stats)
            if ( get_option( 'saurity_threat_feeds_enabled', false ) ) {
                $data['threat_feeds']['enabled'] = true;
                
                if ( $cloud_integration ) {
                    $threat_intel = $cloud_integration->get_threat_intel();
                    if ( $threat_intel ) {
                        try {
                            $ti_stats = $threat_intel->get_statistics();
                            $data['threat_feeds']['total_feeds'] = $ti_stats['total_feeds'] ?? 0;
                            $data['threat_feeds']['total_ips'] = $ti_stats['total_ips'] ?? 0;
                            $data['threat_feeds']['feeds'] = $ti_stats['feeds'] ?? [];
                        } catch ( \Exception $e ) {
                            // Silently handle errors - log stats still available
                        }
                    }
                }
            }

            // GeoIP / Country Blocking (live stats + log stats)
            if ( get_option( 'saurity_geoip_enabled', false ) ) {
                $data['geoip']['enabled'] = true;
                $data['geoip']['mode'] = get_option( 'saurity_geoip_mode', 'blocklist' );
                
                $blocked_countries = get_option( 'saurity_geoip_blocked_countries', [] );
                if ( is_array( $blocked_countries ) ) {
                    $data['geoip']['blocked_countries'] = $blocked_countries;
                    $data['geoip']['blocked_count'] = count( $blocked_countries );
                }
                
                if ( $cloud_integration ) {
                    $geoip = $cloud_integration->get_geoip();
                    if ( $geoip ) {
                        try {
                            $geo_stats = $geoip->get_statistics( 7 );
                            $data['geoip']['total_blocks'] = $geo_stats['total_attacks'] ?? 0;
                            $data['geoip']['unique_countries'] = $geo_stats['unique_countries'] ?? 0;
                            $data['geoip']['top_countries'] = array_slice( $geo_stats['top_countries'] ?? [], 0, 5 );
                        } catch ( \Exception $e ) {
                            // Silently handle errors - log stats still available
                        }
                    }
                }
            }

        } catch ( \Exception $e ) {
            // If anything fails, log stats are still available
        }

        return $data;
    }
    /**
     * Calculate security score based on report data
     *
     * @param array $data Report data.
     * @return int Security score (0-100).
     */
    private function calculate_security_score( $data ) {
        $score = 100;

        // Deduct points for security incidents
        $score -= min( 20, $data['summary']['failed_logins'] * 0.5 );
        $score -= min( 20, $data['summary']['blocked_ips'] * 2 );
        $score -= min( 20, $data['summary']['firewall_blocks'] * 1 );
        $score -= min( 10, $data['event_counts']['critical'] * 5 );
        $score -= min( 10, $data['event_counts']['error'] * 2 );

        return max( 0, (int) $score );
    }

    /**
     * Send report via email
     *
     * @param int   $report_id Report ID.
     * @param array $data Report data.
     * @param int   $score Security score.
     */
    private function send_report_email( $report_id, $data, $score ) {
        $admin_email = get_option( 'admin_email' );
        $site_name = get_bloginfo( 'name' );

        $subject = sprintf( '[%s] Weekly Security Report - Score: %d/100', $site_name, $score );

        $message = $this->generate_email_body( $data, $score );

        $headers = [ 'Content-Type: text/html; charset=UTF-8' ];

        wp_mail( $admin_email, $subject, $message, $headers );
    }

    /**
     * Generate email body
     *
     * @param array $data Report data.
     * @param int   $score Security score.
     * @return string Email HTML.
     */
    private function generate_email_body( $data, $score ) {
        $start_date = gmdate( 'M d, Y', strtotime( $data['period']['start'] ) );
        $end_date = gmdate( 'M d, Y', strtotime( $data['period']['end'] ) );

        $score_color = $score >= 80 ? '#46b450' : ( $score >= 60 ? '#ff9800' : '#dc3232' );

        ob_start();
        ?>
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h1 style="color: #2196F3;">🛡️ Weekly Security Report</h1>
                <p><strong>Period:</strong> <?php echo esc_html( $start_date ); ?> - <?php echo esc_html( $end_date ); ?></p>
                
                <div style="background: <?php echo esc_attr( $score_color ); ?>; color: white; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
                    <h2 style="margin: 0; font-size: 48px;"><?php echo esc_html( $score ); ?>/100</h2>
                    <p style="margin: 10px 0 0 0;">Security Score</p>
                </div>

                <h2>Summary</h2>
                <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
                    <tr style="background: #f5f5f5;">
                        <td style="padding: 10px; border: 1px solid #ddd;">Total Events</td>
                        <td style="padding: 10px; border: 1px solid #ddd;"><strong><?php echo esc_html( $data['summary']['total_events'] ); ?></strong></td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; border: 1px solid #ddd;">Failed Login Attempts</td>
                        <td style="padding: 10px; border: 1px solid #ddd;"><strong><?php echo esc_html( $data['summary']['failed_logins'] ); ?></strong></td>
                    </tr>
                    <tr style="background: #f5f5f5;">
                        <td style="padding: 10px; border: 1px solid #ddd;">Successful Logins</td>
                        <td style="padding: 10px; border: 1px solid #ddd;"><strong><?php echo esc_html( $data['summary']['successful_logins'] ); ?></strong></td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; border: 1px solid #ddd;">Hard Blocked IPs (RateLimiter)</td>
                        <td style="padding: 10px; border: 1px solid #ddd;"><strong><?php echo esc_html( $data['summary']['blocked_ips'] ); ?></strong></td>
                    </tr>
                    <tr style="background: #f5f5f5;">
                        <td style="padding: 10px; border: 1px solid #ddd;">Permanent Blocks (IPManager)</td>
                        <td style="padding: 10px; border: 1px solid #ddd;"><strong><?php echo esc_html( $data['summary']['permanent_blocks'] ); ?></strong></td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; border: 1px solid #ddd;">Rate Limited Requests</td>
                        <td style="padding: 10px; border: 1px solid #ddd;"><strong><?php echo esc_html( $data['summary']['rate_limited'] ); ?></strong></td>
                    </tr>
                    <tr style="background: #f5f5f5;">
                        <td style="padding: 10px; border: 1px solid #ddd;">Total Firewall Blocks</td>
                        <td style="padding: 10px; border: 1px solid #ddd;"><strong><?php echo esc_html( $data['summary']['firewall_blocks'] ); ?></strong></td>
                    </tr>
                </table>

                <h2>Attack Vector Matrix</h2>
                <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
                    <thead>
                        <tr style="background: #2196F3; color: white;">
                            <th style="padding: 10px; border: 1px solid #1976D2; text-align: left;">Attack Type</th>
                            <th style="padding: 10px; border: 1px solid #1976D2; text-align: center;">Count</th>
                            <th style="padding: 10px; border: 1px solid #1976D2; text-align: center;">Severity</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr style="background: <?php echo $data['attack_vectors']['sql_injection'] > 0 ? '#ffebee' : '#f5f5f5'; ?>;">
                            <td style="padding: 10px; border: 1px solid #ddd;">SQL Injection</td>
                            <td style="padding: 10px; border: 1px solid #ddd; text-align: center;"><strong><?php echo esc_html( $data['attack_vectors']['sql_injection'] ); ?></strong></td>
                            <td style="padding: 10px; border: 1px solid #ddd; text-align: center; color: #dc3232;"><strong>HIGH</strong></td>
                        </tr>
                        <tr style="background: <?php echo $data['attack_vectors']['xss'] > 0 ? '#fff3e0' : 'white'; ?>;">
                            <td style="padding: 10px; border: 1px solid #ddd;">XSS Attempts</td>
                            <td style="padding: 10px; border: 1px solid #ddd; text-align: center;"><strong><?php echo esc_html( $data['attack_vectors']['xss'] ); ?></strong></td>
                            <td style="padding: 10px; border: 1px solid #ddd; text-align: center; color: #ff9800;"><strong>MEDIUM</strong></td>
                        </tr>
                        <tr style="background: <?php echo $data['attack_vectors']['xmlrpc_abuse'] > 0 ? '#ffebee' : '#f5f5f5'; ?>;">
                            <td style="padding: 10px; border: 1px solid #ddd;">XML-RPC Abuse</td>
                            <td style="padding: 10px; border: 1px solid #ddd; text-align: center;"><strong><?php echo esc_html( $data['attack_vectors']['xmlrpc_abuse'] ); ?></strong></td>
                            <td style="padding: 10px; border: 1px solid #ddd; text-align: center; color: #dc3232;"><strong>HIGH</strong></td>
                        </tr>
                        <tr style="background: <?php echo $data['attack_vectors']['post_flood'] > 0 ? '#fff3e0' : 'white'; ?>;">
                            <td style="padding: 10px; border: 1px solid #ddd;">POST Flood</td>
                            <td style="padding: 10px; border: 1px solid #ddd; text-align: center;"><strong><?php echo esc_html( $data['attack_vectors']['post_flood'] ); ?></strong></td>
                            <td style="padding: 10px; border: 1px solid #ddd; text-align: center; color: #ff9800;"><strong>MEDIUM</strong></td>
                        </tr>
                        <tr style="background: <?php echo $data['attack_vectors']['sensitive_paths'] > 0 ? '#ffebee' : '#f5f5f5'; ?>;">
                            <td style="padding: 10px; border: 1px solid #ddd;">Sensitive Path Access</td>
                            <td style="padding: 10px; border: 1px solid #ddd; text-align: center;"><strong><?php echo esc_html( $data['attack_vectors']['sensitive_paths'] ); ?></strong></td>
                            <td style="padding: 10px; border: 1px solid #ddd; text-align: center; color: #dc3232;"><strong>HIGH</strong></td>
                        </tr>
                        <tr style="background: <?php echo $data['attack_vectors']['bad_bots'] > 0 ? '#e8f5e9' : 'white'; ?>;">
                            <td style="padding: 10px; border: 1px solid #ddd;">Malicious Bots</td>
                            <td style="padding: 10px; border: 1px solid #ddd; text-align: center;"><strong><?php echo esc_html( $data['attack_vectors']['bad_bots'] ); ?></strong></td>
                            <td style="padding: 10px; border: 1px solid #ddd; text-align: center; color: #4caf50;"><strong>LOW</strong></td>
                        </tr>
                    </tbody>
                </table>

                <?php if ( ! empty( $data['top_attackers'] ) ) : ?>
                <h2>Top Attacking IPs</h2>
                <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
                    <thead>
                        <tr style="background: #f5f5f5;">
                            <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Rank</th>
                            <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">IP Address</th>
                            <th style="padding: 10px; border: 1px solid #ddd; text-align: center;">Incidents</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php $rank = 1; foreach ( array_slice( $data['top_attackers'], 0, 5 ) as $attacker ) : ?>
                        <tr style="background: <?php echo $rank % 2 === 0 ? '#f5f5f5' : 'white'; ?>;">
                            <td style="padding: 10px; border: 1px solid #ddd;"><?php echo esc_html( $rank++ ); ?></td>
                            <td style="padding: 10px; border: 1px solid #ddd;"><code><?php echo esc_html( $attacker['ip_address'] ); ?></code></td>
                            <td style="padding: 10px; border: 1px solid #ddd; text-align: center;"><strong><?php echo esc_html( $attacker['count'] ); ?></strong></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
                <?php endif; ?>

                <?php 
                // Cloud Services Section (only show if any are enabled)
                $cloud = isset( $data['cloud_services'] ) ? $data['cloud_services'] : [];
                $any_cloud_enabled = ( isset( $cloud['cloudflare']['enabled'] ) && $cloud['cloudflare']['enabled'] ) ||
                                     ( isset( $cloud['threat_feeds']['enabled'] ) && $cloud['threat_feeds']['enabled'] ) ||
                                     ( isset( $cloud['geoip']['enabled'] ) && $cloud['geoip']['enabled'] );
                
                if ( $any_cloud_enabled ) : 
                ?>
                <h2>☁️ Cloud Services</h2>
                <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
                    <?php if ( ! empty( $cloud['cloudflare']['enabled'] ) ) : ?>
                    <tr style="background: #fff3e0;">
                        <td colspan="2" style="padding: 10px; border: 1px solid #ddd;">
                            <strong>🔶 Cloudflare Integration</strong>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; border: 1px solid #ddd;">Blocked IPs (Cloudflare)</td>
                        <td style="padding: 10px; border: 1px solid #ddd;"><strong><?php echo esc_html( $cloud['cloudflare']['blocked_ips'] ?? 0 ); ?></strong></td>
                    </tr>
                    <tr style="background: #f5f5f5;">
                        <td style="padding: 10px; border: 1px solid #ddd;">Events Imported (24h)</td>
                        <td style="padding: 10px; border: 1px solid #ddd;"><strong><?php echo esc_html( $cloud['cloudflare']['events_imported'] ?? 0 ); ?></strong></td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; border: 1px solid #ddd;">Last Sync</td>
                        <td style="padding: 10px; border: 1px solid #ddd;"><?php echo esc_html( $cloud['cloudflare']['last_sync'] ?? 'Never' ); ?></td>
                    </tr>
                    <?php endif; ?>
                    
                    <?php if ( ! empty( $cloud['threat_feeds']['enabled'] ) ) : ?>
                    <tr style="background: #f3e5f5;">
                        <td colspan="2" style="padding: 10px; border: 1px solid #ddd;">
                            <strong>🛡️ Threat Intelligence Feeds</strong>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; border: 1px solid #ddd;">Active Feeds</td>
                        <td style="padding: 10px; border: 1px solid #ddd;"><strong><?php echo esc_html( $cloud['threat_feeds']['total_feeds'] ?? 0 ); ?></strong></td>
                    </tr>
                    <tr style="background: #f5f5f5;">
                        <td style="padding: 10px; border: 1px solid #ddd;">Total IPs in Threat Database</td>
                        <td style="padding: 10px; border: 1px solid #ddd;"><strong><?php echo esc_html( number_format( $cloud['threat_feeds']['total_ips'] ?? 0 ) ); ?></strong></td>
                    </tr>
                    <?php endif; ?>
                    
                    <?php if ( ! empty( $cloud['geoip']['enabled'] ) ) : ?>
                    <tr style="background: #e8f5e9;">
                        <td colspan="2" style="padding: 10px; border: 1px solid #ddd;">
                            <strong>🌍 GeoIP / Country Blocking</strong>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; border: 1px solid #ddd;">Mode</td>
                        <td style="padding: 10px; border: 1px solid #ddd;"><strong><?php echo esc_html( ucfirst( $cloud['geoip']['mode'] ?? 'blocklist' ) ); ?></strong></td>
                    </tr>
                    <tr style="background: #f5f5f5;">
                        <td style="padding: 10px; border: 1px solid #ddd;">Countries Configured</td>
                        <td style="padding: 10px; border: 1px solid #ddd;"><strong><?php echo esc_html( $cloud['geoip']['blocked_count'] ?? 0 ); ?></strong></td>
                    </tr>
                    <tr>
                        <td style="padding: 10px; border: 1px solid #ddd;">Geo Blocks (This Week)</td>
                        <td style="padding: 10px; border: 1px solid #ddd;"><strong><?php echo esc_html( $cloud['geoip']['total_blocks'] ?? 0 ); ?></strong></td>
                    </tr>
                    <?php if ( ! empty( $cloud['geoip']['top_countries'] ) ) : ?>
                    <tr style="background: #f5f5f5;">
                        <td style="padding: 10px; border: 1px solid #ddd;">Top Attacking Countries</td>
                        <td style="padding: 10px; border: 1px solid #ddd;">
                            <?php 
                            $countries = [];
                            foreach ( array_slice( $cloud['geoip']['top_countries'], 0, 3 ) as $country ) {
                                $countries[] = ( $country['flag'] ?? '' ) . ' ' . ( $country['name'] ?? 'Unknown' ) . ' (' . ( $country['count'] ?? 0 ) . ')';
                            }
                            echo esc_html( implode( ', ', $countries ) );
                            ?>
                        </td>
                    </tr>
                    <?php endif; ?>
                    <?php endif; ?>
                </table>
                <?php endif; ?>

                <p style="text-align: center; margin-top: 30px;">
                    <a href="<?php echo esc_url( admin_url( 'admin.php?page=saurity-reports' ) ); ?>" 
                       style="display: inline-block; padding: 12px 24px; background: #2196F3; color: white; text-decoration: none; border-radius: 4px;">
                        View Full Report
                    </a>
                </p>
            </div>
        </body>
        </html>
        <?php
        return ob_get_clean();
    }

    /**
     * Get stored reports
     *
     * @param int $limit Number of reports to retrieve.
     * @return array Reports.
     */
    public function get_reports( $limit = 10 ) {
        global $wpdb;

        $table_name = $wpdb->prefix . 'saurity_reports';

        if ( ! $this->table_exists( $table_name ) ) {
            return [];
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Direct DB required for reports
        $results = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM {$wpdb->prefix}saurity_reports ORDER BY created_at DESC LIMIT %d",
                $limit
            ),
            ARRAY_A
        );

        // Decode report data
        foreach ( $results as &$report ) {
            $report['report_data'] = json_decode( $report['report_data'], true );
        }

        return $results;
    }

    /**
     * Get report by ID
     *
     * @param int $report_id Report ID.
     * @return array|null Report data or null if not found.
     */
    public function get_report( $report_id ) {
        global $wpdb;

        $table_name = $wpdb->prefix . 'saurity_reports';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Direct DB required for reports
        $report = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM {$wpdb->prefix}saurity_reports WHERE id = %d",
                $report_id
            ),
            ARRAY_A
        );

        if ( $report ) {
            $report['report_data'] = json_decode( $report['report_data'], true );
        }

        return $report;
    }

    /**
     * Delete old reports
     *
     * @param int $days Number of days to keep.
     */
    public function cleanup_old_reports( $days = 90 ) {
        global $wpdb;

        $table_name = $wpdb->prefix . 'saurity_reports';
        $cutoff_date = gmdate( 'Y-m-d H:i:s', strtotime( "-{$days} days" ) );

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Direct DB required for cleanup
        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$wpdb->prefix}saurity_reports WHERE created_at < %s",
                $cutoff_date
            )
        );
    }

    /**
     * Check if table exists
     *
     * @param string $table_name Table name.
     * @return bool
     */
    private function table_exists( $table_name ) {
        global $wpdb;
        $query = $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name );
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared -- Query is prepared above, direct DB required for table check
        return (bool) $wpdb->get_var( $query );
    }
}