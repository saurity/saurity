<?php
/**
 * Security Reports
 *
 * @package Saurity
 */

namespace Saurity;

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
                'display'  => __( 'Once Weekly', 'saurity' ),
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
            $start_date = date( 'Y-m-d', strtotime( '-7 days', strtotime( $end_date ) ) );
        }

        $start_datetime = $start_date . ' 00:00:00';
        $end_datetime = $end_date . ' 23:59:59';

        // Generate report data
        $report_data = $this->collect_report_data( $start_datetime, $end_datetime );

        // Calculate security score
        $security_score = $this->calculate_security_score( $report_data );

        // Store report in database
        $table_name = $wpdb->prefix . 'saurity_reports';
        
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
        $logs_table = $wpdb->prefix . 'saurity_logs';

        // 1. Single Pass Aggregation Query
        // Instead of running 14 separate queries, we count everything in one go.
        $stats = $wpdb->get_row( $wpdb->prepare( "
            SELECT 
                COUNT(*) as total,
                
                -- Summary Metrics (Fixed patterns to match actual log messages)
                SUM(CASE WHEN message LIKE '%%Failed login%%' THEN 1 ELSE 0 END) as failed_logins,
                SUM(CASE WHEN message LIKE '%%Successful login%%' OR message LIKE '%%logged in successfully%%' THEN 1 ELSE 0 END) as successful_logins,
                SUM(CASE WHEN message LIKE '%%hard blocked%%' OR message LIKE '%%permanently blocked%%' THEN 1 ELSE 0 END) as blocked_ips,
                SUM(CASE WHEN message LIKE '%%rate limited%%' OR message LIKE '%%Rate limit%%' THEN 1 ELSE 0 END) as rate_limited,
                
                -- Firewall / Attack Vector Metrics
                SUM(CASE WHEN message LIKE '%%SQL injection%%' THEN 1 ELSE 0 END) as sql_injection,
                SUM(CASE WHEN message LIKE '%%XSS%%' THEN 1 ELSE 0 END) as xss,
                SUM(CASE WHEN message LIKE '%%XML-RPC%%' THEN 1 ELSE 0 END) as xmlrpc,
                SUM(CASE WHEN message LIKE '%%POST flood%%' THEN 1 ELSE 0 END) as post_flood,
                SUM(CASE WHEN message LIKE '%%sensitive path%%' THEN 1 ELSE 0 END) as sensitive_paths,
                SUM(CASE WHEN message LIKE '%%Malicious user%%' OR message LIKE '%%Bad bot%%' THEN 1 ELSE 0 END) as bad_bots,
                
                -- Severity Counts
                SUM(CASE WHEN event_type = 'critical' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN event_type = 'error' THEN 1 ELSE 0 END) as error,
                SUM(CASE WHEN event_type = 'warning' THEN 1 ELSE 0 END) as warning

            FROM $logs_table 
            WHERE created_at BETWEEN %s AND %s
        ", $start_datetime, $end_datetime ), ARRAY_A );

        // Calculate total firewall blocks (sum of specific vectors + generic blocks)
        $firewall_blocks = (int)$stats['sql_injection'] + (int)$stats['xss'] + (int)$stats['xmlrpc'] + 
                           (int)$stats['post_flood'] + (int)$stats['sensitive_paths'] + (int)$stats['bad_bots'];

        // 2. Top Attackers (Requires separate query for grouping)
        $top_attackers = $wpdb->get_results( $wpdb->prepare(
            "SELECT ip_address, COUNT(*) as count 
             FROM $logs_table 
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
        $top_users = $wpdb->get_results( $wpdb->prepare(
            "SELECT user_login, COUNT(*) as count 
             FROM $logs_table 
             WHERE created_at BETWEEN %s AND %s 
             AND user_login IS NOT NULL AND user_login != ''
             GROUP BY user_login 
             ORDER BY count DESC 
             LIMIT 10",
            $start_datetime,
            $end_datetime
        ), ARRAY_A );

        // 4. Daily Stats (Requires separate query)
        $daily_stats = $wpdb->get_results( $wpdb->prepare(
            "SELECT DATE(created_at) as date, 
            COUNT(*) as total,
            SUM(CASE WHEN event_type = 'warning' THEN 1 ELSE 0 END) as warnings,
            SUM(CASE WHEN event_type = 'error' THEN 1 ELSE 0 END) as errors,
            SUM(CASE WHEN event_type = 'critical' THEN 1 ELSE 0 END) as critical
            FROM $logs_table 
            WHERE created_at BETWEEN %s AND %s 
            GROUP BY DATE(created_at)
            ORDER BY date ASC",
            $start_datetime,
            $end_datetime
        ), ARRAY_A );

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
            // THIS WAS MISSING IN YOUR PREVIOUS CODE:
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
        ];
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
        $start_date = date( 'M d, Y', strtotime( $data['period']['start'] ) );
        $end_date = date( 'M d, Y', strtotime( $data['period']['end'] ) );

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

        $results = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM $table_name ORDER BY created_at DESC LIMIT %d",
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

        $report = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM $table_name WHERE id = %d",
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
        $cutoff_date = date( 'Y-m-d H:i:s', strtotime( "-{$days} days" ) );

        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM $table_name WHERE created_at < %s",
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
        return (bool) $wpdb->get_var( $query );
    }
}