<?php
/**
 * Reports Dashboard
 *
 * @package Saurity
 */

namespace Saurity;

/**
 * ReportsDashboard class - admin interface for security reports
 */
class ReportsDashboard {

    /**
     * Security reports instance
     *
     * @var SecurityReports
     */
    private $reports;

    /**
     * Constructor
     *
     * @param SecurityReports $reports Security reports instance.
     */
    public function __construct( SecurityReports $reports ) {
        $this->reports = $reports;
    }

    /**
     * Hook into WordPress
     */
    public function hook() {
        add_action( 'admin_menu', [ $this, 'add_menu_page' ] );
        add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_assets' ] );
        add_action( 'wp_ajax_saurity_generate_report', [ $this, 'ajax_generate_report' ] );
        add_action( 'wp_ajax_saurity_export_pdf', [ $this, 'ajax_export_pdf' ] );
        add_action( 'wp_ajax_saurity_export_csv', [ $this, 'ajax_export_csv' ] );
    }

    /**
     * Add menu page
     */
    public function add_menu_page() {
        add_submenu_page(
            'saurity',
            'Security Reports',
            'Reports',
            'manage_options',
            'saurity-reports',
            [ $this, 'render_dashboard' ]
        );
    }

    /**
     * Enqueue assets
     */
    public function enqueue_assets( $hook ) {
        if ( 'saurity_page_saurity-reports' !== $hook ) {
            return;
        }

        // Enqueue Chart.js from CDN
        wp_enqueue_script(
            'chartjs',
            'https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js',
            [],
            '4.4.0',
            true
        );
    }

    /**
     * Render dashboard
     */
    public function render_dashboard() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'saurity' ) );
        }

        // Get current report or generate new one
        $report_id = isset( $_GET['report_id'] ) ? absint( $_GET['report_id'] ) : null;
        
        if ( $report_id ) {
            $report = $this->reports->get_report( $report_id );
        } else {
            // Show latest report or generate one
            $reports_list = $this->reports->get_reports( 1 );
            $report = ! empty( $reports_list ) ? $reports_list[0] : null;
        }

        // Get all reports for history
        $reports_history = $this->reports->get_reports( 10 );

        ?>
        <div class="wrap saurity-reports-dashboard">
            <h1>Security Reports Dashboard</h1>

            <?php $this->render_toolbar( $report ); ?>

            <?php if ( $report ) : ?>
                <?php $this->render_report( $report ); ?>
            <?php else : ?>
                <?php $this->render_no_reports(); ?>
            <?php endif; ?>

            <?php $this->render_reports_history( $reports_history ); ?>

            <?php $this->render_styles(); ?>
            <?php $this->render_scripts( $report ); ?>
        </div>
        <?php
    }

    /**
     * Render toolbar
     *
     * @param array|null $report Current report.
     */
    private function render_toolbar( $report = null ) {
        ?>
        <div class="saurity-toolbar">
            <button type="button" class="button button-primary" id="generate-report-btn">
                <span class="dashicons dashicons-update"></span> Generate New Report
            </button>
            <?php if ( $report ) : ?>
            <div class="export-dropdown" style="position: relative; display: inline-block;">
                <button type="button" class="button" id="export-menu-btn">
                    <span class="dashicons dashicons-download"></span> Export Report
                    <span class="dashicons dashicons-arrow-down-alt2" style="font-size: 14px;"></span>
                </button>
                <div id="export-menu" class="export-menu-content" style="display: none;">
                    <a href="#" id="export-pdf-btn">
                        <span class="dashicons dashicons-media-document"></span> Export as PDF
                    </a>
                    <a href="#" id="export-csv-btn">
                        <span class="dashicons dashicons-media-spreadsheet"></span> Export as CSV
                    </a>
                </div>
            </div>
            <?php endif; ?>
            <span id="report-status" style="margin-left: 15px; display: none;"></span>
        </div>
        <?php
    }

    /**
     * Render report
     */
    private function render_report( $report ) {
        $data = $report['report_data'];
        $score = $report['security_score'];
        $score_class = $score >= 80 ? 'excellent' : ( $score >= 60 ? 'good' : 'needs-improvement' );
        
        $start_date = date( 'M d, Y', strtotime( $data['period']['start'] ) );
        $end_date = date( 'M d, Y', strtotime( $data['period']['end'] ) );
        ?>

        <!-- Report Header -->
        <div class="saurity-report-header">
            <div class="report-period">
                <strong>Report Period:</strong> <?php echo esc_html( $start_date ); ?> - <?php echo esc_html( $end_date ); ?>
            </div>
            <div class="report-date">
                Generated: <?php echo esc_html( date( 'M d, Y g:i A', strtotime( $report['created_at'] ) ) ); ?>
            </div>
        </div>

        <!-- Security Score -->
        <div class="saurity-score-card <?php echo esc_attr( $score_class ); ?>">
            <div class="score-circle">
                <div class="score-value"><?php echo esc_html( $score ); ?></div>
                <div class="score-label">Security Score</div>
            </div>
            <div class="score-description">
                <?php if ( $score >= 80 ) : ?>
                    <p><strong>Excellent!</strong> Your site's security is performing well.</p>
                <?php elseif ( $score >= 60 ) : ?>
                    <p><strong>Good.</strong> Your site is secure but there's room for improvement.</p>
                <?php else : ?>
                    <p><strong>Needs Attention!</strong> Several security issues require immediate attention.</p>
                <?php endif; ?>
            </div>
        </div>

        <!-- Key Metrics Grid -->
        <div class="saurity-metrics-grid">
            <div class="metric-card">
                <div class="metric-icon"><span class="dashicons dashicons-chart-bar"></span></div>
                <div class="metric-value"><?php echo esc_html( number_format( $data['summary']['total_events'] ) ); ?></div>
                <div class="metric-label">Total Events</div>
            </div>
            <div class="metric-card warning">
                <div class="metric-icon"><span class="dashicons dashicons-warning"></span></div>
                <div class="metric-value"><?php echo esc_html( number_format( $data['summary']['failed_logins'] ) ); ?></div>
                <div class="metric-label">Failed Logins</div>
            </div>
            <div class="metric-card success">
                <div class="metric-icon"><span class="dashicons dashicons-yes-alt"></span></div>
                <div class="metric-value"><?php echo esc_html( number_format( $data['summary']['successful_logins'] ) ); ?></div>
                <div class="metric-label">Successful Logins</div>
            </div>
            <div class="metric-card danger">
                <div class="metric-icon"><span class="dashicons dashicons-dismiss"></span></div>
                <div class="metric-value"><?php echo esc_html( number_format( $data['summary']['blocked_ips'] ) ); ?></div>
                <div class="metric-label">Blocked IPs</div>
            </div>
            <div class="metric-card info">
                <div class="metric-icon"><span class="dashicons dashicons-clock"></span></div>
                <div class="metric-value"><?php echo esc_html( number_format( $data['summary']['rate_limited'] ) ); ?></div>
                <div class="metric-label">Rate Limited</div>
            </div>
            <div class="metric-card danger">
                <div class="metric-icon"><span class="dashicons dashicons-shield"></span></div>
                <div class="metric-value"><?php echo esc_html( number_format( $data['summary']['firewall_blocks'] ) ); ?></div>
                <div class="metric-label">Firewall Blocks</div>
            </div>
        </div>

        <!-- Charts Row -->
        <div class="saurity-charts-row">
            <div class="chart-container">
                <h3>Event Types Distribution</h3>
                <canvas id="eventTypesChart"></canvas>
            </div>
            <div class="chart-container">
                <h3>Daily Activity Trend</h3>
                <canvas id="dailyTrendChart"></canvas>
            </div>
        </div>

        <!-- Top Attackers Table -->
        <?php if ( ! empty( $data['top_attackers'] ) ) : ?>
        <div class="saurity-section">
            <h2>Top Attacking IPs</h2>
            <table class="saurity-data-table">
                <thead>
                    <tr>
                        <th>Rank</th>
                        <th>IP Address</th>
                        <th>Incidents</th>
                        <th>Threat Level</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ( array_slice( $data['top_attackers'], 0, 10 ) as $index => $attacker ) : ?>
                        <?php
                        $count = (int) $attacker['count'];
                        $threat_level = $count > 50 ? 'Critical' : ( $count > 20 ? 'High' : ( $count > 10 ? 'Medium' : 'Low' ) );
                        $threat_class = strtolower( $threat_level );
                        ?>
                        <tr>
                            <td><strong><?php echo esc_html( $index + 1 ); ?></strong></td>
                            <td><code><?php echo esc_html( $attacker['ip_address'] ); ?></code></td>
                            <td><?php echo esc_html( number_format( $count ) ); ?></td>
                            <td><span class="threat-badge <?php echo esc_attr( $threat_class ); ?>"><?php echo esc_html( $threat_level ); ?></span></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php endif; ?>

        <!-- Top Users Table -->
        <?php if ( ! empty( $data['top_users'] ) ) : ?>
        <div class="saurity-section">
            <h2>Most Active Users</h2>
            <table class="saurity-data-table">
                <thead>
                    <tr>
                        <th>Rank</th>
                        <th>Username</th>
                        <th>Activities</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ( array_slice( $data['top_users'], 0, 10 ) as $index => $user ) : ?>
                        <tr>
                            <td><strong><?php echo esc_html( $index + 1 ); ?></strong></td>
                            <td><?php echo esc_html( $user['user_login'] ); ?></td>
                            <td><?php echo esc_html( number_format( $user['count'] ) ); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php endif; ?>

        <?php
    }

    /**
     * Render no reports message
     */
    private function render_no_reports() {
        ?>
        <div class="saurity-no-reports">
            <div class="icon"><span class="dashicons dashicons-chart-area" style="font-size: 72px; width: 72px; height: 72px;"></span></div>
            <h2>No Reports Available</h2>
            <p>Generate your first security report to get started with comprehensive security monitoring.</p>
            <button type="button" class="button button-primary button-hero" id="generate-first-report">
                Generate First Report
            </button>
        </div>
        <?php
    }

    /**
     * Render reports history
     */
    private function render_reports_history( $reports ) {
        if ( empty( $reports ) ) {
            return;
        }
        ?>
        <div class="saurity-section">
            <h2>Reports History</h2>
            <table class="saurity-data-table">
                <thead>
                    <tr>
                        <th>Period</th>
                        <th>Score</th>
                        <th>Total Events</th>
                        <th>Failed Logins</th>
                        <th>Blocked IPs</th>
                        <th>Generated</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ( $reports as $report ) : ?>
                        <?php
                        $data = $report['report_data'];
                        $score = $report['security_score'];
                        $score_class = $score >= 80 ? 'excellent' : ( $score >= 60 ? 'good' : 'needs-improvement' );
                        ?>
                        <tr>
                            <td>
                                <?php echo esc_html( date( 'M d', strtotime( $data['period']['start'] ) ) ); ?> - 
                                <?php echo esc_html( date( 'M d, Y', strtotime( $data['period']['end'] ) ) ); ?>
                            </td>
                            <td>
                                <span class="score-badge <?php echo esc_attr( $score_class ); ?>">
                                    <?php echo esc_html( $score ); ?>/100
                                </span>
                            </td>
                            <td><?php echo esc_html( number_format( $data['summary']['total_events'] ) ); ?></td>
                            <td><?php echo esc_html( number_format( $data['summary']['failed_logins'] ) ); ?></td>
                            <td><?php echo esc_html( number_format( $data['summary']['blocked_ips'] ) ); ?></td>
                            <td><?php echo esc_html( date( 'M d, Y', strtotime( $report['created_at'] ) ) ); ?></td>
                            <td>
                                <a href="<?php echo esc_url( admin_url( 'admin.php?page=saurity-reports&report_id=' . $report['id'] ) ); ?>" 
                                   class="button button-small">View</a>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php
    }

    /**
     * Render styles
     */
    private function render_styles() {
        ?>
        <style>
            .saurity-reports-dashboard {
                background: #f0f0f1;
                margin: 20px 20px 20px 0;
                padding: 30px;
                border-radius: 8px;
            }
            .saurity-toolbar {
                background: white;
                padding: 20px;
                margin-bottom: 30px;
                border-radius: 8px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .saurity-report-header {
                background: white;
                padding: 20px;
                margin-bottom: 20px;
                border-radius: 8px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }
            .saurity-score-card {
                background: white;
                padding: 40px;
                margin-bottom: 30px;
                border-radius: 8px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                display: flex;
                align-items: center;
                gap: 40px;
            }
            .saurity-score-card.excellent {
                border-left: 5px solid #46b450;
            }
            .saurity-score-card.good {
                border-left: 5px solid #ff9800;
            }
            .saurity-score-card.needs-improvement {
                border-left: 5px solid #dc3232;
            }
            .score-circle {
                text-align: center;
                min-width: 150px;
            }
            .score-value {
                font-size: 64px;
                font-weight: bold;
                color: #2196F3;
                line-height: 1;
            }
            .score-label {
                font-size: 16px;
                color: #666;
                margin-top: 10px;
            }
            .score-description {
                flex: 1;
            }
            .score-description p {
                font-size: 18px;
                margin: 0;
            }
            .saurity-metrics-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }
            .metric-card {
                background: white;
                padding: 25px;
                border-radius: 8px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                text-align: center;
                border-left: 4px solid #2196F3;
            }
            .metric-card.warning {
                border-left-color: #ff9800;
            }
            .metric-card.danger {
                border-left-color: #dc3232;
            }
            .metric-card.success {
                border-left-color: #46b450;
            }
            .metric-card.info {
                border-left-color: #00bcd4;
            }
            .metric-icon {
                font-size: 32px;
                margin-bottom: 10px;
                color: #666;
            }
            .metric-icon .dashicons {
                font-size: 32px;
                width: 32px;
                height: 32px;
            }
            .metric-value {
                font-size: 36px;
                font-weight: bold;
                color: #333;
                line-height: 1;
            }
            .metric-label {
                font-size: 14px;
                color: #666;
                margin-top: 8px;
            }
            .saurity-charts-row {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }
            .chart-container {
                background: white;
                padding: 25px;
                border-radius: 8px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }
            .chart-container h3 {
                margin-top: 0;
                margin-bottom: 20px;
                color: #333;
            }
            .saurity-section {
                background: white;
                padding: 30px;
                margin-bottom: 20px;
                border-radius: 8px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }
            .saurity-section h2 {
                margin-top: 0;
                color: #333;
                border-bottom: 2px solid #f0f0f1;
                padding-bottom: 15px;
                margin-bottom: 20px;
            }
            .saurity-data-table {
                width: 100%;
                border-collapse: collapse;
            }
            .saurity-data-table th {
                background: #f9f9f9;
                padding: 12px;
                text-align: left;
                font-weight: 600;
                color: #333;
                border-bottom: 2px solid #ddd;
            }
            .saurity-data-table td {
                padding: 12px;
                border-bottom: 1px solid #f0f0f1;
            }
            .saurity-data-table tr:hover {
                background: #f9f9f9;
            }
            .threat-badge {
                display: inline-block;
                padding: 4px 12px;
                border-radius: 12px;
                font-size: 12px;
                font-weight: 600;
                text-transform: uppercase;
            }
            .threat-badge.critical {
                background: #dc3232;
                color: white;
            }
            .threat-badge.high {
                background: #ff9800;
                color: white;
            }
            .threat-badge.medium {
                background: #00bcd4;
                color: white;
            }
            .threat-badge.low {
                background: #46b450;
                color: white;
            }
            .score-badge {
                display: inline-block;
                padding: 6px 14px;
                border-radius: 20px;
                font-weight: 600;
                font-size: 14px;
            }
            .score-badge.excellent {
                background: #46b450;
                color: white;
            }
            .score-badge.good {
                background: #ff9800;
                color: white;
            }
            .score-badge.needs-improvement {
                background: #dc3232;
                color: white;
            }
            .saurity-no-reports {
                background: white;
                padding: 60px;
                text-align: center;
                border-radius: 8px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }
            .saurity-no-reports .icon {
                font-size: 72px;
                margin-bottom: 20px;
                color: #666;
            }
            .saurity-no-reports h2 {
                color: #333;
                margin-bottom: 10px;
            }
            .saurity-no-reports p {
                color: #666;
                font-size: 16px;
                margin-bottom: 30px;
            }
            .export-dropdown {
                position: relative;
                display: inline-block;
            }
            .export-menu-content {
                position: absolute;
                top: 100%;
                right: 0;
                margin-top: 5px;
                background: white;
                border: 1px solid #ddd;
                border-radius: 4px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.15);
                min-width: 180px;
                z-index: 1000;
            }
            .export-menu-content a {
                display: block;
                padding: 10px 15px;
                text-decoration: none;
                color: #333;
                border-bottom: 1px solid #f0f0f1;
            }
            .export-menu-content a:last-child {
                border-bottom: none;
            }
            .export-menu-content a:hover {
                background: #f5f5f5;
                color: #0073aa;
            }
            .export-menu-content .dashicons {
                margin-right: 8px;
                color: #666;
            }
        </style>
        <?php
    }

    /**
     * Render scripts
     */
    private function render_scripts( $report ) {
        ?>
        <script>
        jQuery(document).ready(function($) {
            // Generate report button
            $('#generate-report-btn, #generate-first-report').on('click', function() {
                var $btn = $(this);
                var originalText = $btn.text();
                
                $btn.prop('disabled', true).text('Generating...');
                $('#report-status').show().text('Generating report...').css('color', '#2196F3');

                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'saurity_generate_report',
                        nonce: '<?php echo esc_js( wp_create_nonce( 'saurity_generate_report' ) ); ?>'
                    },
                    success: function(response) {
                        if (response.success) {
                            $('#report-status').text('Report generated successfully!').css('color', '#46b450');
                            setTimeout(function() {
                                window.location.reload();
                            }, 1000);
                        } else {
                            $('#report-status').text('Error: ' + response.data).css('color', '#dc3232');
                            $btn.prop('disabled', false).text(originalText);
                        }
                    },
                    error: function() {
                        $('#report-status').text('Error generating report').css('color', '#dc3232');
                        $btn.prop('disabled', false).text(originalText);
                    }
                });
            });

            // Export menu toggle
            $('#export-menu-btn').on('click', function(e) {
                e.stopPropagation();
                $('#export-menu').toggle();
            });

            // Close export menu when clicking outside
            $(document).on('click', function() {
                $('#export-menu').hide();
            });

            // Export as PDF
            $('#export-pdf-btn').on('click', function(e) {
                e.preventDefault();
                $('#export-menu').hide();
                
                var reportId = new URLSearchParams(window.location.search).get('report_id') || '';
                var exportUrl = ajaxurl + '?action=saurity_export_pdf&report_id=' + reportId + '&nonce=<?php echo esc_js( wp_create_nonce( 'saurity_export' ) ); ?>';
                
                $('#report-status').show().text('Generating PDF...').css('color', '#2196F3');
                
                // Open in new tab
                window.open(exportUrl, '_blank');
                
                setTimeout(function() {
                    $('#report-status').hide();
                }, 2000);
            });

            // Export as CSV
            $('#export-csv-btn').on('click', function(e) {
                e.preventDefault();
                $('#export-menu').hide();
                
                var reportId = new URLSearchParams(window.location.search).get('report_id') || '';
                var exportUrl = ajaxurl + '?action=saurity_export_csv&report_id=' + reportId + '&nonce=<?php echo esc_js( wp_create_nonce( 'saurity_export' ) ); ?>';
                
                $('#report-status').show().text('Generating CSV...').css('color', '#2196F3');
                
                // Trigger download
                window.location.href = exportUrl;
                
                setTimeout(function() {
                    $('#report-status').hide();
                }, 2000);
            });

            <?php if ( $report && isset( $report['report_data'] ) ) : ?>
            // Render charts
            var reportData = <?php echo wp_json_encode( $report['report_data'] ); ?>;

            // Event Types Chart
            var eventTypesCtx = document.getElementById('eventTypesChart');
            if (eventTypesCtx) {
                new Chart(eventTypesCtx, {
                    type: 'doughnut',
                    data: {
                        labels: ['Info', 'Warning', 'Error', 'Critical'],
                        datasets: [{
                            data: [
                                reportData.event_counts.info,
                                reportData.event_counts.warning,
                                reportData.event_counts.error,
                                reportData.event_counts.critical
                            ],
                            backgroundColor: [
                                '#2196F3',
                                '#ff9800',
                                '#f44336',
                                '#9c27b0'
                            ]
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            legend: {
                                position: 'bottom'
                            }
                        }
                    }
                });
            }

            // Daily Trend Chart
            var dailyTrendCtx = document.getElementById('dailyTrendChart');
            if (dailyTrendCtx && reportData.daily_stats) {
                var labels = reportData.daily_stats.map(function(stat) {
                    return new Date(stat.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
                });
                
                new Chart(dailyTrendCtx, {
                    type: 'line',
                    data: {
                        labels: labels,
                        datasets: [
                            {
                                label: 'Total Events',
                                data: reportData.daily_stats.map(function(stat) { return stat.total; }),
                                borderColor: '#2196F3',
                                backgroundColor: 'rgba(33, 150, 243, 0.1)',
                                tension: 0.4
                            },
                            {
                                label: 'Warnings',
                                data: reportData.daily_stats.map(function(stat) { return stat.warnings; }),
                                borderColor: '#ff9800',
                                backgroundColor: 'rgba(255, 152, 0, 0.1)',
                                tension: 0.4
                            },
                            {
                                label: 'Errors',
                                data: reportData.daily_stats.map(function(stat) { return stat.errors; }),
                                borderColor: '#f44336',
                                backgroundColor: 'rgba(244, 67, 54, 0.1)',
                                tension: 0.4
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            legend: {
                                position: 'bottom'
                            }
                        },
                        scales: {
                            y: {
                                beginAtZero: true
                            }
                        }
                    }
                });
            }
            <?php endif; ?>
        });
        </script>
        <?php
    }

    /**
     * AJAX: Generate report
     */
    public function ajax_generate_report() {
        check_ajax_referer( 'saurity_generate_report', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( 'Insufficient permissions' );
        }

        $report_id = $this->reports->generate_weekly_report();

        if ( $report_id ) {
            wp_send_json_success( [ 'report_id' => $report_id ] );
        } else {
            wp_send_json_error( 'Failed to generate report' );
        }
    }

    /**
     * AJAX: Export report as PDF
     */
    public function ajax_export_pdf() {
        check_ajax_referer( 'saurity_export', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Insufficient permissions' );
        }

        $report_id = isset( $_GET['report_id'] ) ? absint( $_GET['report_id'] ) : 0;
        
        if ( ! $report_id ) {
            // Get latest report
            $reports = $this->reports->get_reports( 1 );
            if ( empty( $reports ) ) {
                wp_die( 'No reports available' );
            }
            $report = $reports[0];
        } else {
            $report = $this->reports->get_report( $report_id );
            if ( ! $report ) {
                wp_die( 'Report not found' );
            }
        }

        $this->generate_pdf_export( $report );
        exit;
    }

    /**
     * AJAX: Export report as CSV
     */
    public function ajax_export_csv() {
        check_ajax_referer( 'saurity_export', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Insufficient permissions' );
        }

        $report_id = isset( $_GET['report_id'] ) ? absint( $_GET['report_id'] ) : 0;
        
        if ( ! $report_id ) {
            // Get latest report
            $reports = $this->reports->get_reports( 1 );
            if ( empty( $reports ) ) {
                wp_die( 'No reports available' );
            }
            $report = $reports[0];
        } else {
            $report = $this->reports->get_report( $report_id );
            if ( ! $report ) {
                wp_die( 'Report not found' );
            }
        }

        $this->generate_csv_export( $report );
        exit;
    }

    /**
     * Generate PDF export (HTML for browser print)
     *
     * @param array $report Report data.
     */
    private function generate_pdf_export( $report ) {
        $data = $report['report_data'];
        $score = $report['security_score'];
        $start_date = date( 'M d, Y', strtotime( $data['period']['start'] ) );
        $end_date = date( 'M d, Y', strtotime( $data['period']['end'] ) );
        $filename = 'saurity-security-report-' . date( 'Y-m-d', strtotime( $data['period']['start'] ) ) . '.html';

        // Set headers for HTML display (can be converted to PDF by browser)
        header( 'Content-Type: text/html; charset=utf-8' );
        header( 'Content-Disposition: inline; filename="' . $filename . '"' );

        ?>
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Security Report - <?php echo esc_html( $start_date ); ?> to <?php echo esc_html( $end_date ); ?></title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; color: #333; line-height: 1.6; }
                .header { text-align: center; margin-bottom: 40px; border-bottom: 3px solid #2196F3; padding-bottom: 20px; }
                .header h1 { margin: 0; color: #2196F3; font-size: 32px; }
                .header p { margin: 5px 0; color: #666; }
                .score-section { text-align: center; margin: 30px 0; padding: 30px; background: #f5f5f5; border-radius: 8px; }
                .score { font-size: 72px; font-weight: bold; color: <?php echo $score >= 80 ? '#46b450' : ( $score >= 60 ? '#ff9800' : '#dc3232' ); ?>; }
                .score-label { font-size: 18px; color: #666; margin-top: 10px; }
                .metrics { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 30px 0; }
                .metric { text-align: center; padding: 20px; border: 1px solid #ddd; border-radius: 4px; }
                .metric-value { font-size: 32px; font-weight: bold; color: #2196F3; }
                .metric-label { font-size: 14px; color: #666; margin-top: 5px; }
                table { width: 100%; border-collapse: collapse; margin: 20px 0; }
                th { background: #f5f5f5; padding: 12px; text-align: left; border-bottom: 2px solid #ddd; font-weight: 600; }
                td { padding: 12px; border-bottom: 1px solid #f0f0f0; }
                tr:hover { background: #fafafa; }
                h2 { color: #333; border-bottom: 2px solid #2196F3; padding-bottom: 10px; margin-top: 40px; }
                .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666; font-size: 12px; }
                @media print {
                    body { margin: 20px; }
                    .no-print { display: none; }
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Security Report</h1>
                <p><strong>Report Period:</strong> <?php echo esc_html( $start_date ); ?> - <?php echo esc_html( $end_date ); ?></p>
                <p><strong>Generated:</strong> <?php echo esc_html( date( 'M d, Y g:i A', strtotime( $report['created_at'] ) ) ); ?></p>
                <p><strong>Site:</strong> <?php echo esc_html( get_bloginfo( 'name' ) ); ?></p>
            </div>

            <div class="score-section">
                <div class="score"><?php echo esc_html( $score ); ?>/100</div>
                <div class="score-label">Security Score</div>
                <p style="margin-top: 15px; color: #666;">
                    <?php
                    if ( $score >= 80 ) {
                        echo 'Excellent! Your site\'s security is performing well.';
                    } elseif ( $score >= 60 ) {
                        echo 'Good. Your site is secure but there\'s room for improvement.';
                    } else {
                        echo 'Needs Attention! Several security issues require immediate attention.';
                    }
                    ?>
                </p>
            </div>

            <h2>Summary Metrics</h2>
            <div class="metrics">
                <div class="metric">
                    <div class="metric-value"><?php echo esc_html( number_format( $data['summary']['total_events'] ) ); ?></div>
                    <div class="metric-label">Total Events</div>
                </div>
                <div class="metric">
                    <div class="metric-value"><?php echo esc_html( number_format( $data['summary']['failed_logins'] ) ); ?></div>
                    <div class="metric-label">Failed Logins</div>
                </div>
                <div class="metric">
                    <div class="metric-value"><?php echo esc_html( number_format( $data['summary']['successful_logins'] ) ); ?></div>
                    <div class="metric-label">Successful Logins</div>
                </div>
                <div class="metric">
                    <div class="metric-value"><?php echo esc_html( number_format( $data['summary']['blocked_ips'] ) ); ?></div>
                    <div class="metric-label">Blocked IPs</div>
                </div>
                <div class="metric">
                    <div class="metric-value"><?php echo esc_html( number_format( $data['summary']['rate_limited'] ) ); ?></div>
                    <div class="metric-label">Rate Limited</div>
                </div>
                <div class="metric">
                    <div class="metric-value"><?php echo esc_html( number_format( $data['summary']['firewall_blocks'] ) ); ?></div>
                    <div class="metric-label">Firewall Blocks</div>
                </div>
            </div>

            <?php if ( ! empty( $data['top_attackers'] ) ) : ?>
            <h2>Top Attacking IPs</h2>
            <table>
                <thead>
                    <tr>
                        <th>Rank</th>
                        <th>IP Address</th>
                        <th>Incidents</th>
                        <th>Threat Level</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ( array_slice( $data['top_attackers'], 0, 10 ) as $index => $attacker ) : ?>
                        <?php
                        $count = (int) $attacker['count'];
                        $threat_level = $count > 50 ? 'Critical' : ( $count > 20 ? 'High' : ( $count > 10 ? 'Medium' : 'Low' ) );
                        ?>
                        <tr>
                            <td><?php echo esc_html( $index + 1 ); ?></td>
                            <td><code><?php echo esc_html( $attacker['ip_address'] ); ?></code></td>
                            <td><?php echo esc_html( number_format( $count ) ); ?></td>
                            <td><?php echo esc_html( $threat_level ); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>

            <?php if ( ! empty( $data['top_users'] ) ) : ?>
            <h2>Most Active Users</h2>
            <table>
                <thead>
                    <tr>
                        <th>Rank</th>
                        <th>Username</th>
                        <th>Activities</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ( array_slice( $data['top_users'], 0, 10 ) as $index => $user ) : ?>
                        <tr>
                            <td><?php echo esc_html( $index + 1 ); ?></td>
                            <td><?php echo esc_html( $user['user_login'] ); ?></td>
                            <td><?php echo esc_html( number_format( $user['count'] ) ); ?></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <?php endif; ?>

            <div class="footer">
                <p>Generated by Saurity Security Plugin</p>
                <p><?php echo esc_html( home_url() ); ?></p>
                <p class="no-print" style="margin-top: 20px;">
                    <button onclick="window.print()" style="padding: 10px 20px; background: #2196F3; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 14px;">
                        Print / Save as PDF
                    </button>
                </p>
            </div>
        </body>
        </html>
        <?php
    }

    /**
     * Generate CSV export
     *
     * @param array $report Report data.
     */
    private function generate_csv_export( $report ) {
        $data = $report['report_data'];
        $start_date = date( 'Y-m-d', strtotime( $data['period']['start'] ) );
        $filename = 'saurity-security-report-' . $start_date . '.csv';

        header( 'Content-Type: text/csv; charset=utf-8' );
        header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
        header( 'Pragma: no-cache' );
        header( 'Expires: 0' );

        $output = fopen( 'php://output', 'w' );

        // Add BOM for Excel UTF-8 compatibility
        fprintf( $output, chr(0xEF).chr(0xBB).chr(0xBF) );

        // Summary section
        fputcsv( $output, [ 'Security Report Summary' ] );
        fputcsv( $output, [ 'Report Period', date( 'M d, Y', strtotime( $data['period']['start'] ) ) . ' - ' . date( 'M d, Y', strtotime( $data['period']['end'] ) ) ] );
        fputcsv( $output, [ 'Generated', date( 'M d, Y g:i A', strtotime( $report['created_at'] ) ) ] );
        fputcsv( $output, [ 'Security Score', $report['security_score'] . '/100' ] );
        fputcsv( $output, [] );

        // Metrics section
        fputcsv( $output, [ 'Key Metrics' ] );
        fputcsv( $output, [ 'Metric', 'Value' ] );
        fputcsv( $output, [ 'Total Events', $data['summary']['total_events'] ] );
        fputcsv( $output, [ 'Failed Logins', $data['summary']['failed_logins'] ] );
        fputcsv( $output, [ 'Successful Logins', $data['summary']['successful_logins'] ] );
        fputcsv( $output, [ 'Blocked IPs', $data['summary']['blocked_ips'] ] );
        fputcsv( $output, [ 'Rate Limited', $data['summary']['rate_limited'] ] );
        fputcsv( $output, [ 'Firewall Blocks', $data['summary']['firewall_blocks'] ] );
        fputcsv( $output, [] );

        // Event counts
        fputcsv( $output, [ 'Event Types' ] );
        fputcsv( $output, [ 'Type', 'Count' ] );
        fputcsv( $output, [ 'Info', $data['event_counts']['info'] ] );
        fputcsv( $output, [ 'Warning', $data['event_counts']['warning'] ] );
        fputcsv( $output, [ 'Error', $data['event_counts']['error'] ] );
        fputcsv( $output, [ 'Critical', $data['event_counts']['critical'] ] );
        fputcsv( $output, [] );

        // Top attackers
        if ( ! empty( $data['top_attackers'] ) ) {
            fputcsv( $output, [ 'Top Attacking IPs' ] );
            fputcsv( $output, [ 'Rank', 'IP Address', 'Incidents', 'Threat Level' ] );
            foreach ( $data['top_attackers'] as $index => $attacker ) {
                $count = (int) $attacker['count'];
                $threat_level = $count > 50 ? 'Critical' : ( $count > 20 ? 'High' : ( $count > 10 ? 'Medium' : 'Low' ) );
                fputcsv( $output, [ $index + 1, $attacker['ip_address'], $count, $threat_level ] );
            }
            fputcsv( $output, [] );
        }

        // Top users
        if ( ! empty( $data['top_users'] ) ) {
            fputcsv( $output, [ 'Most Active Users' ] );
            fputcsv( $output, [ 'Rank', 'Username', 'Activities' ] );
            foreach ( $data['top_users'] as $index => $user ) {
                fputcsv( $output, [ $index + 1, $user['user_login'], $user['count'] ] );
            }
            fputcsv( $output, [] );
        }

        // Daily stats
        if ( ! empty( $data['daily_stats'] ) ) {
            fputcsv( $output, [ 'Daily Activity' ] );
            fputcsv( $output, [ 'Date', 'Total', 'Warnings', 'Errors', 'Critical' ] );
            foreach ( $data['daily_stats'] as $stat ) {
                fputcsv( $output, [
                    $stat['date'],
                    $stat['total'],
                    $stat['warnings'],
                    $stat['errors'],
                    $stat['critical']
                ] );
            }
        }

        fclose( $output );
    }
}