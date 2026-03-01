<?php
/**
 * Privacy Policy Integration
 *
 * GDPR compliance features for Saurity
 *
 * @package Saurity
 */

namespace Saurity;

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * PrivacyPolicy class - handles GDPR compliance features
 */
class PrivacyPolicy {

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
        // Add privacy policy content suggestion
        add_action( 'admin_init', [ $this, 'add_privacy_policy_content' ] );

        // Register data exporter
        add_filter( 'wp_privacy_personal_data_exporters', [ $this, 'register_data_exporter' ] );

        // Register data eraser
        add_filter( 'wp_privacy_personal_data_erasers', [ $this, 'register_data_eraser' ] );
    }

    /**
     * Add privacy policy content suggestion
     */
    public function add_privacy_policy_content() {
        if ( ! function_exists( 'wp_add_privacy_policy_content' ) ) {
            return;
        }

        $content = $this->get_privacy_policy_content();

        wp_add_privacy_policy_content(
            'Saurity Security',
            wp_kses_post( $content )
        );
    }

    /**
     * Get privacy policy content
     *
     * @return string HTML content.
     */
    private function get_privacy_policy_content() {
        $content = '<h2>' . __( 'Security Monitoring', 'saurity' ) . '</h2>';

        $content .= '<p>' . __( 'This website uses Saurity Security plugin to protect against malicious attacks and unauthorized access.', 'saurity' ) . '</p>';

        $content .= '<h3>' . __( 'What data we collect', 'saurity' ) . '</h3>';
        $content .= '<p>' . __( 'For security purposes, we may collect and store:', 'saurity' ) . '</p>';
        $content .= '<ul>';
        $content .= '<li>' . __( 'IP addresses of visitors', 'saurity' ) . '</li>';
        $content .= '<li>' . __( 'Browser information (user agent strings)', 'saurity' ) . '</li>';
        $content .= '<li>' . __( 'Login attempt details (username, timestamp, success/failure)', 'saurity' ) . '</li>';
        $content .= '<li>' . __( 'Security event timestamps', 'saurity' ) . '</li>';
        $content .= '</ul>';

        $content .= '<h3>' . __( 'Why we collect this data', 'saurity' ) . '</h3>';
        $content .= '<p>' . __( 'This data is collected to:', 'saurity' ) . '</p>';
        $content .= '<ul>';
        $content .= '<li>' . __( 'Protect against brute force attacks', 'saurity' ) . '</li>';
        $content .= '<li>' . __( 'Detect and block malicious traffic', 'saurity' ) . '</li>';
        $content .= '<li>' . __( 'Investigate security incidents', 'saurity' ) . '</li>';
        $content .= '<li>' . __( 'Comply with legal requirements', 'saurity' ) . '</li>';
        $content .= '</ul>';

        $content .= '<h3>' . __( 'Legal basis', 'saurity' ) . '</h3>';
        $content .= '<p>' . sprintf(
            /* translators: %s: GDPR article reference */
            __( 'The legal basis for processing this data is legitimate interest in website security (%s).', 'saurity' ),
            'GDPR Article 6.1(f)'
        ) . '</p>';

        $content .= '<h3>' . __( 'Data retention', 'saurity' ) . '</h3>';
        $retention_days = get_option( 'saurity_log_retention_days', 15 );
        $content .= '<p>' . sprintf(
            /* translators: %d: number of days */
            __( 'Security logs are automatically deleted after %d days.', 'saurity' ),
            $retention_days
        ) . '</p>';

        $content .= '<h3>' . __( 'Third-party services', 'saurity' ) . '</h3>';

        // Check which optional services are enabled
        $cloudflare_enabled = get_option( 'saurity_cloudflare_enabled', false );
        $threat_feeds_enabled = get_option( 'saurity_threat_feeds_enabled', false );
        $geoip_enabled = get_option( 'saurity_geoip_enabled', false );
        $geoip_provider = get_option( 'saurity_geoip_provider', 'maxmind' );

        if ( ! $cloudflare_enabled && ! $threat_feeds_enabled && ! $geoip_enabled ) {
            $content .= '<p>' . __( 'This website does not share security data with any third-party services.', 'saurity' ) . '</p>';
        } else {
            $content .= '<p>' . __( 'The following optional third-party services may be used:', 'saurity' ) . '</p>';
            $content .= '<ul>';

            if ( $cloudflare_enabled ) {
                $content .= '<li>' . __( '<strong>Cloudflare:</strong> Blocked IP addresses may be synced with Cloudflare firewall for enhanced protection.', 'saurity' ) . '</li>';
            }

            if ( $threat_feeds_enabled ) {
                $content .= '<li>' . __( '<strong>Threat Intelligence Feeds:</strong> Public blocklists are downloaded to protect against known malicious IPs. No personal data is sent.', 'saurity' ) . '</li>';
            }

            if ( $geoip_enabled && $geoip_provider === 'ipapi' ) {
                $content .= '<li>' . __( '<strong>IP-API.com:</strong> IP addresses may be sent to determine geographic location for country-based blocking.', 'saurity' ) . '</li>';
            }

            $content .= '</ul>';
        }

        $content .= '<h3>' . __( 'Your rights', 'saurity' ) . '</h3>';
        $content .= '<p>' . __( 'You may request access to, correction of, or deletion of your personal data by contacting the site administrator.', 'saurity' ) . '</p>';

        return $content;
    }

    /**
     * Register data exporter
     *
     * @param array $exporters Existing exporters.
     * @return array Modified exporters.
     */
    public function register_data_exporter( $exporters ) {
        $exporters['saurity'] = [
            'exporter_friendly_name' => __( 'Saurity Security Logs', 'saurity' ),
            'callback' => [ $this, 'export_personal_data' ],
        ];

        return $exporters;
    }

    /**
     * Export personal data
     *
     * @param string $email_address User's email address.
     * @param int    $page Page number.
     * @return array Export data.
     */
    public function export_personal_data( $email_address, $page = 1 ) {
        global $wpdb;

        $data_to_export = [];
        $per_page = 100;
        $offset = ( $page - 1 ) * $per_page;

        // Get user by email
        $user = get_user_by( 'email', $email_address );

        if ( ! $user ) {
            return [
                'data' => [],
                'done' => true,
            ];
        }

        $log_table = $wpdb->prefix . 'saurity_logs';

        // Get logs for this user
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Direct DB required for GDPR export
        $logs = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT event_type, message, ip_address, user_agent, created_at 
                FROM {$wpdb->prefix}saurity_logs 
                WHERE user_login = %s 
                ORDER BY created_at DESC 
                LIMIT %d OFFSET %d",
                $user->user_login,
                $per_page,
                $offset
            )
        );

        if ( ! empty( $logs ) ) {
            $export_items = [];

            foreach ( $logs as $log ) {
                $export_items[] = [
                    'group_id' => 'saurity-logs',
                    'group_label' => __( 'Security Logs', 'saurity' ),
                    'item_id' => 'log-' . md5( $log->created_at . $log->ip_address ),
                    'data' => [
                        [
                            'name' => __( 'Date', 'saurity' ),
                            'value' => $log->created_at,
                        ],
                        [
                            'name' => __( 'Event Type', 'saurity' ),
                            'value' => $log->event_type,
                        ],
                        [
                            'name' => __( 'Message', 'saurity' ),
                            'value' => $log->message,
                        ],
                        [
                            'name' => __( 'IP Address', 'saurity' ),
                            'value' => $log->ip_address ?: __( 'Not recorded', 'saurity' ),
                        ],
                        [
                            'name' => __( 'User Agent', 'saurity' ),
                            'value' => $log->user_agent ?: __( 'Not recorded', 'saurity' ),
                        ],
                    ],
                ];
            }

            $data_to_export = $export_items;
        }

        $done = count( $logs ) < $per_page;

        return [
            'data' => $data_to_export,
            'done' => $done,
        ];
    }

    /**
     * Register data eraser
     *
     * @param array $erasers Existing erasers.
     * @return array Modified erasers.
     */
    public function register_data_eraser( $erasers ) {
        $erasers['saurity'] = [
            'eraser_friendly_name' => __( 'Saurity Security Logs', 'saurity' ),
            'callback' => [ $this, 'erase_personal_data' ],
        ];

        return $erasers;
    }

    /**
     * Erase personal data
     *
     * @param string $email_address User's email address.
     * @param int    $page Page number.
     * @return array Erase result.
     */
    public function erase_personal_data( $email_address, $page = 1 ) {
        global $wpdb;

        $items_removed = 0;
        $items_retained = 0;
        $messages = [];

        // Get user by email
        $user = get_user_by( 'email', $email_address );

        if ( ! $user ) {
            return [
                'items_removed' => 0,
                'items_retained' => 0,
                'messages' => [],
                'done' => true,
            ];
        }

        $log_table = $wpdb->prefix . 'saurity_logs';

        // Count logs for this user
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Direct DB required for GDPR erasure
        $count = $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$wpdb->prefix}saurity_logs WHERE user_login = %s",
                $user->user_login
            )
        );

        if ( $count > 0 ) {
            // Delete logs for this user
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Direct DB required for GDPR erasure
            $deleted = $wpdb->delete(
                $log_table,
                [ 'user_login' => $user->user_login ],
                [ '%s' ]
            );

            if ( false !== $deleted ) {
                $items_removed = $deleted;
                $messages[] = sprintf(
                    /* translators: %d: number of records deleted */
                    __( 'Deleted %d security log entries.', 'saurity' ),
                    $deleted
                );

                // Log the erasure (without personal data)
                $this->logger->log(
                    'info',
                    'Personal data erased via GDPR request'
                );
            }
        }

        // Also check IP allowlist/blocklist for this user's additions
        // We retain these as they are security configurations, not personal data
        // But we notify the user
        $allowlist = get_option( 'saurity_ip_allowlist', [] );
        $blocklist = get_option( 'saurity_ip_blocklist', [] );

        $user_added_allowlist = 0;
        $user_added_blocklist = 0;

        foreach ( $allowlist as $entry ) {
            if ( isset( $entry['added_by'] ) && $entry['added_by'] === $user->user_login ) {
                $user_added_allowlist++;
            }
        }

        foreach ( $blocklist as $entry ) {
            if ( isset( $entry['added_by'] ) && $entry['added_by'] === $user->user_login ) {
                $user_added_blocklist++;
            }
        }

        if ( $user_added_allowlist > 0 || $user_added_blocklist > 0 ) {
            $items_retained = $user_added_allowlist + $user_added_blocklist;
            $messages[] = sprintf(
                /* translators: %d: number of IP rules retained */
                __( '%d IP rules added by this user were retained for security purposes.', 'saurity' ),
                $items_retained
            );
        }

        return [
            'items_removed' => $items_removed,
            'items_retained' => $items_retained,
            'messages' => $messages,
            'done' => true,
        ];
    }
}