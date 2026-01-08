<?php
/**
 * Email Notifications
 *
 * @package Saurity
 */

namespace Saurity;

/**
 * EmailNotifier class - sends email alerts for critical events
 */
class EmailNotifier {

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
        // Listen to critical events
        add_action( 'saurity_critical_event', [ $this, 'handle_critical_event' ], 10, 2 );
        add_action( 'saurity_security_alert', [ $this, 'handle_security_alert' ], 10, 2 );
    }

    /**
     * Handle critical events
     *
     * @param string $event_type Event type.
     * @param array  $context Event context.
     */
    public function handle_critical_event( $event_type, $context ) {
        if ( ! $this->is_email_enabled() ) {
            return;
        }

        $this->send_notification( $event_type, $context, 'critical' );
    }

    /**
     * Handle security alerts
     *
     * @param string $event_type Event type.
     * @param array  $context Event context.
     */
    public function handle_security_alert( $event_type, $context ) {
        if ( ! $this->is_email_enabled() ) {
            return;
        }

        // Only send if enough time has passed since last notification (prevent spam)
        if ( ! $this->should_send_alert( $event_type ) ) {
            return;
        }

        $this->send_notification( $event_type, $context, 'warning' );
    }

    /**
     * Send email notification
     *
     * @param string $event_type Event type.
     * @param array  $context Event context.
     * @param string $severity Severity level.
     */
    private function send_notification( $event_type, $context, $severity ) {
        $admin_email = get_option( 'admin_email' );
        $site_name = get_bloginfo( 'name' );
        $site_url = get_site_url();

        $subject = sprintf(
            '[%s] %s Security Alert: %s',
            $site_name,
            $severity === 'critical' ? 'CRITICAL' : 'WARNING',
            $event_type
        );

        $message = $this->format_email_message( $event_type, $context, $severity, $site_name, $site_url );

        $headers = [
            'Content-Type: text/html; charset=UTF-8',
            'From: Saurity Security <' . $admin_email . '>',
        ];

        wp_mail( $this->get_notification_email(), $subject, $message, $headers );

        // Update last notification time
        $this->update_last_notification_time( $event_type );
    }

    /**
     * Format email message
     *
     * @param string $event_type Event type.
     * @param array  $context Event context.
     * @param string $severity Severity level.
     * @param string $site_name Site name.
     * @param string $site_url Site URL.
     * @return string
     */
    private function format_email_message( $event_type, $context, $severity, $site_name, $site_url ) {
        $color = $severity === 'critical' ? '#dc3232' : '#ff9800';
        $bg_color = $severity === 'critical' ? '#f8d7da' : '#fff3cd';

        $message = '<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; 
            line-height: 1.6; 
            color: #333; 
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
        }
        .container { 
            max-width: 600px; 
            margin: 20px auto; 
            background: #ffffff;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .header { 
            background: ' . $color . '; 
            color: white; 
            padding: 30px 20px; 
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 24px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .header p {
            margin: 10px 0 0 0;
            font-size: 14px;
            opacity: 0.9;
        }
        .content { 
            padding: 30px 20px;
        }
        .alert-badge {
            display: inline-block;
            background: ' . $bg_color . ';
            color: ' . $color . ';
            padding: 8px 16px;
            border-radius: 4px;
            border-left: 4px solid ' . $color . ';
            font-weight: 600;
            text-transform: uppercase;
            font-size: 12px;
            letter-spacing: 0.5px;
            margin-bottom: 20px;
        }
        .event-title {
            font-size: 20px;
            font-weight: 600;
            color: #333;
            margin: 0 0 20px 0;
        }
        .info-row {
            margin: 12px 0;
            padding: 12px;
            background: #f9f9f9;
            border-left: 3px solid ' . $color . ';
            border-radius: 4px;
        }
        .info-label {
            font-weight: 600;
            color: #555;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .info-value {
            margin-top: 5px;
            font-size: 15px;
            color: #333;
        }
        .button { 
            display: inline-block; 
            padding: 12px 24px; 
            background: #2196F3; 
            color: white !important; 
            text-decoration: none; 
            border-radius: 4px; 
            margin: 20px 0;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 13px;
            letter-spacing: 0.5px;
        }
        .footer { 
            background: #2c3e50; 
            color: #ecf0f1; 
            padding: 20px; 
            text-align: center;
            font-size: 13px;
        }
        .footer p {
            margin: 5px 0;
        }
        .footer a {
            color: #3498db;
            text-decoration: none;
        }
        .note {
            margin-top: 20px;
            padding: 15px;
            background: #e7f3ff;
            border-left: 4px solid #2196F3;
            border-radius: 4px;
            font-size: 13px;
            color: #555;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Saurity Security Alert</h1>
            <p>' . esc_html( $site_name ) . '</p>
        </div>
        <div class="content">
            <div class="alert-badge">' . esc_html( strtoupper( $severity ) ) . ' ALERT</div>
            <h2 class="event-title">' . esc_html( $event_type ) . '</h2>
            
            <div class="info-row">
                <div class="info-label">Event Time</div>
                <div class="info-value">' . date_i18n( 'F j, Y \a\t g:i a' ) . '</div>
            </div>';

        // Add context details
        if ( ! empty( $context['ip'] ) ) {
            $message .= '
            <div class="info-row">
                <div class="info-label">IP Address</div>
                <div class="info-value">' . esc_html( $context['ip'] ) . '</div>
            </div>';
        }

        if ( ! empty( $context['username'] ) ) {
            $message .= '
            <div class="info-row">
                <div class="info-label">Username</div>
                <div class="info-value">' . esc_html( $context['username'] ) . '</div>
            </div>';
        }

        if ( ! empty( $context['message'] ) ) {
            $message .= '
            <div class="info-row">
                <div class="info-label">Details</div>
                <div class="info-value">' . esc_html( $context['message'] ) . '</div>
            </div>';
        }

        if ( ! empty( $context['attempt_count'] ) ) {
            $message .= '
            <div class="info-row">
                <div class="info-label">Failed Attempts</div>
                <div class="info-value">' . esc_html( $context['attempt_count'] ) . '</div>
            </div>';
        }

        $admin_url = admin_url( 'admin.php?page=saurity' );

        $message .= '
            <div style="text-align: center;">
                <a href="' . esc_url( $admin_url ) . '" class="button">View Activity Log</a>
            </div>
            
            <div class="note">
                <strong>Note:</strong> This is an automated security notification from Saurity. 
                You can manage notification settings in the WordPress admin panel under Saurity > Settings > Email Notifications.
            </div>
        </div>
        <div class="footer">
            <p><strong>Saurity Security Plugin</strong></p>
            <p>' . esc_html( $site_name ) . '</p>
            <p><a href="' . esc_url( $site_url ) . '">' . esc_html( $site_url ) . '</a></p>
        </div>
    </div>
</body>
</html>';

        return $message;
    }

    /**
     * Check if email notifications are enabled
     *
     * @return bool
     */
    private function is_email_enabled() {
        return (bool) get_option( 'saurity_email_notifications', true );
    }

    /**
     * Get notification email address
     *
     * @return string
     */
    private function get_notification_email() {
        $email = get_option( 'saurity_notification_email', '' );
        return ! empty( $email ) ? $email : get_option( 'admin_email' );
    }

    /**
     * Check if we should send an alert (rate limiting for emails)
     *
     * @param string $event_type Event type.
     * @return bool
     */
    private function should_send_alert( $event_type ) {
        $last_sent = get_transient( 'saurity_email_sent_' . md5( $event_type ) );
        
        if ( false === $last_sent ) {
            return true;
        }

        // Don't send same alert more than once per 15 minutes
        $cooldown = 900; // 15 minutes
        return ( time() - $last_sent ) > $cooldown;
    }

    /**
     * Update last notification time
     *
     * @param string $event_type Event type.
     */
    private function update_last_notification_time( $event_type ) {
        set_transient( 'saurity_email_sent_' . md5( $event_type ), time(), 3600 );
    }

    /**
     * Send test notification
     *
     * @return bool
     */
    public function send_test_email() {
        $admin_email = get_option( 'admin_email' );
        $notification_email = $this->get_notification_email();
        $site_name = get_bloginfo( 'name' );
        $site_url = get_site_url();
        
        $subject = sprintf( '[%s] Saurity Test Email', $site_name );
        
        $message = '<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; 
            line-height: 1.6; 
            color: #333; 
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
        }
        .container { 
            max-width: 600px; 
            margin: 20px auto; 
            background: #ffffff;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .header { 
            background: #2196F3; 
            color: white; 
            padding: 30px 20px; 
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 24px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .header p {
            margin: 10px 0 0 0;
            font-size: 14px;
            opacity: 0.9;
        }
        .content { 
            padding: 30px 20px;
        }
        .success-badge {
            display: inline-block;
            background: #d4edda;
            color: #28a745;
            padding: 8px 16px;
            border-radius: 4px;
            border-left: 4px solid #28a745;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 12px;
            letter-spacing: 0.5px;
            margin-bottom: 20px;
        }
        .info-row {
            margin: 12px 0;
            padding: 12px;
            background: #f9f9f9;
            border-left: 3px solid #2196F3;
            border-radius: 4px;
        }
        .info-label {
            font-weight: 600;
            color: #555;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .info-value {
            margin-top: 5px;
            font-size: 15px;
            color: #333;
        }
        .feature-list {
            margin: 20px 0;
            padding: 0;
            list-style: none;
        }
        .feature-list li {
            padding: 10px 0;
            border-bottom: 1px solid #e0e0e0;
        }
        .feature-list li:last-child {
            border-bottom: none;
        }
        .footer { 
            background: #2c3e50; 
            color: #ecf0f1; 
            padding: 20px; 
            text-align: center;
            font-size: 13px;
        }
        .footer p {
            margin: 5px 0;
        }
        .footer a {
            color: #3498db;
            text-decoration: none;
        }
        .note {
            margin-top: 20px;
            padding: 15px;
            background: #e7f3ff;
            border-left: 4px solid #2196F3;
            border-radius: 4px;
            font-size: 13px;
            color: #555;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Saurity Test Email</h1>
            <p>' . esc_html( $site_name ) . '</p>
        </div>
        <div class="content">
            <div class="success-badge">Email Configuration Successful</div>
            
            <p style="font-size: 16px; margin: 20px 0;">
                This is a test email from the Saurity Security plugin. If you\'re reading this, your email notifications are working correctly!
            </p>
            
            <div class="info-row">
                <div class="info-label">Recipient</div>
                <div class="info-value">' . esc_html( $notification_email ) . '</div>
            </div>
            
            <div class="info-row">
                <div class="info-label">Test Time</div>
                <div class="info-value">' . date_i18n( 'F j, Y \a\t g:i a' ) . '</div>
            </div>
            
            <h3 style="margin-top: 30px; color: #333;">What This Means:</h3>
            <ul class="feature-list">
                <li>Your WordPress site can send emails successfully</li>
                <li>Saurity email notifications are configured correctly</li>
                <li>You will receive alerts for critical security events</li>
                <li>Email delivery is functioning as expected</li>
            </ul>
            
            <div class="note">
                <strong>Important:</strong> Security alerts are rate-limited to prevent spam. 
                You will receive a maximum of 1 email per event type every 15 minutes. 
                This ensures you stay informed without being overwhelmed by notifications.
            </div>
        </div>
        <div class="footer">
            <p><strong>Saurity Security Plugin</strong></p>
            <p>' . esc_html( $site_name ) . '</p>
            <p><a href="' . esc_url( $site_url ) . '">' . esc_html( $site_url ) . '</a></p>
        </div>
    </div>
</body>
</html>';

        $headers = [
            'Content-Type: text/html; charset=UTF-8',
            'From: Saurity Security <' . $admin_email . '>',
        ];

        $result = wp_mail( $notification_email, $subject, $message, $headers );
        
        return $result;
    }
}