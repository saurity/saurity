<?php
/**
 * Warning Display System
 *
 * @package Saurity
 */

namespace Saurity;

/**
 * WarningDisplay class - Shows security warnings before blocking
 */
class WarningDisplay {

    /**
     * Client IP
     *
     * @var string
     */
    private $client_ip;

    /**
     * Constructor
     */
    public function __construct() {
        $this->client_ip = $this->get_client_ip();
    }

    /**
     * Hook into WordPress
     */
    public function hook() {
        // Display warnings on login page
        add_action( 'login_enqueue_scripts', [ $this, 'display_login_warnings' ] );
        add_action( 'login_head', [ $this, 'display_login_warning_banner' ] );
    }

    /**
     * Display warning banner on login page
     */
    public function display_login_warning_banner() {
        $warnings = $this->get_active_warnings();
        
        if ( empty( $warnings ) ) {
            return;
        }

        // Display the most critical warning
        $warning = $warnings[0];
        
        ?>
        <style>
            .saurity-warning-banner {
                background: linear-gradient(135deg, #ff9800 0%, #f57c00 100%);
                border-left: 5px solid #e65100;
                padding: 20px;
                margin: 20px 0;
                border-radius: 8px;
                color: white;
                box-shadow: 0 4px 15px rgba(255, 152, 0, 0.3);
                animation: pulse 2s infinite;
            }
            @keyframes pulse {
                0%, 100% { box-shadow: 0 4px 15px rgba(255, 152, 0, 0.3); }
                50% { box-shadow: 0 4px 25px rgba(255, 152, 0, 0.5); }
            }
            .saurity-warning-banner h3 {
                color: white;
                margin: 0 0 10px 0;
                font-size: 20px;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .saurity-warning-banner p {
                margin: 8px 0;
                line-height: 1.6;
                font-size: 14px;
            }
            .saurity-warning-banner strong {
                color: #fff3e0;
                font-size: 16px;
            }
            .saurity-warning-progress {
                background: rgba(255,255,255,0.2);
                height: 8px;
                border-radius: 4px;
                margin: 15px 0 10px 0;
                overflow: hidden;
            }
            .saurity-warning-progress-bar {
                background: #fff;
                height: 100%;
                transition: width 0.3s;
                border-radius: 4px;
            }
            .saurity-warning-stats {
                background: rgba(255,255,255,0.1);
                padding: 12px;
                border-radius: 4px;
                margin-top: 12px;
                font-size: 13px;
            }
        </style>
        <div class="saurity-warning-banner">
            <h3>
                <span style="font-size: 28px;">⚠️</span>
                <?php echo esc_html( $warning['title'] ); ?>
            </h3>
            <p><?php echo esc_html( $warning['message'] ); ?></p>
            
            <?php if ( isset( $warning['attempts'] ) && isset( $warning['threshold'] ) ) : ?>
                <?php 
                $percentage = ( $warning['attempts'] / $warning['threshold'] ) * 100;
                ?>
                <div class="saurity-warning-progress">
                    <div class="saurity-warning-progress-bar" style="width: <?php echo esc_attr( $percentage ); ?>%;"></div>
                </div>
                <div class="saurity-warning-stats">
                    <strong>Status:</strong> <?php echo esc_html( $warning['attempts'] ); ?> of <?php echo esc_html( $warning['threshold'] ); ?> attempts used
                    (<?php echo esc_html( $warning['remaining'] ); ?> remaining)
                </div>
            <?php endif; ?>
            
            <p style="margin-top: 15px; font-size: 13px; opacity: 0.9;">
                <?php echo esc_html( $warning['action'] ); ?>
            </p>
        </div>
        <?php
    }

    /**
     * Get active warnings for current IP
     *
     * @return array Array of warning data
     */
    private function get_active_warnings() {
        $warnings = [];
        
        // Check login rate limit warning (soft limit approaching)
        $login_warning = get_transient( 'saurity_login_warning_' . md5( $this->client_ip ) );
        if ( $login_warning ) {
            $warnings[] = [
                'type' => 'login_soft',
                'title' => 'Login Rate Limit Warning',
                'message' => 'You are approaching the maximum number of login attempts. If you exceed the limit, delays will be applied to your login requests.',
                'attempts' => $login_warning['attempts'],
                'threshold' => $login_warning['threshold'],
                'remaining' => $login_warning['remaining'],
                'action' => '💡 Tip: Double-check your username and password before trying again.',
                'severity' => 2,
            ];
        }

        // Check hard block warning (critical)
        $rate_warning = get_transient( 'saurity_rate_warning_' . md5( $this->client_ip ) );
        if ( $rate_warning ) {
            $warnings[] = [
                'type' => 'hard_block',
                'title' => '🚨 CRITICAL: Hard Block Warning',
                'message' => 'You are very close to being permanently blocked! After ' . $rate_warning['threshold'] . ' failed attempts, your IP will be blocked for 1 hour.',
                'attempts' => $rate_warning['attempts'],
                'threshold' => $rate_warning['threshold'],
                'remaining' => $rate_warning['remaining'],
                'action' => '⚠️ WARNING: Only ' . $rate_warning['remaining'] . ' attempts remaining before 1-hour block!',
                'severity' => 1,
            ];
        }

        // Check POST flood warning
        $post_warning = get_transient( 'saurity_post_warning_' . md5( $this->client_ip ) );
        if ( $post_warning ) {
            $warnings[] = [
                'type' => 'post_flood',
                'title' => 'POST Request Warning',
                'message' => 'You are submitting forms too quickly. Slow down to avoid being blocked.',
                'action' => '💡 Tip: Wait a few seconds between form submissions.',
                'severity' => 3,
            ];
        }

        // Sort by severity (1 = most critical)
        usort( $warnings, function( $a, $b ) {
            return $a['severity'] - $b['severity'];
        } );

        return $warnings;
    }

    /**
     * Display warnings (enqueue inline styles)
     */
    public function display_login_warnings() {
        // Styles are included in display_login_warning_banner()
    }

    /**
     * Get client IP address
     *
     * @return string
     */
    private function get_client_ip() {
        $ip = isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';

        if ( defined( 'SAURITY_BEHIND_PROXY' ) && SAURITY_BEHIND_PROXY ) {
            $headers = [
                'HTTP_CF_CONNECTING_IP',
                'HTTP_X_FORWARDED_FOR',
                'HTTP_X_REAL_IP',
            ];

            foreach ( $headers as $header ) {
                if ( ! empty( $_SERVER[ $header ] ) ) {
                    $ip_list = explode( ',', $_SERVER[ $header ] );
                    $ip = trim( $ip_list[0] );
                    break;
                }
            }
        }

        return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '0.0.0.0';
    }
}