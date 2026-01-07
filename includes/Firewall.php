<?php
/**
 * Lightweight Firewall
 *
 * @package Saurity
 */

namespace Saurity;

/**
 * Firewall class - minimal rules for obvious abuse
 */
class Firewall {

    /**
     * Logger instance
     *
     * @var ActivityLogger
     */
    private $logger;

    /**
     * Client IP
     *
     * @var string
     */
    private $client_ip;

    /**
     * Constructor
     *
     * @param ActivityLogger $logger Logger instance.
     */
    public function __construct( ActivityLogger $logger ) {
        $this->logger = $logger;
        $this->client_ip = $this->get_client_ip();
    }

    /**
     * Hook into WordPress
     */
    public function hook() {
        add_action( 'init', [ $this, 'check_request' ], 0 );
    }

    /**
     * Check incoming request
     */
    public function check_request() {
        // Block XML-RPC brute force
        if ( $this->is_xmlrpc_abuse() ) {
            $this->block( 'XML-RPC abuse detected' );
        }

        // Block POST flood
        if ( $this->is_post_flood() ) {
            $this->block( 'POST flood detected' );
        }

        // Block access to sensitive paths
        if ( $this->is_sensitive_path() ) {
            $this->block( 'Access to sensitive path blocked' );
        }

        // Block method abuse
        if ( $this->is_method_abuse() ) {
            $this->block( 'HTTP method abuse detected' );
        }
    }

    /**
     * Check for XML-RPC abuse
     *
     * @return bool
     */
    private function is_xmlrpc_abuse() {
        if ( ! defined( 'XMLRPC_REQUEST' ) || ! XMLRPC_REQUEST ) {
            return false;
        }

        // Check for rapid XML-RPC requests
        $key = 'saurity_xmlrpc_' . md5( $this->client_ip );
        $requests = get_transient( $key );

        if ( false === $requests ) {
            $requests = 0;
        }

        $requests++;
        set_transient( $key, $requests, 60 ); // 1 minute window

        // Block if more than 10 XML-RPC requests per minute
        if ( $requests > 10 ) {
            return true;
        }

        return false;
    }

    /**
     * Check for POST flood
     *
     * @return bool
     */
    private function is_post_flood() {
        if ( $_SERVER['REQUEST_METHOD'] !== 'POST' ) {
            return false;
        }

        // Ignore legitimate POST requests
        if ( is_admin() || is_user_logged_in() ) {
            return false;
        }

        // Ignore comment submissions and other legitimate forms
        if ( isset( $_POST['comment'] ) || isset( $_POST['wp-submit'] ) ) {
            return false;
        }

        // Check for rapid POST requests
        $key = 'saurity_post_' . md5( $this->client_ip );
        $requests = get_transient( $key );

        if ( false === $requests ) {
            $requests = 0;
        }

        $requests++;
        set_transient( $key, $requests, 60 ); // 1 minute window

        // Block if more than 30 POST requests per minute
        if ( $requests > 30 ) {
            return true;
        }

        return false;
    }

    /**
     * Check for sensitive path access
     *
     * @return bool
     */
    private function is_sensitive_path() {
        $request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';

        if ( empty( $request_uri ) ) {
            return false;
        }

        // List of sensitive paths that shouldn't exist
        $blocked_paths = [
            '/.env',
            '/.git',
            '/config.php',
            '/configuration.php',
            '/phpmyadmin',
            '/admin/config.php',
            '/.aws/',
            '/.ssh/',
        ];

        foreach ( $blocked_paths as $path ) {
            if ( strpos( $request_uri, $path ) !== false ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check for HTTP method abuse
     *
     * @return bool
     */
    private function is_method_abuse() {
        $method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : 'GET';

        // Block unusual methods
        $allowed_methods = [ 'GET', 'POST', 'HEAD', 'OPTIONS' ];
        
        if ( ! in_array( $method, $allowed_methods, true ) ) {
            return true;
        }

        // Block POST to obviously GET-only endpoints
        if ( $method === 'POST' ) {
            $request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
            
            // Block POST to static file endpoints
            $static_extensions = [ '.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf' ];
            
            foreach ( $static_extensions as $ext ) {
                if ( substr( $request_uri, -strlen( $ext ) ) === $ext ) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Block the request
     *
     * @param string $reason Reason for blocking.
     */
    private function block( $reason ) {
        $this->logger->log(
            'warning',
            $reason,
            [ 'ip' => $this->client_ip ]
        );

        // Return 403 Forbidden
        status_header( 403 );
        nocache_headers();
        
        echo '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1></body></html>';
        
        exit;
    }

    /**
     * Get client IP address
     *
     * @return string
     */
    private function get_client_ip() {
        $headers = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'REMOTE_ADDR',
        ];

        foreach ( $headers as $header ) {
            if ( ! empty( $_SERVER[ $header ] ) ) {
                $ip = sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) );
                
                if ( strpos( $ip, ',' ) !== false ) {
                    $ips = array_map( 'trim', explode( ',', $ip ) );
                    $ip = $ips[0];
                }

                if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
                    return $ip;
                }
            }
        }

        return '0.0.0.0';
    }
}