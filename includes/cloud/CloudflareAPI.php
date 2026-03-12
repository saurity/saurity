<?php
/**
 * Cloudflare API Integration
 *
 * Two-way IP sync and security event import
 * ENHANCED: Comprehensive error handling with try-catch blocks
 *
 * @package Saurity
 */

namespace Saurity\Cloud;

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * CloudflareAPI class - manages Cloudflare firewall integration
 */
class CloudflareAPI {

    /**
     * Logger instance
     *
     * @var \Saurity\ActivityLogger
     */
    private $logger;

    /**
     * Cloudflare API base URL
     *
     * @var string
     */
    private $api_base = 'https://api.cloudflare.com/client/v4';

    /**
     * Last error message
     *
     * @var string
     */
    private $last_error = '';

    /**
     * Constructor
     *
     * @param \Saurity\ActivityLogger $logger Logger instance.
     */
    public function __construct( $logger ) {
        $this->logger = $logger;
    }

    /**
     * Get last error message
     *
     * @return string
     */
    public function get_last_error() {
        return $this->last_error;
    }

    /**
     * Sync blocklist with Cloudflare
     *
     * @return array Result.
     */
    public function sync() {
        try {
            // Validate configuration
            $validation = $this->validate_configuration();
            if ( ! $validation['valid'] ) {
                return [
                    'success' => false,
                    'error' => $validation['error'],
                ];
            }

            $pushed = 0;
            $imported = 0;
            $errors = [];

            // Push WordPress blocklist to Cloudflare
            if ( get_option( 'saurity_cloudflare_sync_blocklist', true ) ) {
                try {
                    $push_result = $this->push_blocklist();
                    $pushed = $push_result['count'];
                    if ( ! empty( $push_result['errors'] ) ) {
                        $errors = array_merge( $errors, $push_result['errors'] );
                    }
                } catch ( \Exception $e ) {
                    $this->logger->log( 'error', 'Cloudflare push failed: ' . $e->getMessage() );
                    $errors[] = 'Push failed: ' . $e->getMessage();
                }
            }

            // Import Cloudflare security events
            if ( get_option( 'saurity_cloudflare_import_events', true ) ) {
                try {
                    $imported = $this->import_security_events();
                } catch ( \Exception $e ) {
                    $this->logger->log( 'error', 'Cloudflare import failed: ' . $e->getMessage() );
                    $errors[] = 'Import failed: ' . $e->getMessage();
                }
            }

            // Update last sync timestamp
            $this->update_last_sync();

            return [
                'success' => empty( $errors ),
                'pushed' => $pushed,
                'imported' => $imported,
                'errors' => $errors,
                'error' => ! empty( $errors ) ? implode( '; ', $errors ) : null,
            ];

        } catch ( \Exception $e ) {
            $this->last_error = $e->getMessage();
            $this->logger->log( 'error', 'Cloudflare sync exception: ' . $e->getMessage() );
            
            return [
                'success' => false,
                'error' => 'Sync failed: ' . $e->getMessage(),
            ];
        }
    }

    /**
     * Validate Cloudflare configuration
     *
     * @return array Validation result.
     */
    private function validate_configuration() {
        $api_token = get_option( 'saurity_cloudflare_api_token', '' );
        $zone_id = get_option( 'saurity_cloudflare_zone_id', '' );

        if ( empty( $api_token ) ) {
            return [
                'valid' => false,
                'error' => 'Cloudflare API token is not configured. Go to Cloud Services tab to add your API token.',
            ];
        }

        if ( strlen( $api_token ) < 20 ) {
            return [
                'valid' => false,
                'error' => 'Cloudflare API token appears to be invalid (too short). Please verify your token.',
            ];
        }

        if ( empty( $zone_id ) ) {
            return [
                'valid' => false,
                'error' => 'Cloudflare Zone ID is not configured. Find it in your Cloudflare dashboard under Overview → API section.',
            ];
        }

        if ( ! preg_match( '/^[a-f0-9]{32}$/i', $zone_id ) ) {
            return [
                'valid' => false,
                'error' => 'Cloudflare Zone ID format is invalid. It should be a 32-character hexadecimal string.',
            ];
        }

        return [ 'valid' => true ];
    }

    /**
     * Push WordPress blocklist to Cloudflare
     *
     * @return array Result with count and errors.
     */
    private function push_blocklist() {
        $plugin = \Saurity\Plugin::get_instance();
        $ip_manager = $plugin->get_component( 'ip_manager' );

        if ( ! $ip_manager ) {
            // IP Manager not available - could be disabled or kill switch active
            // This is not an error, just skip blocklist sync
            $this->logger->log( 'info', 'Cloudflare sync: IP Manager not available, skipping blocklist push' );
            return [ 'count' => 0, 'errors' => [] ];
        }

        $blocklist = $ip_manager->get_blocklist();
        
        if ( empty( $blocklist ) ) {
            return [ 'count' => 0, 'errors' => [] ];
        }

        // Normalize blocklist to extract IPs (handles both string and array formats)
        $blocklist_ips = [];
        foreach ( $blocklist as $entry ) {
            if ( is_array( $entry ) && isset( $entry['ip'] ) ) {
                $blocklist_ips[] = $entry['ip'];
            } elseif ( is_string( $entry ) ) {
                $blocklist_ips[] = $entry;
            }
        }

        if ( empty( $blocklist_ips ) ) {
            return [ 'count' => 0, 'errors' => [] ];
        }

        // Get existing Cloudflare IPs
        $cf_ips = $this->get_cloudflare_blocked_ips();

        // Find IPs that need to be added to Cloudflare
        $to_add = array_diff( $blocklist_ips, $cf_ips );

        if ( empty( $to_add ) ) {
            return [ 'count' => 0, 'errors' => [] ];
        }

        // Limit to 50 IPs per sync to prevent timeouts
        $to_add = array_slice( $to_add, 0, 50 );

        $added_count = 0;
        $errors = [];

        foreach ( $to_add as $ip ) {
            try {
                if ( $this->add_firewall_rule( $ip ) ) {
                    $added_count++;
                }
            } catch ( \Exception $e ) {
                $errors[] = "Failed to add {$ip}: " . $e->getMessage();
            }
        }

        return [ 'count' => $added_count, 'errors' => $errors ];
    }

    /**
     * Get IPs currently blocked in Cloudflare
     *
     * @return array IP addresses.
     */
    private function get_cloudflare_blocked_ips() {
        $zone_id = get_option( 'saurity_cloudflare_zone_id', '' );
        $endpoint = "/zones/{$zone_id}/firewall/access_rules/rules";

        $response = $this->make_request( 'GET', $endpoint, [
            'mode' => 'block',
            'per_page' => 100,
        ] );

        if ( ! $response ) {
            return [];
        }

        if ( ! isset( $response['result'] ) || ! is_array( $response['result'] ) ) {
            return [];
        }

        $ips = [];

        foreach ( $response['result'] as $rule ) {
            if ( isset( $rule['configuration']['value'] ) ) {
                $ips[] = $rule['configuration']['value'];
            }
        }

        return $ips;
    }

    /**
     * Block IP in Cloudflare
     *
     * @param string $ip IP address.
     * @param string $reason Block reason.
     * @return bool Success.
     */
    public function block_ip( $ip, $reason = '' ) {
        try {
            return $this->add_firewall_rule( $ip, $reason );
        } catch ( \Exception $e ) {
            $this->last_error = $e->getMessage();
            $this->logger->log( 'error', "Failed to block IP {$ip}: " . $e->getMessage() );
            return false;
        }
    }

    /**
     * Unblock IP in Cloudflare
     *
     * @param string $ip IP address.
     * @return bool Success.
     */
    public function unblock_ip( $ip ) {
        try {
            $zone_id = get_option( 'saurity_cloudflare_zone_id', '' );
            $endpoint = "/zones/{$zone_id}/firewall/access_rules/rules";

            $response = $this->make_request( 'GET', $endpoint, [
                'mode' => 'block',
                'configuration_value' => $ip,
            ] );

            if ( ! $response || ! isset( $response['result'][0]['id'] ) ) {
                throw new \Exception( "IP {$ip} not found in Cloudflare blocklist" );
            }

            $rule_id = $response['result'][0]['id'];
            $delete_endpoint = "/zones/{$zone_id}/firewall/access_rules/rules/{$rule_id}";

            $delete_response = $this->make_request( 'DELETE', $delete_endpoint );

            if ( ! isset( $delete_response['success'] ) || ! $delete_response['success'] ) {
                $error = $delete_response['errors'][0]['message'] ?? 'Unknown error';
                throw new \Exception( "Failed to remove IP: {$error}" );
            }

            $this->logger->log( 'info', "IP {$ip} removed from Cloudflare firewall" );
            return true;

        } catch ( \Exception $e ) {
            $this->last_error = $e->getMessage();
            $this->logger->log( 'error', $e->getMessage() );
            return false;
        }
    }

    /**
     * Add firewall rule to Cloudflare
     *
     * @param string $ip IP address.
     * @param string $notes Notes/reason.
     * @return bool Success.
     * @throws \Exception On failure.
     */
    private function add_firewall_rule( $ip, $notes = '' ) {
        // Validate IP format
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) && ! $this->validate_cidr( $ip ) ) {
            throw new \Exception( esc_html( "Invalid IP format: {$ip}" ) );
        }

        $zone_id = get_option( 'saurity_cloudflare_zone_id', '' );
        $endpoint = "/zones/{$zone_id}/firewall/access_rules/rules";

        $data = [
            'mode' => 'block',
            'configuration' => [
                'target' => 'ip',
                'value' => $ip,
            ],
            'notes' => ! empty( $notes ) ? $notes : 'Blocked by Saurity Shield',
        ];

        $response = $this->make_request( 'POST', $endpoint, $data );

        if ( ! $response ) {
            // Include the actual error from make_request
            $error_detail = $this->last_error ?: 'No response from Cloudflare API';
            throw new \Exception( esc_html( $error_detail ) );
        }

        if ( isset( $response['success'] ) && $response['success'] ) {
            $this->logger->log( 'info', "IP {$ip} added to Cloudflare firewall" );
            return true;
        }

        // Handle specific error codes
        if ( isset( $response['errors'][0] ) ) {
            $error = $response['errors'][0];
            $error_code = $error['code'] ?? 0;
            $error_message = $error['message'] ?? 'Unknown error';

            // Handle "already exists" error gracefully
            if ( $error_code === 10009 || strpos( $error_message, 'already exists' ) !== false ) {
                // Not an error - IP already blocked
                return true;
            }

            throw new \Exception( esc_html( "Cloudflare error {$error_code}: {$error_message}" ) );
        }

        throw new \Exception( 'Unknown Cloudflare API error' );
    }

    /**
     * Validate CIDR notation
     *
     * @param string $cidr CIDR string.
     * @return bool
     */
    private function validate_cidr( $cidr ) {
        if ( strpos( $cidr, '/' ) === false ) {
            return false;
        }

        list( $ip, $prefix ) = explode( '/', $cidr, 2 );
        
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
            return false;
        }

        $prefix = (int) $prefix;
        return $prefix >= 0 && $prefix <= 32;
    }

    /**
     * Import security events from Cloudflare
     *
     * Note: The security events API may not be available on all Cloudflare plans.
     * Free plans may have limited or no access to this endpoint.
     *
     * @return int Number of events imported.
     */
    private function import_security_events() {
        $zone_id = get_option( 'saurity_cloudflare_zone_id', '' );
        
        // Try the newer firewall events endpoint first (available on more plans)
        // Then fall back to security events if that fails
        $endpoints_to_try = [
            "/zones/{$zone_id}/firewall/events" => 'firewall events',
            "/zones/{$zone_id}/security/events" => 'security events',
        ];

        // Get events from last hour
        $since = gmdate( 'Y-m-d\TH:i:s\Z', strtotime( '-1 hour' ) );
        
        $response = null;
        $used_endpoint = '';
        
        foreach ( $endpoints_to_try as $endpoint => $endpoint_name ) {
            $response = $this->make_request( 'GET', $endpoint, [
                'since' => $since,
                'per_page' => 50,
            ] );
            
            if ( $response !== false ) {
                $used_endpoint = $endpoint_name;
                break;
            }
        }

        if ( ! $response ) {
            // Include the actual error from make_request
            $error_detail = $this->last_error ?: 'Failed to fetch security events';
            
            // Check if this is a plan limitation or endpoint not available
            if ( strpos( $error_detail, 'Permission denied' ) !== false || 
                 strpos( $error_detail, '403' ) !== false ||
                 strpos( $error_detail, '7003' ) !== false ||
                 strpos( $error_detail, 'Could not route' ) !== false ||
                 strpos( $error_detail, '404' ) !== false ) {
                throw new \Exception( 'Security events API is not available on Cloudflare Free plans. Please disable "Import Cloudflare Security Events" in Cloud Services settings.' );
            }
            
            throw new \Exception( esc_html( $error_detail ) );
        }

        if ( ! isset( $response['result'] ) || ! is_array( $response['result'] ) ) {
            // No events is not an error
            return 0;
        }

        $imported_count = 0;

        foreach ( $response['result'] as $event ) {
            // Skip if not a blocked event
            if ( empty( $event['action'] ) || $event['action'] !== 'block' ) {
                continue;
            }

            $ip = $event['source']['ip'] ?? '';
            $ray_id = $event['ray_id'] ?? '';
            $reason = $event['rule_id'] ?? 'Unknown';

            if ( empty( $ip ) ) {
                continue;
            }

            // Log the event
            $this->logger->log(
                'info',
                "Cloudflare blocked IP: {$ip}",
                [
                    'ip' => $ip,
                    'ray_id' => $ray_id,
                    'reason' => $reason,
                    'source' => 'cloudflare',
                ]
            );

            $imported_count++;
        }

        return $imported_count;
    }

    /**
     * Make API request to Cloudflare with comprehensive error handling
     *
     * @param string $method HTTP method.
     * @param string $endpoint API endpoint.
     * @param array  $data Request data.
     * @return array|false Response or false on failure.
     */
    private function make_request( $method, $endpoint, $data = [] ) {
        $api_token = get_option( 'saurity_cloudflare_api_token', '' );

        if ( empty( $api_token ) ) {
            $this->last_error = 'API token not configured';
            return false;
        }

        $url = $this->api_base . $endpoint;
        $args = [
            'method' => $method,
            'timeout' => 30, // Increased timeout
            'headers' => [
                'Authorization' => 'Bearer ' . $api_token,
                'Content-Type' => 'application/json',
            ],
        ];

        if ( $method === 'GET' && ! empty( $data ) ) {
            $url .= '?' . http_build_query( $data );
        } elseif ( in_array( $method, [ 'POST', 'PUT', 'PATCH' ], true ) && ! empty( $data ) ) {
            $args['body'] = wp_json_encode( $data );
        }

        $response = wp_remote_request( $url, $args );

        // Handle WordPress HTTP errors
        if ( is_wp_error( $response ) ) {
            $error_message = $response->get_error_message();
            $this->last_error = $error_message;
            $this->logger->log( 'error', 'Cloudflare API request failed: ' . $error_message );
            return false;
        }

        // Check HTTP status code
        $status_code = wp_remote_retrieve_response_code( $response );
        
        if ( $status_code === 0 ) {
            $this->last_error = 'Network error: Could not connect to Cloudflare';
            $this->logger->log( 'error', 'Cloudflare API: Network connection failed' );
            return false;
        }

        if ( $status_code >= 500 ) {
            $this->last_error = "Cloudflare server error (HTTP {$status_code})";
            $this->logger->log( 'error', "Cloudflare API: Server error {$status_code}" );
            return false;
        }

        if ( $status_code === 401 ) {
            $this->last_error = 'Authentication failed. Please verify your API token.';
            $this->logger->log( 'error', 'Cloudflare API: Invalid API token (401)' );
            return false;
        }

        if ( $status_code === 403 ) {
            // Provide specific guidance based on the endpoint being called
            if ( strpos( $endpoint, 'access_rules' ) !== false ) {
                $this->last_error = 'Permission denied. Your API token needs "Zone > Firewall Services > Edit" permission. Please update your token at dash.cloudflare.com/profile/api-tokens';
            } elseif ( strpos( $endpoint, 'security/events' ) !== false ) {
                $this->last_error = 'Permission denied. Your API token needs "Zone > Analytics > Read" permission for security events. Please update your token at dash.cloudflare.com/profile/api-tokens';
            } else {
                $this->last_error = 'Permission denied. API token may not have required permissions.';
            }
            $this->logger->log( 'error', 'Cloudflare API: Permission denied (403) - ' . $this->last_error );
            return false;
        }

        // Handle other 4xx errors (400, 404, 429, etc.)
        if ( $status_code >= 400 && $status_code < 500 ) {
            $body = wp_remote_retrieve_body( $response );
            $decoded = json_decode( $body, true );
            
            // Try to extract Cloudflare error message
            if ( isset( $decoded['errors'][0]['message'] ) ) {
                $cf_error = $decoded['errors'][0]['message'];
                $cf_code = $decoded['errors'][0]['code'] ?? $status_code;
                $this->last_error = "Cloudflare error ({$cf_code}): {$cf_error}";
            } else {
                $this->last_error = "Cloudflare API error (HTTP {$status_code})";
            }
            
            $this->logger->log( 'error', "Cloudflare API: HTTP {$status_code} - " . $this->last_error );
            return false;
        }

        // Parse response body
        $body = wp_remote_retrieve_body( $response );

        if ( empty( $body ) ) {
            $this->last_error = 'Empty response from Cloudflare';
            return false;
        }

        $decoded = json_decode( $body, true );

        if ( json_last_error() !== JSON_ERROR_NONE ) {
            $this->last_error = 'Invalid JSON response from Cloudflare';
            $this->logger->log( 'error', 'Cloudflare API: Invalid JSON response' );
            return false;
        }

        return $decoded;
    }

    /**
     * Test Cloudflare connection
     *
     * @return array Result with success status and message.
     */
    public function test_connection() {
        try {
            // First validate configuration
            $validation = $this->validate_configuration();
            if ( ! $validation['valid'] ) {
                return [
                    'success' => false,
                    'message' => $validation['error'],
                ];
            }

            $zone_id = get_option( 'saurity_cloudflare_zone_id', '' );
            $endpoint = "/zones/{$zone_id}";

            $response = $this->make_request( 'GET', $endpoint );

            if ( ! $response ) {
                return [
                    'success' => false,
                    'message' => $this->last_error ?: 'Failed to connect to Cloudflare API',
                ];
            }

            if ( isset( $response['success'] ) && $response['success'] ) {
                $zone_name = $response['result']['name'] ?? 'Unknown';
                $zone_status = $response['result']['status'] ?? 'unknown';
                
                return [
                    'success' => true,
                    'message' => "Connected to zone: {$zone_name} (Status: {$zone_status})",
                    'zone_name' => $zone_name,
                    'zone_status' => $zone_status,
                ];
            }

            // Handle specific Cloudflare errors
            if ( isset( $response['errors'][0] ) ) {
                $error = $response['errors'][0];
                $error_code = $error['code'] ?? 0;
                $error_message = $error['message'] ?? 'Unknown error';

                // Provide helpful messages for common errors
                switch ( $error_code ) {
                    case 7000:
                    case 7003:
                        return [
                            'success' => false,
                            'message' => 'Zone not found. Please verify your Zone ID is correct.',
                        ];
                    case 9103:
                        return [
                            'success' => false,
                            'message' => 'Invalid API token. Please generate a new token from Cloudflare dashboard.',
                        ];
                    case 9109:
                        return [
                            'success' => false,
                            'message' => 'API token does not have permission to access this zone.',
                        ];
                    default:
                        return [
                            'success' => false,
                            'message' => "Cloudflare error ({$error_code}): {$error_message}",
                        ];
                }
            }

            return [
                'success' => false,
                'message' => 'Unknown error occurred while testing connection',
            ];

        } catch ( \Exception $e ) {
            return [
                'success' => false,
                'message' => 'Exception: ' . $e->getMessage(),
            ];
        }
    }

    /**
     * Get Cloudflare statistics
     *
     * @return array Statistics.
     */
    public function get_statistics() {
        try {
            $zone_id = get_option( 'saurity_cloudflare_zone_id', '' );

            // Get firewall rules count
            $rules_endpoint = "/zones/{$zone_id}/firewall/access_rules/rules";
            $rules_response = $this->make_request( 'GET', $rules_endpoint, [
                'mode' => 'block',
                'per_page' => 1,
            ] );

            $blocked_ips_count = 0;
            
            if ( $rules_response && isset( $rules_response['result_info']['total_count'] ) ) {
                $blocked_ips_count = (int) $rules_response['result_info']['total_count'];
            }

            // Get security events count (last 24 hours)
            $events_endpoint = "/zones/{$zone_id}/security/events";
            $since = gmdate( 'Y-m-d\TH:i:s\Z', strtotime( '-24 hours' ) );
            
            $events_response = $this->make_request( 'GET', $events_endpoint, [
                'since' => $since,
                'per_page' => 1,
            ] );

            $events_count = 0;
            
            if ( $events_response && isset( $events_response['result_info']['total_count'] ) ) {
                $events_count = (int) $events_response['result_info']['total_count'];
            }

            return [
                'blocked_ips' => $blocked_ips_count,
                'events_24h' => $events_count,
                'last_sync' => get_option( 'saurity_cloudflare_last_sync', 'Never' ),
                'error' => null,
            ];

        } catch ( \Exception $e ) {
            return [
                'blocked_ips' => 0,
                'events_24h' => 0,
                'last_sync' => get_option( 'saurity_cloudflare_last_sync', 'Never' ),
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Update last sync timestamp
     */
    public function update_last_sync() {
        update_option( 'saurity_cloudflare_last_sync', current_time( 'mysql' ) );
    }
}