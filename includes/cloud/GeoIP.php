<?php
/**
 * GeoIP Integration
 *
 * Country-based blocking and analytics with MaxMind GeoLite2
 *
 * @package Saurity
 */

namespace Saurity\Cloud;

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * GeoIP class - handles geographic IP lookups and blocking
 */
class GeoIP {

    /**
     * Logger instance
     *
     * @var \Saurity\ActivityLogger
     */
    private $logger;

    /**
     * Database path
     *
     * @var string
     */
    private $db_path;

    /**
     * Countries data (ISO code => Name mapping)
     *
     * @var array
     */
    private static $countries = [
        'US' => 'United States',
        'CN' => 'China',
        'RU' => 'Russia',
        'IN' => 'India',
        'BR' => 'Brazil',
        'GB' => 'United Kingdom',
        'DE' => 'Germany',
        'FR' => 'France',
        'JP' => 'Japan',
        'CA' => 'Canada',
        'AU' => 'Australia',
        'KR' => 'South Korea',
        'IT' => 'Italy',
        'ES' => 'Spain',
        'MX' => 'Mexico',
        'ID' => 'Indonesia',
        'NL' => 'Netherlands',
        'SA' => 'Saudi Arabia',
        'TR' => 'Turkey',
        'CH' => 'Switzerland',
        'PL' => 'Poland',
        'BE' => 'Belgium',
        'SE' => 'Sweden',
        'NG' => 'Nigeria',
        'AR' => 'Argentina',
        'NO' => 'Norway',
        'AT' => 'Austria',
        'AE' => 'United Arab Emirates',
        'IL' => 'Israel',
        'IE' => 'Ireland',
        'PK' => 'Pakistan',
        'MY' => 'Malaysia',
        'SG' => 'Singapore',
        'DK' => 'Denmark',
        'HK' => 'Hong Kong',
        'FI' => 'Finland',
        'CL' => 'Chile',
        'CO' => 'Colombia',
        'ZA' => 'South Africa',
        'TH' => 'Thailand',
        'PH' => 'Philippines',
        'EG' => 'Egypt',
        'VN' => 'Vietnam',
        'BD' => 'Bangladesh',
        'RO' => 'Romania',
        'CZ' => 'Czech Republic',
        'PT' => 'Portugal',
        'GR' => 'Greece',
        'NZ' => 'New Zealand',
        'UA' => 'Ukraine',
        'HU' => 'Hungary',
        'KP' => 'North Korea',
        'IR' => 'Iran',
    ];

    /**
     * Constructor
     *
     * @param \Saurity\ActivityLogger $logger Logger instance.
     */
    public function __construct( $logger ) {
        $this->logger = $logger;
        $this->db_path = WP_CONTENT_DIR . '/uploads/saurity/geoip/';

        // Create directory if it doesn't exist
        if ( ! file_exists( $this->db_path ) ) {
            wp_mkdir_p( $this->db_path );
        }
    }

    /**
     * Lookup IP address and return geographic data
     *
     * @param string $ip IP address.
     * @return array|false Geographic data or false on failure.
     */
    public function lookup( $ip ) {
        // Check cache first (24 hour TTL)
        $cache_key = 'geoip_' . $ip;
        $cached = \Saurity\CloudIntegration::get_cache( $cache_key, 'geoip' );
        
        if ( $cached !== false ) {
            return $cached;
        }

        // Get provider
        $provider = get_option( 'saurity_geoip_provider', 'maxmind' );

        $result = false;

        if ( $provider === 'maxmind' ) {
            $result = $this->lookup_maxmind( $ip );
        } elseif ( $provider === 'ipapi' ) {
            $result = $this->lookup_ipapi( $ip );
        }

        // Cache result for 24 hours
        if ( $result ) {
            \Saurity\CloudIntegration::set_cache( $cache_key, 'geoip', $result, 86400 );
        }

        return $result;
    }

    /**
     * Check if IP is from a blocked country
     *
     * @param string $ip IP address.
     * @return bool True if blocked.
     */
    public function is_country_blocked( $ip ) {
        $geo_data = $this->lookup( $ip );
        
        if ( ! $geo_data || empty( $geo_data['country_code'] ) ) {
            return false; // Unknown country, don't block
        }

        $country_code = $geo_data['country_code'];
        $mode = get_option( 'saurity_geoip_mode', 'blocklist' );
        
        if ( $mode === 'blocklist' ) {
            // Blocklist mode: Check if country is in blocked list
            $blocked_countries = get_option( 'saurity_geoip_blocked_countries', [] );
            
            // Ensure it's an array (WordPress may return string/empty)
            if ( ! is_array( $blocked_countries ) ) {
                $blocked_countries = [];
            }
            
            return in_array( $country_code, $blocked_countries, true );
        } else {
            // Allowlist mode: Check if country is NOT in allowed list
            $allowed_countries = get_option( 'saurity_geoip_allowed_countries', [] );
            
            // Ensure it's an array
            if ( ! is_array( $allowed_countries ) ) {
                $allowed_countries = [];
            }
            
            return ! in_array( $country_code, $allowed_countries, true );
        }
    }

    /**
     * Lookup using MaxMind GeoLite2 database
     *
     * @param string $ip IP address.
     * @return array|false
     */
    private function lookup_maxmind( $ip ) {
        // Check if MaxMind Reader class is available
        if ( ! class_exists( 'GeoIp2\Database\Reader' ) ) {
            return $this->lookup_ipapi( $ip ); // Fallback to API
        }

        $db_file = $this->db_path . 'GeoLite2-Country.mmdb';
        
        if ( ! file_exists( $db_file ) ) {
            return $this->lookup_ipapi( $ip ); // Fallback to API
        }

        try {
            $reader = new \GeoIp2\Database\Reader( $db_file );
            $record = $reader->country( $ip );
            
            $country_code = $record->country->isoCode;
            
            return [
                'country_code' => $country_code,
                'country_name' => $this->get_country_name( $country_code ),
                'flag' => $this->get_flag_emoji( $country_code ),
            ];
        } catch ( \Exception $e ) {
            $this->logger->log( 'error', 'MaxMind lookup failed: ' . $e->getMessage() );
            return $this->lookup_ipapi( $ip ); // Fallback to API
        }
    }

    /**
     * Lookup using IP-API.com (free tier)
     *
     * @param string $ip IP address.
     * @return array|false
     */
    private function lookup_ipapi( $ip ) {
        // Don't lookup local IPs
        if ( $this->is_local_ip( $ip ) ) {
            return [
                'country_code' => 'XX',
                'country_name' => 'Local Network',
                'flag' => '🏠',
            ];
        }

        // Rate limit: Max 45 requests per minute (free tier)
        $rate_key = 'ipapi_rate_' . gmdate( 'YmdHi' );
        $rate_count = get_transient( $rate_key );
        
        if ( $rate_count && $rate_count >= 45 ) {
            return false; // Rate limit exceeded
        }

        try {
            $response = wp_remote_get(
                'http://ip-api.com/json/' . $ip . '?fields=status,message,country,countryCode',
                [
                    'timeout' => 3,
                    'sslverify' => false,
                ]
            );

            if ( is_wp_error( $response ) ) {
                return false;
            }

            $body = wp_remote_retrieve_body( $response );
            $data = json_decode( $body, true );

            if ( ! $data || $data['status'] !== 'success' ) {
                return false;
            }

            // Update rate limit counter
            set_transient( $rate_key, ( $rate_count ? $rate_count + 1 : 1 ), 60 );

            return [
                'country_code' => $data['countryCode'],
                'country_name' => $data['country'],
                'flag' => $this->get_flag_emoji( $data['countryCode'] ),
            ];
        } catch ( \Exception $e ) {
            $this->logger->log( 'error', 'IP-API lookup failed: ' . $e->getMessage() );
            return false;
        }
    }

    /**
     * Check if IP is a local/private IP
     *
     * @param string $ip IP address.
     * @return bool
     */
    private function is_local_ip( $ip ) {
        return ! filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        );
    }

    /**
     * Get country name from ISO code
     *
     * @param string $code ISO country code.
     * @return string
     */
    public static function get_country_name( $code ) {
        return self::$countries[ $code ] ?? $code;
    }

    /**
     * Get flag emoji from ISO country code
     *
     * @param string $code ISO country code (2 letters).
     * @return string Flag emoji.
     */
    public static function get_flag_emoji( $code ) {
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
     * Get all available countries
     *
     * @return array
     */
    public static function get_all_countries() {
        return self::$countries;
    }

    /**
     * Update MaxMind GeoLite2 database
     *
     * @return array Result with success status and message.
     */
    public function update_database() {
        $license_key = get_option( 'saurity_geoip_license_key', '' );
        
        if ( empty( $license_key ) ) {
            return [
                'success' => false,
                'error' => 'MaxMind license key not configured',
            ];
        }

        // Download URL for GeoLite2 Country database
        $download_url = sprintf(
            'https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=%s&suffix=tar.gz',
            $license_key
        );

        $temp_file = $this->db_path . 'geoip_temp.tar.gz';

        // Download database
        $response = wp_remote_get(
            $download_url,
            [
                'timeout' => 60,
                'stream' => true,
                'filename' => $temp_file,
            ]
        );

        if ( is_wp_error( $response ) ) {
            return [
                'success' => false,
                'error' => $response->get_error_message(),
            ];
        }

        // Extract .mmdb file from tar.gz
        try {
            $phar = new \PharData( $temp_file );
            $phar->extractTo( $this->db_path, null, true );

            // Find the .mmdb file in extracted folder
            $files = glob( $this->db_path . '*/GeoLite2-Country.mmdb' );
            
            if ( empty( $files ) ) {
                return [
                    'success' => false,
                    'error' => 'Database file not found in archive',
                ];
            }

            // Move to main directory using WP_Filesystem
            global $wp_filesystem;
            if ( empty( $wp_filesystem ) ) {
                require_once ABSPATH . 'wp-admin/includes/file.php';
                WP_Filesystem();
            }
            $wp_filesystem->move( $files[0], $this->db_path . 'GeoLite2-Country.mmdb', true );

            // Cleanup using WordPress functions
            wp_delete_file( $temp_file );
            $this->cleanup_extracted_files();

            return [
                'success' => true,
                'message' => 'GeoIP database updated successfully',
            ];
        } catch ( \Exception $e ) {
            return [
                'success' => false,
                'error' => 'Failed to extract database: ' . $e->getMessage(),
            ];
        }
    }

    /**
     * Cleanup extracted files and folders
     */
    private function cleanup_extracted_files() {
        $dirs = glob( $this->db_path . 'GeoLite2-Country_*', GLOB_ONLYDIR );
        
        foreach ( $dirs as $dir ) {
            $this->delete_directory( $dir );
        }
    }

    /**
     * Recursively delete directory using WP_Filesystem
     *
     * @param string $dir Directory path.
     */
    private function delete_directory( $dir ) {
        if ( ! file_exists( $dir ) ) {
            return;
        }

        global $wp_filesystem;
        if ( empty( $wp_filesystem ) ) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
            WP_Filesystem();
        }

        // Use WP_Filesystem to recursively delete directory
        $wp_filesystem->delete( $dir, true );
    }

    /**
     * Get geographic statistics for dashboard
     *
     * @param int $days Number of days to analyze.
     * @return array Statistics.
     */
    public function get_statistics( $days = 7 ) {
        global $wpdb;
        $table = $wpdb->prefix . 'saurity_logs';

        $since = gmdate( 'Y-m-d H:i:s', strtotime( "-{$days} days" ) );

        // Get logs with country data
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Direct DB required for security logs, results change frequently
        $logs = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT context FROM {$wpdb->prefix}saurity_logs WHERE created_at >= %s AND event_type IN ('warning', 'error')",
                $since
            )
        );

        $countries = [];
        $total = 0;

        foreach ( $logs as $log ) {
            $context = maybe_unserialize( $log->context );
            
            if ( ! empty( $context['country'] ) ) {
                $code = $context['country'];
                
                if ( ! isset( $countries[ $code ] ) ) {
                    $countries[ $code ] = [
                        'code' => $code,
                        'name' => $context['country_name'] ?? self::get_country_name( $code ),
                        'flag' => $context['flag'] ?? self::get_flag_emoji( $code ),
                        'count' => 0,
                    ];
                }
                
                $countries[ $code ]['count']++;
                $total++;
            }
        }

        // Sort by count descending
        usort( $countries, function( $a, $b ) {
            return $b['count'] - $a['count'];
        });

        return [
            'total_attacks' => $total,
            'unique_countries' => count( $countries ),
            'top_countries' => array_slice( $countries, 0, 10 ),
            'all_countries' => $countries,
        ];
    }
}