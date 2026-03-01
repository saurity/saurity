<?php
/**
 * Cloud Integration Orchestrator
 *
 * Manages Cloudflare, Threat Intelligence, and GeoIP integrations
 *
 * @package Saurity
 */



namespace Saurity;
// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * CloudIntegration class - orchestrates all cloud services
 */
class CloudIntegration {

    /**
     * Logger instance
     *
     * @var ActivityLogger
     */
    private $logger;

    /**
     * GeoIP instance
     *
     * @var \Saurity\Cloud\GeoIP
     */
    private $geoip;

    /**
     * Threat Intelligence instance
     *
     * @var \Saurity\Cloud\ThreatIntelligence
     */
    private $threat_intel;

    /**
     * Cloudflare API instance
     * DISABLED: Cloudflare integration commented out
     *
     * @var \Saurity\Cloud\CloudflareAPI
     */
    // private $cloudflare;

    /**
     * Constructor
     *
     * @param ActivityLogger $logger Logger instance.
     */
    public function __construct( ActivityLogger $logger ) {
        $this->logger = $logger;

        // Initialize cloud services if enabled (only if cloud files exist)
        // Wrapped in try-catch to prevent any initialization errors
        try {
            if ( $this->is_geoip_enabled() && file_exists( SAURITY_PATH . 'includes/cloud/GeoIP.php' ) ) {
                require_once SAURITY_PATH . 'includes/cloud/GeoIP.php';
                if ( class_exists( '\Saurity\Cloud\GeoIP' ) ) {
                    $this->geoip = new \Saurity\Cloud\GeoIP( $logger );
                }
            }
        } catch ( \Exception $e ) {
            // Silently fail - GeoIP is optional. Error is intentionally not logged.
            unset( $e );
        }

        try {
            if ( $this->is_threat_intel_enabled() && file_exists( SAURITY_PATH . 'includes/cloud/ThreatIntelligence.php' ) ) {
                require_once SAURITY_PATH . 'includes/cloud/ThreatIntelligence.php';
                if ( class_exists( '\Saurity\Cloud\ThreatIntelligence' ) ) {
                    $this->threat_intel = new \Saurity\Cloud\ThreatIntelligence( $logger );
                }
            }
        } catch ( \Exception $e ) {
            // Silently fail - Threat Intel is optional. Error is intentionally not logged.
            unset( $e );
        }

        // DISABLED: Cloudflare integration commented out
        // try {
        //     if ( $this->is_cloudflare_enabled() && file_exists( SAURITY_PATH . 'includes/cloud/CloudflareAPI.php' ) ) {
        //         require_once SAURITY_PATH . 'includes/cloud/CloudflareAPI.php';
        //         if ( class_exists( '\Saurity\Cloud\CloudflareAPI' ) ) {
        //             $this->cloudflare = new \Saurity\Cloud\CloudflareAPI( $logger );
        //         }
        //     }
        // } catch ( \Exception $e ) {
        //     // Silently fail - Cloudflare is optional
        //     if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
        //         error_log( 'Saurity Cloudflare init failed: ' . $e->getMessage() );
        //     }
        // }
    }

    /**
     * Hook into WordPress
     */
    public function hook() {
        // Register cron job actions
        add_action( 'saurity_update_threat_feeds', [ $this, 'update_threat_feeds' ] );
        // DISABLED: Cloudflare integration commented out
        // add_action( 'saurity_sync_cloudflare', [ $this, 'sync_cloudflare' ] );
        add_action( 'saurity_update_geoip_database', [ $this, 'update_geoip_database' ] );
        add_action( 'saurity_cleanup_cloud_cache', [ $this, 'cleanup_cache_cron' ] );

        // Schedule cron jobs on init
        add_action( 'init', [ $this, 'schedule_cron_jobs' ] );

        // Hook into existing security checks
        add_filter( 'saurity_check_ip_country', [ $this, 'check_country_block' ], 10, 2 );
        add_filter( 'saurity_enrich_log_data', [ $this, 'enrich_with_geoip' ], 10, 2 );

        // Hook into IP management changes
        // DISABLED: Cloudflare integration commented out
        // add_action( 'saurity_ip_blocked', [ $this, 'on_ip_blocked' ], 10, 2 );
        // add_action( 'saurity_ip_unblocked', [ $this, 'on_ip_unblocked' ], 10, 1 );
    }

    /**
     * Check if IP is from a blocked country
     *
     * Filter callback for 'saurity_check_ip_country'.
     * Note: WordPress filters pass the "value to filter" as the first parameter.
     * First param is the default (false), second param is the IP to check.
     *
     * @param bool   $should_block Default result (false = don't block).
     * @param string $ip IP address to check.
     * @return bool True if should be blocked, false otherwise.
     */
    public function check_country_block( $should_block, $ip = '' ) {
        // If GeoIP is not enabled or not initialized, don't block
        if ( ! $this->is_geoip_enabled() || ! $this->geoip ) {
            return false;
        }

        // Validate IP parameter
        if ( empty( $ip ) || ! is_string( $ip ) ) {
            return false;
        }

        // Check if country is blocked
        $is_blocked = $this->geoip->is_country_blocked( $ip );

        return $is_blocked;
    }

    /**
     * Enrich log data with GeoIP information
     *
     * @param array  $context Log context.
     * @param string $ip IP address.
     * @return array Enriched context.
     */
    public function enrich_with_geoip( $context, $ip ) {
        if ( ! $this->is_geoip_enabled() || ! $this->geoip ) {
            return $context;
        }

        if ( ! get_option( 'saurity_geoip_show_flags', true ) ) {
            return $context;
        }

        $geo_data = $this->geoip->lookup( $ip );
        if ( $geo_data ) {
            $context['country'] = $geo_data['country_code'];
            $context['country_name'] = $geo_data['country_name'];
            $context['flag'] = $geo_data['flag'];
        }

        return $context;
    }

    /**
     * Handle IP blocked event - sync to Cloudflare
     * DISABLED: Cloudflare integration commented out
     *
     * @param string $ip IP address.
     * @param string $reason Block reason.
     */
    // public function on_ip_blocked( $ip, $reason ) {
    //     if ( ! $this->is_cloudflare_enabled() || ! $this->cloudflare ) {
    //         return;
    //     }
    //
    //     if ( ! get_option( 'saurity_cloudflare_sync_blocklist', true ) ) {
    //         return;
    //     }
    //
    //     // Add to Cloudflare asynchronously
    //     $this->cloudflare->block_ip( $ip, $reason );
    // }

    /**
     * Handle IP unblocked event - sync to Cloudflare
     * DISABLED: Cloudflare integration commented out
     *
     * @param string $ip IP address.
     */
    // public function on_ip_unblocked( $ip ) {
    //     if ( ! $this->is_cloudflare_enabled() || ! $this->cloudflare ) {
    //         return;
    //     }
    //
    //     if ( ! get_option( 'saurity_cloudflare_sync_blocklist', true ) ) {
    //         return;
    //     }
    //
    //     // Remove from Cloudflare asynchronously
    //     $this->cloudflare->unblock_ip( $ip );
    // }

    /**
     * Update threat intelligence feeds (cron job)
     */
    public function update_threat_feeds() {
        if ( ! $this->is_threat_intel_enabled() || ! $this->threat_intel ) {
            return;
        }

        $this->logger->log( 'info', 'Updating threat intelligence feeds' );
        $result = $this->threat_intel->update_all_feeds();
        
        $this->logger->log(
            'info',
            sprintf(
                'Threat feeds updated: %d new IPs added, %d removed',
                $result['added'],
                $result['removed']
            )
        );
    }

    /**
     * Sync with Cloudflare (cron job)
     * DISABLED: Cloudflare integration commented out
     */
    // public function sync_cloudflare() {
    //     if ( ! $this->is_cloudflare_enabled() || ! $this->cloudflare ) {
    //         return;
    //     }
    //
    //     $this->logger->log( 'info', 'Syncing with Cloudflare' );
    //     $result = $this->cloudflare->sync();
    //     
    //     if ( $result['success'] ) {
    //         $this->logger->log(
    //             'info',
    //             sprintf(
    //                 'Cloudflare sync complete: %d IPs pushed, %d events imported',
    //                 $result['pushed'],
    //                 $result['imported']
    //             )
    //         );
    //     } else {
    //         $this->logger->log(
    //             'error',
    //             'Cloudflare sync failed: ' . $result['error']
    //         );
    //     }
    // }

    /**
     * Update GeoIP database (cron job)
     */
    public function update_geoip_database() {
        if ( ! $this->is_geoip_enabled() || ! $this->geoip ) {
            return;
        }

        $this->logger->log( 'info', 'Updating GeoIP database' );
        $result = $this->geoip->update_database();
        
        if ( $result['success'] ) {
            $this->logger->log( 'info', 'GeoIP database updated successfully' );
        } else {
            $this->logger->log( 'error', 'GeoIP database update failed: ' . $result['error'] );
        }
    }

    /**
     * Get GeoIP instance
     *
     * @return \Saurity\Cloud\GeoIP|null
     */
    public function get_geoip() {
        return $this->geoip;
    }

    /**
     * Get Threat Intelligence instance
     *
     * @return \Saurity\Cloud\ThreatIntelligence|null
     */
    public function get_threat_intel() {
        return $this->threat_intel;
    }

    /**
     * Get Cloudflare API instance
     * DISABLED: Cloudflare integration commented out
     *
     * @return \Saurity\Cloud\CloudflareAPI|null
     */
    public function get_cloudflare() {
        // return $this->cloudflare;
        return null;
    }

    /**
     * Check if GeoIP is enabled
     *
     * @return bool
     */
    private function is_geoip_enabled() {
        return (bool) get_option( 'saurity_geoip_enabled', false );
    }

    /**
     * Check if Threat Intelligence is enabled
     *
     * @return bool
     */
    private function is_threat_intel_enabled() {
        return (bool) get_option( 'saurity_threat_feeds_enabled', false );
    }

    /**
     * Check if Cloudflare is enabled
     * DISABLED: Cloudflare integration commented out
     *
     * @return bool
     */
    private function is_cloudflare_enabled() {
        // return (bool) get_option( 'saurity_cloudflare_enabled', false );
        return false;
    }

    /**
     * Get cache from database
     *
     * @param string $key Cache key.
     * @param string $type Cache type.
     * @return mixed|false Cached data or false if not found/expired.
     */
    public static function get_cache( $key, $type ) {
        global $wpdb;
        $table = $wpdb->prefix . 'saurity_cloud_cache';

        // Check if table exists
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name safe (uses $wpdb->prefix), direct DB required for cache
        if ( $wpdb->get_var( "SHOW TABLES LIKE '{$table}'" ) !== $table ) {
            return false;
        }

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Direct DB required for cache
        $row = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT cache_data, expires_at FROM {$wpdb->prefix}saurity_cloud_cache 
                WHERE cache_key = %s AND cache_type = %s AND expires_at > NOW()",
                $key,
                $type
            )
        );

        if ( ! $row ) {
            return false;
        }

        return maybe_unserialize( $row->cache_data );
    }

    /**
     * Set cache in database
     *
     * @param string $key Cache key.
     * @param string $type Cache type.
     * @param mixed  $data Data to cache.
     * @param int    $ttl Time to live in seconds.
     * @return bool Success.
     */
    public static function set_cache( $key, $type, $data, $ttl = 3600 ) {
        global $wpdb;
        $table = $wpdb->prefix . 'saurity_cloud_cache';

        // Check if table exists
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name safe (uses $wpdb->prefix), direct DB required for cache
        if ( $wpdb->get_var( "SHOW TABLES LIKE '{$table}'" ) !== $table ) {
            return false;
        }

        // Delete existing cache
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Direct DB required for cache
        $wpdb->delete(
            $table,
            [
                'cache_key' => $key,
                'cache_type' => $type,
            ]
        );

        // Insert new cache
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Direct DB required for cache
        return $wpdb->insert(
            $table,
            [
                'cache_key' => $key,
                'cache_type' => $type,
                'cache_data' => maybe_serialize( $data ),
                'expires_at' => gmdate( 'Y-m-d H:i:s', time() + $ttl ),
                'created_at' => current_time( 'mysql' ),
            ]
        ) !== false;
    }

    /**
     * Clear expired cache entries
     */
    public static function cleanup_cache() {
        global $wpdb;
        $table = $wpdb->prefix . 'saurity_cloud_cache';

        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name safe (uses $wpdb->prefix), direct DB required for cache
        if ( $wpdb->get_var( "SHOW TABLES LIKE '{$table}'" ) !== $table ) {
            return;
        }

        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name safe (uses $wpdb->prefix), direct DB required for cleanup
        $wpdb->query( "DELETE FROM {$table} WHERE expires_at < NOW()" );
    }

    /**
     * Cleanup cache cron job wrapper
     * 
     * GDPR Note: Removes expired cached data. No personal data is stored.
     */
    public function cleanup_cache_cron() {
        self::cleanup_cache();
    }

    /**
     * Schedule cron jobs for cloud services
     * 
     * GDPR Compliance Note:
     * Scheduled tasks process IP addresses for security purposes only.
     * - GeoIP: Lookups are cached locally (24h), no external transmission with MaxMind
     * - Threat Feeds: Only public IP addresses, no personal data
     * - Cloudflare: Data already shared if using Cloudflare proxy
     * - Cache: Auto-deleted after TTL expires
     * 
     * Data retention: Logs follow configurable retention policy (default 15 days)
     */
    public function schedule_cron_jobs() {
        // Threat feed updates
        if ( $this->is_threat_intel_enabled() ) {
            $interval = get_option( 'saurity_threat_feeds_update_interval', 'daily' );
            if ( ! wp_next_scheduled( 'saurity_update_threat_feeds' ) ) {
                wp_schedule_event( time(), $interval, 'saurity_update_threat_feeds' );
            }
        } else {
            // Unschedule if disabled
            $timestamp = wp_next_scheduled( 'saurity_update_threat_feeds' );
            if ( $timestamp ) {
                wp_unschedule_event( $timestamp, 'saurity_update_threat_feeds' );
            }
        }

        // DISABLED: Cloudflare integration commented out
        // Cloudflare sync (hourly)
        // if ( $this->is_cloudflare_enabled() && get_option( 'saurity_cloudflare_sync_blocklist', true ) ) {
        //     if ( ! wp_next_scheduled( 'saurity_sync_cloudflare' ) ) {
        //         wp_schedule_event( time(), 'hourly', 'saurity_sync_cloudflare' );
        //     }
        // } else {
        //     $timestamp = wp_next_scheduled( 'saurity_sync_cloudflare' );
        //     if ( $timestamp ) {
        //         wp_unschedule_event( $timestamp, 'saurity_sync_cloudflare' );
        //     }
        // }
        // Unschedule any existing Cloudflare cron
        $timestamp = wp_next_scheduled( 'saurity_sync_cloudflare' );
        if ( $timestamp ) {
            wp_unschedule_event( $timestamp, 'saurity_sync_cloudflare' );
        }

        // GeoIP database update (monthly)
        if ( $this->is_geoip_enabled() && get_option( 'saurity_geoip_provider', 'maxmind' ) === 'maxmind' ) {
            if ( ! wp_next_scheduled( 'saurity_update_geoip_database' ) ) {
                wp_schedule_event( time(), 'monthly', 'saurity_update_geoip_database' );
            }
        } else {
            $timestamp = wp_next_scheduled( 'saurity_update_geoip_database' );
            if ( $timestamp ) {
                wp_unschedule_event( $timestamp, 'saurity_update_geoip_database' );
            }
        }

        // Cache cleanup (daily)
        if ( ! wp_next_scheduled( 'saurity_cleanup_cloud_cache' ) ) {
            wp_schedule_event( time(), 'daily', 'saurity_cleanup_cloud_cache' );
        }
    }
}
