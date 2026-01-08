<?php
/**
 * IP Manager - Allowlist/Blocklist Management
 *
 * @package Saurity
 */

namespace Saurity;

/**
 * IPManager class - manages IP allowlist and blocklist
 */
class IPManager {

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
     * Check if IP is in allowlist (supports CIDR)
     *
     * @param string $ip IP address.
     * @return bool
     */
    public function is_allowed( $ip ) {
        $allowlist = $this->get_allowlist();
        
        // Check exact match first
        if ( in_array( $ip, $allowlist, true ) ) {
            return true;
        }
        
        // Check CIDR ranges
        foreach ( $allowlist as $entry ) {
            if ( $this->ip_in_cidr( $ip, $entry ) ) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Check if IP is in permanent blocklist (supports CIDR)
     *
     * @param string $ip IP address.
     * @return bool
     */
    public function is_blocked( $ip ) {
        $blocklist = $this->get_blocklist();
        
        // Check exact match first
        if ( in_array( $ip, $blocklist, true ) ) {
            return true;
        }
        
        // Check CIDR ranges
        foreach ( $blocklist as $entry ) {
            if ( $this->ip_in_cidr( $ip, $entry ) ) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Add IP or CIDR range to allowlist
     *
     * @param string $ip IP address or CIDR range.
     * @param string $note Optional note.
     * @return bool|string True on success, error message string on failure.
     */
    public function add_to_allowlist( $ip, $note = '' ) {
        $ip = trim( $ip );
        
        // Validate IP or CIDR
        if ( ! $this->validate_ip_or_cidr( $ip ) ) {
            return 'invalid_ip';
        }

        $allowlist = $this->get_allowlist();
        $blocklist = $this->get_blocklist();
        
        // Check if already in allowlist
        if ( in_array( $ip, $allowlist, true ) ) {
            return 'already_in_allowlist';
        }

        // Check if IP is in blocklist
        if ( in_array( $ip, $blocklist, true ) ) {
            return 'already_in_blocklist';
        }

        $allowlist[] = $ip;
        update_option( 'saurity_ip_allowlist', $allowlist );

        // Save metadata
        $metadata = $this->get_allowlist_metadata();
        $metadata[ $ip ] = [
            'note' => $note,
            'added' => current_time( 'mysql' ),
            'added_by' => wp_get_current_user()->user_login,
        ];
        update_option( 'saurity_ip_allowlist_meta', $metadata );

        $this->logger->log( 'info', "IP/CIDR {$ip} added to allowlist" . ( $note ? ": {$note}" : '' ) );

        return true;
    }

    /**
     * Add IP or CIDR range to blocklist
     *
     * @param string $ip IP address or CIDR range.
     * @param string $reason Reason for blocking.
     * @return bool|string True on success, error message string on failure.
     */
    public function add_to_blocklist( $ip, $reason = '' ) {
        $ip = trim( $ip );
        
        // Validate IP or CIDR
        if ( ! $this->validate_ip_or_cidr( $ip ) ) {
            return 'invalid_ip';
        }

        $allowlist = $this->get_allowlist();
        $blocklist = $this->get_blocklist();
        
        // Check if already in blocklist
        if ( in_array( $ip, $blocklist, true ) ) {
            return 'already_in_blocklist';
        }

        // Check if IP is in allowlist
        if ( in_array( $ip, $allowlist, true ) ) {
            return 'already_in_allowlist';
        }

        $blocklist[] = $ip;
        update_option( 'saurity_ip_blocklist', $blocklist );

        // Save metadata
        $metadata = $this->get_blocklist_metadata();
        $metadata[ $ip ] = [
            'reason' => $reason,
            'added' => current_time( 'mysql' ),
            'added_by' => wp_get_current_user()->user_login,
        ];
        update_option( 'saurity_ip_blocklist_meta', $metadata );

        $this->logger->log( 'warning', "IP/CIDR {$ip} added to permanent blocklist" . ( $reason ? ": {$reason}" : '' ) );

        // Trigger email notification
        do_action( 'saurity_security_alert', 'IP Added to Blocklist', [
            'ip' => $ip,
            'message' => "IP/CIDR {$ip} has been permanently blocked." . ( $reason ? " Reason: {$reason}" : '' ),
        ] );

        return true;
    }

    /**
     * Remove IP from allowlist
     *
     * @param string $ip IP address.
     * @return bool
     */
    public function remove_from_allowlist( $ip ) {
        $allowlist = $this->get_allowlist();
        $key = array_search( $ip, $allowlist, true );

        if ( false === $key ) {
            return false; // Not in list
        }

        unset( $allowlist[ $key ] );
        update_option( 'saurity_ip_allowlist', array_values( $allowlist ) );

        // Remove metadata
        $metadata = $this->get_allowlist_metadata();
        unset( $metadata[ $ip ] );
        update_option( 'saurity_ip_allowlist_meta', $metadata );

        $this->logger->log( 'info', "IP {$ip} removed from allowlist" );

        return true;
    }

    /**
     * Remove IP from blocklist
     *
     * @param string $ip IP address.
     * @return bool
     */
    public function remove_from_blocklist( $ip ) {
        $blocklist = $this->get_blocklist();
        $key = array_search( $ip, $blocklist, true );

        if ( false === $key ) {
            return false; // Not in list
        }

        unset( $blocklist[ $key ] );
        update_option( 'saurity_ip_blocklist', array_values( $blocklist ) );

        // Remove metadata
        $metadata = $this->get_blocklist_metadata();
        unset( $metadata[ $ip ] );
        update_option( 'saurity_ip_blocklist_meta', $metadata );

        $this->logger->log( 'info', "IP {$ip} removed from blocklist" );

        return true;
    }

    /**
     * Get allowlist
     *
     * @return array
     */
    public function get_allowlist() {
        return get_option( 'saurity_ip_allowlist', [] );
    }

    /**
     * Get blocklist
     *
     * @return array
     */
    public function get_blocklist() {
        return get_option( 'saurity_ip_blocklist', [] );
    }

    /**
     * Get allowlist metadata
     *
     * @return array
     */
    public function get_allowlist_metadata() {
        return get_option( 'saurity_ip_allowlist_meta', [] );
    }

    /**
     * Get blocklist metadata
     *
     * @return array
     */
    public function get_blocklist_metadata() {
        return get_option( 'saurity_ip_blocklist_meta', [] );
    }

    /**
     * Get current user's IP
     *
     * @return string
     */
    public function get_current_ip() {
        $ip = '';

        if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
            $ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
        } elseif ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
            $ip = explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] )[0];
        } elseif ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
            $ip = $_SERVER['REMOTE_ADDR'];
        }

        return sanitize_text_field( trim( $ip ) );
    }

    /**
     * Validate IP address or CIDR range
     *
     * @param string $ip IP address or CIDR range.
     * @return bool
     */
    private function validate_ip_or_cidr( $ip ) {
        // Check if it's a CIDR range
        if ( strpos( $ip, '/' ) !== false ) {
            return $this->validate_cidr( $ip );
        }
        
        // Check if it's a valid IP
        return filter_var( $ip, FILTER_VALIDATE_IP ) !== false;
    }

    /**
     * Validate CIDR notation
     *
     * @param string $cidr CIDR notation (e.g., 192.168.1.0/24).
     * @return bool
     */
    private function validate_cidr( $cidr ) {
        $parts = explode( '/', $cidr );
        
        if ( count( $parts ) !== 2 ) {
            return false;
        }
        
        list( $ip, $prefix ) = $parts;
        
        // Validate IP part
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
            return false;
        }
        
        // Validate prefix (0-32 for IPv4)
        $prefix = intval( $prefix );
        if ( $prefix < 0 || $prefix > 32 ) {
            return false;
        }
        
        return true;
    }

    /**
     * Check if IP is within CIDR range
     *
     * @param string $ip IP address to check.
     * @param string $cidr CIDR notation or single IP.
     * @return bool
     */
    private function ip_in_cidr( $ip, $cidr ) {
        // If not CIDR notation, do exact match
        if ( strpos( $cidr, '/' ) === false ) {
            return $ip === $cidr;
        }
        
        list( $subnet, $prefix ) = explode( '/', $cidr );
        
        // Convert to long integers
        $ip_long = ip2long( $ip );
        $subnet_long = ip2long( $subnet );
        
        if ( $ip_long === false || $subnet_long === false ) {
            return false;
        }
        
        // Calculate network mask
        $mask = -1 << ( 32 - (int) $prefix );
        
        // Check if IP is in subnet
        return ( $ip_long & $mask ) === ( $subnet_long & $mask );
    }

    /**
     * Export allowlist to CSV
     *
     * @return string CSV content.
     */
    public function export_allowlist_csv() {
        $allowlist = $this->get_allowlist();
        $metadata = $this->get_allowlist_metadata();
        
        $output = fopen( 'php://temp', 'r+' );
        
        // Add BOM for Excel UTF-8 compatibility
        fprintf( $output, chr(0xEF).chr(0xBB).chr(0xBF) );
        
        // Headers
        fputcsv( $output, [ 'IP/CIDR', 'Note', 'Added Date', 'Added By' ] );
        
        // Data
        foreach ( $allowlist as $ip ) {
            $meta = $metadata[ $ip ] ?? [];
            fputcsv( $output, [
                $ip,
                $meta['note'] ?? '',
                $meta['added'] ?? '',
                $meta['added_by'] ?? ''
            ] );
        }
        
        rewind( $output );
        $csv = stream_get_contents( $output );
        fclose( $output );
        
        return $csv;
    }

    /**
     * Export blocklist to CSV
     *
     * @return string CSV content.
     */
    public function export_blocklist_csv() {
        $blocklist = $this->get_blocklist();
        $metadata = $this->get_blocklist_metadata();
        
        $output = fopen( 'php://temp', 'r+' );
        
        // Add BOM for Excel UTF-8 compatibility
        fprintf( $output, chr(0xEF).chr(0xBB).chr(0xBF) );
        
        // Headers
        fputcsv( $output, [ 'IP/CIDR', 'Reason', 'Added Date', 'Added By' ] );
        
        // Data
        foreach ( $blocklist as $ip ) {
            $meta = $metadata[ $ip ] ?? [];
            fputcsv( $output, [
                $ip,
                $meta['reason'] ?? '',
                $meta['added'] ?? '',
                $meta['added_by'] ?? ''
            ] );
        }
        
        rewind( $output );
        $csv = stream_get_contents( $output );
        fclose( $output );
        
        return $csv;
    }

    /**
     * Import IPs from CSV to allowlist
     *
     * @param string $csv_content CSV file content.
     * @return array Result with success count and errors.
     */
    public function import_allowlist_csv( $csv_content ) {
        $lines = str_getcsv( $csv_content, "\n" );
        $success_count = 0;
        $errors = [];
        
        // Skip header row
        $is_first_row = true;
        
        foreach ( $lines as $line ) {
            if ( $is_first_row ) {
                $is_first_row = false;
                continue;
            }
            
            $data = str_getcsv( $line );
            
            if ( empty( $data[0] ) ) {
                continue; // Skip empty rows
            }
            
            $ip = trim( $data[0] );
            $note = isset( $data[1] ) ? trim( $data[1] ) : '';
            
            if ( $this->add_to_allowlist( $ip, $note ) ) {
                $success_count++;
            } else {
                $errors[] = "Failed to add: {$ip}";
            }
        }
        
        return [
            'success' => $success_count,
            'errors' => $errors,
        ];
    }

    /**
     * Import IPs from CSV to blocklist
     *
     * @param string $csv_content CSV file content.
     * @return array Result with success count and errors.
     */
    public function import_blocklist_csv( $csv_content ) {
        $lines = str_getcsv( $csv_content, "\n" );
        $success_count = 0;
        $errors = [];
        
        // Skip header row
        $is_first_row = true;
        
        foreach ( $lines as $line ) {
            if ( $is_first_row ) {
                $is_first_row = false;
                continue;
            }
            
            $data = str_getcsv( $line );
            
            if ( empty( $data[0] ) ) {
                continue; // Skip empty rows
            }
            
            $ip = trim( $data[0] );
            $reason = isset( $data[1] ) ? trim( $data[1] ) : '';
            
            if ( $this->add_to_blocklist( $ip, $reason ) ) {
                $success_count++;
            } else {
                $errors[] = "Failed to add: {$ip}";
            }
        }
        
        return [
            'success' => $success_count,
            'errors' => $errors,
        ];
    }
}
