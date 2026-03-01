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
        
        foreach ( $allowlist as $entry ) {
            // Handle both array format (from bulk operations) and string format
            $entry_ip = $this->extract_ip_from_entry( $entry );
            
            if ( empty( $entry_ip ) ) {
                continue;
            }
            
            // Check exact match
            if ( $entry_ip === $ip ) {
                return true;
            }
            
            // Check CIDR range
            if ( $this->ip_in_cidr( $ip, $entry_ip ) ) {
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
        
        foreach ( $blocklist as $entry ) {
            // Handle both array format (from bulk operations) and string format
            $entry_ip = $this->extract_ip_from_entry( $entry );
            
            if ( empty( $entry_ip ) ) {
                continue;
            }
            
            // Check exact match
            if ( $entry_ip === $ip ) {
                return true;
            }
            
            // Check CIDR range
            if ( $this->ip_in_cidr( $ip, $entry_ip ) ) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Extract IP address from entry (handles both string and array formats)
     *
     * @param mixed $entry Entry from allowlist/blocklist.
     * @return string|null IP address or null if invalid.
     */
    private function extract_ip_from_entry( $entry ) {
        // String format (original format)
        if ( is_string( $entry ) ) {
            return trim( $entry );
        }
        
        // Array format (from threat feeds bulk import)
        if ( is_array( $entry ) && isset( $entry['ip'] ) ) {
            return trim( $entry['ip'] );
        }
        
        // Invalid format
        return null;
    }

    /**
     * Check if an IP exists in a list (handles both string and array formats)
     *
     * @param string $ip IP address to check.
     * @param array  $list The list to search (allowlist or blocklist).
     * @return bool True if IP exists in list.
     */
    private function ip_exists_in_list( $ip, $list ) {
        foreach ( $list as $entry ) {
            $entry_ip = $this->extract_ip_from_entry( $entry );
            if ( $entry_ip === $ip ) {
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
        
        // Check if already in allowlist (handles both string and array formats)
        if ( $this->ip_exists_in_list( $ip, $allowlist ) ) {
            return 'already_in_allowlist';
        }

        // Check if IP is in blocklist (handles both string and array formats)
        if ( $this->ip_exists_in_list( $ip, $blocklist ) ) {
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
        
        // Check if already in blocklist (handles both string and array formats)
        if ( $this->ip_exists_in_list( $ip, $blocklist ) ) {
            return 'already_in_blocklist';
        }

        // Check if IP is in allowlist (handles both string and array formats)
        if ( $this->ip_exists_in_list( $ip, $allowlist ) ) {
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

        // Trigger cloud sync hook (Cloudflare integration)
        do_action( 'saurity_ip_blocked', $ip, $reason );

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

        // Trigger cloud sync hook (Cloudflare integration)
        do_action( 'saurity_ip_unblocked', $ip );

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
     * Get paginated allowlist with search and sorting
     *
     * @param int    $page     Current page number.
     * @param int    $per_page Items per page.
     * @param string $search   Search term.
     * @param string $sort_by  Sort by field (ip, note, added).
     * @param string $order    Sort order (asc, desc).
     * @return array Array with 'items', 'total', 'pages'.
     */
    public function get_allowlist_paginated( $page = 1, $per_page = 20, $search = '', $sort_by = 'added', $order = 'desc' ) {
        $allowlist = $this->get_allowlist();
        $metadata = $this->get_allowlist_metadata();
        
        // Build combined data array
        $items = [];
        foreach ( $allowlist as $ip ) {
            $meta = $metadata[ $ip ] ?? [];
            $items[] = [
                'ip'       => $ip,
                'note'     => $meta['note'] ?? '',
                'added'    => $meta['added'] ?? '',
                'added_by' => $meta['added_by'] ?? '',
            ];
        }
        
        // Filter by search term
        if ( ! empty( $search ) ) {
            $search = strtolower( $search );
            $items = array_filter( $items, function( $item ) use ( $search ) {
                return strpos( strtolower( $item['ip'] ), $search ) !== false ||
                       strpos( strtolower( $item['note'] ), $search ) !== false;
            } );
            $items = array_values( $items ); // Re-index
        }
        
        // Sort
        usort( $items, function( $a, $b ) use ( $sort_by, $order ) {
            $val_a = $a[ $sort_by ] ?? '';
            $val_b = $b[ $sort_by ] ?? '';
            
            $result = strcmp( $val_a, $val_b );
            return $order === 'desc' ? -$result : $result;
        } );
        
        // Calculate pagination
        $total = count( $items );
        $pages = ceil( $total / $per_page );
        $offset = ( $page - 1 ) * $per_page;
        
        // Slice for current page
        $items = array_slice( $items, $offset, $per_page );
        
        return [
            'items' => $items,
            'total' => $total,
            'pages' => $pages,
        ];
    }

    /**
     * Get paginated blocklist with search and sorting
     * ENHANCED: Handles both string format and array format (from threat feeds)
     *
     * @param int    $page     Current page number.
     * @param int    $per_page Items per page.
     * @param string $search   Search term.
     * @param string $sort_by  Sort by field (ip, reason, added).
     * @param string $order    Sort order (asc, desc).
     * @return array Array with 'items', 'total', 'pages'.
     */
    public function get_blocklist_paginated( $page = 1, $per_page = 20, $search = '', $sort_by = 'added', $order = 'desc' ) {
        $blocklist = $this->get_blocklist();
        $metadata = $this->get_blocklist_metadata();
        
        // Build combined data array
        $items = [];
        foreach ( $blocklist as $entry ) {
            // Handle both string and array formats
            if ( is_array( $entry ) ) {
                // Array format from threat feeds
                $ip = isset( $entry['ip'] ) ? $entry['ip'] : '';
                $items[] = [
                    'ip'       => $ip,
                    'reason'   => $entry['reason'] ?? '',
                    'added'    => $entry['added'] ?? '',
                    'added_by' => $entry['added_by'] ?? '',
                ];
            } else {
                // String format - use metadata
                $meta = $metadata[ $entry ] ?? [];
                $items[] = [
                    'ip'       => $entry,
                    'reason'   => $meta['reason'] ?? '',
                    'added'    => $meta['added'] ?? '',
                    'added_by' => $meta['added_by'] ?? '',
                ];
            }
        }
        
        // Filter by search term
        if ( ! empty( $search ) ) {
            $search = strtolower( $search );
            $items = array_filter( $items, function( $item ) use ( $search ) {
                return strpos( strtolower( $item['ip'] ), $search ) !== false ||
                       strpos( strtolower( $item['reason'] ), $search ) !== false;
            } );
            $items = array_values( $items ); // Re-index
        }
        
        // Sort
        usort( $items, function( $a, $b ) use ( $sort_by, $order ) {
            $val_a = $a[ $sort_by ] ?? '';
            $val_b = $b[ $sort_by ] ?? '';
            
            $result = strcmp( $val_a, $val_b );
            return $order === 'desc' ? -$result : $result;
        } );
        
        // Calculate pagination
        $total = count( $items );
        $pages = ceil( $total / $per_page );
        $offset = ( $page - 1 ) * $per_page;
        
        // Slice for current page
        $items = array_slice( $items, $offset, $per_page );
        
        return [
            'items' => $items,
            'total' => $total,
            'pages' => $pages,
        ];
    }

    /**
     * Bulk remove IPs from allowlist
     *
     * @param array $ips Array of IP addresses.
     * @return int Number of IPs removed.
     */
    public function bulk_remove_from_allowlist( $ips ) {
        $count = 0;
        foreach ( $ips as $ip ) {
            if ( $this->remove_from_allowlist( $ip ) ) {
                $count++;
            }
        }
        return $count;
    }

    /**
     * Bulk remove IPs from blocklist
     *
     * @param array $ips Array of IP addresses.
     * @return int Number of IPs removed.
     */
    public function bulk_remove_from_blocklist( $ips ) {
        $count = 0;
        foreach ( $ips as $ip ) {
            if ( $this->remove_from_blocklist( $ip ) ) {
                $count++;
            }
        }
        return $count;
    }

    /**
     * Bulk move IPs from blocklist to allowlist
     *
     * @param array $ips Array of IP addresses.
     * @return int Number of IPs moved.
     */
    public function bulk_move_to_allowlist( $ips ) {
        $count = 0;
        foreach ( $ips as $ip ) {
            if ( $this->remove_from_blocklist( $ip ) ) {
                if ( $this->add_to_allowlist( $ip, 'Moved from blocklist' ) === true ) {
                    $count++;
                }
            }
        }
        return $count;
    }

    /**
     * Bulk move IPs from allowlist to blocklist
     *
     * @param array $ips Array of IP addresses.
     * @return int Number of IPs moved.
     */
    public function bulk_move_to_blocklist( $ips ) {
        $count = 0;
        foreach ( $ips as $ip ) {
            if ( $this->remove_from_allowlist( $ip ) ) {
                if ( $this->add_to_blocklist( $ip, 'Moved from allowlist' ) === true ) {
                    $count++;
                }
            }
        }
        return $count;
    }

    /**
     * Get statistics for IP lists
     * ENHANCED: Handles both string format and array format (from threat feeds)
     *
     * @return array
     */
    public function get_statistics() {
        $allowlist = $this->get_allowlist();
        $blocklist = $this->get_blocklist();
        $allowlist_meta = $this->get_allowlist_metadata();
        $blocklist_meta = $this->get_blocklist_metadata();
        
        // Count CIDR ranges vs single IPs
        $allowlist_cidr = 0;
        $allowlist_single = 0;
        foreach ( $allowlist as $entry ) {
            $ip = $this->extract_ip_from_entry( $entry );
            if ( ! empty( $ip ) && strpos( $ip, '/' ) !== false ) {
                $allowlist_cidr++;
            } else {
                $allowlist_single++;
            }
        }
        
        $blocklist_cidr = 0;
        $blocklist_single = 0;
        foreach ( $blocklist as $entry ) {
            $ip = $this->extract_ip_from_entry( $entry );
            if ( ! empty( $ip ) && strpos( $ip, '/' ) !== false ) {
                $blocklist_cidr++;
            } else {
                $blocklist_single++;
            }
        }
        
        // Get recent additions (last 7 days)
        $week_ago = strtotime( '-7 days' );
        $recent_allowlist = 0;
        $recent_blocklist = 0;
        
        foreach ( $allowlist_meta as $meta ) {
            if ( ! empty( $meta['added'] ) && strtotime( $meta['added'] ) >= $week_ago ) {
                $recent_allowlist++;
            }
        }
        
        foreach ( $blocklist_meta as $meta ) {
            if ( ! empty( $meta['added'] ) && strtotime( $meta['added'] ) >= $week_ago ) {
                $recent_blocklist++;
            }
        }
        
        return [
            'allowlist_total'   => count( $allowlist ),
            'allowlist_cidr'    => $allowlist_cidr,
            'allowlist_single'  => $allowlist_single,
            'blocklist_total'   => count( $blocklist ),
            'blocklist_cidr'    => $blocklist_cidr,
            'blocklist_single'  => $blocklist_single,
            'recent_allowlist'  => $recent_allowlist,
            'recent_blocklist'  => $recent_blocklist,
        ];
    }

    /**
     * Get current user's IP
     *
     * @return string
     */
    public function get_current_ip() {
        $ip = '';

        if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
            $ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
        } elseif ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
            $forwarded = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
            $ip = explode( ',', $forwarded )[0];
        } elseif ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
            $ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
        }

        return trim( $ip );
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
        
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Using php://temp for in-memory CSV generation
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
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Closing php://temp stream
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
        
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Using php://temp for in-memory CSV generation
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
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Closing php://temp stream
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
