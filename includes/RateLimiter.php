<?php
/**
 * Rate Limiter
 *
 * @package Saurity
 */

namespace Saurity;

/**
 * RateLimiter class - sliding window rate limiting
 */
class RateLimiter {

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
     * Check if IP or username is rate limited
     *
     * @param string $ip IP address.
     * @param string $username Username (optional).
     * @return array ['limited' => bool, 'action' => string, 'delay' => int]
     */
    public function check( $ip, $username = '' ) {
        // Check for hard block first
        if ( $this->is_hard_blocked( $ip ) ) {
            return [
                'limited' => true,
                'action' => 'block',
                'delay' => 0,
            ];
        }

        // Check rate limit counters
        $ip_attempts = $this->get_attempts( 'ip', $ip );
        $username_attempts = $username ? $this->get_attempts( 'username', $username ) : 0;

        $max_attempts = (int) get_option( 'saurity_rate_limit_attempts', 5 );
        $hard_block_threshold = (int) get_option( 'saurity_hard_block_attempts', 20 );

        // Determine which counter is higher
        $total_attempts = max( $ip_attempts, $username_attempts );

        // Hard block if threshold exceeded
        if ( $total_attempts >= $hard_block_threshold ) {
            $this->set_hard_block( $ip );
            $this->logger->log(
                'error',
                "IP $ip hard blocked after $total_attempts failed attempts",
                [ 'ip' => $ip, 'username' => $username ]
            );

            return [
                'limited' => true,
                'action' => 'block',
                'delay' => 0,
            ];
        }

        // Progressive delay if soft limit exceeded
        if ( $total_attempts >= $max_attempts ) {
            $delay = $this->calculate_delay( $total_attempts - $max_attempts + 1 );
            
            return [
                'limited' => true,
                'action' => 'delay',
                'delay' => $delay,
            ];
        }

        // Not rate limited
        return [
            'limited' => false,
            'action' => 'allow',
            'delay' => 0,
        ];
    }

    /**
     * Record a failed attempt
     *
     * @param string $ip IP address.
     * @param string $username Username (optional).
     */
    public function record_failure( $ip, $username = '' ) {
        $this->increment_attempts( 'ip', $ip );
        
        if ( ! empty( $username ) ) {
            $this->increment_attempts( 'username', $username );
        }
    }

    /**
     * Reset rate limit for IP/username
     *
     * @param string $ip IP address.
     * @param string $username Username (optional).
     */
    public function reset( $ip, $username = '' ) {
        $this->clear_attempts( 'ip', $ip );
        
        if ( ! empty( $username ) ) {
            $this->clear_attempts( 'username', $username );
        }

        $this->remove_hard_block( $ip );
    }

    /**
     * Get attempt count
     *
     * @param string $type Type (ip or username).
     * @param string $identifier Identifier.
     * @return int
     */
    private function get_attempts( $type, $identifier ) {
        $key = $this->get_transient_key( $type, $identifier );
        $attempts = get_transient( $key );

        return $attempts ? (int) $attempts : 0;
    }

    /**
     * Increment attempt count
     *
     * @param string $type Type (ip or username).
     * @param string $identifier Identifier.
     */
    private function increment_attempts( $type, $identifier ) {
        $key = $this->get_transient_key( $type, $identifier );
        $attempts = $this->get_attempts( $type, $identifier );
        $attempts++;

        $window = (int) get_option( 'saurity_rate_limit_window', 600 );
        set_transient( $key, $attempts, $window );
    }

    /**
     * Clear attempt count
     *
     * @param string $type Type (ip or username).
     * @param string $identifier Identifier.
     */
    private function clear_attempts( $type, $identifier ) {
        $key = $this->get_transient_key( $type, $identifier );
        delete_transient( $key );
    }

    /**
     * Check if IP is hard blocked
     *
     * @param string $ip IP address.
     * @return bool
     */
    private function is_hard_blocked( $ip ) {
        $key = 'saurity_blocked_' . md5( $ip );
        return (bool) get_transient( $key );
    }

    /**
     * Set hard block for IP
     *
     * @param string $ip IP address.
     */
    private function set_hard_block( $ip ) {
        $key = 'saurity_blocked_' . md5( $ip );
        $duration = (int) get_option( 'saurity_hard_block_duration', 3600 );
        set_transient( $key, 1, $duration );
    }

    /**
     * Remove hard block for IP
     *
     * @param string $ip IP address.
     */
    private function remove_hard_block( $ip ) {
        $key = 'saurity_blocked_' . md5( $ip );
        delete_transient( $key );
    }

    /**
     * Calculate progressive delay
     *
     * @param int $excess_attempts Number of attempts over the limit.
     * @return int Delay in seconds.
     */
    private function calculate_delay( $excess_attempts ) {
        $base_delay = (int) get_option( 'saurity_progressive_delay', 2 );
        
        // Exponential backoff: 2, 4, 8, 16... seconds
        $delay = $base_delay * pow( 2, min( $excess_attempts - 1, 5 ) );
        
        // Cap at 60 seconds
        return min( $delay, 60 );
    }

    /**
     * Get transient key
     *
     * @param string $type Type (ip or username).
     * @param string $identifier Identifier.
     * @return string
     */
    private function get_transient_key( $type, $identifier ) {
        return 'saurity_' . $type . '_' . md5( $identifier );
    }

    /**
     * Apply delay
     *
     * @param int $seconds Number of seconds to delay.
     */
    public function apply_delay( $seconds ) {
        if ( $seconds > 0 ) {
            sleep( min( $seconds, 60 ) ); // Cap at 60 seconds for safety
        }
    }
}