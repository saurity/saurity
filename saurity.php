<?php
/**
 * Plugin Name: Saurity Security
 * Plugin URI: https://github.com/saurity/saurity
 * Description: Enterprise-grade WordPress security: Smart rate limiting, advanced firewall, IP management, real-time threat detection. Protects login, forms, comments & XML-RPC. Zero false positives. Built for performance.
 * Version: 1.1.0
 * Requires at least: 6.0
 * Requires PHP: 8.0
 * Author: Saurav Kumar
 * Author URI: https://github.com/saurity
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: saurity
 * Domain Path: /languages
 * Tags: security, firewall, brute force, rate limiting, login protection, spam protection, ddos protection, ip blocking, wordpress security
 *
 * @package Saurity
 */

namespace Saurity;

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// Define plugin constants
define( 'SAURITY_VERSION', '1.1.0' );
define( 'SAURITY_FILE', __FILE__ );
define( 'SAURITY_PATH', plugin_dir_path( __FILE__ ) );
define( 'SAURITY_URL', plugin_dir_url( __FILE__ ) );
define( 'SAURITY_BASENAME', plugin_basename( __FILE__ ) );

// Require Composer autoloader if it exists
if ( file_exists( SAURITY_PATH . 'vendor/autoload.php' ) ) {
    require_once SAURITY_PATH . 'vendor/autoload.php';
}

// Manual autoloader for when Composer isn't available
spl_autoload_register( function ( $class ) {
    $prefix = 'Saurity\\';
    $base_dir = SAURITY_PATH . 'includes/';

    $len = strlen( $prefix );
    if ( strncmp( $prefix, $class, $len ) !== 0 ) {
        return;
    }

    $relative_class = substr( $class, $len );
    $file = $base_dir . str_replace( '\\', '/', $relative_class ) . '.php';

    if ( file_exists( $file ) ) {
        require $file;
    }
} );

// Note: load_plugin_textdomain() is no longer needed since WordPress 4.6
// when plugins are hosted on WordPress.org. WordPress automatically loads
// translations from translate.wordpress.org. Keeping this hook for backward
// compatibility with custom translation files in /languages folder, but
// the function is empty to suppress the deprecation warning.
function load_textdomain() {
    // Intentionally empty - WordPress handles translations automatically since 4.6
    // Custom translations can still be placed in /languages folder and WordPress
    // will load them automatically.
}

// Initialize plugin
function init() {
    // Load core components
    $plugin = Plugin::get_instance();
    $plugin->init();
}

// Hook into WordPress
// Note: Plugin must initialize at 'init' action (not plugins_loaded) because:
// 1. WordPress authenticates users during 'init' (is_user_logged_in() needs this)
// 2. Translations should be loaded at 'init' or later (WordPress 6.7+ requirement)
// 3. The Firewall hooks to 'init' at priority 0, so we init at priority -1
// This ensures CloudIntegration registers its filter BEFORE Firewall runs
add_action( 'init', __NAMESPACE__ . '\\init', -1 );
add_action( 'init', __NAMESPACE__ . '\\load_textdomain', 1 );

// Activation hook
register_activation_hook( __FILE__, function() {
    require_once SAURITY_PATH . 'includes/Installer.php';
    Installer::activate();
} );

// Deactivation hook
register_deactivation_hook( __FILE__, function() {
    require_once SAURITY_PATH . 'includes/Installer.php';
    Installer::deactivate();
} );

// Uninstall hook
register_uninstall_hook( __FILE__, [ 'Saurity\\Installer', 'uninstall' ] );

// Add settings link on plugin page
add_filter( 'plugin_action_links_' . SAURITY_BASENAME, function( $links ) {
    $settings_link = '<a href="' . admin_url( 'admin.php?page=saurity' ) . '">Settings</a>';
    array_unshift( $links, $settings_link );
    return $links;
} );
