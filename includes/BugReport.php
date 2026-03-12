<?php
/**
 * Bug Report Handler
 *
 * @package Saurity
 */

namespace Saurity;

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * BugReport class - handles bug report UI linking to GitHub
 */
class BugReport {

    /**
     * GitHub repository URL
     *
     * @var string
     */
    private $github_repo = 'https://github.com/saurity/saurity';

    /**
     * GitHub issues URL
     *
     * @var string
     */
    private $github_issues_url = 'https://github.com/saurity/saurity/issues/new';

    /**
     * Constructor
     */
    public function __construct() {
        // No dependencies needed
    }

    /**
     * Hook into WordPress
     */
    public function hook() {
        add_action( 'wp_ajax_saurity_get_system_info', [ $this, 'ajax_get_system_info' ] );
    }

    /**
     * AJAX handler to get system info
     */
    public function ajax_get_system_info() {
        check_ajax_referer( 'saurity_bug_report', 'nonce' );

        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( [ 'message' => 'Unauthorized' ] );
        }

        $system_info = $this->get_system_info();
        $formatted = $this->format_system_info_markdown( $system_info );

        wp_send_json_success( [ 'system_info' => $formatted ] );
    }

    /**
     * Get system information
     *
     * @return array
     */
    private function get_system_info() {
        global $wpdb;

        $info = [];

        // WordPress version
        $info['WordPress Version'] = get_bloginfo( 'version' );

        // Saurity version
        $info['Saurity Version'] = SAURITY_VERSION;

        // PHP version
        $info['PHP Version'] = phpversion();

        // MySQL version
        $info['MySQL Version'] = $wpdb->db_version();

        // Web server
        $info['Web Server'] = isset( $_SERVER['SERVER_SOFTWARE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) : 'Unknown';

        // Active theme
        $theme = wp_get_theme();
        $info['Active Theme'] = $theme->get( 'Name' ) . ' v' . $theme->get( 'Version' );

        // PHP Memory Limit
        $info['PHP Memory Limit'] = ini_get( 'memory_limit' );

        // WordPress Memory Limit
        $info['WP Memory Limit'] = WP_MEMORY_LIMIT;

        // Debug mode
        $info['WP Debug Mode'] = defined( 'WP_DEBUG' ) && WP_DEBUG ? 'Enabled' : 'Disabled';

        // Multisite
        $info['Multisite'] = is_multisite() ? 'Yes' : 'No';

        // SSL
        $info['SSL Enabled'] = is_ssl() ? 'Yes' : 'No';

        // Active plugins count
        $active_plugins = get_option( 'active_plugins', [] );
        $info['Active Plugins'] = count( $active_plugins );

        // Saurity settings summary
        $info['Rate Limiting'] = get_option( 'saurity_enable_rate_limiting', true ) ? 'Enabled' : 'Disabled';
        $info['Firewall'] = get_option( 'saurity_enable_firewall', true ) ? 'Enabled' : 'Disabled';
        $info['Logging'] = get_option( 'saurity_enable_logging', true ) ? 'Enabled' : 'Disabled';

        return $info;
    }

    /**
     * Format system info as markdown
     *
     * @param array $info System info array.
     * @return string
     */
    private function format_system_info_markdown( $info ) {
        $markdown = "### System Information\n\n";
        $markdown .= "| Setting | Value |\n";
        $markdown .= "|---------|-------|\n";

        foreach ( $info as $key => $value ) {
            $markdown .= "| {$key} | {$value} |\n";
        }

        return $markdown;
    }

    /**
     * Get bug report template
     *
     * @param string $type Report type (bug, feature, etc).
     * @return string
     */
    public function get_issue_template( $type = 'bug' ) {
        $templates = [
            'bug' => "## Bug Report

### Description
<!-- A clear and concise description of the bug -->

### Steps to Reproduce
1. Go to '...'
2. Click on '...'
3. Scroll down to '...'
4. See error

### Expected Behavior
<!-- What did you expect to happen? -->

### Actual Behavior
<!-- What actually happened? -->

### Screenshots
<!-- If applicable, add screenshots to help explain your problem -->

### System Information
<!-- Click 'Copy System Info' button and paste below -->

### Additional Context
<!-- Add any other context about the problem here -->
",
            'feature' => "## Feature Request

### Is your feature request related to a problem?
<!-- A clear and concise description of what the problem is. Ex. I'm always frustrated when [...] -->

### Describe the solution you'd like
<!-- A clear and concise description of what you want to happen -->

### Describe alternatives you've considered
<!-- A clear and concise description of any alternative solutions or features you've considered -->

### Additional context
<!-- Add any other context or screenshots about the feature request here -->
",
            'security' => "## Security Issue

**⚠️ For sensitive security vulnerabilities, please email security concerns privately instead of creating a public issue.**

### Description
<!-- Describe the security issue -->

### Impact
<!-- What is the potential impact? -->

### Steps to Reproduce
<!-- How can this be exploited? -->

### Suggested Fix
<!-- If you have suggestions on how to fix this -->
",
        ];

        return $templates[ $type ] ?? $templates['bug'];
    }

    /**
     * Render bug report page (linking to GitHub)
     */
    public function render() {
        $system_info = $this->get_system_info();
        $system_info_markdown = $this->format_system_info_markdown( $system_info );
        ?>
        <div style="max-width: 900px;">
            <!-- Header -->
            <div style="margin-bottom: 25px; padding: 25px; background: linear-gradient(135deg, #24292e 0%, #1a1e22 100%); border-radius: 12px; color: white;">
                <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 15px;">
                    <svg height="40" width="40" viewBox="0 0 16 16" fill="white">
                        <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
                    </svg>
                    <div>
                        <h2 style="margin: 0; font-size: 24px; font-weight: 600;">Report an Issue on GitHub</h2>
                        <p style="margin: 5px 0 0 0; opacity: 0.8; font-size: 14px;">Help us improve Saurity by reporting bugs or suggesting features</p>
                    </div>
                </div>
            </div>

            <!-- Quick Links -->
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-bottom: 25px;">
                <a href="<?php echo esc_url( $this->github_issues_url . '?template=bug_report.md&labels=bug' ); ?>" 
                   target="_blank" rel="noopener"
                   style="display: flex; flex-direction: column; align-items: center; padding: 25px 20px; background: #fff; border: 2px solid #dc3545; border-radius: 12px; text-decoration: none; transition: all 0.2s;">
                    <span style="font-size: 36px; margin-bottom: 10px;">🐛</span>
                    <span style="font-size: 16px; font-weight: 600; color: #dc3545;">Report Bug</span>
                    <span style="font-size: 12px; color: #666; margin-top: 5px;">Something isn't working</span>
                </a>
                <a href="<?php echo esc_url( $this->github_issues_url . '?template=feature_request.md&labels=enhancement' ); ?>" 
                   target="_blank" rel="noopener"
                   style="display: flex; flex-direction: column; align-items: center; padding: 25px 20px; background: #fff; border: 2px solid #28a745; border-radius: 12px; text-decoration: none; transition: all 0.2s;">
                    <span style="font-size: 36px; margin-bottom: 10px;">💡</span>
                    <span style="font-size: 16px; font-weight: 600; color: #28a745;">Feature Request</span>
                    <span style="font-size: 12px; color: #666; margin-top: 5px;">Suggest an improvement</span>
                </a>
                <a href="<?php echo esc_url( $this->github_repo . '/issues' ); ?>" 
                   target="_blank" rel="noopener"
                   style="display: flex; flex-direction: column; align-items: center; padding: 25px 20px; background: #fff; border: 2px solid #0366d6; border-radius: 12px; text-decoration: none; transition: all 0.2s;">
                    <span style="font-size: 36px; margin-bottom: 10px;">📋</span>
                    <span style="font-size: 16px; font-weight: 600; color: #0366d6;">View All Issues</span>
                    <span style="font-size: 12px; color: #666; margin-top: 5px;">Browse existing issues</span>
                </a>
            </div>

            <!-- System Information Section -->
            <div style="margin-bottom: 25px; padding: 20px; background: #fff; border: 1px solid #ddd; border-radius: 12px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                    <h3 style="margin: 0; font-size: 18px; color: #333;">
                        <span style="margin-right: 8px;">🖥️</span>System Information
                    </h3>
                    <button type="button" id="copy-system-info" class="button button-primary">
                        📋 Copy to Clipboard
                    </button>
                </div>
                <p style="margin: 0 0 15px 0; font-size: 13px; color: #666;">
                    Include this information when reporting bugs to help us diagnose issues faster.
                </p>
                <div style="background: #f6f8fa; border: 1px solid #e1e4e8; border-radius: 6px; overflow: hidden;">
                    <pre id="system-info-text" style="margin: 0; padding: 15px; font-size: 13px; font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word;"><?php echo esc_html( $system_info_markdown ); ?></pre>
                </div>
            </div>

            <!-- Bug Report Template -->
            <div style="margin-bottom: 25px; padding: 20px; background: #fff; border: 1px solid #ddd; border-radius: 12px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                    <h3 style="margin: 0; font-size: 18px; color: #333;">
                        <span style="margin-right: 8px;">📝</span>Bug Report Template
                    </h3>
                    <button type="button" id="copy-bug-template" class="button button-secondary">
                        📋 Copy Template
                    </button>
                </div>
                <p style="margin: 0 0 15px 0; font-size: 13px; color: #666;">
                    Use this template when creating a bug report for consistent and helpful issue submissions.
                </p>
                <div style="background: #f6f8fa; border: 1px solid #e1e4e8; border-radius: 6px; overflow: hidden;">
                    <pre id="bug-template-text" style="margin: 0; padding: 15px; font-size: 13px; font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word;"><?php echo esc_html( $this->get_issue_template( 'bug' ) ); ?></pre>
                </div>
            </div>

            <!-- Feature Request Template -->
            <div style="margin-bottom: 25px; padding: 20px; background: #fff; border: 1px solid #ddd; border-radius: 12px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                    <h3 style="margin: 0; font-size: 18px; color: #333;">
                        <span style="margin-right: 8px;">💡</span>Feature Request Template
                    </h3>
                    <button type="button" id="copy-feature-template" class="button button-secondary">
                        📋 Copy Template
                    </button>
                </div>
                <div style="background: #f6f8fa; border: 1px solid #e1e4e8; border-radius: 6px; overflow: hidden;">
                    <pre id="feature-template-text" style="margin: 0; padding: 15px; font-size: 13px; font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word;"><?php echo esc_html( $this->get_issue_template( 'feature' ) ); ?></pre>
                </div>
            </div>

            <!-- Guidelines -->
            <div style="padding: 20px; background: #fff3cd; border: 1px solid #ffc107; border-radius: 12px;">
                <h3 style="margin: 0 0 15px 0; font-size: 16px; color: #856404;">
                    <span style="margin-right: 8px;">📌</span>Guidelines for Good Issue Reports
                </h3>
                <ul style="margin: 0; padding-left: 20px; font-size: 14px; line-height: 1.8; color: #856404;">
                    <li><strong>Search first:</strong> Check if a similar issue already exists before creating a new one.</li>
                    <li><strong>Be specific:</strong> Include exact error messages, URLs, and steps to reproduce.</li>
                    <li><strong>One issue per report:</strong> This helps us track and resolve issues efficiently.</li>
                    <li><strong>Include system info:</strong> Click "Copy to Clipboard" above and paste into your issue.</li>
                    <li><strong>Screenshots help:</strong> Attach screenshots or screen recordings when relevant.</li>
                    <li><strong>Security issues:</strong> For sensitive security vulnerabilities, please email us privately instead of creating a public issue.</li>
                </ul>
            </div>

            <!-- GitHub Links -->
            <div style="margin-top: 25px; padding: 20px; background: #f8f9fa; border-radius: 12px; text-align: center;">
                <p style="margin: 0 0 15px 0; font-size: 14px; color: #666;">
                    <strong>Saurity is open source!</strong> Contributions, bug reports, and feature requests are welcome.
                </p>
                <div style="display: flex; justify-content: center; gap: 15px; flex-wrap: wrap;">
                    <a href="<?php echo esc_url( $this->github_repo ); ?>" target="_blank" rel="noopener" class="button button-secondary">
                        ⭐ Star on GitHub
                    </a>
                    <a href="<?php echo esc_url( $this->github_repo . '/issues' ); ?>" target="_blank" rel="noopener" class="button button-secondary">
                        📋 View Issues
                    </a>
                    <a href="<?php echo esc_url( $this->github_repo . '/pulls' ); ?>" target="_blank" rel="noopener" class="button button-secondary">
                        🔀 Pull Requests
                    </a>
                    <a href="<?php echo esc_url( $this->github_repo . '/discussions' ); ?>" target="_blank" rel="noopener" class="button button-secondary">
                        💬 Discussions
                    </a>
                </div>
            </div>
        </div>
        <?php
    }
}