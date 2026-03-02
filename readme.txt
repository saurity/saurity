=== Saurity Security ===
Contributors: sauravkumar
Tags: security, firewall, brute force, rate limiting, login protection
Requires at least: 6.0
Tested up to: 6.9
Requires PHP: 8.0
Stable tag: 1.1.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Enterprise-grade WordPress security: Smart rate limiting, firewall, IP management, real-time threat detection. Zero false positives.

== Description ==

Saurity protects your WordPress site from brute force attacks, spam floods, and malicious traffic with intelligent rate limiting, advanced firewall rules, and real-time threat detection.

**Zero false positives. Production-ready. Shared hosting compatible.**

= Why Saurity? =

* **Never locks out admins** - Intelligent detection + emergency recovery
* **Zero false positives** - Honeypot + timing checks catch only real bots
* **Lightning fast** - Optimized for shared hosting, minimal overhead (<0.5ms)
* **Simple configuration** - Smart defaults, works out of the box
* **3-tier recovery system** - Kill switch, bypass URL, manual disable

= Key Features =

**Smart Rate Limiting**

* Login Protection: Exponential delays after failed attempts
* POST Flood Protection: Two-tier system (device + IP) for NAT/office safety
* XML-RPC Protection: Stops pingback and trackback abuse
* Comment Rate Limiting: Prevents spam floods without CAPTCHA
* General Request Throttling: DoS protection (disabled by default)

**Advanced Firewall**

* SQL Injection Detection: Pattern-based SQLi blocking
* XSS Protection: Blocks cross-site scripting attempts
* Malicious User Agent Blocking: Stops known bad bots
* Sensitive Path Protection: Blocks .env, .git, wp-config.php access

**IP Management**

* Allowlist: Trusted IPs bypass all security checks
* Blocklist: Permanently block malicious IPs
* CIDR Support: Block entire IP ranges (e.g., 192.168.1.0/24)
* Import/Export: CSV bulk operations

**Advanced Bot Detection**

* Honeypot: Hidden fields catch form-filling bots (100% accuracy)
* Timing Analysis: Detects instant form submissions
* Tarpitting: Delays blocks to waste attacker resources

**Emergency Recovery**

1. Kill Switch: One-click disable all protection
2. Emergency Bypass URL: Secret URL for 10-minute admin access
3. Manual Disable: Rename plugin folder as last resort

= Optional Cloud Services =

The following cloud features are **disabled by default** and require explicit opt-in:

* **Cloudflare Integration** - Sync blocklist with Cloudflare firewall (requires your API token)
* **Threat Intelligence Feeds** - Import IPs from public blocklists (emergingthreats.net, spamhaus.org, blocklist.de)
* **GeoIP** - Country-based blocking using MaxMind (local database) or IP-API.com (external)

All external services are optional and documented. See the Privacy section below.

= Performance =

* Overhead: < 0.5ms per request
* Memory: < 2MB RAM usage
* Database: 1 query per security event
* Compatible with all caching plugins

== Installation ==

1. Upload the `saurity` folder to `/wp-content/plugins/`
2. Activate the plugin through the 'Plugins' menu
3. Navigate to **Saurity** in the admin menu
4. **Save your Emergency Bypass URL immediately!**

= Requirements =

* WordPress 6.0 or higher
* PHP 8.0 or higher
* MySQL 5.7+ / MariaDB 10.2+

== Frequently Asked Questions ==

= Will this lock me out? =

No. Saurity has a 3-tier recovery system:

1. **Kill Switch** - One-click disable in admin panel
2. **Bypass URL** - Secret URL for emergency access (save this!)
3. **Manual** - Rename plugin folder via FTP

= Does it slow down my site? =

No. Saurity adds less than 0.5ms to page loads. It uses file-based counters instead of database queries for rate limiting.

= Does it track users? =

**Core features (no external calls):**
All core security features work locally without external calls. IP addresses are logged for security purposes only and automatically deleted based on your retention settings (default: 15 days).

**Optional cloud services (opt-in only):**
If you enable optional cloud features, the following external connections may be made:

* Cloudflare API - Only if you enable Cloudflare integration
* Threat feeds - Download-only (no data sent) from emergingthreats.net, spamhaus.org, blocklist.de
* GeoIP - MaxMind (local database) or IP-API.com (sends IPs for country lookup)

All cloud features are **disabled by default** and clearly documented.

= Does it work with caching plugins? =

Yes. Saurity is compatible with WP Super Cache, W3 Total Cache, LiteSpeed Cache, and all other caching plugins.

= What about GDPR? =

Saurity logs IP addresses for legitimate security purposes (GDPR Article 6.1.f). Logs are automatically deleted based on your configured retention period. No personal data is shared with third parties unless you explicitly enable optional cloud features.

== Screenshots ==

1. Dashboard - Security overview and recent activity
2. Settings - Feature toggles and configuration
3. IP Management - Allowlist and blocklist management
4. Activity Log - Searchable security events
5. Recovery - Emergency access options

== Changelog ==

= 1.1.1 =
* Fixed: Large threat feed processing (Blocklist.de) now properly stores all IPs
* Added: Incremental saves during threat feed updates
* Added: Overflow storage for large blocklists exceeding database limits
* Improved: IPManager now checks overflow storage
* Improved: UI shows overflow indicator when database limits reached

= 1.0.0 =
* Initial release
* Smart rate limiting (login, POST, XML-RPC, comments)
* Advanced firewall (SQLi, XSS, malicious patterns)
* IP management with CIDR support
* Activity logging with search and export
* Email notifications
* Emergency recovery system
* Optional cloud integrations (Cloudflare, threat feeds, GeoIP)

== Upgrade Notice ==

= 1.1.1 =
Fixed threat feed processing for large IP lists. Recommended update.

= 1.0.0 =
Initial release. After installation, save your Emergency Bypass URL!

== Privacy ==

= Data Collected =

Saurity collects the following data for security purposes:

* IP addresses of visitors
* User agent strings
* Login usernames (for failed attempts)
* Timestamps of security events

= Data Storage =

All data is stored locally in your WordPress database. Data is automatically deleted based on your configured retention period (default: 15 days).

= External Services =

**No external calls by default.** Optional cloud services (disabled by default):

* **Cloudflare** - If enabled, syncs your blocklist with Cloudflare. Requires your Cloudflare API token. Data sent: blocked IP addresses.
* **Threat Feeds** - If enabled, downloads public IP blocklists. No data sent, download only.
* **GeoIP** - If enabled with IP-API provider, sends IP addresses to ip-api.com for country lookup. MaxMind option uses local database (no external calls).

= GDPR Compliance =

IP logging is justified under GDPR Article 6.1(f) - legitimate interest in website security. Users can request their data be deleted by contacting the site administrator.

== Additional Information ==

= Support =

For support, please use the [WordPress.org support forum](https://wordpress.org/support/plugin/saurity/) or [GitHub Issues](https://github.com/saurity/saurity/issues).

= Contributing =

Contributions welcome on [GitHub](https://github.com/saurity/saurity).