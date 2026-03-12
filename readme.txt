=== Saurity Shield ===
Contributors: sauravkumar
Tags: security, firewall, brute force, rate limiting, login protection
Requires at least: 6.0
Tested up to: 6.9
Requires PHP: 8.0
Stable tag: 1.1.2
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Enterprise-grade WordPress security: Smart rate limiting, firewall, IP management, and real-time threat detection.

== Description ==

Saurity protects your WordPress site from brute force attacks, spam floods, and malicious traffic with intelligent rate limiting, advanced firewall rules, and real-time threat detection.

**Designed to minimize false positives. Production-ready. Shared hosting compatible.**

= Why Saurity? =

* **Protects admin access** - Intelligent detection + 3-tier emergency recovery system
* **Minimal false positives** - Honeypot + timing checks designed to target real bots
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

* Honeypot: Hidden fields help detect form-filling bots
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

Saurity is designed with a 3-tier recovery system to help prevent lockouts:

1. **Kill Switch** - One-click disable in admin panel
2. **Bypass URL** - Secret URL for emergency access (save this!)
3. **Manual** - Rename plugin folder via FTP

As with any security plugin, testing recovery options in a staging environment before going live is recommended.

= Does it slow down my site? =

Saurity is designed for minimal overhead, typically adding less than 0.5ms to page loads. It uses file-based counters instead of database queries for rate limiting. Actual performance impact may vary depending on your server environment.

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

= 1.1.2 =
* Fixed: PHP session warning interfering with REST API and loopback requests
* Added: session_write_close() calls to properly close sessions
* Improved: Skip session handling for REST API, AJAX, and cron requests

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

= 1.1.2 =
Fixed PHP session warning with REST API. Recommended update.

= 1.1.1 =
Fixed threat feed processing for large IP lists. Recommended update.

= 1.0.0 =
Initial release. After installation, save your Emergency Bypass URL!

== External services ==

This plugin can optionally connect to external services. **All external connections are opt-in and disabled by default.** No external connections are made by the core security features unless you explicitly enable them in Settings → Cloud Services.

= Cloudflare API =

**What it is:** Cloudflare's firewall management API, used to sync your WordPress IP blocklist with Cloudflare's edge firewall and import Cloudflare security events into the activity log.

**What data is sent:** Your blocked IP addresses are pushed to Cloudflare's Access Rules. No visitor personal data (usernames, cookies, passwords) is ever sent.

**When:** Only when you enable Cloudflare integration, enter your API token and Zone ID, and either trigger a manual sync or the scheduled hourly sync runs.

**Service provider:** Cloudflare, Inc.
**Terms of Service:** https://www.cloudflare.com/terms/
**Privacy Policy:** https://www.cloudflare.com/privacypolicy/

---

= IP-API.com (GeoIP Lookup) =

**What it is:** A free IP geolocation service used to determine the country of origin of visitor IP addresses.

**What data is sent:** Each incoming visitor's IP address is sent to ip-api.com to retrieve the corresponding country code. No other data (usernames, cookies, page content) is sent.

**When:** Only when GeoIP is enabled **and** the "IP-API.com" provider is selected. Each non-cached request sends the visitor's IP address. Results are cached per-IP to minimise calls.

**Service provider:** ip-api.com
**Terms of Service / Legal:** https://ip-api.com/docs/legal
**Privacy Policy:** https://ip-api.com/docs/legal

---

= MaxMind GeoLite2 (GeoIP Database Download) =

**What it is:** MaxMind's GeoLite2 country database, used locally to determine visitor country without sending requests for every page load.

**What data is sent:** Your MaxMind license key is included in the download URL when fetching the database file. No visitor IP addresses are ever sent to MaxMind — all lookups are performed locally.

**When:** Only when GeoIP is enabled with the "MaxMind" provider selected. The database file is downloaded once during setup and refreshed periodically.

**Service provider:** MaxMind, Inc.
**Terms of Use:** https://www.maxmind.com/en/terms_of_use
**Privacy Policy:** https://www.maxmind.com/en/privacy-policy

---

= Emerging Threats (Threat Intelligence Feed) =

**What it is:** A free, open-source threat intelligence feed listing known compromised and malicious IP addresses.

**What data is sent:** Nothing. This is a download-only operation — the plugin fetches a plain-text IP list. No data from your site is transmitted.

**When:** Only when Threat Intelligence Feeds are enabled and the "Emerging Threats" feed is selected. Updated on your configured schedule (default: daily).

**Service provider:** Emerging Threats / Proofpoint, Inc.
**Usage terms:** https://rules.emergingthreats.net/OPEN_usage.txt
**Privacy Policy:** https://www.proofpoint.com/us/privacy-policy

---

= Spamhaus DROP (Threat Intelligence Feed) =

**What it is:** The Spamhaus "Don't Route Or Peer" blocklist — a list of hijacked netblocks and cybercriminal networks.

**What data is sent:** Nothing. This is a download-only operation.

**When:** Only when Threat Intelligence Feeds are enabled and the "Spamhaus DROP" feed is selected. Updated on your configured schedule.

**Service provider:** The Spamhaus Project Ltd.
**Terms of Use:** https://www.spamhaus.org/organization/dnsblusage/
**Privacy Policy:** https://www.spamhaus.org/privacy-policy/

---

= Blocklist.de (Threat Intelligence Feed) =

**What it is:** A community-maintained IP blocklist of servers reported for SSH brute-force, mail abuse, and web attack activity.

**What data is sent:** Nothing. This is a download-only operation.

**When:** Only when Threat Intelligence Feeds are enabled and the "Blocklist.de" feed is selected. Updated on your configured schedule.

**Service provider:** blocklist.de
**Info / Terms:** https://www.blocklist.de/en/info.html

---

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