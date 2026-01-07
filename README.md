# SAURITY v0.1

**Minimal Viable Security Foundation for WordPress**

SAURITY v0.1 exists for trust, stability, and survival — NOT feature richness.

## What SAURITY v0.1 Does

### ✅ Blocks Brute Force
- Progressive rate limiting on login attempts
- Per-IP and per-username counters
- Sliding window (5 attempts / 10 minutes)
- Exponential delay, not instant block
- Hard block only after extreme abuse (20+ attempts)

### ✅ Lightweight Firewall
- Blocks XML-RPC brute force
- Prevents POST flooding
- Blocks access to non-existent sensitive paths (`.env`, `.git`, etc.)
- Prevents HTTP method abuse

### ✅ Human-Readable Logging
- Login successes and failures
- Throttled and blocked IPs
- Plugin activation/deactivation
- Auto-cleanup (keeps last 1000 entries)

### ✅ Safety First
- **Global Kill Switch** - Disable all enforcement instantly
- **Auto-Disable** - Automatically disables if admin lockout detected
- **Emergency Bypass URL** - Secret URL to bypass all protection
- **Manual Recovery** - Clear instructions for hosting-level disable

## Installation

1. Upload the `saurity` folder to `/wp-content/plugins/`
2. Activate through WordPress admin
3. Configure settings at **Settings → SAURITY**
4. **Save your Emergency Bypass URL** (shown in admin)

## Default Settings

- **Rate Limit:** 5 attempts per 10 minutes
- **Hard Block:** 20 attempts = 1 hour block
- **Progressive Delay:** 2 seconds exponential backoff
- **Fail Mode:** Always fails open, never closed

## Emergency Recovery

### Method 1: Kill Switch
Navigate to **Settings → SAURITY** and click "Activate Kill Switch"

### Method 2: Emergency Bypass URL
Use the secret URL provided in admin:
```
https://yoursite.com/?saurity_bypass=YOUR_SECRET_KEY
```

### Method 3: File System
Rename or delete the plugin folder:
```
wp-content/plugins/saurity/
```

### Method 4: Database (via phpMyAdmin)
```sql
UPDATE wp_options SET option_value = '1' WHERE option_name = 'saurity_kill_switch';
```

## Performance

- **Near-zero overhead** on normal requests
- Uses WordPress transients (no custom tables for counters)
- Single database query for logging (with auto-cleanup)
- No cron jobs or background processes
- Shared hosting compatible

## Architecture

```
saurity/
├── saurity.php              # Bootstrap
├── includes/
│   ├── Plugin.php           # Core orchestration
│   ├── Installer.php        # Activation/deactivation
│   ├── KillSwitch.php       # Emergency disable
│   ├── RateLimiter.php      # Rate limiting logic
│   ├── LoginGateway.php     # Login protection
│   ├── Firewall.php         # Request filtering
│   ├── ActivityLogger.php   # Event logging
│   └── Admin.php            # Settings interface
└── README.md
```

## Requirements

- WordPress 6.0+
- PHP 8.0+
- MySQL 5.7+ / MariaDB 10.2+

## What SAURITY v0.1 Does NOT Do

❌ OAuth, 2FA, CAPTCHA  
❌ Malware scanning  
❌ File integrity monitoring  
❌ CSP headers or advanced hardening  
❌ Cloud connectivity or external services  
❌ Deep payload inspection  
❌ Regex-heavy or AI logic  
❌ Block admins aggressively  
❌ Modify WordPress authentication  

These features are intentionally excluded to maintain stability and zero admin lockouts.

## Known Limitations

1. **No dashboard widget** - Access via Settings → SAURITY
2. **No email notifications** - Check logs manually
3. **Transient-based counters** - May reset if cache is cleared
4. **Soft 404 on blocks** - Returns 404 instead of explicit block message
5. **No geolocation** - IP-based blocking only
6. **No allowlist/blocklist UI** - Manual database edits required

## Configuration

All settings available at **Settings → SAURITY**:

- **Rate Limit Attempts** (1-20, default: 5)
- **Rate Limit Window** (60-3600 seconds, default: 600)
- **Hard Block Threshold** (10-100, default: 20)
- **Hard Block Duration** (300-86400 seconds, default: 3600)
- **Progressive Delay** (1-10 seconds, default: 2)

## Logging

Logs are human-readable and stored in the database:

```
Failed login for user 'admin' from IP 192.168.1.1 (throttled)
IP 192.168.1.100 hard blocked after 25 failed attempts
Successful login for user 'admin'
Kill switch activated: Manual activation by admin
```

## Uninstallation

The plugin cleans up after itself:

1. Deactivate the plugin
2. Delete the plugin
3. All tables, options, and transients are removed automatically

## Support

This is an MVP (Minimal Viable Product). It does what it says and nothing more.

For issues:
1. Check kill switch status
2. Review activity logs
3. Use emergency bypass URL
4. Manually disable via filesystem

## Roadmap (v1.0 and beyond)

Potential future features (NOT in v0.1):

- [ ] Email notifications
- [ ] Dashboard widget
- [ ] Allowlist/blocklist management
- [ ] Geolocation support
- [ ] REST API protection
- [ ] CSV log export
- [ ] Integration with Cloudflare
- [ ] Multi-site support
- [ ] Advanced firewall rules
- [ ] Rate limit API endpoints

## Philosophy

SAURITY v0.1 is built on these principles:

1. **Stability over features**
2. **Fail open, never closed**
3. **Zero admin lockouts**
4. **Performance first**
5. **Shared hosting compatible**
6. **No cloud dependencies**
7. **Defensive coding**
8. **Clean uninstall**

## License

GPL v2 or later

## Credits

Built by a senior WordPress security engineer who values trust and stability over feature bloat.

---

**Remember:** SAURITY v0.1 is a foundation. It blocks obvious attacks without breaking your site. Install it, configure it, and forget it's there.