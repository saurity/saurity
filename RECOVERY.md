# SAURITY Emergency Recovery Guide

**If you're locked out, follow these steps in order.**

## Step 1: Use Emergency Bypass URL

Every SAURITY installation generates a unique bypass URL. If you saved it, use it now:

```
https://yoursite.com/?saurity_bypass=YOUR_SECRET_KEY
```

This URL temporarily disables all protection for that single request, allowing you to log in.

**Where to find it:** Settings → SAURITY → Recovery & Safety section (you need to save this BEFORE getting locked out)

---

## Step 2: Activate Kill Switch (If Logged In)

If you can still access WordPress admin:

1. Go to **Settings → SAURITY**
2. Click **"Activate Kill Switch"**
3. All enforcement is immediately disabled

---

## Step 3: File System Access (FTP/SFTP/File Manager)

If you have file system access, you can disable the plugin:

### Option A: Rename Plugin Folder

```
wp-content/plugins/saurity/
→ rename to →
wp-content/plugins/saurity-disabled/
```

### Option B: Delete Plugin Folder

```
wp-content/plugins/saurity/
```

Delete the entire folder. WordPress will automatically deactivate it.

### Option C: Rename Main Plugin File

```
wp-content/plugins/saurity/saurity.php
→ rename to →
wp-content/plugins/saurity/saurity.php.disabled
```

---

## Step 4: Database Access (phpMyAdmin / SQL)

If you have database access, run this SQL command:

```sql
UPDATE wp_options 
SET option_value = '1' 
WHERE option_name = 'saurity_kill_switch';
```

This activates the kill switch directly in the database.

**Note:** Replace `wp_` with your actual table prefix if different.

---

## Step 5: Clear All SAURITY Data (Nuclear Option)

If nothing else works, completely remove SAURITY from the database:

```sql
-- Delete all SAURITY options
DELETE FROM wp_options WHERE option_name LIKE 'saurity%';

-- Delete all SAURITY transients
DELETE FROM wp_options WHERE option_name LIKE '%saurity%';

-- Drop logs table
DROP TABLE IF EXISTS wp_saurity_logs;
```

Then delete the plugin folder via FTP/SFTP.

**Warning:** This removes all SAURITY data permanently.

---

## Step 6: Hosting Control Panel (cPanel / Plesk)

### Via File Manager:
1. Log into your hosting control panel
2. Navigate to File Manager
3. Go to `public_html/wp-content/plugins/`
4. Rename or delete the `saurity` folder

### Via SSH:
```bash
cd /path/to/wordpress/wp-content/plugins/
mv saurity saurity-disabled
```

---

## Step 7: Contact Your Host

If you cannot access files or database:

1. Contact your hosting provider
2. Ask them to rename: `wp-content/plugins/saurity/`
3. Or ask them to run the kill switch SQL command

---

## Prevention: Save These BEFORE Lockout

When you install SAURITY, immediately save these:

### 1. Emergency Bypass URL
Found at: **Settings → SAURITY → Recovery & Safety**

```
https://yoursite.com/?saurity_bypass=abc123...
```

**Save this in your password manager or safe location.**

### 2. File System Access
- FTP credentials
- SFTP credentials
- Hosting control panel login

### 3. Database Access
- phpMyAdmin URL
- Database credentials
- Table prefix

---

## Auto-Disable Protection

SAURITY v0.1 has built-in protection against admin lockouts:

- If admin accounts fail login 10+ times in 5 minutes
- SAURITY automatically activates the kill switch
- Check logs at **Settings → SAURITY** after regaining access

---

## Common Scenarios

### Scenario: Forgot Password
**Not a SAURITY issue.** Use WordPress password reset:
1. Go to login page
2. Click "Lost your password?"
3. Follow email instructions

### Scenario: IP Changed While Rate Limited
**Wait 10 minutes** or use emergency bypass URL.

### Scenario: Shared IP (Office/School)
Configure higher thresholds:
- Rate Limit Attempts: 10-15
- Hard Block Threshold: 40-50

### Scenario: Development Environment
Activate kill switch during development to disable all enforcement.

---

## Support Checklist

Before asking for help, try:

- [ ] Emergency bypass URL
- [ ] Wait 10-15 minutes (rate limits expire)
- [ ] Rename plugin folder via FTP
- [ ] Activate kill switch via database
- [ ] Check hosting control panel
- [ ] Review activity logs (if accessible)

---

## Why SAURITY Won't Lock You Out Forever

SAURITY is designed to fail open:

1. **Auto-disable:** Detects admin lockout patterns
2. **Time-based:** All blocks expire (default: 1 hour)
3. **Multiple bypasses:** 4+ ways to disable
4. **No permanent blocks:** Everything is temporary
5. **Transient storage:** Cache clear removes all blocks

---

## Manual Reset Everything

If you want to completely reset SAURITY:

### 1. Via Admin (If Accessible)
- Settings → SAURITY → Clear Logs
- Activate Kill Switch
- Deactivate plugin
- Delete plugin

### 2. Via Database
```sql
-- Clear all rate limits
DELETE FROM wp_options WHERE option_name LIKE '_transient_saurity%';
DELETE FROM wp_options WHERE option_name LIKE '_transient_timeout_saurity%';

-- Reset settings to defaults
UPDATE wp_options SET option_value = '5' WHERE option_name = 'saurity_rate_limit_attempts';
UPDATE wp_options SET option_value = '600' WHERE option_name = 'saurity_rate_limit_window';
UPDATE wp_options SET option_value = '0' WHERE option_name = 'saurity_kill_switch';

-- Clear logs
TRUNCATE TABLE wp_saurity_logs;
```

---

## Still Locked Out?

If none of these methods work, you're likely dealing with a different issue:

- **Hosting-level firewall:** Check with your host
- **Cloudflare protection:** Pause Cloudflare temporarily
- **Other security plugins:** Disable other security plugins
- **Server-level blocks:** Check Apache/Nginx configs
- **IP banned by host:** Contact hosting support

SAURITY only controls WordPress-level access, not server or CDN level blocks.

---

## Remember

**SAURITY v0.1 is designed to never permanently lock you out.**

All blocks are temporary. All enforcement can be disabled. Multiple recovery methods exist.

If you're locked out, it's likely not SAURITY — but we've given you the tools to verify and recover anyway.