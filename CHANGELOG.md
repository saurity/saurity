# Changelog

## [0.1.1] - 2026-01-07

### Added
- **Comprehensive Activity Logging**:
  - Now logs all WordPress events: user logins/logouts, post/page creation/updates/deletion, user registration/deletion, profile updates, plugin/theme changes, and important settings changes
  - Search functionality across message, IP address, and username
  - Pagination support (25 entries per page)
  - Filter tabs: All, Info, Warning, Error, Critical with counts
  - Log retention changed from 1000 entries to 15 days (configurable cleanup)
  - Better log display with user and IP information
  - Improved readability with color-coded log types
- **Interactive Tooltips**: Added informative "i" buttons that show helpful explanations on hover for each configuration setting

### Fixed
- **Critical Bug**: Fixed "Sorry, you are not allowed to access this page" error when kill switch is active
  - Admin interface now initializes regardless of kill switch state
  - Users can now access settings to deactivate kill switch
  - Security components are skipped when kill switch is active, but admin interface remains accessible
- **Logging Issues**:
  - Removed excessive "Kill switch is active" logging on every page load
  - Only activation/deactivation events are logged now (cleaner log history)
  - Fixed timezone display for existing logs (converts UTC to local time)
  - New logs now store timestamps in WordPress local timezone
- **Emergency Bypass URL**:
  - Added logging when bypass URL is used (security audit trail)
  - Added visual warning notice when bypass is active
  - Improved documentation explaining bypass URL is temporary (one request only)
  - Better UI explanation in admin interface

### Changed
- **Branding Update**: Changed plugin name from "SAURITY" (all caps) to "Saurity" (proper case)
- **Author Information**: Updated author name to "Saurav Kumar" and website to "https://www.saurity.com"
- **Menu Placement**: Moved admin interface from Settings submenu to main admin menu with shield icon
- **Timezone Fix**: Activity logs now use WordPress local timezone instead of server timezone

### Improved
- **Kill Switch UX**: 
  - Added prominent status indicator in admin bar (red when disabled, green when active)
  - Added quick toggle button in top warning banner
  - Added success/warning notifications when toggling kill switch
  - Improved visual hierarchy on admin page
- **User Experience**:
  - Better visual feedback with colored status indicators
  - One-click protection enable/disable from banner
  - Admin bar indicator for quick status check
  - Enhanced admin page layout with clear status messages

### Technical
- Added `current_time('mysql')` for timezone-aware logging
- Added admin bar hooks for status indicators
- Added inline CSS for admin bar styling
- Improved admin notice system with transients
- Better redirect handling after actions

### Documentation
- Updated README.md with new branding
- Updated menu access instructions
- Updated author credits

## [0.1.0] - Initial Release

### Features
- Progressive rate limiting on login attempts
- Lightweight firewall protection
- Human-readable activity logging
- Global kill switch for emergency disable
- Auto-disable to prevent admin lockout
- Emergency bypass URL
- Manual recovery options