# Changelog

All notable changes to SYNTRAF will be documented in this file.

## [0.46] - 2026-02-03

### Added
- **VictoriaMetrics support**: New database engine option alongside InfluxDB2 and InfluxDB3
  - Uses native InfluxDB line protocol for data ingestion
  - HTTP API for database communication
  - Health check via `/health` endpoint
  - Multi-tenancy support via `DB_TENANT` configuration
- **Internationalization (i18n)**: Multi-language support for WebUI
  - English and French translations
  - Language selector in navigation bar
  - Translation files in `lib/web_ui_kindafixed2/translations/`
- **Log viewer**: New logs page in WebUI to view application logs (newest first)
- **User management**: Change password functionality
- **Enhanced queue page**: Shows both client-side queue and per-database write queues with status information

### Fixed
- **PID file check**: Improved `check_pid()` to verify process is actually SYNTRAF, not just any process with the same PID
- **Thread status display**: Fixed modal not showing thread status (was checking wrong property)
- **Client reconnect/restart**: Fixed actions failing for clients with "CONNECTED (PASSIVE)" status
- **Database status display**: Fixed status showing "ERROR" for connected VictoriaMetrics (was checking for "OK" instead of "ONLINE")
- **Dropdown visibility**: Fixed client options dropdown being clipped in small tables
- **DataTable error**: Removed DataTable dependency for thread status modal, using jQuery instead
- **Queue display**: Added "Queue:" label to database backlog display on home page

### Changed
- **Database config UI**: VictoriaMetrics option in engine dropdown, hides org/bucket fields when selected
- **Status display**: Normalized status values between backend and frontend
- **Navigation**: Removed "Processes" submenu from Status dropdown

### Dependencies
- Added `requests` library to requirements (for VictoriaMetrics HTTP API)

## [0.45] - Previous Release

- Initial tracked release
