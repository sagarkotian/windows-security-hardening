# Changelog

All notable changes to this project are documented here.

## [1.2.1] - 2026-09-07

### Fixed

- Prevented empty WSL probe values from terminating distribution audits.
- Added safe handling for missing systemd, package-manager, and firewall configuration values.

## [1.2.0] - 2026-09-07

### Added

- Interactive and unattended WSL host auditing.
- Installed Linux distribution inventory and security checks.
- Optional running-only inspection that does not start stopped distributions.
- WSL results in JSON and HTML exports.

## [1.1.0] - 2026-09-06

### Added

- Initial Windows 11 security posture audit and guided-remediation TUI.
