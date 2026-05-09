# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-05-09

### Added
- Initial release.
- `Vault` actor holding the OAuth2 access token for one service.
- Proactive refresh at a configurable percentage of `expires_in`.
- Bounded retry with backoff schedule for transient refresh failures.
- Typed errors distinguishing retryable vs unauthorised failures.
- `on_refresh` persistence hook.
- `supervised/1` for supervision under `gleam_otp`.
