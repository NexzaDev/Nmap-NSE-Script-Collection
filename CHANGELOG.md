# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `CONTRIBUTING.md` with contribution guidelines and PR checklist
- `SECURITY.md` with responsible disclosure policy
- CI workflow to lint all `.nse` scripts with `luacheck`
- GitHub issue templates for bug reports and feature requests
- README badges, table of contents, and cross-links to contributing/security/changelog docs

## [1.0.0] - 2026-07-04

### Added
- Initial stable release of the full script collection (55 scripts, 198+ checks)
- **HTTP** category — 10 scripts (security headers, cookies, CORS, caching, error disclosure, methods enum, server fingerprint, directory listing, robots/sitemap, TRACE method)
- **DNS** category — 9 scripts (zone transfer, subdomain enum, recursion check, amplification risk, cache snooping, SRV enum, SPF/DMARC audit, SOA consistency, wildcard detection)
- **SMB** category — 9 scripts (null session, guest access, security level, signing config, capabilities, protocol dialects, extended security, share accessibility, buffer limits)
- **SSL/TLS** category — 9 scripts (weak ciphers, protocol versions, cert info/expiry/hostname mismatch/weak signature, compression check, OCSP stapling, secure renegotiation)
- **Database** category — 9 scripts (MongoDB, MSSQL, MySQL, PostgreSQL, Redis checks)
- **FTP** category — 9 scripts (anonymous login, banner grab, bounce check, cleartext enforcement, command enum, directory listing, passive mode, TLS support, writable dirs)
- Full README documentation with installation guide, per-script usage examples, comprehensive scanning scenarios, and risk-level reference table
- MIT License

[Unreleased]: https://github.com/NexzaDev/Nmap-NSE-Script-Collection/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/NexzaDev/Nmap-NSE-Script-Collection/releases/tag/v1.0.0
