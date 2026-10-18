# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-18

### Added
- Initial release: 432 Nmap NSE scripts across 27 protocol categories (HTTP, DNS, SMB, SSL/TLS, Database, FTP, Docker, GraphQL, MQTT, SSH, SNMP, LDAP, RDP, VNC, NTP, Telnet, SIP, SMTP, Kerberos, NFS/RPC, ICS/SCADA, Kubernetes, Elasticsearch, Memcached, Kafka/AMQP, Cloud Metadata/SSRF, WebSocket)
- Per-category `README.md` with script descriptions, risk levels, usage and sample output
- Local Docker Compose test targets and `TESTING.md`
- Lint gate and mock-based smoke-test harness in `tools/`
- GitHub Actions lint workflow and issue templates
- `CONTRIBUTING.md`, `SECURITY.md` and MIT `LICENSE`

[1.0.0]: https://github.com/NexzaDev/Nmap-NSE-Script-Collection/releases/tag/v1.0.0
