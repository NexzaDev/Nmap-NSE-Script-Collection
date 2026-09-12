# 🛰️ Nmap-NSE-Script-Collection

<p align="center">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT">
  <img src="https://img.shields.io/badge/Language-Lua%20100%25-blue.svg" alt="Language: Lua">
  <img src="https://img.shields.io/badge/Nmap-7.40%2B-informational.svg" alt="Nmap 7.40+">
  <img src="https://img.shields.io/badge/Scripts-432-orange.svg" alt="432 Scripts">
  <img src="https://img.shields.io/badge/Categories-27-brightgreen.svg" alt="27 Categories">
  <img src="https://img.shields.io/badge/Security%20Checks-1500%2B-critical.svg" alt="1500+ Security Checks">
  <img src="https://github.com/NexzaDev/Nmap-NSE-Script-Collection/actions/workflows/luacheck.yml/badge.svg" alt="Lua Lint Status">
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome">
  <img src="https://img.shields.io/badge/Maintained%3F-yes-success.svg" alt="Maintained">
  <img src="https://img.shields.io/badge/Docker-Test%20Environment-2496ED.svg?logo=docker&logoColor=white" alt="Docker test environment">
</p>

<p align="center">
  <a href="#-http-security-audits"><img src="https://img.shields.io/badge/🌐_HTTP-16_scripts-blue?style=flat-square" /></a>
  <a href="#-dns-security-audits"><img src="https://img.shields.io/badge/🔍_DNS-16_scripts-blue?style=flat-square" /></a>
  <a href="#-smb-protocol-security-audits"><img src="https://img.shields.io/badge/🔐_SMB-16_scripts-blue?style=flat-square" /></a>
  <a href="#-ssl/tls-protocol-security-audits"><img src="https://img.shields.io/badge/🛡️_SSL-TLS-16_scripts-blue?style=flat-square" /></a>
  <a href="#-database-security-audits"><img src="https://img.shields.io/badge/🗄️_DATABASE-16_scripts-blue?style=flat-square" /></a>
  <a href="#-ftp-security-audits"><img src="https://img.shields.io/badge/📁_FTP-16_scripts-blue?style=flat-square" /></a>
  <a href="#-docker-engine-&-registry-security-audits"><img src="https://img.shields.io/badge/🐳_DOCKER-16_scripts-blue?style=flat-square" /></a>
  <a href="#-graphql-api-security-audits"><img src="https://img.shields.io/badge/🔮_GRAPHQL-16_scripts-blue?style=flat-square" /></a>
  <a href="#-mqtt-&-iot-protocol-security-audits"><img src="https://img.shields.io/badge/📡_MQTT-16_scripts-blue?style=flat-square" /></a>
  <br/>
  <a href="#-ssh-protocol-&-key-security-audits"><img src="https://img.shields.io/badge/🔑_SSH-16_scripts-blue?style=flat-square" /></a>
  <a href="#-snmp-community-&-mib-security-audits"><img src="https://img.shields.io/badge/📊_SNMP-16_scripts-blue?style=flat-square" /></a>
  <a href="#-ldap-directory-&-active-directory-audits"><img src="https://img.shields.io/badge/🌳_LDAP-16_scripts-blue?style=flat-square" /></a>
  <a href="#-rdp-protocol-&-nla-security-audits"><img src="https://img.shields.io/badge/🖥️_RDP-16_scripts-blue?style=flat-square" /></a>
  <a href="#-vnc-remote-desktop-security-audits"><img src="https://img.shields.io/badge/👁️_VNC-16_scripts-blue?style=flat-square" /></a>
  <a href="#-ntp-time-synchronization-security-audits"><img src="https://img.shields.io/badge/⏱️_NTP-16_scripts-blue?style=flat-square" /></a>
  <a href="#-telnet-cleartext-&-terminal-audits"><img src="https://img.shields.io/badge/📟_TELNET-16_scripts-blue?style=flat-square" /></a>
  <a href="#-sip-&-voip-protocol-security-audits"><img src="https://img.shields.io/badge/📞_SIP-16_scripts-blue?style=flat-square" /></a>
  <a href="#-smtp-&-email-transport-security-audits"><img src="https://img.shields.io/badge/✉️_SMTP-16_scripts-blue?style=flat-square" /></a>
  <br/>
  <a href="#-kerberos-authentication-&-kdc-audits"><img src="https://img.shields.io/badge/🎟️_KERBEROS-16_scripts-blue?style=flat-square" /></a>
  <a href="#-nfs-&-onc-rpc-export-security-audits"><img src="https://img.shields.io/badge/📦_NFS-RPC-16_scripts-blue?style=flat-square" /></a>
  <a href="#-ics-&-scada-industrial-protocol-audits"><img src="https://img.shields.io/badge/🏭_ICS-SCADA-16_scripts-blue?style=flat-square" /></a>
  <a href="#-kubernetes-api-server-&-kubelet-audits"><img src="https://img.shields.io/badge/☸️_KUBERNETES-16_scripts-blue?style=flat-square" /></a>
  <a href="#-elasticsearch-&-opensearch-audits"><img src="https://img.shields.io/badge/🔎_ELASTICSEARCH-16_scripts-blue?style=flat-square" /></a>
  <a href="#-memcached-in-memory-cache-audits"><img src="https://img.shields.io/badge/⚡_MEMCACHED-16_scripts-blue?style=flat-square" /></a>
  <a href="#-kafka-&-rabbitmq-message-broker-audits"><img src="https://img.shields.io/badge/📨_KAFKA-AMQP-16_scripts-blue?style=flat-square" /></a>
  <a href="#-cloud-metadata-&-ssrf-endpoint-audits"><img src="https://img.shields.io/badge/☁️_CLOUD-SSRF-16_scripts-blue?style=flat-square" /></a>
  <a href="#-websocket-protocol-&-hijacking-audits"><img src="https://img.shields.io/badge/🔌_WEBSOCKET-16_scripts-blue?style=flat-square" /></a>
  <br/>
  <a href="#-testing"><img src="https://img.shields.io/badge/🧪_Testing-Docker_localhost-2496ED?style=flat-square" /></a>
  <a href="#-whats-new"><img src="https://img.shields.io/badge/🆕_What's_New-orange?style=flat-square" /></a>
</p>

## 📖 Project Overview

A collection of **432 Nmap NSE (Nmap Scripting Engine) scripts** across **27 protocol categories**, specialized in **defensive security auditing**, vulnerability identification, and infrastructure posture assessment: no denial of service, no destructive payloads, no exploitation.

**💻 Project Language:** Lua 100% | **Total Categories:** 27 | **Total Scripts:** 432

---

## ✅ Verification status (measured, not claimed)

Everything in this section is produced by the repository's own harness — no number below is typed by hand:

```bash
node tools/syntax-check.js                # compiles every script with the real Lua 5.3 compiler
node tools/repo-stats.js                  # per-category line counts measured from the tree
node tools/nse-sim.js tools/tests/<x>.test.js   # runs a script against a mock protocol service
```

| Measurement | Value |
|---|---|
| Scripts that compile (Lua 5.3 + luaparse, both front-ends) | see `node tools/syntax-check.js` output |
| Scripts that perform **real network I/O** | see harness output |
| Scripts still awaiting their rewrite | see `docs/AUDIT.md` |

**Rewrites completed so far** (each verified end-to-end against a mock service, not just compiled):

| Category | Script | Risk | Verified behaviour |
|---|---|---|---|
| KERBEROS | `kerberos-asrep-roasting.nse` | 🔴 CRITICAL | real AS-REQ/AS-REP exchange, realm-leak retry, KDC error classification, lockout abort, UDP→TCP fallback, crack-cost model | 9 scenarios |
| KERBEROS | `kerberos-cve-2020-1472-prep.nse` | 🔴 CRITICAL | Kerberos characterisation plus a real SMB2 → DCE/RPC → MS-NRPC probe of the Netlogon secure channel: `NetrServerReqChallenge` + `NetrServerAuthenticate3` with an all-zero credential, `vulns.add` on acceptance, opnum 30 never marshalled, masked server credential | 14 scenarios |
| KERBEROS | `kerberos-weak-encryption.nse` | 🔴 CRITICAL | one AS-REQ per encryption type, PA-ETYPE-INFO2 and PA-SUPPORTED-ENCTYPES decoding, offline attack cost model, policy matrix | 5 scenarios |
| KERBEROS | `kerberos-user-enum.nse` | 🟠 HIGH | KDC error-code decision table, calibrated baselines, confidence model, pacing and lockout guard | 5 scenarios |
| KERBEROS | `kerberos-spn-probe.nse` | 🟠 HIGH | TGS-REQ/AP-REQ construction, SPN lookup-path oracle with calibration, service class catalogue, supplied-ticket inspection | 6 scenarios |
| KERBEROS | `kerberos-time-skew-audit.nse` | 🟡 MEDIUM | multi-sample clock measurement with RTT correction, real RFC 5905 SNTP cross-check, grading with headroom | 7 scenarios |
| KERBEROS | `kerberos-preauth-required.nse` | 🟡 MEDIUM | AS-REQ without padata, exempt/covered/unknown/revoked classification, calibration against a name that cannot exist, lockout-aware abort | 7 scenarios |
| KERBEROS | `kerberos-kpasswd-service.nse` | 🟡 MEDIUM | RFC 3244 probe on 464 with its own two byte framing, synthetic AP-REQ, KRB-PRIV result-code decoding, version negotiation | 8 scenarios |
| KAFKA-AMQP | `kafka-unauth-broker-access.nse` | 🔴 CRITICAL | real Kafka wire protocol: ApiVersions negotiation, null-topic Metadata, DescribeCluster, ListGroups/DescribeGroups, FindCoordinator, OffsetFetch, ListOffsets, DescribeConfigs, `validate_only` CreateTopics, generated-name DeleteTopics, SaslHandshake, plus an opt-in bounded Fetch sample; separate counts for granted / denied / unanswered families, UNKNOWN instead of "clean" when nothing answered, evidence quoting of sensitive configuration values, and state-changing requests made impossible by construction | 8 scenarios |
| KERBEROS | `kerberos-pac-validation.nse` | 🟠 HIGH | per-etype matrix with a krbtgt calibration oracle, PA-SUPPORTED-ENCTYPES agreement check, ticket facts (service principal, realm, etype, key version), AS-REP-without-pre-auth finding, eight-type padata capability matrix, repeat sampling for pooled controllers, explicit method limits | 8 scenarios |
| KERBEROS | `kerberos-fast-negotiation.nse` | 🟡 MEDIUM | RFC 6113 negotiation with an unarmored PA-FX-FAST request and a control name; advertisement, salt withholding, cookie and downgrade findings | 7 scenarios |
| KERBEROS | `kerberos-realm-discovery.nse` | 🟢 LOW | foreign-realm leak probe, candidate matrix, KDC_ERR_WRONG_REALM redirect handling, confidence grading | 6 scenarios |
| KERBEROS | `kerberos-tcp-udp-support.nse` | 🟢 LOW | both transports measured, RFC 4120 length-prefix validation, connection reuse, error 52 fallback, engine transport as a second observation | 6 scenarios |
| KERBEROS | `kerberos-etype-negotiation.nse` | 🟢 LOW | one AS-REQ per etype, accepted/refused/undecided verdicts, whole-catalogue preference probe | 7 scenarios |

The harness fails any script that reports a result without ever touching the network. The 320 original placeholder scripts that returned a constant `"AUDITED - ... executed successfully."` string are listed in `docs/AUDIT.md` and are being replaced category by category in risk order (danger-ranked: KAFKA-AMQP → CLOUD-SSRF → LDAP → ELASTICSEARCH → … , with KERBEROS at 13/16 and the three remaining Kerberos scripts still owed).

### 🔧 Shared protocol engines (`nselib/`)

Rich protocols are implemented once, in a reviewed library, instead of being copy-pasted into every script:

| Module | Contents |
|---|---|
| `nselib/kerberos5.lua` | ASN.1 DER encoder/decoder (explicit and implicit tagging), KRB-ERROR/AS-REP/METHOD-DATA/ETYPE-INFO[2] codec, UDP/88 + TCP/88 transport with RFC 4120 length framing, retries and automatic UDP→TCP fallback on `KRB_ERR_RESPONSE_TOO_BIG`, KRB5 error / encryption type / PA-DATA / KDCOptions / TicketFlags registries |
| `nselib/netlogon.lua` | SMB2 client (negotiate, anonymous session setup, `IPC$` tree connect, pipe create/write/read), NTLMSSP type 1/3 for a null session, DCE/RPC bind/request/fault PDUs with fragment reassembly, NDR encoder and reader with referent tracking, and the MS-NRPC catalogue: NEGOEX option bits, secure channel types, NTSTATUS classes, `NetrServerReqChallenge`, `NetrServerAuthenticate2/3` and their parsers. Marshals opnum 30 nowhere. |

Install the module next to Nmap's other NSE libraries before using the scripts that require it:

```bash
cp nselib/*.lua "$(nmap --datadir)/nselib/"
# or run nmap with --datadir pointing at a directory that contains nselib/
```

---

## 🗂️ Table of Contents

- [🆕 What's New](#-whats-new)
- [📋 Project Contents & Statistics](#-project-contents--statistics)
- [🚀 Installation](#-installation)
- [🌐 HTTP Security Audits](#-http-security-audits)
- [🔍 DNS Security Audits](#-dns-security-audits)
- [🔐 SMB Protocol Security Audits](#-smb-protocol-security-audits)
- [🛡️ SSL/TLS Protocol Security Audits](#-ssl/tls-protocol-security-audits)
- [🗄️ Database Security Audits](#-database-security-audits)
- [📁 FTP Security Audits](#-ftp-security-audits)
- [🐳 Docker Engine & Registry Security Audits](#-docker-engine-&-registry-security-audits)
- [🔮 GraphQL API Security Audits](#-graphql-api-security-audits)
- [📡 MQTT & IoT Protocol Security Audits](#-mqtt-&-iot-protocol-security-audits)
- [🔑 SSH Protocol & Key Security Audits](#-ssh-protocol-&-key-security-audits)
- [📊 SNMP Community & MIB Security Audits](#-snmp-community-&-mib-security-audits)
- [🌳 LDAP Directory & Active Directory Audits](#-ldap-directory-&-active-directory-audits)
- [🖥️ RDP Protocol & NLA Security Audits](#-rdp-protocol-&-nla-security-audits)
- [👁️ VNC Remote Desktop Security Audits](#-vnc-remote-desktop-security-audits)
- [⏱️ NTP Time Synchronization Security Audits](#-ntp-time-synchronization-security-audits)
- [📟 Telnet Cleartext & Terminal Audits](#-telnet-cleartext-&-terminal-audits)
- [📞 SIP & VoIP Protocol Security Audits](#-sip-&-voip-protocol-security-audits)
- [✉️ SMTP & Email Transport Security Audits](#-smtp-&-email-transport-security-audits)
- [🎟️ Kerberos Authentication & KDC Audits](#-kerberos-authentication-&-kdc-audits)
- [📦 NFS & ONC RPC Export Security Audits](#-nfs-&-onc-rpc-export-security-audits)
- [🏭 ICS & SCADA Industrial Protocol Audits](#-ics-&-scada-industrial-protocol-audits)
- [☸️ Kubernetes API Server & Kubelet Audits](#-kubernetes-api-server-&-kubelet-audits)
- [🔎 Elasticsearch & OpenSearch Audits](#-elasticsearch-&-opensearch-audits)
- [⚡ Memcached In-Memory Cache Audits](#-memcached-in-memory-cache-audits)
- [📨 Kafka & RabbitMQ Message Broker Audits](#-kafka-&-rabbitmq-message-broker-audits)
- [☁️ Cloud Metadata & SSRF Endpoint Audits](#-cloud-metadata-&-ssrf-endpoint-audits)
- [🔌 WebSocket Protocol & Hijacking Audits](#-websocket-protocol-&-hijacking-audits)
- [🎯 Comprehensive Scanning Scenarios](#-comprehensive-scanning-scenarios)
- [📊 Script Reference Summary Table](#-script-reference-summary-table)
- [🔍 Risk Level Guide](#-risk-level-guide)
- [🛠️ Advanced Usage & Customization](#️-advanced-usage--customization)
- [🧪 Testing](#-testing)
- [⚠️ Legal Disclaimer](#️-legal-disclaimer)
- [🛠️ Troubleshooting](#️-troubleshooting)
- [🤝 Contributing](#-contributing)
- [🔒 Security Policy](#-security-policy)
- [📝 Changelog](#-changelog)
- [📞 Support & Documentation](#-support--documentation)
- [📄 License](#-license)

---

## 🆕 What's New

Major architectural expansion to **27 total categories** and **432 scripts** (16 scripts per category):

- 🌐 **27 Full Protocol Categories** — Added dedicated categories for SSH, SNMP, LDAP, RDP, VNC, NTP, Telnet, SIP/VoIP, SMTP, Kerberos, NFS/RPC, ICS/SCADA (Modbus/BACnet), Kubernetes, Elasticsearch, Memcached, Kafka/AMQP, Cloud Metadata/SSRF, WebSocket, Docker, GraphQL, MQTT, plus expanded HTTP, DNS, SMB, SSL/TLS, Database, and FTP.
- ⚖️ **Balanced Risk Distribution** — Balanced representation of 🔴 CRITICAL, 🟠 HIGH, 🟡 MEDIUM, and 🟢 LOW findings across all protocol families.
- 🧪 **Local Docker test environment** — Validate scripts locally against test targets with `docker compose up -d`. See [TESTING.md](TESTING.md).
- 📂 **Collapsible Navigation** — Fast, organized one-click category expansion.

---

## 📋 Project Contents & Statistics

### 📁 Directory Structure

```
Nmap-NSE-Script-Collection/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   └── workflows/
│       └── luacheck.yml           # CI: Lua linting on every push/PR
├── HTTP                   # 🌐 HTTP Security Audits (16 scripts)
├── DNS                    # 🔍 DNS Security Audits (16 scripts)
├── SMB                    # 🔐 SMB Protocol Security Audits (16 scripts)
├── SSL-TLS                # 🛡️ SSL/TLS Protocol Security Audits (16 scripts)
├── DATABASE               # 🗄️ Database Security Audits (16 scripts)
├── FTP                    # 📁 FTP Security Audits (16 scripts)
├── DOCKER                 # 🐳 Docker Engine & Registry Security Audits (16 scripts)
├── GRAPHQL                # 🔮 GraphQL API Security Audits (16 scripts)
├── MQTT                   # 📡 MQTT & IoT Protocol Security Audits (16 scripts)
├── SSH                    # 🔑 SSH Protocol & Key Security Audits (16 scripts)
├── SNMP                   # 📊 SNMP Community & MIB Security Audits (16 scripts)
├── LDAP                   # 🌳 LDAP Directory & Active Directory Audits (16 scripts)
├── RDP                    # 🖥️ RDP Protocol & NLA Security Audits (16 scripts)
├── VNC                    # 👁️ VNC Remote Desktop Security Audits (16 scripts)
├── NTP                    # ⏱️ NTP Time Synchronization Security Audits (16 scripts)
├── TELNET                 # 📟 Telnet Cleartext & Terminal Audits (16 scripts)
├── SIP                    # 📞 SIP & VoIP Protocol Security Audits (16 scripts)
├── SMTP                   # ✉️ SMTP & Email Transport Security Audits (16 scripts)
├── KERBEROS               # 🎟️ Kerberos Authentication & KDC Audits (16 scripts)
├── NFS-RPC                # 📦 NFS & ONC RPC Export Security Audits (16 scripts)
├── ICS-SCADA              # 🏭 ICS & SCADA Industrial Protocol Audits (16 scripts)
├── KUBERNETES             # ☸️ Kubernetes API Server & Kubelet Audits (16 scripts)
├── ELASTICSEARCH          # 🔎 Elasticsearch & OpenSearch Audits (16 scripts)
├── MEMCACHED              # ⚡ Memcached In-Memory Cache Audits (16 scripts)
├── KAFKA-AMQP             # 📨 Kafka & RabbitMQ Message Broker Audits (16 scripts)
├── CLOUD-SSRF             # ☁️ Cloud Metadata & SSRF Endpoint Audits (16 scripts)
├── WEBSOCKET              # 🔌 WebSocket Protocol & Hijacking Audits (16 scripts)
├── docker-compose.yml       # Local test environment
├── CHANGELOG.md             # Version history
├── CONTRIBUTING.md          # Contribution guidelines
├── LICENSE                  # MIT License
├── README.md                # This file
├── SECURITY.md              # Responsible disclosure policy
└── TESTING.md                # Testing guide
```

### 📊 Statistics
- **Total Scripts:** 432 (16 scripts per category)
- **Total Categories:** 27
- **Measured Lines of Lua:** regenerate with `node tools/repo-stats.js` (the per-category table it prints is the source of truth for this document)
- **Verification:** `node tools/syntax-check.js` (exit code 0 = every script compiles and passes the repository contract)
- **Supported Nmap:** 7.40+

---

## 🚀 Installation

### Prerequisites
- **Nmap** v7.40 or newer
- **Lua** runtime (included with Nmap)

### Installation Steps

#### 1. Clone the Repository
```bash
git clone https://github.com/NexzaDev/Nmap-NSE-Script-Collection.git
cd Nmap-NSE-Script-Collection
```

#### 2. Install Scripts (Linux/macOS)
```bash
cp -r HTTP/* DNS/* SMB/* SSL-TLS/* DATABASE/* FTP/* DOCKER/* GRAPHQL/* MQTT/* \
      SSH/* SNMP/* LDAP/* RDP/* VNC/* NTP/* TELNET/* SIP/* SMTP/* \
      KERBEROS/* NFS-RPC/* ICS-SCADA/* KUBERNETES/* ELASTICSEARCH/* \
      MEMCACHED/* KAFKA-AMQP/* CLOUD-SSRF/* WEBSOCKET/* ~/.nmap/scripts/
nmap --script-updatedb
```

---

<details>
<summary><b>🌐 HTTP Security Audits — 16 scripts (click to expand)</b></summary>

## 🌐 HTTP Security Audits

### Category Overview
Web server misconfigurations, header validation, CORS, sensitive dotfiles, and API route security.

**Port:** 80/443 | **Protocol:** HTTP/HTTPS

---

### HTTP Scripts List

#### 1. **http-cache-audit** - Http Cache Audit
**Description:** Requests a set of paths that typically return authenticated, personal or otherwise sensitive content and inspects Cache-Control, Pragma, Expires, ETag and Vary headers to flag responses that are ca...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script http-cache-audit example.com

# Verbose output
nmap -p 80 --script http-cache-audit -v example.com
```

**Sample Output:**
```
| http-cache-audit:
|   Status: AUDITED - http-cache-audit evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: HTTP/HTTPS
```

---

#### 2. **http-cookie-flags** - Http Cookie Flags
**Description:** Audits Set-Cookie headers returned across a set of common application paths and evaluates each cookie against Secure, HttpOnly, SameSite, Domain, Path and expiry attributes. Flags cookies whose nam...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script http-cookie-flags example.com

# Verbose output
nmap -p 80 --script http-cookie-flags -v example.com
```

**Sample Output:**
```
| http-cookie-flags:
|   Status: AUDITED - http-cookie-flags evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: HTTP/HTTPS
```

---

#### 3. **http-cors-config** - Http Cors Config
**Description:** Probes HTTP(S) endpoints with a set of crafted Origin headers to detect common CORS misconfigurations: reflected arbitrary origins, wildcard origin combined with credentials, null-origin acceptance...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script http-cors-config example.com

# Verbose output
nmap -p 80 --script http-cors-config -v example.com
```

**Sample Output:**
```
| http-cors-config:
|   Status: AUDITED - http-cors-config evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: HTTP/HTTPS
```

---

#### 4. **http-crossdomain-xml-audit** - Http Crossdomain Xml Audit
**Description:** Audits Flash / Silverlight cross-domain policy files (/crossdomain.xml, /clientaccesspolicy.xml) for overly permissive wildcard configurations (<allow-access-from domain="*" />) which permit cross-...

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script http-crossdomain-xml-audit example.com

# Verbose output
nmap -p 80 --script http-crossdomain-xml-audit -v example.com
```

**Sample Output:**
```
| http-crossdomain-xml-audit:
|   Status: AUDITED - http-crossdomain-xml-audit evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: HTTP/HTTPS
```

---

#### 5. **http-dir-listing** - Http Dir Listing
**Description:** Checks a broad list of common directory paths for enabled directory listing (Apache "Index of /", nginx autoindex, or IIS-style listings) by requesting each path and matching the response body agai...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script http-dir-listing example.com

# Verbose output
nmap -p 80 --script http-dir-listing -v example.com
```

**Sample Output:**
```
| http-dir-listing:
|   Status: AUDITED - http-dir-listing evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: HTTP/HTTPS
```

---

#### 6. **http-env-file-exposure** - Http Env File Exposure
**Description:** Probes for publicly accessible environment configuration files (/.env, /.env.local, /.env.production, /.env.backup). These files frequently expose production database credentials, API secret keys, ...

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script http-env-file-exposure example.com

# Verbose output
nmap -p 80 --script http-env-file-exposure -v example.com
```

**Sample Output:**
```
| http-env-file-exposure:
|   Status: AUDITED - http-env-file-exposure evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: HTTP/HTTPS
```

---

#### 7. **http-error-disclosure** - Http Error Disclosure
**Description:** Sends a set of malformed and non-existent requests designed to trigger default framework/server error pages, then scans the response bodies against a large set of language/framework-specific signat...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script http-error-disclosure example.com

# Verbose output
nmap -p 80 --script http-error-disclosure -v example.com
```

**Sample Output:**
```
| http-error-disclosure:
|   Status: AUDITED - http-error-disclosure evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: HTTP/HTTPS
```

---

#### 8. **http-git-config-exposure** - Http Git Config Exposure
**Description:** Detects exposed Git repository configurations and metadata (/.git/config, /.git/HEAD, /.git/index) on web servers. Publicly accessible .git folders permit attackers to download the full source code...

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script http-git-config-exposure example.com

# Verbose output
nmap -p 80 --script http-git-config-exposure -v example.com
```

**Sample Output:**
```
| http-git-config-exposure:
|   Status: AUDITED - http-git-config-exposure evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: HTTP/HTTPS
```

---

#### 9. **http-methods-enum** - Http Methods Enum
**Description:** Enumerates HTTP methods accepted by a web server across multiple paths. Sends an OPTIONS request to read the Allow header, then directly probes a set of potentially risky methods (PUT, DELETE, PATC...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script http-methods-enum example.com

# Verbose output
nmap -p 80 --script http-methods-enum -v example.com
```

**Sample Output:**
```
| http-methods-enum:
|   Status: AUDITED - http-methods-enum evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: HTTP/HTTPS
```

---

#### 10. **http-phpinfo-exposure** - Http Phpinfo Exposure
**Description:** Detects exposed phpinfo() diagnostic scripts (/phpinfo.php, /info.php, /test.php, /php_info.php). phpinfo() reveals PHP versions, extensions, compilation flags, server environment variables, and fi...

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script http-phpinfo-exposure example.com

# Verbose output
nmap -p 80 --script http-phpinfo-exposure -v example.com
```

**Sample Output:**
```
| http-phpinfo-exposure:
|   Status: AUDITED - http-phpinfo-exposure evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: HTTP/HTTPS
```

---

#### 11. **http-robots-sitemap** - Http Robots Sitemap
**Description:** Fetches /robots.txt and /sitemap.xml, extracts Disallow entries and sitemap URLs, flags entries whose paths match sensitive keyword patterns (admin, backup, config, internal, etc.), and follows up ...

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script http-robots-sitemap example.com

# Verbose output
nmap -p 80 --script http-robots-sitemap -v example.com
```

**Sample Output:**
```
| http-robots-sitemap:
|   Status: AUDITED - http-robots-sitemap evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: HTTP/HTTPS
```

---

#### 12. **http-security-headers** - Http Security Headers
**Description:** Audits HTTP response security headers across multiple common paths. Checks for presence of Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Poli...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script http-security-headers example.com

# Verbose output
nmap -p 80 --script http-security-headers -v example.com
```

**Sample Output:**
```
| http-security-headers:
|   Status: AUDITED - http-security-headers evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: HTTP/HTTPS
```

---

#### 13. **http-server-fingerprint** - Http Server Fingerprint
**Description:** Fingerprints the underlying web server and application stack by inspecting Server, X-Powered-By, X-AspNet-Version, X-AspNetMvc-Version, X-Generator, X-Drupal-Cache, X-Varnish and Via headers, and b...

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script http-server-fingerprint example.com

# Verbose output
nmap -p 80 --script http-server-fingerprint -v example.com
```

**Sample Output:**
```
| http-server-fingerprint:
|   Status: AUDITED - http-server-fingerprint evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: HTTP/HTTPS
```

---

#### 14. **http-swagger-ui-exposure** - Http Swagger Ui Exposure
**Description:** Detects exposed interactive Swagger / OpenAPI documentation endpoints (/swagger-ui.html, /openapi.json, /v2/api-docs, /api/docs). Exposed API specifications reveal complete private API route schema...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script http-swagger-ui-exposure example.com

# Verbose output
nmap -p 80 --script http-swagger-ui-exposure -v example.com
```

**Sample Output:**
```
| http-swagger-ui-exposure:
|   Status: AUDITED - http-swagger-ui-exposure evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: HTTP/HTTPS
```

---

#### 15. **http-trace-method** - Http Trace Method
**Description:** Tests for Cross-Site Tracing (XST) exposure by sending TRACE and TRACK requests with a distinctive marker header across multiple paths, then checking whether the response body/headers echo the requ...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script http-trace-method example.com

# Verbose output
nmap -p 80 --script http-trace-method -v example.com
```

**Sample Output:**
```
| http-trace-method:
|   Status: AUDITED - http-trace-method evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: HTTP/HTTPS
```

---

#### 16. **http-waf-detect** - Http Waf Detect
**Description:** Detects the presence of Web Application Firewalls (WAF) and reverse proxy security solutions (Cloudflare, AWS WAF, Akamai, Imperva Incapsula, ModSecurity, F5 BIG-IP ASM) by analyzing HTTP response ...

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script http-waf-detect example.com

# Verbose output
nmap -p 80 --script http-waf-detect -v example.com
```

**Sample Output:**
```
| http-waf-detect:
|   Status: AUDITED - http-waf-detect evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: HTTP/HTTPS
```

---

</details>

<details>
<summary><b>🔍 DNS Security Audits — 16 scripts (click to expand)</b></summary>

## 🔍 DNS Security Audits

### Category Overview
DNS infrastructure vulnerabilities, zone transfers, amplification, subdomain enumeration, and DNSSEC.

**Port:** 53 | **Protocol:** DNS (UDP/TCP)

---

### DNS Scripts List

#### 1. **dns-amplification-risk** - Dns Amplification Risk
**Description:** Sends a small ANY-type query for a domain supplied via script-arg and compares the size of the query sent against the size of the response received to estimate the amplification factor. Resolvers t...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-amplification-risk example.com

# Verbose output
nmap -p 53 --script dns-amplification-risk -v example.com
```

**Sample Output:**
```
| dns-amplification-risk:
|   Status: AUDITED - dns-amplification-risk evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: DNS (UDP/TCP)
```

---

#### 2. **dns-axfr-source-spoof** - Dns Axfr Source Spoof
**Description:** Tests whether DNS zone transfers (AXFR) are restricted to authorized source IP addresses or open to arbitrary external hosts.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-axfr-source-spoof example.com

# Verbose output
nmap -p 53 --script dns-axfr-source-spoof -v example.com
```

**Sample Output:**
```
| dns-axfr-source-spoof:
|   Status: AUDITED - dns-axfr-source-spoof evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: DNS (UDP/TCP)
```

---

#### 3. **dns-cache-snooping** - Dns Cache Snooping
**Description:** Performs non-recursive queries (RD=0) for a list of popular domains against the target resolver. A non-recursive query only succeeds if the answer is already present in the resolver's cache, so a p...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-cache-snooping example.com

# Verbose output
nmap -p 53 --script dns-cache-snooping -v example.com
```

**Sample Output:**
```
| dns-cache-snooping:
|   Status: AUDITED - dns-cache-snooping evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: DNS (UDP/TCP)
```

---

#### 4. **dns-cname-takeover-audit** - Dns Cname Takeover Audit
**Description:** Audits CNAME records for dangling aliases pointing to unclaimed cloud services (S3, GitHub Pages, Heroku) susceptible to Subdomain Takeover.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-cname-takeover-audit example.com

# Verbose output
nmap -p 53 --script dns-cname-takeover-audit -v example.com
```

**Sample Output:**
```
| dns-cname-takeover-audit:
|   Status: AUDITED - dns-cname-takeover-audit evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: DNS (UDP/TCP)
```

---

#### 5. **dns-dnscrypt-support** - Dns Dnscrypt Support
**Description:** Probes whether a DNS server supports the DNSCrypt protocol extension for authenticated and encrypted DNS transport on UDP/TCP port 53 or 443.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-dnscrypt-support example.com

# Verbose output
nmap -p 53 --script dns-dnscrypt-support -v example.com
```

**Sample Output:**
```
| dns-dnscrypt-support:
|   Status: AUDITED - dns-dnscrypt-support evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: DNS (UDP/TCP)
```

---

#### 6. **dns-dnssec-validation** - Dns Dnssec Validation
**Description:** Evaluates whether a recursive DNS resolver validates DNSSEC signatures (RRSIG/DNSKEY) and sets the Authenticated Data (AD) flag in responses.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-dnssec-validation example.com

# Verbose output
nmap -p 53 --script dns-dnssec-validation -v example.com
```

**Sample Output:**
```
| dns-dnssec-validation:
|   Status: AUDITED - dns-dnssec-validation evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: DNS (UDP/TCP)
```

---

#### 7. **dns-doh-endpoint-probe** - Dns Doh Endpoint Probe
**Description:** Probes web and DNS endpoints for DNS-over-HTTPS (DoH) support via /dns-query.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-doh-endpoint-probe example.com

# Verbose output
nmap -p 53 --script dns-doh-endpoint-probe -v example.com
```

**Sample Output:**
```
| dns-doh-endpoint-probe:
|   Status: AUDITED - dns-doh-endpoint-probe evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: DNS (UDP/TCP)
```

---

#### 8. **dns-ns-recursion-abuse** - Dns Ns Recursion Abuse
**Description:** Tests DNS server response amplification ratio on ANY and EDNS0 queries to evaluate DDoS reflection risk.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-ns-recursion-abuse example.com

# Verbose output
nmap -p 53 --script dns-ns-recursion-abuse -v example.com
```

**Sample Output:**
```
| dns-ns-recursion-abuse:
|   Status: AUDITED - dns-ns-recursion-abuse evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: DNS (UDP/TCP)
```

---

#### 9. **dns-recursion-check** - Dns Recursion Check
**Description:** Sends a recursive query (RD=1) for a domain the target server is very unlikely to be authoritative for, and inspects whether the server sets RA=1 and returns a resolved answer. A server that recurs...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-recursion-check example.com

# Verbose output
nmap -p 53 --script dns-recursion-check -v example.com
```

**Sample Output:**
```
| dns-recursion-check:
|   Status: AUDITED - dns-recursion-check evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: DNS (UDP/TCP)
```

---

#### 10. **dns-reverse-ptr-leak** - Dns Reverse Ptr Leak
**Description:** Queries reverse PTR records on local IP ranges to discover internal server naming schemes and network infrastructure details.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-reverse-ptr-leak example.com

# Verbose output
nmap -p 53 --script dns-reverse-ptr-leak -v example.com
```

**Sample Output:**
```
| dns-reverse-ptr-leak:
|   Status: AUDITED - dns-reverse-ptr-leak evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: DNS (UDP/TCP)
```

---

#### 11. **dns-soa-consistency-check** - Dns Soa Consistency Check
**Description:** Queries the SOA record for a domain supplied via script-arg and reports its serial, refresh, retry, expire and minimum values, flagging parameter combinations that fall outside commonly recommended...

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-soa-consistency-check example.com

# Verbose output
nmap -p 53 --script dns-soa-consistency-check -v example.com
```

**Sample Output:**
```
| dns-soa-consistency-check:
|   Status: AUDITED - dns-soa-consistency-check evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: DNS (UDP/TCP)
```

---

#### 12. **dns-srv-enum** - Dns Srv Enum
**Description:** Queries a set of common SRV record names under a domain supplied via script-arg to enumerate advertised internal/external services such as SIP, LDAP, Kerberos, Autodiscover and XMPP, which can reve...

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-srv-enum example.com

# Verbose output
nmap -p 53 --script dns-srv-enum -v example.com
```

**Sample Output:**
```
| dns-srv-enum:
|   Status: AUDITED - dns-srv-enum evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: DNS (UDP/TCP)
```

---

#### 13. **dns-subdomain-enum** - Dns Subdomain Enum
**Description:** Brute forces a list of common subdomain labels against a domain supplied via script-arg by issuing A record queries through the target DNS server, and reports which subdomains resolve along with th...

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-subdomain-enum example.com

# Verbose output
nmap -p 53 --script dns-subdomain-enum -v example.com
```

**Sample Output:**
```
| dns-subdomain-enum:
|   Status: AUDITED - dns-subdomain-enum evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: DNS (UDP/TCP)
```

---

#### 14. **dns-txt-spf-dmarc-audit** - Dns Txt Spf Dmarc Audit
**Description:** Queries TXT records at the domain root for an SPF policy and at _dmarc.<domain> for a DMARC policy, then evaluates the strength of each: SPF mechanisms ending in a permissive "all" qualifier, and D...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-txt-spf-dmarc-audit example.com

# Verbose output
nmap -p 53 --script dns-txt-spf-dmarc-audit -v example.com
```

**Sample Output:**
```
| dns-txt-spf-dmarc-audit:
|   Status: AUDITED - dns-txt-spf-dmarc-audit evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: DNS (UDP/TCP)
```

---

#### 15. **dns-wildcard-detector** - Dns Wildcard Detector
**Description:** Queries several randomly generated subdomain labels under a domain supplied via script-arg. If most or all random, non-existent labels resolve to an IP address, the zone is using a wildcard DNS rec...

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-wildcard-detector example.com

# Verbose output
nmap -p 53 --script dns-wildcard-detector -v example.com
```

**Sample Output:**
```
| dns-wildcard-detector:
|   Status: AUDITED - dns-wildcard-detector evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: DNS (UDP/TCP)
```

---

#### 16. **dns-zone-transfer-check** - Dns Zone Transfer Check
**Description:** Attempts a full zone transfer (AXFR) against the target DNS server for a domain supplied via script-arg. A successful transfer indicates the server is misconfigured to allow unauthenticated zone tr...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-zone-transfer-check example.com

# Verbose output
nmap -p 53 --script dns-zone-transfer-check -v example.com
```

**Sample Output:**
```
| dns-zone-transfer-check:
|   Status: AUDITED - dns-zone-transfer-check evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: DNS (UDP/TCP)
```

---

</details>

<details>
<summary><b>🔐 SMB Protocol Security Audits — 16 scripts (click to expand)</b></summary>

## 🔐 SMB Protocol Security Audits

### Category Overview
SMB and Windows protocol misconfigurations, signing, null sessions, guest access, and dialect security.

**Port:** 139/445 | **Protocol:** SMB/Microsoft-DS

---

### SMB Scripts List

#### 1. **smb-anonymous-ipc-pipe** - Smb Anonymous Ipc Pipe
**Description:** Tests whether anonymous null sessions can connect to IPC$ named pipes (\pipe\samr, \pipe\lsarpc, \pipe\netlogon) to enumerate domain accounts.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 139 --script smb-anonymous-ipc-pipe example.com

# Verbose output
nmap -p 139 --script smb-anonymous-ipc-pipe -v example.com
```

**Sample Output:**
```
| smb-anonymous-ipc-pipe:
|   Status: AUDITED - smb-anonymous-ipc-pipe evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: SMB/Microsoft-DS
```

---

#### 2. **smb-buffer-limits** - Smb Buffer Limits
**Description:** Reports the buffer and transaction size limits negotiated during the SMB handshake (max buffer size, max multiplex count, max raw size, max transaction size where available). Useful recon context a...

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 139 --script smb-buffer-limits example.com

# Verbose output
nmap -p 139 --script smb-buffer-limits -v example.com
```

**Sample Output:**
```
| smb-buffer-limits:
|   Status: AUDITED - smb-buffer-limits evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SMB/Microsoft-DS
```

---

#### 3. **smb-capabilities** - Smb Capabilities
**Description:** Decodes the capability flags returned in the SMB negotiate response (raw mode, unicode, large files, NT SMBs, DFS, extended security, Unix extensions, compression, persistent handles, and others) i...

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 139 --script smb-capabilities example.com

# Verbose output
nmap -p 139 --script smb-capabilities -v example.com
```

**Sample Output:**
```
| smb-capabilities:
|   Status: AUDITED - smb-capabilities evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SMB/Microsoft-DS
```

---

#### 4. **smb-dfs-referral-leak** - Smb Dfs Referral Leak
**Description:** Queries Distributed File System (DFS) referrals to map domain share topology and DFS roots.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 139 --script smb-dfs-referral-leak example.com

# Verbose output
nmap -p 139 --script smb-dfs-referral-leak -v example.com
```

**Sample Output:**
```
| smb-dfs-referral-leak:
|   Status: AUDITED - smb-dfs-referral-leak evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SMB/Microsoft-DS
```

---

#### 5. **smb-eternalblue-precondition** - Smb Eternalblue Precondition
**Description:** Checks whether the SMB service accepts SMBv1 (NT LM 0.12) dialect negotiation, which is the mandatory precondition for MS17-010 (EternalBlue) exploitation.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 139 --script smb-eternalblue-precondition example.com

# Verbose output
nmap -p 139 --script smb-eternalblue-precondition -v example.com
```

**Sample Output:**
```
| smb-eternalblue-precondition:
|   Status: AUDITED - smb-eternalblue-precondition evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: SMB/Microsoft-DS
```

---

#### 6. **smb-extended-security** - Smb Extended Security
**Description:** Checks whether the server supports SMB extended security negotiation (SPNEGO, enabling NTLMv2 and Kerberos authentication) versus legacy authentication only. Servers limited to legacy authenticatio...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 139 --script smb-extended-security example.com

# Verbose output
nmap -p 139 --script smb-extended-security -v example.com
```

**Sample Output:**
```
| smb-extended-security:
|   Status: AUDITED - smb-extended-security evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SMB/Microsoft-DS
```

---

#### 7. **smb-guest-access-check** - Smb Guest Access Check
**Description:** Attempts to establish an SMB session using the built-in "guest" account with a blank password. Reports whether guest access is permitted, which can expose shares and files not intended for unauthen...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 139 --script smb-guest-access-check example.com

# Verbose output
nmap -p 139 --script smb-guest-access-check -v example.com
```

**Sample Output:**
```
| smb-guest-access-check:
|   Status: AUDITED - smb-guest-access-check evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SMB/Microsoft-DS
```

---

#### 8. **smb-ntlm-version-downgrade** - Smb Ntlm Version Downgrade
**Description:** Tests whether the SMB service accepts legacy NTLMv1 authentication responses, which can be cracked offline in deterministic time.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 139 --script smb-ntlm-version-downgrade example.com

# Verbose output
nmap -p 139 --script smb-ntlm-version-downgrade -v example.com
```

**Sample Output:**
```
| smb-ntlm-version-downgrade:
|   Status: AUDITED - smb-ntlm-version-downgrade evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: SMB/Microsoft-DS
```

---

#### 9. **smb-null-session-check** - Smb Null Session Check
**Description:** Attempts to establish an SMB session using a fully anonymous null session (empty username, empty password, empty domain). A server that accepts this is exposed to the classic SMB null session infor...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 139 --script smb-null-session-check example.com

# Verbose output
nmap -p 139 --script smb-null-session-check -v example.com
```

**Sample Output:**
```
| smb-null-session-check:
|   Status: AUDITED - smb-null-session-check evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SMB/Microsoft-DS
```

---

#### 10. **smb-protocol-dialects** - Smb Protocol Dialects
**Description:** Negotiates the SMB protocol and reports which dialect the server selected (SMBv1 "NT LM 0.12" through SMB 3.1.1). Flags SMBv1 as a deprecated, legacy dialect that should be disabled on modern systems.

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 139 --script smb-protocol-dialects example.com

# Verbose output
nmap -p 139 --script smb-protocol-dialects -v example.com
```

**Sample Output:**
```
| smb-protocol-dialects:
|   Status: AUDITED - smb-protocol-dialects evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SMB/Microsoft-DS
```

---

#### 11. **smb-security-level** - Smb Security Level
**Description:** For SMB1 (NT LM 0.12) negotiations, reports whether the server uses user-level or share-level security and whether it accepts plaintext passwords instead of challenge/response authentication. Not a...

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 139 --script smb-security-level example.com

# Verbose output
nmap -p 139 --script smb-security-level -v example.com
```

**Sample Output:**
```
| smb-security-level:
|   Status: AUDITED - smb-security-level evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SMB/Microsoft-DS
```

---

#### 12. **smb-share-accessibility** - Smb Share Accessibility
**Description:** Establishes an anonymous or guest SMB session (whichever succeeds first) and then attempts a tree connect to a set of default and administrative share names (IPC$, ADMIN$, C$, D$, print$) to report...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 139 --script smb-share-accessibility example.com

# Verbose output
nmap -p 139 --script smb-share-accessibility -v example.com
```

**Sample Output:**
```
| smb-share-accessibility:
|   Status: AUDITED - smb-share-accessibility evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SMB/Microsoft-DS
```

---

#### 13. **smb-signing-config** - Smb Signing Config
**Description:** Reports the SMB message signing configuration advertised in the negotiate response security_mode field: whether signing is enabled, and whether it is required. A server that allows unsigned session...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 139 --script smb-signing-config example.com

# Verbose output
nmap -p 139 --script smb-signing-config -v example.com
```

**Sample Output:**
```
| smb-signing-config:
|   Status: AUDITED - smb-signing-config evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SMB/Microsoft-DS
```

---

#### 14. **smb-smbghost-precondition** - Smb Smbghost Precondition
**Description:** Evaluates whether an SMBv3 server negotiates SMB 3.1.1 dialect with LZNT1 or LZ77 compression enabled (CVE-2020-0796 / SMBGhost precondition).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 139 --script smb-smbghost-precondition example.com

# Verbose output
nmap -p 139 --script smb-smbghost-precondition -v example.com
```

**Sample Output:**
```
| smb-smbghost-precondition:
|   Status: AUDITED - smb-smbghost-precondition evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: SMB/Microsoft-DS
```

---

#### 15. **smb-version-fingerprint** - Smb Version Fingerprint
**Description:** Extracts exact Windows OS build, NetBIOS computer name, workgroup/domain, and SMB dialect details.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 139 --script smb-version-fingerprint example.com

# Verbose output
nmap -p 139 --script smb-version-fingerprint -v example.com
```

**Sample Output:**
```
| smb-version-fingerprint:
|   Status: AUDITED - smb-version-fingerprint evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: SMB/Microsoft-DS
```

---

#### 16. **smb-webdav-exposure** - Smb Webdav Exposure
**Description:** Checks for WebDAV extensions and HTTP-to-SMB authentication redirection risks.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 139 --script smb-webdav-exposure example.com

# Verbose output
nmap -p 139 --script smb-webdav-exposure -v example.com
```

**Sample Output:**
```
| smb-webdav-exposure:
|   Status: AUDITED - smb-webdav-exposure evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SMB/Microsoft-DS
```

---

</details>

<details>
<summary><b>🛡️ SSL/TLS Protocol Security Audits — 16 scripts (click to expand)</b></summary>

## 🛡️ SSL/TLS Protocol Security Audits

### Category Overview
Cryptographic cipher suite strength, protocol version deprecation, certificate validation, and renegotiation.

**Port:** 443 | **Protocol:** SSL/TLS

---

### SSL-TLS Scripts List

#### 1. **ssl-alpn-negotiation** - Ssl Alpn Negotiation
**Description:** Probes Application-Layer Protocol Negotiation (ALPN) extension for HTTP/2 (h2) and HTTP/3 support.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-alpn-negotiation example.com

# Verbose output
nmap -p 443 --script ssl-alpn-negotiation -v example.com
```

**Sample Output:**
```
| ssl-alpn-negotiation:
|   Status: AUDITED - ssl-alpn-negotiation evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: SSL/TLS
```

---

#### 2. **ssl-cert-expiry** - Ssl Cert Expiry
**Description:** Checks the validity window of the presented TLS certificate against the current time. Flags certificates that are already expired, not yet valid, or expiring within a configurable warning threshold...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-cert-expiry example.com

# Verbose output
nmap -p 443 --script ssl-cert-expiry -v example.com
```

**Sample Output:**
```
| ssl-cert-expiry:
|   Status: AUDITED - ssl-cert-expiry evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SSL/TLS
```

---

#### 3. **ssl-cert-hostname-mismatch** - Ssl Cert Hostname Mismatch
**Description:** Compares the target hostname (or an explicitly supplied name via the ssl-cert-hostname-mismatch.name script argument) against the certificate's CommonName and Subject Alternative Names, including w...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-cert-hostname-mismatch example.com

# Verbose output
nmap -p 443 --script ssl-cert-hostname-mismatch -v example.com
```

**Sample Output:**
```
| ssl-cert-hostname-mismatch:
|   Status: AUDITED - ssl-cert-hostname-mismatch evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SSL/TLS
```

---

#### 4. **ssl-cert-info** - Ssl Cert Info
**Description:** Retrieves the X.509 certificate presented during the TLS handshake and reports subject, issuer, serial number, validity window, signature algorithm, public key details, Subject Alternative Names, a...

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-cert-info example.com

# Verbose output
nmap -p 443 --script ssl-cert-info -v example.com
```

**Sample Output:**
```
| ssl-cert-info:
|   Status: AUDITED - ssl-cert-info evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SSL/TLS
```

---

#### 5. **ssl-cert-weak-signature** - Ssl Cert Weak Signature
**Description:** Inspects the certificate's signature algorithm and public key strength for known-weak configurations: MD5 or SHA-1 signatures, RSA/DSA keys under 2048 bits, EC keys under 224 bits, and self-signed ...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-cert-weak-signature example.com

# Verbose output
nmap -p 443 --script ssl-cert-weak-signature -v example.com
```

**Sample Output:**
```
| ssl-cert-weak-signature:
|   Status: AUDITED - ssl-cert-weak-signature evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SSL/TLS
```

---

#### 6. **ssl-compression-check** - Ssl Compression Check
**Description:** Sends a ClientHello advertising both NULL and DEFLATE compression methods and inspects the ServerHello's chosen compression method. If the server selects DEFLATE, the connection is potentially expo...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-compression-check example.com

# Verbose output
nmap -p 443 --script ssl-compression-check -v example.com
```

**Sample Output:**
```
| ssl-compression-check:
|   Status: AUDITED - ssl-compression-check evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SSL/TLS
```

---

#### 7. **ssl-dh-params-weak** - Ssl Dh Params Weak
**Description:** Checks for weak Diffie-Hellman parameters (< 2048-bit prime moduli, Logjam attack risk).

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-dh-params-weak example.com

# Verbose output
nmap -p 443 --script ssl-dh-params-weak -v example.com
```

**Sample Output:**
```
| ssl-dh-params-weak:
|   Status: AUDITED - ssl-dh-params-weak evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: SSL/TLS
```

---

#### 8. **ssl-fallback-scsv** - Ssl Fallback Scsv
**Description:** Tests TLS_FALLBACK_SCSV support to prevent forced protocol downgrade attacks.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-fallback-scsv example.com

# Verbose output
nmap -p 443 --script ssl-fallback-scsv -v example.com
```

**Sample Output:**
```
| ssl-fallback-scsv:
|   Status: AUDITED - ssl-fallback-scsv evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SSL/TLS
```

---

#### 9. **ssl-heartbleed-precondition** - Ssl Heartbleed Precondition
**Description:** Evaluates TLS Heartbeat extension (RFC 6520) support, indicating potential susceptibility to CVE-2014-0160 (Heartbleed).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-heartbleed-precondition example.com

# Verbose output
nmap -p 443 --script ssl-heartbleed-precondition -v example.com
```

**Sample Output:**
```
| ssl-heartbleed-precondition:
|   Status: AUDITED - ssl-heartbleed-precondition evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: SSL/TLS
```

---

#### 10. **ssl-hsts-preload-status** - Ssl Hsts Preload Status
**Description:** Validates HSTS header max-age, includeSubDomains, and preload token compliance against browser preload lists.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-hsts-preload-status example.com

# Verbose output
nmap -p 443 --script ssl-hsts-preload-status -v example.com
```

**Sample Output:**
```
| ssl-hsts-preload-status:
|   Status: AUDITED - ssl-hsts-preload-status evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SSL/TLS
```

---

#### 11. **ssl-ocsp-stapling** - Ssl Ocsp Stapling
**Description:** Sends a ClientHello including the status_request extension (RFC 6066) requesting an OCSP response, then inspects the handshake messages returned by the server for a CertificateStatus message, indic...

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-ocsp-stapling example.com

# Verbose output
nmap -p 443 --script ssl-ocsp-stapling -v example.com
```

**Sample Output:**
```
| ssl-ocsp-stapling:
|   Status: AUDITED - ssl-ocsp-stapling evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SSL/TLS
```

---

#### 12. **ssl-poodle-sslv3** - Ssl Poodle Sslv3
**Description:** Checks whether the server supports SSLv3 protocol with CBC mode ciphers (POODLE / CVE-2014-3566).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-poodle-sslv3 example.com

# Verbose output
nmap -p 443 --script ssl-poodle-sslv3 -v example.com
```

**Sample Output:**
```
| ssl-poodle-sslv3:
|   Status: AUDITED - ssl-poodle-sslv3 evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: SSL/TLS
```

---

#### 13. **ssl-protocol-versions** - Ssl Protocol Versions
**Description:** Attempts a minimal TLS handshake for each protocol version (SSLv3, TLSv1.0, TLSv1.1, TLSv1.2, and a best-effort TLSv1.3 probe via the supported_versions extension) and reports which versions the se...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-protocol-versions example.com

# Verbose output
nmap -p 443 --script ssl-protocol-versions -v example.com
```

**Sample Output:**
```
| ssl-protocol-versions:
|   Status: AUDITED - ssl-protocol-versions evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SSL/TLS
```

---

#### 14. **ssl-secure-renegotiation** - Ssl Secure Renegotiation
**Description:** Sends a ClientHello including the renegotiation_info extension (RFC 5746) and checks whether the server's ServerHello echoes the extension back. Absence of the extension indicates the server may be...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-secure-renegotiation example.com

# Verbose output
nmap -p 443 --script ssl-secure-renegotiation -v example.com
```

**Sample Output:**
```
| ssl-secure-renegotiation:
|   Status: AUDITED - ssl-secure-renegotiation evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SSL/TLS
```

---

#### 15. **ssl-sweet32-check** - Ssl Sweet32 Check
**Description:** Detects 64-bit block cipher suites (3DES, IDEA, Blowfish) vulnerable to Sweet32 (CVE-2016-2183).

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-sweet32-check example.com

# Verbose output
nmap -p 443 --script ssl-sweet32-check -v example.com
```

**Sample Output:**
```
| ssl-sweet32-check:
|   Status: AUDITED - ssl-sweet32-check evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: SSL/TLS
```

---

#### 16. **ssl-weak-ciphers** - Ssl Weak Ciphers
**Description:** Advertises groups of known-weak TLS cipher suites (NULL ciphers, export-grade ciphers, DES/3DES, RC4, and anonymous Diffie-Hellman) in separate ClientHello attempts and reports which groups the ser...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script ssl-weak-ciphers example.com

# Verbose output
nmap -p 443 --script ssl-weak-ciphers -v example.com
```

**Sample Output:**
```
| ssl-weak-ciphers:
|   Status: AUDITED - ssl-weak-ciphers evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SSL/TLS
```

---

</details>

<details>
<summary><b>🗄️ Database Security Audits — 16 scripts (click to expand)</b></summary>

## 🗄️ Database Security Audits

### Category Overview
Unauthenticated access, weak credentials, and transport encryption across SQL and NoSQL engines.

**Port:** 1433/3306/5432/6379/27017/9042 | **Protocol:** Database wire protocols

---

### DATABASE Scripts List

#### 1. **cassandra-unauth-check** - Cassandra Unauth Check
**Description:** Checks for unauthenticated CQL native protocol access on Apache Cassandra (port 9042).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1433 --script cassandra-unauth-check example.com

# Verbose output
nmap -p 1433 --script cassandra-unauth-check -v example.com
```

**Sample Output:**
```
| cassandra-unauth-check:
|   Status: AUDITED - cassandra-unauth-check evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Database wire protocols
```

---

#### 2. **clickhouse-unauth-check** - Clickhouse Unauth Check
**Description:** Probes ClickHouse HTTP interface on port 8123 for unauthenticated query execution.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1433 --script clickhouse-unauth-check example.com

# Verbose output
nmap -p 1433 --script clickhouse-unauth-check -v example.com
```

**Sample Output:**
```
| clickhouse-unauth-check:
|   Status: AUDITED - clickhouse-unauth-check evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: Database wire protocols
```

---

#### 3. **couchdb-unauth-check** - Couchdb Unauth Check
**Description:** Probes Apache CouchDB (port 5984) for unauthenticated administrative access to /_all_dbs and /_membership.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1433 --script couchdb-unauth-check example.com

# Verbose output
nmap -p 1433 --script couchdb-unauth-check -v example.com
```

**Sample Output:**
```
| couchdb-unauth-check:
|   Status: AUDITED - couchdb-unauth-check evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Database wire protocols
```

---

#### 4. **etcd-unauth-keyspace** - Etcd Unauth Keyspace
**Description:** Probes etcd distributed key-value store on port 2379 for unauthenticated keyspace dumping (/v2/keys or /v3/kv/range).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1433 --script etcd-unauth-keyspace example.com

# Verbose output
nmap -p 1433 --script etcd-unauth-keyspace -v example.com
```

**Sample Output:**
```
| etcd-unauth-keyspace:
|   Status: AUDITED - etcd-unauth-keyspace evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Database wire protocols
```

---

#### 5. **influxdb-unauth-check** - Influxdb Unauth Check
**Description:** Probes InfluxDB API (port 8086) for unauthenticated query execution (/query?q=SHOW+DATABASES).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1433 --script influxdb-unauth-check example.com

# Verbose output
nmap -p 1433 --script influxdb-unauth-check -v example.com
```

**Sample Output:**
```
| influxdb-unauth-check:
|   Status: AUDITED - influxdb-unauth-check evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Database wire protocols
```

---

#### 6. **memcached-stats-dump** - Memcached Stats Dump
**Description:** Sends stats and stats items to Memcached on port 11211 to extract cached key counts and memory metrics.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1433 --script memcached-stats-dump example.com

# Verbose output
nmap -p 1433 --script memcached-stats-dump -v example.com
```

**Sample Output:**
```
| memcached-stats-dump:
|   Status: AUDITED - memcached-stats-dump evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Database wire protocols
```

---

#### 7. **mongodb-unauthenticated-check** - Mongodb Unauthenticated Check
**Description:** Sends an OP_MSG "hello" (legacy alias "isMaster") command to a MongoDB instance without authenticating and inspects the BSON response for maxWireVersion and the isWritablePrimary/ismaster fields to...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1433 --script mongodb-unauthenticated-check example.com

# Verbose output
nmap -p 1433 --script mongodb-unauthenticated-check -v example.com
```

**Sample Output:**
```
| mongodb-unauthenticated-check:
|   Status: AUDITED - mongodb-unauthenticated-check evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Database wire protocols
```

---

#### 8. **mssql-prelogin-check** - Mssql Prelogin Check
**Description:** Sends a TDS PRELOGIN packet to a Microsoft SQL Server instance and parses the VERSION and ENCRYPTION options from the response to report the server's product version and whether TLS encryption is o...

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1433 --script mssql-prelogin-check example.com

# Verbose output
nmap -p 1433 --script mssql-prelogin-check -v example.com
```

**Sample Output:**
```
| mssql-prelogin-check:
|   Status: AUDITED - mssql-prelogin-check evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Database wire protocols
```

---

#### 9. **mysql-banner-grab** - Mysql Banner Grab
**Description:** Connects to a MySQL/MariaDB service and parses the server's initial handshake packet (Protocol::HandshakeV10) to extract the protocol version, server version string, and negotiated capability flags...

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1433 --script mysql-banner-grab example.com

# Verbose output
nmap -p 1433 --script mysql-banner-grab -v example.com
```

**Sample Output:**
```
| mysql-banner-grab:
|   Status: AUDITED - mysql-banner-grab evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Database wire protocols
```

---

#### 10. **mysql-empty-password-check** - Mysql Empty Password Check
**Description:** Attempts to authenticate as the "root" account with an empty password using the MySQL Protocol::HandshakeResponse41 message and the mysql_native_password plugin. Reports whether the server accepted...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1433 --script mysql-empty-password-check example.com

# Verbose output
nmap -p 1433 --script mysql-empty-password-check -v example.com
```

**Sample Output:**
```
| mysql-empty-password-check:
|   Status: AUDITED - mysql-empty-password-check evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Database wire protocols
```

---

#### 11. **mysql-ssl-support-check** - Mysql Ssl Support Check
**Description:** Parses the capability flags in the MySQL/MariaDB initial handshake packet to determine whether the server advertises CLIENT_SSL support, indicating that connections can optionally or must be encryp...

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1433 --script mysql-ssl-support-check example.com

# Verbose output
nmap -p 1433 --script mysql-ssl-support-check -v example.com
```

**Sample Output:**
```
| mysql-ssl-support-check:
|   Status: AUDITED - mysql-ssl-support-check evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Database wire protocols
```

---

#### 12. **neo4j-unauth-browser** - Neo4J Unauth Browser
**Description:** Probes Neo4j Graph Database HTTP management interface on port 7474 for unauthenticated discovery endpoints.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1433 --script neo4j-unauth-browser example.com

# Verbose output
nmap -p 1433 --script neo4j-unauth-browser -v example.com
```

**Sample Output:**
```
| neo4j-unauth-browser:
|   Status: AUDITED - neo4j-unauth-browser evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: Database wire protocols
```

---

#### 13. **postgresql-ssl-support-check** - Postgresql Ssl Support Check
**Description:** Sends a PostgreSQL SSLRequest packet and checks the single-byte response ('S' for supported, 'N' for not supported) to determine whether the server can negotiate an encrypted connection before the ...

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1433 --script postgresql-ssl-support-check example.com

# Verbose output
nmap -p 1433 --script postgresql-ssl-support-check -v example.com
```

**Sample Output:**
```
| postgresql-ssl-support-check:
|   Status: AUDITED - postgresql-ssl-support-check evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Database wire protocols
```

---

#### 14. **postgresql-trust-auth-check** - Postgresql Trust Auth Check
**Description:** Sends a PostgreSQL StartupMessage for the "postgres" user/database and inspects the server's authentication request to determine the configured authentication method. An immediate AuthenticationOk ...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1433 --script postgresql-trust-auth-check example.com

# Verbose output
nmap -p 1433 --script postgresql-trust-auth-check -v example.com
```

**Sample Output:**
```
| postgresql-trust-auth-check:
|   Status: AUDITED - postgresql-trust-auth-check evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Database wire protocols
```

---

#### 15. **redis-admin-command-exposure** - Redis Admin Command Exposure
**Description:** Uses the read-only COMMAND INFO subcommand to check whether a set of high-risk administrative Redis commands (FLUSHALL, FLUSHDB, CONFIG, SHUTDOWN, DEBUG, SLAVEOF, REPLICAOF, MODULE, SCRIPT) are pre...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1433 --script redis-admin-command-exposure example.com

# Verbose output
nmap -p 1433 --script redis-admin-command-exposure -v example.com
```

**Sample Output:**
```
| redis-admin-command-exposure:
|   Status: AUDITED - redis-admin-command-exposure evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Database wire protocols
```

---

#### 16. **redis-unauthenticated-access** - Redis Unauthenticated Access
**Description:** Sends PING and INFO commands to a Redis service without any AUTH command and reports whether the server processes them, indicating unauthenticated access is permitted. If INFO succeeds, extracts th...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1433 --script redis-unauthenticated-access example.com

# Verbose output
nmap -p 1433 --script redis-unauthenticated-access -v example.com
```

**Sample Output:**
```
| redis-unauthenticated-access:
|   Status: AUDITED - redis-unauthenticated-access evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Database wire protocols
```

---

</details>

<details>
<summary><b>📁 FTP Security Audits — 16 scripts (click to expand)</b></summary>

## 📁 FTP Security Audits

### Category Overview
Anonymous access, cleartext credential enforcement, directory listings, writable directories, and FTPS support.

**Port:** 21 | **Protocol:** FTP/FTPS

---

### FTP Scripts List

#### 1. **ftp-anonymous-login** - Ftp Anonymous Login
**Description:** Attempts anonymous FTP login using a set of common anonymous credential pairs (anonymous/anonymous, anonymous/anonymous@example.com, ftp/ftp, and blank password) and reports whether unauthenticated...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-anonymous-login example.com

# Verbose output
nmap -p 21 --script ftp-anonymous-login -v example.com
```

**Sample Output:**
```
| ftp-anonymous-login:
|   Status: AUDITED - ftp-anonymous-login evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: FTP/FTPS
```

---

#### 2. **ftp-banner-grab** - Ftp Banner Grab
**Description:** Grabs the FTP welcome banner and attempts to fingerprint the server software and version from it (vsftpd, ProFTPD, Pure-FTPd, FileZilla Server, Microsoft FTP Service, WU-FTPD, glFTPd, Serv-U, and o...

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-banner-grab example.com

# Verbose output
nmap -p 21 --script ftp-banner-grab -v example.com
```

**Sample Output:**
```
| ftp-banner-grab:
|   Status: AUDITED - ftp-banner-grab evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: FTP/FTPS
```

---

#### 3. **ftp-bounce-check** - Ftp Bounce Check
**Description:** Checks whether the FTP server accepts a PORT command specifying an IP address other than the client's own control-connection address. This script only tests whether the PORT command is syntacticall...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-bounce-check example.com

# Verbose output
nmap -p 21 --script ftp-bounce-check -v example.com
```

**Sample Output:**
```
| ftp-bounce-check:
|   Status: AUDITED - ftp-bounce-check evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: FTP/FTPS
```

---

#### 4. **ftp-brute-rate-limit** - Ftp Brute Rate Limit
**Description:** Tests whether the FTP daemon throttles consecutive failed login attempts or allows fast password brute-forcing.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-brute-rate-limit example.com

# Verbose output
nmap -p 21 --script ftp-brute-rate-limit -v example.com
```

**Sample Output:**
```
| ftp-brute-rate-limit:
|   Status: AUDITED - ftp-brute-rate-limit evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: FTP/FTPS
```

---

#### 5. **ftp-chroot-escape-precondition** - Ftp Chroot Escape Precondition
**Description:** Tests directory traversal and chroot containment patterns (CWD /.../, CDUP) across FTP root tree.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-chroot-escape-precondition example.com

# Verbose output
nmap -p 21 --script ftp-chroot-escape-precondition -v example.com
```

**Sample Output:**
```
| ftp-chroot-escape-precondition:
|   Status: AUDITED - ftp-chroot-escape-precondition evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: FTP/FTPS
```

---

#### 6. **ftp-cleartext-enforcement** - Ftp Cleartext Enforcement
**Description:** Attempts a plaintext USER/PASS login without first negotiating TLS and reports whether the server processes the credentials in the clear or refuses login until AUTH TLS/AUTH SSL has been performed....

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-cleartext-enforcement example.com

# Verbose output
nmap -p 21 --script ftp-cleartext-enforcement -v example.com
```

**Sample Output:**
```
| ftp-cleartext-enforcement:
|   Status: AUDITED - ftp-cleartext-enforcement evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: FTP/FTPS
```

---

#### 7. **ftp-command-enum** - Ftp Command Enum
**Description:** Enumerates supported FTP extended features via the FEAT command and probes for a set of individually risky or notable commands (SITE EXEC, SITE CHMOD, SITE, MDTM, SIZE, REST, RNFR/RNTO) to determin...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-command-enum example.com

# Verbose output
nmap -p 21 --script ftp-command-enum -v example.com
```

**Sample Output:**
```
| ftp-command-enum:
|   Status: AUDITED - ftp-command-enum evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: FTP/FTPS
```

---

#### 8. **ftp-directory-listing** - Ftp Directory Listing
**Description:** Logs in anonymously and lists the root directory plus a set of common subdirectories, then scans the returned filenames against a set of sensitive keyword patterns (backup, config, password, .sql, ...

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-directory-listing example.com

# Verbose output
nmap -p 21 --script ftp-directory-listing -v example.com
```

**Sample Output:**
```
| ftp-directory-listing:
|   Status: AUDITED - ftp-directory-listing evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: FTP/FTPS
```

---

#### 9. **ftp-fxp-cross-server** - Ftp Fxp Cross Server
**Description:** Tests whether the FTP server allows File Exchange Protocol (FXP) third-party server-to-server data connections.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-fxp-cross-server example.com

# Verbose output
nmap -p 21 --script ftp-fxp-cross-server -v example.com
```

**Sample Output:**
```
| ftp-fxp-cross-server:
|   Status: AUDITED - ftp-fxp-cross-server evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: FTP/FTPS
```

---

#### 10. **ftp-passive-mode-check** - Ftp Passive Mode Check
**Description:** Sends PASV and EPSV commands and inspects the returned data-channel address. Flags cases where the PASV response advertises a private/ internal IP address different from the control connection's pu...

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-passive-mode-check example.com

# Verbose output
nmap -p 21 --script ftp-passive-mode-check -v example.com
```

**Sample Output:**
```
| ftp-passive-mode-check:
|   Status: AUDITED - ftp-passive-mode-check evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: FTP/FTPS
```

---

#### 11. **ftp-proftpd-mod-copy** - Ftp Proftpd Mod Copy
**Description:** Probes ProFTPD mod_copy (CPFR / CPTO) unauthenticated file copying commands (CVE-2015-3306).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-proftpd-mod-copy example.com

# Verbose output
nmap -p 21 --script ftp-proftpd-mod-copy -v example.com
```

**Sample Output:**
```
| ftp-proftpd-mod-copy:
|   Status: AUDITED - ftp-proftpd-mod-copy evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: FTP/FTPS
```

---

#### 12. **ftp-syst-fingerprint** - Ftp Syst Fingerprint
**Description:** Sends SYST and FEAT commands to fingerprint FTP daemon family and supported RFC extensions.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-syst-fingerprint example.com

# Verbose output
nmap -p 21 --script ftp-syst-fingerprint -v example.com
```

**Sample Output:**
```
| ftp-syst-fingerprint:
|   Status: AUDITED - ftp-syst-fingerprint evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: FTP/FTPS
```

---

#### 13. **ftp-tls-cipher-audit** - Ftp Tls Cipher Audit
**Description:** Audits SSL/TLS cipher suites and protocol versions negotiated over explicit FTPS (AUTH TLS).

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-tls-cipher-audit example.com

# Verbose output
nmap -p 21 --script ftp-tls-cipher-audit -v example.com
```

**Sample Output:**
```
| ftp-tls-cipher-audit:
|   Status: AUDITED - ftp-tls-cipher-audit evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: FTP/FTPS
```

---

#### 14. **ftp-tls-support** - Ftp Tls Support
**Description:** Checks whether the FTP server supports explicit FTPS by sending AUTH TLS and AUTH SSL commands, and inspects the FEAT command response for advertised AUTH, PBSZ and PROT mechanisms. A server offeri...

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-tls-support example.com

# Verbose output
nmap -p 21 --script ftp-tls-support -v example.com
```

**Sample Output:**
```
| ftp-tls-support:
|   Status: AUDITED - ftp-tls-support evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: FTP/FTPS
```

---

#### 15. **ftp-vsftpd-backdoor-fingerprint** - Ftp Vsftpd Backdoor Fingerprint
**Description:** Checks for the vsftpd 2.3.4 smiley face backdoor banner signature (CVE-2011-2523).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-vsftpd-backdoor-fingerprint example.com

# Verbose output
nmap -p 21 --script ftp-vsftpd-backdoor-fingerprint -v example.com
```

**Sample Output:**
```
| ftp-vsftpd-backdoor-fingerprint:
|   Status: AUDITED - ftp-vsftpd-backdoor-fingerprint evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: FTP/FTPS
```

---

#### 16. **ftp-writable-dirs** - Ftp Writable Dirs
**Description:** Logs in anonymously and attempts to upload a small harmless test file into a set of common directories to determine which are writable by unauthenticated users. Any successfully uploaded test file ...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 21 --script ftp-writable-dirs example.com

# Verbose output
nmap -p 21 --script ftp-writable-dirs -v example.com
```

**Sample Output:**
```
| ftp-writable-dirs:
|   Status: AUDITED - ftp-writable-dirs evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: FTP/FTPS
```

---

</details>

<details>
<summary><b>🐳 Docker Engine & Registry Security Audits — 16 scripts (click to expand)</b></summary>

## 🐳 Docker Engine & Registry Security Audits

### Category Overview
Daemon REST API exposure, container breakout vectors, secrets leakage, volume binds, and registry security.

**Port:** 2375/2376/5000/2377/4243 | **Protocol:** Docker REST API

---

### DOCKER Scripts List

#### 1. **docker-build-cache-leak** - Docker Build Cache Leak
**Description:** Connects to an accessible Docker REST API, enumerates intermediate build images and dangling layers (/images/json?all=1), and inspects image history (/images/{id}/history) for residual build argume...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 2375 --script docker-build-cache-leak example.com

# Verbose output
nmap -p 2375 --script docker-build-cache-leak -v example.com
```

**Sample Output:**
```
| docker-build-cache-leak:
|   Status: AUDITED - docker-build-cache-leak evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Docker REST API
```

---

#### 2. **docker-cgroup-resource-limits** - Docker Cgroup Resource Limits
**Description:** Audits Docker containers on an accessible REST API for missing cgroup resource limits. Identifies containers with: 1. No memory limits (Memory: 0) — allows runaway processes to trigger host Out-Of-...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 2375 --script docker-cgroup-resource-limits example.com

# Verbose output
nmap -p 2375 --script docker-cgroup-resource-limits -v example.com
```

**Sample Output:**
```
| docker-cgroup-resource-limits:
|   Status: AUDITED - docker-cgroup-resource-limits evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Docker REST API
```

---

#### 3. **docker-container-inspect-secrets** - Docker Container Inspect Secrets
**Description:** Queries an accessible Docker REST API for all active and stopped containers (/containers/json?all=1) and inspects their configuration metadata (/containers/{id}/json) to detect plaintext secrets, p...

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 2375 --script docker-container-inspect-secrets example.com

# Verbose output
nmap -p 2375 --script docker-container-inspect-secrets -v example.com
```

**Sample Output:**
```
| docker-container-inspect-secrets:
|   Status: AUDITED - docker-container-inspect-secrets evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Docker REST API
```

---

#### 4. **docker-daemon-security-opts** - Docker Daemon Security Opts
**Description:** Evaluates the host-level Docker daemon security options returned by the /info endpoint. Audits whether hardening features are enabled or missing: 1. AppArmor / SELinux mandatory access control 2. D...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 2375 --script docker-daemon-security-opts example.com

# Verbose output
nmap -p 2375 --script docker-daemon-security-opts -v example.com
```

**Sample Output:**
```
| docker-daemon-security-opts:
|   Status: AUDITED - docker-daemon-security-opts evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Docker REST API
```

---

#### 5. **docker-debug-pprof-exposure** - Docker Debug Pprof Exposure
**Description:** Probes Docker daemon and container management endpoints for exposed Go runtime profiling endpoints (/debug/pprof, /debug/vars). These debug interfaces expose: 1. Active Goroutine stack traces and e...

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 2375 --script docker-debug-pprof-exposure example.com

# Verbose output
nmap -p 2375 --script docker-debug-pprof-exposure -v example.com
```

**Sample Output:**
```
| docker-debug-pprof-exposure:
|   Status: AUDITED - docker-debug-pprof-exposure evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: Docker REST API
```

---

#### 6. **docker-event-stream-exposure** - Docker Event Stream Exposure
**Description:** Evaluates whether the Docker daemon /events streaming endpoint is accessible without authentication. The Docker events API continuously streams real-time system events (container creation, start, e...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 2375 --script docker-event-stream-exposure example.com

# Verbose output
nmap -p 2375 --script docker-event-stream-exposure -v example.com
```

**Sample Output:**
```
| docker-event-stream-exposure:
|   Status: AUDITED - docker-event-stream-exposure evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Docker REST API
```

---

#### 7. **docker-network-host-mode** - Docker Network Host Mode
**Description:** Audits container network configurations on an accessible Docker REST API. Detects: 1. Containers running with host networking (NetworkMode: host) which bypasses    network isolation, exposes local ...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 2375 --script docker-network-host-mode example.com

# Verbose output
nmap -p 2375 --script docker-network-host-mode -v example.com
```

**Sample Output:**
```
| docker-network-host-mode:
|   Status: AUDITED - docker-network-host-mode evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Docker REST API
```

---

#### 8. **docker-privileged-containers** - Docker Privileged Containers
**Description:** Audits containers on an accessible Docker REST API to identify instances running with dangerous execution privileges, including: 1. Privileged mode (HostConfig.Privileged: true) 2. High-risk Linux ...

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 2375 --script docker-privileged-containers example.com

# Verbose output
nmap -p 2375 --script docker-privileged-containers -v example.com
```

**Sample Output:**
```
| docker-privileged-containers:
|   Status: AUDITED - docker-privileged-containers evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Docker REST API
```

---

#### 9. **docker-registry-delete-allowed** - Docker Registry Delete Allowed
**Description:** Evaluates whether a Docker Registry v2 endpoint permits unauthenticated DELETE requests on manifests and image tags. If deletion is enabled (REGISTRY_STORAGE_DELETE_ENABLED=true) without strict aut...

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 2375 --script docker-registry-delete-allowed example.com

# Verbose output
nmap -p 2375 --script docker-registry-delete-allowed -v example.com
```

**Sample Output:**
```
| docker-registry-delete-allowed:
|   Status: AUDITED - docker-registry-delete-allowed evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: Docker REST API
```

---

#### 10. **docker-registry-manifest-leak** - Docker Registry Manifest Leak
**Description:** Connects to an accessible Docker Registry v2, enumerates image tags via /v2/<repo>/tags/list, and downloads image manifests (/v2/<repo>/manifests/<tag>) to inspect container layer history, Dockerfi...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 2375 --script docker-registry-manifest-leak example.com

# Verbose output
nmap -p 2375 --script docker-registry-manifest-leak -v example.com
```

**Sample Output:**
```
| docker-registry-manifest-leak:
|   Status: AUDITED - docker-registry-manifest-leak evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Docker REST API
```

---

#### 11. **docker-registry-unauth-catalog** - Docker Registry Unauth Catalog
**Description:** Detects unauthenticated Docker Registry v2 services and enumerates hosted private container repositories via the /v2/_catalog endpoint. An open Docker registry allows unauthenticated users to downl...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 2375 --script docker-registry-unauth-catalog example.com

# Verbose output
nmap -p 2375 --script docker-registry-unauth-catalog -v example.com
```

**Sample Output:**
```
| docker-registry-unauth-catalog:
|   Status: AUDITED - docker-registry-unauth-catalog evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Docker REST API
```

---

#### 12. **docker-socket-proxy-misconfig** - Docker Socket Proxy Misconfig
**Description:** Tests Docker socket security proxies (such as tecnativa/docker-socket-proxy, HAProxy, or Nginx Docker reverse proxies) for method-filtering misconfigurations. Socket proxies are intended to expose ...

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 2375 --script docker-socket-proxy-misconfig example.com

# Verbose output
nmap -p 2375 --script docker-socket-proxy-misconfig -v example.com
```

**Sample Output:**
```
| docker-socket-proxy-misconfig:
|   Status: AUDITED - docker-socket-proxy-misconfig evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Docker REST API
```

---

#### 13. **docker-swarm-node-leak** - Docker Swarm Node Leak
**Description:** Queries an unauthenticated Docker daemon to detect if Docker Swarm cluster mode is active, and extracts sensitive Swarm topology data: 1. Swarm Cluster ID and Join Tokens (Manager & Worker join tok...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 2375 --script docker-swarm-node-leak example.com

# Verbose output
nmap -p 2375 --script docker-swarm-node-leak -v example.com
```

**Sample Output:**
```
| docker-swarm-node-leak:
|   Status: AUDITED - docker-swarm-node-leak evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Docker REST API
```

---

#### 14. **docker-unauthenticated-api** - Docker Unauthenticated Api
**Description:** Detects unauthenticated access to the Docker Engine REST API (typically exposed on TCP ports 2375 or 2376). When the API is accessible without client TLS certificates or bearer authentication, the ...

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 2375 --script docker-unauthenticated-api example.com

# Verbose output
nmap -p 2375 --script docker-unauthenticated-api -v example.com
```

**Sample Output:**
```
| docker-unauthenticated-api:
|   Status: AUDITED - docker-unauthenticated-api evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Docker REST API
```

---

#### 15. **docker-version-cve-fingerprint** - Docker Version Cve Fingerprint
**Description:** Extracts Docker Engine, containerd, and runc component versions from the /version endpoint and performs defensive fingerprinting against known critical container vulnerabilities, including: 1. CVE-...

**Risk Level:** 🟢 LOW | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 2375 --script docker-version-cve-fingerprint example.com

# Verbose output
nmap -p 2375 --script docker-version-cve-fingerprint -v example.com
```

**Sample Output:**
```
| docker-version-cve-fingerprint:
|   Status: AUDITED - docker-version-cve-fingerprint evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: Docker REST API
```

---

#### 16. **docker-volume-host-mounts** - Docker Volume Host Mounts
**Description:** Inspects storage mounts and host filesystem binds across containers on an accessible Docker REST API. Flags dangerous host path exposures, including: 1. Docker daemon socket mounts (/var/run/docker...

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 2375 --script docker-volume-host-mounts example.com

# Verbose output
nmap -p 2375 --script docker-volume-host-mounts -v example.com
```

**Sample Output:**
```
| docker-volume-host-mounts:
|   Status: AUDITED - docker-volume-host-mounts evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Docker REST API
```

---

</details>

<details>
<summary><b>🔮 GraphQL API Security Audits — 16 scripts (click to expand)</b></summary>

## 🔮 GraphQL API Security Audits

### Category Overview
Schema introspection leaks, batch query amplification, circular query depth, alias multiplication, and IDE exposures.

**Port:** 80/443/3000/4000/8080 | **Protocol:** GraphQL HTTP/WS

---

### GRAPHQL Scripts List

#### 1. **graphql-alias-overloading** - Graphql Alias Overloading
**Description:** Evaluates whether a GraphQL server limits the number of field aliases in a single request. By defining hundreds of field aliases (e.g. { a1: user, a2: user, ... }), an attacker can force the GraphQ...

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script graphql-alias-overloading example.com

# Verbose output
nmap -p 80 --script graphql-alias-overloading -v example.com
```

**Sample Output:**
```
| graphql-alias-overloading:
|   Status: AUDITED - graphql-alias-overloading evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: GraphQL HTTP/WS
```

---

#### 2. **graphql-batch-query-abuse** - Graphql Batch Query Abuse
**Description:** Evaluates whether a GraphQL server supports array-based batch query execution without imposing batch size limits or per-query rate limiting. Batching allows an attacker to wrap hundreds of individu...

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script graphql-batch-query-abuse example.com

# Verbose output
nmap -p 80 --script graphql-batch-query-abuse -v example.com
```

**Sample Output:**
```
| graphql-batch-query-abuse:
|   Status: AUDITED - graphql-batch-query-abuse evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: GraphQL HTTP/WS
```

---

#### 3. **graphql-circular-query-depth** - Graphql Circular Query Depth
**Description:** Evaluates whether a GraphQL server enforces maximum query depth limits. Sends progressively deeper nested queries using the built-in introspection type tree (__schema { types { fields { type { fiel...

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script graphql-circular-query-depth example.com

# Verbose output
nmap -p 80 --script graphql-circular-query-depth -v example.com
```

**Sample Output:**
```
| graphql-circular-query-depth:
|   Status: AUDITED - graphql-circular-query-depth evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: GraphQL HTTP/WS
```

---

#### 4. **graphql-content-type-bypass** - Graphql Content Type Bypass
**Description:** Evaluates whether a GraphQL server parses and executes GraphQL queries sent with non-standard HTTP Content-Type headers (text/plain, application/x-www-form-urlencoded, or missing Content-Type). If ...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script graphql-content-type-bypass example.com

# Verbose output
nmap -p 80 --script graphql-content-type-bypass -v example.com
```

**Sample Output:**
```
| graphql-content-type-bypass:
|   Status: AUDITED - graphql-content-type-bypass evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: GraphQL HTTP/WS
```

---

#### 5. **graphql-cost-analysis-bypass** - Graphql Cost Analysis Bypass
**Description:** Evaluates whether a GraphQL server implements Query Cost Analysis (Complexity Calculation) or allows computationally heavy, multi-field, and multi-argument expansion queries to execute unrestricted...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script graphql-cost-analysis-bypass example.com

# Verbose output
nmap -p 80 --script graphql-cost-analysis-bypass -v example.com
```

**Sample Output:**
```
| graphql-cost-analysis-bypass:
|   Status: AUDITED - graphql-cost-analysis-bypass evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: GraphQL HTTP/WS
```

---

#### 6. **graphql-debug-trace-exposure** - Graphql Debug Trace Exposure
**Description:** Detects whether a GraphQL server returns sensitive debugging extensions (Apollo Tracing, GraphQL-Java tracing, debug exceptions, or execution metrics) in HTTP responses. These debug extensions expo...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script graphql-debug-trace-exposure example.com

# Verbose output
nmap -p 80 --script graphql-debug-trace-exposure -v example.com
```

**Sample Output:**
```
| graphql-debug-trace-exposure:
|   Status: AUDITED - graphql-debug-trace-exposure evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: GraphQL HTTP/WS
```

---

#### 7. **graphql-endpoint-discovery** - Graphql Endpoint Discovery
**Description:** Performs comprehensive endpoint discovery for GraphQL interfaces across 35+ standard, framework-specific, and obfuscated URL paths (e.g. /graphql, /api/graphql, /v1/graphql, /query, /gql, /hasura/v...

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script graphql-endpoint-discovery example.com

# Verbose output
nmap -p 80 --script graphql-endpoint-discovery -v example.com
```

**Sample Output:**
```
| graphql-endpoint-discovery:
|   Status: AUDITED - graphql-endpoint-discovery evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: GraphQL HTTP/WS
```

---

#### 8. **graphql-error-info-disclosure** - Graphql Error Info Disclosure
**Description:** Probes GraphQL endpoints with malformed syntax, invalid types, and unexpected arguments to audit the structure of returned error messages. Detects information leakage including: 1. Database error m...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script graphql-error-info-disclosure example.com

# Verbose output
nmap -p 80 --script graphql-error-info-disclosure -v example.com
```

**Sample Output:**
```
| graphql-error-info-disclosure:
|   Status: AUDITED - graphql-error-info-disclosure evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: GraphQL HTTP/WS
```

---

#### 9. **graphql-field-suggestions** - Graphql Field Suggestions
**Description:** Tests whether a GraphQL endpoint leaks schema fields via didactic field suggestions (e.g. "Cannot query field 'passwrd' on type 'Query'. Did you mean 'password'?"). Even when schema introspection (...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script graphql-field-suggestions example.com

# Verbose output
nmap -p 80 --script graphql-field-suggestions -v example.com
```

**Sample Output:**
```
| graphql-field-suggestions:
|   Status: AUDITED - graphql-field-suggestions evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: GraphQL HTTP/WS
```

---

#### 10. **graphql-get-mutation-bypass** - Graphql Get Mutation Bypass
**Description:** Evaluates whether a GraphQL server permits executing GraphQL mutations over HTTP GET requests (e.g. GET /graphql?query=mutation+Probe{__typename}). According to GraphQL over HTTP specifications, mu...

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script graphql-get-mutation-bypass example.com

# Verbose output
nmap -p 80 --script graphql-get-mutation-bypass -v example.com
```

**Sample Output:**
```
| graphql-get-mutation-bypass:
|   Status: AUDITED - graphql-get-mutation-bypass evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: GraphQL HTTP/WS
```

---

#### 11. **graphql-ide-exposure** - Graphql Ide Exposure
**Description:** Detects whether interactive GraphQL web development consoles and IDEs (GraphiQL, GraphQL Playground, Altair GraphQL Client, Apollo Sandbox, Prisma Studio) are exposed to external networks. Leaving ...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script graphql-ide-exposure example.com

# Verbose output
nmap -p 80 --script graphql-ide-exposure -v example.com
```

**Sample Output:**
```
| graphql-ide-exposure:
|   Status: AUDITED - graphql-ide-exposure evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: GraphQL HTTP/WS
```

---

#### 12. **graphql-introspection-enabled** - Graphql Introspection Enabled
**Description:** Detects whether GraphQL schema introspection (__schema, __type) is enabled on the target web service. In production environments, introspection allows unauthenticated attackers to download the enti...

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script graphql-introspection-enabled example.com

# Verbose output
nmap -p 80 --script graphql-introspection-enabled -v example.com
```

**Sample Output:**
```
| graphql-introspection-enabled:
|   Status: AUDITED - graphql-introspection-enabled evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: GraphQL HTTP/WS
```

---

#### 13. **graphql-persisted-queries-audit** - Graphql Persisted Queries Audit
**Description:** Audits support for Automatic Persisted Queries (APQ) on a GraphQL endpoint. Tests whether: 1. APQ protocol (extensions.persistedQuery) is supported by the server. 2. The server accepts arbitrary un...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script graphql-persisted-queries-audit example.com

# Verbose output
nmap -p 80 --script graphql-persisted-queries-audit -v example.com
```

**Sample Output:**
```
| graphql-persisted-queries-audit:
|   Status: AUDITED - graphql-persisted-queries-audit evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: GraphQL HTTP/WS
```

---

#### 14. **graphql-schema-directive-leak** - Graphql Schema Directive Leak
**Description:** Audits GraphQL custom schema directives (__schema { directives { ... } }) to detect exposed internal authorization policies, role definitions, and sensitive annotations (@auth, @hasRole, @admin, @r...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script graphql-schema-directive-leak example.com

# Verbose output
nmap -p 80 --script graphql-schema-directive-leak -v example.com
```

**Sample Output:**
```
| graphql-schema-directive-leak:
|   Status: AUDITED - graphql-schema-directive-leak evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: GraphQL HTTP/WS
```

---

#### 15. **graphql-subscription-websocket** - Graphql Subscription Websocket
**Description:** Evaluates whether a GraphQL WebSocket subscription endpoint (/graphql, /subscriptions, /ws) accepts unauthenticated WebSocket upgrades using standard GraphQL subprotocols (graphql-ws, subscriptions...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script graphql-subscription-websocket example.com

# Verbose output
nmap -p 80 --script graphql-subscription-websocket -v example.com
```

**Sample Output:**
```
| graphql-subscription-websocket:
|   Status: AUDITED - graphql-subscription-websocket evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: GraphQL HTTP/WS
```

---

#### 16. **graphql-unauth-mutation-detection** - Graphql Unauth Mutation Detection
**Description:** Discovers exposed mutating root operations (Mutation schema type) on a GraphQL endpoint and evaluates whether state-altering operations (such as user creation, password reset, configuration updates...

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script graphql-unauth-mutation-detection example.com

# Verbose output
nmap -p 80 --script graphql-unauth-mutation-detection -v example.com
```

**Sample Output:**
```
| graphql-unauth-mutation-detection:
|   Status: AUDITED - graphql-unauth-mutation-detection evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: GraphQL HTTP/WS
```

---

</details>

<details>
<summary><b>📡 MQTT & IoT Protocol Security Audits — 16 scripts (click to expand)</b></summary>

## 📡 MQTT & IoT Protocol Security Audits

### Category Overview
Unauthenticated broker access, wildcard telemetry harvesting, internal $SYS metrics, and mutual TLS enforcement.

**Port:** 1883/8883/1884 | **Protocol:** MQTT 3.1/3.1.1/5.0

---

### MQTT Scripts List

#### 1. **mqtt-anonymous-publish-test** - Mqtt Anonymous Publish Test
**Description:** Evaluates whether an MQTT broker allows unauthenticated clients to publish messages (write/inject data) to topics. Connects anonymously and sends a safe diagnostic PUBLISH packet with QoS 1 to an a...

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1883 --script mqtt-anonymous-publish-test example.com

# Verbose output
nmap -p 1883 --script mqtt-anonymous-publish-test -v example.com
```

**Sample Output:**
```
| mqtt-anonymous-publish-test:
|   Status: AUDITED - mqtt-anonymous-publish-test evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: MQTT 3.1/3.1.1/5.0
```

---

#### 2. **mqtt-broker-fingerprint** - Mqtt Broker Fingerprint
**Description:** Fingerprints the MQTT message broker engine (Eclipse Mosquitto, EMQX, HiveMQ, VerneMQ, Apache ActiveMQ, RabbitMQ MQTT Plugin, AWS IoT Core) by analyzing MQTT 3.1.1 and MQTT 5.0 CONNACK response byt...

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1883 --script mqtt-broker-fingerprint example.com

# Verbose output
nmap -p 1883 --script mqtt-broker-fingerprint -v example.com
```

**Sample Output:**
```
| mqtt-broker-fingerprint:
|   Status: AUDITED - mqtt-broker-fingerprint evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: MQTT 3.1/3.1.1/5.0
```

---

#### 3. **mqtt-cleartext-credential-risk** - Mqtt Cleartext Credential Risk
**Description:** Evaluates whether an MQTT broker accepts authentication credentials over unencrypted plain-text TCP connections (typically port 1883). Transmitting MQTT usernames and passwords in cleartext allows ...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1883 --script mqtt-cleartext-credential-risk example.com

# Verbose output
nmap -p 1883 --script mqtt-cleartext-credential-risk -v example.com
```

**Sample Output:**
```
| mqtt-cleartext-credential-risk:
|   Status: AUDITED - mqtt-cleartext-credential-risk evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: MQTT 3.1/3.1.1/5.0
```

---

#### 4. **mqtt-clientid-spoof-hijack** - Mqtt Clientid Spoof Hijack
**Description:** Tests whether an MQTT broker permits connecting with arbitrary, fixed, or privileged Client IDs (e.g. gateway, bridge, admin, master) without enforcing Client-ID-to-Certificate bindings or token AC...

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1883 --script mqtt-clientid-spoof-hijack example.com

# Verbose output
nmap -p 1883 --script mqtt-clientid-spoof-hijack -v example.com
```

**Sample Output:**
```
| mqtt-clientid-spoof-hijack:
|   Status: AUDITED - mqtt-clientid-spoof-hijack evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: MQTT 3.1/3.1.1/5.0
```

---

#### 5. **mqtt-default-credentials** - Mqtt Default Credentials
**Description:** Attempts authentication against an MQTT broker using a curated set of common default and weak IoT/industrial credentials (admin/admin, root/root, mosquitto/mosquitto, emqx/public, hivemq/hivemq, us...

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1883 --script mqtt-default-credentials example.com

# Verbose output
nmap -p 1883 --script mqtt-default-credentials -v example.com
```

**Sample Output:**
```
| mqtt-default-credentials:
|   Status: AUDITED - mqtt-default-credentials evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: MQTT 3.1/3.1.1/5.0
```

---

#### 6. **mqtt-keepalive-dos-tolerance** - Mqtt Keepalive Dos Tolerance
**Description:** Evaluates how an MQTT broker handles extreme KeepAlive values (KeepAlive = 0 disabling timeout, and KeepAlive = 65535s). According to the MQTT standard, a KeepAlive value of 0 instructs the broker ...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1883 --script mqtt-keepalive-dos-tolerance example.com

# Verbose output
nmap -p 1883 --script mqtt-keepalive-dos-tolerance -v example.com
```

**Sample Output:**
```
| mqtt-keepalive-dos-tolerance:
|   Status: AUDITED - mqtt-keepalive-dos-tolerance evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: MQTT 3.1/3.1.1/5.0
```

---

#### 7. **mqtt-packet-size-limit** - Mqtt Packet Size Limit
**Description:** Evaluates whether an MQTT broker enforces Maximum Packet Size limits. Sends malformed/oversized packet length headers (e.g. Remaining Length with maximum 4-byte 256MB variable length encoding: 0xFF...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1883 --script mqtt-packet-size-limit example.com

# Verbose output
nmap -p 1883 --script mqtt-packet-size-limit -v example.com
```

**Sample Output:**
```
| mqtt-packet-size-limit:
|   Status: AUDITED - mqtt-packet-size-limit evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: MQTT 3.1/3.1.1/5.0
```

---

#### 8. **mqtt-protocol-version-support** - Mqtt Protocol Version Support
**Description:** Probes an MQTT broker across multiple protocol versions: 1. MQTT 3.1 (Legacy MQIsdp protocol name, version 3) 2. MQTT 3.1.1 (Standard OASIS MQTT, version 4) 3. MQTT 5.0 (Enhanced features, user pro...

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1883 --script mqtt-protocol-version-support example.com

# Verbose output
nmap -p 1883 --script mqtt-protocol-version-support -v example.com
```

**Sample Output:**
```
| mqtt-protocol-version-support:
|   Status: AUDITED - mqtt-protocol-version-support evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: MQTT 3.1/3.1.1/5.0
```

---

#### 9. **mqtt-qos2-handshake-audit** - Mqtt Qos2 Handshake Audit
**Description:** Audits the MQTT Quality of Service 2 (QoS 2 - Exactly Once) protocol state machine implementation on the target broker. Executes the four-step handshake: 1. Client -> Broker: PUBLISH (QoS 2, Packet...

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1883 --script mqtt-qos2-handshake-audit example.com

# Verbose output
nmap -p 1883 --script mqtt-qos2-handshake-audit -v example.com
```

**Sample Output:**
```
| mqtt-qos2-handshake-audit:
|   Status: AUDITED - mqtt-qos2-handshake-audit evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: MQTT 3.1/3.1.1/5.0
```

---

#### 10. **mqtt-retained-message-harvest** - Mqtt Retained Message Harvest
**Description:** Connects to an accessible MQTT broker and harvests retained messages (messages with RETAIN flag set). Retained messages persist indefinitely in broker memory and disk storage, and are immediately d...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1883 --script mqtt-retained-message-harvest example.com

# Verbose output
nmap -p 1883 --script mqtt-retained-message-harvest -v example.com
```

**Sample Output:**
```
| mqtt-retained-message-harvest:
|   Status: AUDITED - mqtt-retained-message-harvest evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: MQTT 3.1/3.1.1/5.0
```

---

#### 11. **mqtt-sys-topic-leak** - Mqtt Sys Topic Leak
**Description:** Subscribes to the MQTT broker internal system topic hierarchy ($SYS/#) and harvests operational metrics and infrastructure details, including: 1. Broker software name and version ($SYS/broker/versi...

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1883 --script mqtt-sys-topic-leak example.com

# Verbose output
nmap -p 1883 --script mqtt-sys-topic-leak -v example.com
```

**Sample Output:**
```
| mqtt-sys-topic-leak:
|   Status: AUDITED - mqtt-sys-topic-leak evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: MQTT 3.1/3.1.1/5.0
```

---

#### 12. **mqtt-tls-client-cert-check** - Mqtt Tls Client Cert Check
**Description:** Evaluates whether an MQTT TLS endpoint (typically TCP port 8883) strictly enforces Mutual TLS (mTLS / client certificate authentication) or allows anonymous TLS handshakes without client certificat...

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1883 --script mqtt-tls-client-cert-check example.com

# Verbose output
nmap -p 1883 --script mqtt-tls-client-cert-check -v example.com
```

**Sample Output:**
```
| mqtt-tls-client-cert-check:
|   Status: AUDITED - mqtt-tls-client-cert-check evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: MQTT 3.1/3.1.1/5.0
```

---

#### 13. **mqtt-topic-permission-bypass** - Mqtt Topic Permission Bypass
**Description:** Audits Topic Access Control List (ACL) enforcement on an MQTT broker. Connects anonymously and attempts to subscribe to commonly protected or administrative topic paths (admin/#, system/#, control/...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1883 --script mqtt-topic-permission-bypass example.com

# Verbose output
nmap -p 1883 --script mqtt-topic-permission-bypass -v example.com
```

**Sample Output:**
```
| mqtt-topic-permission-bypass:
|   Status: AUDITED - mqtt-topic-permission-bypass evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: MQTT 3.1/3.1.1/5.0
```

---

#### 14. **mqtt-unauthenticated-broker** - Mqtt Unauthenticated Broker
**Description:** Detects unauthenticated MQTT message brokers (typically listening on TCP ports 1883 or 8883). Connects using an unauthenticated MQTT 3.1.1 CONNECT packet with no credentials and evaluates the broke...

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1883 --script mqtt-unauthenticated-broker example.com

# Verbose output
nmap -p 1883 --script mqtt-unauthenticated-broker -v example.com
```

**Sample Output:**
```
| mqtt-unauthenticated-broker:
|   Status: AUDITED - mqtt-unauthenticated-broker evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: MQTT 3.1/3.1.1/5.0
```

---

#### 15. **mqtt-wildcard-subscribe-all** - Mqtt Wildcard Subscribe All
**Description:** Connects to an MQTT broker anonymously, subscribes to the root multi-level wildcard topic (#), and listens for incoming PUBLISH messages. Audits received topics and message payloads for sensitive i...

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1883 --script mqtt-wildcard-subscribe-all example.com

# Verbose output
nmap -p 1883 --script mqtt-wildcard-subscribe-all -v example.com
```

**Sample Output:**
```
| mqtt-wildcard-subscribe-all:
|   Status: AUDITED - mqtt-wildcard-subscribe-all evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: MQTT 3.1/3.1.1/5.0
```

---

#### 16. **mqtt-will-message-injection** - Mqtt Will Message Injection
**Description:** Evaluates whether an MQTT broker permits anonymous clients to register arbitrary Last Will and Testament (LWT) messages on sensitive topic paths (such as system/status, alerts/emergency, or devices...

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 1883 --script mqtt-will-message-injection example.com

# Verbose output
nmap -p 1883 --script mqtt-will-message-injection -v example.com
```

**Sample Output:**
```
| mqtt-will-message-injection:
|   Status: AUDITED - mqtt-will-message-injection evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: MQTT 3.1/3.1.1/5.0
```

---

</details>

<details>
<summary><b>🔑 SSH Protocol & Key Security Audits — 16 scripts (click to expand)</b></summary>

## 🔑 SSH Protocol & Key Security Audits

### Category Overview
SSH cryptographic algorithms, deprecated ciphers, weak host keys, password authentication, and CVE fingerprinting.

**Port:** 22 | **Protocol:** SSH-2.0

---

### SSH Scripts List

#### 1. **ssh-agent-forwarding-probe** - Ssh Agent Forwarding Probe
**Description:** Probes SSH agent forwarding negotiation options and environment handling.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 22 --script ssh-agent-forwarding-probe example.com

# Verbose output
nmap -p 22 --script ssh-agent-forwarding-probe -v example.com
```

**Sample Output:**
```
| ssh-agent-forwarding-probe:
|   Status: AUDITED - ssh-agent-forwarding-probe evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SSH-2.0
```

---

#### 2. **ssh-auth-methods-enum** - Ssh Auth Methods Enum
**Description:** Sends none auth request to enumerate allowed authentication methods (password, publickey).

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 22 --script ssh-auth-methods-enum example.com

# Verbose output
nmap -p 22 --script ssh-auth-methods-enum -v example.com
```

**Sample Output:**
```
| ssh-auth-methods-enum:
|   Status: AUDITED - ssh-auth-methods-enum evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SSH-2.0
```

---

#### 3. **ssh-compression-support** - Ssh Compression Support
**Description:** Checks for zlib/zlib@openssh.com compression support before/after authentication.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 22 --script ssh-compression-support example.com

# Verbose output
nmap -p 22 --script ssh-compression-support -v example.com
```

**Sample Output:**
```
| ssh-compression-support:
|   Status: AUDITED - ssh-compression-support evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: SSH-2.0
```

---

#### 4. **ssh-hostkey-fingerprint** - Ssh Hostkey Fingerprint
**Description:** Extracts RSA/ECDSA/Ed25519 host keys and generates MD5/SHA256 fingerprints.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 22 --script ssh-hostkey-fingerprint example.com

# Verbose output
nmap -p 22 --script ssh-hostkey-fingerprint -v example.com
```

**Sample Output:**
```
| ssh-hostkey-fingerprint:
|   Status: AUDITED - ssh-hostkey-fingerprint evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: SSH-2.0
```

---

#### 5. **ssh-hostkey-size-audit** - Ssh Hostkey Size Audit
**Description:** Verifies RSA host key length is >= 2048 bits and DSA keys are deprecated.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 22 --script ssh-hostkey-size-audit example.com

# Verbose output
nmap -p 22 --script ssh-hostkey-size-audit -v example.com
```

**Sample Output:**
```
| ssh-hostkey-size-audit:
|   Status: AUDITED - ssh-hostkey-size-audit evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SSH-2.0
```

---

#### 6. **ssh-keyboard-interactive-info** - Ssh Keyboard Interactive Info
**Description:** Inspects keyboard-interactive prompts and PAM banner disclosures.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 22 --script ssh-keyboard-interactive-info example.com

# Verbose output
nmap -p 22 --script ssh-keyboard-interactive-info -v example.com
```

**Sample Output:**
```
| ssh-keyboard-interactive-info:
|   Status: AUDITED - ssh-keyboard-interactive-info evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: SSH-2.0
```

---

#### 7. **ssh-libssh-bypass-check** - Ssh Libssh Bypass Check
**Description:** Checks for libssh authentication bypass vulnerability fingerprint (CVE-2018-10933).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 22 --script ssh-libssh-bypass-check example.com

# Verbose output
nmap -p 22 --script ssh-libssh-bypass-check -v example.com
```

**Sample Output:**
```
| ssh-libssh-bypass-check:
|   Status: AUDITED - ssh-libssh-bypass-check evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: SSH-2.0
```

---

#### 8. **ssh-max-auth-tries** - Ssh Max Auth Tries
**Description:** Tests SSH MaxAuthTries configuration by submitting multiple bad auth attempts.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 22 --script ssh-max-auth-tries example.com

# Verbose output
nmap -p 22 --script ssh-max-auth-tries -v example.com
```

**Sample Output:**
```
| ssh-max-auth-tries:
|   Status: AUDITED - ssh-max-auth-tries evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SSH-2.0
```

---

#### 9. **ssh-password-auth-allowed** - Ssh Password Auth Allowed
**Description:** Checks if password authentication is permitted instead of enforcing publickey-only.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 22 --script ssh-password-auth-allowed example.com

# Verbose output
nmap -p 22 --script ssh-password-auth-allowed -v example.com
```

**Sample Output:**
```
| ssh-password-auth-allowed:
|   Status: AUDITED - ssh-password-auth-allowed evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SSH-2.0
```

---

#### 10. **ssh-regresshion-cve-check** - Ssh Regresshion Cve Check
**Description:** Fingerprints OpenSSH versions vulnerable to regreSSHion signal handler race condition (CVE-2024-6387).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 22 --script ssh-regresshion-cve-check example.com

# Verbose output
nmap -p 22 --script ssh-regresshion-cve-check -v example.com
```

**Sample Output:**
```
| ssh-regresshion-cve-check:
|   Status: AUDITED - ssh-regresshion-cve-check evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: SSH-2.0
```

---

#### 11. **ssh-root-login-allowed** - Ssh Root Login Allowed
**Description:** Probes whether root account authentication is permitted or explicitly disabled.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 22 --script ssh-root-login-allowed example.com

# Verbose output
nmap -p 22 --script ssh-root-login-allowed -v example.com
```

**Sample Output:**
```
| ssh-root-login-allowed:
|   Status: AUDITED - ssh-root-login-allowed evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: SSH-2.0
```

---

#### 12. **ssh-terrapin-vulnerability** - Ssh Terrapin Vulnerability
**Description:** Evaluates susceptibility to Terrapin attack (CVE-2023-48795) via ChaCha20-Poly1305 / EtM.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 22 --script ssh-terrapin-vulnerability example.com

# Verbose output
nmap -p 22 --script ssh-terrapin-vulnerability -v example.com
```

**Sample Output:**
```
| ssh-terrapin-vulnerability:
|   Status: AUDITED - ssh-terrapin-vulnerability evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: SSH-2.0
```

---

#### 13. **ssh-unauth-banner-grab** - Ssh Unauth Banner Grab
**Description:** Grabs SSH identification string, protocol version (SSH-2.0 vs SSH-1.99), and software banner.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 22 --script ssh-unauth-banner-grab example.com

# Verbose output
nmap -p 22 --script ssh-unauth-banner-grab -v example.com
```

**Sample Output:**
```
| ssh-unauth-banner-grab:
|   Status: AUDITED - ssh-unauth-banner-grab evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: SSH-2.0
```

---

#### 14. **ssh-weak-ciphers** - Ssh Weak Ciphers
**Description:** Checks for weak/broken symmetric encryption ciphers (3des-cbc, arcfour, blowfish-cbc).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 22 --script ssh-weak-ciphers example.com

# Verbose output
nmap -p 22 --script ssh-weak-ciphers -v example.com
```

**Sample Output:**
```
| ssh-weak-ciphers:
|   Status: AUDITED - ssh-weak-ciphers evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: SSH-2.0
```

---

#### 15. **ssh-weak-kex-algorithms** - Ssh Weak Kex Algorithms
**Description:** Probes SSH Key Exchange algorithms for weak/deprecated ones (diffie-hellman-group1-sha1).

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 22 --script ssh-weak-kex-algorithms example.com

# Verbose output
nmap -p 22 --script ssh-weak-kex-algorithms -v example.com
```

**Sample Output:**
```
| ssh-weak-kex-algorithms:
|   Status: AUDITED - ssh-weak-kex-algorithms evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: SSH-2.0
```

---

#### 16. **ssh-weak-macs** - Ssh Weak Macs
**Description:** Checks for weak Message Authentication Codes (hmac-md5, hmac-sha1-96).

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 22 --script ssh-weak-macs example.com

# Verbose output
nmap -p 22 --script ssh-weak-macs -v example.com
```

**Sample Output:**
```
| ssh-weak-macs:
|   Status: AUDITED - ssh-weak-macs evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: SSH-2.0
```

---

</details>

<details>
<summary><b>📊 SNMP Community & MIB Security Audits — 16 scripts (click to expand)</b></summary>

## 📊 SNMP Community & MIB Security Audits

### Category Overview
Default community strings, network routing tables, process execution leaks, and SNMPv3 security levels.

**Port:** 161 | **Protocol:** SNMPv1/v2c/v3 (UDP)

---

### SNMP Scripts List

#### 1. **snmp-amplification-factor** - Snmp Amplification Factor
**Description:** Measures UDP response payload size amplification factor for DDoS reflection risk.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 161 --script snmp-amplification-factor example.com

# Verbose output
nmap -p 161 --script snmp-amplification-factor -v example.com
```

**Sample Output:**
```
| snmp-amplification-factor:
|   Status: AUDITED - snmp-amplification-factor evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: SNMPv1/v2c/v3 (UDP)
```

---

#### 2. **snmp-arp-table-leak** - Snmp Arp Table Leak
**Description:** Queries ipNetToMediaPhysAddress to dump ARP table and active host IP/MAC mappings.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 161 --script snmp-arp-table-leak example.com

# Verbose output
nmap -p 161 --script snmp-arp-table-leak -v example.com
```

**Sample Output:**
```
| snmp-arp-table-leak:
|   Status: AUDITED - snmp-arp-table-leak evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SNMPv1/v2c/v3 (UDP)
```

---

#### 3. **snmp-cisco-config-copy** - Snmp Cisco Config Copy
**Description:** Checks for Cisco CISCO-CONFIG-COPY-MIB OID presence allowing remote TFTP config copy.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 161 --script snmp-cisco-config-copy example.com

# Verbose output
nmap -p 161 --script snmp-cisco-config-copy -v example.com
```

**Sample Output:**
```
| snmp-cisco-config-copy:
|   Status: AUDITED - snmp-cisco-config-copy evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: SNMPv1/v2c/v3 (UDP)
```

---

#### 4. **snmp-default-community** - Snmp Default Community
**Description:** Probes SNMPv1/v2c with common default community strings (public, private, community, cisco).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 161 --script snmp-default-community example.com

# Verbose output
nmap -p 161 --script snmp-default-community -v example.com
```

**Sample Output:**
```
| snmp-default-community:
|   Status: AUDITED - snmp-default-community evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: SNMPv1/v2c/v3 (UDP)
```

---

#### 5. **snmp-device-type-fingerprint** - Snmp Device Type Fingerprint
**Description:** Fingerprints device hardware category (Router, Switch, Firewall, Printer, Server, UPS).

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 161 --script snmp-device-type-fingerprint example.com

# Verbose output
nmap -p 161 --script snmp-device-type-fingerprint -v example.com
```

**Sample Output:**
```
| snmp-device-type-fingerprint:
|   Status: AUDITED - snmp-device-type-fingerprint evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: SNMPv1/v2c/v3 (UDP)
```

---

#### 6. **snmp-installed-software** - Snmp Installed Software
**Description:** Queries hrSWInstalledTable to dump installed OS software packages and versions.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 161 --script snmp-installed-software example.com

# Verbose output
nmap -p 161 --script snmp-installed-software -v example.com
```

**Sample Output:**
```
| snmp-installed-software:
|   Status: AUDITED - snmp-installed-software evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SNMPv1/v2c/v3 (UDP)
```

---

#### 7. **snmp-interfaces-dump** - Snmp Interfaces Dump
**Description:** Dumps network interface table (ifDescr, ifType, ifSpeed, ifPhysAddress, ifAdminStatus).

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 161 --script snmp-interfaces-dump example.com

# Verbose output
nmap -p 161 --script snmp-interfaces-dump -v example.com
```

**Sample Output:**
```
| snmp-interfaces-dump:
|   Status: AUDITED - snmp-interfaces-dump evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SNMPv1/v2c/v3 (UDP)
```

---

#### 8. **snmp-ip-routing-table** - Snmp Ip Routing Table
**Description:** Dumps IP routing table (ipRouteDest, ipRouteNextHop, ipRouteMask) leaking network topology.

**Risk Level:** 🟠 HIGH | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 161 --script snmp-ip-routing-table example.com

# Verbose output
nmap -p 161 --script snmp-ip-routing-table -v example.com
```

**Sample Output:**
```
| snmp-ip-routing-table:
|   Status: AUDITED - snmp-ip-routing-table evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: SNMPv1/v2c/v3 (UDP)
```

---

#### 9. **snmp-running-processes** - Snmp Running Processes
**Description:** Queries HOST-RESOURCES-MIB hrSWRunTable to list running processes and daemon paths.

**Risk Level:** 🟠 HIGH | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 161 --script snmp-running-processes example.com

# Verbose output
nmap -p 161 --script snmp-running-processes -v example.com
```

**Sample Output:**
```
| snmp-running-processes:
|   Status: AUDITED - snmp-running-processes evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: SNMPv1/v2c/v3 (UDP)
```

---

#### 10. **snmp-snmpv3-auth-probe** - Snmp Snmpv3 Auth Probe
**Description:** Probes SNMPv3 engine ID, security levels (noAuthNoPriv, authNoPriv, authPriv), and USM users.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 161 --script snmp-snmpv3-auth-probe example.com

# Verbose output
nmap -p 161 --script snmp-snmpv3-auth-probe -v example.com
```

**Sample Output:**
```
| snmp-snmpv3-auth-probe:
|   Status: AUDITED - snmp-snmpv3-auth-probe evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SNMPv1/v2c/v3 (UDP)
```

---

#### 11. **snmp-snmpv3-weak-auth** - Snmp Snmpv3 Weak Auth
**Description:** Checks for weak SNMPv3 auth protocols (MD5 vs SHA256) and DES/3DES encryption.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 161 --script snmp-snmpv3-weak-auth example.com

# Verbose output
nmap -p 161 --script snmp-snmpv3-weak-auth -v example.com
```

**Sample Output:**
```
| snmp-snmpv3-weak-auth:
|   Status: AUDITED - snmp-snmpv3-weak-auth evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: SNMPv1/v2c/v3 (UDP)
```

---

#### 12. **snmp-storage-metrics** - Snmp Storage Metrics
**Description:** Queries hrStorageTable for disk partitions, total memory, and filesystem utilization.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 161 --script snmp-storage-metrics example.com

# Verbose output
nmap -p 161 --script snmp-storage-metrics -v example.com
```

**Sample Output:**
```
| snmp-storage-metrics:
|   Status: AUDITED - snmp-storage-metrics evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: SNMPv1/v2c/v3 (UDP)
```

---

#### 13. **snmp-system-info-leak** - Snmp System Info Leak
**Description:** Queries sysDescr, sysObjectID, sysUpTime, sysContact, sysName, sysLocation OIDs.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 161 --script snmp-system-info-leak example.com

# Verbose output
nmap -p 161 --script snmp-system-info-leak -v example.com
```

**Sample Output:**
```
| snmp-system-info-leak:
|   Status: AUDITED - snmp-system-info-leak evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SNMPv1/v2c/v3 (UDP)
```

---

#### 14. **snmp-tcp-udp-connections** - Snmp Tcp Udp Connections
**Description:** Dumps active TCP listening ports and UDP listeners via tcpConnTable / udpTable.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 161 --script snmp-tcp-udp-connections example.com

# Verbose output
nmap -p 161 --script snmp-tcp-udp-connections -v example.com
```

**Sample Output:**
```
| snmp-tcp-udp-connections:
|   Status: AUDITED - snmp-tcp-udp-connections evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SNMPv1/v2c/v3 (UDP)
```

---

#### 15. **snmp-user-accounts-leak** - Snmp User Accounts Leak
**Description:** Queries enterprise MIBs and process tables for local user accounts and login names.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 161 --script snmp-user-accounts-leak example.com

# Verbose output
nmap -p 161 --script snmp-user-accounts-leak -v example.com
```

**Sample Output:**
```
| snmp-user-accounts-leak:
|   Status: AUDITED - snmp-user-accounts-leak evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: SNMPv1/v2c/v3 (UDP)
```

---

#### 16. **snmp-write-access-check** - Snmp Write Access Check
**Description:** Tests if SNMP community string grants write permissions (SetRequest on test OID).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 161 --script snmp-write-access-check example.com

# Verbose output
nmap -p 161 --script snmp-write-access-check -v example.com
```

**Sample Output:**
```
| snmp-write-access-check:
|   Status: AUDITED - snmp-write-access-check evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: SNMPv1/v2c/v3 (UDP)
```

---

</details>

<details>
<summary><b>🌳 LDAP Directory & Active Directory Audits — 16 scripts (click to expand)</b></summary>

## 🌳 LDAP Directory & Active Directory Audits

### Category Overview
Anonymous binding, rootDSE leaks, user account attributes, SPN accounts, and AS-REP roasting candidates.

**Port:** 389/636 | **Protocol:** LDAP/LDAPS

---

### LDAP Scripts List

#### 1. **ldap-ad-domain-info** - Ldap Ad Domain Info
**Description:** Extracts Active Directory forest name, schema version, domain controller roles.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 389 --script ldap-ad-domain-info example.com

# Verbose output
nmap -p 389 --script ldap-ad-domain-info -v example.com
```

**Sample Output:**
```
| ldap-ad-domain-info:
|   Status: AUDITED - ldap-ad-domain-info evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: LDAP/LDAPS
```

---

#### 2. **ldap-anonymous-bind** - Ldap Anonymous Bind
**Description:** Tests unauthenticated (anonymous) LDAP bind and checks if base rootDSE is queryable.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 389 --script ldap-anonymous-bind example.com

# Verbose output
nmap -p 389 --script ldap-anonymous-bind -v example.com
```

**Sample Output:**
```
| ldap-anonymous-bind:
|   Status: AUDITED - ldap-anonymous-bind evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: LDAP/LDAPS
```

---

#### 3. **ldap-asreproast-candidates** - Ldap Asreproast Candidates
**Description:** Identifies accounts with DONT_REQ_PREAUTH bit (0x400000) set in userAccountControl.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 389 --script ldap-asreproast-candidates example.com

# Verbose output
nmap -p 389 --script ldap-asreproast-candidates -v example.com
```

**Sample Output:**
```
| ldap-asreproast-candidates:
|   Status: AUDITED - ldap-asreproast-candidates evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: LDAP/LDAPS
```

---

#### 4. **ldap-certificate-templates** - Ldap Certificate Templates
**Description:** Queries Active Directory Certificate Services (AD CS) templates (pKIEnrollmentService).

**Risk Level:** 🟠 HIGH | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 389 --script ldap-certificate-templates example.com

# Verbose output
nmap -p 389 --script ldap-certificate-templates -v example.com
```

**Sample Output:**
```
| ldap-certificate-templates:
|   Status: AUDITED - ldap-certificate-templates evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: LDAP/LDAPS
```

---

#### 5. **ldap-cleartext-auth-risk** - Ldap Cleartext Auth Risk
**Description:** Checks whether LDAP on port 389 processes Simple Bind credentials without StartTLS.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 389 --script ldap-cleartext-auth-risk example.com

# Verbose output
nmap -p 389 --script ldap-cleartext-auth-risk -v example.com
```

**Sample Output:**
```
| ldap-cleartext-auth-risk:
|   Status: AUDITED - ldap-cleartext-auth-risk evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: LDAP/LDAPS
```

---

#### 6. **ldap-gpo-permissions-audit** - Ldap Gpo Permissions Audit
**Description:** Queries Group Policy Objects (GPOs) container and sysvol path references.

**Risk Level:** 🟠 HIGH | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 389 --script ldap-gpo-permissions-audit example.com

# Verbose output
nmap -p 389 --script ldap-gpo-permissions-audit -v example.com
```

**Sample Output:**
```
| ldap-gpo-permissions-audit:
|   Status: AUDITED - ldap-gpo-permissions-audit evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: LDAP/LDAPS
```

---

#### 7. **ldap-laps-password-exposure** - Ldap Laps Password Exposure
**Description:** Tests if anonymous or low-privileged binds can read ms-Mcs-AdmPwd (legacy LAPS password).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 389 --script ldap-laps-password-exposure example.com

# Verbose output
nmap -p 389 --script ldap-laps-password-exposure -v example.com
```

**Sample Output:**
```
| ldap-laps-password-exposure:
|   Status: AUDITED - ldap-laps-password-exposure evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: LDAP/LDAPS
```

---

#### 8. **ldap-null-bind-enum** - Ldap Null Bind Enum
**Description:** Attempts null-bind directory search to dump user accounts, groups, and organizational units.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 389 --script ldap-null-bind-enum example.com

# Verbose output
nmap -p 389 --script ldap-null-bind-enum -v example.com
```

**Sample Output:**
```
| ldap-null-bind-enum:
|   Status: AUDITED - ldap-null-bind-enum evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: LDAP/LDAPS
```

---

#### 9. **ldap-paged-search-limit** - Ldap Paged Search Limit
**Description:** Tests LDAP server pagination control (1.2.840.113556.1.4.319) and size limits.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 389 --script ldap-paged-search-limit example.com

# Verbose output
nmap -p 389 --script ldap-paged-search-limit -v example.com
```

**Sample Output:**
```
| ldap-paged-search-limit:
|   Status: AUDITED - ldap-paged-search-limit evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: LDAP/LDAPS
```

---

#### 10. **ldap-rootdse-leak** - Ldap Rootdse Leak
**Description:** Queries rootDSE for namingContexts, defaultNamingContext, dnsHostName, domainFunctionality.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 389 --script ldap-rootdse-leak example.com

# Verbose output
nmap -p 389 --script ldap-rootdse-leak -v example.com
```

**Sample Output:**
```
| ldap-rootdse-leak:
|   Status: AUDITED - ldap-rootdse-leak evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: LDAP/LDAPS
```

---

#### 11. **ldap-signing-enforced** - Ldap Signing Enforced
**Description:** Checks if LDAP server enforces LDAP signing and channel binding tokens (CBT).

**Risk Level:** 🟠 HIGH | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 389 --script ldap-signing-enforced example.com

# Verbose output
nmap -p 389 --script ldap-signing-enforced -v example.com
```

**Sample Output:**
```
| ldap-signing-enforced:
|   Status: AUDITED - ldap-signing-enforced evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: LDAP/LDAPS
```

---

#### 12. **ldap-spn-service-accounts** - Ldap Spn Service Accounts
**Description:** Queries accounts with servicePrincipalName (SPN) set, identifying Kerberoasting targets.

**Risk Level:** 🟠 HIGH | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 389 --script ldap-spn-service-accounts example.com

# Verbose output
nmap -p 389 --script ldap-spn-service-accounts -v example.com
```

**Sample Output:**
```
| ldap-spn-service-accounts:
|   Status: AUDITED - ldap-spn-service-accounts evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: LDAP/LDAPS
```

---

#### 13. **ldap-starttls-support** - Ldap Starttls Support
**Description:** Probes LDAP StartTLS extended operation OID (1.3.6.1.4.1.1466.20037) support.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 389 --script ldap-starttls-support example.com

# Verbose output
nmap -p 389 --script ldap-starttls-support -v example.com
```

**Sample Output:**
```
| ldap-starttls-support:
|   Status: AUDITED - ldap-starttls-support evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: LDAP/LDAPS
```

---

#### 14. **ldap-supported-controls** - Ldap Supported Controls
**Description:** Enumerates supported LDAP controls, extensions, and SASL mechanisms.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 389 --script ldap-supported-controls example.com

# Verbose output
nmap -p 389 --script ldap-supported-controls -v example.com
```

**Sample Output:**
```
| ldap-supported-controls:
|   Status: AUDITED - ldap-supported-controls evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: LDAP/LDAPS
```

---

#### 15. **ldap-unconstrained-delegation** - Ldap Unconstrained Delegation
**Description:** Finds computers/users configured with TRUSTED_FOR_DELEGATION (Kerberos unconstrained delegation).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 389 --script ldap-unconstrained-delegation example.com

# Verbose output
nmap -p 389 --script ldap-unconstrained-delegation -v example.com
```

**Sample Output:**
```
| ldap-unconstrained-delegation:
|   Status: AUDITED - ldap-unconstrained-delegation evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: LDAP/LDAPS
```

---

#### 16. **ldap-user-account-attributes** - Ldap User Account Attributes
**Description:** Audits user objects for sensitive attributes (userPassword, unicodePwd, description).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 389 --script ldap-user-account-attributes example.com

# Verbose output
nmap -p 389 --script ldap-user-account-attributes -v example.com
```

**Sample Output:**
```
| ldap-user-account-attributes:
|   Status: AUDITED - ldap-user-account-attributes evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: LDAP/LDAPS
```

---

</details>

<details>
<summary><b>🖥️ RDP Protocol & NLA Security Audits — 16 scripts (click to expand)</b></summary>

## 🖥️ RDP Protocol & NLA Security Audits

### Category Overview
Network Level Authentication (NLA), legacy encryption ciphers, NTLM domain leaks, and BlueKeep preconditions.

**Port:** 3389 | **Protocol:** RDP/CredSSP

---

### RDP Scripts List

#### 1. **rdp-bluekeep-precondition** - Rdp Bluekeep Precondition
**Description:** Checks for legacy RDP protocols and absence of NLA indicating CVE-2019-0708 (BlueKeep).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 3389 --script rdp-bluekeep-precondition example.com

# Verbose output
nmap -p 3389 --script rdp-bluekeep-precondition -v example.com
```

**Sample Output:**
```
| rdp-bluekeep-precondition:
|   Status: AUDITED - rdp-bluekeep-precondition evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: RDP/CredSSP
```

---

#### 2. **rdp-cert-name-mismatch** - Rdp Cert Name Mismatch
**Description:** Extracts RDP TLS certificate and checks for self-signed or internal hostname disclosures.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 3389 --script rdp-cert-name-mismatch example.com

# Verbose output
nmap -p 3389 --script rdp-cert-name-mismatch -v example.com
```

**Sample Output:**
```
| rdp-cert-name-mismatch:
|   Status: AUDITED - rdp-cert-name-mismatch evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: RDP/CredSSP
```

---

#### 3. **rdp-cookie-routing-token** - Rdp Cookie Routing Token
**Description:** Checks for RDP routing token cookies (mstshash=...) used in load-balanced RDS farms.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 3389 --script rdp-cookie-routing-token example.com

# Verbose output
nmap -p 3389 --script rdp-cookie-routing-token -v example.com
```

**Sample Output:**
```
| rdp-cookie-routing-token:
|   Status: AUDITED - rdp-cookie-routing-token evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: RDP/CredSSP
```

---

#### 4. **rdp-credssp-version-audit** - Rdp Credssp Version Audit
**Description:** Probes CredSSP protocol version (v2, v3, v4, v5, v6) and flags Oracle Remediation status.

**Risk Level:** 🟠 HIGH | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 3389 --script rdp-credssp-version-audit example.com

# Verbose output
nmap -p 3389 --script rdp-credssp-version-audit -v example.com
```

**Sample Output:**
```
| rdp-credssp-version-audit:
|   Status: AUDITED - rdp-credssp-version-audit evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: RDP/CredSSP
```

---

#### 5. **rdp-cve-2012-0002-check** - Rdp Cve 2012 0002 Check
**Description:** Checks MS12-020 RDP maxChannelIds vulnerability fingerprint.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 3389 --script rdp-cve-2012-0002-check example.com

# Verbose output
nmap -p 3389 --script rdp-cve-2012-0002-check -v example.com
```

**Sample Output:**
```
| rdp-cve-2012-0002-check:
|   Status: AUDITED - rdp-cve-2012-0002-check evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: RDP/CredSSP
```

---

#### 6. **rdp-hybrid-auth-support** - Rdp Hybrid Auth Support
**Description:** Tests RDP hybrid authentication and Azure AD Web-Sign-in support flags.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 3389 --script rdp-hybrid-auth-support example.com

# Verbose output
nmap -p 3389 --script rdp-hybrid-auth-support -v example.com
```

**Sample Output:**
```
| rdp-hybrid-auth-support:
|   Status: AUDITED - rdp-hybrid-auth-support evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: RDP/CredSSP
```

---

#### 7. **rdp-nla-disabled** - Rdp Nla Disabled
**Description:** Checks if Network Level Authentication (NLA / CredSSP) is disabled on port 3389.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 3389 --script rdp-nla-disabled example.com

# Verbose output
nmap -p 3389 --script rdp-nla-disabled -v example.com
```

**Sample Output:**
```
| rdp-nla-disabled:
|   Status: AUDITED - rdp-nla-disabled evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: RDP/CredSSP
```

---

#### 8. **rdp-ntlm-info-disclosure** - Rdp Ntlm Info Disclosure
**Description:** Initiates NTLMSSP handshake to extract Windows domain name, computer NetBIOS name, OS build.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 3389 --script rdp-ntlm-info-disclosure example.com

# Verbose output
nmap -p 3389 --script rdp-ntlm-info-disclosure -v example.com
```

**Sample Output:**
```
| rdp-ntlm-info-disclosure:
|   Status: AUDITED - rdp-ntlm-info-disclosure evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: RDP/CredSSP
```

---

#### 9. **rdp-restricted-admin-mode** - Rdp Restricted Admin Mode
**Description:** Tests whether RDP Restricted Admin Mode is enabled.

**Risk Level:** 🟢 LOW | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 3389 --script rdp-restricted-admin-mode example.com

# Verbose output
nmap -p 3389 --script rdp-restricted-admin-mode -v example.com
```

**Sample Output:**
```
| rdp-restricted-admin-mode:
|   Status: AUDITED - rdp-restricted-admin-mode evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: RDP/CredSSP
```

---

#### 10. **rdp-screen-resolution-dos** - Rdp Screen Resolution Dos
**Description:** Tests server handling of oversized desktop resolution parameters in GCC Conference Create.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 3389 --script rdp-screen-resolution-dos example.com

# Verbose output
nmap -p 3389 --script rdp-screen-resolution-dos -v example.com
```

**Sample Output:**
```
| rdp-screen-resolution-dos:
|   Status: AUDITED - rdp-screen-resolution-dos evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: RDP/CredSSP
```

---

#### 11. **rdp-session-negotiation** - Rdp Session Negotiation
**Description:** Probes RDP X.224 Connection Request protocols (RDP, TLS, CredSSP, RDSTLS, Early User Auth).

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 3389 --script rdp-session-negotiation example.com

# Verbose output
nmap -p 3389 --script rdp-session-negotiation -v example.com
```

**Sample Output:**
```
| rdp-session-negotiation:
|   Status: AUDITED - rdp-session-negotiation evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: RDP/CredSSP
```

---

#### 12. **rdp-session-shadowing-risk** - Rdp Session Shadowing Risk
**Description:** Evaluates RDP Remote Assistance and Shadowing configuration flags.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 3389 --script rdp-session-shadowing-risk example.com

# Verbose output
nmap -p 3389 --script rdp-session-shadowing-risk -v example.com
```

**Sample Output:**
```
| rdp-session-shadowing-risk:
|   Status: AUDITED - rdp-session-shadowing-risk evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: RDP/CredSSP
```

---

#### 13. **rdp-tls-security-layer** - Rdp Tls Security Layer
**Description:** Tests whether RDP enforces TLS/SSL Security Layer vs legacy RDP Standard Encryption.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 3389 --script rdp-tls-security-layer example.com

# Verbose output
nmap -p 3389 --script rdp-tls-security-layer -v example.com
```

**Sample Output:**
```
| rdp-tls-security-layer:
|   Status: AUDITED - rdp-tls-security-layer evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: RDP/CredSSP
```

---

#### 14. **rdp-udp-transport-check** - Rdp Udp Transport Check
**Description:** Tests whether RDP UDP transport (port 3389 UDP / MS-RDPEUDP) is enabled.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 3389 --script rdp-udp-transport-check example.com

# Verbose output
nmap -p 3389 --script rdp-udp-transport-check -v example.com
```

**Sample Output:**
```
| rdp-udp-transport-check:
|   Status: AUDITED - rdp-udp-transport-check evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: RDP/CredSSP
```

---

#### 15. **rdp-virtual-channels-enum** - Rdp Virtual Channels Enum
**Description:** Enumerates static and dynamic virtual channels (cliprdr, rdpdr, rdpsnd, drdynvc).

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 3389 --script rdp-virtual-channels-enum example.com

# Verbose output
nmap -p 3389 --script rdp-virtual-channels-enum -v example.com
```

**Sample Output:**
```
| rdp-virtual-channels-enum:
|   Status: AUDITED - rdp-virtual-channels-enum evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: RDP/CredSSP
```

---

#### 16. **rdp-weak-rc4-ciphers** - Rdp Weak Rc4 Ciphers
**Description:** Checks if RDP Standard Encryption accepts weak 40-bit/56-bit or 128-bit RC4 ciphers.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 3389 --script rdp-weak-rc4-ciphers example.com

# Verbose output
nmap -p 3389 --script rdp-weak-rc4-ciphers -v example.com
```

**Sample Output:**
```
| rdp-weak-rc4-ciphers:
|   Status: AUDITED - rdp-weak-rc4-ciphers evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: RDP/CredSSP
```

---

</details>

<details>
<summary><b>👁️ VNC Remote Desktop Security Audits — 16 scripts (click to expand)</b></summary>

## 👁️ VNC Remote Desktop Security Audits

### Category Overview
No-auth VNC servers, default passwords, weak DES challenges, clipboard sharing, and noVNC WebSockets.

**Port:** 5900/5800/6080 | **Protocol:** RFB (Remote Framebuffer)

---

### VNC Scripts List

#### 1. **vnc-auth-bypass-cve-check** - Vnc Auth Bypass Cve Check
**Description:** Checks for RealVNC 4.1.1 authentication bypass condition (CVE-2006-0006).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5900 --script vnc-auth-bypass-cve-check example.com

# Verbose output
nmap -p 5900 --script vnc-auth-bypass-cve-check -v example.com
```

**Sample Output:**
```
| vnc-auth-bypass-cve-check:
|   Status: AUDITED - vnc-auth-bypass-cve-check evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: RFB (Remote Framebuffer)
```

---

#### 2. **vnc-cleartext-des-warning** - Vnc Cleartext Des Warning
**Description:** Evaluates standard VNC 8-byte DES authentication, flagging weak 56-bit single-DES.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5900 --script vnc-cleartext-des-warning example.com

# Verbose output
nmap -p 5900 --script vnc-cleartext-des-warning -v example.com
```

**Sample Output:**
```
| vnc-cleartext-des-warning:
|   Status: AUDITED - vnc-cleartext-des-warning evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: RFB (Remote Framebuffer)
```

---

#### 3. **vnc-clipboard-leak-risk** - Vnc Clipboard Leak Risk
**Description:** Checks if server accepts ServerCutText / ClientCutText clipboard sharing without restrictions.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5900 --script vnc-clipboard-leak-risk example.com

# Verbose output
nmap -p 5900 --script vnc-clipboard-leak-risk -v example.com
```

**Sample Output:**
```
| vnc-clipboard-leak-risk:
|   Status: AUDITED - vnc-clipboard-leak-risk evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: RFB (Remote Framebuffer)
```

---

#### 4. **vnc-color-depth-dos-check** - Vnc Color Depth Dos Check
**Description:** Checks server negotiation for low-bandwidth 8-bit color palettes vs 32-bit TrueColor.

**Risk Level:** 🟢 LOW | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5900 --script vnc-color-depth-dos-check example.com

# Verbose output
nmap -p 5900 --script vnc-color-depth-dos-check -v example.com
```

**Sample Output:**
```
| vnc-color-depth-dos-check:
|   Status: AUDITED - vnc-color-depth-dos-check evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: RFB (Remote Framebuffer)
```

---

#### 5. **vnc-default-passwords** - Vnc Default Passwords
**Description:** Tests common default VNC passwords (password, 123456, admin, vnc, root).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5900 --script vnc-default-passwords example.com

# Verbose output
nmap -p 5900 --script vnc-default-passwords -v example.com
```

**Sample Output:**
```
| vnc-default-passwords:
|   Status: AUDITED - vnc-default-passwords evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: RFB (Remote Framebuffer)
```

---

#### 6. **vnc-desktop-geometry-leak** - Vnc Desktop Geometry Leak
**Description:** Connects and reads FramebufferUpdate header (width, height, desktop name).

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5900 --script vnc-desktop-geometry-leak example.com

# Verbose output
nmap -p 5900 --script vnc-desktop-geometry-leak -v example.com
```

**Sample Output:**
```
| vnc-desktop-geometry-leak:
|   Status: AUDITED - vnc-desktop-geometry-leak evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: RFB (Remote Framebuffer)
```

---

#### 7. **vnc-http-web-interface** - Vnc Http Web Interface
**Description:** Probes Java/HTML5 VNC HTTP web viewer interface on port 5800.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5900 --script vnc-http-web-interface example.com

# Verbose output
nmap -p 5900 --script vnc-http-web-interface -v example.com
```

**Sample Output:**
```
| vnc-http-web-interface:
|   Status: AUDITED - vnc-http-web-interface evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: RFB (Remote Framebuffer)
```

---

#### 8. **vnc-max-auth-failures** - Vnc Max Auth Failures
**Description:** Tests whether VNC server locks out IP after multiple failed authentication attempts.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5900 --script vnc-max-auth-failures example.com

# Verbose output
nmap -p 5900 --script vnc-max-auth-failures -v example.com
```

**Sample Output:**
```
| vnc-max-auth-failures:
|   Status: AUDITED - vnc-max-auth-failures evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: RFB (Remote Framebuffer)
```

---

#### 9. **vnc-no-auth-check** - Vnc No Auth Check
**Description:** Detects VNC RFB servers configured with Security Type 1 (None / No Authentication).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5900 --script vnc-no-auth-check example.com

# Verbose output
nmap -p 5900 --script vnc-no-auth-check -v example.com
```

**Sample Output:**
```
| vnc-no-auth-check:
|   Status: AUDITED - vnc-no-auth-check evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: RFB (Remote Framebuffer)
```

---

#### 10. **vnc-novnc-websocket-probe** - Vnc Novnc Websocket Probe
**Description:** Checks for unauthenticated noVNC WebSocket endpoints (/websockify).

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5900 --script vnc-novnc-websocket-probe example.com

# Verbose output
nmap -p 5900 --script vnc-novnc-websocket-probe -v example.com
```

**Sample Output:**
```
| vnc-novnc-websocket-probe:
|   Status: AUDITED - vnc-novnc-websocket-probe evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: RFB (Remote Framebuffer)
```

---

#### 11. **vnc-repeater-proxy-detect** - Vnc Repeater Proxy Detect
**Description:** Detects UltraVNC Repeater proxy services on port 5900/5901.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5900 --script vnc-repeater-proxy-detect example.com

# Verbose output
nmap -p 5900 --script vnc-repeater-proxy-detect -v example.com
```

**Sample Output:**
```
| vnc-repeater-proxy-detect:
|   Status: AUDITED - vnc-repeater-proxy-detect evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: RFB (Remote Framebuffer)
```

---

#### 12. **vnc-reverse-connection-probe** - Vnc Reverse Connection Probe
**Description:** Probes VNC listening in reverse-connection (listening viewer) mode on port 5500.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5900 --script vnc-reverse-connection-probe example.com

# Verbose output
nmap -p 5900 --script vnc-reverse-connection-probe -v example.com
```

**Sample Output:**
```
| vnc-reverse-connection-probe:
|   Status: AUDITED - vnc-reverse-connection-probe evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: RFB (Remote Framebuffer)
```

---

#### 13. **vnc-rfb-version-fingerprint** - Vnc Rfb Version Fingerprint
**Description:** Negotiates RFB protocol versions (RFB 003.003 to 004.001) and extracts server banner.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5900 --script vnc-rfb-version-fingerprint example.com

# Verbose output
nmap -p 5900 --script vnc-rfb-version-fingerprint -v example.com
```

**Sample Output:**
```
| vnc-rfb-version-fingerprint:
|   Status: AUDITED - vnc-rfb-version-fingerprint evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: RFB (Remote Framebuffer)
```

---

#### 14. **vnc-security-types-enum** - Vnc Security Types Enum
**Description:** Enumerate all security types supported by server (None, VNC Auth, RA2, TLS, VeNCrypt).

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5900 --script vnc-security-types-enum example.com

# Verbose output
nmap -p 5900 --script vnc-security-types-enum -v example.com
```

**Sample Output:**
```
| vnc-security-types-enum:
|   Status: AUDITED - vnc-security-types-enum evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: RFB (Remote Framebuffer)
```

---

#### 15. **vnc-tightvnc-backdoor-audit** - Vnc Tightvnc Backdoor Audit
**Description:** Fingerprints TightVNC / UltraVNC versions vulnerable to pre-auth buffer overflows.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5900 --script vnc-tightvnc-backdoor-audit example.com

# Verbose output
nmap -p 5900 --script vnc-tightvnc-backdoor-audit -v example.com
```

**Sample Output:**
```
| vnc-tightvnc-backdoor-audit:
|   Status: AUDITED - vnc-tightvnc-backdoor-audit evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: RFB (Remote Framebuffer)
```

---

#### 16. **vnc-vencrypt-tls-support** - Vnc Vencrypt Tls Support
**Description:** Probes VeNCrypt security subtype negotiation and TLS encryption enforcement.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5900 --script vnc-vencrypt-tls-support example.com

# Verbose output
nmap -p 5900 --script vnc-vencrypt-tls-support -v example.com
```

**Sample Output:**
```
| vnc-vencrypt-tls-support:
|   Status: AUDITED - vnc-vencrypt-tls-support evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: RFB (Remote Framebuffer)
```

---

</details>

<details>
<summary><b>⏱️ NTP Time Synchronization Security Audits — 16 scripts (click to expand)</b></summary>

## ⏱️ NTP Time Synchronization Security Audits

### Category Overview
Monlist amplification (CVE-2013-5211), Mode 6 readvar variable leaks, peer associations, and time offset skew.

**Port:** 123 | **Protocol:** NTP (UDP)

---

### NTP Scripts List

#### 1. **ntp-autokey-support-audit** - Ntp Autokey Support Audit
**Description:** Checks for Autokey protocol (RFC 5906) support and vulnerable crypto parameters.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 123 --script ntp-autokey-support-audit example.com

# Verbose output
nmap -p 123 --script ntp-autokey-support-audit -v example.com
```

**Sample Output:**
```
| ntp-autokey-support-audit:
|   Status: AUDITED - ntp-autokey-support-audit evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: NTP (UDP)
```

---

#### 2. **ntp-broadcast-mode-detect** - Ntp Broadcast Mode Detect
**Description:** Listens for unsolicited NTP broadcast/multicast packets on local subnets.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 123 --script ntp-broadcast-mode-detect example.com

# Verbose output
nmap -p 123 --script ntp-broadcast-mode-detect -v example.com
```

**Sample Output:**
```
| ntp-broadcast-mode-detect:
|   Status: AUDITED - ntp-broadcast-mode-detect evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: NTP (UDP)
```

---

#### 3. **ntp-control-query-rate-limit** - Ntp Control Query Rate Limit
**Description:** Tests whether ntpd enforces restrict default noquery or allows unlimited control packets.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 123 --script ntp-control-query-rate-limit example.com

# Verbose output
nmap -p 123 --script ntp-control-query-rate-limit -v example.com
```

**Sample Output:**
```
| ntp-control-query-rate-limit:
|   Status: AUDITED - ntp-control-query-rate-limit evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: NTP (UDP)
```

---

#### 4. **ntp-leap-second-vulnerability** - Ntp Leap Second Vulnerability
**Description:** Checks NTP version for historical leap-second parsing CPU saturation bugs.

**Risk Level:** 🟡 MEDIUM | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 123 --script ntp-leap-second-vulnerability example.com

# Verbose output
nmap -p 123 --script ntp-leap-second-vulnerability -v example.com
```

**Sample Output:**
```
| ntp-leap-second-vulnerability:
|   Status: AUDITED - ntp-leap-second-vulnerability evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: NTP (UDP)
```

---

#### 5. **ntp-mac-authentication-test** - Ntp Mac Authentication Test
**Description:** Sends NTP packets with dummy Key IDs to test MD5/SHA1 symmetric MAC verification.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 123 --script ntp-mac-authentication-test example.com

# Verbose output
nmap -p 123 --script ntp-mac-authentication-test -v example.com
```

**Sample Output:**
```
| ntp-mac-authentication-test:
|   Status: AUDITED - ntp-mac-authentication-test evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: NTP (UDP)
```

---

#### 6. **ntp-mode6-readlist-leak** - Ntp Mode6 Readlist Leak
**Description:** Dumps peer association list via Mode 6 readlist to map upstream time servers.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 123 --script ntp-mode6-readlist-leak example.com

# Verbose output
nmap -p 123 --script ntp-mode6-readlist-leak -v example.com
```

**Sample Output:**
```
| ntp-mode6-readlist-leak:
|   Status: AUDITED - ntp-mode6-readlist-leak evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: NTP (UDP)
```

---

#### 7. **ntp-mode6-readvar-leak** - Ntp Mode6 Readvar Leak
**Description:** Sends Mode 6 readvar request to dump system variables (version, processor, system, stratum, refid).

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 123 --script ntp-mode6-readvar-leak example.com

# Verbose output
nmap -p 123 --script ntp-mode6-readvar-leak -v example.com
```

**Sample Output:**
```
| ntp-mode6-readvar-leak:
|   Status: AUDITED - ntp-mode6-readvar-leak evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: NTP (UDP)
```

---

#### 8. **ntp-monlist-amplification** - Ntp Monlist Amplification
**Description:** Sends NTP Mode 7 REQ_MON_GETLIST command and measures reflection amplification factor (CVE-2013-5211).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 123 --script ntp-monlist-amplification example.com

# Verbose output
nmap -p 123 --script ntp-monlist-amplification -v example.com
```

**Sample Output:**
```
| ntp-monlist-amplification:
|   Status: AUDITED - ntp-monlist-amplification evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: NTP (UDP)
```

---

#### 9. **ntp-nts-support-check** - Ntp Nts Support Check
**Description:** Probes Network Time Security (NTS) TLS key establishment on port 4460.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 123 --script ntp-nts-support-check example.com

# Verbose output
nmap -p 123 --script ntp-nts-support-check -v example.com
```

**Sample Output:**
```
| ntp-nts-support-check:
|   Status: AUDITED - ntp-nts-support-check evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: NTP (UDP)
```

---

#### 10. **ntp-peer-association-spoof** - Ntp Peer Association Spoof
**Description:** Evaluates whether ntpd accepts unauthenticated symmetric active/passive association packets.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 123 --script ntp-peer-association-spoof example.com

# Verbose output
nmap -p 123 --script ntp-peer-association-spoof -v example.com
```

**Sample Output:**
```
| ntp-peer-association-spoof:
|   Status: AUDITED - ntp-peer-association-spoof evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: NTP (UDP)
```

---

#### 11. **ntp-stratum-zero-anomaly** - Ntp Stratum Zero Anomaly
**Description:** Checks for Stratum 0 Kiss-of-Death (KoD) packets and rate-limiting responses.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 123 --script ntp-stratum-zero-anomaly example.com

# Verbose output
nmap -p 123 --script ntp-stratum-zero-anomaly -v example.com
```

**Sample Output:**
```
| ntp-stratum-zero-anomaly:
|   Status: AUDITED - ntp-stratum-zero-anomaly evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: NTP (UDP)
```

---

#### 12. **ntp-time-offset-skew** - Ntp Time Offset Skew
**Description:** Calculates target clock offset, round-trip delay, and jitter relative to scan host.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 123 --script ntp-time-offset-skew example.com

# Verbose output
nmap -p 123 --script ntp-time-offset-skew -v example.com
```

**Sample Output:**
```
| ntp-time-offset-skew:
|   Status: AUDITED - ntp-time-offset-skew evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: NTP (UDP)
```

---

#### 13. **ntp-trap-logging-leak** - Ntp Trap Logging Leak
**Description:** Sends Mode 6 set_trap request to test if unauthenticated event trapping is enabled.

**Risk Level:** 🟠 HIGH | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 123 --script ntp-trap-logging-leak example.com

# Verbose output
nmap -p 123 --script ntp-trap-logging-leak -v example.com
```

**Sample Output:**
```
| ntp-trap-logging-leak:
|   Status: AUDITED - ntp-trap-logging-leak evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: NTP (UDP)
```

---

#### 14. **ntp-unauth-config-dump** - Ntp Unauth Config Dump
**Description:** Sends Mode 7 REQ_SYS_CONFIG to test if remote reconfiguration is enabled without key auth.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 123 --script ntp-unauth-config-dump example.com

# Verbose output
nmap -p 123 --script ntp-unauth-config-dump -v example.com
```

**Sample Output:**
```
| ntp-unauth-config-dump:
|   Status: AUDITED - ntp-unauth-config-dump evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: NTP (UDP)
```

---

#### 15. **ntp-unauth-reslist-query** - Ntp Unauth Reslist Query
**Description:** Sends Mode 7 REQ_GET_RESTRICT to dump access control lists (ACLs) configured on ntpd.

**Risk Level:** 🟠 HIGH | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 123 --script ntp-unauth-reslist-query example.com

# Verbose output
nmap -p 123 --script ntp-unauth-reslist-query -v example.com
```

**Sample Output:**
```
| ntp-unauth-reslist-query:
|   Status: AUDITED - ntp-unauth-reslist-query evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: NTP (UDP)
```

---

#### 16. **ntp-version-fingerprint** - Ntp Version Fingerprint
**Description:** Analyzes NTP response headers (Leap Indicator, Version, Mode, Stratum, Precision).

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 123 --script ntp-version-fingerprint example.com

# Verbose output
nmap -p 123 --script ntp-version-fingerprint -v example.com
```

**Sample Output:**
```
| ntp-version-fingerprint:
|   Status: AUDITED - ntp-version-fingerprint evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: NTP (UDP)
```

---

</details>

<details>
<summary><b>📟 Telnet Cleartext & Terminal Audits — 16 scripts (click to expand)</b></summary>

## 📟 Telnet Cleartext & Terminal Audits

### Category Overview
Cleartext transport risks, default switch/router credentials, environment variable leaks, and IAC handling.

**Port:** 23 | **Protocol:** Telnet (TCP)

---

### TELNET Scripts List

#### 1. **telnet-auth-option-bypass** - Telnet Auth Option Bypass
**Description:** Probes Telnet AUTHENTICATION option (RFC 1416) for Kerberos/SRP/None bypass conditions.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 23 --script telnet-auth-option-bypass example.com

# Verbose output
nmap -p 23 --script telnet-auth-option-bypass -v example.com
```

**Sample Output:**
```
| telnet-auth-option-bypass:
|   Status: AUDITED - telnet-auth-option-bypass evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Telnet (TCP)
```

---

#### 2. **telnet-banner-grab** - Telnet Banner Grab
**Description:** Grabs Telnet initial login banner, OS prompt, and legal notice disclosures.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 23 --script telnet-banner-grab example.com

# Verbose output
nmap -p 23 --script telnet-banner-grab -v example.com
```

**Sample Output:**
```
| telnet-banner-grab:
|   Status: AUDITED - telnet-banner-grab evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: Telnet (TCP)
```

---

#### 3. **telnet-busybox-fingerprint** - Telnet Busybox Fingerprint
**Description:** Identifies BusyBox / Linux embedded appliance Telnet banners.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 23 --script telnet-busybox-fingerprint example.com

# Verbose output
nmap -p 23 --script telnet-busybox-fingerprint -v example.com
```

**Sample Output:**
```
| telnet-busybox-fingerprint:
|   Status: AUDITED - telnet-busybox-fingerprint evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Telnet (TCP)
```

---

#### 4. **telnet-cisco-login-prompt** - Telnet Cisco Login Prompt
**Description:** Detects Cisco IOS/NX-OS Telnet authentication prompts and password-only modes.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 23 --script telnet-cisco-login-prompt example.com

# Verbose output
nmap -p 23 --script telnet-cisco-login-prompt -v example.com
```

**Sample Output:**
```
| telnet-cisco-login-prompt:
|   Status: AUDITED - telnet-cisco-login-prompt evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Telnet (TCP)
```

---

#### 5. **telnet-cleartext-warning** - Telnet Cleartext Warning
**Description:** Flags unencrypted cleartext terminal transport on port 23 and passive credential sniffing risk.

**Risk Level:** 🔴 CRITICAL | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 23 --script telnet-cleartext-warning example.com

# Verbose output
nmap -p 23 --script telnet-cleartext-warning -v example.com
```

**Sample Output:**
```
| telnet-cleartext-warning:
|   Status: AUDITED - telnet-cleartext-warning evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Telnet (TCP)
```

---

#### 6. **telnet-default-credentials** - Telnet Default Credentials
**Description:** Tests common embedded router/switch default Telnet credentials (admin/admin, root/root).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 23 --script telnet-default-credentials example.com

# Verbose output
nmap -p 23 --script telnet-default-credentials -v example.com
```

**Sample Output:**
```
| telnet-default-credentials:
|   Status: AUDITED - telnet-default-credentials evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Telnet (TCP)
```

---

#### 7. **telnet-encrypt-option-audit** - Telnet Encrypt Option Audit
**Description:** Checks if Telnet ENCRYPT option (RFC 2946) is supported or completely missing.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 23 --script telnet-encrypt-option-audit example.com

# Verbose output
nmap -p 23 --script telnet-encrypt-option-audit -v example.com
```

**Sample Output:**
```
| telnet-encrypt-option-audit:
|   Status: AUDITED - telnet-encrypt-option-audit evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Telnet (TCP)
```

---

#### 8. **telnet-env-var-disclosure** - Telnet Env Var Disclosure
**Description:** Sends IAC SB NEW-ENVIRON SEND requests to extract server environment variables (USER, PATH).

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 23 --script telnet-env-var-disclosure example.com

# Verbose output
nmap -p 23 --script telnet-env-var-disclosure -v example.com
```

**Sample Output:**
```
| telnet-env-var-disclosure:
|   Status: AUDITED - telnet-env-var-disclosure evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: Telnet (TCP)
```

---

#### 9. **telnet-escape-character-enum** - Telnet Escape Character Enum
**Description:** Identifies configured escape characters and command menu hotkeys.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 23 --script telnet-escape-character-enum example.com

# Verbose output
nmap -p 23 --script telnet-escape-character-enum -v example.com
```

**Sample Output:**
```
| telnet-escape-character-enum:
|   Status: AUDITED - telnet-escape-character-enum evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: Telnet (TCP)
```

---

#### 10. **telnet-iac-buffer-overflow** - Telnet Iac Buffer Overflow
**Description:** Fingerprints legacy Telnet daemons susceptible to IAC escape sequence buffer overflows.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 23 --script telnet-iac-buffer-overflow example.com

# Verbose output
nmap -p 23 --script telnet-iac-buffer-overflow -v example.com
```

**Sample Output:**
```
| telnet-iac-buffer-overflow:
|   Status: AUDITED - telnet-iac-buffer-overflow evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Telnet (TCP)
```

---

#### 11. **telnet-max-connections-dos** - Telnet Max Connections Dos
**Description:** Probes maximum concurrent Telnet connection handling.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 23 --script telnet-max-connections-dos example.com

# Verbose output
nmap -p 23 --script telnet-max-connections-dos -v example.com
```

**Sample Output:**
```
| telnet-max-connections-dos:
|   Status: AUDITED - telnet-max-connections-dos evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Telnet (TCP)
```

---

#### 12. **telnet-option-negotiation** - Telnet Option Negotiation
**Description:** Negotiates Telnet IAC options (ECHO, SUPPRESS_GO_AHEAD, TERMINAL_TYPE, TSPEED, NAWS).

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 23 --script telnet-option-negotiation example.com

# Verbose output
nmap -p 23 --script telnet-option-negotiation -v example.com
```

**Sample Output:**
```
| telnet-option-negotiation:
|   Status: AUDITED - telnet-option-negotiation evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: Telnet (TCP)
```

---

#### 13. **telnet-root-login-allowed** - Telnet Root Login Allowed
**Description:** Checks whether Telnet login prompt allows direct root/administrator logins.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 23 --script telnet-root-login-allowed example.com

# Verbose output
nmap -p 23 --script telnet-root-login-allowed -v example.com
```

**Sample Output:**
```
| telnet-root-login-allowed:
|   Status: AUDITED - telnet-root-login-allowed evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: Telnet (TCP)
```

---

#### 14. **telnet-subnegotiation-leak** - Telnet Subnegotiation Leak
**Description:** Audits subnegotiation parameter leaks (window size NAWS, terminal speed).

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 23 --script telnet-subnegotiation-leak example.com

# Verbose output
nmap -p 23 --script telnet-subnegotiation-leak -v example.com
```

**Sample Output:**
```
| telnet-subnegotiation-leak:
|   Status: AUDITED - telnet-subnegotiation-leak evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: Telnet (TCP)
```

---

#### 15. **telnet-terminal-type-dos** - Telnet Terminal Type Dos
**Description:** Tests server handling of oversized or malformed TERMINAL-TYPE subnegotiation strings.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 23 --script telnet-terminal-type-dos example.com

# Verbose output
nmap -p 23 --script telnet-terminal-type-dos -v example.com
```

**Sample Output:**
```
| telnet-terminal-type-dos:
|   Status: AUDITED - telnet-terminal-type-dos evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Telnet (TCP)
```

---

#### 16. **telnet-windows-auth-ntlm** - Telnet Windows Auth Ntlm
**Description:** Checks for Microsoft Windows Telnet NTLM authentication support.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 23 --script telnet-windows-auth-ntlm example.com

# Verbose output
nmap -p 23 --script telnet-windows-auth-ntlm -v example.com
```

**Sample Output:**
```
| telnet-windows-auth-ntlm:
|   Status: AUDITED - telnet-windows-auth-ntlm evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Telnet (TCP)
```

---

</details>

<details>
<summary><b>📞 SIP & VoIP Protocol Security Audits — 16 scripts (click to expand)</b></summary>

## 📞 SIP & VoIP Protocol Security Audits

### Category Overview
Extension enumeration, default PBX credentials, unauthenticated calling/registration relay, and Caller ID spoofing.

**Port:** 5060/5061 | **Protocol:** SIP/SDP (UDP/TCP)

---

### SIP Scripts List

#### 1. **sip-bye-teardown-spoof** - Sip Bye Teardown Spoof
**Description:** Checks if server validates Call-ID and tags on BYE requests or allows blind call teardown.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5060 --script sip-bye-teardown-spoof example.com

# Verbose output
nmap -p 5060 --script sip-bye-teardown-spoof -v example.com
```

**Sample Output:**
```
| sip-bye-teardown-spoof:
|   Status: AUDITED - sip-bye-teardown-spoof evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: SIP/SDP (UDP/TCP)
```

---

#### 2. **sip-call-eavesdropping-rtp** - Sip Call Eavesdropping Rtp
**Description:** Checks if SDP payload specifies unencrypted plain RTP instead of SRTP (Secure RTP).

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5060 --script sip-call-eavesdropping-rtp example.com

# Verbose output
nmap -p 5060 --script sip-call-eavesdropping-rtp -v example.com
```

**Sample Output:**
```
| sip-call-eavesdropping-rtp:
|   Status: AUDITED - sip-call-eavesdropping-rtp evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: SIP/SDP (UDP/TCP)
```

---

#### 3. **sip-callerid-spoof-check** - Sip Callerid Spoof Check
**Description:** Tests whether server validates From and P-Asserted-Identity headers or accepts spoofed Caller IDs.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5060 --script sip-callerid-spoof-check example.com

# Verbose output
nmap -p 5060 --script sip-callerid-spoof-check -v example.com
```

**Sample Output:**
```
| sip-callerid-spoof-check:
|   Status: AUDITED - sip-callerid-spoof-check evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: SIP/SDP (UDP/TCP)
```

---

#### 4. **sip-cleartext-udp-warning** - Sip Cleartext Udp Warning
**Description:** Flags cleartext UDP/TCP SIP signaling on port 5060 instead of SIPS / TLS on port 5061.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5060 --script sip-cleartext-udp-warning example.com

# Verbose output
nmap -p 5060 --script sip-cleartext-udp-warning -v example.com
```

**Sample Output:**
```
| sip-cleartext-udp-warning:
|   Status: AUDITED - sip-cleartext-udp-warning evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SIP/SDP (UDP/TCP)
```

---

#### 5. **sip-default-credentials** - Sip Default Credentials
**Description:** Tests common default SIP extension credentials (100/100, admin/admin) with MD5 digest auth.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5060 --script sip-default-credentials example.com

# Verbose output
nmap -p 5060 --script sip-default-credentials -v example.com
```

**Sample Output:**
```
| sip-default-credentials:
|   Status: AUDITED - sip-default-credentials evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: SIP/SDP (UDP/TCP)
```

---

#### 6. **sip-extension-enumeration** - Sip Extension Enumeration
**Description:** Enumerates internal PBX extensions (100-110, 1000-1010) via SIP REGISTER / INVITE responses.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5060 --script sip-extension-enumeration example.com

# Verbose output
nmap -p 5060 --script sip-extension-enumeration -v example.com
```

**Sample Output:**
```
| sip-extension-enumeration:
|   Status: AUDITED - sip-extension-enumeration evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: SIP/SDP (UDP/TCP)
```

---

#### 7. **sip-message-spam-relay** - Sip Message Spam Relay
**Description:** Sends SIP MESSAGE instant text payloads to test for unauthenticated message relay.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5060 --script sip-message-spam-relay example.com

# Verbose output
nmap -p 5060 --script sip-message-spam-relay -v example.com
```

**Sample Output:**
```
| sip-message-spam-relay:
|   Status: AUDITED - sip-message-spam-relay evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: SIP/SDP (UDP/TCP)
```

---

#### 8. **sip-method-flood-dos** - Sip Method Flood Dos
**Description:** Tests rate-limiting on SIP request processing (OPTIONS/REGISTER).

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5060 --script sip-method-flood-dos example.com

# Verbose output
nmap -p 5060 --script sip-method-flood-dos -v example.com
```

**Sample Output:**
```
| sip-method-flood-dos:
|   Status: AUDITED - sip-method-flood-dos evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SIP/SDP (UDP/TCP)
```

---

#### 9. **sip-nat-traversal-leak** - Sip Nat Traversal Leak
**Description:** Inspects Via and Contact headers for internal RFC1918 PBX IP address disclosures.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5060 --script sip-nat-traversal-leak example.com

# Verbose output
nmap -p 5060 --script sip-nat-traversal-leak -v example.com
```

**Sample Output:**
```
| sip-nat-traversal-leak:
|   Status: AUDITED - sip-nat-traversal-leak evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SIP/SDP (UDP/TCP)
```

---

#### 10. **sip-presence-subscription** - Sip Presence Subscription
**Description:** Tests unauthenticated SIP SUBSCRIBE for user presence/status event streams.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5060 --script sip-presence-subscription example.com

# Verbose output
nmap -p 5060 --script sip-presence-subscription -v example.com
```

**Sample Output:**
```
| sip-presence-subscription:
|   Status: AUDITED - sip-presence-subscription evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SIP/SDP (UDP/TCP)
```

---

#### 11. **sip-sdp-codec-audit** - Sip Sdp Codec Audit
**Description:** Inspects supported audio codecs (G.711 PCMU/PCMA, G.729, Opus, Speex) in SDP bodies.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5060 --script sip-sdp-codec-audit example.com

# Verbose output
nmap -p 5060 --script sip-sdp-codec-audit -v example.com
```

**Sample Output:**
```
| sip-sdp-codec-audit:
|   Status: AUDITED - sip-sdp-codec-audit evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: SIP/SDP (UDP/TCP)
```

---

#### 12. **sip-server-fingerprint** - Sip Server Fingerprint
**Description:** Fingerprints PBX engines (Asterisk, FreePBX, Cisco CUCM, 3CX, Kamailio, OpenSIPS).

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5060 --script sip-server-fingerprint example.com

# Verbose output
nmap -p 5060 --script sip-server-fingerprint -v example.com
```

**Sample Output:**
```
| sip-server-fingerprint:
|   Status: AUDITED - sip-server-fingerprint evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: SIP/SDP (UDP/TCP)
```

---

#### 13. **sip-tls-cert-validation** - Sip Tls Cert Validation
**Description:** Audits SIPS TLS certificate validity and SAN/CN hostname matching on port 5061.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5060 --script sip-tls-cert-validation example.com

# Verbose output
nmap -p 5060 --script sip-tls-cert-validation -v example.com
```

**Sample Output:**
```
| sip-tls-cert-validation:
|   Status: AUDITED - sip-tls-cert-validation evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SIP/SDP (UDP/TCP)
```

---

#### 14. **sip-unauth-options-enum** - Sip Unauth Options Enum
**Description:** Sends SIP OPTIONS request and extracts Allow, Supported, Server, User-Agent headers.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5060 --script sip-unauth-options-enum example.com

# Verbose output
nmap -p 5060 --script sip-unauth-options-enum -v example.com
```

**Sample Output:**
```
| sip-unauth-options-enum:
|   Status: AUDITED - sip-unauth-options-enum evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: SIP/SDP (UDP/TCP)
```

---

#### 15. **sip-unauthenticated-invite** - Sip Unauthenticated Invite
**Description:** Sends unauthenticated INVITE request to test for open SIP relay (toll fraud / unauthorized calls).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5060 --script sip-unauthenticated-invite example.com

# Verbose output
nmap -p 5060 --script sip-unauthenticated-invite -v example.com
```

**Sample Output:**
```
| sip-unauthenticated-invite:
|   Status: AUDITED - sip-unauthenticated-invite evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: SIP/SDP (UDP/TCP)
```

---

#### 16. **sip-unauthenticated-register** - Sip Unauthenticated Register
**Description:** Tests if SIP server permits registering phone extensions without MD5 digest authentication.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 5060 --script sip-unauthenticated-register example.com

# Verbose output
nmap -p 5060 --script sip-unauthenticated-register -v example.com
```

**Sample Output:**
```
| sip-unauthenticated-register:
|   Status: AUDITED - sip-unauthenticated-register evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: SIP/SDP (UDP/TCP)
```

---

</details>

<details>
<summary><b>✉️ SMTP & Email Transport Security Audits — 16 scripts (click to expand)</b></summary>

## ✉️ SMTP & Email Transport Security Audits

### Category Overview
Open mail relaying, STARTTLS enforcement, VRFY/RCPT TO user harvesting, and cleartext authentication risks.

**Port:** 25/587/465 | **Protocol:** SMTP/ESMTP

---

### SMTP Scripts List

#### 1. **smtp-banner-grab** - Smtp Banner Grab
**Description:** Captures SMTP initial 220 banner, hostname, and mail server software version.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 25 --script smtp-banner-grab example.com

# Verbose output
nmap -p 25 --script smtp-banner-grab -v example.com
```

**Sample Output:**
```
| smtp-banner-grab:
|   Status: AUDITED - smtp-banner-grab evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: SMTP/ESMTP
```

---

#### 2. **smtp-cleartext-auth-allowed** - Smtp Cleartext Auth Allowed
**Description:** Checks if server advertises AUTH PLAIN or AUTH LOGIN before STARTTLS is negotiated.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 25 --script smtp-cleartext-auth-allowed example.com

# Verbose output
nmap -p 25 --script smtp-cleartext-auth-allowed -v example.com
```

**Sample Output:**
```
| smtp-cleartext-auth-allowed:
|   Status: AUDITED - smtp-cleartext-auth-allowed evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: SMTP/ESMTP
```

---

#### 3. **smtp-commands-enum** - Smtp Commands Enum
**Description:** Sends EHLO and extracts all supported ESMTP capabilities (SIZE, 8BITMIME, PIPELINING).

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 25 --script smtp-commands-enum example.com

# Verbose output
nmap -p 25 --script smtp-commands-enum -v example.com
```

**Sample Output:**
```
| smtp-commands-enum:
|   Status: AUDITED - smtp-commands-enum evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: SMTP/ESMTP
```

---

#### 4. **smtp-default-credentials** - Smtp Default Credentials
**Description:** Tests common default SMTP credentials on submission ports (587/465/25).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 25 --script smtp-default-credentials example.com

# Verbose output
nmap -p 25 --script smtp-default-credentials -v example.com
```

**Sample Output:**
```
| smtp-default-credentials:
|   Status: AUDITED - smtp-default-credentials evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: SMTP/ESMTP
```

---

#### 5. **smtp-help-info-leak** - Smtp Help Info Leak
**Description:** Sends HELP and HELP <command> to check for verbose help disclosures.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 25 --script smtp-help-info-leak example.com

# Verbose output
nmap -p 25 --script smtp-help-info-leak -v example.com
```

**Sample Output:**
```
| smtp-help-info-leak:
|   Status: AUDITED - smtp-help-info-leak evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: SMTP/ESMTP
```

---

#### 6. **smtp-max-message-size** - Smtp Max Message Size
**Description:** Checks SIZE extension limit to detect denial-of-service / mailbox overflow risks.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 25 --script smtp-max-message-size example.com

# Verbose output
nmap -p 25 --script smtp-max-message-size -v example.com
```

**Sample Output:**
```
| smtp-max-message-size:
|   Status: AUDITED - smtp-max-message-size evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SMTP/ESMTP
```

---

#### 7. **smtp-null-sender-bounce** - Smtp Null Sender Bounce
**Description:** Tests handling of bounce notifications (MAIL FROM:<>) to prevent backscatter spam.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 25 --script smtp-null-sender-bounce example.com

# Verbose output
nmap -p 25 --script smtp-null-sender-bounce -v example.com
```

**Sample Output:**
```
| smtp-null-sender-bounce:
|   Status: AUDITED - smtp-null-sender-bounce evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SMTP/ESMTP
```

---

#### 8. **smtp-open-relay-check** - Smtp Open Relay Check
**Description:** Tests for open mail relaying by sending non-destructive test envelopes (MAIL FROM, RCPT TO).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 25 --script smtp-open-relay-check example.com

# Verbose output
nmap -p 25 --script smtp-open-relay-check -v example.com
```

**Sample Output:**
```
| smtp-open-relay-check:
|   Status: AUDITED - smtp-open-relay-check evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: SMTP/ESMTP
```

---

#### 9. **smtp-pipelining-dos-tolerance** - Smtp Pipelining Dos Tolerance
**Description:** Tests server handling of command pipelining and buffer overflows.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 25 --script smtp-pipelining-dos-tolerance example.com

# Verbose output
nmap -p 25 --script smtp-pipelining-dos-tolerance -v example.com
```

**Sample Output:**
```
| smtp-pipelining-dos-tolerance:
|   Status: AUDITED - smtp-pipelining-dos-tolerance evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SMTP/ESMTP
```

---

#### 10. **smtp-rcpt-to-user-enum** - Smtp Rcpt To User Enum
**Description:** Probes RCPT TO response codes (250 OK vs 550 User unknown) for dictionary user harvesting.

**Risk Level:** 🟠 HIGH | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 25 --script smtp-rcpt-to-user-enum example.com

# Verbose output
nmap -p 25 --script smtp-rcpt-to-user-enum -v example.com
```

**Sample Output:**
```
| smtp-rcpt-to-user-enum:
|   Status: AUDITED - smtp-rcpt-to-user-enum evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: SMTP/ESMTP
```

---

#### 11. **smtp-smarthost-auth-bypass** - Smtp Smarthost Auth Bypass
**Description:** Tests whether internal IP ranges bypass authentication for relaying.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 25 --script smtp-smarthost-auth-bypass example.com

# Verbose output
nmap -p 25 --script smtp-smarthost-auth-bypass -v example.com
```

**Sample Output:**
```
| smtp-smarthost-auth-bypass:
|   Status: AUDITED - smtp-smarthost-auth-bypass evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: SMTP/ESMTP
```

---

#### 12. **smtp-spf-dkim-dmarc-check** - Smtp Spf Dkim Dmarc Check
**Description:** Audits MTA HELO/EHLO hostname alignment with DNS SPF and MX records.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 25 --script smtp-spf-dkim-dmarc-check example.com

# Verbose output
nmap -p 25 --script smtp-spf-dkim-dmarc-check -v example.com
```

**Sample Output:**
```
| smtp-spf-dkim-dmarc-check:
|   Status: AUDITED - smtp-spf-dkim-dmarc-check evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SMTP/ESMTP
```

---

#### 13. **smtp-starttls-support** - Smtp Starttls Support
**Description:** Checks if SMTP server advertises and negotiates STARTTLS on ports 25/587.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 25 --script smtp-starttls-support example.com

# Verbose output
nmap -p 25 --script smtp-starttls-support -v example.com
```

**Sample Output:**
```
| smtp-starttls-support:
|   Status: AUDITED - smtp-starttls-support evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SMTP/ESMTP
```

---

#### 14. **smtp-strict-tls-enforcement** - Smtp Strict Tls Enforcement
**Description:** Tests whether server rejects unencrypted inbound mail delivery.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 25 --script smtp-strict-tls-enforcement example.com

# Verbose output
nmap -p 25 --script smtp-strict-tls-enforcement -v example.com
```

**Sample Output:**
```
| smtp-strict-tls-enforcement:
|   Status: AUDITED - smtp-strict-tls-enforcement evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SMTP/ESMTP
```

---

#### 15. **smtp-tls-ciphers-audit** - Smtp Tls Ciphers Audit
**Description:** Audits SSL/TLS cipher suites accepted during STARTTLS negotiation.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 25 --script smtp-tls-ciphers-audit example.com

# Verbose output
nmap -p 25 --script smtp-tls-ciphers-audit -v example.com
```

**Sample Output:**
```
| smtp-tls-ciphers-audit:
|   Status: AUDITED - smtp-tls-ciphers-audit evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: SMTP/ESMTP
```

---

#### 16. **smtp-vrfy-user-enumeration** - Smtp Vrfy User Enumeration
**Description:** Tests whether VRFY and EXPN commands are enabled, allowing automated user enumeration.

**Risk Level:** 🟠 HIGH | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 25 --script smtp-vrfy-user-enumeration example.com

# Verbose output
nmap -p 25 --script smtp-vrfy-user-enumeration -v example.com
```

**Sample Output:**
```
| smtp-vrfy-user-enumeration:
|   Status: AUDITED - smtp-vrfy-user-enumeration evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: SMTP/ESMTP
```

---

</details>

<details>
<summary><b>🎟️ Kerberos Authentication & KDC Audits — 16 scripts (click to expand)</b></summary>

## 🎟️ Kerberos Authentication & KDC Audits

### Category Overview
AS-REP Roasting, username enumeration, weak encryption tickets (DES/RC4), and clock skew validation.

**Port:** 88/464 | **Protocol:** Kerberos v5

---

### KERBEROS Scripts List

#### 1. **kerberos-anonymous-pkinit** - Kerberos Anonymous Pkinit
**Description:** Tests support for anonymous PKINIT / FAST armor authentication.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 88 --script kerberos-anonymous-pkinit example.com

# Verbose output
nmap -p 88 --script kerberos-anonymous-pkinit -v example.com
```

**Sample Output:**
```
| kerberos-anonymous-pkinit:
|   Status: AUDITED - kerberos-anonymous-pkinit evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: Kerberos v5
```

---

#### 2. **kerberos-asrep-roasting** - Kerberos Asrep Roasting
**Description:** Sends AS-REQ without pre-authentication to test if server returns AS-REP encrypted timestamp for cracking.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 88 --script kerberos-asrep-roasting example.com

# Verbose output
nmap -p 88 --script kerberos-asrep-roasting -v example.com
```

**Sample Output:**
```
| kerberos-asrep-roasting:
|   Status: AUDITED - kerberos-asrep-roasting evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Kerberos v5
```

---

#### 3. **kerberos-constrained-deleg** - Kerberos Constrained Deleg
**Description:** Tests S4U2self / S4U2proxy transition extension support.

**Risk Level:** 🟠 HIGH | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 88 --script kerberos-constrained-deleg example.com

# Verbose output
nmap -p 88 --script kerberos-constrained-deleg -v example.com
```

**Sample Output:**
```
| kerberos-constrained-deleg:
|   Status: AUDITED - kerberos-constrained-deleg evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: Kerberos v5
```

---

#### 4. **kerberos-cve-2020-1472-prep** - Kerberos Cve 2020 1472 Prep
**Description:** Fingerprints DC Netlogon / Kerberos preconditions related to Zerologon.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 88 --script kerberos-cve-2020-1472-prep example.com

# Verbose output
nmap -p 88 --script kerberos-cve-2020-1472-prep -v example.com
```

**Sample Output:**
```
| kerberos-cve-2020-1472-prep:
|   Status: AUDITED - kerberos-cve-2020-1472-prep evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Kerberos v5
```

---

#### 5. **kerberos-etype-negotiation** - Kerberos Etype Negotiation
**Description:** Probes supported encryption types (AES256-CTS-HMAC-SHA1-96, AES128, RC4, DES).

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 88 --script kerberos-etype-negotiation example.com

# Verbose output
nmap -p 88 --script kerberos-etype-negotiation -v example.com
```

**Sample Output:**
```
| kerberos-etype-negotiation:
|   Status: AUDITED - kerberos-etype-negotiation evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: Kerberos v5
```

---

#### 6. **kerberos-fast-negotiation** - Kerberos Fast Negotiation
**Description:** Tests support for Kerberos FAST (Flexible Authentication Secure Tunneling / RFC 6113).

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 88 --script kerberos-fast-negotiation example.com

# Verbose output
nmap -p 88 --script kerberos-fast-negotiation -v example.com
```

**Sample Output:**
```
| kerberos-fast-negotiation:
|   Status: AUDITED - kerberos-fast-negotiation evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Kerberos v5
```

---

#### 7. **kerberos-kdc-proxy-probe** - Kerberos Kdc Proxy Probe
**Description:** Probes MS-KKDCP (Kerberos KDC Proxy protocol over HTTPS /KdcProxy).

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 88 --script kerberos-kdc-proxy-probe example.com

# Verbose output
nmap -p 88 --script kerberos-kdc-proxy-probe -v example.com
```

**Sample Output:**
```
| kerberos-kdc-proxy-probe:
|   Status: AUDITED - kerberos-kdc-proxy-probe evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Kerberos v5
```

---

#### 8. **kerberos-kpasswd-service** - Kerberos Kpasswd Service
**Description:** Probes Kerberos password change service (kpasswd on port 464 UDP/TCP).

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 88 --script kerberos-kpasswd-service example.com

# Verbose output
nmap -p 88 --script kerberos-kpasswd-service -v example.com
```

**Sample Output:**
```
| kerberos-kpasswd-service:
|   Status: AUDITED - kerberos-kpasswd-service evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Kerberos v5
```

---

#### 9. **kerberos-pac-validation** - Kerberos Pac Validation
**Description:** Tests whether KDC enforces PAC signature validation (CVE-2022-37967 mitigation).

**Risk Level:** 🟠 HIGH | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 88 --script kerberos-pac-validation example.com

# Verbose output
nmap -p 88 --script kerberos-pac-validation -v example.com
```

**Sample Output:**
```
| kerberos-pac-validation:
|   Status: AUDITED - kerberos-pac-validation evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: Kerberos v5
```

---

#### 10. **kerberos-preauth-required** - Kerberos Preauth Required
**Description:** Verifies whether pre-authentication (PA-ENC-TIMESTAMP) is mandatory for user accounts.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 88 --script kerberos-preauth-required example.com

# Verbose output
nmap -p 88 --script kerberos-preauth-required -v example.com
```

**Sample Output:**
```
| kerberos-preauth-required:
|   Status: AUDITED - kerberos-preauth-required evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Kerberos v5
```

---

#### 11. **kerberos-realm-discovery** - Kerberos Realm Discovery
**Description:** Probes KDC with dummy realm to extract true Active Directory realm name from KDC_ERR_WRONG_REALM.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 88 --script kerberos-realm-discovery example.com

# Verbose output
nmap -p 88 --script kerberos-realm-discovery -v example.com
```

**Sample Output:**
```
| kerberos-realm-discovery:
|   Status: AUDITED - kerberos-realm-discovery evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: Kerberos v5
```

---

#### 12. **kerberos-spn-probe** - Kerberos Spn Probe
**Description:** Sends TGS-REQ for common Service Principal Names (SPNs) to test Kerberoasting response.

**Risk Level:** 🟠 HIGH | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 88 --script kerberos-spn-probe example.com

# Verbose output
nmap -p 88 --script kerberos-spn-probe -v example.com
```

**Sample Output:**
```
| kerberos-spn-probe:
|   Status: AUDITED - kerberos-spn-probe evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: Kerberos v5
```

---

#### 13. **kerberos-tcp-udp-support** - Kerberos Tcp Udp Support
**Description:** Tests whether KDC accepts large TCP requests vs standard UDP port 88.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 88 --script kerberos-tcp-udp-support example.com

# Verbose output
nmap -p 88 --script kerberos-tcp-udp-support -v example.com
```

**Sample Output:**
```
| kerberos-tcp-udp-support:
|   Status: AUDITED - kerberos-tcp-udp-support evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: Kerberos v5
```

---

#### 14. **kerberos-time-skew-audit** - Kerberos Time Skew Audit
**Description:** Measures KDC clock skew (flags KDC_ERR_TIME_SKEW > 5 minutes).

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 88 --script kerberos-time-skew-audit example.com

# Verbose output
nmap -p 88 --script kerberos-time-skew-audit -v example.com
```

**Sample Output:**
```
| kerberos-time-skew-audit:
|   Status: AUDITED - kerberos-time-skew-audit evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Kerberos v5
```

---

#### 15. **kerberos-user-enum** - Kerberos User Enum
**Description:** Enumerates valid Active Directory usernames based on KDC error codes (KDC_ERR_C_PRINCIPAL_UNKNOWN).

**Risk Level:** 🟠 HIGH | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 88 --script kerberos-user-enum example.com

# Verbose output
nmap -p 88 --script kerberos-user-enum -v example.com
```

**Sample Output:**
```
| kerberos-user-enum:
|   Status: AUDITED - kerberos-user-enum evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: Kerberos v5
```

---

#### 16. **kerberos-weak-encryption** - Kerberos Weak Encryption
**Description:** Checks if KDC negotiates deprecated DES (DES-CBC-MD5/CRC) or RC4-HMAC (etype 23) tickets.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 88 --script kerberos-weak-encryption example.com

# Verbose output
nmap -p 88 --script kerberos-weak-encryption -v example.com
```

**Sample Output:**
```
| kerberos-weak-encryption:
|   Status: AUDITED - kerberos-weak-encryption evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Kerberos v5
```

---

</details>

<details>
<summary><b>📦 NFS & ONC RPC Export Security Audits — 16 scripts (click to expand)</b></summary>

## 📦 NFS & ONC RPC Export Security Audits

### Category Overview
World-readable NFS exports, no_root_squash misconfigurations, portmapper enumeration, and NIS ypbind exposures.

**Port:** 111/2049 | **Protocol:** NFS/ONC-RPC

---

### NFS-RPC Scripts List

#### 1. **nfs-file-handle-leak** - Nfs File Handle Leak
**Description:** Inspects predictability of returned NFS file handles (FH).

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 111 --script nfs-file-handle-leak example.com

# Verbose output
nmap -p 111 --script nfs-file-handle-leak -v example.com
```

**Sample Output:**
```
| nfs-file-handle-leak:
|   Status: AUDITED - nfs-file-handle-leak evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: NFS/ONC-RPC
```

---

#### 2. **nfs-insecure-port-allowed** - Nfs Insecure Port Allowed
**Description:** Tests if NFS server accepts connections originating from non-reserved ports (> 1024).

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 111 --script nfs-insecure-port-allowed example.com

# Verbose output
nmap -p 111 --script nfs-insecure-port-allowed -v example.com
```

**Sample Output:**
```
| nfs-insecure-port-allowed:
|   Status: AUDITED - nfs-insecure-port-allowed evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: NFS/ONC-RPC
```

---

#### 3. **nfs-krb5-security-flavor** - Nfs Krb5 Security Flavor
**Description:** Checks if NFS exports require Kerberos (sec=krb5p) vs insecure sec=sys (AUTH_SYS).

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 111 --script nfs-krb5-security-flavor example.com

# Verbose output
nmap -p 111 --script nfs-krb5-security-flavor -v example.com
```

**Sample Output:**
```
| nfs-krb5-security-flavor:
|   Status: AUDITED - nfs-krb5-security-flavor evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: NFS/ONC-RPC
```

---

#### 4. **nfs-lock-manager-check** - Nfs Lock Manager Check
**Description:** Probes Network Lock Manager (nlockmgr / NLM) RPC availability.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 111 --script nfs-lock-manager-check example.com

# Verbose output
nmap -p 111 --script nfs-lock-manager-check -v example.com
```

**Sample Output:**
```
| nfs-lock-manager-check:
|   Status: AUDITED - nfs-lock-manager-check evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: NFS/ONC-RPC
```

---

#### 5. **nfs-mountd-auth-bypass** - Nfs Mountd Auth Bypass
**Description:** Tests whether NFS daemon allows direct NFSv3 LOOKUP/READ calls bypassing Mountd.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 111 --script nfs-mountd-auth-bypass example.com

# Verbose output
nmap -p 111 --script nfs-mountd-auth-bypass -v example.com
```

**Sample Output:**
```
| nfs-mountd-auth-bypass:
|   Status: AUDITED - nfs-mountd-auth-bypass evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: NFS/ONC-RPC
```

---

#### 6. **nfs-no-root-squash-check** - Nfs No Root Squash Check
**Description:** Evaluates export options for no_root_squash (allows remote client root to access files as UID 0).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 111 --script nfs-no-root-squash-check example.com

# Verbose output
nmap -p 111 --script nfs-no-root-squash-check -v example.com
```

**Sample Output:**
```
| nfs-no-root-squash-check:
|   Status: AUDITED - nfs-no-root-squash-check evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: NFS/ONC-RPC
```

---

#### 7. **nfs-readlink-traversal** - Nfs Readlink Traversal
**Description:** Checks if NFS server follows symlinks pointing outside exported paths.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 111 --script nfs-readlink-traversal example.com

# Verbose output
nmap -p 111 --script nfs-readlink-traversal -v example.com
```

**Sample Output:**
```
| nfs-readlink-traversal:
|   Status: AUDITED - nfs-readlink-traversal evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: NFS/ONC-RPC
```

---

#### 8. **nfs-rpc-programs-enum** - Nfs Rpc Programs Enum
**Description:** Queries Portmapper (rpcbind) on port 111 for registered RPC programs.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 111 --script nfs-rpc-programs-enum example.com

# Verbose output
nmap -p 111 --script nfs-rpc-programs-enum -v example.com
```

**Sample Output:**
```
| nfs-rpc-programs-enum:
|   Status: AUDITED - nfs-rpc-programs-enum evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: NFS/ONC-RPC
```

---

#### 9. **nfs-rpc-rquotad-check** - Nfs Rpc Rquotad Check
**Description:** Checks for exposed rquotad RPC service leaking disk quota details.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 111 --script nfs-rpc-rquotad-check example.com

# Verbose output
nmap -p 111 --script nfs-rpc-rquotad-check -v example.com
```

**Sample Output:**
```
| nfs-rpc-rquotad-check:
|   Status: AUDITED - nfs-rpc-rquotad-check evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: NFS/ONC-RPC
```

---

#### 10. **nfs-rpc-rusers-enum** - Nfs Rpc Rusers Enum
**Description:** Queries rusersd RPC service to enumerate logged-in users on host.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 111 --script nfs-rpc-rusers-enum example.com

# Verbose output
nmap -p 111 --script nfs-rpc-rusers-enum -v example.com
```

**Sample Output:**
```
| nfs-rpc-rusers-enum:
|   Status: AUDITED - nfs-rpc-rusers-enum evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: NFS/ONC-RPC
```

---

#### 11. **nfs-rpc-spray-dos** - Nfs Rpc Spray Dos
**Description:** Tests RPC request rate handling and portmapper transaction ID unpredictability.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 111 --script nfs-rpc-spray-dos example.com

# Verbose output
nmap -p 111 --script nfs-rpc-spray-dos -v example.com
```

**Sample Output:**
```
| nfs-rpc-spray-dos:
|   Status: AUDITED - nfs-rpc-spray-dos evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: NFS/ONC-RPC
```

---

#### 12. **nfs-rpc-statd-check** - Nfs Rpc Statd Check
**Description:** Probes rpc.statd (status) RPC service for remote monitoring and legacy format string risks.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 111 --script nfs-rpc-statd-check example.com

# Verbose output
nmap -p 111 --script nfs-rpc-statd-check -v example.com
```

**Sample Output:**
```
| nfs-rpc-statd-check:
|   Status: AUDITED - nfs-rpc-statd-check evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: NFS/ONC-RPC
```

---

#### 13. **nfs-rpc-ypbind-nis-leak** - Nfs Rpc Ypbind Nis Leak
**Description:** Detects exposed NIS (ypbind/ypserv) RPC services exposing /etc/passwd hashes.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 111 --script nfs-rpc-ypbind-nis-leak example.com

# Verbose output
nmap -p 111 --script nfs-rpc-ypbind-nis-leak -v example.com
```

**Sample Output:**
```
| nfs-rpc-ypbind-nis-leak:
|   Status: AUDITED - nfs-rpc-ypbind-nis-leak evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: NFS/ONC-RPC
```

---

#### 14. **nfs-showmount-leak** - Nfs Showmount Leak
**Description:** Calls MOUNTPROC_EXPORT to list all exported filesystem directory paths.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 111 --script nfs-showmount-leak example.com

# Verbose output
nmap -p 111 --script nfs-showmount-leak -v example.com
```

**Sample Output:**
```
| nfs-showmount-leak:
|   Status: AUDITED - nfs-showmount-leak evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: NFS/ONC-RPC
```

---

#### 15. **nfs-version-support** - Nfs Version Support
**Description:** Probes NFS versions (NFSv2, NFSv3, NFSv4, NFSv4.1, NFSv4.2).

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 111 --script nfs-version-support example.com

# Verbose output
nmap -p 111 --script nfs-version-support -v example.com
```

**Sample Output:**
```
| nfs-version-support:
|   Status: AUDITED - nfs-version-support evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: NFS/ONC-RPC
```

---

#### 16. **nfs-world-readable-exports** - Nfs World Readable Exports
**Description:** Queries Mountd RPC on port 111/2049 for NFS exports with world/wildcard (*) permissions.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 111 --script nfs-world-readable-exports example.com

# Verbose output
nmap -p 111 --script nfs-world-readable-exports -v example.com
```

**Sample Output:**
```
| nfs-world-readable-exports:
|   Status: AUDITED - nfs-world-readable-exports evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: NFS/ONC-RPC
```

---

</details>

<details>
<summary><b>🏭 ICS & SCADA Industrial Protocol Audits — 16 scripts (click to expand)</b></summary>

## 🏭 ICS & SCADA Industrial Protocol Audits

### Category Overview
Unauthenticated coil/register reading, industrial setpoint tampering, BACnet Who-Is broadcasts, and PLC fingerprinting.

**Port:** 502/47808/20000/44818/102 | **Protocol:** Modbus/BACnet/DNP3/EtherNetIP/S7

---

### ICS-SCADA Scripts List

#### 1. **bacnet-device-whois-leak** - Bacnet Device Whois Leak
**Description:** Sends BACnet/IP Who-Is broadcast on UDP port 47808 to extract Vendor ID, Device ID, Firmware.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 502 --script bacnet-device-whois-leak example.com

# Verbose output
nmap -p 502 --script bacnet-device-whois-leak -v example.com
```

**Sample Output:**
```
| bacnet-device-whois-leak:
|   Status: AUDITED - bacnet-device-whois-leak evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Modbus/BACnet/DNP3/EtherNetIP/S7
```

---

#### 2. **bacnet-read-property-leak** - Bacnet Read Property Leak
**Description:** Queries BACnet ReadProperty (Object: Device, Prop: Object_Name, Location, Description).

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 502 --script bacnet-read-property-leak example.com

# Verbose output
nmap -p 502 --script bacnet-read-property-leak -v example.com
```

**Sample Output:**
```
| bacnet-read-property-leak:
|   Status: AUDITED - bacnet-read-property-leak evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Modbus/BACnet/DNP3/EtherNetIP/S7
```

---

#### 3. **dnp3-unauth-link-status** - Dnp3 Unauth Link Status
**Description:** Sends DNP3 (Distributed Network Protocol) Request Link Status on port 20000.

**Risk Level:** 🟠 HIGH | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 502 --script dnp3-unauth-link-status example.com

# Verbose output
nmap -p 502 --script dnp3-unauth-link-status -v example.com
```

**Sample Output:**
```
| dnp3-unauth-link-status:
|   Status: AUDITED - dnp3-unauth-link-status evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: Modbus/BACnet/DNP3/EtherNetIP/S7
```

---

#### 4. **ethernetip-identity-dump** - Ethernetip Identity Dump
**Description:** Sends EtherNet/IP (CIP) List Identity command on port 44818 to extract PLC Vendor, Device Type.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 502 --script ethernetip-identity-dump example.com

# Verbose output
nmap -p 502 --script ethernetip-identity-dump -v example.com
```

**Sample Output:**
```
| ethernetip-identity-dump:
|   Status: AUDITED - ethernetip-identity-dump evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Modbus/BACnet/DNP3/EtherNetIP/S7
```

---

#### 5. **fins-omron-plc-dump** - Fins Omron Plc Dump
**Description:** Sends Omron FINS controller status read command on UDP/TCP port 9600.

**Risk Level:** 🟠 HIGH | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 502 --script fins-omron-plc-dump example.com

# Verbose output
nmap -p 502 --script fins-omron-plc-dump -v example.com
```

**Sample Output:**
```
| fins-omron-plc-dump:
|   Status: AUDITED - fins-omron-plc-dump evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: Modbus/BACnet/DNP3/EtherNetIP/S7
```

---

#### 6. **fox-niagara-unauth-check** - Fox Niagara Unauth Check
**Description:** Probes Tridium Niagara Fox protocol on port 1911/4911 for unauthenticated building automation access.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 502 --script fox-niagara-unauth-check example.com

# Verbose output
nmap -p 502 --script fox-niagara-unauth-check -v example.com
```

**Sample Output:**
```
| fox-niagara-unauth-check:
|   Status: AUDITED - fox-niagara-unauth-check evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Modbus/BACnet/DNP3/EtherNetIP/S7
```

---

#### 7. **hart-ip-device-probe** - Hart Ip Device Probe
**Description:** Probes HART-IP industrial instrumentation protocol on UDP/TCP port 5094.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 502 --script hart-ip-device-probe example.com

# Verbose output
nmap -p 502 --script hart-ip-device-probe -v example.com
```

**Sample Output:**
```
| hart-ip-device-probe:
|   Status: AUDITED - hart-ip-device-probe evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: Modbus/BACnet/DNP3/EtherNetIP/S7
```

---

#### 8. **iec104-apci-test** - Iec104 Apci Test
**Description:** Probes IEC 60870-5-104 (SCADA electrical grid) STARTACT / TESTFR APCI frames on port 2404.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 502 --script iec104-apci-test example.com

# Verbose output
nmap -p 502 --script iec104-apci-test -v example.com
```

**Sample Output:**
```
| iec104-apci-test:
|   Status: AUDITED - iec104-apci-test evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Modbus/BACnet/DNP3/EtherNetIP/S7
```

---

#### 9. **melsec-mitsubishi-probe** - Melsec Mitsubishi Probe
**Description:** Probes Mitsubishi MELSEC-Q/L series PLC protocol on port 5007.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 502 --script melsec-mitsubishi-probe example.com

# Verbose output
nmap -p 502 --script melsec-mitsubishi-probe -v example.com
```

**Sample Output:**
```
| melsec-mitsubishi-probe:
|   Status: AUDITED - melsec-mitsubishi-probe evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Modbus/BACnet/DNP3/EtherNetIP/S7
```

---

#### 10. **modbus-device-id-leak** - Modbus Device Id Leak
**Description:** Sends Function Code 0x2B / MEI 0x0E (Read Device Identification) to extract VendorName, ProductCode.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 502 --script modbus-device-id-leak example.com

# Verbose output
nmap -p 502 --script modbus-device-id-leak -v example.com
```

**Sample Output:**
```
| modbus-device-id-leak:
|   Status: AUDITED - modbus-device-id-leak evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Modbus/BACnet/DNP3/EtherNetIP/S7
```

---

#### 11. **modbus-unauth-read-coils** - Modbus Unauth Read Coils
**Description:** Sends Modbus TCP function code 0x01 (Read Coils) on port 502 without auth to inspect digital outputs.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 502 --script modbus-unauth-read-coils example.com

# Verbose output
nmap -p 502 --script modbus-unauth-read-coils -v example.com
```

**Sample Output:**
```
| modbus-unauth-read-coils:
|   Status: AUDITED - modbus-unauth-read-coils evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Modbus/BACnet/DNP3/EtherNetIP/S7
```

---

#### 12. **modbus-unauth-read-holding** - Modbus Unauth Read Holding
**Description:** Sends Modbus TCP function code 0x03 (Read Holding Registers) to read industrial sensor/setpoint values.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 502 --script modbus-unauth-read-holding example.com

# Verbose output
nmap -p 502 --script modbus-unauth-read-holding -v example.com
```

**Sample Output:**
```
| modbus-unauth-read-holding:
|   Status: AUDITED - modbus-unauth-read-holding evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Modbus/BACnet/DNP3/EtherNetIP/S7
```

---

#### 13. **modbus-unauth-write-risk** - Modbus Unauth Write Risk
**Description:** Checks whether Modbus TCP allows write operations (Function 0x05 / 0x06) without authentication.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 502 --script modbus-unauth-write-risk example.com

# Verbose output
nmap -p 502 --script modbus-unauth-write-risk -v example.com
```

**Sample Output:**
```
| modbus-unauth-write-risk:
|   Status: AUDITED - modbus-unauth-write-risk evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Modbus/BACnet/DNP3/EtherNetIP/S7
```

---

#### 14. **modbus-unit-id-scan** - Modbus Unit Id Scan
**Description:** Scans for active Modbus slave Unit IDs (1 to 247) on the serial bridge.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 502 --script modbus-unit-id-scan example.com

# Verbose output
nmap -p 502 --script modbus-unit-id-scan -v example.com
```

**Sample Output:**
```
| modbus-unit-id-scan:
|   Status: AUDITED - modbus-unit-id-scan evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: Modbus/BACnet/DNP3/EtherNetIP/S7
```

---

#### 15. **profinet-dcp-discovery** - Profinet Dcp Discovery
**Description:** Probes PROFINET Discovery and Configuration Protocol (DCP) services on port 34964.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 502 --script profinet-dcp-discovery example.com

# Verbose output
nmap -p 502 --script profinet-dcp-discovery -v example.com
```

**Sample Output:**
```
| profinet-dcp-discovery:
|   Status: AUDITED - profinet-dcp-discovery evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: Modbus/BACnet/DNP3/EtherNetIP/S7
```

---

#### 16. **s7comm-plc-fingerprint** - S7Comm Plc Fingerprint
**Description:** Sends S7Comm ISO-on-TCP (port 102) setup communication to fingerprint Siemens S7 PLCs.

**Risk Level:** 🟠 HIGH | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 502 --script s7comm-plc-fingerprint example.com

# Verbose output
nmap -p 502 --script s7comm-plc-fingerprint -v example.com
```

**Sample Output:**
```
| s7comm-plc-fingerprint:
|   Status: AUDITED - s7comm-plc-fingerprint evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: Modbus/BACnet/DNP3/EtherNetIP/S7
```

---

</details>

<details>
<summary><b>☸️ Kubernetes API Server & Kubelet Audits — 16 scripts (click to expand)</b></summary>

## ☸️ Kubernetes API Server & Kubelet Audits

### Category Overview
Unauthenticated API access, Kubelet unauth exec/pods, Kubernetes Dashboard exposure, and etcd keyspace leaks.

**Port:** 6443/10250/10255/8443/2379 | **Protocol:** Kubernetes REST API

---

### KUBERNETES Scripts List

#### 1. **k8s-admission-webhook-audit** - K8S Admission Webhook Audit
**Description:** Probes ValidatingWebhookConfiguration / MutatingWebhookConfiguration endpoints on port 8443.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 6443 --script k8s-admission-webhook-audit example.com

# Verbose output
nmap -p 6443 --script k8s-admission-webhook-audit -v example.com
```

**Sample Output:**
```
| k8s-admission-webhook-audit:
|   Status: AUDITED - k8s-admission-webhook-audit evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Kubernetes REST API
```

---

#### 2. **k8s-anonymous-auth-enabled** - K8S Anonymous Auth Enabled
**Description:** Checks whether API server permits system:anonymous user access.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 6443 --script k8s-anonymous-auth-enabled example.com

# Verbose output
nmap -p 6443 --script k8s-anonymous-auth-enabled -v example.com
```

**Sample Output:**
```
| k8s-anonymous-auth-enabled:
|   Status: AUDITED - k8s-anonymous-auth-enabled evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: Kubernetes REST API
```

---

#### 3. **k8s-api-unauthenticated-access** - K8S Api Unauthenticated Access
**Description:** Checks unauthenticated access to Kubernetes API server (/api/v1/namespaces, /apis) on port 6443/8443.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 6443 --script k8s-api-unauthenticated-access example.com

# Verbose output
nmap -p 6443 --script k8s-api-unauthenticated-access -v example.com
```

**Sample Output:**
```
| k8s-api-unauthenticated-access:
|   Status: AUDITED - k8s-api-unauthenticated-access evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Kubernetes REST API
```

---

#### 4. **k8s-cni-portmap-exposure** - K8S Cni Portmap Exposure
**Description:** Checks CNI plugin portmap exposures on host interfaces.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 6443 --script k8s-cni-portmap-exposure example.com

# Verbose output
nmap -p 6443 --script k8s-cni-portmap-exposure -v example.com
```

**Sample Output:**
```
| k8s-cni-portmap-exposure:
|   Status: AUDITED - k8s-cni-portmap-exposure evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Kubernetes REST API
```

---

#### 5. **k8s-coredns-metrics-exposure** - K8S Coredns Metrics Exposure
**Description:** Probes CoreDNS metrics endpoint on port 9153.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 6443 --script k8s-coredns-metrics-exposure example.com

# Verbose output
nmap -p 6443 --script k8s-coredns-metrics-exposure -v example.com
```

**Sample Output:**
```
| k8s-coredns-metrics-exposure:
|   Status: AUDITED - k8s-coredns-metrics-exposure evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: Kubernetes REST API
```

---

#### 6. **k8s-dashboard-unauth-access** - K8S Dashboard Unauth Access
**Description:** Checks for unauthenticated Kubernetes Dashboard web UI on ports 8443/30000/443.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 6443 --script k8s-dashboard-unauth-access example.com

# Verbose output
nmap -p 6443 --script k8s-dashboard-unauth-access -v example.com
```

**Sample Output:**
```
| k8s-dashboard-unauth-access:
|   Status: AUDITED - k8s-dashboard-unauth-access evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Kubernetes REST API
```

---

#### 7. **k8s-etcd-unauth-keyspace** - K8S Etcd Unauth Keyspace
**Description:** Connects to Kubernetes backend etcd cluster on port 2379 without client certificates to dump secrets.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 6443 --script k8s-etcd-unauth-keyspace example.com

# Verbose output
nmap -p 6443 --script k8s-etcd-unauth-keyspace -v example.com
```

**Sample Output:**
```
| k8s-etcd-unauth-keyspace:
|   Status: AUDITED - k8s-etcd-unauth-keyspace evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Kubernetes REST API
```

---

#### 8. **k8s-kube-proxy-debug-leak** - K8S Kube Proxy Debug Leak
**Description:** Probes kube-proxy healthz (/healthz) and config endpoints on port 10256.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 6443 --script k8s-kube-proxy-debug-leak example.com

# Verbose output
nmap -p 6443 --script k8s-kube-proxy-debug-leak -v example.com
```

**Sample Output:**
```
| k8s-kube-proxy-debug-leak:
|   Status: AUDITED - k8s-kube-proxy-debug-leak evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Kubernetes REST API
```

---

#### 9. **k8s-kubelet-readonly-pods** - K8S Kubelet Readonly Pods
**Description:** Probes Kubelet read-only port 10255 (/pods, /spec) for unauthenticated pod list and secret leaks.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 6443 --script k8s-kubelet-readonly-pods example.com

# Verbose output
nmap -p 6443 --script k8s-kubelet-readonly-pods -v example.com
```

**Sample Output:**
```
| k8s-kubelet-readonly-pods:
|   Status: AUDITED - k8s-kubelet-readonly-pods evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Kubernetes REST API
```

---

#### 10. **k8s-kubelet-unauth-exec** - K8S Kubelet Unauth Exec
**Description:** Probes Kubelet HTTPS API on port 10250 (/runningpods/, /exec, /run) for unauthenticated RCE.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 6443 --script k8s-kubelet-unauth-exec example.com

# Verbose output
nmap -p 6443 --script k8s-kubelet-unauth-exec -v example.com
```

**Sample Output:**
```
| k8s-kubelet-unauth-exec:
|   Status: AUDITED - k8s-kubelet-unauth-exec evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Kubernetes REST API
```

---

#### 11. **k8s-metrics-token-leak** - K8S Metrics Token Leak
**Description:** Probes /metrics and /metrics/cadvisor on port 10250/10255 for service token and metric disclosures.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 6443 --script k8s-metrics-token-leak example.com

# Verbose output
nmap -p 6443 --script k8s-metrics-token-leak -v example.com
```

**Sample Output:**
```
| k8s-metrics-token-leak:
|   Status: AUDITED - k8s-metrics-token-leak evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Kubernetes REST API
```

---

#### 12. **k8s-node-proxy-misconfig** - K8S Node Proxy Misconfig
**Description:** Tests /api/v1/nodes/{name}/proxy for unauthenticated pod/node proxy access.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 6443 --script k8s-node-proxy-misconfig example.com

# Verbose output
nmap -p 6443 --script k8s-node-proxy-misconfig -v example.com
```

**Sample Output:**
```
| k8s-node-proxy-misconfig:
|   Status: AUDITED - k8s-node-proxy-misconfig evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: Kubernetes REST API
```

---

#### 13. **k8s-openapi-spec-leak** - K8S Openapi Spec Leak
**Description:** Downloads /openapi/v2 and /swagger.json to map all deployed CRDs and API endpoints.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 6443 --script k8s-openapi-spec-leak example.com

# Verbose output
nmap -p 6443 --script k8s-openapi-spec-leak -v example.com
```

**Sample Output:**
```
| k8s-openapi-spec-leak:
|   Status: AUDITED - k8s-openapi-spec-leak evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Kubernetes REST API
```

---

#### 14. **k8s-pod-security-standards** - K8S Pod Security Standards
**Description:** Evaluates Pod Security Standards (Privileged, Baseline, Restricted) on namespace metadata.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 6443 --script k8s-pod-security-standards example.com

# Verbose output
nmap -p 6443 --script k8s-pod-security-standards -v example.com
```

**Sample Output:**
```
| k8s-pod-security-standards:
|   Status: AUDITED - k8s-pod-security-standards evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Kubernetes REST API
```

---

#### 15. **k8s-serviceaccount-token-probe** - K8S Serviceaccount Token Probe
**Description:** Tests default ServiceAccount token mounting and RBAC permission boundaries.

**Risk Level:** 🟠 HIGH | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 6443 --script k8s-serviceaccount-token-probe example.com

# Verbose output
nmap -p 6443 --script k8s-serviceaccount-token-probe -v example.com
```

**Sample Output:**
```
| k8s-serviceaccount-token-probe:
|   Status: AUDITED - k8s-serviceaccount-token-probe evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: Kubernetes REST API
```

---

#### 16. **k8s-version-fingerprint** - K8S Version Fingerprint
**Description:** Queries /version on API server to extract GitVersion, GitCommit, Platform, and GoVersion.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 6443 --script k8s-version-fingerprint example.com

# Verbose output
nmap -p 6443 --script k8s-version-fingerprint -v example.com
```

**Sample Output:**
```
| k8s-version-fingerprint:
|   Status: AUDITED - k8s-version-fingerprint evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: Kubernetes REST API
```

---

</details>

<details>
<summary><b>🔎 Elasticsearch & OpenSearch Audits — 16 scripts (click to expand)</b></summary>

## 🔎 Elasticsearch & OpenSearch Audits

### Category Overview
Unauthenticated cluster information, indices data dumping, search query extraction, and Kibana exposures.

**Port:** 9200/5601 | **Protocol:** Elasticsearch REST API

---

### ELASTICSEARCH Scripts List

#### 1. **elasticsearch-aliases-enum** - Elasticsearch Aliases Enum
**Description:** Queries /_aliases and /_cat/aliases to discover hidden index routing.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9200 --script elasticsearch-aliases-enum example.com

# Verbose output
nmap -p 9200 --script elasticsearch-aliases-enum -v example.com
```

**Sample Output:**
```
| elasticsearch-aliases-enum:
|   Status: AUDITED - elasticsearch-aliases-enum evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Elasticsearch REST API
```

---

#### 2. **elasticsearch-cluster-health-leak** - Elasticsearch Cluster Health Leak
**Description:** Queries /_cluster/health and /_cluster/stats for node counts, shard status, disk usage.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9200 --script elasticsearch-cluster-health-leak example.com

# Verbose output
nmap -p 9200 --script elasticsearch-cluster-health-leak -v example.com
```

**Sample Output:**
```
| elasticsearch-cluster-health-leak:
|   Status: AUDITED - elasticsearch-cluster-health-leak evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: Elasticsearch REST API
```

---

#### 3. **elasticsearch-cve-2015-1427-check** - Elasticsearch Cve 2015 1427 Check
**Description:** Fingerprints legacy versions vulnerable to Groovy Sandbox RCE.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9200 --script elasticsearch-cve-2015-1427-check example.com

# Verbose output
nmap -p 9200 --script elasticsearch-cve-2015-1427-check -v example.com
```

**Sample Output:**
```
| elasticsearch-cve-2015-1427-check:
|   Status: AUDITED - elasticsearch-cve-2015-1427-check evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: Elasticsearch REST API
```

---

#### 4. **elasticsearch-delete-index-allowed** - Elasticsearch Delete Index Allowed
**Description:** Tests if unauthenticated DELETE requests are accepted by API router.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9200 --script elasticsearch-delete-index-allowed example.com

# Verbose output
nmap -p 9200 --script elasticsearch-delete-index-allowed -v example.com
```

**Sample Output:**
```
| elasticsearch-delete-index-allowed:
|   Status: AUDITED - elasticsearch-delete-index-allowed evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: Elasticsearch REST API
```

---

#### 5. **elasticsearch-field-caps-audit** - Elasticsearch Field Caps Audit
**Description:** Queries /_field_caps to map schema fields (passwords, emails, credit cards, PII).

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9200 --script elasticsearch-field-caps-audit example.com

# Verbose output
nmap -p 9200 --script elasticsearch-field-caps-audit -v example.com
```

**Sample Output:**
```
| elasticsearch-field-caps-audit:
|   Status: AUDITED - elasticsearch-field-caps-audit evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Elasticsearch REST API
```

---

#### 6. **elasticsearch-indices-data-dump** - Elasticsearch Indices Data Dump
**Description:** Queries /_cat/indices?v and /_cat/shards to enumerate all private indices and document counts.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9200 --script elasticsearch-indices-data-dump example.com

# Verbose output
nmap -p 9200 --script elasticsearch-indices-data-dump -v example.com
```

**Sample Output:**
```
| elasticsearch-indices-data-dump:
|   Status: AUDITED - elasticsearch-indices-data-dump evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Elasticsearch REST API
```

---

#### 7. **elasticsearch-kibana-unauth-access** - Elasticsearch Kibana Unauth Access
**Description:** Probes Kibana interface on port 5601 (/api/status, /app/kibana) without authentication.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9200 --script elasticsearch-kibana-unauth-access example.com

# Verbose output
nmap -p 9200 --script elasticsearch-kibana-unauth-access -v example.com
```

**Sample Output:**
```
| elasticsearch-kibana-unauth-access:
|   Status: AUDITED - elasticsearch-kibana-unauth-access evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Elasticsearch REST API
```

---

#### 8. **elasticsearch-license-status** - Elasticsearch License Status
**Description:** Queries /_license for X-Pack license type (basic, enterprise, trial).

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9200 --script elasticsearch-license-status example.com

# Verbose output
nmap -p 9200 --script elasticsearch-license-status -v example.com
```

**Sample Output:**
```
| elasticsearch-license-status:
|   Status: AUDITED - elasticsearch-license-status evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: Elasticsearch REST API
```

---

#### 9. **elasticsearch-nodes-settings-leak** - Elasticsearch Nodes Settings Leak
**Description:** Queries /_nodes/settings and /_nodes/env to extract environment variables, AWS keys, and paths.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9200 --script elasticsearch-nodes-settings-leak example.com

# Verbose output
nmap -p 9200 --script elasticsearch-nodes-settings-leak -v example.com
```

**Sample Output:**
```
| elasticsearch-nodes-settings-leak:
|   Status: AUDITED - elasticsearch-nodes-settings-leak evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Elasticsearch REST API
```

---

#### 10. **elasticsearch-painless-script-rce** - Elasticsearch Painless Script Rce
**Description:** Checks if Painless / Groovy scripting engine is enabled for dynamic script execution (/_scripts).

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9200 --script elasticsearch-painless-script-rce example.com

# Verbose output
nmap -p 9200 --script elasticsearch-painless-script-rce -v example.com
```

**Sample Output:**
```
| elasticsearch-painless-script-rce:
|   Status: AUDITED - elasticsearch-painless-script-rce evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: Elasticsearch REST API
```

---

#### 11. **elasticsearch-search-query-leak** - Elasticsearch Search Query Leak
**Description:** Executes unauthenticated GET /_search across all indices to extract sensitive stored documents.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9200 --script elasticsearch-search-query-leak example.com

# Verbose output
nmap -p 9200 --script elasticsearch-search-query-leak -v example.com
```

**Sample Output:**
```
| elasticsearch-search-query-leak:
|   Status: AUDITED - elasticsearch-search-query-leak evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Elasticsearch REST API
```

---

#### 12. **elasticsearch-security-disabled** - Elasticsearch Security Disabled
**Description:** Checks whether xpack.security.enabled is false (absence of basic authentication & TLS).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9200 --script elasticsearch-security-disabled example.com

# Verbose output
nmap -p 9200 --script elasticsearch-security-disabled -v example.com
```

**Sample Output:**
```
| elasticsearch-security-disabled:
|   Status: AUDITED - elasticsearch-security-disabled evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Elasticsearch REST API
```

---

#### 13. **elasticsearch-snapshot-repo-leak** - Elasticsearch Snapshot Repo Leak
**Description:** Queries /_snapshot/_all for registered backup snapshot repositories (S3 buckets, NFS paths).

**Risk Level:** 🟠 HIGH | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9200 --script elasticsearch-snapshot-repo-leak example.com

# Verbose output
nmap -p 9200 --script elasticsearch-snapshot-repo-leak -v example.com
```

**Sample Output:**
```
| elasticsearch-snapshot-repo-leak:
|   Status: AUDITED - elasticsearch-snapshot-repo-leak evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: Elasticsearch REST API
```

---

#### 14. **elasticsearch-tasks-monitoring** - Elasticsearch Tasks Monitoring
**Description:** Queries /_tasks to inspect active background jobs, reindexing operations, and queries.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9200 --script elasticsearch-tasks-monitoring example.com

# Verbose output
nmap -p 9200 --script elasticsearch-tasks-monitoring -v example.com
```

**Sample Output:**
```
| elasticsearch-tasks-monitoring:
|   Status: AUDITED - elasticsearch-tasks-monitoring evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Elasticsearch REST API
```

---

#### 15. **elasticsearch-templates-leak** - Elasticsearch Templates Leak
**Description:** Queries /_template to extract index mapping templates and analyzers.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9200 --script elasticsearch-templates-leak example.com

# Verbose output
nmap -p 9200 --script elasticsearch-templates-leak -v example.com
```

**Sample Output:**
```
| elasticsearch-templates-leak:
|   Status: AUDITED - elasticsearch-templates-leak evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Elasticsearch REST API
```

---

#### 16. **elasticsearch-unauth-cluster-info** - Elasticsearch Unauth Cluster Info
**Description:** Queries base URL (GET /) without credentials to extract cluster name, UUID, Lucene version.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9200 --script elasticsearch-unauth-cluster-info example.com

# Verbose output
nmap -p 9200 --script elasticsearch-unauth-cluster-info -v example.com
```

**Sample Output:**
```
| elasticsearch-unauth-cluster-info:
|   Status: AUDITED - elasticsearch-unauth-cluster-info evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Elasticsearch REST API
```

---

</details>

<details>
<summary><b>⚡ Memcached In-Memory Cache Audits — 16 scripts (click to expand)</b></summary>

## ⚡ Memcached In-Memory Cache Audits

### Category Overview
Unauthenticated cache access, UDP amplification DDoS risk, slab cachedump key harvesting, and live watch streams.

**Port:** 11211 | **Protocol:** Memcached ASCII/Binary

---

### MEMCACHED Scripts List

#### 1. **memcached-ascii-udp-disable-check** - Memcached Ascii Udp Disable Check
**Description:** Checks whether UDP listener (port 11211 UDP) has been safely disabled (-U 0).

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 11211 --script memcached-ascii-udp-disable-check example.com

# Verbose output
nmap -p 11211 --script memcached-ascii-udp-disable-check -v example.com
```

**Sample Output:**
```
| memcached-ascii-udp-disable-check:
|   Status: AUDITED - memcached-ascii-udp-disable-check evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Memcached ASCII/Binary
```

---

#### 2. **memcached-binary-protocol-probe** - Memcached Binary Protocol Probe
**Description:** Sends binary protocol GetK / Stat packets (magic 0x80) to test binary parser.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 11211 --script memcached-binary-protocol-probe example.com

# Verbose output
nmap -p 11211 --script memcached-binary-protocol-probe -v example.com
```

**Sample Output:**
```
| memcached-binary-protocol-probe:
|   Status: AUDITED - memcached-binary-protocol-probe evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: Memcached ASCII/Binary
```

---

#### 3. **memcached-connection-limit-dos** - Memcached Connection Limit Dos
**Description:** Tests max connection ceiling and slow connection handling.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 11211 --script memcached-connection-limit-dos example.com

# Verbose output
nmap -p 11211 --script memcached-connection-limit-dos -v example.com
```

**Sample Output:**
```
| memcached-connection-limit-dos:
|   Status: AUDITED - memcached-connection-limit-dos evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Memcached ASCII/Binary
```

---

#### 4. **memcached-flush-all-risk** - Memcached Flush All Risk
**Description:** Tests whether flush_all command is accepted (allowing unauthenticated cache wiping / DoS).

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 11211 --script memcached-flush-all-risk example.com

# Verbose output
nmap -p 11211 --script memcached-flush-all-risk -v example.com
```

**Sample Output:**
```
| memcached-flush-all-risk:
|   Status: AUDITED - memcached-flush-all-risk evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: Memcached ASCII/Binary
```

---

#### 5. **memcached-key-data-retrieval** - Memcached Key Data Retrieval
**Description:** Sends get <key> for common session/cache keys (session_id, user_token, auth_cache).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 11211 --script memcached-key-data-retrieval example.com

# Verbose output
nmap -p 11211 --script memcached-key-data-retrieval -v example.com
```

**Sample Output:**
```
| memcached-key-data-retrieval:
|   Status: AUDITED - memcached-key-data-retrieval evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Memcached ASCII/Binary
```

---

#### 6. **memcached-sasl-auth-enforced** - Memcached Sasl Auth Enforced
**Description:** Probes whether binary protocol SASL authentication is enabled or disabled.

**Risk Level:** 🟠 HIGH | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 11211 --script memcached-sasl-auth-enforced example.com

# Verbose output
nmap -p 11211 --script memcached-sasl-auth-enforced -v example.com
```

**Sample Output:**
```
| memcached-sasl-auth-enforced:
|   Status: AUDITED - memcached-sasl-auth-enforced evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: Memcached ASCII/Binary
```

---

#### 7. **memcached-settings-leak** - Memcached Settings Leak
**Description:** Sends stats settings to extract maxconns, maxbytes, slab reassign, and auth settings.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 11211 --script memcached-settings-leak example.com

# Verbose output
nmap -p 11211 --script memcached-settings-leak -v example.com
```

**Sample Output:**
```
| memcached-settings-leak:
|   Status: AUDITED - memcached-settings-leak evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Memcached ASCII/Binary
```

---

#### 8. **memcached-sizes-memory-dump** - Memcached Sizes Memory Dump
**Description:** Sends stats sizes to analyze memory allocation distribution across chunk sizes.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 11211 --script memcached-sizes-memory-dump example.com

# Verbose output
nmap -p 11211 --script memcached-sizes-memory-dump -v example.com
```

**Sample Output:**
```
| memcached-sizes-memory-dump:
|   Status: AUDITED - memcached-sizes-memory-dump evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Memcached ASCII/Binary
```

---

#### 9. **memcached-slab-automove-audit** - Memcached Slab Automove Audit
**Description:** Evaluates slab automove and eviction policies.

**Risk Level:** 🟢 LOW | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 11211 --script memcached-slab-automove-audit example.com

# Verbose output
nmap -p 11211 --script memcached-slab-automove-audit -v example.com
```

**Sample Output:**
```
| memcached-slab-automove-audit:
|   Status: AUDITED - memcached-slab-automove-audit evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: Memcached ASCII/Binary
```

---

#### 10. **memcached-slabs-item-dump** - Memcached Slabs Item Dump
**Description:** Uses stats items and stats cachedump to enumerate and dump cached keys and session tokens.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 11211 --script memcached-slabs-item-dump example.com

# Verbose output
nmap -p 11211 --script memcached-slabs-item-dump -v example.com
```

**Sample Output:**
```
| memcached-slabs-item-dump:
|   Status: AUDITED - memcached-slabs-item-dump evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Memcached ASCII/Binary
```

---

#### 11. **memcached-touch-command-audit** - Memcached Touch Command Audit
**Description:** Tests touch command for expiration time tampering.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 11211 --script memcached-touch-command-audit example.com

# Verbose output
nmap -p 11211 --script memcached-touch-command-audit -v example.com
```

**Sample Output:**
```
| memcached-touch-command-audit:
|   Status: AUDITED - memcached-touch-command-audit evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Memcached ASCII/Binary
```

---

#### 12. **memcached-udp-amplification-ddos** - Memcached Udp Amplification Ddos
**Description:** Measures UDP reflection amplification factor (CVE-2018-1000115 / Memcrashed).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 11211 --script memcached-udp-amplification-ddos example.com

# Verbose output
nmap -p 11211 --script memcached-udp-amplification-ddos -v example.com
```

**Sample Output:**
```
| memcached-udp-amplification-ddos:
|   Status: AUDITED - memcached-udp-amplification-ddos evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Memcached ASCII/Binary
```

---

#### 13. **memcached-unauthenticated-access** - Memcached Unauthenticated Access
**Description:** Sends version and stats to port 11211 (TCP/UDP) without credentials.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 11211 --script memcached-unauthenticated-access example.com

# Verbose output
nmap -p 11211 --script memcached-unauthenticated-access -v example.com
```

**Sample Output:**
```
| memcached-unauthenticated-access:
|   Status: AUDITED - memcached-unauthenticated-access evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Memcached ASCII/Binary
```

---

#### 14. **memcached-verbosity-command-leak** - Memcached Verbosity Command Leak
**Description:** Sends verbosity command to test if logging levels can be altered remotely.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 11211 --script memcached-verbosity-command-leak example.com

# Verbose output
nmap -p 11211 --script memcached-verbosity-command-leak -v example.com
```

**Sample Output:**
```
| memcached-verbosity-command-leak:
|   Status: AUDITED - memcached-verbosity-command-leak evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Memcached ASCII/Binary
```

---

#### 15. **memcached-version-fingerprint** - Memcached Version Fingerprint
**Description:** Extracts exact Memcached engine version and OS platform.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 11211 --script memcached-version-fingerprint example.com

# Verbose output
nmap -p 11211 --script memcached-version-fingerprint -v example.com
```

**Sample Output:**
```
| memcached-version-fingerprint:
|   Status: AUDITED - memcached-version-fingerprint evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: Memcached ASCII/Binary
```

---

#### 16. **memcached-watch-stream-exposure** - Memcached Watch Stream Exposure
**Description:** Sends watch / watch fetchers command to eavesdrop on live key operations.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 11211 --script memcached-watch-stream-exposure example.com

# Verbose output
nmap -p 11211 --script memcached-watch-stream-exposure -v example.com
```

**Sample Output:**
```
| memcached-watch-stream-exposure:
|   Status: AUDITED - memcached-watch-stream-exposure evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: Memcached ASCII/Binary
```

---

</details>

<details>
<summary><b>📨 Kafka & RabbitMQ Message Broker Audits — 16 scripts (click to expand)</b></summary>

## 📨 Kafka & RabbitMQ Message Broker Audits

### Category Overview
Unauthenticated topic metadata dumping, anonymous consumer group access, RabbitMQ management UI, and default creds.

**Port:** 9092/5672/15672 | **Protocol:** Kafka / AMQP 0-9-1

---

### KAFKA-AMQP Scripts List

#### 1. **kafka-anonymous-consumer-group** - Kafka Anonymous Consumer Group
**Description:** Probes whether unauthenticated clients can join consumer groups and consume topic messages.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9092 --script kafka-anonymous-consumer-group example.com

# Verbose output
nmap -p 9092 --script kafka-anonymous-consumer-group -v example.com
```

**Sample Output:**
```
| kafka-anonymous-consumer-group:
|   Status: AUDITED - kafka-anonymous-consumer-group evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Kafka / AMQP 0-9-1
```

---

#### 2. **kafka-broker-fingerprint** - Kafka Broker Fingerprint
**Description:** Analyzes supported Kafka ApiVersions ranges (API Key 18) to pinpoint exact Kafka broker version.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9092 --script kafka-broker-fingerprint example.com

# Verbose output
nmap -p 9092 --script kafka-broker-fingerprint -v example.com
```

**Sample Output:**
```
| kafka-broker-fingerprint:
|   Status: AUDITED - kafka-broker-fingerprint evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: Kafka / AMQP 0-9-1
```

---

#### 3. **kafka-controller-epoch-leak** - Kafka Controller Epoch Leak
**Description:** Inspects cluster Controller ID and epoch leadership status.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9092 --script kafka-controller-epoch-leak example.com

# Verbose output
nmap -p 9092 --script kafka-controller-epoch-leak -v example.com
```

**Sample Output:**
```
| kafka-controller-epoch-leak:
|   Status: AUDITED - kafka-controller-epoch-leak evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: Kafka / AMQP 0-9-1
```

---

#### 4. **kafka-create-topic-allowed** - Kafka Create Topic Allowed
**Description:** Tests whether unauthenticated clients can execute CreateTopics API (API Key 19).

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9092 --script kafka-create-topic-allowed example.com

# Verbose output
nmap -p 9092 --script kafka-create-topic-allowed -v example.com
```

**Sample Output:**
```
| kafka-create-topic-allowed:
|   Status: AUDITED - kafka-create-topic-allowed evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: Kafka / AMQP 0-9-1
```

---

#### 5. **kafka-delete-topic-allowed** - Kafka Delete Topic Allowed
**Description:** Tests whether unauthenticated clients can execute DeleteTopics API (API Key 20).

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9092 --script kafka-delete-topic-allowed example.com

# Verbose output
nmap -p 9092 --script kafka-delete-topic-allowed -v example.com
```

**Sample Output:**
```
| kafka-delete-topic-allowed:
|   Status: AUDITED - kafka-delete-topic-allowed evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: Kafka / AMQP 0-9-1
```

---

#### 6. **kafka-metadata-topic-leak** - Kafka Metadata Topic Leak
**Description:** Sends Kafka ApiVersions and Metadata request (API Key 3) to dump all topic names, partition counts.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9092 --script kafka-metadata-topic-leak example.com

# Verbose output
nmap -p 9092 --script kafka-metadata-topic-leak -v example.com
```

**Sample Output:**
```
| kafka-metadata-topic-leak:
|   Status: AUDITED - kafka-metadata-topic-leak evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Kafka / AMQP 0-9-1
```

---

#### 7. **kafka-plain-auth-over-cleartext** - Kafka Plain Auth Over Cleartext
**Description:** Checks whether SASL/PLAIN credentials are accepted over unencrypted plaintext port 9092.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9092 --script kafka-plain-auth-over-cleartext example.com

# Verbose output
nmap -p 9092 --script kafka-plain-auth-over-cleartext -v example.com
```

**Sample Output:**
```
| kafka-plain-auth-over-cleartext:
|   Status: AUDITED - kafka-plain-auth-over-cleartext evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Kafka / AMQP 0-9-1
```

---

#### 8. **kafka-sasl-mechanism-audit** - Kafka Sasl Mechanism Audit
**Description:** Probes Kafka SaslHandshake API (API Key 17) for PLAIN, SCRAM-SHA-256, SCRAM-SHA-512, GSSAPI.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9092 --script kafka-sasl-mechanism-audit example.com

# Verbose output
nmap -p 9092 --script kafka-sasl-mechanism-audit -v example.com
```

**Sample Output:**
```
| kafka-sasl-mechanism-audit:
|   Status: AUDITED - kafka-sasl-mechanism-audit evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: Kafka / AMQP 0-9-1
```

---

#### 9. **kafka-unauth-broker-access** - Kafka Unauth Broker Access
**Description:** Connects to Apache Kafka on port 9092 without SASL/TLS authentication.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9092 --script kafka-unauth-broker-access example.com

# Verbose output
nmap -p 9092 --script kafka-unauth-broker-access -v example.com
```

**Sample Output:**
```
| kafka-unauth-broker-access:
|   Status: AUDITED - kafka-unauth-broker-access evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Kafka / AMQP 0-9-1
```

---

#### 10. **rabbitmq-amqp-anonymous-login** - Rabbitmq Amqp Anonymous Login
**Description:** Tests PLAIN/ANONYMOUS SASL mechanisms on AMQP port 5672.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9092 --script rabbitmq-amqp-anonymous-login example.com

# Verbose output
nmap -p 9092 --script rabbitmq-amqp-anonymous-login -v example.com
```

**Sample Output:**
```
| rabbitmq-amqp-anonymous-login:
|   Status: AUDITED - rabbitmq-amqp-anonymous-login evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Kafka / AMQP 0-9-1
```

---

#### 11. **rabbitmq-amqp-protocol-handshake** - Rabbitmq Amqp Protocol Handshake
**Description:** Sends AMQP 0-9-1 connection header and reads Connection.Start frame.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9092 --script rabbitmq-amqp-protocol-handshake example.com

# Verbose output
nmap -p 9092 --script rabbitmq-amqp-protocol-handshake -v example.com
```

**Sample Output:**
```
| rabbitmq-amqp-protocol-handshake:
|   Status: AUDITED - rabbitmq-amqp-protocol-handshake evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: Kafka / AMQP 0-9-1
```

---

#### 12. **rabbitmq-default-credentials** - Rabbitmq Default Credentials
**Description:** Tests default RabbitMQ credentials (guest/guest, admin/admin) on AMQP (5672) and HTTP (15672).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9092 --script rabbitmq-default-credentials example.com

# Verbose output
nmap -p 9092 --script rabbitmq-default-credentials -v example.com
```

**Sample Output:**
```
| rabbitmq-default-credentials:
|   Status: AUDITED - rabbitmq-default-credentials evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Kafka / AMQP 0-9-1
```

---

#### 13. **rabbitmq-definitions-export-leak** - Rabbitmq Definitions Export Leak
**Description:** Probes /api/definitions on Management API to download entire schema, users, and password hashes.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9092 --script rabbitmq-definitions-export-leak example.com

# Verbose output
nmap -p 9092 --script rabbitmq-definitions-export-leak -v example.com
```

**Sample Output:**
```
| rabbitmq-definitions-export-leak:
|   Status: AUDITED - rabbitmq-definitions-export-leak evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Kafka / AMQP 0-9-1
```

---

#### 14. **rabbitmq-management-unauth** - Rabbitmq Management Unauth
**Description:** Probes RabbitMQ Management HTTP API on port 15672 (/api/overview, /api/nodes) without auth.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9092 --script rabbitmq-management-unauth example.com

# Verbose output
nmap -p 9092 --script rabbitmq-management-unauth -v example.com
```

**Sample Output:**
```
| rabbitmq-management-unauth:
|   Status: AUDITED - rabbitmq-management-unauth evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: Kafka / AMQP 0-9-1
```

---

#### 15. **rabbitmq-queue-messages-dump** - Rabbitmq Queue Messages Dump
**Description:** Probes /api/queues/{vhost}/{name}/get to read queued application messages.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9092 --script rabbitmq-queue-messages-dump example.com

# Verbose output
nmap -p 9092 --script rabbitmq-queue-messages-dump -v example.com
```

**Sample Output:**
```
| rabbitmq-queue-messages-dump:
|   Status: AUDITED - rabbitmq-queue-messages-dump evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: Kafka / AMQP 0-9-1
```

---

#### 16. **rabbitmq-tls-auth-enforced** - Rabbitmq Tls Auth Enforced
**Description:** Tests whether AMQP over TLS (port 5671) enforces client certificate authentication.

**Risk Level:** 🟠 HIGH | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 9092 --script rabbitmq-tls-auth-enforced example.com

# Verbose output
nmap -p 9092 --script rabbitmq-tls-auth-enforced -v example.com
```

**Sample Output:**
```
| rabbitmq-tls-auth-enforced:
|   Status: AUDITED - rabbitmq-tls-auth-enforced evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: Kafka / AMQP 0-9-1
```

---

</details>

<details>
<summary><b>☁️ Cloud Metadata & SSRF Endpoint Audits — 16 scripts (click to expand)</b></summary>

## ☁️ Cloud Metadata & SSRF Endpoint Audits

### Category Overview
AWS IMDSv1 vs IMDSv2 token enforcement, IAM credential leaks, GCP, Azure, and Kubernetes pod metadata SSRF vectors.

**Port:** 80/443/8080 | **Protocol:** HTTP / Link-Local

---

### CLOUD-SSRF Scripts List

#### 1. **alibaba-cloud-metadata-leak** - Alibaba Cloud Metadata Leak
**Description:** Probes Alibaba Cloud ECS metadata http://100.100.100.200/latest/meta-data/ for RAM role credentials.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script alibaba-cloud-metadata-leak example.com

# Verbose output
nmap -p 80 --script alibaba-cloud-metadata-leak -v example.com
```

**Sample Output:**
```
| alibaba-cloud-metadata-leak:
|   Status: AUDITED - alibaba-cloud-metadata-leak evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: HTTP / Link-Local
```

---

#### 2. **aws-iam-credentials-leak** - Aws Iam Credentials Leak
**Description:** Probes /latest/meta-data/iam/security-credentials/ to extract IAM role name and STS credentials.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script aws-iam-credentials-leak example.com

# Verbose output
nmap -p 80 --script aws-iam-credentials-leak -v example.com
```

**Sample Output:**
```
| aws-iam-credentials-leak:
|   Status: AUDITED - aws-iam-credentials-leak evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: HTTP / Link-Local
```

---

#### 3. **aws-metadata-imdsv1-check** - Aws Metadata Imdsv1 Check
**Description:** Probes AWS EC2 Instance Metadata Service http://169.254.169.254/latest/meta-data/ without IMDSv2 token.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script aws-metadata-imdsv1-check example.com

# Verbose output
nmap -p 80 --script aws-metadata-imdsv1-check -v example.com
```

**Sample Output:**
```
| aws-metadata-imdsv1-check:
|   Status: AUDITED - aws-metadata-imdsv1-check evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: HTTP / Link-Local
```

---

#### 4. **aws-user-data-script-leak** - Aws User Data Script Leak
**Description:** Probes /latest/user-data for EC2 initialization bash scripts containing hardcoded secrets.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script aws-user-data-script-leak example.com

# Verbose output
nmap -p 80 --script aws-user-data-script-leak -v example.com
```

**Sample Output:**
```
| aws-user-data-script-leak:
|   Status: AUDITED - aws-user-data-script-leak evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: HTTP / Link-Local
```

---

#### 5. **azure-imds-identity-leak** - Azure Imds Identity Leak
**Description:** Probes Azure IMDS http://169.254.169.254/metadata/identity/oauth2/token with Metadata: true header.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script azure-imds-identity-leak example.com

# Verbose output
nmap -p 80 --script azure-imds-identity-leak -v example.com
```

**Sample Output:**
```
| azure-imds-identity-leak:
|   Status: AUDITED - azure-imds-identity-leak evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: HTTP / Link-Local
```

---

#### 6. **cloud-imds-v2-token-enforced** - Cloud Imds V2 Token Enforced
**Description:** Probes PUT /latest/api/token with X-aws-ec2-metadata-token-ttl-seconds to verify IMDSv2 enforcement.

**Risk Level:** 🟢 LOW | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script cloud-imds-v2-token-enforced example.com

# Verbose output
nmap -p 80 --script cloud-imds-v2-token-enforced -v example.com
```

**Sample Output:**
```
| cloud-imds-v2-token-enforced:
|   Status: AUDITED - cloud-imds-v2-token-enforced evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: HTTP / Link-Local
```

---

#### 7. **cloud-init-log-exposure** - Cloud Init Log Exposure
**Description:** Probes /var/log/cloud-init.log and /var/log/cloud-init-output.log via web root exposures.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script cloud-init-log-exposure example.com

# Verbose output
nmap -p 80 --script cloud-init-log-exposure -v example.com
```

**Sample Output:**
```
| cloud-init-log-exposure:
|   Status: AUDITED - cloud-init-log-exposure evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: HTTP / Link-Local
```

---

#### 8. **cloud-instance-identity-doc** - Cloud Instance Identity Doc
**Description:** Extracts dynamic instance identity document (Region, AvailabilityZone, AccountID, InstanceType).

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script cloud-instance-identity-doc example.com

# Verbose output
nmap -p 80 --script cloud-instance-identity-doc -v example.com
```

**Sample Output:**
```
| cloud-instance-identity-doc:
|   Status: AUDITED - cloud-instance-identity-doc evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: HTTP / Link-Local
```

---

#### 9. **cloud-metadata-ip-proxy-probe** - Cloud Metadata Ip Proxy Probe
**Description:** Tests whether HTTP forward/reverse proxy passes requests to link-local address 169.254.169.254.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script cloud-metadata-ip-proxy-probe example.com

# Verbose output
nmap -p 80 --script cloud-metadata-ip-proxy-probe -v example.com
```

**Sample Output:**
```
| cloud-metadata-ip-proxy-probe:
|   Status: AUDITED - cloud-metadata-ip-proxy-probe evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: HTTP / Link-Local
```

---

#### 10. **cloud-ssrf-dns-rebinding-check** - Cloud Ssrf Dns Rebinding Check
**Description:** Evaluates whether HTTP endpoint resolves domains pointing to link-local metadata IPs.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script cloud-ssrf-dns-rebinding-check example.com

# Verbose output
nmap -p 80 --script cloud-ssrf-dns-rebinding-check -v example.com
```

**Sample Output:**
```
| cloud-ssrf-dns-rebinding-check:
|   Status: AUDITED - cloud-ssrf-dns-rebinding-check evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: HTTP / Link-Local
```

---

#### 11. **digitalocean-metadata-leak** - Digitalocean Metadata Leak
**Description:** Probes DigitalOcean Droplet metadata http://169.254.169.254/metadata/v1/ for user-data and SSH keys.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script digitalocean-metadata-leak example.com

# Verbose output
nmap -p 80 --script digitalocean-metadata-leak -v example.com
```

**Sample Output:**
```
| digitalocean-metadata-leak:
|   Status: AUDITED - digitalocean-metadata-leak evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: HTTP / Link-Local
```

---

#### 12. **gcp-metadata-flavor-check** - Gcp Metadata Flavor Check
**Description:** Probes GCP metadata http://metadata.google.internal/computeMetadata/v1/ with/without Metadata-Flavor header.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script gcp-metadata-flavor-check example.com

# Verbose output
nmap -p 80 --script gcp-metadata-flavor-check -v example.com
```

**Sample Output:**
```
| gcp-metadata-flavor-check:
|   Status: AUDITED - gcp-metadata-flavor-check evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: HTTP / Link-Local
```

---

#### 13. **gcp-service-account-token** - Gcp Service Account Token
**Description:** Probes /computeMetadata/v1/instance/service-accounts/default/token for OAuth2 access tokens.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script gcp-service-account-token example.com

# Verbose output
nmap -p 80 --script gcp-service-account-token -v example.com
```

**Sample Output:**
```
| gcp-service-account-token:
|   Status: AUDITED - gcp-service-account-token evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: HTTP / Link-Local
```

---

#### 14. **kubernetes-pod-metadata-ssrf** - Kubernetes Pod Metadata Ssrf
**Description:** Probes internal K8s API server https://kubernetes.default.svc from pod-facing reverse proxies.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script kubernetes-pod-metadata-ssrf example.com

# Verbose output
nmap -p 80 --script kubernetes-pod-metadata-ssrf -v example.com
```

**Sample Output:**
```
| kubernetes-pod-metadata-ssrf:
|   Status: AUDITED - kubernetes-pod-metadata-ssrf evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: HTTP / Link-Local
```

---

#### 15. **openstack-metadata-probe** - Openstack Metadata Probe
**Description:** Probes OpenStack Nova metadata service http://169.254.169.254/openstack/latest/meta_data.json.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script openstack-metadata-probe example.com

# Verbose output
nmap -p 80 --script openstack-metadata-probe -v example.com
```

**Sample Output:**
```
| openstack-metadata-probe:
|   Status: AUDITED - openstack-metadata-probe evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: HTTP / Link-Local
```

---

#### 16. **oracle-cloud-metadata-leak** - Oracle Cloud Metadata Leak
**Description:** Probes OCI metadata http://169.254.169.254/opc/v2/instance/ for tenancy ID and compartment details.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script oracle-cloud-metadata-leak example.com

# Verbose output
nmap -p 80 --script oracle-cloud-metadata-leak -v example.com
```

**Sample Output:**
```
| oracle-cloud-metadata-leak:
|   Status: AUDITED - oracle-cloud-metadata-leak evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: HTTP / Link-Local
```

---

</details>

<details>
<summary><b>🔌 WebSocket Protocol & Hijacking Audits — 16 scripts (click to expand)</b></summary>

## 🔌 WebSocket Protocol & Hijacking Audits

### Category Overview
Unauthenticated connections, Cross-Site WebSocket Hijacking (CSWSH), unmasked frames, and STOMP/ActionCable probes.

**Port:** 80/443 | **Protocol:** WebSocket (RFC 6455)

---

### WEBSOCKET Scripts List

#### 1. **ws-actioncable-rails-probe** - Ws Actioncable Rails Probe
**Description:** Probes Ruby on Rails ActionCable WebSocket endpoint (/cable) and protocols.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script ws-actioncable-rails-probe example.com

# Verbose output
nmap -p 80 --script ws-actioncable-rails-probe -v example.com
```

**Sample Output:**
```
| ws-actioncable-rails-probe:
|   Status: AUDITED - ws-actioncable-rails-probe evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: WebSocket (RFC 6455)
```

---

#### 2. **ws-auth-ticket-probe** - Ws Auth Ticket Probe
**Description:** Tests whether WebSocket requires query string auth tickets (/ws?ticket=...) or cookies.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script ws-auth-ticket-probe example.com

# Verbose output
nmap -p 80 --script ws-auth-ticket-probe -v example.com
```

**Sample Output:**
```
| ws-auth-ticket-probe:
|   Status: AUDITED - ws-auth-ticket-probe evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: WebSocket (RFC 6455)
```

---

#### 3. **ws-binary-frame-deserialization** - Ws Binary Frame Deserialization
**Description:** Sends binary frames (Opcode 0x02) to probe for unsafe Java/Python/Node deserialization.

**Risk Level:** 🟠 HIGH | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script ws-binary-frame-deserialization example.com

# Verbose output
nmap -p 80 --script ws-binary-frame-deserialization -v example.com
```

**Sample Output:**
```
| ws-binary-frame-deserialization:
|   Status: AUDITED - ws-binary-frame-deserialization evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: WebSocket (RFC 6455)
```

---

#### 4. **ws-chat-broadcast-leak** - Ws Chat Broadcast Leak
**Description:** Connects to WebSocket chat/feed endpoint and listens for unauthenticated message broadcasts.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script ws-chat-broadcast-leak example.com

# Verbose output
nmap -p 80 --script ws-chat-broadcast-leak -v example.com
```

**Sample Output:**
```
| ws-chat-broadcast-leak:
|   Status: AUDITED - ws-chat-broadcast-leak evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: WebSocket (RFC 6455)
```

---

#### 5. **ws-cleartext-transport-warning** - Ws Cleartext Transport Warning
**Description:** Flags unencrypted ws:// transport on port 80/8080 exposing message frames to sniffing.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script ws-cleartext-transport-warning example.com

# Verbose output
nmap -p 80 --script ws-cleartext-transport-warning -v example.com
```

**Sample Output:**
```
| ws-cleartext-transport-warning:
|   Status: AUDITED - ws-cleartext-transport-warning evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: WebSocket (RFC 6455)
```

---

#### 6. **ws-cross-site-hijacking-cswsh** - Ws Cross Site Hijacking Cswsh
**Description:** Sends arbitrary Origin header (https://attacker.com) to test for Cross-Site WebSocket Hijacking (CSWSH).

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script ws-cross-site-hijacking-cswsh example.com

# Verbose output
nmap -p 80 --script ws-cross-site-hijacking-cswsh -v example.com
```

**Sample Output:**
```
| ws-cross-site-hijacking-cswsh:
|   Status: AUDITED - ws-cross-site-hijacking-cswsh evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: WebSocket (RFC 6455)
```

---

#### 7. **ws-graphql-transport-ws** - Ws Graphql Transport Ws
**Description:** Probes GraphQL graphql-transport-ws protocol handshake initialization.

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script ws-graphql-transport-ws example.com

# Verbose output
nmap -p 80 --script ws-graphql-transport-ws -v example.com
```

**Sample Output:**
```
| ws-graphql-transport-ws:
|   Status: AUDITED - ws-graphql-transport-ws evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: WebSocket (RFC 6455)
```

---

#### 8. **ws-masked-frame-enforcement** - Ws Masked Frame Enforcement
**Description:** Sends unmasked client frames (mask bit = 0) to verify RFC 6455 enforcement.

**Risk Level:** 🟠 HIGH | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script ws-masked-frame-enforcement example.com

# Verbose output
nmap -p 80 --script ws-masked-frame-enforcement -v example.com
```

**Sample Output:**
```
| ws-masked-frame-enforcement:
|   Status: AUDITED - ws-masked-frame-enforcement evaluation completed
|   Risk Level: 🟠 HIGH
|   Protocol: WebSocket (RFC 6455)
```

---

#### 9. **ws-max-frame-size-dos** - Ws Max Frame Size Dos
**Description:** Sends large declared payload lengths (64-bit length header) to test memory allocation limits.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script ws-max-frame-size-dos example.com

# Verbose output
nmap -p 80 --script ws-max-frame-size-dos -v example.com
```

**Sample Output:**
```
| ws-max-frame-size-dos:
|   Status: AUDITED - ws-max-frame-size-dos evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: WebSocket (RFC 6455)
```

---

#### 10. **ws-permessage-deflate-audit** - Ws Permessage Deflate Audit
**Description:** Tests Sec-WebSocket-Extensions: permessage-deflate and checks for CRIME-style compression leakage.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script ws-permessage-deflate-audit example.com

# Verbose output
nmap -p 80 --script ws-permessage-deflate-audit -v example.com
```

**Sample Output:**
```
| ws-permessage-deflate-audit:
|   Status: AUDITED - ws-permessage-deflate-audit evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: WebSocket (RFC 6455)
```

---

#### 11. **ws-ping-pong-dos-tolerance** - Ws Ping Pong Dos Tolerance
**Description:** Tests server handling of rapid WebSocket Ping (0x09) frames and Pong (0x0A) response timing.

**Risk Level:** 🟡 MEDIUM | **Category:** Defensive

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script ws-ping-pong-dos-tolerance example.com

# Verbose output
nmap -p 80 --script ws-ping-pong-dos-tolerance -v example.com
```

**Sample Output:**
```
| ws-ping-pong-dos-tolerance:
|   Status: AUDITED - ws-ping-pong-dos-tolerance evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: WebSocket (RFC 6455)
```

---

#### 12. **ws-socketio-handshake-probe** - Ws Socketio Handshake Probe
**Description:** Probes Socket.io engine.io transport (/socket.io/?EIO=4&transport=websocket).

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script ws-socketio-handshake-probe example.com

# Verbose output
nmap -p 80 --script ws-socketio-handshake-probe -v example.com
```

**Sample Output:**
```
| ws-socketio-handshake-probe:
|   Status: AUDITED - ws-socketio-handshake-probe evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: WebSocket (RFC 6455)
```

---

#### 13. **ws-spring-stomp-probe** - Ws Spring Stomp Probe
**Description:** Probes Spring STOMP over WebSocket (CONNECT\naccept-version:1.2\n\n\x00).

**Risk Level:** 🟡 MEDIUM | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script ws-spring-stomp-probe example.com

# Verbose output
nmap -p 80 --script ws-spring-stomp-probe -v example.com
```

**Sample Output:**
```
| ws-spring-stomp-probe:
|   Status: AUDITED - ws-spring-stomp-probe evaluation completed
|   Risk Level: 🟡 MEDIUM
|   Protocol: WebSocket (RFC 6455)
```

---

#### 14. **ws-subprotocol-enumeration** - Ws Subprotocol Enumeration
**Description:** Probes Sec-WebSocket-Protocol header with common subprotocols (graphql-ws, wamp, json, soap).

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script ws-subprotocol-enumeration example.com

# Verbose output
nmap -p 80 --script ws-subprotocol-enumeration -v example.com
```

**Sample Output:**
```
| ws-subprotocol-enumeration:
|   Status: AUDITED - ws-subprotocol-enumeration evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: WebSocket (RFC 6455)
```

---

#### 15. **ws-unauth-connection-check** - Ws Unauth Connection Check
**Description:** Tests whether WebSocket endpoint completes HTTP 101 Switching Protocols upgrade without credentials.

**Risk Level:** 🔴 CRITICAL | **Category:** Vulnerability

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script ws-unauth-connection-check example.com

# Verbose output
nmap -p 80 --script ws-unauth-connection-check -v example.com
```

**Sample Output:**
```
| ws-unauth-connection-check:
|   Status: AUDITED - ws-unauth-connection-check evaluation completed
|   Risk Level: 🔴 CRITICAL
|   Protocol: WebSocket (RFC 6455)
```

---

#### 16. **ws-version-handshake-negotiation** - Ws Version Handshake Negotiation
**Description:** Probes Sec-WebSocket-Version (v13, v8, v7) and downgrade error responses.

**Risk Level:** 🟢 LOW | **Category:** Discovery

**What it checks:**
- Protocol state validation and handshake negotiation
- Vulnerability confirmation and risk severity scoring
- Security misconfigurations and sensitive metadata disclosure

**How to Execute:**
```bash
# Basic scan
nmap -p 80 --script ws-version-handshake-negotiation example.com

# Verbose output
nmap -p 80 --script ws-version-handshake-negotiation -v example.com
```

**Sample Output:**
```
| ws-version-handshake-negotiation:
|   Status: AUDITED - ws-version-handshake-negotiation evaluation completed
|   Risk Level: 🟢 LOW
|   Protocol: WebSocket (RFC 6455)
```

---

</details>


## 🎯 Comprehensive Scanning Scenarios

### Scenario 1: Enterprise Perimeter Audit
```bash
nmap -p 21,22,23,25,53,80,88,111,123,139,161,389,443,445,502,1883,2049,2375,2379,3306,3389,5060,5432,5900,6379,6443,8080,8883,9092,9200,11211 \
  --script 'http-*,dns-*,smb-*,ssl-*,ftp-*,docker-*,graphql-*,mqtt-*,ssh-*,snmp-*,ldap-*,rdp-*,vnc-*,ntp-*,telnet-*,sip-*,smtp-*,kerberos-*,nfs-*,modbus-*,k8s-*,elasticsearch-*,memcached-*,kafka-*,cloud-*,ws-*' \
  -sV -v -oA enterprise-audit example.com
```

### Scenario 2: Cloud & Kubernetes Infrastructure
```bash
nmap -p 80,443,2375,2376,2379,5000,6443,8080,8443,10250,10255 \
  --script 'docker-*,k8s-*,cloud-*,graphql-*' \
  -v -oA cloud-k8s-audit example.com
```

### Scenario 3: Industrial & IoT Network Assessment
```bash
nmap -p 502,1883,2404,5060,5094,5500,8883,9600,20000,44818,47808 \
  --script 'modbus-*,bacnet-*,dnp3-*,ethernetip-*,s7comm-*,mqtt-*,sip-*' \
  -v -oA iot-ics-audit 192.168.1.0/24
```

---

## 📊 Script Reference Summary Table

| Protocol | Script Name | Port | Risk Level | Category | Check Type |
|----------|-------------|------|-----------|----------|-----------|
| **HTTP** | http-cache-audit | 80/443 | 🟡 MEDIUM | Vulnerability | Audit |
| **HTTP** | http-cookie-flags | 80/443 | 🟡 MEDIUM | Vulnerability | Flags |
| **HTTP** | http-cors-config | 80/443 | 🟡 MEDIUM | Vulnerability | Config |
| **HTTP** | http-crossdomain-xml-audit | 80/443 | 🟠 HIGH | Vulnerability | Audit |
| **HTTP** | http-dir-listing | 80/443 | 🟡 MEDIUM | Vulnerability | Listing |
| **HTTP** | http-env-file-exposure | 80/443 | 🔴 CRITICAL | Vulnerability | Exposure |
| **HTTP** | http-error-disclosure | 80/443 | 🟡 MEDIUM | Vulnerability | Disclosure |
| **HTTP** | http-git-config-exposure | 80/443 | 🔴 CRITICAL | Vulnerability | Exposure |
| **HTTP** | http-methods-enum | 80/443 | 🟡 MEDIUM | Vulnerability | Enum |
| **HTTP** | http-phpinfo-exposure | 80/443 | 🟠 HIGH | Vulnerability | Exposure |
| **HTTP** | http-robots-sitemap | 80/443 | 🟡 MEDIUM | Discovery | Sitemap |
| **HTTP** | http-security-headers | 80/443 | 🟡 MEDIUM | Vulnerability | Headers |
| **HTTP** | http-server-fingerprint | 80/443 | 🟡 MEDIUM | Discovery | Fingerprint |
| **HTTP** | http-swagger-ui-exposure | 80/443 | 🟡 MEDIUM | Vulnerability | Exposure |
| **HTTP** | http-trace-method | 80/443 | 🟡 MEDIUM | Vulnerability | Method |
| **HTTP** | http-waf-detect | 80/443 | 🟢 LOW | Discovery | Detect |
| **DNS** | dns-amplification-risk | 53 | 🟡 MEDIUM | Vulnerability | Risk |
| **DNS** | dns-axfr-source-spoof | 53 | 🔴 CRITICAL | Vulnerability | Spoof |
| **DNS** | dns-cache-snooping | 53 | 🟡 MEDIUM | Vulnerability | Snooping |
| **DNS** | dns-cname-takeover-audit | 53 | 🟠 HIGH | Vulnerability | Audit |
| **DNS** | dns-dnscrypt-support | 53 | 🟢 LOW | Discovery | Support |
| **DNS** | dns-dnssec-validation | 53 | 🟡 MEDIUM | Discovery | Validation |
| **DNS** | dns-doh-endpoint-probe | 53 | 🟢 LOW | Discovery | Probe |
| **DNS** | dns-ns-recursion-abuse | 53 | 🔴 CRITICAL | Vulnerability | Abuse |
| **DNS** | dns-recursion-check | 53 | 🟡 MEDIUM | Vulnerability | Check |
| **DNS** | dns-reverse-ptr-leak | 53 | 🟡 MEDIUM | Discovery | Leak |
| **DNS** | dns-soa-consistency-check | 53 | 🟡 MEDIUM | Discovery | Check |
| **DNS** | dns-srv-enum | 53 | 🟡 MEDIUM | Discovery | Enum |
| **DNS** | dns-subdomain-enum | 53 | 🟡 MEDIUM | Discovery | Enum |
| **DNS** | dns-txt-spf-dmarc-audit | 53 | 🟡 MEDIUM | Vulnerability | Audit |
| **DNS** | dns-wildcard-detector | 53 | 🟡 MEDIUM | Discovery | Detector |
| **DNS** | dns-zone-transfer-check | 53 | 🟡 MEDIUM | Vulnerability | Check |
| **SMB** | smb-anonymous-ipc-pipe | 139/445 | 🟠 HIGH | Vulnerability | Pipe |
| **SMB** | smb-buffer-limits | 139/445 | 🟡 MEDIUM | Discovery | Limits |
| **SMB** | smb-capabilities | 139/445 | 🟡 MEDIUM | Discovery | Capabilities |
| **SMB** | smb-dfs-referral-leak | 139/445 | 🟡 MEDIUM | Discovery | Leak |
| **SMB** | smb-eternalblue-precondition | 139/445 | 🔴 CRITICAL | Vulnerability | Precondition |
| **SMB** | smb-extended-security | 139/445 | 🟡 MEDIUM | Vulnerability | Security |
| **SMB** | smb-guest-access-check | 139/445 | 🟡 MEDIUM | Vulnerability | Check |
| **SMB** | smb-ntlm-version-downgrade | 139/445 | 🟠 HIGH | Vulnerability | Downgrade |
| **SMB** | smb-null-session-check | 139/445 | 🟡 MEDIUM | Vulnerability | Check |
| **SMB** | smb-protocol-dialects | 139/445 | 🟡 MEDIUM | Vulnerability | Dialects |
| **SMB** | smb-security-level | 139/445 | 🟡 MEDIUM | Discovery | Level |
| **SMB** | smb-share-accessibility | 139/445 | 🟡 MEDIUM | Vulnerability | Accessibility |
| **SMB** | smb-signing-config | 139/445 | 🟡 MEDIUM | Vulnerability | Config |
| **SMB** | smb-smbghost-precondition | 139/445 | 🔴 CRITICAL | Vulnerability | Precondition |
| **SMB** | smb-version-fingerprint | 139/445 | 🟢 LOW | Discovery | Fingerprint |
| **SMB** | smb-webdav-exposure | 139/445 | 🟡 MEDIUM | Discovery | Exposure |
| **SSL-TLS** | ssl-alpn-negotiation | 443 | 🟢 LOW | Discovery | Negotiation |
| **SSL-TLS** | ssl-cert-expiry | 443 | 🟡 MEDIUM | Vulnerability | Expiry |
| **SSL-TLS** | ssl-cert-hostname-mismatch | 443 | 🟡 MEDIUM | Vulnerability | Mismatch |
| **SSL-TLS** | ssl-cert-info | 443 | 🟡 MEDIUM | Discovery | Info |
| **SSL-TLS** | ssl-cert-weak-signature | 443 | 🟡 MEDIUM | Vulnerability | Signature |
| **SSL-TLS** | ssl-compression-check | 443 | 🟡 MEDIUM | Vulnerability | Check |
| **SSL-TLS** | ssl-dh-params-weak | 443 | 🟠 HIGH | Vulnerability | Weak |
| **SSL-TLS** | ssl-fallback-scsv | 443 | 🟡 MEDIUM | Defensive | Scsv |
| **SSL-TLS** | ssl-heartbleed-precondition | 443 | 🔴 CRITICAL | Vulnerability | Precondition |
| **SSL-TLS** | ssl-hsts-preload-status | 443 | 🟡 MEDIUM | Defensive | Status |
| **SSL-TLS** | ssl-ocsp-stapling | 443 | 🟡 MEDIUM | Discovery | Stapling |
| **SSL-TLS** | ssl-poodle-sslv3 | 443 | 🔴 CRITICAL | Vulnerability | Sslv3 |
| **SSL-TLS** | ssl-protocol-versions | 443 | 🟡 MEDIUM | Vulnerability | Versions |
| **SSL-TLS** | ssl-secure-renegotiation | 443 | 🟡 MEDIUM | Vulnerability | Renegotiation |
| **SSL-TLS** | ssl-sweet32-check | 443 | 🟠 HIGH | Vulnerability | Check |
| **SSL-TLS** | ssl-weak-ciphers | 443 | 🟡 MEDIUM | Vulnerability | Ciphers |
| **DATABASE** | cassandra-unauth-check | 1433/3306/5432/6379/27017/9042 | 🔴 CRITICAL | Vulnerability | Check |
| **DATABASE** | clickhouse-unauth-check | 1433/3306/5432/6379/27017/9042 | 🟠 HIGH | Vulnerability | Check |
| **DATABASE** | couchdb-unauth-check | 1433/3306/5432/6379/27017/9042 | 🔴 CRITICAL | Vulnerability | Check |
| **DATABASE** | etcd-unauth-keyspace | 1433/3306/5432/6379/27017/9042 | 🔴 CRITICAL | Vulnerability | Keyspace |
| **DATABASE** | influxdb-unauth-check | 1433/3306/5432/6379/27017/9042 | 🔴 CRITICAL | Vulnerability | Check |
| **DATABASE** | memcached-stats-dump | 1433/3306/5432/6379/27017/9042 | 🟡 MEDIUM | Discovery | Dump |
| **DATABASE** | mongodb-unauthenticated-check | 1433/3306/5432/6379/27017/9042 | 🟡 MEDIUM | Vulnerability | Check |
| **DATABASE** | mssql-prelogin-check | 1433/3306/5432/6379/27017/9042 | 🟡 MEDIUM | Discovery | Check |
| **DATABASE** | mysql-banner-grab | 1433/3306/5432/6379/27017/9042 | 🟡 MEDIUM | Discovery | Grab |
| **DATABASE** | mysql-empty-password-check | 1433/3306/5432/6379/27017/9042 | 🟡 MEDIUM | Vulnerability | Check |
| **DATABASE** | mysql-ssl-support-check | 1433/3306/5432/6379/27017/9042 | 🟡 MEDIUM | Discovery | Check |
| **DATABASE** | neo4j-unauth-browser | 1433/3306/5432/6379/27017/9042 | 🟠 HIGH | Vulnerability | Browser |
| **DATABASE** | postgresql-ssl-support-check | 1433/3306/5432/6379/27017/9042 | 🟡 MEDIUM | Discovery | Check |
| **DATABASE** | postgresql-trust-auth-check | 1433/3306/5432/6379/27017/9042 | 🟡 MEDIUM | Vulnerability | Check |
| **DATABASE** | redis-admin-command-exposure | 1433/3306/5432/6379/27017/9042 | 🟡 MEDIUM | Vulnerability | Exposure |
| **DATABASE** | redis-unauthenticated-access | 1433/3306/5432/6379/27017/9042 | 🟡 MEDIUM | Vulnerability | Access |
| **FTP** | ftp-anonymous-login | 21 | 🟡 MEDIUM | Vulnerability | Login |
| **FTP** | ftp-banner-grab | 21 | 🟡 MEDIUM | Discovery | Grab |
| **FTP** | ftp-bounce-check | 21 | 🟡 MEDIUM | Vulnerability | Check |
| **FTP** | ftp-brute-rate-limit | 21 | 🟡 MEDIUM | Defensive | Limit |
| **FTP** | ftp-chroot-escape-precondition | 21 | 🟠 HIGH | Vulnerability | Precondition |
| **FTP** | ftp-cleartext-enforcement | 21 | 🟡 MEDIUM | Vulnerability | Enforcement |
| **FTP** | ftp-command-enum | 21 | 🟡 MEDIUM | Vulnerability | Enum |
| **FTP** | ftp-directory-listing | 21 | 🟡 MEDIUM | Discovery | Listing |
| **FTP** | ftp-fxp-cross-server | 21 | 🟠 HIGH | Vulnerability | Server |
| **FTP** | ftp-passive-mode-check | 21 | 🟡 MEDIUM | Discovery | Check |
| **FTP** | ftp-proftpd-mod-copy | 21 | 🔴 CRITICAL | Vulnerability | Copy |
| **FTP** | ftp-syst-fingerprint | 21 | 🟢 LOW | Discovery | Fingerprint |
| **FTP** | ftp-tls-cipher-audit | 21 | 🟡 MEDIUM | Defensive | Audit |
| **FTP** | ftp-tls-support | 21 | 🟡 MEDIUM | Discovery | Support |
| **FTP** | ftp-vsftpd-backdoor-fingerprint | 21 | 🔴 CRITICAL | Vulnerability | Fingerprint |
| **FTP** | ftp-writable-dirs | 21 | 🟡 MEDIUM | Vulnerability | Dirs |
| **DOCKER** | docker-build-cache-leak | 2375/2376/5000/2377/4243 | 🟡 MEDIUM | Vulnerability | Leak |
| **DOCKER** | docker-cgroup-resource-limits | 2375/2376/5000/2377/4243 | 🟡 MEDIUM | Vulnerability | Limits |
| **DOCKER** | docker-container-inspect-secrets | 2375/2376/5000/2377/4243 | 🔴 CRITICAL | Vulnerability | Secrets |
| **DOCKER** | docker-daemon-security-opts | 2375/2376/5000/2377/4243 | 🟡 MEDIUM | Vulnerability | Opts |
| **DOCKER** | docker-debug-pprof-exposure | 2375/2376/5000/2377/4243 | 🟠 HIGH | Vulnerability | Exposure |
| **DOCKER** | docker-event-stream-exposure | 2375/2376/5000/2377/4243 | 🟡 MEDIUM | Vulnerability | Exposure |
| **DOCKER** | docker-network-host-mode | 2375/2376/5000/2377/4243 | 🟡 MEDIUM | Vulnerability | Mode |
| **DOCKER** | docker-privileged-containers | 2375/2376/5000/2377/4243 | 🔴 CRITICAL | Vulnerability | Containers |
| **DOCKER** | docker-registry-delete-allowed | 2375/2376/5000/2377/4243 | 🟠 HIGH | Vulnerability | Allowed |
| **DOCKER** | docker-registry-manifest-leak | 2375/2376/5000/2377/4243 | 🟡 MEDIUM | Vulnerability | Leak |
| **DOCKER** | docker-registry-unauth-catalog | 2375/2376/5000/2377/4243 | 🟡 MEDIUM | Vulnerability | Catalog |
| **DOCKER** | docker-socket-proxy-misconfig | 2375/2376/5000/2377/4243 | 🔴 CRITICAL | Vulnerability | Misconfig |
| **DOCKER** | docker-swarm-node-leak | 2375/2376/5000/2377/4243 | 🟡 MEDIUM | Vulnerability | Leak |
| **DOCKER** | docker-unauthenticated-api | 2375/2376/5000/2377/4243 | 🔴 CRITICAL | Vulnerability | Api |
| **DOCKER** | docker-version-cve-fingerprint | 2375/2376/5000/2377/4243 | 🟢 LOW | Vulnerability | Fingerprint |
| **DOCKER** | docker-volume-host-mounts | 2375/2376/5000/2377/4243 | 🔴 CRITICAL | Vulnerability | Mounts |
| **GRAPHQL** | graphql-alias-overloading | 80/443/3000/4000/8080 | 🔴 CRITICAL | Vulnerability | Overloading |
| **GRAPHQL** | graphql-batch-query-abuse | 80/443/3000/4000/8080 | 🔴 CRITICAL | Vulnerability | Abuse |
| **GRAPHQL** | graphql-circular-query-depth | 80/443/3000/4000/8080 | 🟠 HIGH | Vulnerability | Depth |
| **GRAPHQL** | graphql-content-type-bypass | 80/443/3000/4000/8080 | 🟡 MEDIUM | Vulnerability | Bypass |
| **GRAPHQL** | graphql-cost-analysis-bypass | 80/443/3000/4000/8080 | 🟡 MEDIUM | Vulnerability | Bypass |
| **GRAPHQL** | graphql-debug-trace-exposure | 80/443/3000/4000/8080 | 🟡 MEDIUM | Vulnerability | Exposure |
| **GRAPHQL** | graphql-endpoint-discovery | 80/443/3000/4000/8080 | 🟢 LOW | Discovery | Discovery |
| **GRAPHQL** | graphql-error-info-disclosure | 80/443/3000/4000/8080 | 🟡 MEDIUM | Vulnerability | Disclosure |
| **GRAPHQL** | graphql-field-suggestions | 80/443/3000/4000/8080 | 🟡 MEDIUM | Vulnerability | Suggestions |
| **GRAPHQL** | graphql-get-mutation-bypass | 80/443/3000/4000/8080 | 🟠 HIGH | Vulnerability | Bypass |
| **GRAPHQL** | graphql-ide-exposure | 80/443/3000/4000/8080 | 🟡 MEDIUM | Vulnerability | Exposure |
| **GRAPHQL** | graphql-introspection-enabled | 80/443/3000/4000/8080 | 🔴 CRITICAL | Vulnerability | Enabled |
| **GRAPHQL** | graphql-persisted-queries-audit | 80/443/3000/4000/8080 | 🟡 MEDIUM | Vulnerability | Audit |
| **GRAPHQL** | graphql-schema-directive-leak | 80/443/3000/4000/8080 | 🟡 MEDIUM | Vulnerability | Leak |
| **GRAPHQL** | graphql-subscription-websocket | 80/443/3000/4000/8080 | 🟡 MEDIUM | Vulnerability | Websocket |
| **GRAPHQL** | graphql-unauth-mutation-detection | 80/443/3000/4000/8080 | 🔴 CRITICAL | Vulnerability | Detection |
| **MQTT** | mqtt-anonymous-publish-test | 1883/8883/1884 | 🔴 CRITICAL | Vulnerability | Test |
| **MQTT** | mqtt-broker-fingerprint | 1883/8883/1884 | 🟢 LOW | Discovery | Fingerprint |
| **MQTT** | mqtt-cleartext-credential-risk | 1883/8883/1884 | 🟡 MEDIUM | Vulnerability | Risk |
| **MQTT** | mqtt-clientid-spoof-hijack | 1883/8883/1884 | 🟠 HIGH | Vulnerability | Hijack |
| **MQTT** | mqtt-default-credentials | 1883/8883/1884 | 🔴 CRITICAL | Vulnerability | Credentials |
| **MQTT** | mqtt-keepalive-dos-tolerance | 1883/8883/1884 | 🟡 MEDIUM | Vulnerability | Tolerance |
| **MQTT** | mqtt-packet-size-limit | 1883/8883/1884 | 🟡 MEDIUM | Vulnerability | Limit |
| **MQTT** | mqtt-protocol-version-support | 1883/8883/1884 | 🟢 LOW | Discovery | Support |
| **MQTT** | mqtt-qos2-handshake-audit | 1883/8883/1884 | 🟡 MEDIUM | Discovery | Audit |
| **MQTT** | mqtt-retained-message-harvest | 1883/8883/1884 | 🟡 MEDIUM | Vulnerability | Harvest |
| **MQTT** | mqtt-sys-topic-leak | 1883/8883/1884 | 🟡 MEDIUM | Discovery | Leak |
| **MQTT** | mqtt-tls-client-cert-check | 1883/8883/1884 | 🟠 HIGH | Vulnerability | Check |
| **MQTT** | mqtt-topic-permission-bypass | 1883/8883/1884 | 🟡 MEDIUM | Vulnerability | Bypass |
| **MQTT** | mqtt-unauthenticated-broker | 1883/8883/1884 | 🔴 CRITICAL | Vulnerability | Broker |
| **MQTT** | mqtt-wildcard-subscribe-all | 1883/8883/1884 | 🔴 CRITICAL | Vulnerability | All |
| **MQTT** | mqtt-will-message-injection | 1883/8883/1884 | 🟡 MEDIUM | Vulnerability | Injection |
| **SSH** | ssh-agent-forwarding-probe | 22 | 🟡 MEDIUM | Discovery | Probe |
| **SSH** | ssh-auth-methods-enum | 22 | 🟡 MEDIUM | Discovery | Enum |
| **SSH** | ssh-compression-support | 22 | 🟢 LOW | Discovery | Support |
| **SSH** | ssh-hostkey-fingerprint | 22 | 🟢 LOW | Discovery | Fingerprint |
| **SSH** | ssh-hostkey-size-audit | 22 | 🟡 MEDIUM | Defensive | Audit |
| **SSH** | ssh-keyboard-interactive-info | 22 | 🟢 LOW | Discovery | Info |
| **SSH** | ssh-libssh-bypass-check | 22 | 🔴 CRITICAL | Vulnerability | Check |
| **SSH** | ssh-max-auth-tries | 22 | 🟡 MEDIUM | Defensive | Tries |
| **SSH** | ssh-password-auth-allowed | 22 | 🟡 MEDIUM | Defensive | Allowed |
| **SSH** | ssh-regresshion-cve-check | 22 | 🔴 CRITICAL | Vulnerability | Check |
| **SSH** | ssh-root-login-allowed | 22 | 🟠 HIGH | Vulnerability | Allowed |
| **SSH** | ssh-terrapin-vulnerability | 22 | 🔴 CRITICAL | Vulnerability | Vulnerability |
| **SSH** | ssh-unauth-banner-grab | 22 | 🟢 LOW | Discovery | Grab |
| **SSH** | ssh-weak-ciphers | 22 | 🔴 CRITICAL | Vulnerability | Ciphers |
| **SSH** | ssh-weak-kex-algorithms | 22 | 🟠 HIGH | Vulnerability | Algorithms |
| **SSH** | ssh-weak-macs | 22 | 🟠 HIGH | Vulnerability | Macs |
| **SNMP** | snmp-amplification-factor | 161 | 🟢 LOW | Discovery | Factor |
| **SNMP** | snmp-arp-table-leak | 161 | 🟡 MEDIUM | Discovery | Leak |
| **SNMP** | snmp-cisco-config-copy | 161 | 🔴 CRITICAL | Vulnerability | Copy |
| **SNMP** | snmp-default-community | 161 | 🔴 CRITICAL | Vulnerability | Community |
| **SNMP** | snmp-device-type-fingerprint | 161 | 🟢 LOW | Discovery | Fingerprint |
| **SNMP** | snmp-installed-software | 161 | 🟡 MEDIUM | Discovery | Software |
| **SNMP** | snmp-interfaces-dump | 161 | 🟡 MEDIUM | Discovery | Dump |
| **SNMP** | snmp-ip-routing-table | 161 | 🟠 HIGH | Discovery | Table |
| **SNMP** | snmp-running-processes | 161 | 🟠 HIGH | Discovery | Processes |
| **SNMP** | snmp-snmpv3-auth-probe | 161 | 🟡 MEDIUM | Discovery | Probe |
| **SNMP** | snmp-snmpv3-weak-auth | 161 | 🟠 HIGH | Vulnerability | Auth |
| **SNMP** | snmp-storage-metrics | 161 | 🟢 LOW | Discovery | Metrics |
| **SNMP** | snmp-system-info-leak | 161 | 🟡 MEDIUM | Discovery | Leak |
| **SNMP** | snmp-tcp-udp-connections | 161 | 🟡 MEDIUM | Discovery | Connections |
| **SNMP** | snmp-user-accounts-leak | 161 | 🔴 CRITICAL | Vulnerability | Leak |
| **SNMP** | snmp-write-access-check | 161 | 🔴 CRITICAL | Vulnerability | Check |
| **LDAP** | ldap-ad-domain-info | 389/636 | 🟢 LOW | Discovery | Info |
| **LDAP** | ldap-anonymous-bind | 389/636 | 🔴 CRITICAL | Vulnerability | Bind |
| **LDAP** | ldap-asreproast-candidates | 389/636 | 🔴 CRITICAL | Vulnerability | Candidates |
| **LDAP** | ldap-certificate-templates | 389/636 | 🟠 HIGH | Discovery | Templates |
| **LDAP** | ldap-cleartext-auth-risk | 389/636 | 🟡 MEDIUM | Defensive | Risk |
| **LDAP** | ldap-gpo-permissions-audit | 389/636 | 🟠 HIGH | Discovery | Audit |
| **LDAP** | ldap-laps-password-exposure | 389/636 | 🔴 CRITICAL | Vulnerability | Exposure |
| **LDAP** | ldap-null-bind-enum | 389/636 | 🔴 CRITICAL | Vulnerability | Enum |
| **LDAP** | ldap-paged-search-limit | 389/636 | 🟢 LOW | Discovery | Limit |
| **LDAP** | ldap-rootdse-leak | 389/636 | 🟡 MEDIUM | Discovery | Leak |
| **LDAP** | ldap-signing-enforced | 389/636 | 🟠 HIGH | Defensive | Enforced |
| **LDAP** | ldap-spn-service-accounts | 389/636 | 🟠 HIGH | Discovery | Accounts |
| **LDAP** | ldap-starttls-support | 389/636 | 🟡 MEDIUM | Defensive | Support |
| **LDAP** | ldap-supported-controls | 389/636 | 🟢 LOW | Discovery | Controls |
| **LDAP** | ldap-unconstrained-delegation | 389/636 | 🔴 CRITICAL | Vulnerability | Delegation |
| **LDAP** | ldap-user-account-attributes | 389/636 | 🔴 CRITICAL | Vulnerability | Attributes |
| **RDP** | rdp-bluekeep-precondition | 3389 | 🔴 CRITICAL | Vulnerability | Precondition |
| **RDP** | rdp-cert-name-mismatch | 3389 | 🟡 MEDIUM | Defensive | Mismatch |
| **RDP** | rdp-cookie-routing-token | 3389 | 🟢 LOW | Discovery | Token |
| **RDP** | rdp-credssp-version-audit | 3389 | 🟠 HIGH | Defensive | Audit |
| **RDP** | rdp-cve-2012-0002-check | 3389 | 🔴 CRITICAL | Vulnerability | Check |
| **RDP** | rdp-hybrid-auth-support | 3389 | 🟡 MEDIUM | Discovery | Support |
| **RDP** | rdp-nla-disabled | 3389 | 🔴 CRITICAL | Vulnerability | Disabled |
| **RDP** | rdp-ntlm-info-disclosure | 3389 | 🟡 MEDIUM | Discovery | Disclosure |
| **RDP** | rdp-restricted-admin-mode | 3389 | 🟢 LOW | Defensive | Mode |
| **RDP** | rdp-screen-resolution-dos | 3389 | 🟡 MEDIUM | Defensive | Dos |
| **RDP** | rdp-session-negotiation | 3389 | 🟢 LOW | Discovery | Negotiation |
| **RDP** | rdp-session-shadowing-risk | 3389 | 🟡 MEDIUM | Defensive | Risk |
| **RDP** | rdp-tls-security-layer | 3389 | 🟡 MEDIUM | Defensive | Layer |
| **RDP** | rdp-udp-transport-check | 3389 | 🟢 LOW | Discovery | Check |
| **RDP** | rdp-virtual-channels-enum | 3389 | 🟢 LOW | Discovery | Enum |
| **RDP** | rdp-weak-rc4-ciphers | 3389 | 🟠 HIGH | Vulnerability | Ciphers |
| **VNC** | vnc-auth-bypass-cve-check | 5900/5800/6080 | 🔴 CRITICAL | Vulnerability | Check |
| **VNC** | vnc-cleartext-des-warning | 5900/5800/6080 | 🟡 MEDIUM | Defensive | Warning |
| **VNC** | vnc-clipboard-leak-risk | 5900/5800/6080 | 🟠 HIGH | Vulnerability | Risk |
| **VNC** | vnc-color-depth-dos-check | 5900/5800/6080 | 🟢 LOW | Defensive | Check |
| **VNC** | vnc-default-passwords | 5900/5800/6080 | 🔴 CRITICAL | Vulnerability | Passwords |
| **VNC** | vnc-desktop-geometry-leak | 5900/5800/6080 | 🟢 LOW | Discovery | Leak |
| **VNC** | vnc-http-web-interface | 5900/5800/6080 | 🟠 HIGH | Vulnerability | Interface |
| **VNC** | vnc-max-auth-failures | 5900/5800/6080 | 🟡 MEDIUM | Defensive | Failures |
| **VNC** | vnc-no-auth-check | 5900/5800/6080 | 🔴 CRITICAL | Vulnerability | Check |
| **VNC** | vnc-novnc-websocket-probe | 5900/5800/6080 | 🟠 HIGH | Vulnerability | Probe |
| **VNC** | vnc-repeater-proxy-detect | 5900/5800/6080 | 🟡 MEDIUM | Discovery | Detect |
| **VNC** | vnc-reverse-connection-probe | 5900/5800/6080 | 🟡 MEDIUM | Discovery | Probe |
| **VNC** | vnc-rfb-version-fingerprint | 5900/5800/6080 | 🟢 LOW | Discovery | Fingerprint |
| **VNC** | vnc-security-types-enum | 5900/5800/6080 | 🟢 LOW | Discovery | Enum |
| **VNC** | vnc-tightvnc-backdoor-audit | 5900/5800/6080 | 🔴 CRITICAL | Vulnerability | Audit |
| **VNC** | vnc-vencrypt-tls-support | 5900/5800/6080 | 🟡 MEDIUM | Defensive | Support |
| **NTP** | ntp-autokey-support-audit | 123 | 🟠 HIGH | Vulnerability | Audit |
| **NTP** | ntp-broadcast-mode-detect | 123 | 🟡 MEDIUM | Discovery | Detect |
| **NTP** | ntp-control-query-rate-limit | 123 | 🟡 MEDIUM | Defensive | Limit |
| **NTP** | ntp-leap-second-vulnerability | 123 | 🟡 MEDIUM | Vulnerability | Vulnerability |
| **NTP** | ntp-mac-authentication-test | 123 | 🟡 MEDIUM | Defensive | Test |
| **NTP** | ntp-mode6-readlist-leak | 123 | 🟡 MEDIUM | Discovery | Leak |
| **NTP** | ntp-mode6-readvar-leak | 123 | 🟡 MEDIUM | Discovery | Leak |
| **NTP** | ntp-monlist-amplification | 123 | 🔴 CRITICAL | Vulnerability | Amplification |
| **NTP** | ntp-nts-support-check | 123 | 🟢 LOW | Discovery | Check |
| **NTP** | ntp-peer-association-spoof | 123 | 🔴 CRITICAL | Vulnerability | Spoof |
| **NTP** | ntp-stratum-zero-anomaly | 123 | 🟡 MEDIUM | Discovery | Anomaly |
| **NTP** | ntp-time-offset-skew | 123 | 🟢 LOW | Discovery | Skew |
| **NTP** | ntp-trap-logging-leak | 123 | 🟠 HIGH | Discovery | Leak |
| **NTP** | ntp-unauth-config-dump | 123 | 🔴 CRITICAL | Vulnerability | Dump |
| **NTP** | ntp-unauth-reslist-query | 123 | 🟠 HIGH | Discovery | Query |
| **NTP** | ntp-version-fingerprint | 123 | 🟢 LOW | Discovery | Fingerprint |
| **TELNET** | telnet-auth-option-bypass | 23 | 🔴 CRITICAL | Vulnerability | Bypass |
| **TELNET** | telnet-banner-grab | 23 | 🟢 LOW | Discovery | Grab |
| **TELNET** | telnet-busybox-fingerprint | 23 | 🟡 MEDIUM | Discovery | Fingerprint |
| **TELNET** | telnet-cisco-login-prompt | 23 | 🟡 MEDIUM | Discovery | Prompt |
| **TELNET** | telnet-cleartext-warning | 23 | 🔴 CRITICAL | Defensive | Warning |
| **TELNET** | telnet-default-credentials | 23 | 🔴 CRITICAL | Vulnerability | Credentials |
| **TELNET** | telnet-encrypt-option-audit | 23 | 🟡 MEDIUM | Defensive | Audit |
| **TELNET** | telnet-env-var-disclosure | 23 | 🟠 HIGH | Vulnerability | Disclosure |
| **TELNET** | telnet-escape-character-enum | 23 | 🟢 LOW | Discovery | Enum |
| **TELNET** | telnet-iac-buffer-overflow | 23 | 🔴 CRITICAL | Vulnerability | Overflow |
| **TELNET** | telnet-max-connections-dos | 23 | 🟡 MEDIUM | Defensive | Dos |
| **TELNET** | telnet-option-negotiation | 23 | 🟢 LOW | Discovery | Negotiation |
| **TELNET** | telnet-root-login-allowed | 23 | 🟠 HIGH | Vulnerability | Allowed |
| **TELNET** | telnet-subnegotiation-leak | 23 | 🟢 LOW | Discovery | Leak |
| **TELNET** | telnet-terminal-type-dos | 23 | 🟡 MEDIUM | Defensive | Dos |
| **TELNET** | telnet-windows-auth-ntlm | 23 | 🟡 MEDIUM | Discovery | Ntlm |
| **SIP** | sip-bye-teardown-spoof | 5060/5061 | 🟠 HIGH | Vulnerability | Spoof |
| **SIP** | sip-call-eavesdropping-rtp | 5060/5061 | 🟠 HIGH | Vulnerability | Rtp |
| **SIP** | sip-callerid-spoof-check | 5060/5061 | 🟠 HIGH | Vulnerability | Check |
| **SIP** | sip-cleartext-udp-warning | 5060/5061 | 🟡 MEDIUM | Defensive | Warning |
| **SIP** | sip-default-credentials | 5060/5061 | 🔴 CRITICAL | Vulnerability | Credentials |
| **SIP** | sip-extension-enumeration | 5060/5061 | 🔴 CRITICAL | Vulnerability | Enumeration |
| **SIP** | sip-message-spam-relay | 5060/5061 | 🟠 HIGH | Vulnerability | Relay |
| **SIP** | sip-method-flood-dos | 5060/5061 | 🟡 MEDIUM | Defensive | Dos |
| **SIP** | sip-nat-traversal-leak | 5060/5061 | 🟡 MEDIUM | Discovery | Leak |
| **SIP** | sip-presence-subscription | 5060/5061 | 🟡 MEDIUM | Discovery | Subscription |
| **SIP** | sip-sdp-codec-audit | 5060/5061 | 🟢 LOW | Discovery | Audit |
| **SIP** | sip-server-fingerprint | 5060/5061 | 🟢 LOW | Discovery | Fingerprint |
| **SIP** | sip-tls-cert-validation | 5060/5061 | 🟡 MEDIUM | Defensive | Validation |
| **SIP** | sip-unauth-options-enum | 5060/5061 | 🟢 LOW | Discovery | Enum |
| **SIP** | sip-unauthenticated-invite | 5060/5061 | 🔴 CRITICAL | Vulnerability | Invite |
| **SIP** | sip-unauthenticated-register | 5060/5061 | 🔴 CRITICAL | Vulnerability | Register |
| **SMTP** | smtp-banner-grab | 25/587/465 | 🟢 LOW | Discovery | Grab |
| **SMTP** | smtp-cleartext-auth-allowed | 25/587/465 | 🔴 CRITICAL | Vulnerability | Allowed |
| **SMTP** | smtp-commands-enum | 25/587/465 | 🟢 LOW | Discovery | Enum |
| **SMTP** | smtp-default-credentials | 25/587/465 | 🔴 CRITICAL | Vulnerability | Credentials |
| **SMTP** | smtp-help-info-leak | 25/587/465 | 🟢 LOW | Discovery | Leak |
| **SMTP** | smtp-max-message-size | 25/587/465 | 🟡 MEDIUM | Defensive | Size |
| **SMTP** | smtp-null-sender-bounce | 25/587/465 | 🟡 MEDIUM | Defensive | Bounce |
| **SMTP** | smtp-open-relay-check | 25/587/465 | 🔴 CRITICAL | Vulnerability | Check |
| **SMTP** | smtp-pipelining-dos-tolerance | 25/587/465 | 🟡 MEDIUM | Defensive | Tolerance |
| **SMTP** | smtp-rcpt-to-user-enum | 25/587/465 | 🟠 HIGH | Discovery | Enum |
| **SMTP** | smtp-smarthost-auth-bypass | 25/587/465 | 🟠 HIGH | Vulnerability | Bypass |
| **SMTP** | smtp-spf-dkim-dmarc-check | 25/587/465 | 🟡 MEDIUM | Defensive | Check |
| **SMTP** | smtp-starttls-support | 25/587/465 | 🟡 MEDIUM | Defensive | Support |
| **SMTP** | smtp-strict-tls-enforcement | 25/587/465 | 🟡 MEDIUM | Defensive | Enforcement |
| **SMTP** | smtp-tls-ciphers-audit | 25/587/465 | 🟡 MEDIUM | Defensive | Audit |
| **SMTP** | smtp-vrfy-user-enumeration | 25/587/465 | 🟠 HIGH | Discovery | Enumeration |
| **KERBEROS** | kerberos-anonymous-pkinit | 88/464 | 🟠 HIGH | Vulnerability | Pkinit |
| **KERBEROS** | kerberos-asrep-roasting | 88/464 | 🔴 CRITICAL | Vulnerability | Roasting |
| **KERBEROS** | kerberos-constrained-deleg | 88/464 | 🟠 HIGH | Discovery | Deleg |
| **KERBEROS** | kerberos-cve-2020-1472-prep | 88/464 | 🔴 CRITICAL | Vulnerability | Prep |
| **KERBEROS** | kerberos-etype-negotiation | 88/464 | 🟢 LOW | Discovery | Negotiation |
| **KERBEROS** | kerberos-fast-negotiation | 88/464 | 🟡 MEDIUM | Defensive | Negotiation |
| **KERBEROS** | kerberos-kdc-proxy-probe | 88/464 | 🟡 MEDIUM | Discovery | Probe |
| **KERBEROS** | kerberos-kpasswd-service | 88/464 | 🟡 MEDIUM | Discovery | Service |
| **KERBEROS** | kerberos-pac-validation | 88/464 | 🟠 HIGH | Defensive | Validation |
| **KERBEROS** | kerberos-preauth-required | 88/464 | 🟡 MEDIUM | Defensive | Required |
| **KERBEROS** | kerberos-realm-discovery | 88/464 | 🟢 LOW | Discovery | Discovery |
| **KERBEROS** | kerberos-spn-probe | 88/464 | 🟠 HIGH | Discovery | Probe |
| **KERBEROS** | kerberos-tcp-udp-support | 88/464 | 🟢 LOW | Discovery | Support |
| **KERBEROS** | kerberos-time-skew-audit | 88/464 | 🟡 MEDIUM | Defensive | Audit |
| **KERBEROS** | kerberos-user-enum | 88/464 | 🟠 HIGH | Discovery | Enum |
| **KERBEROS** | kerberos-weak-encryption | 88/464 | 🔴 CRITICAL | Vulnerability | Encryption |
| **NFS-RPC** | nfs-file-handle-leak | 111/2049 | 🟡 MEDIUM | Discovery | Leak |
| **NFS-RPC** | nfs-insecure-port-allowed | 111/2049 | 🟠 HIGH | Vulnerability | Allowed |
| **NFS-RPC** | nfs-krb5-security-flavor | 111/2049 | 🟡 MEDIUM | Defensive | Flavor |
| **NFS-RPC** | nfs-lock-manager-check | 111/2049 | 🟢 LOW | Discovery | Check |
| **NFS-RPC** | nfs-mountd-auth-bypass | 111/2049 | 🔴 CRITICAL | Vulnerability | Bypass |
| **NFS-RPC** | nfs-no-root-squash-check | 111/2049 | 🔴 CRITICAL | Vulnerability | Check |
| **NFS-RPC** | nfs-readlink-traversal | 111/2049 | 🟠 HIGH | Vulnerability | Traversal |
| **NFS-RPC** | nfs-rpc-programs-enum | 111/2049 | 🟢 LOW | Discovery | Enum |
| **NFS-RPC** | nfs-rpc-rquotad-check | 111/2049 | 🟡 MEDIUM | Discovery | Check |
| **NFS-RPC** | nfs-rpc-rusers-enum | 111/2049 | 🟡 MEDIUM | Discovery | Enum |
| **NFS-RPC** | nfs-rpc-spray-dos | 111/2049 | 🟡 MEDIUM | Defensive | Dos |
| **NFS-RPC** | nfs-rpc-statd-check | 111/2049 | 🟠 HIGH | Vulnerability | Check |
| **NFS-RPC** | nfs-rpc-ypbind-nis-leak | 111/2049 | 🔴 CRITICAL | Vulnerability | Leak |
| **NFS-RPC** | nfs-showmount-leak | 111/2049 | 🟡 MEDIUM | Discovery | Leak |
| **NFS-RPC** | nfs-version-support | 111/2049 | 🟢 LOW | Discovery | Support |
| **NFS-RPC** | nfs-world-readable-exports | 111/2049 | 🔴 CRITICAL | Vulnerability | Exports |
| **ICS-SCADA** | bacnet-device-whois-leak | 502/47808/20000/44818/102 | 🔴 CRITICAL | Vulnerability | Leak |
| **ICS-SCADA** | bacnet-read-property-leak | 502/47808/20000/44818/102 | 🟡 MEDIUM | Discovery | Leak |
| **ICS-SCADA** | dnp3-unauth-link-status | 502/47808/20000/44818/102 | 🟠 HIGH | Discovery | Status |
| **ICS-SCADA** | ethernetip-identity-dump | 502/47808/20000/44818/102 | 🟡 MEDIUM | Discovery | Dump |
| **ICS-SCADA** | fins-omron-plc-dump | 502/47808/20000/44818/102 | 🟠 HIGH | Discovery | Dump |
| **ICS-SCADA** | fox-niagara-unauth-check | 502/47808/20000/44818/102 | 🔴 CRITICAL | Vulnerability | Check |
| **ICS-SCADA** | hart-ip-device-probe | 502/47808/20000/44818/102 | 🟢 LOW | Discovery | Probe |
| **ICS-SCADA** | iec104-apci-test | 502/47808/20000/44818/102 | 🟡 MEDIUM | Discovery | Test |
| **ICS-SCADA** | melsec-mitsubishi-probe | 502/47808/20000/44818/102 | 🟡 MEDIUM | Discovery | Probe |
| **ICS-SCADA** | modbus-device-id-leak | 502/47808/20000/44818/102 | 🟡 MEDIUM | Discovery | Leak |
| **ICS-SCADA** | modbus-unauth-read-coils | 502/47808/20000/44818/102 | 🔴 CRITICAL | Vulnerability | Coils |
| **ICS-SCADA** | modbus-unauth-read-holding | 502/47808/20000/44818/102 | 🔴 CRITICAL | Vulnerability | Holding |
| **ICS-SCADA** | modbus-unauth-write-risk | 502/47808/20000/44818/102 | 🔴 CRITICAL | Vulnerability | Risk |
| **ICS-SCADA** | modbus-unit-id-scan | 502/47808/20000/44818/102 | 🟢 LOW | Discovery | Scan |
| **ICS-SCADA** | profinet-dcp-discovery | 502/47808/20000/44818/102 | 🟢 LOW | Discovery | Discovery |
| **ICS-SCADA** | s7comm-plc-fingerprint | 502/47808/20000/44818/102 | 🟠 HIGH | Discovery | Fingerprint |
| **KUBERNETES** | k8s-admission-webhook-audit | 6443/10250/10255/8443/2379 | 🟡 MEDIUM | Defensive | Audit |
| **KUBERNETES** | k8s-anonymous-auth-enabled | 6443/10250/10255/8443/2379 | 🟠 HIGH | Vulnerability | Enabled |
| **KUBERNETES** | k8s-api-unauthenticated-access | 6443/10250/10255/8443/2379 | 🔴 CRITICAL | Vulnerability | Access |
| **KUBERNETES** | k8s-cni-portmap-exposure | 6443/10250/10255/8443/2379 | 🟡 MEDIUM | Defensive | Exposure |
| **KUBERNETES** | k8s-coredns-metrics-exposure | 6443/10250/10255/8443/2379 | 🟢 LOW | Discovery | Exposure |
| **KUBERNETES** | k8s-dashboard-unauth-access | 6443/10250/10255/8443/2379 | 🔴 CRITICAL | Vulnerability | Access |
| **KUBERNETES** | k8s-etcd-unauth-keyspace | 6443/10250/10255/8443/2379 | 🔴 CRITICAL | Vulnerability | Keyspace |
| **KUBERNETES** | k8s-kube-proxy-debug-leak | 6443/10250/10255/8443/2379 | 🟡 MEDIUM | Discovery | Leak |
| **KUBERNETES** | k8s-kubelet-readonly-pods | 6443/10250/10255/8443/2379 | 🔴 CRITICAL | Vulnerability | Pods |
| **KUBERNETES** | k8s-kubelet-unauth-exec | 6443/10250/10255/8443/2379 | 🔴 CRITICAL | Vulnerability | Exec |
| **KUBERNETES** | k8s-metrics-token-leak | 6443/10250/10255/8443/2379 | 🟡 MEDIUM | Discovery | Leak |
| **KUBERNETES** | k8s-node-proxy-misconfig | 6443/10250/10255/8443/2379 | 🟠 HIGH | Vulnerability | Misconfig |
| **KUBERNETES** | k8s-openapi-spec-leak | 6443/10250/10255/8443/2379 | 🟡 MEDIUM | Discovery | Leak |
| **KUBERNETES** | k8s-pod-security-standards | 6443/10250/10255/8443/2379 | 🟡 MEDIUM | Defensive | Standards |
| **KUBERNETES** | k8s-serviceaccount-token-probe | 6443/10250/10255/8443/2379 | 🟠 HIGH | Discovery | Probe |
| **KUBERNETES** | k8s-version-fingerprint | 6443/10250/10255/8443/2379 | 🟢 LOW | Discovery | Fingerprint |
| **ELASTICSEARCH** | elasticsearch-aliases-enum | 9200/5601 | 🟡 MEDIUM | Discovery | Enum |
| **ELASTICSEARCH** | elasticsearch-cluster-health-leak | 9200/5601 | 🟢 LOW | Discovery | Leak |
| **ELASTICSEARCH** | elasticsearch-cve-2015-1427-check | 9200/5601 | 🟢 LOW | Discovery | Check |
| **ELASTICSEARCH** | elasticsearch-delete-index-allowed | 9200/5601 | 🟠 HIGH | Vulnerability | Allowed |
| **ELASTICSEARCH** | elasticsearch-field-caps-audit | 9200/5601 | 🟡 MEDIUM | Discovery | Audit |
| **ELASTICSEARCH** | elasticsearch-indices-data-dump | 9200/5601 | 🔴 CRITICAL | Vulnerability | Dump |
| **ELASTICSEARCH** | elasticsearch-kibana-unauth-access | 9200/5601 | 🔴 CRITICAL | Vulnerability | Access |
| **ELASTICSEARCH** | elasticsearch-license-status | 9200/5601 | 🟢 LOW | Discovery | Status |
| **ELASTICSEARCH** | elasticsearch-nodes-settings-leak | 9200/5601 | 🔴 CRITICAL | Vulnerability | Leak |
| **ELASTICSEARCH** | elasticsearch-painless-script-rce | 9200/5601 | 🟠 HIGH | Vulnerability | Rce |
| **ELASTICSEARCH** | elasticsearch-search-query-leak | 9200/5601 | 🔴 CRITICAL | Vulnerability | Leak |
| **ELASTICSEARCH** | elasticsearch-security-disabled | 9200/5601 | 🔴 CRITICAL | Vulnerability | Disabled |
| **ELASTICSEARCH** | elasticsearch-snapshot-repo-leak | 9200/5601 | 🟠 HIGH | Discovery | Leak |
| **ELASTICSEARCH** | elasticsearch-tasks-monitoring | 9200/5601 | 🟡 MEDIUM | Discovery | Monitoring |
| **ELASTICSEARCH** | elasticsearch-templates-leak | 9200/5601 | 🟡 MEDIUM | Discovery | Leak |
| **ELASTICSEARCH** | elasticsearch-unauth-cluster-info | 9200/5601 | 🔴 CRITICAL | Vulnerability | Info |
| **MEMCACHED** | memcached-ascii-udp-disable-check | 11211 | 🟡 MEDIUM | Defensive | Check |
| **MEMCACHED** | memcached-binary-protocol-probe | 11211 | 🟢 LOW | Discovery | Probe |
| **MEMCACHED** | memcached-connection-limit-dos | 11211 | 🟡 MEDIUM | Defensive | Dos |
| **MEMCACHED** | memcached-flush-all-risk | 11211 | 🟠 HIGH | Vulnerability | Risk |
| **MEMCACHED** | memcached-key-data-retrieval | 11211 | 🔴 CRITICAL | Vulnerability | Retrieval |
| **MEMCACHED** | memcached-sasl-auth-enforced | 11211 | 🟠 HIGH | Defensive | Enforced |
| **MEMCACHED** | memcached-settings-leak | 11211 | 🟡 MEDIUM | Discovery | Leak |
| **MEMCACHED** | memcached-sizes-memory-dump | 11211 | 🟡 MEDIUM | Discovery | Dump |
| **MEMCACHED** | memcached-slab-automove-audit | 11211 | 🟢 LOW | Defensive | Audit |
| **MEMCACHED** | memcached-slabs-item-dump | 11211 | 🔴 CRITICAL | Vulnerability | Dump |
| **MEMCACHED** | memcached-touch-command-audit | 11211 | 🟡 MEDIUM | Defensive | Audit |
| **MEMCACHED** | memcached-udp-amplification-ddos | 11211 | 🔴 CRITICAL | Vulnerability | Ddos |
| **MEMCACHED** | memcached-unauthenticated-access | 11211 | 🔴 CRITICAL | Vulnerability | Access |
| **MEMCACHED** | memcached-verbosity-command-leak | 11211 | 🟡 MEDIUM | Discovery | Leak |
| **MEMCACHED** | memcached-version-fingerprint | 11211 | 🟢 LOW | Discovery | Fingerprint |
| **MEMCACHED** | memcached-watch-stream-exposure | 11211 | 🟠 HIGH | Vulnerability | Exposure |
| **KAFKA-AMQP** | kafka-anonymous-consumer-group | 9092/5672/15672 | 🔴 CRITICAL | Vulnerability | Group |
| **KAFKA-AMQP** | kafka-broker-fingerprint | 9092/5672/15672 | 🟢 LOW | Discovery | Fingerprint |
| **KAFKA-AMQP** | kafka-controller-epoch-leak | 9092/5672/15672 | 🟢 LOW | Discovery | Leak |
| **KAFKA-AMQP** | kafka-create-topic-allowed | 9092/5672/15672 | 🟠 HIGH | Vulnerability | Allowed |
| **KAFKA-AMQP** | kafka-delete-topic-allowed | 9092/5672/15672 | 🟠 HIGH | Vulnerability | Allowed |
| **KAFKA-AMQP** | kafka-metadata-topic-leak | 9092/5672/15672 | 🔴 CRITICAL | Vulnerability | Leak |
| **KAFKA-AMQP** | kafka-plain-auth-over-cleartext | 9092/5672/15672 | 🟡 MEDIUM | Defensive | Cleartext |
| **KAFKA-AMQP** | kafka-sasl-mechanism-audit | 9092/5672/15672 | 🟡 MEDIUM | Discovery | Audit |
| **KAFKA-AMQP** | kafka-unauth-broker-access | 9092/5672/15672 | 🔴 CRITICAL | Vulnerability | Access |
| **KAFKA-AMQP** | rabbitmq-amqp-anonymous-login | 9092/5672/15672 | 🔴 CRITICAL | Vulnerability | Login |
| **KAFKA-AMQP** | rabbitmq-amqp-protocol-handshake | 9092/5672/15672 | 🟢 LOW | Discovery | Handshake |
| **KAFKA-AMQP** | rabbitmq-default-credentials | 9092/5672/15672 | 🔴 CRITICAL | Vulnerability | Credentials |
| **KAFKA-AMQP** | rabbitmq-definitions-export-leak | 9092/5672/15672 | 🔴 CRITICAL | Vulnerability | Leak |
| **KAFKA-AMQP** | rabbitmq-management-unauth | 9092/5672/15672 | 🔴 CRITICAL | Vulnerability | Unauth |
| **KAFKA-AMQP** | rabbitmq-queue-messages-dump | 9092/5672/15672 | 🟠 HIGH | Vulnerability | Dump |
| **KAFKA-AMQP** | rabbitmq-tls-auth-enforced | 9092/5672/15672 | 🟠 HIGH | Defensive | Enforced |
| **CLOUD-SSRF** | alibaba-cloud-metadata-leak | 80/443/8080 | 🟠 HIGH | Vulnerability | Leak |
| **CLOUD-SSRF** | aws-iam-credentials-leak | 80/443/8080 | 🔴 CRITICAL | Vulnerability | Leak |
| **CLOUD-SSRF** | aws-metadata-imdsv1-check | 80/443/8080 | 🔴 CRITICAL | Vulnerability | Check |
| **CLOUD-SSRF** | aws-user-data-script-leak | 80/443/8080 | 🔴 CRITICAL | Vulnerability | Leak |
| **CLOUD-SSRF** | azure-imds-identity-leak | 80/443/8080 | 🔴 CRITICAL | Vulnerability | Leak |
| **CLOUD-SSRF** | cloud-imds-v2-token-enforced | 80/443/8080 | 🟢 LOW | Defensive | Enforced |
| **CLOUD-SSRF** | cloud-init-log-exposure | 80/443/8080 | 🟡 MEDIUM | Discovery | Exposure |
| **CLOUD-SSRF** | cloud-instance-identity-doc | 80/443/8080 | 🟢 LOW | Discovery | Doc |
| **CLOUD-SSRF** | cloud-metadata-ip-proxy-probe | 80/443/8080 | 🟡 MEDIUM | Defensive | Probe |
| **CLOUD-SSRF** | cloud-ssrf-dns-rebinding-check | 80/443/8080 | 🟡 MEDIUM | Defensive | Check |
| **CLOUD-SSRF** | digitalocean-metadata-leak | 80/443/8080 | 🟠 HIGH | Vulnerability | Leak |
| **CLOUD-SSRF** | gcp-metadata-flavor-check | 80/443/8080 | 🔴 CRITICAL | Vulnerability | Check |
| **CLOUD-SSRF** | gcp-service-account-token | 80/443/8080 | 🔴 CRITICAL | Vulnerability | Token |
| **CLOUD-SSRF** | kubernetes-pod-metadata-ssrf | 80/443/8080 | 🔴 CRITICAL | Vulnerability | Ssrf |
| **CLOUD-SSRF** | openstack-metadata-probe | 80/443/8080 | 🟡 MEDIUM | Discovery | Probe |
| **CLOUD-SSRF** | oracle-cloud-metadata-leak | 80/443/8080 | 🟠 HIGH | Vulnerability | Leak |
| **WEBSOCKET** | ws-actioncable-rails-probe | 80/443 | 🟢 LOW | Discovery | Probe |
| **WEBSOCKET** | ws-auth-ticket-probe | 80/443 | 🟡 MEDIUM | Discovery | Probe |
| **WEBSOCKET** | ws-binary-frame-deserialization | 80/443 | 🟠 HIGH | Vulnerability | Deserialization |
| **WEBSOCKET** | ws-chat-broadcast-leak | 80/443 | 🔴 CRITICAL | Vulnerability | Leak |
| **WEBSOCKET** | ws-cleartext-transport-warning | 80/443 | 🟡 MEDIUM | Defensive | Warning |
| **WEBSOCKET** | ws-cross-site-hijacking-cswsh | 80/443 | 🔴 CRITICAL | Vulnerability | Cswsh |
| **WEBSOCKET** | ws-graphql-transport-ws | 80/443 | 🟡 MEDIUM | Discovery | Ws |
| **WEBSOCKET** | ws-masked-frame-enforcement | 80/443 | 🟠 HIGH | Defensive | Enforcement |
| **WEBSOCKET** | ws-max-frame-size-dos | 80/443 | 🟡 MEDIUM | Defensive | Dos |
| **WEBSOCKET** | ws-permessage-deflate-audit | 80/443 | 🟡 MEDIUM | Defensive | Audit |
| **WEBSOCKET** | ws-ping-pong-dos-tolerance | 80/443 | 🟡 MEDIUM | Defensive | Tolerance |
| **WEBSOCKET** | ws-socketio-handshake-probe | 80/443 | 🟢 LOW | Discovery | Probe |
| **WEBSOCKET** | ws-spring-stomp-probe | 80/443 | 🟡 MEDIUM | Discovery | Probe |
| **WEBSOCKET** | ws-subprotocol-enumeration | 80/443 | 🟢 LOW | Discovery | Enumeration |
| **WEBSOCKET** | ws-unauth-connection-check | 80/443 | 🔴 CRITICAL | Vulnerability | Check |
| **WEBSOCKET** | ws-version-handshake-negotiation | 80/443 | 🟢 LOW | Discovery | Negotiation |

---

## 🔍 Risk Level Guide

### 🔴 CRITICAL - Immediate Action Required
- Exploitable without credentials or leading to remote daemon takeover, unauthenticated administrative access, or direct container breakout.
- Examples: Docker unauthenticated API, GraphQL batch query abuse, MQTT open broker, Memcrashed UDP amplification, RDP NLA disabled, NFS no_root_squash.

### 🟠 HIGH - High Priority
- Significant security impact, weak cryptography, lack of mutual TLS enforcement, or authentication downgrade vectors.
- Examples: Weak SSH ciphers, CredSSP Oracle Remediation, MQTT Client ID spoofing, unmasked WebSocket frames.

### 🟡 MEDIUM - Medium Priority
- Configuration weaknesses, information disclosure, missing security headers, or missing cgroup limits.
- Examples: GraphQL debug tracing leak, Docker cgroup resource constraints, SNMP routing table disclosure, NTP readvar leak.

### 🟢 LOW - Informational & Discovery
- Service identification, protocol version matrix probing, feature detection, and defensive fingerprinting.
- Examples: GraphQL endpoint discovery, MQTT protocol version matrix, SSH hostkey fingerprinting, WAF detection.

---

## 🧪 Testing

```bash
docker compose up -d
nmap -p 8080 --script ./HTTP/http-security-headers.nse localhost
docker compose down
```

See **[TESTING.md](TESTING.md)** for detailed guides.

---

## ⚠️ Legal Disclaimer

**IMPORTANT:** These scripts are exclusively for authorized defensive audits, compliance verification, and educational research. Unauthorized network scanning against targets without explicit permission is strictly prohibited.

---

## 📄 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.
All scripts are designed to run in the Nmap Scripting Engine.

---

<p align="center">Made with 🛡️ for the global defensive and offensive security engineering community.</p>
