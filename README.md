# 🛰️ Nmap NSE Script Collection

<p align="center">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT">
  <img src="https://img.shields.io/badge/Language-Lua-blue.svg" alt="Language: Lua">
  <img src="https://img.shields.io/badge/Nmap-7.40%2B-informational.svg" alt="Nmap 7.40+">
  <img src="https://img.shields.io/badge/Scripts-432-orange.svg" alt="432 scripts">
  <img src="https://img.shields.io/badge/Categories-27-brightgreen.svg" alt="27 categories">
  <img src="https://github.com/NexzaDev/Nmap-NSE-Script-Collection/actions/workflows/lint.yml/badge.svg" alt="Lint status">
  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs welcome">
</p>

A collection of **432 Nmap NSE scripts** across **27 protocol categories** for defensive security auditing, misconfiguration detection and infrastructure posture assessment. Each script talks to the target service directly, parses the real responses and reports evidence-based findings with a risk level, covering web, DNS, databases, containers, Kubernetes, cloud metadata, message brokers, identity services, remote access and industrial protocols.

The scripts are built for authorized audits: probes are bounded by request budgets and timeouts, payloads are inert, secrets are masked in output, and no exploitation code is included. A small number of scripts perform a clearly documented minimal write test against a sentinel object (for example a reverted SNMP `sysName` set or a uniquely named Memcached key); these are described in the relevant folder README.

## Table of Contents

- [Categories](#categories)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Scanning Scenarios](#scanning-scenarios)
- [Risk Levels](#risk-levels)
- [Repository Layout](#repository-layout)
- [Testing](#testing)
- [Contributing](#contributing)
- [Security Policy](#security-policy)
- [Legal Disclaimer](#legal-disclaimer)
- [License](#license)

## Categories

Every category folder contains 16 scripts and its own `README.md` with a per-script description, risk level, NSE categories, usage, `--script-args` and sample output.

| Folder | Covers | Ports |
|---|---|---|
| 🌐 [HTTP](HTTP/README.md) | Security headers, cookie flags, CORS, caching, exposed files (`.env`, `.git`, `phpinfo`, Swagger), WAF and server fingerprinting | 80, 443, any HTTP service |
| 🔍 [DNS](DNS/README.md) | Zone transfers, recursion and amplification, DNSSEC, cache snooping, CNAME takeover, SPF/DMARC, DoH and DNSCrypt | 53 |
| 🔐 [SMB](SMB/README.md) | Dialects, signing, null and guest sessions, NTLM downgrade, DFS leakage, EternalBlue and SMBGhost preconditions | 139, 445 |
| 🛡️ [SSL-TLS](SSL-TLS/README.md) | Protocol versions, weak ciphers, certificates, Heartbleed, POODLE, Sweet32, Logjam-class DH, OCSP, HSTS | 443, any TLS service |
| 🗄️ [DATABASE](DATABASE/README.md) | Unauthenticated access and TLS posture for Cassandra, ClickHouse, CouchDB, etcd, InfluxDB, MongoDB, MSSQL, MySQL, Neo4j, PostgreSQL, Redis | various |
| 📁 [FTP](FTP/README.md) | Anonymous access, bounce/FXP, mod_copy, vsftpd backdoor, FTPS, writable directories, rate limiting | 21 |
| 🐳 [DOCKER](DOCKER/README.md) | Engine API exposure, privileged containers, host mounts, secret leakage, Registry v2, CVE fingerprinting | 2375, 2376, 5000 |
| 🔮 [GRAPHQL](GRAPHQL/README.md) | Introspection, unauthenticated mutations, alias and batch abuse, depth limits, IDE exposure, subscriptions | any HTTP port |
| 📡 [MQTT](MQTT/README.md) | Unauthenticated brokers, default credentials, wildcard subscribe, `$SYS` leaks, Client-ID hijack, mTLS | 1883, 8883 |
| 🔑 [SSH](SSH/README.md) | regreSSHion, libssh bypass, Terrapin, weak algorithms, root login, host keys, MaxAuthTries | 22 |
| 📊 [SNMP](SNMP/README.md) | Default and writable communities, SNMPv3 USM, interface/route/ARP/process dumps, amplification | 161/udp |
| 🌳 [LDAP](LDAP/README.md) | Anonymous bind, rootDSE, AD enumeration, AS-REP roasting and Kerberoasting targets, AD CS, LAPS, signing | 389, 636 |
| 🖥️ [RDP](RDP/README.md) | NLA, BlueKeep and MS12-020 preconditions, CredSSP, NTLM disclosure, certificates, weak RC4 | 3389 |
| 👁️ [VNC](VNC/README.md) | No-auth servers, default passwords, DES challenge, clipboard, noVNC, repeaters, VeNCrypt | 5900, 5800, 6080 |
| ⏱️ [NTP](NTP/README.md) | Monlist amplification, mode 6/7 leaks, MAC enforcement, Autokey, NTS, clock skew | 123/udp |
| 📟 [TELNET](TELNET/README.md) | Cleartext transport, default credentials, option negotiation, BusyBox and Cisco fingerprinting | 23 |
| 📞 [SIP](SIP/README.md) | Extension enumeration, default credentials, open registration and relay, SDP/SRTP, SIPS certificates | 5060, 5061 |
| ✉️ [SMTP](SMTP/README.md) | Open relay, VRFY/EXPN/RCPT enumeration, STARTTLS, cipher audit, default credentials | 25, 587 |
| 🎟️ [KERBEROS](KERBEROS/README.md) | AS-REP roasting, SPN probing, user enumeration, weak etypes, FAST, PKINIT, Zerologon precondition | 88, 464 |
| 📦 [NFS-RPC](NFS-RPC/README.md) | Export disclosure, no_root_squash, file-handle entropy, symlink traversal, legacy RPC services | 2049, 111 |
| 🏭 [ICS-SCADA](ICS-SCADA/README.md) | Modbus, BACnet, DNP3, EtherNet/IP, FINS, Niagara Fox, HART-IP, IEC 104, MELSEC, PROFINET, S7comm | 502, 102, 2404, 44818, 47808/udp, … |
| ☸️ [KUBERNETES](KUBERNETES/README.md) | Anonymous API access, kubelet, etcd, service-account tokens, pod security, admission webhooks | 6443, 10250, 10255, 2379 |
| 🔎 [ELASTICSEARCH](ELASTICSEARCH/README.md) | Unauthenticated cluster and Kibana access, index and snapshot leaks, CVE mapping, security-disabled posture | 9200, 5601 |
| ⚡ [MEMCACHED](MEMCACHED/README.md) | Unauthenticated access, key and slab disclosure, UDP amplification, SASL enforcement, flush_all exposure | 11211 |
| 📨 [KAFKA-AMQP](KAFKA-AMQP/README.md) | Kafka broker and RabbitMQ AMQP/management exposure, SASL posture, default credentials, definitions export | 9092, 5672, 5671, 15672 |
| ☁️ [CLOUD-SSRF](CLOUD-SSRF/README.md) | AWS/Azure/GCP/Alibaba/DigitalOcean/OCI/OpenStack metadata, IMDSv2 enforcement, SSRF and DNS-rebinding primitives | 80, 443, 8080 |
| 🔌 [WEBSOCKET](WEBSOCKET/README.md) | Cross-site hijacking, unauthenticated upgrades, broadcast leaks, masking, frame limits, framework probes | 80, 443 |

## Requirements

- [Nmap](https://nmap.org/download.html) 7.40 or newer (the Lua runtime is bundled with Nmap)
- Written authorization to scan every target (see [Legal Disclaimer](#legal-disclaimer))

## Installation

Clone the repository:

```bash
git clone https://github.com/NexzaDev/Nmap-NSE-Script-Collection.git
cd Nmap-NSE-Script-Collection
```

**Option A: run scripts straight from the checkout** (no install step):

```bash
nmap -p 443 --script ./SSL-TLS/ssl-protocol-versions.nse example.com
```

**Option B: install every script into your Nmap scripts directory:**

```bash
mkdir -p ~/.nmap/scripts
find . -name '*.nse' -exec cp {} ~/.nmap/scripts/ \;
nmap --script-updatedb
```

Scripts can then be called by name, or by wildcard (`--script 'ssh-*'`). Script names are unique across the whole collection.

## Usage

```bash
# Show the description, arguments and categories of a script
nmap --script-help ssh-weak-ciphers

# Single script
nmap -p 22 --script ssh-weak-ciphers example.com

# Everything in one protocol family
nmap -p 6379,27017,9042 --script 'redis-*,mongodb-*,cassandra-*' example.com

# Script arguments, verbose output, saved results
nmap -p 53 --script dns-zone-transfer-check --script-args maxns=16,maxrequests=48 -v -oA dns-audit ns1.example.com
```

Script-specific arguments are listed in each script's header and in its folder README.

## Scanning Scenarios

**Enterprise perimeter audit**

```bash
nmap -sV -p 21,22,23,25,53,80,88,111,123,139,161,389,443,445,1883,2049,3306,3389,5060,5432,5900,6379,8080,8883,9200,11211 \
  --script 'http-*,dns-*,smb-*,ssl-*,ftp-*,ssh-*,snmp-*,ldap-*,rdp-*,vnc-*,ntp-*,telnet-*,sip-*,smtp-*,kerberos-*,nfs-*,mqtt-*,redis-*,mysql-*,postgresql-*,elasticsearch-*,memcached-*' \
  -v -oA perimeter-audit example.com
```

**Cloud and Kubernetes infrastructure**

```bash
nmap -p 80,443,2375,2376,2379,5000,6443,8080,8443,10250,10255 \
  --script 'docker-*,k8s-*,kubernetes-*,aws-*,azure-*,gcp-*,cloud-*,graphql-*' \
  -v -oA cloud-k8s-audit example.com
```

**Industrial and IoT networks**

```bash
nmap -p 102,502,1883,2404,5060,8883,20000,44818,47808 \
  --script 'modbus-*,bacnet-*,dnp3-*,ethernetip-*,s7comm-*,iec104-*,mqtt-*,sip-*' \
  -v -oA ics-iot-audit 192.168.1.0/24
```

## Risk Levels

| Level | Meaning | Examples |
|---|---|---|
| 🔴 CRITICAL | Exploitable without credentials, unauthenticated administrative access, or direct takeover and breakout paths | Docker unauthenticated API, open MQTT broker, RDP without NLA, NFS `no_root_squash` |
| 🟠 HIGH | Significant impact, weak cryptography, authentication downgrade vectors | Weak SSH ciphers, MQTT Client-ID spoofing, unmasked WebSocket frames |
| 🟡 MEDIUM | Configuration weaknesses, information disclosure, missing hardening | GraphQL debug tracing, missing cgroup limits, SNMP routing table disclosure |
| 🟢 LOW | Service identification, version and feature discovery | GraphQL endpoint discovery, SSH host key fingerprinting, WAF detection |

## Repository Layout

```
Nmap-NSE-Script-Collection/
├── HTTP/ DNS/ SMB/ SSL-TLS/ DATABASE/ FTP/ DOCKER/ GRAPHQL/ MQTT/ SSH/
├── SNMP/ LDAP/ RDP/ VNC/ NTP/ TELNET/ SIP/ SMTP/ KERBEROS/ NFS-RPC/
├── ICS-SCADA/ KUBERNETES/ ELASTICSEARCH/ MEMCACHED/ KAFKA-AMQP/
├── CLOUD-SSRF/ WEBSOCKET/     # one folder per protocol: 16 .nse scripts + README.md
├── tools/                     # lint and smoke-test utilities
├── test-fixtures/             # content served by the local test targets
├── docker-compose.yml         # local, intentionally insecure test targets
├── .github/                   # CI workflow and issue templates
├── CHANGELOG.md  CONTRIBUTING.md  SECURITY.md  TESTING.md  LICENSE
└── README.md
```

## Testing

A Docker Compose file provides local, deliberately insecure targets (HTTP, FTP, Redis) bound to `localhost`:

```bash
docker compose up -d
nmap -p 8080 --script ./HTTP/http-security-headers.nse localhost
docker compose down
```

The `tools/` folder also contains a lint gate (`tools/lint_nse.py`) and a mock-based smoke harness (`tools/smoke_nse.py`). See [TESTING.md](TESTING.md) for the full guide.

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) for the ground rules, script structure and pull request checklist.

## Security Policy

To report unsafe script behavior or a vulnerability, follow [SECURITY.md](SECURITY.md).

## Legal Disclaimer

These scripts are intended exclusively for authorized security audits, compliance verification and educational research. Scanning systems without explicit permission from their owner may be illegal. You are responsible for how you use this software, and the authors accept no liability for misuse or damage.

## License

Released under the [MIT License](LICENSE).
