# 📊 SNMP Security Audits

**16 Nmap NSE scripts** for auditing SNMP v1/v2c/v3 agents:

**Covers:**

- Default and writable community detection
- CISCO-CONFIG-COPY-MIB remote configuration exposure
- SNMPv3 USM engine/level/user probing and weak MD5/SHA-1/DES protocol classification
- User/account identity leakage
- Interface/route/ARP/process/software/storage/connection table dumps
- Device type fingerprinting
- System identity leakage and UDP response amplification-factor measurement

Every script speaks real SNMP over UDP - BER-encoded GetRequest/GetNextRequest/GetBulkRequest/SetRequest PDUs for v1/v2c and RFC 3412/3414 USM messages (engine ID, security parameters, scoped PDU) for v3, with a built-in BER codec, OID table, and pure-Lua MD5/SHA-1/SHA-256/HMAC plus RFC 3414 key localization, DES-CBC and AES-128-CFB for privacy - and turns the observed MIB data into evidence-based findings.

All probes are read-only except a single documented sysName write test that is immediately reverted; request budgets and timeouts bound every session.

**Ports:** 161 or matched `snmp` service | **Protocol:** SNMP v1/v2c (RFC 1157/1901/3416) and SNMPv3/USM (RFC 3412/3414) over plain UDP | **Total lines of Lua:** 42,939

---

## 📋 Script Index

| # | Script | Risk Level | Category | Lines |
|---|--------|-----------|----------|-------|
| 1 | [snmp-cisco-config-copy](#1-snmp-cisco-config-copy---cisco-configuration-copy-exposure) | 🔴 CRITICAL | vuln, safe | 2654 |
| 2 | [snmp-default-community](#2-snmp-default-community---default-community-detection) | 🔴 CRITICAL | vuln, safe | 2702 |
| 3 | [snmp-user-accounts-leak](#3-snmp-user-accounts-leak---account-identity-enumeration) | 🔴 CRITICAL | vuln, safe | 2730 |
| 4 | [snmp-write-access-check](#4-snmp-write-access-check---unauthenticated-write-permissions) | 🔴 CRITICAL | vuln, safe | 2660 |
| 5 | [snmp-ip-routing-table](#5-snmp-ip-routing-table---network-topology-disclosure) | 🟠 HIGH | discovery, safe | 2673 |
| 6 | [snmp-running-processes](#6-snmp-running-processes---process-inventory-exposure) | 🟠 HIGH | discovery, safe | 2677 |
| 7 | [snmp-snmpv3-weak-auth](#7-snmp-snmpv3-weak-auth---md5sha-1des-usm-protocols) | 🟠 HIGH | vuln, safe | 2746 |
| 8 | [snmp-arp-table-leak](#8-snmp-arp-table-leak---live-host-mapping-disclosure) | 🟡 MEDIUM | discovery, safe | 2659 |
| 9 | [snmp-installed-software](#9-snmp-installed-software---software-inventory-disclosure) | 🟡 MEDIUM | discovery, safe | 2679 |
| 10 | [snmp-interfaces-dump](#10-snmp-interfaces-dump---interface-and-mac-inventory) | 🟡 MEDIUM | discovery, safe | 2698 |
| 11 | [snmp-snmpv3-auth-probe](#11-snmp-snmpv3-auth-probe---usm-engine-and-level-probing) | 🟡 MEDIUM | discovery, safe | 2665 |
| 12 | [snmp-system-info-leak](#12-snmp-system-info-leak---device-identity-disclosure) | 🟡 MEDIUM | discovery, safe | 2676 |
| 13 | [snmp-tcp-udp-connections](#13-snmp-tcp-udp-connections---live-endpoint-disclosure) | 🟡 MEDIUM | discovery, safe | 2698 |
| 14 | [snmp-amplification-factor](#14-snmp-amplification-factor---ddos-reflection-measurement) | 🟢 LOW | discovery, safe | 2684 |
| 15 | [snmp-device-type-fingerprint](#15-snmp-device-type-fingerprint---hardware-category-classification) | 🟢 LOW | discovery, safe | 2664 |
| 16 | [snmp-storage-metrics](#16-snmp-storage-metrics---filesystem-and-utilization-telemetry) | 🟢 LOW | discovery, safe | 2674 |

---

### 1. **snmp-cisco-config-copy** - Cisco Configuration Copy Exposure
**Description:** Checks whether a Cisco (or Cisco-clone) device exposes the CISCO-CONFIG-COPY-MIB control objects, which let any community client request a full configuration copy to an attacker-chosen TFTP/FTP server. The script reads the control objects and registered server objects to measure exposure without ever triggering a copy.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- cccCopyInOpStatus / cccCopyInMode control objects under 1.3.6.1.4.1.9.9.96.1.1
- cccProtocol and cccCopyInServer registrations
- Whether a readable community reaches the MIB at all
- CVSS 9.1 verdict when the copy MIB is readable

**How to Execute:**
```bash
nmap -sU -p 161 --script snmp-cisco-config-copy target.example.com

# Adjust the request budget for slow links
nmap -sU -p 161 --script snmp-cisco-config-copy --script-args snmp-cisco-config-copy.maxrequests=30 target.example.com
```

**Sample Output:**
```
| snmp-cisco-config-copy:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - CISCO-CONFIG-COPY-MIB exposed: remote configuration copy available
|   Severity counts: CRITICAL=1 HIGH=1 MEDIUM=0 LOW=0 INFO=0
|   Findings:
|     [CRITICAL] CISCO-CONFIG-COPY-MIB is readable by an unauthenticated community (cccCopyIn)
|     [HIGH] Full device configuration can be pulled to an attacker-controlled TFTP/FTP server
|   CISCO-CONFIG-COPY Audit:
|     Reading community: public
|     Control objects present: cccCopyInOpStatus = 1 | cccCopyInMode = 1
|     Registered copy servers: sysObjectID (1.3.6.1.2.1.1.2.0)
```

---

### 2. **snmp-default-community** - Default Community Detection
**Description:** Probes the agent with the community strings vendors ship by default (public, private, community, cisco, admin, manager, test, root, default, mycommunity, snmp, monitor, internal, operator), records which respond, then tests every readable community for write permission with a single immediately-reverted sysName SetRequest.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- One GetRequest on sysName per candidate community (14 defaults)
- One reverted SetRequest per readable community to classify read vs read/write
- Per-community device identity (sysName) exposed by the hit
- CVSS 9.8 for writable, 7.5 for read-only exposure

**How to Execute:**
```bash
nmap -sU -p 161 --script snmp-default-community target.example.com

# Larger candidate budget and shorter timeout
nmap -sU -p 161 --script snmp-default-community --script-args 'snmp-default-community.maxrequests=40,snmp-default-community.timeout=4' target.example.com
```

**Sample Output:**
```
| snmp-default-community:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - writable default community exposed (unauthenticated write access)
|   Severity counts: CRITICAL=1 HIGH=2 MEDIUM=0 LOW=0 INFO=0
|   Findings:
|     [CRITICAL] Default community 'private' grants write access
|     [HIGH] Default community 'public' is readable
|   Community Audit:
|     Communities tested: 14
|     Readable communities: public, private
|     Write test detail: public: Set rejected (badValue) | private: Set accepted (status 0)
```

---

### 3. **snmp-user-accounts-leak** - Account Identity Enumeration
**Description:** Enumerates the account identities an SNMP agent leaks: USM security names from the usmUserTable (with each user's auth/privacy protocol), the sysContact e-mail, and user-like tokens hidden in hrSWRunTable process parameters (-u flags, home directories).

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Full usmUserTable walk (security name, usmUserAuthProtocol, usmUserPrivProtocol per user)
- sysContact for e-mail style identities
- hrSWRunTable parameters scanned for -u flags and /home/<user> paths
- Distinct identity list with the leaking source per name
- CVSS 7.5 for the identity map

**How to Execute:**
```bash
nmap -sU -p 161 --script snmp-user-accounts-leak target.example.com

# Wider candidate community list budget
nmap -sU -p 161 --script snmp-user-accounts-leak --script-args snmp-user-accounts-leak.maxrequests=40 target.example.com
```

**Sample Output:**
```
| snmp-user-accounts-leak:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - 2 account identity(ies) leaked via SNMP
|   Severity counts: CRITICAL=1 HIGH=2 MEDIUM=1 LOW=0 INFO=0
|   Findings:
|     [CRITICAL] SNMPv3 security names are world-readable through the USM user table
|     [HIGH] Account identity leaked: operator
|     [HIGH] Account identity leaked: audit
|     [MEDIUM] Administrative contact address exposed via sysContact
|   Account Identity Leak:
|     USM security names: operator (auth: MD5, priv: DES), audit (auth: SHA-1, priv: AES-128)
|     sysContact identities: admin@corp.example
```

---

### 4. **snmp-write-access-check** - Unauthenticated Write Permissions
**Description:** Determines whether any community grants write permission. Each candidate (private, public, community, cisco, admin, write, set, mycommunity) is read-tested, then write-tested with exactly one SetRequest on sysName that is immediately reverted, and the agent's error status is recorded.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Read capability per candidate community (one GetRequest each)
- One reverted SetRequest per readable community (status 0 = writable, badValue/noSuch = rejected)
- Read-only vs read/write classification per community
- CVSS 9.8 verdict when any community is writable

**How to Execute:**
```bash
nmap -sU -p 161 --script snmp-write-access-check target.example.com

# More candidates per run
nmap -sU -p 161 --script snmp-write-access-check --script-args snmp-write-access-check.maxrequests=50 target.example.com
```

**Sample Output:**
```
| snmp-write-access-check:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - SNMP write access available without authentication
|   Severity counts: CRITICAL=1 HIGH=1 MEDIUM=0 LOW=0 INFO=0
|   Findings:
|     [CRITICAL] Community 'private' grants unauthenticated write access
|     [HIGH] Write access permits USM key table manipulation and interface control
|   Write Access Audit:
|     Writable communities: private
|     Read-only communities: public (badValue)
```

---

### 5. **snmp-ip-routing-table** - Network Topology Disclosure
**Description:** Dumps the ipRouteTable (destination, interface, metric, next hop) to reconstruct the network topology the device sits in: default gateway, directly connected segments and remote paths.

**Risk Level:** 🟠 HIGH | **Category:** discovery, safe

**What it checks:**
- Full ipRouteTable walk (ipRouteDest, ipRouteIfIndex, ipRouteMetric1, ipRouteNextHop)
- Route classification: default gateway vs directly connected vs remote segment
- Per-route detail list (destination, next hop, interface, metric)
- CVSS 5.3 for topology disclosure

**How to Execute:**
```bash
nmap -sU -p 161 --script snmp-ip-routing-table target.example.com

# Cap the walk width / budget
nmap -sU -p 161 --script snmp-ip-routing-table --script-args snmp-ip-routing-table.maxrequests=20 target.example.com
```

**Sample Output:**
```
| snmp-ip-routing-table:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - full IP routing table exposed (3 routes)
|   Topology Summary:
|     Default gateways: default -> 192.168.1.1 (if 1)
|     Directly connected segments: 2
|     Remote segments: 10.10.0.0 -> 192.168.1.2 (if 2, metric 1)
|   Route Detail:
|     Routes:
|     1. dest 0.0.0.0  next 192.168.1.1  if 1  metric 0
|     2. dest 10.10.0.0  next 192.168.1.2  if 2  metric 1
|     3. dest 192.168.1.0  next 0.0.0.0  if 1  metric 0
```

---

### 6. **snmp-running-processes** - Process Inventory Exposure
**Description:** Walks the HOST-RESOURCES hrSWRunTable to list every running process (name, path, full parameter string, status) and flags suspicious argv patterns: URLs, /tmp staging paths, -u user flags, -p style flags and /etc/shadow references.

**Risk Level:** 🟠 HIGH | **Category:** discovery, safe

**What it checks:**
- Full hrSWRunTable walk (hrSWRunName, hrSWRunPath, hrSWRunParameters, hrSWRunStatus)
- Suspicious parameter scan (7 built-in needle patterns with notes)
- Sorted process inventory with per-entry parameters
- CVSS 5.3 for the inventory

**How to Execute:**
```bash
nmap -sU -p 161 --script snmp-running-processes target.example.com

# Bounded walk for large process tables
nmap -sU -p 161 --script snmp-running-processes --script-args snmp-running-processes.maxrequests=20 target.example.com
```

**Sample Output:**
```
| snmp-running-processes:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - process table exposed (4 running entries)
|   Severity counts: CRITICAL=0 HIGH=2 MEDIUM=0 LOW=0 INFO=0
|   Findings:
|     [HIGH] hrSWRunTable readable via community exposes the full process inventory
|     [HIGH] Suspicious process indicator: snmpd (user flag (service account disclosure))
|   Process Inventory:
|     Total processes: 4
|     Inventory:
|     1. cron  (/usr/sbin/cron)
|     2. nginx  (/usr/sbin/nginx)  args: -g daemon off
|     3. snmpd  (/usr/sbin/snmpd)  args: -LS3Df -C -c /etc/snmpd.conf
|     4. sshd  (/usr/sbin/sshd)  args: -D
```

---

### 7. **snmp-snmpv3-weak-auth** - MD5/SHA-1/DES USM Protocols
**Description:** Audits the SNMPv3 USM configuration for weak security: discovers the engine ID, probes which security levels each candidate user is accepted at, and walks the usmUserTable (via any readable community) to classify each user's authentication and privacy protocol OIDs, flagging MD5/SHA-1 auth, DES/3DES privacy and noAuthNoPriv users.

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Engine ID discovery via noAuthNoPriv probes from 5 candidate users
- Per-user security level acceptance (noAuthNoPriv / authNoPriv)
- usmUserTable auth/priv protocol OIDs mapped to names (MD5, SHA-1, SHA-256, SHA-384, SHA-512, DES-CBC, AES-128/256-CFB)
- CVSS 7.5 for weak USM configuration

**How to Execute:**
```bash
nmap -sU -p 161 --script snmp-snmpv3-weak-auth target.example.com

# Probe a specific user name first
nmap -sU -p 161 --script snmp-snmpv3-weak-auth --script-args snmp-snmpv3-weak-auth.user=admin target.example.com
```

**Sample Output:**
```
| snmp-snmpv3-weak-auth:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - weak SNMPv3 security configuration detected
|   Severity counts: CRITICAL=0 HIGH=5 MEDIUM=0 LOW=0 INFO=0
|   Findings:
|     [HIGH] SNMPv3 user 'operator' accepted at noAuthNoPriv (no authentication, no privacy)
|     [HIGH] SNMPv3 user 'audit' accepted at noAuthNoPriv (no authentication, no privacy)
|     [HIGH] USM user 'operator' authenticates with MD5
|     [HIGH] USM user 'audit' authenticates with SHA-1
|     [HIGH] USM user 'operator' encrypts with DES-CBC
```

---

### 8. **snmp-arp-table-leak** - Live Host Mapping Disclosure
**Description:** Walks the ipNetToMediaTable to dump the device's live ARP table: every IP-to-MAC mapping with the interface it sits on, grouped per interface.

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Full ipNetToMediaTable walk (ifIndex, IP address, MAC)
- Per-interface grouping of active host mappings
- MAC formatting (xx:xx:xx:xx:xx:xx) and host count
- CVSS 5.3 for active host enumeration

**How to Execute:**
```bash
nmap -sU -p 161 --script snmp-arp-table-leak target.example.com

# Budget cap for busy switches
nmap -sU -p 161 --script snmp-arp-table-leak --script-args snmp-arp-table-leak.maxrequests=20 target.example.com
```

**Sample Output:**
```
| snmp-arp-table-leak:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - live ARP table exposed (3 host mappings)
|   ARP Table:
|     Total mappings: 3
|     Grouped by interface: if 1: 192.168.1.10, 192.168.1.20 | if 2: 192.168.1.30
|     Mappings:
|     1. 192.168.1.10     aa:bb:cc:dd:ee:01  (if 1)
|     2. 192.168.1.20     aa:bb:cc:dd:ee:02  (if 1)
|     3. 192.168.1.30     aa:bb:cc:dd:ee:03  (if 2)
```

---

### 9. **snmp-installed-software** - Software Inventory Disclosure
**Description:** Dumps installed software names, versions and install dates from the hrSWInstalledTable; when that table is empty (common on network gear) it falls back to the hrSWRunTable running entries, which still reveal package names, versions and paths.

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- hrSWInstalledTable walk (name, version, install date)
- Automatic hrSWRunTable fallback (name, path) when the installed table is empty
- Ancient-version hints (pre-1.0 and legacy major patterns) as LOW findings
- CVSS 5.3 for the inventory

**How to Execute:**
```bash
nmap -sU -p 161 --script snmp-installed-software target.example.com

# Budget for large package tables
nmap -sU -p 161 --script snmp-installed-software --script-args snmp-installed-software.maxrequests=25 target.example.com
```

**Sample Output:**
```
| snmp-installed-software:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - software inventory exposed (4 entries)
|   Software Inventory:
|     Source: hrSWInstalledTable
|     Total entries: 4
|     Inventory:
|     1. OpenSSH                9.6p1              20240411
|     2. Ubuntu                 22.04.4 LTS        20240702
|     3. nginx                  1.24.0-2ubuntu7.3  20240601
|     4. snmpd                  5.9.1+dfsg-1ubuntu5.4  20240315
```

---

### 10. **snmp-interfaces-dump** - Interface and MAC Inventory
**Description:** Dumps the ifTable (ifDescr, ifType, ifSpeed, ifPhysAddress, ifAdminStatus, ifOperStatus) to enumerate the device's physical and logical interfaces, speeds, MAC addresses and states, with an up/down summary and interface type mix.

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Full ifTable walk (6 standard columns)
- ifType mapping (ethernetCsmacd, bridge, loopback, tunnel, ...)
- Admin/oper state classification and type mix summary
- CVSS 5.3 for interface and MAC disclosure

**How to Execute:**
```bash
nmap -sU -p 161 --script snmp-interfaces-dump target.example.com

# Budget cap
nmap -sU -p 161 --script snmp-interfaces-dump --script-args snmp-interfaces-dump.maxrequests=20 target.example.com
```

**Sample Output:**
```
| snmp-interfaces-dump:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - interface table exposed (4 interfaces)
|   Interface Summary:
|     Operational up: 4
|     Operational down/other: 0
|     Type mix: bridge x1, ethernetCsmacd x2, loopback x1
|   Interface Detail:
|     Total interfaces: 4
|     Inventory:
|     1. eth0     ethernetCsmacd  speed 1000000000  mac 00:1a:2b:3c:4d:5e  admin up  oper up
|     2. eth1     ethernetCsmacd  speed 1000000000  mac 00:1a:2b:3c:4d:5f  admin up  oper up
|     3. br0      bridge          speed 1000000000  mac 00:1a:2b:3c:4d:60  admin up  oper up
|     4. lo       loopback        speed 10000000000  mac 00:00:00:00:00:00  admin up  oper up
```

---

### 11. **snmp-snmpv3-auth-probe** - USM Engine and Level Probing
**Description:** Probes the SNMPv3 engine to discover the engine ID, determine which USM security levels the agent accepts, and enumerate the candidate user names that respond (admin, audit, operator, user, public, monitor, nms or a custom --script-args user).

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Engine ID discovery via noAuthNoPriv probe per candidate user
- AuthNoPriv re-probe for every responding user
- Per-user level matrix (accepted / accepted with data / rejected / silent)
- CVSS 4.3 when unauthenticated users are reachable

**How to Execute:**
```bash
nmap -sU -p 161 --script snmp-snmpv3-auth-probe target.example.com

# Probe a specific user only
nmap -sU -p 161 --script snmp-snmpv3-auth-probe --script-args snmp-snmpv3-auth-probe.user=nms target.example.com
```

**Sample Output:**
```
| snmp-snmpv3-auth-probe:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - SNMPv3 engine reachable with unauthenticated users
|   Severity counts: CRITICAL=0 HIGH=1 MEDIUM=1 LOW=0 INFO=0
|   Findings:
|     [MEDIUM] Engine ID discoverable and noAuthNoPriv accepted for user(s): audit, operator
|     [HIGH] Unauthenticated data access as user 'audit'
|   USM Level Matrix:
|     User probes:
|     admin      noAuthNoPriv: silent              authNoPriv: rejected
|     audit      noAuthNoPriv: accepted (data)     authNoPriv: accepted
|     operator   noAuthNoPriv: accepted (data)     authNoPriv: accepted
|     Responding users: audit, operator
```

---

### 12. **snmp-system-info-leak** - Device Identity Disclosure
**Description:** Reads the MIB-II system group (sysDescr, sysObjectID, sysUpTime, sysContact, sysName, sysLocation) to capture the device identity, vendor model, uptime (formatted, with reload-recency classification), administrative contact and physical location.

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- All six system objects in a single GetRequest
- sysObjectID mapped to IANA enterprise vendor names
- Uptime formatted (d/h/m) and classified (<6h recent reload, <30d, >=30d)
- Contact e-mail extraction from sysContact
- CVSS 5.3 for identity disclosure

**How to Execute:**
```bash
nmap -sU -p 161 --script snmp-system-info-leak target.example.com

# Timeout tuning for high-latency links
nmap -sU -p 161 --script snmp-system-info-leak --script-args snmp-system-info-leak.timeout=15 target.example.com
```

**Sample Output:**
```
| snmp-system-info-leak:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - system group exposed via readable community
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=2 INFO=0
|   Findings:
|     [MEDIUM] Device identity (model, firmware, contact) readable via SNMP
|     [LOW] Uptime indicator: recent reload (<6h) - possible recovery or reconfiguration
|     [LOW] Administrative contact address exposed
|   System Group:
|     sysDescr: NETGEAR GS724Tv2 Gigabit Smart Web Managed Switch 6.12.22
|     sysObjectID: NETGEAR (enterprise 1.3.6.1.4.1.3798)
|     sysUpTime: 0d 3h 25m
|     sysContact: admin@corp.example
|     sysName: core-switch-01
|     sysLocation: DC1 Rack A U12
```

---

### 13. **snmp-tcp-udp-connections** - Live Endpoint Disclosure
**Description:** Dumps the tcpConnTable and udpTable: local/remote addresses and ports with TCP state, split into listening, established and other states. A live map of what the device is connected to and which services it binds.

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- tcpConnTable walk (state, local/remote IP:port)
- udpTable walk (bound sockets)
- State split: listen vs established vs transient
- Established peer list for cross-checking against the sanctioned inventory
- CVSS 5.3 for live endpoint disclosure

**How to Execute:**
```bash
nmap -sU -p 161 --script snmp-tcp-udp-connections target.example.com

# Budget for busy hosts
nmap -sU -p 161 --script snmp-tcp-udp-connections --script-args snmp-tcp-udp-connections.maxrequests=20 target.example.com
```

**Sample Output:**
```
| snmp-tcp-udp-connections:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - connection tables exposed (4 TCP, 2 UDP)
|   Connection Tables:
|     TCP listening: 0.0.0.0:22, 0.0.0.0:80, 0.0.0.0:443
|     TCP established: 192.168.1.50:51234 <-> 10.0.0.5:443
|     TCP other states: none
|     UDP bound sockets: 0.0.0.0:53, 0.0.0.0:161
```

---

### 14. **snmp-amplification-factor** - DDoS Reflection Measurement
**Description:** Measures the UDP response amplification factor: the size ratio of a minimal single-OID GetRequest (spoofable source) versus the response, plus a bounded GetBulk (max-repetitions 10) for the worst case. High factors mark the agent as a DDoS reflection candidate.

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Exact byte size of one minimal GetRequest and its response
- Exact byte size of one bounded GetBulk (10 reps) and its response
- Request/response ratios with thresholds: >=4 significant, >=10 strong, >=40 extreme
- CVSS 7.5 when the factor reaches the reflector threshold

**How to Execute:**
```bash
nmap -sU -p 161 --script snmp-amplification-factor target.example.com

# Timeout tuning
nmap -sU -p 161 --script snmp-amplification-factor --script-args snmp-amplification-factor.timeout=10 target.example.com
```

**Sample Output:**
```
| snmp-amplification-factor:
|   Risk Level: 🟢 LOW
|   Status: VULNERABLE - significant SNMP amplification factor (5.3x)
|   Amplification Measurement:
|     Minimal GetRequest: 40 bytes in / 54 bytes out
|     GetRequest factor: 1.35
|     Bounded GetBulk (max-reps 10): 40 bytes in / 214 bytes out
|     GetBulk factor: 5.35
|     Worst factor: 5.35
|     Classification: significant amplification (DDoS reflector candidate)
```

---

### 15. **snmp-device-type-fingerprint** - Hardware Category Classification
**Description:** Fingerprints the device hardware category (router, switch, firewall, printer, server, UPS, load balancer) from sysDescr keyword scoring plus interface-shape heuristics (bridge ports indicate switching, tunnels with multiple ethernet ports indicate routing).

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Keyword scoring over sysDescr (7 device classes, ~30 keywords)
- Interface shape from the ifTable (bridge / tunnel / ethernet counts)
- Winning class with the evidence lines that selected it
- CVSS 3.7 for the identity disclosure

**How to Execute:**
```bash
nmap -sU -p 161 --script snmp-device-type-fingerprint target.example.com

# Budget cap
nmap -sU -p 161 --script snmp-device-type-fingerprint --script-args snmp-device-type-fingerprint.maxrequests=12 target.example.com
```

**Sample Output:**
```
| snmp-device-type-fingerprint:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - device fingerprinted as Switch
|   Device Fingerprint:
|     Detected class: Switch
|     sysDescr: NETGEAR GS724Tv2 Gigabit Smart Web Managed Switch 6.12.22
|     Interface shape: total 4, ethernet 2, bridge 1, tunnel 0
|     Classification evidence: sysDescr matches 'switch'; sysDescr matches 'managed switch'
```

---

### 16. **snmp-storage-metrics** - Filesystem and Utilization Telemetry
**Description:** Walks the hrStorageTable (type, description, allocation units, total size, used size) to enumerate disks, memory and filesystems, computing the utilization percentage per row and flagging rows above 80%.

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Full hrStorageTable walk (hrStorageType, hrStorageDescr, hrStorageAllocUnits, hrStorageSize, hrStorageUsed)
- Storage type mapping (ram, fixedDisk, flash, net, ...)
- Used/total byte computation and percentage per row
- High-utilization (>=80%) flags
- CVSS 3.7 for the telemetry

**How to Execute:**
```bash
nmap -sU -p 161 --script snmp-storage-metrics target.example.com

# Budget cap
nmap -sU -p 161 --script snmp-storage-metrics --script-args snmp-storage-metrics.maxrequests=12 target.example.com
```

**Sample Output:**
```
| snmp-storage-metrics:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - storage metrics exposed (3 rows)
|   Storage Metrics:
|     Total rows: 3
|     Storage:
|     1. other      /dev/sda1     256.8M / 500.0M (51%)
|     2. other      ramdisk       512.0M / 1024.0M (50%)
|     3. ram        /tmp          10.0M / 200.0M (5%)
```

