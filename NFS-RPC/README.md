# 📦 NFS / ONC-RPC Security Audits

**16 Nmap NSE scripts** for auditing NFS file servers and the surrounding ONC-RPC ecosystem directly on the wire:

**Covers:**

- A full XDR/record-marking codec (call/reply framing with accepted/rejected status and auth-state decoding, PMAP GETPORT/DUMP, MOUNT v1/v3 MNT/DUMP/EXPORT, NFS v2/v3 GETATTR/LOOKUP/READLINK/FSINFO/ACCESS with fattr3 permission-bit decoding, NLM v4 TEST, rusersd, rquotad, ypbind, statd and sprayd procedures)
- A budgeted TCP session layer with rpcbind-driven port discovery
- Fhandle entropy analysis for handle-forging risk

**The suite covers the classic NFS attack surface:**

- Export and mount disclosure
- Anonymous mount bypass
- No_root_squash verification through uid-0 ACCESS
- World-readable files inside world exports
- Symlink traversal out of the export root
- Predictable file handles
- Legacy flavours without Kerberos enforcement
- Non-privileged port registrations
- Statd/rusersd/rquotad/ypbind/sprayd legacy-service exposure and NLM locking health

**Every probe is bounded and non-destructive:**

- Attribute reads only
- No file contents are opened
- No writes are attempted and no state is modified on the server.

**Ports:** 2049/tcp (nfs) + 111/tcp (rpcbind) | **Protocol:** NFS v2/v3/v4 over ONC-RPC RFC 5531 (XDR RFC 4506, PMAP RFC 1050, MOUNT RFC 1813, NLM v4, rquota, rusers, ypbind) | **Total lines of Lua:** 31,305

---

## 📋 Script Index

| # | Script | Risk Level | Category | Lines |
|---|--------|-----------|----------|-------|
| 1 | [nfs-mountd-auth-bypass](#1-nfs-mountd-auth-bypass---mountd-anonymous-mount-bypass-test) | 🔴 CRITICAL | vuln, safe | 1957 |
| 2 | [nfs-no-root-squash-check](#2-nfs-no-root-squash-check---no_root_squash-detection-uid-0-access) | 🔴 CRITICAL | vuln, safe | 1958 |
| 3 | [nfs-rpc-ypbind-nis-leak](#3-nfs-rpc-ypbind-nis-leak---nisypbind-domain-disclosure) | 🔴 CRITICAL | vuln, safe | 1952 |
| 4 | [nfs-world-readable-exports](#4-nfs-world-readable-exports---world-readable-export-exposure) | 🔴 CRITICAL | vuln, safe | 1971 |
| 5 | [nfs-insecure-port-allowed](#5-nfs-insecure-port-allowed---non-privileged-nfs-port-detection) | 🟠 HIGH | vuln, safe | 1952 |
| 6 | [nfs-readlink-traversal](#6-nfs-readlink-traversal---symlink-traversal-out-of-export-root) | 🟠 HIGH | vuln, safe | 1971 |
| 7 | [nfs-rpc-statd-check](#7-nfs-rpc-statd-check---rpcstatd-exposure-check) | 🟠 HIGH | vuln, safe | 1951 |
| 8 | [nfs-file-handle-leak](#8-nfs-file-handle-leak---file-handle-predictability-analysis) | 🟡 MEDIUM | vuln, safe | 1955 |
| 9 | [nfs-krb5-security-flavor](#9-nfs-krb5-security-flavor---rpcsec_gss--kerberos-flavour-audit) | 🟡 MEDIUM | defensive, safe | 1968 |
| 10 | [nfs-rpc-rquotad-check](#10-nfs-rpc-rquotad-check---rquotad-quota-disclosure-check) | 🟡 MEDIUM | discovery, safe | 1961 |
| 11 | [nfs-rpc-rusers-enum](#11-nfs-rpc-rusers-enum---rusersd-login-enumeration) | 🟡 MEDIUM | vuln, safe | 1953 |
| 12 | [nfs-rpc-spray-dos](#12-nfs-rpc-spray-dos---sprayd-echo-surface-probe-defensive) | 🟡 MEDIUM | defensive, safe | 1952 |
| 13 | [nfs-showmount-leak](#13-nfs-showmount-leak---export--mount-disclosure-showmount) | 🟡 MEDIUM | discovery, safe | 1961 |
| 14 | [nfs-lock-manager-check](#14-nfs-lock-manager-check---nlm-lock-manager-health-check) | 🟢 LOW | discovery, safe | 1952 |
| 15 | [nfs-rpc-programs-enum](#15-nfs-rpc-programs-enum---onc-rpc-program-enumeration-rpcbind-dump) | 🟢 LOW | discovery, safe | 1934 |
| 16 | [nfs-version-support](#16-nfs-version-support---nfs-protocol-version-profile) | 🟢 LOW | discovery, safe | 1957 |

---

### 1. **nfs-mountd-auth-bypass** - mountd Anonymous Mount Bypass Test
**Description:** Attempts to mount access-restricted exports (host/group scoped) with

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Enumerates exports via EXPORT.
- Attempts MNT with AUTH_NULL on every group-restricted export.
- Flags any accepted mount as a critical bypass.
- Why it matters: A successful anonymous mount of a group-restricted export defeats the entire NFS authorisation model: the attacker then negotiates file access with uid guessing alone. This single condition is the classic "NFS instant root" recipe.
- Safety: one mount attempt per restricted export; nothing is read after a successful mount.

**How to Execute:**
```bash
nmap -p 2049 --script nfs-mountd-auth-bypass fileserver01.corp.example.com

# Tuned request budget
nmap -p 2049 --script nfs-mountd-auth-bypass --script-args 'nfs-mountd-auth-bypass.timeout=8,nfs-mountd-auth-bypass.maxrequests=48,nfs-mountd-auth-bypass.recv_window=3' fileserver01.corp.example.com
```

**Sample Output:**
```
| nfs-mountd-auth-bypass:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - 2 restricted export(s) mounted with NO credentials: /export/data, /export/backup
```

---

### 2. **nfs-no-root-squash-check** - no_root_squash Detection (uid 0 ACCESS)
**Description:** Detects exports without root squashing: mounts each export, then uses

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Enumerates exports via EXPORT.
- Mounts each and issues NFS ACCESS with an AUTH_SYS uid-0 credential.
- Flags exports granting uid 0 full rights (no squash).
- Why it matters: no_root_squash maps client uid 0 to server uid 0: any compromised client machine becomes root on the fileserver for that export. It is the standard privilege-escalation primitive in NFS estates.
- Safety: ACCESS metadata checks only; no files are read or written.

**How to Execute:**
```bash
nmap -p 2049 --script nfs-no-root-squash-check fileserver01.corp.example.com

# Tuned request budget
nmap -p 2049 --script nfs-no-root-squash-check --script-args 'nfs-no-root-squash-check.timeout=8,nfs-no-root-squash-check.maxrequests=48,nfs-no-root-squash-check.recv_window=3' fileserver01.corp.example.com
```

**Sample Output:**
```
| nfs-no-root-squash-check:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - client uid 0 retains full access on: /export/data
```

---

### 3. **nfs-rpc-ypbind-nis-leak** - NIS/ypbind Domain Disclosure
**Description:** Checks whether ypbind (100007) is registered and answers YPBINDPROC_

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Looks up the ypbind registration in the rpcbind map.
- Sends YPBINDPROC_DOMAIN for the configured domain.
- Grades the disclosure.
- Why it matters: A live NIS binding exposes the legacy directory service to the network: domain enumeration feeds ypcat-style dumps and NIS has no modern authentication hardening. NIS presence usually means legacy password maps are one query away.
- Safety: one read-only ypbind query.

**How to Execute:**
```bash
nmap -p 111 --script nfs-rpc-ypbind-nis-leak fileserver01.corp.example.com

# Tuned request budget
nmap -p 111 --script nfs-rpc-ypbind-nis-leak --script-args 'nfs-rpc-ypbind-nis-leak.timeout=8,nfs-rpc-ypbind-nis-leak.maxrequests=48,nfs-rpc-ypbind-nis-leak.recv_window=3' fileserver01.corp.example.com
```

**Sample Output:**
```
| nfs-rpc-ypbind-nis-leak:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - ypbind answers DOMAIN as bound; the NIS domain and ypserv endpoint are disclosed
```

---

### 4. **nfs-world-readable-exports** - World-Readable Export Exposure
**Description:** Finds world-accessible exports and inspects the permission bits of

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Enumerates exports and keeps those with no host/group restriction.
- Mounts each and reads directory attributes.
- Looks up common filenames and grades their permission bits.
- Why it matters: Any host on the network can mount a world export; if its contents are world-readable, confidential data is effectively public. World-writable exports let any principal plant files (cron payloads, SSH keys) that other clients execute.
- Safety: attribute reads only; no file content is accessed.

**How to Execute:**
```bash
nmap -p 2049 --script nfs-world-readable-exports fileserver01.corp.example.com

# Tuned request budget
nmap -p 2049 --script nfs-world-readable-exports --script-args 'nfs-world-readable-exports.timeout=8,nfs-world-readable-exports.maxrequests=48,nfs-world-readable-exports.recv_window=3' fileserver01.corp.example.com
```

**Sample Output:**
```
| nfs-world-readable-exports:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - 2 exposure(s) in world-accessible exports (/export/public: world-readable file readme.txt, mode 0644)
```

---

### 5. **nfs-insecure-port-allowed** - Non-Privileged NFS Port Detection
**Description:** Detects NFS services registered on non-privileged TCP ports (above

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Reads NFS and mountd registrations from the rpcbind map.
- Flags every NFS instance on a port above 1024.
- Verifies flagged instances answer real NFS calls.
- Why it matters: NFS on a high port can be mounted/spoofed by unprivileged local users on compromised machines, defeating the client-root trust model. Registrations on unexpected ports are also a common persistence trick.
- Safety: rpcbind read + one NULL probe per flagged instance.

**How to Execute:**
```bash
nmap -p 2049 --script nfs-insecure-port-allowed fileserver01.corp.example.com

# Tuned request budget
nmap -p 2049 --script nfs-insecure-port-allowed --script-args 'nfs-insecure-port-allowed.timeout=8,nfs-insecure-port-allowed.maxrequests=48,nfs-insecure-port-allowed.recv_window=3' fileserver01.corp.example.com
```

**Sample Output:**
```
| nfs-insecure-port-allowed:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - 1 NFS instance(s) registered on non-privileged port(s) (4000)
```

---

### 6. **nfs-readlink-traversal** - Symlink Traversal Out of Export Root
**Description:** Follows symlinks inside exports and checks whether their targets

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Mounts each accessible export.
- Looks up common filenames and READLINKs anything symlink-shaped.
- Flags targets leaving the export root.
- Why it matters: A symlink pointing outside an export lets any mounting client read arbitrary server paths (/etc/shadow, SSH keys) with the exported permissions. Historical NFS daemons resolved such targets server-side without containment checks.
- Safety: READLINK metadata calls only; the target is never opened.

**How to Execute:**
```bash
nmap -p 2049 --script nfs-readlink-traversal fileserver01.corp.example.com

# Tuned request budget
nmap -p 2049 --script nfs-readlink-traversal --script-args 'nfs-readlink-traversal.timeout=8,nfs-readlink-traversal.maxrequests=48,nfs-readlink-traversal.recv_window=3' fileserver01.corp.example.com
```

**Sample Output:**
```
| nfs-readlink-traversal:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - 1 symlink(s) escape the export root (/export/data/shadow -> ../../etc/shadow)
```

---

### 7. **nfs-rpc-statd-check** - rpc.statd Exposure Check
**Description:** Checks whether the rpc.statd service (100024) is registered and answers

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Looks up the statd registration in the rpcbind map.
- Sends SM_STAT for a probe hostname.
- Grades exposure by answer behaviour.
- Why it matters: statd implementations have a long history of remotely exploitable overflow/format-string bugs; exposure on untrusted networks is a standing risk. The state value also leaks NFS client restart activity.
- Safety: one read-only SM_STAT request.

**How to Execute:**
```bash
nmap -p 111 --script nfs-rpc-statd-check fileserver01.corp.example.com

# Tuned request budget
nmap -p 111 --script nfs-rpc-statd-check --script-args 'nfs-rpc-statd-check.timeout=8,nfs-rpc-statd-check.maxrequests=48,nfs-rpc-statd-check.recv_window=3' fileserver01.corp.example.com
```

**Sample Output:**
```
| nfs-rpc-statd-check:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - rpc.statd answers SM_STAT with state 7 to anonymous callers
```

---

### 8. **nfs-file-handle-leak** - File Handle Predictability Analysis
**Description:** Collects NFS file handles from multiple mounts and analyses their

**Risk Level:** 🟡 MEDIUM | **Category:** vuln, safe

**What it checks:**
- Mounts every accessible export and collects the returned handles.
- Estimates entropy (distinct bytes, zero runs) per handle.
- Grades the predictability profile.
- Why it matters: Legacy NFS file handles derived from inode numbers can be guessed, bypassing the mount permission layer entirely (handle -> direct file access). High-entropy handles (v4-style) close the forging path.
- Safety: attribute-level mount calls only.

**How to Execute:**
```bash
nmap -p 2049 --script nfs-file-handle-leak fileserver01.corp.example.com

# Tuned request budget
nmap -p 2049 --script nfs-file-handle-leak --script-args 'nfs-file-handle-leak.timeout=8,nfs-file-handle-leak.maxrequests=48,nfs-file-handle-leak.recv_window=3' fileserver01.corp.example.com
```

**Sample Output:**
```
| nfs-file-handle-leak:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - 4 of 4 file handles show predictable structure (low entropy, long zero runs)
```

---

### 9. **nfs-krb5-security-flavor** - RPCSEC_GSS / Kerberos Flavour Audit
**Description:** Audits the RPC security flavours the NFS stack accepts: mounts

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Enumerates exports and picks the access-restricted ones.
- Attempts MNT with AUTH_NULL on each restricted export.
- Records the auth_flavour list the mountd offers.
- Why it matters: AUTH_SYS trusts a client-supplied UID with no verification; only sec=krb5p provides cryptographically verified identity and privacy. Any restricted export mountable with legacy flavours is protected by network position alone.
- Safety: at most one mount attempt per restricted export; no files are accessed after mount.

**How to Execute:**
```bash
nmap -p 2049 --script nfs-krb5-security-flavor fileserver01.corp.example.com

# Tuned request budget
nmap -p 2049 --script nfs-krb5-security-flavor --script-args 'nfs-krb5-security-flavor.timeout=8,nfs-krb5-security-flavor.maxrequests=48,nfs-krb5-security-flavor.recv_window=3' fileserver01.corp.example.com
```

**Sample Output:**
```
| nfs-krb5-security-flavor:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - 2 of 2 restricted export(s) mount with legacy flavours only (no RPCSEC_GSS enforcement)
```

---

### 10. **nfs-rpc-rquotad-check** - rquotad Quota Disclosure Check
**Description:** Queries rquotad (100011) GETQUOTA for a sample UID and reports whether

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Looks up rquotad in the rpcbind map.
- Sends GETQUOTA for the export and sample UID 1000.
- Reports the quota profile.
- Why it matters: Quota values expose user activity levels and filesystem sizing, useful for planning resource-exhaustion abuse. An over-soft-quota answer proves the quota system is actively enforced and its limits are readable.
- Safety: one read-only quota query.

**How to Execute:**
```bash
nmap -p 111 --script nfs-rpc-rquotad-check fileserver01.corp.example.com

# Tuned request budget
nmap -p 111 --script nfs-rpc-rquotad-check --script-args 'nfs-rpc-rquotad-check.timeout=8,nfs-rpc-rquotad-check.maxrequests=48,nfs-rpc-rquotad-check.recv_window=3' fileserver01.corp.example.com
```

**Sample Output:**
```
| nfs-rpc-rquotad-check:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - rquotad disclosed quota accounting (used 1000000 of soft 976562 blocks)
```

---

### 11. **nfs-rpc-rusers-enum** - rusersd Login Enumeration
**Description:** Calls RUSERSPROC_NAMES on rusersd (100002) to enumerate logged-in

**Risk Level:** 🟡 MEDIUM | **Category:** vuln, safe

**What it checks:**
- Looks up rusersd in the rpcbind map.
- Sends RUSERSPROC_NAMES.
- Grades the disclosure by user count.
- Why it matters: The list feeds social engineering and targeted credential attacks; service accounts seen here (oracle, backup) are high-value targets. Combined with rstatd data it maps machine usage patterns.
- Safety: one read-only rusersd query.

**How to Execute:**
```bash
nmap -p 111 --script nfs-rpc-rusers-enum fileserver01.corp.example.com

# Tuned request budget
nmap -p 111 --script nfs-rpc-rusers-enum --script-args 'nfs-rpc-rusers-enum.timeout=8,nfs-rpc-rusers-enum.maxrequests=48,nfs-rpc-rusers-enum.recv_window=3' fileserver01.corp.example.com
```

**Sample Output:**
```
| nfs-rpc-rusers-enum:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - rusersd disclosed 3 active session(s): root et al.
```

---

### 12. **nfs-rpc-spray-dos** - sprayd Echo Surface Probe (defensive)
**Description:** Defensive probe of the sprayd (100012) packet-echo service: measures

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Looks up sprayd in the rpcbind map.
- Sends a single SPRAY packet and reads SPRAYPROC_GET counters.
- Grades the exposure (service present = unexpected echo surface).
- Why it matters: Echo-style RPC services were historically abused for amplification; any exposed echo surface deserves explicit justification. The probe documents residual daemons that modern NFS stacks do not need.
- Safety: at most two tiny packets; no volume is generated.

**How to Execute:**
```bash
nmap -p 111 --script nfs-rpc-spray-dos fileserver01.corp.example.com

# Tuned request budget
nmap -p 111 --script nfs-rpc-spray-dos --script-args 'nfs-rpc-spray-dos.timeout=8,nfs-rpc-spray-dos.maxrequests=48,nfs-rpc-spray-dos.recv_window=3' fileserver01.corp.example.com
```

**Sample Output:**
```
| nfs-rpc-spray-dos:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - sprayd is registered and answers echo probes (counter 6)
```

---

### 13. **nfs-showmount-leak** - Export & Mount Disclosure (showmount)
**Description:** Calls MOUNTPROC_EXPORT and MOUNTPROC_DUMP to list exported directories

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Discovers the mountd port via rpcbind.
- Calls EXPORT (directory + group list) and DUMP (active mounts).
- Grades the disclosure by world exports and active clients.
- Why it matters: Export lists with host/group patterns map exactly which clients can mount which paths, and active-mount dumps disclose internal client addresses for impersonation. World-writable exports shown here are the fastest route to root on NFS clients.
- Safety: two read-only mountd queries.

**How to Execute:**
```bash
nmap -p 111 --script nfs-showmount-leak fileserver01.corp.example.com

# Tuned request budget
nmap -p 111 --script nfs-showmount-leak --script-args 'nfs-showmount-leak.timeout=8,nfs-showmount-leak.maxrequests=48,nfs-showmount-leak.recv_window=3' fileserver01.corp.example.com
```

**Sample Output:**
```
| nfs-showmount-leak:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - showmount-equivalent data disclosed: 4 exports (2 world) and 2 active mounts
```

---

### 14. **nfs-lock-manager-check** - NLM Lock Manager Health Check
**Description:** Checks the NLM lock manager (100021): verifies registration, performs

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Reads the nlockmgr registration from the rpcbind map.
- Sends NLM4 NULL and NLM4 TEST.
- Renders the locking health profile.
- Why it matters: Broken or absent locking silently corrupts concurrent file access; the check validates the NFSv3 locking chain (statd + lockd). Exposed lock managers on untrusted networks carry historical DoS advisories.
- Safety: two read-only lock-manager calls.

**How to Execute:**
```bash
nmap -p 2049 --script nfs-lock-manager-check fileserver01.corp.example.com

# Tuned request budget
nmap -p 2049 --script nfs-lock-manager-check --script-args 'nfs-lock-manager-check.timeout=8,nfs-lock-manager-check.maxrequests=48,nfs-lock-manager-check.recv_window=3' fileserver01.corp.example.com
```

**Sample Output:**
```
| nfs-lock-manager-check:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - lock manager healthy on 4045 (NULL and TEST answered)
```

---

### 15. **nfs-rpc-programs-enum** - ONC-RPC Program Enumeration (rpcbind DUMP)
**Description:** Enumerates every registered ONC-RPC program, version and port from the

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Sends PMAPPROC_DUMP to port 111.
- Decodes the program/version/protocol/port tuple list.
- Renders the inventory with known program names.
- Why it matters: The rpcbind map exposes every RPC service (NFS, mountd, nlockmgr, statd, rusersd, rquotad, ypbind) including versions and ports, which drives every other NFS audit. Legacy or unexpected registrations widen the attack surface.
- Safety: one read-only rpcbind query.

**How to Execute:**
```bash
nmap -p 111 --script nfs-rpc-programs-enum fileserver01.corp.example.com

# Tuned request budget
nmap -p 111 --script nfs-rpc-programs-enum --script-args 'nfs-rpc-programs-enum.timeout=8,nfs-rpc-programs-enum.maxrequests=48,nfs-rpc-programs-enum.recv_window=3' fileserver01.corp.example.com
```

**Sample Output:**
```
| nfs-rpc-programs-enum:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - 12 RPC registrations enumerated
```

---

### 16. **nfs-version-support** - NFS Protocol Version Profile
**Description:** Maps the NFS protocol versions the server advertises (v2/v3/v4 via its

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Reads the NFS version registrations from the rpcbind map.
- Sends NULL + FSINFO on the primary NFS port.
- Renders the version support profile.
- Why it matters: NFSv2 has no secure extensible auth and legacy stacks carry known bugs; knowing which versions are live drives the upgrade plan. FSINFO answers reveal the server's I/O preference limits.
- Safety: two read-only probes.

**How to Execute:**
```bash
nmap -p 2049 --script nfs-version-support fileserver01.corp.example.com

# Tuned request budget
nmap -p 2049 --script nfs-version-support --script-args 'nfs-version-support.timeout=8,nfs-version-support.maxrequests=48,nfs-version-support.recv_window=3' fileserver01.corp.example.com
```

**Sample Output:**
```
| nfs-version-support:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - NFS versions registered: 3 (including 1 legacy pre-v3)
```

