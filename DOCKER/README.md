# 🐳 Docker Security Audits

**16 Nmap NSE scripts** for auditing Docker hosts and registries:

**Covers:**

- Unauthenticated Engine API exposure (and what it implies for host root)
- Privileged-container and capability/device escape preconditions
- Dangerous host volume mounts (Docker socket, `/`, `/etc`)
- Socket-proxy method-filtering gaps (tecnativa/docker-socket-proxy, HAProxy, Nginx)
- Secret leakage through container configuration (masked env/label scanning)
- Missing cgroup resource limits
- Daemon hardening options
- Go `/debug/pprof` exposure
- Live event-stream surveillance
- Host-network and wide port bindings
- Image build-history secret leakage
- Registry v2 unauthenticated catalog/manifest reads
- Unauthenticated manifest deletion - plus defensive CVE fingerprinting of the engine/containerd/runc triplet

Every script speaks the Docker Engine REST API or the Registry v2 protocol directly - real HTTP requests, real JSON parsing, real verdicts - and reports evidence-based findings.

All findings mask secret material; no container is started, stopped, or deleted by the probe itself (deletion probing targets a nonexistent probe object).

**Ports:** 2375/tcp (plain Docker Engine API), 2376/tcp (TLS Engine API), 5000/tcp (Registry v2) - any `docker`/`docker-registry` matched port | **Protocol:** Docker Engine REST API (v1.41) + Registry v2 (OCI distribution) | **Total lines of Lua:** 26,277

---

## 📋 Script Index

| # | Script | Risk Level | Category | Lines |
|---|--------|-----------|----------|-------|
| 1 | [docker-container-inspect-secrets](#1-docker-container-inspect-secrets---secrets-in-container-configuration) | 🔴 CRITICAL | vuln, discovery, safe | 1653 |
| 2 | [docker-privileged-containers](#2-docker-privileged-containers---privilegedcontainer-escape-preconditions) | 🔴 CRITICAL | vuln, safe | 1648 |
| 3 | [docker-socket-proxy-misconfig](#3-docker-socket-proxy-misconfig---socket-proxy-method-filtering) | 🔴 CRITICAL | vuln, safe | 1587 |
| 4 | [docker-unauthenticated-api](#4-docker-unauthenticated-api---unauthenticated-engine-api-detection) | 🔴 CRITICAL | vuln, auth, safe | 1691 |
| 5 | [docker-volume-host-mounts](#5-docker-volume-host-mounts---dangerous-host-volume-mounts) | 🔴 CRITICAL | vuln, discovery, safe | 1635 |
| 6 | [docker-debug-pprof-exposure](#6-docker-debug-pprof-exposure---go-pprof-debug-endpoints) | 🟠 HIGH | vuln, discovery, safe | 1627 |
| 7 | [docker-registry-delete-allowed](#7-docker-registry-delete-allowed---unauthenticated-manifest-deletion) | 🟠 HIGH | vuln, safe | 1615 |
| 8 | [docker-build-cache-leak](#8-docker-build-cache-leak---secrets-in-image-build-history) | 🟡 MEDIUM | vuln, discovery, safe | 1642 |
| 9 | [docker-cgroup-resource-limits](#9-docker-cgroup-resource-limits---missing-resource-limits) | 🟡 MEDIUM | vuln, safe | 1616 |
| 10 | [docker-daemon-security-opts](#10-docker-daemon-security-opts---daemon-hardening-options) | 🟡 MEDIUM | vuln, discovery, safe | 1648 |
| 11 | [docker-event-stream-exposure](#11-docker-event-stream-exposure---live-event-stream-surveillance) | 🟡 MEDIUM | vuln, discovery, safe | 1633 |
| 12 | [docker-network-host-mode](#12-docker-network-host-mode---host-networking-and-port-bindings) | 🟡 MEDIUM | vuln, discovery, safe | 1657 |
| 13 | [docker-registry-manifest-leak](#13-docker-registry-manifest-leak---secrets-in-registry-manifest-history) | 🟡 MEDIUM | vuln, discovery, safe | 1709 |
| 14 | [docker-registry-unauth-catalog](#14-docker-registry-unauth-catalog---unauthenticated-registry-catalog) | 🟡 MEDIUM | vuln, discovery, safe | 1624 |
| 15 | [docker-swarm-node-leak](#15-docker-swarm-node-leak---swarm-topology-and-join-tokens) | 🟡 MEDIUM | vuln, discovery, safe | 1648 |
| 16 | [docker-version-cve-fingerprint](#16-docker-version-cve-fingerprint---enginecontainerdrunc-cve-fingerprint) | 🟢 LOW | discovery, vuln, safe | 1644 |

---

### 1. **docker-container-inspect-secrets** - Secrets in Container Configuration
**Description:** Queries all active and stopped containers and scans their configuration metadata (Env, Labels, Cmd) with a rule set covering AWS keys, GitHub/Slack/Stripe tokens, generic passwords, connection strings, private keys, and JWTs. Every hit is masked in the report.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, discovery, safe

**What it checks:**
- /containers/json?all=1 inventory + per-container /containers/{id}/json
- env/label pair scanning against 20+ secret rules (aws-access-key-id, aws-secret-key, github-token, slack-token, db-password, connection-string, private-key-block, bearer-jwt, generic-secret, ...)
- value-shape validation (AKIA prefix, ghp_/xox/sk_live patterns, scheme://user:pass@)
- masking of all reported secret material (first 4 + last 4 chars, length)
- fleet-level summary: containers inspected, values found, worst severity

**How to Execute:**
```bash
# Basic scan
nmap -p 2375 --script docker-container-inspect-secrets target.example.com

# Bound the scan
nmap -p 2375 --script docker-container-inspect-secrets --script-args 'docker-container-inspect-secrets.max_containers=100 docker-container-inspect-secrets.timeout=15' target.example.com
```

**Sample Output:**
```
| docker-container-inspect-secrets:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - 5 plaintext secret(s) exposed in container configuration
|   Severity counts: CRITICAL=4 HIGH=2 MEDIUM=0 LOW=0 INFO=0
|   Weighted score: 54
|   Exposed Secrets (masked):
|     internal-builder | AWS_ACCESS_KEY_ID   | AKIA****MPLE (len=20) | aws-access-key-id | CRITICAL
|     internal-builder | AWS_SECRET_ACCESS_KEY | wJal****EKEY (len=40) | aws-secret-key  | CRITICAL
|     internal-builder | GITHUB_TOKEN        | ghp_****9876 (len=40) | github-token    | CRITICAL
|     internal-builder | DB_PASSWORD         | Pr0d****2024 (len=18) | db-password     | HIGH
|   Requests issued: 7
```

---

### 2. **docker-privileged-containers** - Privileged/Container Escape Preconditions
**Description:** Audits every container on an accessible Docker API for the execution-privilege preconditions that turn a container into a host root shell: privileged mode, dangerous capabilities, host device access, disabled seccomp/AppArmor, and escape-relevant mount bindings.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- HostConfig.Privileged = true (all capabilities + all host devices)
- CapAdd lists: SYS_ADMIN, SYS_PTRACE, SYS_RAWIO, SYS_MODULE, NET_ADMIN, SYS_BOOT with per-capability severity
- HostConfig.Devices: /dev/mem, /dev/sda, /dev/kmsg and other sensitive device passes
- SeccompProfileName / AppArmorProfile = unconfined
- Docker socket and host-root binds (cross-referenced with the mount scanner)
- missing resource limits and OomKillDisable as aggravating factors

**How to Execute:**
```bash
# Basic scan
nmap -p 2375 --script docker-privileged-containers target.example.com

# Bound the number of containers inspected
nmap -p 2375 --script docker-privileged-containers --script-args 'docker-privileged-containers.max_containers=50' target.example.com
```

**Sample Output:**
```
| docker-privileged-containers:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - 3 container(s) can escape to host root
|   Severity counts: CRITICAL=4 HIGH=3 MEDIUM=11 LOW=1 INFO=0
|   Findings:
|     [CRITICAL] api-gateway: HostConfig.Privileged = true - privileged container, trivial escape
|     [CRITICAL] internal-builder: Mounts = /var/run/docker.sock (rw)
|     [HIGH] api-gateway: HostConfig.Devices = /dev/mem - full host memory access
|     [HIGH] api-gateway: SeccompProfileName = unconfined
|     [MEDIUM] payment-db: PidsLimit = -1 - fork-bomb can exhaust host PIDs
|   Requests issued: 7
```

---

### 3. **docker-socket-proxy-misconfig** - Socket Proxy Method Filtering
**Description:** Tests Docker socket security proxies (tecnativa/docker-socket-proxy, HAProxy, Nginx Docker reverse proxies) for method-filtering misconfiguration: the proxy is supposed to allow only GET, and any accepted POST/PUT/DELETE/PATCH re-opens host root through the API surface.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- baseline: GET /_ping and GET /version reachability through the proxy
- write-verb probes with harmless payloads: POST /containers/create, POST /images/create, POST /build, PUT /images/<ref>/tag, DELETE on a nonexistent object
- verdict classification per probe: open (2xx/4xx that reached the daemon), filtered (403/405), unreachable
- aggregate verdict: how many of the write verbs reached the daemon surface

**How to Execute:**
```bash
# Basic scan
nmap -p 2375 --script docker-socket-proxy-misconfig target.example.com

# Tighter budget
nmap -p 2375 --script docker-socket-proxy-misconfig --script-args 'docker-socket-proxy-misconfig.maxrequests=12' target.example.com
```

**Sample Output:**
```
| docker-socket-proxy-misconfig:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - 5 mutating endpoint(s) reachable through the socket proxy
|   Severity counts: CRITICAL=6 HIGH=0 MEDIUM=0 LOW=0 INFO=0
|   Weighted score: 60
|   Write-Verb Probe Results:
|     method | endpoint                          | http-status | verdict
|     POST   | /containers/create                | 201         | open
|     POST   | /images/create                    | 200         | open
|     PUT    | /images/audit-probe/...           | 400         | open
|     DELETE | /containers/auditprobe...         | 404         | open
|   Findings:
|     [CRITICAL] Socket proxy does not filter mutating HTTP verbs
|   Remediation:
|     Deny mutating verbs: allow only GET (and at most HEAD); return 403/405 for POST, PUT, DELETE, PATCH.
```

---

### 4. **docker-unauthenticated-api** - Unauthenticated Engine API Detection
**Description:** Detects unauthenticated access to the Docker Engine REST API (the classic exposed 2375/2376 port) and maps exactly what the anonymous endpoint allows: engine version, daemon info, container inventory, and - critically - the write surface that implies host root code execution.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, auth, safe

**What it checks:**
- API version negotiation (GET /version) and daemon reachability (GET /info) with and without credentials
- unauthenticated read surface: container list, image list, network list
- write-surface implication mapping: POST /containers/create reachable with the same (absent) auth = host root
- swarm state, security options, storage driver and docker root directory disclosure
- TLS-terminated variants (2376) and 401/403 classification of a correctly gated daemon

**How to Execute:**
```bash
# Basic scan
nmap -p 2375 --script docker-unauthenticated-api target.example.com

# Custom request budget and timeout
nmap -p 2375 --script docker-unauthenticated-api --script-args 'docker-unauthenticated-api.maxrequests=10 docker-unauthenticated-api.timeout=15' target.example.com
```

**Sample Output:**
```
| docker-unauthenticated-api:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - Unauthenticated Docker Daemon API Exposed
|   Severity counts: CRITICAL=2 HIGH=1 MEDIUM=0 LOW=0 INFO=1
|   Weighted score: 30
|   Daemon Details:
|     Docker Engine Version: 20.10.7
|     API Version: 1.41
|     Operating System: Ubuntu 20.04.6 LTS
|   Findings:
|     [CRITICAL] Docker Engine API is fully accessible without credentials (/info)
|     [CRITICAL] Unauthenticated container creation would allow host root code execution
|     [HIGH] Docker Swarm is active on this daemon and its topology is readable unauthenticated
|   Requests issued: 5
```

---

### 5. **docker-volume-host-mounts** - Dangerous Host Volume Mounts
**Description:** Inspects storage mounts and host filesystem binds across all containers and flags the exposures that give a workload access to the host: the Docker daemon socket, the root filesystem, /etc, /var, home directories, and other sensitive paths - with read/write mode and severity per mount.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, discovery, safe

**What it checks:**
- /var/run/docker.sock or /run/docker.sock binds (rw = instant daemon control, ro = information)
- / or / host-root binds (ro = full host read; rw = full host write)
- /etc, /var, /home, /root, /boot, /lib, /usr, /sys, /proc binds with path-classification
- named-volume vs bind classification and RW/Mode parsing
- fleet-level summary: critical (socket/root) count vs sensitive count

**How to Execute:**
```bash
# Basic scan
nmap -p 2375 --script docker-volume-host-mounts target.example.com

# Inspect more containers per run
nmap -p 2375 --script docker-volume-host-mounts --script-args 'docker-volume-host-mounts.max_containers=50' target.example.com
```

**Sample Output:**
```
| docker-volume-host-mounts:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - 2 critical host mount(s) (Docker socket or host root)
|   Severity counts: CRITICAL=3 HIGH=1 MEDIUM=0 LOW=0 INFO=0
|   Sensitive Mounts:
|     container        | host-source         | container-dest | mode | severity
|     internal-builder | /var/run/docker.sock| /var/run/docker.sock | rw | CRITICAL
|     legacy-cache     | /                   | /host-root     | ro | CRITICAL
|     legacy-cache     | /etc                | /host-etc      | rw | HIGH
|   Fleet Summary:
|     Critical (socket/root) mounts: 2
|     Sensitive mount findings: 3
|   Requests issued: 7
```

---

### 6. **docker-debug-pprof-exposure** - Go pprof Debug Endpoints
**Description:** Probes the daemon and container-management endpoints for exposed Go runtime profiling endpoints (/debug/pprof/*, /debug/vars). These debug interfaces leak the daemon command line, runtime flags, goroutine stacks, and memory statistics.

**Risk Level:** 🟠 HIGH | **Category:** vuln, discovery, safe

**What it checks:**
- /debug/pprof index (lists available profiles)
- /debug/pprof/cmdline (daemon command line - hosts, flags, tokens)
- /debug/pprof/flags (runtime flag JSON)
- /debug/pprof/goroutine (stack trace of every daemon goroutine)
- /debug/vars (expvar runtime counters)
- per-endpoint EXPOSED/BLOCKED/NOT FOUND verdicts plus extracted details

**How to Execute:**
```bash
# Basic scan
nmap -p 2375 --script docker-debug-pprof-exposure target.example.com

# Custom endpoint root (some proxies mount pprof elsewhere)
nmap -p 2375 --script docker-debug-pprof-exposure --script-args 'docker-debug-pprof-exposure.maxrequests=12' target.example.com
```

**Sample Output:**
```
| docker-debug-pprof-exposure:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - 5 Go runtime profiling endpoint(s) exposed on the daemon
|   Severity counts: CRITICAL=0 HIGH=6 MEDIUM=0 LOW=0 INFO=0
|   Endpoint Verdicts:
|     /debug/pprof            | EXPOSED
|     /debug/pprof/cmdline    | EXPOSED
|     /debug/pprof/flags      | EXPOSED
|     /debug/pprof/goroutine  | EXPOSED
|     /debug/vars             | EXPOSED
|   Exposed Detail:
|     /debug/pprof/cmdline: dockerd --host tcp://0.0.0.0:2375 --iptables true --debug
|     /debug/pprof/goroutine: active goroutines=42
|   Requests issued: 5
```

---

### 7. **docker-registry-delete-allowed** - Unauthenticated Manifest Deletion
**Description:** Evaluates whether a Docker Registry v2 endpoint permits unauthenticated DELETE requests. Probes a deliberately nonexistent repository so that a real registry never deletes a real image: 404 = deletion enabled but object unknown (open), 405 = deletion disabled, 401/403 = auth-gated.

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Registry v2 API identity (GET /v2/)
- tag listing on the probe repository (context: how much is visible)
- DELETE /v2/<probe-repo>/manifests/<probe-ref> once and classifies:
  - 202 = deletion accepted (CRITICAL, real objects would be destroyed)
  - 404 = deletion enabled, probe object not found, no auth gate (HIGH)
  - 405 = deletion disabled by configuration (NOT VULNERABLE)
  - 401/403 = authentication-gated (NOT VULNERABLE)
- explicit-destructive mode only when repo=, tag= and confirm=true are all supplied

**How to Execute:**
```bash
# Basic scan (non-destructive probe of a nonexistent object)
nmap -p 5000 --script docker-registry-delete-allowed target.example.com

# Target a specific repository/tag (requires explicit confirmation)
nmap -p 5000 --script docker-registry-delete-allowed --script-args 'docker-registry-delete-allowed.repo=acme/web-frontend docker-registry-delete-allowed.tag=v1.2.3 docker-registry-delete-allowed.confirm=true' target.example.com
```

**Sample Output:**
```
| docker-registry-delete-allowed:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - unauthenticated DELETE is permitted (probe object not found, no auth gate)
|   Severity counts: CRITICAL=0 HIGH=1 MEDIUM=0 LOW=0 INFO=2
|   Probe Sequence:
|     GET    | /v2/audit-probe-nonexistent-repo/tags/list      | 200 | 3 tag(s) visible
|     DELETE | /v2/audit-probe-nonexistent-repo/manifests/...  | 404 |
|   Findings:
|     [HIGH] Registry permits unauthenticated DELETE on manifests
|     [evidence: status=404: the probe repository does not exist, but the request was not rejected
|            for authorization or disabled configuration - any existing tag is deletable]
|   Requests issued: 3
```

---

### 8. **docker-build-cache-leak** - Secrets in Image Build History
**Description:** Enumerates images (including dangling/intermediate ones) and inspects their build history for residual secrets: ENV lines with keys, ARG values, and RUN commands containing curl basic-auth, Bearer JWTs, AWS keys, or vendor tokens. Image history is an append-only ledger - deleting the file later does not remove the history.

**Risk Level:** 🟡 MEDIUM | **Category:** vuln, discovery, safe

**What it checks:**
- /images/json?all=1 listing (tagged + dangling)
- per-image /images/{id}/history and rule scanning of every CreatedBy step:
  - aws-key-in-build (AKIA...), aws-secret-in-build (ENV AWS_SECRET_ACCESS_KEY=...)
  - github/slack/stripe tokens in ARG and RUN
  - basic-auth in curl (-u user:pass, --basic-auth)
  - Bearer/JWT in RUN steps, private keys, pass-in-url patterns
- dangling-image detection (RepoTags null) as a LOW signal
- masked output of every leaking step

**How to Execute:**
```bash
# Basic scan
nmap -p 2375 --script docker-build-cache-leak target.example.com

# Scan more images (default 20, max 50)
nmap -p 2375 --script docker-build-cache-leak --script-args 'docker-build-cache-leak.max_images=50' target.example.com
```

**Sample Output:**
```
| docker-build-cache-leak:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - 20 build step(s) leak secret material in image history
|   Severity counts: CRITICAL=10 HIGH=10 MEDIUM=1 LOW=1 INFO=0
|   Findings:
|     [CRITICAL] Build step in golang:1.17-builder leaks aws-secret-in-build
|     [CRITICAL] Build step in postgres:13 leaks stripe-token-in-build (ARG API_KEY=sk_live_****)
|     [HIGH] Build step in nginx:1.21 leaks basic-auth-in-curl (RUN curl -u deploy:****)
|     [HIGH] Build step in acme/internal-builder:latest leaks bearer-in-build
|     [LOW] Dangling image sha256:aaa111bbb222 (abandoned build stage)
|   Scan Summary:
|     Images listed: 5 | Images scanned: 5 | Leaking steps: 20
```

---

### 9. **docker-cgroup-resource-limits** - Missing Resource Limits
**Description:** Audits containers for missing cgroup resource limits (memory, CPU, PID) that let a single workload starve or crash the host: Memory=0, NanoCpus/CpuShares=0, PidsLimit=0/-1, and OomKillDisable=true.

**Risk Level:** 🟡 MEDIUM | **Category:** vuln, safe

**What it checks:**
- Memory = 0 (unlimited - runaway allocations OOM-kill host processes)
- NanoCpus = 0 and CpuShares = 0 (unlimited CPU starvation)
- PidsLimit = 0 or -1 (fork-bomb can exhaust host PIDs)
- OomKillDisable = true (memory overuse no longer self-mitigating)
- fleet summary of limit gaps across inspected containers

**How to Execute:**
```bash
# Basic scan
nmap -p 2375 --script docker-cgroup-resource-limits target.example.com

# Inspect up to 100 containers
nmap -p 2375 --script docker-cgroup-resource-limits --script-args 'docker-cgroup-resource-limits.max_containers=100' target.example.com
```

**Sample Output:**
```
| docker-cgroup-resource-limits:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - 10 missing resource limit(s) across inspected containers
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=10 LOW=1 INFO=0
|   Weighted score: 42
|   Findings:
|     [MEDIUM] api-gateway: no Memory limit - runaway allocations can OOM-kill host processes
|     [MEDIUM] payment-db: PidsLimit = -1 - fork-bomb can exhaust host PIDs
|     [LOW] payment-db: OomKillDisable = true
|   Requests issued: 7
```

---

### 10. **docker-daemon-security-opts** - Daemon Hardening Options
**Description:** Evaluates the host-level Docker daemon security options from /info: seccomp default profile, AppArmor/SELinux mandatory access control, user namespace remapping, live-restore, and other hardening flags from the CIS Docker Benchmark baseline.

**Risk Level:** 🟡 MEDIUM | **Category:** vuln, discovery, safe

**What it checks:**
- SecurityOptions parsing (name=seccomp profile, name=apparmor, name=selinux)
- default seccomp profile present or non-default/absent
- MAC enforced (AppArmor or SELinux) or missing
- user namespace remapping (idmap driver / userns) detection
- live-restore, cgroup driver, and storage driver context lines
- hardening-matrix gap count with per-option evidence

**How to Execute:**
```bash
# Basic scan
nmap -p 2375 --script docker-daemon-security-opts target.example.com

# Custom budget
nmap -p 2375 --script docker-daemon-security-opts --script-args 'docker-daemon-security-opts.maxrequests=8 docker-daemon-security-opts.timeout=15' target.example.com
```

**Sample Output:**
```
| docker-daemon-security-opts:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - 3 daemon hardening gap(s) (seccomp/MAC/userns)
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=3 LOW=1 INFO=1
|   Findings:
|     [MEDIUM] Daemon hardening baseline is not met - 3 gap(s) in the hardening matrix
|     [MEDIUM] Daemon uses a non-default seccomp profile
|     [MEDIUM] No AppArmor or SELinux mandatory access control on the daemon
|     [LOW] User namespace remapping not detected
|   Requests issued: 2
```

---

### 11. **docker-event-stream-exposure** - Live Event Stream Surveillance
**Description:** Evaluates whether the Docker daemon /events streaming endpoint is accessible without authentication. The events stream delivers a real-time feed of container starts/stops, image pulls, exec creation, and network changes - passive surveillance of the whole host.

**Risk Level:** 🟡 MEDIUM | **Category:** vuln, discovery, safe

**What it checks:**
- bounded read of /events (never hangs: max_events cap, maxrequests cap)
- event count and type classification (container/image/network/exec)
- 401/403 = gated, 200 + events = open stream
- sensitive action extraction (exec_create, image pull, container start)

**How to Execute:**
```bash
# Basic scan
nmap -p 2375 --script docker-event-stream-exposure target.example.com

# Read more events before closing the stream
nmap -p 2375 --script docker-event-stream-exposure --script-args 'docker-event-stream-exposure.max_events=100' target.example.com
```

**Sample Output:**
```
| docker-event-stream-exposure:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - unauthenticated event stream delivering live daemon events
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=0 INFO=1
|   Weighted score: 5
|   Findings:
|     [MEDIUM] Docker event stream is readable without credentials (passive surveillance)
|     [evidence: 4 event(s) received on first bounded read]
|   Event Types:
|     container: 2 | image: 1 | network: 1
|   Requests issued: 2
```

---

### 12. **docker-network-host-mode** - Host Networking and Port Bindings
**Description:** Audits container network configurations: host networking (shared network namespace and loopback), containers binding ports to non-loopback addresses (0.0.0.0), and bridge networks with inter-container communication enabled.

**Risk Level:** 🟡 MEDIUM | **Category:** vuln, discovery, safe

**What it checks:**
- HostConfig.NetworkMode = host (container shares host netns, can reach 127.0.0.1 services)
- Ports bound to non-loopback HostIp (0.0.0.0 exposure of internal services)
- /networks listing: bridge networks with com.docker.network.bridge.icc=true
- fleet summary: host-networked count, wide-port bindings, ICC bridges

**How to Execute:**
```bash
# Basic scan
nmap -p 2375 --script docker-network-host-mode target.example.com

# Inspect more containers
nmap -p 2375 --script docker-network-host-mode --script-args 'docker-network-host-mode.max_containers=50' target.example.com
```

**Sample Output:**
```
| docker-network-host-mode:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - 1 host-networked, 3 wide-port, 1 ICC-enabled network issue(s)
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=6 LOW=0 INFO=0
|   Findings:
|     [MEDIUM] web-frontend: NetworkMode = host - shares the host network namespace
|     [MEDIUM] api-gateway binds 1 port(s) to non-loopback addresses - 0.0.0.0:8080
|     [MEDIUM] Bridge network bridge allows inter-container communication (icc=true)
|   Requests issued: 8
```

---

### 13. **docker-registry-manifest-leak** - Secrets in Registry Manifest History
**Description:** Connects to a Registry v2, enumerates tags (auto-selecting the first catalog repository when none is supplied), downloads manifests, and scans the embedded v1Compatibility history and config env for leaked secrets - the registry-side twin of the build-cache-leak scan.

**Risk Level:** 🟡 MEDIUM | **Category:** vuln, discovery, safe

**What it checks:**
- /v2/ identity, /v2/_catalog auto-repository selection, /v2/<repo>/tags/list
- manifest download with correct Accept headers (schema v2 + OCI)
- nested v1Compatibility JSON decode per history entry
- env and created_by rule scanning (same rule set as container-inspect-secrets)
- per-tag CRITICAL/HIGH findings with masked values, tag scan summary

**How to Execute:**
```bash
# Basic scan (auto-selects first repository from the catalog)
nmap -p 5000 --script docker-registry-manifest-leak target.example.com

# Target a specific repository and scan more tags
nmap -p 5000 --script docker-registry-manifest-leak --script-args 'docker-registry-manifest-leak.repo=acme/api-gateway docker-registry-manifest-leak.max_tags=10' target.example.com
```

**Sample Output:**
```
| docker-registry-manifest-leak:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - 9 secret(s) exposed in manifest history of acme/api-gateway
|   Severity counts: CRITICAL=3 HIGH=6 MEDIUM=1 LOW=3 INFO=1
|   Weighted score: 83
|   Leaking History Entries (masked):
|     acme/api-gateway:latest | env AWS_ACCESS_KEY_ID | CRITICAL | aws-access-key-id | AKIA****MPLE
|     acme/api-gateway:latest | env DB_PASSWORD       | HIGH     | db-password     | Pr0d****2024
|     acme/api-gateway:latest | 2                     | HIGH     | basic-auth-in-curl
|   Scan Summary:
|     Manifests read: 3 | Tags available: 3 | Tags scanned: 3 | Leaking entries: 9
```

---

### 14. **docker-registry-unauth-catalog** - Unauthenticated Registry Catalog
**Description:** Detects unauthenticated Docker Registry v2 services and enumerates the hosted private container repositories via /v2/_catalog, plus per-repository tag lists. An open catalog on a private registry exposes the full inventory of internal images and is the first step toward manifest/blob exfiltration.

**Risk Level:** 🟡 MEDIUM | **Category:** vuln, discovery, safe

**What it checks:**
- /v2/ API identity with the Docker-Distribution-Api-Version header
- /v2/_catalog without credentials (paginated, bounded by max_repos)
- tag listing for a bounded set of repositories
- 401/403 classification of a correctly gated registry

**How to Execute:**
```bash
# Basic scan
nmap -p 5000 --script docker-registry-unauth-catalog target.example.com

# Enumerate more repositories (default 50, max 500)
nmap -p 5000 --script docker-registry-unauth-catalog --script-args 'docker-registry-unauth-catalog.max_repos=200' target.example.com
```

**Sample Output:**
```
| docker-registry-unauth-catalog:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - unauthenticated catalog exposes 5 repository(ies)
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=0 INFO=1
|   Weighted score: 5
|   Findings:
|     [MEDIUM] Registry catalog is readable without credentials
|     [evidence: 5 repository(ies) enumerable; pull access on the same endpoint is typically open too]
|   Catalog:
|     acme/api-gateway, acme/internal-builder, acme/legacy-cache, acme/payment-db, acme/web-frontend
|   Requests issued: 2
```

---

### 15. **docker-swarm-node-leak** - Swarm Topology and Join Tokens
**Description:** Queries an unauthenticated daemon for Docker Swarm state and extracts the sensitive topology: cluster ID, node inventory with manager/worker roles and addresses, service inventory, and the worker/manager join tokens (masked in the report).

**Risk Level:** 🟡 MEDIUM | **Category:** vuln, discovery, safe

**What it checks:**
- /info LocalNodeState (active/inactive) as the swarm-active gate
- /swarm full state: cluster ID, NodeID, manager leader
- node inventory: hostname, ManagerAddr, role (manager/worker), status
- service inventory (names, task counts)
- JoinTokens: worker and manager join tokens - masked, with impact note (a full token read allows joining the cluster)

**How to Execute:**
```bash
# Basic scan
nmap -p 2375 --script docker-swarm-node-leak target.example.com

# Custom budget
nmap -p 2375 --script docker-swarm-node-leak --script-args 'docker-swarm-node-leak.maxrequests=8 docker-swarm-node-leak.timeout=15' target.example.com
```

**Sample Output:**
```
| docker-swarm-node-leak:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - Swarm cluster topology and join tokens readable without credentials
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=3 LOW=0 INFO=1
|   Weighted score: 13
|   Findings:
|     [MEDIUM] Swarm cluster is active and its full state is readable unauthenticated
|     [MEDIUM] Swarm join tokens are exposed (masked in this report)
|     [evidence: worker=SWMTKN-1-3z1**** manager=SWMTKN-1-9x8**** - a full token read
|            allows joining the cluster and running workloads on every node]
|     [MEDIUM] Swarm node inventory exposed (3 node(s): 1 manager, 2 worker)
|   Requests issued: 2
```

---

### 16. **docker-version-cve-fingerprint** - Engine/Containerd/Runc CVE Fingerprint
**Description:** Extracts the Docker Engine, containerd, and runc component versions from /version and performs defensive fingerprinting against a built-in table of critical container CVEs (runc breakouts, engine flaws). Reports per-CVE POSSIBLY AFFECTED / not affected verdicts - a starting point, not a vulnerability scanner (cross-check current advisories).

**Risk Level:** 🟢 LOW | **Category:** discovery, vuln, safe

**What it checks:**
- /version component table (Engine, containerd, runc with versions)
- version comparison with proper pre-release ordering (1.0.1 > 1.0-rc8)
- built-in CVE table: CVE-2024-21626, CVE-2023-25807 (runc workdir breakouts), CVE-2020-13401 (Swarm IPv6 RA spoofing), CVE-2020-15228, CVE-2019-5736, CVE-2019-14271, CVE-2018-15664
- per-CVE verdict rows: component, running version, fixed version, status
- LOW findings only for POSSIBLY AFFECTED rows (defensive posture)

**How to Execute:**
```bash
# Basic scan
nmap -p 2375 --script docker-version-cve-fingerprint target.example.com

# Custom budget
nmap -p 2375 --script docker-version-cve-fingerprint --script-args 'docker-version-cve-fingerprint.maxrequests=8' target.example.com
```

**Sample Output:**
```
| docker-version-cve-fingerprint:
|   Risk Level: 🟢 LOW
|   Status: FINGERPRINT - 3 component version(s) possibly affected by known container CVEs
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=0 LOW=4 INFO=4
|   CVE Comparison Table:
|     cve           | component | running | fixed   | status
|     CVE-2024-21626| runc      | 1.0.1   | 1.1.12  | POSSIBLY AFFECTED
|     CVE-2023-25807| runc      | 1.0.1   | 1.1.12  | POSSIBLY AFFECTED
|     CVE-2020-13401| engine    | 20.10.7 | 20.10.8 | POSSIBLY AFFECTED
|     CVE-2019-5736 | runc      | 1.0.1   | 1.0-rc4 | not affected
|     CVE-2018-15664| runc      | 1.0.1   | 1.0-rc8 | not affected
|   Component Versions:
|     engine: 20.10.7 | containerd: 1.5.13 | runc: 1.0.1
|   Requests issued: 3
```

## 🔒 Safe & Non-Destructive

- All 16 scripts are **read-only** against real state. The only write-verb probes (socket-proxy, delete-allowed) use **nonexistent probe objects** or **harmless dummy payloads** so a real host is never modified and no real image/manifest/container is touched.
- All secret material is **masked** in output (prefix/suffix + length).
- Every scan is **budget-bounded** (`maxrequests`, `timeout`, `max_containers`, `max_images`, `max_tags`, `max_repos`, `max_events` script-args).
- Scripts that need an open API classify 401/403 cleanly as NOT VULNERABLE instead of erroring.

## 🧰 Common script-args (all scripts)

| Arg | Default | Meaning |
|-----|---------|---------|
| `<script>.maxrequests` | 6-40 | total request budget for the scan |
| `<script>.timeout` | 10 | per-request timeout in seconds |
| `<script>.max_containers` | 25-30 | max containers to inspect (container scripts) |
| `<script>.max_images` | 20 | max images to history-scan (build-cache-leak, max 50) |
| `<script>.max_tags` | 3 | max tags to scan per repository (manifest-leak, max 20) |
| `<script>.max_repos` | 50 | max repositories to enumerate (unauth-catalog, max 500) |
| `<script>.max_events` | 50 | max events to read from /events (event-stream, max 200) |
| `<script>.repo` / `<script>.tag` / `<script>.confirm` | - | explicit registry targets (delete-allowed; destructive only with confirm=true) |
