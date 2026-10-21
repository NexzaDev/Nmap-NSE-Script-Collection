# ☸️ Kubernetes Security Audits

**16 Nmap NSE scripts** for auditing Kubernetes control planes and node surfaces directly on the wire:

**Covers:**

- A complete HTTP/1.1 client with JSON codec and chunked-transfer decoding
- A Kubernetes knowledge layer (API/kubelet/etcd/kube-proxy path maps, version-to-CVE advisory mapping, JWT service-account token analysis with base64url decoding and kubernetes.io claim extraction, pod-security analysis for privileged containers, host namespaces and dangerous Linux capabilities, admission webhook configuration summaries, Prometheus metrics parsing, dashboard marker detection and OpenAPI surface summarisation) and a budgeted session transport with Bearer-token support and TLS-greeting detection

**The suite covers the cluster attack surface that matters:**

- Unauthenticated API reachability and anonymous-auth posture
- Etcd keyspace exposure
- The kubelet read-only port and anonymous control surface (the exec precondition)
- Metrics/debug endpoint leaks
- Node-proxy relay misconfiguration
- Dashboard authentication posture
- Admission webhook fail-open policies and Pod Security Standard signals

**Every probe is bounded and non-destructive:**

- GET requests only
- No writes or exec calls are ever issued
- Local-only analysis (token parsing, pod security scoring) never contacts the issuer.

**Ports:** 6443, 8443, 2379, 9153, 10250, 10255, 10256 (tcp) | **Protocols:** Kubernetes API (HTTP/JSON), etcd v2 API, kubelet/kube-proxy HTTP surfaces, JWT | **Total lines of Lua:** 24,758

---

## 📋 Script Index

| # | Script | Risk Level | Category | Lines |
|---|--------|-----------|----------|-------|
| 1 | [k8s-api-unauthenticated-access](#1-k8s-api-unauthenticated-access---unauthenticated-api-surface-mapping) | 🔴 CRITICAL | vuln, safe | 1546 |
| 2 | [k8s-dashboard-unauth-access](#2-k8s-dashboard-unauth-access---kubernetes-dashboard-authentication-posture) | 🔴 CRITICAL | vuln, safe | 1544 |
| 3 | [k8s-etcd-unauth-keyspace](#3-k8s-etcd-unauth-keyspace---etcd-unauthenticated-keyspace-probe) | 🔴 CRITICAL | vuln, safe | 1537 |
| 4 | [k8s-kubelet-readonly-pods](#4-k8s-kubelet-readonly-pods---kubelet-read-only-port-pod-disclosure) | 🔴 CRITICAL | vuln, safe | 1529 |
| 5 | [k8s-kubelet-unauth-exec](#5-k8s-kubelet-unauth-exec---kubelet-unauthenticated-control-surface-exec-precondition) | 🔴 CRITICAL | vuln, safe | 1544 |
| 6 | [k8s-anonymous-auth-enabled](#6-k8s-anonymous-auth-enabled---anonymous-authentication-posture-probe) | 🟠 HIGH | vuln, safe | 1540 |
| 7 | [k8s-node-proxy-misconfig](#7-k8s-node-proxy-misconfig---node-proxy-relay-misconfiguration) | 🟠 HIGH | vuln, safe | 1552 |
| 8 | [k8s-serviceaccount-token-probe](#8-k8s-serviceaccount-token-probe---service-account-inventory--jwt-token-analysis) | 🟠 HIGH | vuln, safe | 1591 |
| 9 | [k8s-admission-webhook-audit](#9-k8s-admission-webhook-audit---admission-webhook-configuration-audit) | 🟡 MEDIUM | defensive, safe | 1568 |
| 10 | [k8s-cni-portmap-exposure](#10-k8s-cni-portmap-exposure---cni-port-mapping-exposure-signals) | 🟡 MEDIUM | defensive, safe | 1558 |
| 11 | [k8s-kube-proxy-debug-leak](#11-k8s-kube-proxy-debug-leak---kube-proxy-debug-surface-leak) | 🟡 MEDIUM | discovery, safe | 1532 |
| 12 | [k8s-metrics-token-leak](#12-k8s-metrics-token-leak---kubelet-metrics-token-less-exposure) | 🟡 MEDIUM | discovery, safe | 1539 |
| 13 | [k8s-openapi-spec-leak](#13-k8s-openapi-spec-leak---openapi-schema-disclosure) | 🟡 MEDIUM | discovery, safe | 1547 |
| 14 | [k8s-pod-security-standards](#14-k8s-pod-security-standards---pod-security-standards-workload-audit) | 🟡 MEDIUM | defensive, safe | 1572 |
| 15 | [k8s-coredns-metrics-exposure](#15-k8s-coredns-metrics-exposure---coredns-metrics-exposure) | 🟢 LOW | discovery, safe | 1528 |
| 16 | [k8s-version-fingerprint](#16-k8s-version-fingerprint---api-server-version-fingerprint--advisory-mapping) | 🟢 LOW | discovery, safe | 1531 |

---

### 1. **k8s-api-unauthenticated-access** - Unauthenticated API Surface Mapping
**Description:** Probes the unauthenticated API surface with a bounded probe set:

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Sends anonymous GETs to pods, nodes, serviceaccounts, openapi.
- Records status and object kind per probe.
- Grades the exposure from the reachable object kinds.
- Why it matters: Pod/node/serviceaccount reads give an attacker the workload map and service-account inventory - the inputs for privilege escalation. The 2021-era cluster takeovers started from exactly such exposed API endpoints.
- Safety: four read-only GETs.

**How to Execute:**
```bash
nmap -p 6443 --script k8s-api-unauthenticated-access api01.cluster.example.com

# Tuned request budget
nmap -p 6443 --script k8s-api-unauthenticated-access --script-args 'k8s-api-unauthenticated-access.timeout=8,k8s-api-unauthenticated-access.maxrequests=24,k8s-api-unauthenticated-access.token=' api01.cluster.example.com
```

**Sample Output:**
```
| k8s-api-unauthenticated-access:
|   Risk Level: 🔴 CRITICAL
|   Status: SECURE - all 4 anonymous API probes refused
```

---

### 2. **k8s-dashboard-unauth-access** - Kubernetes Dashboard Authentication Posture
**Description:** Grades the Kubernetes Dashboard authentication posture: a plaintext

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- GET / and inspects for dashboard markers versus login gating.
- Follows with a /login probe to classify the response mode.
- Grades the dashboard exposure.
- Why it matters: The Dashboard supports SKIP login historically; an overview served without authentication is full cluster UI control for any peer. Exposed dashboards were the Tesla 2018 cryptojacking entry point.
- Safety: two read-only GETs; no login attempts.

**How to Execute:**
```bash
nmap -p 6443 --script k8s-dashboard-unauth-access api01.cluster.example.com

# Tuned request budget
nmap -p 6443 --script k8s-dashboard-unauth-access --script-args 'k8s-dashboard-unauth-access.timeout=8,k8s-dashboard-unauth-access.maxrequests=24,k8s-dashboard-unauth-access.token=' api01.cluster.example.com
```

**Sample Output:**
```
| k8s-dashboard-unauth-access:
|   Risk Level: 🔴 CRITICAL
|   Status: INFORMATIONAL - Kubernetes audit incomplete: dashboard root request failed
```

---

### 3. **k8s-etcd-unauth-keyspace** - etcd Unauthenticated Keyspace Probe
**Description:** Checks whether the etcd datastore answers unauthenticated API

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- GET /version for the etcd release.
- GET /v2/keys?prefix=true (bounded response) for anonymous reads.
- Grades keyspace exposure.
- Why it matters: Open etcd equals full cluster compromise: every secret, token and config object lives in the keyspace. Exposed 2379 is the single most critical Kubernetes finding class.
- Safety: two read-only GETs; no writes and no deep traversal.

**How to Execute:**
```bash
nmap -p 6443 --script k8s-etcd-unauth-keyspace api01.cluster.example.com

# Tuned request budget
nmap -p 6443 --script k8s-etcd-unauth-keyspace --script-args 'k8s-etcd-unauth-keyspace.timeout=8,k8s-etcd-unauth-keyspace.maxrequests=24,k8s-etcd-unauth-keyspace.token=' api01.cluster.example.com
```

**Sample Output:**
```
| k8s-etcd-unauth-keyspace:
|   Risk Level: 🔴 CRITICAL
|   Status: SECURE - etcd keyspace not readable (no successful anonymous answer)
```

---

### 4. **k8s-kubelet-readonly-pods** - kubelet Read-Only Port Pod Disclosure
**Description:** Checks the kubelet read-only port (10255): anonymous /pods listing

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- GET /pods on 10255 without credentials.
- Summarises the disclosed pod inventory.
- Grades the read-only port exposure.
- Why it matters: 10255 predates kubelet authentication; an open read-only port discloses the entire node workload inventory including secret volume mounts and environment variables. CIS Kubernetes Benchmark explicitly requires this port disabled.
- Safety: one read-only GET.

**How to Execute:**
```bash
nmap -p 6443 --script k8s-kubelet-readonly-pods api01.cluster.example.com

# Tuned request budget
nmap -p 6443 --script k8s-kubelet-readonly-pods --script-args 'k8s-kubelet-readonly-pods.timeout=8,k8s-kubelet-readonly-pods.maxrequests=24,k8s-kubelet-readonly-pods.token=' api01.cluster.example.com
```

**Sample Output:**
```
| k8s-kubelet-readonly-pods:
|   Risk Level: 🔴 CRITICAL
|   Status: SECURE - kubelet read-only port did not answer
```

---

### 5. **k8s-kubelet-unauth-exec** - kubelet Unauthenticated Control Surface (exec precondition)
**Description:** Probes the kubelet secure port for an unauthenticated control surface:

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- GET /pods and /runningpods/ without credentials on 10250.
- Detects TLS-only behaviour for transport grading.
- Grades the anonymous kubelet surface (exec precondition).
- Why it matters: Kubelet 10250 with anonymous reads plus always-allow authorization is the 2018-class full node takeover path (exec included). Verifying the read surface proves whether anonymous kubelet access is possible at all.
- Safety: two read-only GETs; exec is never invoked.

**How to Execute:**
```bash
nmap -p 6443 --script k8s-kubelet-unauth-exec api01.cluster.example.com

# Tuned request budget
nmap -p 6443 --script k8s-kubelet-unauth-exec --script-args 'k8s-kubelet-unauth-exec.timeout=8,k8s-kubelet-unauth-exec.maxrequests=24,k8s-kubelet-unauth-exec.token=' api01.cluster.example.com
```

**Sample Output:**
```
| k8s-kubelet-unauth-exec:
|   Risk Level: 🔴 CRITICAL
|   Status: 
```

---

### 6. **k8s-anonymous-auth-enabled** - Anonymous Authentication Posture Probe
**Description:** Tests whether the API server serves namespace listings to

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- GET /api/v1/namespaces without credentials.
- Grades 200 (anonymous listing) vs 401/403 (auth enforced).
- Optionally re-probes with the Bearer token script-arg.
- Why it matters: --anonymous-auth=true plus permissive RBAC lets any network peer enumerate clusters and reach the API surface. Namespace enumeration is the first authenticated-looking step an attacker takes without credentials.
- Safety: one read-only GET.

**How to Execute:**
```bash
nmap -p 6443 --script k8s-anonymous-auth-enabled api01.cluster.example.com

# Tuned request budget
nmap -p 6443 --script k8s-anonymous-auth-enabled --script-args 'k8s-anonymous-auth-enabled.timeout=8,k8s-anonymous-auth-enabled.maxrequests=24,k8s-anonymous-auth-enabled.token=' api01.cluster.example.com
```

**Sample Output:**
```
| k8s-anonymous-auth-enabled:
|   Risk Level: 🟠 HIGH
|   Status: INFORMATIONAL - Kubernetes audit incomplete: namespaces request failed
```

---

### 7. **k8s-node-proxy-misconfig** - Node Proxy Relay Misconfiguration
**Description:** Tests the node proxy path: anonymous reads of the node list followed

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- GET /api/v1/nodes anonymously and takes the first node name.
- Probes /api/v1/nodes/<name>/proxy/healthz (read-only healthz).
- Grades the relay exposure.
- Why it matters: Working anonymous node-proxy access turns the API server into a relay into every kubelet - full node command surface without credentials. It is the historical upgrade-bypass vector (CVE-2018-1002105).
- Safety: two read-only GETs; only healthz is requested.

**How to Execute:**
```bash
nmap -p 6443 --script k8s-node-proxy-misconfig api01.cluster.example.com

# Tuned request budget
nmap -p 6443 --script k8s-node-proxy-misconfig --script-args 'k8s-node-proxy-misconfig.timeout=8,k8s-node-proxy-misconfig.maxrequests=24,k8s-node-proxy-misconfig.token=' api01.cluster.example.com
```

**Sample Output:**
```
| k8s-node-proxy-misconfig:
|   Risk Level: 🟠 HIGH
|   Status: SECURE - node list not readable without credentials; proxy relay path closed
```

---

### 8. **k8s-serviceaccount-token-probe** - Service-Account Inventory & JWT Token Analysis
**Description:** Probes the service-account inventory and analyses JWT tokens: lists

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- GET /api/v1/serviceaccounts and counts readable accounts.
- Parses the token script-arg JWT locally (no validation calls).
- Grades inventory and token hygiene.
- Why it matters: Projected and legacy SA tokens are bearer credentials; inventory plus expiry analysis drives the token-hygiene audit. Legacy long-lived SA secrets are a standing takeover risk.
- Safety: one read-only GET plus local token parsing.

**How to Execute:**
```bash
nmap -p 6443 --script k8s-serviceaccount-token-probe api01.cluster.example.com

# Tuned request budget
nmap -p 6443 --script k8s-serviceaccount-token-probe --script-args 'k8s-serviceaccount-token-probe.timeout=8,k8s-serviceaccount-token-probe.maxrequests=24,k8s-serviceaccount-token-probe.token=' api01.cluster.example.com
```

**Sample Output:**
```
| k8s-serviceaccount-token-probe:
|   Risk Level: 🟠 HIGH
|   Status: SECURE - service account inventory not readable without credentials
```

---

### 9. **k8s-admission-webhook-audit** - Admission Webhook Configuration Audit
**Description:** Reads the admission webhook configurations (validating and mutating)

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- GET validating + mutating webhook configuration lists.
- Summarises each webhook's failure/match policy and scope.
- Grades policy enforcement risk (Ignore policies flagged).
- Why it matters: failurePolicy=Ignore webhooks silently disable policy enforcement when the webhook is down - a classic audit finding. Anonymous readability of the webhook configs is itself an exposure.
- Safety: two read-only GETs.

**How to Execute:**
```bash
nmap -p 6443 --script k8s-admission-webhook-audit api01.cluster.example.com

# Tuned request budget
nmap -p 6443 --script k8s-admission-webhook-audit --script-args 'k8s-admission-webhook-audit.timeout=8,k8s-admission-webhook-audit.maxrequests=24,k8s-admission-webhook-audit.token=' api01.cluster.example.com
```

**Sample Output:**
```
| k8s-admission-webhook-audit:
|   Risk Level: 🟡 MEDIUM
|   Status: SECURE - admission webhook configurations not readable anonymously (no answer)
```

---

### 10. **k8s-cni-portmap-exposure** - CNI Port-Mapping Exposure Signals
**Description:** Audits CNI-related exposure signals through the API: host-network

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- GET /api/v1/pods and counts hostNetwork pods.
- GET /api/v1/nodes for the node inventory.
- Grades the port-mapping exposure surface.
- Why it matters: hostNetwork pods bind node ports directly, bypassing Service NetworkPolicy controls - the classic CNI portmap exposure path. Combined with the node list this maps the external surface of the cluster fabric.
- Safety: two read-only GETs.

**How to Execute:**
```bash
nmap -p 6443 --script k8s-cni-portmap-exposure api01.cluster.example.com

# Tuned request budget
nmap -p 6443 --script k8s-cni-portmap-exposure --script-args 'k8s-cni-portmap-exposure.timeout=8,k8s-cni-portmap-exposure.maxrequests=24,k8s-cni-portmap-exposure.token=' api01.cluster.example.com
```

**Sample Output:**
```
| k8s-cni-portmap-exposure:
|   Risk Level: 🟡 MEDIUM
|   Status: SECURE - fabric inventory not readable without credentials (no answer)
```

---

### 11. **k8s-kube-proxy-debug-leak** - kube-proxy Debug Surface Leak
**Description:** Probes the kube-proxy health port debug surface: /healthz (normal),

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- GET /healthz, /configz and /debug/pprof/ without credentials.
- Records which debug paths answer.
- Grades the debug surface exposure.
- Why it matters: /configz leaks the kube-proxy mode and feature gates; /debug/pprof allows heap/profile dumps - both assist targeted exploitation. Profiling endpoints enabled by default is a CIS Benchmark finding.
- Safety: three read-only GETs.

**How to Execute:**
```bash
nmap -p 6443 --script k8s-kube-proxy-debug-leak api01.cluster.example.com

# Tuned request budget
nmap -p 6443 --script k8s-kube-proxy-debug-leak --script-args 'k8s-kube-proxy-debug-leak.timeout=8,k8s-kube-proxy-debug-leak.maxrequests=24,k8s-kube-proxy-debug-leak.token=' api01.cluster.example.com
```

**Sample Output:**
```
| k8s-kube-proxy-debug-leak:
|   Risk Level: 🟡 MEDIUM
|   Status: SECURE - kube-proxy debug surface not served anonymously (no answer)
```

---

### 12. **k8s-metrics-token-leak** - kubelet Metrics Token-Less Exposure
**Description:** Checks whether the kubelet /metrics endpoint answers without

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- GET /metrics on 10250 without credentials.
- Parses Prometheus families and sample count.
- Grades the telemetry exposure.
- Why it matters: /metrics exposes pod names, image digests and resource curves - recon data plus a side-channel for workload fingerprinting. CIS Benchmark requires kubelet authentication for the metrics serving paths.
- Safety: one read-only GET.

**How to Execute:**
```bash
nmap -p 6443 --script k8s-metrics-token-leak api01.cluster.example.com

# Tuned request budget
nmap -p 6443 --script k8s-metrics-token-leak --script-args 'k8s-metrics-token-leak.timeout=8,k8s-metrics-token-leak.maxrequests=24,k8s-metrics-token-leak.token=' api01.cluster.example.com
```

**Sample Output:**
```
| k8s-metrics-token-leak:
|   Risk Level: 🟡 MEDIUM
|   Status: INFORMATIONAL - Kubernetes audit incomplete: metrics request failed
```

---

### 13. **k8s-openapi-spec-leak** - OpenAPI Schema Disclosure
**Description:** Checks whether the OpenAPI schema is served to anonymous callers and

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- GET /openapi/v2 without credentials.
- Summarises title, API version, path count, sensitive paths.
- Grades the schema disclosure.
- Why it matters: The OpenAPI document is a complete map of the API surface - it removes all recon work for an attacker. Sensitive paths (exec, secrets) in the document telegraph high-value targets.
- Safety: one read-only GET.

**How to Execute:**
```bash
nmap -p 6443 --script k8s-openapi-spec-leak api01.cluster.example.com

# Tuned request budget
nmap -p 6443 --script k8s-openapi-spec-leak --script-args 'k8s-openapi-spec-leak.timeout=8,k8s-openapi-spec-leak.maxrequests=24,k8s-openapi-spec-leak.token=' api01.cluster.example.com
```

**Sample Output:**
```
| k8s-openapi-spec-leak:
|   Risk Level: 🟡 MEDIUM
|   Status: INFORMATIONAL - Kubernetes audit incomplete: openapi request failed
```

---

### 14. **k8s-pod-security-standards** - Pod Security Standards Workload Audit
**Description:** Audits workload security signals: reads the pod list and reports

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- GET /api/v1/pods (anonymous or with the token script-arg).
- Analyses privileged/host-namespace/capability signals per pod.
- Grades the workload security posture.
- Why it matters: Privileged containers and host namespaces are the container-escape primitives auditors look for under the Pod Security Standards. hostPID + SYS_ADMIN historically equals host compromise.
- Safety: one read-only GET plus local analysis.

**How to Execute:**
```bash
nmap -p 6443 --script k8s-pod-security-standards api01.cluster.example.com

# Tuned request budget
nmap -p 6443 --script k8s-pod-security-standards --script-args 'k8s-pod-security-standards.timeout=8,k8s-pod-security-standards.maxrequests=24,k8s-pod-security-standards.token=' api01.cluster.example.com
```

**Sample Output:**
```
| k8s-pod-security-standards:
|   Risk Level: 🟡 MEDIUM
|   Status: INFORMATIONAL - Kubernetes audit incomplete: pods request failed
```

---

### 15. **k8s-coredns-metrics-exposure** - CoreDNS Metrics Exposure
**Description:** Checks the CoreDNS Prometheus endpoint (9153): reads /metrics and

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- GET /metrics on 9153 without credentials.
- Parses Prometheus families (dns_requests, cache, etc.).
- Renders the telemetry disclosure.
- Why it matters: CoreDNS metrics leak query volumes and client behaviour - useful recon for DNS-based attacks and zone knowledge. Exposure signals missing NetworkPolicy between tenants.
- Safety: one read-only GET.

**How to Execute:**
```bash
nmap -p 6443 --script k8s-coredns-metrics-exposure api01.cluster.example.com

# Tuned request budget
nmap -p 6443 --script k8s-coredns-metrics-exposure --script-args 'k8s-coredns-metrics-exposure.timeout=8,k8s-coredns-metrics-exposure.maxrequests=24,k8s-coredns-metrics-exposure.token=' api01.cluster.example.com
```

**Sample Output:**
```
| k8s-coredns-metrics-exposure:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - Kubernetes audit incomplete: coredns metrics request failed
```

---

### 16. **k8s-version-fingerprint** - API Server Version Fingerprint & Advisory Mapping
**Description:** Fingerprints the Kubernetes API server: reads /version and maps the

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- GET /version and decodes major/minor/gitVersion.
- Maps the minor version to the advisory table.
- Reports the fingerprint with advisories.
- Why it matters: The exact version selects the applicable CVE set (API proxy, admission, symlink classes) for the rest of the audit. /version is typically public; the fingerprint anchors the report.
- Safety: one read-only GET.

**How to Execute:**
```bash
nmap -p 6443 --script k8s-version-fingerprint api01.cluster.example.com

# Tuned request budget
nmap -p 6443 --script k8s-version-fingerprint --script-args 'k8s-version-fingerprint.timeout=8,k8s-version-fingerprint.maxrequests=24,k8s-version-fingerprint.token=' api01.cluster.example.com
```

**Sample Output:**
```
| k8s-version-fingerprint:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - Kubernetes audit incomplete: /version request failed
```

