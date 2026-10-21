# 🔎 Elasticsearch Security Audits

**16 Nmap NSE scripts** for auditing Elasticsearch clusters and Kibana directly on the wire:

**Covers:**

- An HTTP/1.1 client with full JSON codec and chunked-transfer decoding
- An Elasticsearch knowledge layer (endpoint map for root, _cluster/health, _cat indices/aliases, _field_caps, _tasks, _license, _nodes/settings, _template and _snapshot; version-to-CVE advisory mapping covering CVE-2014-3120, CVE-2015-1427, CVE-2015-3337 and CVE-2015-5531; Kibana marker/login-gate detection with Timelion CVE mapping; script-probe builders for the scripting-engine surface; CAT-row, template, repository, node-settings, task and license decoding) and a budgeted session transport

**The suite covers the classic Elasticsearch attack surface:**

- Anonymous cluster identity and health
- Index/alias/field-schema inventory
- Document reads and data sampling
- Node settings with wildcard-bind detection
- Snapshot repositories
- Index templates
- Live task activity
- Licence tier
- The scripting-engine reachability check with a harmless 1+1 constant expression
- A sentinel DELETE of an index name that cannot exist
- Security-posture inference and Kibana authentication posture

**Every probe is bounded and non-destructive:**

- Reads only
- No data is dumped beyond counts
- The single write test deletes a nonexistent sentinel index and the script tests evaluate pure arithmetic.

**Ports:** 9200/tcp (elasticsearch) + 5601/tcp (kibana) | **Protocols:** Elasticsearch REST API (HTTP/JSON), Kibana web surface | **Total lines of Lua:** 30,112

---

## 📋 Script Index

| # | Script | Risk Level | Category | Lines |
|---|--------|-----------|----------|-------|
| 1 | [elasticsearch-indices-data-dump](#1-elasticsearch-indices-data-dump---anonymous-index-inventory--data-read) | 🔴 CRITICAL | vuln, safe | 1901 |
| 2 | [elasticsearch-kibana-unauth-access](#2-elasticsearch-kibana-unauth-access---kibana-authentication-posture) | 🔴 CRITICAL | vuln, safe | 1878 |
| 3 | [elasticsearch-nodes-settings-leak](#3-elasticsearch-nodes-settings-leak---node-settings--binding-disclosure) | 🔴 CRITICAL | vuln, safe | 1884 |
| 4 | [elasticsearch-search-query-leak](#4-elasticsearch-search-query-leak---anonymous-document-search-probe) | 🔴 CRITICAL | vuln, safe | 1887 |
| 5 | [elasticsearch-security-disabled](#5-elasticsearch-security-disabled---security-posture-inference) | 🔴 CRITICAL | vuln, safe | 1875 |
| 6 | [elasticsearch-unauth-cluster-info](#6-elasticsearch-unauth-cluster-info---anonymous-cluster-info-disclosure) | 🔴 CRITICAL | vuln, safe | 1880 |
| 7 | [elasticsearch-delete-index-allowed](#7-elasticsearch-delete-index-allowed---anonymous-delete-sentinel-probe) | 🟠 HIGH | vuln, safe | 1881 |
| 8 | [elasticsearch-painless-script-rce](#8-elasticsearch-painless-script-rce---scripting-reachability-painlessgroovy-class) | 🟠 HIGH | vuln, safe | 1883 |
| 9 | [elasticsearch-snapshot-repo-leak](#9-elasticsearch-snapshot-repo-leak---snapshot-repository-disclosure) | 🟠 HIGH | discovery, safe | 1880 |
| 10 | [elasticsearch-aliases-enum](#10-elasticsearch-aliases-enum---index-alias-enumeration) | 🟡 MEDIUM | discovery, safe | 1878 |
| 11 | [elasticsearch-field-caps-audit](#11-elasticsearch-field-caps-audit---field-schema-field-caps-disclosure) | 🟡 MEDIUM | discovery, safe | 1883 |
| 12 | [elasticsearch-tasks-monitoring](#12-elasticsearch-tasks-monitoring---running-task-list-disclosure) | 🟡 MEDIUM | discovery, safe | 1877 |
| 13 | [elasticsearch-templates-leak](#13-elasticsearch-templates-leak---index-template-disclosure) | 🟡 MEDIUM | discovery, safe | 1879 |
| 14 | [elasticsearch-cluster-health-leak](#14-elasticsearch-cluster-health-leak---cluster-health-disclosure) | 🟢 LOW | discovery, safe | 1875 |
| 15 | [elasticsearch-cve-2015-1427-check](#15-elasticsearch-cve-2015-1427-check---cve-2015-1427-scripting-engine-check) | 🟢 LOW | discovery, safe | 1892 |
| 16 | [elasticsearch-license-status](#16-elasticsearch-license-status---license-status-disclosure) | 🟢 LOW | discovery, safe | 1879 |

---

### 1. **elasticsearch-indices-data-dump** - Anonymous Index Inventory & Data Read
**Description:** Maps the readable data surface: lists indices via the CAT API and

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- GET /_cat/indices for the inventory.
- POST /<index>/_search with size=1 (one document cap).
- Grades the data exposure.
- Why it matters: Open Elasticsearch clusters are full-text databases; anonymous reads have leaked billions of records historically (public misconfiguration scans find them constantly). Proving read access converts an "info leak" into a confirmed data exposure.
- Safety: reads only, one document retrieved maximum; no _source is printed beyond counts.

**How to Execute:**
```bash
nmap -p 9200 --script elasticsearch-indices-data-dump es01.corp.example.com

# Tuned request budget
nmap -p 9200 --script elasticsearch-indices-data-dump --script-args 'elasticsearch-indices-data-dump.timeout=8,elasticsearch-indices-data-dump.maxrequests=24,elasticsearch-indices-data-dump.index=logs-2015' es01.corp.example.com
```

**Sample Output:**
```
| elasticsearch-indices-data-dump:
|   Risk Level: 🔴 CRITICAL
|   Status: INFORMATIONAL - Elasticsearch audit incomplete: cat indices request failed
```

---

### 2. **elasticsearch-kibana-unauth-access** - Kibana Authentication Posture
**Description:** Grades the Kibana authentication posture: distinguishes a login gate

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- GET / on 5601 and classifies markers (kbn-name, login gate).
- Probes /app/kibana for direct app serving.
- Grades the posture.
- Why it matters: Kibana grants full Elasticsearch interaction; unauthenticated access equals cluster UI takeover (the Svanpire/Tesla class of incidents started at exposed Kibana). Old Kibana versions add CVE-2019-7609 (Timelion RCE) to the surface.
- Safety: two read-only GETs; no login attempts.

**How to Execute:**
```bash
nmap -p 9200 --script elasticsearch-kibana-unauth-access es01.corp.example.com

# Tuned request budget
nmap -p 9200 --script elasticsearch-kibana-unauth-access --script-args 'elasticsearch-kibana-unauth-access.timeout=8,elasticsearch-kibana-unauth-access.maxrequests=24,elasticsearch-kibana-unauth-access.index=logs-2015' es01.corp.example.com
```

**Sample Output:**
```
| elasticsearch-kibana-unauth-access:
|   Risk Level: 🔴 CRITICAL
|   Status: INFORMATIONAL - Elasticsearch audit incomplete: kibana root request failed
```

---

### 3. **elasticsearch-nodes-settings-leak** - Node Settings & Binding Disclosure
**Description:** Reads /_nodes/settings anonymously and reports node names, transport

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- GET /_nodes/settings without credentials.
- Decodes node names, publish addresses, bind hosts.
- Flags 0.0.0.0-style bindings.
- Why it matters: Node settings expose internal addressing (10.x transport hosts, 0.0.0.0 binds) and topology - the internal network map. Combined with anonymous queries this is full cluster situational awareness for an attacker.
- Safety: one read-only GET.

**How to Execute:**
```bash
nmap -p 9200 --script elasticsearch-nodes-settings-leak es01.corp.example.com

# Tuned request budget
nmap -p 9200 --script elasticsearch-nodes-settings-leak --script-args 'elasticsearch-nodes-settings-leak.timeout=8,elasticsearch-nodes-settings-leak.maxrequests=24,elasticsearch-nodes-settings-leak.index=logs-2015' es01.corp.example.com
```

**Sample Output:**
```
| elasticsearch-nodes-settings-leak:
|   Risk Level: 🔴 CRITICAL
|   Status: INFORMATIONAL - Elasticsearch audit incomplete: nodes settings request failed
```

---

### 4. **elasticsearch-search-query-leak** - Anonymous Document Search Probe
**Description:** Runs a read-only match_all search (size 1) against the configured

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- POST /<index>/_search with a match_all query, size 1.
- Parses hit totals and provenance.
- Grades the read exposure.
- Why it matters: One successful query proves full read access to the index contents - the direct path to data theft (PII, credentials, chat logs). This is the single probe that separates "info leak" from "breach".
- Safety: one read-only query; result content is counted, not dumped.

**How to Execute:**
```bash
nmap -p 9200 --script elasticsearch-search-query-leak es01.corp.example.com

# Tuned request budget
nmap -p 9200 --script elasticsearch-search-query-leak --script-args 'elasticsearch-search-query-leak.timeout=8,elasticsearch-search-query-leak.maxrequests=24,elasticsearch-search-query-leak.index=logs-2015' es01.corp.example.com
```

**Sample Output:**
```
| elasticsearch-search-query-leak:
|   Risk Level: 🔴 CRITICAL
|   Status: INFORMATIONAL - Elasticsearch audit incomplete: search request failed
```

---

### 5. **elasticsearch-security-disabled** - Security Posture Inference
**Description:** Infers the security posture from the anonymous answer surface: when

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Probes root, health, and CAT APIs anonymously.
- Counts which surfaces answered without 401/403.
- Grades the posture: any open monitoring surface = security off.
- Why it matters: Disabled xpack security is the root cause finding behind the majority of public Elasticsearch data leaks. Evidence-based posture (which endpoints answered anonymously) beats version assumptions.
- Safety: three read-only GETs.

**How to Execute:**
```bash
nmap -p 9200 --script elasticsearch-security-disabled es01.corp.example.com

# Tuned request budget
nmap -p 9200 --script elasticsearch-security-disabled --script-args 'elasticsearch-security-disabled.timeout=8,elasticsearch-security-disabled.maxrequests=24,elasticsearch-security-disabled.index=logs-2015' es01.corp.example.com
```

**Sample Output:**
```
| elasticsearch-security-disabled:
|   Risk Level: 🔴 CRITICAL
|   Status: SECURE - all probed endpoints require authentication
```

---

### 6. **elasticsearch-unauth-cluster-info** - Anonymous Cluster Info Disclosure
**Description:** Reads the Elasticsearch root endpoint and grades whether cluster

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- GET / without credentials.
- Decodes cluster name/UUID/version and flags default naming.
- Grades the disclosure.
- Why it matters: The root document is the standard recon target: cluster name and version select the exploit set (scripting engines, traversal CVEs). Anonymous 9200 exposure is the defining misconfiguration class of publicly-owned Elasticsearch clusters.
- Safety: one read-only GET.

**How to Execute:**
```bash
nmap -p 9200 --script elasticsearch-unauth-cluster-info es01.corp.example.com

# Tuned request budget
nmap -p 9200 --script elasticsearch-unauth-cluster-info --script-args 'elasticsearch-unauth-cluster-info.timeout=8,elasticsearch-unauth-cluster-info.maxrequests=24,elasticsearch-unauth-cluster-info.index=logs-2015' es01.corp.example.com
```

**Sample Output:**
```
| elasticsearch-unauth-cluster-info:
|   Risk Level: 🔴 CRITICAL
|   Status: INFORMATIONAL - Elasticsearch audit incomplete: root request failed
```

---

### 7. **elasticsearch-delete-index-allowed** - Anonymous Delete Sentinel Probe
**Description:** Probes whether the delete function is open to anonymous callers: a

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- DELETE /nse-audit-sentinel-zz0x (an index that was never created).
- Grades index_not_found (write path open) versus 401/403 (walled).
- Reports the manipulation risk.
- Why it matters: An accepted DELETE - even of a nonexistent index - proves unauthenticated callers can destroy data, the most destructive primitive on the cluster. The sentinel name makes the probe safe by construction.
- Safety: the probe index name never exists; nothing can be deleted.

**How to Execute:**
```bash
nmap -p 9200 --script elasticsearch-delete-index-allowed es01.corp.example.com

# Tuned request budget
nmap -p 9200 --script elasticsearch-delete-index-allowed --script-args 'elasticsearch-delete-index-allowed.timeout=8,elasticsearch-delete-index-allowed.maxrequests=24,elasticsearch-delete-index-allowed.index=logs-2015' es01.corp.example.com
```

**Sample Output:**
```
| elasticsearch-delete-index-allowed:
|   Risk Level: 🟠 HIGH
|   Status: INFORMATIONAL - Elasticsearch audit incomplete: delete probe failed
```

---

### 8. **elasticsearch-painless-script-rce** - Scripting Reachability (Painless/Groovy Class)
**Description:** Checks whether script inputs are processed by the scripting layer at

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- Sends a script_fields probe with the expression engine (1+1).
- Repeats with painless on the same constant.
- Grades the scripting reachability.
- Why it matters: Script-enabled clusters turn search into execution: sandbox escapes (painless) and groovy RCE made this the worst Elasticsearch bug class. Detecting an active scripting surface with a constant expression is the safe way to audit it.
- Safety: both probes evaluate the constant 1+1 - no data access, no system properties, no code beyond arithmetic.

**How to Execute:**
```bash
nmap -p 9200 --script elasticsearch-painless-script-rce es01.corp.example.com

# Tuned request budget
nmap -p 9200 --script elasticsearch-painless-script-rce --script-args 'elasticsearch-painless-script-rce.timeout=8,elasticsearch-painless-script-rce.maxrequests=24,elasticsearch-painless-script-rce.index=logs-2015' es01.corp.example.com
```

**Sample Output:**
```
| elasticsearch-painless-script-rce:
|   Risk Level: 🟠 HIGH
|   Status: SECURE - no scripting engine evaluated the anonymous probes
```

---

### 9. **elasticsearch-snapshot-repo-leak** - Snapshot Repository Disclosure
**Description:** Enumerates snapshot repositories (/_snapshot) and their backing

**Risk Level:** 🟠 HIGH | **Category:** discovery, safe

**What it checks:**
- GET /_snapshot without credentials.
- Decodes repository names, types and locations.
- Grades the backup surface disclosure.
- Why it matters: Snapshot repositories name the backup destinations - S3 buckets and NFS paths that hold complete copies of every index. The CVE-2015-5531 traversal class made unreadable repos exploitable; the inventory is the first step either way.
- Safety: one read-only GET.

**How to Execute:**
```bash
nmap -p 9200 --script elasticsearch-snapshot-repo-leak es01.corp.example.com

# Tuned request budget
nmap -p 9200 --script elasticsearch-snapshot-repo-leak --script-args 'elasticsearch-snapshot-repo-leak.timeout=8,elasticsearch-snapshot-repo-leak.maxrequests=24,elasticsearch-snapshot-repo-leak.index=logs-2015' es01.corp.example.com
```

**Sample Output:**
```
| elasticsearch-snapshot-repo-leak:
|   Risk Level: 🟠 HIGH
|   Status: INFORMATIONAL - Elasticsearch audit incomplete: snapshot repos request failed
```

---

### 10. **elasticsearch-aliases-enum** - Index Alias Enumeration
**Description:** Enumerates index aliases via the CAT API, exposing the logical data

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- GET /_cat/aliases?format=json.
- Decodes alias/index/filter rows.
- Grades the layout disclosure.
- Why it matters: Aliases name the datasets (logs, customers, transactions) and their filter scopes - the map attackers use to target extraction. Write aliases also identify ingest paths.
- Safety: one read-only GET.

**How to Execute:**
```bash
nmap -p 9200 --script elasticsearch-aliases-enum es01.corp.example.com

# Tuned request budget
nmap -p 9200 --script elasticsearch-aliases-enum --script-args 'elasticsearch-aliases-enum.timeout=8,elasticsearch-aliases-enum.maxrequests=24,elasticsearch-aliases-enum.index=logs-2015' es01.corp.example.com
```

**Sample Output:**
```
| elasticsearch-aliases-enum:
|   Risk Level: 🟡 MEDIUM
|   Status: INFORMATIONAL - Elasticsearch audit incomplete: aliases request failed
```

---

### 11. **elasticsearch-field-caps-audit** - Field Schema (Field Caps) Disclosure
**Description:** Reads the cluster-wide field capabilities (/ _field_caps) and

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- GET /_field_caps?fields=*.
- Decodes field names, types, searchable flags.
- Grades the schema disclosure.
- Why it matters: The field schema reveals the data model (emails, tokens, geo, passwords-as-keywords) without reading a single document. Searchable fields identify the fastest extraction paths.
- Safety: one read-only metadata GET; no documents read.

**How to Execute:**
```bash
nmap -p 9200 --script elasticsearch-field-caps-audit es01.corp.example.com

# Tuned request budget
nmap -p 9200 --script elasticsearch-field-caps-audit --script-args 'elasticsearch-field-caps-audit.timeout=8,elasticsearch-field-caps-audit.maxrequests=24,elasticsearch-field-caps-audit.index=logs-2015' es01.corp.example.com
```

**Sample Output:**
```
| elasticsearch-field-caps-audit:
|   Risk Level: 🟡 MEDIUM
|   Status: INFORMATIONAL - Elasticsearch audit incomplete: field_caps request failed
```

---

### 12. **elasticsearch-tasks-monitoring** - Running Task List Disclosure
**Description:** Reads the running task list (/_tasks) and reports active work:

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- GET /_tasks without credentials.
- Decodes nodes, running tasks and actions.
- Grades the activity disclosure.
- Why it matters: The task list is a live wiretap on cluster activity - reindex jobs, searches and administrative actions of other users. Task actions (reindex, snapshot) reveal data movement worth intercepting or disrupting.
- Safety: one read-only GET.

**How to Execute:**
```bash
nmap -p 9200 --script elasticsearch-tasks-monitoring es01.corp.example.com

# Tuned request budget
nmap -p 9200 --script elasticsearch-tasks-monitoring --script-args 'elasticsearch-tasks-monitoring.timeout=8,elasticsearch-tasks-monitoring.maxrequests=24,elasticsearch-tasks-monitoring.index=logs-2015' es01.corp.example.com
```

**Sample Output:**
```
| elasticsearch-tasks-monitoring:
|   Risk Level: 🟡 MEDIUM
|   Status: INFORMATIONAL - Elasticsearch audit incomplete: tasks request failed
```

---

### 13. **elasticsearch-templates-leak** - Index Template Disclosure
**Description:** Enumerates index templates (/_template) - the declared structure of

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- GET /_template without credentials.
- Decodes template names, patterns, shard settings.
- Grades the disclosure.
- Why it matters: Templates document the schema of the whole pipeline (logstash-*, *) and hint at data classification before any document is read. Anonymous template reads pair with the index inventory for complete cluster mapping.
- Safety: one read-only GET.

**How to Execute:**
```bash
nmap -p 9200 --script elasticsearch-templates-leak es01.corp.example.com

# Tuned request budget
nmap -p 9200 --script elasticsearch-templates-leak --script-args 'elasticsearch-templates-leak.timeout=8,elasticsearch-templates-leak.maxrequests=24,elasticsearch-templates-leak.index=logs-2015' es01.corp.example.com
```

**Sample Output:**
```
| elasticsearch-templates-leak:
|   Risk Level: 🟡 MEDIUM
|   Status: INFORMATIONAL - Elasticsearch audit incomplete: templates request failed
```

---

### 14. **elasticsearch-cluster-health-leak** - Cluster Health Disclosure
**Description:** Reads /_cluster/health and grades disclosure of cluster topology

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- GET /_cluster/health anonymously.
- Decodes status/node/shard counters.
- Grades the disclosure and health state.
- Why it matters: Health data reveals node counts and shard pressure - operational intelligence for an attacker planning data extraction or disruption. red/yellow status also surfaces reliability issues for defenders.
- Safety: one read-only GET.

**How to Execute:**
```bash
nmap -p 9200 --script elasticsearch-cluster-health-leak es01.corp.example.com

# Tuned request budget
nmap -p 9200 --script elasticsearch-cluster-health-leak --script-args 'elasticsearch-cluster-health-leak.timeout=8,elasticsearch-cluster-health-leak.maxrequests=24,elasticsearch-cluster-health-leak.index=logs-2015' es01.corp.example.com
```

**Sample Output:**
```
| elasticsearch-cluster-health-leak:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - Elasticsearch audit incomplete: health request failed
```

---

### 15. **elasticsearch-cve-2015-1427-check** - CVE-2015-1427 Scripting Engine Check
**Description:** Probes the scripting-engine surface (CVE-2015-1427 class): sends one

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- POST /<index>/_search with script_fields expression "1+1".
- Distinguishes evaluation (script result), unsupported engine, and auth walls.
- Grades the scripting surface.
- Why it matters: Dynamic scripting enabled was the direct RCE primitive behind the 2014-2015 mass-compromise wave of Elasticsearch clusters. The engine still runs by default in expression form on old clusters - detection matters for 1.x deployments.
- Safety: the probe computes the constant 1+1 on the coordinator node - no data access, no code beyond arithmetic.

**How to Execute:**
```bash
nmap -p 9200 --script elasticsearch-cve-2015-1427-check es01.corp.example.com

# Tuned request budget
nmap -p 9200 --script elasticsearch-cve-2015-1427-check --script-args 'elasticsearch-cve-2015-1427-check.timeout=8,elasticsearch-cve-2015-1427-check.maxrequests=24,elasticsearch-cve-2015-1427-check.index=logs-2015' es01.corp.example.com
```

**Sample Output:**
```
| elasticsearch-cve-2015-1427-check:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - Elasticsearch audit incomplete: script probe failed
```

---

### 16. **elasticsearch-license-status** - License Status Disclosure
**Description:** Reads the license endpoint (/_license) and reports the licence type

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- GET /_license without credentials.
- Decodes type/status/issued_to.
- Grades the disclosure.
- Why it matters: Licence tier maps the available security controls (basic = no advanced auth/xpack features in 5.x-6.x) - guiding both attacker and defender expectations. It is another anonymous-read surface to close.
- Safety: one read-only GET.

**How to Execute:**
```bash
nmap -p 9200 --script elasticsearch-license-status es01.corp.example.com

# Tuned request budget
nmap -p 9200 --script elasticsearch-license-status --script-args 'elasticsearch-license-status.timeout=8,elasticsearch-license-status.maxrequests=24,elasticsearch-license-status.index=logs-2015' es01.corp.example.com
```

**Sample Output:**
```
| elasticsearch-license-status:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - Elasticsearch audit incomplete: license request failed
```

