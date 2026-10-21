# 🗄️ Database Security Audits

**16 Nmap NSE scripts** for auditing database and data-store endpoints:

**Covers:**

- Unauthenticated access on Cassandra (CQL native protocol)
- ClickHouse (HTTP SQL)
- CouchDB (HTTP/JSON API)
- Etcd (v2 + v3 keyspaces)
- InfluxDB (InfluxQL)
- MongoDB (OP_MSG hello/ping)
- Redis (PING/INFO/COMMAND INFO + bounded write probe)
- Memcached (stats surface); credential-posture checks on MySQL/MariaDB (empty-password login, SSL capability, full HandshakeV10 banner)
- PostgreSQL (SSLRequest offer, trust authentication)
- SQL Server (TDS PRELOGIN encryption mode + build fingerprint); plus Neo4j's unauthenticated HTTP browser API. Every script speaks the real wire protocol — building and parsing the actual handshake/query frames by hand — and reports evidence-based verdicts

**Ports:** 9042 (Cassandra), 8123 (ClickHouse), 5984 (CouchDB), 2379 (etcd), 8086 (InfluxDB), 11211 (memcached), 27017 (MongoDB), 1433 (SQL Server), 3306 (MySQL/MariaDB), 7474 (Neo4j), 5432 (PostgreSQL), 6379 (Redis) | **Protocols:** CQL binary v4, HTTP/1.1 JSON, RESP, memcached text, MySQL protocol v10, PostgreSQL FE/BE, TDS 7.x PRELOGIN, BSON/OP_MSG | **Total lines of Lua:** 34,626

---

## 📋 Script Index

| # | Script | Risk Level | Category | Lines |
|---|--------|-----------|----------|-------|
| 1 | [cassandra-unauth-check](#1-cassandra-unauth-check---unauthenticated-cql-native-access) | 🔴 CRITICAL | vuln, auth, safe | 2248 |
| 2 | [couchdb-unauth-check](#2-couchdb-unauth-check---unauthenticated-httpjson-api) | 🔴 CRITICAL | vuln, safe | 2280 |
| 3 | [etcd-unauth-keyspace](#3-etcd-unauth-keyspace---unauthenticated-keyspace-reads) | 🔴 CRITICAL | vuln, safe | 2242 |
| 4 | [influxdb-unauth-check](#4-influxdb-unauth-check---unauthenticated-influxql) | 🔴 CRITICAL | vuln, safe | 2191 |
| 5 | [clickhouse-unauth-check](#5-clickhouse-unauth-check---unauthenticated-http-sql) | 🟠 HIGH | vuln, safe | 2198 |
| 6 | [neo4j-unauth-browser](#6-neo4j-unauth-browser---unauthenticated-http-browser-api) | 🟠 HIGH | vuln, safe | 2151 |
| 7 | [memcached-stats-dump](#7-memcached-stats-dump---unauthenticated-stats-surface) | 🟡 MEDIUM | discovery, safe | 2203 |
| 8 | [mongodb-unauthenticated-check](#8-mongodb-unauthenticated-check---unauthenticated-command-execution) | 🟡 MEDIUM | safe, discovery, vuln | 2154 |
| 9 | [mssql-prelogin-check](#9-mssql-prelogin-check---encryption-posture--build-fingerprint) | 🟡 MEDIUM | safe, discovery | 2095 |
| 10 | [mysql-empty-password-check](#10-mysql-empty-password-check---empty-password-login) | 🟡 MEDIUM | safe, discovery, vuln | 2153 |
| 11 | [mysql-ssl-support-check](#11-mysql-ssl-support-check---client_ssl-capability) | 🟡 MEDIUM | safe, discovery | 2112 |
| 12 | [postgresql-ssl-support-check](#12-postgresql-ssl-support-check---sslrequest-offer) | 🟡 MEDIUM | safe, discovery | 2029 |
| 13 | [postgresql-trust-auth-check](#13-postgresql-trust-auth-check---trust-authentication) | 🟡 MEDIUM | safe, discovery, vuln | 2097 |
| 14 | [redis-admin-command-exposure](#14-redis-admin-command-exposure---administrative-command-surface) | 🟡 MEDIUM | safe, discovery, vuln | 2143 |
| 15 | [redis-unauthenticated-access](#15-redis-unauthenticated-access---unauthenticated-command-execution) | 🟡 MEDIUM | safe, discovery, vuln | 2173 |
| 16 | [mysql-banner-grab](#16-mysql-banner-grab---handshakev10-banner-capture) | 🟢 LOW | safe, discovery, version | 2157 |

---

## ⚙️ Common Script Arguments

All 16 scripts share the following `--script-args` (script-specific extras are listed per script):

| Argument | Default | Purpose |
|----------|---------|---------|
| `maxrequests` | per script | Hard request budget for the run |
| `timeout` | 10 | Per-exchange timeout (seconds) |

---

## 📜 Script Details

### 1. **cassandra-unauth-check** - Unauthenticated CQL Native Access
**Description:** Sends a standard CQL STARTUP frame (v4, no credentials) to port 9042 and classifies the response: READY means the node accepts anonymous sessions (CRITICAL); an ERROR frame with an authentication message means the node is protected. When a session is accepted, it issues three strictly read-only queries (release_version, cluster_name, keyspace enumeration) to confirm the exposure, fingerprint the version and count exposed keyspaces, then checks the release against the 2.1–5.0 end-of-life table.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, auth, safe

**What it checks:**
- CQL STARTUP answered READY without credentials (CRITICAL)
- release_version / cluster_name read without credentials
- keyspace enumeration via system_schema (HIGH)
- end-of-life Cassandra line while exposed (MEDIUM)

**How to Execute:**
```bash
# Basic scan
nmap -p 9042 --script cassandra-unauth-check target.example.com

# Different CQL negotiation version / skip keyspace enumeration
nmap -p 9042 --script cassandra-unauth-check --script-args cassandra-unauth-check.cql_version=4.0.0,cassandra-unauth-check.skipkeyspaces=true target.example.com
```

**Sample Output:**
```
| cassandra-unauth-check:
|   Risk Level: 🔴 CRITICAL
|   Status: AUDITED - CQL native port 9042 checked for unauthenticated access.
|   Findings:
|     [CRITICAL] Cassandra accepted a CQL session with NO credentials
|                (STARTUP answered READY); any host that can reach port 9042
|                can read and write every keyspace (unauthenticated-cql)
|                [evidence: STARTUP(3.4.5) -> READY]
|     [HIGH] unauthenticated metadata read enumerated 3 keyspace(s); the
|            schema of the entire cluster is visible to anonymous clients
|            (keyspace-enum) [evidence: sample: system, application_db, metrics]
|   Severity counts: CRITICAL=1 HIGH=1 MEDIUM=0 LOW=0 INFO=1
|   Weighted score: 18
|   exposed_keyspaces:
|     1: system
|     2: application_db
|     3: metrics
|   release_version: 4.1.3
|   startup_class: ready
```

---

### 2. **couchdb-unauth-check** - Unauthenticated HTTP/JSON API
**Description:** Walks the CouchDB HTTP API (port 5984) without credentials: root banner + version, /_all_dbs database enumeration, /_membership cluster topology (node list, admin party, cookie hash), /_users user-document enumeration and /_local/_design design documents. A 200 on any data endpoint is a complete unauthenticated breach of the JSON API (CRITICAL); a 401/403 on the root is reported as enforced (INFO).

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- root endpoint open without auth (CRITICAL)
- /_all_dbs database enumeration (CRITICAL)
- /_membership cluster topology exposure (CRITICAL)
- /_users user enumeration (HIGH)
- /_local/_design document exposure (MEDIUM)
- CouchDB 1.x/2.x end-of-life line (MEDIUM)

**How to Execute:**
```bash
# Basic scan
nmap -p 5984 --script couchdb-unauth-check target.example.com
```

**Sample Output:**
```
| couchdb-unauth-check:
|   Risk Level: 🔴 CRITICAL
|   Status: AUDITED - CouchDB HTTP API checked for unauthenticated access.
|   Findings:
|     [CRITICAL] cluster membership is publicly readable via /_membership:
|                active_users=1, admin_party=1, all_nodes=2, cluster_nodes=2,
|                cookie_hash=present, partitioned_dbs=0 (membership-exposed)
|     [CRITICAL] the CouchDB root endpoint answers without authentication
|                (HTTP 200) (root-open)
|     [CRITICAL] unauthenticated database enumeration: 2 database(s) listed
|                via /_all_dbs (appdb, logdb) (all-dbs-exposed)
|   Severity counts: CRITICAL=3 HIGH=0 MEDIUM=0 LOW=0 INFO=1
|   Weighted score: 31
|   cluster_membership:
|     1: active_users=1
|     2: admin_party=1
|     3: all_nodes=2
|     4: cluster_nodes=2
|     5: cookie_hash=present
|   couchdb_version: 3.3.2
|   databases:
|     1: appdb
|     2: logdb
```

---

### 3. **etcd-unauth-keyspace** - Unauthenticated Keyspace Reads
**Description:** Reads the etcd keyspace (port 2379) over both API generations: GET /v2/keys (legacy tree) and POST /v3/kv/range (modern prefix scan, base64-decoded). Every readable string value is scanned for embedded credential patterns (user:pass@ URLs, AWS-style access keys, private-key headers, bearer tokens) and flagged by key without printing the secret. An open v2 or v3 surface is CRITICAL; 401/403 on both is INFO.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- v2 keyspace readable without auth (CRITICAL)
- v3 range scan readable without auth (CRITICAL)
- plaintext credential-looking values (CRITICAL)
- /version and /health context (INFO)

**How to Execute:**
```bash
# Basic scan
nmap -p 2379 --script etcd-unauth-keyspace target.example.com
```

**Sample Output:**
```
| etcd-unauth-keyspace:
|   Risk Level: 🔴 CRITICAL
|   Status: AUDITED - etcd keyspace checked for unauthenticated reads (v2 + v3).
|   Findings:
|     [CRITICAL] credential-looking values are stored in plaintext in the
|                v2 keyspace: /config looks like url-credentials (v2-secrets-exposed)
|     [CRITICAL] the legacy v2 keyspace is readable without authentication
|                (GET /v2/keys -> 200); 2 key(s) visible (v2-open)
|     [CRITICAL] the v3 keyspace is readable without authentication
|                (POST /v3/kv/range -> 200 with kvs) (v3-open)
|   Severity counts: CRITICAL=3 HIGH=0 MEDIUM=0 LOW=0 INFO=0
|   Weighted score: 30
|   v2_keys:
|     1: /config
|     2: /config/db
|   v2_keys_status: 200
|   v3_range_status: 200
```

---

### 4. **influxdb-unauth-check** - Unauthenticated InfluxQL
**Description:** Executes InfluxQL against the InfluxDB HTTP API (port 8086) without credentials: /ping for version context, SHOW DATABASES for the core test, and SHOW MEASUREMENTS when the API is open. A 200 with data rows means the query API runs anonymously (CRITICAL); a 401/403 is INFO. The reported version line is classified (1.x EOL, 2.x supported).

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- credentialless SHOW DATABASES success (CRITICAL)
- measurement enumeration (HIGH)
- empty-result open API (HIGH)
- InfluxDB 1.x unsupported line (MEDIUM)

**How to Execute:**
```bash
# Basic scan
nmap -p 8086 --script influxdb-unauth-check target.example.com
```

**Sample Output:**
```
| influxdb-unauth-check:
|   Risk Level: 🔴 CRITICAL
|   Status: AUDITED - InfluxDB HTTP API checked for unauthenticated query execution.
|   Findings:
|     [CRITICAL] InfluxQL executes without authentication: SHOW DATABASES
|                returned 200 and lists 1 database(s) (metrics) (query-api-open)
|     [HIGH] measurement names are enumerable without authentication:
|            1 measurement(s) listed via SHOW MEASUREMENTS (metrics)
|   Severity counts: CRITICAL=1 HIGH=1 MEDIUM=0 LOW=0 INFO=0
|   Weighted score: 17
|   databases:
|     1: metrics
|   ping_status: 204
|   show_databases_status: 200
```

---

### 5. **clickhouse-unauth-check** - Unauthenticated HTTP SQL
**Description:** Executes SELECT version() against the ClickHouse HTTP interface (port 8123). A 200 whose body is a bare version string means the default (or empty-password) user runs SQL anonymously (HIGH); a 401/403 means authentication is enforced. When open, it follows up with two read-only enumeration queries (system.tables count, SHOW DATABASES) and classifies the version line (22.x/23.3 EOL, 23.8/24.3 LTS).

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- credentialless SELECT version() success (HIGH)
- system.tables / SHOW DATABASES enumeration (HIGH)
- open interface with restricted enumeration (MEDIUM)
- end-of-life ClickHouse line (MEDIUM)

**How to Execute:**
```bash
# Basic scan
nmap -p 8123 --script clickhouse-unauth-check target.example.com
```

**Sample Output:**
```
| clickhouse-unauth-check:
|   Risk Level: 🟠 HIGH
|   Status: AUDITED - ClickHouse HTTP interface checked for unauthenticated SQL.
|   Findings:
|     [HIGH] ClickHouse executed SELECT version() without authentication:
|            the interface answers with version 23.8.12.14 - the default
|            (or empty-password) user is usable by anyone who can reach
|            port 8123 (unauth-sql) [evidence: GET /?query=SELECT+version() -> 200 23.8.12.14]
|     [MEDIUM] the interface is open but the follow-up enumeration queries
|              were not answered (open-restricted)
|   Severity counts: CRITICAL=0 HIGH=1 MEDIUM=1 LOW=0 INFO=1
|   Weighted score: 12
|   clickhouse_version: 23.8.12.14
|   version_query_status: 200
```

---

### 6. **neo4j-unauth-browser** - Unauthenticated HTTP Browser API
**Description:** Probes the Neo4j HTTP browser API (port 7474): GET /db/ returns the dbms JSON object (version, edition, address) and the full database inventory with states. A 200 with a parseable inventory is HIGH (the graph store's inventory — and usually its data — is anonymously reachable); 401/403 is INFO. Classifies the Neo4j line (3.5/4.x EOL, 5.x supported, 5.26 LTS).

**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- unauthenticated /db/ with database inventory (HIGH)
- unauthenticated /db/ without parseable inventory (MEDIUM)
- unsupported Neo4j line (MEDIUM)
- dbms version/edition/address (context)

**How to Execute:**
```bash
# Basic scan
nmap -p 7474 --script neo4j-unauth-browser target.example.com
```

**Sample Output:**
```
| neo4j-unauth-browser:
|   Risk Level: 🟠 HIGH
|   Status: AUDITED - Neo4j HTTP browser API checked for unauthenticated access.
|   Findings:
|     [HIGH] the Neo4j /db/ endpoint answers without authentication and
|            lists 2 database(s): system (online), neo4j (online)
|            (unauth-db-api)
|     [MEDIUM] Neo4j 3.5.39 is on an unsupported line (version-eol)
|   Severity counts: CRITICAL=0 HIGH=1 MEDIUM=1 LOW=0 INFO=0
|   Weighted score: 11
|   databases:
|     1: system (online)
|     2: neo4j (online)
|   dbms_version: 3.5.39
|   dbms_edition: enterprise
```

---

### 7. **memcached-stats-dump** - Unauthenticated Stats Surface
**Description:** Connects to memcached (port 11211) and collects VERSION, STATS and (best-effort) STATS settings — all of which memcached serves without authentication by design. Derives operational metrics (memory usage ratio, hit rate, eviction pressure, connection counts) and interprets the load: a hot cache is holding live production data, which raises the value of the equally unauthenticated GET path.

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- VERSION/STATS reachable anonymously (MEDIUM)
- production-load interpretation of the stats (MEDIUM reinforcement)
- legacy 1.0–1.5 line (LOW)
- configured limits via stats settings (context)

**How to Execute:**
```bash
# Basic scan
nmap -p 11211 --script memcached-stats-dump target.example.com
```

**Sample Output:**
```
| memcached-stats-dump:
|   Risk Level: 🟡 MEDIUM
|   Status: AUDITED - memcached stats collected without authentication.
|   Findings:
|     [MEDIUM] memcached answered VERSION and STATS without authentication;
|              by the same token any client can GET cached values (unauth-stats)
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=0 INFO=1
|   Weighted score: 5
|   memcached_version: 1.6.20
|   memory_usage: 10.0 MB
|   memory_limit: 64.0 MB
|   memory_usage_pct: 15.6%
|   hit_rate: 90.0%
|   current_items: 1200
|   uptime_seconds: 86400
|   load_interpretation: the cache appears lightly loaded
```

---

### 8. **mongodb-unauthenticated-check** - Unauthenticated Command Execution
**Description:** Sends an OP_MSG hello (hand-constructed BSON) and a ping to MongoDB (port 27017) without authenticating. A successful hello proves the server executes commands for anonymous clients (MEDIUM); a BSON error with code 13 (Unauthorized) is the positive evidence that auth is enforced. Parses maxWireVersion → release era, isWritablePrimary, replica-set name, and classifies the version line (4.4/5.0 EOL, 6.0/7.0 LTS).

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery, vuln

**What it checks:**
- unauthenticated hello success (MEDIUM)
- unauthenticated ping success (MEDIUM reinforcement)
- end-of-life MongoDB line while exposed (MEDIUM)
- wire-version → release-era mapping (context)

**How to Execute:**
```bash
# Basic scan
nmap -p 27017 --script mongodb-unauthenticated-check target.example.com
```

**Sample Output:**
```
| mongodb-unauthenticated-check:
|   Risk Level: 🟡 MEDIUM
|   Status: AUDITED - MongoDB checked for unauthenticated command execution (hello + ping).
|   Findings:
|     [MEDIUM] MongoDB processed an unauthenticated hello command (ok=1.0,
|              version 4.4.29, wire 13) (unauth-hello)
|     [MEDIUM] the follow-up ping command also succeeded without
|              authentication (unauth-ping)
|     [MEDIUM] the unauthenticated MongoDB is 4.4.29, an unsupported line
|              (version-eol)
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=3 LOW=0 INFO=0
|   Weighted score: 12
|   server_version: 4.4.29
|   max_wire_version: 13
|   wire_version_line: wire 13 -> 4.4 era
|   writable_primary: true
```

---

### 9. **mssql-prelogin-check** - Encryption Posture & Build Fingerprint
**Description:** Performs a TDS PRELOGIN exchange against SQL Server (port 1433) with the encryption preference OFF — exactly what a generic client sends — and parses the response tokens: VERSION (build), ENCRYPTION, INSTOPT, THREADID, LANGUAGE, DATABASE. OFF/NOT_SUP means login packets travel in cleartext (MEDIUM); ON/REQ means a TDS-encrypted channel is negotiated (INFO). The build is mapped to the product line (15.0 = 2019, 16.0 = 2022, …) with its support window.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery

**What it checks:**
- PRELOGIN ENCRYPTION OFF/NOT_SUP → cleartext logins (MEDIUM)
- ENCRYPTION ON/REQ → transport security (INFO)
- exact build number + product line + support window (INFO)

**How to Execute:**
```bash
# Basic scan
nmap -p 1433 --script mssql-prelogin-check target.example.com
```

**Sample Output:**
```
| mssql-prelogin-check:
|   Risk Level: 🟡 MEDIUM
|   Status: AUDITED - SQL Server PRELOGIN examined for encryption posture and build.
|   Findings:
|     [MEDIUM] the SQL Server PRELOGIN answers ENCRYPT_OFF: login packets
|              (including passwords) will travel in cleartext (cleartext-login)
|     [INFO] SQL Server build 15.0.4332.0 (SQL Server 2019) answered
|            PRELOGIN; support window: extended support ends May 2030
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=0 INFO=1
|   Weighted score: 5
|   build_version: 15.0.4332.0
|   encryption_mode: ENCRYPT_OFF
|   product_line: SQL Server 2019
```

---

### 10. **mysql-empty-password-check** - Empty-Password Login
**Description:** Attempts a credentialless HandshakeResponse41 login (default user root, empty password) against MySQL/MariaDB port 3306. An OK packet proves the account accepts no password at all (MEDIUM — reinforced wording for superuser names); ERROR 1045 is the positive evidence that auth is enforced (INFO). The handshake fingerprint (version, plugin, capability flags) is reported alongside.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery, vuln

**What it checks:**
- root (or configured user) empty-password login accepted (MEDIUM)
- ERROR 1045/1130/1049 rejection evidence (INFO)
- server version + plugin context (INFO/LOW)

**How to Execute:**
```bash
# Basic scan (default user root)
nmap -p 3306 --script mysql-empty-password-check target.example.com

# Test a different account
nmap -p 3306 --script mysql-empty-password-check --script-args mysql-empty-password-check.user=app target.example.com
```

**Sample Output:**
```
| mysql-empty-password-check:
|   Risk Level: 🟡 MEDIUM
|   Status: AUDITED - MySQL empty-password login tested for the 'root' account.
|   Findings:
|     [MEDIUM] the 'root' account accepted an EMPTY password: the
|              credentialless login succeeded (a superuser account can
|              connect with no password at all) (empty-password)
|     [LOW] the server reports 5.7.42-log, an unsupported line (version-eol)
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=1 INFO=0
|   Weighted score: 6
|   server_version: 5.7.42-log
|   auth_plugin: mysql_native_password
```

---

### 11. **mysql-ssl-support-check** - CLIENT_SSL Capability
**Description:** Reads the HandshakeV10 the server sends on every new connection and decodes the 32-bit capability field. CLIENT_SSL (0x0800) set means the server can negotiate TLS (INFO — exposure depends on client ssl policy); not set means no client can get a TLS channel, so credentials travel in cleartext (MEDIUM). Every set capability bit is named; CLIENT_PLUGIN_AUTH and CLIENT_CONNECT_ATTRS are noted.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery

**What it checks:**
- CLIENT_SSL advertised (INFO) / absent (MEDIUM)
- full capability flag decoding (context)
- auth plugin + version context (INFO)

**How to Execute:**
```bash
# Basic scan
nmap -p 3306 --script mysql-ssl-support-check target.example.com
```

**Sample Output:**
```
| mysql-ssl-support-check:
|   Risk Level: 🟡 MEDIUM
|   Status: AUDITED - MySQL HandshakeV10 examined for the CLIENT_SSL capability.
|   Findings:
|     [MEDIUM] the HandshakeV10 does NOT advertise CLIENT_SSL (0x0800): the
|              server will not negotiate TLS, so the password exchange and all
|              queries travel in cleartext (ssl-not-offered)
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=0 INFO=1
|   Weighted score: 5
|   client_ssl: not advertised
|   capability_flags: 0x0008a201
|   server_version: 8.0.32
```

---

### 12. **postgresql-ssl-support-check** - SSLRequest Offer
**Description:** Sends the 8-byte PostgreSQL SSLRequest (code 80877103) and parses the single-byte reply: 'S' means the server can negotiate TLS (INFO — the exposure depends on client sslmode policy and certificate trust); 'N' means the server refuses TLS and every connection is cleartext (MEDIUM). No handshake is completed and no credentials are involved.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery

**What it checks:**
- SSLRequest answered 'S' (INFO) / 'N' (MEDIUM)
- raw reply byte + client-side mitigation context (context)

**How to Execute:**
```bash
# Basic scan
nmap -p 5432 --script postgresql-ssl-support-check target.example.com
```

**Sample Output:**
```
| postgresql-ssl-support-check:
|   Risk Level: 🟡 MEDIUM
|   Status: AUDITED - PostgreSQL SSLRequest probed for TLS offer.
|   Findings:
|     [MEDIUM] PostgreSQL answered the SSLRequest with 'N': the server will
|              not negotiate TLS, so every connection - including the password
|              exchange - is cleartext on the wire (ssl-refused)
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=0 INFO=0
|   Weighted score: 4
|   sslreply_class: refused
|   raw_reply_byte: 0x4e
|   context: no client can establish a TLS channel to this server
```

---

### 13. **postgresql-trust-auth-check** - Trust Authentication
**Description:** Sends a StartupMessage for the postgres user with no password (user/database configurable) and classifies the AuthenticationRequest: code 0 (AuthenticationOk) means pg_hba.conf is using trust authentication for this host — anyone on the network becomes the postgres superuser (MEDIUM); codes 3/5/9/12 mean a password exchange is required (INFO, method reported; SASL/SCRAM mechanism captured); an ErrorResponse is the positive denial evidence.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery, vuln

**What it checks:**
- AuthenticationOk with no credentials (MEDIUM — trust auth)
- cleartext/MD5/SASL/SCRAM password requirement (INFO/LOW)
- SCRAM mechanism list (context)
- ErrorResponse denial evidence (INFO)

**How to Execute:**
```bash
# Basic scan (default postgres/postgres)
nmap -p 5432 --script postgresql-trust-auth-check target.example.com

# Probe a specific role/database
nmap -p 5432 --script postgresql-trust-auth-check --script-args postgresql-trust-auth-check.user=app,postgresql-trust-auth-check.database=appdb target.example.com
```

**Sample Output:**
```
| postgresql-trust-auth-check:
|   Risk Level: 🟡 MEDIUM
|   Status: AUDITED - PostgreSQL trust authentication probed for the postgres role.
|   Findings:
|     [MEDIUM] PostgreSQL granted an immediate session for user 'postgres'
|              with NO credentials (AuthenticationOk, code 0) - pg_hba.conf
|              is using trust authentication for this host (trust-auth)
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=1 LOW=0 INFO=0
|   Weighted score: 4
|   auth_code: 0
|   auth_method: trust (no password)
```

---

### 14. **redis-admin-command-exposure** - Administrative Command Surface
**Description:** After establishing the auth posture with PING, sends COMMAND INFO for a fixed list of 15 administrative commands (FLUSHALL, FLUSHDB, CONFIG, SHUTDOWN, DEBUG, SLAVEOF, REPLICAOF, MODULE, SCRIPT, EVAL, SAVE, BGSAVE, BGREWRITEAOF, KEYS, SCAN) and reports which are present in the server's command table. COMMAND INFO does not execute any of them. Present admin commands are MEDIUM; the dangerous subset (CONFIG, SHUTDOWN, SLAVEOF/REPLICAOF, MODULE, EVAL, DEBUG) is additionally HIGH.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery, vuln

**What it checks:**
- admin commands present and anonymously visible (MEDIUM)
- dangerous admin subset present (HIGH)
- full-keyspace data commands present (LOW)
- auth-required short-circuit (INFO)

**How to Execute:**
```bash
# Basic scan
nmap -p 6379 --script redis-admin-command-exposure target.example.com
```

**Sample Output:**
```
| redis-admin-command-exposure:
|   Risk Level: 🟡 MEDIUM
|   Status: AUDITED - Redis administrative command surface checked via COMMAND INFO.
|   Findings:
|     [HIGH] dangerous administrative commands are present and anonymously
|            visible: CONFIG, SHUTDOWN, DEBUG, SLAVEOF, REPLICAOF, MODULE,
|            EVAL (dangerous-admin-commands)
|     [MEDIUM] 13 administrative command(s) are present in the anonymous
|              command table (admin-commands-present)
|     [LOW] full-keyspace data commands are present: KEYS, SCAN
|   Severity counts: CRITICAL=0 HIGH=1 MEDIUM=1 LOW=1 INFO=0
|   Weighted score: 13
|   auth_posture: anonymous
```

---

### 15. **redis-unauthenticated-access** - Unauthenticated Command Execution
**Description:** Sends PING to Redis (port 6379) without AUTH: a PONG means commands execute anonymously (MEDIUM); -NOAUTH means auth is enforced (INFO). When open, it parses INFO (version, memory, hit rate, clients), performs one bounded write probe — SET/GET/DEL on a unique per-host key that is always deleted again, leaving no residue — and classifies the Redis line (4.x/5.x EOL, 6.x aging, 7.x supported).

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery, vuln

**What it checks:**
- anonymous PING success (MEDIUM)
- anonymous write probe success (MEDIUM reinforcement, self-cleaning)
- EOL/aging Redis line (MEDIUM/LOW)
- INFO memory/hit-rate posture (context)

**How to Execute:**
```bash
# Basic scan (write probe enabled)
nmap -p 6379 --script redis-unauthenticated-access target.example.com

# Read-only variant
nmap -p 6379 --script redis-unauthenticated-access --script-args redis-unauthenticated-access.skipwriteprobe=true target.example.com
```

**Sample Output:**
```
| redis-unauthenticated-access:
|   Risk Level: 🟡 MEDIUM
|   Status: AUDITED - Redis checked for unauthenticated command execution.
|   Findings:
|     [MEDIUM] Redis executed PING without authentication and answered PONG
|              (unauth-ping)
|     [MEDIUM] the anonymous write probe succeeded: SET/GET/DEL on key
|              nse-audit:192.0.2.10:6379 all worked without authentication
|              (the key was deleted again) (unauth-write-probe)
|     [LOW] Redis 6.2.7 is in its end-of-life window (version-aging)
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=2 LOW=1 INFO=0
|   Weighted score: 10
|   redis_version: 6.2.7
|   used_memory: 1.00M
|   keyspace_hit_rate: 95.7%
```

---

### 16. **mysql-banner-grab** - HandshakeV10 Banner Capture
**Description:** Captures the full MySQL/MariaDB HandshakeV10 banner from the spontaneous server packet: version string, thread id, 32-bit capability flags with every set bit named, default charset, status flags, auth plugin, auth-data length and the SSL offer. Classifies the family (MySQL vs MariaDB) and release line with end-of-support state. Purely discovery — nothing is sent.

**Risk Level:** 🟢 LOW | **Category:** safe, discovery, version

**What it checks:**
- server version string + family + support line (INFO/LOW when EOL)
- full capability flag decoding (context)
- auth plugin choice (mysql_native_password vs caching_sha2_password, INFO)
- 21-byte v10 salt consistency (context)

**How to Execute:**
```bash
# Basic scan
nmap -p 3306 --script mysql-banner-grab target.example.com
```

**Sample Output:**
```
| mysql-banner-grab:
|   Risk Level: 🟢 LOW
|   Status: AUDITED - MySQL/MariaDB HandshakeV10 banner captured.
|   Findings:
|     [LOW] the banner reports MySQL 5.7.42-log, an unsupported line
|           (MySQL 5.7 left Extended Support in October 2023) (version-eol)
|     [INFO] the advertised auth plugin is mysql_native_password (legacy SHA1)
|   Severity counts: CRITICAL=0 HIGH=0 MEDIUM=0 LOW=1 INFO=1
|   Weighted score: 3
|   server_version: 5.7.42-log
|   server_family: MySQL
|   capability_flags: 0x0008aa01
|   auth_plugin: mysql_native_password
|   ssl_offered: yes (CLIENT_SSL)
|   auth_data_note: full 21-byte v10 salt, consistent with HandshakeV10
```

## Typical Scan

```bash
# Full database audit of a host running the common set
nmap -p 3306,5432,6379,27017,11211 --script database-* target.example.com

# Everything in this folder at once
nmap -p 3306,5432,6379,27017,11211,9042,8123,5984,2379,8086,7474,1433 \
  --script cassandra-unauth-check,clickhouse-unauth-check,couchdb-unauth-check,etcd-unauth-keyspace,influxdb-unauth-check,memcached-stats-dump,mongodb-unauthenticated-check,mssql-prelogin-check,mysql-banner-grab,mysql-empty-password-check,mysql-ssl-support-check,neo4j-unauth-browser,postgresql-ssl-support-check,postgresql-trust-auth-check,redis-admin-command-exposure,redis-unauthenticated-access \
  target.example.com
```
