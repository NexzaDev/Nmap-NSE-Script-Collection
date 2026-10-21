# ☁️ Cloud Metadata & SSRF Security Audits

**16 Nmap NSE scripts** for auditing the cloud metadata / SSRF attack surface over HTTP:

**Covers:**

- A metadata knowledge layer covering the seven-provider matrix (AWS IMDS, Alibaba ECS, GCP, Azure, Oracle OCI, DigitalOcean, OpenStack) with their required headers and gate semantics
- IP-obfuscation encodings (decimal/hex/octal) with link-local and RFC1918 classification
- IMDSv2 token issuance and the enforcement verdict matrix
- AWS roles/credential-document/identity-document decoders
- GCP flavor checks and service-account token parsing
- Azure instance and managed-identity token parsing
- Droplet/OpenStack/OCI instance parsers
- User-data and cloud-init classifiers with secret-pattern masking
- Scheme-risk grading
- Redirect-chain and DNS-rebinding classifiers

The suite audits the two classic cloud pivots: direct metadata readability (IMDSv1 openness, IAM credential documents, user-data secrets, service-account tokens, instance identities) and SSRF primitives that reach it indirectly (open fetch proxies with plain and obfuscated targets, DNS-rebinding TOCTOU windows, Kubernetes API relays)

Credential material is always masked in output - key ids, secrets and tokens appear as lengths and short masked prefixes - and every probe is a bounded read-only HTTP exchange.

**Port:** target HTTP service (any port with `shortport.http`) | **Metadata targets:** 169.254.169.254, 100.100.100.200 | **Protocols:** HTTP/1.1 (IMDS, IMDSv2, metadata APIs, fetch proxies) | **Total lines of Lua:** 23,996

---

## 📋 Script Index

| # | Script | Risk Level | Category | Lines |
|---|--------|-----------|----------|-------|
| 1 | [aws-iam-credentials-leak](#1-aws-iam-credentials-leak---aws-iam-role-credential-documents) | 🔴 CRITICAL | vuln, safe | 1518 |
| 2 | [aws-metadata-imdsv1-check](#2-aws-metadata-imdsv1-check---aws-imdsv1-openness-check) | 🔴 CRITICAL | vuln, safe | 1501 |
| 3 | [aws-user-data-script-leak](#3-aws-user-data-script-leak---ec2-user-data-secret-classification) | 🔴 CRITICAL | vuln, safe | 1522 |
| 4 | [azure-imds-identity-leak](#4-azure-imds-identity-leak---azure-imds-instance--managed-identity) | 🔴 CRITICAL | vuln, safe | 1511 |
| 5 | [gcp-metadata-flavor-check](#5-gcp-metadata-flavor-check---gcp-metadata-flavor-header-matrix) | 🔴 CRITICAL | vuln, safe | 1504 |
| 6 | [gcp-service-account-token](#6-gcp-service-account-token---gcp-service-account-token-minting) | 🔴 CRITICAL | vuln, safe | 1530 |
| 7 | [kubernetes-pod-metadata-ssrf](#7-kubernetes-pod-metadata-ssrf---kubernetes-api-via-fetch-proxy) | 🔴 CRITICAL | vuln, safe | 1514 |
| 8 | [alibaba-cloud-metadata-leak](#8-alibaba-cloud-metadata-leak---alibaba-ecs-metadata-100.100.100.200) | 🟠 HIGH | vuln, safe | 1520 |
| 9 | [digitalocean-metadata-leak](#9-digitalocean-metadata-leak---digitalocean-droplet-metadata) | 🟠 HIGH | vuln, safe | 1505 |
| 10 | [oracle-cloud-metadata-leak](#10-oracle-cloud-metadata-leak---oracle-cloud-instance-metadata) | 🟠 HIGH | vuln, safe | 1514 |
| 11 | [cloud-init-log-exposure](#11-cloud-init-log-exposure---cloud-init-artifact-exposure) | 🟡 MEDIUM | discovery, safe | 1477 |
| 12 | [cloud-metadata-ip-proxy-probe](#12-cloud-metadata-ip-proxy-probe---proxy-fetch-ssrf-plain--obfuscated-ips) | 🟡 MEDIUM | defensive, safe | 1492 |
| 13 | [cloud-ssrf-dns-rebinding-check](#13-cloud-ssrf-dns-rebinding-check---dns-rebinding-double-lookup-probe) | 🟡 MEDIUM | defensive, safe | 1483 |
| 14 | [openstack-metadata-probe](#14-openstack-metadata-probe---openstack-tenant-metadata) | 🟡 MEDIUM | discovery, safe | 1470 |
| 15 | [cloud-imds-v2-token-enforced](#15-cloud-imds-v2-token-enforced---imdsv2-token-enforcement-verification) | 🟢 LOW | defensive, safe | 1464 |
| 16 | [cloud-instance-identity-doc](#16-cloud-instance-identity-doc---aws-identity-document-disclosure) | 🟢 LOW | discovery, safe | 1471 |

---

### 1. **aws-iam-credentials-leak** - AWS IAM Role Credential Documents
**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Lists /latest/meta-data/iam/security-credentials/.
- Fetches each role's document and parses code, type, key ids.
- Masks secrets and session tokens; reports lengths and expiry.
- Grades the leak.
- Why it matters: The credential document IS the cloud compromise: AccessKeyId plus session token authenticates as the instance role within seconds. Role names alone already map workload permissions for an attacker.
- Safety: read-only GETs; the audit never prints secret values and never uses the credentials it sees.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script aws-iam-credentials-leak target.corp.example.com

# Tuned request budget
nmap -p 80,8080,443 --script aws-iam-credentials-leak --script-args 'aws-iam-credentials-leak.timeout=8,aws-iam-credentials-leak.maxrequests=48' target.corp.example.com
```

**Sample Output:**
```
| aws-iam-credentials-leak:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - full IAM credential documents readable without authentication
```

---

### 2. **aws-metadata-imdsv1-check** - AWS IMDSv1 Openness Check
**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Sends GET /latest/meta-data/ without a token.
- Sends PUT /latest/api/token to check the v2 endpoint.
- Grades enforcement (v1 open vs token required).
- Reports the metadata index size as exposure evidence.
- Why it matters: IMDSv1 is the enabler of every cloud credential-theft story: one SSRF on any application running on the host becomes IAM keys. IMDSv2 enforcement is the single most effective metadata hardening and this probe proves whether it is actually active.
- Safety: two read-only HTTP exchanges against the link-local service; no credentials are requested or rendered.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script aws-metadata-imdsv1-check target.corp.example.com

# Tuned request budget
nmap -p 80,8080,443 --script aws-metadata-imdsv1-check --script-args 'aws-metadata-imdsv1-check.timeout=8,aws-metadata-imdsv1-check.maxrequests=48' target.corp.example.com
```

**Sample Output:**
```
| aws-metadata-imdsv1-check:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - IMDSv1 answers without a session token
```

---

### 3. **aws-user-data-script-leak** - EC2 user-data Secret Classification
**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- GETs /latest/user-data without a session token.
- Profiles the payload: size, shebang, fetch commands, metadata calls.
- Scans for secret-shaped patterns and reports masked samples.
- Grades the exposure.
- Why it matters: Bootstrap scripts notoriously embed database passwords, API keys and bootstrap-time IAM commands - all readable next to the metadata service they configure. Even secret-free scripts disclose internal hostnames, repos and topology that shape the next attack step.
- Safety: a single read-only GET; secret matches are masked before rendering and never printed in full.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script aws-user-data-script-leak target.corp.example.com

# Tuned request budget
nmap -p 80,8080,443 --script aws-user-data-script-leak --script-args 'aws-user-data-script-leak.timeout=8,aws-user-data-script-leak.maxrequests=48' target.corp.example.com
```

**Sample Output:**
```
| aws-user-data-script-leak:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - user-data readable and contains secret-shaped values
```

---

### 4. **azure-imds-identity-leak** - Azure IMDS Instance & Managed Identity
**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- GETs /metadata/instance without and with Metadata: true.
- On success parses subscription, vmId, resource group, location.
- Mints a managed-identity token and reports it masked.
- Grades the identity exposure.
- Why it matters: A reachable Azure IMDS converts any SSRF into subscription-level access: instance data first, then a management-API token minted from the attached managed identity. The header matrix distinguishes true refusal (header required and probes blocked) from network reachability.
- Safety: three read-only GETs; token values are masked and never reused.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script azure-imds-identity-leak target.corp.example.com

# Tuned request budget
nmap -p 80,8080,443 --script azure-imds-identity-leak --script-args 'azure-imds-identity-leak.timeout=8,azure-imds-identity-leak.maxrequests=48' target.corp.example.com
```

**Sample Output:**
```
| azure-imds-identity-leak:
|   Risk Level: 🔴 CRITICAL
|   Status: SECURE - Azure IMDS requires the Metadata header and refused both probes
```

---

### 5. **gcp-metadata-flavor-check** - GCP Metadata-Flavor Header Matrix
**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- GETs /computeMetadata/v1/instance/ without the flavor header.
- GETs the same path with Metadata-Flavor: Google.
- Lists the directory entries that the instance exposes.
- Grades reachability and header enforcement.
- Why it matters: GCP metadata leaks project IDs, zones, service-account emails and (via one more call) OAuth tokens; the flavor header is the only gate between an SSRF and those secrets. Header-based refusals prove the server is hardened; 200s prove any SSRF on this host reads the directory.
- Safety: two read-only GETs; no token endpoints are touched.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script gcp-metadata-flavor-check target.corp.example.com

# Tuned request budget
nmap -p 80,8080,443 --script gcp-metadata-flavor-check --script-args 'gcp-metadata-flavor-check.timeout=8,gcp-metadata-flavor-check.maxrequests=48' target.corp.example.com
```

**Sample Output:**
```
| gcp-metadata-flavor-check:
|   Risk Level: 🔴 CRITICAL
|   Status: SECURE - GCP metadata refuses non-Google-flavor requests
```

---

### 6. **gcp-service-account-token** - GCP Service-Account Token Minting
**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Lists /computeMetadata/v1/instance/service-accounts/.
- Mints one token per account via .../token with the flavor header.
- Reports tokens masked with type, length and expiry.
- Grades the identity exposure.
- Why it matters: The service-account token is the GCP equivalent of the AWS credential document: with it, an attacker calls Google APIs as the workload identity immediately. The account list itself scopes the attack (default compute SA vs dedicated least-privilege identities).
- Safety: read-only GETs; token values are masked in output, never printed in full and never used against Google APIs.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script gcp-service-account-token target.corp.example.com

# Tuned request budget
nmap -p 80,8080,443 --script gcp-service-account-token --script-args 'gcp-service-account-token.timeout=8,gcp-service-account-token.maxrequests=48' target.corp.example.com
```

**Sample Output:**
```
| gcp-service-account-token:
|   Risk Level: 🔴 CRITICAL
|   Status: SECURE - service-account directory refused the probe
```

---

### 7. **kubernetes-pod-metadata-ssrf** - Kubernetes API via Fetch Proxy
**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Relays three kube-apiserver paths through /fetch?url=.
- Parses PodList/ServiceAccount payloads from the answers.
- Cross-checks whether the link-local metadata also relays.
- Grades the combined cluster+cloud exposure.
- Why it matters: Pod-list reads through a proxy disclose workload topology, images and service accounts - the staging map for container escape. The same open relay usually reaches cloud metadata too, chaining pod inventory directly into credential theft.
- Safety: four read-only GETs through the target's own proxy; no tokens are presented and no cluster state is modified.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script kubernetes-pod-metadata-ssrf target.corp.example.com

# Tuned request budget
nmap -p 80,8080,443 --script kubernetes-pod-metadata-ssrf --script-args 'kubernetes-pod-metadata-ssrf.timeout=8,kubernetes-pod-metadata-ssrf.maxrequests=48' target.corp.example.com
```

**Sample Output:**
```
| kubernetes-pod-metadata-ssrf:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - internal Kubernetes API readable through the fetch proxy
```

---

### 8. **alibaba-cloud-metadata-leak** - Alibaba ECS Metadata (100.100.100.200)
**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- GETs the metadata index on the Alibaba endpoint.
- Reads instance-id and lists RAM security-credentials roles.
- Grades the exposure with role names as evidence.
- Why it matters: Alibaba metadata mirrors the AWS pattern; an open service hands out instance identity and RAM role names whose credential documents are one additional request away. The dedicated 100.100.100.200 endpoint is often forgotten in firewall rules that only mention the AWS address.
- Safety: three read-only GETs; no RAM credential documents are fetched and no values are rendered unmasked.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script alibaba-cloud-metadata-leak target.corp.example.com

# Tuned request budget
nmap -p 80,8080,443 --script alibaba-cloud-metadata-leak --script-args 'alibaba-cloud-metadata-leak.timeout=8,alibaba-cloud-metadata-leak.maxrequests=48' target.corp.example.com
```

**Sample Output:**
```
| alibaba-cloud-metadata-leak:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - Alibaba ECS metadata readable without authentication
```

---

### 9. **digitalocean-metadata-leak** - DigitalOcean Droplet Metadata
**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- GETs /metadata/v1.json and parses droplet identity.
- Cross-checks the plain /metadata/v1/hostname and /id endpoints.
- Grades the disclosure.
- Why it matters: Droplet id, region, hostname and enabled features are the targeting layer for control-plane and snapshot attacks. A reachable metadata endpoint also proves which SSRF primitive can pivot into cloud-specific data on this host.
- Safety: three read-only GETs; no account tokens exist on this service and none are requested.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script digitalocean-metadata-leak target.corp.example.com

# Tuned request budget
nmap -p 80,8080,443 --script digitalocean-metadata-leak --script-args 'digitalocean-metadata-leak.timeout=8,digitalocean-metadata-leak.maxrequests=48' target.corp.example.com
```

**Sample Output:**
```
| digitalocean-metadata-leak:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - DigitalOcean droplet metadata readable without authentication
```

---

### 10. **oracle-cloud-metadata-leak** - Oracle Cloud Instance Metadata
**Risk Level:** 🟠 HIGH | **Category:** vuln, safe

**What it checks:**
- GETs /opc/v2/instance/ with the Oracle bearer header.
- Cross-checks the canonicalRegionName endpoint.
- Probes the v1 auth surface without headers.
- Grades the metadata exposure.
- Why it matters: The required OCI header is documented publicly, so the gate stops nothing but accidental SSRF; compartment OCIDs, region, shape and display name still leak to a real attacker. The v1 auth surface adds instance identity material when reachable.
- Safety: three read-only GETs; compartment OCIDs are masked and no instance principal actions are attempted.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script oracle-cloud-metadata-leak target.corp.example.com

# Tuned request budget
nmap -p 80,8080,443 --script oracle-cloud-metadata-leak --script-args 'oracle-cloud-metadata-leak.timeout=8,oracle-cloud-metadata-leak.maxrequests=48' target.corp.example.com
```

**Sample Output:**
```
| oracle-cloud-metadata-leak:
|   Risk Level: 🟠 HIGH
|   Status: SECURE - OCI metadata refused the probe
```

---

### 11. **cloud-init-log-exposure** - cloud-init Artifact Exposure
**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Probes the three common cloud-init artifact paths.
- On content: profiles stages, datasource, instance id, token refs.
- Grades the log exposure with masked evidence.
- Why it matters: cloud-init logs record datasources, instance ids and sometimes the bootstrap tokens or curl lines used to fetch secrets. An exposed log turns a bland metadata service into a forensic gold mine and confirms the instance identity for follow-up attacks.
- Safety: up to three read-only GETs; token-shaped strings are reported as counts and masked samples only.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script cloud-init-log-exposure target.corp.example.com

# Tuned request budget
nmap -p 80,8080,443 --script cloud-init-log-exposure --script-args 'cloud-init-log-exposure.timeout=8,cloud-init-log-exposure.maxrequests=48' target.corp.example.com
```

**Sample Output:**
```
| cloud-init-log-exposure:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - cloud-init log exposes bootstrap identity material
```

---

### 12. **cloud-metadata-ip-proxy-probe** - Proxy Fetch SSRF (Plain + Obfuscated IPs)
**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Sends five /fetch?url= probes: index, instance-id, IAM roles, decimal-encoded and hex-encoded metadata URLs.
- Classifies each answer: relayed content, marker seen, 4xx block.
- Grades the proxy's SSRF posture.
- Why it matters: Open URL-fetch features (webhooks, previewers, importers) are the classic SSRF doorway to 169.254.169.254 - the whole class of cloud credential theft starts here. Encoded IPs (decimal, hex, octal) bypass naive string filters, so the probe tests both plain and obfuscated forms.
- Safety: read-only GETs through the target's own proxy; no schemes beyond http are attempted and no user data is fetched.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script cloud-metadata-ip-proxy-probe target.corp.example.com

# Tuned request budget
nmap -p 80,8080,443 --script cloud-metadata-ip-proxy-probe --script-args 'cloud-metadata-ip-proxy-probe.timeout=8,cloud-metadata-ip-proxy-probe.maxrequests=48' target.corp.example.com
```

**Sample Output:**
```
| cloud-metadata-ip-proxy-probe:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - proxy fetch reaches metadata including obfuscated targets
```

---

### 13. **cloud-ssrf-dns-rebinding-check** - DNS Rebinding Double-Lookup Probe
**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Asks the target resolver for the same name twice.
- Classifies the pair (stable public / rebound to metadata / rebound to private / inconsistent).
- Probes the fetch path for echoed connection IPs.
- Grades the TOCTOU exposure.
- Why it matters: Rebinding defeats IP allowlists: the first lookup passes the check, the second (at connect time) flips to 169.254.169.254 and the fetch relays straight into metadata. The probe needs no attacker DNS - it simply asks the resolver twice and classifies the delta.
- Safety: three read-only requests; the probe hostname is audit-owned and no external DNS infrastructure is contacted beyond the target's resolver path.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script cloud-ssrf-dns-rebinding-check target.corp.example.com

# Tuned request budget
nmap -p 80,8080,443 --script cloud-ssrf-dns-rebinding-check --script-args 'cloud-ssrf-dns-rebinding-check.timeout=8,cloud-ssrf-dns-rebinding-check.maxrequests=48' target.corp.example.com
```

**Sample Output:**
```
| cloud-ssrf-dns-rebinding-check:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - resolver answers switch into the metadata range on repeat lookups
```

---

### 14. **openstack-metadata-probe** - OpenStack Tenant Metadata
**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- GETs /openstack/latest/meta_data.json.
- Parses uuid, project_id (masked), hostname, AZ and meta keys.
- Grades the tenant-context disclosure.
- Why it matters: OpenStack metadata exposes tenant project ids and instance uuids - the map needed to target the control plane or sibling workloads in a multi-tenant cloud. In private clouds this endpoint often ends up routed on shared management networks where every tenant can reach it.
- Safety: one read-only GET; project identifiers are masked.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script openstack-metadata-probe target.corp.example.com

# Tuned request budget
nmap -p 80,8080,443 --script openstack-metadata-probe --script-args 'openstack-metadata-probe.timeout=8,openstack-metadata-probe.maxrequests=48' target.corp.example.com
```

**Sample Output:**
```
| openstack-metadata-probe:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - OpenStack instance metadata readable without authentication
```

---

### 15. **cloud-imds-v2-token-enforced** - IMDSv2 Token Enforcement Verification
**Risk Level:** 🟢 LOW | **Category:** defensive, safe

**What it checks:**
- PUTs /latest/api/token and parses the issued session token.
- GETs metadata without the token (expect 401 when enforced).
- GETs metadata with the token (expect 200) to confirm token flow.
- Grades enforcement with actionable notes.
- Why it matters: HttpTokens=optional is a false sense of security: attackers simply skip the token. Only the observed 401-without-token / 200-with-token matrix proves real enforcement. This is the positive-control probe defenders can schedule to catch enforcement drift after AMI or launch-template changes.
- Safety: three read-only exchanges; the issued token is used once for verification and then discarded (masked in output).

**How to Execute:**
```bash
nmap -p 80,8080,443 --script cloud-imds-v2-token-enforced target.corp.example.com

# Tuned request budget
nmap -p 80,8080,443 --script cloud-imds-v2-token-enforced --script-args 'cloud-imds-v2-token-enforced.timeout=8,cloud-imds-v2-token-enforced.maxrequests=48' target.corp.example.com
```

**Sample Output:**
```
| cloud-imds-v2-token-enforced:
|   Risk Level: 🟢 LOW
|   Status: VULNERABLE - token endpoint exists but token-less reads still succeed
```

---

### 16. **cloud-instance-identity-doc** - AWS Identity Document Disclosure
**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- GETs /latest/dynamic/instance-identity/document token-less.
- Parses accountId, instanceId, region, AZ, type, image.
- Reports the disclosure with INFO/MEDIUM grading.
- Why it matters: The identity document confirms the exact account, region and instance type - everything an attacker needs to aim console, STS or billing attacks and to price the value of the role they hope to steal. It is also a reliable AWS fingerprint when endpoints are proxied.
- Safety: one read-only GET; no signature verification or STS calls are performed.

**How to Execute:**
```bash
nmap -p 80,8080,443 --script cloud-instance-identity-doc target.corp.example.com

# Tuned request budget
nmap -p 80,8080,443 --script cloud-instance-identity-doc --script-args 'cloud-instance-identity-doc.timeout=8,cloud-instance-identity-doc.maxrequests=48' target.corp.example.com
```

**Sample Output:**
```
| cloud-instance-identity-doc:
|   Risk Level: 🟢 LOW
|   Status: VULNERABLE - instance identity document readable without authentication
```

