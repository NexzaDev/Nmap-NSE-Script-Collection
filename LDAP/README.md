# 🌳 LDAP Security Audits

**16 Nmap NSE scripts** for auditing Active Directory and standalone LDAP directories over the LDAPv3 wire protocol (RFC 4511):

**Covers:**

- Anonymous/null bind enumeration
- AD domain identity mapping via rootDSE
- ASREPROAST and Kerberoasting target discovery through SPN and UAC-flag analysis
- AD CS certificate template exposure
- Legacy LAPS password readability
- GPO container enumeration
- Unconstrained delegation discovery
- Cleartext Simple Bind risk
- StartTLS support
- LDAP signing/channel-binding enforcement (LdapErr 531/533 signatures)
- Paged-results and size-limit behaviour
- Sensitive password-attribute readability (userPassword/unicodePwd)
- RootDSE metadata leakage and the supported controls/extensions surface

Every script speaks real LDAP BER - message envelopes, BindRequest/SearchRequest/ExtendedRequest codecs, full RFC 4511 filter encoding (and/or/not/equality/substrings/greaterOrEqual/lessOrEqual/present/approxMatch), entry and SearchResultDone parsing, controls (paged results 1.2.840.113556.1.4.319, StartTLS 1.3.6.1.4.1.1466.20037) - and turns the returned directory data into evidence-based findings.

All probes are read-only binds and searches with bounded request budgets, page caps and timeouts.

**Ports:** 389 (`ldap`), 636 (`ldaps`) or matched `ldap` service | **Protocol:** LDAPv3 over TCP (RFC 4511/4512) with AD extensions (MS-ADTS paged results, StartTLS) | **Total lines of Lua:** 29,647

---

## 📋 Script Index

| # | Script | Risk Level | Category | Lines |
|---|--------|-----------|----------|-------|
| 1 | [ldap-anonymous-bind](#1-ldap-anonymous-bind---anonymous-bind-enumeration) | 🔴 CRITICAL | vuln, safe | 1877 |
| 2 | [ldap-asreproast-candidates](#2-ldap-asreproast-candidates---asreproast-candidate-discovery) | 🔴 CRITICAL | vuln, safe | 1835 |
| 3 | [ldap-laps-password-exposure](#3-ldap-laps-password-exposure---laps-password-exposure) | 🔴 CRITICAL | vuln, safe | 1825 |
| 4 | [ldap-null-bind-enum](#4-ldap-null-bind-enum---null-bind-directory-enumeration) | 🔴 CRITICAL | vuln, safe | 1854 |
| 5 | [ldap-unconstrained-delegation](#5-ldap-unconstrained-delegation---unconstrained-delegation-discovery) | 🔴 CRITICAL | vuln, safe | 1852 |
| 6 | [ldap-user-account-attributes](#6-ldap-user-account-attributes---sensitive-account-attribute-exposure) | 🔴 CRITICAL | vuln, safe | 1915 |
| 7 | [ldap-certificate-templates](#7-ldap-certificate-templates---ad-cs-certificate-template-exposure) | 🟠 HIGH | discovery, safe | 1878 |
| 8 | [ldap-gpo-permissions-audit](#8-ldap-gpo-permissions-audit---gpo-container-enumeration) | 🟠 HIGH | discovery, safe | 1868 |
| 9 | [ldap-signing-enforced](#9-ldap-signing-enforced---ldap-signing-enforcement-check) | 🟠 HIGH | defensive, safe | 1895 |
| 10 | [ldap-spn-service-accounts](#10-ldap-spn-service-accounts---spn-and-service-account-enumeration) | 🟠 HIGH | discovery, safe | 1906 |
| 11 | [ldap-cleartext-auth-risk](#11-ldap-cleartext-auth-risk---cleartext-authentication-exposure) | 🟡 MEDIUM | defensive, safe | 1818 |
| 12 | [ldap-rootdse-leak](#12-ldap-rootdse-leak---rootdse-metadata-leakage) | 🟡 MEDIUM | discovery, safe | 1801 |
| 13 | [ldap-starttls-support](#13-ldap-starttls-support---starttls-support-probe) | 🟡 MEDIUM | defensive, safe | 1820 |
| 14 | [ldap-ad-domain-info](#14-ldap-ad-domain-info---ad-domain-info-mapping) | 🟢 LOW | discovery, safe | 1834 |
| 15 | [ldap-paged-search-limit](#15-ldap-paged-search-limit---paged-results-and-size-limit-audit) | 🟢 LOW | discovery, safe | 1839 |
| 16 | [ldap-supported-controls](#16-ldap-supported-controls---supported-controls-surface) | 🟢 LOW | discovery, safe | 1830 |

---

### 1. **ldap-anonymous-bind** - Anonymous Bind Enumeration
**Description:** Tests unauthenticated (anonymous) LDAP bind and checks if base rootDSE is queryable.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Opens a TCP session and issues an anonymous (null) BindRequest.
- Checks whether the rootDSE base is queryable anonymously.
- Attempts a bounded anonymous search for user accounts with a sAMAccountName, using the server's default naming context.
- Classifies the exposure: rejected bind, queryable metadata only, or full anonymous directory enumeration.
- Why it matters: Anonymous (null) binds are the cheapest entry point into a directory: no credential, no Kerberos ticket, just an empty DN.
- Safety: one bind, two bounded read-only searches with a small size limit; no write operations.

**How to Execute:**
```bash
nmap -p 389 --script ldap-anonymous-bind dc01.corp.example.com

# Tuned request budget
nmap -p 389 --script ldap-anonymous-bind --script-args 'ldap-anonymous-bind.maxrequests=30,ldap-anonymous-bind.timeout=8,ldap-anonymous-bind.user_limit=20' dc01.corp.example.com
```

**Sample Output:**
```
| ldap-anonymous-bind:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - anonymous directory enumeration enabled (6 accounts visible)
```

---

### 2. **ldap-asreproast-candidates** - ASREPROAST Candidate Discovery
**Description:** Identifies accounts with DONT_REQ_PREAUTH bit (0x400000) set in userAccountControl.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Opens a TCP session and issues an anonymous (null) BindRequest.
- Discovers the default naming context from the rootDSE.
- Searches all user objects for sAMAccountName and userAccountControl.
- Decodes the userAccountControl flags per account and flags every account with the DONT_REQ_PREAUTH bit (0x400000) set.
- Why it matters: Accounts that do not require Kerberos pre-authentication are exposed to ASREPROAST: an attacker can request AS tickets without a password and crack the resulting encrypted checksum offline.
- Safety: one anonymous bind plus one bounded read-only search; no write operations.

**How to Execute:**
```bash
nmap -p 389 --script ldap-asreproast-candidates dc01.corp.example.com

# Tuned request budget
nmap -p 389 --script ldap-asreproast-candidates --script-args 'ldap-asreproast-candidates.maxrequests=40,ldap-asreproast-candidates.timeout=8,ldap-asreproast-candidates.user_limit=100' dc01.corp.example.com
```

**Sample Output:**
```
| ldap-asreproast-candidates:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - 1 ASREPROAST candidate(s) (pre-authentication disabled)
```

---

### 3. **ldap-laps-password-exposure** - LAPS Password Exposure
**Description:** Tests if anonymous or low-privileged binds can read ms-Mcs-AdmPwd (legacy LAPS password).

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Opens a TCP session and issues an anonymous (null) BindRequest.
- Discovers the default naming context from the rootDSE.
- Searches all objects for a populated ms-Mcs-AdmPwd attribute, reading cn, dNSHostName and the password attribute.
- Reports each exposed machine with the password masked.
- Why it matters: The legacy LAPS extension stores the local admin password in the computer object's ms-Mcs-AdmPwd attribute, in plain text.
- Safety: one anonymous bind plus one bounded read-only search; the password value is never emitted, only a masked prefix and length.

**How to Execute:**
```bash
nmap -p 389 --script ldap-laps-password-exposure dc01.corp.example.com

# Tuned request budget
nmap -p 389 --script ldap-laps-password-exposure --script-args 'ldap-laps-password-exposure.maxrequests=30,ldap-laps-password-exposure.timeout=8,ldap-laps-password-exposure.machine_limit=100' dc01.corp.example.com
```

**Sample Output:**
```
| ldap-laps-password-exposure:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - legacy LAPS passwords readable on 1 machine(s)
```

---

### 4. **ldap-null-bind-enum** - Null Bind Directory Enumeration
**Description:** Attempts null-bind directory search to dump user accounts, groups, and organizational units.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Opens a TCP session and issues an anonymous (null) BindRequest.
- Discovers the default naming context from the rootDSE.
- Runs bounded searches for users, groups, computers and OUs (sAMAccountName/cn, objectClass filters), each with a size limit.
- Summarises the exposure per class and classifies the overall verdict.
- Why it matters: A null (anonymous) bind followed by searches is the classic full directory dump: every account, group and OU becomes visible.
- Safety: one anonymous bind plus four bounded read-only searches with small size limits; no write operations.

**How to Execute:**
```bash
nmap -p 389 --script ldap-null-bind-enum dc01.corp.example.com

# Tuned request budget
nmap -p 389 --script ldap-null-bind-enum --script-args 'ldap-null-bind-enum.maxrequests=60,ldap-null-bind-enum.timeout=8,ldap-null-bind-enum.class_limit=50' dc01.corp.example.com
```

**Sample Output:**
```
| ldap-null-bind-enum:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - anonymous directory dump possible (15 objects across 4 classes)
```

---

### 5. **ldap-unconstrained-delegation** - Unconstrained Delegation Discovery
**Description:** Finds computers/users configured with TRUSTED_FOR_DELEGATION (Kerberos unconstrained delegation).

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Opens a TCP session and issues an anonymous (null) BindRequest.
- Discovers the default naming context from the rootDSE.
- Searches all computer and user objects for userAccountControl.
- Decodes the flags per object and flags TRUSTED_FOR_DELEGATION (0x2000), rating computers higher than users.
- Why it matters: Unconstrained delegation means the Kerberos TGT of ANY user who logs on to the target is stored on that machine, letting an attacker impersonate that user (golden-ticket style escalation).
- Safety: one anonymous bind plus one bounded read-only search; no write operations.

**How to Execute:**
```bash
nmap -p 389 --script ldap-unconstrained-delegation dc01.corp.example.com

# Tuned request budget
nmap -p 389 --script ldap-unconstrained-delegation --script-args 'ldap-unconstrained-delegation.maxrequests=40,ldap-unconstrained-delegation.timeout=8,ldap-unconstrained-delegation.object_limit=100' dc01.corp.example.com
```

**Sample Output:**
```
| ldap-unconstrained-delegation:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - 1 object(s) allow Kerberos unconstrained delegation
```

---

### 6. **ldap-user-account-attributes** - Sensitive Account Attribute Exposure
**Description:** Audits user objects for sensitive attributes (userPassword, unicodePwd, description).

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- Opens a TCP session and issues an anonymous (null) BindRequest.
- Discovers the default naming context from the rootDSE.
- Searches user objects requesting the sensitive attributes (userPassword, unicodePwd, description, mail, cn, sAMAccountName).
- Reports which sensitive attributes are readable, masks every secret in the output, and summarises unicodePwd character coverage without revealing the password.
- Why it matters: userPassword is a reversible Salsa200/MD4 blob and unicodePwd is UTF-16 hex: both are effectively cleartext when readable.
- Safety: one anonymous bind plus one bounded read-only search; all secret values are masked in the report; no write operations.

**How to Execute:**
```bash
nmap -p 389 --script ldap-user-account-attributes dc01.corp.example.com

# Tuned request budget
nmap -p 389 --script ldap-user-account-attributes --script-args 'ldap-user-account-attributes.maxrequests=40,ldap-user-account-attributes.timeout=8,ldap-user-account-attributes.user_limit=100' dc01.corp.example.com
```

**Sample Output:**
```
| ldap-user-account-attributes:
|   Risk Level: 🔴 CRITICAL
|   Status: VULNERABLE - cleartext-equivalent password attributes readable (1 userPassword, 1 unicodePwd)
```

---

### 7. **ldap-certificate-templates** - AD CS Certificate Template Exposure
**Description:** Queries Active Directory Certificate Services (AD CS) templates (pKIEnrollmentService).

**Risk Level:** 🟠 HIGH | **Category:** discovery, safe

**What it checks:**
- Opens a TCP session and issues an anonymous (null) BindRequest.
- Discovers the default naming context from the rootDSE.
- Searches for pKIEnrollmentService objects (the enrollment service).
- Searches for msPKI-CertificateTemplate objects and maps each template's pKIExtendedKeyUsage to EKU names, flagging client EKUs.
- Why it matters: AD CS templates define who can request certificates and for what Extended Key Usage (EKU). A template that allows self-enrollment with a clientAuth EKU is a certificate-forgery path to domain escalation.
- Safety: anonymous bind plus two bounded read-only searches; no certificate requests, no write operations.

**How to Execute:**
```bash
nmap -p 389 --script ldap-certificate-templates dc01.corp.example.com

# Tuned request budget
nmap -p 389 --script ldap-certificate-templates --script-args 'ldap-certificate-templates.maxrequests=40,ldap-certificate-templates.timeout=8,ldap-certificate-templates.template_limit=50' dc01.corp.example.com
```

**Sample Output:**
```
| ldap-certificate-templates:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - 2 certificate template(s) with a client EKU exposed
```

---

### 8. **ldap-gpo-permissions-audit** - GPO Container Enumeration
**Description:** Queries Group Policy Objects (GPOs) container and sysvol path references.

**Risk Level:** 🟠 HIGH | **Category:** discovery, safe

**What it checks:**
- Opens a TCP session and issues an anonymous (null) BindRequest.
- Discovers the default naming context from the rootDSE.
- Searches all objects with populated gPCMachineQuotas (GPOs).
- Parses the quota values and gPOptions flags per GPO and summarises the exposure.
- Why it matters: GPOs are the domain's policy enforcement surface: read access exposes the full policy inventory and quota settings, and write access (even for a low-privileged account) translates directly into domain-wide policy modification.
- Safety: one anonymous bind plus one bounded read-only search; no policy modification, no write operations.

**How to Execute:**
```bash
nmap -p 389 --script ldap-gpo-permissions-audit dc01.corp.example.com

# Tuned request budget
nmap -p 389 --script ldap-gpo-permissions-audit --script-args 'ldap-gpo-permissions-audit.maxrequests=30,ldap-gpo-permissions-audit.timeout=8,ldap-gpo-permissions-audit.gpo_limit=50' dc01.corp.example.com
```

**Sample Output:**
```
| ldap-gpo-permissions-audit:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - GPO container readable (2 GPO(s) exposed)
```

---

### 9. **ldap-signing-enforced** - LDAP Signing Enforcement Check
**Description:** Checks if LDAP server enforces LDAP signing and channel binding tokens (CBT).

**Risk Level:** 🟠 HIGH | **Category:** defensive, safe

**What it checks:**
- Opens a TCP session and issues an anonymous (null) BindRequest.
- Attempts exactly one Simple Bind with an auditor-owned credential on the clear channel (never a real target credential).
- If rejected and StartTLS is advertised, upgrades with the StartTLS extended operation and retries the auditor credential once.
- Performs one bounded search and classifies: data readable without signing (vulnerable) versus rejected with LdapErr data 531/533/586 (signing/channel security enforced).
- Why it matters: Without signing, an on-path attacker can relay a victim's bind to a different server (NTLM/Kerberos relay) and read unencrypted traffic.
- Safety: at most two auditor-credential binds, one StartTLS, one bounded read-only search; strict request budget.

**How to Execute:**
```bash
nmap -p 389 --script ldap-signing-enforced dc01.corp.example.com

# Tuned request budget
nmap -p 389 --script ldap-signing-enforced --script-args 'ldap-signing-enforced.maxrequests=30,ldap-signing-enforced.timeout=8,ldap-signing-enforced.binduser="ldap-auditor-probe"' dc01.corp.example.com
```

**Sample Output:**
```
| ldap-signing-enforced:
|   Risk Level: 🟠 HIGH
|   Status: SECURE - LDAP signing/channel binding enforced (LdapErr data 531)
```

---

### 10. **ldap-spn-service-accounts** - SPN and Service Account Enumeration
**Description:** Queries accounts with servicePrincipalName (SPN) set, identifying Kerberoasting targets.

**Risk Level:** 🟠 HIGH | **Category:** discovery, safe

**What it checks:**
- Opens a TCP session and issues an anonymous (null) BindRequest.
- Discovers the default naming context from the rootDSE.
- Searches all objects with a populated servicePrincipalName, reading the account name, SPN list and userAccountControl.
- Classifies each SPN by service prefix and separates service accounts from machine accounts.
- Why it matters: Every SPN can be requested as a service ticket (TGS) by any authenticated user; the RC4-encrypted TGS can be cracked offline (Kerberoasting).
- Safety: one anonymous bind plus one bounded read-only search; no ticket requests, no write operations.

**How to Execute:**
```bash
nmap -p 389 --script ldap-spn-service-accounts dc01.corp.example.com

# Tuned request budget
nmap -p 389 --script ldap-spn-service-accounts --script-args 'ldap-spn-service-accounts.maxrequests=40,ldap-spn-service-accounts.timeout=8,ldap-spn-service-accounts.spn_limit=100' dc01.corp.example.com
```

**Sample Output:**
```
| ldap-spn-service-accounts:
|   Risk Level: 🟠 HIGH
|   Status: VULNERABLE - 3 Kerberoasting target(s) (2 service account(s), 1 machine(s))
```

---

### 11. **ldap-cleartext-auth-risk** - Cleartext Authentication Exposure
**Description:** Checks whether LDAP on port 389 processes Simple Bind credentials without StartTLS.

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Opens a TCP session and reads the rootDSE to see whether StartTLS is advertised in supportedExtension.
- Sends exactly one Simple Bind using an auditor-owned probe credential over the clear channel (never a real target credential, never retried).
- Classifies: clear-channel simple bind accepted (risk), rejected with a signing/TLS diagnostic, or rejected with plain invalid credentials.
- If StartTLS is advertised, performs the StartTLS extended operation and re-tests the auditor credential over the upgraded channel.
- Why it matters: Simple Bind transmits the password in clear text. On port 389 without StartTLS any on-path listener captures the credential outright.
- Safety: one documented auditor-credential bind on the clear channel and one over the upgraded channel; bounded request budget.

**How to Execute:**
```bash
nmap -p 389 --script ldap-cleartext-auth-risk dc01.corp.example.com

# Tuned request budget
nmap -p 389 --script ldap-cleartext-auth-risk --script-args 'ldap-cleartext-auth-risk.maxrequests=30,ldap-cleartext-auth-risk.timeout=8,ldap-cleartext-auth-risk.binduser="ldap-auditor-probe"' dc01.corp.example.com
```

**Sample Output:**
```
| ldap-cleartext-auth-risk:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - Simple Bind credentials accepted on the unencrypted channel (port 389)
```

---

### 12. **ldap-rootdse-leak** - rootDSE Metadata Leakage
**Description:** Queries rootDSE for namingContexts, defaultNamingContext, dnsHostName, domainFunctionality.

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- Opens a TCP session and issues a scope=base search on the rootDSE ("") requesting the high-signal identity attributes.
- Records which identity attributes the server actually returned.
- Classifies the severity of the identity exposure.
- Why it matters: The rootDSE is readable without any bind and can leak the forest/domain naming context, the DC host name and the domain functional level.
- Safety: a single read-only scope=base search; no bind, no write.

**How to Execute:**
```bash
nmap -p 389 --script ldap-rootdse-leak dc01.corp.example.com

# Tuned request budget
nmap -p 389 --script ldap-rootdse-leak --script-args 'ldap-rootdse-leak.maxrequests=16,ldap-rootdse-leak.timeout=8' dc01.corp.example.com
```

**Sample Output:**
```
| ldap-rootdse-leak:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - rich rootDSE identity exposure (8 high-signal attributes)
```

---

### 13. **ldap-starttls-support** - StartTLS Support Probe
**Description:** Probes LDAP StartTLS extended operation OID (1.3.6.1.4.1.1466.20037) support.

**Risk Level:** 🟡 MEDIUM | **Category:** defensive, safe

**What it checks:**
- Opens a TCP session and reads the rootDSE supportedExtension list for the StartTLS OID.
- Attempts one Simple Bind with an auditor-owned credential on the clear channel to see whether plaintext auth is still accepted.
- Sends the StartTLS extended operation and records the result.
- If the upgrade is accepted, re-tests the auditor credential over the upgraded channel and classifies the enforcement posture.
- Why it matters: StartTLS lets clients upgrade a port-389 session to TLS in place. If the server advertises and accepts StartTLS but still processes simple binds on the clear channel, the upgrade is optional and effectively unused.
- Safety: at most two auditor-credential binds and one StartTLS extended operation; bounded request budget.

**How to Execute:**
```bash
nmap -p 389 --script ldap-starttls-support dc01.corp.example.com

# Tuned request budget
nmap -p 389 --script ldap-starttls-support --script-args 'ldap-starttls-support.maxrequests=30,ldap-starttls-support.timeout=8,ldap-starttls-support.binduser="ldap-auditor-probe"' dc01.corp.example.com
```

**Sample Output:**
```
| ldap-starttls-support:
|   Risk Level: 🟡 MEDIUM
|   Status: VULNERABLE - StartTLS works but clear-channel Simple Bind is still accepted
```

---

### 14. **ldap-ad-domain-info** - AD Domain Info Mapping
**Description:** Extracts Active Directory forest name, schema version, domain controller roles.

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Reads the rootDSE (defaultNamingContext, dnsHostName, domainFunctionality, schemaNamingContext, configurationNamingContext, isGlobalCatalogReady).
- Derives the forest name from the domain components of the default naming context.
- Attempts a bounded search for the domain object to confirm the domain is queryable.
- Reports the DC role (global catalog readiness) and functional levels.
- Why it matters: The rootDSE plus the domain object reveal the forest/domain names, the functional levels and whether the answering host is a global catalog.
- Safety: one rootDSE search and one bounded read-only search; no bind with credentials, no write.

**How to Execute:**
```bash
nmap -p 389 --script ldap-ad-domain-info dc01.corp.example.com

# Tuned request budget
nmap -p 389 --script ldap-ad-domain-info --script-args 'ldap-ad-domain-info.maxrequests=24,ldap-ad-domain-info.timeout=8' dc01.corp.example.com
```

**Sample Output:**
```
| ldap-ad-domain-info:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - AD domain identity fully mapped (functional level + DC host + domain object)
```

---

### 15. **ldap-paged-search-limit** - Paged Results and Size Limit Audit
**Description:** Tests LDAP server pagination control (1.2.840.113556.1.4.319) and size limits.

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Reads the rootDSE supportedControl list for the paged results OID.
- Runs one bounded search with a small sizeLimit to observe how the server honours per-request size limits.
- Runs a paged search (page size 5, at most 3 pages) and observes the page count, total entries and cookie termination.
- Classifies the enumeration surface.
- Why it matters: The paged results control lets a client pull an unbounded number of entries in small chunks, silently defeating per-request size limits.
- Safety: bounded read-only searches only; small page size; hard cap on pages.

**How to Execute:**
```bash
nmap -p 389 --script ldap-paged-search-limit dc01.corp.example.com

# Tuned request budget
nmap -p 389 --script ldap-paged-search-limit --script-args 'ldap-paged-search-limit.maxrequests=40,ldap-paged-search-limit.timeout=8,ldap-paged-search-limit.page_size=5' dc01.corp.example.com
```

**Sample Output:**
```
| ldap-paged-search-limit:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - paged results enabled (6 entries traversed in 1 pages)
```

---

### 16. **ldap-supported-controls** - Supported Controls Surface
**Description:** Enumerates supported LDAP controls, extensions, and SASL mechanisms.

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Reads the rootDSE control, extension and SASL attribute lists.
- Maps each OID/mechanism to its functional name.
- Highlights the high-signal capabilities (pagination, persistent search, StartTLS, Kerberos SASL, legacy DIGEST-MD5).
- Classifies the breadth of the exposed feature surface.
- Why it matters: The supportedControl / supportedExtension / supportedSASLMechanisms attributes on the rootDSE fingerprint the directory feature set: pagination, persistent search, change notification, StartTLS, SASL.
- Safety: one read-only scope=base search; no bind, no write.

**How to Execute:**
```bash
nmap -p 389 --script ldap-supported-controls dc01.corp.example.com

# Tuned request budget
nmap -p 389 --script ldap-supported-controls --script-args 'ldap-supported-controls.maxrequests=16,ldap-supported-controls.timeout=8' dc01.corp.example.com
```

**Sample Output:**
```
| ldap-supported-controls:
|   Risk Level: 🟢 LOW
|   Status: INFORMATIONAL - broad control surface exposed on rootDSE
```

