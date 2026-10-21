# 🔍 DNS Security Audits

**16 Nmap NSE scripts** for auditing DNS infrastructure:

**Covers:**

- Authoritative servers
- Resolvers
- Zone transfers
- DNSSEC
- DoH/DNSCrypt transports and email-authentication records

Every script builds real DNS wire-format queries (A, AAAA, NS, SOA, MX, TXT, SRV, ANY, DNSKEY, RRSIG, AXFR, IXFR, CAA, PTR, NAPTR, HTTPS) over UDP and TCP, parses the binary response, and reports evidence-based verdicts.

**Port:** 53/udp + 53/tcp (443 for DoH / DNSCrypt) | **Protocol:** DNS | **Total lines of Lua:** 27,383

---

## 📋 Script Index

| # | Script | Risk Level | Category | Lines |
|---|--------|-----------|----------|-------|
| 1 | [dns-axfr-source-spoof](#1-dns-axfr-source-spoof---dns-axfr-source-spoof) | 🔴 CRITICAL | vuln, safe | 1841 |
| 2 | [dns-ns-recursion-abuse](#2-dns-ns-recursion-abuse---dns-ns-recursion-abuse) | 🔴 CRITICAL | vuln, safe | 1658 |
| 3 | [dns-cname-takeover-audit](#3-dns-cname-takeover-audit---dns-cname-takeover-audit) | 🟠 HIGH | vuln, discovery, safe | 1849 |
| 4 | [dns-amplification-risk](#4-dns-amplification-risk---dns-amplification-risk) | 🟡 MEDIUM | safe, discovery, vuln | 1600 |
| 5 | [dns-cache-snooping](#5-dns-cache-snooping---dns-cache-snooping) | 🟡 MEDIUM | safe, discovery, vuln | 1741 |
| 6 | [dns-dnssec-validation](#6-dns-dnssec-validation---dns-dnssec-validation) | 🟡 MEDIUM | discovery, safe | 1704 |
| 7 | [dns-recursion-check](#7-dns-recursion-check---dns-recursion-check) | 🟡 MEDIUM | safe, discovery, vuln | 1689 |
| 8 | [dns-reverse-ptr-leak](#8-dns-reverse-ptr-leak---dns-reverse-ptr-leak) | 🟡 MEDIUM | discovery, safe | 1808 |
| 9 | [dns-soa-consistency-check](#9-dns-soa-consistency-check---dns-soa-consistency-check) | 🟡 MEDIUM | safe, discovery | 1807 |
| 10 | [dns-srv-enum](#10-dns-srv-enum---dns-srv-enum) | 🟡 MEDIUM | safe, discovery | 1625 |
| 11 | [dns-subdomain-enum](#11-dns-subdomain-enum---dns-subdomain-enum) | 🟡 MEDIUM | safe, discovery | 1662 |
| 12 | [dns-txt-spf-dmarc-audit](#12-dns-txt-spf-dmarc-audit---dns-txt-spf-dmarc-audit) | 🟡 MEDIUM | safe, discovery, vuln | 1737 |
| 13 | [dns-wildcard-detector](#13-dns-wildcard-detector---dns-wildcard-detector) | 🟡 MEDIUM | safe, discovery | 1605 |
| 14 | [dns-zone-transfer-check](#14-dns-zone-transfer-check---dns-zone-transfer-check) | 🟡 MEDIUM | safe, discovery, vuln | 1874 |
| 15 | [dns-dnscrypt-support](#15-dns-dnscrypt-support---dns-dnscrypt-support) | 🟢 LOW | discovery, safe | 1551 |
| 16 | [dns-doh-endpoint-probe](#16-dns-doh-endpoint-probe---dns-doh-endpoint-probe) | 🟢 LOW | discovery, safe | 1632 |

---

## ⚙️ Common Script Arguments

All 16 scripts share the following `--script-args` (script-specific extras are listed per script):

| Argument | Default | Purpose |
|----------|---------|---------|
| `domain` | audited hostname | Override the zone/domain being audited |
| `maxrequests` | per script | Hard request budget for the run |
| `retries` | 0 | Retries per query on timeout/refused |
| `timeout` | 10000 | Per-query timeout (ms) |
| `delay` | 0.05 | Polite delay between queries (s) |

---

## 📜 Script Details

### 1. **dns-axfr-source-spoof** - Dns Axfr Source Spoof
**Description:** Evaluates how the target guards its zone transfers against an UNAUTHORIZED source - the classic DNS access-control failure that hands the entire zone (every host, every internal IP, every TXT payload, every service record) to anyone who asks, or - when the transfer is at least restricted - how easy it would be to impersonate an authorized secondary. This is a defensive audit: the script never forges source addresses, never sends traffic at volume, and never attacks the server.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- AXFR from an unauthorized (non-allow-listed) source over TCP
- IXFR (serial 0) behaviour as a transfer surface
- AXFR over UDP (truncated vs refused)
- Credential-shaped TXT records inside an allowed transfer (values masked in output)
- NS/SOA evidence of which sources the transfer policy trusts

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-axfr-source-spoof example.com

# Skip the secondary-style checks
nmap -p 53 --script dns-axfr-source-spoof --script-args ixfr_check=false,udp_check=false example.com
```

**Sample Output:**
```
| dns-axfr-source-spoof:
|   Status: VULNERABLE - AXFR zone transfer for target.example.com is open to unauthorized sources.
|   Risk Level: 🔴 CRITICAL
|   AXFR (TCP) verdict: open
|   AXFR (UDP) verdict: answered-truncated - NOERROR, SOA serial in authority: 2026092101
|   Credential-looking TXT exposed (masked):
|     1: _deploy.target.example.com: de************************et (32 chars)
|     2: _internal-note.target.example.com: st************************26 (37 chars)
|   Fetch log:
|     1: AXFR (TCP) target.example.com -> TRANSFERED: 31 records, 5 packets, 2200 bytes
|        (server streamed the zone to this source)
```

---

### 2. **dns-ns-recursion-abuse** - Dns Ns Recursion Abuse
**Description:** Audits how the resolver serves RECURSION to untrusted clients - the control that decides whether this server is a private, access-managed recursor or an open resolver that will chase any name for any client on the internet. An open resolver is a critical exposure for two reasons: (1) it can be abused as a DNS reflection/amplification source against third parties, and (2) it commonly resolves INTERNAL names (split-horizon leak), publishing the organisation's internal infrastructure to the outside world.

**Risk Level:** 🔴 CRITICAL | **Category:** vuln, safe

**What it checks:**
- RD=1 recursion for arbitrary third-party domains (open resolver proof)
- RD=0 non-recursive answering (stronger misconfiguration signal)
- Internal-name probing: common internal suffixes (.internal, .local, .lan, .corp) resolved externally
- Sizing: ANY-response size as an amplification surface
- Combined verdict: open resolver AND internal leakage

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-ns-recursion-abuse example.com

# Wider internal-suffix list and budget
nmap -p 53 --script dns-ns-recursion-abuse --script-args internal_check=true,sizing_check=true,maxrequests=64 example.com
```

**Sample Output:**
```
| dns-ns-recursion-abuse:
|   Status: VULNERABLE - open resolver AND 1 internal name(s) resolvable externally.
|   Risk Level: 🔴 CRITICAL
|   Fetch log:
|     1: example.org (RD=1) -> ANSWERED (192.0.2.44) - recursion performed for an external client
|     10: internal.lan (RD=1) -> NXDOMAIN (not resolvable from outside)
|     14: ANY target.example.com (RD=1, plain) -> NOERROR (641 bytes)
|   Cache served in both modes:
|     1: example.org
|     2: cloudflare.com
```

---

### 3. **dns-cname-takeover-audit** - Dns Cname Takeover Audit
**Description:** Audits the DNS zone for CNAME records that point at third-party hosting/collaboration/SaaS providers (Shopify, GitLab Pages, GitHub Pages, Heroku, S3, Netlify, Vercel, Webflow, Firebase, CloudFront, Medium, Ghost, Azure App Service and more). When the organisation releases or lets lapse the account behind one of those CNAMEs, the provider's default behaviour is to serve a "this page is available" claim page - and in several well-documented cases the claim flow lets a new account holder take over the subdomain.

**Risk Level:** 🟠 HIGH | **Category:** vuln, discovery, safe

**What it checks:**
- Full CNAME inventory (from live probing or the zone dump when AXFR is allowed)
- Dangling CNAMEs to known provider claim domains (Shopify, Heroku, GitLab Pages, BunnyCDN, ...)
- Provider recognition table with takeover-risk classification (ACTIVE / DANGLING / internal)
- CNAME wildcard behaviour that would mask dangling records
- Per-record evidence source (zone dump vs live resolution)

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-cname-takeover-audit example.com

# Use the zone dump for a complete inventory
nmap -p 53 --script dns-cname-takeover-audit --script-args axfr=true,maxcandidates=100 example.com
```

**Sample Output:**
```
| dns-cname-takeover-audit:
|   Status: VULNERABLE - 4 dangling third-party CNAME(s) found: subdomain takeover possible.
|   Risk Level: 🟠 HIGH
|   CNAME inventory:
|     1:       www.target.example.com     -> target.example.com [internal] (same zone)
|     2:       lost-blog.target.example.com -> abandoned-blogs.customdomains.example [DANGLING]
|     3:       old-shop.target.example.com  -> myshop.myshopify.com [ACTIVE] [Shopify]
|     4:       old-wiki.target.example.com  -> mywiki.gitlab.io [DANGLING] [GitLab Pages]
|   CNAMEs inventoried: 7
|   Dangling (takeable): 4
```

---

### 4. **dns-amplification-risk** - Dns Amplification Risk
**Description:** Estimates how well the tested DNS server performs as a DNS amplification reflector. In a DNS amplification attack the attacker sends a small DNS query with a spoofed source address (the victim) to an open, well-connected resolver; the resolver's much larger response goes to the victim. The amplification factor is the response size divided by the query size - a factor above ~10 means the target can turn 1 byte of attacker traffic into 10 bytes of flood traffic.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery, vuln

**What it checks:**
- ANY-query amplification factor (the classic reflector) with response-size comparison
- TXT / DNSKEY / SRV / NAPTR / HTTPS / CAA query-to-response size ratios
- AXFR-over-UDP truncation behaviour (response size vs the tiny request)
- Wildcard A answering (any-name flood source)
- Recursion enablement (RD=1 answering for foreign names)

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-amplification-risk example.com

# Bigger budget and custom zone
nmap -p 53 --script dns-amplification-risk --script-args maxrequests=60,domain=corp.example.com example.com
```

**Sample Output:**
```
| dns-amplification-risk:
|   Status: VULNERABLE - strong DNS amplification reflector (factor 17.8x).
|   Risk Level: 🟡 MEDIUM
|   ANY response: answered (641 bytes)
|   Findings:
|     [HIGH] the server returns a large ANY response for target.example.com
|            (641 bytes, amplification factor 17.8x): it can be used to flood
|            victims - the attacker needs only the small query
|            (amplification-any:target.example.com) [evidence: 641 bytes ANY]
```

---

### 5. **dns-cache-snooping** - Dns Cache Snooping
**Description:** Tests whether the target DNS resolver leaks its cache contents to any client - a cache snooping information disclosure. The resolver's cache remembers the names other clients looked up; if the resolver answers a *non-recursive* (RD=0) query for a name it is not authoritative for, the only place a positive answer can come from is its own cache. The probe succeeds exactly when someone else recently asked the resolver for that same name.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery, vuln

**What it checks:**
- RD=0 (non-recursive) queries for popular third-party domains answered from cache
- Cache freshness tracking via TTL decrease across repeated apex queries
- Positive-vs-NXDOMAIN split that separates cache hits from honest negatives
- Which popular domains were recently resolved through this resolver

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-cache-snooping example.com

# Custom probe list and budget
nmap -p 53 --script dns-cache-snooping --script-args "probes=google.com,cloudflare.com,example.org",maxrequests=80 example.com
```

**Sample Output:**
```
| dns-cache-snooping:
|   Status: VULNERABLE - cache snooping confirmed (9 of 24 probe domains served from the resolver cache).
|   Risk Level: 🟡 MEDIUM
|   Apex control (round 3):
|     1:       target.example.com TTL 300 -> 1 (decreasing between queries)
|   Cached hits (snooping disclosures):
|     1: google.com (TTL 300, 192.0.2.44)
|     2: amazon.com (TTL 300, 192.0.2.44)
|     3: microsoft.com (TTL 300, 192.0.2.44)
```

---

### 6. **dns-dnssec-validation** - Dns Dnssec Validation
**Description:** Validates the DNSSEC posture of a zone: whether the zone is signed, whether the delegation from the parent is signed (DS record), whether the published key set is complete (KSK + ZSK) with current algorithms, whether the SOA carries a valid, unexpired RRSIG, and whether authentic negative responses are available (NSEC/NSEC3). A zone that is unsigned (or half-signed) can have its answers forged by an attacker in the middle, which underpins subdomain hijack and certificate-transparency abuse.

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- DNSKEY RRset presence, count and key roles (KSK/ZSK split, SEP)
- Algorithms in use and deprecation state (RSA/1, RSA/3, ECDSA P-256/384, Ed25519)
- SOA RRSIG presence, signature validity window and signer
- Parent DS delegation record
- NSEC / NSEC3 for authenticated denial of existence

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-dnssec-validation example.com

# Audit a specific zone
nmap -p 53 --script dns-dnssec-validation --script-args domain=corp.example.com example.com
```

**Sample Output:**
```
| dns-dnssec-validation:
|   Status: VULNERABLE - zone target.example.com is not DNSSEC-signed.
|   Risk Level: 🟡 MEDIUM
|   Posture: unsigned
|   DNSKEY: absent
|   Parent DS: absent
|   Authenticated denial: none
|   Findings:
|     [MEDIUM] the zone target.example.com publishes no DNSKEY records: it is
|              unsigned, so DNS answers for it can be forged by an on-path
|              attacker (no authenticated denial, no integrity)
```

---

### 7. **dns-recursion-check** - Dns Recursion Check
**Description:** Determines whether the tested DNS resolver performs recursive resolution for arbitrary third-party domains on behalf of any client - the classic "open resolver" exposure. An open resolver lets an attacker use the organisation's (typically well-connected, whitelisted, low-latency) resolver as a free recursive cache, hides the attacker's real source address from the authoritative servers, and can be used to poison or probe the resolver's cache. It is also the prerequisite for DNS cache-poisoning and amplification abuse.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery, vuln

**What it checks:**
- SOA first (establishes the zone of authority, to exclude it from "recursion" evidence)
- RD=1 queries for popular third-party domains (recursion proof)
- RD=0 non-recursive queries answered positively (strong misconfiguration)
- PTR probes for internal reverse-zone leakage
- TCP recursion check (UDP-only restrictions are common)
- Honest-negative vs answered split for confidence scoring

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-recursion-check example.com

# Include TCP and more probes
nmap -p 53 --script dns-recursion-check --script-args tcp=true,rd0=true,maxprobes=20,maxrequests=80 example.com
```

**Sample Output:**
```
| dns-recursion-check:
|   Status: VULNERABLE - open resolver: performs recursion for arbitrary third-party domains.
|   Risk Level: 🟡 MEDIUM
|   Fetch log:
|     1: SOA target.example.com -> NOERROR (zone of authority established)
|     10: A apple.com -> NOERROR, answered 192.0.2.44 (third-party domain resolved: recursion)
|     16: A example.org (RD=0) -> NOERROR, answered 192.0.2.44 (non-recursive query answered: strong misconfiguration)
|     19: PTR 1.1.168.192.in-addr.arpa -> answered workstation-01.internal.lan (internal reverse zone leak)
```

---

### 8. **dns-reverse-ptr-leak** - Dns Reverse Ptr Leak
**Description:** Maps reverse (PTR) records for the addresses the audited zone is associated with and analyses what the reverse zone discloses about the organisation's internal infrastructure. Reverse DNS is a classic reconnaissance channel: organisations often maintain their reverse zones far less carefully than their forward zones, leaving stale records, test hostnames, and - most tellingly - PTR records that point at names in INTERNAL domains (for example workstation-01.internal.lan for a public mail IP).

**Risk Level:** 🟡 MEDIUM | **Category:** discovery, safe

**What it checks:**
- PTR records for every A/AAAA address associated with the audited zone
- Zone-consistency: PTR names inside vs outside the audited zone (foreign names = leak)
- Forward confirmation for each PTR target (orphan PTR detection)
- Internal-suffix classification (.internal, .local, .lan, .corp, .home, .domain)
- IPv4 and IPv6 reverse coverage

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-reverse-ptr-leak example.com

# Explicit address list and no forward confirmation
nmap -p 53 --script dns-reverse-ptr-leak --script-args "addresses=203.0.113.10,203.0.113.11",confirm_forward=false example.com
```

**Sample Output:**
```
| dns-reverse-ptr-leak:
|   Status: AUDITED - reverse DNS discloses internal hostnames (1 foreign PTR name(s), 3 PTR total).
|   Risk Level: 🟡 MEDIUM
|   Fetch log:
|     2: 203.0.113.10 (10.113.0.203.in-addr.arpa) -> PTR target.example.com (TTL 300) - zone-consistent
|     5: 203.0.113.12 (12.113.0.203.in-addr.arpa) -> PTR mailhost-backup.internal.corp (TTL 300) - FOREIGN name (leak)
|     8: forward mailhost-backup.internal.corp -> NXDOMAIN (orphan PTR)
|   Findings:
|     [MEDIUM] reverse DNS for 203.0.113.12 returns the FOREIGN name
|              mailhost-backup.internal.corp - the reverse zone exposes an internal
|              hostname (suffix internal.corp) that is outside the audited zone
```

---

### 9. **dns-soa-consistency-check** - Dns Soa Consistency Check
**Description:** Audits the zone's SOA record for parameter sanity and cross-checks the zone's own data for internal consistency: does the SOA's primary nameserver (MNAME) actually appear in the zone's NS set? Do the NS hosts resolve? Is the serial date-based and still current? And when a zone transfer is available, does the transfer start and end with the same SOA (an atomic snapshot)?

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery

**What it checks:**
- SOA timer sanity (refresh < retry < expire, minimum sensible, values in expected ranges)
- MNAME membership in the NS set
- NS host resolvability (dangling nameserver detection)
- Serial format (date-based YYYYMMDDNN) and currency vs the current date
- AXFR atomicity: start SOA serial == end SOA serial

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-soa-consistency-check example.com

# Include the AXFR atomicity check
nmap -p 53 --script dns-soa-consistency-check --script-args axfr_check=true,check_ns=true example.com
```

**Sample Output:**
```
| dns-soa-consistency-check:
|   Status: AUDITED - SOA / zone consistency issues detected (1 finding(s)).
|   Risk Level: 🟡 MEDIUM
|   AXFR atomicity: transfer atomic (31 records, 5 packets, 2200 bytes;
|                   start and end SOA serial 2026092101 match)
|   Fetch log:
|     1: SOA target.example.com -> ns1.target.example.com hostmaster.target.example.com
|        serial=2026092101 refresh=7200 retry=3600 expire=1209600 minimum=300
|     5: A ns3.dns-hq.internal -> NXDOMAIN
|   Findings:
|     [MEDIUM] nameserver ns3.dns-hq.internal has no A record: the NS entry is
|              dangling and resolvers chasing it will fail (soa-ns:dangling)
```

---

### 10. **dns-srv-enum** - Dns Srv Enum
**Description:** Enumerates SRV (Service Location, RFC 2782) records published under a domain. SRV records advertise the hostnames and ports of the organisation's services - SIP/VoIP, XMPP, Lync/Teams federation, autodiscover, LDAP/Active Directory, MySQL/PostgreSQL/Redis/Kafka, STUN/TURN, gRPC, H.323 and dozens more. They are frequently left in production even after the service itself moves, and because SRV targets are real hostnames (often internal ones) the record set is a compact map of the internal service topology.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery

**What it checks:**
- ~30 well-known SRV service labels (_sip, _xmpp-client, _ldap, _imaps, _autodiscover, _mysql, _postgres, _redis, _kafka, _stun, _turn, _grpc, _h323, ...)
- Internal-target detection on SRV hostnames (topology leak)
- Service classification (SIP/VoIP, XMPP, LDAP, database, federation, ...)
- Optional resolution of SRV targets (records -> addresses)

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-srv-enum example.com

# Also resolve the advertised targets
nmap -p 53 --script dns-srv-enum --script-args resolve=true,maxrequests=100 example.com
```

**Sample Output:**
```
| dns-srv-enum:
|   Status: VULNERABLE - SRV records leak internal service topology for target.example.com.
|   Risk Level: 🟡 MEDIUM
|   Fetch log:
|     1: SRV _sip._tcp.target.example.com -> 20 5 5060 sip1.target.example.com (SIP/VoIP)
|     6: SRV _ldap._tcp.target.example.com -> 0 0 389 ldap.dcs.internal.corp (LDAP)
|     8: SRV _mysql._tcp.target.example.com -> 0 0 3306 db1.target.example.com (MySQL)
|   Findings:
|     [MEDIUM] SRV _ldap._tcp.target.example.com advertises an internal target:
|              ldap.dcs.internal.corp:389 (LDAP) - internal service topology is leaking via DNS
```

---

### 11. **dns-subdomain-enum** - Dns Subdomain Enum
**Description:** Enumerates subdomains of the audited zone by probing a curated wordlist of common service labels (web, mail, dev/staging, monitoring, git, backup, ...) with single A-record queries, and - crucially - separates REAL records from wildcard noise before reporting anything. Most public zones today answer any unregistered name with a wildcard A record, so a naive brute-force that reports "X resolved" is useless on such zones.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery

**What it checks:**
- Wildcard baseline: random-label probes establish the catch-all answer first
- Curated wordlist of ~80 common service labels (www, mail, vpn, git, dev, staging, backup, ...)
- Distinct-record classification: answered-inline, wildcard-consistent (noise), CNAME-resolved, dangling CNAME
- CNAME following for records that point outside the zone
- NXDOMAIN / error accounting for confidence

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-subdomain-enum example.com

# Custom label list
nmap -p 53 --script dns-subdomain-enum --script-args "labels=www,mail,dev,api,vpn,billing,git,backup" example.com
```

**Sample Output:**
```
| dns-subdomain-enum:
|   Status: AUDITED - subdomain enumeration on wildcarding zone target.example.com:
|          7 distinct record(s), 58 wildcard-consistent (noise), 0 NXDOMAIN.
|   Risk Level: 🟡 MEDIUM
|   Counts: distinct=7 wildcard-consistent=58 nxdomain=0 errors=0
|   Distinct subdomain records:
|     1:       www.target.example.com        CNAME target.example.com (answered-inline) | A 203.0.113.10
|     2:       vpn.target.example.com        A 192.168.8.1
|     6:       cdn.target.example.com        CNAME bunny.net (resolved) | A 198.41.0.1
|     7:       static.target.example.com     CNAME cdn-origin.bunny.net (dangling)
```

---

### 12. **dns-txt-spf-dmarc-audit** - Dns Txt Spf Dmarc Audit
**Description:** Audits the email-authentication TXT records for a domain - SPF, DKIM and DMARC - and reports on how well the domain is protected against spoofing and impersonation. Email authentication is a primary defence against phishing and business-email-compromise: SPF tells receivers which IPs may send for the domain, DKIM adds a cryptographic signature that receivers can verify, and DMARC tells receivers what to do with mail that fails the other two and where to send aggregate reports.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery, vuln

**What it checks:**
- SPF: presence, mechanism inventory (ip4/ip6/mx/include/a/redirect), -all vs ~all vs none, multiple-include depth, 10-lookup limit, syntax errors
- DMARC: presence, policy (p=none/quarantine/reject), subdomain policy, rua/ruf reporting, pct
- DKIM: selector discovery (default, selector1-10, google, k1, s1, mail, ...) and key strength (RSA bit size)
- Combined posture: which of the three is missing or weak

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-txt-spf-dmarc-audit example.com

# Skip DKIM selector discovery
nmap -p 53 --script dns-txt-spf-dmarc-audit --script-args dkim=false example.com
```

**Sample Output:**
```
| dns-txt-spf-dmarc-audit:
|   Status: AUDITED - email authentication present but weakly enforced for target.example.com.
|   Risk Level: 🟡 MEDIUM
|   Domain: target.example.com
|   DMARC: present (p=none)
|   DMARC rua:
|     1: mailto:dmarc@target.example.com
|   DKIM: 1 usable key(s)
|   DKIM selectors:
|     1:       default._domainkey.target.example.com: key present (k=rsa, v=DKIM1)
|     2:       selector1._domainkey.target.example.com: no key (k=rsa, v=DKIM1)
```

---

### 13. **dns-wildcard-detector** - Dns Wildcard Detector
**Description:** Detects whether a zone answers wildcard DNS records - that is, whether unregistered subdomain names resolve to the same address/records as if they existed. Wildcard DNS records are commonly used as a catch-all for unknown hosts, and while not a vulnerability by themselves they have real security consequences: subdomain enumeration via DNS becomes meaningless, subdomain-takeover alerts are noisy, and monitoring/allow-listing systems are weakened.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery

**What it checks:**
- Random-label A / AAAA / NS / CNAME / MX probes (several rounds, distinct random names)
- Control probe against a guaranteed-negative domain (.invalid)
- Consistency: identical answers across rounds = wildcard per record type
- Per-type wildcard classification (A wildcard, NS wildcard, ...)
- Impact guidance (enumeration degradation, takeover noise)

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-wildcard-detector example.com

# More sample labels per type
nmap -p 53 --script dns-wildcard-detector --script-args samples=10,maxrequests=100 example.com
```

**Sample Output:**
```
| dns-wildcard-detector:
|   Status: VULNERABLE - wildcard DNS records detected (subdomain enumeration degraded).
|   Risk Level: 🟡 MEDIUM
|   Control probe: nmap-wildcard-nhndqlf7.invalid -> negative (NXDOMAIN)
|   Fetch log:
|     1: SOA target.example.com -> NOERROR (zone confirmed)
|     10: AAAA n502lypb3u.target.example.com -> answered 2001:db8::99 (ttl 300)
|     14: NS za5584tsko.target.example.com -> answered ns1.target.example.com (ttl 3600)
|     17: NS 4ysumdtopl.target.example.com -> answered ns1.target.example.com (ttl 3600)
```

---

### 14. **dns-zone-transfer-check** - Dns Zone Transfer Check
**Description:** Checks whether the DNS zone for the target domain can be transferred (AXFR / IXFR) by an unauthenticated remote client, and how much of the zone it exposes. A zone transfer grants a complete, authoritative dump of every record in the zone: all subdomains, internal hostnames, the mailing infrastructure, service records (SRV) with internal targets, TXT records that frequently carry deployment notes, credentials and token-shaped strings, and the SOA serial that reveals how the zone is versioned.

**Risk Level:** 🟡 MEDIUM | **Category:** safe, discovery, vuln

**What it checks:**
- AXFR over TCP from an unauthorized source (streaming, multi-packet, terminating-SOA validation)
- IXFR (serial 0) as an alternative transfer path
- AXFR over UDP (refused vs truncated)
- Credential-shaped TXT scanning inside the dump (values MASKED in output)
- External/third-party CNAME inventory inside the dump (takeover candidates)
- NS set and SOA serial reporting

**How to Execute:**
```bash
# Basic scan
nmap -p 53 --script dns-zone-transfer-check example.com

# More nameservers to test and a bigger budget
nmap -p 53 --script dns-zone-transfer-check --script-args maxns=16,maxrequests=48 example.com
```

**Sample Output:**
```
| dns-zone-transfer-check:
|   Status: VULNERABLE - unauthenticated zone transfer (AXFR) is allowed for target.example.com.
|   Risk Level: 🟡 MEDIUM
|   AXFR (TCP): GRANTED
|   AXFR details: 31 records, 5 packets, 2200 bytes, via resolver (port 53), terminated at repeating SOA
|   AXFR over UDP: truncated (TC set)
|   Credential-shaped TXT in dump (masked):
|     1:       [HIGH] _deploy.target.example.com: de************************et (32 chars) (matched 'secret')
|     2:       [HIGH] _internal-note.target.example.com: st************************26 (37 chars) (matched 'password')
```

---

### 15. **dns-dnscrypt-support** - Dns Dnscrypt Support
**Description:** Detects whether the target offers DNSCrypt v2 (authenticated and encrypted DNS) on the probed port, over both UDP and TCP. DNSCrypt lets clients on untrusted networks (public Wi-Fi, hostile ISPs, corporate NATs that inspect DNS) query DNS with the server's identity authenticated and the payload encrypted - without the certificate management burden of TLS/DoT or the path dependency of DoH. The script performs the real certificate exchange of the DNSCrypt v2 protocol.

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- DNSCrypt v2 certificate request/response over UDP (0x19 0x13 client magic)
- The same exchange over TCP (protocol-accurate framing)
- Certificate fields: version, type, length, key fingerprint
- Fingerprint comparison between transports and between audit runs
- Malformed-payload handling (server should drop, not crash)

**How to Execute:**
```bash
# Basic scan (probes port 443 udp+tcp)
nmap -p 443 --script dns-dnscrypt-support example.com

# Skip the malformed probe
nmap -p 443 --script dns-dnscrypt-support --script-args malformed_probe=false example.com
```

**Sample Output:**
```
| dns-dnscrypt-support:
|   Status: AUDITED - DNSCrypt v2 supported on port 443 over udp and tcp.
|   Risk Level: 🟢 LOW
|   Certificate exchange:
|     1:       UDP      certificate OK: version 0, type 0, 33 bytes, key fingerprint 7b60e5ed
|     2:       TCP      certificate OK: version 0, type 0, 33 bytes, key fingerprint 7b60e5ed
|   Fetch log:
|     1: UDP/443 certificate request (36 bytes) -> supported
|     2: TCP/443 certificate request (36 bytes) -> supported
|     3: UDP malformed payload probe -> no response (dropped, expected)
```

---

### 16. **dns-doh-endpoint-probe** - Dns Doh Endpoint Probe
**Description:** Probes whether the target serves a DNS-over-HTTPS (DoH) endpoint at /dns-query, the path mandated by RFC 8484, and validates that the endpoint actually speaks the DoH wire format - not just that the URL exists. DoH lets clients resolve DNS inside TLS on port 443, which defeats DNS interception on untrusted networks. The audit tells you whether the endpoint is real, which request modes it supports, and whether its transport and CORS configuration are sound.

**Risk Level:** 🟢 LOW | **Category:** discovery, safe

**What it checks:**
- Encoded mode (RFC 8484): a real DNS A query, base64url-encoded, GET /dns-query?dns=<message> with Accept: application/dns-message; response ID must match
- Simple mode: GET /dns-query?name=<host>&type=A
- 406 negative control (Accept: text/html must be rejected)
- Content-Type application/dns-message validation
- TLS presence and Access-Control-Allow-Origin (browser DoH clients)

**How to Execute:**
```bash
# Basic scan
nmap -p 443 --script dns-doh-endpoint-probe example.com

# Skip the simple-mode and negative probes
nmap -p 443 --script dns-doh-endpoint-probe --script-args simple_check=false,negative_check=false example.com
```

**Sample Output:**
```
| dns-doh-endpoint-probe:
|   Status: IDENTIFIED - DNS-over-HTTPS (DoH) endpoint active on /dns-query
|          (RFC 8484: encoded and simple modes).
|   Risk Level: 🟢 LOW
|   Request mode support:
|     1:       encoded (dns=base64url):  ok / rcode NOERROR
|     2:       simple  (name=, type=):   ok / rcode NOERROR
|     3:       negative (Accept: text/html): correct-406
|   Probed endpoint: https://target.example.com:443/dns-query
|   Findings:
|     1: no weaknesses detected by this audit
```

## 🛡️ Safety Notes

- All 16 scripts are **defensive and non-destructive**: they send standard DNS queries at a polite rate, never forge source addresses, never flood, and never modify any data.
- Zone-transfer scripts stream the zone **read-only**; credential-shaped strings are **masked** in the output (first 2 + last 2 characters).
- Every script enforces a `maxrequests` budget and a `delay` between queries; a hostile or rate-limiting server simply stops answering and the audit degrades to evidence-gathering of the refusals.
