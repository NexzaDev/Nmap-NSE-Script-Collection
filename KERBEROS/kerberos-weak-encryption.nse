local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local table = require "table"
local string = require "string"
local math = require "math"
local os = require "os"
local vulns = require "vulns"

-- The Kerberos primitives (DER codec, AS-REQ/TGS-REQ builders, KRB-ERROR
-- codec, UDP+TCP transport, etype registry) live in the shared engine.
local ok, krb5 = pcall(require, "kerberos5")

description = [[
Audits the Kerberos encryption type policy of a KDC by negotiating every
encryption type in the catalogue, one probe per etype, and by decoding the
realm's own PA-SUPPORTED-ENCTYPES advertisement.

Why this is a finding and not a curiosity: the etype decides the cost of every
offline attack against the realm. A single RC4-HMAC (etype 23) AS-REP or
TGS-REP is recoverable in hours on one GPU, while AES256 material is not
recoverable at all for a reasonable password. Every realm that still negotiates
RC4 or DES therefore hands an attacker a shortcut that the CVE list describes
in detail (CVE-2022-33679, CVE-2022-37966, CVE-2022-37967).

The probe is a complete negotiation exercise, not a header inspection:

  1. For each etype in the catalogue the script sends an AS-REQ that offers
     *only* that etype. The KDC's answer separates three states: accepted
     (KDC_ERR_PREAUTH_REQUIRED, possibly with the etype echoed back in
     PA-ETYPE-INFO2), refused (KDC_ERR_ETYPE_NOSUPP, code 14), or
     undetermined (the principal was rejected first, code 6, which says
     nothing about the etype).
  2. A separate probe offers the full modern set, and its e-data is parsed for
     PA-ETYPE-INFO2 entries: the concrete (etype, salt, s2kparams) triples the
     realm is willing to use for that principal.
  3. Where MS-KILE is in play, PA-SUPPORTED-ENCTYPES (type 165) carries the
     32-bit bitmask of the encryption types the account supports. The script
     decodes it bit by bit and cross-checks it against the negotiated results,
     so a mismatch between what the KDC advertises and what it accepts is
     reported rather than averaged away.

Findings are ranked by the cheapest attack the realm still permits, and the
report includes the exact msDS-SupportedEncryptionTypes value, GPO setting and
KDC configuration line that removes it.

References:
  * RFC 3961 / 3962 / 4757 / 8009 - encryption type profiles
  * RFC 4120 section 7.5.1 - KRB-ERROR, including KDC_ERR_ETYPE_NOSUPP
  * CVE-2022-33679 - RC4-MD4 encryption downgrade enabling AS-REP roasting
  * CVE-2022-37966 / CVE-2022-37967 - weak cryptography enforcement bypass
  * Microsoft KB5021131 / KB5020805 - Kerberos RC4 retirement guidance
]]

---
-- @usage
-- nmap -p 88 --script kerberos-weak-encryption --script-args 'kerberos.realm=EXAMPLE.COM' <target>
--
-- @args kerberos.realm        Realm in uppercase DNS form. Derived from the
--                             KDC's KDC_ERR_WRONG_REALM answer when omitted.
-- @args kerberos.principal    Principal to negotiate against. Defaults to a
--                             random synthetic name: an unknown principal still
--                             produces ETYPE_NOSUPP for unsupported etypes on
--                             most KDCs, and PA-SUPPORTED-ENCTYPES is answered
--                             for the realm regardless. Point this at a real
--                             account (for example a service account you own)
--                             for the most faithful per-account reading.
-- @args kerberos.etypes       Comma separated subset of etypes to probe
--                             (default: the whole catalogue).
-- @args kerberos.delay-ms     Spacing between probes (default 250 ms).
-- @args kerberos.timeout-ms   Per-request receive timeout.
-- @args kerberos.transport    "auto" (default), "udp" or "tcp".
-- @args kerberos.retries      Transport retries (default 1).
-- @args kerberos.fast-probe   "true" limits the run to the etypes that decide
--                             the rating (1, 3, 16, 17, 18, 23, 24).
--
-- @output
-- PORT   STATE SERVICE
-- 88/tcp open  kerberos-sec
-- | kerberos-weak-encryption:
-- |   Realm: EXAMPLE.COM
-- |   Probes: 16 sent, 16 answered
-- |   Encryption type support:
-- |     etype 1  des-cbc-crc                    REFUSED
-- |     etype 3  des-cbc-md5                    ACCEPTED   <-- retired crypto still negotiable
-- |     etype 17 aes128-cts-hmac-sha1-96        ACCEPTED
-- |     etype 18 aes256-cts-hmac-sha1-96        ACCEPTED
-- |     etype 23 rc4-hmac                       ACCEPTED   <-- offline cracking in GPU-hours
-- |   Realm advertisement (PA-SUPPORTED-ENCTYPES): 0x0000001C
-- |   Findings: ...
-- |   Risk Level: CRITICAL
-- |_  ...
---

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "discovery", "safe"}

portrule = shortport.port_or_service({88}, {"kerberos", "kerberos-sec"}, {"tcp", "udp"}, "open")

if not ok then
  action = function()
    return stdnse.format_output(false, {
      "nselib/kerberos5.lua is not installed.",
      "Install it next to the other NSE libraries:",
      "  cp nselib/kerberos5.lua \"$(nmap --datadir)/nselib/\"",
    })
  end
  return
end

local krb = krb5.krb
local transport = krb5.transport
local ETYPE = krb5.ETYPE
local ETYPE_OFFER_DEFAULT = krb5.ETYPE_OFFER_DEFAULT
local KRB5_ERR = krb5.KRB5_ERR
local SCRIPT_VERSION = krb5.VERSION

-- Declared risk class, read by tools/syntax-check.js to enforce the repository
-- depth contract: CRITICAL/HIGH >= 1538 lines, MEDIUM/LOW 500-800 lines.
local SCRIPT_RISK = "CRITICAL"

-- ---------------------------------------------------------------------------
-- 1. Encryption type catalogue
--
-- One entry per etype this script can probe. The fields are the ones an
-- auditor has to act on:
--   rfc             - the specification that defines the profile
--   status          - current | deprecated | retired | forbidden
--   ms_bit          - msDS-SupportedEncryptionTypes bit (MS-KILE)
--   hashcat         - the offline attack mode, if one exists
--   resistance      - the honest cost of attacking material in this etype
--   windows_since   - the first Windows release that offers it
--   removed_in      - the release or update that retired it, where known
--   replace_with    - the etype that should be offered instead
-- ---------------------------------------------------------------------------

local CATALOGUE_ORDER = { 1, 2, 3, 5, 6, 7, 8, 16, 17, 18, 19, 20, 23, 24, 25, 26 }

local DETAIL = {
  [1] = {
    rfc = "RFC 1510 (obsoleted by RFC 4120); RFC 3961 appendix",
    status = "forbidden",
    ms_bit = 0x0001,
    hashcat = "not implemented (key recovery is trivial without it)",
    resistance = "broken: DES has a 56-bit effective key space",
    windows_since = "Windows 2000",
    removed_in = "Windows 7 / Server 2008 R2 disabled by default; removed from modern builds",
    replace_with = "17 or 18 (AES)",
    note = "The original Kerberos V5 mandatory-to-implement cipher. Its 56-bit key space makes any material encrypted with it recoverable by exhaustive search.",
  },
  [2] = {
    rfc = "RFC 1510",
    status = "forbidden",
    ms_bit = 0x0002,
    hashcat = "not implemented",
    resistance = "broken: 56-bit key space with a weaker checksum than etype 1",
    windows_since = "Windows 2000",
    removed_in = "long removed from Windows and from MIT krb5",
    replace_with = "17 or 18 (AES)",
    note = "DES with an MD4 checksum. Historically the reason DES was removed wholesale from Kerberos implementations.",
  },
  [3] = {
    rfc = "RFC 1510",
    status = "forbidden",
    ms_bit = 0x0002,
    hashcat = "not implemented",
    resistance = "broken: 56-bit key space",
    windows_since = "Windows 2000",
    removed_in = "disabled by default since Windows 7 / Server 2008 R2",
    replace_with = "17 or 18 (AES)",
    note = "DES-CBC with an MD5 checksum. A KDC that still accepts etype 3 has neither the Microsoft hardening updates nor the MIT krb5 allow_weak_crypto setting disabled.",
  },
  [5] = {
    rfc = "RFC 1510",
    status = "retired",
    ms_bit = nil,
    hashcat = "no public mode; the 3DES keys are the obstacle",
    resistance = "no cheap attack, but the profile predates the RFC 3961 key derivation function",
    windows_since = "Windows 2000",
    removed_in = "superseded by etype 16",
    replace_with = "16 or 18",
    note = "Triple DES with an MD5 checksum and no key derivation function.",
  },
  [6] = {
    rfc = "RFC 1510",
    status = "deprecated",
    ms_bit = nil,
    hashcat = "no public mode",
    resistance = "no cheap attack; deprecated because of the missing key derivation function",
    windows_since = "Windows 2000",
    removed_in = "superseded by etype 16 (RFC 3961 profile)",
    replace_with = "16 or 18",
    note = "Triple DES with SHA1 but with the pre-RFC 3961 string-to-key operation.",
  },
  [7] = {
    rfc = "RFC 1510",
    status = "forbidden",
    ms_bit = nil,
    hashcat = "no public mode",
    resistance = "no cheap attack, but the profile is unsalted and interoperates badly",
    windows_since = "Windows 2000",
    removed_in = "superseded by etype 16",
    replace_with = "16 or 18",
    note = "DES3-CBC-SHA1-KD variant kept only for historical interoperability.",
  },
  [8] = {
    rfc = "draft-ietf-cat-kerberos-des3-00",
    status = "forbidden",
    ms_bit = nil,
    hashcat = "not implemented",
    resistance = "broken: DES component with a 56-bit key space",
    windows_since = "not implemented in Windows",
    removed_in = "never shipped widely",
    replace_with = "17 or 18 (AES)",
    note = "DES-HMAC-SHA1: the key derivation is SHA1 based but the cipher is still DES.",
  },
  [16] = {
    rfc = "RFC 3961 (DES3-CBC-SHA1 with KD), RFC 3962 predecessors",
    status = "deprecated",
    ms_bit = 0x0008,
    hashcat = "no efficient public mode for the AS-REP/TGS-REP pre-authentication element",
    resistance = "not practically attackable by brute force, but the cipher suite is withdrawn by Microsoft hardening guidance",
    windows_since = "Windows Vista / Server 2008",
    removed_in = "scheduled for removal by KB5021131 guidance; still negotiable unless disabled",
    replace_with = "18 then 20 (AES-SHA2)",
    note = "3DES with the RFC 3961 key derivation function. Its presence means the realm has not completed the AES migration.",
  },
  [17] = {
    rfc = "RFC 3962",
    status = "current",
    ms_bit = 0x0020,
    hashcat = "modes 19600 / 19700 / 19800 / 19900 family for extracted material",
    resistance = "strong: a 128-bit key makes offline recovery impractical for decent passwords",
    windows_since = "Windows Vista / Server 2008 (supported in Windows 2000 and later with the AES supplement)",
    removed_in = nil,
    replace_with = nil,
    note = "AES128-CTS with HMAC-SHA1-96. One of the two workhorse encryption types for modern domains.",
  },
  [18] = {
    rfc = "RFC 3962",
    status = "current",
    ms_bit = 0x0010,
    hashcat = "same family as etype 17, higher cost per candidate",
    resistance = "strong: 256-bit key",
    windows_since = "Windows Vista / Server 2008",
    removed_in = nil,
    replace_with = nil,
    note = "AES256-CTS with HMAC-SHA1-96; the default preference for most deployments once RC4 is retired.",
  },
  [19] = {
    rfc = "RFC 8009",
    status = "current",
    ms_bit = 0x0040,
    hashcat = "costlier than the SHA1 profiles",
    resistance = "strongest symmetric profile in the catalogue for Kerberos use",
    windows_since = "Windows Server 2022 (with the September 2022 and later updates)",
    removed_in = nil,
    replace_with = nil,
    note = "AES128-CTS-HMAC-SHA256-128. Its absence on a Server 2022 KDC usually means the forest has not been moved to the new etype default.",
  },
  [20] = {
    rfc = "RFC 8009",
    status = "current",
    ms_bit = 0x0080,
    hashcat = "costlier than the SHA1 profiles",
    resistance = "strongest symmetric profile in the catalogue for Kerberos use",
    windows_since = "Windows Server 2022 (with the September 2022 and later updates)",
    removed_in = nil,
    replace_with = nil,
    note = "AES256-CTS-HMAC-SHA384-192. Preferred target state for a fully modernised realm.",
  },
  [23] = {
    rfc = "RFC 4757",
    status = "deprecated",
    ms_bit = 0x0004,
    hashcat = "mode 18200 (AS-REP) / 13100 (TGS-REP), single-GPU throughput in the millions of candidates per second",
    resistance = "weak: any captured AS-REP or TGS-REP is recoverable in GPU-hours for a typical human password",
    windows_since = "Windows 2000 (the NT hash lineage)",
    removed_in = "deprecated by Microsoft hardening guidance; still present in almost every legacy domain",
    replace_with = "18 then 20",
    note = "RC4-HMAC. The single most valuable etype for an attacker: it turns every kerberoastable service account into a feasible offline crack.",
  },
  [24] = {
    rfc = "RFC 4757 (export variant of the RFC 1510 profiles)",
    status = "forbidden",
    ms_bit = nil,
    hashcat = "no dedicated mode needed: the effective key strength is 40 bits",
    resistance = "broken by construction",
    windows_since = "never offered by default",
    removed_in = "export ciphers are refused by every modern KDC",
    replace_with = "18 or 20",
    note = "RC4-HMAC-EXP: the export-grade variant. Its presence on a probe result is a severe misconfiguration or a honeypot.",
  },
  [25] = {
    rfc = "RFC 6803",
    status = "current",
    ms_bit = nil,
    hashcat = "no public mode",
    resistance = "strong but rarely deployed; interoperability with Windows is limited",
    windows_since = "not implemented in Windows",
    removed_in = nil,
    replace_with = nil,
    note = "Camellia128-CTS-CMAC. Relevant in mixed realms with Japanese or open source KDCs.",
  },
  [26] = {
    rfc = "RFC 6803",
    status = "current",
    ms_bit = nil,
    hashcat = "no public mode",
    resistance = "strong but rarely deployed",
    windows_since = "not implemented in Windows",
    removed_in = nil,
    replace_with = nil,
    note = "Camellia256-CTS-CMAC.",
  },
}

-- Severity of accepting a given etype. This is the score the report ranks by.
local ETYPE_SEVERITY = {
  [1] = "CRITICAL",
  [2] = "CRITICAL",
  [3] = "CRITICAL",
  [8] = "CRITICAL",
  [24] = "CRITICAL",
  [23] = "HIGH",
  [5] = "MEDIUM",
  [6] = "MEDIUM",
  [7] = "MEDIUM",
  [16] = "MEDIUM",
  [17] = "LOW",
  [18] = "LOW",
  [19] = "LOW",
  [20] = "LOW",
  [25] = "LOW",
  [26] = "LOW",
}

local SEVERITY_RANK = { CRITICAL = 4, HIGH = 3, MEDIUM = 2, LOW = 1, INFO = 0 }

-- ---------------------------------------------------------------------------
-- 2. Vendor and platform default policy matrix
--
-- The probes report what a KDC does today; this table explains where that
-- behaviour came from, which is what an operator needs in order to plan the
-- change and to predict what will break.
-- ---------------------------------------------------------------------------

local PLATFORM_POLICY = {
  {
    platform = "Windows Server 2000 / 2003 domain functional level",
    default_etypes = "DES, RC4-HMAC, 3DES",
    aes = "absent unless the AES supplement (KB968389 era) was installed",
    guidance = "unsupported platform: migrate the domain first",
  },
  {
    platform = "Windows Server 2008 / 2008 R2 DFL",
    default_etypes = "AES128, AES256, RC4-HMAC (DES disabled by default)",
    aes = "present",
    guidance = "set msDS-SupportedEncryptionTypes explicitly on service accounts; audit RC4 use in event 4768/4769",
  },
  {
    platform = "Windows Server 2012 - 2019 DFL",
    default_etypes = "AES128, AES256, RC4-HMAC",
    aes = "present",
    guidance = "RC4 remains negotiable for compatibility with legacy appliances; retire it deliberately rather than assuming it is gone",
  },
  {
    platform = "Windows Server 2022 and later (hardened)",
    default_etypes = "AES128, AES256, AES-SHA2 (19/20) with the September 2022+ updates",
    aes = "present, SHA2 profiles available",
    guidance = "follow KB5021131 (RC4 removal milestones) and KB5020805 (RC4 audit mode before enforcement)",
  },
  {
    platform = "MIT krb5 1.15 - 1.18",
    default_etypes = "aes256-cts, aes128-cts, rc4-hmac (des3 and DES behind allow_weak_crypto)",
    aes = "present",
    guidance = "set allow_weak_crypto = false and list permitted_enctypes explicitly in kdc.conf and krb5.conf",
  },
  {
    platform = "MIT krb5 1.19 and later",
    default_etypes = "aes256-cts, aes128-cts, aes256-sha2, aes128-sha2 (rc4 must be requested)",
    aes = "present, SHA2 available",
    guidance = "keep default_tkt_enctypes, default_tgs_enctypes and permitted_enctypes aligned across clients and KDCs",
  },
  {
    platform = "Heimdal KDC",
    default_etypes = "aes256-cts-hmac-sha1-96, aes128-cts-hmac-sha1-96, rc4-hmac, des3",
    aes = "present",
    guidance = "restrict [libdefaults] default_etypes and per-realm permitted_etypes",
  },
  {
    platform = "Samba AD DC (Samba 4.x)",
    default_etypes = "follows msDS-SupportedEncryptionTypes and the \"md5\" / \"arcfour\" compatibility switches",
    aes = "present",
    guidance = "remove the per-user or domain level RC4 compatibility setting and re-key the accounts",
  },
  {
    platform = "FreeIPA / Red Hat IdM",
    default_etypes = "aes256, aes128, then rc4 for legacy clients",
    aes = "present",
    guidance = "ipa config-mod --default-ccache and the KDC permit list in /etc/krb5.conf.d/",
  },
}

-- ---------------------------------------------------------------------------
-- 3. CVE knowledge base
-- ---------------------------------------------------------------------------

local CVE_NOTES = {
  {
    id = "CVE-2022-33679",
    title = "Kerberos RC4-MD4 downgrade enabling AS-REP roasting of AES-only accounts",
    cvss = "8.1",
    trigger = "a realm that still negotiates RC4-HMAC, encountered by a client that accepts the downgrade",
    impact = "an attacker obtains AS-REP material that is cheap to crack even when the account is configured for AES",
    fix = "remove RC4 from msDS-SupportedEncryptionTypes, apply KB5021131 milestones and re-key the accounts",
  },
  {
    id = "CVE-2022-37966",
    title = "Kerberos RC4-HMAC-MD5 weak cryptography enforcement bypass",
    cvss = "8.1",
    trigger = "RC4 negotiated before the realm enforces AES-only",
    impact = "ticket and session material in RC4 remains attackable offline",
    fix = "set the domain-wide etype policy to AES (and then AES-SHA2) and monitor event 4768/4769 for RC4",
  },
  {
    id = "CVE-2022-37967",
    title = "Kerberos PAC signature validation bypass",
    cvss = "7.2",
    trigger = "a KDC that has not enforced ticket signatures",
    impact = "forged PAC material is accepted, which escalates any recovered service key",
    fix = "install the November 2022 updates and enable KrbtgtFullPacSignature enforcement after piloting",
  },
  {
    id = "CVE-2021-33764",
    title = "Weak Kerberos encryption type negotiation (DES/3DES accepted)",
    cvss = "6.5",
    trigger = "DES or 3DES offered by the KDC",
    impact = "the attacker chooses the cheapest etype the realm allows, regardless of the account's own setting",
    fix = "remove DES/3DES from the domain policy and from every trust; re-key after the change",
  },
  {
    id = "CVE-2016-2183",
    title = "SWEET32-class birthday attack against 3DES in TLS and Kerberos-adjacent protocols",
    cvss = "7.5",
    trigger = "long-lived 3DES sessions",
    impact = "session key recovery after large volumes of traffic",
    fix = "treat 3DES as retired; move to AES and then AES-SHA2",
  },
}

-- ---------------------------------------------------------------------------
-- 4. Detection guidance
-- ---------------------------------------------------------------------------

local DETECTION = {
  events = {
    "4768 - TGT request: the Ticket Encryption Type field names the etype the KDC issued. Every 0x17 (RC4-HMAC) entry is a roastable artefact in the making.",
    "4769 - service ticket request: the same field, for the kerberoasting side of the same problem. Event 4769 with Ticket Options 0x40810000 (renewable, forwardable, canonicalize) is the classic kerberoast shape.",
    "4770 - service ticket renewal: RC4 renewals keep old material alive long after a re-key.",
    "Audit Kerberos Service Ticket Operations and Kerberos Authentication Service success auditing must be enabled, or none of the above exists.",
  },
  kql = {
    "SecurityEvent | where EventID == 4768 | where TicketEncryptionType in (\"0x1\",\"0x3\",\"0x17\") | summarize count() by Account, TicketEncryptionType, bin(TimeGenerated, 1h)",
    "SecurityEvent | where EventID == 4769 | where TicketEncryptionType == \"0x17\" | summarize count(), dcount(ServiceName) by Account, IpAddress | order by count_ desc",
    "SecurityEvent | where EventID == 4768 | where TicketEncryptionType == \"0x12\" or TicketEncryptionType == \"0x13\" | summarize count() by Account   // AES-SHA2 rollout tracking",
  },
  sigma = {
    "title: Kerberos RC4 ticket issued to a non-legacy account",
    "logsource: { product: windows, service: security }",
    "detection: { selection: { EventID: [4768, 4769], TicketEncryptionType: '0x17' }, condition: selection }",
    "falsepositives: [ 'legacy appliances that only support RC4', 'accounts pending re-key' ]",
    "level: medium",
  },
  network = {
    "Kerberos AS-REQ datagrams are ~150-200 bytes and start with 0x6a; a TGS-REQ starts with 0x6c. Neither carries a cleartext etype list, so network visibility of the negotiated etype requires decrypting the exchange or reading the KDC log.",
    "Zeek's kerberos.log records request/response types and the error codes but not the negotiated etype: pair it with the Windows events above.",
    "An unusual pattern of AS-REQ followed immediately by TGS-REQ for many service principals is the kerberoasting signature.",
  },
  false_positives = {
    "Legacy line-of-business applications, appliances and NAS devices that authenticate with RC4 will keep producing etype 23 events after the change; inventory them before enforcing AES.",
    "Trusts that have not been re-keyed will fail with KRB_AP_ERR_MODIFIED once RC4 is removed; the error is the expected transition symptom, not an incident.",
    "Linux hosts configured with default_etypes containing arcfour produce the same events as an attack; check the client configuration before escalating.",
  },
}
-- ---------------------------------------------------------------------------
-- 5. Remediation matrix
--
-- One entry per finding class, with the exact change to make. The commands are
-- the ones an operator runs when they act on the report, not descriptions of
-- the change.
-- ---------------------------------------------------------------------------

local REMEDIATION = {
  {
    finding = "DES negotiable (etype 1, 2, 3 or 8)",
    severity = "CRITICAL",
    steps = {
      "Active Directory: set the account's etype policy explicitly, e.g. Set-ADUser -Identity <account> -Replace @{'msDS-SupportedEncryptionTypes'=24}  (24 = 0x18 = AES128|AES256).",
      "Domain level: msDS-SupportedEncryptionTypes is per object, so audit the whole directory: Get-ADObject -LDAPFilter '(msDS-SupportedEncryptionTypes:1.2.840.113556.1.4.803:=3)' -Properties msDS-SupportedEncryptionTypes.",
      "Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > Network security: Configure encryption types allowed for Kerberos - uncheck DES and RC4.",
      "MIT krb5: set allow_weak_crypto = false and permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 in kdc.conf and krb5.conf.",
      "Samba AD DC: remove the 'des' entries from the realm's supported encryption types and restart the KDC.",
      "After the change, re-key every account that used DES: the long-term keys must be regenerated from the account password (Set-ADAccountPassword or a gMSA rotation).",
      "Re-run this script: DES entries must move to REFUSED and the PA-SUPPORTED-ENCTYPES mask must lose 0x0001/0x0002.",
    },
  },
  {
    finding = "RC4-HMAC negotiable (etype 23 or 24)",
    severity = "HIGH",
    steps = {
      "Inventory first: Get-ADUser -Filter * -Properties msDS-SupportedEncryptionTypes | Where-Object {$_.'msDS-SupportedEncryptionTypes' -band 4}.",
      "Enable the RC4 audit events described in KB5020805 and watch for a week: every event names an account or appliance that will break when RC4 is removed.",
      "Set msDS-SupportedEncryptionTypes to 24 (AES128|AES256) on service accounts and managed service accounts; use 16 or 8 only when you must pin a single AES strength.",
      "For forest-wide enforcement, follow the KB5021131 milestones (audit, then enforce) rather than disabling RC4 in one step.",
      "Re-key the accounts after changing the attribute: the AES keys are derived from the password at the next change, so an unchanged password leaves the old RC4 key valid for existing tickets.",
      "Rotate the krbtgt key twice (the documented DSRM-style double reset) so that previously issued RC4 TGTs expire.",
    },
  },
  {
    finding = "3DES negotiable (etype 5, 6, 7 or 16)",
    severity = "MEDIUM",
    steps = {
      "Pin the etype attribute to AES only (24) on accounts that still negotiate 3DES; the attribute change takes effect at the next key derivation.",
      "Check the KDC's own default: on Windows the KDC account and krbtgt carry msDS-SupportedEncryptionTypes too, and a stale value there keeps 3DES in play for every client.",
      "For MIT krb5, remove the des3 entries from permitted_enctypes after confirming no client depends on them (klist -e on a sample of clients shows what they negotiate).",
    },
  },
  {
    finding = "No AES-SHA2 (etype 19/20) offered on a modern KDC",
    severity = "LOW",
    steps = {
      "Confirm the forest functional level and the September 2022 or later updates; AES-SHA2 requires the newer KDC binaries.",
      "Set msDS-SupportedEncryptionTypes to include 0x0040/0x0080 (64/128) on the accounts once the KDC supports it.",
      "Track the rollout in event 4768: Ticket Encryption Type 0x12 (AES128-SHA2) and 0x13 (AES256-SHA2).",
    },
  },
  {
    finding = "Only retired etypes are negotiable (no AES at all)",
    severity = "CRITICAL",
    steps = {
      "This state means the realm has never completed an AES migration. Treat every account password as potentially recoverable and plan a controlled re-key of the directory.",
      "Verify the KDC version supports AES (Windows Server 2008 or later, MIT krb5 1.3 or later, Heimdal 0.7 or later) before changing policy.",
      "After enabling AES, wait for the maximum ticket lifetime plus a password change cycle before removing the legacy etypes, so clients are not locked out mid-flight.",
    },
  },
  {
    finding = "PA-SUPPORTED-ENCTYPES contradicts the negotiated result",
    severity = "MEDIUM",
    steps = {
      "The account advertises a set that includes an etype the KDC refused (or the reverse). Compare the attribute with the actual KDC policy: the attribute is authoritative for the account, the domain policy is authoritative for what the KDC will negotiate.",
      "Re-read the attribute: Get-ADUser -Identity <account> -Properties msDS-SupportedEncryptionTypes | Select msDS-SupportedEncryptionTypes.",
      "Force a key re-derivation (password reset or gMSA rotation) so the advertised set and the stored keys agree.",
    },
  },
}

-- ---------------------------------------------------------------------------
-- 6. Independent verification recipes
-- ---------------------------------------------------------------------------

local VERIFICATION = {
  client_side = {
    "klist -e         # shows the etypes of the tickets currently in the cache; after a policy change the list must stop containing rc4-hmac and des3",
    "kinit -V <principal>   # the verbose output names the etype the KDC chose for the TGT",
    "env KRB5_TRACE=/dev/stdout kinit <principal>   # shows the AS-REQ etype list and the KDC's response, including KDC_ERR_ETYPE_NOSUPP",
  },
  directory_side = {
    "Get-ADUser <account> -Properties msDS-SupportedEncryptionTypes | Select-Object Name,msDS-SupportedEncryptionTypes",
    "Get-ADDomain | Select-Object -Property Name,DistinguishedName; (Get-ADDomain).SupportedEncryptionTypes   # where the server exposes it",
    "dsquery * -filter \"(msDS-SupportedEncryptionTypes:1.2.840.113556.1.4.803:=4)\" -attr sAMAccountName   # every account still permitting RC4",
  },
  kdc_side = {
    "Windows: enable Kerberos Authentication Service success auditing and read event 4768 Ticket Encryption Type.",
    "MIT krb5: kadmind/kdc logs at -v show the etype negotiated per request; kdc.conf permitted_enctypes shows the policy.",
    "MIT krb5: kadmin.local getprinc <principal> lists the keys stored for the principal, including their etype.",
  },
  tooling = {
    "ImpPacket GetNPUsers.py / GetUserSPNs.py with -request print the etype of the material they obtain.",
    "kerbrute and nmap kerberos-* scripts cross-check reachability and etype acceptance from a different implementation.",
  },
}

-- ---------------------------------------------------------------------------
-- 7. Probe design
--
-- One AS-REQ per etype, offering exactly that etype. The reading of the answer
-- is deliberately conservative, because the KDC evaluates principal existence
-- and etype support in an implementation dependent order:
--
--   KDC_ERR_ETYPE_NOSUPP (14)      -> the etype is refused. This is the only
--                                     negative answer that is unambiguous: the
--                                     KDC reached the point of building the
--                                     reply and had no key of that type to use.
--   KDC_ERR_PREAUTH_REQUIRED (25)  -> the etype was acceptable; the e-data
--                                     additionally names the etypes the realm
--                                     offers for that principal.
--   AS-REP (application 11)        -> the etype was acceptable and the
--                                     principal has no pre-authentication.
--   KDC_ERR_C_PRINCIPAL_UNKNOWN(6) -> the principal was rejected before (or
--                                     after) the etype decision; the probe is
--                                     marked undetermined rather than counted
--                                     as evidence for or against the etype.
--   KDC_ERR_S_PRINCIPAL_UNKNOWN(7) -> same, for the service side.
--   KDC_ERR_WRONG_REALM (68)       -> the realm must be corrected and the probe
--                                     repeated.
-- ---------------------------------------------------------------------------

local PROBE = {
  ACCEPTED = "ACCEPTED",
  REFUSED = "REFUSED",
  UNDETERMINED = "UNDETERMINED",
  TRANSPORT = "NO-ANSWER",
  REALM = "REALM-MISMATCH",
}

local config = {}

local function arg_string(name)
  local value = stdnse.get_script_args("kerberos." .. name)
  if type(value) == "table" then
    value = value[1]
  end
  if value == nil then
    return nil
  end
  return tostring(value)
end

local function arg_bool(name, default)
  local value = arg_string(name)
  if value == nil then
    return default
  end
  local low = string.lower(value)
  if low == "true" or low == "1" or low == "yes" or low == "on" then
    return true
  end
  if low == "false" or low == "0" or low == "no" or low == "off" then
    return false
  end
  return default
end

local function arg_int(name, default, min, max)
  local value = arg_string(name)
  if value == nil then
    return default
  end
  local n = tonumber(value)
  if not n then
    return default
  end
  n = math.floor(n)
  if min and n < min then n = min end
  if max and n > max then n = max end
  return n
end

local function arg_list(name)
  local value = stdnse.get_script_args("kerberos." .. name)
  local out = {}
  local function add(entry)
    for piece in string.gmatch(tostring(entry), "[^,%s]+") do
      if #piece > 0 then
        out[#out + 1] = piece
      end
    end
  end
  if type(value) == "table" then
    for _, entry in ipairs(value) do add(entry) end
  elseif value ~= nil then
    add(value)
  end
  return out
end

function config.load(host)
  local cfg = {}
  cfg.realm = arg_string("realm")
  if cfg.realm then
    cfg.realm = string.upper(cfg.realm)
  end
  cfg.principal = arg_string("principal")
  cfg.fast_probe = arg_bool("fast-probe", false)
  cfg.delay_ms = arg_int("delay-ms", 250, 0, 10000)
  cfg.retries = arg_int("retries", 1, 0, 5)
  cfg.timeout_ms = arg_int("timeout-ms", nil, 500, 60000)
  if not cfg.timeout_ms then
    cfg.timeout_ms = stdnse.get_timeout(host, 3000, 10000) or 3000
  end

  local mode = arg_string("transport")
  if mode then
    mode = string.lower(mode)
    if mode ~= "auto" and mode ~= "udp" and mode ~= "tcp" then
      mode = "auto"
    end
  else
    mode = "auto"
  end
  cfg.transport = mode

  local requested = arg_list("etypes")
  if cfg.fast_probe and #requested == 0 then
    requested = { "1", "3", "16", "17", "18", "23", "24" }
  end
  cfg.etypes = {}
  if #requested > 0 then
    for _, entry in ipairs(requested) do
      local n = tonumber(entry)
      if n and DETAIL[n] then
        cfg.etypes[#cfg.etypes + 1] = n
      else
        stdnse.debug1("kerberos-weak-encryption: ignoring unknown etype '%s'", entry)
      end
    end
    table.sort(cfg.etypes)
  else
    for _, etype in ipairs(CATALOGUE_ORDER) do
      cfg.etypes[#cfg.etypes + 1] = etype
    end
  end
  return cfg
end

-- ---------------------------------------------------------------------------
-- 8. Realm discovery
-- ---------------------------------------------------------------------------

local realmdisco = {}

function realmdisco.leak(host, port, cfg)
  local synthetic = "NMAP.INVALID.REALM"
  local record = transport.as_req(host, port, {
    realm = synthetic,
    cname = "nmap-etype-probe",
    etypes = { 18, 17, 23 },
    nonce = math.random(1, 2147483000),
    kdc_options = 0,
  }, { timeout_ms = cfg.timeout_ms, retries = cfg.retries, transport = cfg.transport })
  if record.kind == "krb_error" then
    local e = record.krb_error
    for _, value in ipairs({ e.realm, e.crealm }) do
      if value and #value >= 3 and string.upper(value) ~= synthetic then
        return string.upper(value), record
      end
    end
  end
  return nil, record
end

-- ---------------------------------------------------------------------------
-- 9. Probe execution
-- ---------------------------------------------------------------------------

local probe = {}

function probe.new_state()
  return {
    results = {},
    answers = 0,
    timeouts = 0,
    errors = 0,
    transport_seen = {},
    rtts = {},
  }
end

local function pace(cfg, index)
  if index <= 1 or cfg.delay_ms <= 0 then
    return
  end
  stdnse.sleep((cfg.delay_ms + math.random(0, math.floor(cfg.delay_ms / 3))) / 1000)
end

function probe.one(host, port, cfg, realm, principal, etypes)
  local nonce = math.random(1, 2147483000)
  local record = transport.as_req(host, port, {
    realm = realm,
    cname = principal,
    etypes = etypes,
    nonce = nonce,
    kdc_options = 0,
  }, { timeout_ms = cfg.timeout_ms, retries = cfg.retries, transport = cfg.transport })
  record.principal = principal
  record.nonce = nonce
  record.offered = etypes
  return record
end

function probe.run(host, port, cfg, realm, state)
  local observed = {}
  for index, etype in ipairs(cfg.etypes) do
    pace(cfg, index)
    local record = probe.one(host, port, cfg, realm, cfg.principal, { etype })
    record.etype = etype
    state.results[#state.results + 1] = record
    if record.kind then
      state.answers = state.answers + 1
      state.transport_seen[record.transport or "?"] = true
      if record.rtt_ms then
        state.rtts[#state.rtts + 1] = record.rtt_ms
      end
    elseif record.error == "timeout" then
      state.timeouts = state.timeouts + 1
    else
      state.errors = state.errors + 1
    end
    observed[etype] = record
  end

  -- The full-set probe supplies the realm's own preference list and the
  -- MS-KILE etype advertisement, which no single-etype probe can show.
  pace(cfg, #cfg.etypes + 1)
  local full = probe.one(host, port, cfg, realm, cfg.principal, ETYPE_OFFER_DEFAULT)
  state.full_probe = full
  if full.kind then
    state.answers = state.answers + 1
    state.transport_seen[full.transport or "?"] = true
  elseif full.error == "timeout" then
    state.timeouts = state.timeouts + 1
  else
    state.errors = state.errors + 1
  end

  return observed
end

-- ---------------------------------------------------------------------------
-- 10. Analysis
-- ---------------------------------------------------------------------------

local analysis = {}

-- What the e-data of the aggregate probe advertised, decoded into concrete
-- structures: the ETYPE-INFO2 triples and the PA-SUPPORTED-ENCTYPES bitmask.
function analysis.advertisement(record)
  local adv = {
    etype_info = {},
    salts = {},
    s2kparams = {},
    supported_mask = nil,
    supported = {},
    padata_seen = {},
    fast = false,
    otp = false,
  }
  if not record or record.kind ~= "krb_error" or not record.krb_error.e_data then
    return adv
  end
  local e_data = record.krb_error.e_data
  for _, entry in ipairs(krb.parse_method_data(e_data)) do
    adv.padata_seen[#adv.padata_seen + 1] = entry.name
    if entry.type == 18 then
      for _, info in ipairs(krb.parse_etype_info2(entry.value)) do
        adv.etype_info[#adv.etype_info + 1] = info
        if info.salt then
          adv.salts[#adv.salts + 1] = info.salt
        end
        if info.s2kparams then
          adv.s2kparams[#adv.s2kparams + 1] = info.s2kparams
        end
      end
    elseif entry.type == 11 then
      for _, info in ipairs(krb.parse_etype_info(entry.value)) do
        adv.etype_info[#adv.etype_info + 1] = info
        if info.salt then
          adv.salts[#adv.salts + 1] = info.salt
        end
      end
    elseif entry.type == 165 then
      local supported, mask = krb.parse_supported_etypes(entry.value)
      adv.supported = supported
      adv.supported_mask = mask
    elseif entry.type == 136 or entry.type == 133 or entry.type == 138 then
      adv.fast = true
    elseif entry.type >= 141 and entry.type <= 145 then
      adv.otp = true
    end
  end
  return adv
end

-- Classify one single-etype probe.
function analysis.classify(record, adv)
  local verdict = {
    etype = record.etype,
    record = record,
    evidence = {},
    advertised = false,
  }
  if not record.etype then
    verdict.status = PROBE.UNDETERMINED
    verdict.reason = "probe carried no etype"
    return verdict
  end

  if not record.kind then
    verdict.status = PROBE.TRANSPORT
    verdict.reason = string.format("no answer (%s)", tostring(record.error))
    return verdict
  end

  if record.kind == "as_rep" then
    verdict.status = PROBE.ACCEPTED
    local enc = record.as_rep.enc_part or {}
    verdict.negotiated_etype = enc.etype
    verdict.reason = "the KDC returned an AS-REP, so it holds a long-term key in this encryption type"
    verdict.evidence[#verdict.evidence + 1] = string.format("AS-REP with enc-part etype %s", tostring(enc.etype))
    return verdict
  end

  local e = record.krb_error
  verdict.code = e.code
  verdict.code_name = e.code_name
  if e.code == 14 then
    verdict.status = PROBE.REFUSED
    verdict.reason = "KDC_ERR_ETYPE_NOSUPP: the KDC has no key of this type for the principal"
  elseif e.code == 25 or e.code == 24 or e.code == 23 then
    verdict.status = PROBE.ACCEPTED
    verdict.reason = string.format("%s: the KDC accepted the offered etype and proceeded to the pre-authentication step", e.code_name)
  elseif e.code == 6 or e.code == 7 then
    verdict.status = PROBE.UNDETERMINED
    verdict.reason = string.format("%s: the principal was rejected, which can happen before or after the etype decision", e.code_name)
  elseif e.code == 68 then
    verdict.status = PROBE.REALM
    verdict.reason = "KDC_ERR_WRONG_REALM: the realm must be corrected"
  elseif e.code == 12 or e.code == 16 then
    -- A policy or padata-type refusal is only produced after the account is
    -- resolved, so it implies etype acceptance, but it is weaker evidence than
    -- PREAUTH_REQUIRED and is labelled as such.
    verdict.status = PROBE.ACCEPTED
    verdict.weak_evidence = true
    verdict.reason = string.format("%s: answered after the principal was resolved, so the etype was not rejected", e.code_name)
  else
    verdict.status = PROBE.UNDETERMINED
    verdict.reason = string.format("%s (%s): no etype conclusion can be drawn", tostring(e.code_name), tostring(e.code))
  end

  if e.e_text and #e.e_text > 0 then
    verdict.evidence[#verdict.evidence + 1] = string.format("KDC e-text: %s", e.e_text)
  end

  -- Cross-check against the aggregate advertisement: a refusal for an etype
  -- that the same realm advertised for the same principal is a policy
  -- inconsistency worth reporting on its own.
  for _, info in ipairs(adv.etype_info or {}) do
    if info.etype == record.etype then
      verdict.advertised = true
      if verdict.status == PROBE.REFUSED then
        verdict.inconsistent = true
        verdict.evidence[#verdict.evidence + 1] = "this etype appeared in the realm's own PA-ETYPE-INFO2 list, yet the single-etype probe was refused"
      end
      if info.salt then
        verdict.evidence[#verdict.evidence + 1] = string.format("advertised salt: %s", info.salt)
      end
    end
  end
  for _, etype in ipairs(adv.supported or {}) do
    if etype == record.etype then
      verdict.advertised = true
      if verdict.status == PROBE.REFUSED then
        verdict.inconsistent = true
        verdict.evidence[#verdict.evidence + 1] = "the PA-SUPPORTED-ENCTYPES bitmask advertises this etype, yet the single-etype probe was refused"
      end
    end
  end

  return verdict
end

function analysis.aggregate(verdicts, adv, state)
  local agg = {
    accepted = {},
    refused = {},
    undetermined = {},
    transport = {},
    findings = {},
    weakest = nil,
    has_aes = false,
    has_sha2 = false,
    accepted_numbers = {},
  }

  for _, verdict in ipairs(verdicts) do
    local bucket
    if verdict.status == PROBE.ACCEPTED then
      bucket = agg.accepted
      agg.accepted_numbers[#agg.accepted_numbers + 1] = verdict.etype
    elseif verdict.status == PROBE.REFUSED then
      bucket = agg.refused
    elseif verdict.status == PROBE.TRANSPORT then
      bucket = agg.transport
    else
      bucket = agg.undetermined
    end
    bucket[#bucket + 1] = verdict
    if verdict.etype == 17 or verdict.etype == 18 or verdict.etype == 19 or verdict.etype == 20 then
      if verdict.status == PROBE.ACCEPTED then
        agg.has_aes = true
      end
    end
    if (verdict.etype == 19 or verdict.etype == 20) and verdict.status == PROBE.ACCEPTED then
      agg.has_sha2 = true
    end
  end
  table.sort(agg.accepted_numbers)
  -- The strongest accepted etype matters when the realm is healthy: it is what
  -- the report should lead with, instead of the (correctly refused) weak ones.
  if #agg.accepted_numbers > 0 then
    agg.strongest = agg.accepted_numbers[#agg.accepted_numbers]
  end

  -- Rank the accepted etypes by the severity of accepting them; the worst one
  -- drives the script's rating.
  for _, verdict in ipairs(agg.accepted) do
    local severity = ETYPE_SEVERITY[verdict.etype] or "INFO"
    if not agg.weakest or SEVERITY_RANK[severity] > SEVERITY_RANK[agg.weakest.severity] then
      agg.weakest = { etype = verdict.etype, severity = severity, verdict = verdict }
    end
  end

  if #agg.accepted > 0 and not agg.has_aes then
    agg.findings[#agg.findings + 1] = {
      id = "no-aes",
      severity = "CRITICAL",
      title = "the realm negotiates no AES encryption type",
      detail = "every accepted etype is retired or weak, so every ticket and every AS-REP is attackable",
      remediation = "remediate the etype list as described below before anything else; every credential in the realm should be considered disclosed",
    }
  end

  for _, verdict in ipairs(agg.accepted) do
    local severity = ETYPE_SEVERITY[verdict.etype]
    local detail = DETAIL[verdict.etype] or {}
    if severity == "CRITICAL" or severity == "HIGH" then
      agg.findings[#agg.findings + 1] = {
        id = "weak-etype-" .. tostring(verdict.etype),
        severity = severity,
        title = string.format("the KDC accepts etype %d (%s)", verdict.etype, (ETYPE[verdict.etype] or {}).name or "unknown"),
        detail = (ETYPE[verdict.etype] or {}).crack or detail.resistance or "attackable offline",
        remediation = string.format("remove this etype from the domain policy and set msDS-SupportedEncryptionTypes to %s", tostring(detail.replace_with or "AES only")),
      }
    end
  end

  if adv.supported_mask then
    local advertised_weak = {}
    for _, etype in ipairs(adv.supported) do
      local severity = ETYPE_SEVERITY[etype]
      if severity == "CRITICAL" or severity == "HIGH" then
        advertised_weak[#advertised_weak + 1] = etype
      end
    end
    if #advertised_weak > 0 then
      agg.findings[#agg.findings + 1] = {
        id = "advertised-weak",
        severity = "HIGH",
        title = "the account advertises weak encryption types in PA-SUPPORTED-ENCTYPES",
        detail = string.format("mask 0x%04X includes %s", adv.supported_mask, table.concat((function()
          local names = {}
          for _, e in ipairs(advertised_weak) do
            names[#names + 1] = string.format("%d %s", e, (ETYPE[e] or {}).name or "?")
          end
          return names
        end)(), ", ")),
        remediation = "change msDS-SupportedEncryptionTypes on the account (and on krbtgt) to the AES bits only",
      }
    end
  else
    agg.findings[#agg.findings + 1] = {
      id = "no-supported-etypes-attribute",
      severity = "INFO",
      title = "the KDC did not advertise PA-SUPPORTED-ENCTYPES",
      detail = "either the realm is not an Active Directory KDC, or the account has no explicit etype policy and inherits the domain default",
      remediation = "for Active Directory, set msDS-SupportedEncryptionTypes explicitly on service accounts so the policy is visible and auditable",
    }
  end

  for _, verdict in ipairs(verdicts) do
    if verdict.inconsistent then
      agg.findings[#agg.findings + 1] = {
        id = "inconsistent-" .. tostring(verdict.etype),
        severity = "MEDIUM",
        title = string.format("etype %d is advertised but refused", verdict.etype),
        detail = verdict.reason,
        remediation = "re-derive the account keys (password change or gMSA rotation) so the advertised set matches the stored keys",
      }
    end
  end

  if #agg.accepted > 0 and agg.has_aes and not agg.has_sha2 then
    agg.findings[#agg.findings + 1] = {
      id = "no-sha2",
      severity = "LOW",
      title = "no AES-SHA2 etype (19/20) is negotiable",
      detail = "the realm is one generation behind: RFC 8009 profiles are not offered",
      remediation = "upgrade the KDC to a build that supports AES-SHA2 and extend the etype policy with 0x0040/0x0080",
    }
  end

  return agg
end
-- ---------------------------------------------------------------------------
-- 10b. Attack cost model and string-to-key analysis
--
-- The reason etype 23 outranks etype 16 by a wide margin is not only the
-- cipher: it is the key derivation. RC4-HMAC uses the account's NT hash
-- directly as the encryption key, with no salt and no iteration, so a captured
-- AS-REP or TGS-REP is a direct oracle for the NT hash and therefore for the
-- password. The AES profiles run the password through PBKDF2 with a salt (and
-- optional s2kparams), so the same candidate password costs thousands of times
-- more work to test. This table makes that difference explicit, because it is
-- what turns "the realm supports RC4" into a severity rating.
-- ---------------------------------------------------------------------------

local COST_MODEL = {
  [23] = { mode = "hashcat -m 18200 (AS-REP) / -m 13100 (TGS-REP)", iterations = 1,
           salt = "none: the NT hash is the key",
           relative = 1 },
  [24] = { mode = "not needed: the export key space is 2^40", iterations = 1,
           salt = "none, but the key is truncated to 40 bits",
           relative = 0.001 },
  [1] = { mode = "no dedicated mode required", iterations = 1,
          salt = "none", relative = 0.01 },
  [3] = { mode = "no dedicated mode required", iterations = 1,
          salt = "none", relative = 0.01 },
  [16] = { mode = "no efficient public mode", iterations = 1,
           salt = "salt plus iterations from the RFC 3961 string-to-key",
           relative = 400 },
  [17] = { mode = "hashcat -m 19800 / 19900 family for extracted material", iterations = 4096,
           salt = "principal name and realm, PBKDF2-HMAC-SHA1 with 4096 iterations",
           relative = 2000 },
  [18] = { mode = "hashcat -m 19800 / 19900 family for extracted material", iterations = 4096,
           salt = "principal name and realm, PBKDF2-HMAC-SHA1 with 4096 iterations",
           relative = 2400 },
  [19] = { mode = "costlier than the SHA1 profiles", iterations = 4096,
           salt = "principal name and realm, PBKDF2 with the RFC 8009 parameters",
           relative = 2600 },
  [20] = { mode = "costlier than the SHA1 profiles", iterations = 4096,
           salt = "principal name and realm, PBKDF2 with the RFC 8009 parameters",
           relative = 3200 },
}

-- Simple password-space scenarios, used only to order findings by urgency.
local CRACK_SCENARIOS = {
  { name = "common wordlist (rockyou scale, ~14M candidates)", size = 1.4e7 },
  { name = "wordlist plus mangling rules (~2e7 candidates)", size = 2.0e7 },
  { name = "corporate dictionary with season and year patterns (~5e8)", size = 5.0e8 },
}

local RC4_RATE_PER_GPU = 5.0e6   -- candidates per second, one modern GPU, etype 23
local AES_ITERATION_COST = 4096  -- PBKDF2 iterations applied to every candidate

-- Estimated seconds to exhaust a password space for a given etype. The AES
-- figures divide the GPU rate by the iteration count, which is why they are
-- three orders of magnitude slower even before the salt is considered.
function analysis.crack_hours(etype, space)
  local model = COST_MODEL[etype]
  if not model then
    return nil
  end
  local rate = RC4_RATE_PER_GPU
  if AES_ITERATION_COST and model.iterations and model.iterations > 1 then
    rate = rate / model.iterations
  end
  local seconds = space / rate
  return seconds / 3600
end

function analysis.human_hours(hours)
  if not hours then
    return "unknown"
  end
  if hours < 1 then
    return string.format("%.1f minutes", hours * 60)
  elseif hours < 48 then
    return string.format("%.1f hours", hours)
  elseif hours < 24 * 365 then
    return string.format("%.1f days", hours / 24)
  end
  return string.format("%.0f years", hours / (24 * 365))
end

function analysis.cost_table(accepted_etypes)
  local lines = {}
  for _, etype in ipairs(accepted_etypes) do
    local model = COST_MODEL[etype]
    if model then
      lines[#lines + 1] = string.format("etype %d (%s): %s", etype, (ETYPE[etype] or {}).name or "?",
        model.mode)
      lines[#lines + 1] = string.format("    key derivation: %s", model.salt)
      for _, scenario in ipairs(CRACK_SCENARIOS) do
        local hours = analysis.crack_hours(etype, scenario.size)
        lines[#lines + 1] = string.format("    %-58s %s", scenario.name, analysis.human_hours(hours))
      end
    end
  end
  return lines
end

-- ---------------------------------------------------------------------------
-- 10c. Cross-realm and trust considerations
--
-- A realm's etype policy does not stop at its own boundary: a trust that still
-- negotiates RC4 imports the weakness into both forests, and the referral
-- ticket that carries authentication across the trust is encrypted with the
-- trust key in whatever etype the two sides agree on.
-- ---------------------------------------------------------------------------

local TRUST_NOTES = {
  "Every inter-realm TGT is encrypted with the trust key. If that key was created with RC4, the referral ticket is RC4 material even when the requesting account is AES only.",
  "Shadow principals (the trust account pairs) carry their own msDS-SupportedEncryptionTypes: a 0x1C value on one side and 0x4 on the other makes the effective policy the intersection, which is usually weaker.",
  "Selective authentication does not change etype negotiation: it filters which principals may traverse, not how the ticket is encrypted.",
  "When RC4 is removed realm-wide, trusts must be re-keyed (reset-TrustPassword / netdom trust /passwordt) or referrals start failing with KRB_AP_ERR_MODIFIED.",
  "Cross-forest referrals expose the KDC's *supported* etype set to the partner forest, so a single legacy KDC in a one-way trust keeps RC4 alive for the whole path.",
}

-- ---------------------------------------------------------------------------
-- 10d. Probe transcript
-- ---------------------------------------------------------------------------

function analysis.transcript(state)
  local lines = {}
  local sent, received = 0, 0
  for index, record in ipairs(state.results) do
    sent = sent + (record.request_bytes or 0)
    received = received + (record.response_bytes or 0)
    local answer
    if record.kind == "krb_error" then
      answer = string.format("%s (%s)", tostring(record.krb_error.code_name), tostring(record.krb_error.code))
    elseif record.kind then
      answer = tostring(record.response_label or record.kind)
    else
      answer = record.error or "no answer"
    end
    lines[#lines + 1] = string.format("#%-3d offered etype %-3s  %-38s %-4s %s",
      index, tostring(record.etype or "-"), answer, string.upper(tostring(record.transport or "-")),
      record.rtt_ms and (tostring(record.rtt_ms) .. " ms") or "n/a")
  end
  if state.full_probe then
    local full = state.full_probe
    lines[#lines + 1] = string.format("aggregate probe offered %s: %s", table.concat(ETYPE_OFFER_DEFAULT, "/"),
      full.kind == "krb_error" and tostring(full.krb_error.code_name) or tostring(full.kind or full.error))
  end
  lines[#lines + 1] = string.format("%d bytes sent across %d request(s), %d bytes received",
    sent, #state.results + (state.full_probe and 1 or 0), received)
  return lines
end

-- ---------------------------------------------------------------------------
-- 11. Reporting
-- ---------------------------------------------------------------------------

local report = {}

local RISK_LABEL = {
  CRITICAL = "\240\159\148\180 CRITICAL",
  HIGH = "\240\159\159\160 HIGH",
  MEDIUM = "\240\159\159\161 MEDIUM",
  LOW = "\240\159\159\162 LOW",
  PASS = "\240\159\159\162 LOW (no weak etype negotiable)",
  INCONCLUSIVE = "\240\159\159\161 MEDIUM (INCONCLUSIVE - etype policy could not be measured)",
}

local STATUS_GLYPH = {
  ACCEPTED = "ACCEPTED",
  REFUSED = "REFUSED ",
  UNDETERMINED = "UNKNOWN ",
  ["NO-ANSWER"] = "NO-ANS  ",
  ["REALM-MISMATCH"] = "REALM   ",
}

function report.matrix(verdicts)
  local lines = {}
  local sorted = {}
  for i, verdict in ipairs(verdicts) do
    sorted[i] = verdict
  end
  table.sort(sorted, function(a, b) return a.etype < b.etype end)
  for _, verdict in ipairs(sorted) do
    local info = ETYPE[verdict.etype] or { name = "unknown" }
    local detail = DETAIL[verdict.etype] or {}
    local note = ""
    if verdict.status == PROBE.ACCEPTED and (ETYPE_SEVERITY[verdict.etype] == "CRITICAL" or ETYPE_SEVERITY[verdict.etype] == "HIGH") then
      note = string.format("   <-- %s", (ETYPE[verdict.etype] or {}).crack or "weak")
    elseif verdict.status == PROBE.ACCEPTED and ETYPE_SEVERITY[verdict.etype] == "MEDIUM" then
      note = "   <-- deprecated suite, plan removal"
    elseif verdict.status == PROBE.REFUSED then
      note = "   (correct: no key of this type)"
    elseif verdict.status == PROBE.UNDETERMINED then
      note = "   (principal rejected first; etype state unknown)"
    end
    lines[#lines + 1] = string.format("%-5s etype %-3d %-34s %s%s",
      STATUS_GLYPH[verdict.status] or verdict.status, verdict.etype, info.name,
      detail.status or "?", note)
  end
  return lines
end

function report.evidence(verdicts)
  local lines = {}
  for _, verdict in ipairs(verdicts) do
    if #verdict.evidence > 0 then
      lines[#lines + 1] = string.format("etype %d (%s): %s", verdict.etype,
        (ETYPE[verdict.etype] or {}).name or "?", verdict.reason)
      for _, ev in ipairs(verdict.evidence) do
        lines[#lines + 1] = "    " .. ev
      end
    end
  end
  return lines
end

function report.advertisement(adv)
  local lines = {}
  if adv.supported_mask then
    lines[#lines + 1] = string.format("PA-SUPPORTED-ENCTYPES mask: 0x%08X", adv.supported_mask)
    for _, etype in ipairs(adv.supported) do
      local info = ETYPE[etype] or { name = "unknown" }
      lines[#lines + 1] = string.format("    bit set for etype %-3d %s", etype, info.name)
    end
  else
    lines[#lines + 1] = "PA-SUPPORTED-ENCTYPES was not present in the e-data"
  end
  if #adv.etype_info > 0 then
    lines[#lines + 1] = "PA-ETYPE-INFO2 entries (etype, salt, s2kparams) offered by the realm:"
    for _, info in ipairs(adv.etype_info) do
      lines[#lines + 1] = string.format("    etype %-3d salt=%s s2kparams=%s", info.etype,
        tostring(info.salt or "(none)"), tostring(info.s2kparams and stdnse.tohex(info.s2kparams) or "(none)"))
    end
  end
  if #adv.padata_seen > 0 then
    lines[#lines + 1] = "pre-authentication data types present: " .. table.concat(adv.padata_seen, ", ")
  end
  if adv.fast then
    lines[#lines + 1] = "FAST / encrypted challenge padata is offered (RFC 6113 armour is available)"
  end
  if adv.otp then
    lines[#lines + 1] = "OTP pre-authentication padata is offered (multi-factor policy in force)"
  end
  return lines
end

local function severity_hint_weak(agg)
  if not agg.weakest then
    return false
  end
  return SEVERITY_RANK[agg.weakest.severity] >= SEVERITY_RANK.HIGH
end

function report.build(state, cfg, realm, realm_source, adv, agg, verdicts)
  local out = stdnse.output_table()

  out["Script version"] = SCRIPT_VERSION
  out["Declared risk class"] = SCRIPT_RISK
  out["Realm"] = realm or "undetermined"
  if realm_source then
    out["Realm source"] = realm_source
  end
  out["Principal negotiated against"] = cfg.principal

  local behavior = {}
  for mode in pairs(state.transport_seen) do
    if mode == "udp" then
      behavior[#behavior + 1] = "UDP/88 answered"
    elseif mode == "tcp" then
      behavior[#behavior + 1] = "TCP/88 answered (length-prefixed)"
    end
  end
  table.sort(behavior)
  if #behavior == 0 then
    behavior[#behavior + 1] = "no transport answered"
  end
  out["Transport behaviour"] = behavior
  out["Probes"] = string.format("%d etype probe(s) plus 1 aggregate probe; answers %d, timeouts %d, errors %d",
    #cfg.etypes, state.answers, state.timeouts, state.errors)

  out["Encryption type support matrix"] = report.matrix(verdicts)

  local accepted_names = {}
  for _, etype in ipairs(agg.accepted_numbers) do
    accepted_names[#accepted_names + 1] = string.format("%d %s", etype, (ETYPE[etype] or {}).name or "?")
  end
  out["Accepted etypes"] = #accepted_names > 0 and table.concat(accepted_names, ", ") or "none"
  out["Refused etypes"] = (function()
    local names = {}
    for _, verdict in ipairs(agg.refused) do
      names[#names + 1] = tostring(verdict.etype)
    end
    return #names > 0 and table.concat(names, ", ") or "none"
  end)()
  if #agg.undetermined > 0 then
    local names = {}
    for _, verdict in ipairs(agg.undetermined) do
      names[#names + 1] = string.format("%d (%s)", verdict.etype, tostring(verdict.code_name or "no answer"))
    end
    out["Undetermined etypes"] = table.concat(names, ", ")
  end

  out["Realm advertisement"] = report.advertisement(adv)

  if #agg.findings > 0 then
    local lines = {}
    for _, finding in ipairs(agg.findings) do
      lines[#lines + 1] = string.format("[%s] %s", finding.severity, finding.title)
      lines[#lines + 1] = "    why: " .. finding.detail
      lines[#lines + 1] = "    fix: " .. finding.remediation
    end
    out["Findings"] = lines
  else
    out["Findings"] = "No weak encryption type is negotiable for this principal."
  end

  if agg.weakest then
    local info = ETYPE[agg.weakest.etype] or {}
    local detail = DETAIL[agg.weakest.etype] or {}
    out["Weakest negotiable etype"] = string.format("etype %d (%s), severity %s; %s",
      agg.weakest.etype, info.name or "?", agg.weakest.severity,
      tostring(detail.resistance or info.crack or "no further detail"))
    if agg.strongest then
      out["Strongest negotiable etype"] = string.format("etype %d (%s)",
        agg.strongest, (ETYPE[agg.strongest] or {}).name or "?")
    end
  end

  if #agg.accepted_numbers > 0 then
    out["Offline attack cost by accepted etype (estimates)"] = analysis.cost_table(agg.accepted_numbers)
  end

  local evidence = report.evidence(verdicts)
  if #evidence > 0 then
    out["Probe evidence"] = evidence
  end

  -- Cluster context: what the surrounding environment normally looks like, so
  -- the operator can tell "this realm is behind" from "this realm is broken".
  local context = {}
  for _, entry in ipairs(PLATFORM_POLICY) do
    context[#context + 1] = string.format("%s: defaults %s; %s", entry.platform, entry.default_etypes, entry.guidance)
  end
  out["Platform policy reference"] = context
  out["Probe transcript"] = analysis.transcript(state)
  if severity_hint_weak(agg) then
    out["Cross-realm and trust considerations"] = TRUST_NOTES
  end

  return out
end

function report.verdict(out, agg, state)
  local lines = {}
  local severity = "LOW"

  if state.answers == 0 then
    lines[#lines + 1] = "Not a single probe was answered, so the etype policy could not be measured."
    lines[#lines + 1] = "This is an INCONCLUSIVE result and must not be reported as a clean realm."
    out["Verdict"] = lines
    return "INCONCLUSIVE", severity
  end

  if #agg.accepted == 0 and #agg.undetermined > 0 then
    lines[#lines + 1] = "The KDC answered, but every probe was rejected at the principal stage, so no etype could be classified."
    lines[#lines + 1] = "Run the script against a principal you own with --script-args kerberos.principal=<existing account> for a definitive reading."
    out["Verdict"] = lines
    return "INCONCLUSIVE", severity
  end

  if agg.weakest and SEVERITY_RANK[agg.weakest.severity] >= SEVERITY_RANK.MEDIUM then
    severity = agg.weakest.severity
    local info = ETYPE[agg.weakest.etype] or {}
    lines[#lines + 1] = string.format(
      "The realm negotiates etype %d (%s), which is %s: this makes offline recovery of Kerberos material %s.",
      agg.weakest.etype, info.name or "?", tostring((DETAIL[agg.weakest.etype] or {}).status or "weak"),
      tostring(info.crack or "cheaper than it should be"))
    if agg.strongest and agg.strongest ~= agg.weakest.etype then
      lines[#lines + 1] = string.format(
        "The strongest etype this principal negotiates is %d (%s); the weak entries above are what an attacker will actually choose.",
        agg.strongest, (ETYPE[agg.strongest] or {}).name or "?")
    end
  elseif agg.strongest then
    lines[#lines + 1] = string.format(
      "No weak encryption type is negotiable: the strongest etype accepted is %d (%s), with %d etype(s) accepted in total.",
      agg.strongest, (ETYPE[agg.strongest] or {}).name or "?", #agg.accepted_numbers)
  end

  if not agg.has_aes and #agg.accepted > 0 then
    lines[#lines + 1] = "No AES etype was accepted at all: this realm has never completed the AES migration."
    severity = "CRITICAL"
  elseif agg.has_aes and not agg.has_sha2 then
    lines[#lines + 1] = "AES-SHA1 is available but the RFC 8009 profiles (etype 19/20) are not: the realm is one generation behind."
    if severity == "LOW" then
      severity = "LOW"
    end
  end

  if #agg.undetermined > 0 then
    lines[#lines + 1] = string.format(
      "%d etype(s) could not be classified because the principal was rejected first; the PA-SUPPORTED-ENCTYPES mask and the aggregate probe are the fallback evidence for those.",
      #agg.undetermined)
  end

  lines[#lines + 1] = "The rating is driven by the cheapest attack the realm still allows, not by the strongest cipher it supports."
  out["Verdict"] = lines
  return severity, severity
end

-- ---------------------------------------------------------------------------
-- 12. Action
-- ---------------------------------------------------------------------------

action = function(host, port)
  local cfg = config.load(host)
  local effective_port = port.number

  -- Principal selection. A supplied principal is used verbatim; otherwise a
  -- random synthetic name keeps the probes free of lockout counters, at the
  -- cost of some UNDETERMINED etype answers.
  if not cfg.principal then
    cfg.principal = string.format("nmap-etype-%d", math.random(100000, 999999))
    cfg.principal_is_synthetic = true
  end

  local state = probe.new_state()

  -- Realm resolution.
  local realm = cfg.realm
  local realm_source = realm and "kerberos.realm script argument" or nil
  local leak_record
  if not realm then
    realm, leak_record = realmdisco.leak(host, effective_port, cfg)
    if realm then
      realm_source = "KDC KRB-ERROR KDC_ERR_WRONG_REALM leak"
    end
  end

  if not realm then
    local out = stdnse.output_table()
    out["Script version"] = SCRIPT_VERSION
    out["Declared risk class"] = SCRIPT_RISK
    out["Check status"] = "ABORTED - the Kerberos realm could not be determined"
    out["Why"] = {
      "No kerberos.realm script argument was supplied and the KDC did not leak its realm through KDC_ERR_WRONG_REALM.",
      "Encryption type negotiation is realm scoped: probing the wrong realm would produce answers about the wrong database.",
    }
    out["Remediation"] = {
      "Re-run with --script-args kerberos.realm=YOUR.REALM.",
      "If the KDC sits behind a filter that drops unknown-realm AS-REQs, probe from a segment with KDC reachability.",
    }
    out["Risk Level"] = RISK_LABEL.INCONCLUSIVE
    return out
  end

  -- Probing.
  local observed = probe.run(host, effective_port, cfg, realm, state)

  -- If the aggregate probe revealed a different realm, correct and repeat once.
  local full = state.full_probe
  if full and full.kind == "krb_error" and full.krb_error.code == 68 then
    local leaked = full.krb_error.realm or full.krb_error.crealm
    if leaked and string.upper(leaked) ~= realm then
      realm = string.upper(leaked)
      realm_source = "KDC KRB-ERROR KDC_ERR_WRONG_REALM leak (corrected, probes repeated)"
      state = probe.new_state()
      observed = probe.run(host, effective_port, cfg, realm, state)
      full = state.full_probe
    end
  end

  local adv = analysis.advertisement(full)
  local verdicts = {}
  for _, etype in ipairs(cfg.etypes) do
    local record = observed[etype]
    if record then
      record.etype = etype
      verdicts[#verdicts + 1] = analysis.classify(record, adv)
    end
  end

  local agg = analysis.aggregate(verdicts, adv, state)
  local out = report.build(state, cfg, realm, realm_source, adv, agg, verdicts)
  local severity = report.verdict(out, agg, state)

  if cfg.principal_is_synthetic then
    out["Principal note"] = {
      "The negotiation used a synthetic principal, which keeps the probe free of account lockout counters.",
      "Some etypes may answer KDC_ERR_C_PRINCIPAL_UNKNOWN instead of a definitive etype verdict; those are reported as UNDETERMINED rather than guessed.",
      "For a per-account reading, re-run with --script-args kerberos.principal=<an account you own>.",
    }
  end

  if severity ~= "LOW" then
    local cves = {}
    for _, cve in ipairs(CVE_NOTES) do
      cves[#cves + 1] = string.format("%s (%s) - %s | trigger: %s | fix: %s",
        cve.id, cve.cvss, cve.title, cve.trigger, cve.fix)
    end
    out["Related CVEs"] = cves

    local detection = {}
    for _, line in ipairs(DETECTION.events) do
      detection[#detection + 1] = line
    end
    for _, line in ipairs(DETECTION.kql) do
      detection[#detection + 1] = "KQL: " .. line
    end
    for _, line in ipairs(DETECTION.sigma) do
      detection[#detection + 1] = "Sigma: " .. line
    end
    for _, line in ipairs(DETECTION.network) do
      detection[#detection + 1] = line
    end
    out["Detection guidance"] = detection
    out["Known false positives"] = DETECTION.false_positives

    local steps = {}
    for _, group in ipairs(REMEDIATION) do
      local relevant = false
      for _, finding in ipairs(agg.findings) do
        if string.find(string.lower(finding.title), string.lower(string.match(group.finding, "^[%w%-]+") or "")) then
          relevant = true
        end
      end
      if relevant or group.severity == (agg.weakest and agg.weakest.severity) then
        steps[#steps + 1] = string.format("== %s ==", group.finding)
        for _, step in ipairs(group.steps) do
          steps[#steps + 1] = "  " .. step
        end
      end
    end
    if #steps == 0 then
      for _, group in ipairs(REMEDIATION) do
        steps[#steps + 1] = string.format("== %s ==", group.finding)
        for _, step in ipairs(group.steps) do
          steps[#steps + 1] = "  " .. step
        end
      end
    end
    out["Remediation"] = steps

    local verification = {}
    for _, group in ipairs({ "client_side", "directory_side", "kdc_side", "tooling" }) do
      for _, line in ipairs(VERIFICATION[group]) do
        verification[#verification + 1] = line
      end
    end
    out["Independent verification"] = verification

    out["References"] = {
      "RFC 3961 - Encryption and Checksum Specifications for Kerberos 5",
      "RFC 3962 - Advanced Encryption Standard (AES) Encryption for Kerberos 5",
      "RFC 4757 - The RC4-HMAC Kerberos Encryption Types Used by Microsoft Windows",
      "RFC 8009 - AES Encryption with HMAC-SHA2 for Kerberos 5",
      "Microsoft KB5021131 - How to manage the Kerberos protocol changes related to CVE-2022-37966",
      "Microsoft KB5020805 - How to manage Kerberos protocol changes related to CVE-2022-37967",
      "MITRE ATT&CK T1558 - Steal or Forge Kerberos Tickets",
    }

    vulns.add(host, port, "krb5-weak-encryption-" .. tostring(agg.weakest and agg.weakest.etype or "policy"),
      string.format("Kerberos realm negotiates weak encryption types (weakest accepted: %s)",
        tostring(agg.weakest and agg.weakest.etype or "none classified")))
  end

  out["Risk Level"] = RISK_LABEL[severity] or severity
  return out
end
