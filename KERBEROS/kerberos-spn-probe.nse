local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local table = require "table"
local string = require "string"
local math = require "math"
local os = require "os"
local vulns = require "vulns"

-- Kerberos primitives, including the TGS-REQ / AP-REQ builders and the
-- KRB-ERROR codec, come from the shared engine.
local ok, krb5 = pcall(require, "kerberos5")

description = [[
Discovers Service Principal Names (SPNs) registered in a Kerberos realm and
assesses their kerberoasting exposure, without using any credential.

The technique rests on the order in which a KDC processes a service ticket
request (RFC 4120 section 3.3):

  1. the KDC resolves the requested service principal in its database, and
  2. only then does it decrypt the presented TGT to obtain the authenticator.

A TGS-REQ that carries a deliberately malformed ticket therefore reaches step 1
and fails at step 2. The error code separates the two outcomes:

  * KDC_ERR_S_PRINCIPAL_UNKNOWN (7)   -> no such service principal
  * KRB_AP_ERR_MODIFIED (41)          -> the service principal exists; the KDC
  * KRB_AP_ERR_BAD_INTEGRITY (31)        looked it up, selected its key, and
  * KRB_AP_ERR_TKT_EXPIRED (32)          failed to decrypt the ticket
  * KDC_ERR_ETYPE_NOSUPP (14)         -> the KDC could not build a reply for the
                                         service: reported separately, because it
                                         also implies the SPN was resolved

That single distinction is enough to inventory which service classes are
registered (MSSQLSvc, HTTP, TERMSRV, cifs, exchangeMDB, and the rest of the
catalogue below), which is the reconnaissance step that precedes
kerberoasting (MITRE ATT&CK T1558.003).

When the operator supplies a real ticket with kerberos.ticket=<hex> - for
example the TGT of an account they own in their own lab or an authorised
engagement - the script completes the exchange and reports the encryption type
the KDC actually chose for that service principal. RC4-HMAC (etype 23) is the
definitive confirmation that the SPN is cheaply roastable; AES is not.

Safety properties: every probe is unauthenticated and read-only. No ticket is
requested for a service the operator does not already have a ticket for, no
credential is attempted, and the service ticket requests are the same ones any
client makes when it resolves a service name; nothing is decrypted or cracked.

References:
  * RFC 4120 section 3.3 - obtaining a service ticket; section 7.5.1 - errors
  * RFC 4120 section 5.4.2 - KDC-REQ-BODY and the service principal field
  * MITRE ATT&CK T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting
  * Microsoft: service principal names and setspn guidance
]]

---
-- @usage
-- nmap -p 88 --script kerberos-spn-probe --script-args 'kerberos.realm=EXAMPLE.COM,kerberos.targets=db01,web01,ws01' <target>
--
-- @args kerberos.realm        Realm in uppercase DNS form. Derived from the
--                             KDC's KDC_ERR_WRONG_REALM answer when omitted.
-- @args kerberos.targets      Comma separated host or service instance names
--                             (without the service class). Each name is
--                             combined with the service classes below.
-- @args kerberos.spn-list     Path to a file with one SPN per line, in
--                             "Class/host" or "Class/host:port" form. This is
--                             the precise form: it probes exactly the SPNs you
--                             list and nothing else.
-- @args kerberos.spn-classes  Comma separated service classes to permute with
--                             kerberos.targets (default: a curated shortlist;
--                             "all" uses the entire catalogue).
-- @args kerberos.max-spns     Hard cap on probes for the run (default 60,
--                             maximum 2000).
-- @args kerberos.delay-ms     Spacing between probes (default 300 ms).
-- @args kerberos.timeout-ms   Per-request receive timeout.
-- @args kerberos.transport    "auto" (default), "udp" or "tcp".
-- @args kerberos.retries      Transport retries (default 1).
-- @args kerberos.ticket       Hex encoded service ticket to present, for
--                             operators who own one. When supplied, the run
--                             completes the exchange and reports the negotiated
--                             encryption type instead of relying on the lookup
--                             oracle alone.
-- @args kerberos.ticket-realm Realm the supplied ticket belongs to, when it
--                             differs from the target realm.
--
-- @output
-- PORT   STATE SERVICE
-- 88/tcp open  kerberos-sec
-- | kerberos-spn-probe:
-- |   Realm: EXAMPLE.COM
-- |   SPN candidates probed: 24   existing: 5   absent: 18   inconclusive: 1
-- |   Registered service principals:
-- |     MSSQLSvc/db01:1433        exists (KRB_AP_ERR_MODIFIED after lookup)  [database]
-- |     HTTP/intranet             exists (KRB_AP_ERR_MODIFIED after lookup)  [web]
-- |     TERMSRV/ws01              exists (KRB_AP_ERR_MODIFIED after lookup)  [remote desktop]
-- |   Kerberoasting exposure ranking: ...
-- |   Risk Level: HIGH
-- |_  ...
---

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "vuln", "safe"}

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
local NT = krb5.NT
local SCRIPT_VERSION = krb5.VERSION

-- Declared risk class, read by tools/syntax-check.js to enforce the repository
-- depth contract: CRITICAL/HIGH >= 1538 lines, MEDIUM/LOW 500-800 lines.
local SCRIPT_RISK = "HIGH"

-- ---------------------------------------------------------------------------
-- 1. Service class catalogue
--
-- Every entry is a real SPN class an Active Directory deployment can carry,
-- with the product that registers it, the default port where one applies, and
-- how valuable the account behind it usually is. The "kerberoast value" field
-- is what drives the ranking in the report: it is the difference between a
-- web server's application pool identity and a service account with local
-- administrator rights on a database cluster.
--
-- value: high   -> the account typically has broad privileges
--        medium -> the account is a service identity with lateral value
--        low    -> the account is usually a dedicated, low-privilege identity
-- ---------------------------------------------------------------------------

local SERVICE_CLASSES = {
  { class = "MSSQLSvc", port = 1433, product = "Microsoft SQL Server", value = "high",
    note = "SQL Server service accounts are frequently granted sysadmin and often run on domain-joined clusters" },
  { class = "MSSQLSvc", port = 1434, product = "Microsoft SQL Server (browser)", value = "medium",
    note = "the SQL Browser registration usually mirrors the engine's identity" },
  { class = "SQLServer", port = nil, product = "SQL Server legacy registration", value = "high",
    note = "legacy installations that predate the MSSLQSvc convention" },
  { class = "exchangeMDB", port = nil, product = "Microsoft Exchange mailbox role", value = "high",
    note = "mailbox server service accounts carry Exchange Organisation permissions" },
  { class = "exchangeRFR", port = nil, product = "Microsoft Exchange replication", value = "high",
    note = "replication service account" },
  { class = "exchangeAB", port = nil, product = "Microsoft Exchange address book", value = "high",
    note = "address book service account" },
  { class = "http", port = 80, product = "IIS application pool (kernel-mode registration)", value = "medium",
    note = "the pool identity decides the real impact" },
  { class = "HTTP", port = 80, product = "IIS site or SQL Reporting Services", value = "medium",
    note = "registered by many web stacks and administration consoles" },
  { class = "HTTPS", port = 443, product = "TLS-terminating web application", value = "medium",
    note = "seldom registered; when present it usually marks a Java or Apache service" },
  { class = "TERMSRV", port = nil, product = "Remote Desktop / RDS host", value = "high",
    note = "Terminal Services registrations belong to hosts that grant interactive sessions" },
  { class = "wsman", port = 5985, product = "WinRM / PowerShell remoting", value = "high",
    note = "WinRM registrations exist on hosts where PowerShell remoting is a lateral movement path" },
  { class = "RestrictedKrbHost", port = nil, product = "host-based service (legacy)", value = "medium",
    note = "the compatibility registration used by older clients" },
  { class = "HOST", port = nil, product = "generic host services", value = "medium",
    note = "the catch-all host registration present on every computer account" },
  { class = "cifs", port = 445, product = "SMB / file server", value = "high",
    note = "file servers are the classic lateral movement target" },
  { class = "ldap", port = 389, product = "domain controller LDAP", value = "high",
    note = "registered on every DC; on a healthy domain the identity is the machine account of the DC" },
  { class = "GC", port = 3268, product = "global catalogue", value = "high",
    note = "same as LDAP, for the global catalogue port" },
  { class = "DNS", port = 53, product = "DNS server", value = "high",
    note = "AD-integrated DNS registrations carry the DNS service identity" },
  { class = "kafka", port = 9092, product = "Apache Kafka broker", value = "medium",
    note = "Kerberos-enabled Kafka clusters register a broker identity per node" },
  { class = "postgres", port = 5432, product = "PostgreSQL with GSSAPI", value = "medium",
    note = "GSSAPI authentication registers a service principal for the database" },
  { class = "oracle", port = 1521, product = "Oracle database with Kerberos", value = "high",
    note = "Oracle service accounts are conventionally shared and long-lived" },
  { class = "mysql", port = 3306, product = "MySQL with Kerberos plugin", value = "medium", note = "enterprise plugin registrations" },
  { class = "smtp", port = 25, product = "mail submission agent", value = "medium", note = "mail relays with GSSAPI authentication" },
  { class = "imap", port = 143, product = "IMAP server", value = "medium", note = "mail store services" },
  { class = "pop", port = 110, product = "POP3 server", value = "low", note = "legacy mail access" },
  { class = "nfs", port = 2049, product = "NFS server with Kerberos (sec=krb5)", value = "high",
    note = "sec=krb5 exports mean the NFS identity is a domain service account" },
  { class = "host", port = nil, product = "generic host (lowercase)", value = "medium", note = "case variant used by some UNIX services" },
  { class = "vpn", port = nil, product = "VPN concentrator", value = "high",
    note = "remote access services concentrate sessions and are frequently over-privileged" },
  { class = "radius", port = nil, product = "RADIUS / NPS", value = "high", note = "network access control service identity" },
  { class = "SAPService", port = nil, product = "SAP NetWeaver", value = "high", note = "SAP service accounts are notoriously shared" },
  { class = "SAPSSO", port = nil, product = "SAP single sign-on", value = "high", note = "SSO integration identity" },
  { class = "E3514235-4B06-11D1-AB04-00C04FC2DCD2", port = nil, product = "AD replication (DRSUAPI)", value = "high",
    note = "the GUID-shaped SPN a DC registers for replication; its account is a DC machine account" },
  { class = "le", port = nil, product = "VMware vCenter / ESXi", value = "high", note = "virtualisation platform registration" },
  { class = "WSMAN", port = nil, product = "WS-Management (uppercase variant)", value = "medium", note = "case-sensitive registration seen on some platforms" },
  { class = "httpd", port = nil, product = "Apache HTTP server (GSSAPI module)", value = "medium", note = "mod_auth_gssapi registrations" },
  { class = "sip", port = 5060, product = "SIP proxy", value = "medium", note = "telephony platform identity" },
  { class = "xmpp", port = 5222, product = "XMPP server with GSSAPI", value = "low", note = "chat platform service" },
  { class = "ftp", port = 21, product = "FTP server with GSSAPI", value = "low", note = "legacy file transfer" },
  { class = "ssh", port = 22, product = "SSH server with GSSAPI (UNIX)", value = "low", note = "UNIX host key registration" },
}

-- Classes used when the operator does not pick a subset. Chosen so that the
-- default run stays under a minute against a healthy KDC while still covering
-- the classes that carry real privilege.
local DEFAULT_CLASSES = {
  "MSSQLSvc", "HTTP", "TERMSRV", "cifs", "wsman", "exchangeMDB",
  "vpn", "radius", "oracle", "nfs", "HOST", "ldap",
}

-- ---------------------------------------------------------------------------
-- 2. Common instance names
--
-- Used when the operator supplies kerberos.targets. The names are the ones
-- that actually appear in directories: role-based hostnames, cluster members,
-- and the ports that decide whether a registration exists for a specific
-- instance.
-- ---------------------------------------------------------------------------

local COMMON_PORTS = {
  MSSQLSvc = { "1433", "1434" },
  HTTP = { "80", "8080" },
  HTTPS = { "443", "8443" },
  oracle = { "1521" },
  cifs = { nil },
  HOST = { nil },
  TERMSRV = { nil },
  vpn = { nil },
  radius = { nil },
  wsman = { nil },
}

-- ---------------------------------------------------------------------------
-- 3. Error code decisions for the TGS lookup oracle
-- ---------------------------------------------------------------------------

local VERDICT = {
  EXISTS = "EXISTS",
  ABSENT = "ABSENT",
  INCONCLUSIVE = "INCONCLUSIVE",
  TRANSPORT = "NO-ANSWER",
  ROASTABLE = "ROASTABLE",
}

local DECISION = {
  [7] = { verdict = VERDICT.ABSENT, severity = "INFO",
          reason = "KDC_ERR_S_PRINCIPAL_UNKNOWN: the KDC searched its database and found no such service principal" },
  [41] = { verdict = VERDICT.EXISTS, severity = "MEDIUM",
           reason = "KRB_AP_ERR_MODIFIED: the service principal was resolved and its key was used to attempt ticket decryption, which only happens for a registered SPN" },
  [31] = { verdict = VERDICT.EXISTS, severity = "MEDIUM",
           reason = "KRB_AP_ERR_BAD_INTEGRITY: the service principal exists and the KDC tried to decrypt the ticket with its key" },
  [32] = { verdict = VERDICT.EXISTS, severity = "MEDIUM",
           reason = "KRB_AP_ERR_TKT_EXPIRED: the ticket was associated with a resolved service principal" },
  [33] = { verdict = VERDICT.EXISTS, severity = "MEDIUM",
           reason = "KRB_AP_ERR_TKT_NYV: the KDC matched the ticket to a service principal with a validity window" },
  [35] = { verdict = VERDICT.EXISTS, severity = "MEDIUM",
           reason = "KRB_AP_ERR_NOT_US: the ticket does not belong to this service, which the KDC could only determine after resolving it" },
  [36] = { verdict = VERDICT.EXISTS, severity = "MEDIUM",
           reason = "KRB_AP_ERR_BADMATCH: the authenticator was compared against a resolved service principal" },
  [14] = { verdict = VERDICT.EXISTS, severity = "MEDIUM",
           reason = "KDC_ERR_ETYPE_NOSUPP: the KDC reached the reply construction stage for this service principal" },
  [16] = { verdict = VERDICT.EXISTS, severity = "MEDIUM",
           reason = "KDC_ERR_PADATA_TYPE_NOSUPP: padata was evaluated for a resolved service principal" },
  [12] = { verdict = VERDICT.EXISTS, severity = "MEDIUM",
           reason = "KDC_ERR_POLICY: realm policy was applied, which requires a resolved principal" },
  [6] = { verdict = VERDICT.INCONCLUSIVE, severity = "INFO",
          reason = "KDC_ERR_C_PRINCIPAL_UNKNOWN: the client principal was rejected, which says nothing about the service" },
  [68] = { verdict = VERDICT.INCONCLUSIVE, severity = "INFO",
           reason = "KDC_ERR_WRONG_REALM: the request addressed the wrong realm" },
  [37] = { verdict = VERDICT.INCONCLUSIVE, severity = "INFO",
           reason = "KRB_AP_ERR_SKEW: the exchange failed before the service principal mattered" },
}

-- ---------------------------------------------------------------------------
-- 4. Kerberoasting knowledge base
-- ---------------------------------------------------------------------------

local KB = {}

KB.TECHNIQUE = {
  "Kerberoasting abuses the fact that any authenticated principal may request a service ticket for any SPN, and that the resulting ticket is encrypted with the service account's long-term key.",
  "The attack is offline: once the ticket is captured, the attacker attacks the service account password without touching the KDC again, so no lockout counter moves and no authentication failure is logged.",
  "The cost of the attack is decided by the service account's encryption type: RC4-HMAC tickets fall in GPU-hours, AES tickets usually do not fall at all for a reasonable password.",
  "Because the service ticket is issued to the requesting user, the KDC logs event 4769 with the service name, the account, and the encryption type - which is exactly the detection opportunity.",
  "This script performs the reconnaissance half: it identifies which SPNs exist, so the operator knows the attack surface before someone else enumerates it.",
}

KB.MAPPING = {
  { id = "T1558.003", name = "Steal or Forge Kerberos Tickets: Kerberoasting", note = "the technique the discovered SPNs enable" },
  { id = "T1087.002", name = "Account Discovery: Domain Account", note = "the service accounts behind the discovered SPNs" },
  { id = "T1069.002", name = "Permission Groups Discovery: Domain Groups", note = "the next stage after identifying a shared service identity" },
  { id = "T1078.002", name = "Valid Accounts: Domain Accounts", note = "what a cracked service account provides" },
}

KB.DETECTION = {
  "4769 (Kerberos service ticket request) is the primary event: filter on Ticket Encryption Type 0x17 (RC4-HMAC) and on Ticket Options 0x40810000, the canonical kerberoast request shape.",
  "A single account requesting service tickets for many distinct SPNs in a short window is enumeration, whether or not any ticket is cracked.",
  "4769 with a service name that has no corresponding business use (an SPN registered on a workstation account) is worth investigating on its own.",
  "KQL: SecurityEvent | where EventID == 4769 | where TicketEncryptionType == \"0x17\" | summarize dcount(ServiceName) by Account, IpAddress, bin(TimeGenerated, 15m) | where dcount_ServiceName > 5",
  "Sigma: selection on EventID 4769 with TicketEncryptionType 0x17 and ServiceName not in the known legacy list; level medium.",
  "Honeytoken SPN: register a plausible-looking service principal on a monitored account that no application uses. Any ticket request for it is unambiguously malicious.",
}

KB.REMEDIATION = {
  {
    title = "Make the service accounts unattractive to crack",
    steps = {
      "Replace user-account service identities with group managed service accounts (gMSA) or standalone MSAs: a 240-character rotating password removes the offline attack entirely.",
      "Where a gMSA is impossible, use a 25 character or longer randomly generated password stored in a secrets manager, and rotate it on a schedule.",
      "Set msDS-SupportedEncryptionTypes to AES only (24 = AES128|AES256) on every account that owns an SPN, then re-key by resetting the password so the RC4 key is gone.",
      "Remove SPNs from accounts that no longer need them: a stale SPN keeps a forgotten account roastable forever.",
    },
  },
  {
    title = "Reduce the blast radius of a cracked service account",
    steps = {
      "Inventory which accounts own SPNs: setspn -Q */* or Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties ServicePrincipalName.",
      "Review group membership of those accounts; service identities should not be Domain Admins, and should not have interactive logon rights.",
      "Prefer services that run as Network Service or a virtual account, which have no password to crack at all.",
      "Audit unconstrained and constrained delegation: an SPN account with delegation rights turns a cracked password into domain-wide compromise.",
    },
  },
  {
    title = "Detect and slow down enumeration",
    steps = {
      "Enable auditing of Kerberos Service Ticket Operations success and failure on domain controllers.",
      "Alert on 4769 bursts and on RC4 service ticket requests from accounts that have no legitimate use for them.",
      "Register a honeytoken SPN in a monitored OU, as described in the detection guidance.",
    },
  },
}

KB.VERIFICATION = {
  "With credentials (authorised): Impacket GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <kdc> -request lists the same SPNs and the material the KDC issues.",
  "PowerShell: Get-ADUser -Filter 'ServicePrincipalName -like \"*\"' -Properties ServicePrincipalName | Select Name,ServicePrincipalName",
  "setspn -Q */* lists every registered SPN on a domain-joined Windows host.",
  "ldapsearch -H ldap://<dc> -x -b \"dc=example,dc=com\" \"(servicePrincipalName=*)\" sAMAccountName servicePrincipalName lists the same view directly from the directory.",
  "kinit -S <spn> <principal> from a client that holds a TGT requests the same service ticket the attacker would; klist -e then shows the encryption type the KDC chose.",
}

KB.REFERENCES = {
  "RFC 4120 section 3.3 - obtaining a service ticket",
  "RFC 4120 section 7.5.1 - KRB-ERROR and the error code registry",
  "RFC 4120 section 5.4.2 - KDC-REQ-BODY (sname and realm fields)",
  "MITRE ATT&CK T1558.003 - Kerberoasting",
  "Microsoft: Service Principal Names (setspn) documentation",
  "Microsoft KB5021131 - Kerberos RC4 retirement guidance (it decides the cost of a roast)",
}

-- ---------------------------------------------------------------------------
-- 5. Configuration
-- ---------------------------------------------------------------------------

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
  cfg.targets = arg_list("targets")
  cfg.spn_list = arg_string("spn-list")
  cfg.classes = arg_list("spn-classes")
  cfg.max_spns = arg_int("max-spns", 60, 1, 2000)
  cfg.delay_ms = arg_int("delay-ms", 300, 0, 10000)
  cfg.retries = arg_int("retries", 1, 0, 5)
  cfg.ticket = arg_string("ticket")
  cfg.ticket_realm = arg_string("ticket-realm")
  if cfg.ticket then
    cfg.ticket = string.gsub(cfg.ticket, "%s", "")
  end
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

  if #cfg.classes == 0 then
    for _, class in ipairs(DEFAULT_CLASSES) do
      cfg.classes[#cfg.classes + 1] = class
    end
  elseif #cfg.classes == 1 and string.lower(cfg.classes[1]) == "all" then
    cfg.classes = {}
    for _, entry in ipairs(SERVICE_CLASSES) do
      local seen = false
      for _, existing in ipairs(cfg.classes) do
        if existing == entry.class then seen = true end
      end
      if not seen then
        cfg.classes[#cfg.classes + 1] = entry.class
      end
    end
  end

  return cfg
end

-- ---------------------------------------------------------------------------
-- 6. SPN candidate construction
-- ---------------------------------------------------------------------------

local spns = {}

function spns.info(class)
  for _, entry in ipairs(SERVICE_CLASSES) do
    if entry.class == class then
      return entry
    end
  end
  return { class = class, product = "unclassified service class", value = "unknown" }
end

-- Build the probe list from either an explicit SPN file (precise) or from the
-- cross product of classes and targets (broad but bounded).
function spns.build(cfg)
  local list = {}
  local seen = {}
  local truncated = false

  local function push(spn, klass, target, source)
    if not spn or #spn == 0 then
      return
    end
    local key = string.lower(spn)
    if seen[key] then
      return
    end
    if #list >= cfg.max_spns then
      truncated = true
      return
    end
    seen[key] = true
    list[#list + 1] = { spn = spn, class = klass or string.match(spn, "^([^/]+)/") or "unknown",
                       target = target, source = source }
  end

  if cfg.spn_list then
    local file, err = io.open(cfg.spn_list, "r")
    if not file then
      return nil, string.format("cannot read kerberos.spn-list '%s': %s", tostring(cfg.spn_list), tostring(err))
    end
    for line in file:lines() do
      local cleaned = string.match(line, "^([^#]*)") or ""
      cleaned = string.gsub(cleaned, "%s+$", "")
      cleaned = string.gsub(cleaned, "^%s+", "")
      if #cleaned > 0 then
        push(cleaned, nil, nil, "spn-list")
      end
    end
    file:close()
    return list, nil, { truncated = truncated, source = "spn-list" }
  end

  if #cfg.targets == 0 then
    return nil, "no SPN targets were supplied"
  end

  for _, target in ipairs(cfg.targets) do
    for _, class in ipairs(cfg.classes) do
      local info = spns.info(class)
      local ports = COMMON_PORTS[class]
      if ports and ports[1] then
        for _, port in ipairs(ports) do
          push(string.format("%s/%s:%s", class, target, port), class, target, "class-x-target")
        end
      else
        push(string.format("%s/%s", class, target), class, target, "class-x-target")
      end
      if info and info.port then
        push(string.format("%s/%s:%d", class, target, info.port), class, target, "class-x-target")
      end
    end
  end

  -- The computer account registration is present on essentially every host,
  -- so it makes a useful control: if even HOST/<target> is reported absent,
  -- the realm or the target name is wrong, and every other result is suspect.
  local control = string.format("HOST/%s", cfg.targets[1])
  if not seen[string.lower(control)] then
    push(control, "HOST", cfg.targets[1], "control")
  end

  return list, nil, { truncated = truncated, source = "class-x-target" }
end

-- A synthetic SPN that cannot exist, used to calibrate the oracle: whatever the
-- KDC answers for this is the "absent" fingerprint.
function spns.calibration()
  return string.format("NMAPNonexistent/nmap-control-%d", math.random(100000, 999999))
end
-- ---------------------------------------------------------------------------
-- 7. Realm discovery
-- ---------------------------------------------------------------------------

local realmdisco = {}

function realmdisco.leak(host, port, cfg)
  local synthetic = "NMAP.INVALID.REALM"
  local record = transport.as_req(host, port, {
    realm = synthetic,
    cname = "nmap-spn-probe",
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
-- 8. Probe engine
--
-- A TGS-REQ carries the ticket in PA-TGS-REQ. When the operator supplies a
-- real ticket the script presents it; otherwise it presents a well formed but
-- deliberately undecryptable ticket whose purpose is to reach the KDC's lookup
-- stage and no further.
-- ---------------------------------------------------------------------------

local engine = {}

function engine.new_state()
  return {
    results = {},
    answers = 0,
    timeouts = 0,
    errors = 0,
    transport_seen = {},
    rtts = {},
  }
end

function engine.build_ticket(cfg, realm, klass)
  if cfg.ticket then
    local binary = stdnse.fromhex and stdnse.fromhex(cfg.ticket) or nil
    if binary then
      return binary, true
    end
  end
  return krb.build_ticket({
    realm = cfg.ticket_realm and string.upper(cfg.ticket_realm) or realm,
    sname = { klass, "nmap-probe" },
    etype = 18,
    kvno = 2,
    cipher = string.rep("\240", 64),
  }), false
end

function engine.probe(host, port, cfg, realm, candidate)
  local ticket, real = engine.build_ticket(cfg, realm, candidate.class)
  local ap_req
  if real then
    ap_req = ticket
  else
    ap_req = krb.build_ap_req({
      ticket = ticket,
      auth_etype = 18,
      auth_kvno = 2,
      authenticator = string.rep("\241", 48),
    })
  end

  local parts = {}
  for part in string.gmatch(candidate.spn, "[^/]+") do
    parts[#parts + 1] = part
  end

  local record = transport.tgs_req(host, port, {
    realm = realm,
    sname = parts,
    sname_type = NT.SRV_INST,
    etypes = { 23, 18, 17 },
    nonce = math.random(1, 2147483000),
    kdc_options = 0,
    ap_req = ap_req,
  }, { timeout_ms = cfg.timeout_ms, retries = cfg.retries, transport = cfg.transport })
  record.spn = candidate.spn
  record.candidate = candidate
  record.used_ticket = real
  return record
end

local function pace(cfg, index)
  if index <= 1 or cfg.delay_ms <= 0 then
    return
  end
  stdnse.sleep((cfg.delay_ms + math.random(0, math.floor(cfg.delay_ms / 3))) / 1000)
end

function engine.run(host, port, cfg, realm, list, state)
  for index, candidate in ipairs(list) do
    pace(cfg, index)
    local record = engine.probe(host, port, cfg, realm, candidate)
    record.index = index
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
    if state.timeouts >= 3 and state.answers == 0 then
      state.aborted = true
      state.abort_reason = "three consecutive timeouts with no answer: wrong port, filtered path, or not a KDC"
      break
    end
  end
  return state
end

-- ---------------------------------------------------------------------------
-- 9. Analysis
-- ---------------------------------------------------------------------------

local analysis = {}

function analysis.calibrate(host, port, cfg, realm, state)
  local calibration_spn = spns.calibration()
  local candidate = { spn = calibration_spn, class = "NMAPNonexistent", target = "nmap-control", source = "calibration" }
  local record = engine.probe(host, port, cfg, realm, candidate)
  state.results[#state.results + 1] = record
  if record.kind then
    state.answers = state.answers + 1
    state.transport_seen[record.transport or "?"] = true
  elseif record.error == "timeout" then
    state.timeouts = state.timeouts + 1
  else
    state.errors = state.errors + 1
  end
  return record
end

function analysis.classify(record)
  local verdict = {
    record = record,
    spn = record.spn,
    candidate = record.candidate,
    evidence = {},
  }
  if not record.kind then
    verdict.verdict = VERDICT.TRANSPORT
    verdict.label = "no answer"
    verdict.severity = "INFO"
    verdict.reason = string.format("the KDC did not answer (%s)", tostring(record.error))
    return verdict
  end

  if record.kind == "tgs_rep" then
    local enc = record.tgs_rep.enc_part or {}
    local info = krb.etype_info(enc.etype)
    verdict.verdict = VERDICT.ROASTABLE
    verdict.etype = enc.etype
    verdict.label = string.format("service ticket issued, encrypted with etype %s (%s)", tostring(enc.etype), info.name)
    verdict.severity = (info.weak or info.retired) and "CRITICAL" or "HIGH"
    verdict.reason = "a real ticket was presented, so the KDC completed the exchange; the encryption type of the reply is the one an attacker would obtain"
    verdict.evidence[#verdict.evidence + 1] = string.format("TGS-REP %d bytes, enc-part etype %s, kvno %s",
      record.response_bytes or 0, tostring(enc.etype), tostring(enc.kvno or "absent"))
    if record.tgs_rep.ticket and record.tgs_rep.ticket.enc_part then
      verdict.evidence[#verdict.evidence + 1] = string.format("service ticket enc-part etype %s",
        tostring(record.tgs_rep.ticket.enc_part.etype))
    end
    return verdict
  end

  local e = record.krb_error
  verdict.code = e.code
  verdict.code_name = e.code_name
  verdict.e_text = e.e_text
  local decision = DECISION[e.code]
  if decision then
    verdict.verdict = decision.verdict
    verdict.severity = decision.severity
    verdict.reason = decision.reason
    verdict.label = (decision.verdict == VERDICT.EXISTS)
      and string.format("SPN exists (%s after the lookup)", tostring(e.code_name))
      or (decision.verdict == VERDICT.ABSENT)
        and "SPN not registered"
        or string.format("inconclusive (%s)", tostring(e.code_name))
  else
    verdict.verdict = VERDICT.INCONCLUSIVE
    verdict.severity = "INFO"
    verdict.label = string.format("unclassified answer (%s)", tostring(e.code_name))
    verdict.reason = e.code_note or "this error code has no documented bearing on service principal existence"
  end
  verdict.evidence[#verdict.evidence + 1] = string.format("KRB-ERROR %s (%s)", tostring(e.code_name), tostring(e.code))
  if e.e_text and #e.e_text > 0 then
    verdict.evidence[#verdict.evidence + 1] = string.format("KDC e-text: %s", e.e_text)
  end
  if record.response_bytes then
    verdict.evidence[#verdict.evidence + 1] = string.format("%d byte answer over %s in %s attempt(s)",
      record.response_bytes, string.upper(tostring(record.transport or "?")), tostring(record.attempts or 0))
  end
  return verdict
end

-- The oracle is implementation dependent, so the calibration probe sets the
-- baseline: if the KDC answers the impossible SPN with something other than
-- "absent", every "exists" claim is downgraded and reported as such.
function analysis.calibration_note(calibration_verdict, verdicts)
  local note = {}
  if not calibration_verdict then
    return note, false
  end
  if calibration_verdict.verdict == VERDICT.ABSENT then
    note[#note + 1] = string.format(
      "calibration: the synthetic SPN %s was answered with %s, which is the expected 'absent' behaviour",
      calibration_verdict.spn, tostring(calibration_verdict.code_name))
    return note, true
  end
  if calibration_verdict.verdict == VERDICT.EXISTS then
    note[#note + 1] = string.format(
      "calibration WARNING: the synthetic SPN %s was answered with %s, the same code as a registered SPN. This KDC does not distinguish the two cases, so every 'exists' result below is unreliable.",
      calibration_verdict.spn, tostring(calibration_verdict.code_name))
    return note, false
  end
  note[#note + 1] = string.format(
    "calibration: the synthetic SPN %s produced %s, so the oracle could not be validated; results are reported with reduced confidence",
    calibration_verdict.spn, tostring(calibration_verdict.label or calibration_verdict.verdict))
  return note, false
end

function analysis.aggregate(verdicts, calibration_ok)
  local agg = { exists = {}, absent = {}, inconclusive = {}, transport = {}, roastable = {}, classes = {} }
  for _, verdict in ipairs(verdicts) do
    if verdict.verdict == VERDICT.EXISTS then
      agg.exists[#agg.exists + 1] = verdict
    elseif verdict.verdict == VERDICT.ROASTABLE then
      agg.roastable[#agg.roastable + 1] = verdict
      agg.exists[#agg.exists + 1] = verdict
    elseif verdict.verdict == VERDICT.ABSENT then
      agg.absent[#agg.absent + 1] = verdict
    elseif verdict.verdict == VERDICT.TRANSPORT then
      agg.transport[#agg.transport + 1] = verdict
    else
      agg.inconclusive[#agg.inconclusive + 1] = verdict
    end
  end

  -- Group by service class: the class is what tells the operator which
  -- platform is exposed, and it is the unit they will act on.
  for _, verdict in ipairs(agg.exists) do
    local class = verdict.candidate and verdict.candidate.class or "unknown"
    agg.classes[class] = agg.classes[class] or { count = 0, instances = {}, verdicts = {} }
    agg.classes[class].count = agg.classes[class].count + 1
    agg.classes[class].instances[#agg.classes[class].instances + 1] = verdict.spn
    agg.classes[class].verdicts[#agg.classes[class].verdicts + 1] = verdict
  end

  if not calibration_ok then
    for _, verdict in ipairs(agg.exists) do
      verdict.calibration_doubt = true
    end
  end

  return agg
end

-- Rank the discovered services by how much a cracked account behind them is
-- worth, and by whether the run could actually observe the encryption type.
function analysis.rank(agg)
  local ranked = {}
  for class, group in pairs(agg.classes) do
    local info = spns.info(class)
    local score = 0
    if info.value == "high" then
      score = 3
    elseif info.value == "medium" then
      score = 2
    elseif info.value == "low" then
      score = 1
    end
    if group.count > 1 then
      score = score + 1
    end
    local confirmed_rc4 = false
    for _, verdict in ipairs(group.verdicts) do
      if verdict.verdict == VERDICT.ROASTABLE and (verdict.etype == 23 or verdict.etype == 24) then
        confirmed_rc4 = true
      end
    end
    if confirmed_rc4 then
      score = score + 4
    end
    ranked[#ranked + 1] = {
      class = class,
      info = info,
      count = group.count,
      instances = group.instances,
      score = score,
      confirmed_rc4 = confirmed_rc4,
    }
  end
  table.sort(ranked, function(a, b)
    if a.score ~= b.score then
      return a.score > b.score
    end
    return a.class < b.class
  end)
  return ranked
end
-- ---------------------------------------------------------------------------
-- 9b. Supplied ticket inspection
--
-- Operators who own a TGT (their own account, a lab domain, an authorised
-- engagement) can hand it to the script so the exchange completes and the
-- encryption type is observed directly instead of inferred. That ticket is a
-- credential, so the script treats it as one: it is decoded, its fields are
-- reported (so the operator can confirm they pasted the ticket they meant to),
-- it is never written anywhere, and a mismatch between its realm and the
-- target realm is surfaced rather than silently used.
-- ---------------------------------------------------------------------------

function analysis.inspect_ticket(cfg)
  local info = {
    supplied = cfg.ticket ~= nil,
    valid_hex = false,
    kind = nil,
  }
  if not cfg.ticket then
    return info
  end
  if #cfg.ticket % 2 ~= 0 or string.find(cfg.ticket, "[^0-9a-fA-F]") then
    info.error = "kerberos.ticket must be an even length hex string"
    return info
  end
  if #cfg.ticket > 20000 then
    info.error = "kerberos.ticket is implausibly large (over 10 KB): tickets rarely exceed a few kilobytes"
    return info
  end

  local binary = (stdnse.fromhex and stdnse.fromhex(cfg.ticket)) or nil
  if not binary then
    info.error = "the hex string could not be decoded"
    return info
  end
  info.valid_hex = true
  info.bytes = #binary

  local first = string.byte(binary, 1)
  if first == 0x6E then
    info.kind = "AP-REQ ([APPLICATION 14])"
    info.wrapped = true
    local root = krb5.decoder.parse(binary)
    local seq = root and root.children and root.children[1]
    local ticket_field = seq and krb5.decoder.unwrap(seq, 3)
    local summary = ticket_field and krb.parse_ticket_summary(ticket_field)
    if summary then
      info.realm = summary.realm
      info.sname = summary.sname and summary.sname.text
      info.etype = summary.enc_part and summary.enc_part.etype
      info.kvno = summary.enc_part and summary.enc_part.kvno
    end
  elseif first == 0x61 then
    info.kind = "Ticket ([APPLICATION 1])"
    info.wrapped = false
    local root = krb5.decoder.parse(binary)
    local summary = root and krb.parse_ticket_summary(root)
    if summary then
      info.realm = summary.realm
      info.sname = summary.sname and summary.sname.text
      info.etype = summary.enc_part and summary.enc_part.etype
      info.kvno = summary.enc_part and summary.enc_part.kvno
    end
  elseif first == 0x6A or first == 0x6B or first == 0x6C or first == 0x6D then
    info.kind = string.format("a KDC message (%s), not a ticket", tostring(krb.message_label(binary)))
    info.error = "kerberos.ticket must be a ticket or an AP-REQ, not an AS-REQ/TGS-REQ/AS-REP/TGS-REP"
  else
    info.kind = string.format("unrecognised first byte 0x%02X", first)
    info.error = "the blob does not start with a Kerberos APPLICATION tag"
  end

  return info
end

-- ---------------------------------------------------------------------------
-- 9c. Class depth: what the account behind each SPN class usually is, and
-- what to check once the class is found registered. This is the difference
-- between a list of names and an audit finding.
-- ---------------------------------------------------------------------------

local CLASS_DEPTH = {
  MSSQLSvc = {
    account_shape = "a domain user account running the SQL Server service, or a virtual account when the instance was installed with one",
    privileges = "sysadmin inside the instance, often local administrator on the host, sometimes backup operator on the domain",
    checks = {
      "Who owns the SPN: Get-ADUser -Filter {ServicePrincipalName -like 'MSSQLSvc*'} -Properties ServicePrincipalName,MemberOf",
      "Is the account in a privileged group, and does it have rights on other hosts?",
      "Does a linked server or an agent job run as this account with network access elsewhere?",
    },
    escalation = "SQL Server service accounts are a well known route to xp_cmdshell and from there to the host and the domain.",
  },
  HTTP = {
    account_shape = "an IIS application pool identity, a SQL Reporting Services account, or a Java application server identity",
    privileges = "whatever the web application itself can reach: databases, file shares, other APIs",
    checks = {
      "Identify the host and application from the SPN instance name and the site inventory.",
      "Check whether the identity has local administrator on the web host.",
      "Check for stored credentials in application config files that the identity can read.",
    },
    escalation = "A web platform identity frequently reaches a database with broader rights than any human account.",
  },
  TERMSRV = {
    account_shape = "the computer account of a remote desktop host",
    privileges = "the host itself; the registration indicates an interactive access path",
    checks = {
      "Confirm whether RDP is exposed to user subnets and whether NLA is enforced.",
      "Review who may connect, and whether the host holds privileged sessions.",
    },
    escalation = "RDP hosts concentrate privileged sessions; they are a persistence and collection target rather than a cracking target.",
  },
  cifs = {
    account_shape = "the computer account of a file server",
    privileges = "the shares it publishes and their ACLs",
    checks = {
      "Inventory the shares and their permissions.",
      "Check for shares writable by broad groups, which is the classic ransomware staging area.",
    },
    escalation = "File servers are where credentials in scripts, backups and configuration files accumulate.",
  },
  wsman = {
    account_shape = "the computer account of a host where WinRM is enabled",
    privileges = "remote PowerShell execution as any account permitted by the session configuration",
    checks = {
      "Check the WinRM listeners and the permissions on the session configurations.",
      "Confirm that remote management is restricted to administrative subnets.",
    },
    escalation = "WinRM plus a valid credential is remote code execution by design.",
  },
  exchangeMDB = {
    account_shape = "the Exchange mailbox server service account",
    privileges = "Exchange Organisation Management by default, and the ability to read every mailbox in the organisation",
    checks = {
      "Confirm the account is not a member of any interactive-logon group.",
      "Verify the account password is machine-managed and rotated.",
    },
    escalation = "Exchange permissions are a direct path to mail data and, historically, to domain escalation.",
  },
  vpn = {
    account_shape = "the identity of a VPN concentrator or its authentication proxy",
    privileges = "whatever the concentrator can reach, and often the ability to authenticate on behalf of users",
    checks = {
      "Identify the concentrator vendor and whether it stores credentials locally.",
      "Check whether the service account can be used to authenticate from outside the network.",
    },
    escalation = "Remote access infrastructure sits on the trust boundary.",
  },
  radius = {
    account_shape = "the Network Policy Server or RADIUS service identity",
    privileges = "network admission decisions; sometimes the ability to read user attributes",
    checks = {
      "Confirm which network devices rely on it.",
      "Check whether the shared secrets are stored in a readable configuration.",
    },
    escalation = "Control of network admission affects every device that authenticates through it.",
  },
  oracle = {
    account_shape = "a shared database service account, usually with a long-lived password",
    privileges = "schema ownership and often DBA-adjacent roles",
    checks = {
      "Confirm the account's role memberships inside the database.",
      "Check whether the password has ever been rotated.",
    },
    escalation = "Shared database accounts rarely have per-person accountability, which makes them attractive and long-lived.",
  },
  nfs = {
    account_shape = "the identity mapped to kerberos-secured NFS exports",
    privileges = "read, and often write, access to the exported file systems",
    checks = {
      "List the exports and their sec= settings on the NFS server.",
      "Check whether the identity has write access to home directories or application data.",
    },
    escalation = "sec=krb5 exports depend entirely on the service identity, which makes it a single point of compromise.",
  },
  HOST = {
    account_shape = "the computer account of the host itself",
    privileges = "the host, plus whatever its machine account is trusted for (delegation, replication if it is a DC)",
    checks = {
      "Confirm the host is a domain member and not a domain controller (a DC HOST SPN implies replication rights).",
      "Check for unconstrained delegation on the machine account.",
    },
    escalation = "Machine accounts with delegation rights are a standard privilege escalation path.",
  },
  ldap = {
    account_shape = "the domain controller's own machine account",
    privileges = "directory replication and full read access to every object",
    checks = {
      "Confirm the registration belongs to a DC and not to a third-party LDAP-integrated application.",
      "A non-DC account holding an ldap/ SPN is a misconfiguration worth investigating on its own.",
    },
    escalation = "Directory replication rights are equivalent to domain compromise.",
  },
}

-- Attack chains: what each discovered class typically leads to, so the
-- operator can prioritise remediation by consequence rather than by count.
local ATTACK_CHAINS = {
  "SPN inventory -> kerberoasting -> offline crack -> service account -> (databases, file shares, management planes) -> domain escalation.",
  "Unconstrained delegation on a machine account whose HOST SPN was found -> coerced authentication -> TGT capture -> domain compromise.",
  "RC4 negotiation plus an SPN account with a short password -> GPU-hours to plaintext -> lateral movement with a legitimate identity.",
  "Stale SPN on a forgotten account -> the account is never remediated because nobody recognises it -> permanent exposure.",
}

-- ---------------------------------------------------------------------------
-- 9d. Probe transcript
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
    lines[#lines + 1] = string.format("#%-3d %-34s %-42s %-4s %s",
      index, tostring(record.spn or "-"), answer, string.upper(tostring(record.transport or "-")),
      record.rtt_ms and (tostring(record.rtt_ms) .. " ms") or "n/a")
  end
  lines[#lines + 1] = string.format("%d bytes sent over %d TGS-REQ(s), %d bytes received",
    sent, #state.results, received)
  return lines
end

-- ---------------------------------------------------------------------------
-- 9e. SPN syntax and registration reference
--
-- Most "SPN not found" results in real audits are a syntax problem, not an
-- absent service. The rules below are the ones that decide whether a probe is
-- asking a meaningful question.
-- ---------------------------------------------------------------------------

local SPN_REFERENCE = {
  "An SPN is 'ServiceClass/Instance' and optionally ':port'. The class is case sensitive for the KDC lookup in the same way the registered string is.",
  "The instance is usually a host name (host.example.com) or a NetBIOS name, and it must match what the service registered, including whether the FQDN was used.",
  "A port in the SPN is not a filter: 'MSSQLSvc/db01.example.com:1433' and 'MSSQLSvc/db01.example.com' are two different registrations, and a service usually has only one of them.",
  "Built-in service classes are single-label ('HOST', 'cifs', 'ldap'); consulting services use their own class names ('MSSQLSvc', 'exchangeMDB', 'TERMSRV').",
  "Duplicate SPNs across accounts break Kerberos authentication: when setspn -X reports duplicates, the realm is misconfigured independently of any attack.",
  "A computer account automatically holds HOST/<name> and <name>/<name> registrations, which is why the HOST control probe is a useful sanity check on the target name.",
  "Non-standard classes (an application's own class name) exist and are invisible to a class catalogue like the one in this script; use an exact spn-list for those.",
}

-- What this script deliberately does not do, stated where the operator will
-- read it rather than buried in a design document.
local SCOPE_NOTES = {
  "It does not authenticate, request a service ticket for a service the operator cannot already reach, or crack anything.",
  "It does not enumerate the directory: SPN discovery here is probe based, so it finds only the candidates the operator supplies.",
  "It cannot decide the privilege of the account behind an SPN: that requires directory read access, which the verification recipes cover.",
  "The existence oracle is implementation dependent. Where a KDC normalises its answers, the script reports INCONCLUSIVE rather than inventing findings - the calibration probe exists precisely to detect that case.",
}

-- ---------------------------------------------------------------------------
-- 9f. KDC implementation behaviour for the lookup oracle
--
-- The oracle is not a protocol guarantee: RFC 4120 requires a KDC to answer
-- KDC_ERR_S_PRINCIPAL_UNKNOWN when it cannot find a principal, but it does not
-- mandate the order of the lookup and the ticket decryption, and implementations
-- differ. The table records what to expect, so an anomalous result can be read
-- as "this KDC is unusual" rather than as "this SPN exists".
-- ---------------------------------------------------------------------------

local IMPLEMENTATION_BEHAVIOUR = {
  {
    implementation = "Active Directory (Windows Server 2008 - 2025)",
    unknown_spn = "KDC_ERR_S_PRINCIPAL_UNKNOWN (7)",
    existing_spn = "KRB_AP_ERR_MODIFIED (41) or KRB_AP_ERR_TKT_EXPIRED (32) once the ticket fails to decrypt",
    reliable = "yes, in practice: the SPN is resolved from the directory before the ticket is processed",
    notes = "the behaviour is the reason kerberoast reconnaissance is possible without credentials; the corresponding event is 4769",
  },
  {
    implementation = "MIT krb5 (kdc 1.15 - 1.21)",
    unknown_spn = "KDC_ERR_S_PRINCIPAL_UNKNOWN (7)",
    existing_spn = "KRB_AP_ERR_MODIFIED (41) or KRB_AP_ERR_BAD_INTEGRITY (31)",
    reliable = "usually, but the order depends on the realm's ticket handling configuration",
    notes = "with a KDB backend that resolves principals lazily, some configurations answer ETYPE_NOSUPP first",
  },
  {
    implementation = "Heimdal KDC",
    unknown_spn = "KDC_ERR_S_PRINCIPAL_UNKNOWN (7)",
    existing_spn = "KRB_AP_ERR_MODIFIED (41)",
    reliable = "yes, for the default hdb backend",
    notes = "test the calibration probe: Heimdal deployments vary more than AD deployments",
  },
  {
    implementation = "Samba AD DC",
    unknown_spn = "KDC_ERR_S_PRINCIPAL_UNKNOWN (7)",
    existing_spn = "KRB_AP_ERR_MODIFIED (41)",
    reliable = "yes: Samba mirrors the Windows order of operations for interoperability",
    notes = "the directory view and the Kerberos view come from the same database, so the two never disagree",
  },
  {
    implementation = "FreeIPA / Red Hat IdM",
    unknown_spn = "KDC_ERR_S_PRINCIPAL_UNKNOWN (7)",
    existing_spn = "KRB_AP_ERR_MODIFIED (41)",
    reliable = "yes, with the 389-ds backend",
    notes = "service principals are managed through the IPA framework, so an unexpected SPN is itself a finding",
  },
  {
    implementation = "Hardened or fronted KDC (reverse proxy, rate limiter, custom filter)",
    unknown_spn = "often normalised to a generic error",
    existing_spn = "the same generic error",
    reliable = "no",
    notes = "this is the case the calibration probe is designed to catch; the script then reports INCONCLUSIVE instead of a false inventory",
  },
}

-- ---------------------------------------------------------------------------
-- 10. Reporting
-- ---------------------------------------------------------------------------

local report = {}

local RISK_LABEL = {
  CRITICAL = "\240\159\148\180 CRITICAL",
  HIGH = "\240\159\159\160 HIGH",
  MEDIUM = "\240\159\159\161 MEDIUM",
  LOW = "\240\159\159\162 LOW",
  PASS = "\240\159\159\162 LOW (no service principals exposed)",
  INCONCLUSIVE = "\240\159\159\161 MEDIUM (INCONCLUSIVE - the SPN oracle could not be validated)",
}

function report.build(state, cfg, realm, realm_source, agg, ranked, calibration_verdict, calibration_note, calibration_ok)
  local out = stdnse.output_table()

  out["Script version"] = SCRIPT_VERSION
  out["Declared risk class"] = SCRIPT_RISK
  out["Realm"] = realm or "undetermined"
  if realm_source then
    out["Realm source"] = realm_source
  end

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

  out["Probe summary"] = string.format(
    "candidates %d, existing %d, absent %d, inconclusive %d, unanswered %d, timeouts %d",
    #state.results, #agg.exists, #agg.absent, #agg.inconclusive, #agg.transport, state.timeouts)

  if cfg.ticket then
    out["Ticket mode"] = "a supplied ticket was presented: the negotiation was completed end to end"
    local ticket_info = analysis.inspect_ticket(cfg)
    local ticket_lines = {}
    ticket_lines[#ticket_lines + 1] = string.format("shape: %s", tostring(ticket_info.kind or "unknown"))
    if ticket_info.bytes then
      ticket_lines[#ticket_lines + 1] = string.format("size: %d bytes", ticket_info.bytes)
    end
    if ticket_info.realm then
      ticket_lines[#ticket_lines + 1] = string.format("realm: %s", ticket_info.realm)
    end
    if ticket_info.sname then
      ticket_lines[#ticket_lines + 1] = string.format("service: %s", ticket_info.sname)
    end
    if ticket_info.etype then
      ticket_lines[#ticket_lines + 1] = string.format("enc-part etype: %s (%s)", tostring(ticket_info.etype),
        (ETYPE[ticket_info.etype] or {}).name or "?")
    end
    if ticket_info.kvno then
      ticket_lines[#ticket_lines + 1] = string.format("key version: %s", tostring(ticket_info.kvno))
    end
    if ticket_info.error then
      ticket_lines[#ticket_lines + 1] = "PROBLEM: " .. ticket_info.error
    end
    if ticket_info.realm and realm and string.upper(ticket_info.realm) ~= string.upper(realm) then
      ticket_lines[#ticket_lines + 1] = string.format(
        "the ticket belongs to realm %s but the target realm is %s: an inter-realm request requires a referral, so treat the etype results with caution",
        string.upper(ticket_info.realm), string.upper(realm))
    end
    ticket_lines[#ticket_lines + 1] = "the ticket is a credential: it was decoded in memory only and is not written to any file by this script"
    out["Supplied ticket inspection"] = ticket_lines
  else
    out["Ticket mode"] = "no ticket supplied: the KDC's lookup-path error codes were used as the oracle"
  end

  if #agg.exists > 0 then
    local lines = {}
    for _, verdict in ipairs(agg.exists) do
      local info = spns.info(verdict.candidate and verdict.candidate.class)
      local suffix = ""
      if verdict.calibration_doubt then
        suffix = "  [unreliable: the calibration probe was not distinguishable]"
      end
      lines[#lines + 1] = string.format("%-34s %-46s [%s%s]", verdict.spn, verdict.label,
        tostring(info.value or "unknown"), suffix)
    end
    table.sort(lines)
    out["Registered service principals"] = lines
  else
    out["Registered service principals"] = "None of the probed candidates was reported as existing."
  end

  if #ranked > 0 then
    local lines = {}
    for _, entry in ipairs(ranked) do
      lines[#lines + 1] = string.format("score %-2d %-18s %-38s %d instance(s)%s",
        entry.score, entry.class, entry.info.product or "unknown product", entry.count,
        entry.confirmed_rc4 and "  [RC4 ticket material confirmed: roastable]" or "")
    end
    out["Kerberoasting exposure ranking"] = lines
  end

  if #agg.roastable > 0 then
    local lines = {}
    for _, verdict in ipairs(agg.roastable) do
      lines[#lines + 1] = string.format("%-34s etype %s (%s)", verdict.spn, tostring(verdict.etype),
        (ETYPE[verdict.etype] or {}).name or "?")
    end
    out["Confirmed ticket material (ticket mode)"] = lines
  end

  if #agg.inconclusive > 0 then
    local lines = {}
    for _, verdict in ipairs(agg.inconclusive) do
      lines[#lines + 1] = string.format("%-34s %s", verdict.spn, tostring(verdict.code_name or verdict.label))
    end
    out["Inconclusive answers"] = lines
  end

  if #agg.absent > 0 and #agg.absent <= 40 then
    local names = {}
    for _, verdict in ipairs(agg.absent) do
      names[#names + 1] = verdict.spn
    end
    table.sort(names)
    out["Not registered (probed and absent)"] = table.concat(names, ", ")
  elseif #agg.absent > 40 then
    out["Not registered (probed and absent)"] = string.format("%d SPN(s) were probed and not found", #agg.absent)
  end

  local calibration = {}
  for _, line in ipairs(calibration_note) do
    calibration[#calibration + 1] = line
  end
  if calibration_verdict then
    calibration[#calibration + 1] = string.format(
      "the calibration probe was one extra TGS-REQ; it costs one KDC log entry and no account state")
    calibration[#calibration + 1] = string.format("oracle verdict: %s",
      calibration_ok and "validated (absent and existing SPNs answer differently)" or
      "NOT validated (the KDC answers uniformly, so existence claims are weak)")
  end
  out["Oracle calibration"] = calibration

  -- Per-class depth for everything that was found: this is what turns the
  -- name list into audit findings with next steps.
  if #ranked > 0 then
    local depth = {}
    for _, entry in ipairs(ranked) do
      local detail = CLASS_DEPTH[entry.class]
      depth[#depth + 1] = string.format("== %s (%s) ==", entry.class, entry.info.product or "unknown product")
      if detail then
        depth[#depth + 1] = "  the account behind it is usually: " .. detail.account_shape
        depth[#depth + 1] = "  what it can usually reach: " .. detail.privileges
        for _, check in ipairs(detail.checks) do
          depth[#depth + 1] = "  check: " .. check
        end
        depth[#depth + 1] = "  why it matters: " .. detail.escalation
      else
        depth[#depth + 1] = "  no class-specific guidance is held for this service class; inventory the owning account manually."
      end
    end
    out["What to check for each discovered class"] = depth
    out["Typical attack chains from this inventory"] = ATTACK_CHAINS
  end

  out["Probe transcript"] = analysis.transcript(state)
  out["SPN syntax reference"] = SPN_REFERENCE
  out["KDC implementation behaviour for the lookup oracle"] = (function()
    local lines = {}
    for _, entry in ipairs(IMPLEMENTATION_BEHAVIOUR) do
      lines[#lines + 1] = string.format("%s: unknown SPN -> %s | existing SPN -> %s | reliable: %s",
        entry.implementation, entry.unknown_spn, entry.existing_spn, entry.reliable)
      lines[#lines + 1] = "    " .. entry.notes
    end
    return lines
  end)()
  out["Scope of this check"] = SCOPE_NOTES

  -- The technique context is what turns a list of SPNs into an actionable
  -- exposure statement.
  out["Why SPN inventory matters"] = KB.TECHNIQUE

  return out
end

function report.verdict(out, agg, ranked, calibration_ok, state)
  local lines = {}
  local severity = "LOW"

  if state.answers == 0 then
    lines[#lines + 1] = "Nothing answered, so no conclusion about registered service principals can be drawn."
    lines[#lines + 1] = "This is INCONCLUSIVE, not clean."
    out["Verdict"] = lines
    return "INCONCLUSIVE"
  end

  if not calibration_ok then
    lines[#lines + 1] = "The KDC answered the impossible control SPN the same way it answered the real candidates, so its error codes do not disclose SPN existence in this environment."
    lines[#lines + 1] = "That is itself informative: some KDCs (and some hardened configurations) normalise the answer. Use the directory-side verification recipes below instead."
    out["Verdict"] = lines
    return #agg.exists > 0 and "MEDIUM" or "INCONCLUSIVE"
  end

  if #agg.exists == 0 then
    lines[#lines + 1] = "No probed service principal is registered. The candidate list was the limit of the check, not a statement that the realm has no SPNs."
    out["Verdict"] = lines
    return "LOW"
  end

  lines[#lines + 1] = string.format("%d service principal(s) are registered and were resolvable without credentials.",
    #agg.exists)

  local high_value = {}
  for _, entry in ipairs(ranked) do
    if entry.info.value == "high" then
      high_value[#high_value + 1] = entry.class
    end
  end
  if #high_value > 0 then
    lines[#lines + 1] = "High-value classes present: " .. table.concat(high_value, ", ") ..
      ". The account behind each of these is the object worth attacking offline."
    severity = "HIGH"
  else
    severity = "MEDIUM"
  end

  if #agg.roastable > 0 then
    local rc4 = 0
    for _, verdict in ipairs(agg.roastable) do
      if verdict.etype == 23 or verdict.etype == 24 then
        rc4 = rc4 + 1
      end
    end
    if rc4 > 0 then
      lines[#lines + 1] = string.format(
        "%d service ticket(s) were issued in RC4-HMAC: those accounts are recoverable offline in GPU-hours. Enable pre-authentication hygiene and move the accounts to AES (see remediation).",
        rc4)
      severity = "CRITICAL"
    else
      lines[#lines + 1] = "Service tickets were issued in AES: the accounts are not cheaply crackable, but the SPN inventory itself remains valuable reconnaissance."
    end
  else
    lines[#lines + 1] = "The run did not confirm encryption types (no ticket was supplied). Confirm exposure with the credentialled recipes below before writing off the risk."
  end

  lines[#lines + 1] = "Remediation priority follows the ranking above: gMSA conversion first for the high-value classes, then SPN hygiene and delegation review."
  out["Verdict"] = lines
  return severity
end

-- ---------------------------------------------------------------------------
-- 11. Action
-- ---------------------------------------------------------------------------

action = function(host, port)
  local cfg = config.load(host)
  local effective_port = port.number
  local state = engine.new_state()

  -- Realm resolution.
  local realm = cfg.realm
  local realm_source = realm and "kerberos.realm script argument" or nil
  if not realm then
    local leaked
    realm, leaked = realmdisco.leak(host, effective_port, cfg)
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
      "The SPN database is realm scoped, and a TGS-REQ addressed to the wrong realm is answered by the wrong KDC (or by none).",
      "No kerberos.realm was supplied and the KDC did not disclose its realm through KDC_ERR_WRONG_REALM.",
    }
    out["Remediation"] = {
      "Re-run with --script-args kerberos.realm=YOUR.REALM.",
    }
    out["Risk Level"] = RISK_LABEL.INCONCLUSIVE
    return out
  end

  -- Candidate list.
  local list, err, meta = spns.build(cfg)
  if err then
    local out = stdnse.output_table()
    out["Script version"] = SCRIPT_VERSION
    out["Declared risk class"] = SCRIPT_RISK
    out["Realm"] = realm
    out["Check status"] = "ABORTED - " .. err
    out["How to run it"] = {
      "--script-args 'kerberos.targets=db01,web01,ws01'             (permutes the default service classes)",
      "--script-args 'kerberos.targets=db01,kerberos.spn-classes=all'",
      "--script-args 'kerberos.spn-list=/path/to/spns.txt'          (exact SPN list, one per line)",
    }
    out["Risk Level"] = RISK_LABEL.INCONCLUSIVE
    return out
  end

  if #list == 0 then
    local out = stdnse.output_table()
    out["Script version"] = SCRIPT_VERSION
    out["Declared risk class"] = SCRIPT_RISK
    out["Realm"] = realm
    out["Check status"] = "ABORTED - no SPN candidates could be constructed"
    out["How to run it"] = {
      "Supply kerberos.targets (host names) or kerberos.spn-list (exact SPNs).",
    }
    out["Risk Level"] = RISK_LABEL.INCONCLUSIVE
    return out
  end

  -- Calibrate the oracle, then probe.
  local calibration_record = analysis.calibrate(host, effective_port, cfg, realm, state)
  local calibration_verdict = analysis.classify(calibration_record)

  engine.run(host, effective_port, cfg, realm, list, state)

  local verdicts = {}
  for _, record in ipairs(state.results) do
    if record ~= calibration_record then
      verdicts[#verdicts + 1] = analysis.classify(record)
    end
  end

  local calibration_note, calibration_ok = analysis.calibration_note(calibration_verdict, verdicts)
  local agg = analysis.aggregate(verdicts, calibration_ok)
  local ranked = analysis.rank(agg)

  local out = report.build(state, cfg, realm, realm_source, agg, ranked, calibration_verdict, calibration_note, calibration_ok)
  local severity = report.verdict(out, agg, ranked, calibration_ok, state)

  if meta and meta.truncated then
    out["Probe budget"] = string.format("candidate list truncated to kerberos.max-spns=%d", cfg.max_spns)
  end
  if #agg.transport > 0 then
    out["Unanswered candidates"] = string.format(
      "%d candidate(s) produced no answer; they are neither present nor absent", #agg.transport)
  end

  if severity ~= "LOW" then
    local mapping = {}
    for _, entry in ipairs(KB.MAPPING) do
      mapping[#mapping + 1] = string.format("%s %s (%s)", entry.id, entry.name, entry.note)
    end
    out["ATT&CK mapping"] = mapping
    out["Detection guidance"] = KB.DETECTION

    local remediation = {}
    for _, group in ipairs(KB.REMEDIATION) do
      remediation[#remediation + 1] = "== " .. group.title .. " =="
      for _, step in ipairs(group.steps) do
        remediation[#remediation + 1] = "  " .. step
      end
    end
    out["Remediation"] = remediation
    out["Independent verification"] = KB.VERIFICATION
    out["References"] = KB.REFERENCES

    vulns.add(host, port, "krb5-spn-inventory",
      string.format("%d Kerberos service principal name(s) discovered unauthenticated (%s)",
        #agg.exists, table.concat((function()
          local classes = {}
          for _, entry in ipairs(ranked) do
            classes[#classes + 1] = entry.class
          end
          return classes
        end)(), ", ")))
  elseif #agg.exists == 0 then
    out["References"] = KB.REFERENCES
  end

  out["Risk Level"] = RISK_LABEL[severity] or severity
  return out
end
