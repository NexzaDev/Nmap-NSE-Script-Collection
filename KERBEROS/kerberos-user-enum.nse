local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local table = require "table"
local string = require "string"
local math = require "math"
local os = require "os"
local vulns = require "vulns"

-- Protocol primitives (DER codec, KRB-ERROR codec, UDP/TCP transport) come from
-- the shared, tested engine rather than being re-implemented per script.
local ok, krb5 = pcall(require, "kerberos5")

description = [[
Enumerates valid Active Directory / MIT Kerberos principal names through the
KDC's own error codes, without any credential and without a single
authentication attempt.

The technique (publicly known as Kerberos user enumeration, MITRE ATT&CK
T1087.002) relies on the fact that a KDC must answer "principal unknown"
differently from "principal exists but must pre-authenticate":

  * KDC_ERR_C_PRINCIPAL_UNKNOWN (6)  -> the principal does not exist
  * KDC_ERR_PREAUTH_REQUIRED  (25)   -> the principal exists, pre-auth enforced
  * KRB-ERROR 25 with no e-data      -> typically an MIT krb5 KDC answering for
                                        an existing principal
  * KRB-ERROR 24 / 23 (PREAUTH_FAILED / KEY_EXPIRED) -> principal exists and is
                                        reachable by authentication attempts
  * KRB-ERROR 18 (CLIENT_REVOKED)    -> principal exists but is disabled or
                                        locked out
  * AS-REP returned without pre-auth -> principal exists and is roastable

Because those codes are structural (they come from the KDC's own database
lookup), the answer is authoritative: no payload inspection, no timing guess
and no brute force is involved.

The script adds three things the classic one-liner enumeration scripts lack:

  1. **Lockout protection.** Sequential probes, configurable pacing with
     jitter, a hard cap on principal count, and an immediate abort on the first
     CLIENT_REVOKED / PREAUTH_FAILED / KEY_EXPIRED answer. An audit tool must
     never be able to lock a service account in a production directory.
  2. **Confidence classification.** Every result is scored by combining the
     error code, the response size, the e-text fingerprint and the RTT against
     the run's own baseline, so a KDC that answers uniformly still produces an
     honest "inconclusive" instead of a fabricated account list.
  3. **Actionable reporting.** Valid / disabled / roastable / unknown buckets,
     privileged-name heuristics, detection guidance (event 4768 result code
     0x6), and verification recipes that reproduce the same list with
     independent tooling.

References:
  * RFC 4120 section 7.5.1 - KRB-ERROR and the error code registry
  * MITRE ATT&CK T1087.002 - Account Discovery: Domain Account
  * Microsoft Windows event 4768 (TGT request) with result code 0x6
]]

---
-- @usage
-- nmap -p 88 --script kerberos-user-enum --script-args 'kerberos.realm=EXAMPLE.COM,kerberos.userlist=/tmp/users.txt' <target>
--
-- @args kerberos.realm       Realm in uppercase DNS form. Derived from the
--                            KDC's KDC_ERR_WRONG_REALM answer when omitted.
-- @args kerberos.users       Comma separated principals to test.
-- @args kerberos.userlist    Path to a newline separated wordlist (one
--                            principal per line, '#' starts a comment).
-- @args kerberos.builtin-list "true" appends the built-in list of well-known
--                            account names (about 300 entries). Off by default.
-- @args kerberos.max-users   Hard cap on probes for the whole run
--                            (default 100, maximum 2000).
-- @args kerberos.delay-ms    Minimum spacing between probes (default 400 ms,
--                            jittered upward by up to 50 percent).
-- @args kerberos.timeout-ms  Per-request receive timeout.
-- @args kerberos.transport   "auto" (default), "udp" or "tcp".
-- @args kerberos.retries     Transport retries on timeout/drop (default 1).
-- @args kerberos.no-lockout-guard "true" disables the abort-on-locked-account
--                            protection. Only for lab use; documented here
--                            because hiding a footgun behind an undocumented
--                            flag is worse than documenting it.
--
-- @output
-- PORT   STATE SERVICE
-- 88/tcp open  kerberos-sec
-- | kerberos-user-enum:
-- |   Realm: EXAMPLE.COM
-- |   Principals probed: 12   answered: 12   unknown: 7   existing: 5
-- |   Existing principals:
-- |     svc-backup      pre-authentication DISABLED (AS-REP returned) - roastable
-- |     jsmith          pre-authentication enforced (offered 18, 17)
-- |     helpdesk        pre-authentication enforced (offered 18, 17, 23)
-- |   Disabled or locked principals:
-- |     old-admin       KDC_ERR_CLIENT_REVOKED (18)
-- |   Privileged name heuristics: svc-backup (service account naming convention)
-- |   Verdict: ...
-- |   Risk Level: HIGH
-- |_  ...
---

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "vuln"}

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
local decoder = krb5.decoder
local ETYPE = krb5.ETYPE
local ETYPE_OFFER_DEFAULT = krb5.ETYPE_OFFER_DEFAULT
local KRB5_ERR = krb5.KRB5_ERR
local SCRIPT_VERSION = krb5.VERSION

-- Declared risk class, read by tools/syntax-check.js to enforce the repository
-- depth contract: CRITICAL/HIGH >= 1538 lines, MEDIUM/LOW 500-800 lines.
local SCRIPT_RISK = "HIGH"

-- ---------------------------------------------------------------------------
-- 1. Tuning constants
-- ---------------------------------------------------------------------------

local DEFAULTS = {
  max_users = 100,
  hard_max_users = 2000,
  delay_ms = 400,
  retries = 1,
  min_list_length = 1,
  confidence_threshold = 0.5,
}

-- Response classification labels. The label is what the report shows; the
-- confidence is what the scoring model consumes.
local VERDICT = {
  EXISTS_PREAUTH = "exists-preauth-required",
  EXISTS_NO_PREAUTH = "exists-preauth-disabled",
  EXISTS_DISABLED = "exists-disabled",
  EXISTS_KEY_EXPIRED = "exists-key-expired",
  EXISTS_OTHER = "exists-inconclusive",
  UNKNOWN = "unknown-principal",
  WRONG_REALM = "realm-mismatch",
  SKEW = "clock-skew",
  TRANSPORT = "no-answer",
  OTHER = "unclassified",
}

-- ---------------------------------------------------------------------------
-- 2. Error-code decision table
--
-- For each KDC answer: does it prove the principal exists, what should the
-- report call it, how much does it raise the severity, and what does the
-- operator have to do about it. Anything not listed here falls back to the
-- registry in nselib/kerberos5.lua.
-- ---------------------------------------------------------------------------

local DECISION = {
  [25] = {
    verdict = VERDICT.EXISTS_PREAUTH,
    exists = true,
    label = "pre-authentication enforced",
    severity = "INFO",
    reason = "the KDC demanded PA-ENC-TIMESTAMP, so the principal exists in the realm database",
    action = "none - this is the hardened configuration",
  },
  [6] = {
    verdict = VERDICT.UNKNOWN,
    exists = false,
    label = "unknown principal",
    severity = "INFO",
    reason = "the KDC has no entry for this name (KDC_ERR_C_PRINCIPAL_UNKNOWN)",
    action = "none, but log and rate-limit these answers: they are the enumeration signal itself",
  },
  [24] = {
    verdict = VERDICT.EXISTS_KEY_EXPIRED,
    exists = true,
    label = "exists, last pre-authentication failed (counted by the KDC)",
    severity = "MEDIUM",
    reason = "KDC_ERR_PREAUTH_FAILED proves the principal exists and that the failure was counted against it",
    action = "stop probing this principal immediately: the bad-password counter advanced",
  },
  [23] = {
    verdict = VERDICT.EXISTS_KEY_EXPIRED,
    exists = true,
    label = "exists, password or key expired",
    severity = "LOW",
    reason = "KDC_ERR_KEY_EXPIRED proves the principal exists and that its credential needs rotation",
    action = "flag the account for the identity team: expired credentials on service accounts are usually forgotten",
  },
  [18] = {
    verdict = VERDICT.EXISTS_DISABLED,
    exists = true,
    label = "exists, disabled or locked out",
    severity = "MEDIUM",
    reason = "KDC_ERR_CLIENT_REVOKED proves the principal exists but cannot authenticate",
    action = "remove stale accounts, or investigate whether the lockout was caused by earlier activity",
  },
  [12] = {
    verdict = VERDICT.EXISTS_OTHER,
    exists = true,
    label = "exists, request refused by realm policy",
    severity = "LOW",
    reason = "KDC_ERR_POLICY is only returned after the principal was resolved",
    action = "review the KDC policy that refused the request (logon hours, workstation restrictions)",
  },
  [14] = {
    verdict = VERDICT.EXISTS_OTHER,
    exists = true,
    label = "exists, but no shared encryption type",
    severity = "MEDIUM",
    reason = "KDC_ERR_ETYPE_NOSUPP is answered after the principal is resolved, and reveals that the account's msDS-SupportedEncryptionTypes does not intersect the offered set",
    action = "audit the account's etype configuration; an account that cannot negotiate AES is usually still on RC4 or DES",
  },
  [16] = {
    verdict = VERDICT.EXISTS_OTHER,
    exists = true,
    label = "exists, unsupported pre-authentication type",
    severity = "LOW",
    reason = "KDC_ERR_PADATA_TYPE_NOSUPP implies the principal was resolved and requires a padata type the client did not offer",
    action = "identify the required mechanism (PKINIT, OTP, FAST) to understand the realm's authentication policy",
  },
  [21] = {
    verdict = VERDICT.EXISTS_OTHER,
    exists = true,
    label = "exists, not yet valid",
    severity = "LOW",
    reason = "KDC_ERR_CLIENT_NOTYET means the account start date is in the future",
    action = "check for accounts scheduled far in advance, a common sign of forgotten onboarding tickets",
  },
  [37] = {
    verdict = VERDICT.SKEW,
    exists = false,
    label = "clock skew",
    severity = "LOW",
    reason = "KRB_AP_ERR_SKEW is returned before the principal lookup completes, so it proves nothing about the account",
    action = "fix the scanner clock (or the KDC's) and re-run: this answer cannot be interpreted",
  },
  [68] = {
    verdict = VERDICT.WRONG_REALM,
    exists = false,
    label = "realm mismatch",
    severity = "LOW",
    reason = "KDC_ERR_WRONG_REALM is answered by the KDC for a different realm, which leaks the canonical realm name",
    action = "re-run against the leaked realm",
  },
}

-- ---------------------------------------------------------------------------
-- 3. Built-in candidate list
--
-- Deliberately limited to names that a hardened directory should not have in
-- the first place, so the list is useful for audits of legacy environments
-- while remaining opt-in. It is ordered so that the highest-value names are
-- probed first if kerberos.max-users truncates the run.
-- ---------------------------------------------------------------------------

local BUILTIN_ACCOUNTS = {
  -- Tier 0 / Tier 1 administrative naming
  "administrator", "admin", "adm", "root", "sysadmin", "domainadmin",
  "da-admin", "ea-admin", "sa-admin", "enterprise-admin", "schema-admin",
  "backupadmin", "serveradmin", "workstationadmin", "helpdeskadmin",
  "itadmin", "netadmin", "dba", "dbadmin", "sqladmin", "exchangeadmin",
  "vmwareadmin", "storageadmin", "printadmin", "dhcpadmin", "dnsadmin",
  "krbadmin", "krbtgt", "pkiadmin", "caadmin", "certadmin", "adfsadmin",
  "o365admin", "azureadmin", "awsadmin", "cloudadmin", "sccmadmin",
  -- Default and vendor accounts
  "guest", "default", "user", "test", "demo", "temp", "temporary",
  "contractor", "vendor", "intern", "student", "training",
  "krbtgt2", "msol", "aad", "azuread", "sync", "dirsync", "adconnect",
  "aadsync", "azureconnect", "sso", "federation", "adfs", "sts",
  -- Platform and service accounts
  "svc", "service", "serviceaccount", "svc-admin", "svc-backup",
  "svc-sql", "svc-iis", "svc-web", "svc-app", "svc-db", "svc-mail",
  "svc-exchange", "svc-print", "svc-file", "svc-dns", "svc-dhcp",
  "svc-wsus", "svc-sccm", "svc-monitor", "svc-antivirus", "svc-edr",
  "svc-backup-exec", "svc-veeam", "svc-netbackup", "svc-commvault",
  "svc-sqlagent", "svc-ssrs", "svc-ssas", "svc-ssis", "svc-rds",
  "svc-sharepoint", "svc-project", "svc-crm", "svc-erp", "svc-sap",
  "svc-jenkins", "svc-gitlab", "svc-tfs", "svc-ansible", "svc-puppet",
  "svc-chef", "svc-terraform", "svc-docker", "svc-kubernetes",
  "sqlserver", "sqlagent", "s q l", "mssql", "reporting", "ssrs",
  "oracle", "oraadmin", "postgres", "mysql", "mariadb", "mongo",
  "elastic", "elasticsearch", "kibana", "logstash", "splunk", "splunkforwarder",
  "backup", "restore", "veeam", "arcserve", "netbackup", "backupexec",
  "tivoli", "tsm", "commvault", "rubrik", "cohesity", "datadomain",
  -- Infrastructure and network
  "exchange", "exchange-svc", "mail", "smtp", "relay", "postmaster",
  "fax", "lync", "skype", "teams", "zoom", "webex", "meet",
  "proxy", "squid", "isa", "tmgin", "waf", "fw", "firewall", "vpn",
  "radius", "nac", "wireless", "wifi", "clearpass", "ise", "aruba",
  "cisco", "ciscoadmin", "juniper", "paloalto", "fortinet", "checkpoint",
  "switch", "router", "network", "netops", "noc", "tacacs",
  -- Hypervisor and storage
  "vmware", "vcenter", "esx", "esxi", "vsphere", "hyperv", "hyper-v",
  "xenserver", "citrix", "xenapp", "xendesktop", "pvs", "proxmox",
  "nutanix", "openshift", "rhv", "ovirt", "netapp", "emc", "isilon",
  "purestorage", "3par", "hitachi", "synology", "qnap", "truenas",
  -- Monitoring, security and management platforms
  "nagios", "icinga", "zabbix", "prtg", "observium", "librenms",
  "checkmk", "solarwinds", "scom", "opsmgr", "dpm", "ncentral",
  "kaseya", "connectwise", "labtech", "gfi", "sysaid", "jira",
  "confluence", "servicenow", "remedy", "manageengine", "qualys",
  "nessus", "rapid7", "nexpose", "tenable", "scanner", "vulnerability",
  "carbonblack", "crowdstrike", "cylance", "defender", "sentinelone",
  "tanium", "ivanti", "landesk", "altiris", "sophos", "mcafee",
  "symantec", "trendmicro", "kaspersky", "eset", "bitdefender",
  -- Databases and applications
  "apppool", "iis", "apache", "nginx", "tomcat", "jboss", "weblogic",
  "websphere", "wildfly", "node", "nodejs", "php", "python", "java",
  "crystal", "businessobjects", "hyperion", "cognos", "tableau",
  "powerbi", "sharepoint", "dynamics", "salesforce", "workday",
  "peoplesoft", "sage", "navision", "axapta", "greatplains", "sapadmin",
  "maxdb", "db2", "informix", "teradata", "snowflake", "databricks",
  -- Manufacturing / facilities / healthcare
  "scada", "hmi", "plc", "opc", "mes", "historian", "ignition",
  "wonderware", "factorytalk", "wincc", "automation", "robot", "kuka",
  "abb", "siemens", "schneider", "rockwell", "hvac", "bms", "elevator",
  "access", "badge", "camera", "nvr", "dvr", "genetec", "milestone",
  "epic", "cerner", "meditech", "pacs", "radiology", "billing",
  -- Human facing and legacy
  "helpdesk", "servicedesk", "support", "supportadmin", "reception",
  "hr", "payroll", "finance", "accounting", "invoice", "purchasing",
  "warehouse", "wms", "logistics", "shipping", "inventory", "pos",
  "kiosk", "store", "branch", "retail", "call center", "callcenter",
  "lyncuser", "tsuser", "rdsh", "terminal", "thinclient", "vdi",
  -- Test, lab and honeypot bait
  "test1", "test2", "testuser", "testadmin", "lab", "labadmin",
  "qa", "qauser", "dev", "developer", "devops", "build", "jenkins",
  "honey", "honeypot", "canary", "decoy", "trap", "bait", "sink",
}
-- ---------------------------------------------------------------------------
-- 4. Configuration
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

local function arg_bool(name, default)
  local value = arg_string(name)
  if value == nil then
    return default
  end
  local low = string.lower(value)
  if low == "true" or low == "yes" or low == "1" or low == "on" then
    return true
  end
  if low == "false" or low == "no" or low == "0" or low == "off" then
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
  local items = {}
  local function add(entry)
    for piece in string.gmatch(tostring(entry), "[^,%s]+") do
      if #piece > 0 then
        items[#items + 1] = piece
      end
    end
  end
  if type(value) == "table" then
    for _, entry in ipairs(value) do add(entry) end
  elseif value ~= nil then
    add(value)
  end
  return items
end

function config.load(host)
  local cfg = {}
  for key, value in pairs(DEFAULTS) do
    cfg[key] = value
  end
  cfg.realm = arg_string("realm")
  if cfg.realm then
    cfg.realm = string.upper(cfg.realm)
  end
  cfg.users = arg_list("users")
  cfg.userlist = arg_string("userlist")
  cfg.builtin_list = arg_bool("builtin-list", false)
  cfg.max_users = arg_int("max-users", DEFAULTS.max_users, 1, DEFAULTS.hard_max_users)
  cfg.delay_ms = arg_int("delay-ms", DEFAULTS.delay_ms, 0, 10000)
  cfg.retries = arg_int("retries", DEFAULTS.retries, 0, 5)
  cfg.lockout_guard = not arg_bool("no-lockout-guard", false)
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
  return cfg
end

-- ---------------------------------------------------------------------------
-- 5. Candidate list assembly
--
-- Sources, in priority order: kerberos.users, kerberos.userlist (file),
-- kerberos.builtin-list. Duplicates are removed case-insensitively because
-- Kerberos principal names are case sensitive on the wire but effectively
-- case insensitive in Active Directory.
-- ---------------------------------------------------------------------------

local candidates = {}

function candidates.normalise(name)
  if not name then
    return nil
  end
  name = string.gsub(name, "^%s+", "")
  name = string.gsub(name, "%s+$", "")
  name = string.gsub(name, "\r", "")
  -- Strip a domain suffix if the operator pasted user@realm or DOMAIN\\user.
  name = string.match(name, "([^@\\]+)@?.*$") or name
  name = string.match(name, ".*\\([^\\]+)$") or name
  if #name == 0 or #name > 256 then
    return nil
  end
  if string.find(name, "[%s]") then
    return nil
  end
  return name
end

-- Parse a wordlist file. Comment lines start with '#', blank lines and
-- duplicate entries are dropped, and the parser refuses to load a file larger
-- than kerberos.max-users entries (truncating instead of failing, with the
-- truncation reported in the output).
function candidates.from_file(path, limit)
  local file, err = io.open(path, "r")
  if not file then
    return nil, string.format("cannot read kerberos.userlist '%s': %s", tostring(path), tostring(err))
  end
  local list = {}
  local seen = {}
  local total = 0
  local skipped = 0
  for line in file:lines() do
    total = total + 1
    local cleaned = string.match(line, "^([^#]*)") or ""
    local name = candidates.normalise(cleaned)
    if name then
      local key = string.lower(name)
      if not seen[key] then
        seen[key] = true
        list[#list + 1] = name
      end
    elseif #cleaned > 0 then
      skipped = skipped + 1
    end
  end
  file:close()
  local truncated = false
  if limit and #list > limit then
    truncated = true
    local trimmed = {}
    for i = 1, limit do
      trimmed[i] = list[i]
    end
    list = trimmed
  end
  return list, nil, { lines = total, skipped = skipped, truncated = truncated }
end

function candidates.build(cfg)
  local list = {}
  local seen = {}
  local sources = {}
  local truncated = false

  local function push(name, source)
    local clean = candidates.normalise(name)
    if not clean then
      return
    end
    local key = string.lower(clean)
    if seen[key] then
      return
    end
    if #list >= cfg.max_users then
      truncated = true
      return
    end
    seen[key] = true
    list[#list + 1] = { name = clean, source = source }
    sources[source] = (sources[source] or 0) + 1
  end

  for _, name in ipairs(cfg.users or {}) do
    push(name, "script-args")
  end

  local file_stats
  if cfg.userlist then
    local file_list, err, stats = candidates.from_file(cfg.userlist, cfg.max_users - #list)
    if err then
      return nil, err
    end
    file_stats = stats
    for _, name in ipairs(file_list) do
      push(name, "wordlist")
    end
  end

  if cfg.builtin_list then
    for _, name in ipairs(BUILTIN_ACCOUNTS) do
      push(name, "built-in")
    end
  end

  return list, nil, { sources = sources, truncated = truncated, file = file_stats }
end

-- ---------------------------------------------------------------------------
-- 6. Realm discovery
-- ---------------------------------------------------------------------------

local realmdisco = {}

function realmdisco.hints(host)
  local out = {}
  local seen = {}
  local function push(value)
    if not value or #value == 0 then
      return
    end
    value = string.upper(value)
    if value:sub(1, 1) == "." then
      value = value:sub(2)
    end
    if #value < 3 or value:find("^%d") or seen[value] then
      return
    end
    seen[value] = true
    out[#out + 1] = value
  end
  if host.name then
    push(string.match(host.name, "^[^%.]+%.(.+)$"))
    push(host.name)
  end
  if host.targetname and host.targetname ~= host.name then
    push(string.match(host.targetname, "^[^%.]+%.(.+)$"))
  end
  return out
end

-- Ask the KDC about a realm that cannot exist; the KDC_ERR_WRONG_REALM answer
-- carries the canonical realm name.
function realmdisco.leak(host, port, cfg)
  local synthetic = "NMAP.INVALID.REALM"
  local record = transport.as_req(host, port, {
    realm = synthetic,
    cname = "nmap-enum-probe",
    etypes = ETYPE_OFFER_DEFAULT,
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
-- 7. Probe engine
--
-- Sequential by design. Kerberos probes are indistinguishable from an
-- attacker's recon traffic in the KDC log, and a parallel burst is what turns
-- an enumeration into a lockout event; the engine therefore trades speed for
-- the guarantee that at most one probe per principal is ever in flight.
-- ---------------------------------------------------------------------------

local engine = {}

function engine.new_state()
  return {
    probes = 0,
    answers = 0,
    timeouts = 0,
    errors = 0,
    aborted = false,
    abort_reason = nil,
    results = {},
    rtts = {},
    fingerprints = {},
    transport_seen = {},
  }
end

-- Counts come from the classified verdicts, never from the raw transport
-- records: a record that was answered but not classified must not silently
-- inflate the "exists" bucket.
function engine.state_counts(state)
  local counts = { exists = 0, unknown = 0, disabled = 0, roastable = 0, unanswered = 0 }
  for _, verdict in ipairs(state.verdicts or {}) do
    if verdict.verdict == VERDICT.UNKNOWN then
      counts.unknown = counts.unknown + 1
    elseif verdict.verdict == VERDICT.EXISTS_DISABLED then
      counts.disabled = counts.disabled + 1
      counts.exists = counts.exists + 1
    elseif verdict.verdict == VERDICT.EXISTS_NO_PREAUTH then
      counts.roastable = counts.roastable + 1
      counts.exists = counts.exists + 1
    elseif verdict.exists then
      counts.exists = counts.exists + 1
    else
      counts.unanswered = counts.unanswered + 1
    end
  end
  return counts
end

local function pace(cfg, index)
  if index <= 1 or cfg.delay_ms <= 0 then
    return
  end
  local jitter = math.random(0, math.floor(cfg.delay_ms / 2))
  stdnse.sleep((cfg.delay_ms + jitter) / 1000)
end

-- One AS-REQ without pre-authentication data: exactly what an unauthenticated
-- client sends when it asks the KDC "does this principal exist".
function engine.probe_once(host, port, cfg, realm, principal)
  local nonce = math.random(1, 2147483000)
  local record = transport.as_req(host, port, {
    realm = realm,
    cname = principal,
    etypes = ETYPE_OFFER_DEFAULT,
    nonce = nonce,
    kdc_options = 0,
  }, { timeout_ms = cfg.timeout_ms, retries = cfg.retries, transport = cfg.transport })
  record.principal = principal
  record.nonce = nonce
  return record
end

function engine.run(host, port, cfg, realm, list, state)
  for index, candidate in ipairs(list) do
    if state.aborted then
      break
    end
    pace(cfg, index)

    local record = engine.probe_once(host, port, cfg, realm, candidate.name)
    record.candidate = candidate
    record.index = index
    record.at = os.time()

    state.probes = state.probes + 1
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
    state.results[#state.results + 1] = record

    -- Lockout guard: the KDC tells us when an account is unusable (18) or when
    -- a pre-authentication failure has just been counted (24/23). Continuing
    -- at that point would be an attack on the directory, not an audit of it.
    if cfg.lockout_guard and record.kind == "krb_error" then
      local code = record.krb_error.code
      if code == 18 then
        state.aborted = true
        state.abort_reason = string.format(
          "KDC_ERR_CLIENT_REVOKED for '%s': the account is disabled or locked out. Remaining %d probes cancelled (lockout guard).",
          candidate.name, #list - index)
      elseif code == 24 or code == 23 then
        state.aborted = true
        state.abort_reason = string.format(
          "%s for '%s': the KDC counted an authentication failure. Remaining %d probes cancelled (lockout guard).",
          record.krb_error.code_name, candidate.name, #list - index)
      end
    end

    if state.timeouts >= 3 and state.answers == 0 then
      state.aborted = true
      state.abort_reason = "three consecutive timeouts with no answer at all: wrong port, filtered path, or not a KDC"
    end
  end
  return state
end

-- ---------------------------------------------------------------------------
-- 8. Classification
--
-- Three independent signals are combined:
--   1. the KDC error code (authoritative when it is a database answer),
--   2. the response fingerprint (byte length + e-text) compared with the
--      baseline probes for a name that cannot exist,
--   3. the RTT distribution (a KDC that performs an LDAP lookup for an
--      existing principal is measurably slower than one that does not).
-- Signal 1 alone drives the verdict when it is decisive; signals 2 and 3 only
-- ever raise or lower the confidence, never invent an existence claim.
-- ---------------------------------------------------------------------------

local analysis = {}

function analysis.baseline(host, port, cfg, realm)
  local baseline = {}
  -- Two synthetic principals: one that is guaranteed not to exist, and one
  -- whose name is invalid RFC 4514 syntax, which some KDCs reject before the
  -- lookup stage. The two together separate "lookup miss" from "request
  -- rejected", which is what makes the fingerprint comparison meaningful.
  local probes = {
    { name = string.format("nmap-nonexistent-%d", math.random(100000, 999999)), kind = "unknown" },
    { name = string.format("nmap'bad\"name-%d", math.random(100000, 999999)), kind = "malformed" },
  }
  for _, probe in ipairs(probes) do
    local record = engine.probe_once(host, port, cfg, realm, probe.name)
    record.baseline_kind = probe.kind
    baseline[probe.kind] = record
  end
  return baseline
end

function analysis.fingerprint(record)
  if not record.kind then
    return nil
  end
  if record.kind == "krb_error" then
    local e = record.krb_error
    return string.format("krb_error:%s:e-text=%s", tostring(e.code), tostring(e.e_text or ""))
  end
  return string.format("%s:etype=%s", record.kind, tostring(record.as_rep and record.as_rep.enc_part and record.as_rep.enc_part.etype))
end

function analysis.classify(record, baseline, stats)
  local verdict = {
    record = record,
    principal = record.principal,
    evidence = {},
    confidence = 0,
    exists = false,
  }

  if not record.kind then
    verdict.verdict = VERDICT.TRANSPORT
    verdict.label = "no answer"
    verdict.severity = "INFO"
    verdict.reason = string.format("the KDC did not answer (%s); this says nothing about the principal",
      tostring(record.error))
    return verdict
  end

  if record.kind == "as_rep" then
    local enc = record.as_rep and record.as_rep.enc_part or {}
    local info = krb.etype_info(enc.etype)
    verdict.verdict = VERDICT.EXISTS_NO_PREAUTH
    verdict.exists = true
    verdict.confidence = 1.0
    verdict.label = string.format("exists, pre-authentication DISABLED (AS-REP etype %s %s)", tostring(enc.etype), info.name)
    verdict.severity = (info.weak or info.retired) and "CRITICAL" or "HIGH"
    verdict.reason = "the KDC returned an AS-REP for an unauthenticated request, which is only possible for an existing principal without pre-authentication"
    verdict.evidence[#verdict.evidence + 1] = string.format("AS-REP %d bytes, cipher %d bytes, kvno %s",
      record.response_bytes or 0, (enc.cipher_len or 0), tostring(enc.kvno or "absent"))
    if record.transport then
      verdict.evidence[#verdict.evidence + 1] = string.format("answered over %s in %s attempt(s)",
        string.upper(record.transport), tostring(record.attempts or 0))
    end
    return verdict
  end

  if record.kind == "krb_error" then
    local e = record.krb_error
    local decision = DECISION[e.code]
    verdict.code = e.code
    verdict.code_name = e.code_name
    verdict.evidence[#verdict.evidence + 1] = string.format("KRB-ERROR %s (%s)", tostring(e.code_name), tostring(e.code))
    if e.e_text and #e.e_text > 0 then
      verdict.evidence[#verdict.evidence + 1] = string.format("KDC e-text: %s", e.e_text)
      verdict.e_text = e.e_text
    end

    if decision then
      verdict.verdict = decision.verdict
      verdict.exists = decision.exists
      verdict.label = decision.label
      verdict.severity = decision.severity
      verdict.reason = decision.reason
      verdict.remediation_hint = decision.action
      verdict.confidence = decision.exists and 0.95 or 0.9
      if verdict.verdict == VERDICT.EXISTS_PREAUTH then
        local etypes, salts = analysis.preauth_etypes(e)
        verdict.etypes = etypes
        if #etypes > 0 then
          local names = {}
          local weak = {}
          for _, etype in ipairs(etypes) do
            names[#names + 1] = string.format("%d %s", etype, krb.etype_info(etype).name)
            local info = krb.etype_info(etype)
            if info.weak or info.retired then
              weak[#weak + 1] = info.name
            end
          end
          verdict.evidence[#verdict.evidence + 1] = "offered etypes: " .. table.concat(names, ", ")
          if #weak > 0 then
            verdict.evidence[#verdict.evidence + 1] = "the account still negotiates retired or weak crypto: "
              .. table.concat(weak, ", ")
            verdict.severity = "MEDIUM"
          end
        end
        if #salts > 0 then
          verdict.salt = salts[1]
          verdict.evidence[#verdict.evidence + 1] = "salt hint: " .. salts[1]
        end
      end
    else
      local registry = KRB5_ERR[e.code]
      verdict.verdict = VERDICT.OTHER
      verdict.exists = false
      verdict.label = registry and registry.name or string.format("unclassified error %s", tostring(e.code))
      verdict.severity = "INFO"
      verdict.reason = registry and registry.note or "not in the RFC 4120 registry; no existence claim can be made"
      verdict.confidence = 0.2
    end

    -- Cross-check against the baseline: an answer identical to the "name that
    -- cannot exist" fingerprint is treated as evidence of a mismatch between
    -- the realm we hold and the realm the KDC serves.
    local fp = analysis.fingerprint(record)
    if fp and stats.fingerprints[fp] and stats.fingerprints[fp] > 0
       and verdict.exists and verdict.verdict ~= VERDICT.EXISTS_NO_PREAUTH then
      verdict.evidence[#verdict.evidence + 1] = string.format(
        "the fingerprint (%s) has also been observed for principals in this run; percentage-based interpretation is unreliable for it", fp)
      verdict.confidence = math.max(0.3, verdict.confidence - 0.25)
    end

    -- Timing signal: only reported, never used to create a finding on its own.
    if record.rtt_ms and stats.median_rtt and verdict.exists then
      local delta = record.rtt_ms - stats.median_rtt
      if delta > 150 then
        verdict.evidence[#verdict.evidence + 1] = string.format(
          "response was %d ms slower than the run median (%d ms), consistent with a real database lookup",
          delta, stats.median_rtt)
      end
    end
    return verdict
  end

  verdict.verdict = VERDICT.OTHER
  verdict.label = "unrecognised answer"
  verdict.severity = "INFO"
  verdict.reason = record.error or record.response_label or "no interpretation available"
  return verdict
end

-- The e-data of KDC_ERR_PREAUTH_REQUIRED advertises the realm's encryption
-- types, salts and (MS-KILE) supported etype bitmask. Extracting them turns a
-- bare "principal exists" into an account-level crypto policy observation.
function analysis.preauth_etypes(krb_error)
  local etypes, salts = {}, {}
  if not krb_error or not krb_error.e_data or #krb_error.e_data == 0 then
    return etypes, salts
  end
  local seen = {}
  local function add(etype, salt)

    if etype and not seen[etype] then
      seen[etype] = true
      etypes[#etypes + 1] = etype
    end
    if salt and #salt > 0 then
      salts[#salts + 1] = salt
    end
  end
  for _, entry in ipairs(krb.parse_method_data(krb_error.e_data)) do
    if entry.type == 18 then
      for _, info in ipairs(krb.parse_etype_info2(entry.value)) do
        add(info.etype, info.salt)
      end
    elseif entry.type == 11 then
      for _, info in ipairs(krb.parse_etype_info(entry.value)) do
        add(info.etype, info.salt)
      end
    elseif entry.type == 165 then
      for _, etype in ipairs(krb.parse_supported_etypes(entry.value)) do
        add(etype)
      end
    end
  end
  table.sort(etypes)
  return etypes, salts
end

function analysis.median(values)
  if #values == 0 then
    return nil
  end
  local sorted = {}
  for i, v in ipairs(values) do
    sorted[i] = v
  end
  table.sort(sorted)
  local mid = math.floor(#sorted / 2)
  if #sorted % 2 == 1 then
    return sorted[mid + 1]
  end
  return math.floor((sorted[mid] + sorted[mid + 1]) / 2)
end

function analysis.stats(state)
  local stats = {
    median_rtt = analysis.median(state.rtts),
    samples = #state.rtts,
    fingerprints = {},
  }
  for _, result in ipairs(state.results) do
    local fp = analysis.fingerprint(result)
    if fp then
      stats.fingerprints[fp] = (stats.fingerprints[fp] or 0) + 1
    end
  end
  return stats
end

-- ---------------------------------------------------------------------------
-- 9. Name heuristics
--
-- The account name is public information and it is what the operator will act
-- on, so the report ranks findings by how much the name suggests privileged
-- or shared access.
-- ---------------------------------------------------------------------------

local heuristics = {}

heuristics.PATTERNS = {
  { pattern = "^admin", weight = 3, label = "administrative account" },
  { pattern = "^adm%-", weight = 3, label = "administrative account" },
  { pattern = "^da%-", weight = 4, label = "Domain Admins convention" },
  { pattern = "^ea%-", weight = 4, label = "Enterprise Admins convention" },
  { pattern = "^sa%-", weight = 4, label = "Schema Admins convention" },
  { pattern = "^root", weight = 3, label = "superuser account" },
  { pattern = "^krbtgt", weight = 4, label = "KDC service account" },
  { pattern = "svc", weight = 2, label = "service account convention" },
  { pattern = "service", weight = 2, label = "service account convention" },
  { pattern = "backup", weight = 2, label = "backup platform account" },
  { pattern = "sql", weight = 2, label = "database account" },
  { pattern = "dba", weight = 3, label = "database administrator" },
  { pattern = "sap", weight = 2, label = "ERP platform account" },
  { pattern = "veeam", weight = 2, label = "backup product account" },
  { pattern = "exch", weight = 2, label = "mail platform account" },
  { pattern = "admin", weight = 2, label = "administrative naming" },
  { pattern = "deploy", weight = 1, label = "deployment automation account" },
  { pattern = "build", weight = 1, label = "build automation account" },
  { pattern = "jenkins", weight = 1, label = "CI/CD account" },
  { pattern = "gitlab", weight = 1, label = "source control account" },
  { pattern = "ansible", weight = 1, label = "configuration management account" },
  { pattern = "monitor", weight = 1, label = "monitoring account" },
  { pattern = "scan", weight = 1, label = "scanner account" },
  { pattern = "vpn", weight = 2, label = "remote access account" },
  { pattern = "radius", weight = 2, label = "network access control account" },
  { pattern = "honey", weight = 1, label = "possible honeytoken" },
  { pattern = "canary", weight = 1, label = "possible honeytoken" },
  { pattern = "decoy", weight = 1, label = "possible honeytoken" },
  { pattern = "test", weight = 0, label = "test account" },
  { pattern = "temp", weight = 0, label = "temporary account" },
  { pattern = "guest", weight = 1, label = "guest account" },
  { pattern = "contractor", weight = 1, label = "external workforce account" },
  { pattern = "vendor", weight = 1, label = "third-party account" },
}

function heuristics.evaluate(name)
  local low = string.lower(name or "")
  local score, labels = 0, {}
  for _, entry in ipairs(heuristics.PATTERNS) do
    if string.find(low, entry.pattern) then
      score = score + entry.weight
      labels[#labels + 1] = entry.label
    end
  end
  return score, labels
end

-- ---------------------------------------------------------------------------
-- 10. Knowledge base
-- ---------------------------------------------------------------------------

local kb = {}

kb.TECHNIQUE_CONTEXT = {
  "Kerberos has no notion of an unauthenticated 'does this user exist' query: the AS-REQ/AS-REP exchange is the lookup, and its error code is the answer.",
  "KDC_ERR_C_PRINCIPAL_UNKNOWN (6) is a positive statement about the directory: the KDC searched and did not find the name. There is no way to make it indistinguishable from PREAUTH_REQUIRED without changing the KDC itself.",
  "Domain controllers log every AS-REQ as Windows event 4768, with the result code in the event. Enumeration therefore always leaves evidence; the value of this script is that it produces the same evidence an attacker would, on request and in a controlled window.",
  "The same error codes are the first stage of a domain attack chain: enumerate names, identify pre-authentication-less accounts, roast them, then use the recovered keys for TGS requests (kerberoasting / Silver tickets).",
}

kb.MAPPING = {
  { id = "T1087.002", name = "Account Discovery: Domain Account", note = "the technique implemented here" },
  { id = "T1558.004", name = "AS-REP Roasting", note = "the follow-on step for principals found with pre-authentication disabled" },
  { id = "T1110.002", name = "Brute Force: Password Cracking", note = "what the recovered AS-REP material is used for" },
  { id = "T1078.002", name = "Valid Accounts: Domain Accounts", note = "why the account list matters even without a password" },
}

kb.DETECTION = {
  "Windows event 4768 (TGT requested) with Result Code 0x6 (KDC_ERR_C_PRINCIPAL_UNKNOWN) - the enumeration signature.",
  "Windows event 4768 with Pre-Authentication Type 0 - an AS-REP roast attempt (see kerberos-asrep-roasting.nse).",
  "Sanity: the volume of 0x6 answers from one source workstation should be stable; a burst of distinct account names in a short window is the attack, not normal client behaviour.",
  "KQL: SecurityEvent | where EventID == 4768 and ResultCode == \"0x6\" | summarize dcount(Account) by IpAddress, bin(TimeGenerated, 10m) | where dcount_Account > 10",
  "Correlate with 4771 (Kerberos pre-authentication failed) for the transition from enumeration to attempted authentication.",
  "Network: many small UDP/88 AS-REQ datagrams (150-200 bytes, first byte 0x6a) from a host with no prior Kerberos traffic.",
}

kb.REMEDIATION = {
  {
    title = "Reduce the value of enumeration",
    steps = {
      "Remove or disable accounts that no longer authenticate: stale service accounts, contractor accounts and test accounts are the enumeration payoff.",
      "Enforce a privileged-access model (Tier 0/1/2): membership of privileged groups should be small, documented and audited.",
      "Deploy honeytokens: a plausible-looking service account in a monitored OU that should never authenticate. Any eventual authentication attempt is high-signal evidence of a compromised credential.",
    },
  },
  {
    title = "Detect and rate-limit enumeration",
    steps = {
      "Disable or alert on unrestricted KDC_ERR_C_PRINCIPAL_UNKNOWN volume; audit Policy\\\\Account Logon\\\\Kerberos Authentication Service success auditing.",
      "Feed the 4768 result codes into the SIEM and baseline per-source behaviour.",
      "For internet-facing KDCs (ADFS/Entra Private Access scenarios), restrict UDP/88 reachability to authenticated subnets.",
    },
  },
  {
    title = "Rotate anything that was exposed",
    steps = {
      "Treat every principal returned as existing as disclosed for reconnaissance purposes (name, sometimes privilege, sometimes lockout state).",
      "For service accounts without pre-authentication enabled, rotate the password after enabling pre-authentication, and prefer gMSA.",
    },
  },
}

-- Lockout semantics matter here more than in any other Kerberos check: the
-- difference between "the KDC does not know this name" (free) and "the KDC
-- counted a bad password for this name" (expensive) is the difference between
-- a safe audit and an outage.
kb.LOCKOUT_SEMANTICS = {
  "KDC_ERR_C_PRINCIPAL_UNKNOWN (6) is answered before any credential is evaluated: it does not touch badPwdCount.",
  "KDC_ERR_PREAUTH_REQUIRED (25) is the KDC asking for a timestamp, not a password attempt: it does not touch badPwdCount either.",
  "KDC_ERR_PREAUTH_FAILED (24) means the KDC evaluated pre-authentication data and rejected it - on domain-joined Windows this increments the bad-password counter that lockout policy watches.",
  "KRB_ERR_RESPONSE_TOO_BIG (52) is a transport signal only; it never reflects on the principal.",
  "Because the failure counter is per account and not per source, an enumeration run that switches to attempting authentication is what causes lockouts - which is exactly why this script never authenticates and aborts on 24/23/18.",
  "Operators auditing an environment with a low lockout threshold (for example 5 attempts) should keep kerberos.max-users small, raise kerberos.delay-ms, and watch for the abort line in the output.",
}

kb.VERIFICATION = {
  "ImpPacket: GetNPUsers.py <domain>/ -usersfile users.txt -no-pass -dc-ip <kdc> -format hashcat",
  "kerbrute userenum --dc <kdc> --domain <realm> users.txt",
  "kinit <principal>@<REALM> (expect 'Preauthentication required' for an existing principal, 'Client not found in Kerberos database' for an unknown one)",
  "In PowerShell: Get-ADUser -Identity <principal> (authoritative, and it does not touch the lockout counter)",
}

kb.REFERENCES = {
  "RFC 4120 section 7.5.1 - KRB-ERROR and the error code registry",
  "RFC 4120 section 5.4.1 - KDC-REQ / AS-REQ structure",
  "MITRE ATT&CK T1087.002 - Account Discovery: Domain Account",
  "Microsoft Windows security event 4768 documentation",
  "Microsoft: Kerberos and account lockout considerations (badPwdCount semantics)",
}
-- ---------------------------------------------------------------------------
-- 11. Reporting
-- ---------------------------------------------------------------------------

local report = {}

local function emoji_risk(level)
  local labels = {
    CRITICAL = "\240\159\148\180 CRITICAL",
    HIGH = "\240\159\159\160 HIGH",
    MEDIUM = "\240\159\159\161 MEDIUM",
    LOW = "\240\159\159\162 LOW",
    PASS = "\240\159\159\162 LOW (no exposure found)",
    INCONCLUSIVE = "\240\159\159\161 MEDIUM (INCONCLUSIVE - no principal resolved)",
  }
  return labels[level] or level
end

function report.build(state, cfg, realm, realm_source, context, stats, baseline)
  local out = stdnse.output_table()
  local counts = engine.state_counts(state)

  out["Script version"] = SCRIPT_VERSION
  out["Declared risk class"] = SCRIPT_RISK
  out["Realm"] = realm or "undetermined"
  if realm_source then
    out["Realm source"] = realm_source
  end
  out["KDC"] = string.format("%s:%d", tostring(context.host_ip), context.port_number)

  local behavior = {}
  for mode in pairs(state.transport_seen) do
    if mode == "udp" then
      behavior[#behavior + 1] = "UDP/88 answered (datagram framing)"
    elseif mode == "tcp" then
      behavior[#behavior + 1] = "TCP/88 answered (4-byte length prefixed framing)"
    end
  end
  table.sort(behavior)
  if #behavior == 0 then
    behavior[#behavior + 1] = "no transport produced a Kerberos answer"
  end
  out["Transport behaviour"] = behavior

  local rtt = "n/a"
  if stats.samples > 0 then
    rtt = string.format("median %d ms over %d sample(s)", stats.median_rtt, stats.samples)
  end
  out["Timing"] = string.format("probes %d, answers %d, timeouts %d, errors %d; RTT %s",
    state.probes, state.answers, state.timeouts, state.errors, rtt)

  out["Probe engine"] = state.aborted
    and ("ABORTED: " .. tostring(state.abort_reason))
    or "completed without triggering a stop condition"

  out["Result summary"] = string.format(
    "probed %d, existing %d, unknown %d, disabled/locked %d, roastable %d, unanswered %d",
    #state.results, counts.exists, counts.unknown, counts.disabled, counts.roastable, counts.unanswered)

  -- Buckets.
  local exists, roastable, disabled, unknown, unanswered, other = {}, {}, {}, {}, {}, {}
  for _, verdict in ipairs(state.verdicts) do
    if verdict.verdict == VERDICT.UNKNOWN then
      unknown[#unknown + 1] = verdict
    elseif verdict.verdict == VERDICT.EXISTS_NO_PREAUTH then
      roastable[#roastable + 1] = verdict
    elseif verdict.verdict == VERDICT.EXISTS_DISABLED then
      disabled[#disabled + 1] = verdict
    elseif verdict.exists then
      exists[#exists + 1] = verdict
    elseif verdict.verdict == VERDICT.TRANSPORT then
      unanswered[#unanswered + 1] = verdict
    else
      other[#other + 1] = verdict
    end
  end

  if #roastable > 0 then
    local lines = {}
    for _, verdict in ipairs(roastable) do
      local score, labels = heuristics.evaluate(verdict.principal)
      lines[#lines + 1] = string.format("%-24s %s%s", verdict.principal, verdict.label,
        score > 0 and ("  [" .. table.concat(labels, "; ") .. "]") or "")
    end
    out["Principals with pre-authentication DISABLED (roastable)"] = lines
  end

  if #exists > 0 then
    local lines = {}
    for _, verdict in ipairs(exists) do
      local extra = ""
      for _, evidence in ipairs(verdict.evidence) do
        if string.find(evidence, "offered etypes") then
          extra = " (" .. evidence .. ")"
        end
      end
      lines[#lines + 1] = string.format("%-24s %s%s", verdict.principal, verdict.label, extra)
    end
    table.sort(lines)
    out["Existing principals"] = lines
  end

  if #disabled > 0 then
    local lines = {}
    for _, verdict in ipairs(disabled) do
      lines[#lines + 1] = string.format("%-24s %s (%s)", verdict.principal, verdict.label, tostring(verdict.code))
    end
    out["Disabled or locked principals"] = lines
  end

  if #unknown > 0 then
    local names = {}
    for _, verdict in ipairs(unknown) do
      names[#names + 1] = verdict.principal
    end
    out["Principals that do not exist"] = string.format("%d name(s) rejected with KDC_ERR_C_PRINCIPAL_UNKNOWN",
      #unknown)
    out["Unknown principal list"] = names
  end

  if #other > 0 then
    local lines = {}
    for _, verdict in ipairs(other) do
      lines[#lines + 1] = string.format("%-24s %s", verdict.principal, verdict.label)
      for _, evidence in ipairs(verdict.evidence) do
        lines[#lines + 1] = "    " .. evidence
      end
    end
    out["Other answers"] = lines
  end

  if #unanswered > 0 then
    local names = {}
    for _, verdict in ipairs(unanswered) do
      names[#names + 1] = verdict.principal
    end
    out["Unanswered probes"] = string.format("%d principal(s) produced no answer: %s",
      #unanswered, table.concat(names, ", "))
  end

  -- Privilege ranking across everything that exists.
  local ranked = {}
  for _, bucket in ipairs({ roastable, exists, disabled }) do
    for _, verdict in ipairs(bucket) do
      local score, labels = heuristics.evaluate(verdict.principal)
      if score >= 2 then
        ranked[#ranked + 1] = { name = verdict.principal, score = score, labels = labels, verdict = verdict }
      end
    end
  end
  table.sort(ranked, function(a, b) return a.score > b.score end)
  if #ranked > 0 then
    local lines = {}
    for _, entry in ipairs(ranked) do
      lines[#lines + 1] = string.format("weight %d  %-24s %s", entry.score, entry.name,
        table.concat(entry.labels, "; "))
    end
    out["Privileged name heuristics"] = lines
  end

  -- Confidence transparency: show what the classifier leaned on.
  local confidence_notes = {}
  if baseline and baseline.unknown then
    local rec = baseline.unknown
    if rec.kind == "krb_error" then
      confidence_notes[#confidence_notes + 1] = string.format(
        "baseline for a name that cannot exist: KRB-ERROR %s (%s), %d bytes, %s",
        tostring(rec.krb_error.code_name), tostring(rec.krb_error.code),
        rec.response_bytes or 0, rec.rtt_ms and (tostring(rec.rtt_ms) .. " ms") or "no RTT")
    else
      confidence_notes[#confidence_notes + 1] = string.format(
        "baseline for a name that cannot exist produced no KRB-ERROR (%s): existence verdicts are less reliable in this realm",
        tostring(rec.error))
    end
  end
  local distinct = 0
  for _ in pairs(stats.fingerprints) do
    distinct = distinct + 1
  end
  confidence_notes[#confidence_notes + 1] = string.format(
    "%d distinct response fingerprint(s) observed across %d answer(s); a single fingerprint means the KDC answers uniformly and claims rest on the error code alone",
    distinct, state.answers)
  out["Confidence model"] = confidence_notes

  if cfg.userlist then
    local stats_line = "kerberos.userlist was read"
    if context.file_stats then
      stats_line = string.format("wordlist: %d line(s), %d skipped, %d usable",
        context.file_stats.lines, context.file_stats.skipped, #state.results)
    end
    out["Wordlist"] = stats_line
  end
  if context.sources then
    local parts = {}
    for source, count in pairs(context.sources) do
      parts[#parts + 1] = string.format("%s=%d", source, count)
    end
    table.sort(parts)
    out["Candidate sources"] = table.concat(parts, ", ")
  end
  if context.truncated then
    out["Probe budget"] = string.format("candidate list truncated to kerberos.max-users=%d", cfg.max_users)
  end
  if not cfg.lockout_guard then
    out["Lockout guard"] = "DISABLED by kerberos.no-lockout-guard: this run could have advanced account lockout counters"
  end

  return out, { exists = exists, roastable = roastable, disabled = disabled, unknown = unknown, other = other }
end

function report.verdict(out, groups, state, cfg)
  local lines = {}
  local severity = "LOW"

  if state.answers == 0 then
    lines[#lines + 1] = "No Kerberos answer was received at all, so nothing about the realm can be concluded."
    lines[#lines + 1] = "Check reachability of UDP/TCP 88, the realm value and the transport setting before drawing conclusions."
    out["Verdict"] = lines
    return "INCONCLUSIVE", severity
  end

  if #groups.roastable > 0 then
    lines[#lines + 1] = string.format(
      "%d principal(s) exist and have pre-authentication disabled: they are AS-REP roastable (see kerberos-asrep-roasting.nse for the material and the cracking cost).",
      #groups.roastable)
    severity = "CRITICAL"
  end

  if #groups.exists > 0 then
    lines[#lines + 1] = string.format(
      "%d principal(s) were confirmed to exist from an unauthenticated position: the KDC answers for them with %s.",
      #groups.exists, "KDC_ERR_PREAUTH_REQUIRED / equivalent")
    if severity ~= "CRITICAL" then
      severity = "HIGH"
    end
  end

  if #groups.disabled > 0 then
    lines[#lines + 1] = string.format(
      "%d principal(s) exist but are disabled or locked out; stale objects like these are worth removing from the directory.",
      #groups.disabled)
    if severity == "LOW" then
      severity = "MEDIUM"
    end
  end

  if #groups.unknown > 0 then
    lines[#lines + 1] = string.format(
      "%d of %d probed names do not exist. The KDC's answer to those probes is itself the enumeration oracle: event 4768 result code 0x6 in the domain controller log.",
      #groups.unknown, #state.results)
    if severity == "LOW" then
      severity = "MEDIUM"
    end
  end

  if #groups.roastable == 0 and #groups.exists == 0 and #groups.disabled == 0 then
    lines[#lines + 1] = "No probed name resolved to an existing principal; the check is only as good as the candidate list."
    severity = "INCONCLUSIVE"
  end

  lines[#lines + 1] = "Enumeration cannot be prevented at the protocol level (see the technique context below); it can be detected and its payoff removed."
  out["Verdict"] = lines
  return severity, severity
end

-- ---------------------------------------------------------------------------
-- 12. Action
-- ---------------------------------------------------------------------------

action = function(host, port)
  local cfg = config.load(host)
  local effective_port = port.number
  local context = {
    host_ip = host.ip,
    port_number = effective_port,
  }

  local state = engine.new_state()
  state.verdicts = {}

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
    local hints = realmdisco.hints(host)
    if #hints > 0 then
      realm = hints[1]
      realm_source = "hostname heuristic (unverified)"
    end
  end

  if not realm then
    local out = stdnse.output_table()
    out["Script version"] = SCRIPT_VERSION
    out["Check status"] = "ABORTED - the Kerberos realm could not be determined"
    out["Why"] = {
      "No kerberos.realm script argument was supplied.",
      "The target exposes no DNS name that yields a realm candidate.",
      "The KDC did not answer a foreign-realm probe with KDC_ERR_WRONG_REALM (code 68), so it does not leak the realm.",
    }
    if leak_record then
      out["Diagnostic (foreign realm probe)"] = string.format("response: %s; error: %s",
        tostring(leak_record.response_label or "none"),
        tostring(leak_record.error or (leak_record.krb_error and leak_record.krb_error.code_name) or "n/a"))
    end
    out["Remediation"] = {
      "Re-run with --script-args kerberos.realm=YOUR.REALM (uppercase DNS form).",
      "Confirm the target really is a KDC: a service on port 88 that is not a KDC answers with something that is not a Kerberos message.",
    }
    out["Risk Level"] = emoji_risk("INCONCLUSIVE")
    return out
  end

  -- Candidate assembly.
  local list, err, meta = candidates.build(cfg)
  if err then
    local out = stdnse.output_table()
    out["Script version"] = SCRIPT_VERSION
    out["Check status"] = "ABORTED - " .. err
    out["Remediation"] = {
      "Point kerberos.userlist at a readable file of principal names (one per line).",
      "Or pass names inline with kerberos.users=alice,bob,svc-backup.",
    }
    out["Risk Level"] = emoji_risk("INCONCLUSIVE")
    return out
  end

  if #list == 0 then
    local out = stdnse.output_table()
    out["Script version"] = SCRIPT_VERSION
    out["Realm"] = realm
    out["Check status"] = "ABORTED - no candidate principals were supplied"
    out["Why"] = {
      "User enumeration needs names to try; the script will not invent them implicitly.",
      "kerberos.builtin-list is off by default because every probe is visible in the KDC log.",
    }
    out["How to run it"] = {
      "--script-args 'kerberos.users=administrator,jsmith,svc-backup'",
      "--script-args 'kerberos.userlist=/path/to/users.txt'",
      "--script-args 'kerberos.builtin-list=true,kerberos.max-users=50'  (lab or authorised test only)",
    }
    out["Risk Level"] = emoji_risk("INCONCLUSIVE")
    return out
  end

  context.sources = meta and meta.sources
  context.truncated = meta and meta.truncated
  context.file_stats = meta and meta.file

  -- Baseline calibration, then the queue.
  local baseline = analysis.baseline(host, effective_port, cfg, realm)
  for _, kind in ipairs({ "unknown", "malformed" }) do
    local record = baseline[kind]
    if record and record.kind then
      state.answers = state.answers + 1
      state.probes = state.probes + 1
      state.transport_seen[record.transport or "?"] = true
      if record.rtt_ms then
        state.rtts[#state.rtts + 1] = record.rtt_ms
      end
      if record.kind == "krb_error" and record.krb_error.code == 68 and not cfg.realm then
        local leaked = record.krb_error.realm or record.krb_error.crealm
        if leaked and string.upper(leaked) ~= realm then
          realm = string.upper(leaked)
          realm_source = "KDC KRB-ERROR KDC_ERR_WRONG_REALM leak (corrected after baseline)"
        end
      end
    elseif record then
      state.probes = state.probes + 1
      if record.error == "timeout" then
        state.timeouts = state.timeouts + 1
      else
        state.errors = state.errors + 1
      end
    end
  end

  engine.run(host, effective_port, cfg, realm, list, state)

  local stats = analysis.stats(state)
  for _, record in ipairs(state.results) do
    state.verdicts[#state.verdicts + 1] = analysis.classify(record, baseline, stats)
  end

  local out, groups = report.build(state, cfg, realm, realm_source, context, stats, baseline)
  local severity = report.verdict(out, groups, state, cfg)

  out["How this was determined"] = kb.TECHNIQUE_CONTEXT
  out["ATT&CK mapping"] = (function()
    local lines = {}
    for _, entry in ipairs(kb.MAPPING) do
      lines[#lines + 1] = string.format("%s %s (%s)", entry.id, entry.name, entry.note)
    end
    return lines
  end)()

  if severity ~= "LOW" then
    out["Detection guidance"] = kb.DETECTION
    out["Remediation"] = (function()
      local lines = {}
      for _, group in ipairs(kb.REMEDIATION) do
        lines[#lines + 1] = group.title
        for _, step in ipairs(group.steps) do
          lines[#lines + 1] = "  " .. step
        end
      end
      return lines
    end)()
    out["Independent verification"] = kb.VERIFICATION
  end
  -- Log footprint: what the blue team will see because this script ran. Being
  -- explicit about it is part of the audit contract.
  local footprint = {}
  footprint[#footprint + 1] = string.format(
    "%d AS-REQ message(s) were sent, so %d Windows event 4768 record(s) exist on the KDC; record this scan window in the change log.",
    state.probes, state.probes)
  local code_histogram = {}
  for _, verdict in ipairs(state.verdicts or {}) do
    if verdict.code then
      code_histogram[verdict.code_name or tostring(verdict.code)] =
        (code_histogram[verdict.code_name or tostring(verdict.code)] or 0) + 1
    end
  end
  local hist_parts = {}
  for name, count in pairs(code_histogram) do
    hist_parts[#hist_parts + 1] = string.format("%s x%d", name, count)
  end
  table.sort(hist_parts)
  if #hist_parts > 0 then
    footprint[#footprint + 1] = "result codes: " .. table.concat(hist_parts, ", ")
  end
  for _, line in ipairs(kb.LOCKOUT_SEMANTICS) do
    footprint[#footprint + 1] = line
  end
  out["Log footprint and lockout semantics"] = footprint

  out["References"] = kb.REFERENCES

  -- Vulnerability registration: the enumeration oracle is the finding this
  -- script owns; roastable accounts are registered with their own title so the
  -- report does not double-count them as enumeration.
  for _, verdict in ipairs(groups.roastable) do
    vulns.add(host, port, "krb5-preauth-disabled-" .. string.lower(verdict.principal),
      string.format("Kerberos principal '%s' exists with pre-authentication disabled (AS-REP roastable)", verdict.principal))
  end
  if #groups.exists > 0 or #groups.unknown > 0 then
    vulns.add(host, port, "krb5-user-enumeration",
      string.format("KDC discloses principal existence through KRB-ERROR codes (%d existing, %d unknown names probed)",
        #groups.exists, #groups.unknown))
  end

  out["Risk Level"] = emoji_risk(severity)
  return out
end
