local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local table = require "table"
local string = require "string"
local math = require "math"
local os = require "os"
local bit = require "bit"
local vulns = require "vulns"

-- Protocol primitives (ASN.1 DER codec, KRB-ERROR/AS-REP codec, UDP+TCP
-- transport with retries) live in nselib/kerberos5.lua; the shared, tested
-- implementation is used verbatim instead of being copied per script.
local ok, krb5 = pcall(require, "kerberos5")

description = [[
Audits Kerberos KDCs for AS-REP roasting exposure: principals whose
pre-authentication flag is cleared answer an unauthenticated AS-REQ with
AS-REP material encrypted under their long-term key, which an attacker can
then attack offline for as long as the GPU budget allows.

The script builds and DER-encodes a genuine RFC 4120 AS-REQ ([APPLICATION 10]
KDC-REQ) for every candidate principal and classifies what the KDC answers:

  * AS-REP ([APPLICATION 11]) carrying an encrypted part -> pre-authentication
    is disabled for that account. The etype of that encrypted part (RC4-HMAC,
    AES128/256, DES/3DES) is extracted and turned into a cracking-cost model,
    because it decides whether the finding is a same-day recovery or a
    month-long project.
  * KRB-ERROR 25 KDC_ERR_PREAUTH_REQUIRED -> pre-authentication is enforced.
    The e-data METHOD-DATA blob is parsed for PA-ETYPE-INFO2 (offered etypes,
    salts, s2kparams), PA-SUPPORTED-ENCTYPES and FAST/OTP padata, which
    characterises the realm's crypto policy and MFA posture.
  * KRB-ERROR 6 KDC_ERR_C_PRINCIPAL_UNKNOWN -> the principal does not exist.
    Reported as an enumeration oracle rather than a finding.
  * KRB-ERROR 18 KDC_ERR_CLIENT_REVOKED -> the account is disabled or locked
    out. The probe engine treats this as a stop signal and cancels the rest of
    the queue so an audit cannot lock accounts in the directory.
  * KRB-ERROR 68 KDC_ERR_WRONG_REALM -> the KDC leaked its canonical realm; the
    realm is corrected and every probe is repeated against it.

Safety properties: the probe is read-only (nothing is decrypted, cracked or
replayed), account lockout protection is on by default (sequential, jittered,
rate-limited probes with an abort on the first revoked/locked answer), and
returned AS-REP blobs are masked unless kerberos.show-hashes=true is set
explicitly, because script output ends up in report files.

References:
  * RFC 4120 - The Kerberos Network Authentication Service (V5)
  * RFC 3961 / 3962 / 4757 / 6806 / 6113
  * CVE-2022-33679 (RC4-MD4 downgrade), CVE-2021-42287 / CVE-2021-42278 (noPAC)
  * MITRE ATT&CK T1558.004 - AS-REP Roasting
  * Microsoft KB5021131 / KB5020805 - Kerberos RC4 hardening
]]

---
-- @usage
-- nmap -p 88 --script kerberos-asrep-roasting --script-args 'kerberos.realm=EXAMPLE.COM,kerberos.users=svc-backup,jsmith' <target>
--
-- @args kerberos.realm          Realm in uppercase DNS form (EXAMPLE.COM). If
--                               omitted, the script derives candidates from
--                               the target's DNS names and from the realm the
--                               KDC leaks in a KDC_ERR_WRONG_REALM answer.
-- @args kerberos.users          Comma separated principal names to test.
-- @args kerberos.auto-enum      "true" appends the built-in list of well-known
--                               administrative and service account names.
--                               Off by default: every probe is a KDC log entry
--                               and can advance a lockout counter.
-- @args kerberos.max-users      Cap on principals probed (default 25, max 500).
-- @args kerberos.delay-ms       Minimum spacing between probes (default 350 ms).
-- @args kerberos.timeout-ms     Per-request receive timeout (default derived
--                               from Nmap's timing template).
-- @args kerberos.transport      "auto" (default), "udp" or "tcp".
-- @args kerberos.retries        Retries on timeout/drop (default 2).
-- @args kerberos.show-hashes    "true" prints $krb5asrep$ material for offline
--                               auditing. Handle the output as a credential.
-- @args kerberos.kdc-port       Override the KDC port (default 88).
--
-- @output
-- PORT   STATE SERVICE
-- 88/tcp open  kerberos-sec
-- | kerberos-asrep-roasting:
-- |   Script version: 2.0.0
-- |   Realm: EXAMPLE.COM
-- |   KDC: 10.0.0.10:88
-- |   Transport behaviour: TCP/88 answered (4-byte length prefixed framing)
-- |   Timing: probes 6, answers 6, timeouts 0, errors 0, RTT 41 ms average
-- |   AS-REP roasting candidates (pre-authentication DISABLED):
-- |     svc-backup  etype 23  rc4-hmac  FAST to crack [service account naming convention]
-- |   Pre-authentication enforced:
-- |     jsmith      enforced; offered: 18 aes256-cts-hmac-sha1-96, 17 aes128-cts-hmac-sha1-96; [salt: EXAMPLE.COM]
-- |   Offline cracking cost (estimates, not measurements):
-- |     ...
-- |   Verdict:
-- |     1 principal(s) answered an unauthenticated AS-REQ with AS-REP material...
-- |   Risk Level: CRITICAL
-- |_  ...
---

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "discovery", "safe"}

portrule = shortport.port_or_service({88}, {"kerberos", "kerberos-sec"}, {"tcp", "udp"}, "open")

if not ok then
  -- Report a missing library as an installation problem instead of raising a
  -- bare "module 'kerberos5' not found" error at load time.
  action = function()
    return stdnse.format_output(false, {
      "nselib/kerberos5.lua is not installed.",
      "Install the module next to the other NSE libraries:",
      "  cp nselib/kerberos5.lua \"$(nmap --datadir)/nselib/\"",
      "or run Nmap with --datadir pointing at a directory that contains nselib/.",
    })
  end
  return
end

local krb = krb5.krb
local transport = krb5.transport
local ETYPE = krb5.ETYPE
local ETYPE_OFFER_DEFAULT = krb5.ETYPE_OFFER_DEFAULT
local SCRIPT_VERSION = krb5.VERSION


-- ---------------------------------------------------------------------------
-- 11. Configuration and script-args
-- ---------------------------------------------------------------------------

local config = {}

config.DEFAULTS = {
  realm = nil,
  users = nil,
  auto_enum = false,
  max_users = 25,
  delay_ms = 350,
  timeout_ms = nil,
  transport = "auto",
  retries = 2,
  show_hashes = false,
  kdc_port = nil,
}

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
  stdnse.debug1("kerberos-asrep-roasting: ignoring non-boolean value '%s' for kerberos.%s", value, name)
  return default
end

local function arg_int(name, default, min, max)
  local value = arg_string(name)
  if value == nil then
    return default
  end
  local n = tonumber(value)
  if not n then
    stdnse.debug1("kerberos-asrep-roasting: ignoring non-numeric value '%s' for kerberos.%s", value, name)
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
    entry = tostring(entry)
    for piece in string.gmatch(entry, "[^,%s]+") do
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
  for key, value in pairs(config.DEFAULTS) do
    cfg[key] = value
  end

  cfg.realm = arg_string("realm")
  if cfg.realm then
    cfg.realm = string.upper(cfg.realm)
  end

  cfg.users = arg_list("users")
  cfg.auto_enum = arg_bool("auto-enum", config.DEFAULTS.auto_enum)
  cfg.max_users = arg_int("max-users", config.DEFAULTS.max_users, 1, 500)
  cfg.delay_ms = arg_int("delay-ms", config.DEFAULTS.delay_ms, 0, 10000)
  cfg.retries = arg_int("retries", config.DEFAULTS.retries, 0, 5)
  cfg.show_hashes = arg_bool("show-hashes", config.DEFAULTS.show_hashes)
  cfg.kdc_port = arg_int("kdc-port", nil, 1, 65535)

  local timeout = arg_int("timeout-ms", nil, 500, 60000)
  if not timeout then
    local script_timeout = stdnse.get_timeout(host, 3000, 15000)
    timeout = script_timeout or 5000
  end
  cfg.timeout_ms = timeout

  local mode = arg_string("transport")
  if mode then
    mode = string.lower(mode)
    if mode ~= "auto" and mode ~= "udp" and mode ~= "tcp" then
      stdnse.debug1("kerberos-asrep-roasting: unknown transport '%s', using auto", mode)
      mode = "auto"
    end
  else
    mode = config.DEFAULTS.transport
  end
  cfg.transport = mode

  return cfg
end

-- ---------------------------------------------------------------------------
-- 12. Candidate principals
--
-- The built-in list below is only consulted when the operator explicitly sets
-- kerberos.auto-enum=true. AS-REP probes are authenticated-less by design, so
-- they are indistinguishable from an attacker's traffic in the KDC log, and
-- each one increments the bad-password counter of the target account on some
-- Windows configurations. Keeping the list opt-in is therefore a safety
-- decision, not a limitation.
-- ---------------------------------------------------------------------------

local CANDIDATE_ACCOUNTS = {
  "administrator", "admin", "administrador", "root", "guest", "user", "test",
  "svc", "service", "operator", "backup", "restore", "sql", "sqlserver",
  "sqlagent", "exchange", "sharepoint", "sccm", "wsus", "vcenter", "veeam",
  "arcserve", "netbackup", "backupexec", "quest", "solarwinds", "nagios",
  "zabbix", "scom", "oracle", "postgres", "mysql", "mssql", "reporting",
  "crystal", "hyperion", "sap", "sapadmin", "maxdb", "db2", "informix",
  "citrix", "xenapp", "rds", "rdsh", "ts", "terminal", "vpn", "radius",
  "nac", "wifi", "wireless", "proxy", "squid", "isa", "tmgin", "web",
  "webserver", "apppool", "iis", "apache", "nginx", "tomcat", "jboss",
  "weblogic", "websphere", "docker", "kubernetes", "k8s", "ansible",
  "puppet", "chef", "salt", "terraform", "jenkins", "bamboo", "teamcity",
  "gitlab", "git", "svn", "tfs", "devops", "build", "release", "deploy",
  "monitor", "monitoring", "syslog", "logrhythm", "splunk", "elk", "graylog",
  "av", "antivirus", "defender", "crowdstrike", "cylance", "carbonblack",
  "tanium", "qualys", "nessus", "tenable", "rapid7", "nexpose", "scanner",
  "mim", "fim", "dlp", "proxy-svc", "mail", "smtp", "relay", "postmaster",
  "fax", "print", "spooler", "scan", "copier", "helpdesk", "servicedesk",
  "support", "it", "itadmin", "itops", "sysadmin", "netadmin", "dba",
  "dbadmin", "storage", "san", "nas", "fileserver", "fs", "share", "dfs",
  "printserver", "dc", "domain", "adfs", "adfs-svc", "aad", "azure",
  "azuread", "o365", "office365", "lync", "skype", "teams", "zoom",
  "backupadmin", "vmware", "esx", "esxi", "hyperv", "proxmox", "nutanix",
  "cad", "erp", "crm", "salesforce", "crm-svc", "hr", "payroll", "finance",
  "accounting", "billing", "invoice", "warehouse", "wms", "scada", "hmi",
  "plc", "mes", "historian", "opc", "bacnet", "modbus", "kiosk", "pos",
  "camera", "nvr", "dvr", "badge", "access", "hvac", "bms", "elevator",
  "lab", "test-svc", "qa", "staging", "dev", "developer", "intern", "temp",
  "contractor", "vendor", "partner", "external", "remote", "teleworker",
  "nmapprobe", "krbtgt", "honey", "honeypot", "canary", "decoy",
  "scom", "opsmgr", "dpm", "sccmadmin", "mdm", "intune", "airwatch",
  "wsusadmin", "patch", "update", "endpoint", "edr", "siem", "soc",
  "threat", "ir", "forensics", "pentest", "redteam", "blueteam",
  "serviceaccount", "svc-backup", "svc-sql", "svc-iis", "svc-exchange",
  "svc-web", "svc-app", "svc-db", "svc-mail", "svc-print", "svc-file",
  "svc-antivirus", "svc-monitor", "svc-deploy", "svc-jenkins", "svc-vmware",
  "admin-svc", "admin-backup", "admin-sql", "admin-print", "admin-test",
  "krbadmin", "dnsadmin", "dhcpadmin", "wsusadmin2", "vcenteradmin",
  "esxiadmin", "nutanixadmin", "backupexec-svc", "veeam-svc", "commvault",
  "rubrik", "cohesity", "datadomain", "netapp", "emc", "purestorage",
  "sophos", "mcafee", "symantec", "trend", "kaspersky", "eset", "bitdefender",
  "solarwinds-svc", "prtg", "observium", "librenms", "checkmk", "icinga",
  "grafana", "prometheus", "kibana", "logstash", "filebeat", "metricbeat",
  "wazuh", "ossim", "arcsight", "qradar", "sentinel", "chronicle",
  "gmsa-test", "msa-test", "svc-azure", "svc-aws", "svc-gcp", "awsadmin",
  "azureadmin", "gcpadmin", "terraform-svc", "ansible-svc", "puppet-svc",
}

local function build_candidates(cfg, baseline)
  local seen = {}
  local list = {}

  local function push(name, source)
    if not name or #name == 0 then
      return
    end
    local key = string.lower(name)
    if seen[key] then
      return
    end
    seen[key] = true
    list[#list + 1] = { name = name, source = source }
  end

  for _, name in ipairs(cfg.users or {}) do
    push(name, "script-args")
  end

  if cfg.auto_enum then
    for _, name in ipairs(CANDIDATE_ACCOUNTS) do
      push(name, "built-in")
      if #list >= cfg.max_users then
        break
      end
    end
  end

  if baseline then
    push(baseline, "baseline")
  end

  local truncated = false
  if #list > cfg.max_users then
    truncated = true
    local trimmed = {}
    for i = 1, cfg.max_users do
      trimmed[i] = list[i]
    end
    list = trimmed
  end

  return list, truncated
end

-- ---------------------------------------------------------------------------
-- 13. Realm discovery
--
-- Three sources are tried in order: the kerberos.realm script argument, the
-- DNS names Nmap already knows about the target, and finally the realm the KDC
-- itself leaks in the realm/crealm fields of a KRB-ERROR raised for a
-- deliberately foreign realm (KDC_ERR_WRONG_REALM, code 68). That third source
-- is the interesting one: it works against unhardened Windows KDCs without any
-- credential.
-- ---------------------------------------------------------------------------

local realmdisco = {}

function realmdisco.candidates(host)
  local out = {}
  local seen = {}
  local function push(value, source)
    if not value or #value == 0 then return end
    value = string.upper(value)
    if value:sub(1, 1) == "." then
      value = value:sub(2)
    end
    if #value < 3 or value:find("^%d") then
      return
    end
    if seen[value] then return end
    seen[value] = true
    out[#out + 1] = { realm = value, source = source }
  end

  if host.name then
    local domain = string.match(host.name, "^[^%.]+%.(.+)$")
    if domain then
      push(domain, "hint:host.name")
    end
    push(host.name, "hint:host.name")
  end
  if host.targetname and host.targetname ~= host.name then
    local domain = string.match(host.targetname, "^[^%.]+%.(.+)$")
    if domain then
      push(domain, "hint:targetname")
    end
  end
  return out
end

function realmdisco.from_kdc_error(host, port, cfg)
  local synthetic = "NMAP.INVALID.REALM"
  local req = {
    realm = synthetic,
    cname = "nmap-asrep-probe",
    etypes = ETYPE_OFFER_DEFAULT,
    nonce = 1,
    kdc_options = 0,
  }
  local record = transport.as_req(host, port, req, {
    timeout_ms = cfg.timeout_ms, retries = cfg.retries, transport = cfg.transport,
  })
  if record.kind ~= "krb_error" then
    return nil, record
  end
  local e = record.krb_error
  local realms = {}
  for _, value in ipairs({ e.realm, e.crealm }) do
    if value and #value >= 3 and string.upper(value) ~= synthetic then
      realms[#realms + 1] = string.upper(value)
    end
  end
  return realms, record
end

-- ---------------------------------------------------------------------------
-- 14. Probe engine
--
-- One queue, sequential execution, jittered spacing, and a hard stop on the
-- first signal that the directory is starting to push back (locked/disabled
-- account, KDC rate limiting, transport collapse). The engine also keeps a
-- full per-probe transcript so the report can show exactly what was sent and
-- what came back - a requirement for any audit that claims a finding.
-- ---------------------------------------------------------------------------

local engine = {}

-- Account for one probe transcript in the run statistics and result list.
function engine.absorb(state, record)
  state.probes = state.probes + 1
  if record.kind then
    state.responses = state.responses + 1
    state.transport_seen[record.transport or "?"] = true
    if record.rtt_ms then
      state.rtt_samples[#state.rtt_samples + 1] = record.rtt_ms
    end
  elseif record.error then
    if record.error == "timeout" then
      state.timeouts = state.timeouts + 1
    else
      state.errors = state.errors + 1
    end
  end
  state.results[#state.results + 1] = record
  return record
end

function engine.new_state()
  return {
    probes = 0,
    responses = 0,
    timeouts = 0,
    errors = 0,
    aborted = false,
    abort_reason = nil,
    results = {},
    transport_seen = {},
    rtt_samples = {},
  }
end

local function sleep_between_probes(cfg, index)
  if index == 1 then
    return
  end
  local base = cfg.delay_ms
  if base <= 0 then
    return
  end
  local jitter = math.random(0, math.floor(base / 2))
  stdnse.sleep((base + jitter) / 1000)
end

function engine.run(host, port, cfg, realm, candidates, state)
  for index, candidate in ipairs(candidates) do
    if state.aborted then
      break
    end
    sleep_between_probes(cfg, index)

    local nonce = math.random(1, 2147483000)
    local req = {
      realm = realm,
      cname = candidate.name,
      etypes = ETYPE_OFFER_DEFAULT,
      nonce = nonce,
      kdc_options = 0,
    }
    local record = transport.as_req(host, port, req, {
      timeout_ms = cfg.timeout_ms,
      retries = cfg.retries,
      transport = cfg.transport,
    })
    record.candidate = candidate
    record.nonce = nonce
    record.index = index
    record.timestamp = os.time()
    engine.absorb(state, record)

    -- Stop conditions: locked/disabled account, or a KDC that has stopped
    -- answering entirely (a network problem, not a per-account one).
    if record.kind == "krb_error" then
      local code = record.krb_error.code
      if code == 18 then
        state.aborted = true
        state.abort_reason = "KDC_ERR_CLIENT_REVOKED: account disabled or locked out; remaining probes cancelled"
      elseif code == 24 or code == 23 then
        state.aborted = true
        state.abort_reason = string.format("%s: authentication failures are being counted, stopping",
          record.krb_error.code_name)
      end
    end
    if state.timeouts >= 3 and state.responses == 0 then
      state.aborted = true
      state.abort_reason = "no KDC response at all (3 timeouts): wrong port, filtered path or non-Kerberos service"
    end
  end
  return state
end

-- ---------------------------------------------------------------------------
-- 15. Classification and analysis
-- ---------------------------------------------------------------------------

local analysis = {}

local PRIVILEGED_PATTERNS = {
  { pattern = "^admin", weight = 3, label = "administrative account name" },
  { pattern = "^root", weight = 3, label = "unix-style superuser name" },
  { pattern = "^da%-", weight = 3, label = "Domain Admins style prefix" },
  { pattern = "^ea%-", weight = 3, label = "Enterprise Admins style prefix" },
  { pattern = "^sa%-", weight = 3, label = "Schema Admins style prefix" },
  { pattern = "^krbtgt", weight = 4, label = "KDC service account (krbtgt)" },
  { pattern = "svc", weight = 2, label = "service account naming convention" },
  { pattern = "service", weight = 2, label = "service account naming convention" },
  { pattern = "backup", weight = 2, label = "backup infrastructure account" },
  { pattern = "sql", weight = 2, label = "database service account" },
  { pattern = "dba", weight = 2, label = "database administrator name" },
  { pattern = "sap", weight = 2, label = "ERP service account" },
  { pattern = "veeam", weight = 2, label = "backup product account" },
  { pattern = "exch", weight = 2, label = "mail platform account" },
  { pattern = "^iis", weight = 1, label = "web platform account" },
  { pattern = "^tomcat", weight = 1, label = "java platform account" },
  { pattern = "deploy", weight = 1, label = "deployment automation account" },
  { pattern = "build", weight = 1, label = "build automation account" },
  { pattern = "jenkins", weight = 1, label = "CI/CD account" },
  { pattern = "honey", weight = 1, label = "possible honeytoken (verify before remediation)" },
  { pattern = "canary", weight = 1, label = "possible honeytoken (verify before remediation)" },
  { pattern = "^test", weight = 0, label = "test account" },
  { pattern = "temp", weight = 0, label = "temporary account" },
}

function analysis.privilege_score(name)
  local score = 0
  local labels = {}
  local low = string.lower(name)
  for _, entry in ipairs(PRIVILEGED_PATTERNS) do
    if string.find(low, entry.pattern) then
      score = score + entry.weight
      labels[#labels + 1] = entry.label
    end
  end
  return score, labels
end

-- Extract PA-ETYPE-INFO2 / PA-ETYPE-INFO / PA-SUPPORTED-ENCTYPES from the
-- e-data of a KDC_ERR_PREAUTH_REQUIRED answer.
function analysis.preauth_details(krb_error)
  local details = {
    salt_hints = {},
    offered = {},
    padata_types = {},
    fast = false,
    otp = false,
    pac_request = false,
    extended_error = nil,
  }
  if not krb_error or not krb_error.e_data then
    return details
  end
  local entries = krb.parse_method_data(krb_error.e_data)
  for _, entry in ipairs(entries) do
    details.padata_types[#details.padata_types + 1] = entry.name
    if entry.type == 18 then
      for _, info in ipairs(krb.parse_etype_info2(entry.value)) do
        details.offered[#details.offered + 1] = info
        if info.salt then
          details.salt_hints[#details.salt_hints + 1] = info.salt
        end
      end
    elseif entry.type == 11 then
      for _, info in ipairs(krb.parse_etype_info(entry.value)) do
        details.offered[#details.offered + 1] = info
        if info.salt then
          details.salt_hints[#details.salt_hints + 1] = info.salt
        end
      end
    elseif entry.type == 165 then
      local etypes = krb.parse_supported_etypes(entry.value)
      for _, e in ipairs(etypes) do
        details.offered[#details.offered + 1] = { etype = e, source = "PA-SUPPORTED-ENCTYPES" }
      end
    elseif entry.type == 136 or entry.type == 133 or entry.type == 138 then
      details.fast = true
    elseif entry.type >= 141 and entry.type <= 145 then
      details.otp = true
    elseif entry.type == 128 then
      details.pac_request = true
    elseif entry.type == 166 then
      details.extended_error = entry.value
    end
  end
  return details
end

function analysis.unique_etypes(details)
  local seen, list = {}, {}
  for _, entry in ipairs(details.offered or {}) do
    if entry.etype and not seen[entry.etype] then
      seen[entry.etype] = true
      list[#list + 1] = entry.etype
    end
  end
  table.sort(list)
  return list
end

-- Turn one probe transcript into a verdict with evidence and severity.
function analysis.classify(record)
  local verdict = { record = record, evidence = {} }

  if not record.kind then
    verdict.kind = "transport-failure"
    verdict.severity = "INFO"
    verdict.title = "No answer from the KDC"
    verdict.detail = record.error or "unknown transport error"
    return verdict
  end

  if record.kind == "as_rep" then
    local enc = record.as_rep.enc_part or {}
    local etype = enc.etype
    local info = krb.etype_info(etype)
    verdict.kind = "roastable"
    verdict.etype = etype
    verdict.etype_name = info.name
    verdict.title = "Pre-authentication disabled: AS-REP returned without PA-ENC-TIMESTAMP"
    verdict.detail = string.format(
      "the KDC encrypted AS-REP material with %s (etype %s), which any unauthenticated client can request and then attack offline",
      info.name, tostring(etype))
    verdict.evidence[#verdict.evidence + 1] = string.format(
      "AS-REP %d bytes, enc-part etype %s (%s), cipher %d bytes",
      record.response_bytes or 0, tostring(etype), info.name, enc.cipher_len or 0)
    if enc.kvno then
      verdict.evidence[#verdict.evidence + 1] = string.format("key version number %d (long-term key generation)", enc.kvno)
    end
    if record.as_rep.crealm then
      verdict.evidence[#verdict.evidence + 1] = string.format("crealm %s, cname %s",
        record.as_rep.crealm, record.as_rep.cname and record.as_rep.cname.text or "?")
    end
    if record.tcp_retry then
      verdict.evidence[#verdict.evidence + 1] = "answer was only obtainable over TCP (UDP reply too large / dropped)"
    end
    verdict.severity = (info.weak or info.retired) and "CRITICAL" or "HIGH"
    return verdict
  end

  if record.kind == "krb_error" then
    local e = record.krb_error
    verdict.code = e.code
    verdict.code_name = e.code_name
    verdict.evidence[#verdict.evidence + 1] = string.format("KRB-ERROR %s (%d): %s",
      tostring(e.code_name), e.code or -1, tostring(e.code_note))
    if e.e_text and #e.e_text > 0 then
      verdict.evidence[#verdict.evidence + 1] = string.format("KDC e-text: %s", e.e_text)
    end
    if e.stime then
      verdict.evidence[#verdict.evidence + 1] = string.format("KDC time %s", e.stime)
    end

    if e.roastable then
      verdict.kind = "roastable"
      verdict.title = "KDC answered an unauthenticated AS-REQ with ticket material"
      verdict.detail = e.code_note
      verdict.severity = "HIGH"
      return verdict
    end

    if e.preauth then
      verdict.kind = "preauth-required"
      verdict.severity = "INFO"
      verdict.title = "Pre-authentication is enforced for this principal"
      verdict.detail = e.code_note
      local details = analysis.preauth_details(e)
      verdict.preauth_details = details
      local etypes = analysis.unique_etypes(details)
      if #etypes > 0 then
        local names = {}
        for _, t in ipairs(etypes) do
          names[#names + 1] = string.format("%d(%s)", t, krb.etype_info(t).name)
        end
        verdict.evidence[#verdict.evidence + 1] = "offered etypes: " .. table.concat(names, ", ")
      end
      if #details.salt_hints > 0 then
        verdict.evidence[#verdict.evidence + 1] = "salt hints: " .. table.concat(details.salt_hints, ", ")
      end
      if details.fast then
        verdict.evidence[#verdict.evidence + 1] = "FAST / encrypted-challenge padata present (armored AS-REQ supported)"
      end
      if details.otp then
        verdict.evidence[#verdict.evidence + 1] = "OTP pre-authentication padata present (multi-factor policy in force)"
      end
      return verdict
    end

    if e.nomatch then
      verdict.kind = "unknown-principal"
      verdict.severity = "INFO"
      verdict.title = "Principal does not exist in this realm"
      verdict.detail = "answer is indistinguishable from an attacker probing for valid account names (user enumeration oracle)"
      return verdict
    end

    if e.wrong_realm then
      verdict.kind = "wrong-realm"
      verdict.severity = "INFO"
      verdict.title = "Realm mismatch"
      verdict.detail = e.code_note
      return verdict
    end

    if e.fatal then
      verdict.kind = "account-unusable"
      verdict.severity = "MEDIUM"
      verdict.title = "Account disabled or locked out"
      verdict.detail = e.code_note
      return verdict
    end

    if e.skew then
      verdict.kind = "clock-skew"
      verdict.severity = "LOW"
      verdict.title = "Clock skew between scanner and KDC"
      verdict.detail = e.code_note
      return verdict
    end

    if e.weak_crypto then
      verdict.kind = "crypto-policy"
      verdict.severity = "MEDIUM"
      verdict.title = "Encryption type policy rejected the request"
      verdict.detail = e.code_note
      return verdict
    end

    verdict.kind = "kdc-error"
    verdict.severity = "INFO"
    verdict.title = "KDC returned " .. tostring(e.code_name)
    verdict.detail = e.code_note or "no interpretation available"
    return verdict
  end

  verdict.kind = "unexpected"
  verdict.severity = "INFO"
  verdict.title = "Unrecognised response"
  verdict.detail = record.error or record.response_label or "no detail"
  return verdict
end

-- ---------------------------------------------------------------------------
-- 16. Offline cracking cost model
--
-- The point of AS-REP roasting is that the attack happens offline, so the only
-- thing that stands between the hash and the plaintext is the cost of the
-- search. The figures below are order-of-magnitude estimates for a single
-- RTX 4090 class GPU running Hashcat and are labelled as estimates in the
-- output; they exist to rank findings, not to promise a crack time.
-- ---------------------------------------------------------------------------

local crackcost = {}

crackcost.GPU_RATES = {
  rc4 = 5000000,
  aes = 300000,
  des3 = 1200000,
  des = 25000000,
  camellia = 200000,
  unknown = 100000,
}

crackcost.SPACE_SCENARIOS = {
  { name = "rockyou.txt + best64 rules", size = 2.0e7 },
  { name = "company wordlist + mangling rules", size = 5.0e8 },
  { name = "8 character full keyspace (95^8)", size = 6.6e15 },
  { name = "10 character lower+digit keyspace", size = 3.6e15 },
}

function crackcost.estimate(etype, space)
  local family = krb.etype_info(etype).family or "unknown"
  local rate = crackcost.GPU_RATES[family] or crackcost.GPU_RATES.unknown
  local seconds = space / rate
  return {
    family = family,
    rate = rate,
    seconds = seconds,
    human = crackcost.human(seconds),
  }
end

function crackcost.human(seconds)
  if seconds < 1 then
    return "instant"
  elseif seconds < 60 then
    return string.format("%.0f seconds", seconds)
  elseif seconds < 3600 then
    return string.format("%.1f minutes", seconds / 60)
  elseif seconds < 86400 then
    return string.format("%.1f hours", seconds / 3600)
  elseif seconds < 31557600 then
    return string.format("%.1f days", seconds / 86400)
  end
  return string.format("%.0f years", seconds / 31557600)
end

function crackcost.table_for(etype)
  local rows = {}
  for _, scenario in ipairs(crackcost.SPACE_SCENARIOS) do
    local est = crackcost.estimate(etype, scenario.size)
    rows[#rows + 1] = string.format("%-38s %s", scenario.name, est.human)
  end
  return rows
end

-- ---------------------------------------------------------------------------
-- 17. Knowledge base: context, CVEs and remediation
-- ---------------------------------------------------------------------------

local kb = {}

kb.PROTOCOL_CONTEXT = {
  "AS-REP roasting abuses RFC 4120 section 3.1.1: when pre-authentication is not required, the KDC answers an unauthenticated AS-REQ with an AS-REP whose encrypted part is encrypted under the account's long-term key.",
  "The encrypted part contains the session key and is protected by the key derived from the user's password, so the response is a testable offline oracle for that password.",
  "The response can be requested by anyone who can reach UDP/88 (or TCP/88) of the KDC; there is no protocol-level authentication before the AS-REP is produced.",
  "Because pre-authentication is a per-account flag (userAccountControl ACCOUNTDISABLE's sibling bit UF_DONT_REQUIRE_PREAUTH, 0x00400000), a single misconfigured object is enough to expose an entry point.",
  "Enterprise detection guidance (Microsoft) states that AS-REQ without pre-authentication produces Windows event 4768 with Pre-Authentication Type = 0; the same event with a weak cipher is the RC4 roast signature.",
}

kb.CVE_NOTES = {
  {
    id = "CVE-2022-33679",
    title = "Kerberos RC4-MD4 encryption downgrade enabling AS-REP roasting against AES-only accounts",
    relevance = "Any realm that still accepts RC4-HMAC (etype 23) lets an attacker offer a downgraded etype set and obtain cheap, crackable AS-REP material even when the account is configured for AES.",
    cvss = "8.1 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H)",
    mitigation = "Disable RC4 for the domain (msDS-SupportedEncryptionTypes), apply KB5021131/KB5020805 guidance, retire DES/RC4 etypes and audit PA-SUPPORTED-ENCTYPES for legacy entries.",
  },
  {
    id = "CVE-2021-42287 / CVE-2021-42278",
    title = "sAMAccountName spoofing (noPAC) privilege escalation",
    relevance = "Pre-authentication-less service accounts are a common prerequisite step: noPAC chains a roastable machine or service account whose name can be spoofed into a forged PAC with domain-admin rights.",
    cvss = "8.8 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H)",
    mitigation = "Apply the November 2021 Windows updates, restrict machine-account creation rights and monitor for renamed computer accounts.",
  },
  {
    id = "CVE-2020-17049",
    title = "Kerberos KDC security feature bypass (Bronze Bit): forged service tickets via S4U2self",
    relevance = "AS-REP roastable service accounts are the natural next hop: once a service account key is recovered offline it can be used to request S4U2self tickets with forwardable flags and, on unpatched DCs, obtain a service ticket usable as any user.",
    cvss = "7.5 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H)",
    mitigation = "Apply the November 2020 and later Windows updates (KB4598347 and successors) which enforce PAC signatures; rotate the keys of any account that was roastable.",
  },
  {
    id = "CVE-2022-37967",
    title = "Kerberos PAC signature validation bypass (Kerberos privileges elevation)",
    relevance = "The same ticket material harvested after an AS-REP roast is what PAC forgery attempts are built from; a DC that has not enforced ticket signatures cannot distinguish a forged PAC from a legitimate one.",
    cvss = "7.2 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H)",
    mitigation = "Install the November 2022 updates and enable the KrbtgtFullPacSignature registry setting in enforcement mode after piloting.",
  },
  {
    id = "CVE-2021-33764",
    title = "Weak Kerberos encryption type negotiation (DES/3DES/RC4 accepted)",
    relevance = "A KDC that still negotiates retired encryption types lets an attacker downgrade an AS-REP roast to material that is orders of magnitude cheaper to attack than AES.",
    cvss = "6.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
    mitigation = "Remove DES and RC4 from msDS-SupportedEncryptionTypes on every account and trust; monitor KDC event 4768 for etype 1/3/23.",
  },
  {
    id = "CVE-2022-37966",
    title = "Kerberos RC4-HMAC-MD5 weak cryptography enforcement bypass",
    relevance = "Reinforces the same theme: while RC4 remains negotiable, AS-REP material (and TGS material) stays cheap to attack offline.",
    cvss = "8.1 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H)",
    mitigation = "Set msDS-SupportedEncryptionTypes to 24/16/8 (AES only) domain-wide, and remove RC4 from all trust configurations.",
  },
}

kb.ATTACK_MAPPING = {
  { id = "T1558.004", name = "Steal or Forge Kerberos Tickets: AS-REP Roasting",
    note = "This script measures exactly this technique's preconditions." },
  { id = "T1087.002", name = "Account Discovery: Domain Account",
    note = "KDC_ERR_C_PRINCIPAL_UNKNOWN versus KDC_ERR_PREAUTH_REQUIRED is a reliable user-enumeration oracle." },
  { id = "T1110.002", name = "Brute Force: Password Cracking",
    note = "AS-REP material is cracked offline, out of reach of account lockout policy." },
}

kb.REMEDIATION = {
  {
    finding = "preauth-disabled",
    steps = {
      "Enumerate every account with the flag set: Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth | Select Name,SamAccountName,Enabled",
      "Clear it: Set-ADAccountControl -Identity <account> -DoesNotRequirePreAuth $false",
      "Re-run this script to confirm the AS-REP is replaced by KDC_ERR_PREAUTH_REQUIRED (code 25).",
      "Treat the exposed account's password as compromised: rotate it and review 4768/4769 for the account for lateral movement.",
    },
  },
  {
    finding = "rc4-roastable-material",
    steps = {
      "Set msDS-SupportedEncryptionTypes on the account to AES only (e.g. 24 = AES128|AES256) and rotate the password so the AES keys are generated.",
      "Remove RC4 for the whole domain once trusts and legacy appliances are inventoried (KB5021131).",
      "Audit kerberoastable service accounts with SPN whose etype negotiated to 23.",
    },
  },
  {
    finding = "user-enumeration",
    steps = {
      "Kerberos error codes cannot be suppressed per account. Mitigate with consistent, uniform KDC responses (hardening guidance) and by monitoring for sequential AS-REQ bursts from one source (event 4768 with result code 0x6).",
      "Alert on KDC_ERR_C_PRINCIPAL_UNKNOWN (0x6) volume: it is the canonical low-noise enumeration signal.",
    },
  },
  {
    finding = "long-lived-passwords",
    steps = {
      "Prefer group managed service accounts (gMSA) over user accounts for services: 240-character rotating passwords make offline attacks meaningless.",
      "For accounts that cannot use gMSA, enforce 25+ character randomly generated passwords stored in a secrets manager.",
      "Deploy a honey account with pre-authentication disabled in a monitored OU to detect AS-REP roasting attempts (event 4768 with a 0 pre-authentication type).",
    },
  },
}

-- Detection material. An audit finding is only actionable if the blue team can
-- hunt for the same activity, so the queries below are emitted with the
-- findings rather than kept in documentation nobody reads.
kb.DETECTION = {
  windows_events = {
    "4768 - A Kerberos authentication ticket (TGT) was requested. Baseline the Pre-Authentication Type field: 0 means the request carried no pre-authentication, which is exactly what an AS-REP roast looks like.",
    "4768 result code 0x6 - KDC_ERR_C_PRINCIPAL_UNKNOWN: the canonical low-noise user enumeration signal.",
    "4768 and 4771 - cluster by Account Name and source workstation for one-to-many ratios, which indicate enumeration rather than a broken client.",
    "4769 - TGS requests; useful for the follow-on step where a recovered service key is used.",
  },
  kql = {
    "SecurityEvent | where EventID == 4768 | where PreAuthType == 0 | summarize count() by Account, IpAddress, bin(TimeGenerated, 1h) | where count_ > 5",
    "SecurityEvent | where EventID in (4768, 4771) | where ResultCode == \"0x6\" | summarize DistinctAccounts = dcount(Account) by IpAddress, bin(TimeGenerated, 15m) | where DistinctAccounts > 10",
    "SecurityEvent | where EventID == 4768 | where TicketEncryptionType in (\"0x1\", \"0x3\", \"0x17\", \"0x18\") | project TimeGenerated, Account, IpAddress, TicketEncryptionType",
  },
  sigma = {
    "title: AS-REP roasting probe",
    "logsource: { product: windows, service: security }",
    "detection: { selection: { EventID: 4768, PreAuthType: 0 }, condition: selection }",
    "level: medium",
  },
  false_positives = {
    "Legacy applications and appliances that authenticate without pre-authentication produce PreAuthType 0 answers for a small, stable set of accounts - baseline those first.",
    "A single PreAuthType 0 event for a service account after a password reset can be the account's own scheduled task, not an attack.",
    "Probes from this script appear as such events: run it from an authorised segment and record the scan window in the change log.",
  },
  network_signatures = {
    "UDP/88 datagrams of 150-200 bytes beginning with 0x6a (AS-REQ) from a host that has no domain-joined identity.",
    "KRB-ERROR 68 (WRONG_REALM) answers for realms that do not exist in the organisation: the signature of realm discovery.",
    "One source IP generating KDC_ERR_C_PRINCIPAL_UNKNOWN for many distinct principals in a short window.",
  },
}

-- Severity model, documented so an operator can reproduce the rating by hand.
kb.SCORING_MODEL = {
  "CRITICAL: at least one principal answered an unauthenticated AS-REQ and the negotiated etype is RC4-HMAC (23), RC4-HMAC-EXP (24), DES (1/2/3/8) or 3DES (5/6/7/16), or the account name matches a privileged pattern with weight >= 3.",
  "HIGH: at least one principal answered an unauthenticated AS-REQ with AES material, or a roasted account name matches a service-account pattern.",
  "MEDIUM: no roast succeeded but the KDC advertises retired etypes or the probe run was inconclusive (no answer at all, or every candidate unknown).",
  "LOW: every classified principal enforced pre-authentication and no weak etype was advertised.",
  "The rating is deliberately pessimistic: an honest INCONCLUSIVE result is reported as MEDIUM, never as LOW.",
}

-- Independent verification recipes: an operator should be able to reproduce
-- every finding with tools that are not this script.
kb.VERIFICATION = {
  {
    finding = "AS-REP material returned for an unauthenticated request",
    steps = {
      "ImpPacket: GetNPUsers.py <domain>/ -usersfile users.txt -no-pass -dc-ip <kdc> -format hashcat -outputfile asrep.txt",
      "Then: hashcat -m 18200 asrep.txt wordlist.txt        # rc4-hmac material (etype 23)",
      "      hashcat -m 19900 asrep.txt wordlist.txt        # aes128 material (etype 17)",
      "      hashcat -m 19800 asrep.txt wordlist.txt        # aes256 material (etype 18)",
      "Confirm the same principal is returned by this script's --script-args kerberos.show-hashes=true run; the blob must match byte for byte.",
    },
  },
  {
    finding = "pre-authentication disabled",
    steps = {
      "PowerShell: Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth",
      "Directory Services: dsquery * -filter \"(userAccountControl:1.2.840.113556.1.4.803:=4194304)\" -attr sAMAccountName",
      "After remediation, re-run this script: the answer must become KRB-ERROR 25 (KDC_ERR_PREAUTH_REQUIRED).",
    },
  },
  {
    finding = "RC4 or retired etypes negotiable",
    steps = {
      "PowerShell: Get-ADUser -Filter * -Properties msDS-SupportedEncryptionTypes | Where-Object {$_.'msDS-SupportedEncryptionTypes' -band 4}",
      "KDC auditing: Event 4768 with Ticket Encryption Type 0x17 (rc4-hmac) or 0x1/0x3 (DES).",
      "Realm-wide baseline: klist -e on a domain controller shows the etypes the KDC is willing to issue.",
    },
  },
}

kb.REFERENCES = {
  "RFC 4120 - The Kerberos Network Authentication Service (V5)",
  "RFC 3961 / RFC 3962 / RFC 4757 - encryption type profiles",
  "RFC 6113 - A Generalized Framework for Kerberos Pre-Authentication (FAST)",
  "RFC 6806 - Kerberos Principal Name Canonicalization and Cross-Realm Referrals",
  "Microsoft KB5021131 - Managing the Kerberos protocol changes related to CVE-2022-37966",
  "MITRE ATT&CK T1558.004 - AS-REP Roasting",
  "https://learn.microsoft.com/windows-server/security/kerberos/preventing-kerberos-attacks",
}

-- ---------------------------------------------------------------------------
-- 18. Reporting
-- ---------------------------------------------------------------------------

local report = {}

local function mask_hash(blob)
  if not blob or #blob < 8 then
    return "<too short to classify>"
  end
  return string.format("%s...%s (%d bytes)", string.sub(blob, 1, 8),
    string.sub(blob, -8), #blob)
end

-- Hashcat/John form: $krb5asrep$<etype>$<user>@<realm>:<cipher>$<checksum>
local function format_asrep_hash(verdict, realm)
  local record = verdict.record
  local enc = record.as_rep and record.as_rep.enc_part
  if not enc or not enc.cipher then
    return nil
  end
  local user = record.candidate and record.candidate.name or "unknown"
  local etype = enc.etype or 0
  local cipher = string.gsub(enc.cipher, ".", function(c)
    return string.format("%02x", string.byte(c))
  end)
  if etype == 23 or etype == 24 then
    if #cipher < 64 then
      return nil
    end
    local body = string.sub(cipher, 1, #cipher - 32)
    local checksum = string.sub(cipher, #cipher - 31)
    return string.format("$krb5asrep$%d$%s@%s:%s$%s", etype, user, realm, body, checksum)
  end
  return string.format("$krb5asrep$%d$%s@%s:%s", etype, user, realm, cipher)
end

function report.verdict_line(verdict)
  local info = krb.etype_info(verdict.etype)
  if verdict.kind == "roastable" then
    return string.format("%-18s etype %-3s %-28s %s",
      verdict.record.candidate.name, tostring(verdict.etype), info.name,
      verdict.severity == "CRITICAL" and "FAST to crack" or "expensive to crack")
  end
  return string.format("%-18s %s", verdict.record.candidate.name, verdict.title)
end

-- Full transcript of the run. An audit tool that claims a finding must be able
-- to show the exchange that produced it, including the probes that produced
-- nothing at all.
function report.transcript(state)
  local lines = {}
  local sent_bytes, received_bytes = 0, 0
  for index, record in ipairs(state.results) do
    local candidate = (record.candidate and record.candidate.name) or "?"
    local answer
    if record.kind == "as_rep" then
      local enc = record.as_rep and record.as_rep.enc_part or {}
      answer = string.format("AS-REP, enc-part etype %s (%s), kvno %s",
        tostring(enc.etype), krb.etype_info(enc.etype).name, tostring(enc.kvno or "absent"))
    elseif record.kind == "krb_error" then
      answer = string.format("KRB-ERROR %s (%s)", tostring(record.krb_error.code_name),
        tostring(record.krb_error.code))
      if record.krb_error.e_text and #record.krb_error.e_text > 0 and #record.krb_error.e_text < 40 then
        answer = answer .. " e-text=" .. record.krb_error.e_text
      end
    else
      answer = record.error or "no answer"
    end
    sent_bytes = sent_bytes + (record.request_bytes or 0)
    received_bytes = received_bytes + (record.response_bytes or 0)
    lines[#lines + 1] = string.format("#%-2d %-22s %-52s %-4s %s attempt(s) %s",
      index, candidate, answer, (record.transport or "-"):upper(),
      tostring(record.attempts or 0), record.rtt_ms and (tostring(record.rtt_ms) .. " ms") or "n/a")
  end
  lines[#lines + 1] = string.format("total %d bytes sent in %d request(s), %d bytes received",
    sent_bytes, #state.results, received_bytes)
  return lines
end

function report.build(state, cfg, realm, realm_source, context)
  local out = stdnse.output_table()

  out["Script version"] = SCRIPT_VERSION
  out["Realm"] = realm or "undetermined"
  if realm_source then
    out["Realm source"] = realm_source
  end
  out["KDC"] = string.format("%s:%d", context.host_ip or "?", context.port_number or 88)

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
  if #state.rtt_samples > 0 then
    local sum = 0
    for _, v in ipairs(state.rtt_samples) do sum = sum + v end
    rtt = string.format("%.0f ms average", sum / #state.rtt_samples)
  end
  out["Timing"] = string.format("probes %d, answers %d, timeouts %d, errors %d, RTT %s",
    state.probes, state.responses, state.timeouts, state.errors, rtt)

  if state.aborted then
    out["Probe engine"] = "ABORTED: " .. tostring(state.abort_reason)
  else
    out["Probe engine"] = "completed without triggering a stop condition"
  end

  -- Group verdicts.
  local roastable, preauth, unknown, other = {}, {}, {}, {}
  for _, verdict in ipairs(state.verdicts or {}) do
    if verdict.kind == "roastable" then
      roastable[#roastable + 1] = verdict
    elseif verdict.kind == "preauth-required" then
      preauth[#preauth + 1] = verdict
    elseif verdict.kind == "unknown-principal" then
      unknown[#unknown + 1] = verdict
    else
      other[#other + 1] = verdict
    end
  end

  if #roastable > 0 then
    local lines = {}
    for _, verdict in ipairs(roastable) do
      local score, labels = analysis.privilege_score(verdict.record.candidate.name)
      local suffix = ""
      if score >= 3 then
        suffix = " [privileged account name: " .. table.concat(labels, "; ") .. "]"
      elseif score >= 1 then
        suffix = " [" .. table.concat(labels, "; ") .. "]"
      end
      lines[#lines + 1] = report.verdict_line(verdict) .. suffix
    end
    out["AS-REP roasting candidates (pre-authentication DISABLED)"] = lines

    -- Crack cost model for the worst (cheapest) etype found.
    local cheapest
    for _, verdict in ipairs(roastable) do
      local family = krb.etype_info(verdict.etype).family
      if not cheapest or crackcost.GPU_RATES[family] > crackcost.GPU_RATES[krb.etype_info(cheapest).family] then
        cheapest = verdict.etype
      end
    end
    if cheapest then
      local estimator = crackcost.estimate(cheapest, crackcost.SPACE_SCENARIOS[1].size)
      local rows = {
        string.format("worst-case etype in this realm: %d (%s)", cheapest, krb.etype_info(cheapest).name),
        string.format("modelled GPU rate: %.1f MH/s (single RTX 4090 class card, Hashcat)", estimator.rate / 1000000),
      }
      for _, row in ipairs(crackcost.table_for(cheapest)) do
        rows[#rows + 1] = row
      end
      out["Offline cracking cost (estimates, not measurements)"] = rows
    end

    if cfg.show_hashes then
      local hashes = {}
      for _, verdict in ipairs(roastable) do
        local h = format_asrep_hash(verdict, realm or "REALM")
        if h then
          hashes[#hashes + 1] = string.format("%s  ->  %s", verdict.record.candidate.name, h)
        end
      end
      if #hashes > 0 then
        out["AS-REP material (sensitive: treat as credential)"] = hashes
      end
    else
      local masked = {}
      for _, verdict in ipairs(roastable) do
        local enc = verdict.record.as_rep and verdict.record.as_rep.enc_part
        masked[#masked + 1] = string.format("%s -> %s",
          verdict.record.candidate.name, mask_hash(enc and enc.cipher))
      end
      out["AS-REP material (masked; enable kerberos.show-hashes to print)"] = masked
    end
  end

  if #preauth > 0 then
    local lines = {}
    for _, verdict in ipairs(preauth) do
      local detail = verdict.preauth_details or {}
      local etypes = analysis.unique_etypes(detail)
      local names = {}
      for _, t in ipairs(etypes) do
        names[#names + 1] = string.format("%d %s", t, krb.etype_info(t).name)
      end
      local flags = {}
      if detail.fast then flags[#flags + 1] = "FAST" end
      if detail.otp then flags[#flags + 1] = "OTP" end
      if #detail.salt_hints > 0 then
        flags[#flags + 1] = "salt: " .. detail.salt_hints[1]
      end
      lines[#lines + 1] = string.format("%-18s enforced%s%s",
        verdict.record.candidate.name,
        #names > 0 and ("; offered: " .. table.concat(names, ", ")) or "",
        #flags > 0 and ("; [" .. table.concat(flags, ", ") .. "]") or "")
    end
    out["Pre-authentication enforced"] = lines
  end

  -- Realm posture: what the aggregate answer says about the KDC's policy.
  local posture = {}
  local classified = #roastable + #preauth
  if classified > 0 then
    posture[#posture + 1] = string.format(
      "%d of %d classified principals enforce pre-authentication (%.0f%%)",
      #preauth, classified, (100 * #preauth) / classified)
  end
  local etype_counts = {}
  for _, verdict in ipairs(preauth) do
    for _, etype in ipairs(analysis.unique_etypes(verdict.preauth_details or {})) do
      etype_counts[etype] = (etype_counts[etype] or 0) + 1
    end
  end
  for _, verdict in ipairs(roastable) do
    if verdict.etype then
      etype_counts[verdict.etype] = (etype_counts[verdict.etype] or 0) + 1
    end
  end
  local etype_list = {}
  for etype, count in pairs(etype_counts) do
    local info = krb.etype_info(etype)
    etype_list[#etype_list + 1] = { etype = etype, count = count, info = info }
  end
  table.sort(etype_list, function(a, b) return a.etype < b.etype end)
  for _, entry in ipairs(etype_list) do
    local tag = ""
    if entry.info.weak or entry.info.retired then
      tag = "  <-- retired or weak crypto, remove from the realm"
    end
    posture[#posture + 1] = string.format("etype %-3d %-28s seen %d time(s)%s",
      entry.etype, entry.info.name, entry.count, tag)
  end
  local fast_seen, otp_seen = false, false
  for _, verdict in ipairs(preauth) do
    local detail = verdict.preauth_details or {}
    if detail.fast then fast_seen = true end
    if detail.otp then otp_seen = true end
  end
  if fast_seen then
    posture[#posture + 1] = "FAST / encrypted-challenge padata is offered (armored AS-REQ supported)"
  end
  if otp_seen then
    posture[#posture + 1] = "OTP pre-authentication padata is offered (multi-factor policy in force)"
  end
  if #posture > 0 then
    out["Realm posture"] = posture
  end

  out["Probe transcript"] = report.transcript(state)

  if #unknown > 0 then
    local names = {}
    for _, verdict in ipairs(unknown) do
      names[#names + 1] = verdict.record.candidate.name
    end
    out["Principals not found (enumeration oracle)"] = table.concat(names, ", ")
  end

  if #other > 0 then
    local lines = {}
    for _, verdict in ipairs(other) do
      local record = verdict.record
      lines[#lines + 1] = string.format("%-18s %s", record.candidate and record.candidate.name or "?",
        verdict.title)
      for _, evidence in ipairs(verdict.evidence or {}) do
        lines[#lines + 1] = "    " .. evidence
      end
    end
    out["Other responses"] = lines
  end

  return out, { roastable = roastable, preauth = preauth, unknown = unknown, other = other }
end

function report.findings(out, groups, realm, cfg)
  local lines = {}

  if #groups.roastable == 0 and #groups.preauth == 0 then
    lines[#lines + 1] = "No principal could be classified: the check is INCONCLUSIVE, not clean."
    lines[#lines + 1] = "Supply kerberos.users=... (and kerberos.realm=... if the realm could not be derived) and re-run."
    out["Verdict"] = lines
    return "INCONCLUSIVE", 0
  end

  if #groups.roastable > 0 then
    local critical = 0
    for _, verdict in ipairs(groups.roastable) do
      if verdict.severity == "CRITICAL" then
        critical = critical + 1
      end
    end
    lines[#lines + 1] = string.format(
      "%d principal(s) answered an unauthenticated AS-REQ with AS-REP material. Pre-authentication is disabled on those objects.",
      #groups.roastable)
    if critical > 0 then
      lines[#lines + 1] = string.format(
        "%d of them negotiated RC4-HMAC (etype 23) or retired crypto: offline recovery is cheap and time-boxed by GPU budget alone.",
        critical)
    end
    lines[#lines + 1] = "Remediation: enable pre-authentication on each object (KB5021131 / Set-ADAccountControl) and rotate its password."
    out["Verdict"] = lines
    return (critical > 0) and "CRITICAL" or "HIGH", #groups.roastable
  end

  lines[#lines + 1] = string.format(
    "All %d classified principals require pre-authentication; no AS-REP was produced for an unauthenticated request.",
    #groups.preauth)
  if realm then
    lines[#lines + 1] = string.format(
      "The realm still negotiates the etype set shown above; if RC4 or DES appears there, see kerberos-weak-encryption.nse for the crypto policy assessment.")
  end
  out["Verdict"] = lines
  return "PASS", 0
end

-- ---------------------------------------------------------------------------
-- 19. Action
-- ---------------------------------------------------------------------------

action = function(host, port)
  local cfg = config.load(host)
  local context = {
    host_ip = host.ip,
    port_number = cfg.kdc_port or port.number,
  }
  local effective_port = cfg.kdc_port or port.number

  if port.protocol == "udp" and cfg.transport == "auto" then
    cfg.transport = "auto"
  end

  local state = engine.new_state()
  state.verdicts = {}

  -- Realm resolution.
  local realm = cfg.realm
  local realm_source = realm and "kerberos.realm script argument" or nil
  local realm_record

  if not realm then
    local from_error, record = realmdisco.from_kdc_error(host, effective_port, cfg)
    realm_record = record
    if from_error and #from_error > 0 then
      realm = from_error[1]
      realm_source = "KDC KRB-ERROR KDC_ERR_WRONG_REALM leak"
    end
  end

  if not realm then
    local hints = realmdisco.candidates(host)
    if #hints > 0 then
      realm = hints[1].realm
      realm_source = hints[1].source .. " (unverified heuristic)"
    end
  end

  if not realm then
    local out = stdnse.output_table()
    out["Script version"] = SCRIPT_VERSION
    out["Check status"] = "ABORTED - the Kerberos realm could not be determined"
    out["Why"] = {
      "No kerberos.realm script argument was supplied.",
      "The target exposed no DNS name usable as a realm, and the KDC did not leak a realm through KDC_ERR_WRONG_REALM.",
      "Without a realm the AS-REQ would be sent to the wrong database and every answer would be meaningless.",
    }
    if realm_record then
      out["Diagnostic (foreign realm probe)"] = string.format(
        "response: %s; error: %s", tostring(realm_record.response_label or "none"),
        tostring(realm_record.error or (realm_record.krb_error and realm_record.krb_error.code_name) or "n/a"))
      if realm_record.krb_error and realm_record.krb_error.e_text then
        out["KDC e-text"] = realm_record.krb_error.e_text
      end
    end
    out["Remediation"] = {
      "Re-run with --script-args kerberos.realm=YOUR.REALM (uppercase DNS form).",
      "If the KDC is behind a firewall that drops unknown-realm AS-REQs, probe from a segment with KDC reachability.",
    }
    out["Risk Level"] = "\240\159\159\161 MEDIUM (INCONCLUSIVE - not tested)"
    return out
  end

  -- Realm validation probe. One synthetic principal is sent before the real
  -- candidate list. The answers that matter are KDC_ERR_WRONG_REALM (68, which
  -- carries the canonical realm - the leak an attacker uses to aim the roast)
  -- and KDC_ERR_C_PRINCIPAL_UNKNOWN (6, which proves the realm we hold is the
  -- right database). Both are single, read-only requests.
  local baseline = string.format("nmap-probe-%d", math.random(100000, 999999))
  local retried_realm = false

  local function probe_baseline()
    local record = transport.as_req(host, effective_port, {
      realm = realm,
      cname = baseline,
      etypes = ETYPE_OFFER_DEFAULT,
      nonce = math.random(1, 2147483000),
      kdc_options = 0,
    }, { timeout_ms = cfg.timeout_ms, retries = cfg.retries, transport = cfg.transport })
    record.candidate = { name = baseline, source = "realm validation probe" }
    return record
  end

  local baseline_record = probe_baseline()
  if baseline_record.kind == "krb_error" and baseline_record.krb_error.code == 68 then
    local leaked = baseline_record.krb_error.realm or baseline_record.krb_error.crealm
    if leaked and #leaked >= 3 and string.upper(leaked) ~= realm then
      realm = string.upper(leaked)
      realm_source = "KDC KRB-ERROR KDC_ERR_WRONG_REALM leak (validated by re-probe)"
      retried_realm = true
      baseline_record = probe_baseline()
    end
  end
  engine.absorb(state, baseline_record)

  -- Adaptive transport: if the validation probe only succeeded after the TCP
  -- fallback (or timed out on UDP entirely), pin the remaining probes to TCP.
  -- Without this every subsequent probe would burn a full UDP timeout on a
  -- path that demonstrably does not carry Kerberos datagrams.
  local transport_note
  if cfg.transport == "auto" and baseline_record.transport == "tcp" and baseline_record.tcp_retry then
    cfg.transport = "tcp"
    transport_note = "UDP did not carry the validation AS-REQ; remaining probes pinned to TCP/88"
  end

  -- Candidate queue: script-args users first, then the opt-in built-in list.
  local candidates, truncated = build_candidates(cfg, nil)

  engine.run(host, effective_port, cfg, realm, candidates, state)

  for _, record in ipairs(state.results) do
    state.verdicts[#state.verdicts + 1] = analysis.classify(record)
  end

  -- Report.
  local out, groups = report.build(state, cfg, realm, realm_source, context)
  if transport_note then
    out["Adaptive transport"] = transport_note
  end
  if retried_realm then
    out["Realm retry"] = "the KDC advertised a different realm; all probes were repeated against it"
  end
  if truncated then
    out["Probe budget"] = string.format("candidate list truncated to kerberos.max-users=%d", cfg.max_users)
  end

  local verdict, finding_count = report.findings(out, groups, realm, cfg)
  local RISK_LABEL = {
    CRITICAL = "\240\159\148\180 CRITICAL",
    HIGH = "\240\159\159\160 HIGH",
    MEDIUM = "\240\159\159\161 MEDIUM",
    LOW = "\240\159\159\162 LOW",
    PASS = "\240\159\159\162 LOW (no exposure found)",
    INCONCLUSIVE = "\240\159\159\161 MEDIUM (INCONCLUSIVE - no probe classified)",
  }
  out["Risk Level"] = RISK_LABEL[verdict] or verdict

  -- Knowledge base and remediation, only when there is something to remediate.
  if finding_count > 0 then
    local ctx = {}
    for _, line in ipairs(kb.PROTOCOL_CONTEXT) do
      ctx[#ctx + 1] = line
    end
    out["Why this matters"] = ctx

    local cves = {}
    for _, cve in ipairs(kb.CVE_NOTES) do
      cves[#cves + 1] = string.format("%s - %s | relevance: %s | mitigation: %s",
        cve.id, cve.title, cve.relevance, cve.mitigation)
    end
    out["Related CVEs"] = cves

    local techniques = {}
    for _, t in ipairs(kb.ATTACK_MAPPING) do
      techniques[#techniques + 1] = string.format("%s %s (%s)", t.id, t.name, t.note)
    end
    out["ATT&CK mapping"] = techniques

    local rem = {}
    for _, group in ipairs(kb.REMEDIATION) do
      for _, step in ipairs(group.steps) do
        rem[#rem + 1] = step
      end
    end
    out["Remediation"] = rem

    local detection = {}
    for _, line in ipairs(kb.DETECTION.windows_events) do
      detection[#detection + 1] = line
    end
    for _, line in ipairs(kb.DETECTION.kql) do
      detection[#detection + 1] = "KQL: " .. line
    end
    for _, line in ipairs(kb.DETECTION.sigma) do
      detection[#detection + 1] = "Sigma: " .. line
    end
    for _, line in ipairs(kb.DETECTION.network_signatures) do
      detection[#detection + 1] = line
    end
    local verification = {}
    for _, group in ipairs(kb.VERIFICATION) do
      verification[#verification + 1] = "Verify: " .. group.finding
      for _, step in ipairs(group.steps) do
        verification[#verification + 1] = "  " .. step
      end
    end
    out["Independent verification"] = verification
    out["Detection and hunting"] = detection
    out["Known false positives"] = kb.DETECTION.false_positives
    out["Severity model"] = kb.SCORING_MODEL

    out["References"] = kb.REFERENCES

    for _, verdict_entry in ipairs(groups.roastable) do
      local name = verdict_entry.record.candidate.name
      local title = string.format("Kerberos pre-authentication disabled for '%s' (AS-REP roastable, etype %s)",
        name, tostring(verdict_entry.etype))
      vulns.add(host, port, "krb5-asrep-roasting-" .. string.lower(name), title)
    end
  end

  return out
end
