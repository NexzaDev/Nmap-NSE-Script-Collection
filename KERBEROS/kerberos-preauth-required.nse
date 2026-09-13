local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local string = require "string"
local table = require "table"
local math = require "math"
local io = require "io"

-- Message construction and transport come from the shared Kerberos engine.
local ok, krb5 = pcall(require, "kerberos5")

description = [[
Audits whether Kerberos pre-authentication is enforced for the accounts it is
given, and reports the policy coverage rather than a single verdict.

Pre-authentication is the step that proves a client knows the principal's key
before the KDC answers. Without it the KDC answers an AS-REQ for anyone who
asks, and the answer is encrypted with the account's key: the account can be
attacked offline with no interaction, which is what AS-REP roasting is. Active
Directory exposes the setting per account (the DONT_REQ_PREAUTH bit of
userAccountControl), so one misconfigured service account is enough.

The script sends one AS-REQ per account, deliberately without pre-authentication
data, and classifies the answer: an AS-REP means the account is exempt and
roastable, KDC_ERR_PREAUTH_REQUIRED means it is covered,
KDC_ERR_C_PRINCIPAL_UNKNOWN means the name does not exist - an observation about
the wordlist, not the policy - and KDC_ERR_CLIENT_REVOKED means it is disabled
or locked, which is reported separately and stops the run.

A KDC can be configured to answer uniformly, so the oracle is calibrated first
with a name that cannot exist. If the calibration answer matches the account
answers, the report says the realm does not disclose the difference instead of
claiming enforcement. The script is read-only; AS-REP material is reported as a
length and an encryption type unless kerberos.show-hashes=true is set on purpose.

References:
  * RFC 4120 section 5.4.1 - the AS-REQ and its optional padata sequence
  * RFC 4120 section 7.5.1 - KDC_ERR_PREAUTH_REQUIRED (25) and the error
    registry used for the classification
  * RFC 4120 section 5.2.7 - PA-ETYPE-INFO2 and the salt a guess would need
  * Microsoft, 'User Account Control and User Account Control attributes':
    the DONT_REQ_PREAUTH (0x00000040) bit of userAccountControl
]]

---
-- @usage
-- nmap -p 88 --script kerberos-preauth-required --script-args 'kerberos.realm=EXAMPLE.COM,kerberos.accounts=svc-backup,svc-sql' <target>
-- nmap -p 88 --script kerberos-preauth-required --script-args 'kerberos.realm=EXAMPLE.COM,kerberos.account-list=/tmp/accounts.txt' <target>
--
-- @args kerberos.realm          Realm in uppercase DNS form; discovered with a
--                               foreign realm probe when omitted.
-- @args kerberos.accounts       Comma separated account names to check.
-- @args kerberos.account-list   File with one account name per line; blank
--                               lines and lines starting with # are ignored.
-- @args kerberos.max-accounts   Cap on the accounts probed from any source
--                               (default 16, maximum 128).
-- @args kerberos.delay-ms       Spacing between AS-REQs (default 150 ms).
-- @args kerberos.stop-on-locked "true" (default) stops the run when the KDC
--                               reports a disabled or locked account.
-- @args kerberos.show-hashes    "true" prints the AS-REP material that is
--                               attacked offline; off by default.
-- @args kerberos.kdc-port       KDC port (default 88).
-- @args kerberos.timeout-ms     Per-request timeout, 500-60000.
-- @args kerberos.retries        Transport retries (default 1).
-- @args kerberos.transport      "auto" (default), "udp" or "tcp".
-- @args kerberos.verbose        "true" adds the per-account transcript.
--
-- @output
-- 88/tcp open  kerberos-sec
-- | kerberos-preauth-required:
-- |   Realm: EXAMPLE.COM
-- |   Policy coverage: 1 of 3 account(s) do not require pre-authentication
-- |     svc-backup   exempt    an AS-REP was issued without pre-authentication
-- |     svc-sql      covered   KDC_ERR_PREAUTH_REQUIRED
-- |   Findings: [1] MEDIUM (PREAUTH-NOT-REQUIRED) - 1 account(s) do not require
-- |_  Risk Level: MEDIUM
---

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(88, "kerberos-sec", {"tcp", "udp"})

local SCRIPT_RISK = "MEDIUM"
local SCRIPT_VERSION = "2.0.0"

if not ok or type(krb5) ~= "table" then
  action = function()
    return "\n  The Kerberos engine (nselib/kerberos5.lua) is not installed.\n"
      .. "  Install it next to this script and re-run the scan.\n"
  end
  return
end

local krb = krb5.krb
local transport = krb5.transport
local timeutil = krb5.timeutil
local NT = krb5.NT

-- 1. Knowledge base

local KB = {}

-- The positions an account can take with respect to the policy. The report
-- states them in one line; the classification itself is computed by
-- probe.classify, which keeps the raw answer next to every verdict.
-- Errors whose meaning is specific enough to report by name.
KB.ERROR_CLASS = {
  [6] = "unknown",
  [18] = "revoked",
  [12] = "policy",
  [14] = "inconclusive",
  [24] = "inconclusive",
  [25] = "covered",
  [68] = "inconclusive",
  [37] = "inconclusive",
}

KB.REMEDIATION = {
  { title = "Remove exemptions that are not needed",
    steps = {
      "Clear the flag on every account that does not need it: Set-ADAccountControl -Identity <account> -DoesNotRequirePreAuth $false.",
      "Find them from the directory, not from an audit: Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' -Properties DoesNotRequirePreAuth -SearchBase $domainDN.",
      "An exemption is a documented decision or a finding. Record the reason next to the account.",
    } },
  { title = "Make the remaining exemptions expensive to attack",
    steps = {
      "Give an exempt account a long random password: the attack is offline, so length is the only cost that scales.",
      "Rotate it on a schedule shorter than the time the material takes to crack, and treat each rotation as a retirement date for the exemption.",
      "Watch for the attack: event 4768 with pre-authentication type 0 for an account that normally uses 15 is the signature.",
    } },
  { title = "Keep the policy where clients cannot weaken it",
    steps = {
      "Do not rely on client settings: the account attribute is what the KDC enforces.",
      "Include the exemption list in the change review, so restoring an account from a template does not silently restore the exemption.",
      "After a migration or a forest consolidation, re-run this script: the flag travels with the account.",
    } },
}

KB.VERIFICATION = {
  "Confirm in the directory: Get-ADUser -Identity <account> -Properties DoesNotRequirePreAuth returns the effective flag, and the attribute view shows DONT_REQ_PREAUTH in userAccountControl.",
  "Confirm on the wire: a client that does not pre-authenticate receives an AS-REP without sending padata, which is the exchange this script performs.",
  "Confirm on the KDC: event 4768 records the pre-authentication type (0 means none was used, 15 means encrypted timestamp).",
}

KB.REFERENCES = {
  "RFC 4120 section 5.4.1 - the AS-REQ and the optional padata field",
  "RFC 4120 section 7.5.1 - KDC_ERR_PREAUTH_REQUIRED (25), KDC_ERR_C_PRINCIPAL_UNKNOWN (6) and KDC_ERR_CLIENT_REVOKED (18)",
  "RFC 4120 section 5.2.7 - PA-ETYPE-INFO2 and the salt a cracker needs",
  "Microsoft, 'User Account Control and User Account Control attributes' - the DONT_REQ_PREAUTH bit",
  "Microsoft, 'Audit Kerberos authentication': events 4768 and 4771 and the pre-authentication type field",
}

-- 2. Configuration

local config = {}

local function arg_string(name)
  local value = stdnse.get_script_args("kerberos." .. name)
  if value == nil then
    return nil
  end
  if type(value) == "table" then
    value = value[1]
  end
  value = tostring(value)
  if #value == 0 then
    return nil
  end
  return value
end

local function arg_int(name, default, minimum, maximum)
  local value = tonumber(arg_string(name))
  if value == nil then
    return default
  end
  value = math.floor(value)
  if value < minimum then
    return minimum
  end
  if value > maximum then
    return maximum
  end
  return value
end

local function arg_bool(name, default)
  local value = arg_string(name)
  if value == nil then
    return default
  end
  value = string.lower(value)
  if value == "true" or value == "yes" or value == "1" or value == "on" then
    return true
  end
  if value == "false" or value == "no" or value == "0" or value == "off" then
    return false
  end
  return default
end

function config.load(host)
  local cfg = {}
  cfg.realm = arg_string("realm")
  if cfg.realm then
    cfg.realm = string.upper(cfg.realm)
  end
  cfg.accounts = {}
  local listed = arg_string("accounts")
  if listed then
    for entry in string.gmatch(listed, "[^,%s]+") do
      cfg.accounts[#cfg.accounts + 1] = entry
    end
  end
  cfg.account_list = arg_string("account-list")
  cfg.account_list_file = arg_string("account-list-file")
  cfg.max_accounts = arg_int("max-accounts", 16, 1, 128)
  cfg.delay_ms = arg_int("delay-ms", 150, 0, 5000)
  cfg.stop_on_locked = arg_bool("stop-on-locked", true)
  cfg.show_hashes = arg_bool("show-hashes", false)
  cfg.kdc_port = arg_int("kdc-port", 88, 1, 65535)
  cfg.retries = arg_int("retries", 1, 0, 5)
  cfg.timeout_ms = arg_int("timeout-ms", nil, 500, 60000)
  if not cfg.timeout_ms then
    cfg.timeout_ms = stdnse.get_timeout(host, 3000, 10000) or 3000
  end
  local mode = arg_string("transport")
  if mode then
    mode = string.lower(mode)
    if mode ~= "udp" and mode ~= "tcp" then
      mode = "auto"
    end
  else
    mode = "auto"
  end
  cfg.transport = mode
  cfg.verbose = arg_bool("verbose", false)
  return cfg
end

-- 3. Account sources

local accounts = {}

-- The list is the union of the script arguments and an optional file, deduped
-- and capped. A file is read line by line so a large inventory does not have to
-- fit on a command line.
function accounts.load(cfg, host)
  local list = {}
  local seen = {}
  local sources = {}

  local function push(name, source)
    if name == nil then
      return
    end
    name = tostring(name)
    name = string.gsub(name, "^%s+", "")
    name = string.gsub(name, "%s+$", "")
    if #name == 0 or string.sub(name, 1, 1) == "#" then
      return
    end
    local key = string.lower(name)
    if seen[key] then
      return
    end
    seen[key] = true
    list[#list + 1] = { name = name, source = source }
  end

  for _, name in ipairs(cfg.accounts) do
    push(name, "kerberos.accounts script argument")
  end
  local path = cfg.account_list or cfg.account_list_file
  if path then
    local handle, open_err = io.open(path, "r")
    if handle then
      local count = 0
      for line in handle:lines() do
        count = count + 1
        push(line, "kerberos.account-list file")
      end
      handle:close()
      sources[#sources + 1] = string.format("%s (%d line(s))", path, count)
    else
      sources[#sources + 1] = string.format("%s could not be read (%s)", path, tostring(open_err))
    end
  end
  if #list == 0 then
    -- Without a list, the target's own short name is a reasonable single
    -- candidate, and the report says where it came from.
    local name = host.name or host.targetname
    if name then
      local short = string.match(name, "^([^%.]+)")
      if short then
        push(string.lower(short), "the target's own name")
      end
    end
  end
  local capped = {}
  for _, entry in ipairs(list) do
    if #capped < cfg.max_accounts then
      capped[#capped + 1] = entry
    end
  end
  return capped, sources
end

-- 4. Probing

local probe = {}

-- The probe request deliberately carries no padata: that is the whole point of
-- the check. A KDC that answers it with an AS-REP has issued a ticket without
-- asking for proof.
function probe.ask(host, port, cfg, realm_name, name)
  local record = transport.as_req(host, port, {
    realm = realm_name,
    cname = name,
    cname_type = NT.PRINCIPAL,
    etypes = { 23, 18, 17 },
    kdc_options = 0,
    till = timeutil.os_utc(3600),
    nonce = math.random(1, 2147483000),
  }, {
    timeout_ms = cfg.timeout_ms,
    retries = cfg.retries,
    transport = cfg.transport,
    delay_ms = cfg.delay_ms,
  })
  record.requested_realm = realm_name
  record.requested_cname = name
  return record
end

-- Turn one answer into a position on the policy, keeping the raw fields the
-- report quotes.
function probe.classify(record, cfg)
  local row = {
    name = record.requested_cname,
    rtt_ms = record.rtt_ms,
    transport = record.transport,
    record = record,
  }
  if record.kind == "as_rep" and record.as_rep then
    row.class = "exempt"
    local enc = record.as_rep.enc_part or {}
    row.etype = enc.etype
    row.material_bytes = enc.cipher and #enc.cipher or nil
    row.detail = string.format("an AS-REP was issued without pre-authentication (etype %s, %s bytes of material)",
      tostring(enc.etype), tostring(enc.cipher and #enc.cipher or 0))
    if cfg.show_hashes and enc.etype and enc.cipher then
      -- The crackable string is only assembled when the operator asked for it
      -- on purpose; the default report carries the shape, not the material.
      row.material = string.format("$krb5asrep$%d$%s@%s$%s", enc.etype, row.name,
        tostring(record.as_rep.crealm or record.requested_realm),
        stdnse.tohex(enc.cipher))
    end
    return row
  end
  if record.kind == "krb_error" and record.krb_error then
    local err = record.krb_error
    row.error_code = err.code
    row.error_name = err.code_name
    row.class = KB.ERROR_CLASS[err.code] or "inconclusive"
    local DETAIL = {
      covered = "%s: the account requires pre-authentication",
      revoked = "%s: the account exists and is disabled or locked",
      unknown = "%s: the name does not exist",
      inconclusive = "%s (code %d) does not place the account on either side of the policy",
    }
    if row.class == "covered" then
      row.detail = string.format("%s: the account requires pre-authentication", tostring(err.code_name))
      local info = krb.parse_method_data(err.e_data)
      for _, entry in ipairs(info) do
        if entry.type == 18 or entry.type == 11 then
          local list = entry.type == 18 and krb.parse_etype_info2(entry.value) or krb.parse_etype_info(entry.value)
          for _, item in ipairs(list) do
            if item.salt and not row.salt then
              row.salt = item.salt
              row.etype = item.etype
            end
          end
        end
      end
      if row.salt then
        row.detail = row.detail .. string.format("; it also disclosed the salt for etype %s", tostring(row.etype))
      end
    elseif err.code == 68 then
      row.detail = string.format("KDC_ERR_WRONG_REALM: this KDC serves %s instead", tostring(err.realm))
    else
      row.detail = string.format(DETAIL[row.class] or DETAIL.inconclusive,
        tostring(err.code_name or "unlisted answer"), tostring(err.code))
    end
    return row
  end
  row.class = "no-answer"
  row.detail = string.format("no answer (%s)", tostring(record.error or "timeout"))
  return row
end

-- The calibration name cannot exist, so its answer states what this KDC says
-- about names it does not have. When that answer is the same one an account
-- receives, the account answer carries no policy information at all and the
-- report must say so instead of calling the account covered.
function probe.calibrate(host, port, cfg, realm_name)
  local name = string.format("nmap-nonexistent-%d", math.random(100000, 999999))
  local record = probe.ask(host, port, cfg, realm_name, name)
  local row = probe.classify(record, cfg)
  row.calibration_name = name
  return row
end

-- 5. Analysis

local analysis = {}

-- The per-account positions, with the uniform-answer case folded in: when the
-- calibration answered like a covered account, "covered" becomes "unresolved"
-- because the same answer would come back for a name that does not exist.
function analysis.evaluate(cfg, calibration, rows)
  local out = {
    rows = rows,
    calibration = calibration,
    covered = 0,
    exempt = 0,
    unknown = 0,
    revoked = 0,
    unresolved = 0,
    skipped = {},
    stopped = false,
  }
  local COUNTED = { covered = "covered", exempt = "exempt", unknown = "unknown", revoked = "revoked" }
  for _, row in ipairs(rows) do
    if row.class == "covered" and calibration.class == "covered" then
      row.effective_class = "unresolved"
      row.detail = row.detail .. "; the calibration name received the same answer, so this does not prove the account exists"
    else
      row.effective_class = row.class
    end
    if COUNTED[row.effective_class] then
      out[COUNTED[row.effective_class]] = out[COUNTED[row.effective_class]] + 1
    else
      out.unresolved = out.unresolved + 1
    end
  end
  out.counted = out.covered + out.exempt + out.unknown + out.revoked
  return out
end

function analysis.coverage_statement(evaluation)
  if evaluation.counted == 0 then
    return "no account could be placed on either side of the policy"
  end
  local notes = {}
  if evaluation.unresolved > 0 then notes[#notes + 1] = string.format("%d unresolved", evaluation.unresolved) end
  if evaluation.revoked > 0 then notes[#notes + 1] = string.format("%d disabled or locked", evaluation.revoked) end
  return string.format("%d of %d account(s) do not require pre-authentication%s", evaluation.exempt,
    evaluation.counted, #notes > 0 and ("; " .. table.concat(notes, ", ")) or "")
end

-- 6. Realm resolution

local realm = {}

-- The realm is needed before any account can be checked. When the operator did
-- not supply one, a request for a name in a realm this KDC cannot serve is
-- answered with KDC_ERR_WRONG_REALM, and the error carries the realm the server
-- does serve. That is the only oracle used here.
function realm.resolve(host, port, cfg)
  if cfg.realm then
    return cfg.realm, "kerberos.realm script argument"
  end
  local synthetic = "NMAP-NONEXISTENT.INVALID"
  local record = transport.as_req(host, port, {
    realm = synthetic,
    cname = "realm-probe",
    cname_type = NT.PRINCIPAL,
    etypes = { 23, 18 },
    kdc_options = 0,
    till = timeutil.os_utc(3600),
    nonce = math.random(1, 2147483000),
  }, {
    timeout_ms = cfg.timeout_ms,
    retries = cfg.retries,
    transport = cfg.transport,
  })
  if record.kind == "krb_error" and record.krb_error and record.krb_error.realm then
    return string.upper(record.krb_error.realm),
      "KDC_ERR_WRONG_REALM answered by the target for a realm it does not serve"
  end
  if record.kind == "krb_error" and record.krb_error and record.krb_error.code == 6 then
    -- The KDC accepted the realm and refused the name, which means it does serve
    -- the synthetic realm. Unusual, but it is a measurement, not an assumption.
    return synthetic, "the target accepted a realm that does not exist"
  end
  local derived
  local name = host.name or host.targetname
  if name then
    derived = string.upper(string.match(name, "%.(.+)$") or name)
  end
  if derived then
    return derived, "derived from the target name; verify it before trusting the account results"
  end
  return nil, "not determined"
end

-- 7. Reporting

local RISK_LABEL = {
  CRITICAL = "\240\159\148\180 CRITICAL",
  HIGH = "\240\159\159\160 HIGH",
  MEDIUM = "\240\159\159\161 MEDIUM",
  LOW = "\240\159\159\162 LOW",
  INFO = "\226\154\170 INFO",
  INCONCLUSIVE = "\226\154\170 INCONCLUSIVE",
}

local report = {}

local SEVERITY_ORDER = { CRITICAL = 5, HIGH = 4, MEDIUM = 3, LOW = 2, INFO = 1 }

function report.findings(evaluation, cfg)
  local list = {}
  local function add(finding)
    list[#list + 1] = finding
  end

  local exempt = {}
  local unresolved = {}
  local unknown = {}
  local revoked = {}
  local answered = 0
  for _, row in ipairs(evaluation.rows) do
    if row.effective_class == "exempt" then
      exempt[#exempt + 1] = row
    elseif row.effective_class == "unresolved" then
      unresolved[#unresolved + 1] = row
    elseif row.effective_class == "unknown" then
      unknown[#unknown + 1] = row
    elseif row.effective_class == "revoked" then
      revoked[#revoked + 1] = row
    end
    if row.class ~= "no-answer" then
      answered = answered + 1
    end
  end

  if #exempt > 0 then
    local names = {}
    for _, row in ipairs(exempt) do
      names[#names + 1] = row.name
    end
    add({
      id = "PREAUTH-NOT-REQUIRED",
      severity = "MEDIUM",
      title = string.format("%d account(s) do not require Kerberos pre-authentication", #exempt),
      evidence = {
        "accounts: " .. table.concat(names, ", "),
        string.format("each received an AS-REP for a request that carried no padata, so the KDC issued the ticket before asking for proof"),
        "material reported by length and encryption type only; the crackable string is printed only with kerberos.show-hashes=true",
      },
      impact = "An attacker with a list of account names receives an AS-REP encrypted with the account's key. The exchange needs no credentials and no interaction, and the material is attacked offline, so the account's password length and randomness decide how long it survives. Exemptions exist for a reason - replication, inter-realm trusts, legacy services - so the finding is the exemption, not the protocol.",
      remediation = "For every account in the list: if the exemption is not required, clear the DONT_REQ_PREAUTH bit of userAccountControl; if it is required, rotate the account to a long random password and document why the exemption stays.",
    })
  end

  if evaluation.counted == 0 then
    add({
      id = "POLICY-INCONCLUSIVE",
      severity = "MEDIUM",
      title = "No account could be placed on either side of the pre-authentication policy",
      evidence = {
        string.format("calibration name %s answered %s", tostring(evaluation.calibration and evaluation.calibration.calibration_name), tostring(evaluation.calibration and evaluation.calibration.class)),
        string.format("%d of %d probed name(s) had no answer", #evaluation.rows - answered, #evaluation.rows),
      },
      impact = "The run produced no statement about the policy. Either the realm does not distinguish existing from non-existing names, or every probe failed at the transport.",
      remediation = "Re-run with kerberos.verbose=true and a longer kerberos.timeout-ms; if the calibration and the accounts keep answering alike, the KDC is not disclosing the difference and this check cannot conclude anything.",
    })
  elseif #unresolved > 0 then
    local names = {}
    for _, row in ipairs(unresolved) do
      names[#names + 1] = row.name
    end
    add({
      id = "POLICY-PARTIALLY-RESOLVED",
      severity = "LOW",
      title = string.format("%d account(s) answered like the calibration name", #unresolved),
      evidence = {
        "accounts: " .. table.concat(names, ", "),
        string.format("calibration name %s received the same answer (%s), so the answer carries no policy information",
          tostring(evaluation.calibration and evaluation.calibration.calibration_name),
          tostring(evaluation.calibration and evaluation.calibration.detail)),
      },
      impact = "The account may or may not be exempt; the KDC answers names it does not have the same way. Reporting it as covered would be a false negative, and reporting it as exempt would be a false alarm.",
      remediation = "Verify the account names against the directory, then re-run: an existing account in a healthy realm answers with KDC_ERR_PREAUTH_REQUIRED while a name that does not exist answers with KDC_ERR_C_PRINCIPAL_UNKNOWN.",
    })
  end

  if #revoked > 0 and cfg.stop_on_locked then
    local names = {}
    for _, row in ipairs(revoked) do
      names[#names + 1] = row.name
    end
    add({
      id = "LOCKED-ACCOUNT-ENCOUNTERED",
      severity = "LOW",
      title = string.format("%d account(s) are disabled or locked", #revoked),
      evidence = {
        "accounts: " .. table.concat(names, ", "),
        string.format("%s was stopped after this answer, because continuing would keep failing the same account against the lockout threshold",
          cfg.stop_on_locked and "the run" or "the run would have been"),
      },
      impact = "A locked account produces the same KDC answer as a disabled one, so the state is not distinguishable from the answer alone. Continuing to probe it risks extending a lockout that is affecting a real user.",
      remediation = "Check the account state in the directory before probing it again, and space out runs so the probe itself cannot cause a lockout.",
    })
  end

  if #unknown > 0 then
    local names = {}
    for _, row in ipairs(unknown) do
      names[#names + 1] = row.name
    end
    add({
      id = "ACCOUNT-UNKNOWN",
      severity = "INFO",
      title = string.format("%d name(s) do not exist in the realm", #unknown),
      evidence = { "KDC_ERR_C_PRINCIPAL_UNKNOWN for " .. table.concat(names, ", ") },
      impact = "The name list contains entries the directory does not have, so the run spent requests on names that cannot inform the policy.",
      remediation = "Correct the wordlist and re-run; an existing account that is reported as unknown usually means a missing realm or a wrong name form.",
    })
  end

  if answered == 0 then
    add({
      id = "KDC-UNREACHABLE",
      severity = "MEDIUM",
      title = "No AS-REQ received an answer",
      evidence = {
        string.format("calibration: %s", tostring(evaluation.calibration and evaluation.calibration.detail)),
        string.format("timeout %d ms, transport %s, retries %d", cfg.timeout_ms, cfg.transport, cfg.retries),
      },
      impact = "The pre-authentication policy is unknown, and every other observation in this run is absent rather than negative.",
      remediation = "Confirm that UDP/88 and TCP/88 reach the KDC and re-run; use kerberos.transport=tcp to rule out a datagram path that is filtered.",
    })
  elseif #exempt == 0 and evaluation.counted > 0 then
    add({
      id = "PREAUTH-ENFORCED",
      severity = "INFO",
      title = "Every account that could be placed requires pre-authentication",
      evidence = {
        string.format("%d account(s) answered KDC_ERR_PREAUTH_REQUIRED", evaluation.covered),
        string.format("calibration name %s answered %s, so the classification is calibrated",
          tostring(evaluation.calibration and evaluation.calibration.calibration_name),
          tostring(evaluation.calibration and evaluation.calibration.class)),
      },
      impact = "The accounts checked cannot be roasted: an attacker must know the password before the KDC will answer.",
      remediation = "No action required. Re-run against a wider account list after any directory change, because the exemption is a per-account attribute.",
    })
  end

  if #list == 0 then
    add({
      id = "NO-FINDINGS",
      severity = "INFO",
      title = "No pre-authentication weakness was observed",
      evidence = { "every probed name either required pre-authentication or was accounted for by the calibration" },
      impact = "The checked accounts are covered by the policy.",
      remediation = "No action required.",
    })
  end
  return list
end

function report.build(host, port, cfg, realm_result, evaluation, account_sources)
  local out = stdnse.output_table()
  out["Script version"] = SCRIPT_VERSION
  out["Engine version"] = string.format("kerberos5.lua %s", tostring(krb5.VERSION))
  out["Declared risk class"] = SCRIPT_RISK
  out["Realm"] = realm_result.realm or "not determined"
  out["Realm source"] = realm_result.source
  out["Target"] = string.format("%s (%s)", tostring(host.name or host.ip or "target"),
    tostring(port.number) .. "/" .. tostring(port.protocol or "tcp"))
  out["Accounts probed"] = string.format("%d of at most %d, from %s", #evaluation.rows, cfg.max_accounts,
    #account_sources > 0 and table.concat(account_sources, "; ") or "the script arguments")
  out["Policy coverage"] = analysis.coverage_statement(evaluation)

  local lines = {}
  for _, row in ipairs(evaluation.rows) do
    lines[#lines + 1] = string.format("%s -> %s: %s", row.name, row.effective_class, row.detail)
    if row.salt then
      lines[#lines + 1] = string.format("    salt for etype %s: %s", tostring(row.etype), tostring(row.salt))
    end
    if row.material then
      lines[#lines + 1] = string.format("    material: %s", tostring(row.material))
    end
  end
  out["Accounts"] = lines

  if evaluation.calibration then
    out["Calibration"] = string.format("%s -> %s (%s)", tostring(evaluation.calibration.calibration_name),
      tostring(evaluation.calibration.class), tostring(evaluation.calibration.detail))
  end

  local findings = report.findings(evaluation, cfg)
  table.sort(findings, function(a, b)
    local sa, sb = SEVERITY_ORDER[a.severity] or 0, SEVERITY_ORDER[b.severity] or 0
    if sa == sb then
      return tostring(a.id) < tostring(b.id)
    end
    return sa > sb
  end)
  local finding_lines = {}
  local worst = "INFO"
  for index, finding in ipairs(findings) do
    finding_lines[#finding_lines + 1] = string.format("[%d] %s (%s) - %s", index, finding.severity, finding.id, finding.title)
    for _, item in ipairs(finding.evidence or {}) do
      finding_lines[#finding_lines + 1] = "      evidence: " .. tostring(item)
    end
    finding_lines[#finding_lines + 1] = "      impact: " .. tostring(finding.impact)
    finding_lines[#finding_lines + 1] = "      remediation: " .. tostring(finding.remediation)
    if (SEVERITY_ORDER[finding.severity] or 0) > (SEVERITY_ORDER[worst] or 0) then
      worst = finding.severity
    end
  end
  out["Findings"] = finding_lines

  out["Classification"] = "exempt = an AS-REP was issued without pre-authentication; covered = KDC_ERR_PREAUTH_REQUIRED; unknown = the name does not exist; revoked = disabled or locked; unresolved = the calibration answered the same way"

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

  if cfg.verbose then
    local transcript = { string.format("realm %s from %s; timeout %d ms; transport %s; retries %d",
      tostring(realm_result.realm), tostring(realm_result.source), cfg.timeout_ms, cfg.transport, cfg.retries),
      "AS-REQ padata: none, by design; the exchange is the measurement" }
    for _, row in ipairs(evaluation.rows) do
      transcript[#transcript + 1] = string.format("%-20s class=%-10s transport=%s rtt=%s ms",
        row.name, tostring(row.effective_class), tostring(row.transport or (row.record or {}).transport), tostring(row.rtt_ms))
    end
    out["Protocol transcript"] = transcript
  end

  out["Risk Level"] = RISK_LABEL[worst] or worst
  return out
end

-- 8. Action

action = function(host, port)
  local cfg = config.load(host)
  local names, sources = accounts.load(cfg, host)
  local effective_port = port.number == 88 and port.number or cfg.kdc_port
  local realm_name, realm_source = realm.resolve(host, effective_port, cfg)
  local realm_result = { realm = realm_name, source = realm_source }

  local calibration = probe.calibrate(host, effective_port, cfg, realm_name)
  local rows = {}
  local stopped = false
  for _, entry in ipairs(names) do
    if stopped then
      break
    end
    local record = probe.ask(host, effective_port, cfg, realm_name, entry.name)
    local row = probe.classify(record, cfg)
    row.source = entry.source
    rows[#rows + 1] = row
    if row.class == "revoked" and cfg.stop_on_locked then
      stopped = true
    end
  end

  local evaluation = analysis.evaluate(cfg, calibration, rows)
  evaluation.stopped = stopped
  return report.build(host, port, cfg, realm_result, evaluation, sources)
end
