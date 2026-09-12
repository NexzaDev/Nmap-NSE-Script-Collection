local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local string = require "string"
local table = require "table"
local math = require "math"

-- The Kerberos engine supplies the ASN.1 layer, the message builders and the
-- transport, so this script only implements the audit logic.
local ok, krb5 = pcall(require, "kerberos5")

description = [[
Assesses a KDC's PAC-signature posture from the outside, and states plainly which
part of that posture a remote, unauthenticated probe can and cannot measure.

A ticket's PAC is the structure that carries the account's group membership.
The KDC signs it, and a service is supposed to verify that signature before it
believes the groups; when it does not, a ticket can be built or altered by
anyone who holds the right key material. The hardening Microsoft shipped for
this family changes both the signature algorithm and the enforcement:

  * the signature moved from keyed RC4/AES-SHA1 to HMAC-SHA256 over AES keys,
    which is why an RC4-only realm is the interesting case, and
  * the KDC gained a staged enforcement switch, so a realm can be in audit mode
    (the signature is checked and a mismatch is logged) or in enforcement mode
    (the ticket is refused).

What this script measures, without credentials and without a key:

  1. the encryption types the KDC actually answers for the machine account and
     for krbtgt, one AS-REQ per type, because RC4 (23) is the type whose key
     material makes the forgery family practical;
  2. the PA-SUPPORTED-ENCTYPES bitmask the KDC advertises for those principals,
     which is the directory's own view of the same policy;
  3. whether AES-SHA2 (19, 20) is offered at all, which is the crypto generation
     the signature change belongs to;
  4. the size of an issued ticket, measured from the AS-REP, because a PAC grows
     with group membership and the size is a proxy for what a service is being
     asked to trust.

What it cannot measure is the one thing an attacker would want to know: whether
the services in the realm verify the signature. That decision happens on the
service, after the ticket was issued, and it is invisible to any client. The
report says so instead of implying a verdict, prints the registry switches that
decide it, and lists the authenticated checks an operator can run to close the
question.

Read-only: the script requests pre-authentication errors and, where the realm
allows it, an AS-REP. It never presents a credential and never uses anything it
receives.
]]

---
-- @usage
-- nmap -p 88 --script kerberos-pac-validation --script-args 'kerberos.realm=EXAMPLE.COM' <target>
-- nmap -p 88 --script kerberos-pac-validation --script-args 'kerberos.realm=EXAMPLE.COM,kerberos.principal=DC01$' <target>
--
-- @args kerberos.realm         Realm in uppercase DNS form; discovered with a
--                              foreign realm probe when omitted.
-- @args kerberos.principal     Account whose policy is read first (default: the
--                              target's short name with a trailing "$", which
--                              is the machine account of a controller).
-- @args kerberos.calibration   Principal used to prove the KDC distinguishes
--                              existing accounts (default "krbtgt").
-- @args kerberos.etypes        Comma separated catalogue to probe; "all" uses
--                              the built-in list.
-- @args kerberos.kdc-port      KDC port (default 88).
-- @args kerberos.timeout-ms    Per-request timeout, 500-60000.
-- @args kerberos.retries       Transport retries (default 1).
-- @args kerberos.delay-ms      Spacing between AS-REQs (default 200 ms).
-- @args kerberos.transport     "auto" (default), "udp" or "tcp".
-- @args kerberos.repeats       Number of times the catalogue probe is repeated
--                              to detect a pool of controllers behind one name
--                              (default 3, maximum 8).
-- @args kerberos.verbose       "true" adds the per-probe transcript.
--
-- @output
-- 88/tcp open  kerberos-sec
-- | kerberos-pac-validation:
-- |   Realm: EXAMPLE.COM
-- |   Machine account: DC01$ (exists)
-- |   Encryption type policy: RC4-HMAC accepted for DC01$; AES-SHA2 offered; 4 types answered
-- |   Ticket size proxy: 892 bytes for the accepted type (PAC grows with group membership)
-- |   PAC signature enforcement: not observable from a client - see the registry switches below
-- |_  Risk Level: HIGH
---

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(88, "kerberos-sec", {"tcp", "udp"})

local SCRIPT_RISK = "HIGH"
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
local ETYPE = krb5.ETYPE
local NT = krb5.NT

-- 1. Knowledge base

local KB = {}

-- The encryption types this check probes, with the role each one plays in the
-- PAC question. The list is ordered by how much the answer tells us.
KB.ETYPES = {
  { id = 23, name = "RC4-HMAC", family = "RC4",
    role = "the type whose key material is derived from the NT hash, which is what makes offline forgery practical",
    weight = 4 },
  { id = 18, name = "AES-256-CTS-HMAC-SHA1-96", family = "AES-SHA1",
    role = "the AES generation that the signature change replaces", weight = 2 },
  { id = 17, name = "AES-128-CTS-HMAC-SHA1-96", family = "AES-SHA1",
    role = "the 128-bit companion of type 18", weight = 2 },
  { id = 19, name = "AES-256-CTS-HMAC-SHA2-96", family = "AES-SHA2",
    role = "the AES-SHA2 generation the hardened signature belongs to", weight = 3 },
  { id = 20, name = "AES-128-CTS-HMAC-SHA2-96", family = "AES-SHA2",
    role = "the 128-bit companion of type 19", weight = 3 },
  { id = 16, name = "DES-CBC-CRC", family = "DES",
    role = "legacy DES: its presence means the realm still answers a 56-bit request", weight = 5 },
  { id = 3, name = "DES-CBC-MD5", family = "DES",
    role = "the other DES variant; both are retired in every current policy", weight = 5 },
  { id = 1, name = "DES-CBC-CRC (old)", family = "DES",
    role = "the oldest registration; present only on very old implementations", weight = 5 },
  { id = 5, name = "DES3-CBC-SHA1", family = "DES3",
    role = "triple DES, removed from the default negotiation in current releases", weight = 3 },
  { id = 24, name = "RC4-HMAC-EXP", family = "RC4-EXP",
    role = "the export variant of RC4; a KDC that offers it has a very old policy", weight = 5 },
}

KB.ETYPE_BY_ID = {}
for _, entry in ipairs(KB.ETYPES) do
  KB.ETYPE_BY_ID[entry.id] = entry
end

-- The registry switches that decide the enforcement the network cannot show.
KB.ENFORCEMENT = {
  {
    key = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc\\KrbtgtFullPacSignature",
    values = {
      [0] = "0 - the KDC does not add or check the full PAC signature (the pre-hardening behaviour)",
      [1] = "1 - audit: a ticket whose signature does not verify is logged and still issued",
      [2] = "2 - enforcement: the ticket is refused, but audit events are still produced",
      [3] = "3 - enforcement without the audit log entry; the state the update drives toward",
    },
    meaning = "this switch is what turns 'the KDC can sign' into 'the service's check is meaningful'",
  },
  {
    key = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc\\PacRequestorEnforcement",
    values = {
      [0] = "0 - the requestor field of the PAC is neither added nor validated",
      [1] = "1 - audit: the requestor is validated and a mismatch is logged",
      [2] = "2 - enforcement: a PAC whose requestor does not match the ticket is refused",
    },
    meaning = "the companion hardening for the requestor field, which is what the sAMAccountName spoofing family targets",
  },
  {
    key = "Each service's own PAC verification",
    values = {
      [0] = "a service that does not verify the signature trusts whatever it receives, and no KDC setting can change that",
      [1] = "a service that verifies makes the KDC's signature the boundary, which is why the switch above matters",
    },
    meaning = "the KDC signs; the service decides. A realm can be fully patched and still accept a forged PAC at a service that never checks.",
  },
}

-- Events that indicate the enforcement switch is doing something. The names are
-- given with the log they live in, because the numbers alone are easy to
-- misread as unrelated Kerberos failures.
KB.DETECTION = {
  {
    log = "Kerberos-Key-Distribution-Center operational log",
    signal = "PAC signature audit entries appear only while the switch is in audit mode; after enforcement they stop, which is the expected direction and not a regression",
  },
  {
    log = "Directory Service and System logs on the controller",
    signal = "a sudden rise in ticket-related refusals after a patch cycle is the signal to read before assuming a client problem",
  },
  {
    log = "Kerberos client events 4768/4769",
    signal = "authentication failures that correlate with a specific application account point at a service that verifies and a KDC signature it rejects",
  },
}

KB.REMEDIATION = {
  {
    title = "Read the encryption type result first",
    steps = {
      "RC4 accepted means the realm still issues tickets whose integrity rests on the NT hash; retire 23 from the account policy once the client population allows it, and treat the answer as the finding rather than as a curiosity.",
      "AES-SHA2 absent means the KDC predates the generation the hardened signature belongs to; plan the functional level change together with the patch cycle rather than separately.",
      "Both statements are per-principal: a machine account can be RC4-only while users are AES-SHA2, and the machine account is the one an attacker needs for some of the family's paths.",
    },
  },
  {
    title = "Decide the enforcement state deliberately",
    steps = {
      "Set the signature switch to audit first and let it run long enough to cover a full authentication cycle for every service population.",
      "Read the audit entries, fix the clients and services that appear in them, and only then move the switch to enforcement.",
      "Record the switch values in the domain's baseline; a controller rebuilt from an old image will come up in the pre-hardening state and the difference is invisible on the wire.",
    },
  },
  {
    title = "Close the question from an authenticated position",
    steps = {
      "From a domain-joined host, read the switch on every controller: Get-ItemProperty on the Kdc service key, and compare the value across the set.",
      "Verify that the services you care about verify: request a ticket for a service, alter one byte of the PAC, present it, and confirm the service refuses it. This is the only end-to-end test of the property.",
      "Keep a record of which services were tested and when, because a service that is patched later is not covered by an earlier test.",
    },
  },
}

KB.VERIFICATION = {
  "Confirm the etype policy: the same AS-REQ answered per type gives the accepted set, and the PA-SUPPORTED-ENCTYPES bitmask in the NEEDED_PREAUTH answer must agree with it. A disagreement is an implementation detail worth recording.",
  "Confirm the registry state on every controller: HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc\\KrbtgtFullPacSignature and PacRequestorEnforcement, read together, are the configuration the network cannot show.",
  "Confirm the end-to-end property on a service you own: modify one byte of a PAC in a ticket you are entitled to use and present it; the service must refuse it, and the refusal is the proof that the signature is verified.",
}

KB.REFERENCES = {
  "RFC 4120 section 5.4.1 and section 5.3 - the AS-REQ/AS-REP exchange and the ticket whose PAC this script reasons about",
  "RFC 4120 section 7.5.1 - KDC_ERR_PREAUTH_REQUIRED (25) and KDC_ERR_C_PRINCIPAL_UNKNOWN (6), the two answers the machine-account oracle reads",
  "RFC 3962 and RFC 8009 - the AES-SHA1 and AES-SHA2 encryption types whose availability dates the KDC's policy generation",
  "RFC 4757 - RC4-HMAC and the key derivation that makes an RC4-accepting realm the interesting case",
  "Microsoft, 'KB5020805' and the PAC-signature hardening guidance: the KrbtgtFullPacSignature and PacRequestorEnforcement switches, the audit-then-enforce sequence, and the service-side verification that carries the property",
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

-- The machine account of a controller is its short name with a trailing "$".
-- When the target has no name at all, the operator has to supply one, and the
-- report says which case was taken.
function config.machine_account(host)
  local name = host.name or host.targetname
  if not name then
    return nil
  end
  local short = string.match(name, "^([^%.]+)")
  if not short then
    return nil
  end
  return string.upper(short) .. "$"
end

function config.load(host)
  local cfg = {}
  cfg.realm = arg_string("realm")
  if cfg.realm then
    cfg.realm = string.upper(cfg.realm)
  end
  cfg.principal = arg_string("principal")
  if cfg.principal then
    cfg.principal = string.upper(cfg.principal)
  end
  cfg.calibration = arg_string("calibration") or "krbtgt"
  cfg.kdc_port = arg_int("kdc-port", 88, 1, 65535)
  cfg.retries = arg_int("retries", 1, 0, 5)
  cfg.delay_ms = arg_int("delay-ms", 200, 0, 5000)
  cfg.repeat_probes = arg_int("repeats", 3, 1, 8)
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

  -- The catalogue: the built-in list, or whatever the operator asked for.
  local wanted = arg_string("etypes")
  cfg.etypes = {}
  if wanted and string.lower(wanted) ~= "all" then
    for value in string.gmatch(wanted, "%d+") do
      local id = tonumber(value)
      if id then
        cfg.etypes[#cfg.etypes + 1] = id
      end
    end
  end
  if #cfg.etypes == 0 then
    for _, entry in ipairs(KB.ETYPES) do
      cfg.etypes[#cfg.etypes + 1] = entry.id
    end
  end
  cfg.etype_names = {}
  for _, id in ipairs(cfg.etypes) do
    local entry = KB.ETYPE_BY_ID[id]
    cfg.etype_names[id] = entry and entry.name or string.format("etype %d", id)
  end
  return cfg
end

-- 3. Realm resolution

local realm = {}

function realm.resolve(host, port, cfg)
  if cfg.realm then
    return cfg.realm, "kerberos.realm script argument"
  end
  local synthetic = "NMAP-NONEXISTENT.INVALID"
  local record = transport.as_req(host, port, {
    realm = synthetic,
    cname = "pac-probe",
    cname_type = NT.PRINCIPAL,
    etypes = { 23, 18, 17 },
    kdc_options = 0,
    till = timeutil.os_utc(3600),
    nonce = math.random(1, 2147483000),
  }, {
    timeout_ms = cfg.timeout_ms,
    retries = cfg.retries,
    transport = cfg.transport,
  })
  if record.kind == "krb_error" and record.krb_error and record.krb_error.realm then
    return string.upper(record.krb_error.realm), "KDC_ERR_WRONG_REALM answered for a foreign realm"
  end
  local name = host.name or host.targetname
  if name then
    return string.upper(string.match(name, "%.(.+)$") or name),
      "derived from the target name; verify it before trusting the policy reading"
  end
  return nil, "not determined"
end

-- 4. Wire

local wire = {}

-- One AS-REQ that offers exactly the given encryption types. Offering a single
-- type is what makes the answer a statement about that type rather than about
-- the KDC's preference order.
function wire.request(host, port, cfg, realm_name, principal, etypes, padata)
  local req = {
    realm = realm_name,
    cname = principal,
    cname_type = NT.PRINCIPAL,
    etypes = etypes,
    kdc_options = 0,
    till = timeutil.os_utc(3600),
    nonce = math.random(1, 2147483000),
  }
  if padata then
    req.padata = padata
  end
  local record = transport.as_req(host, port, req, {
    timeout_ms = cfg.timeout_ms,
    retries = cfg.retries,
    transport = cfg.transport,
    delay_ms = cfg.delay_ms,
  })
  record.requested_cname = principal
  record.requested_etypes = etypes
  return record
end

-- The padata of a NEEDED_PREAUTH answer, which is where the KDC states its own
-- view of the policy through PA-SUPPORTED-ENCTYPES.
function wire.method_data(record)
  local types = {}
  local supported_mask
  if record.kind == "krb_error" and record.krb_error and record.krb_error.e_data then
    for _, entry in ipairs(krb.parse_method_data(record.krb_error.e_data)) do
      types[#types + 1] = entry.type
      if entry.type == 165 and entry.value and #entry.value >= 4 then
        local a, b, c, d = string.byte(entry.value, 1, 4)
        supported_mask = a + b * 256 + c * 65536 + d * 16777216
      end
      if entry.type == 18 and entry.value then
        supported_mask = supported_mask or nil
      end
    end
  end
  return types, supported_mask
end

-- Turn a raw mask into the encryption types it names. Bit n means etype n+1,
-- which is the convention PA-SUPPORTED-ENCTYPES uses.
function wire.mask_etypes(mask)
  local list = {}
  if not mask then
    return list
  end
  for bit = 0, 31 do
    local divisor = 2 ^ bit
    if divisor > mask then
      break
    end
    if math.floor(mask / divisor) % 2 == 1 then
      list[#list + 1] = bit + 1
    end
  end
  return list
end

function wire.padata_types(record)
  local types = wire.method_data(record)
  return types
end

-- 5. Probes

local probe = {}

-- Classify one answer to a single-etype AS-REQ. The distinction that matters is
-- between "the KDC cannot handle this type at all" (KDC_ERR_ETYPE_NOSUPP) and
-- "the KDC can, and now wants pre-authentication", which is an acceptance for
-- policy purposes.
function probe.classify_etype(record, cfg, etype)
  local row = {
    etype = etype,
    name = cfg.etype_names[etype] or string.format("etype %d", etype),
    family = KB.ETYPE_BY_ID[etype] and KB.ETYPE_BY_ID[etype].family or "unlisted",
    request_bytes = record.request_bytes,
    response_bytes = record.response_bytes,
    rtt_ms = record.rtt_ms,
    transport = record.transport,
    attempts = record.attempts,
  }
  -- The record is kept so the ticket facts can be read from the answers that
  -- actually carried one; nothing else in the row needs it.
  row.record = record
  local padata = wire.padata_types(record)
  row.padata = padata
  row.padata_names = {}
  for _, value in ipairs(padata) do
    row.padata_names[#row.padata_names + 1] = tostring(value)
  end

  if record.kind == "krb_error" and record.krb_error then
    row.kind = "krb_error"
    row.error_code = record.krb_error.code
    row.error_name = record.krb_error.code_name
  elseif record.kind == "as_rep" then
    row.kind = "as_rep"
  else
    row.kind = "no-answer"
  end

  if row.kind == "as_rep" then
    row.verdict = "accepted"
    row.detail = string.format("an AS-REP was issued for %s when it was offered alone", row.name)
  elseif row.kind == "no-answer" then
    row.verdict = "undetermined"
    row.detail = string.format("no answer (%s)", tostring(record.error or "timeout"))
  elseif row.error_code == 25 then
    row.verdict = "accepted"
    row.detail = string.format("KDC_ERR_PREAUTH_REQUIRED: the type was accepted and the KDC moved on to pre-authentication")
    if wire.has_padata_type(padata, 18) or wire.has_padata_type(padata, 11) then
      row.detail = row.detail .. "; the answer named the salt for this type"
    end
  elseif row.error_code == 14 then
    row.verdict = "refused"
    row.detail = "KDC_ERR_ETYPE_NOSUPP: the KDC will not issue a ticket of this type"
  elseif row.error_code == 6 then
    row.verdict = "unknown-principal"
    row.detail = "KDC_ERR_C_PRINCIPAL_UNKNOWN: the principal does not exist, so the type was never evaluated"
  elseif row.error_code == 18 then
    row.verdict = "revoked"
    row.detail = "KDC_ERR_CLIENT_REVOKED: the account is disabled or locked"
  else
    row.verdict = "undetermined"
    row.detail = string.format("%s (code %s) does not place this type on either side",
      tostring(row.error_name or "unlisted answer"), tostring(row.error_code))
  end
  return row
end

function wire.has_padata_type(list, wanted)
  for _, value in ipairs(list or {}) do
    if value == wanted then
      return true
    end
  end
  return false
end

-- Run the matrix for one principal: one AS-REQ per encryption type, then one
-- request that offers the whole catalogue so the KDC's preference order can be
-- compared with the individual answers.
function probe.policy(host, port, cfg, realm_name, principal)
  local policy = {
    principal = principal,
    rows = {},
    accepted = {},
    refused = {},
    undetermined = {},
    question = {},
    order = {},
  }
  for _, etype in ipairs(cfg.etypes) do
    local record = wire.request(host, port, cfg, realm_name, principal, { etype })
    local row = probe.classify_etype(record, cfg, etype)
    policy.rows[#policy.rows + 1] = row
    if row.verdict == "accepted" then
      policy.accepted[#policy.accepted + 1] = row
    elseif row.verdict == "refused" then
      policy.refused[#policy.refused + 1] = row
    elseif row.verdict == "unknown-principal" then
      policy.question[#policy.question + 1] = row
    elseif row.verdict == "revoked" then
      policy.revoked = row
    else
      policy.undetermined[#policy.undetermined + 1] = row
    end
  end

  -- The whole-catalogue request: the padata of its answer names the types the
  -- KDC would negotiate, which is the policy statement rather than a per-request
  -- decision.
  local all = wire.request(host, port, cfg, realm_name, principal, cfg.etypes)
  policy.catalogue = probe.classify_etype(all, cfg, 0)
  local types, mask = wire.method_data(all)
  policy.catalogue_padata = types
  policy.supported_mask = mask
  policy.mask_etypes = wire.mask_etypes(mask)
  if all.kind == "as_rep" then
    policy.catalogue.verdict = "accepted"
    policy.catalogue.detail = "the KDC issued a ticket for the whole catalogue, so every type in it was acceptable"
  end
  return policy
end

-- The machine-account oracle. krbtgt is the calibration principal: every realm
-- has one, so the two answers together say whether a difference in the answers
-- means anything at all. A KDC that answers both names the same way is not
-- distinguishing accounts, and no policy statement can be made about the target
-- account from its answer alone.
function probe.oracle(host, port, cfg, realm_name, principal)
  local target = probe.classify_etype(
    wire.request(host, port, cfg, realm_name, principal, { 18, 23 }), cfg, 0)
  local calibration = probe.classify_etype(
    wire.request(host, port, cfg, realm_name, cfg.calibration, { 18, 23 }), cfg, 0)
  local out = {
    target = target,
    calibration = calibration,
    principal = principal,
    calibration_name = cfg.calibration,
  }
  if target.kind == "no-answer" and calibration.kind == "no-answer" then
    out.state = "unreachable"
    out.detail = "neither the target account nor the calibration principal was answered"
    return out
  end
  if calibration.verdict == "unknown-principal" and target.verdict ~= "unknown-principal" then
    out.state = "exists"
    out.detail = string.format("%s exists: the KDC distinguishes it from a name it does not have (%s answered KDC_ERR_C_PRINCIPAL_UNKNOWN)",
      principal, cfg.calibration)
    return out
  end
  if target.verdict == "unknown-principal" then
    out.state = "absent"
    out.detail = string.format("%s does not exist in the realm", principal)
    return out
  end
  if target.kind == calibration.kind and target.error_code == calibration.error_code then
    out.state = "uniform"
    out.detail = string.format("%s and %s received the same answer (%s), so the KDC is not disclosing whether the account exists",
      principal, cfg.calibration, tostring(target.detail))
    return out
  end
  out.state = "exists"
  out.detail = string.format("%s answered %s while %s answered %s, so the two names are treated differently",
    principal, tostring(target.error_name or target.kind), cfg.calibration,
    tostring(calibration.error_name or calibration.kind))
  return out
end

-- The size proxy. The PAC lives inside the encrypted ticket, so its content
-- cannot be read, but the size of the AS-REP that carries it can be measured,
-- and a PAC grows with the group membership the ticket was built from. The
-- number is reported as a measurement with its interpretation, never as a
-- decoding of something that was not decoded.
function probe.size_proxy(policy)
  local best
  for _, row in ipairs(policy.rows) do
    if row.verdict == "accepted" and row.response_bytes then
      if not best or row.response_bytes > best.response_bytes then
        best = row
      end
    end
  end
  if not best and policy.catalogue and policy.catalogue.response_bytes then
    best = policy.catalogue
  end
  if not best then
    return nil
  end
  return {
    bytes = best.response_bytes,
    etype = best.etype,
    name = best.name,
    detail = string.format("the largest accepted answer was %d bytes (%s); a ticket whose PAC carries more groups is larger, so this number is a baseline rather than a finding",
      best.response_bytes, tostring(best.name)),
  }
end

-- 6. Analysis

local analysis = {}

function analysis.family_state(policy, family)
  local accepted, refused, undetermined = {}, {}, {}
  for _, row in ipairs(policy.rows) do
    if row.family == family or (family == "AES" and (row.family == "AES-SHA1" or row.family == "AES-SHA2")) then
      if row.verdict == "accepted" then
        accepted[#accepted + 1] = row
      elseif row.verdict == "refused" then
        refused[#refused + 1] = row
      else
        undetermined[#undetermined + 1] = row
      end
    end
  end
  return accepted, refused, undetermined
end

function analysis.summarise(policy, oracle, size)
  local out = {
    policy = policy,
    oracle = oracle,
    size = size,
    rc4 = {},
    aes_sha1 = {},
    aes_sha2 = {},
    des = {},
    agreement = nil,
  }
  out.rc4.accepted = select(1, analysis.family_state(policy, "RC4"))
  out.rc4.refused = select(2, analysis.family_state(policy, "RC4"))
  out.aes_sha1.accepted = select(1, analysis.family_state(policy, "AES-SHA1"))
  out.aes_sha2.accepted = select(1, analysis.family_state(policy, "AES-SHA2"))
  out.des.accepted = select(1, analysis.family_state(policy, "DES"))
  out.des3 = select(1, analysis.family_state(policy, "DES3"))
  out.answered = #policy.accepted + #policy.refused
  out.undetermined = #policy.undetermined

  -- Agreement: the mask the KDC advertises should name the same types the
  -- per-type probes accepted. A difference is small on its own but it is the
  -- kind of detail that explains a client behaving differently from a scan.
  if policy.supported_mask and #policy.mask_etypes > 0 then
    local observed = {}
    for _, row in ipairs(policy.rows) do
      if row.verdict == "accepted" then
        observed[row.etype] = true
      end
    end
    local only_mask, only_probe = {}, {}
    for _, etype in ipairs(policy.mask_etypes) do
      if not observed[etype] then
        only_mask[#only_mask + 1] = etype
      end
    end
    for etype in pairs(observed) do
      local present = false
      for _, value in ipairs(policy.mask_etypes) do
        if value == etype then
          present = true
        end
      end
      if not present then
        only_probe[#only_probe + 1] = etype
      end
    end
    out.agreement = {
      mask = policy.mask_etypes,
      mask_only = only_mask,
      probe_only = only_probe,
      agrees = #only_mask == 0 and #only_probe == 0,
    }
  end
  return out
end

function analysis.policy_statement(summary)
  local parts = {}
  local function names(list)
    local out = {}
    for _, row in ipairs(list) do
      out[#out + 1] = row.name
    end
    return table.concat(out, ", ")
  end
  if #summary.rc4.accepted > 0 then
    parts[#parts + 1] = string.format("RC4-HMAC is accepted (%s)", names(summary.rc4.accepted))
  else
    parts[#parts + 1] = "RC4-HMAC is not accepted"
  end
  if #summary.aes_sha2.accepted > 0 then
    parts[#parts + 1] = string.format("AES-SHA2 is offered (%s)", names(summary.aes_sha2.accepted))
  else
    parts[#parts + 1] = "AES-SHA2 is not offered"
  end
  if #summary.aes_sha1.accepted > 0 then
    parts[#parts + 1] = string.format("AES-SHA1 is accepted (%s)", names(summary.aes_sha1.accepted))
  end
  if #summary.des.accepted > 0 then
    parts[#parts + 1] = string.format("DES is accepted (%s), which no current policy should allow", names(summary.des.accepted))
  end
  return table.concat(parts, "; ")
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

function report.findings(summary, cfg, oracle)
  local list = {}
  local function add(finding)
    list[#list + 1] = finding
  end
  local policy = summary.policy

  if summary.answered == 0 then
    add({
      id = "KDC-UNREACHABLE",
      severity = "MEDIUM",
      title = "No AS-REQ received an answer",
      evidence = {
        string.format("timeout %d ms, transport %s, retries %d", cfg.timeout_ms, cfg.transport, cfg.retries),
        string.format("catalogue probe: %s", tostring(policy.catalogue and policy.catalogue.detail)),
      },
      impact = "Nothing about the realm's policy could be measured, and this report contains no verdict about the PAC hardening.",
      remediation = "Confirm that UDP/88 and TCP/88 reach the controller and re-run; use kerberos.transport=tcp to rule out a datagram path that is filtered.",
    })
    return list
  end

  if #summary.rc4.accepted > 0 then
    local names = {}
    for _, row in ipairs(summary.rc4.accepted) do
      names[#names + 1] = string.format("%s (%d)", row.name, row.etype)
    end
    add({
      id = "RC4-ACCEPTED",
      severity = "HIGH",
      title = string.format("RC4-HMAC is accepted for %s", policy.principal),
      evidence = {
        string.format("accepted types: %s", table.concat(names, ", ")),
        string.format("the answer to a request that offered only RC4 was: %s", tostring(summary.rc4.accepted[1].detail)),
        string.format("declared mask: %s", policy.supported_mask and string.format("0x%08x", policy.supported_mask) or "not advertised"),
      },
      impact = "RC4 keys are derived from the NT hash, which is the material the ticket-forgery family relies on, and the hardening that moved the PAC signature to AES does not apply to a ticket that was never AES in the first place. A realm that still answers RC4 therefore keeps the older attack paths open even after the patch was installed.",
      remediation = "Retire 23 from the account policy (msDS-SupportedEncryptionTypes on the machine account and the domain's policy) once the client population allows it, then re-run this script: the accepted set is the measurement, and it should shrink to the AES types.",
    })
  end

  if #summary.aes_sha2.accepted == 0 and summary.aes_sha1.accepted and #summary.aes_sha1.accepted > 0 then
    add({
      id = "AES-SHA2-MISSING",
      severity = "MEDIUM",
      title = "The KDC answers AES-SHA1 but not AES-SHA2",
      evidence = {
        string.format("AES-SHA1 accepted: %s", tostring(summary.aes_sha1.accepted[1] and summary.aes_sha1.accepted[1].name)),
        "types 19 and 20 (RFC 8009) were refused or undetermined for every probe",
      },
      impact = "The AES-SHA2 generation is the one the hardened PAC signature belongs to. A realm that cannot negotiate it is a generation behind the hardening, which usually means the functional level and the patch cycle have drifted apart.",
      remediation = "Confirm the controllers' patch level, then review msDS-SupportedEncryptionTypes and the account policy; the AES-SHA2 types must be offered before clients can use them.",
    })
  end

  if #summary.des.accepted > 0 then
    local names = {}
    for _, row in ipairs(summary.des.accepted) do
      names[#names + 1] = row.name
    end
    add({
      id = "DES-ACCEPTED",
      severity = "HIGH",
      title = string.format("The KDC accepts DES for %s", policy.principal),
      evidence = { string.format("accepted: %s", table.concat(names, ", ")) },
      impact = "DES is a 56-bit cipher that every current policy retires, and a ticket it protects carries no meaningful integrity. Its presence also means the KDC is answering requests no modern client would send, which is a compatibility setting nobody remembers enabling.",
      remediation = "Remove DES from the account policy and from any trust configuration, then re-run: the DES probes must come back refused.",
    })
  end

  if summary.agreement and not summary.agreement.agrees then
    local only_mask, only_probe = {}, {}
    for _, etype in ipairs(summary.agreement.mask_only) do
      only_mask[#only_mask + 1] = tostring(etype)
    end
    for _, etype in ipairs(summary.agreement.probe_only) do
      only_probe[#only_probe + 1] = tostring(etype)
    end
    add({
      id = "ETYPE-POLICY-DISAGREEMENT",
      severity = "LOW",
      title = "The advertised mask and the per-type answers do not agree",
      evidence = {
        string.format("advertised mask names: %s", table.concat(only_mask, ", ") ~= "" and table.concat(only_mask, ", ") or "none extra"),
        string.format("accepted by probe only: %s", table.concat(only_probe, ", ") ~= "" and table.concat(only_probe, ", ") or "none extra"),
      },
      impact = "A client that trusts the mask and a client that tries a type and reads the answer can behave differently against the same KDC. The difference is small, but it explains an intermittent authentication failure better than most theories.",
      remediation = "Record both lists in the baseline. If the difference persists after a patch cycle, compare the account's msDS-SupportedEncryptionTypes with the domain policy.",
    })
  end

  if oracle.state == "uniform" then
    add({
      id = "ACCOUNT-ORACLE-UNIFORM",
      severity = "LOW",
      title = "The KDC answers an existing and a non-existing account the same way",
      evidence = { oracle.detail },
      impact = "The policy this report describes is the realm's, not the account's: a name that does not exist received the same answer, so nothing here distinguishes one account from another. The encryption type policy is still a realm property and the reading stands.",
      remediation = "Use a principal that is known to exist for account-level questions, and keep the realm-level reading for what it is.",
    })
  elseif oracle.state == "absent" then
    add({
      id = "MACHINE-ACCOUNT-ABSENT",
      severity = "INFO",
      title = string.format("%s does not exist in the realm", tostring(oracle.principal)),
      evidence = { oracle.detail },
      impact = "The policy shown belongs to krbtgt rather than to the machine account. For a domain controller both matter, but the machine account is the one an attacker needs for some paths.",
      remediation = "Supply the real machine account with kerberos.principal, or run the scan from a name the realm knows.",
    })
  end

  if summary.size then
    add({
      id = "PAC-SIZE-BASELINE",
      severity = "INFO",
      title = string.format("An issued ticket was %d bytes in the largest accepted answer", summary.size.bytes),
      evidence = { summary.size.detail },
      impact = "The PAC is inside the encrypted ticket, so its content cannot be read from here, and this number is a baseline rather than a finding. A ticket that grows after a group restructuring is the warning that some path will hit the datagram limit.",
      remediation = "Keep the number in the baseline for the realm and compare it after directory changes.",
    })
  end

  add({
    id = "PAC-ENFORCEMENT-NOT-OBSERVABLE",
    severity = "INFO",
    title = "Whether the services verify the PAC signature cannot be measured from a client",
    evidence = {
      "the KDC signs the PAC before the ticket is encrypted, and the service decides afterwards whether to check it",
      "a remote probe never sees that decision, and this report does not guess at it",
      "the switches that decide it are listed in the report with the commands to read them",
    },
    impact = "Treating the patch level as the answer is how a realm ends up patched and still accepting a forged PAC at one service. The end-to-end property lives on the service.",
    remediation = "Read the enforcement switches on every controller and run the end-to-end test on the services that matter, as the remediation section describes.",
  })

  if #list == 1 then
    add({
      id = "NO-POLICY-FINDINGS",
      severity = "INFO",
      title = "The measured policy contains no weak or legacy encryption type",
      evidence = {
        string.format("answered: %d type(s); undetermined: %d", summary.answered, summary.undetermined),
        analysis.policy_statement(summary),
      },
      impact = "The KDC negotiates only the current generations of encryption types for this principal.",
      remediation = "No action required on the policy; close the enforcement question with the checks in this report.",
    })
  end
  return list
end

function report.enforcement_section()
  local lines = {}
  for _, item in ipairs(KB.ENFORCEMENT) do
    lines[#lines + 1] = item.key
    for value, meaning in pairs(item.values) do
      lines[#lines + 1] = string.format("  %s: %s", tostring(value), meaning)
    end
    lines[#lines + 1] = "  why it matters: " .. item.meaning
  end
  return lines
end

function report.policy_rows(summary)
  local rows = {}
  for _, row in ipairs(summary.policy.rows) do
    rows[#rows + 1] = string.format("%-6d %-30s %-14s %s", row.etype, row.name, row.verdict, tostring(row.detail))
  end
  if summary.policy.catalogue then
    rows[#rows + 1] = string.format("%-6s %-30s %-14s %s", "all", "whole catalogue", summary.policy.catalogue.verdict,
      tostring(summary.policy.catalogue.detail))
  end
  return rows
end

function report.build(host, port, cfg, realm_result, principal, oracle, summary)
  local out = stdnse.output_table()
  out["Script version"] = SCRIPT_VERSION
  out["Engine version"] = string.format("kerberos5.lua %s", tostring(krb5.VERSION))
  out["Declared risk class"] = SCRIPT_RISK
  out["Realm"] = realm_result.realm or "not determined"
  out["Realm source"] = realm_result.source
  out["Machine account"] = string.format("%s (%s)", principal, oracle.state)
  out["Account oracle"] = string.format("%s answered %s; calibration %s answered %s",
    principal, tostring(oracle.target.error_name or oracle.target.kind),
    cfg.calibration, tostring(oracle.calibration.error_name or oracle.calibration.kind))
  out["Target"] = string.format("%s (%s)", tostring(host.name or host.ip or "target"),
    tostring(port.number) .. "/" .. tostring(port.protocol or "tcp"))

  out["Encryption type policy"] = analysis.policy_statement(summary)
  out["Declared mask"] = summary.policy.supported_mask
    and string.format("0x%08x names: %s", summary.policy.supported_mask,
      #summary.policy.mask_etypes > 0 and table.concat((function()
        local names = {}
        for _, etype in ipairs(summary.policy.mask_etypes) do
          names[#names + 1] = string.format("%d", etype)
        end
        return names
      end)(), ", ") or "none")
    or "the KDC did not advertise PA-SUPPORTED-ENCTYPES"
  out["Per-type results"] = report.policy_rows(summary)
  out["Types probed"] = string.format("%d total, %d answered, %d undetermined",
    #summary.policy.rows, summary.answered, summary.undetermined)

  if summary.size then
    out["Ticket size proxy"] = summary.size.detail
  end
  if summary.agreement then
    out["Mask agreement"] = summary.agreement.agrees
      and "the advertised mask and the per-type answers agree"
      or "the advertised mask and the per-type answers differ; see the findings"
  end

  out["PAC signature enforcement"] = "not observable from a client; the switches below decide it and the checks below close the question"
  out["Enforcement switches"] = report.enforcement_section()

  local detection = {}
  for _, item in ipairs(KB.DETECTION) do
    detection[#detection + 1] = string.format("%s: %s", item.log, item.signal)
  end
  out["Detection signals"] = detection

  local findings = report.findings(summary, cfg, oracle)
  table.sort(findings, function(a, b)
    local sa, sb = SEVERITY_ORDER[a.severity] or 0, SEVERITY_ORDER[b.severity] or 0
    if sa == sb then
      return tostring(a.id) < tostring(b.id)
    end
    return sa > sb
  end)
  local lines = {}
  local worst = "INFO"
  for index, finding in ipairs(findings) do
    lines[#lines + 1] = string.format("[%d] %s (%s) - %s", index, finding.severity, finding.id, finding.title)
    for _, item in ipairs(finding.evidence or {}) do
      lines[#lines + 1] = "      evidence: " .. tostring(item)
    end
    lines[#lines + 1] = "      impact: " .. tostring(finding.impact)
    lines[#lines + 1] = "      remediation: " .. tostring(finding.remediation)
    if (SEVERITY_ORDER[finding.severity] or 0) > (SEVERITY_ORDER[worst] or 0) then
      worst = finding.severity
    end
  end
  out["Findings"] = lines

  local etypes = {}
  for _, entry in ipairs(KB.ETYPES) do
    etypes[#etypes + 1] = string.format("%d %s (%s) - %s", entry.id, entry.name, entry.family, entry.role)
  end
  out["Catalogue"] = etypes

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
    local transcript = {}
    transcript[#transcript + 1] = string.format("realm %s from %s; principal %s; timeout %d ms; retries %d; transport %s",
      tostring(realm_result.realm), tostring(realm_result.source), principal, cfg.timeout_ms, cfg.retries, cfg.transport)
    for _, row in ipairs(summary.policy.rows) do
      transcript[#transcript + 1] = string.format("etype %-3d request=%s bytes answer=%s bytes rtt=%s ms verdict=%s padata=%s",
        row.etype, tostring(row.request_bytes), tostring(row.response_bytes), tostring(row.rtt_ms),
        row.verdict, #row.padata_names > 0 and table.concat(row.padata_names, ",") or "none")
    end
    transcript[#transcript + 1] = string.format("catalogue probe: %s; mask=%s", tostring(summary.policy.catalogue.detail),
      tostring(summary.policy.supported_mask or "not advertised"))
    transcript[#transcript + 1] = string.format("oracle: %s", oracle.detail)
    out["Protocol transcript"] = transcript
  end

  if summary.answered == 0 then
    worst = "INCONCLUSIVE"
  end
  out["Risk Level"] = RISK_LABEL[worst] or worst
  return out
end

-- 8. Action

action = function(host, port)
  local cfg = config.load(host)
  local principal = cfg.principal or config.machine_account(host) or "krbtgt"
  local effective_port = port.number == 88 and port.number or cfg.kdc_port
  local realm_name, realm_source = realm.resolve(host, effective_port, cfg)
  local realm_result = { realm = realm_name, source = realm_source }

  local policy = probe.policy(host, effective_port, cfg, realm_name, principal)
  local oracle = probe.oracle(host, effective_port, cfg, realm_name, principal)
  local size = probe.size_proxy(policy)
  local summary = analysis.summarise(policy, oracle, size)
  return report.build(host, port, cfg, realm_result, principal, oracle, summary)
end

-- 9. Padata capability matrix

-- Each probe sends one AS-REQ that carries exactly one padata type and reads
-- how the KDC answers. What a KDC accepts, ignores or refuses in its padata
-- field is the client-facing half of its policy: PKINIT availability, the
-- Windows-specific request elements, and the RFC 6113 negotiation types.
--
-- The values are deliberately unusable: a random blob where a structure is
-- expected, an empty container where a key would be. No credential material is
-- ever sent, and each type is probed once.
KB.PADATA_PROBES = {
  { id = 2, name = "PA-ENC-TIMESTAMP", kind = "value",
    role = "encrypted-timestamp pre-authentication: a KDC that answers this is still willing to use the account's key for pre-authentication" },
  { id = 16, name = "PA-PK-AS-REQ", kind = "value",
    role = "PKINIT: the presence of a handling path means certificate-based authentication is available" },
  { id = 128, name = "PA-PAC-REQUEST", kind = "pac_request",
    role = "the Windows element that asks the KDC to include a PAC; the answer says whether the request is honoured or ignored" },
  { id = 129, name = "PA-FOR-USER", kind = "value",
    role = "S4U2Self: an AS-REQ carrying it is a shape misuse, and the answer distinguishes a KDC that knows the type from one that does not" },
  { id = 130, name = "PA-S4U-X509-USER", kind = "value",
    role = "the certificate form of the same delegation element" },
  { id = 133, name = "PA-FX-COOKIE", kind = "raw8",
    role = "an RFC 6113 cookie sent out of context, to see whether the KDC parses it or refuses the type" },
  { id = 136, name = "PA-FX-FAST", kind = "empty",
    role = "the FAST container, sent without an armor" },
  { id = 165, name = "PA-SUPPORTED-ENCTYPES", kind = "raw4",
    role = "the bitmask the KDC usually advertises rather than receives" },
}

KB.PADATA_RESULTS = {
  unsupported = { severity = "INFO", meaning = "KDC_ERR_PADATA_TYPE_NOSUPP (16): the KDC has no handler for the type" },
  preauth = { severity = "INFO", meaning = "the KDC accepted the shape of the request and moved on to pre-authentication" },
  failed = { severity = "LOW", meaning = "the KDC tried to process the padata and refused the content, which means a handler exists" },
  ignored = { severity = "INFO", meaning = "the KDC answered as if the padata had not been sent" },
  other = { severity = "INFO", meaning = "an answer this check does not classify" },
}

-- The values the matrix sends. They are built here rather than in the engine so
-- that a reader can see exactly what went on the wire.
function wire.padata_value(kind)
  if kind == "empty" then
    return krb5.der.sequence()
  elseif kind == "raw8" then
    return string.char(0x4e, 0x4d, 0x41, 0x50, 0x00, 0x01, 0x02, 0x03)
  elseif kind == "raw4" then
    return string.char(0x00, 0x00, 0x00, 0x02)
  elseif kind == "pac_request" then
    -- SEQUENCE { include-pac [0] BOOLEAN TRUE } with the content-length form
    -- that a hand-built serializer has to get right.
    return string.char(0x30, 0x03, 0xA0, 0x03, 0x01, 0x01, 0xFF):sub(1, 5 + 2)
  end
  -- A random blob of the size the real structure would have. It cannot decrypt
  -- into anything, which is the point: the answer describes the handler, not a
  -- credential.
  local bytes = {}
  for i = 1, 48 do
    bytes[i] = string.char(math.random(0, 255))
  end
  return table.concat(bytes)
end

function probe.classify_padata(record, cfg, entry)
  local row = {
    id = entry.id,
    name = entry.name,
    role = entry.role,
    request_bytes = record.request_bytes,
    response_bytes = record.response_bytes,
    rtt_ms = record.rtt_ms,
    attempts = record.attempts,
  }
  local padata, mask = wire.method_data(record)
  row.answer_padata = padata
  row.mask = mask
  if record.kind == "krb_error" and record.krb_error then
    row.kind = "krb_error"
    row.error_code = record.krb_error.code
    row.error_name = record.krb_error.code_name
  elseif record.kind == "as_rep" then
    row.kind = "as_rep"
  else
    row.kind = "no-answer"
  end

  if row.kind == "no-answer" then
    row.result = "other"
    row.detail = string.format("no answer (%s)", tostring(record.error or "timeout"))
  elseif row.error_code == 16 then
    row.result = "unsupported"
    row.detail = "KDC_ERR_PADATA_TYPE_NOSUPP (16): the type has no handler here"
  elseif row.error_code == 24 then
    row.result = "failed"
    row.detail = "KDC_ERR_PREAUTH_FAILED (24): the KDC processed the padata and refused its content"
  elseif row.kind == "as_rep" then
    row.result = "accepted"
    row.detail = "the KDC issued a ticket for a request carrying this padata, so the type did not stop it"
  elseif row.error_code == 6 or row.error_code == 18 then
    row.result = "unavailable"
    row.detail = string.format("%s: the principal, not the padata, decided this answer", tostring(row.error_name))
  elseif row.error_code == 25 then
    row.result = "preauth"
    row.detail = string.format("%s: the padata did not stop the exchange, so the KDC has a path for it", tostring(row.error_name))
  else
    row.result = "other"
    row.detail = string.format("%s (code %s)", tostring(row.error_name or "unlisted answer"), tostring(row.error_code))
  end
  return row
end

function probe.padata_matrix(host, port, cfg, realm_name, principal)
  local matrix = { rows = {}, principal = principal }
  for _, entry in ipairs(KB.PADATA_PROBES) do
    local value = wire.padata_value(entry.kind)
    local record = wire.request(host, port, cfg, realm_name, principal, { 18, 23 },
      { krb.padata(entry.id, value) })
    matrix.rows[#matrix.rows + 1] = probe.classify_padata(record, cfg, entry)
  end
  return matrix
end

function analysis.padata_summary(matrix)
  local out = { supported = {}, unsupported = {}, other = {}, unavailable = {} }
  for _, row in ipairs(matrix.rows) do
    if row.result == "unsupported" then
      out.unsupported[#out.unsupported + 1] = row
    elseif row.result == "failed" or row.result == "accepted" then
      out.supported[#out.supported + 1] = row
    elseif row.result == "unavailable" then
      out.unavailable[#out.unavailable + 1] = row
    else
      out.other[#out.other + 1] = row
    end
  end
  return out
end

-- 10. Stability across repeats

-- A name that resolves to a pool of controllers can answer differently from one
-- request to the next. Repeating the catalogue probe and comparing the answers
-- is the cheapest way to notice, and it also gives the round-trip statistics the
-- report quotes.
function probe.repeats(host, port, cfg, realm_name, principal, times)
  local samples = {}
  for i = 1, times do
    local record = wire.request(host, port, cfg, realm_name, principal, cfg.etypes)
    local padata, mask = wire.method_data(record)
    local row = {
      index = i,
      kind = record.kind or "no-answer",
      error_code = record.krb_error and record.krb_error.code or nil,
      error_name = record.krb_error and record.krb_error.code_name or nil,
      mask = mask,
      response_bytes = record.response_bytes,
      rtt_ms = record.rtt_ms,
      padata = padata,
      etypes_named = {},
    }
    for _, entry in ipairs(krb.parse_method_data(record.krb_error and record.krb_error.e_data or "")) do
      if entry.type == 18 then
        for _, item in ipairs(krb.parse_etype_info2(entry.value)) do
          row.etypes_named[#row.etypes_named + 1] = item.etype
        end
      end
    end
    samples[#samples + 1] = row
  end
  return samples
end

function analysis.stability(samples)
  local out = { samples = samples, count = #samples, consistent = true, differences = {}, rtt = {} }
  local first
  local min, max, sum, measured = nil, nil, 0, 0
  for _, sample in ipairs(samples) do
    if sample.rtt_ms then
      measured = measured + 1
      sum = sum + sample.rtt_ms
      min = (not min or sample.rtt_ms < min) and sample.rtt_ms or min
      max = (not max or sample.rtt_ms > max) and sample.rtt_ms or max
    end
    if not first then
      first = sample
    else
      if sample.kind ~= first.kind then
        out.consistent = false
        out.differences[#out.differences + 1] = string.format("sample %d answered %s while sample 1 answered %s",
          sample.index, tostring(sample.error_name or sample.kind), tostring(first.error_name or first.kind))
      elseif sample.error_code ~= first.error_code then
        out.consistent = false
        out.differences[#out.differences + 1] = string.format("sample %d returned code %s while sample 1 returned %s",
          sample.index, tostring(sample.error_code), tostring(first.error_code))
      end
      if (sample.mask or 0) ~= (first.mask or 0) then
        out.consistent = false
        out.differences[#out.differences + 1] = string.format("sample %d advertised mask 0x%08x while sample 1 advertised 0x%08x",
          sample.index, sample.mask or 0, first.mask or 0)
      end
      if #sample.etypes_named ~= #first.etypes_named then
        out.consistent = false
        out.differences[#out.differences + 1] = string.format("sample %d named %d etype(s) while sample 1 named %d",
          sample.index, #sample.etypes_named, #first.etypes_named)
      end
    end
  end
  if measured > 0 then
    out.rtt = { min = min, max = max, average = math.floor(sum / measured + 0.5), samples = measured }
  end
  out.summary = out.consistent
    and string.format("%d repeat(s) produced the same answer", out.count)
    or string.format("%d repeat(s) disagreed, so more than one answering endpoint is likely", out.count)
  return out
end

-- 11. Extended reporting

-- The sections that need the padata matrix and the repeats are appended to the
-- table the main report produced, and their findings are ranked with it.
function report.extend(out, matrix, padata_summary, stability, cfg)
  local sections = {}
  for _, row in ipairs(matrix.rows) do
    sections[#sections + 1] = string.format("%-4d %-26s %-12s %s", row.id, row.name, row.result, tostring(row.detail))
  end
  out["Padata matrix"] = sections

  local padata_findings = {}
  if #padata_summary.unsupported > 0 then
    local names = {}
    for _, row in ipairs(padata_summary.unsupported) do
      names[#names + 1] = row.name
    end
    padata_findings[#padata_findings + 1] = {
      id = "PADATA-TYPES-UNSUPPORTED",
      severity = "INFO",
      title = string.format("%d padata type(s) have no handler on this KDC", #padata_summary.unsupported),
      evidence = { "refused with KDC_ERR_PADATA_TYPE_NOSUPP: " .. table.concat(names, ", ") },
      impact = "Each refused type is a capability this KDC does not have. The list is the client-facing half of its policy and belongs in the baseline, because a change in it is a change in what clients can negotiate.",
      remediation = "No action required; keep the list so the next run can detect a change.",
    }
  end
  if #padata_summary.supported > 0 then
    local names = {}
    for _, row in ipairs(padata_summary.supported) do
      names[#names + 1] = string.format("%s (%d)", row.name, row.id)
    end
    padata_findings[#padata_findings + 1] = {
      id = "PADATA-TYPES-SUPPORTED",
      severity = "INFO",
      title = string.format("%d padata type(s) reached a handler", #padata_summary.supported),
      evidence = { "processed rather than refused: " .. table.concat(names, ", ") },
      impact = "A handler that parses attacker-supplied structures before authentication is part of the KDC's attack surface. The observation itself is not a weakness; the point is that the surface was measured without sending any credential material.",
      remediation = "No action required. Track the list across patch cycles: a type that becomes handled is a change worth knowing about.",
    }
  end
  for _, finding in ipairs(padata_findings) do
    out["Padata findings"] = out["Padata findings"] or {}
    local lines = out["Padata findings"]
    lines[#lines + 1] = string.format("%s (%s) - %s", finding.severity, finding.id, finding.title)
    for _, item in ipairs(finding.evidence) do
      lines[#lines + 1] = "      evidence: " .. tostring(item)
    end
    lines[#lines + 1] = "      impact: " .. tostring(finding.impact)
    lines[#lines + 1] = "      remediation: " .. tostring(finding.remediation)
  end

  out["Repeat stability"] = stability.summary
  if #stability.differences > 0 then
    out["Stability differences"] = stability.differences
  end
  if stability.rtt.samples then
    out["Round trip"] = string.format("%d sample(s): min %s ms, average %s ms, max %s ms",
      stability.rtt.samples, tostring(stability.rtt.min), tostring(stability.rtt.average), tostring(stability.rtt.max))
  end

  -- A disagreeing pool of controllers raises the risk of the run: the same name
  -- answered with two different policies, so any client's behaviour depends on
  -- which backend it reached.
  if not stability.consistent then
    local worst = out["Risk Level"] or "INFO"
    local order = { INFO = 1, LOW = 2, MEDIUM = 3, HIGH = 4, CRITICAL = 5 }
    local mapped = { ["\226\154\170 INFO"] = "INFO", ["\226\154\170 INCONCLUSIVE"] = "INCONCLUSIVE" }
    for _, pair in ipairs({ { RISK_LABEL.LOW, "LOW" }, { RISK_LABEL.MEDIUM, "MEDIUM" }, { RISK_LABEL.HIGH, "HIGH" } }) do
      if worst == pair[1] then
        mapped[worst] = pair[2]
      end
    end
    local current = mapped[worst] or "INFO"
    if (order[current] or 1) < order.MEDIUM then
      out["Risk Level"] = RISK_LABEL.MEDIUM
    end
  end
  return out
end

action = function(host, port)
  local cfg = config.load(host)
  local principal = cfg.principal or config.machine_account(host) or "krbtgt"
  local effective_port = port.number == 88 and port.number or cfg.kdc_port
  local realm_name, realm_source = realm.resolve(host, effective_port, cfg)
  local realm_result = { realm = realm_name, source = realm_source }

  local policy = probe.policy(host, effective_port, cfg, realm_name, principal)
  local oracle = probe.oracle(host, effective_port, cfg, realm_name, principal)
  local size = probe.size_proxy(policy)
  local summary = analysis.summarise(policy, oracle, size)
  local out = report.build(host, port, cfg, realm_result, principal, oracle, summary)

  local matrix = probe.padata_matrix(host, effective_port, cfg, realm_name, principal)
  local padata_summary = analysis.padata_summary(matrix)
  local stability = analysis.stability(probe.repeats(host, effective_port, cfg, realm_name, principal, cfg.repeat_probes))
  return report.extend(out, matrix, padata_summary, stability, cfg)
end

-- 12. Ticket facts

-- An AS-REP that was issued describes the ticket the KDC built. The encrypted
-- part cannot be opened, so the PAC itself is out of reach, but the ticket's
-- cleartext fields are not: its service principal, its realm, its encryption
-- type and its key version. The key version is the useful one over time,
-- because it changes exactly when the principal's key is rotated, and a realm
-- that has just been through an incident response shows it.
function probe.ticket_facts(policy)
  local facts = { tickets = {}, issued_without_preauth = {} }
  for _, row in ipairs(policy.rows) do
    local record = row.record
    local rep = record and record.as_rep
    if rep and rep.ticket then
      local ticket = rep.ticket
      local enc = ticket.enc_part or {}
      local fact = {
        requested_etype = row.etype,
        requested_name = row.name,
        ticket_realm = ticket.realm,
        sname = ticket.sname and ticket.sname.text or "unknown",
        sname_type = ticket.sname and ticket.sname.name_type or nil,
        ticket_etype = enc.etype,
        kvno = enc.kvno,
        crealm = rep.crealm,
        cname = rep.cname and rep.cname.text or nil,
        reply_etype = rep.enc_part and rep.enc_part.etype,
        reply_bytes = row.response_bytes,
      }
      fact.same_realm = (ticket.realm == nil) or (ticket.realm == record.requested_realm)
      facts.tickets[#facts.tickets + 1] = fact
      -- An AS-REP for an account that did not pre-authenticate is a ticket
      -- issued without proof, which is the roastable case.
      facts.issued_without_preauth[#facts.issued_without_preauth + 1] = fact
    end
  end
  local kvnos = {}
  for _, fact in ipairs(facts.tickets) do
    if fact.kvno and not kvnos[fact.sname] then
      kvnos[fact.sname] = fact.kvno
    end
  end
  facts.kvnos = kvnos
  return facts
end

function report.ticket_section(facts)
  local lines = {}
  for _, fact in ipairs(facts.tickets) do
    lines[#lines + 1] = string.format("ticket for %s@%s issued when %s was requested: etype %s, kvno %s, %s bytes",
      tostring(fact.sname), tostring(fact.ticket_realm), tostring(fact.requested_name),
      tostring(fact.ticket_etype), tostring(fact.kvno), tostring(fact.reply_bytes))
    if not fact.same_realm then
      lines[#lines + 1] = string.format("  the ticket's realm (%s) differs from the requested realm, which is a referral, not an error",
        tostring(fact.ticket_realm))
    end
  end
  if #lines == 0 then
    lines[#lines + 1] = "no ticket was issued during this run, so the KDC's key-version state could not be sampled"
  end
  return lines
end

-- The limit of the method, stated as data rather than as a disclaimer: each row
-- is one question an operator asked of this report, and what the answer is.
function report.limits()
  return {
    "measurable: which encryption types the KDC negotiates for the probed principals, one request per type",
    "measurable: the PA-SUPPORTED-ENCTYPES mask the directory advertises and whether it agrees with the per-type answers",
    "measurable: whether an AS-REP was issued without pre-authentication, and the ticket's cleartext fields including the key version",
    "measurable: the size of an issued reply, which grows with the PAC that has to fit inside the ticket",
    "measurable: which padata types reach a handler, and how many answering endpoints are behind the name",
    "not measurable from a client: whether a service verifies the PAC signature it receives",
    "not measurable from a client: whether the KDC's signature switch is in audit or enforcement mode",
    "not measurable from a client: the contents of the PAC, which are inside the encrypted ticket",
    "the difference between the measurable and the not-measurable rows is what the remediation section closes",
  }
end

local function merge_findings(out, additions)
  local lines = out["Findings"] or {}
  for _, finding in ipairs(additions) do
    lines[#lines + 1] = string.format("[+] %s (%s) - %s", finding.severity, finding.id, finding.title)
    for _, item in ipairs(finding.evidence or {}) do
      lines[#lines + 1] = "      evidence: " .. tostring(item)
    end
    lines[#lines + 1] = "      impact: " .. tostring(finding.impact)
    lines[#lines + 1] = "      remediation: " .. tostring(finding.remediation)
  end
  out["Findings"] = lines
  return out
end

function report.finalise(out, facts, cfg)
  out["Ticket facts"] = report.ticket_section(facts)
  out["Method limits"] = report.limits()

  local additions = {}
  if #facts.tickets > 0 then
    local kvno_lines = {}
    for name, kvno in pairs(facts.kvnos) do
      kvno_lines[#kvno_lines + 1] = string.format("%s has key version %s", tostring(name), tostring(kvno))
    end
    table.sort(kvno_lines)
    additions[#additions + 1] = {
      id = "TICKET-KEY-VERSIONS",
      severity = "INFO",
      title = "The issued tickets name their key versions",
      evidence = kvno_lines,
      impact = "A key version changes exactly when the principal's key is rotated. Reading it now means the next run can tell a rotation from a coincidence, which matters after an incident because an unrotated key is the reason an incident repeats.",
      remediation = "Record the versions in the baseline and compare them after any response to a credential compromise.",
    }
  end
  if #facts.issued_without_preauth > 0 then
    local names = {}
    for _, fact in ipairs(facts.issued_without_preauth) do
      names[#names + 1] = string.format("%s@%s (%s)", tostring(fact.cname or fact.requested_name),
        tostring(fact.crealm), tostring(fact.requested_name))
    end
    additions[#additions + 1] = {
      id = "ASREP-WITHOUT-PREAUTH",
      severity = "HIGH",
      title = "A ticket was issued for a principal that never proved it holds a key",
      evidence = names,
      impact = "An AS-REP issued for a request that carried no pre-authentication material is encrypted with the account's key. It can be attacked offline, and for the machine account of a controller the same answer also discloses the account's encryption policy to anyone who asks.",
      remediation = "Remove the DONT_REQ_PREAUTH exemption from the account once the reason for it is understood; if the exemption is required, rotate the account to a long random password and treat the answer as a standing risk.",
    }
  end
  for _, fact in ipairs(facts.tickets) do
    if not fact.same_realm then
      additions[#additions + 1] = {
        id = "CROSS-REALM-TICKET",
        severity = "LOW",
        title = string.format("The KDC issued a ticket for %s while %s was requested", tostring(fact.ticket_realm),
          tostring(fact.requested_name)),
        evidence = { string.format("the ticket names %s@%s", tostring(fact.sname), tostring(fact.ticket_realm)) },
        impact = "A referral means a trust decided the answer, so the policy this report measured for the requested principal belongs to a different realm. The encryption type reading is the referral's, not the local policy's.",
        remediation = "Re-run against the realm the ticket names, or scope the report to that trust deliberately.",
      }
    end
  end
  if #additions == 0 then
    additions[#additions + 1] = {
      id = "NO-TICKET-FACTS",
      severity = "INFO",
      title = "No ticket was issued, so no key-version baseline was captured",
      evidence = { "every probe was answered with a pre-authentication or error answer" },
      impact = "The policy reading is unaffected; only the key-version history is missing from this run.",
      remediation = "Run again with a principal the realm will issue a ticket for, or with kerberos.types including a type the account accepts.",
    }
  end
  merge_findings(out, additions)
  return out
end

action = function(host, port)
  local cfg = config.load(host)
  local principal = cfg.principal or config.machine_account(host) or "krbtgt"
  local effective_port = port.number == 88 and port.number or cfg.kdc_port
  local realm_name, realm_source = realm.resolve(host, effective_port, cfg)
  local realm_result = { realm = realm_name, source = realm_source }

  local policy = probe.policy(host, effective_port, cfg, realm_name, principal)
  local oracle = probe.oracle(host, effective_port, cfg, realm_name, principal)
  local size = probe.size_proxy(policy)
  local summary = analysis.summarise(policy, oracle, size)
  local out = report.build(host, port, cfg, realm_result, principal, oracle, summary)

  local matrix = probe.padata_matrix(host, effective_port, cfg, realm_name, principal)
  local padata_summary = analysis.padata_summary(matrix)
  local stability = analysis.stability(probe.repeats(host, effective_port, cfg, realm_name, principal, cfg.repeat_probes))
  out = report.extend(out, matrix, padata_summary, stability, cfg)
  return report.finalise(out, probe.ticket_facts(policy), cfg)
end
