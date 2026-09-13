local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local string = require "string"
local table = require "table"
local math = require "math"

-- Message construction and transport come from the shared Kerberos engine.
local ok, krb5 = pcall(require, "kerberos5")

description = [[
Maps how a KDC negotiates encryption types, without any credential.

RFC 4120 lets the client offer a list of encryption types and requires the KDC
to answer with one of them; RFC 4121 and RFC 3961 define the types themselves.
Real deployments differ in ways that matter to an assessment, and this script
measures the differences instead of guessing them:

  1. Which types does the realm accept? Each catalogue entry is offered alone
     in an AS-REQ. An answer that mentions the type (an AS-REP, or a
     KDC_ERR_PREAUTH_REQUIRED whose PA-ETYPE-INFO2 lists it) means the realm
     accepts it; KDC_ERR_ETYPE_NOSUPP (14) means it does not.
  2. In which order does the KDC prefer them? One AS-REQ offers several types
     in a chosen order; the order the KDC lists salts and parameters in its
     PA-ETYPE-INFO2 answer is its own preference, which RFC 4120 leaves to the
     KDC. A KDC that answers with its own order rather than the client's is
     normal (Active Directory sorts by its own priority) but worth recording,
     because a client that depends on its own order then negotiates something
     it did not intend.
  3. What parameters come back? The salt, the iteration count and the
     string-to-key parameters of each offered type are reported as the KDC
     states them, which is what a password-audit engagement needs to reproduce
     the KDC's keys.

The script reports an inventory. It deliberately does not grade the types: the
risk of a legacy type belongs to kerberos-weak-encryption, which measures what
the realm will actually issue.

References:
  * RFC 4120 section 3.1.3 - the encryption type list a client offers and the
    KDC's obligation to choose from it
  * RFC 4120 section 5.2.7 - PA-ETYPE-INFO and the salt it carries
  * RFC 4120 section 7.5.1 - KDC_ERR_ETYPE_NOSUPP (14)
  * RFC 3961 and RFC 3962 - enctype definitions: AES-128/256 CTS mode with
    HMAC-SHA1-96, and the DES and RC4-HMAC legacy types
  * RFC 4121 - the Kerberos V5 GSS-API mechanism and its use of the negotiated
    encryption type
]]

---
-- @usage
-- nmap -p 88 --script kerberos-etype-negotiation <target>
-- nmap -p 88 --script kerberos-etype-negotiation --script-args 'kerberos.realm=EXAMPLE.COM,kerberos.principal=jsmith' <target>
--
-- @args kerberos.realm        Realm in uppercase DNS form. Discovered with a
--                             foreign realm probe when omitted.
-- @args kerberos.principal    Principal to probe with. A synthetic name works
--                             for the refusal tests, but a real one (or a name
--                             the KDC resolves) is needed for the salt and
--                             preference answers.
-- @args kerberos.etypes       Comma separated etype numbers to probe instead of
--                             the built-in catalogue (for example 18,17,23).
-- @args kerberos.max-etypes   Maximum catalogue entries to probe (default 10).
-- @args kerberos.kdc-port     KDC port (default 88).
-- @args kerberos.timeout-ms   Per-request timeout, 500-60000.
-- @args kerberos.retries      Transport retries (default 1).
-- @args kerberos.transport    "auto" (default), "udp" or "tcp".
-- @args kerberos.verbose      "true" adds the per-probe transcript.
--
-- @output
-- 88/tcp open  kerberos-sec
-- | kerberos-etype-negotiation:
-- |   Realm: EXAMPLE.COM
-- |   Negotiation matrix:
-- |     etype 18  AES256-CTS-HMAC-SHA1-96     accepted   KDC_ERR_PREAUTH_REQUIRED listed it in PA-ETYPE-INFO2
-- |     etype 23  RC4-HMAC                    accepted   KDC_ERR_PREAUTH_REQUIRED listed it in PA-ETYPE-INFO2
-- |     etype 16  DES-CBC-CRC                 refused    KDC_ERR_ETYPE_NOSUPP
-- |   KDC preference: 18, 17, 23 (the KDC's own order, not the requested order)
-- |_  Risk Level: INFO
---

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(88, "kerberos-sec", {"tcp", "udp"})

local SCRIPT_RISK = "LOW"
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

-- The catalogue is the RFC 3961/4120 registry filtered to what a KDC actually
-- offers. The family column is what the report groups by; the note column is
-- what an operator needs to know about the type, not a verdict (the verdict
-- belongs to kerberos-weak-encryption).
KB.ENCTYPES = {
  { id = 18, name = "AES256-CTS-HMAC-SHA1-96", family = "aes", keysize = 256, note = "the modern default for Active Directory" },
  { id = 17, name = "AES128-CTS-HMAC-SHA1-96", family = "aes", keysize = 128, note = "the 128 bit companion of etype 18" },
  { id = 20, name = "AES256-CTS-HMAC-SHA384-192", family = "aes-sha2", keysize = 256, note = "RFC 8009, only offered by newer implementations" },
  { id = 19, name = "AES128-CTS-HMAC-SHA256-128", family = "aes-sha2", keysize = 128, note = "RFC 8009, the 128 bit companion of etype 20" },
  { id = 23, name = "RC4-HMAC", family = "rc4", keysize = 128, note = "the legacy Active Directory default, still issued for compatibility" },
  { id = 24, name = "RC4-HMAC-EXP", family = "rc4", keysize = 56, note = "the export variant, almost never enabled" },
  { id = 16, name = "DES-CBC-CRC", family = "des", keysize = 56, note = "removed from modern KDCs; presence marks a historic configuration" },
  { id = 3, name = "DES-CBC-MD5", family = "des", keysize = 56, note = "the MIT implementation variant of DES" },
  { id = 1, name = "DES-CBC-CRC (old)", family = "des", keysize = 56, note = "the original DES type, listed for completeness" },
  { id = 5, name = "DES3-CBC-SHA1", family = "des3", keysize = 112, note = "triple DES, deprecated by RFC 8429" },
}

KB.BY_ID = {}
for _, entry in ipairs(KB.ENCTYPES) do
  KB.BY_ID[entry.id] = entry
end

function KB.describe(id)
  local entry = KB.BY_ID[id]
  if entry then
    return entry
  end
  return { id = id, name = string.format("etype %d (not in the catalogue)", id), family = "unlisted", keysize = 0,
    note = "the KDC named a type this script does not have a description for" }
end

-- The etype-bearing padata, with the registry numbers from RFC 4120 section
-- 7.5.2 as the engine implements them: PA-ETYPE-INFO (11) is the older salt
-- carrier, PA-ETYPE-INFO2 (18) is the modern one, and
-- PA-SUPPORTED-ENCTYPES (165, an MS-KILE extension) is the policy mask a
-- principal publishes.
KB.PADATA = {
  [2] = { name = "PA-ENC-TIMESTAMP", note = "the timestamp pre-authentication type, not an etype carrier" },
  [11] = { name = "PA-ETYPE-INFO", note = "the older salt carrier, one entry per accepted type" },
  [18] = { name = "PA-ETYPE-INFO2", note = "the modern salt and parameter carrier" },
  [16] = { name = "PA-PK-AS-REQ", note = "PKINIT, which changes how the reply is encrypted" },
  [128] = { name = "PA-PAC-REQUEST", note = "the PAC request extension" },
  [129] = { name = "PA-FOR-USER", note = "the S4U2Self extension" },
  [165] = { name = "PA-SUPPORTED-ENCTYPES", note = "the msDS-SupportedEncryptionTypes mask a principal publishes" },
}

KB.REMEDIATION = {
  {
    title = "Keep the offer and the policy aligned",
    steps = {
      "A KDC must be able to satisfy the types its clients offer. When the catalogue says a type is accepted but the clients do not offer it, every client negotiates the next best type and the inventory is misleading.",
      "Set msDS-SupportedEncryptionTypes on accounts deliberately: leaving it unset on an Active Directory principal means the domain default applies, which is RC4 on historic forests.",
      "After changing the policy, re-run this script: the matrix should change, and any type that is still accepted is a type the realm will really issue.",
    },
  },
  {
    title = "Record the preference order",
    steps = {
      "RFC 4120 leaves the choice among the offered types to the KDC, so the order the KDC lists in PA-ETYPE-INFO2 is its preference, not necessarily the request's order.",
      "A client that requires a specific type must offer that type alone, as this script does, rather than rely on the KDC preferring it.",
      "Store the preference order with the asset record: after a domain upgrade it is the fastest way to see that the negotiated default changed.",
    },
  },
}

KB.VERIFICATION = {
  "Confirm the policy on the directory side: msDS-SupportedEncryptionTypes on the krbtgt account and on a sample of principals, read with Get-ADUser -Properties msDS-SupportedEncryptionTypes or with an LDAP query.",
  "Confirm the client side: klist -e shows the encryption type of every ticket in a cache, and a client that cannot obtain a ticket for a service reports KDC_ERR_ETYPE_NOSUPP (14).",
  "Confirm the KDC side: a failure audit entry 4768 carries the offered types, and the Kerberos-Key-Distribution-Center log records the type actually used.",
  "Compare the matrix across controllers: a forest whose controllers disagree about the catalogue produces authentication that works on one replica and fails on another.",
}

KB.REFERENCES = {
  "RFC 4120 section 3.1.3 - the client's offer and the KDC's obligation to choose from it",
  "RFC 4120 section 5.2.7 - PA-ETYPE-INFO and PA-ETYPE-INFO2 salt parameters",
  "RFC 3961 and RFC 3962 - encryption type definitions and the AES CTS mode",
  "RFC 8009 - AES-SHA2 encryption types 19 and 20",
  "RFC 8429 - the deprecation of DES and triple DES in Kerberos",
  "Microsoft, 'Decrypting the Selection of Supported Kerberos Encryption Types' - how msDS-SupportedEncryptionTypes and the domain default interact",
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
  cfg.principal = arg_string("principal")
  cfg.max_etypes = arg_int("max-etypes", 10, 1, 20)
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

  cfg.etype_list = {}
  local listed = arg_string("etypes")
  if listed then
    for entry in string.gmatch(listed, "[^,%s]+") do
      local id = tonumber(entry)
      if id then
        cfg.etype_list[#cfg.etype_list + 1] = math.floor(id)
      end
    end
  end
  if #cfg.etype_list == 0 then
    for _, entry in ipairs(KB.ENCTYPES) do
      if #cfg.etype_list < cfg.max_etypes then
        cfg.etype_list[#cfg.etype_list + 1] = entry.id
      end
    end
  end
  return cfg
end

-- 3. Probing

local probe = {}

function probe.ask(host, port, cfg, realm, principal, etypes)
  local record = transport.as_req(host, port, {
    realm = realm,
    cname = principal,
    cname_type = NT.PRINCIPAL,
    etypes = etypes,
    kdc_options = 0,
    till = timeutil.os_utc(3600),
    nonce = math.random(1, 2147483000),
  }, {
    timeout_ms = cfg.timeout_ms,
    retries = cfg.retries,
    transport = cfg.transport,
    delay_ms = 0,
  })
  record.requested_etypes = etypes
  record.requested_realm = realm
  record.requested_cname = principal
  return record
end

-- PA-ETYPE-INFO2 (19) and PA-ETYPE-INFO (11, and its pre-RFC 4120 form 2)
-- carry (etype, salt, optional s2kparams). PA-SUPPORTED-ENCTYPES (165) carries
-- the principal's own policy mask. Both are read here so the classification
-- rests on what the KDC stated, not on what the request asked for.
function probe.read_padata(padata_entries, mentioned, extra)
  for _, entry in ipairs(padata_entries) do
    local label = (KB.PADATA[entry.type] and KB.PADATA[entry.type].name) or entry.name or "unknown padata"
    extra.padata_seen[label] = true
    if entry.type == 18 then
      for _, info in ipairs(krb.parse_etype_info2(entry.value)) do
        mentioned[#mentioned + 1] = {
          id = info.etype,
          salt = info.salt,
          s2kparams = info.s2kparams,
          source = "PA-ETYPE-INFO2 (padata 18)",
        }
      end
    elseif entry.type == 11 then
      for _, info in ipairs(krb.parse_etype_info(entry.value)) do
        mentioned[#mentioned + 1] = {
          id = info.etype,
          salt = info.salt,
          source = string.format("%s (padata %d)", label, entry.type),
        }
      end
    elseif entry.type == 165 then
      local supported, mask = krb.parse_supported_etypes(entry.value)
      extra.supported_mask = mask
      extra.supported = supported
    end
  end
end

-- Which types does the answer itself mention? An AS-REP is encrypted with one
-- of them; a KRB-ERROR names them in the PA-ETYPE-INFO* padata it carries. Both
-- are answers *about* specific types, which is what makes the classification
-- meaningful rather than a guess.
function probe.mentioned_etypes(record)
  local mentioned = {}
  local extra = { padata_seen = {} }
  local saw_as_rep = false
  if record.kind == "as_rep" and record.as_rep then
    saw_as_rep = true
    local etype = record.as_rep.enc_part and record.as_rep.enc_part.etype
    if etype then
      mentioned[#mentioned + 1] = { id = etype, source = "the AS-REP's encrypted part" }
    end
    probe.read_padata(record.as_rep.padata or {}, mentioned, extra)
  elseif record.kind == "krb_error" and record.krb_error then
    local err = record.krb_error
    probe.read_padata(krb.parse_method_data(err.e_data), mentioned, extra)
  end
  return mentioned, saw_as_rep, extra
end


-- 4. Negotiation matrix

local negotiation = {}

-- One probe per catalogue entry: the type is offered alone, so "accepted" and
-- "refused" are statements about that type and nothing else.
function negotiation.single_matrix(host, port, cfg, realm, principal, etypes)
  local rows = {}
  for _, id in ipairs(etypes) do
    local record = probe.ask(host, port, cfg, realm, principal, { id })
    local mentioned, saw_as_rep, extra = probe.mentioned_etypes(record)
    local row = {
      id = id,
      info = KB.describe(id),
      record = record,
      mentioned = mentioned,
      padata_seen = extra.padata_seen,
      supported_mask = extra.supported_mask,
      supported = extra.supported,
      salt = nil,
      s2kparams = nil,
      answered = record.kind ~= nil,
      error_code = record.krb_error and record.krb_error.code or nil,
      error_name = record.krb_error and record.krb_error.code_name or nil,
    }
    for _, item in ipairs(mentioned) do
      if item.id == id and item.salt and not row.salt then
        row.salt = item.salt
        row.s2kparams = item.s2kparams
      end
    end
    if saw_as_rep then
      row.verdict = "accepted"
      row.label = "accepted"
      row.detail = "an AS-REP was issued for this type alone (the principal needs no pre-authentication)"
    elseif record.kind == "krb_error" and record.krb_error then
      local code = record.krb_error.code
      if code == 14 then
        row.verdict = "refused"
        row.label = "refused"
        row.detail = "KDC_ERR_ETYPE_NOSUPP: the realm refused this type even when it was the only one offered"
      elseif code == 25 or code == 24 then
        local listed = nil
        for _, item in ipairs(mentioned) do
          if item.id == id then
            listed = item
            break
          end
        end
        if listed then
          row.verdict = "accepted"
          row.label = "accepted"
          row.detail = string.format("%s listed this type in %s", row.error_name or "the pre-auth answer", listed.source)
        else
          row.verdict = "ambiguous"
          row.label = "unlisted"
          row.detail = string.format("%s did not list this type in its pre-authentication data, so the answer does not decide",
            tostring(row.error_name or "the pre-auth answer"))
        end
      elseif code == 6 then
        row.verdict = "unknown-principal"
        row.label = "no principal"
        row.detail = "KDC_ERR_C_PRINCIPAL_UNKNOWN: the realm was accepted, but the probe principal does not exist, so no parameter list was disclosed"
      elseif code == 68 then
        row.verdict = "wrong-realm"
        row.label = "wrong realm"
        row.detail = string.format("KDC_ERR_WRONG_REALM: this KDC serves %s instead", tostring(record.krb_error.realm))
      else
        row.verdict = "other"
        row.label = "other"
        row.detail = string.format("%s (code %d) for a single-type offer", tostring(row.error_name or "unlisted answer"), code)
      end
    else
      row.verdict = "no-answer"
      row.label = "unanswered"
      row.detail = string.format("no answer (%s)", tostring(record.error or "timeout"))
    end
    rows[#rows + 1] = row
  end
  return rows
end

-- The preference probe: several types are offered together and the order the
-- KDC lists them in its answer is its own preference. RFC 4120 leaves the
-- choice to the KDC, so this is an observation about the deployment, not an
-- error - but a client cannot rely on its own order, and the report says so.
function negotiation.preference(host, port, cfg, realm, principal, etypes)
  local offer = {}
  for _, id in ipairs(etypes) do
    offer[#offer + 1] = id
  end
  local record = probe.ask(host, port, cfg, realm, principal, offer)
  local mentioned, saw_as_rep, extra = probe.mentioned_etypes(record)
  local order = {}
  local seen = {}
  for _, item in ipairs(mentioned) do
    if item.id and not seen[item.id] then
      seen[item.id] = true
      order[#order + 1] = item.id
    end
  end
  local out = {
    requested_order = offer,
    observed_order = order,
    record = record,
    saw_as_rep = saw_as_rep,
    etype = record.as_rep and record.as_rep.enc_part and record.as_rep.enc_part.etype or nil,
    padata_seen = extra.padata_seen,
    supported_mask = extra.supported_mask,
    supported = extra.supported,
    follows_request = true,
  }
  local limit = math.min(#offer, #order)
  for index = 1, limit do
    if offer[index] ~= order[index] then
      out.follows_request = false
      break
    end
  end
  if #order == 0 then
    out.detail = "the answer did not name an encryption type, so the preference order could not be observed"
  elseif out.follows_request then
    out.detail = "the KDC listed the types in the order they were offered"
  else
    out.detail = string.format("the KDC listed %s while %s was offered: the KDC applies its own priority",
      negotiation.join(order), negotiation.join(offer))
  end
  return out
end

function negotiation.join(list)
  local parts = {}
  for _, id in ipairs(list) do
    parts[#parts + 1] = tostring(id)
  end
  if #parts == 0 then
    return "none"
  end
  return table.concat(parts, ", ")
end

-- 5. Realm resolution

-- The realm is needed before any etype can be attributed to it. The foreign
-- realm probe is the cheapest source and the operator's answer wins when both
-- exist, because an operator who names a realm is probing that realm.
local realm = {}

function realm.resolve(host, port, cfg)
  local out = { candidates = {}, source = nil }
  local function attempt(candidate, source)
    local record = probe.ask(host, port, cfg, candidate, cfg.principal or "nmap-etype-probe", { 18, 17, 23 })
    out.candidates[#out.candidates + 1] = {
      realm = candidate,
      source = source,
      detail = record.kind == "krb_error" and (record.krb_error.code_name or "KRB-ERROR")
        or (record.kind == "as_rep" and "AS-REP") or "no answer",
      record = record,
    }
    return record
  end

  if cfg.realm then
    local record = attempt(cfg.realm, "kerberos.realm script argument")
    if record.kind then
      out.realm = cfg.realm
      out.source = "kerberos.realm script argument"
      return out
    end
  end

  local record = attempt("NMAP-INVALID-INVALID.REALM", "deliberately foreign realm")
  if record.kind == "krb_error" and record.krb_error.code == 68 and record.krb_error.realm then
    out.realm = string.upper(record.krb_error.realm)
    out.source = "KDC_ERR_WRONG_REALM leak from a deliberately foreign realm"
    return out
  end

  -- Derive from the target's name, the same way realm discovery does.
  local name = host.name or host.targetname
  if name then
    local labels = {}
    for label in string.gmatch(string.lower(name), "[^%.]+") do
      labels[#labels + 1] = label
    end
    if #labels >= 2 then
      local parts = {}
      for index = 2, #labels do
        parts[#parts + 1] = labels[index]
      end
      local candidate = string.upper(table.concat(parts, "."))
      local probe_record = attempt(candidate, "the target's own name")
      if probe_record.kind and not (probe_record.kind == "krb_error" and probe_record.krb_error.code == 68) then
        out.realm = candidate
        out.source = "the target's own name"
        return out
      end
    end
  end
  return out
end

-- 6. Reporting

local RISK_LABEL = {
  CRITICAL = "\240\159\148\180 CRITICAL",
  HIGH = "\240\159\159\160 HIGH",
  MEDIUM = "\240\159\159\161 MEDIUM",
  LOW = "\240\159\159\162 LOW",
  INFO = "\226\154\170 INFO",
  INCONCLUSIVE = "\226\154\170 INCONCLUSIVE",
}

local report = {}

function report.row_line(row, padata_lookup)
  local line = string.format("etype %-3d %-28s %-11s %s", row.id, row.info.name, row.label, row.detail)
  if row.salt then
    line = line .. string.format("\n                              salt %q%s", row.salt,
      row.s2kparams and (" s2kparams " .. row.s2kparams) or "")
  end
  return line
end

function report.build(host, port, cfg, realm_result, rows, preference)
  local out = stdnse.output_table()
  out["Script version"] = SCRIPT_VERSION
  out["Engine version"] = string.format("kerberos5.lua %s", tostring(krb5.VERSION))
  out["Declared risk class"] = SCRIPT_RISK
  out["Realm"] = realm_result.realm or "not determined"
  out["Realm source"] = realm_result.source or "not determined"
  out["Target"] = string.format("%s (%s)", tostring(host.name or host.ip or "target"),
    tostring(port.number) .. "/" .. tostring(port.protocol or "tcp"))

  local matrix = {}
  local accepted, refused, undecided = 0, 0, 0
  for _, row in ipairs(rows) do
    matrix[#matrix + 1] = report.row_line(row)
    if row.verdict == "accepted" then
      accepted = accepted + 1
    elseif row.verdict == "refused" then
      refused = refused + 1
    else
      undecided = undecided + 1
    end
  end
  out["Negotiation matrix"] = matrix
  out["Matrix summary"] = string.format("%d accepted, %d refused, %d undecided of %d probed",
    accepted, refused, undecided, #rows)

  local families = {}
  for _, row in ipairs(rows) do
    if row.verdict == "accepted" then
      families[row.info.family] = (families[row.info.family] or 0) + 1
    end
  end
  local family_lines = {}
  for _, name in ipairs({ "aes", "aes-sha2", "rc4", "des3", "des", "unlisted" }) do
    if families[name] then
      family_lines[#family_lines + 1] = string.format("%s: %d accepted type(s)", name, families[name])
    end
  end
  if #family_lines > 0 then
    out["Accepted families"] = family_lines
  end

  if preference then
    out["KDC preference"] = {
      string.format("requested order: %s", negotiation.join(preference.requested_order)),
      string.format("observed order: %s", negotiation.join(preference.observed_order)),
      preference.detail,
    }
    if preference.supported then
      out["Published policy"] = {
        string.format("the principal's PA-SUPPORTED-ENCTYPES mask 0x%s", krb5.hex32 and krb5.hex32(preference.supported_mask or 0) or tostring(preference.supported_mask or 0)),
        table.concat(preference.supported, ", "),
      }
    end
  end

  local probe_lines = {}
  for _, row in ipairs(rows) do
    probe_lines[#probe_lines + 1] = string.format("etype %d: %s", row.id,
      row.answered and (row.error_name or "answered") or "no answer")
  end
  out["Probe summary"] = probe_lines

  local findings = {}
  local function add(id, severity, title, evidence, impact, remediation)
    findings[#findings + 1] = {
      id = id, severity = severity, title = title,
      evidence = evidence, impact = impact, remediation = remediation,
    }
  end

  if accepted == 0 and refused > 0 then
    add("NO-COMMON-TYPE", "HIGH", "No probed encryption type was accepted by the realm",
      { string.format("%d type(s) refused with KDC_ERR_ETYPE_NOSUPP", refused) },
      "A client cannot obtain a ticket at all when it offers only the types this script probed. Either the catalogue is wrong for this realm, or the realm requires types outside it.",
      "Probe the realm's actual catalogue with kerberos.etypes, and reconcile the client configuration with the realm's policy.")
  elseif accepted > 0 then
    add("NEGOTIATION-MAPPED", "INFO", string.format("%d encryption type(s) are accepted by this realm", accepted),
      { string.format("probed: %s", negotiation.join(cfg.etype_list)) },
      "The matrix records which types the realm will issue, which is the input to every password-audit and cracking decision.",
      "Keep the accepted list aligned with the client configuration; re-run after each policy change.")
  end

  if undecided == #rows and #rows > 0 and accepted == 0 then
    add("NEGOTIATION-INCONCLUSIVE", "MEDIUM", "The realm answered every probe without deciding about the type",
      { "no accepted and no refused type could be established from the answers" },
      "Without a decision per type the negotiation inventory is empty. The usual cause is that the probe principal does not exist, so the KDC never reaches the pre-authentication answers that carry the parameters.",
      "Supply a principal that exists with kerberos.principal (a name the realm resolves), and re-run.")
  end

  for _, row in ipairs(rows) do
    if row.verdict == "accepted" and row.info.family == "des" then
      add("DES-ACCEPTED", "LOW", string.format("The realm still accepts %s (etype %d)", row.info.name, row.id),
        { row.detail },
        "DES is removed from every modern Kerberos implementation; a realm that still negotiates it is running a historic configuration. The exploitable-grade judgement belongs to kerberos-weak-encryption.",
        "Remove DES from the domain policy (msDS-SupportedEncryptionTypes and the KDC's supported list) after confirming that no legacy client depends on it.")
    end
  end

  if #findings == 0 then
    add("NO-FINDINGS", "INFO", "No negotiation finding was produced",
      { "the probes completed without an observation worth reporting" },
      "The scope of this run was the encryption type negotiation matrix.",
      "No action required.")
  end

  local lines = {}
  local SEVERITY_ORDER = { CRITICAL = 5, HIGH = 4, MEDIUM = 3, LOW = 2, INFO = 1 }
  table.sort(findings, function(a, b)
    local sa, sb = SEVERITY_ORDER[a.severity] or 0, SEVERITY_ORDER[b.severity] or 0
    if sa == sb then
      return tostring(a.id) < tostring(b.id)
    end
    return sa > sb
  end)
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

  local remediate = {}
  for _, group in ipairs(KB.REMEDIATION) do
    remediate[#remediate + 1] = "== " .. group.title .. " =="
    for _, step in ipairs(group.steps) do
      remediate[#remediate + 1] = "  " .. step
    end
  end
  out["Remediation"] = remediate
  out["Independent verification"] = KB.VERIFICATION
  out["References"] = KB.REFERENCES

  if cfg.verbose then
    local transcript = {}
    transcript[#transcript + 1] = string.format("target %s port %d transport %s timeout %d ms",
      tostring(host.ip), cfg.kdc_port, cfg.transport, cfg.timeout_ms)
    for _, entry in ipairs(realm_result.candidates or {}) do
      transcript[#transcript + 1] = string.format("realm candidate %s (%s): %s", entry.realm, entry.source, entry.detail)
    end
    for _, row in ipairs(rows) do
      transcript[#transcript + 1] = string.format("AS-REQ offer { %d } -> %s (%s)", row.id, row.label,
        row.answered and "answered" or "no answer")
    end
    if preference then
      transcript[#transcript + 1] = string.format("AS-REQ offer { %s } -> %s", negotiation.join(preference.requested_order),
        negotiation.join(preference.observed_order))
    end
    out["Protocol transcript"] = transcript
  end

  out["Risk Level"] = RISK_LABEL[worst] or worst
  return out
end

-- 7. Action

action = function(host, port)
  local cfg = config.load(host)
  local effective_port = port.number == 88 and port.number or cfg.kdc_port
  local realm_result = realm.resolve(host, effective_port, cfg)

  if not realm_result.realm then
    local out = stdnse.output_table()
    out["Script version"] = SCRIPT_VERSION
    out["Engine version"] = string.format("kerberos5.lua %s", tostring(krb5.VERSION))
    out["Declared risk class"] = SCRIPT_RISK
    out["Realm"] = "not determined"
    out["Summary"] = {
      "The realm could not be established, and an encryption type cannot be attributed to a realm that is unknown.",
      "Supply it with kerberos.realm, or run kerberos-realm-discovery against the same target first.",
    }
    out["Evidence"] = {
      string.format("%d realm candidate(s) probed", #(realm_result.candidates or {})),
    }
    out["Risk Level"] = RISK_LABEL.INCONCLUSIVE
    return out
  end

  local principal = cfg.principal or "nmap-etype-probe"
  local rows = negotiation.single_matrix(host, effective_port, cfg, realm_result.realm, principal, cfg.etype_list)
  local preference = negotiation.preference(host, effective_port, cfg, realm_result.realm, principal, cfg.etype_list)
  return report.build(host, port, cfg, realm_result, rows, preference)
end
