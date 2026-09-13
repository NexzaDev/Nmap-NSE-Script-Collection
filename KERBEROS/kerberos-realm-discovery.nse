local nmap = require "nmap"
local stdnse = require "stdnse"
local shortport = require "shortport"
local string = require "string"
local table = require "table"
local math = require "math"

-- Message construction and transport come from the shared Kerberos engine.
local ok, krb5 = pcall(require, "kerberos5")

description = [[
Discovers the Kerberos realm of a KDC without any credential.

A realm is not a secret - the protocol publishes it in three separate ways,
and this script collects all of them instead of trusting one:

  1. KDC_ERR_WRONG_REALM. RFC 4120 section 7.5.1 requires a KDC to answer a
     request for a realm it does not serve with error 68, carrying the realm it
     does serve. The script asks for a realm that cannot exist, so one packet
     can name the target realm.
  2. KDC_ERR_C_PRINCIPAL_UNKNOWN / KDC_ERR_PREAUTH_REQUIRED. An AS-REQ for a
     synthetic principal in a candidate realm proves the KDC serves that realm:
     the answer decides about the principal, not about the realm.
  3. Naming conventions. An Active Directory realm is the DNS domain in upper
     case, and the target's own name (dc01.corp.example.com) discloses it, so
     the realm can be derived even when the operator supplies nothing.

Each candidate is probed and classified, and the report carries the realm, the
evidence that produced it and a confidence level. Refused candidates are
reported as well: a realm list is an inventory, and the refusals are what make
it trustworthy.
]]

---
-- @usage
-- nmap -p 88 --script kerberos-realm-discovery <target>
-- nmap -p 88 --script kerberos-realm-discovery --script-args 'kerberos.realm-candidates=CORP.EXAMPLE.COM,EXAMPLE.COM' <target>
--
-- @args kerberos.realm             A realm the operator already knows. It is
--                                  used as the first candidate and, when the
--                                  KDC confirms it, short circuits the search.
-- @args kerberos.realm-candidates  Comma separated list of further candidates.
-- @args kerberos.realm-max         Maximum number of candidates to probe
--                                  (default 8, maximum 32).
-- @args kerberos.kdc-port          KDC port (default 88).
-- @args kerberos.timeout-ms        Per-request timeout, 500-60000.
-- @args kerberos.retries           Transport retries (default 1).
-- @args kerberos.transport         "auto" (default), "udp" or "tcp".
-- @args kerberos.verbose           "true" adds the per-candidate transcript.
--
-- @output
-- 88/tcp open  kerberos-sec
-- | kerberos-realm-discovery:
-- |   Discovered realm: CORP.EXAMPLE.COM
-- |   Method: KDC_ERR_WRONG_REALM leak from a deliberately foreign realm
-- |   Confidence: HIGH
-- |   Candidates probed: 4
-- |_  Risk Level: LOW
---

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(88, "kerberos-sec", {"tcp", "udp"})

local SCRIPT_RISK = "LOW"
local SCRIPT_VERSION = "2.0.0"

if not ok or type(krb5) ~= "table" then
  -- The engine missing is a deployment problem: say so instead of emitting a
  -- canned result.
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

-- The realm-bearing errors, and what each one proves about the realm that was
-- addressed. The distinction matters: a realm-scoped answer means the KDC
-- served that realm, a principal-scoped answer means it did not refuse the
-- realm either, and a realm refusal means the KDC serves something else.
KB.REALM_ERRORS = {
  {
    code = 68,
    name = "KDC_ERR_WRONG_REALM",
    scope = "realm",
    meaning = "the KDC does not serve the realm we named and its answer carries the realm it does serve",
  },
  {
    code = 6,
    name = "KDC_ERR_C_PRINCIPAL_UNKNOWN",
    scope = "principal",
    meaning = "the realm was accepted and the principal lookup failed, so the KDC serves this realm",
  },
  {
    code = 25,
    name = "KDC_ERR_PREAUTH_REQUIRED",
    scope = "principal",
    meaning = "the realm was accepted and the principal exists; the KDC wants pre-authentication before it answers",
  },
  {
    code = 18,
    name = "KDC_ERR_CLIENT_REVOKED",
    scope = "principal",
    meaning = "the realm was accepted and the principal exists but is disabled or locked",
  },
  {
    code = 14,
    name = "KDC_ERR_ETYPE_NOSUPP",
    scope = "realm",
    meaning = "the realm was accepted and then refused every encryption type offered, so this KDC serves it",
  },
  {
    code = 12,
    name = "KDC_ERR_POLICY",
    scope = "realm",
    meaning = "the realm was accepted but a policy refused the request; the realm itself is served here",
  },
  {
    code = 7,
    name = "KDC_ERR_S_PRINCIPAL_UNKNOWN",
    scope = "principal",
    meaning = "the realm was accepted; the service principal in the request is unknown",
  },
  {
    code = 37,
    name = "KRB_AP_ERR_SKEW",
    scope = "realm",
    meaning = "the realm was accepted and the request's timestamp was rejected, which still proves the realm",
  },
}

KB.ERROR_BY_CODE = {}
for _, entry in ipairs(KB.REALM_ERRORS) do
  KB.ERROR_BY_CODE[entry.code] = entry
end

-- Answers that are neither a realm confirmation nor a realm refusal. They are
-- reported as they are rather than being forced into one of the two buckets.
KB.OTHER_ANSWERS = {
  [0] = "an AS-REP was issued: the realm exists and this principal has no pre-authentication requirement",
  [24] = "KDC_ERR_PREAUTH_FAILED: the realm exists and rejected the pre-authentication data (never sent by this script)",
  [29] = "KDC_ERR_SVC_UNAVAILABLE: the KDC is up but a service it depends on is not, so the realm answer is inconclusive",
  [52] = "KRB_ERR_RESPONSE_TOO_BIG: the answer arrived over UDP but did not fit; retry with TCP",
  [59] = "KDC_ERR_NEVER_VALID: the requested validity window is impossible, which still proves the realm is served",
}

-- The naming conventions the script uses to derive candidates from a name.
-- They are the same conventions the Active Directory documentation describes.
KB.NAMING_RULES = {
  {
    id = "dns-upper",
    description = "the DNS domain of the target in upper case (the Active Directory realm)",
    pattern = "corp.example.com -> CORP.EXAMPLE.COM",
  },
  {
    id = "dns-parents",
    description = "each parent domain of the target's DNS name, in upper case",
    pattern = "dc01.corp.example.com -> CORP.EXAMPLE.COM, EXAMPLE.COM, COM",
  },
  {
    id = "netbios",
    description = "the first label of the DNS domain, which is the NetBIOS domain name",
    pattern = "corp.example.com -> CORP",
  },
  {
    id = "single-label",
    description = "the target's own short name, which a single-label realm uses",
    pattern = "DC01 -> DC01",
  },
}

KB.REMEDIATION = {
  {
    title = "No action required for the disclosure itself",
    steps = {
      "A Kerberos realm is published by design: the KDC must tell a client which realm it serves, or no client could ever authenticate. Realm discovery is reconnaissance, not a vulnerability.",
      "Do not attempt to hide the realm by disabling the KDC_ERR_WRONG_REALM answer: clients that are configured with a stale realm then fail with an ambiguous error, and the realm is still derivable from DNS SRV records.",
      "Record the realm in the asset inventory so that the discovery step is not needed on the next engagement.",
    },
  },
  {
    title = "Reduce the reconnaissance value around it",
    steps = {
      "Publish only the SRV records the domain needs (_kerberos._udp, _kerberos._tcp, _ldap._tcp) and review the remainder for hosts that are not domain controllers.",
      "Keep unauthenticated principal enumeration separate from realm discovery: this script never confirms whether a principal exists on the strength of a single answer, because AD can be configured to normalise the response.",
      "If the environment has a two-realm trust, expect a cross-realm referral: the realm that answers is not always the realm that authenticates the user.",
    },
  },
}

KB.VERIFICATION = {
  "Confirm the discovered realm on a domain-joined host: echo %USERDNSDOMAIN% returns the DNS domain and set USERDNSDOMAIN on Linux, klist -d lists the realm of the current credential cache.",
  "Cross-check the KDC list: nslookup -type=SRV _kerberos._udp(<discovered realm>) returns every KDC the domain publishes.",
  "Run the check from outside the domain and from inside it: a KDC that answers foreign realms externally and refuses them internally is a segmentation finding, not a discovery one.",
}

KB.REFERENCES = {
  "RFC 4120 section 7.5.1 - KRB-ERROR and the KDC_ERR_WRONG_REALM (68) answer that carries the served realm",
  "RFC 4120 section 3.1.5 - realms and the convention that they are DNS names in upper case",
  "RFC 4120 section 5.4.1 - the AS-REQ fields this script varies",
  "RFC 4121 and RFC 3961 - the encryption types that decide KDC_ERR_ETYPE_NOSUPP answers",
  "Microsoft, 'How Domain Controllers Are Located in Windows' - SRV records and the realm/DNS relationship",
}

-- ---------------------------------------------------------------------------
-- 2. Configuration
-- ---------------------------------------------------------------------------

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
  cfg.realm_candidates = {}
  local list = arg_string("realm-candidates") or arg_string("realms")
  if list then
    for entry in string.gmatch(list, "[^,%s]+") do
      cfg.realm_candidates[#cfg.realm_candidates + 1] = string.upper(entry)
    end
  end
  cfg.max_candidates = arg_int("realm-max", 8, 1, 32)
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

-- ---------------------------------------------------------------------------
-- 3. Candidate generation
-- ---------------------------------------------------------------------------

local candidates = {}

-- A name is turned into the realm forms the deployment could be using. The
-- order is deliberate: the Active Directory convention (DNS domain in upper
-- case) is tried before the NetBIOS and single-label forms, because a realm
-- that exists is answered on the first probe.
function candidates.from_name(name, list, seen)
  if not name or #name == 0 then
    return
  end
  local clean = string.lower(name)
  clean = string.gsub(clean, "%.$", "")
  -- Host names and DNS names both arrive here; the realm candidates are the
  -- domain part, so a leading host label is dropped when the name has one.
  local labels = {}
  for label in string.gmatch(clean, "[^%.]+") do
    labels[#labels + 1] = label
  end
  if #labels < 2 then
    return
  end
  local function push(realm)
    realm = string.upper(realm)
    if #realm > 0 and not seen[realm] then
      seen[realm] = true
      list[#list + 1] = realm
    end
  end
  -- The full domain, then each parent domain, then the first label alone.
  for start = 2, #labels do
    local parts = {}
    for index = start, #labels do
      parts[#parts + 1] = labels[index]
    end
    push(table.concat(parts, "."))
  end
  push(labels[2])
  push(labels[#labels])
end

-- Candidates in priority order: what the operator supplied, then everything
-- the target's own names disclose. The list is capped so a target with an
-- unusual name cannot turn the script into a packet generator.
function candidates.build(host, cfg)
  local list = {}
  local seen = {}
  local function push(realm, source)
    if realm == nil then
      return
    end
    realm = string.upper(realm)
    if #realm == 0 or seen[realm] then
      return
    end
    seen[realm] = true
    list[#list + 1] = { realm = realm, source = source }
  end

  if cfg.realm then
    push(cfg.realm, "kerberos.realm script argument")
  end
  for _, entry in ipairs(cfg.realm_candidates) do
    push(entry, "kerberos.realm-candidates script argument")
  end

  local generated = {}
  local generated_seen = {}
  -- Only information the scan already carries is used: a reverse DNS lookup
  -- would add a dependency and a network round trip to the scanner host, and
  -- the realm is usually visible in the name the target itself reports.
  candidates.from_name(host.name, generated, generated_seen)
  candidates.from_name(host.targetname, generated, generated_seen)
  for _, realm in ipairs(generated) do
    push(realm, "the target's own name")
  end

  local capped = {}
  for _, entry in ipairs(list) do
    if #capped < cfg.max_candidates then
      capped[#capped + 1] = entry
    end
  end
  return capped
end

-- The realm that cannot exist. Any answer other than KDC_ERR_WRONG_REALM means
-- the KDC did not treat the request as a foreign realm at all, which is itself
-- worth reporting.
candidates.IMPOSSIBLE_REALM = "NMAP-INVALID-INVALID.REALM"


-- ---------------------------------------------------------------------------
-- 4. Probing
-- ---------------------------------------------------------------------------

local probe = {}

-- The error registry in the knowledge base is the decision table: an answer
-- that mentions the realm proves the realm, an answer that refuses it proves
-- something else, and anything unlisted is reported as an unclassified answer
-- rather than folded into one of the two.
function probe.classify(record)
  local out = {
    request_realm = record.requested_realm,
    request_principal = record.requested_cname,
    transport = record.transport,
    rtt_ms = record.rtt_ms,
    attempts = record.attempts,
  }
  if record.kind == "as_rep" then
    out.class = "realm-confirmed"
    out.label = "confirmed"
    out.detail = "an AS-REP was issued, so the realm exists and the probe principal needs no pre-authentication"
    out.evidence_code = 0
    out.evidence_name = "AS-REP"
    return out
  end
  if record.kind == "krb_error" and record.krb_error then
    local err = record.krb_error
    out.error_code = err.code
    out.error_name = err.code_name
    out.error_text = err.e_text
    out.error_realm = err.realm
    local entry = KB.ERROR_BY_CODE[err.code]
    if entry then
      out.evidence_code = err.code
      out.evidence_name = entry.name
      if entry.scope == "realm" then
        out.class = "realm-served"
        out.label = "served"
        out.detail = err.code_name .. ": " .. entry.meaning
      else
        out.class = "realm-confirmed"
        out.label = "confirmed"
        out.detail = err.code_name .. ": " .. entry.meaning
      end
    else
      local other = KB.OTHER_ANSWERS[err.code]
      out.class = "other-answer"
      out.label = "answered"
      out.detail = string.format("%s (code %d)%s", tostring(err.code_name or "unlisted error"), err.code,
        other and (": " .. other) or "")
    end
    if err.code == 68 and err.realm and #err.realm > 0 then
      out.leaked_realm = string.upper(err.realm)
      out.class = "realm-refused"
      out.label = "refused"
      out.detail = string.format("KDC_ERR_WRONG_REALM: this KDC serves %s instead", out.leaked_realm)
    elseif err.code == 52 then
      out.retry_tcp = true
    end
    return out
  end
  out.class = "no-answer"
  out.label = "unanswered"
  out.detail = string.format("no Kerberos answer (%s)", tostring(record.error or "timeout"))
  return out
end

function probe.ask(host, port, cfg, realm, principal)
  local record = transport.as_req(host, port, {
    realm = realm,
    cname = principal,
    cname_type = NT.PRINCIPAL,
    etypes = krb5.ETYPE_OFFER_DEFAULT,
    kdc_options = 0,
    till = timeutil.os_utc(3600),
    nonce = math.random(1, 2147483000),
  }, {
    timeout_ms = cfg.timeout_ms,
    retries = cfg.retries,
    transport = cfg.transport,
    delay_ms = 0,
  })
  record.requested_realm = realm
  record.requested_cname = principal
  return probe.classify(record)
end

-- ---------------------------------------------------------------------------
-- 5. Discovery
-- ---------------------------------------------------------------------------

local discovery = {}

-- The cheapest probe there is: a realm that cannot exist. A KDC that serves
-- anything is supposed to answer KDC_ERR_WRONG_REALM with its own realm, which
-- resolves the question in one packet and without touching a real principal.
function discovery.leak_probe(host, port, cfg)
  local verdict = probe.ask(host, port, cfg, candidates.IMPOSSIBLE_REALM, "nmap-realm-leak-probe")
  verdict.purpose = "deliberately foreign realm"
  if verdict.class == "realm-refused" and verdict.leaked_realm then
    verdict.conclusive = true
  elseif verdict.class == "no-answer" then
    verdict.conclusive = false
  else
    -- The KDC answered something other than "wrong realm" for a realm that
    -- cannot exist, which means it resolves realms locally or normalises the
    -- error. Either way the answer does not name the target realm.
    verdict.conclusive = false
  end
  return verdict
end

-- Validation of one candidate: a synthetic principal that cannot exist is
-- enough, because the KDC decides about the realm before it looks the
-- principal up.
function discovery.validate(host, port, cfg, realm, index)
  local principal = string.format("nmap-realm-probe-%d", index or 1)
  local verdict = probe.ask(host, port, cfg, realm, principal)
  verdict.purpose = "candidate realm validation"
  return verdict
end

-- The full search. The leak probe runs first because it is the only probe that
-- can name a realm the operator did not guess; the candidate list then
-- confirms it and covers the case where the KDC does not leak.
function discovery.resolve(host, port, cfg)
  local result = {
    candidates = {},
    evidence = {},
    kdc_answered = false,
  }

  result.leak = discovery.leak_probe(host, port, cfg)
  result.evidence[#result.evidence + 1] = string.format("foreign realm %s: %s",
    candidates.IMPOSSIBLE_REALM, result.leak.detail)
  if result.leak.class ~= "no-answer" then
    result.kdc_answered = true
  end

  local ordered = candidates.build(host, cfg)
  if result.leak.leaked_realm then
    -- The leaked realm goes first so the search stops on the first probe.
    table.insert(ordered, 1, { realm = result.leak.leaked_realm, source = "KDC_ERR_WRONG_REALM leak" })
  end

  local seen = {}
  local index = 0
  for _, entry in ipairs(ordered) do
    if not seen[entry.realm] then
      seen[entry.realm] = true
      index = index + 1
      local verdict = discovery.validate(host, port, cfg, entry.realm, index)
      verdict.source = entry.source
      result.candidates[#result.candidates + 1] = verdict
      if verdict.class ~= "no-answer" then
        result.kdc_answered = true
      end
      if not result.realm and verdict.class == "realm-confirmed" then
        result.realm = entry.realm
        result.realm_source = entry.source
        result.realm_probe = verdict
      end
    end
  end

  -- Confidence: a leak is the strongest evidence, a confirmed candidate is
  -- strong, and a realm that only the naming convention suggested is weak.
  if result.leak.conclusive and result.realm == result.leak.leaked_realm then
    result.method = "KDC_ERR_WRONG_REALM leak from a deliberately foreign realm"
    result.confidence = "HIGH"
  elseif result.realm and result.realm_probe and result.realm_probe.class == "realm-confirmed" then
    result.method = "candidate realm confirmed by the KDC's answer about the probe principal"
    result.confidence = "HIGH"
  elseif result.realm and result.realm_probe and result.realm_probe.class == "realm-served" then
    result.method = "candidate realm accepted and then refused on policy grounds"
    result.confidence = "MEDIUM"
  elseif result.leak.leaked_realm and not result.realm then
    result.method = "the leak named a realm that the candidate probes could not confirm"
    result.confidence = "MEDIUM"
    result.realm = result.leak.leaked_realm
    result.realm_source = "KDC_ERR_WRONG_REALM leak (unconfirmed)"
  elseif result.kdc_answered then
    result.method = "no candidate was confirmed"
    result.confidence = "INCONCLUSIVE"
  else
    result.method = "the KDC did not answer any probe"
    result.confidence = "INCONCLUSIVE"
  end
  return result
end

-- ---------------------------------------------------------------------------
-- 6. Reporting
-- ---------------------------------------------------------------------------

local RISK_LABEL = {
  CRITICAL = "\240\159\148\180 CRITICAL",
  HIGH = "\240\159\159\160 HIGH",
  MEDIUM = "\240\159\159\161 MEDIUM",
  LOW = "\240\159\159\162 LOW",
  INFO = "\226\154\170 INFO",
  INCONCLUSIVE = "\226\154\170 INCONCLUSIVE",
}

local report = {}

function report.findings(result, cfg)
  local list = {}
  local function add(finding)
    list[#list + 1] = finding
  end

  if result.realm then
    add({
      id = "REALM-DISCLOSED",
      severity = "INFO",
      title = string.format("The Kerberos realm %s is published by this KDC", result.realm),
      evidence = {
        string.format("method: %s", result.method),
        string.format("confidence: %s", result.confidence),
        result.realm_probe and string.format("answer that confirmed it: %s", result.realm_probe.detail) or nil,
      },
      impact = "A realm is not a secret: the protocol requires it to be discoverable so that clients can authenticate. It is inventory, not a vulnerability.",
      remediation = "Record the realm in the asset inventory and use it to scope the rest of the assessment.",
    })
  else
    add({
      id = "REALM-NOT-DISCOVERED",
      severity = "MEDIUM",
      title = "No Kerberos realm could be established for this target",
      evidence = {
        string.format("%d candidate(s) probed", #result.candidates),
        result.kdc_answered and "the KDC answered at least one probe" or "the KDC did not answer any probe",
      },
      impact = "Without the realm, every later Kerberos check has to guess, and a KDC that answers nothing is either filtered, not a KDC, or listening on a different port.",
      remediation = "Confirm the port and the transport (kerberos.transport=tcp), supply the realm with kerberos.realm, and re-run.",
    })
  end

  if result.leak and result.leak.class == "other-answer" then
    add({
      id = "LEAK-NOT-HONOURED",
      severity = "INFO",
      title = "The KDC does not answer a foreign realm with KDC_ERR_WRONG_REALM",
      evidence = { result.leak.detail },
      impact = "The single-packet realm leak does not work here, so the realm has to come from the candidate list or from the operator. Some appliances answer every realm identically to avoid disclosing the realm; others simply are not Active Directory.",
      remediation = "No action required. Add the known realm to kerberos.realm to skip the search.",
    })
  end

  if result.leak and result.leak.retry_tcp then
    add({
      id = "UDP-TRUNCATION",
      severity = "LOW",
      title = "At least one answer was too large for UDP",
      evidence = { result.leak.detail },
      impact = "A KDC answer that does not fit a datagram forces the client to retry over TCP. Clients that do not retry report a spurious authentication failure.",
      remediation = "Ensure both UDP/88 and TCP/88 reach the KDC from every client subnet, and let the client library fall back to TCP.",
    })
  end

  if #result.candidates > 0 then
    local refused = 0
    for _, entry in ipairs(result.candidates) do
      if entry.class == "realm-refused" then
        refused = refused + 1
      end
    end
    if refused > 0 then
      add({
        id = "REALM-REDIRECTED",
        severity = "INFO",
        title = string.format("%d candidate realm(s) were redirected to another realm", refused),
        evidence = { "the answers carried KDC_ERR_WRONG_REALM with the served realm" },
        impact = "In a forest with a trust, a client that asks for the wrong realm is redirected rather than rejected. That is normal, but it means a realm name in a configuration file can silently point at a different forest.",
        remediation = "Verify the realm in every client configuration against the realm the KDC actually serves.",
      })
    end
  end

  if #list == 0 then
    add({
      id = "NO-FINDINGS",
      severity = "INFO",
      title = "No realm observation was produced",
      evidence = { "the probes completed without a classified answer" },
      impact = "The scope of this run was realm discovery.",
      remediation = "No action required.",
    })
  end
  return list
end

local SEVERITY_ORDER = { CRITICAL = 5, HIGH = 4, MEDIUM = 3, LOW = 2, INFO = 1 }

function report.build(host, port, cfg, result)
  local out = stdnse.output_table()
  out["Script version"] = SCRIPT_VERSION
  out["Engine version"] = string.format("kerberos5.lua %s", tostring(krb5.VERSION))
  out["Declared risk class"] = SCRIPT_RISK
  out["Discovered realm"] = result.realm or "not determined"
  out["Method"] = result.method
  out["Confidence"] = result.confidence
  out["Target"] = string.format("%s (%s)", tostring(host.name or host.ip or "target"),
    tostring(port.number) .. "/" .. tostring(port.protocol or "tcp"))
  out["Candidates probed"] = #result.candidates

  local matrix = {}
  matrix[#matrix + 1] = "candidate realm            result      evidence"
  for _, entry in ipairs(result.candidates) do
    matrix[#matrix + 1] = string.format("%-26s %-11s %s (%s)", entry.request_realm, entry.label,
      entry.detail, tostring(entry.source))
    if cfg.verbose and entry.rtt_ms then
      matrix[#matrix + 1] = string.format("%-26s %-11s round trip %d ms over %s, %d attempt(s)",
        "", "", entry.rtt_ms, tostring(entry.transport), entry.attempts or 1)
    end
  end
  out["Candidate matrix"] = matrix

  local evidence = {}
  for _, line in ipairs(result.evidence) do
    evidence[#evidence + 1] = line
  end
  if result.leak and result.leak.leaked_realm then
    evidence[#evidence + 1] = string.format("the foreign realm probe was answered with %s", result.leak.leaked_realm)
  end
  for _, entry in ipairs(result.candidates) do
    if entry.class ~= "no-answer" then
      evidence[#evidence + 1] = string.format("%s -> %s", entry.request_realm, entry.detail)
    end
  end
  out["Evidence"] = evidence

  local findings = report.findings(result, cfg)
  local lines = {}
  for index, finding in ipairs(findings) do
    lines[#lines + 1] = string.format("[%d] %s (%s) - %s", index, finding.severity, finding.id, finding.title)
    for _, item in ipairs(finding.evidence or {}) do
      if item then
        lines[#lines + 1] = "      evidence: " .. tostring(item)
      end
    end
    lines[#lines + 1] = "      impact: " .. tostring(finding.impact)
    lines[#lines + 1] = "      remediation: " .. tostring(finding.remediation)
  end
  out["Findings"] = lines

  if result.confidence ~= "HIGH" then
    local naming = {}
    for _, rule in ipairs(KB.NAMING_RULES) do
      naming[#naming + 1] = string.format("%s: %s (%s)", rule.id, rule.description, rule.pattern)
    end
    out["Naming conventions used"] = naming
    local remediation = {}
    for _, group in ipairs(KB.REMEDIATION) do
      remediation[#remediation + 1] = "== " .. group.title .. " =="
      for _, step in ipairs(group.steps) do
        remediation[#remediation + 1] = "  " .. step
      end
    end
    out["Remediation"] = remediation
  end

  out["Independent verification"] = KB.VERIFICATION
  out["References"] = KB.REFERENCES

  if cfg.verbose then
    local transcript = {}
    transcript[#transcript + 1] = string.format("target %s port %d transport %s timeout %d ms",
      tostring(host.ip), cfg.kdc_port, cfg.transport, cfg.timeout_ms)
    transcript[#transcript + 1] = string.format("foreign realm probe: %s", result.leak.detail)
    for _, entry in ipairs(result.candidates) do
      transcript[#transcript + 1] = string.format("%s via %s: %s", entry.request_realm,
        tostring(entry.transport), entry.detail)
    end
    out["Protocol transcript"] = transcript
  end

  local worst = "INFO"
  for _, finding in ipairs(findings) do
    if (SEVERITY_ORDER[finding.severity] or 0) > (SEVERITY_ORDER[worst] or 0) then
      worst = finding.severity
    end
  end
  if worst == "INFO" and result.confidence == "INCONCLUSIVE" then
    worst = "INCONCLUSIVE"
  end
  out["Risk Level"] = RISK_LABEL[worst] or worst
  return out
end

-- ---------------------------------------------------------------------------
-- 7. Action
-- ---------------------------------------------------------------------------

action = function(host, port)
  local cfg = config.load(host)
  local effective_port = port.number == 88 and port.number or cfg.kdc_port
  local result = discovery.resolve(host, effective_port, cfg)
  return report.build(host, port, cfg, result)
end
