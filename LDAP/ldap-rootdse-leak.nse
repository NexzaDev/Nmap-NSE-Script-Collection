local shortport = require "shortport"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Queries rootDSE for namingContexts, defaultNamingContext, dnsHostName, domainFunctionality.

Why it matters
- The rootDSE is readable without any bind and can leak the forest/domain
  naming context, the DC host name and the domain functional level.
- That combination lets an off-network attacker pre-position for
  targeted attacks (knowing the domain and DC host) even before a bind.

What the script does
1. Opens a TCP session and issues a scope=base search on the rootDSE
   ("") requesting the high-signal identity attributes.
2. Records which identity attributes the server actually returned.
3. Classifies the severity of the identity exposure.

Safe operation: a single read-only scope=base search; no bind, no write.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

portrule = shortport.port_or_service(
  389,
  "ldap",
  "tcp"
)

local SCRIPT_NAME = "ldap-rootdse-leak"

local RISK_LEVEL = "🟡 MEDIUM"

local DEFAULT_ARGS = {
  maxrequests = 16,
  timeout = 8,
}

local NUMERIC_ARGS = {
  { key = "maxrequests", minimum = 1, integer = true },
  { key = "timeout", minimum = 1, integer = true },
}

local BOOLEAN_ARGS = {}

local STRING_ARGS = {}

local ROOTDSE_CVSS = "5.3"

local HIGH_SIGNAL_ATTRS = {
  { name = "namingContexts", label = "naming context(s)" },
  { name = "defaultNamingContext", label = "default naming context" },
  { name = "dnsHostName", label = "DC DNS host name" },
  { name = "domainFunctionality", label = "domain functional level" },
  { name = "supportedSASLMechanisms", label = "SASL mechanisms" },
  { name = "supportedLDAPVersion", label = "LDAP version" },
  { name = "serverName", label = "NTDS server name" },
  { name = "isGlobalCatalogReady", label = "global catalog state" },
}

local SEVERITY = {
  CRITICAL = 10,
  HIGH = 7,
  MEDIUM = 4,
  LOW = 2,
  INFO = 1,
}

local function trim(value)
  if type(value) ~= "string" then
    return value
  end
  value = string.gsub(value, "^%s+", "")
  value = string.gsub(value, "%s+$", "")
  return value
end

local function lower(value)
  if type(value) ~= "string" then
    return ""
  end
  return string.lower(trim(value))
end

local function starts_with(value, prefix)
  return string.sub(value, 1, #prefix) == prefix
end

local function ends_with(value, suffix)
  if #suffix > #value then
    return false
  end
  return string.sub(value, -#suffix) == suffix
end

local function contains(value, needle)
  return string.find(value or "", needle, 1, true) ~= nil
end

local function split(value, separator)
  local parts = {}
  if type(value) ~= "string" or #value == 0 then
    return parts
  end
  for chunk in string.gmatch(value, "([^" .. separator .. "]+)") do
    table.insert(parts, trim(chunk))
  end
  return parts
end

local function list_contains(list, needle)
  for _, item in ipairs(list or {}) do
    if item == needle then
      return true
    end
  end
  return false
end

local function table_size(tbl)
  local count = 0
  for _ in pairs(tbl or {}) do
    count = count + 1
  end
  return count
end

local function sorted_keys(tbl)
  local keys = {}
  for key in pairs(tbl or {}) do
    table.insert(keys, key)
  end
  table.sort(keys)
  return keys
end

local function unique_append(list, seen, value)
  if seen[value] then
    return false
  end
  seen[value] = true
  table.insert(list, value)
  return true
end

local function clamp(value, minimum, maximum)
  if value < minimum then
    return minimum
  end
  if value > maximum then
    return maximum
  end
  return value
end

local function byte_hex(value, count)
  local out = {}
  for i = 1, math.min(count or 16, #(value or "")) do
    table.insert(out, string.format("%02x", string.byte(value, i)))
  end
  return table.concat(out, " ")
end

local function truncate(value, limit)
  if type(value) ~= "string" then
    return tostring(value)
  end
  if #value <= limit then
    return value
  end
  return string.sub(value, 1, limit) .. "..."
end

local function fnv1a32(value)
  local hash = 2166136261
  for i = 1, #(value or "") do
    hash = (hash ~ string.byte(value, i)) & 0xFFFFFFFF
    hash = (hash * 16777619) & 0xFFFFFFFF
  end
  return string.format("%08x", hash)
end

local function entropy_bits(value)
  if type(value) ~= "string" or #value == 0 then
    return 0
  end
  local counts = {}
  for i = 1, #value do
    local char = string.sub(value, i, i)
    counts[char] = (counts[char] or 0) + 1
  end
  local length = #value
  local entropy = 0
  for _, count in pairs(counts) do
    local probability = count / length
    entropy = entropy - probability * (math.log(probability) / math.log(2))
  end
  return entropy
end

local function random_token(length, uppercase)
  local alphabet = uppercase and "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    or "abcdefghijklmnopqrstuvwxyz0123456789"
  local out = {}
  for _ = 1, length do
    local index = math.random(1, #alphabet)
    table.insert(out, string.sub(alphabet, index, index))
  end
  return table.concat(out)
end

local function seed_random(port)
  math.randomseed((os.time() * 65537) + ((port and port.number) or 0)
    + ((stdnse.clock_ms and stdnse.clock_ms()) or 0))
end

local state = { requests = 0, rate_limited = 0, errors = 0, blocked = 0 }

local function reset_state()
  state = { requests = 0, rate_limited = 0, errors = 0, blocked = 0 }
end

local function budget_exhausted(args)
  return state.requests >= args.maxrequests
end

local function sleep(seconds)
  if seconds and seconds > 0 then
    stdnse.sleep(seconds)
  end
end

local function read_args()
  local args = {}
  for key, value in pairs(DEFAULT_ARGS) do
    args[key] = value
  end

  for _, spec in ipairs(NUMERIC_ARGS) do
    local raw = stdnse.get_script_args(SCRIPT_NAME .. "." .. spec.key)
    local value = tonumber(raw)
    if value and value >= spec.minimum and (not spec.maximum or value <= spec.maximum) then
      if spec.integer then
        args[spec.key] = math.floor(value)
      else
        args[spec.key] = value
      end
    end
  end

  for _, key in ipairs(BOOLEAN_ARGS) do
    local value = stdnse.get_script_args(SCRIPT_NAME .. "." .. key)
    if value ~= nil then
      args[key] = not (value == false or value == "false" or value == "no" or value == "0")
    end
  end

  for _, key in ipairs(STRING_ARGS) do
    local value = stdnse.get_script_args(SCRIPT_NAME .. "." .. key)
    if type(value) == "string" and #trim(value) > 0 then
      args[key] = trim(value)
    elseif type(value) == "table" and #value > 0 then
      args[key] = trim(tostring(value[1]))
    end
  end

  local raw_list = stdnse.get_script_args(SCRIPT_NAME .. ".paths")
  if raw_list and #tostring(raw_list) > 0 then
    local list = {}
    for candidate in string.gmatch(tostring(raw_list), "[^,]+") do
      local normalized = trim(candidate)
      if #normalized > 0 then
        if not starts_with(normalized, "/") then
          normalized = "/" .. normalized
        end
        table.insert(list, normalized)
      end
    end
    if #list > 0 then
      args.paths = list
    end
  end

  return args
end

local function ldap_ber_len(n)
  if n < 128 then
    return string.char(n)
  end
  local bytes = {}
  local v = math.floor(n)
  while v > 0 do
    table.insert(bytes, 1, string.char(v % 256))
    v = math.floor(v / 256)
  end
  return string.char(128 + #bytes) .. table.concat(bytes)
end

local function ldap_encode_int(value)
  value = math.floor(value)
  if value >= 0 and value < 128 then
    return string.char(0x02, 0x01, value)
  end
  local neg = value < 0
  local v = math.abs(value)
  local bytes = {}
  while v > 0 do
    table.insert(bytes, 1, string.char(v % 256))
    v = math.floor(v / 256)
  end
  if #bytes == 0 then
    bytes = { string.char(0) }
  end
  if neg then
    if bytes[1] < 128 then
      table.insert(bytes, 1, string.char(0xFF))
    end
  else
    if bytes[1] >= 128 then
      table.insert(bytes, 1, string.char(0x00))
    end
  end
  return string.char(0x02) .. ldap_ber_len(#bytes) .. table.concat(bytes)
end

local function ldap_encode_enum(value)
  value = math.floor(value)
  if value >= 0 and value < 128 then
    return string.char(0x0A, 0x01, value)
  end
  return string.char(0x0A) .. ldap_ber_len(1) .. string.char(value % 256)
end

local function ldap_encode_bool(flag)
  if flag then
    return string.char(0x01, 0x01, 0xFF)
  end
  return string.char(0x01, 0x01, 0x00)
end

local function ldap_encode_octets(data)
  return string.char(0x04) .. ldap_ber_len(#tostring(data)) .. tostring(data)
end

local function ldap_encode_null()
  return string.char(0x05, 0x00)
end

local function ldap_encode_sequence(body)
  return string.char(0x30) .. ldap_ber_len(#body) .. body
end

local function ldap_encode_set(body)
  return string.char(0x31) .. ldap_ber_len(#body) .. body
end

local function ldap_encode_context(index, body)
  return string.char(0x80 + index) .. ldap_ber_len(#body) .. body
end

local function ldap_encode_oid(oid_str)
  local arcs = {}
  for arc in tostring(oid_str):gmatch("%d+") do
    arcs[#arcs + 1] = tonumber(arc)
  end
  if #arcs < 2 then
    return nil
  end
  local out = { string.char(arcs[1] * 40 + arcs[2]) }
  for i = 3, #arcs do
    local v = arcs[i]
    local chunks = {}
    chunks[1] = string.char(v % 128)
    v = math.floor(v / 128)
    while v > 0 do
      table.insert(chunks, 1, string.char(0x80 + (v % 128)))
      v = math.floor(v / 128)
    end
    out[#out + 1] = table.concat(chunks)
  end
  local body = table.concat(out)
  return string.char(0x06) .. ldap_ber_len(#body) .. body
end

local function ldap_decode_int(body)
  if body == nil or #body == 0 then
    return 0
  end
  local n = 0
  for k = 1, #body do
    n = n * 256 + body:byte(k)
  end
  if #body > 0 and body:byte(1) >= 128 then
    n = n - 256 ^ #body
  end
  return n
end

local function ldap_decode_oid_bytes(body)
  if body == nil or #body == 0 then
    return nil
  end
  local arcs = { math.floor(body:byte(1) / 40), body:byte(1) % 40 }
  local i = 2
  while i <= #body do
    local b = body:byte(i)
    local v = b % 128
    i = i + 1
    while b >= 128 and i <= #body do
      b = body:byte(i)
      v = v * 128 + (b % 128)
      i = i + 1
    end
    arcs[#arcs + 1] = v
  end
  local parts = {}
  for _, a in ipairs(arcs) do
    parts[#parts + 1] = tostring(a)
  end
  return table.concat(parts, ".")
end

local function ldap_tlv_next(data, pos)
  if data == nil or pos == nil or pos > #data then
    return nil, nil, nil
  end
  local tag = data:byte(pos)
  local lenb = data:byte(pos + 1)
  if lenb == nil then
    return nil, nil, nil
  end
  local body_start
  local vlen
  if lenb < 128 then
    body_start = pos + 2
    vlen = lenb
  else
    local nlen = lenb - 128
    if pos + 2 + nlen > #data then
      return nil, nil, nil
    end
    vlen = 0
    for k = 1, nlen do
      vlen = vlen * 256 + data:byte(pos + 1 + k)
    end
    body_start = pos + 2 + nlen
  end
  if body_start + vlen - 1 > #data then
    return nil, nil, nil
  end
  return tag, data:sub(body_start, body_start + vlen - 1), body_start + vlen
end

local function ldap_tlv_total(data, pos)
  local tag, body, nxt = ldap_tlv_next(data, pos)
  if tag == nil then
    return nil
  end
  return nxt
end

local function ldap_parse_tlv_list(body)
  local items = {}
  local p = 1
  while p <= #body do
    local tag, value, nxt = ldap_tlv_next(body, p)
    if tag == nil then
      break
    end
    items[#items + 1] = { tag = tag, value = value }
    p = nxt
  end
  return items
end

local OP_BIND_REQUEST = 0x60
local OP_BIND_RESPONSE = 0x61
local OP_UNBIND_REQUEST = 0x42
local OP_SEARCH_REQUEST = 0x63
local OP_SEARCH_RESULT_ENTRY = 0x64
local OP_SEARCH_RESULT_DONE = 0x65
local OP_SEARCH_RESULT_REF = 0x73
local OP_EXTENDED_REQUEST = 0x77
local OP_EXTENDED_RESPONSE = 0x78

local SCOPE_BASE = 0
local SCOPE_ONE = 1
local SCOPE_SUB = 2

local DEREF_NEVER = 0

local FILTER_TAG_AND = 0xA0
local FILTER_TAG_OR = 0xA1
local FILTER_TAG_NOT = 0xA2
local FILTER_TAG_EQUALITY = 0xA3
local FILTER_TAG_SUBSTRINGS = 0xA4
local FILTER_TAG_GE = 0xA5
local FILTER_TAG_LE = 0xA6
local FILTER_TAG_PRESENT = 0x87
local FILTER_TAG_APPROX = 0xA8
local FILTER_TAG_EXTENSIBLE = 0xA9

local RESULT_CODES = {
  [0] = "success",
  [1] = "operationsError",
  [2] = "protocolError",
  [3] = "timeLimitExceeded",
  [4] = "sizeLimitExceeded",
  [5] = "compareTrue",
  [6] = "compareFalse",
  [7] = "authMethodNotSupported",
  [8] = "strongerAuthRequired",
  [10] = "referral",
  [11] = "adminLimitExceeded",
  [12] = "busy",
  [13] = "unavailable",
  [14] = "unavailableCriticalExtension",
  [15] = "unwillingToPerform",
  [16] = "noSuchAttribute",
  [17] = "loopDetect",
  [20] = "alreadyExists",
  [21] = "invalidAttributeSyntax",
  [32] = "noSuchObject",
  [33] = "aliasProblem",
  [34] = "invalidDNSSyntax",
  [35] = "invalidAttributeType",
  [36] = "itemNotPermitted",
  [37] = "constraintViolation",
  [43] = "securityError",
  [44] = "permissionDenied",
  [45] = "dataError",
  [46] = "typeError",
  [47] = "invalidReference",
  [48] = "unavailableCriticalExtension",
  [49] = "invalidCredentials",
  [50] = "insufficientAccessRights",
  [51] = "privacyViolation",
  [52] = "unsupportedCriticalExtension",
  [53] = "unwillingToPerform",
  [80] = "other",
}

local function ldap_result_name(code)
  if code == nil then
    return "unknown"
  end
  return RESULT_CODES[code] or ("code " .. tostring(code))
end

local CONTROL_OIDS = {
  ["1.2.840.113556.1.4.319"] = "pagedResults",
  ["1.2.840.113556.1.4.473"] = "vListView",
  ["1.2.840.113556.1.4.528"] = "server-side sort",
  ["1.2.840.113556.1.4.841"] = "persistent search",
  ["1.2.840.113556.1.4.2064"] = "sync request",
  ["1.3.6.1.4.1.4203.1.11.3"] = "DIT change notification",
  ["1.3.6.1.4.1.72016.2.12"] = "server API control",
  ["2.16.840.1.113730.3.4.17"] = "AD DS replication sync",
}

local EXTENSION_OIDS = {
  ["1.3.6.1.4.1.1466.20036"] = "cancel",
  ["1.3.6.1.4.1.1466.20037"] = "startTLS",
  ["1.3.6.1.4.1.1466.20038"] = "whoAmI",
}

local EXT_STARTTLS = "1.3.6.1.4.1.1466.20037"
local EXT_CANCEL = "1.3.6.1.4.1.1466.20036"
local CTRL_PAGED = "1.2.840.113556.1.4.319"

local SASL_MECHANISMS = {
  GSSAPI = "GSSAPI (Kerberos SPNEGO)",
  EXTERNAL = "EXTERNAL (channel-bound identity)",
  DIGESTMD5 = "DIGEST-MD5 (challenge/response)",
  NTLM = "NTLM (legacy NT hash challenge)",
  SIMPLEX = "SIMPLE",
  SCRAMSHA1PLUS = "SCRAM-SHA-1-PLUS",
  SCRAMSHA256PLUS = "SCRAM-SHA-256-PLUS",
}

local function ldap_sasl_name(mech)
  local key = tostring(mech or ""):upper():gsub("-", "")
  return SASL_MECHANISMS[key] or mech
end

local function ldap_control_name(oid)
  return CONTROL_OIDS[tostring(oid)] or tostring(oid)
end

local function ldap_extension_name(oid)
  return EXTENSION_OIDS[tostring(oid)] or tostring(oid)
end

local UAC_TABLE = {
  { bit = 0x1, name = "SCRIPT_PASSWORD" },
  { bit = 0x2, name = "ACCOUNTDISABLE" },
  { bit = 0x8, name = "HOMEDIR_REQUIRED" },
  { bit = 0x10, name = "LOCKED_OUT" },
  { bit = 0x100, name = "PASSWD_NOT_REQUIRED" },
  { bit = 0x200, name = "NORMAL_ACCOUNT" },
  { bit = 0x1000, name = "MACHINE_ACCOUNT" },
  { bit = 0x2000, name = "TRUSTED_FOR_DELEGATION" },
  { bit = 0x4000, name = "TRUSTED_TO_AUTH_FOR_DELEGATION" },
  { bit = 0x8000, name = "SERVER_TRUST_ACCOUNT" },
  { bit = 0x40000, name = "USE_DES_KEY_ONLY" },
  { bit = 0x400000, name = "DONT_REQ_PREAUTH" },
  { bit = 0x800000, name = "PASSWORD_EXPIRED" },
  { bit = 0x1000000, name = "PASSWORD_NO_EXPIRE" },
}

local function ldap_uac_flags(value)
  local names = {}
  local v = tonumber(value) or 0
  for _, entry in ipairs(UAC_TABLE) do
    if v % (entry.bit * 2) >= entry.bit then
      names[#names + 1] = entry.name
    end
  end
  return names
end

local function ldap_uac_has(value, bit)
  local v = tonumber(value) or 0
  return v % (bit * 2) >= bit
end

local DOMAIN_FUNCTIONALITY = {
  [0] = "Windows 2000",
  [1] = "Windows Server 2003 (interim)",
  [2] = "Windows Server 2003",
  [3] = "Windows Server 2008 R2",
  [4] = "Windows Server 2008",
  [5] = "Windows Server 2012 R2",
  [6] = "Windows Server 2012",
  [7] = "Windows Server 2016 or later",
}

local FOREST_FUNCTIONALITY = {
  [0] = "Windows 2000",
  [1] = "Windows Server 2003 (interim)",
  [2] = "Windows Server 2003",
  [3] = "Windows Server 2008 R2",
  [4] = "Windows Server 2008",
  [5] = "Windows Server 2012 R2",
  [6] = "Windows Server 2012",
  [7] = "Windows Server 2016 or later",
}

local function ldap_domain_functionality_name(level)
  return DOMAIN_FUNCTIONALITY[tonumber(level)] or ("level " .. tostring(level))
end

local function ldap_forest_functionality_name(level)
  return FOREST_FUNCTIONALITY[tonumber(level)] or ("level " .. tostring(level))
end

local EKU_TABLE = {
  ["1.3.6.1.5.5.7.3.1"] = "serverAuth",
  ["1.3.6.1.5.5.7.3.2"] = "clientAuth",
  ["1.3.6.1.5.5.7.3.3"] = "codeSigning",
  ["1.3.6.1.5.5.7.3.4"] = "emailProtection",
  ["1.3.6.1.5.5.7.3.8"] = "timeStamping",
  ["2.5.29.37.0"] = "anyEKU",
  ["1.3.6.1.4.1.311.80.1"] = "machineAuth (Smart Card Logon)",
  ["1.3.6.1.4.1.311.20.2.2"] = "smartcardLogon",
  ["1.3.6.1.4.1.311.84.1.1"] = "servicesForServer",
}

local function ldap_eku_name(oid)
  return EKU_TABLE[tostring(oid)] or tostring(oid)
end

local LDAPERR_DATA_CODES = {
  [502] = "server is not authorized to perform this operation (rebind-class restriction)",
  [531] = "data must be signed (LDAP signing / channel binding enforced)",
  [532] = "data must be encrypted (channel binding / encryption enforced)",
  [533] = "bind requires signing or channel binding token",
  [552] = "server rejected the request (unclassified server policy)",
  [586] = "the requested operation requires a secured channel",
  [818] = "the account is locked out or disabled for this operation",
  [1689] = "insufficient rights for the requested attribute",
  [365] = "the directory agent could not process the request",
}

local function ldap_ldaperr_name(data)
  if data == nil then
    return nil
  end
  return LDAPERR_DATA_CODES[tonumber(data)]
end

local function ldap_parse_ldaperr(diagnostic)
  local text = tostring(diagnostic or "")
  local dsid = text:match("DSID%-(%x+)")
  local comment = text:match("comment:%s*(.-),%s*data%s+")
  local data = text:match("data%s+(%d+)")
  local version = text:match("v(%d+)")
  local base = text:match("^(%d+):")
  local is_ldaperr = (text:find("LdapErr") ~= nil)
  return {
    present = is_ldaperr,
    base_code = base,
    dsid = dsid,
    comment = comment,
    data_code = data,
    data_meaning = (data ~= nil) and ldap_ldaperr_name(data) or nil,
    version = version,
  }
end

local function ldap_hex(data)
  local out = {}
  for i = 1, #tostring(data) do
    out[i] = string.format("%02x", tostring(data):byte(i))
  end
  return table.concat(out)
end

local function ldap_mask_secret(value)
  local text = tostring(value or "")
  if text:sub(1, 8) == "{unicode}" then
    text = text:sub(9)
  end
  if #text <= 2 then
    return "****"
  end
  return text:sub(1, 2) .. string.rep("*", 8) .. " (masked, " .. #text .. " chars)"
end

local function ldap_unicode_pwd_info(value)
  local text = tostring(value or "")
  local hex = text
  if text:sub(1, 8) == "{unicode}" then
    hex = text:sub(9)
  end
  local is_hex = (hex:match("^%x+$") ~= nil) and (#hex % 2 == 0)
  local byte_count = is_hex and (#hex / 2) or 0
  local char_count = math.floor(byte_count / 2)
  local classes = {}
  if is_hex then
    for i = 1, #hex - 1, 2 do
      local ch = tonumber(hex:sub(i, i + 1), 16)
      if ch == 0 then
      else
        if ch >= 0x41 and ch <= 0x5A then
          classes["upper"] = true
        elseif ch >= 0x61 and ch <= 0x7A then
          classes["lower"] = true
        elseif ch >= 0x30 and ch <= 0x39 then
          classes["digit"] = true
        else
          classes["other"] = true
        end
      end
    end
  end
  local class_list = {}
  if classes["upper"] then class_list[#class_list + 1] = "uppercase" end
  if classes["lower"] then class_list[#class_list + 1] = "lowercase" end
  if classes["digit"] then class_list[#class_list + 1] = "digits" end
  if classes["other"] then class_list[#class_list + 1] = "symbols" end
  local entropy_hint = "unknown"
  if #class_list >= 4 and char_count >= 8 then
    entropy_hint = "strong character coverage"
  elseif #class_list >= 3 and char_count >= 8 then
    entropy_hint = "moderate character coverage"
  elseif #class_list >= 1 then
    entropy_hint = "limited character coverage"
  end
  return {
    decoded_length = char_count,
    classes = class_list,
    coverage = entropy_hint,
  }
end

local function ldap_filter_present(attr)
  return string.char(FILTER_TAG_PRESENT) .. ldap_ber_len(#tostring(attr)) .. tostring(attr)
end

local function ldap_filter_equality(attr, value)
  local inner = ldap_encode_octets(attr) .. ldap_encode_octets(value)
  return string.char(FILTER_TAG_EQUALITY) .. ldap_ber_len(#inner) .. inner
end

local function ldap_filter_substring(attr, parts)
  local pieces = ldap_encode_octets(attr)
  local subs = {}
  if parts.initial then
    subs[#subs + 1] = ldap_encode_context(0, parts.initial)
  end
  if parts.any then
    for _, chunk in ipairs(parts.any) do
      subs[#subs + 1] = ldap_encode_context(1, chunk)
    end
  end
  if parts.final then
    subs[#subs + 1] = ldap_encode_context(2, parts.final)
  end
  local inner = pieces .. ldap_encode_sequence(table.concat(subs))
  return string.char(FILTER_TAG_SUBSTRINGS) .. ldap_ber_len(#inner) .. inner
end

local function ldap_filter_ge(attr, value)
  local inner = ldap_encode_octets(attr) .. ldap_encode_octets(value)
  return string.char(FILTER_TAG_GE) .. ldap_ber_len(#inner) .. inner
end

local function ldap_filter_le(attr, value)
  local inner = ldap_encode_octets(attr) .. ldap_encode_octets(value)
  return string.char(FILTER_TAG_LE) .. ldap_ber_len(#inner) .. inner
end

local function ldap_filter_and(list)
  local body = table.concat(list)
  return string.char(FILTER_TAG_AND) .. ldap_ber_len(#body) .. body
end

local function ldap_filter_or(list)
  local body = table.concat(list)
  return string.char(FILTER_TAG_OR) .. ldap_ber_len(#body) .. body
end

local function ldap_filter_not(filter)
  return string.char(FILTER_TAG_NOT) .. ldap_ber_len(#filter) .. filter
end

local function ldap_encode_control(oid, critical, value)
  local body = ldap_encode_oid(oid)
  if critical then
    body = body .. string.char(0xA1, 0x01, 0xFF)
  end
  if value ~= nil and #tostring(value) > 0 then
    body = body .. ldap_encode_context(3, tostring(value))
  end
  return ldap_encode_sequence(body)
end

local function ldap_paged_control(page_size, cookie)
  local value = ldap_encode_sequence(ldap_encode_int(page_size) .. ldap_encode_octets(cookie or ""))
  return ldap_encode_control(CTRL_PAGED, false, value)
end

local function ldap_encode_bind_op(dn, simple_password)
  local body = ldap_encode_int(3) .. ldap_encode_octets(dn or "")
  if simple_password == nil then
    body = body .. ldap_encode_context(0, ldap_encode_null())
  else
    body = body .. ldap_encode_context(0, ldap_encode_octets(simple_password))
  end
  return string.char(OP_BIND_REQUEST) .. ldap_ber_len(#body) .. body
end

local function ldap_encode_unbind_op()
  return string.char(OP_UNBIND_REQUEST, 0x00)
end

local function ldap_encode_search_op(base, scope, filter, attrs_bytes, size_limit, time_limit, controls_bytes)
  local body = ldap_encode_octets(base or "")
    .. ldap_encode_enum(scope)
    .. ldap_encode_enum(DEREF_NEVER)
    .. ldap_encode_int(size_limit or 0)
    .. ldap_encode_int(time_limit or 0)
    .. ldap_encode_bool(false)
    .. ldap_encode_context(0x30, filter)
    .. ldap_encode_context(0x31, attrs_bytes or "")
  if controls_bytes ~= nil and #controls_bytes > 0 then
    body = body .. ldap_encode_context(0, controls_bytes)
  end
  return string.char(OP_SEARCH_REQUEST) .. ldap_ber_len(#body) .. body
end

local function ldap_encode_extended_op(oid, value)
  local body = ldap_encode_oid(oid)
  if value ~= nil then
    body = body .. ldap_encode_context(0, tostring(value))
  end
  return string.char(OP_EXTENDED_REQUEST) .. ldap_ber_len(#body) .. body
end

local function ldap_parse_message(data)
  local tag, body, _ = ldap_tlv_next(data, 1)
  if tag == nil or tag ~= 0x30 then
    return nil, "not an LDAP message"
  end
  local fields = ldap_parse_tlv_list(body)
  if #fields < 2 then
    return nil, "truncated LDAP message"
  end
  local msgid = ldap_decode_int(fields[1].value)
  local op_tag = fields[2].tag
  local op_body = fields[2].value
  local controls = {}
  for i = 3, #fields do
    if fields[i].tag == 0x30 then
      controls[#controls + 1] = fields[i].value
    end
  end
  return { msgid = msgid, op = op_tag, body = op_body, controls = controls }
end

local function ldap_parse_bind_response(body)
  local fields = ldap_parse_tlv_list(body)
  if #fields < 1 then
    return nil, "truncated bind response"
  end
  return {
    result = ldap_decode_int(fields[1].value),
    matched = (fields[2] ~= nil) and fields[2].value or "",
    diagnostic = (fields[3] ~= nil) and fields[3].value or "",
  }
end

local function ldap_parse_search_entry(body)
  local fields = ldap_parse_tlv_list(body)
  if #fields < 2 then
    return nil, "truncated search entry"
  end
  local dn = fields[1].value
  local attrs = {}
  local attr_set = fields[2].value
  local ap = 1
  while ap <= #attr_set do
    local atag, aval, anxt = ldap_tlv_next(attr_set, ap)
    if atag == nil then
      break
    end
    if atag == 0x30 then
      local inner = ldap_parse_tlv_list(aval)
      if #inner >= 2 then
        local name = inner[1].value
        local values = {}
        local setbody = inner[2].value
        local sp = 1
        while sp <= #setbody do
          local st, sv, snxt = ldap_tlv_next(setbody, sp)
          if st == nil then
            break
          end
          if st == 0x04 then
            values[#values + 1] = sv
          end
          sp = snxt
        end
        if attrs[name] == nil then
          attrs[name] = values
        else
          for _, v in ipairs(values) do
            attrs[name][#attrs[name] + 1] = v
          end
        end
      end
    end
    ap = anxt
  end
  return { dn = dn, attrs = attrs }
end

local function ldap_parse_search_done(body)
  local fields = ldap_parse_tlv_list(body)
  if #fields < 1 then
    return nil, "truncated search done"
  end
  local out = {
    result = ldap_decode_int(fields[1].value),
    matched = (fields[2] ~= nil) and fields[2].value or "",
    diagnostic = (fields[3] ~= nil) and fields[3].value or "",
    controls = {},
  }
  for i = 4, #fields do
    if fields[i].tag == 0x30 then
      out.controls[#out.controls + 1] = fields[i].value
    end
  end
  return out
end

local function ldap_parse_search_ref(body)
  local fields = ldap_parse_tlv_list(body)
  local refs = {}
  for _, f in ipairs(fields) do
    if f.tag == 0x04 then
      refs[#refs + 1] = f.value
    end
  end
  return refs
end

local function ldap_parse_extended_response(body)
  local fields = ldap_parse_tlv_list(body)
  if #fields < 1 then
    return nil, "truncated extended response"
  end
  local out = {
    result = ldap_decode_int(fields[1].value),
    matched = (fields[2] ~= nil) and fields[2].value or "",
    diagnostic = (fields[3] ~= nil) and fields[3].value or "",
    response = nil,
    controls = {},
  }
  for i = 4, #fields do
    if fields[i].tag == 0x80 then
      out.response = fields[i].value
    elseif fields[i].tag == 0x30 then
      out.controls[#out.controls + 1] = fields[i].value
    end
  end
  return out
end

local function ldap_parse_paged_control(control_body)
  local fields = ldap_parse_tlv_list(control_body)
  for _, f in ipairs(fields) do
    if f.tag == 0x06 then
      local oid = ldap_decode_oid_bytes(f.value)
      if oid == CTRL_PAGED then
        for _, g in ipairs(fields) do
          if g.tag == 0x83 then
            local inner = ldap_parse_tlv_list(g.value)
            if #inner >= 2 and inner[2].tag == 0x04 then
              return inner[2].value
            end
          end
        end
      end
    end
  end
  return nil
end

local function ldap_classify_done(done)
  if done == nil then
    return "no response"
  end
  local name = ldap_result_name(done.result)
  if done.diagnostic ~= nil and #tostring(done.diagnostic) > 0 then
    local errinfo = ldap_parse_ldaperr(done.diagnostic)
    if errinfo.present then
      local bits = {}
      if errinfo.dsid then bits[#bits + 1] = "DSID-" .. errinfo.dsid end
      if errinfo.comment then bits[#bits + 1] = errinfo.comment end
      if errinfo.data_code then bits[#bits + 1] = "data " .. errinfo.data_code end
      if errinfo.data_meaning then bits[#bits + 1] = errinfo.data_meaning end
      return name .. " (" .. table.concat(bits, ", ") .. ")"
    end
    return name .. " (" .. tostring(done.diagnostic) .. ")"
  end
  return name
end

local function ldap_dn_components(dn)
  local parts = {}
  local cleaned = tostring(dn or ""):gsub("^%s+", ""):gsub("%s+$", "")
  for chunk in cleaned:gmatch("[^,]+") do
    local component = chunk:match("^%s*(.-)%s*$")
    local key, value = component:match("^([^=,]+)%s*=%s*(.*)$")
    if key and value then
      parts[#parts + 1] = { key = key:lower(), value = value }
    else
      parts[#parts + 1] = { key = nil, value = component }
    end
  end
  return parts
end

local function ldap_dn_rdn(dn)
  local parts = ldap_dn_components(dn)
  if #parts > 0 then
    return parts[1].value
  end
  return ""
end

local function ldap_dn_local_part(dn)
  local parts = ldap_dn_components(dn)
  for _, p in ipairs(parts) do
    if p.key == "dc" then
      return p.value
    end
  end
  return ""
end

local function ldap_attrs_to_lines(attrs, skip_masked)
  local lines = {}
  local names = {}
  for name in pairs(attrs) do
    names[#names + 1] = name
  end
  table.sort(names)
  for _, name in ipairs(names) do
    local values = attrs[name]
    if values ~= nil and #values > 0 then
      local shown = {}
      for _, v in ipairs(values) do
        shown[#shown + 1] = tostring(v)
      end
      lines[#lines + 1] = name .. " = " .. table.concat(shown, "; ")
    end
  end
  return lines
end

local function ldap_attr_first(attrs, name)
  if attrs == nil or attrs[name] == nil then
    return nil
  end
  return attrs[name][1]
end

local function ldap_attr_all(attrs, name)
  if attrs == nil or attrs[name] == nil then
    return {}
  end
  return attrs[name]
end

local ldap_message_counter = 0

local function ldap_next_message_id()
  ldap_message_counter = (ldap_message_counter + 1) % 2147483647
  if ldap_message_counter < 1 then
    ldap_message_counter = 1
  end
  return ldap_message_counter
end

local function ldap_session_new(host, port, args)
  return {
    host = host,
    port = port,
    args = args,
    sock = nil,
    connected = false,
    closed = false,
    recvbuf = "",
    pending = {},
    msgid = 0,
    bound = false,
    bind_result = nil,
    bind_diagnostic = nil,
    bind_dn = nil,
    tls = false,
    entries_seen = 0,
    responses = 0,
    errors = 0,
    timeouts = 0,
  }
end

local function ldap_socket_open(sess)
  local sock = nmap.new_socket("tcp")
  if not sock then
    return nil, "socket allocation failed"
  end
  sock:set_timeout(math.floor((sess.args.timeout or 8) * 1000))
  local ok, err = sock:connect(sess.host, sess.port, "tcp")
  if not ok then
    sock:close()
    return nil, "TCP connect failed: " .. tostring(err or "unknown")
  end
  sess.sock = sock
  sess.connected = true
  return sock
end

local function ldap_close_session(sess)
  if sess and sess.sock and not sess.closed then
    if sess.bound then
      local unbind = ldap_encode_sequence(
        ldap_encode_int(ldap_next_message_id()) .. ldap_encode_unbind_op())
      sess.sock:send(unbind)
    end
    sess.sock:close()
  end
  if sess then
    sess.closed = true
    sess.connected = false
    sess.bound = false
  end
end

local function ldap_send_raw(sess, data)
  if sess.closed or not sess.sock then
    return nil, "session closed"
  end
  if budget_exhausted(sess.args) then
    return nil, "request budget exhausted"
  end
  state.requests = state.requests + 1
  local ok, err = sess.sock:send(data)
  if not ok then
    sess.errors = sess.errors + 1
    return nil, "send failed: " .. tostring(err or "unknown")
  end
  return 1
end

local function ldap_drain_buffer(sess)
  local parsed_any = false
  while true do
    local nxt = ldap_tlv_total(sess.recvbuf, 1)
    if nxt == nil then
      break
    end
    local msg_bytes = sess.recvbuf:sub(1, nxt - 1)
    sess.recvbuf = sess.recvbuf:sub(nxt)
    local parsed, err = ldap_parse_message(msg_bytes)
    if parsed == nil then
      sess.errors = sess.errors + 1
      break
    end
    sess.pending[#sess.pending + 1] = parsed
    parsed_any = true
  end
  return parsed_any
end

local function ldap_recv_message(sess, want_msgid)
  local attempts = 0
  local max_attempts = math.max(4, (sess.args.timeout or 8) * 2)
  while attempts < max_attempts do
    ldap_drain_buffer(sess)
    for i = 1, #sess.pending do
      if sess.pending[i].msgid == want_msgid then
        local parsed = sess.pending[i]
        table.remove(sess.pending, i)
        sess.responses = sess.responses + 1
        return parsed
      end
    end
    if budget_exhausted(sess.args) then
      return nil, "request budget exhausted while waiting for response"
    end
    local ok, dat = sess.sock:receive(65535)
    attempts = attempts + 1
    if ok and dat and #dat > 0 then
      sess.recvbuf = sess.recvbuf .. dat
    else
      sess.timeouts = sess.timeouts + 1
      return nil, "timeout waiting for LDAP message"
    end
  end
  sess.timeouts = sess.timeouts + 1
  return nil, "too many receive attempts without a matching message"
end

local function ldap_transact(sess, op_tag, op_bytes)
  local msgid = ldap_next_message_id()
  local msg = ldap_encode_sequence(ldap_encode_int(msgid) .. op_bytes)
  local ok, err = ldap_send_raw(sess, msg)
  if not ok then
    return nil, nil, err
  end
  local parsed, rerr = ldap_recv_message(sess, msgid)
  if parsed == nil then
    return nil, nil, rerr
  end
  if parsed.msgid ~= msgid then
    return nil, nil, "message-id mismatch in response"
  end
  return parsed.op, parsed.body, nil
end

local function ldap_bind_simple(sess, dn, simple_password)
  local op = ldap_encode_bind_op(dn or "", simple_password)
  local op_tag, body, err = ldap_transact(sess, OP_BIND_REQUEST, op)
  if op_tag == nil then
    return nil, err
  end
  local resp, perr = ldap_parse_bind_response(body)
  if resp == nil then
    return nil, perr
  end
  if resp.result == 0 then
    sess.bound = true
    sess.bind_dn = dn
    sess.bind_result = 0
    sess.bind_diagnostic = ""
  else
    sess.bound = false
    sess.bind_result = resp.result
    sess.bind_diagnostic = resp.diagnostic
  end
  return resp
end

local function ldap_anonymous_bind(sess)
  return ldap_bind_simple(sess, "", nil)
end

local function ldap_search(sess, base, scope, filter, attrs, opts)
  opts = opts or {}
  local max_entries = opts.max_entries or 200
  local msgid = ldap_next_message_id()
  local controls_bytes = ""
  if opts.controls then
    controls_bytes = table.concat(opts.controls)
  end
  local attrs_bytes = ""
  for _, name in ipairs(attrs or {}) do
    attrs_bytes = attrs_bytes .. ldap_encode_octets(tostring(name))
  end
  local op = ldap_encode_search_op(base or "", scope, filter, attrs_bytes,
    opts.size_limit or 0, opts.time_limit or 0, controls_bytes)
  local msg = ldap_encode_sequence(ldap_encode_int(msgid) .. op)
  local ok, err = ldap_send_raw(sess, msg)
  if not ok then
    return nil, err
  end
  local out = { entries = {}, done = nil, refs = {}, truncated = false }
  local guard = 0
  while true do
    guard = guard + 1
    if guard > (max_entries + 8) then
      out.truncated = true
      break
    end
    local parsed, rerr = ldap_recv_message(sess, msgid)
    if parsed == nil then
      out.truncated = true
      out.done = { result = nil, diagnostic = rerr or "timeout", matched = "" }
      break
    end
    if parsed.op == OP_SEARCH_RESULT_ENTRY then
      local entry, perr = ldap_parse_search_entry(parsed.body)
      if entry == nil then
        out.truncated = true
        out.done = { result = nil, diagnostic = perr or "entry parse failure", matched = "" }
        break
      end
      out.entries[#out.entries + 1] = entry
      sess.entries_seen = sess.entries_seen + 1
      if #out.entries >= max_entries then
        out.truncated = true
      end
    elseif parsed.op == OP_SEARCH_RESULT_REF then
      local refs = ldap_parse_search_ref(parsed.body)
      for _, r in ipairs(refs) do
        out.refs[#out.refs + 1] = r
      end
    elseif parsed.op == OP_SEARCH_RESULT_DONE then
      local done, perr = ldap_parse_search_done(parsed.body)
      if done == nil then
        out.truncated = true
        out.done = { result = nil, diagnostic = perr or "done parse failure", matched = "" }
        break
      end
      out.done = done
      break
    else
      out.truncated = true
      out.done = { result = nil, diagnostic = "unexpected operation " .. tostring(parsed.op), matched = "" }
      break
    end
  end
  return out
end

local function ldap_extended_op(sess, oid, value)
  local op = ldap_encode_extended_op(oid, value)
  local op_tag, body, err = ldap_transact(sess, OP_EXTENDED_REQUEST, op)
  if op_tag == nil then
    return nil, err
  end
  local resp, perr = ldap_parse_extended_response(body)
  if resp == nil then
    return nil, perr
  end
  return resp
end

local function ldap_probe_starttls(sess)
  local resp, err = ldap_extended_op(sess, EXT_STARTTLS, nil)
  if resp == nil then
    return nil, err
  end
  if resp.result == 0 then
    sess.tls = true
  end
  return resp
end

local function ldap_paged_search(sess, base, scope, filter, attrs, page_size, max_pages)
  max_pages = max_pages or 3
  local out = { entries = {}, pages = 0, cookie = "", final = nil }
  local cookie = ""
  for page = 1, max_pages do
    if budget_exhausted(sess.args) then
      break
    end
    local ctl = ldap_paged_control(page_size, cookie)
    local res, err = ldap_search(sess, base, scope, filter, attrs, {
      size_limit = 0,
      max_entries = page_size + 4,
      controls = { ctl },
    })
    if res == nil then
      out.final = { result = nil, diagnostic = err or "search failed", matched = "" }
      break
    end
    out.pages = page
    for _, e in ipairs(res.entries) do
      out.entries[#out.entries + 1] = e
    end
    if res.done == nil then
      out.final = { result = nil, diagnostic = "no terminal result", matched = "" }
      break
    end
    out.final = res.done
    local next_cookie = nil
    for _, c in ipairs(res.done.controls or {}) do
      next_cookie = ldap_parse_paged_control(c)
      if next_cookie ~= nil then
        break
      end
    end
    if next_cookie == nil or #next_cookie == 0 then
      break
    end
    cookie = next_cookie
    if #res.entries == 0 then
      break
    end
  end
  return out
end

local function ldap_probe_rootdse(sess, attrs)
  local filter = ldap_filter_present("objectClass")
  local res, err = ldap_search(sess, "", SCOPE_BASE, filter, attrs or { "*" }, {
    size_limit = 1,
    max_entries = 1,
  })
  if res == nil then
    return nil, err
  end
  if res.done ~= nil and res.done.result == 0 and #res.entries >= 1 then
    return res.entries[1]
  end
  if res.done ~= nil and res.done.result == 0 then
    return nil, "rootDSE search returned no entry"
  end
  return nil, "rootDSE search failed: " .. ldap_classify_done(res.done)
end

local function ldap_attr_value_list(entry, name)
  if entry == nil or entry.attrs == nil then
    return {}
  end
  return entry.attrs[name] or {}
end

local function ldap_first_value(entry, name)
  local values = ldap_attr_value_list(entry, name)
  if #values > 0 then
    return values[1]
  end
  return nil
end

local function ldap_entry_rdn(entry)
  return ldap_dn_rdn(entry.dn)
end

local function ldap_summary(sess)
  return {
    requests = state.requests,
    responses = sess.responses,
    errors = sess.errors,
    timeouts = sess.timeouts,
    entries = sess.entries_seen,
    bound = sess.bound,
    tls = sess.tls,
  }
end

local function ldap_session_open(host, port, args)
  local sess = ldap_session_new(host, port, args)
  local sock, err = ldap_socket_open(sess)
  if sock == nil then
    return nil, err
  end
  return sess
end

local findings = {}

local function add_finding(severity, detail, extra)
  local entry = {
    severity = severity,
    weight = SEVERITY[severity] or SEVERITY.INFO,
    detail = detail,
    path = extra and extra.path,
    subject = extra and extra.subject,
    confidence = extra and extra.confidence or "high",
    evidence = extra and extra.evidence,
  }
  if entry.confidence == "low" then
    entry.weight = math.max(0, math.floor(entry.weight / 2))
  end
  table.insert(findings, entry)
  return entry
end

local function reset_findings()
  findings = {}
end

local function dedupe_findings()
  local unique = {}
  local index = {}
  local counts = { CRITICAL = 0, HIGH = 0, MEDIUM = 0, LOW = 0, INFO = 0 }

  for _, finding in ipairs(findings) do
    local key = tostring(finding.subject or "-") .. "|" .. finding.severity .. "|" .. finding.detail
    if not index[key] then
      index[key] = {
        severity = finding.severity,
        weight = finding.weight,
        subject = finding.subject,
        detail = finding.detail,
        confidence = finding.confidence,
        paths = {},
        evidence = {},
      }
      table.insert(unique, index[key])
    end
    local entry = index[key]
    if finding.path then
      local seen_path = false
      for _, existing in ipairs(entry.paths) do
        if existing == finding.path then
          seen_path = true
        end
      end
      if not seen_path then
        table.insert(entry.paths, finding.path)
      end
    end
    if finding.evidence then
      local sample = truncate(tostring(finding.evidence), 120)
      local seen_evidence = false
      for _, existing in ipairs(entry.evidence) do
        if existing == sample then
          seen_evidence = true
        end
      end
      if not seen_evidence and #entry.evidence < 4 then
        table.insert(entry.evidence, sample)
      end
    end
    counts[finding.severity] = (counts[finding.severity] or 0) + 1
  end

  local order = { CRITICAL = 1, HIGH = 2, MEDIUM = 3, LOW = 4, INFO = 5 }
  table.sort(unique, function(a, b)
    local first = order[a.severity] or 9
    local second = order[b.severity] or 9
    if first ~= second then
      return first < second
    end
    if a.weight ~= b.weight then
      return a.weight > b.weight
    end
    return tostring(a.detail) < tostring(b.detail)
  end)

  return unique, counts
end

local function weighted_score(unique)
  local score = 0
  for _, finding in ipairs(unique) do
    local multiplier = 1
    local path_count = #(finding.paths or {})
    if path_count > 1 then
      multiplier = multiplier + math.min(path_count - 1, 5) * 0.1
    end
    score = score + (finding.weight or 0) * multiplier
  end
  return math.floor(score + 0.5)
end

local function render_findings(unique, include_info)
  local rendered = {}
  for _, finding in ipairs(unique) do
    if finding.severity ~= "INFO" or include_info then
      local line = string.format("[%s] %s", finding.severity, finding.detail)
      if finding.subject and finding.subject ~= "-" then
        line = line .. " (" .. tostring(finding.subject) .. ")"
      end
      if finding.paths and #finding.paths > 0 then
        local shown = finding.paths
        if #shown > 3 then
          shown = { shown[1], shown[2], string.format("+%d more", #finding.paths - 2) }
        end
        line = line .. " [paths: " .. table.concat(shown, ", ") .. "]"
      end
      if finding.evidence and #finding.evidence > 0 then
        line = line .. " [evidence: " .. table.concat(finding.evidence, " | ") .. "]"
      end
      if finding.confidence == "low" then
        line = line .. " [low confidence]"
      end
      table.insert(rendered, line)
    end
  end
  return rendered
end

local function new_output(risk, status)
  local out = stdnse.output_table()
  out["Risk Level"] = risk
  out["Status"] = status
  return out
end

local function finish_output(out, unique, counts, extra_sections)
  local rendered = render_findings(unique, false)
  if #rendered == 0 then
    table.insert(rendered, "no weaknesses detected by this audit")
  end
  out["Findings"] = rendered
  out["Severity counts"] = string.format("CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d INFO=%d",
    counts.CRITICAL or 0, counts.HIGH or 0, counts.MEDIUM or 0,
    counts.LOW or 0, counts.INFO or 0)
  out["Weighted score"] = tostring(weighted_score(unique))
  for _, section in ipairs(extra_sections or {}) do
    if section.value ~= nil then
      out[section.key] = section.value
    end
  end
  out["Requests issued"] = tostring(state.requests)
  if state.rate_limited > 0 then
    out["Rate limited responses"] = tostring(state.rate_limited)
  end
  if state.errors > 0 then
    out["Transport errors"] = tostring(state.errors)
  end
  return out
end

local function fetch_rootdse(sess)
  local filter = ldap_filter_present("objectClass")
  local res, err = ldap_search(sess, "", SCOPE_BASE, filter, { "*" }, {
    size_limit = 1,
    max_entries = 1,
  })
  if res == nil then
    return nil, nil, err
  end
  if res.done == nil or res.done.result ~= 0 then
    return nil, nil, "rootDSE query failed: " .. (res.done and ldap_classify_done(res.done) or "no result")
  end
  if #res.entries < 1 then
    return nil, nil, "rootDSE returned no entry"
  end
  return res.entries[1]
end

local function first_of(entry, name)
  return ldap_first_value(entry, name)
end

local function all_of(entry, name)
  return ldap_attr_value_list(entry, name)
end

local function describe_functionality(level)
  local value = tonumber(level)
  if value == nil then
    return "unknown (" .. tostring(level) .. ")"
  end
  return ldap_domain_functionality_name(value)
end

local function remediation_section()
  local remediation = stdnse.output_table()
  remediation["1. Restrict rootDSE Attributes"] = "Remove unnecessary identity attributes from the rootDSE where the directory schema permits it, so anonymous clients only learn what they must."
  remediation["2. Hide the DC Host Name"] = "Avoid exposing dnsHostName on the rootDSE if off-network enumeration of the DC is a concern."
  remediation["3. Rate-limit Anonymous Queries"] = "Apply connection rate limits on anonymous rootDSE queries to blunt bulk fingerprinting."
  return { key = "Remediation", value = remediation }
end

action = function(host, port)

local args = read_args()
reset_findings()
reset_state()

local sess, err = ldap_session_open(host, port, args)
local sections = {}

if not sess then
  local status_text = "INFORMATIONAL - rootDSE audit incomplete: " .. tostring(err)
  add_finding("INFO", "Could not open a TCP session to the LDAP server", {
    subject = "session",
    evidence = tostring(err),
    confidence = "low",
  })
  local fail_out = new_output(RISK_LEVEL, status_text)
  local unique, counts = dedupe_findings()
  return finish_output(fail_out, unique, counts, sections)
end

local entry, entry_err = fetch_rootdse(sess)
local status_text

if entry == nil then
  status_text = "SECURE - rootDSE did not return an identity-bearing entry"
  add_finding("INFO", "The rootDSE query returned no usable entry", {
    subject = "rootdse",
    evidence = tostring(entry_err),
    confidence = "medium",
  })
else
  local identity = stdnse.output_table()
  local leaked = {}
  for _, spec in ipairs(HIGH_SIGNAL_ATTRS) do
    local value = first_of(entry, spec.name)
    if value ~= nil then
      identity[spec.label] = tostring(value)
      leaked[#leaked + 1] = spec
    end
  end

  local multi = all_of(entry, "namingContexts")
  if #multi > 1 then
    local parts = {}
    for i, v in ipairs(multi) do
      parts[i] = tostring(v)
    end
    identity["naming context(s)"] = table.concat(parts, " | ")
  end

  local func = first_of(entry, "domainFunctionality")
  if func ~= nil then
    identity["Functional level name"] = describe_functionality(func)
  end

  table.insert(sections, { key = "rootDSE Identity", value = identity })

  if #leaked >= 3 then
    status_text = "VULNERABLE - rich rootDSE identity exposure (" .. #leaked .. " high-signal attributes)"
    add_finding("MEDIUM", "The rootDSE leaks domain and DC identity without authentication", {
      subject = "rootdse",
      evidence = #leaked .. " high-signal attribute(s) returned anonymously: " .. table.concat({ "namingContexts", "dnsHostName", "domainFunctionality" }, ", "),
      confidence = "high",
    })
    local dns = first_of(entry, "dnsHostName")
    if dns ~= nil then
      add_finding("LOW", "Domain controller host name exposed via rootDSE: " .. tostring(dns), {
        subject = "dc identity",
        evidence = "dnsHostName attribute",
        confidence = "high",
      })
    end
  elseif #leaked > 0 then
    status_text = "INFORMATIONAL - minimal rootDSE exposure (" .. #leaked .. " attribute(s))"
    add_finding("LOW", "Only limited rootDSE attributes are exposed", {
      subject = "rootdse",
      evidence = #leaked .. " high-signal attribute(s) returned",
      confidence = "high",
    })
  else
    status_text = "SECURE - no high-signal rootDSE attributes returned"
    add_finding("INFO", "The rootDSE returned no high-signal identity attributes", {
      subject = "rootdse",
      evidence = "all high-signal lookups were empty",
      confidence = "medium",
    })
  end
end

table.insert(sections, remediation_section())
table.insert(sections, {
  key = "CVSS Score",
  value = (status_text:find("VULNERABLE") ~= nil) and (ROOTDSE_CVSS .. " (anonymous identity disclosure)") or "n/a - no meaningful identity exposure",
})

ldap_close_session(sess)
local unique, counts = dedupe_findings()
local out = new_output(RISK_LEVEL, status_text)
return finish_output(out, unique, counts, sections)

end
