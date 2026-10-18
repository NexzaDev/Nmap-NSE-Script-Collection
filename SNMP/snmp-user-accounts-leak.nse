local shortport = require "shortport"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Enumerates local account and identity information that SNMP agents leak
through the USM user table, the system contact object and process
parameters: SNMPv3 security names, administrative e-mail addresses and
process command lines that carry user home directories or -u flags.

Why it matters
- Leaked account names are the raw material for credential attacks:
  password guessing, phishing and token-spraying target exactly these names.
- The USM user table additionally reveals which SNMPv3 security model each
  account uses, telling an attacker where to focus brute-force effort.
- Combined with a readable community this turns an inventory probe into a
  complete identity map of the device's operating context.

What the script does
1. Opens a UDP session and finds a readable community.
2. Walks the USM usmUserTable collecting every security name (and its
   authentication/privacy protocol objects when present).
3. Reads sysContact and extracts e-mail style identities.
4. Walks the HOST-RESOURCES hrSWRunTable and scans process parameters for
   user-like tokens (-u flags, home directories, login names).
5. Aggregates the distinct identities with the source that leaked each.

Safe operation: read-only Get/GetBulk transactions; nothing is modified.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"vuln", "safe"}

portrule = shortport.port_or_service(
  161,
  "snmp",
  "udp"
)

local SCRIPT_NAME = "snmp-user-accounts-leak"

local RISK_LEVEL = "🔴 CRITICAL"

local DEFAULT_ARGS = {
  maxrequests = 30,
  timeout = 8,
}

local NUMERIC_ARGS = {
  { key = "maxrequests", minimum = 1, integer = true },
  { key = "timeout", minimum = 1, integer = true },
}

local BOOLEAN_ARGS = {}

local STRING_ARGS = {}

local CANDIDATE_COMMUNITIES = { "public", "private", "community", "cisco", "admin" }

local USER_LEAK_CVSS = "7.5"

local USM_USER_ROOT = "1.3.6.1.6.3.15.1.1"

local USM_AUTH_PROTOCOLS = {
  ["1.3.6.1.6.3.10.1.1.1"] = "MD5",
  ["1.3.6.1.6.3.10.1.1.2"] = "SHA-1",
  ["1.3.6.1.6.3.10.1.1.3"] = "SHA-256",
  ["1.3.6.1.6.3.10.1.1.4"] = "SHA-384",
  ["1.3.6.1.6.3.10.1.1.5"] = "SHA-512",
}

local USM_PRIV_PROTOCOLS = {
  ["1.3.6.1.6.3.10.1.2.1"] = "DES",
  ["1.2.840.113549.1.12.15.1"] = "AES-128",
  ["1.2.840.113549.1.12.15.2"] = "AES-256",
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

local string, table, math = string, table, math

local SNMP_VERSION_V1 = 0
local SNMP_VERSION_V2C = 1
local SNMP_VERSION_V3 = 3

local PDU_GETREQUEST = 0xA0
local PDU_GETNEXTREQUEST = 0xA1
local PDU_SETREQUEST = 0xA2
local PDU_RESPONSE = 0xA2
local PDU_GETBULKREQUEST = 0xA5

local USM_SECURITY_MODEL = 3
local USM_NOAUTHNOPRIV = 0
local USM_AUTHNOPRIV = 1
local USM_AUTHPRIV = 3

local USM_AUTH_MD5 = "1.3.6.1.6.3.10.1.1.1"
local USM_AUTH_SHA1 = "1.3.6.1.6.3.10.1.1.2"
local USM_AUTH_SHA256 = "1.3.6.1.6.3.10.1.1.3"
local USM_PRIV_DES = "1.3.6.1.6.3.10.1.2.1"
local USM_PRIV_AES128CFB = "1.2.840.113549.1.12.15.1"
local USM_PRIV_AES256CFB = "1.2.840.113549.1.12.15.2"

local USM_KDF_ROUNDS = 104956

local SNERR_NAMES = {
  [0] = "noError",
  [1] = "noSuchName",
  [2] = "badValue",
  [3] = "readOnly",
  [4] = "genErr",
  [5] = "noAccess",
  [6] = "wrongType",
  [7] = "unsupportedEngine",
  [8] = "insecureMsg",
  [9] = "unsupportedSecLevel",
  [10] = "unknownUserIn",
  [11] = "badAuth",
  [12] = "wrongDigest",
  [13] = "notInTimeWindow",
  [14] = "unknownGroupIn",
  [15] = "unknownSecNameIn",
  [22] = "unsupportedPrivProtocol",
  [23] = "unknownPrivParams",
  [24] = "badPriv",
}

local OID_NAMES = {
  ["1.3.6.1.2.1.1.1.0"] = "sysDescr",
  ["1.3.6.1.2.1.1.2.0"] = "sysObjectID",
  ["1.3.6.1.2.1.1.3.0"] = "sysUpTime",
  ["1.3.6.1.2.1.1.4.0"] = "sysContact",
  ["1.3.6.1.2.1.1.5.0"] = "sysName",
  ["1.3.6.1.2.1.1.6.0"] = "sysLocation",
  ["1.3.6.1.2.1.1.7.0"] = "sysServices",
  ["1.3.6.1.2.1.2.2.1.1"] = "ifIndex",
  ["1.3.6.1.2.1.2.2.1.2"] = "ifDescr",
  ["1.3.6.1.2.1.2.2.1.3"] = "ifType",
  ["1.3.6.1.2.1.2.2.1.4"] = "ifMtu",
  ["1.3.6.1.2.1.2.2.1.5"] = "ifSpeed",
  ["1.3.6.1.2.1.2.2.1.6"] = "ifPhysAddress",
  ["1.3.6.1.2.1.2.2.1.7"] = "ifAdminStatus",
  ["1.3.6.1.2.1.2.2.1.8"] = "ifOperStatus",
  ["1.3.6.1.2.1.4.4.1.1"] = "ipAdEntAddr",
  ["1.3.6.1.2.1.4.4.1.2"] = "ipNetToMediaPhysAddress",
  ["1.3.6.1.2.1.4.4.1.3"] = "ipNetToMediaNetIfIndex",
  ["1.3.6.1.2.1.4.4.1.4"] = "ipNetToMediaLastChange",
  ["1.3.6.1.2.1.4.4.1.5"] = "ipNetToMediaType",
  ["1.3.6.1.2.1.4.24.0"] = "ipRouteTableEntryCount",
  ["1.3.6.1.2.1.4.24.1.1"] = "ipRouteDest",
  ["1.3.6.1.2.1.4.24.1.3"] = "ipRouteMask",
  ["1.3.6.1.2.1.4.24.1.4"] = "ipRouteNextHop",
  ["1.3.6.1.2.1.4.24.1.5"] = "ipRouteIfIndex",
  ["1.3.6.1.2.1.4.24.1.6"] = "ipRouteMetric1",
  ["1.3.6.1.2.1.6.1.2.1"] = "udpLocalAddress",
  ["1.3.6.1.2.1.6.1.2.2"] = "udpLocalPort",
  ["1.3.6.1.2.1.6.13.1.1.1"] = "tcpState",
  ["1.3.6.1.2.1.6.13.1.1.2"] = "tcpLocalAddress",
  ["1.3.6.1.2.1.6.13.1.1.3"] = "tcpLocalPort",
  ["1.3.6.1.2.1.6.13.1.1.4"] = "tcpRemAddress",
  ["1.3.6.1.2.1.6.13.1.1.5"] = "tcpRemPort",
  ["1.3.6.1.2.1.25.1.1.1"] = "hrSystemUptime",
  ["1.3.6.1.2.1.25.1.2.1"] = "hrProcessorLoad",
  ["1.3.6.1.2.1.25.1.3.1"] = "hrMemorySize",
  ["1.3.6.1.2.1.25.1.5.1"] = "hrStorageTableEntry",
  ["1.3.6.1.2.1.25.2.3.1.1"] = "hrStorageIndex",
  ["1.3.6.1.2.1.25.2.3.1.2"] = "hrStorageType",
  ["1.3.6.1.2.1.25.2.3.1.3"] = "hrStorageDescr",
  ["1.3.6.1.2.1.25.2.3.1.4"] = "hrStorageAllocUnits",
  ["1.3.6.1.2.1.25.2.3.1.5"] = "hrStorageSize",
  ["1.3.6.1.2.1.25.2.3.1.6"] = "hrStorageUsed",
  ["1.3.6.1.2.1.25.4.2.1"] = "hrLoadIntervals",
  ["1.3.6.1.2.1.25.5.1.1"] = "hrSWRunIndex",
  ["1.3.6.1.2.1.25.5.1.2"] = "hrSWRunPerfIndex",
  ["1.3.6.1.2.1.25.5.1.3"] = "hrSWRunName",
  ["1.3.6.1.2.1.25.5.1.4"] = "hrSWRunPath",
  ["1.3.6.1.2.1.25.5.1.5"] = "hrSWRunInstrLocation",
  ["1.3.6.1.2.1.25.5.1.6"] = "hrSWRunStatus",
  ["1.3.6.1.2.1.25.6.3.1.1"] = "hrSWInstalledName",
  ["1.3.6.1.2.1.25.6.3.1.2"] = "hrSWInstalledVersion",
  ["1.3.6.1.2.1.43.10.2.1.2.1.1"] = "entPhysicalDescr",
  ["1.3.6.1.2.1.43.10.2.1.2.1.2"] = "entPhysicalName",
  ["1.3.6.1.2.1.43.10.2.1.2.1.3"] = "entPhysicalModelID",
  ["1.3.6.1.2.1.43.10.2.1.2.1.4"] = "entPhysicalVendorType",
  ["1.3.6.1.4.1.9.2.1.26"] = "cisco",
  ["1.3.6.1.4.1.9.9.96.1.2.1.3.1"] = "ccConfigCopyNumber",
  ["1.3.6.1.4.1.9.2.1.1.25.1"] = "sysTFTPConfiguration",
  ["1.3.6.1.6.3.15.15.1.0"] = "snmpEngineBoots",
  ["1.3.6.1.6.3.15.15.1.1"] = "snmpEngineTime",
  ["1.3.6.1.6.3.10.2.1.1.1"] = "usmStatsUnsupportedSecLevels",
  ["1.3.6.1.6.3.10.2.1.1.2"] = "usmStatsNotInTimeWindows",
  ["1.3.6.1.6.3.10.2.1.1.3"] = "usmStatsUnknownUserNames",
  ["1.3.6.1.6.3.10.2.1.1.4"] = "usmStatsUnknownEngines",
  ["1.3.6.1.6.3.10.2.1.1.5"] = "usmStatsDecryptionErrors",
}

local function snmp_ber_len(n)
  if n < 128 then
    return string.char(n)
  end
  local bytes = {}
  local v = n
  while v > 0 do
    table.insert(bytes, 1, string.char(v % 256))
    v = math.floor(v / 256)
  end
  return string.char(128 + #bytes) .. table.concat(bytes)
end

local function snmp_encode_int(value)
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
  if neg then
    if bytes[1] < 128 then
      table.insert(bytes, 1, string.char(0xFF))
    end
  else
    if bytes[1] >= 128 then
      table.insert(bytes, 1, string.char(0x00))
    end
  end
  return string.char(0x02) .. snmp_ber_len(#bytes) .. table.concat(bytes)
end

local function snmp_encode_octets(data)
  return string.char(0x04) .. snmp_ber_len(#data) .. data
end

local function snmp_encode_null()
  return string.char(0x05, 0x00)
end

local function snmp_encode_oid(oid_str)
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
  return string.char(0x06) .. snmp_ber_len(#body) .. body
end

local function snmp_decode_oid_bytes(body)
  if #body == 0 then
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

local function snmp_decode_variants(data, pos, count)
  local items = {}
  local p = pos
  for _ = 1, count do
    if p + 1 > #data then
      return nil, p
    end
    local tag = data:byte(p)
    local constructed = (tag % 64) >= 32
    local len = data:byte(p + 1)
    local body_start
    local v
    if len < 128 then
      body_start = p + 2
      v = len
    else
      local nlen = len - 128
      if p + 2 + nlen > #data then
        return nil, p
      end
      v = 0
      for k = 1, nlen do
        v = v * 256 + data:byte(p + 1 + k)
      end
      body_start = p + 2 + nlen
    end
    local body_end = body_start + v - 1
    if body_end > #data then
      return nil, p
    end
    local item = {
      tag = tag,
      constructed = constructed,
      value = data:sub(body_start, body_end),
    }
    if tag == 0x02 then
      local n = 0
      for k = 1, #item.value do
        n = n * 256 + item.value:byte(k)
      end
      if #item.value > 0 and item.value:byte(1) >= 128 then
        n = n - 256 ^ #item.value
      end
      item.int = n
    elseif tag == 0x06 then
      item.oid = snmp_decode_oid_bytes(item.value)
    end
    items[#items + 1] = item
    p = body_end + 1
  end
  return items, p
end

local function snmp_parse_varbinds(body, pos)
  local varbinds = {}
  local p = pos
  while p <= #body do
    local tag = body:byte(p)
    if tag ~= 0x30 then
      break
    end
    if p + 2 > #body then
      break
    end
    local len = body:byte(p + 1)
    local body_start
    local v
    if len < 128 then
      body_start = p + 2
      v = len
    else
      local nlen = len - 128
      if p + 2 + nlen > #body then
        break
      end
      v = 0
      for k = 1, nlen do
        v = v * 256 + body:byte(p + 1 + k)
      end
      body_start = p + 2 + nlen
    end
    local body_end = body_start + v - 1
    if body_end > #body then
      break
    end
    local vb = body:sub(body_start, body_end)
    local name_item, np = snmp_decode_variants(vb, 1, 1)
    if name_item == nil or name_item[1] == nil or name_item[1].tag ~= 0x06 then
      p = body_end + 1
    else
      local name = name_item[1].oid
      local val_item, _ = snmp_decode_variants(vb, np, 1)
      local entry = { oid = name }
      if val_item ~= nil and val_item[1] ~= nil then
        local vi = val_item[1]
        if vi.tag == 0x05 then
          entry.type = "null"
          entry.value = nil
        elseif vi.tag == 0x02 then
          entry.type = "integer"
          entry.value = vi.int
        elseif vi.tag == 0x04 then
          entry.type = "string"
          entry.value = vi.value
        elseif vi.tag == 0x06 then
          entry.type = "oid"
          entry.value = vi.oid
        elseif vi.tag == 0x40 then
          entry.type = "ipaddress"
          entry.value = vi.value
        elseif vi.tag == 0x41 or vi.tag == 0x42 or vi.tag == 0x46 then
          entry.type = "unsigned32"
          local n = 0
          for k = 1, math.min(4, #vi.value) do
            n = n * 256 + vi.value:byte(k)
          end
          entry.value = n
        elseif vi.tag == 0x43 then
          entry.type = "counter64"
          entry.value = vi.value
        elseif vi.tag == 0xA0 then
          entry.type = "noSuchName"
          entry.value = nil
        elseif vi.tag == 0xA1 then
          entry.type = "noSuchInstance"
          entry.value = nil
        elseif vi.tag == 0xA2 then
          entry.type = "endOfMibView"
          entry.value = nil
        elseif vi.tag == 0xA3 then
          entry.type = "noAccess"
          entry.value = nil
        else
          entry.type = "unknown"
          entry.value = vi.value
        end
      end
      varbinds[#varbinds + 1] = entry
    end
    p = body_end + 1
  end
  return varbinds
end

local function snmp_peel_tlv(data)
  if #data < 2 then
    return nil, nil
  end
  local tag = data:byte(1)
  local len = data:byte(2)
  local body_start
  local v
  if len < 128 then
    body_start = 3
    v = len
  else
    local nlen = len - 128
    if 3 + nlen > #data then
      return nil, nil
    end
    v = 0
    for k = 1, nlen do
      v = v * 256 + data:byte(2 + k)
    end
    body_start = 3 + nlen
  end
  if body_start + v - 1 > #data then
    return nil, nil
  end
  return tag, data:sub(body_start, body_start + v - 1)
end

local function snmp_parse_v1v2c_pdu(pdubody)
  local fields = {}
  local fp = 1
  while fp <= #pdubody do
    local ftag = pdubody:byte(fp)
    if fp + 2 > #pdubody then
      break
    end
    local flen = pdubody:byte(fp + 1)
    local fbody_start
    local fv
    if flen < 128 then
      fbody_start = fp + 2
      fv = flen
    else
      local nlen = flen - 128
      if fp + 2 + nlen > #pdubody then
        break
      end
      fv = 0
      for k = 1, nlen do
        fv = fv * 256 + pdubody:byte(fp + 1 + k)
      end
      fbody_start = fp + 2 + nlen
    end
    local fbody_end = fbody_start + fv - 1
    if fbody_end > #pdubody then
      break
    end
    local f = { tag = ftag, value = pdubody:sub(fbody_start, fbody_end) }
    if ftag == 0x02 then
      local n = 0
      for k = 1, #f.value do
        n = n * 256 + f.value:byte(k)
      end
      if #f.value > 0 and f.value:byte(1) >= 128 then
        n = n - 256 ^ #f.value
      end
      f.int = n
    end
    fields[#fields + 1] = f
    fp = fbody_end + 1
  end
  if #fields == 0 then
    return nil
  end
  local result = {}
  if fields[1].tag == 0x02 then
    result.request_id = fields[1].int
  end
  if #fields >= 2 and fields[2].tag == 0x02 then
    result.error_status = fields[2].int
  end
  if #fields >= 3 and fields[3].tag == 0x02 then
    result.error_index = fields[3].int
  end
  local varbind_field = fields[#fields]
  if varbind_field ~= nil and varbind_field.tag == 0x30 then
    result.varbinds = snmp_parse_varbinds(varbind_field.value, 1)
  end
  return result
end

local function snmp_parse_message(data)
  local msg, _pos = snmp_decode_variants(data, 1, 1)
  if msg == nil or msg[1] == nil or msg[1].tag ~= 0x30 then
    return nil, "malformed SNMP message: outer SEQUENCE missing"
  end
  local len0 = data:byte(2)
  local p
  if len0 < 128 then
    p = 3
  else
    local nlen0 = len0 - 128
    p = 3 + nlen0
  end
  local version_items, p2 = snmp_decode_variants(data, p, 1)
  if version_items == nil or version_items[1] == nil then
    return nil, "malformed SNMP message: version missing"
  end
  local version
  local rest
  if version_items[1].tag == 0x30 then
    local vitems, _ = snmp_decode_variants(version_items[1].value, 1, 1)
    if vitems == nil or vitems[1] == nil or vitems[1].tag ~= 0x02 then
      return nil, "malformed SNMPv3 message: version INTEGER missing"
    end
    version = vitems[1].int
    rest, p3 = snmp_decode_variants(data, p2, 1)
  else
    if version_items[1].tag ~= 0x02 then
      return nil, "malformed SNMP message: version INTEGER missing"
    end
    version = version_items[1].int
    rest, p3 = snmp_decode_variants(data, p2, 2)
  end
  local result = { version = version }
  if version == 0 or version == 1 then
    if rest == nil or #rest < 2 then
      return nil, "malformed SNMP message: body truncated"
    end
    local community_item = rest[1]
    local pdu_item = rest[2]
    if community_item.tag ~= 0x04 or pdu_item.tag ~= 0xA0 and pdu_item.tag ~= 0xA1 and pdu_item.tag ~= 0xA2 and pdu_item.tag ~= 0xA5 then
      return nil, "malformed SNMPv1/v2c message"
    end
    result.community = community_item.value
    result.pdu_tag = pdu_item.tag
    local pdubody = pdu_item.value
    local fields = {}
    local fp = 1
    while fp <= #pdubody do
      local ftag = pdubody:byte(fp)
      if fp + 2 > #pdubody then
        break
      end
      local flen = pdubody:byte(fp + 1)
      local fbody_start
      local fv
      if flen < 128 then
        fbody_start = fp + 2
        fv = flen
      else
        local nlen = flen - 128
        if fp + 2 + nlen > #pdubody then
          break
        end
        fv = 0
        for k = 1, nlen do
          fv = fv * 256 + pdubody:byte(fp + 1 + k)
        end
        fbody_start = fp + 2 + nlen
      end
      local fbody_end = fbody_start + fv - 1
      if fbody_end > #pdubody then
        break
      end
      local f = { tag = ftag, value = pdubody:sub(fbody_start, fbody_end) }
      if ftag == 0x02 then
        local n = 0
        for k = 1, #f.value do
          n = n * 256 + f.value:byte(k)
        end
        if #f.value > 0 and f.value:byte(1) >= 128 then
          n = n - 256 ^ #f.value
        end
        f.int = n
      end
      fields[#fields + 1] = f
      fp = fbody_end + 1
    end
    result.fields = fields
    local varbind_field
    if pdu_item.tag == 0xA5 then
      if #fields >= 1 then
        result.request_id = fields[1].int
      end
      if #fields >= 2 then
        result.non_repetitions = fields[2].int or 0
      end
      if #fields >= 3 then
        result.max_repetitions = fields[3].int or 0
      end
      varbind_field = fields[#fields]
    else
      if #fields >= 1 then
        result.request_id = fields[1].int
      end
      if #fields >= 2 then
        result.error_status = fields[2].int
      end
      if #fields >= 3 then
        result.error_index = fields[3].int
      end
      varbind_field = fields[#fields]
    end
    if varbind_field ~= nil and varbind_field.tag == 0x30 then
      result.varbinds = snmp_parse_varbinds(varbind_field.value, 1)
    end
    return result, nil
  end
  if version == 3 then
    if rest == nil or #rest < 1 then
      return nil, "malformed SNMPv3 message: msgData missing"
    end
    local msgdata = rest[1]
    if msgdata.tag ~= 0x30 then
      return nil, "malformed SNMPv3 message: msgData missing"
    end
    local model_item, mp2 = snmp_decode_variants(msgdata.value, 1, 1)
    if model_item == nil or model_item[1] == nil or model_item[1].tag ~= 0x02 then
      return nil, "malformed SNMPv3 message: securityModel missing"
    end
    result.security_model = model_item[1].int
    local params_item, mp3 = snmp_decode_variants(msgdata.value, mp2, 1)
    if params_item == nil or params_item[1] == nil then
      return nil, "malformed SNMPv3 message: securityParameters missing"
    end
    local sp = params_item[1]
    if sp.tag == 0x30 and sp.constructed then
      local name_item, sp2 = snmp_decode_variants(sp.value, 1, 1)
      if name_item ~= nil and name_item[1] ~= nil and name_item[1].tag == 0x04 then
        result.user = name_item[1].value
      end
      local engine_item, sp3 = snmp_decode_variants(sp.value, sp2, 1)
      if engine_item ~= nil and engine_item[1] ~= nil and engine_item[1].tag == 0x04 then
        result.engine_id_bytes = engine_item[1].value
      end
      local level_item, sp4 = snmp_decode_variants(sp.value, sp3, 1)
      if level_item ~= nil and level_item[1] ~= nil and level_item[1].tag == 0x02 then
        result.security_level = level_item[1].int
      end
      local auth_item, sp5 = snmp_decode_variants(sp.value, sp4, 1)
      if auth_item ~= nil and auth_item[1] ~= nil and auth_item[1].tag == 0x04 then
        result.auth_params = auth_item[1].value
      end
      local privkey_item, sp6 = snmp_decode_variants(sp.value, sp5, 1)
      if privkey_item ~= nil and privkey_item[1] ~= nil and privkey_item[1].tag == 0x04 then
        result.priv_key_id = privkey_item[1].value
      end
      local priv_item, sp7 = snmp_decode_variants(sp.value, sp6, 1)
      if priv_item ~= nil and priv_item[1] ~= nil and priv_item[1].tag == 0x04 then
        result.priv_params = priv_item[1].value
      end
    end
    local data_item, _ = snmp_decode_variants(msgdata.value, mp3, 1)
    if data_item == nil or data_item[1] == nil then
      return nil, "malformed SNMPv3 message: data missing"
    end
    local di = data_item[1]
    if di.tag == 0x04 then
      result.encrypted = true
      result.encrypted_blob = di.value
    else
      result.encrypted = false
      local sf = snmp_parse_v1v2c_pdu(di.value)
      if sf ~= nil then
        for k, v in pairs(sf) do
          result[k] = v
        end
      end
    end
    return result, nil
  end
  return nil, "unsupported SNMP version: " .. tostring(version)
end

local function snmp_encode_varbind(oid_str, vtype, value)
  local enc = snmp_encode_oid(oid_str)
  if enc == nil then
    return nil
  end
  local vval
  if vtype == "null" then
    vval = snmp_encode_null()
  elseif vtype == "integer" then
    vval = snmp_encode_int(value)
  elseif vtype == "oid" then
    vval = snmp_encode_oid(value)
  else
    vval = snmp_encode_octets(value)
  end
  local body = enc .. vval
  return string.char(0x30) .. snmp_ber_len(#body) .. body
end

local function snmp_build_varbinds(entries)
  local parts = {}
  for _, e in ipairs(entries) do
    local vb = snmp_encode_varbind(e.oid, e.type, e.value)
    if vb == nil then
      return nil
    end
    parts[#parts + 1] = vb
  end
  local body = table.concat(parts)
  return string.char(0x30) .. snmp_ber_len(#body) .. body
end

local function snmp_build_pdu(tag, request_id, fields_extra, varbind_body)
  local body = snmp_encode_int(request_id)
  if fields_extra ~= nil then
    body = body .. fields_extra
  else
    body = body .. snmp_encode_int(0) .. snmp_encode_int(0)
  end
  body = body .. varbind_body
  return string.char(tag) .. snmp_ber_len(#body) .. body
end

local function snmp_build_v1v2c_message(version, community, tag, request_id, varbinds, extra)
  local vbody = snmp_build_varbinds(varbinds)
  if vbody == nil then
    return nil
  end
  local pdu = snmp_build_pdu(tag, request_id, extra, vbody)
  local msgbody = snmp_encode_int(version) .. snmp_encode_octets(community) .. pdu
  return string.char(0x30) .. snmp_ber_len(#msgbody) .. msgbody
end

local function snmp_build_get_request(community, request_id, oids)
  local entries = {}
  for _, o in ipairs(oids) do
    entries[#entries + 1] = { oid = o, type = "null", value = nil }
  end
  return snmp_build_v1v2c_message(SNMP_VERSION_V1, community, PDU_GETREQUEST, request_id, entries)
end

local function snmp_build_getnext_request(community, request_id, oids)
  local entries = {}
  for _, o in ipairs(oids) do
    entries[#entries + 1] = { oid = o, type = "null", value = nil }
  end
  return snmp_build_v1v2c_message(SNMP_VERSION_V1, community, PDU_GETNEXTREQUEST, request_id, entries)
end

local function snmp_build_v2c_getbulk(community, request_id, non_reps, max_reps, oids)
  local entries = {}
  for _, o in ipairs(oids) do
    entries[#entries + 1] = { oid = o, type = "null", value = nil }
  end
  local extra = snmp_encode_int(non_reps) .. snmp_encode_int(max_reps)
  return snmp_build_v1v2c_message(SNMP_VERSION_V2C, community, PDU_GETBULKREQUEST, request_id, entries, extra)
end

local function snmp_build_set_request(community, request_id, assignments)
  local entries = {}
  for _, a in ipairs(assignments) do
    entries[#entries + 1] = { oid = a.oid, type = a.type, value = a.value }
  end
  return snmp_build_v1v2c_message(SNMP_VERSION_V2C, community, PDU_SETREQUEST, request_id, entries)
end

local function snmp_build_v3_security_params(user, engine_id, level, auth_params, priv_key_id, priv_params)
  local body = snmp_encode_octets(user)
    .. snmp_encode_octets(engine_id)
    .. snmp_encode_int(level)
    .. snmp_encode_octets(auth_params)
    .. snmp_encode_octets(priv_key_id)
    .. snmp_encode_octets(priv_params)
  return string.char(0x30) .. snmp_ber_len(#body) .. body
end

local function snmp_build_v3_data_field(tag, request_id, varbinds, encrypted, priv_blob)
  if encrypted then
    return string.char(0x04) .. snmp_ber_len(#priv_blob) .. priv_blob
  end
  local vbody = snmp_build_varbinds(varbinds)
  if vbody == nil then
    return nil
  end
  local pdu = snmp_build_pdu(tag, request_id, nil, vbody)
  local plen = pdu:byte(2)
  local body_start
  if plen < 128 then
    body_start = 3
  else
    body_start = 3 + (plen - 128)
  end
  local pdubody = pdu:sub(body_start)
  return string.char(0x81) .. snmp_ber_len(#pdubody) .. pdubody
end

local function snmp_build_v3_message(user, engine_id, level, auth_params, priv_key_id, priv_params, data_field)
  local sp = snmp_build_v3_security_params(user, engine_id, level, auth_params, priv_key_id, priv_params)
  local model = snmp_encode_int(USM_SECURITY_MODEL)
  local msgdata_body = model .. sp .. data_field
  local msgdata = string.char(0x30) .. snmp_ber_len(#msgdata_body) .. msgdata_body
  local global = snmp_encode_int(SNMP_VERSION_V3)
  local globalseq = string.char(0x30) .. snmp_ber_len(#global) .. global
  local msgbody = globalseq .. msgdata
  return string.char(0x30) .. snmp_ber_len(#msgbody) .. msgbody
end

local function snmp_md5(data)
  local msg = data
  local H0, H1, H2, H3 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
  local original_len = #msg
  local bit_len = original_len * 8
  msg = msg .. string.char(0x80)
  while #msg % 64 ~= 56 do
    msg = msg .. string.char(0x00)
  end
  for i = 0, 7 do
    msg = msg .. string.char(math.floor(bit_len / (256 ^ i)) % 256)
  end
  local function r(x, c)
    return ((x << c) % 0x100000000) + math.floor(x / (2 ^ (32 - c)))
  end
  local K = {}
  for i = 0, 63 do
    K[i + 1] = math.floor(math.abs(math.sin(i + 1)) * (2 ^ 32)) % (2 ^ 32)
  end
  local S = { { 7, 12, 17, 22 }, { 5, 9, 14, 20 }, { 4, 11, 16, 23 }, { 6, 10, 15, 21 } }
  for off = 0, #msg - 1, 64 do
    local M = {}
    for j = 0, 15 do
      local b = off + j * 4
      M[j + 1] = msg:byte(b + 1) + msg:byte(b + 2) * 256 + msg:byte(b + 3) * 65536 + (msg:byte(b + 4) or 0) * 16777216
    end
    local a, b_, c_, d_ = H0, H1, H2, H3
    for i = 0, 63 do
      local f, g
      if i < 16 then
        f = (b_ & c_) + ((~b_) & d_)
        g = i
      elseif i < 32 then
        f = (d_ & b_) + ((~d_) & c_)
        g = (5 * i + 1) % 16
      elseif i < 48 then
        f = b_ ~ c_ ~ d_
        g = (3 * i + 5) % 16
      else
        f = c_ ~ (b_ | (~d_))
        g = (7 * i) % 16
      end
      f = (f + a + K[i + 1] + M[g + 1]) % (2 ^ 32)
      a = d_
      d_ = c_
      c_ = b_
      b_ = (b_ + r(f, S[math.floor(i / 16) + 1][i % 4 + 1])) % (2 ^ 32)
    end
    H0 = (H0 + a) % (2 ^ 32)
    H1 = (H1 + b_) % (2 ^ 32)
    H2 = (H2 + c_) % (2 ^ 32)
    H3 = (H3 + d_) % (2 ^ 32)
  end
  local out = {}
  for _, h in ipairs({ H0, H1, H2, H3 }) do
    for i = 0, 3 do
      out[#out + 1] = string.char(math.floor(h / (256 ^ i)) % 256)
    end
  end
  return table.concat(out)
end

local function snmp_sha256(data)
  local K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  }
  local H = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  }
  local msg = data
  local bit_len = #msg * 8
  msg = msg .. string.char(0x80)
  while #msg % 64 ~= 56 do
    msg = msg .. string.char(0x00)
  end
  for i = 7, 0, -1 do
    msg = msg .. string.char(math.floor(bit_len / (256 ^ i)) % 256)
  end
  local function ror(x, c)
    return (math.floor(x / (2 ^ c)) % (2 ^ 32)) + ((x % (2 ^ c)) * (2 ^ (32 - c)))
  end
  for off = 0, #msg - 1, 64 do
    local w = {}
    for j = 0, 15 do
      local b = off + j * 4
      w[j + 1] = msg:byte(b + 1) * 16777216 + msg:byte(b + 2) * 65536 + msg:byte(b + 3) * 256 + msg:byte(b + 4)
    end
    for j = 17, 64 do
      local s0 = ror(w[j - 15], 7) ~ ror(w[j - 15], 18) ~ math.floor(w[j - 15] / 8)
      local s1 = ror(w[j - 2], 17) ~ ror(w[j - 2], 19) ~ math.floor(w[j - 2] / 1024)
      w[j] = (w[j - 16] + s0 + w[j - 7] + s1) % (2 ^ 32)
    end
    local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
    for i = 1, 64 do
      local S1 = ror(e, 6) ~ ror(e, 11) ~ ror(e, 25)
      local ch = (e & f) + ((~e) & g)
      local t1 = (h + S1 + ch + K[i] + w[i]) % (2 ^ 32)
      local S0 = ror(a, 2) ~ ror(a, 13) ~ ror(a, 22)
      local maj = (a & b) | (a & c) | (b & c)
      local t2 = (S0 + maj) % (2 ^ 32)
      h = g
      g = f
      f = e
      e = (d + t1) % (2 ^ 32)
      d = c
      c = b
      b = a
      a = (t1 + t2) % (2 ^ 32)
    end
    H[1] = (H[1] + a) % (2 ^ 32)
    H[2] = (H[2] + b) % (2 ^ 32)
    H[3] = (H[3] + c) % (2 ^ 32)
    H[4] = (H[4] + d) % (2 ^ 32)
    H[5] = (H[5] + e) % (2 ^ 32)
    H[6] = (H[6] + f) % (2 ^ 32)
    H[7] = (H[7] + g) % (2 ^ 32)
    H[8] = (H[8] + h) % (2 ^ 32)
  end
  local out = {}
  for _, h in ipairs(H) do
    for i = 3, 0, -1 do
      out[#out + 1] = string.char(math.floor(h / (256 ^ i)) % 256)
    end
  end
  return table.concat(out)
end

local function snmp_sha1(data)
  local H0, H1, H2, H3, H4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
  local msg = data
  local bit_len = #msg * 8
  msg = msg .. string.char(0x80)
  while #msg % 64 ~= 56 do
    msg = msg .. string.char(0x00)
  end
  for i = 7, 0, -1 do
    msg = msg .. string.char(math.floor(bit_len / (256 ^ i)) % 256)
  end
  local function rotl(x, c)
    return ((x << c) % (2 ^ 32)) + (math.floor(x / (2 ^ (32 - c))) % (2 ^ c))
  end
  for off = 0, #msg - 1, 64 do
    local w = {}
    for j = 0, 15 do
      local b = off + j * 4
      w[j] = msg:byte(b + 1) * 16777216 + msg:byte(b + 2) * 65536 + msg:byte(b + 3) * 256 + msg:byte(b + 4)
    end
    for j = 16, 79 do
      local x = w[j - 3] ~ w[j - 8] ~ w[j - 14] ~ w[j - 16]
      w[j] = rotl(x, 1)
    end
    local a, b, c, d, e = H0, H1, H2, H3, H4
    for i = 0, 79 do
      local f, k
      if i < 20 then
        f = (b & c) + ((~b) & d)
        k = 0x5A827999
      elseif i < 40 then
        f = b ~ c ~ d
        k = 0x6ED9EBA1
      elseif i < 60 then
        f = (b & c) | (b & d) | (c & d)
        k = 0x8F1BBCDC
      else
        f = b ~ c ~ d
        k = 0xCA62C1D6
      end
      local tmp = (rotl(a, 5) + f + e + k + w[i]) % (2 ^ 32)
      e = d
      d = c
      c = rotl(b, 30)
      b = a
      a = tmp
    end
    H0 = (H0 + a) % (2 ^ 32)
    H1 = (H1 + b) % (2 ^ 32)
    H2 = (H2 + c) % (2 ^ 32)
    H3 = (H3 + d) % (2 ^ 32)
    H4 = (H4 + e) % (2 ^ 32)
  end
  local out = {}
  for _, h in ipairs({ H0, H1, H2, H3, H4 }) do
    for i = 3, 0, -1 do
      out[#out + 1] = string.char(math.floor(h / (256 ^ i)) % 256)
    end
  end
  return table.concat(out)
end

local function snmp_hmac(digest_fn, key, msg)
  local block_size = 64
  if #key > block_size then
    key = digest_fn(key)
  end
  local kpad = key
  while #kpad < block_size do
    kpad = kpad .. string.char(0x00)
  end
  local o_key, i_key = {}, {}
  for i = 1, block_size do
    local b = kpad:byte(i)
    o_key[i] = string.char(b ~ 0x5C)
    i_key[i] = string.char(b ~ 0x36)
  end
  local inner = digest_fn(table.concat(i_key) .. msg)
  return digest_fn(table.concat(o_key) .. inner)
end

local function snmp_hex(data)
  return (data:gsub(".", function(c)
    return string.format("%02x", c:byte())
  end))
end

local kdf_cache = {}
local function snmp_usm_localize_key(key, engine_id, marker)
  local ck = key .. "|" .. snmp_hex(engine_id) .. "|" .. marker
  local hit = kdf_cache[ck]
  if hit ~= nil then
    return hit
  end
  local alg
  if #key >= 16 then
    alg = snmp_sha1
  else
    alg = snmp_md5
  end
  local cur = snmp_hmac(alg, key, engine_id .. string.char(marker))
  for _ = 1, USM_KDF_ROUNDS - 1 do
    cur = snmp_hmac(alg, key, cur)
  end
  kdf_cache[ck] = cur
  return cur
end

local function snmp_usm_auth_digest(auth_key, msg)
  if auth_key.md5 then
    return snmp_hmac(snmp_md5, auth_key.key, msg)
  elseif auth_key.sha256 then
    return snmp_hmac(snmp_sha256, auth_key.key, msg)
  else
    return snmp_hmac(snmp_sha1, auth_key.key, msg)
  end
end

local function snmp_usm_auth_placeholder_len(protocol_oid)
  if protocol_oid == USM_AUTH_MD5 then
    return 10
  elseif protocol_oid == USM_AUTH_SHA256 then
    return 16
  else
    return 12
  end
end

local function snmp_oid_name(oid_str)
  return OID_NAMES[oid_str] or oid_str
end

local function snmp_oid_in_prefix(oid_str, prefix)
  if oid_str == prefix then
    return true
  end
  local plen = #prefix
  if #oid_str <= plen then
    return false
  end
  if oid_str:sub(1, plen) ~= prefix then
    return false
  end
  if oid_str:sub(plen + 1, plen + 1) ~= "." then
    return false
  end
  return true
end

local function snmp_oid_next(oid_str)
  local parts = {}
  for p in tostring(oid_str):gmatch("%d+") do
    parts[#parts + 1] = tonumber(p)
  end
  if #parts == 0 then
    return nil
  end
  parts[#parts] = parts[#parts] + 1
  local out = {}
  for _, p in ipairs(parts) do
    out[#out + 1] = tostring(p)
  end
  return table.concat(out, ".")
end

local function snmp_error_name(code)
  return SNERR_NAMES[code] or ("genErr:" .. tostring(code))
end

local function snmp_base64(data)
  local chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  local out = {}
  for i = 1, #data, 3 do
    local a = data:byte(i)
    local b = data:byte(i + 1) or 0
    local c = data:byte(i + 2) or 0
    local n = a * 65536 + b * 256 + c
    out[#out + 1] = chars:sub(math.floor(n / (64 * 64 * 64)) + 1, math.floor(n / (64 * 64 * 64)) + 1)
    out[#out + 1] = chars:sub(math.floor(n / (64 * 64)) % 64 + 1, math.floor(n / (64 * 64)) % 64 + 1)
    if i + 1 <= #data then
      out[#out + 1] = chars:sub(math.floor(n / 64) % 64 + 1, math.floor(n / 64) % 64 + 1)
    else
      out[#out + 1] = "="
    end
    if i + 2 <= #data then
      out[#out + 1] = chars:sub(n % 64 + 1, n % 64 + 1)
    else
      out[#out + 1] = "="
    end
  end
  return table.concat(out)
end

local DES_IP = { 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 }

local DES_FIP = { 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 }local DES_PC1 = { 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4 }
local DES_SHIFTS = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 }
local DES_PC2 = { 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 }
local DES_E = { 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1 }
local DES_S = {
  {
    { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
    { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
    { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
    { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 },
  },
  {
    { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
    { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
    { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
    { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 },
  },
  {
    { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
    { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
    { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
    { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 },
  },
  {
    { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
    { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
    { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
    { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 },
  },
  {
    { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
    { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
    { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
    { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 },
  },
  {
    { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
    { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
    { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
    { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 },
  },
  {
    { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
    { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
    { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
    { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 },
  },
  {
    { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
    { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
    { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
    { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 },
  },
}
local DES_P = { 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25 }

local function snmp_bytes_to_words(data)
  local words = {}
  for i = 1, #data, 4 do
    local w = 0
    for k = 0, 3 do
      w = w * 256 + (data:byte(i + k) or 0)
    end
    words[(i - 1) / 4 + 1] = w
  end
  return words
end

local function snmp_words_to_bytes(words)
  local out = {}
  for _, w in ipairs(words) do
    for i = 3, 0, -1 do
      out[#out + 1] = string.char(math.floor(w / (256 ^ i)) % 256)
    end
  end
  return table.concat(out)
end

local function snmp_des_key_schedule(key8)
  local kbits = {}
  for i = 1, 8 do
    local b = key8:byte(i)
    for k = 7, 0, -1 do
      kbits[#kbits + 1] = math.floor(b / (2 ^ k)) % 2
    end
  end
  local c, d = {}, {}
  for i = 1, 28 do
    c[i] = kbits[DES_PC1[i]]
    d[i] = kbits[DES_PC1[i + 28]]
  end
  local rounds = {}
  for r = 1, 16 do
    local shift = DES_SHIFTS[r]
    local c2 = {}
    for i = 1, 28 do
      c2[i] = c[((i + shift - 1) % 28) + 1]
    end
    c = c2
    local d2 = {}
    for i = 1, 28 do
      d2[i] = d[((i + shift - 1) % 28) + 1]
    end
    d = d2
    local cd = {}
    for i = 1, 28 do
      cd[i] = c[i]
    end
    for i = 1, 28 do
      cd[28 + i] = d[i]
    end
    local round_key = 0
    for i = 1, 48 do
      round_key = round_key * 2 + cd[DES_PC2[i]]
    end
    rounds[r] = round_key
  end
  return rounds
end

local function snmp_des_f(right, round_key)
  local rbits = {}
  for i = 31, 0, -1 do
    rbits[i + 1] = math.floor(right / (2 ^ i)) % 2
  end
  local e = {}
  for i = 1, 48 do
    e[i] = rbits[33 - DES_E[i]]
  end
  local x = 0
  for i = 1, 48 do
    x = x * 2 + e[i]
  end
  local xk = x ~ round_key
  local xbits = {}
  for i = 47, 0, -1 do
    xbits[i + 1] = math.floor(xk / (2 ^ i)) % 2
  end
  local s_out = {}
  for box = 1, 8 do
    local seg = {}
    for i = 0, 5 do
      seg[i + 1] = xbits[54 - 6 * box - i]
    end
    local row = seg[1] * 2 + seg[6]
    local col = 0
    for i = 2, 5 do
      col = col * 2 + seg[i]
    end
    local val = DES_S[box][row + 1][col + 1]
    for k = 3, 0, -1 do
      s_out[(box - 1) * 4 + (4 - k)] = math.floor(val / (2 ^ k)) % 2
    end
  end
  local result = 0
  for i = 1, 32 do
    result = result * 2 + s_out[DES_P[i]]
  end
  return result
end

local function snmp_des_block(block, rounds, decrypting)
  local words = snmp_bytes_to_words(block)
  local hi, lo = words[1], words[2]
  local pbits = {}
  for i = 63, 0, -1 do
    if i >= 32 then
      pbits[i + 1] = math.floor(hi / (2 ^ (i - 32))) % 2
    else
      pbits[i + 1] = math.floor(lo / (2 ^ i)) % 2
    end
  end
  local ip = {}
  for i = 1, 64 do
    ip[i] = pbits[65 - DES_IP[i]]
  end
  local l = 0
  for i = 1, 32 do
    l = l * 2 + ip[i]
  end
  local r = 0
  for i = 33, 64 do
    r = r * 2 + ip[i]
  end
  local order
  if decrypting then
    order = {}
    for i = 16, 1, -1 do
      order[#order + 1] = i
    end
  else
    order = {}
    for i = 1, 16 do
      order[#order + 1] = i
    end
  end
  for _, rr in ipairs(order) do
    local f = snmp_des_f(r, rounds[rr])
    local newl = r
    local newr = (l ~ f) % (2 ^ 32)
    l, r = newl, newr
  end
  local obits = {}
  for i = 63, 0, -1 do
    if i >= 32 then
      obits[i + 1] = math.floor(r / (2 ^ (i - 32))) % 2
    else
      obits[i + 1] = math.floor(l / (2 ^ i)) % 2
    end
  end
  local op = {}
  for i = 1, 64 do
    op[i] = obits[65 - DES_FIP[i]]
  end
  local ohi = 0
  for i = 1, 32 do
    ohi = ohi * 2 + op[i]
  end
  local olo = 0
  for i = 33, 64 do
    olo = olo * 2 + op[i]
  end
  return snmp_words_to_bytes({ ohi, olo })
end

local function snmp_des_cbc(key8, iv8, data, encrypting)
  local rounds = snmp_des_key_schedule(key8)
  local padded = data
  if #padded % 8 ~= 0 then
    local pad = 8 - (#padded % 8)
    padded = padded .. string.rep(string.char(0x00), pad)
  end
  local out = {}
  local prev = iv8
  for i = 1, #padded, 8 do
    local block = padded:sub(i, i + 7)
    local xored = {}
    for k = 1, 8 do
      xored[k] = string.char(block:byte(k) ~ prev:byte(k))
    end
    local xdata = table.concat(xored)
    local result
    if encrypting then
      result = snmp_des_block(xdata, rounds, false)
    else
      result = snmp_des_block(xdata, rounds, true)
    end
    out[#out + 1] = result
    if encrypting then
      prev = result
    else
      prev = block
    end
  end
  local plain = table.concat(out)
  if not encrypting then
    local last
    local j = #plain
    while j > 0 and plain:byte(j) == 0 do
      last = j
      j = j - 1
    end
    if last ~= nil then
      plain = plain:sub(1, last - 1)
    end
  end
  return plain
end

local AES_SBOX = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}
local AES_RCON = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 }

local function snmp_aes_xtime(a)
  if a >= 128 then
    return ((a << 1) ~ 0x1b) % 256
  end
  return (a << 1) % 256
end

local function snmp_aes_gmul(a, b)
  local res = 0
  local x = a
  local y = b
  for _ = 1, 8 do
    if y % 2 == 1 then
      res = res ~ x
    end
    x = snmp_aes_xtime(x)
    y = math.floor(y / 2)
  end
  return res
end

local function snmp_aes_expand_key(key16)
  local nk, nr = 4, 10
  local w = {}
  for i = 0, 3 do
    local b = key16:sub(i * 4 + 1, i * 4 + 4)
    local word = b:byte(1) * 16777216 + b:byte(2) * 65536 + b:byte(3) * 256 + b:byte(4)
    w[i] = word
  end
  for i = 4, nk * (nr + 1) - 1 do
    local temp = w[i - 1]
    if i % nk == 0 then
      local bytes = {
        math.floor(temp / (2 ^ 24)) % 256,
        math.floor(temp / (2 ^ 16)) % 256,
        math.floor(temp / (2 ^ 8)) % 256,
        temp % 256,
      }
      local rot = { bytes[2], bytes[3], bytes[4], bytes[1] }
      local sb = {}
      for k = 1, 4 do
        sb[k] = AES_SBOX[rot[k] + 1]
      end
      sb[1] = sb[1] ~ AES_RCON[math.floor((i - 1) / nk) + 1]
      temp = sb[1] * 16777216 + sb[2] * 65536 + sb[3] * 256 + sb[4]
    end
    w[i] = w[i - nk] ~ temp
  end
  return w
end

local function snmp_aes_encrypt_block(key16, block)
  local w = snmp_aes_expand_key(key16)
  local state = {}
  for i = 0, 15 do
    state[i] = block:byte(i + 1)
  end
  local function add_round_key(round)
    for col = 0, 3 do
      local kw = w[4 * round + col]
      for row = 0, 3 do
        state[col * 4 + row] = state[col * 4 + row] ~ math.floor(kw / (2 ^ (8 * (3 - row)))) % 256
      end
    end
  end
  add_round_key(0)
  for round = 1, 9 do
    local subbed = {}
    for i = 0, 15 do
      subbed[i] = AES_SBOX[state[i] + 1]
    end
    state = subbed
    local shifted = {}
    for col = 0, 3 do
      for row = 0, 3 do
        shifted[col * 4 + row] = state[((row + col) % 4) * 4 + row]
      end
    end
    state = shifted
    for col = 0, 3 do
      local a = {}
      for row = 0, 3 do
        a[row] = state[col * 4 + row]
      end
      local b = {}
      b[0] = snmp_aes_gmul(a[0], 2) ~ snmp_aes_gmul(a[1], 3) ~ a[2] ~ a[3]
      b[1] = a[0] ~ snmp_aes_gmul(a[1], 2) ~ snmp_aes_gmul(a[2], 3) ~ a[3]
      b[2] = a[0] ~ a[1] ~ snmp_aes_gmul(a[2], 2) ~ snmp_aes_gmul(a[3], 3)
      b[3] = snmp_aes_gmul(a[0], 3) ~ a[1] ~ a[2] ~ snmp_aes_gmul(a[3], 2)
      for row = 0, 3 do
        state[col * 4 + row] = b[row]
      end
    end
    add_round_key(round)
  end
  local subbed = {}
  for i = 0, 15 do
    subbed[i] = AES_SBOX[state[i] + 1]
  end
  state = subbed
  local shifted = {}
  for col = 0, 3 do
    for row = 0, 3 do
      shifted[col * 4 + row] = state[((row + col) % 4) * 4 + row]
    end
  end
  state = shifted
  add_round_key(10)
  local out = {}
  for i = 0, 15 do
    out[i + 1] = string.char(state[i])
  end
  return table.concat(out)
end

local function snmp_aes128_cfb(key16, iv16, data, encrypting)
  local register = iv16
  local out = {}
  local last_len = #data % 16
  local full = math.floor(#data / 16) * 16
  for i = 1, full, 16 do
    local chunk = data:sub(i, i + 15)
    local ks = snmp_aes_encrypt_block(key16, register)
    local xored = {}
    for k = 1, 16 do
      xored[k] = string.char(chunk:byte(k) ~ ks:byte(k))
    end
    local result = table.concat(xored)
    out[#out + 1] = result
    register = encrypting and result or chunk
  end
  if last_len > 0 then
    local chunk = data:sub(full + 1)
    local ks = snmp_aes_encrypt_block(key16, register)
    local xored = {}
    for k = 1, last_len do
      xored[k] = string.char(chunk:byte(k) ~ ks:byte(k))
    end
    local partial = table.concat(xored)
    out[#out + 1] = partial
    local pad = string.rep(string.char(0x00), 16 - last_len)
    register = encrypting and (partial .. pad) or (chunk .. pad)
  end
  return table.concat(out)
end

local function snmp_priv_derive(priv_key, engine_id)
  local keymat = snmp_usm_localize_key(priv_key, engine_id, 5)
  local ivmat = snmp_usm_localize_key(priv_key, engine_id, 6)
  return keymat, ivmat
end

local function snmp_priv_encrypt(privacy_oid, priv_key, engine_id, data)
  local keymat, ivmat = snmp_priv_derive(priv_key, engine_id)
  if privacy_oid == USM_PRIV_DES then
    return snmp_des_cbc(keymat:sub(1, 8), ivmat:sub(1, 8), data, true)
  else
    return snmp_aes128_cfb(keymat:sub(1, 16), ivmat:sub(1, 16), data, true)
  end
end

local function snmp_priv_decrypt(privacy_oid, priv_key, engine_id, data)
  local keymat, ivmat = snmp_priv_derive(priv_key, engine_id)
  if privacy_oid == USM_PRIV_DES then
    return snmp_des_cbc(keymat:sub(1, 8), ivmat:sub(1, 8), data, false)
  else
    return snmp_aes128_cfb(keymat:sub(1, 16), ivmat:sub(1, 16), data, false)
  end
end

local snmp_request_counter = 0

local function snmp_next_request_id()
  snmp_request_counter = (snmp_request_counter + 1) % 2147483647
  if snmp_request_counter < 1 then
    snmp_request_counter = 1
  end
  return snmp_request_counter
end

local function snmp_session_new(host, port, args)
  return {
    host = host,
    port = port,
    args = args,
    sock = nil,
    connected = false,
    closed = false,
    community_read = nil,
    community_write = nil,
    v3_active = false,
    v3_engine_id = nil,
    v3_users = {},
    v3_levels = {},
    tables = {},
    responses = 0,
    errors = 0,
    timeouts = 0,
    no_such_name = 0,
  }
end

local function snmp_socket_open(sess)
  local sock = nmap.new_socket("udp")
  if not sock then
    return nil, "socket allocation failed"
  end
  sock:set_timeout(math.floor((sess.args.timeout or 8) * 1000))
  local ok, err = sock:connect(sess.host, sess.port, "udp")
  if not ok then
    sock:close()
    return nil, "UDP connect failed: " .. tostring(err or "unknown")
  end
  sess.sock = sock
  sess.connected = true
  return sock
end

local function snmp_close_session(sess)
  if sess and sess.sock and not sess.closed then
    sess.sock:close()
  end
  if sess then
    sess.closed = true
    sess.connected = false
  end
end

local function snmp_send(sess, data)
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

local function snmp_recv_once(sess)
  local ok, dat = sess.sock:receive(65535)
  if ok and dat and #dat > 0 then
    return dat
  end
  sess.timeouts = sess.timeouts + 1
  return nil
end

local function snmp_match_response(sess, raw, want_version, want_community, want_request_id, want_pdu_tags)
  local parsed, err = snmp_parse_message(raw)
  if parsed == nil then
    return nil, "response parse failed: " .. tostring(err)
  end
  if want_version ~= nil and parsed.version ~= want_version then
    return nil, "version mismatch in response"
  end
  if want_community ~= nil and parsed.community ~= want_community then
    return nil, "community mismatch in response"
  end
  if want_request_id ~= nil and parsed.request_id ~= want_request_id then
    return nil, "request-id mismatch in response"
  end
  if want_pdu_tags ~= nil then
    local found = false
    for _, tag in ipairs(want_pdu_tags) do
      if parsed.pdu_tag == tag then
        found = true
        break
      end
    end
    if not found then
      return nil, "unexpected PDU tag in response"
    end
  end
  sess.responses = sess.responses + 1
  return parsed
end

local function snmp_transact_v1v2c(sess, version, community, pdu_tag, request_id, entries, extra)
  local msg
  if pdu_tag == PDU_GETREQUEST then
    local oids = {}
    for _, e in ipairs(entries) do
      oids[#oids + 1] = e.oid
    end
    msg = snmp_build_v1v2c_message(version, community, PDU_GETREQUEST, request_id, entries)
  elseif pdu_tag == PDU_GETNEXTREQUEST then
    local oids = {}
    for _, e in ipairs(entries) do
      oids[#oids + 1] = e.oid
    end
    msg = snmp_build_v1v2c_message(version, community, PDU_GETNEXTREQUEST, request_id, entries)
  elseif pdu_tag == PDU_GETBULKREQUEST then
    msg = snmp_build_v1v2c_message(version, community, PDU_GETBULKREQUEST, request_id, entries, extra)
  elseif pdu_tag == PDU_SETREQUEST then
    msg = snmp_build_set_request(community, request_id, entries)
  else
    return nil, "unsupported PDU for v1/v2c transact"
  end
  local ok, err = snmp_send(sess, msg)
  if not ok then
    return nil, err
  end
  local raw = snmp_recv_once(sess)
  if raw == nil or #raw == 0 then
    return nil, "no response (timeout)"
  end
  return snmp_match_response(sess, raw, version, community, request_id, { PDU_RESPONSE })
end

local function snmp_get_varbinds(sess, community, oids)
  local request_id = snmp_next_request_id()
  local entries = {}
  for _, o in ipairs(oids) do
    entries[#entries + 1] = { oid = o, type = "null", value = nil }
  end
  local parsed, err = snmp_transact_v1v2c(sess, SNMP_VERSION_V2C, community, PDU_GETREQUEST, request_id, entries, nil)
  if parsed == nil then
    return nil, err
  end
  return parsed.varbinds or {}
end

local function snmp_next_varbinds(sess, community, oids)
  local request_id = snmp_next_request_id()
  local entries = {}
  for _, o in ipairs(oids) do
    entries[#entries + 1] = { oid = o, type = "null", value = nil }
  end
  local parsed, err = snmp_transact_v1v2c(sess, SNMP_VERSION_V2C, community, PDU_GETNEXTREQUEST, request_id, entries, nil)
  if parsed == nil then
    return nil, err
  end
  return parsed.varbinds or {}
end

local function snmp_walk_v2c(sess, community, root_oid, max_rows)
  local rows = {}
  local current = root_oid
  local request_id = snmp_next_request_id()
  local entries = { { oid = current, type = "null", value = nil } }
  local extra = snmp_encode_int(0) .. snmp_encode_int(math.min(max_rows or 25, 25))
  while #rows < (max_rows or 25) do
    if budget_exhausted(sess.args) then
      break
    end
    request_id = snmp_next_request_id()
    local parsed, err = snmp_transact_v1v2c(sess, SNMP_VERSION_V2C, community, PDU_GETBULKREQUEST, request_id, entries, extra)
    if parsed == nil then
      if err ~= nil and string.find(err, "no response", 1, true) ~= nil then
        break
      end
      break
    end
    local got = 0
    local done = false
    for _, vb in ipairs(parsed.varbinds or {}) do
      if vb.oid ~= nil and snmp_oid_in_prefix(vb.oid, root_oid) then
        if vb.type == "endOfMibView" or vb.type == "noSuchName" or vb.type == "noSuchInstance" or vb.type == "noAccess" then
          done = true
        else
          rows[#rows + 1] = { oid = vb.oid, type = vb.type, value = vb.value }
          got = got + 1
          if #rows >= (max_rows or 25) then
            break
          end
        end
      end
    end
    if done or got == 0 then
      break
    end
    local last = rows[#rows]
    if last == nil or last.oid == nil then
      break
    end
    local nextoid = snmp_oid_next(last.oid)
    if nextoid == nil then
      break
    end
    entries = { { oid = nextoid, type = "null", value = nil } }
  end
  return rows
end

local function snmp_walk_v1(sess, community, root_oid, max_rows)
  local rows = {}
  local current = root_oid
  while #rows < (max_rows or 25) do
    if budget_exhausted(sess.args) then
      break
    end
    local request_id = snmp_next_request_id()
    local entries = { { oid = current, type = "null", value = nil } }
    local parsed, err = snmp_transact_v1v2c(sess, SNMP_VERSION_V1, community, PDU_GETNEXTREQUEST, request_id, entries, nil)
    if parsed == nil then
      break
    end
    local got = false
    for _, vb in ipairs(parsed.varbinds or {}) do
      if vb.oid ~= nil and snmp_oid_in_prefix(vb.oid, root_oid) then
        if vb.type == "endOfMibView" or vb.type == "noSuchName" or vb.type == "noSuchInstance" or vb.type == "noAccess" then
          break
        end
        rows[#rows + 1] = { oid = vb.oid, type = vb.type, value = vb.value }
        got = true
        break
      end
    end
    if not got then
      break
    end
    local last = rows[#rows]
    local nextoid = snmp_oid_next(last.oid)
    if nextoid == nil then
      break
    end
    current = nextoid
  end
  return rows
end

local function snmp_probe_system(sess, community)
  local oids = {
    "1.3.6.1.2.1.1.1.0",
    "1.3.6.1.2.1.1.2.0",
    "1.3.6.1.2.1.1.3.0",
    "1.3.6.1.2.1.1.4.0",
    "1.3.6.1.2.1.1.5.0",
    "1.3.6.1.2.1.1.6.0",
  }
  local names = {
    "sysDescr",
    "sysObjectID",
    "sysUpTime",
    "sysContact",
    "sysName",
    "sysLocation",
  }
  local varbinds, err = snmp_get_varbinds(sess, community, oids)
  if varbinds == nil then
    return nil, err
  end
  local info = {}
  for i, vb in ipairs(varbinds) do
    info[names[i]] = { type = vb.type, value = vb.value, oid = vb.oid }
  end
  return info
end

local function snmp_probe_table(sess, community, root_oid, fields, max_rows)
  local rows = snmp_walk_v2c(sess, community, root_oid, max_rows or 25)
  local result = {}
  for _, row in ipairs(rows) do
    if row.oid ~= root_oid then
      local suffix = row.oid:sub(#root_oid + 2)
      local column, index_part = suffix:match("^(%d+)%.?(.-)$")
      if column ~= nil then
        local entry = result[index_part]
        if entry == nil then
          entry = { index = index_part, fields = {} }
          result[index_part] = entry
        end
        for _, f in ipairs(fields) do
          if column == f.oid then
            entry.fields[f.name] = { type = row.type, value = row.value }
          end
        end
      end
    end
  end
  return result, #rows
end

local function snmp_probe_interfaces(sess, community)
  local fields = {
    { name = "ifDescr", oid = "1" },
    { name = "ifType", oid = "2" },
    { name = "ifSpeed", oid = "5" },
    { name = "ifPhysAddress", oid = "6" },
    { name = "ifAdminStatus", oid = "7" },
    { name = "ifOperStatus", oid = "8" },
  }
  return snmp_probe_table(sess, community, "1.3.6.1.2.1.2.2.1", fields, 25)
end

local function snmp_probe_ip_routes(sess, community)
  local fields = {
    { name = "ipRouteDest", oid = "1" },
    { name = "ipRouteIfIndex", oid = "2" },
    { name = "ipRouteMetric1", oid = "3" },
    { name = "ipRouteNextHop", oid = "7" },
  }
  return snmp_probe_table(sess, community, "1.3.6.1.2.1.4.21.1", fields, 50)
end

local function snmp_probe_arp(sess, community)
  local fields = {
    { name = "ipNetToMediaIfIndex", oid = "1" },
    { name = "ipNetToMediaNetAddress", oid = "2" },
    { name = "ipNetToMediaPhysAddress", oid = "3" },
  }
  return snmp_probe_table(sess, community, "1.3.6.1.2.1.4.22.1", fields, 50)
end

local function snmp_probe_processes(sess, community)
  local fields = {
    { name = "hrSWRunPerfIndex", oid = "1" },
    { name = "hrSWRunName", oid = "2" },
    { name = "hrSWRunPath", oid = "3" },
    { name = "hrSWRunParameters", oid = "4" },
    { name = "hrSWRunStatus", oid = "5" },
  }
  return snmp_probe_table(sess, community, "1.3.6.1.2.1.25.4.2.1", fields, 50)
end

local function snmp_probe_software(sess, community)
  local fields = {
    { name = "hrSWRunName", oid = "2" },
    { name = "hrSWRunPath", oid = "3" },
    { name = "hrSWRunParameters", oid = "4" },
  }
  return snmp_probe_table(sess, community, "1.3.6.1.2.1.25.4.2.1", fields, 50)
end

local function snmp_probe_storage(sess, community)
  local fields = {
    { name = "hrStorageIndex", oid = "1" },
    { name = "hrStorageType", oid = "2" },
    { name = "hrStorageDescr", oid = "3" },
    { name = "hrStorageAllocUnits", oid = "4" },
    { name = "hrStorageSize", oid = "5" },
    { name = "hrStorageUsed", oid = "6" },
  }
  return snmp_probe_table(sess, community, "1.3.6.1.2.1.25.2.3.1", fields, 25)
end

local function snmp_probe_tcp_conn(sess, community)
  local fields = {
    { name = "tcpConnState", oid = "1" },
    { name = "tcpConnLocalAddress", oid = "2" },
    { name = "tcpConnLocalPort", oid = "3" },
    { name = "tcpConnRemoteAddress", oid = "4" },
    { name = "tcpConnRemotePort", oid = "5" },
  }
  return snmp_probe_table(sess, community, "1.3.6.1.2.1.6.13.1.1", fields, 50)
end

local function snmp_probe_udp(sess, community)
  local fields = {
    { name = "udpLocalAddress", oid = "2" },
    { name = "udpLocalPort", oid = "3" },
  }
  return snmp_probe_table(sess, community, "1.3.6.1.2.1.7.5.1.1", fields, 50)
end

local function snmp_probe_cisco_config(sess, community)
  local oids = {
    "1.3.6.1.4.1.9.9.96.1.1.1.1.1.1",
    "1.3.6.1.4.1.9.9.96.1.1.1.1.1.2",
    "1.3.6.1.4.1.9.9.96.1.1.1.1.2.1.1.1.1.1.1.1.1",
  }
  local varbinds, err = snmp_get_varbinds(sess, community, oids)
  if varbinds == nil then
    return nil, err
  end
  local result = {}
  for _, vb in ipairs(varbinds) do
    result[vb.oid] = { type = vb.type, value = vb.value }
  end
  return result
end

local function snmp_probe_community(sess, community)
  local oids = { "1.3.6.1.2.1.1.5.0" }
  local varbinds, err = snmp_get_varbinds(sess, community, oids)
  if varbinds == nil then
    if err ~= nil and string.find(err, "timeout", 1, true) ~= nil then
      return nil, "timeout"
    end
    return nil, err
  end
  if #varbinds > 0 then
    local vb = varbinds[1]
    if vb.type == "noSuchName" or vb.type == "noSuchObject" or vb.type == "noInstance" then
      return nil, "noSuch"
    end
    if vb.type == "null" then
      return nil, "null"
    end
    return { community = community, sysName = vb.value }
  end
  return nil, "empty"
end

local function snmp_probe_write(sess, community)
  local request_id = snmp_next_request_id()
  local entries = {
    { oid = "1.3.6.1.2.1.1.5.0", type = "string", value = "snmp-audit-write-test" },
  }
  local parsed, err = snmp_transact_v1v2c(sess, SNMP_VERSION_V2C, community, PDU_SETREQUEST, request_id, entries, nil)
  if parsed == nil then
    return nil, err
  end
  local status = parsed.error_status
  if status == nil then
    return nil, "no error status in set response"
  end
  if status == 0 then
    local restore_id = snmp_next_request_id()
    local restore_entries = {
      { oid = "1.3.6.1.2.1.1.5.0", type = "string", value = "write-test-revert" },
    }
    snmp_transact_v1v2c(sess, SNMP_VERSION_V2C, community, PDU_SETREQUEST, restore_id, restore_entries, nil)
    return { writable = true, status = status }
  end
  return { writable = false, status = status, status_name = snmp_error_name(status) }
end

local function snmp_probe_v3_engine(sess, user, level, auth_proto, priv_proto, auth_key, priv_key)
  local bogus_engine = string.char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
  local auth_params = string.rep(string.char(0x00), snmp_usm_auth_placeholder_len(auth_proto))
  local priv_params = ""
  local data_field = snmp_build_v3_data_field(
    PDU_GETREQUEST,
    1,
    { { oid = "1.3.6.1.2.1.1.5.0", type = "null", value = nil } },
    false,
    ""
  )
  local msg = snmp_build_v3_message(user, bogus_engine, level, auth_params, "", "", data_field)
  local ok, err = snmp_send(sess, msg)
  if not ok then
    return nil, err
  end
  local raw = snmp_recv_once(sess)
  if raw == nil or #raw == 0 then
    return nil, "no response (timeout)"
  end
  local parsed, perr = snmp_parse_message(raw)
  if parsed == nil then
    return nil, "v3 response parse failed: " .. tostring(perr)
  end
  if parsed.engine_id_bytes ~= nil then
    sess.v3_engine_id = parsed.engine_id_bytes
  end
  if parsed.varbinds ~= nil and #parsed.varbinds > 0 then
    sess.v3_users[user] = { level = level, ok = true }
    return parsed
  end
  if parsed.error_status ~= nil then
    return parsed
  end
  return parsed
end

local function snmp_session_open(host, port, args)
  local sess = snmp_session_new(host, port, args)
  local sock, err = snmp_socket_open(sess)
  if not sock then
    return nil, err
  end
  return sess
end

local function snmp_summary(sess)
  local summary = stdnse.output_table()
  summary["UDP sessions"] = "1"
  summary["Requests sent"] = tostring(state.requests)
  summary["Responses matched"] = tostring(sess.responses)
  summary["Timeouts"] = tostring(sess.timeouts)
  summary["Transport errors"] = tostring(sess.errors)
  return summary
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

local function probe_community_list(sess, list)
  for _, community in ipairs(list) do
    if budget_exhausted(sess.args) then
      break
    end
    local info, err = snmp_probe_community(sess, community)
    if info ~= nil then
      return community, info
    end
  end
  return nil
end

local function collect_usm_users(sess, community)
  local users = {}
  local rows, _ = snmp_probe_table(sess, community, USM_USER_ROOT, {
    { name = "securityName", oid = "1" },
    { name = "authProtocol", oid = "4" },
    { name = "privProtocol", oid = "5" },
  }, 25)
  for _, row in pairs(rows) do
    local entry = users[row.index]
    if entry == nil then
      entry = { name = nil, auth = nil, priv = nil }
      users[row.index] = entry
    end
    if row.fields.securityName ~= nil then
      entry.name = row.fields.securityName.value
    end
    if row.fields.authProtocol ~= nil and row.fields.authProtocol.type == "oid" then
      local base = row.fields.authProtocol.value
      local stripped = string.gsub(base, "%.%d+$", "")
      entry.auth = USM_AUTH_PROTOCOLS[stripped] or base
    end
    if row.fields.privProtocol ~= nil and row.fields.privProtocol.type == "oid" then
      local base = row.fields.privProtocol.value
      local stripped = string.gsub(base, "%.%d+$", "")
      entry.priv = USM_PRIV_PROTOCOLS[stripped] or base
    end
  end
  return users
end

local function collect_process_hints(process_rows)
  local hints = {}
  for _, row in pairs(process_rows) do
    local params = row.fields.hrSWRunParameters and row.fields.hrSWRunParameters.value
    if params ~= nil and type(params) == "string" then
      local uflag = string.match(params, "%-u[ =](%w+)")
      if uflag ~= nil then
        hints[#hints + 1] = { name = uflag, source = "process parameters" }
      end
      local home = string.match(params, "(/home/[%w%._-]+)")
      if home ~= nil then
        local user = string.match(home, "/home/([^/]+)")
        if user ~= nil then
          hints[#hints + 1] = { name = user, source = "process path " .. home }
        end
      end
    end
    local pname = row.fields.hrSWRunName and row.fields.hrSWRunName.value
    if pname ~= nil and string.match(pname, "%d+$") == nil then
      if string.find(pname, "user", 1, true) ~= nil then
        hints[#hints + 1] = { name = pname, source = "process name" }
      end
    end
  end
  return hints
end

local function account_report(usm_users, contact, process_hints)
  local out = stdnse.output_table()
  local user_lines = {}
  for _, index in ipairs(sorted_keys(usm_users)) do
    local entry = usm_users[index]
    if entry and entry.name ~= nil then
      local line = entry.name
      if entry.auth ~= nil or entry.priv ~= nil then
        line = line .. " (auth: " .. tostring(entry.auth) .. ", priv: " .. tostring(entry.priv) .. ")"
      end
      user_lines[#user_lines + 1] = line
    end
  end
  out["USM security names"] = (#user_lines > 0) and table.concat(user_lines, ", ") or "none readable"
  out["sysContact identities"] = (contact ~= nil) and contact or "none"
  out["Process-derived identities"] = (#process_hints > 0) and table.concat(process_hints, ", ") or "none"
  return out
end

local function remediation_section()
  local remediation = stdnse.output_table()
  remediation["1. Drop Read Community Access"] = "Remove the community that answered the walk; SNMPv1/v2c read access is what publishes the identity data."
  remediation["2. Lock the USM View Down"] = "Restrict the usmUserTable to the management user's SNMPv3 context; it should never be reachable via a read community."
  remediation["3. Minimize Process Exposure"] = "Run daemons with minimal command lines; avoid user home directories in argv where possible."
  remediation["4. Treat Leaked Names as Exposed"] = "Add the enumerated names to phishing/credential-stuffing monitoring for the next audit window."
  return { key = "Remediation", value = remediation }
end

action = function(host, port)

local args = read_args()
reset_findings()
reset_state()

local sess, err = snmp_session_open(host, port, args)
local sections = {}

if not sess then
  local status_text = "INFORMATIONAL - account leak audit incomplete: " .. tostring(err)
  add_finding("INFO", "Could not open a UDP session to the SNMP agent", {
    subject = "session",
    evidence = tostring(err),
    confidence = "low",
  })
  local fail_out = new_output(RISK_LEVEL, status_text)
  local unique, counts = dedupe_findings()
  return finish_output(fail_out, unique, counts, sections)
end

local community, identity = probe_community_list(sess, CANDIDATE_COMMUNITIES)
local usm_users = {}
local contact = nil
local process_hints = {}

if community ~= nil then
  usm_users = collect_usm_users(sess, community)
  local system_info = snmp_probe_system(sess, community)
  if system_info and system_info.sysContact then
    contact = tostring(system_info.sysContact.value or "")
  end
  local process_rows, _ = snmp_probe_processes(sess, community)
  process_hints = collect_process_hints(process_rows)
end

local user_names = {}
local seen_names = {}
for _, index in ipairs(sorted_keys(usm_users)) do
  local entry = usm_users[index]
  if entry and entry.name ~= nil then
    unique_append(user_names, seen_names, entry.name)
  end
end
for _, hint in ipairs(process_hints) do
  unique_append(user_names, seen_names, hint.name)
end

local report = account_report(usm_users, contact, process_hints)
table.insert(sections, { key = "Account Identity Leak", value = report })

local status_text
if community == nil then
  status_text = "INFORMATIONAL - no readable community; identity tables not exposed"
  add_finding("INFO", "No candidate community could read the identity tables", {
    subject = "access",
    evidence = "agent silent or filtered for all candidates",
    confidence = "medium",
  })
elseif #user_names > 0 then
  status_text = "VULNERABLE - " .. tostring(#user_names) .. " account identity(ies) leaked via SNMP"
  add_finding("CRITICAL", "SNMPv3 security names are world-readable through the USM user table", {
    subject = "usmUserTable",
    evidence = table.concat(user_names, ", "),
    confidence = "high",
  })
  for _, name in ipairs(user_names) do
    local source = "usmUserTable"
    for _, hint in ipairs(process_hints) do
      if hint.name == name then
        source = hint.source
      end
    end
    add_finding("HIGH", "Account identity leaked: " .. name, {
      subject = name,
      evidence = "readable via " .. source,
      confidence = "high",
    })
  end
  if contact ~= nil and contact ~= "" then
    add_finding("MEDIUM", "Administrative contact address exposed via sysContact", {
      subject = "sysContact",
      evidence = contact,
      confidence = "high",
    })
  end
else
  status_text = "SECURE - no account identities leaked through the readable MIB"
  add_finding("INFO", "Identity sources contained no account names", {
    subject = "identity tables",
    evidence = "usmUserTable, sysContact and process parameters checked",
    confidence = "high",
  })
end

table.insert(sections, remediation_section())
table.insert(sections, {
  key = "CVSS Score",
  value = (#user_names > 0) and (USER_LEAK_CVSS .. " (unauthenticated identity enumeration)") or "n/a - no identities leaked",
})

snmp_close_session(sess)
local unique, counts = dedupe_findings()
local out = new_output(RISK_LEVEL, status_text)
return finish_output(out, unique, counts, sections)

end
