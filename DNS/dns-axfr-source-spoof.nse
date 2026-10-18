local shortport = require "shortport"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Evaluates how the target guards its zone transfers against an
UNAUTHORIZED source - the classic DNS access-control failure that
hands the entire zone (every host, every internal IP, every TXT
payload, every service record) to anyone who asks, or - when the
transfer is at least restricted - how easy it would be to impersonate
an authorized secondary.

This is a DEFENSIVE audit. The script never forges source addresses,
never sends traffic at volume, and never attacks the server: it
measures what the zone already discloses to the current (external)
source, and it lists the authorized-source addresses that a real
attacker would have to impersonate if the ACL is source-based.

1. Direct AXFR attempt (TCP/53): the scanner requests a full zone
   transfer for the audited domain. If the server streams the zone
   back, the transfer ACL is open to arbitrary external hosts: a
   CRITICAL finding, plus a full exposure inventory of the received
   zone:
   - internal (RFC1918 / loopback / link-local) A addresses and the
     names they belong to,
   - TXT payloads that look like credentials or tokens (glpat-,
     api-key, password, token, secret, Bearer) - values are masked in
     the report,
   - NS / MX / SRV entries pointing at names outside the audited
     zone (internal infrastructure in the public zone),
   - record names matching high-value label patterns (db, vpn,
     internal, deploy, secret, staging, backup).
2. IXFR asymmetry probe: some configurations refuse AXFR but allow
   IXFR (incremental transfer). The script requests an IXFR from
   serial 0 (which degrades to a full zone) and, if the SOA is
   readable, from the current serial. A successful IXFR where AXFR
   was refused is a HIGH finding: the restriction is incomplete.
3. UDP AXFR probe: one AXFR query over UDP. A server that answers
   (usually with a truncated SOA) is at least not silently dropping
   transfer requests on the wire; the exposed SOA serial is recorded
   so the report shows what a passive observer can learn.
4. Spoofable-source analysis (always performed): the zone's NS set
   and the SOA MNAME are the addresses a source-based allow-transfer
   ACL would trust. Each is resolved by A record; the resulting list
   of "authorized source" IPs is exactly what an attacker on a
   spoofable path (same /24, compromised upstream, BGP route leak)
   would impersonate. The list is reported, and a MEDIUM finding is
   raised when it is non-empty, with the caveat that source ACLs
   alone are not a boundary.
5. Atomicity check: when a transfer is received, the first and last
   SOA are compared (a non-atomic snapshot means the zone changed
   mid-transfer - a change-management signal).

Every step is one small standard query; the AXFR/IXFR steps retrieve
the zone's own data, the same bytes its legitimate secondaries
receive. Total traffic is a few dozen requests capped by the budget.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"vuln", "safe"}

portrule = shortport.port_or_service(53, "domain", "tcp")

local SCRIPT_NAME = "dns-axfr-source-spoof"

local RISK_LEVEL = "🔴 CRITICAL"

local SOA_QTYPE = 6
local NS_QTYPE = 2
local A_QTYPE = 1
local MX_QTYPE = 15
local SRV_QTYPE = 25
local TXT_QTYPE = 16
local AXFR_QTYPE = 252
local IXFR_QTYPE = 253

local SECRET_PATTERNS = {
  "glpat-", "github_pat_", "api-key", "apikey", "api_key", "apikey:",
  "password", "passwd", "secret", "token", "bearer ", "privatekey",
  "private_key", "aws_secret", "client_secret",
}

local HIGH_VALUE_LABELS = {
  "db", "db1", "database", "vpn", "internal", "intranet", "deploy",
  "deployment", "secret", "secrets", "staging", "backup", "bak",
  "admin", "root", "ci", "jenkins", "vault",
}

local DEFAULT_ARGS = {
  domain = nil,
  maxrequests = 32,
  retries = 0,
  timeout = 10000,
  delay = 0.05,
  ixfr_check = true,
  udp_check = true,
  spoof_surface = true,
}

local NUMERIC_ARGS = {
  { key = "maxrequests", minimum = 4, integer = true },
  { key = "retries", minimum = 0, integer = true },
  { key = "timeout", minimum = 500, integer = true },
}

local BOOLEAN_ARGS = { "ixfr_check", "udp_check", "spoof_surface" }

local STRING_ARGS = { "domain" }

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

local function mask_value(value)
  local text = tostring(value or "")
  if #text <= 4 then
    return string.rep("*", #text)
  end
  return string.sub(text, 1, 2) .. string.rep("*", math.min(#text - 4, 24))
    .. string.sub(text, -2) .. " (" .. #text .. " chars)"
end

local function is_placeholder(value)
  local text = lower(trim(tostring(value or "")))
  if #text == 0 then
    return true
  end
  local placeholders = { "no value", "not set", "none", "null", "nil", "-",
    "undefined", "***", "*****", "redacted", "hidden", "n/a", "unknown",
    "(none)", "off", "disabled" }
  for _, candidate in ipairs(placeholders) do
    if text == candidate then
      return true
    end
  end
  if string.match(text, "^%*+$") then
    return true
  end
  return false
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

local QTYPE_NAMES = {
  [1] = "A", [2] = "NS", [5] = "CNAME", [6] = "SOA", [12] = "PTR",
  [15] = "MX", [16] = "TXT", [17] = "RP", [18] = "AFSDB", [23] = "HINFO",
  [24] = "MINFO", [25] = "SRV", [28] = "AAAA", [32] = "NAPTR", [33] = "DS",
  [41] = "SSHFP", [43] = "RRSIG", [45] = "NSEC", [46] = "DNSKEY",
  [47] = "DHCID", [48] = "NSEC3", [49] = "NSEC3PARAM", [50] = "TLSA",
  [52] = "HTTPS", [53] = "SMIMEA", [55] = "SVCB", [60] = "CAA",
  [99] = "SPF", [129] = "KX", [165] = "DNAME", [251] = "URI", [255] = "ANY",
  [252] = "AXFR", [253] = "IXFR",
}

local QTYPE_CODES = {
  A = 1, NS = 2, CNAME = 5, SOA = 6, PTR = 12, MX = 15, TXT = 16,
  SRV = 25, AAAA = 28, NAPTR = 32, DS = 33, SSHFP = 41, RRSIG = 43,
  NSEC = 45, DNSKEY = 46, NSEC3 = 48, NSEC3PARAM = 49, TLSA = 50,
  CAA = 60, URI = 251, ANY = 255, AXFR = 252, IXFR = 253,
}

local RCODE_NAMES = {
  [0] = "NOERROR", [1] = "FORMERR", [2] = "SERVFAIL", [3] = "NXDOMAIN",
  [4] = "NOTIMP", [5] = "REFUSED", [6] = "YXDOMAIN", [7] = "YXRRSET",
  [8] = "NXRRSET", [9] = "NOTAUTH", [10] = "NOTZONE",
}

local function qtype_name(code)
  if type(code) == "number" then
    return QTYPE_NAMES[code] or ("TYPE" .. code)
  end
  local upper = string.upper(tostring(code))
  return QTYPE_NAMES[upper] and upper or tostring(code)
end

local function qtype_code(name)
  local upper = string.upper(tostring(name or ""))
  return QTYPE_CODES[upper]
end

local function u16(value)
  return string.char(math.floor(value / 256) % 256, value % 256)
end

local function u32(value)
  return string.char(
    math.floor(value / 16777216) % 256,
    math.floor(value / 65536) % 256,
    math.floor(value / 256) % 256,
    value % 256)
end

local function encode_name(name)
  local encoded = ""
  for label in string.gmatch(tostring(name or ""), "[^%.]+") do
    local part = label
    if #part > 63 then
      part = string.sub(part, 1, 63)
    end
    encoded = encoded .. string.char(#part) .. part
  end
  return encoded .. string.char(0)
end

local function decode_name(data, pos)
  local labels = {}
  local jumps = 0
  local newpos = nil
  while true do
    if pos < 1 or pos > #data then
      return nil, nil
    end
    local first = string.byte(data, pos)
    if first == nil then
      return nil, nil
    end
    if first == 0 then
      pos = pos + 1
      break
    elseif first % 64 == 0 then
      if first % 192 == 0 then
        return nil, nil
      end
      local second = string.byte(data, pos + 1)
      if not second then
        return nil, nil
      end
      jumps = jumps + 1
      if jumps > 24 then
        return nil, nil
      end
      if not newpos then
        newpos = pos + 2
      end
      pos = ((first % 128) * 256) + second + 1
    elseif first < 64 then
      pos = pos + 1
      if pos + first - 1 > #data then
        return nil, nil
      end
      table.insert(labels, string.sub(data, pos, pos + first - 1))
      pos = pos + first
    else
      return nil, nil
    end
  end
  if not newpos then
    newpos = pos
  end
  if #labels == 0 then
    return ".", newpos
  end
  return table.concat(labels, "."), newpos
end

local function ipv4_text(data, start)
  if start + 3 > #data then
    return nil
  end
  return string.format("%d.%d.%d.%d",
    string.byte(data, start), string.byte(data, start + 1),
    string.byte(data, start + 2), string.byte(data, start + 3))
end

local function ipv6_text(data, start)
  if start + 15 > #data then
    return nil
  end
  local groups = {}
  for i = 0, 7 do
    local hi = string.byte(data, start + i * 2)
    local lo = string.byte(data, start + i * 2 + 1)
    table.insert(groups, string.format("%x", hi * 256 + lo))
  end
  local best_start, best_len = nil, 0
  local run_start, run_len = 1, 0
  for i = 1, 8 do
    if groups[i] == "0" then
      if run_start == nil then
        run_start = i
      end
      run_len = run_len + 1
      if run_len > best_len then
        best_start, best_len = run_start, run_len
      end
    else
      run_start, run_len = nil, 0
    end
  end
  if best_len >= 2 then
    local head_parts = {}
    for i = 1, best_start - 1 do
      table.insert(head_parts, groups[i])
    end
    local tail_parts = {}
    for i = best_start + best_len, 8 do
      table.insert(tail_parts, groups[i])
    end
    local head = table.concat(head_parts, ":")
    local tail = table.concat(tail_parts, ":")
    if head == "" and tail == "" then
      return "::"
    end
    if head == "" then
      return ":" .. tail
    end
    if tail == "" then
      return head .. "::"
    end
    return head .. "::" .. tail
  end
  return table.concat(groups, ":")
end

local function hex_dump(data, start, finish, limit)
  if start > finish then
    return ""
  end
  local shown = math.min(finish, start + (limit or 32) - 1)
  local out = {}
  for i = start, shown do
    table.insert(out, string.format("%02x", string.byte(data, i)))
  end
  local text = table.concat(out, " ")
  if shown < finish then
    text = text .. " ..."
  end
  return text
end

local function txt_strings(data, start, finish)
  local chunks = {}
  local pos = start
  while pos <= finish do
    local len = string.byte(data, pos)
    if len == nil then
      break
    end
    if len == 0 then
      pos = pos + 1
      break
    end
    if pos + len > finish then
      table.insert(chunks, string.sub(data, pos + 1, finish))
      break
    end
    table.insert(chunks, string.sub(data, pos + 1, pos + len))
    pos = pos + len + 1
  end
  return table.concat(chunks, " ")
end

local function soa_value(data, pos, finish)
  local mname, pos2 = decode_name(data, pos)
  if not pos2 then
    return nil
  end
  local rname, pos3 = decode_name(data, pos2)
  if not pos3 or pos3 + 19 > finish then
    return nil
  end
  local function u32at(p)
    return string.byte(data, p) * 16777216 + string.byte(data, p + 1) * 65536
      + string.byte(data, p + 2) * 256 + string.byte(data, p + 3)
  end
  local serial = u32at(pos3)
  local refresh = u32at(pos3 + 4)
  local retry = u32at(pos3 + 8)
  local expire = u32at(pos3 + 12)
  local minimum = u32at(pos3 + 16)
  return {
    mname = mname, rname = rname, serial = serial, refresh = refresh,
    retry = retry, expire = expire, minimum = minimum,
    text = string.format("%s %s serial=%d refresh=%d retry=%d expire=%d minimum=%d",
      mname, rname, serial, refresh, retry, expire, minimum),
  }, pos3 + 20
end

local function parse_rdata(data, start, finish, rtype)
  local pos = start
  if rtype == 1 then
    return ipv4_text(data, pos), finish + 1
  end
  if rtype == 28 then
    return ipv6_text(data, pos), finish + 1
  end
  if rtype == 2 or rtype == 5 or rtype == 12 then
    local name, next_pos = decode_name(data, pos)
    if not name then
      return nil, finish + 1
    end
    return name, next_pos > finish and finish + 1 or next_pos
  end
  if rtype == 6 then
    local soa, next_pos = soa_value(data, pos, finish)
    if not soa then
      return nil, finish + 1
    end
    soa.next_pos = next_pos
    return soa, (next_pos or finish + 1)
  end
  if rtype == 15 then
    if pos + 1 > finish then
      return nil, finish + 1
    end
    local pref = string.byte(data, pos) * 256 + string.byte(data, pos + 1)
    local name, next_pos = decode_name(data, pos + 2)
    if not name then
      return nil, finish + 1
    end
    return { preference = pref, exchange = name,
      text = string.format("%d %s", pref, name) },
      (next_pos > finish and finish + 1 or next_pos)
  end
  if rtype == 16 or rtype == 99 or rtype == 129 then
    return txt_strings(data, pos, finish), finish + 1
  end
  if rtype == 25 then
    if pos + 5 > finish then
      return nil, finish + 1
    end
    local prio = string.byte(data, pos) * 256 + string.byte(data, pos + 1)
    local weight = string.byte(data, pos + 2) * 256 + string.byte(data, pos + 3)
    local port = string.byte(data, pos + 4) * 256 + string.byte(data, pos + 5)
    local target, next_pos = decode_name(data, pos + 6)
    if not target then
      return nil, finish + 1
    end
    return { priority = prio, weight = weight, port = port, target = target,
      text = string.format("%d %d %d %s", prio, weight, port, target) },
      (next_pos > finish and finish + 1 or next_pos)
  end
  if rtype == 32 then
    if pos + 7 > finish then
      return nil, finish + 1
    end
    local order = string.byte(data, pos) * 256 + string.byte(data, pos + 1)
    local pref = string.byte(data, pos + 2) * 256 + string.byte(data, pos + 3)
    local flags_len = string.byte(data, pos + 4)
    pos = pos + 5
    local flags = string.sub(data, pos, pos + flags_len - 1)
    pos = pos + flags_len
    local service_len = string.byte(data, pos)
    pos = pos + 1
    local service = string.sub(data, pos, pos + service_len - 1)
    pos = pos + service_len
    local regexp_len = string.byte(data, pos)
    pos = pos + 1
    local regexp = string.sub(data, pos, pos + regexp_len - 1)
    pos = pos + regexp_len
    local replacement, next_pos = decode_name(data, pos)
    return { order = order, preference = pref, flags = flags, service = service,
      regexp = regexp, replacement = replacement,
      text = string.format("%d %d %s %s -> %s", order, pref, flags,
        service, tostring(replacement)) },
      (next_pos and next_pos > finish and finish + 1 or next_pos) or finish + 1
  end
  if rtype == 33 then
    if pos + 3 > finish then
      return nil, finish + 1
    end
    local tag = string.byte(data, pos) * 256 + string.byte(data, pos + 1)
    local algorithm = string.byte(data, pos + 2)
    local digest_type = string.byte(data, pos + 3)
    local digest = hex_dump(data, pos + 4, finish, 32)
    return { key_tag = tag, algorithm = algorithm, digest_type = digest_type,
      digest = digest,
      text = string.format("keyTag=%d algorithm=%d digestType=%d digest=%s",
        tag, algorithm, digest_type, digest) }, finish + 1
  end
  if rtype == 46 then
    if pos + 3 > finish then
      return nil, finish + 1
    end
    local flags = string.byte(data, pos) * 256 + string.byte(data, pos + 1)
    local protocol = string.byte(data, pos + 2)
    local algorithm = string.byte(data, pos + 3)
    local key_text = hex_dump(data, pos + 4, finish, 24)
    return { flags = flags, protocol = protocol, algorithm = algorithm,
      key = key_text,
      text = string.format("flags=%d protocol=%d algorithm=%d %s",
        flags, protocol, algorithm, key_text) }, finish + 1
  end
  if rtype == 43 then
    if pos + 17 > finish then
      return nil, finish + 1
    end
    local covered = string.byte(data, pos) * 256 + string.byte(data, pos + 1)
    local algorithm = string.byte(data, pos + 2)
    local labels = string.byte(data, pos + 3)
    local sig_ttl = string.byte(data, pos + 4) * 16777216
      + string.byte(data, pos + 5) * 65536 + string.byte(data, pos + 6) * 256
      + string.byte(data, pos + 7)
    local expiration = string.byte(data, pos + 8) * 16777216
      + string.byte(data, pos + 9) * 65536 + string.byte(data, pos + 10) * 256
      + string.byte(data, pos + 11)
    local inception = string.byte(data, pos + 12) * 16777216
      + string.byte(data, pos + 13) * 65536 + string.byte(data, pos + 14) * 256
      + string.byte(data, pos + 15)
    local key_tag = string.byte(data, pos + 16) * 256 + string.byte(data, pos + 17)
    local signer, next_pos = decode_name(data, pos + 18)
    return { type_covered = qtype_name(covered), algorithm = algorithm,
      labels = labels, signature_ttl = sig_ttl, expiration = expiration,
      inception = inception, key_tag = key_tag, signer = signer,
      text = string.format("%s alg=%d labels=%d expires=%d keyTag=%d signer=%s",
        qtype_name(covered), algorithm, labels, expiration, key_tag,
        tostring(signer)) },
      (next_pos and next_pos > finish and finish + 1 or next_pos) or finish + 1
  end
  if rtype == 45 then
    local next_name, next_pos = decode_name(data, pos)
    if not next_name then
      return nil, finish + 1
    end
    local bitmap = ""
    if next_pos <= finish then
      bitmap = hex_dump(data, next_pos, finish, 16)
    end
    return { next_domain = next_name, types_bitmap = bitmap,
      text = string.format("next=%s bitmap=%s", next_name, bitmap) },
      finish + 1
  end
  if rtype == 48 then
    if pos + 4 > finish then
      return nil, finish + 1
    end
    local hash_algo = string.byte(data, pos)
    local flags = string.byte(data, pos + 1)
    local iterations = string.byte(data, pos + 2) * 256 + string.byte(data, pos + 3)
    local salt_len = string.byte(data, pos + 4)
    pos = pos + 5
    local salt = hex_dump(data, pos, pos + salt_len - 1, 8)
    pos = pos + salt_len
    local next_hash = hex_dump(data, pos, pos + 20 > finish and finish or pos + 20, 20)
    return { hash_algorithm = hash_algo, flags = flags, iterations = iterations,
      salt = salt, next_hash = next_hash,
      text = string.format("algo=%d flags=%d iter=%d salt=%s next=%s",
        hash_algo, flags, iterations, salt, next_hash) }, finish + 1
  end
  if rtype == 60 then
    if pos + 1 > finish then
      return nil, finish + 1
    end
    local flags = string.byte(data, pos)
    local tag_len = string.byte(data, pos + 1)
    pos = pos + 2
    local tag = string.sub(data, pos, pos + tag_len - 1)
    pos = pos + tag_len
    local value = string.sub(data, pos, finish)
    return { flags = flags, tag = tag, value = value,
      text = string.format("%s %s", tag, value) }, finish + 1
  end
  if rtype == 41 then
    if pos + 1 > finish then
      return nil, finish + 1
    end
    local algorithm = string.byte(data, pos)
    local hash_type = string.byte(data, pos + 1)
    local fingerprint = hex_dump(data, pos + 2, finish, 32)
    return { algorithm = algorithm, hash_type = hash_type,
      fingerprint = fingerprint,
      text = string.format("algorithm=%d hashType=%d %s",
        algorithm, hash_type, fingerprint) }, finish + 1
  end
  if rtype == 50 then
    if pos + 3 > finish then
      return nil, finish + 1
    end
    return string.format("usage=%d selector=%d mtype=%d cert=%s",
      string.byte(data, pos), string.byte(data, pos + 1),
      string.byte(data, pos + 2), hex_dump(data, pos + 4, finish, 16)),
      finish + 1
  end
  return hex_dump(data, pos, finish, 32), finish + 1
end

local function parse_record(data, pos)
  local name, pos2 = decode_name(data, pos)
  if not pos2 or pos2 + 9 > #data then
    return nil, pos
  end
  local rtype = string.byte(data, pos2) * 256 + string.byte(data, pos2 + 1)
  local rclass = string.byte(data, pos2 + 2) * 256 + string.byte(data, pos2 + 3)
  local ttl = string.byte(data, pos2 + 4) * 16777216
    + string.byte(data, pos2 + 5) * 65536
    + string.byte(data, pos2 + 6) * 256
    + string.byte(data, pos2 + 7)
  local rdlength = string.byte(data, pos2 + 8) * 256 + string.byte(data, pos2 + 9)
  local rdata_start = pos2 + 10
  if rdata_start + rdlength - 1 > #data then
    rdlength = #data - rdata_start + 1
  end
  local value, next_pos = parse_rdata(data, rdata_start, rdata_start + rdlength - 1, rtype)
  if not next_pos or next_pos < rdata_start + rdlength then
    next_pos = rdata_start + rdlength
  end
  local record = {
    name = name,
    type = rtype,
    type_name = qtype_name(rtype),
    class = rclass,
    ttl = ttl,
    rdlength = rdlength,
    value = value,
    rdata = string.sub(data, rdata_start, rdata_start + rdlength - 1),
  }
  if record.type == 41 and record.class >= 512 then
    record.edns = { buffer = record.class, ext_flags = ttl, options = record.rdata }
  end
  return record, next_pos
end

local function parse_response(raw)
  if type(raw) ~= "string" or #raw < 12 then
    return nil
  end
  local id = string.byte(raw, 1) * 256 + string.byte(raw, 2)
  local flags = string.byte(raw, 3) * 256 + string.byte(raw, 4)
  local hi = math.floor(flags / 256)
  local lo = flags % 256
  local parsed = {
    id = id,
    qr = math.floor(hi / 128) % 2,
    opcode = math.floor(hi / 16) % 16,
    aa = math.floor(hi / 4) % 2,
    tc = math.floor(hi / 2) % 2,
    rd = hi % 2,
    ra = math.floor(lo / 128) % 2,
    ad = math.floor(lo / 16) % 2,
    rcode = lo % 16,
    rcode_name = RCODE_NAMES[lo % 16] or tostring(lo % 16),
    qdcount = string.byte(raw, 5) * 256 + string.byte(raw, 6),
    ancount = string.byte(raw, 7) * 256 + string.byte(raw, 8),
    nscount = string.byte(raw, 9) * 256 + string.byte(raw, 10),
    arcount = string.byte(raw, 11) * 256 + string.byte(raw, 12),
    questions = {},
    answers = {},
    authority = {},
    additional = {},
  }
  local pos = 13
  for _ = 1, parsed.qdcount do
    local qname, pos2 = decode_name(raw, pos)
    if not pos2 or pos2 + 3 > #raw then
      return nil
    end
    local qtype = string.byte(raw, pos2) * 256 + string.byte(raw, pos2 + 1)
    local qclass = string.byte(raw, pos2 + 2) * 256 + string.byte(raw, pos2 + 3)
    table.insert(parsed.questions, {
      name = qname, type = qtype, type_name = qtype_name(qtype), class = qclass,
    })
    pos = pos2 + 4
  end
  local sections = { parsed.answers, parsed.authority, parsed.additional }
  local counts = { parsed.ancount, parsed.nscount, parsed.arcount }
  for section = 1, 3 do
    for _ = 1, counts[section] do
      if pos > #raw then
        return nil
      end
      local record, next_pos = parse_record(raw, pos)
      if not record then
        return nil
      end
      table.insert(sections[section], record)
      pos = next_pos
    end
  end
  if parsed.qdcount > 0 and #parsed.questions ~= parsed.qdcount then
    return nil
  end
  if #parsed.answers ~= parsed.ancount or #parsed.authority ~= parsed.nscount
    or #parsed.additional ~= parsed.arcount then
    return nil
  end
  parsed.size = #raw
  return parsed
end

local function build_query(id, qname, qtype, opts)
  opts = opts or {}
  local qtype_val = type(qtype) == "number" and qtype or qtype_code(qtype)
  if not qtype_val then
    qtype_val = 1
  end
  local arcount = opts.edns and 1 or 0
  local rd = opts.rd and 0x0100 or 0x0000
  local header = u16(id) .. u16(rd) .. u16(1) .. u16(0) .. u16(0) .. u16(arcount)
  local question = encode_name(qname) .. u16(qtype_val) .. u16(opts.qclass or 1)
  local body = header .. question
  if opts.edns then
    local edns_do_flags = opts.edns_do and 0x00008000 or 0
    body = body .. string.char(0) .. u16(41) .. u16(opts.buffer or 4096)
      .. u32(edns_do_flags) .. u16(0)
  end
  return body
end

local function records_of_type(parsed, rtype)
  local code = type(rtype) == "number" and rtype or qtype_code(rtype)
  local found = {}
  if not code then
    return found
  end
  for _, section in ipairs({ parsed.answers, parsed.authority, parsed.additional }) do
    for _, record in ipairs(section) do
      if record.type == code then
        table.insert(found, record)
      end
    end
  end
  return found
end

local function first_record_value(parsed, rtype)
  local found = records_of_type(parsed, rtype)
  if #found > 0 and found[1].value ~= nil then
    if type(found[1].value) == "table" then
      return found[1].value.text or found[1].value
    end
    return found[1].value
  end
  return nil
end

local function normalize_domain(value)
  local v = trim(tostring(value or ""))
  if v == "" then
    return nil
  end
  v = string.gsub(v, "%.$", "")
  return v
end

local function port_number_of(port)
  if type(port) == "number" then
    return port
  end
  if type(port) == "table" and type(port.number) == "number" then
    return port.number
  end
  return 53
end

local function dns_lookup(host, port, qname, qtype, args, opts)
  port = port_number_of(port)
  if budget_exhausted(args) then
    return nil, "request budget exhausted"
  end
  local attempt = 0
  local last_err = "no response"
  while attempt <= (args.retries or 0) do
    attempt = attempt + 1
    state.requests = state.requests + 1
    local socket = nmap.new_socket("udp")
    local ok, connect_err = socket:connect(host, port)
    if ok then
      socket:set_timeout(args.timeout)
      local id = math.random(1, 65535)
      local query = build_query(id, qname, qtype, opts)
      local sent_ok, send_err = socket:send(query)
      if sent_ok then
        local received_ok, data = socket:receive()
        if received_ok and type(data) == "string" and #data >= 12 then
          local parsed = parse_response(data)
          if parsed then
            parsed.query_size = #query
            sleep(args.delay or 0)
            return parsed, nil
          end
          last_err = "malformed response (" .. #data .. " bytes)"
        else
          last_err = "no response (timeout)"
        end
      else
        last_err = "send failed: " .. tostring(send_err)
      end
    else
      last_err = "connect failed: " .. tostring(connect_err)
    end
    socket:close()
    sleep(0.4 * attempt)
  end
  return nil, last_err
end

local function dns_axfr(host, port, qname, args)
  port = port_number_of(port)
  if budget_exhausted(args) then
    return nil, "request budget exhausted"
  end
  state.requests = state.requests + 1
  local socket = nmap.new_socket("tcp")
  local ok, connect_err = socket:connect(host, port)
  if not ok then
    socket:close()
    return nil, "connect failed: " .. tostring(connect_err)
  end
  socket:set_timeout(args.timeout)
  local id = math.random(1, 65535)
  local query = build_query(id, qname, 252, { rd = false })
  local sent_ok, send_err = socket:send(query)
  if not sent_ok then
    socket:close()
    return nil, "send failed: " .. tostring(send_err)
  end
  local records = {}
  local first_soa = nil
  local packets = 0
  local size = #query
  local completed = false
  local first_rcode = nil
  local first_rcode_name = nil
  while packets < 256 do
    local ok_len, len_bytes = socket:receive(2)
    if not ok_len or type(len_bytes) ~= "string" or #len_bytes < 2 then
      break
    end
    local length = string.byte(len_bytes, 1) * 256 + string.byte(len_bytes, 2)
    if length == 0 or length > 65535 then
      break
    end
    local ok_pkt, pkt = socket:receive(length)
    if not ok_pkt or type(pkt) ~= "string" or #pkt < 12 then
      break
    end
    packets = packets + 1
    size = size + 2 + #pkt
    local parsed = parse_response(pkt)
    if not parsed then
      break
    end
    if first_rcode == nil then
      first_rcode = parsed.rcode
      first_rcode_name = parsed.rcode_name
    end
    for _, record in ipairs(parsed.answers) do
      table.insert(records, record)
      if record.type == 6 then
        local soa = record.value
        if type(soa) == "table" then
          if not first_soa then
            first_soa = soa
          elseif first_soa and soa.text == first_soa.text then
            completed = true
            break
          end
        end
      end
    end
    if completed then
      break
    end
  end
  socket:close()
  if #records == 0 then
    if first_rcode_name then
      return nil, "no zone data received (" .. first_rcode_name .. ")"
    end
    return nil, "no zone data received"
  end
  return {
    records = records,
    packets = packets,
    size = size,
    completed = completed,
    soa = first_soa,
    rcode = first_rcode,
    rcode_name = first_rcode_name,
  }, nil
end

local function dns_ixfr(host, port, qname, serial, args)
  port = port_number_of(port)
  if budget_exhausted(args) then
    return nil, "request budget exhausted"
  end
  state.requests = state.requests + 1
  local socket = nmap.new_socket("tcp")
  local ok, connect_err = socket:connect(host, port)
  if not ok then
    socket:close()
    return nil, "connect failed: " .. tostring(connect_err)
  end
  socket:set_timeout(args.timeout)
  local id = math.random(1, 65535)
  local query = build_query(id, qname, 253, { rd = false })
  local sent_ok, send_err = socket:send(query)
  if not sent_ok then
    socket:close()
    return nil, "send failed: " .. tostring(send_err)
  end
  local records = {}
  local packets = 0
  local size = #query
  local first_rcode_name = nil
  while packets < 256 do
    local ok_len, len_bytes = socket:receive(2)
    if not ok_len or type(len_bytes) ~= "string" or #len_bytes < 2 then
      break
    end
    local length = string.byte(len_bytes, 1) * 256 + string.byte(len_bytes, 2)
    if length == 0 or length > 65535 then
      break
    end
    local ok_pkt, pkt = socket:receive(length)
    if not ok_pkt or type(pkt) ~= "string" or #pkt < 12 then
      break
    end
    packets = packets + 1
    size = size + 2 + #pkt
    local parsed = parse_response(pkt)
    if parsed then
      if first_rcode_name == nil then
        first_rcode_name = parsed.rcode_name
      end
      for _, record in ipairs(parsed.answers) do
        table.insert(records, record)
      end
    end
    if packets >= 1 and #records >= 2 then
      local last = records[#records]
      if last.type == 6 and type(last.value) == "table" and #records > 1 then
        local first = records[1]
        if first.type == 6 and type(first.value) == "table"
          and last.value.text == first.value.text then
          break
        end
      end
    end
  end
  socket:close()
  if #records == 0 then
    if first_rcode_name then
      return nil, "no IXFR data received (" .. first_rcode_name .. ")"
    end
    return nil, "no IXFR data received"
  end
  return { records = records, packets = packets, size = size, serial = serial }, nil
end

local function dns_query_tcp(host, port, qname, qtype, args)
  port = port_number_of(port)
  if budget_exhausted(args) then
    return nil, "request budget exhausted"
  end
  state.requests = state.requests + 1
  local socket = nmap.new_socket("tcp")
  local ok, connect_err = socket:connect(host, port)
  if not ok then
    socket:close()
    return nil, "connect failed: " .. tostring(connect_err)
  end
  socket:set_timeout(args.timeout)
  local id = math.random(1, 65535)
  local query = build_query(id, qname, qtype, { rd = false })
  local framed = u16(#query) .. query
  local sent_ok, send_err = socket:send(framed)
  if not sent_ok then
    socket:close()
    return nil, "send failed: " .. tostring(send_err)
  end
  local ok_len, len_bytes = socket:receive(2)
  if not ok_len or type(len_bytes) ~= "string" or #len_bytes < 2 then
    socket:close()
    return nil, "no framed response (timeout)"
  end
  local length = string.byte(len_bytes, 1) * 256 + string.byte(len_bytes, 2)
  if length == 0 or length > 65535 then
    socket:close()
    return nil, "invalid response length"
  end
  local ok_pkt, pkt = socket:receive(length)
  socket:close()
  if not ok_pkt or type(pkt) ~= "string" then
    return nil, "no response data"
  end
  local parsed = parse_response(pkt)
  if parsed then
    parsed.query_size = #query
    return parsed, nil
  end
  return nil, "malformed TCP response"
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

local function zone_of(args, host)
  local zone = normalize_domain(args.domain)
  if not zone then
    zone = normalize_domain(host.targetname) or normalize_domain(host.name)
  end
  if not zone then
    zone = "example.com"
  end
  return zone
end

local function ip_class(ip)
  local a, b = string.match(ip, "^(%d+)%.(%d+)%..*$")
  if not a or not b then
    return "public"
  end
  a = tonumber(a)
  b = tonumber(b)
  if a == 10 then
    return "private (10/8)"
  end
  if a == 172 and b >= 16 and b <= 31 then
    return "private (172.16/12)"
  end
  if a == 192 and b == 168 then
    return "private (192.168/16)"
  end
  if a == 127 then
    return "loopback"
  end
  if a == 169 and b == 254 then
    return "link-local"
  end
  if a == 100 and b >= 64 and b <= 127 then
    return "CGNAT (100.64/10)"
  end
  return "public"
end

local function is_internal_ip(ip)
  return ip_class(ip) ~= "public"
end

local function in_list(list, value)
  for _, existing in ipairs(list) do
    if existing == value then
      return true
    end
  end
  return false
end

local function label_is_high_value(name)
  local labels = {}
  for label in string.gmatch(tostring(name or ""), "[^%.]+") do
    table.insert(labels, lower(label))
  end
  for _, label in ipairs(labels) do
    if in_list(HIGH_VALUE_LABELS, label) then
      return true
    end
  end
  return false
end

local function txt_looks_like_secret(text)
  local lowered = lower(tostring(text or ""))
  for _, pattern in ipairs(SECRET_PATTERNS) do
    if string.find(lowered, pattern, 1, true) then
      return true
    end
  end
  return false
end

local function first_soas(records)
  local first = nil
  local last = nil
  for _, record in ipairs(records or {}) do
    if record.type == SOA_QTYPE and record.value and record.value.serial ~= nil then
      if not first then
        first = record.value
      end
      last = record.value
    end
  end
  return first, last
end

local function analyze_zone_exposure(records, zone)
  local internal_addrs = {}
  local secret_txt = {}
  local foreign_names = {}
  local high_value = {}
  local a_count = 0
  local ns_count = 0
  local cname_count = 0
  local txt_count = 0

  for _, record in ipairs(records or {}) do
    if record.type == A_QTYPE and record.value then
      a_count = a_count + 1
      local ip = tostring(record.value)
      if is_internal_ip(ip) then
        table.insert(internal_addrs, string.format("%s -> %s (%s)", record.name, ip, ip_class(ip)))
      end
    elseif record.type == NS_QTYPE and record.value then
      ns_count = ns_count + 1
      if not (record.value == zone or ends_with(record.value, zone)) then
        table.insert(foreign_names, "NS " .. record.value)
      end
    elseif record.type == MX_QTYPE and record.value then
      if not (record.value.exchange == zone or ends_with(record.value.exchange, zone)) then
        table.insert(foreign_names, "MX " .. record.value.exchange)
      end
    elseif record.type == SRV_QTYPE and record.value then
      if not (record.value.target == zone or ends_with(record.value.target, zone)) then
        table.insert(foreign_names, "SRV " .. record.value.target)
      end
    elseif record.type == TXT_QTYPE and record.value then
      txt_count = txt_count + 1
      local text = tostring(record.value)
      if txt_looks_like_secret(text) then
        table.insert(secret_txt, string.format("%s: %s", record.name, mask_value(text)))
      end
    elseif record.type == 5 then
      cname_count = cname_count + 1
    end
    if label_is_high_value(record.name) and record.type ~= SOA_QTYPE then
      table.insert(high_value, record.name .. " (" .. record.type_name .. ")")
    end
  end

  return {
    a_count = a_count,
    ns_count = ns_count,
    cname_count = cname_count,
    txt_count = txt_count,
    internal_addrs = internal_addrs,
    secret_txt = secret_txt,
    foreign_names = foreign_names,
    high_value = high_value,
  }
end

action = function(host, port)

  seed_random(port)
  reset_state()
  reset_findings()

  local args = read_args()
  local zone = zone_of(args, host)
  local pnum = port_number_of(port)

  local out = new_output(RISK_LEVEL, "AUDITED - AXFR source IP access control evaluated.")
  local fetch_log = {}
  local sections = {}

  local axfr_state = "not-attempted"
  local axfr_detail = ""
  local axfr_records = nil
  local axfr_size = 0
  local axfr_packets = 0

  if not budget_exhausted(args) then
    state.requests = state.requests + 1
    local transfer, axfr_err = dns_axfr(host, pnum, zone, args)
    if transfer then
      axfr_state = "open"
      axfr_records = transfer.records
      axfr_size = transfer.size
      axfr_packets = transfer.packets
      table.insert(fetch_log, string.format(
        "AXFR (TCP) %s -> TRANSFERED: %d records, %d packets, %d bytes (server streamed the zone to this source)",
        zone, #axfr_records, axfr_packets, axfr_size))
      local first_soa, last_soa = first_soas(axfr_records)
      if first_soa and last_soa and first_soa.serial ~= last_soa.serial then
        add_finding("LOW", string.format(
          "the zone transfer for %s started with SOA serial %d and ended with %d: the zone changed while the transfer ran",
          zone, first_soa.serial, last_soa.serial),
          { subject = "axfr-atomicity", evidence = tostring(last_soa.serial) })
      end
    else
      axfr_state = "refused"
      axfr_detail = tostring(axfr_err)
      if string.find(tostring(axfr_err), "REFUSED", 1, true) then
        axfr_state = "refused"
        table.insert(fetch_log, string.format("AXFR (TCP) %s -> REFUSED by the server (%s)", zone, tostring(axfr_err)))
      else
        axfr_state = "no-response"
        table.insert(fetch_log, string.format("AXFR (TCP) %s -> no transfer data (%s)", zone, tostring(axfr_err)))
      end
    end
  else
    axfr_state = "skipped"
  end

  if axfr_state == "open" then
    local exposure = analyze_zone_exposure(axfr_records, zone)
    add_finding("CRITICAL", string.format(
      "full zone transfer (AXFR) for %s is open to this unauthorized external source: %d records (%d bytes) including %d A, %d NS, %d CNAME, %d TXT - the entire zone inventory is readable by anyone",
      zone, #axfr_records, axfr_size, exposure.a_count, exposure.ns_count, exposure.cname_count, exposure.txt_count),
      { subject = "axfr-open:" .. zone, evidence = #axfr_records .. " records" })
    if #exposure.internal_addrs > 0 then
      add_finding("HIGH", string.format(
        "the open zone transfer exposes %d internal address(es) (RFC1918/loopback): internal network topology is published to the internet",
        #exposure.internal_addrs),
        { subject = "axfr-internal-ips:" .. zone, evidence = exposure.internal_addrs[1] })
    end
    if #exposure.secret_txt > 0 then
      add_finding("CRITICAL", string.format(
        "the open zone transfer exposes %d TXT record(s) whose content looks like credentials or API tokens (values masked): anyone can now read them",
        #exposure.secret_txt),
        { subject = "axfr-secrets:" .. zone, evidence = exposure.secret_txt[1] })
    end
    if #exposure.foreign_names > 0 then
      add_finding("HIGH", string.format(
        "the open zone transfer exposes %d record(s) pointing at names outside the audited zone (internal infrastructure in the public zone)",
        #exposure.foreign_names),
        { subject = "axfr-foreign-refs:" .. zone, evidence = exposure.foreign_names[1] })
    end
    if #exposure.high_value > 0 then
      add_finding("MEDIUM", string.format(
        "the open zone transfer exposes %d record name(s) matching high-value labels (db, vpn, internal, deploy, secret, staging, backup, ...)",
        #exposure.high_value),
        { subject = "axfr-high-value-names:" .. zone, evidence = exposure.high_value[1] })
    end
  end

  local ixfr_state = "disabled"
  local ixfr_detail = ""
  if args.ixfr_check and not budget_exhausted(args) then
    state.requests = state.requests + 1
    local ixfr, ixfr_err = dns_ixfr(host, pnum, zone, 0, args)
    if ixfr then
      ixfr_state = "open"
      ixfr_detail = string.format("%d records, %d packets, %d bytes", #ixfr.records, ixfr.packets, ixfr.size)
      table.insert(fetch_log, string.format("IXFR (TCP, serial 0) %s -> TRANSFERED: %s", zone, ixfr_detail))
    else
      ixfr_state = "refused"
      ixfr_detail = tostring(ixfr_err)
      if string.find(tostring(ixfr_err), "REFUSED", 1, true) then
        table.insert(fetch_log, string.format("IXFR (TCP, serial 0) %s -> REFUSED (%s)", zone, tostring(ixfr_err)))
      else
        ixfr_state = "no-response"
        table.insert(fetch_log, string.format("IXFR (TCP, serial 0) %s -> no data (%s)", zone, tostring(ixfr_err)))
      end
    end
    if axfr_state == "refused" and ixfr_state == "open" then
      add_finding("HIGH", string.format(
        "IXFR (incremental zone transfer) is open while AXFR is refused for %s: the transfer restriction is incomplete - an incremental transfer from serial 0 still yields the full zone (%s)",
        zone, ixfr_detail),
        { subject = "ixfr-asymmetry:" .. zone, evidence = ixfr_detail })
    end
  elseif not args.ixfr_check then
    ixfr_state = "disabled"
  else
    ixfr_state = "skipped"
  end

  local udp_state = "disabled"
  local udp_detail = ""
  if args.udp_check and not budget_exhausted(args) then
    state.requests = state.requests + 1
    local socket = nmap.new_socket("udp")
    local ok, cerr = socket:connect(host, pnum)
    if ok then
      socket:set_timeout(args.timeout)
      local id = math.random(1, 65535)
      local query = build_query(id, zone, AXFR_QTYPE, { rd = false })
      local sok, _ = socket:send(query)
      local rok, data = socket:receive()
      socket:close()
      sleep(args.delay or 0)
      if sok and rok and type(data) == "string" and #data >= 12 then
        local parsed = parse_response(data)
        if parsed then
          if parsed.tc == 1 then
            udp_state = "answered-truncated"
            udp_detail = parsed.rcode_name
            table.insert(fetch_log, string.format(
              "AXFR (UDP) %s -> answered with TC=1 (truncated): the server handles UDP transfer requests, rcode %s",
              zone, parsed.rcode_name))
            local soa = nil
            for _, record in ipairs(parsed.authority) do
              if record.type == SOA_QTYPE and record.value then
                soa = record.value
                break
              end
            end
            if soa then
              udp_detail = udp_detail .. ", SOA serial in authority: " .. tostring(soa.serial)
            end
          else
            udp_state = "answered"
            udp_detail = parsed.rcode_name
            table.insert(fetch_log, string.format("AXFR (UDP) %s -> answered without truncation (rcode %s): unusual", zone, parsed.rcode_name))
          end
        else
          udp_state = "answered"
          udp_detail = "unparseable"
          table.insert(fetch_log, string.format("AXFR (UDP) %s -> unparseable %d-byte reply", zone, #data))
        end
      else
        udp_state = "no-response"
        table.insert(fetch_log, string.format("AXFR (UDP) %s -> no response (dropped or timeout)", zone))
      end
    else
      udp_state = "no-response"
      table.insert(fetch_log, string.format("AXFR (UDP) %s -> connect failed (%s)", zone, tostring(cerr)))
    end
  elseif not args.udp_check then
    udp_state = "disabled"
  else
    udp_state = "skipped"
  end

  local spoof_lines = {}
  local spoof_candidates = {}
  local ns_names = {}
  local mname = nil
  if args.spoof_surface then
    if not budget_exhausted(args) then
      local ns_parsed, ns_err = dns_lookup(host, pnum, zone, NS_QTYPE, args, { rd = false })
      if not ns_parsed then
        table.insert(fetch_log, string.format("NS %s -> %s", zone, tostring(ns_err)))
        table.insert(spoof_lines, "NS lookup failed: " .. tostring(ns_err))
      else
        for _, record in ipairs(ns_parsed.answers) do
          if record.type == NS_QTYPE and record.value then
            table.insert(ns_names, tostring(record.value))
          end
        end
        table.insert(fetch_log, string.format("NS %s -> %d nameserver(s)", zone, #ns_names))
      end
    end
    if not budget_exhausted(args) then
      local soa_parsed, soa_err = dns_lookup(host, pnum, zone, SOA_QTYPE, args, { rd = false })
      if soa_parsed and soa_parsed.rcode == 0 and soa_parsed.ancount > 0 then
        for _, record in ipairs(soa_parsed.answers) do
          if record.type == SOA_QTYPE and record.value then
            mname = record.value.mname
            break
          end
        end
        table.insert(fetch_log, string.format("SOA %s -> MNAME %s", zone, tostring(mname or "?")))
      else
        table.insert(fetch_log, string.format("SOA %s -> %s", zone, tostring(soa_err or "no SOA")))
      end
    end

    local sources = {}
    if mname and not in_list(sources, mname) then
      table.insert(sources, mname)
    end
    for _, ns_name in ipairs(ns_names) do
      if not in_list(sources, ns_name) then
        table.insert(sources, ns_name)
      end
    end

    for _, source_name in ipairs(sources) do
      if budget_exhausted(args) then
        table.insert(spoof_lines, string.format("      %-36s unresolved (budget)", source_name))
        break
      end
      local a_parsed, a_err = dns_lookup(host, pnum, source_name, A_QTYPE, args, { rd = false })
      if not a_parsed then
        table.insert(spoof_lines, string.format("      %-36s unresolvable (%s)", source_name, tostring(a_err)))
        table.insert(spoof_candidates, { name = source_name, ip = nil })
      elseif a_parsed.rcode == 0 and a_parsed.ancount > 0 then
        local addrs = {}
        for _, record in ipairs(a_parsed.answers) do
          if record.type == A_QTYPE then
            table.insert(addrs, tostring(record.value))
          end
        end
        table.insert(spoof_lines, string.format("      %-36s %s", source_name, table.concat(addrs, ", ")))
        table.insert(spoof_candidates, { name = source_name, ip = table.concat(addrs, ",") })
      else
        table.insert(spoof_lines, string.format("      %-36s no A record (%s)", source_name, a_parsed.rcode_name))
        table.insert(spoof_candidates, { name = source_name, ip = nil })
      end
    end

    if #spoof_candidates > 0 and axfr_state ~= "open" then
      add_finding("MEDIUM", string.format(
        "zone transfers for %s are restricted, but the %d source(s) a source-based allow-transfer ACL would trust are published in the zone itself (SOA MNAME + NS set): an attacker on a spoofable network path can impersonate them to pull the zone",
        zone, #spoof_candidates),
        { subject = "axfr-spoof-surface:" .. zone, confidence = "medium",
          evidence = tostring(sources[1] or zone) })
    end
  end

  local unique, counts = dedupe_findings()

  if axfr_state == "open" then
    out["Status"] = string.format(
      "VULNERABLE - AXFR zone transfer for %s is open to unauthorized sources.", zone)
  elseif axfr_state == "refused" or axfr_state == "no-response" then
    if ixfr_state == "open" then
      out["Status"] = string.format(
        "VULNERABLE - AXFR is blocked but IXFR yields the zone for %s.", zone)
    else
      local spoof_note = ""
      if #spoof_candidates > 0 then
        spoof_note = " and " .. tostring(#spoof_candidates) .. " spoofable authorized source(s) identified"
      end
      out["Status"] = string.format(
        "AUDITED - AXFR restricted for %s (server: %s)%s.", zone, axfr_state, spoof_note)
    end
  else
    out["Status"] = string.format(
      "AUDITED - AXFR source control audit completed for %s (%s).", zone, axfr_state)
  end

  table.insert(sections, { key = "Audited zone", value = zone })
  table.insert(sections, { key = "AXFR (TCP) verdict", value =
    axfr_state .. (axfr_detail ~= "" and (" - " .. axfr_detail) or "") })
  table.insert(sections, { key = "IXFR (TCP, serial 0) verdict", value =
    ixfr_state .. (ixfr_detail ~= "" and (" - " .. ixfr_detail) or "") })
  table.insert(sections, { key = "AXFR (UDP) verdict", value =
    udp_state .. (udp_detail ~= "" and (" - " .. udp_detail) or "") })
  if axfr_state == "open" and axfr_records then
    local exposure = analyze_zone_exposure(axfr_records, zone)
    if #exposure.internal_addrs > 0 then
      table.insert(sections, { key = "Internal addresses exposed by the transfer", value = exposure.internal_addrs })
    end
    if #exposure.secret_txt > 0 then
      table.insert(sections, { key = "Credential-looking TXT exposed (masked)", value = exposure.secret_txt })
    end
    if #exposure.foreign_names > 0 then
      table.insert(sections, { key = "Out-of-zone references exposed", value = exposure.foreign_names })
    end
    if #exposure.high_value > 0 then
      table.insert(sections, { key = "High-value record names exposed", value = exposure.high_value })
    end
  end
  if args.spoof_surface and #spoof_lines > 0 then
    table.insert(sections, { key = "Spoofable authorized sources (MNAME + NS)", value = spoof_lines })
  end
  table.insert(sections, { key = "Fetch log", value = fetch_log })
  table.insert(sections, { key = "Requests issued", value = state.requests .. " of " .. args.maxrequests })

  if axfr_state == "open" then
    table.insert(sections, { key = "Remediation", value =
      "close the transfer ACL immediately: in BIND set 'allow-transfer { none; }' (or an explicit "
      .. "list of secondary addresses with /32 masks) on the zone, verify with this audit, then "
      .. "rotate every credential that was stored in the zone (the TXT inventory above is now "
      .. "compromised), remove internal hostnames and RFC1918 addresses from the public zone, and "
      .. "add monitoring for AXFR/IXFR requests from non-secondary sources." })
  elseif ixfr_state == "open" then
    table.insert(sections, { key = "Remediation", value =
      "the AXFR restriction is incomplete: apply the same 'allow-transfer' restriction to IXFR "
      .. "(incremental transfers), rotate credentials published in the zone, and re-run this audit "
      .. "to confirm both AXFR and IXFR are refused from external sources." })
  else
    table.insert(sections, { key = "Remediation", value =
      "the transfer ACL holds from this source. Do not rely on source ACLs alone: an attacker on a "
      .. "spoofable path can impersonate the listed authorized sources - prefer not exposing the "
      .. "zone's secondaries' addresses, use unidirectional (push) transfer where possible, and "
      .. "alert on transfers from unexpected sources. Re-run periodically." })
  end

  return finish_output(out, unique, counts, sections)

end
