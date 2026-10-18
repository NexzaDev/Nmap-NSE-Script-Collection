local shortport = require "shortport"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Tests whether the target DNS resolver leaks its cache contents to any
client - a cache snooping information disclosure. The resolver's cache
remembers the names other clients looked up; if the resolver answers
a *non-recursive* (RD=0) query for a name it is not authoritative for,
the only place a positive answer can come from is its own cache. In
other words: the query is a probe that succeeds exactly when someone
else recently asked the resolver for that same name.

Why it matters
Shared resolvers (office DNS, carrier resolvers, public Wi-Fi, VPN
gateways) are snooping magnets. An attacker on the same resolver can
fingerprint what domains other users visited, correlate browsing
sessions, and infer which subdomains are in active use. On internal
resolvers the leak is even worse: non-recursive queries for internal
hostnames confirm the existence of internal services.

What the script does
1. Round 1 - cache probes: for each probe domain (a built-in list of
   widely-used public names, overridable via dns-cache-snooping.probes)
   it sends a NON-recursive A query (RD=0). A NOERROR response with at
   least one answer can only be a cached answer for an out-of-zone
   name, so each such hit is a snooping disclosure and becomes a
   MEDIUM finding. NXDOMAIN/NXRRSET means "not cached" (no leak),
   REFUSED means the resolver actively rejects non-recursive out-of-zone
   queries (an anti-snoop control), and NOERROR-without-answer is
   recorded as ambiguous.
2. Round 2 - TTL freshness: every domain that returned a cached answer
   is re-queried (non-recursive) and the TTLs are compared. A TTL that
   decreased between the two queries proves the cache entry is live and
   being refreshed by recent lookups - stronger evidence that the leak
   tracks current browsing, not stale history. Entries that vanish
   between rounds are noted as "expired".
3. Round 3 - apex control: the zone's own apex A record is queried
   twice (non-recursive) as a control. A stable TTL means the server
   answers its own zone authoritatively; a decreasing apex TTL on a
   server that is not the zone's authority is another cache channel.
4. Round 4 - EDNS variant: one cached probe is repeated with an EDNS0
   OPT record attached. Some resolvers keep separate caches or answer
   EDNS queries differently, so a divergence is recorded as an extra
   (narrower) snooping channel.
5. Scoring: 3 or more cached probe domains = VULNERABLE hot cache,
   1-2 = possible snooping, 0 = no evidence. Two or more TTL
   decrements add an actively-refreshed-cache finding. Refusals are
   reported as positive anti-snoop controls.

Every probe is a single small, legitimate DNS query with RD=0. The
script performs at most a few dozen requests and never sends queries
at volume or with hostile intent.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "discovery", "vuln"}

portrule = shortport.port_or_service(53, "domain", {"udp", "tcp"})

local SCRIPT_NAME = "dns-cache-snooping"

local RISK_LEVEL = "🟡 MEDIUM"

local A_QTYPE = 1
local SNOOP_HOT_CACHE = 3
local FRESH_EVIDENCE_MIN = 2

local DEFAULT_PROBES = {
  "google.com", "facebook.com", "youtube.com", "amazon.com",
  "microsoft.com", "apple.com", "netflix.com", "instagram.com",
  "twitter.com", "linkedin.com", "wikipedia.org", "paypal.com",
  "github.com", "dropbox.com", "zoom.us", "slack.com",
  "salesforce.com", "office.com", "gmail.com", "whatsapp.com",
  "cloudflare.com", "example.org", "example.net", "example.edu",
}

local DEFAULT_ARGS = {
  domain = nil,
  probes = nil,
  maxrequests = 64,
  retries = 0,
  timeout = 10000,
  delay = 0.05,
  freshness = 1,
  include_apex = true,
}

local NUMERIC_ARGS = {
  { key = "maxrequests", minimum = 8, integer = true },
  { key = "retries", minimum = 0, integer = true },
  { key = "timeout", minimum = 500, integer = true },
  { key = "freshness", minimum = 0, maximum = 3, integer = true },
}

local BOOLEAN_ARGS = { "include_apex" }

local STRING_ARGS = { "domain", "probes" }

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
    tc = math.floor(hi / 8) % 2,
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
    return nil, "no zone data received"
  end
  return {
    records = records,
    packets = packets,
    size = size,
    completed = completed,
    soa = first_soa,
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

local function is_listed(list, value)
  for _, existing in ipairs(list) do
    if existing == value then
      return true
    end
  end
  return false
end

local function probes_from_args(args)
  if args.probes and #trim(args.probes) > 0 then
    local list = {}
    for candidate in string.gmatch(trim(args.probes), "%S+") do
      local normalized = normalize_domain(candidate)
      if normalized and #normalized >= 3 and not is_listed(list, normalized) then
        table.insert(list, normalized)
      end
    end
    if #list > 0 then
      return list
    end
  end
  return DEFAULT_PROBES
end

local function first_a_record(parsed)
  for _, record in ipairs(parsed.answers) do
    if record.type == A_QTYPE then
      return record
    end
  end
  return nil
end

local function classify_probe(parsed)
  if parsed.rcode == 0 and parsed.ancount > 0 then
    return "cached"
  end
  if parsed.rcode == 3 then
    return "nxdomain"
  end
  if parsed.rcode == 5 then
    return "refused"
  end
  if parsed.rcode == 8 then
    return "nxrrset"
  end
  if parsed.rcode == 0 then
    return "no-answer"
  end
  return "other"
end

local function run_cache_probe(host, pnum, name, args)
  local parsed, err = dns_lookup(host, pnum, name, A_QTYPE, args, { rd = false })
  if not parsed then
    return { name = name, state = "error", detail = err }
  end
  local result = {
    name = name,
    state = classify_probe(parsed),
    rcode = parsed.rcode,
    rcode_name = parsed.rcode_name,
    aa = parsed.aa == 1,
    ra = parsed.ra == 1,
    ancount = parsed.ancount,
    response_size = parsed.size,
  }
  if result.state == "cached" then
    local a = first_a_record(parsed)
    if a then
      result.answer = a.value
      result.ttl = a.ttl
    else
      result.answer = qtype_name(parsed.answers[1].type) .. " record"
      result.ttl = parsed.answers[1].ttl
    end
  end
  return result
end

local function freshness_probe(host, pnum, name, first_ttl, args)
  local parsed, err = dns_lookup(host, pnum, name, A_QTYPE, args, { rd = false })
  if not parsed then
    return { name = name, state = "error", detail = err, first_ttl = first_ttl }
  end
  if parsed.rcode ~= 0 or parsed.ancount == 0 then
    return {
      name = name, state = "expired",
      rcode_name = parsed.rcode_name, first_ttl = first_ttl,
    }
  end
  local a = first_a_record(parsed) or parsed.answers[1]
  local second_ttl = a and a.ttl or 0
  local state = "stable"
  if second_ttl < first_ttl then
    state = "decreased"
  elseif second_ttl > first_ttl then
    state = "increased"
  end
  return {
    name = name, state = state,
    first_ttl = first_ttl, second_ttl = second_ttl,
  }
end

local function apex_zone(args, host)
  local zone = normalize_domain(args.domain)
  if not zone then
    zone = normalize_domain(host.targetname) or normalize_domain(host.name)
      or normalize_domain(host.ip)
  end
  if not zone then
    zone = "example.com"
  end
  return zone
end

action = function(host, port)

  seed_random(port)
  reset_state()
  reset_findings()

  local args = read_args()
  local zone = apex_zone(args, host)
  local pnum = port_number_of(port)
  local probes = probes_from_args(args)

  local out = new_output(RISK_LEVEL, "AUDITED - DNS cache snooping audit completed.")
  local fetch_log = {}
  local sections = {}
  local round1 = {}
  local cached_count = 0
  local refused_count = 0
  local nxdomain_count = 0
  local noanswer_count = 0
  local error_count = 0

  for _, probe_name in ipairs(probes) do
    if budget_exhausted(args) then
      table.insert(fetch_log, string.format("%s -> skipped (request budget exhausted)", probe_name))
      break
    end
    local result = run_cache_probe(host, pnum, probe_name, args)
    table.insert(round1, result)
    if result.state == "cached" then
      cached_count = cached_count + 1
      add_finding("MEDIUM", string.format(
        "cache snooping: %s answered a NON-recursive query (RD=0) - the answer can only come from the resolver's cache, so this domain was recently resolved by another client",
        result.name),
        { subject = "cache-snoop:" .. result.name,
          evidence = "TTL " .. tostring(result.ttl or "?") })
      if result.aa then
        add_finding("MEDIUM", string.format(
          "%s: authoritative (AA) flag set on a non-recursive answer for an out-of-zone name - misconfigured or rogue upstream in the resolver chain",
          result.name),
          { subject = "cache-snoop-aa:" .. result.name, confidence = "medium" })
      end
      table.insert(fetch_log, string.format(
        "%s -> CACHED (NOERROR, %d answers, TTL %s, answer %s) - snooping hit",
        result.name, result.ancount, tostring(result.ttl or "?"), tostring(result.answer or "?")))
    elseif result.state == "refused" then
      refused_count = refused_count + 1
      table.insert(fetch_log, string.format(
        "%s -> REFUSED - resolver rejects non-recursive out-of-zone queries (anti-snoop control)",
        result.name))
    elseif result.state == "nxdomain" then
      nxdomain_count = nxdomain_count + 1
      table.insert(fetch_log, string.format(
        "%s -> NXDOMAIN - not present in cache (no leak for this name)", result.name))
    elseif result.state == "nxrrset" then
      nxdomain_count = nxdomain_count + 1
      table.insert(fetch_log, string.format(
        "%s -> NXRRSET - name exists, RRset empty: not served from cache", result.name))
    elseif result.state == "no-answer" then
      noanswer_count = noanswer_count + 1
      table.insert(fetch_log, string.format(
        "%s -> NOERROR with no answers - ambiguous (cache disabled or answer suppressed)", result.name))
    elseif result.state == "error" then
      error_count = error_count + 1
      table.insert(fetch_log, string.format("%s -> %s (%s)", result.name, result.state,
        tostring(result.detail)))
    else
      table.insert(fetch_log, string.format(
        "%s -> %s (rcode %s) - not a cache hit", result.name, result.state,
        result.rcode_name or "?"))
    end
  end

  local fresh_lines = {}
  local decrements = 0
  local expired_count = 0
  if args.freshness and args.freshness > 0 then
    for _, result in ipairs(round1) do
      if result.state == "cached" and result.ttl and result.ttl > 0 then
        if budget_exhausted(args) then
          table.insert(fetch_log, string.format("%s -> freshness skipped (budget exhausted)", result.name))
          break
        end
        local fresh = freshness_probe(host, pnum, result.name, result.ttl, args)
        if fresh.state == "decreased" then
          decrements = decrements + 1
          table.insert(fresh_lines, string.format(
            "      %-28s TTL %d -> %d (decreased: live, recently refreshed cache entry)",
            fresh.name, fresh.first_ttl, fresh.second_ttl))
          table.insert(fetch_log, string.format(
            "%s -> re-query TTL %d -> %d (decreased between rounds: entry is hot)",
            fresh.name, fresh.first_ttl, fresh.second_ttl))
        elseif fresh.state == "increased" then
          table.insert(fresh_lines, string.format(
            "      %-28s TTL %d -> %d (increased: re-primed from upstream or authoritative refresh)",
            fresh.name, fresh.first_ttl, fresh.second_ttl))
          table.insert(fetch_log, string.format(
            "%s -> re-query TTL %d -> %d (increased: record re-primed)",
            fresh.name, fresh.first_ttl, fresh.second_ttl))
        elseif fresh.state == "expired" then
          expired_count = expired_count + 1
          table.insert(fresh_lines, string.format(
            "      %-28s TTL %d -> gone (%s between rounds)",
            fresh.name, fresh.first_ttl, fresh.rcode_name or "no answer"))
          table.insert(fetch_log, string.format(
            "%s -> re-query returned %s: cache entry expired or evicted",
            fresh.name, fresh.rcode_name or "no answer"))
        elseif fresh.state == "error" then
          table.insert(fresh_lines, string.format("      %-28s %s (%s)", fresh.name,
            fresh.state, tostring(fresh.detail)))
          table.insert(fetch_log, string.format("%s -> freshness probe error: %s",
            fresh.name, tostring(fresh.detail)))
        else
          table.insert(fresh_lines, string.format(
            "      %-28s TTL %d -> %d (stable: age of entry unknown without clock correlation)",
            fresh.name, fresh.first_ttl, fresh.second_ttl))
          table.insert(fetch_log, string.format(
            "%s -> re-query TTL %d -> %d (stable)", fresh.name, fresh.first_ttl, fresh.second_ttl))
        end
      end
    end
  end

  local apex_lines = {}
  local apex_result = "skipped"
  if args.include_apex and not budget_exhausted(args) then
    local first, err1 = dns_lookup(host, pnum, zone, A_QTYPE, args, { rd = false })
    local second = nil
    if first then
      local a = first_a_record(first)
      if a then
        if budget_exhausted(args) then
          apex_result = "budget"
        else
          second, _ = dns_lookup(host, pnum, zone, A_QTYPE, args, { rd = false })
        end
      end
    end
    if first and first.rcode == 0 and first.ancount > 0 then
      local a = first_a_record(first)
      local ttl1 = a and a.ttl or 0
      if second and second.rcode == 0 and second.ancount > 0 then
        local b = first_a_record(second) or second.answers[1]
        local ttl2 = b and b.ttl or 0
        if ttl2 < ttl1 then
          apex_result = "decreasing"
          table.insert(apex_lines, string.format("      %s TTL %d -> %d (decreasing between queries)", zone, ttl1, ttl2))
          table.insert(fetch_log, string.format("apex %s -> non-recursive A TTL %d -> %d (decreasing)", zone, ttl1, ttl2))
        else
          apex_result = "stable"
          table.insert(apex_lines, string.format("      %s TTL %d -> %d (stable: authoritative for own zone, no apex cache channel)", zone, ttl1, ttl2))
          table.insert(fetch_log, string.format("apex %s -> non-recursive A answered, stable TTL %d (own zone, no cache evidence)", zone, ttl1))
        end
      else
        apex_result = "no-recheck"
        table.insert(apex_lines, string.format("      %s TTL %d (re-check unavailable)", zone, ttl1))
      end
    elseif first then
      apex_result = first.rcode_name
      table.insert(apex_lines, string.format("      %s -> %s (apex not answerable non-recursively)", zone, first.rcode_name))
    else
      apex_result = "error"
      table.insert(apex_lines, string.format("      %s -> %s", zone, tostring(err1)))
    end
  elseif not args.include_apex then
    apex_result = "disabled"
  end

  local edns_note = "not run (no cached probe available)"
  for _, result in ipairs(round1) do
    if result.state == "cached" and not budget_exhausted(args) then
      local parsed, err = dns_lookup(host, pnum, result.name, A_QTYPE, args,
        { rd = false, edns = true })
      if parsed then
        local edns_state = classify_probe(parsed)
        if edns_state == "cached" then
          edns_note = string.format("%s: EDNS0 non-recursive query also served from cache (same leak channel, %d answers)",
            result.name, parsed.ancount)
          table.insert(fetch_log, string.format(
            "%s -> EDNS0 non-recursive re-query: cached (%d answers) - leak channel also open with EDNS",
            result.name, parsed.ancount))
        else
          edns_note = string.format("%s: EDNS0 variant returned %s (EDNS queries not cached the same way)",
            result.name, edns_state)
          table.insert(fetch_log, string.format(
            "%s -> EDNS0 non-recursive re-query: %s (EDNS channel differs)", result.name, edns_state))
        end
      else
        edns_note = string.format("%s: EDNS0 probe failed (%s)", result.name, tostring(err))
        table.insert(fetch_log, string.format("%s -> EDNS0 probe: %s", result.name, tostring(err)))
      end
      break
    end
  end

  if decrements >= FRESH_EVIDENCE_MIN then
    local sev = "MEDIUM"
    if cached_count >= SNOOP_HOT_CACHE then
      sev = "HIGH"
    end
    add_finding(sev, string.format(
      "actively refreshed cache: %d of %d cached probe domains showed a TTL decrease on re-query, so the cache is tracking CURRENT browsing, not stale history - snooping reveals what other clients are resolving right now",
      decrements, cached_count),
      { subject = "cache-snoop-freshness", evidence = decrements .. " TTL decreases" })
  end

  local unique, counts = dedupe_findings()

  if cached_count >= SNOOP_HOT_CACHE then
    out["Status"] = string.format(
      "VULNERABLE - cache snooping confirmed (%d of %d probe domains served from the resolver cache).",
      cached_count, #round1)
  elseif cached_count >= 1 then
    out["Status"] = string.format(
      "AUDITED - cache snooping possible (%d of %d probe domains served from the resolver cache).",
      cached_count, #round1)
  else
    out["Status"] = string.format(
      "AUDITED - no cache snooping evidence (%d of %d probe domains served from the resolver cache).",
      cached_count, #round1)
  end

  local cached_list = {}
  for _, result in ipairs(round1) do
    if result.state == "cached" then
      table.insert(cached_list, string.format("%s (TTL %s, %s)", result.name,
        tostring(result.ttl or "?"), tostring(result.answer or "?")))
    end
  end

  local per_domain = {}
  for _, result in ipairs(round1) do
    if result.state == "cached" then
      table.insert(per_domain, string.format("      %-28s %-10s TTL %s (answer %s)",
        result.name, result.state, tostring(result.ttl or "?"), tostring(result.answer or "?")))
    else
      table.insert(per_domain, string.format("      %-28s %-10s %s",
        result.name, result.state,
        result.rcode_name or tostring(result.detail or "?")))
    end
  end

  table.insert(sections, { key = "Probe domain count", value = tostring(#probes) })
  table.insert(sections, { key = "Cached hits (snooping disclosures)", value =
    (#cached_list > 0 and cached_list or { "none of the tested domains were served from cache" }) })
  if #fresh_lines > 0 then
    table.insert(sections, { key = "TTL freshness (round 2)", value = fresh_lines })
  end
  if #apex_lines > 0 then
    table.insert(sections, { key = "Apex control (round 3)", value = apex_lines })
  end
  table.insert(sections, { key = "EDNS0 variant (round 4)", value = edns_note })
  table.insert(sections, { key = "Per-domain results (round 1)", value = per_domain })
  table.insert(sections, { key = "Fetch log", value = fetch_log })
  table.insert(sections, { key = "Requests issued", value =
    state.requests .. " of " .. args.maxrequests })

  if cached_count >= SNOOP_HOT_CACHE then
    table.insert(sections, { key = "Remediation", value =
      "block or rate-limit non-recursive (RD=0) queries for names the resolver is not authoritative for "
      .. "(bind: view-based recursion policy, or 'deny-query' style ACLs; unbound: 'local-zone' 'local-data' "
      .. "controls plus per-client private views), enable response rate limiting (RRL), and document that "
      .. "clients sharing this resolver can fingerprint each other's browsing. Re-run this audit with "
      .. "--script-args dns-cache-snooping.probes=<your-internal-names> to confirm internal names are covered." })
  elseif cached_count >= 1 then
    table.insert(sections, { key = "Remediation", value =
      "a small cache leak was observed: restrict non-recursive out-of-zone queries for untrusted clients, "
      .. "consider per-client cache isolation for shared resolvers, and re-run periodically to confirm the "
      .. "leak stays bounded." })
  else
    table.insert(sections, { key = "Remediation", value =
      "no snooping evidence on the tested names; keep non-recursive query restrictions in place (note that a "
      .. "negative result only covers the sampled probes - rerun with targeted "
      .. "dns-cache-snooping.probes= to audit names your users actually resolve)." })
  end

  return finish_output(out, unique, counts, sections)

end
