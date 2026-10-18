local shortport = require "shortport"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Enumerates SRV (Service Location, RFC 2782) records published under a
domain. SRV records advertise the hostnames and ports of the
organisation's services - SIP/VoIP, XMPP, Lync/Teams federation,
autodiscover, LDAP/Active Directory, MySQL/PostgreSQL/Redis/Kafka,
STUN/TURN, gRPC, H.323 and dozens more. They are frequently left in
production even after the service itself moves, and because SRV targets
are real hostnames (often internal ones) the record set is a compact
map of the internal service topology: which products are deployed,
their versions' default ports, and which internal hosts carry them.

Why it matters
- Topology disclosure: an SRV set like
  `_ldap._tcp.dc._msdcs.corp -> dc01.internal:389` tells an attacker
  the AD forest layout. `_mysql._tcp -> db1.internal:3306` marks a
  database host.
- Attack-surface discovery: VoIP (SIP/SIP federation), XMPP, and H.323
  services have long histories of protocol-level vulnerabilities;
  knowing they exist (and on which port) saves the attacker discovery
  time.
- Stale records: SRV records pointing at decommissioned hosts are both
  a maintenance smell and a potential takeover/impersonation hook.

What the script does
1. Probes a battery of ~40 common SRV service names (both _tcp and
   _udp transports) under the target zone.
2. Parses every SRV answer into priority / weight / port / target,
   supporting multiple records per service (load-balanced sets).
3. Classifies each target:
   - same-zone target (informational),
   - internal-looking hostname (.internal, .corp, .lan, .local,
     dc./dcs./msdcs naming) -> MEDIUM finding,
   - well-known sensitive service (LDAP, AD DC, databases, message
     brokers, VoIP, federation) -> product note,
   - target resolves to a private address (optional, budget-capped)
     -> MEDIUM finding.
4. Flags large service inventories (>= 5 distinct services) as a
   topology disclosure, and lists every service for the report.

Read-only SRV (and optional A) lookups only, bounded by maxrequests.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}

portrule = shortport.port_or_service(53, "domain", {"udp", "tcp"})

local SCRIPT_NAME = "dns-srv-enum"

local RISK_LEVEL = "🟡 MEDIUM"

local SRV_SERVICES = {
  { name = "_sip._tcp", product = "SIP/VoIP", sensitive = true },
  { name = "_sipfederation._tcp", product = "SIP federation", sensitive = true },
  { name = "_sip._udp", product = "SIP (UDP)", sensitive = true },
  { name = "_sipfederation._udp", product = "SIP federation (UDP)", sensitive = true },
  { name = "_xmpp._tcp", product = "XMPP", sensitive = false },
  { name = "_xmpp-client._tcp", product = "XMPP client", sensitive = false },
  { name = "_xmpp-server._tcp", product = "XMPP server", sensitive = false },
  { name = "_xmpp-cs._tcp", product = "XMPP component", sensitive = false },
  { name = "_autodiscover._tcp", product = "Microsoft autodiscover", sensitive = false },
  { name = "_ms-3pa._tcp", product = "Lync/Teams 3PA", sensitive = true },
  { name = "_ms-dsc._tcp", product = "Lync/Teams DSC", sensitive = false },
  { name = "_ms-push-http._tcp", product = "Lync/Teams push", sensitive = false },
  { name = "_msexch._tcp", product = "Exchange RPC", sensitive = false },
  { name = "_imap._tcp", product = "IMAP", sensitive = false },
  { name = "_imaps._tcp", product = "IMAPS", sensitive = false },
  { name = "_pop3._tcp", product = "POP3", sensitive = false },
  { name = "_submission._tcp", product = "SMTP submission", sensitive = false },
  { name = "_smtp._tcp", product = "SMTP", sensitive = false },
  { name = "_ldap._tcp", product = "LDAP", sensitive = true },
  { name = "_ldaps._tcp", product = "LDAPS", sensitive = true },
  { name = "_ldap._tcp.dc._msdcs", product = "Active Directory DC", sensitive = true },
  { name = "_gc._tcp.dc._msdcs", product = "AD global catalog", sensitive = true },
  { name = "_kerberos._tcp", product = "Kerberos", sensitive = true },
  { name = "_kerberos._udp", product = "Kerberos (UDP)", sensitive = true },
  { name = "_caldav._tcp", product = "CalDAV", sensitive = false },
  { name = "_carddav._tcp", product = "CardDAV", sensitive = false },
  { name = "_h323cs._tcp", product = "H.323 call signal", sensitive = true },
  { name = "_h323s._tcp", product = "H.323 setup", sensitive = true },
  { name = "_mysql._tcp", product = "MySQL", sensitive = true },
  { name = "_postgresql._tcp", product = "PostgreSQL", sensitive = true },
  { name = "_redis._tcp", product = "Redis", sensitive = true },
  { name = "_kafka._tcp", product = "Kafka", sensitive = true },
  { name = "_amqp._tcp", product = "AMQP broker", sensitive = true },
  { name = "_mqtt._tcp", product = "MQTT", sensitive = false },
  { name = "_grpc._tcp", product = "gRPC", sensitive = false },
  { name = "_stun._udp", product = "STUN", sensitive = false },
  { name = "_turn._udp", product = "TURN", sensitive = false },
  { name = "_dns._udp", product = "DNS (SRV-advertised)", sensitive = false },
}

local INTERNAL_TARGET_PATTERNS = {
  ".internal", ".corp", ".lan", ".local", ".intranet",
  "internal.", "intranet.", "dc.", "dcs.", "msdcs.", "domain.",
}

local PRIVATE_IP_PREFIXES = {
  "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
  "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
  "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
  "169.254.", "127.",
}

local DEFAULT_ARGS = {
  domain = nil,
  maxrequests = 60,
  retries = 0,
  timeout = 10000,
  delay = 0.05,
  resolve = false,
}

local NUMERIC_ARGS = {
  { key = "maxrequests", minimum = 4, integer = true },
  { key = "retries", minimum = 0, integer = true },
  { key = "timeout", minimum = 500, integer = true },
}

local BOOLEAN_ARGS = { "resolve" }

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

local function zone_from_args(host, args)
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

local function is_internal_target(name, zone)
  local lowered = lower(tostring(name or ""))
  if lowered == "" then
    return false, nil
  end
  if lowered == zone or lowered:sub(-(#zone) + 1) == "." .. zone then
    return true, "same zone"
  end
  for _, pattern in ipairs(INTERNAL_TARGET_PATTERNS) do
    if contains(lowered, pattern) then
      return true, pattern
    end
  end
  return false, nil
end

local function is_private_address(ip)
  local lowered = lower(tostring(ip or ""))
  for _, prefix in ipairs(PRIVATE_IP_PREFIXES) do
    if starts_with(lowered, prefix) then
      return true
    end
  end
  return false
end

local function probe_srv(host, port, zone, service, args)
  local name = service.name .. "." .. zone
  local parsed, err = dns_lookup(host, port, name, "SRV", args, { rd = false })
  local result = {
    service = service,
    name = name,
    found = false,
    records = {},
    state = "nxdomain",
  }
  if not parsed then
    result.state = "unreachable"
    result.detail = err
    return result
  end
  if parsed.rcode == 5 then
    result.state = "refused"
    return result
  end
  if parsed.rcode == 3 then
    result.state = "nxdomain"
    return result
  end
  if parsed.rcode == 0 and parsed.ancount > 0 then
    for _, record in ipairs(parsed.answers) do
      if record.type == 25 then
        result.found = true
        local value = record.value
        if type(value) == "table" then
          table.insert(result.records, {
            priority = value.priority,
            weight = value.weight,
            port = value.port,
            target = value.target,
            text = value.text,
          })
        elseif type(value) == "string" then
          table.insert(result.records, {
            priority = 0, weight = 0, port = 0, target = value, text = value,
          })
        end
      end
    end
    if #result.records == 0 then
      result.state = "no-srv"
    else
      result.state = "answered"
    end
  else
    result.state = "no-srv"
    result.detail = parsed.rcode_name
  end
  return result
end

local function resolve_target_ip(host, port, target, args)
  local parsed, err = dns_lookup(host, port, target, "A", args, { rd = true })
  if not parsed then
    return nil, err
  end
  if parsed.rcode == 3 then
    return nil, "nxdomain"
  end
  if parsed.rcode == 0 then
    for _, record in ipairs(parsed.answers) do
      if record.type == 1 and type(record.value) == "string" then
        return record.value, nil
      end
    end
  end
  return nil, "no-address"
end

action = function(host, port)

  seed_random(port)
  reset_state()
  reset_findings()

  local args = read_args()
  local zone = zone_from_args(host, args)
  local pnum = port_number_of(port)

  local out = new_output(RISK_LEVEL, "AUDITED - DNS SRV enumeration completed.")
  local fetch_log = {}
  local sections = {}
  local probe_results = {}
  local services_found = 0
  local total_records = 0
  local internal_targets = 0
  local sensitive_services = 0
  local resolved_private = 0

  for _, service in ipairs(SRV_SERVICES) do
    if budget_exhausted(args) then
      table.insert(fetch_log, "request budget exhausted: remaining services skipped")
      break
    end
    local result = probe_srv(host, pnum, zone, service, args)
    table.insert(probe_results, result)
    if result.state == "answered" then
      services_found = services_found + 1
      if service.sensitive then
        sensitive_services = sensitive_services + 1
      end
      for _, rec in ipairs(result.records) do
        total_records = total_records + 1
        local internal, why = is_internal_target(rec.target, zone)
        if internal and why ~= "same zone" then
          internal_targets = internal_targets + 1
          add_finding("MEDIUM", string.format(
            "SRV %s advertises an internal target: %s:%d (%s) - internal service topology is leaking via DNS",
            result.name, rec.target, rec.port, service.product),
            { subject = "srv-internal:" .. result.name, evidence = rec.target })
        end
        if args.resolve and not internal then
          local ip, _err = resolve_target_ip(host, pnum, rec.target, args)
          if ip and is_private_address(ip) then
            resolved_private = resolved_private + 1
            add_finding("MEDIUM", string.format(
              "SRV %s target %s resolves to private address %s: the service is reachable only from inside the network, but the mapping is public",
              result.name, rec.target, ip),
              { subject = "srv-private-ip:" .. result.name, evidence = ip })
          end
        end
      end
      for _, rec in ipairs(result.records) do
        table.insert(fetch_log, string.format(
          "SRV %s -> %d %d %d %s (%s)", result.name,
          rec.priority, rec.weight, rec.port, rec.target, service.product))
      end
    elseif result.state == "refused" then
      table.insert(fetch_log, string.format("SRV %s -> REFUSED", result.name))
    else
      if result.state == "unreachable" then
        table.insert(fetch_log, string.format("SRV %s -> %s", result.name, tostring(result.detail)))
      end
    end
  end

  if services_found >= 5 then
    add_finding("MEDIUM", string.format(
      "the zone publishes %d SRV services (%d records): a detailed map of the internal service topology is available to anyone",
      services_found, total_records),
      { subject = "srv-inventory:" .. zone, evidence = services_found .. " services" })
  end

  if sensitive_services > 0 then
    add_finding("LOW", string.format(
      "%d sensitive service type(s) advertised via SRV (LDAP/AD, databases, brokers, VoIP, federation): each is a product-specific attack surface",
      sensitive_services),
      { subject = "srv-sensitive:" .. zone, evidence = sensitive_services .. " sensitive" })
  end

  local unique, counts = dedupe_findings()

  if internal_targets > 0 or resolved_private > 0 then
    out["Status"] = "VULNERABLE - SRV records leak internal service topology for " .. zone .. "."
  elseif services_found >= 5 then
    out["Status"] = "AUDITED - extensive SRV service inventory published for " .. zone .. "."
  elseif services_found > 0 then
    out["Status"] = "AUDITED - " .. services_found .. " SRV service(s) published for " .. zone .. "."
  else
    out["Status"] = "AUDITED - no SRV services found under " .. zone .. "."
  end

  table.insert(sections, { key = "Zone", value = zone })
  table.insert(sections, { key = "SRV services found", value = services_found })
  table.insert(sections, { key = "SRV records found", value = total_records })
  table.insert(sections, { key = "Internal targets", value = internal_targets })
  table.insert(sections, { key = "Private-address targets", value = resolved_private })
  table.insert(sections, { key = "Sensitive service types", value = sensitive_services })

  local found_lines = {}
  for _, result in ipairs(probe_results) do
    if result.state == "answered" then
      local rec_lines = {}
      for _, rec in ipairs(result.records) do
        table.insert(rec_lines, string.format(
          "        %d %d %d %s", rec.priority, rec.weight, rec.port, rec.target))
      end
      table.insert(found_lines, string.format(
        "      %s [%s]:", result.name, result.service.product))
      for _, line in ipairs(rec_lines) do
        table.insert(found_lines, line)
      end
    end
  end
  if #found_lines > 0 then
    table.insert(sections, { key = "SRV inventory", value = found_lines })
  else
    table.insert(sections, { key = "SRV inventory", value = "      (none)" })
  end

  table.insert(sections, { key = "Fetch log", value = fetch_log })
  table.insert(sections, { key = "Requests issued", value = state.requests .. " of " .. args.maxrequests })

  if internal_targets > 0 or resolved_private > 0 then
    table.insert(sections, { key = "Remediation", value =
      "remove or re-target the SRV records that point at internal hostnames: they exist to help "
      .. "internal clients find services, and publishing them externally maps your infrastructure. "
      .. "If external clients legitimately need some SRV records (federation, autodiscover), keep "
      .. "only those and move the rest into internal-only zones or split-brain DNS. Re-run the "
      .. "audit after the change." })
  else
    table.insert(sections, { key = "Remediation", value =
      "no internal topology leaks detected in the SRV inventory; review the published services "
      .. "annually and remove SRV records for decommissioned services (stale SRV records are a "
      .. "takeover and impersonation hook)." })
  end

  return finish_output(out, unique, counts, sections)

end
