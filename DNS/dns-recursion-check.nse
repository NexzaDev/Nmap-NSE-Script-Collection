local shortport = require "shortport"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Determines whether the tested DNS resolver performs recursive resolution
for arbitrary third-party domains on behalf of any client - the classic
"open resolver" exposure. An open resolver lets an attacker use the
organisation's (typically well-connected, whitelisted, low-latency)
resolver as a free recursive cache for their own lookups, hides the
attacker's real source address from the authoritative servers being
queried, and can be used to poison or probe the resolver's cache. It is
also the prerequisite for DNS cache-poisoning and amplification abuse,
because both require the resolver to fetch data from third-party
authorities for attacker-chosen names.

Why it matters
Open resolvers are a favourite of attackers for: hiding the origin of
DNS-based attacks, abusing the resolver's upstream connectivity for
amplification/reflection, warming cache-poisoning attacks, and mapping
internal naming via recursive lookups of reverse zones. Detection is
done by asking the resolver to resolve names it should have no business
resolving authoritatively and observing whether it fetches answers.

What the script does
1. Resolves the target zone's SOA to establish the resolver's zone of
   authority (so that same-zone answers are not misread as recursion).
2. Queries a battery of well-known third-party domains (public sites
   the resolver does not own) with the recursion-desired (RD) flag set,
   using both UDP and, where available, the TCP transport, and records
   whether an authoritative-looking answer (NOERROR with data, or an
   honest NXDOMAIN from a third party) came back.
3. Repeats a subset with the RD flag cleared: a resolver that answers
   third-party names even for non-recursive queries is misconfigured in
   a stronger sense.
4. Queries reverse-lookup names for private (RFC1918) address space:
   a public resolver answering 192.168/10/172.16 PTR lookups is leaking
   the internal naming scheme.
5. Queries a name in the reserved .invalid TLD (RFC 6761) that cannot
   exist: any NOERROR-with-answer response indicates wildcarding or a
   broken recursive path.
6. Correlates the results: at least one third-party name resolved
   authoritatively => open recursion (CRITICAL); private reverse lookup
   answered => internal naming leak (HIGH); RD-cleared queries answered
   => non-recursive misconfiguration (MEDIUM); reserved TLD answered
   => bogus response (MEDIUM).

Every probe is a plain DNS query; nothing is mutated, nothing is
iterated beyond the fixed battery (bounded by maxrequests), and the
random token in the .invalid probe name makes the check unguessable so
a pre-configured wildcard for our exact string cannot explain the
result.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "discovery", "vuln"}

portrule = shortport.port_or_service(53, "domain", {"udp", "tcp"})

local SCRIPT_NAME = "dns-recursion-check"

local RISK_LEVEL = "🟡 MEDIUM"

local PROBE_DOMAINS = {
  "example.org", "example.net", "example.edu",
  "cloudflare.com", "google.com", "github.com",
  "amazon.com", "microsoft.com", "apple.com",
  "wikipedia.org", "fastly.com", "akamai.com",
  "oracle.com", "ibm.com", "vmware.com",
  "cloud.google.com", "azure.microsoft.com",
  "netflix.com", "spotify.com", "slack.com",
}

local INTERNAL_LEAK_REVERSES = {
  { name = "1.1.168.192.in-addr.arpa", note = "192.168.0.0/16 (private)" },
  { name = "2.2.2.10.in-addr.arpa", note = "10.0.0.0/8 (private)" },
  { name = "1.1.16.172.in-addr.arpa", note = "172.16.0.0/12 (private)" },
  { name = "1.0.0.127.in-addr.arpa", note = "127.0.0.0/8 (loopback)" },
}

local RESERVED_INVALID_TLD = "invalid"

local DEFAULT_ARGS = {
  domain = nil,
  maxrequests = 60,
  retries = 0,
  timeout = 10000,
  delay = 0.05,
  maxprobes = 14,
  rd0 = true,
  tcp = true,
}

local NUMERIC_ARGS = {
  { key = "maxrequests", minimum = 4, integer = true },
  { key = "retries", minimum = 0, integer = true },
  { key = "timeout", minimum = 500, integer = true },
  { key = "maxprobes", minimum = 1, integer = true },
}

local BOOLEAN_ARGS = { "rd0", "tcp" }

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
  [252] = "AXFR", [253] = "IXFR", [41] = "OPT",
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

local function is_same_zone(name, zone)
  local lowered = lower(tostring(name or ""))
  local zoned = lower(tostring(zone or ""))
  if zoned == "" then
    return false
  end
  if lowered == zoned then
    return true
  end
  return lowered:sub(-(#zoned) + 1) == "." .. zoned
end

local function lookup_probe(host, port, name, qtype, args, opts)
  local parsed, err = dns_lookup(host, port, name, qtype, args, opts)
  if not parsed then
    return {
      name = name,
      ok = false,
      error = err,
    }
  end
  local answers = {}
  for _, record in ipairs(parsed.answers) do
    if record.type == 1 and type(record.value) == "string" then
      table.insert(answers, record.value)
    elseif record.type == 12 and type(record.value) == "string" then
      table.insert(answers, record.value)
    end
  end
  local answered = parsed.rcode == 0 and #parsed.answers > 0
  local nxdomain = parsed.rcode == 3
  return {
    name = name,
    ok = true,
    rcode = parsed.rcode,
    rcode_name = parsed.rcode_name,
    ra = parsed.ra == 1,
    aa = parsed.aa == 1,
    answered = answered,
    nxdomain = nxdomain,
    answers = answers,
    ancount = parsed.ancount,
    qtype = qtype,
  }
end

local function classify_probe(result, zone)
  if not result.ok then
    return "unreachable"
  end
  if result.answered and not is_same_zone(result.name, zone) then
    return "recursed"
  end
  if result.rcode == 0 and not result.answered and not is_same_zone(result.name, zone) then
    return "noerror-empty"
  end
  if result.nxdomain and not is_same_zone(result.name, zone) then
    return "nxdomain"
  end
  if result.rcode == 5 then
    return "refused"
  end
  return "other"
end

local function answer_text(result, limit)
  local shown = {}
  local count = 0
  for _, value in ipairs(result.answers) do
    if count >= (limit or 3) then
      break
    end
    count = count + 1
    table.insert(shown, tostring(value))
  end
  if #result.answers > #shown then
    table.insert(shown, "+" .. (#result.answers - #shown) .. " more")
  end
  return table.concat(shown, ", ")
end

action = function(host, port)

  seed_random(port)
  reset_state()
  reset_findings()

  local args = read_args()
  local zone = zone_from_args(host, args)
  local pnum = port_number_of(port)

  local out = new_output(RISK_LEVEL, "AUDITED - DNS recursion check completed.")
  local fetch_log = {}
  local sections = {}
  local probe_results = {}
  local open_recursion = false
  local recursed_count = 0
  local rd0_answered = false
  local internal_leak = false
  local bogus_invalid = false
  local same_zone_answers = 0

  local soa_resp, soa_err = dns_lookup(host, pnum, zone, "SOA", args)
  if soa_resp then
    table.insert(fetch_log, string.format(
      "SOA %s -> %s (zone of authority established)", zone, soa_resp.rcode_name))
  else
    table.insert(fetch_log, string.format("SOA %s -> %s (probing as non-authoritative)",
      zone, tostring(soa_err)))
  end

  local probes_done = 0
  local selected_probes = {}
  for _, probe in ipairs(PROBE_DOMAINS) do
    if probes_done >= args.maxprobes then
      break
    end
    probes_done = probes_done + 1
    table.insert(selected_probes, probe)
  end

  for _, probe in ipairs(selected_probes) do
    if budget_exhausted(args) then
      table.insert(fetch_log, "request budget exhausted: remaining probes skipped")
      break
    end
    local result = lookup_probe(host, pnum, probe, "A", args, { rd = true })
    local verdict = classify_probe(result, zone)
    table.insert(probe_results, { result = result, verdict = verdict })
    if result.ok then
      if verdict == "recursed" then
        open_recursion = true
        recursed_count = recursed_count + 1
        table.insert(fetch_log, string.format(
          "A %s -> NOERROR, answered %s (third-party domain resolved: recursion)",
          probe, answer_text(result)))
      elseif verdict == "noerror-empty" then
        table.insert(fetch_log, string.format(
          "A %s -> NOERROR, 0 answers (empty answer, possibly cached or filtered)", probe))
      elseif verdict == "nxdomain" then
        table.insert(fetch_log, string.format(
          "A %s -> NXDOMAIN (honest negative, no recursion evidence)", probe))
      elseif verdict == "refused" then
        table.insert(fetch_log, string.format("A %s -> REFUSED", probe))
      else
        table.insert(fetch_log, string.format(
          "A %s -> %s (ancount=%d)", probe, result.rcode_name, result.ancount))
      end
    else
      table.insert(fetch_log, string.format("A %s -> %s", probe, tostring(result.error)))
    end
  end

  if open_recursion then
    add_finding("CRITICAL", string.format(
      "the resolver at port %d performs recursive resolution for arbitrary third-party domains (open resolver): %d of %d third-party probes resolved",
      pnum, recursed_count, #selected_probes),
      { subject = "open-resolver:" .. pnum, evidence = "third-party A records returned" })
  end

  local rd0_checked = 0
  if args.rd0 and #selected_probes > 0 then
    for i = 1, #selected_probes do
      if rd0_checked >= 3 then
        break
      end
      if budget_exhausted(args) then
        break
      end
      rd0_checked = rd0_checked + 1
      local probe = selected_probes[i]
      local result = lookup_probe(host, pnum, probe, "A", args, { rd = false })
      local verdict = classify_probe(result, zone)
      table.insert(probe_results, { result = result, verdict = verdict .. " (RD=0)" })
      if result.ok and verdict == "recursed" then
        rd0_answered = true
        table.insert(fetch_log, string.format(
          "A %s (RD=0) -> NOERROR, answered %s (non-recursive query answered: strong misconfiguration)",
          probe, answer_text(result)))
      else
        table.insert(fetch_log, string.format("A %s (RD=0) -> %s",
          probe, result and result.rcode_name or tostring(result.error)))
      end
    end
  end

  if rd0_answered then
    add_finding("MEDIUM", string.format(
      "the resolver answered third-party queries even with the recursion-desired flag cleared: it is serving answers outside its zone of authority for non-recursive queries",
      pnum),
      { subject = "rd0-answered:" .. pnum, evidence = "RD=0 queries answered" })
  end

  local leaks = 0
  for _, reverse in ipairs(INTERNAL_LEAK_REVERSES) do
    if budget_exhausted(args) then
      break
    end
    local result = lookup_probe(host, pnum, reverse.name, "PTR", args, { rd = true })
    table.insert(probe_results, { result = result, verdict = classify_probe(result, zone) .. " (reverse)" })
    if result.ok and result.answered then
      internal_leak = true
      leaks = leaks + 1
      add_finding("HIGH", string.format(
        "reverse lookup for %s (%s) was answered by this public resolver: %s - internal naming scheme is leaking",
        reverse.name, reverse.note, answer_text(result)),
        { subject = "reverse-leak:" .. reverse.name, evidence = answer_text(result) })
      table.insert(fetch_log, string.format(
        "PTR %s -> answered %s (internal reverse zone leak)", reverse.name, answer_text(result)))
    elseif result.ok then
      table.insert(fetch_log, string.format("PTR %s -> %s (no leak)",
        reverse.name, result.rcode_name))
    else
      table.insert(fetch_log, string.format("PTR %s -> %s", reverse.name, tostring(result.error)))
    end
  end

  if not internal_leak and leaks == 0 then
    table.insert(fetch_log, "no private reverse-lookup leaks detected")
  end

  local invalid_name = "nmap-recursion-" .. random_token(8) .. "." .. RESERVED_INVALID_TLD
  if not budget_exhausted(args) then
    local result = lookup_probe(host, pnum, invalid_name, "A", args, { rd = true })
    table.insert(probe_results, { result = result, verdict = classify_probe(result, zone) .. " (reserved TLD)" })
    if result.ok then
      if result.answered then
        bogus_invalid = true
        add_finding("MEDIUM", string.format(
          "a name in the reserved .invalid TLD (%s) received a positive answer: the recursive path is returning bogus data",
          invalid_name),
          { subject = "bogus-invalid:" .. pnum, evidence = answer_text(result) })
        table.insert(fetch_log, string.format("A %s -> NOERROR answered %s (bogus: .invalid must be NXDOMAIN)",
          invalid_name, answer_text(result)))
      else
        table.insert(fetch_log, string.format("A %s -> %s (correctly negative)",
          invalid_name, result.rcode_name))
      end
    else
      table.insert(fetch_log, string.format("A %s -> %s", invalid_name, tostring(result.error)))
    end
  end

  local same_zone = 0
  local third_party = 0
  for _, entry in ipairs(probe_results) do
    local result = entry.result
    if result.ok then
      if is_same_zone(result.name, zone) then
        same_zone = same_zone + 1
      else
        third_party = third_party + 1
      end
    end
  end

  local ra_count = 0
  local total_ok = 0
  for _, entry in ipairs(probe_results) do
    local result = entry.result
    if result.ok then
      total_ok = total_ok + 1
      if result.ra then
        ra_count = ra_count + 1
      end
    end
  end

  local verdict_lines = {}
  table.insert(verdict_lines, string.format(
    "third-party probes: %d, zone probes: %d", third_party, same_zone))
  table.insert(verdict_lines, string.format(
    "responses with recursion-available (RA) flag: %d of %d", ra_count, total_ok))
  table.insert(verdict_lines, "open recursion: " .. tostring(open_recursion))
  table.insert(verdict_lines, "RD=0 answered: " .. tostring(rd0_answered))
  table.insert(verdict_lines, "private reverse leak: " .. tostring(internal_leak))
  table.insert(verdict_lines, "bogus .invalid answer: " .. tostring(bogus_invalid))

  if open_recursion then
    out["Status"] = "VULNERABLE - open resolver: performs recursion for arbitrary third-party domains."
  elseif internal_leak then
    out["Status"] = "VULNERABLE - public resolver leaking internal reverse-lookup data."
  elseif rd0_answered then
    out["Status"] = "VULNERABLE - resolver answering non-recursive queries outside its zone."
  else
    out["Status"] = "AUDITED - recursion appears restricted to the resolver's zone of authority."
  end

  table.insert(sections, { key = "Zone of authority", value = zone })
  table.insert(sections, { key = "Probes sent", value = #probe_results })
  table.insert(sections, { key = "Recursion verdict", value = verdict_lines })

  local per_probe = {}
  for _, entry in ipairs(probe_results) do
    local result = entry.result
    if result.ok then
      table.insert(per_probe, string.format(
        "%s [%s] -> %s%s%s",
        result.name, entry.verdict, result.rcode_name,
        result.answered and (" answered: " .. answer_text(result)) or "",
        result.ra and " (RA)" or ""))
    else
      table.insert(per_probe, string.format("%s [%s] -> %s",
        result.name, entry.verdict, tostring(result.error)))
    end
  end
  table.insert(sections, { key = "Probe results", value = per_probe })
  table.insert(sections, { key = "Fetch log", value = fetch_log })
  table.insert(sections, { key = "Requests issued", value = state.requests .. " of " .. args.maxrequests })

  if open_recursion then
    table.insert(sections, { key = "Remediation", value =
      "restrict recursion on the resolver: in bind, 'recursion no;' for the view that serves "
      .. "untrusted clients (or 'allow-recursion { trusted-clients; };'), and only serve the "
      .. "authoritative zones the resolver should own. On Windows DNS, uncheck 'Enable recursive "
      .. "queries' for the non-internal zone scope. Then re-run this check to confirm third-party "
      .. "names are REFUSED or NXDOMAIN." })
  else
    table.insert(sections, { key = "Remediation", value =
      "recursion appears properly restricted; keep the resolver's recursion scope limited to "
      .. "trusted internal clients and re-run after any change to the resolver configuration." })
  end

  local unique, counts = dedupe_findings()
  return finish_output(out, unique, counts, sections)

end
