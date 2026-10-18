local shortport = require "shortport"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Validates the DNSSEC posture of a zone: whether the zone is signed,
whether the delegation from the parent is signed (DS record), whether
the published key set is complete (KSK + ZSK) with current algorithms,
whether the SOA carries a valid, unexpired RRSIG, and whether
authentic negative responses are available (NSEC/NSEC3). DNSSEC gives
recipients authenticated denial and integrity for DNS answers; a zone
that is unsigned (or half-signed) can have its answers forged by an
attacker in the middle, which underpins subdomain hijack, certificate
transparency bypass and cache poisoning.

Why it matters
- An unsigned zone: any answer for it can be spoofed on-path.
- A zone with a DS at the parent but no DNSKEY: the parent says "this
  zone is signed", but the zone publishes no keys - validators will
  SERVFAIL for the zone, breaking DNSSEC-validating resolvers
  (operational breakage + the delegation is misconfigured).
- Expired or expiring RRSIGs: validators reject the zone until keys
  are rolled.
- Deprecated key algorithms (RSA/SHA-1, algorithm 5): weak signatures,
  deprecated by RFC 8689.
- Missing NSEC/NSEC3: no authenticated denial - NXDOMAIN answers can
  be forged (enables dangling-domain attacks even in a signed zone).

What the script does
1. Fetches the zone's DNSKEY RRset; counts KSKs (flags 257) and ZSKs
   (flags 256), records algorithms, flags deprecated algorithms
   (1, 2, 3, 4, 5, 6), and notes the recommended set (13 ED25519,
   14 ED448, 7/8 ECDSA).
2. Fetches the SOA and checks for an accompanying RRSIG (via an RRSIG
   RRset query): present/absent, covered type, key tag, inception and
   expiration (Unix-second comparison against the audit time; expired
   = MEDIUM, expiring within 30 days = LOW).
3. Fetches the DS RRset for the zone (as delegated by the parent):
   present + DNSKEY present = chain established; DS present but no
   DNSKEY = broken delegation (HIGH); no DS = unsigned delegation
   (informational, common for test zones).
4. Checks NSEC (45) and NSEC3 (48) for authenticated denial.
5. Correlates everything into a posture verdict:
   signed + chained + current algorithm + valid SOA signature =
   healthy; otherwise targeted findings.

Read-only lookups only (DNSKEY/SOA/RRSIG/DS/NSEC/NSEC3), bounded by
maxrequests.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

portrule = shortport.port_or_service(53, "domain", {"udp", "tcp"})

local SCRIPT_NAME = "dns-dnssec-validation"

local RISK_LEVEL = "🟡 MEDIUM"

local KEY_ALGORITHM_STATUS = {
  [1] = { status = "deprecated", note = "RSAMD5 (deprecated, RFC 3110)" },
  [2] = { status = "deprecated", note = "DH (deprecated)" },
  [3] = { status = "deprecated", note = "DSA/SHA-1 (deprecated, RFC 8689)" },
  [4] = { status = "deprecated", note = "ECC-GOST (rare, weak)" },
  [5] = { status = "deprecated", note = "RSA/SHA-1 (deprecated, RFC 8689)" },
  [6] = { status = "deprecated", note = "RSA/SHA-1 NSA (deprecated)" },
  [7] = { status = "ok", note = "ECDSA P-256/SHA-256 (recommended)" },
  [8] = { status = "ok", note = "ECDSA P-384/SHA-384 (recommended)" },
  [10] = { status = "ok", note = "ECDsa P-521 (less common)" },
  [12] = { status = "ok", note = "GOST R 34.10-2001" },
  [13] = { status = "ok", note = "ED25519 (recommended)" },
  [14] = { status = "ok", note = "ED448 (recommended)" },
  [15] = { status = "experimental", note = "INDNS (experimental)" },
  [16] = { status = "experimental", note = "GOST R 34.10-2012 (256)" },
  [17] = { status = "experimental", note = "GOST R 34.10-2012 (512)" },
}

local SIGNATURE_EXPIRY_WARN_SECONDS = 30 * 24 * 3600

local DEFAULT_ARGS = {
  domain = nil,
  maxrequests = 40,
  retries = 0,
  timeout = 10000,
  delay = 0.05,
}

local NUMERIC_ARGS = {
  { key = "maxrequests", minimum = 4, integer = true },
  { key = "retries", minimum = 0, integer = true },
  { key = "timeout", minimum = 500, integer = true },
}

local BOOLEAN_ARGS = {}

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

local function fetch_rrset(host, port, name, qtype, args)
  local parsed, err = dns_lookup(host, port, name, qtype, args, { rd = false })
  if not parsed then
    return nil, err
  end
  local records = {}
  if parsed.rcode == 0 then
    for _, record in ipairs(parsed.answers) do
      if record.type == qtype then
        table.insert(records, record)
      end
    end
  end
  if parsed.rcode == 3 then
    return records, "NXDOMAIN"
  end
  if parsed.rcode == 5 then
    return records, "REFUSED"
  end
  return records, nil
end

local function audit_dnskeys(host, port, zone, args)
  local result = {
    state = "unreachable",
    keys = {},
    ksk = 0,
    zsk = 0,
    algorithms = {},
  }
  local records, err = fetch_rrset(host, port, zone, 46, args)
  if err == "NXDOMAIN" or (records and #records == 0 and err == nil) then
    result.state = "absent"
    return result
  end
  if err then
    result.state = "unreachable"
    result.detail = err
    return result
  end
  for _, record in ipairs(records) do
    local value = record.value
    if type(value) == "table" then
      local is_ksk = value.flags == 257
      local is_zsk = value.flags == 256
      if is_ksk then
        result.ksk = result.ksk + 1
      elseif is_zsk then
        result.zsk = result.zsk + 1
      end
      local algo_info = KEY_ALGORITHM_STATUS[value.algorithm]
      table.insert(result.algorithms, value.algorithm)
      table.insert(result.keys, {
        flags = value.flags,
        role = is_ksk and "KSK" or (is_zsk and "ZSK" or "OTHER(" .. tostring(value.flags) .. ")"),
        algorithm = value.algorithm,
        algorithm_note = algo_info and algo_info.note or "algorithm " .. tostring(value.algorithm),
        algorithm_status = algo_info and algo_info.status or "unknown",
        key = truncate(tostring(value.key or ""), 32),
        ttl = record.ttl,
      })
    end
  end
  result.state = "present"
  return result
end

local function audit_soa_signature(host, port, zone, args)
  local result = {
    state = "unreachable",
    soa_present = false,
    signature = nil,
  }
  local soa_records, soa_err = fetch_rrset(host, port, zone, 6, args)
  if soa_records and #soa_records > 0 then
    result.soa_present = true
  end
  if soa_err and not result.soa_present then
    result.state = "unreachable"
    result.detail = soa_err
    return result
  end
  local sig_records, sig_err = fetch_rrset(host, port, zone, 43, args)
  if sig_err == "NXDOMAIN" or (sig_records and #sig_records == 0 and sig_err == nil) then
    result.state = result.soa_present and "unsigned" or "unreachable"
    return result
  end
  if sig_err then
    result.state = "unreachable"
    result.detail = sig_err
    return result
  end
  for _, record in ipairs(sig_records) do
    local value = record.value
    if type(value) == "table" and (value.type_covered == 6 or value.type_covered == "SOA") then
      result.signature = {
        algorithm = value.algorithm,
        key_tag = value.key_tag,
        inception = value.inception,
        expiration = value.expiration,
        signer = value.signer,
        labels = value.labels,
      }
      result.state = "signed"
    end
  end
  if not result.signature then
    result.state = result.soa_present and "unsigned" or "unreachable"
  end
  return result
end

local function audit_delegation(host, port, zone, args)
  local result = { state = "unreachable", ds_records = 0, key_tags = {} }
  local records, err = fetch_rrset(host, port, zone, 33, args)
  if err == "NXDOMAIN" then
    result.state = "absent"
    return result
  end
  if err then
    result.state = "unreachable"
    result.detail = err
    return result
  end
  if #records == 0 then
    result.state = "absent"
    return result
  end
  result.state = "present"
  for _, record in ipairs(records) do
    result.ds_records = result.ds_records + 1
    local value = record.value
    if type(value) == "table" then
      table.insert(result.key_tags, tostring(value.key_tag))
    end
  end
  return result
end

local function audit_negative_auth(host, port, zone, args)
  local result = { nsec = false, nsec3 = false, nsec3_iterations = nil }
  local nsec_records, nsec_err = fetch_rrset(host, port, zone, 45, args)
  if nsec_records and #nsec_records > 0 then
    result.nsec = true
  end
  local nsec3_records, nsec3_err = fetch_rrset(host, port, zone, 48, args)
  if nsec3_records and #nsec3_records > 0 then
    result.nsec3 = true
    local value = nsec3_records[1].value
    if type(value) == "table" then
      result.nsec3_iterations = value.iterations
      result.nsec3_hash_algorithm = value.hash_algorithm
      result.nsec3_salt = truncate(tostring(value.salt or ""), 16)
    end
  end
  result.state = "checked"
  return result
end

action = function(host, port)

  seed_random(port)
  reset_state()
  reset_findings()

  local args = read_args()
  local zone = zone_from_args(host, args)
  local pnum = port_number_of(port)

  local out = new_output(RISK_LEVEL, "AUDITED - DNSSEC validation completed.")
  local fetch_log = {}
  local sections = {}
  local now = os.time()

  local dnskey = audit_dnskeys(host, pnum, zone, args)
  table.insert(fetch_log, string.format(
    "DNSKEY %s -> %s (%d record(s))", zone, dnskey.state, #dnskey.keys))

  local soa_sig = audit_soa_signature(host, pnum, zone, args)
  table.insert(fetch_log, string.format(
    "SOA/RRSIG %s -> soa=%s state=%s", zone,
    tostring(soa_sig.soa_present), soa_sig.state))

  local delegation = audit_delegation(host, pnum, zone, args)
  table.insert(fetch_log, string.format(
    "DS %s -> %s (%d record(s))", zone, delegation.state, delegation.ds_records))

  local negative = audit_negative_auth(host, pnum, zone, args)
  table.insert(fetch_log, string.format(
    "NSEC/NSEC3 %s -> nsec=%s nsec3=%s", zone, tostring(negative.nsec), tostring(negative.nsec3)))

  local signed = dnskey.state == "present"
  local chained = delegation.state == "present" and signed

  if not signed then
    add_finding("MEDIUM", string.format(
      "the zone %s publishes no DNSKEY records: it is unsigned, so DNS answers for it can be forged by an on-path attacker (no authenticated denial, no integrity)",
      zone),
      { subject = "dnssec-unsigned:" .. zone, evidence = "no DNSKEY RRset" })
  else
    if dnskey.ksk == 0 and dnskey.zsk == 0 then
      add_finding("MEDIUM", string.format(
        "the zone %s publishes %d DNSKEY record(s) but none carries the KSK (257) or ZSK (256) flag: the key set is unusable for validation",
        zone, #dnskey.keys),
        { subject = "dnskey-flags:" .. zone, evidence = tostring(#dnskey.keys) .. " keys, no KSK/ZSK flag" })
    end
    if dnskey.zsk == 0 and dnskey.ksk > 0 then
      add_finding("LOW", string.format(
        "the zone %s publishes a KSK but no ZSK: zone-signing keys should be rolled on a separate (shorter) schedule than the KSK",
        zone),
        { subject = "dnskey-no-zsk:" .. zone, evidence = "KSK only" })
    end
    for _, key in ipairs(dnskey.keys) do
      if key.algorithm_status == "deprecated" then
        add_finding("MEDIUM", string.format(
          "the zone %s uses deprecated DNSKEY algorithm %d (%s) for its %s key: roll to ED25519 (13), ED448 (14) or ECDSA (7/8)",
          zone, key.algorithm, key.algorithm_note, key.role),
          { subject = "dnskey-algo:" .. zone .. ":" .. key.role,
            evidence = "algorithm " .. key.algorithm })
      end
    end
  end

  if soa_sig.state == "signed" and soa_sig.signature then
    local sig = soa_sig.signature
    if sig.expiration and sig.expiration < now then
      add_finding("MEDIUM", string.format(
        "the SOA RRSIG for %s expired (expiration=%d, now=%d): validators will reject the zone until keys are rolled",
        zone, sig.expiration, now),
        { subject = "rrsig-expired:" .. zone, evidence = "expiration in the past" })
    elseif sig.expiration and (sig.expiration - now) < SIGNATURE_EXPIRY_WARN_SECONDS then
      add_finding("LOW", string.format(
        "the SOA RRSIG for %s expires in %d days: plan a signature refresh before it lapses",
        zone, math.floor((sig.expiration - now) / 86400)),
        { subject = "rrsig-expiring:" .. zone, evidence = sig.expiration .. "s" })
    end
  elseif signed then
    add_finding("MEDIUM", string.format(
      "the zone %s publishes DNSKEYs but no RRSIG over the SOA: the zone is not actually signed (or signatures are not served)",
      zone),
      { subject = "rrsig-missing:" .. zone, evidence = "DNSKEY present, no SOA RRSIG" })
  end

  if delegation.state == "present" and not signed then
    add_finding("HIGH", string.format(
      "the parent delegation for %s carries a DS record but the zone publishes no DNSKEY: DNSSEC-validating resolvers will SERVFAIL for the entire zone (broken delegation)",
      zone),
      { subject = "dnssec-broken-chain:" .. zone,
        evidence = delegation.ds_records .. " DS, no DNSKEY" })
  end

  if signed and chained then
    add_finding("INFO", string.format(
      "DNSSEC chain established for %s: DS at the parent (%d record(s), key tag(s) %s) and a published key set",
      zone, delegation.ds_records, table.concat(delegation.key_tags, ",")),
      { subject = "dnssec-chained:" .. zone, evidence = "DS + DNSKEY present" })
  elseif signed and delegation.state == "absent" then
    add_finding("LOW", string.format(
      "the zone %s is signed but the parent delegation has no DS record: trust must be anchored at the zone itself (trust-anchor configuration)",
      zone),
      { subject = "dnssec-no-ds:" .. zone, evidence = "no DS at parent" })
  end

  if not negative.nsec and not negative.nsec3 and signed then
    add_finding("LOW", string.format(
      "the signed zone %s publishes neither NSEC nor NSEC3: there is no authenticated denial of existence (NXDOMAIN can still be forged)",
      zone),
      { subject = "dnssec-no-nsec:" .. zone, evidence = "no NSEC/NSEC3" })
  end
  if negative.nsec3 and negative.nsec3_iterations and negative.nsec3_iterations > 50 then
    add_finding("LOW", string.format(
      "NSEC3 hash iterations for %s are %d (with salt %s): high iteration counts increase CPU cost for resolvers (amplification-prone)",
      zone, negative.nsec3_iterations, tostring(negative.nsec3_salt)),
      { subject = "nsec3-cost:" .. zone, evidence = tostring(negative.nsec3_iterations) .. " iterations" })
  end

  local unique, counts = dedupe_findings()

  local posture
  if not signed then
    posture = "unsigned"
  elseif delegation.state == "present" then
    posture = "signed + parent DS (chained)"
  else
    posture = "signed (no parent DS)"
  end
  if not negative.nsec and not negative.nsec3 and signed then
    posture = posture .. ", no authenticated denial"
  end

  if not signed then
    out["Status"] = "VULNERABLE - zone " .. zone .. " is not DNSSEC-signed."
  elseif delegation.state == "present" and soa_sig.state ~= "signed" then
    out["Status"] = "VULNERABLE - broken DNSSEC delegation for " .. zone .. "."
  elseif soa_sig.state ~= "signed" then
    out["Status"] = "VULNERABLE - zone " .. zone .. " publishes keys but is not signed."
  else
    out["Status"] = "AUDITED - DNSSEC posture for " .. zone .. ": " .. posture .. "."
  end

  table.insert(sections, { key = "Zone", value = zone })
  table.insert(sections, { key = "Posture", value = posture })
  table.insert(sections, { key = "DNSKEY", value = dnskey.state })
  if #dnskey.keys > 0 then
    local key_lines = {}
    for _, key in ipairs(dnskey.keys) do
      table.insert(key_lines, string.format(
        "      %s flags=%d algorithm=%d (%s) key=%s... ttl=%d",
        key.role, key.flags, key.algorithm, key.algorithm_note,
        truncate(tostring(key.key), 16), key.ttl or 0))
    end
    table.insert(sections, { key = "DNSKEY set", value = key_lines })
  end
  table.insert(sections, { key = "SOA RRSIG", value = soa_sig.state })
  if soa_sig.signature then
    local sig = soa_sig.signature
    table.insert(sections, { key = "SOA RRSIG detail", value = string.format(
      "algorithm=%s keyTag=%s inception=%s expiration=%s signer=%s (expires in %s days)",
      tostring(sig.algorithm), tostring(sig.key_tag), tostring(sig.inception),
      tostring(sig.expiration), tostring(sig.signer),
      sig.expiration and tostring(math.floor((sig.expiration - now) / 86400)) or "n/a") })
  end
  table.insert(sections, { key = "Parent DS", value = delegation.state })
  if delegation.state == "present" then
    table.insert(sections, { key = "DS key tags", value = delegation.key_tags })
  end
  table.insert(sections, { key = "Authenticated denial", value =
    (negative.nsec and "NSEC") or (negative.nsec3 and ("NSEC3 (iter " .. tostring(negative.nsec3_iterations) .. ")")) or "none" })
  table.insert(sections, { key = "Fetch log", value = fetch_log })
  table.insert(sections, { key = "Requests issued", value = state.requests .. " of " .. args.maxrequests })

  if not signed then
    table.insert(sections, { key = "Remediation", value =
      "sign the zone: generate a KSK and a ZSK (e.g. 'delv key' or 'dnssec-keygen -K . 256 zsk / 2048 ksk "
      .. "with algorithm 13 or 7'), publish both DNSKEY RRsets, produce RRSIGs for every RRset "
      .. "(dnssec-signzone), publish NSEC or NSEC3 for authenticated denial, and ask the "
      .. "registrar/parent for a DS record matching the KSK key tag. Then re-run this audit to "
      .. "confirm: DNSKEY present (KSK+ZSK), SOA RRSIG unexpired, DS at the parent, NSEC/NSEC3 "
      .. "present." })
  else
    table.insert(sections, { key = "Remediation", value =
      "the zone is signed; keep the ZSK roll schedule ahead of the SOA signature expiration, roll "
      .. "the KSK on a longer schedule, watch the DS/DNSKEY chain after any key change, and avoid "
      .. "high NSEC3 iteration counts." })
  end

  return finish_output(out, unique, counts, sections)

end
