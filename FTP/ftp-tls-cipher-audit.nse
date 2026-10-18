local shortport = require "shortport"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Audits the SSL/TLS protocol versions and cipher suites that the FTP
server will actually negotiate over explicit FTPS (AUTH TLS).

Why it matters
- The FTPS control channel protects the credential exchange, so a
  broken TLS stack on that channel breaks the entire protection
  story: SSLv3 (POODLE), TLS 1.0/1.1 (deprecated by RFC 8996), RC4,
  DES, 3DES (Sweet32) or NULL encryption in the FTPS handshake are
  all standing downgrade paths.
- Many FTP daemons ship with the TLS profile of their build era;
  probing the real negotiation - not just the advertised feature
  list - is the only way to know what a client can actually get.
- Each probe is an independent AUTH TLS + ClientHello exchange, so
  one broken option never masks another.

What the script does
1. Confirms AUTH TLS is accepted at all; if not, reports the
   endpoint as plaintext-only and stops.
2. Runs a default-negotiation baseline to capture the server's
   preferred protocol and cipher (and any Diffie-Hellman modulus
   size, flagged when it is 1024-bit or less).
3. Probes TLS 1.3 availability via the supported_versions
   extension, then SSLv3, TLS 1.0 and TLS 1.1 with legacy
   ClientHellos.
4. Probes weak cipher families - NULL encryption, RC4, DES and
   3DES - on a TLS 1.2 ClientHello; an acceptance of any of these
   is reported with the family context.
5. Emits MEDIUM for accepted legacy protocols and weak cipher
   families, HIGH for accepted NULL encryption or 1024-bit DH, and
   INFO when every option is rejected (modern-only profile).

Every probe is a fresh connection and ends after the server flight;
no client flight is completed and no FTP data ever crosses the
channel.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"defensive", "safe"}

portrule = shortport.port_or_service(21, "ftp")

local SCRIPT_NAME = "ftp-tls-cipher-audit"

local RISK_LEVEL = "🟡 MEDIUM"

local DEFAULT_ARGS = {
  maxrequests = 10,
  timeout = 10,
}

local NUMERIC_ARGS = {
  { key = "maxrequests", minimum = 1, integer = true },
  { key = "timeout", minimum = 1, integer = true },
}

local BOOLEAN_ARGS = {}

local STRING_ARGS = {}

local DEFAULT_CIPHERS = { 0xc02f, 0xc030, 0x009d, 0x009c, 0x0035, 0x0039, 0x0067, 0x006b }

local PROBE_VERSIONS = {
  { name = "SSLv3", version = 0x0300, ciphers = { 0x0035, 0xc02f, 0x009c }, risk = "high",
    note = "SSLv3 is broken by design (POODLE, CVE-2014-3566) and must not be negotiable" },
  { name = "TLS 1.0", version = 0x0301, ciphers = { 0x0035, 0xc02f, 0x009c }, risk = "medium",
    note = "TLS 1.0 is deprecated by RFC 8996 and should not be negotiable" },
  { name = "TLS 1.1", version = 0x0302, ciphers = { 0x0035, 0xc02f, 0x009c }, risk = "medium",
    note = "TLS 1.1 is deprecated by RFC 8996 and should not be negotiable" },
}

local PROBE_CIPHER_FAMILIES = {
  { name = "NULL encryption", ciphers = { 0x0001, 0x0002 }, risk = "high",
    note = "NULL ciphers provide no confidentiality at all" },
  { name = "RC4", ciphers = { 0x0013, 0x0005, 0x000a }, risk = "medium",
    note = "RC4 is broken (biases, RFC 7465 deprecation) and must not be negotiable" },
  { name = "DES", ciphers = { 0x0006, 0x0004 }, risk = "high",
    note = "single-DES and 40-bit export DES are trivially breakable" },
  { name = "3DES", ciphers = { 0x0007, 0x0009, 0x000c }, risk = "medium",
    note = "3DES is vulnerable to the Sweet32 birthday attack (CVE-2016-2183)" },
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

local function ft_trim(value)
  if type(value) ~= "string" then
    return value
  end
  value = string.gsub(value, "^%s+", "")
  value = string.gsub(value, "%s+$", "")
  return value
end

local function ft_lower(value)
  if type(value) ~= "string" then
    return ""
  end
  return string.lower(ft_trim(value))
end

local FTP_BANNER_SIGNATURES = {
  {
    pattern = "%(vsftpd%s+(%S+)%)",
    family = "vsftpd",
    vendor = "vsftpd project",
    source = "vsftpd",
  },
  {
    pattern = "vsftpd%s+([%d%.]+%a?)",
    family = "vsftpd",
    vendor = "vsftpd project",
    source = "vsftpd-versioned",
  },
  {
    pattern = "ProFTPD%s+([%d%.]+%a?)",
    family = "ProFTPD",
    vendor = "ProFTPD project",
    source = "proftpd",
  },
  {
    pattern = "Pure-FTPd%s+(%S+)",
    family = "Pure-FTPd",
    vendor = "FR20",
    source = "pureftpd",
  },
  {
    pattern = "Microsoft FTP Service",
    family = "IIS",
    vendor = "Microsoft",
    source = "microsoft-iis",
  },
  {
    pattern = "FileZilla Server version%s+([%d%.]+)",
    family = "FileZilla",
    vendor = "Tim Kosse",
    source = "filezilla",
  },
  {
    pattern = "glftpd%s+([%d%.]+)",
    family = "glftpd",
    vendor = "Glenn MacGregor",
    source = "glftpd",
  },
  {
    pattern = "wu-ftpd%s+([%d%.]+)",
    family = "wu-ftp",
    vendor = "WU-FTPD Group",
    source = "wuftpd",
  },
  {
    pattern = "lightFTP",
    family = "lightFTP",
    vendor = "LightFTP project",
    source = "lightftp",
  },
  {
    pattern = "OpenFTP",
    family = "OpenFTP",
    vendor = "Nico Salmore",
    source = "openftp",
  },
  {
    pattern = "Serv-U FTP Server v?(%S+)",
    family = "Serv-U",
    vendor = "SolarWinds",
    source = "servu",
  },
  {
    pattern = "Solaris FTP Server%s+([%d%.]+)",
    family = "Solaris",
    vendor = "Oracle",
    source = "solaris-ftpd",
  },
  {
    pattern = "BSD FTP",
    family = "BSD-ftpd",
    vendor = "BSD project",
    source = "bsd-ftpd",
  },
  {
    pattern = "CoreFTP",
    family = "CoreFTP",
    vendor = "CoreFTP",
    source = "coreftp",
  },
  {
    pattern = "zFTP",
    family = "zFTP",
    vendor = "zSoft",
    source = "zftp",
  },
  {
    pattern = "CSFTP",
    family = "CSFTP",
    vendor = "C-System",
    source = "csftp",
  },
  {
    pattern = "Anonymous FTP Server",
    family = "anonymous",
    vendor = "unknown",
    source = "anonymous-ftpd",
  },
}

local FTP_FAMILY_EOL = {
  vsftpd = {
    { min = "2.3.4", max = "2.3.4", note = "vsftpd 2.3.4 shipped with a hardcoded backdoor (CVE-2011-2523); any build answering with a 227 welcome code is compromised or intentionally backdoored" },
    { min = "3.0.0", max = "3.0.2", note = "vsftpd 3.0.2 and earlier are unmaintained releases" },
    { min = "3.0.3", max = "3.0.3", note = "vsftpd 3.0.3 predates the 3.0.4/3.0.5 security fixes; upgrade recommended" },
  },
  ProFTPD = {
    { min = "1.3.4", max = "1.3.4", note = "ProFTPD 1.3.4 is affected by the unauthenticated mod_copy file-copy issue (CVE-2015-3306) when mod_copy is loaded" },
    { min = "1.3.5", max = "1.3.5", note = "ProFTPD 1.3.5 release line (2015) is long past support; later 1.3.6+ releases carry security fixes" },
    { min = "1.2.0", max = "1.3.3", note = "ProFTPD 1.2.x/early 1.3.x lines are unmaintained" },
  },
  ["Pure-FTPd"] = {
    { min = "1.0.0", max = "1.0.4", note = "Pure-FTPd 1.0.x is unmaintained" },
  },
  FileZilla = {
    { min = "0.9.0", max = "0.9.61", note = "FileZilla Server 0.9.x is unmaintained; the 1.x line replaced it" },
  },
  ["wu-ftp"] = {
    { min = "0.1", max = "5.2.0", note = "wu-ftp 5.x ended support in 2005 and never received the classic vulnerability fixes applied by successor daemons" },
  },
  IIS = {
    { min = "5.0", max = "5.0", note = "IIS 5.0 FTP (Windows 2000 era) is end-of-life" },
    { min = "6.0", max = "6.0", note = "IIS 6.0 FTP (Windows Server 2003 era) is end-of-life" },
  },
  ["Serv-U"] = {
    { min = "10.0", max = "10.0", note = "Serv-U 10.x is an old release line" },
  },
}

local function ft_parse_version_tuple(value)
  local parts = {}
  for part in string.gmatch(tostring(value or ""), "%d+") do
    table.insert(parts, tonumber(part))
  end
  return parts
end

local function ft_version_between(version, lo, hi)
  local v = ft_parse_version_tuple(version)
  local a = ft_parse_version_tuple(lo)
  local b = ft_parse_version_tuple(hi)
  local n = math.max(#v, math.max(#a, #b))
  for i = 1, n do
    local x = v[i] or 0
    local y = a[i] or 0
    local z = b[i] or 0
    if x < y then
      return false
    end
    if x > z then
      return false
    end
  end
  return true
end

local function ft_version_note(family, version)
  local rules = FTP_FAMILY_EOL[family]
  if rules == nil then
    return nil
  end
  for _, rule in ipairs(rules) do
    if ft_version_between(version, rule.min, rule.max) then
      return rule.note
    end
  end
  return nil
end

local function ft_backdoor_banner(banner_text)
  local text = ft_lower(banner_text or "")
  local code = string.sub(banner_text or "", 1, 3)
  if code == "227" and text:find("vsftpd", 1, true) then
    return true
  end
  return false
end

local function ft_parse_banner(text)
  local raw = tostring(text or "")
  local code = string.sub(raw, 1, 3)
  local body = ft_trim(string.sub(raw, 4))
  local info = {
    code = code,
    text = ft_trim(raw),
    family = "unknown",
    version = nil,
    backdoor_banner = ft_backdoor_banner(raw),
    suppressed = false,
  }
  if #raw == 0 or code == "" then
    info.suppressed = true
    return info
  end
  if #code == 3 and code:match("^%d%d%d$") == nil then
    info.suppressed = true
    return info
  end
  if info.backdoor_banner then
    info.family = "vsftpd"
    info.vendor = "vsftpd project"
    info.source = "backdoor-banner"
    return info
  end
  local lowered = string.lower(body)
  for _, sig in ipairs(FTP_BANNER_SIGNATURES) do
    local version = string.match(lowered, sig.pattern)
    if version ~= nil then
      info.family = sig.family
      info.vendor = sig.vendor
      info.source = sig.source
      if version ~= nil and #version > 0 then
        info.version = ft_trim(version)
      end
      return info
    end
  end
  if body == "" then
    info.family = "generic"
    info.source = "no-banner-text"
  else
    info.family = "unknown"
    info.source = "unrecognized-banner"
    info.sample = body
  end
  return info
end

local function ft_parse_response(text)
  local raw = tostring(text or "")
  local lines = {}
  for line in (raw .. "\n"):gmatch("(.-)\r?\n") do
    local trimmed = ft_trim(line)
    if trimmed ~= "" then
      table.insert(lines, trimmed)
    end
  end
  local info = { code = nil, text = ft_trim(raw), lines = lines }
  if #lines > 0 then
    local first = lines[1]
    local code, sep = string.match(first, "^(%d%d%d)([%s-])")
    if code ~= nil then
      info.code = code
      if sep == " " and #lines == 1 then
        info.text = ft_trim(string.sub(first, 5))
      end
    end
  end
  return info
end

local function ft_parse_pasv(text)
  local raw = tostring(text or "")
  local a, b, c, d, p1, p2 = string.match(raw, "(%d+),(%d+),(%d+),(%d+),(%d+),(%d+)")
  if a == nil then
    return nil
  end
  local port = tonumber(p1) * 256 + tonumber(p2)
  return {
    ip = string.format("%s.%s.%s.%s", a, b, c, d),
    port = port,
  }
end

local function ft_parse_epsv(text)
  local raw = tostring(text or "")
  local port = string.match(raw, "%|%|(%d+)%|")
  if port == nil then
    return nil
  end
  return { ip = nil, port = tonumber(port) }
end

local function ft_ip_class(ip)
  if type(ip) ~= "string" then
    return "unknown"
  end
  local a, b, c, d = string.match(ip, "^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if a == nil then
    return "invalid"
  end
  a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
  if a > 255 or b > 255 or c > 255 or d > 255 then
    return "invalid"
  end
  if a == 0 then
    return "this-network"
  end
  if a == 127 then
    return "loopback"
  end
  if a == 10 then
    return "private"
  end
  if a == 172 and b >= 16 and b <= 31 then
    return "private"
  end
  if a == 192 and b == 168 then
    return "private"
  end
  if a == 169 and b == 254 then
    return "link-local"
  end
  if a == 192 and b == 0 and c == 2 then
    return "documentation"
  end
  if a == 198 and b >= 51 and b <= 63 then
    return "benchmarking"
  end
  if a == 203 and b == 0 and c == 113 then
    return "documentation"
  end
  if a == 192 and b == 0 and c == 0 and d == 0 then
    return "any"
  end
  if a == 255 and b == 255 and c == 255 and d == 255 then
    return "broadcast"
  end
  if a == 224 or a > 239 then
    return "multicast-reserved"
  end
  return "public"
end

local function ft_eval_data_channel(addr, server_ip)
  local result = {
    classification = "ok",
    risk = "none",
    detail = "data channel address is consistent with the control host",
  }
  if addr == nil then
    result.classification = "unparsed"
    result.risk = "unknown"
    result.detail = "could not parse the advertised data-channel address"
    return result
  end
  if addr.ip ~= nil then
    local klass = ft_ip_class(addr.ip)
    if klass == "invalid" then
      result.classification = "invalid"
      result.risk = "high"
      result.detail = "advertised data address " .. addr.ip .. " is not a valid IPv4 address"
      return result
    end
    if klass == "any" or klass == "this-network" or klass == "broadcast" then
      result.classification = "non-routable"
      result.risk = "medium"
      result.detail = string.format("server advertises %s as the data-channel address; external clients cannot connect to the data channel", addr.ip)
      return result
    end
    if klass == "loopback" then
      result.classification = "loopback"
      result.risk = "medium"
      result.detail = "server advertises a loopback data-channel address; only the host itself can retrieve data"
      return result
    end
    if klass == "private" then
      result.classification = "private"
      result.risk = "medium"
      result.detail = string.format("server advertises RFC1918 address %s for the data channel; clients outside that network cannot complete transfers", addr.ip)
      return result
    end
    if server_ip ~= nil and addr.ip ~= server_ip then
      result.classification = "mismatch"
      result.risk = "medium"
      result.detail = string.format("server advertises %s for data but the control connection is to %s (NAT/proxy without address rewriting)", addr.ip, server_ip)
      return result
    end
  end
  local port = addr.port
  if port ~= nil then
    if port < 1024 then
      result.classification = "privileged-port"
      result.risk = "medium"
      result.detail = string.format("data channel advertised on privileged port %d (below 1024); unusual for a data channel", port)
      return result
    end
    if port >= 49152 and port <= 65535 then
      result.classification = "ephemeral-range"
      result.risk = "none"
      result.detail = string.format("data channel port %d is inside the IANA ephemeral range (RFC 6335)", port)
      return result
    end
    if port < 49152 then
      result.classification = "below-ephemeral"
      result.risk = "low"
      result.detail = string.format("data channel port %d is below the IANA ephemeral range; not insecure but atypical", port)
      return result
    end
  end
  return result
end

local function ft_parse_syst(text)
  local raw = tostring(text or "")
  local info = { code = nil, type = nil, os_hint = "unknown" }
  local code = string.match(raw, "^(%d%d%d)")
  if code ~= nil then
    info.code = code
  end
  local body = ft_lower(raw)
  if body:find("windows", 1, true) ~= nil or body:find("nt", 1, true) == 1 then
    info.type = "Windows"
    info.os_hint = "Windows"
  elseif body:find("unix", 1, true) ~= nil then
    local flavor = "Unix"
    if body:find("L8", 1, true) ~= nil then
      flavor = "Unix L8"
    end
    info.type = "UNIX"
    info.os_hint = flavor
  elseif body:find("vm", 1, true) == 1 then
    info.type = "VM"
    info.os_hint = "VM/OS"
  elseif body:find("dos", 1, true) ~= nil then
    info.type = "DOS"
    info.os_hint = "DOS-class"
  elseif body:find("mac", 1, true) ~= nil then
    info.type = "Mac"
    info.os_hint = "MacOS-class"
  end
  return info
end

local function ft_parse_feat(text)
  local raw = tostring(text or "")
  local info = { code = string.sub(raw, 1, 3), features = {}, lines = {}, raw = ft_trim(raw) }
  local first = true
  for line in (raw .. "\n"):gmatch("(.-)\r?\n") do
    local trimmed = ft_trim(line)
    if trimmed == "" then
      if first then
        first = false
      end
    elseif first then
      first = false
      local inline = string.match(trimmed, "^(%d%d%d)%s+(.*)$")
      if inline ~= nil and inline ~= "" then
        for token in string.gmatch(inline, "%S+") do
          info.features[string.upper(token)] = true
          table.insert(info.lines, token)
        end
      end
    else
      local name = string.match(trimmed, "^%s*([^%s;]+)")
      if name ~= nil and #name > 0 then
        table.insert(info.lines, trimmed)
        info.features[string.upper(name)] = true
      end
    end
  end
  return info
end

local FTP_FEATURE_RISKS = {
  SITE = {
    risk = "medium",
    detail = "SITE is implemented; on several daemons SITE exposes host-specific commands, historically including command execution (SITE EXEC) and file manipulation",
  },
  EXEC = {
    risk = "high",
    detail = "a command named EXEC is advertised; direct command execution surface on the control channel",
  },
  RNFR = {
    risk = "low",
    detail = "RNFR (rename from) is available; combined with writable directories it enables overwriting existing objects",
  },
  REST = {
    risk = "low",
    detail = "REST (restart) is available; restart semantics can be abused to craft partial uploads on writable servers",
  },
  MLST = {
    risk = "none",
    detail = "MLST provides machine-readable file metadata; convenient and low risk",
  },
  EPSV = {
    risk = "none",
    detail = "EPSV (IPv6-capable passive mode) is available",
  },
  AUTH = {
    risk = "none",
    detail = "AUTH is advertised; FTPS negotiation is offered",
  },
  PBSZ = {
    risk = "none",
    detail = "PBSZ (protection buffer size) is advertised",
  },
  PROT = {
    risk = "none",
    detail = "PROT (protection level) is advertised",
  },
  SIZE = {
    risk = "none",
    detail = "SIZE is available for file-length queries",
  },
  MDTM = {
    risk = "low",
    detail = "MDTM exposes last-modified timestamps; minor information disclosure",
  },
  UTF8 = {
    risk = "none",
    detail = "UTF8 filename handling is advertised",
  },
  CLNT = {
    risk = "low",
    detail = "CLNT (client identification) is accepted; client fingerprints are logged",
  },
  LANG = {
    risk = "none",
    detail = "LANG (language negotiation) is advertised",
  },
  SMNT = {
    risk = "low",
    detail = "SMNT (second mount point) is available; can expose alternate filesystem roots",
  },
  STAT = {
    risk = "low",
    detail = "STAT is available; can disclose session state and configuration details",
  },
}

local function ft_feature_risks(features)
  local out = {}
  if type(features) == "table" then
    for name in pairs(features) do
      local rule = FTP_FEATURE_RISKS[name]
      if rule ~= nil then
        out[#out + 1] = {
          feature = name,
          risk = rule.risk,
          detail = rule.detail,
        }
      end
    end
  end
  table.sort(out, function(a, b)
    return a.feature < b.feature
  end)
  return out
end

local function ft_parse_mlst_line(text)
  local facts = {}
  local raw = tostring(text or "")
  local body = string.match(raw, "^%s*%d%d%d%s*-?%s*(.*)$") or raw
  body = string.gsub(body, "^%S*%s*:%s*", "")
  for fact in string.gmatch(body, "([^;]+)") do
    local key, value = string.match(ft_trim(fact), "^([^=]+)=([^=]*)$")
    if key ~= nil then
      facts[string.upper(key)] = value
    end
  end
  return facts
end

local SENSITIVE_NAME_RULES = {
  { starts = { ".git", ".svn", ".hg" }, risk = "high", note = "version-control metadata exposure" },
  { starts = { ".env" }, risk = "high", note = "environment/credential file" },
  { ends = { ".pem", ".key", ".p12", ".pfx", ".jks" }, risk = "high", note = "private key material" },
  { plain = "id_rsa", risk = "high", note = "SSH key material" },
  { plain = "ssh_key", risk = "high", note = "SSH key material" },
  { ends = { ".sql", ".bak", ".old", ".orig", ".save", ".swp", ".tmp" }, risk = "medium", note = "backup or editor temp file" },
  { plain = "backup", risk = "medium", note = "backup artifact" },
  { plain = "dump", risk = "medium", note = "database dump artifact" },
  { plain = "database", risk = "medium", note = "database dump artifact" },
  { ends = { ".htaccess", ".htpasswd" }, risk = "medium", note = "Apache configuration or password file" },
  { ends = { ".config", ".conf", ".ini" }, risk = "low", note = "configuration file" },
}

local function name_ends(name, suffix)
  local n = #suffix
  return #name >= n and string.sub(name, -n) == suffix
end

local function ft_sensitivity(rawname)
  local lowered = ft_lower(rawname)
  for _, rule in ipairs(SENSITIVE_NAME_RULES) do
    local hit = false
    if rule.plain ~= nil then
      hit = lowered:find(rule.plain, 1, true) ~= nil
    end
    if not hit and rule.ends ~= nil then
      for _, suffix in ipairs(rule.ends) do
        if name_ends(lowered, suffix) then
          hit = true
          break
        end
      end
    end
    if not hit and rule.starts ~= nil then
      for _, prefix in ipairs(rule.starts) do
        if string.sub(lowered, 1, #prefix) == prefix then
          hit = true
          break
        end
      end
    end
    if hit then
      return rule.risk, rule.note
    end
  end
  return "none", nil
end

local function ft_parse_list_line(line)
  local entry = { raw = line, is_dir = false, world_writable = false, name = nil, size = nil }
  if type(line) ~= "string" then
    return entry
  end
  local trimmed = ft_trim(line)
  if trimmed == "" then
    return entry
  end
  local perms, links, owner, group, size, date, mon, day, name =
    string.match(trimmed,
    "^([%d%w%-]+)%s+(%d+)%s+(%S+)%s+(%S+)%s+(%d+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(.*)$")
  if perms ~= nil then
    entry.mode = perms
    entry.owner = owner
    entry.size = tonumber(size)
    entry.name = ft_trim(name)
    entry.is_dir = (perms:sub(1, 1) == "d")
    entry.world_writable = (perms:sub(9, 9) == "w") or (perms:sub(10, 10) == "s")
    entry.layout = "unix"
    return entry
  end
  local wdate, wsize, wname = string.match(trimmed,
    "^(%d%d%d%d%-%d%d%-%d%d)%s+%d%d:%d%d%s+([%d: %APM<>]+)%s+(.*)$")
  if wdate ~= nil then
    entry.date = wdate
    local dirmark = string.match(wsize, "<DIR>")
    if dirmark ~= nil then
      entry.is_dir = true
      entry.size = nil
    else
      entry.is_dir = false
      entry.size = tonumber(string.match(wsize, "%d+"))
    end
    entry.name = ft_trim(wname)
    entry.layout = "windows"
    return entry
  end
  entry.name = trimmed
  entry.layout = "bare"
  return entry
end

local function ft_classify_listing(entries, limit)
  local dirs = {}
  local files = 0
  local sensitive = {}
  local world_writable = {}
  local ww_seen = {}
  local sensitive_seen = {}
  for _, entry in ipairs(entries or {}) do
    if entry.is_dir then
      dirs[#dirs + 1] = entry.name
    else
      files = files + 1
    end
    if entry.world_writable and entry.name ~= nil and ww_seen[entry.name] == nil then
      ww_seen[entry.name] = true
      world_writable[#world_writable + 1] = entry.name
    end
    if entry.name ~= nil and entry.name ~= "" and sensitive_seen[entry.name] == nil and #sensitive < (limit or 10) then
      local risk, note = ft_sensitivity(entry.name)
      if risk ~= "none" then
        sensitive_seen[entry.name] = true
        sensitive[#sensitive + 1] = { name = entry.name, risk = risk, note = note }
      end
    end
  end
  return { dirs = dirs, files = files, sensitive = sensitive, world_writable = world_writable }
end

local function ft_cwd_probe_set()
  return {
    { path = "/../../", label = "double-dot from root" },
    { path = "/../", label = "single dot-dot from root" },
    { path = "/..", label = "bare dot-dot" },
    { path = "/etc", label = "absolute system path" },
    { path = "/etc/passwd", label = "absolute system file path" },
    { path = "/root", label = "absolute home path" },
    { path = "/../../etc", label = "chained traversal" },
    { path = "....//....//etc/passwd", label = "filter-evasion traversal" },
  }
end

local function ft_cwd_classify(code, path)
  if code == "250" then
    return "escaped", "server accepted CWD to " .. path .. "; the root is not confined to a jail"
  end
  if code == "550" then
    return "contained", "server rejected CWD to " .. path
  end
  if code == "501" then
    return "normalized", "server could not parse " .. path .. " (path normalization in effect)"
  end
  if code == nil then
    return "no-response", "no response to CWD " .. path
  end
  return "other", "server answered " .. code .. " to CWD " .. path
end

local function ft_login_classify(user_code, pass_code, user_text, pass_text)
  if pass_code == "230" then
    return "success", "login accepted"
  end
  if user_code == "534" then
    return "tls-required", "server requires AUTH before proceeding"
  end
  if user_code == "530" then
    local text = ft_lower((user_text or "") .. " " .. (pass_text or ""))
    if text:find("tls", 1, true) ~= nil or text:find("secure", 1, true) ~= nil then
      return "tls-required", "login refused with a TLS hint"
    end
    return "refused", "login refused by the server"
  end
  if user_code == "421" or pass_code == "421" then
    return "lockout", "control connection closed (possible lockout or rate limit)"
  end
  if user_code == nil and pass_code == nil then
    return "no-response", "server did not answer the login exchange"
  end
  return "refused", string.format("login rejected (USER %s, PASS %s)", tostring(user_code), tostring(pass_code))
end

local function ft_auth_classify(feat_features, tls_code, ssl_code)
  local state = {
    tls_offered = false,
    ssl_offered = false,
    tls_accepted = (tostring(tls_code) == "234"),
    ssl_accepted = (tostring(ssl_code) == "234"),
  }
  if type(feat_features) == "table" then
    for name in pairs(feat_features) do
      local upper = name
      if upper == "AUTH" or upper == "AUTH TLS" then
        state.tls_offered = true
      end
      if upper == "AUTH SSL" then
        state.ssl_offered = true
      end
    end
  end
  if state.tls_accepted then
    state.tls_offered = true
  end
  return state
end

local function ft_tls_version_risk(version_code)
  if version_code == 0x0300 then
    return "high", "SSLv3 is broken (POODLE, CVE-2014-3566)"
  end
  if version_code == 0x0301 then
    return "medium", "TLS 1.0 is deprecated (RFC 8996) and weak by modern standards"
  end
  if version_code == 0x0302 then
    return "medium", "TLS 1.1 is deprecated (RFC 8996)"
  end
  if version_code == 0x0303 then
    return "none", "TLS 1.2 is acceptable"
  end
  if version_code == 0x0304 then
    return "none", "TLS 1.3 is current"
  end
  return "none", nil
end

local function ft_port_target_label(ip)
  local klass = ft_ip_class(ip)
  if klass == "documentation" or klass == "benchmarking" then
    return "documentation/benchmarking range (no real host, safe probe target)"
  end
  return klass
end

local function tl_u16(n)
  return string.char(math.floor(n / 256) % 256, n % 256)
end

local function tl_u24(n)
  return string.char(math.floor(n / 65536) % 256, math.floor(n / 256) % 256, n % 256)
end

local function tl_u32(n)
  return string.char(math.floor(n / 16777216) % 256, math.floor(n / 65536) % 256,
    math.floor(n / 256) % 256, n % 256)
end

local function tl_b16(b)
  return b:byte(1) * 256 + b:byte(2)
end

local function tl_b24(b)
  return b:byte(1) * 65536 + b:byte(2) * 256 + b:byte(3)
end

local function tl_b32(b)
  return b:byte(1) * 16777216 + b:byte(2) * 65536 + b:byte(3) * 256 + b:byte(4)
end

local function tl_record(type_byte, version, payload)
  return string.char(type_byte) .. tl_u16(version or 0x0303) .. tl_u16(#payload) .. payload
end

local function tl_handshake(type_byte, body)
  return string.char(type_byte) .. tl_u24(#body) .. body
end

local function tl_client_hello(opts)
  opts = opts or {}
  local version = opts.version or 0x0303
  local random = opts.random or string.char(
    0xa1, 0x4f, 0x02, 0x9c, 0x77, 0x1b, 0xd3, 0x40,
    0x55, 0x90, 0xe8, 0x2f, 0x66, 0xab, 0x17, 0xc3,
    0x09, 0xd4, 0x2a, 0x58, 0xb1, 0x3e, 0x88, 0x72,
    0xe6, 0x04, 0xc9, 0xd5, 0x11, 0xfa, 0x6b, 0x20)
  local session_id = opts.session_id or ""
  local ciphers = opts.ciphers or { 0xc02f, 0xc030, 0x009c, 0x009d, 0x1301, 0x1302 }
  local comps = opts.comps or { 0 }
  local list = ""
  for _, c in ipairs(ciphers) do
    list = list .. tl_u16(c)
  end
  local comp_list = ""
  for _, c in ipairs(comps) do
    comp_list = comp_list .. string.char(c)
  end
  local exts = ""
  local function add_ext(id, data)
    exts = exts .. tl_u16(id) .. tl_u16(#data) .. data
  end
  if opts.sni then
    local entry = string.char(0) .. tl_u16(#opts.sni) .. opts.sni
    local inner = tl_u16(#entry) .. entry
    add_ext(0, inner)
  end
  if opts.ems ~= false then
    add_ext(0x0017, string.char(0))
  end
  if opts.alpn then
    local al = ""
    for _, p in ipairs(opts.alpn) do
      al = al .. string.char(#p) .. p
    end
    add_ext(16, tl_u16(#al) .. al)
  end
  if opts.status_request then
    add_ext(5, string.char(1, 0))
  end
  if opts.sig_algs then
    local sa = ""
    for _, s in ipairs(opts.sig_algs) do
      sa = sa .. tl_u16(s)
    end
    add_ext(13, tl_u16(#sa) .. sa)
  end
  if opts.supported_versions then
    local sv = ""
    for _, v in ipairs(opts.supported_versions) do
      sv = sv .. tl_u16(v)
    end
    add_ext(43, string.char(#sv) .. sv)
  end
  if opts.heartbeat then
    add_ext(15, tl_u16(1))
  end
  if opts.renegotiation_info then
    add_ext(0xff01, string.char(1, 0))
  end
  if opts.raw_exts then
    for _, re in ipairs(opts.raw_exts) do
      exts = exts .. tl_u16(re.id) .. tl_u16(#re.data) .. re.data
    end
  end
  local body = tl_u16(opts.record_version or version)
    .. random
    .. string.char(#session_id) .. session_id
    .. tl_u16(#list) .. list
    .. string.char(#comps) .. comp_list
    .. tl_u16(#exts) .. exts
  return tl_record(0x16, version, tl_handshake(0x01, body))
end

local function tl_parse_records(buf)
  local records = {}
  local i = 1
  while i + 4 <= #buf do
    local t = buf:byte(i)
    local v = tl_b16(buf:sub(i + 1, i + 2))
    local l = tl_b16(buf:sub(i + 3, i + 4))
    if i + 4 + l > #buf then
      break
    end
    records[#records + 1] = { type = t, version = v, payload = buf:sub(i + 5, i + 4 + l) }
    i = i + 5 + l
  end
  return records
end

local function tl_parse_handshake_messages(payload)
  local msgs = {}
  local i = 1
  while i + 3 <= #payload do
    local t = payload:byte(i)
    local l = tl_b24(payload:sub(i + 1, i + 3))
    if i + 3 + l > #payload then
      break
    end
    msgs[#msgs + 1] = { type = t, body = payload:sub(i + 4, i + 3 + l) }
    i = i + 4 + l
  end
  return msgs
end

local function tl_parse_extensions(body, off)
  local exts = {}
  if off == nil or off + 2 > #body then
    return exts, off
  end
  local total = tl_b16(body:sub(off, off + 1))
  local end_at = off + 2 + total
  local i = off + 2
  while i + 4 <= end_at and i + 3 <= #body do
    local id = tl_b16(body:sub(i, i + 1))
    local len = tl_b16(body:sub(i + 2, i + 3))
    exts[id] = body:sub(i + 4, i + 3 + len)
    i = i + 4 + len
  end
  return exts, i
end

local function tl_parse_server_hello(body)
  local out = {}
  if #body < 2 then
    return out
  end
  out.version = tl_b16(body:sub(1, 2))
  out.random = #body >= 34 and body:sub(3, 34) or nil
  if #body < 35 then
    return out
  end
  local sid_len = body:byte(35)
  if 35 + sid_len + 3 > #body then
    return out
  end
  out.session_id = body:sub(36, 35 + sid_len)
  local ci = 36 + sid_len
  out.cipher = tl_b16(body:sub(ci, ci + 1))
  out.compression = body:byte(ci + 2) or 0
  local ext_off = ci + 3
  if ext_off + 1 <= #body then
    out.extensions = tl_parse_extensions(body, ext_off)
  end
  return out
end

local function tl_parse_certificate(body)
  local out = { certs = {} }
  local total = tl_b24(body:sub(1, 3))
  local i = 4
  local end_at = 4 + total
  while i + 3 <= end_at and i + 3 <= #body do
    local l = tl_b24(body:sub(i, i + 2))
    out.certs[#out.certs + 1] = body:sub(i + 3, i + 2 + l)
    i = i + 3 + l
  end
  return out
end

local function tl_parse_server_key_exchange(body)
  local out = {}
  local i = 1
  if i + 1 > #body then
    return out
  end
  local p_len = tl_b16(body:sub(i, i + 1))
  if i + 1 + p_len > #body then
    return out
  end
  out.dh_prime = body:sub(i + 2, i + 1 + p_len)
  out.prime_bits = #out.dh_prime * 8
  i = i + 2 + p_len
  if i > #body then
    return out
  end
  local g_len = body:byte(i)
  if i + g_len > #body then
    return out
  end
  out.dh_gen = body:sub(i + 1, i + g_len)
  i = i + 1 + g_len
  if i + 1 <= #body then
    out.sig_len = tl_b16(body:sub(i, i + 1))
    i = i + 2
    if i <= #body then
      out.hash_len = body:byte(i)
    end
  end
  return out
end

local function tl_parse_alert(body)
  return { level = body:byte(1), code = body:byte(2) }
end

local function tl_parse_certificate_status(body)
  local out = { status_type = body:byte(1) }
  if out.status_type == 1 then
    local l = tl_b24(body:sub(2, 4))
    out.ocsp_len = l
    out.ocsp = body:sub(5, 4 + l)
  end
  return out
end

local function tl_parse_heartbeat(body)
  local out = {
    type = body:byte(1),
    payload_len = tl_b16(body:sub(2, 3)),
    random = body:sub(4, 19),
  }
  local data_end = math.min(19 + out.payload_len, #body)
  out.data = body:sub(20, data_end)
  out.trailer = #body - data_end
  return out
end

local function tl_alpn_selected(body)
  if body == nil or #body < 3 then
    return nil
  end
  local l = tl_b16(body:sub(1, 2))
  if l < 1 or 2 + l > #body then
    return nil
  end
  return body:sub(3, 2 + l)
end

local function tl_dh_prime_bits(prime)
  if prime == nil or #prime == 0 then
    return nil
  end
  local i = 1
  while i < #prime and prime:byte(i) == 0 do
    i = i + 1
  end
  if i > #prime then
    return 0
  end
  local top = prime:byte(i)
  local bits = 0
  while top > 0 do
    bits = bits + 1
    top = math.floor(top / 2)
  end
  return (#prime - i) * 8 + bits
end

local TL_ALERT_NAMES = {
  [0] = "close_notify", [10] = "unexpected_message", [20] = "bad_record_mac",
  [30] = "handshake_failure", [40] = "bad_certificate",
  [45] = "unsupported_certificate", [46] = "certificate_unknown",
  [50] = "decrypt_error", [70] = "protocol_version",
  [71] = "insufficient_security", [80] = "internal_error",
  [86] = "inappropriate_fallback", [90] = "user_canceled",
  [100] = "no_renegotiation", [109] = "missing_extension",
  [110] = "unsupported_extension", [112] = "unrecognized_name",
  [113] = "bad_certificate_status_response", [115] = "unknown_psk_identity",
  [116] = "certificate_required", [120] = "no_application_protocol",
}

local function tl_alert_name(level, code)
  if level == 2 then
    return "fatal:" .. (TL_ALERT_NAMES[code] or ("0x%02x"):format(code))
  end
  return "warning:" .. (TL_ALERT_NAMES[code] or ("0x%02x"):format(code))
end

local function tl_alert_record(code, version)
  return tl_record(0x15, version or 0x0303, string.char(2, code))
end

local TL_VERSION_NAMES = {
  [0x0300] = "SSL 3.0",
  [0x0301] = "TLS 1.0",
  [0x0302] = "TLS 1.1",
  [0x0303] = "TLS 1.2",
  [0x0304] = "TLS 1.3",
}

local function tl_version_name(v)
  return TL_VERSION_NAMES[v] or string.format("0x%04x", v or 0)
end

local function tl_der_tlv(data, off)
  local tag = data:byte(off)
  local len = data:byte(off + 1)
  local hdr = 2
  if len >= 0x80 then
    local n = len - 0x80
    if off + 1 + n > #data then
      return nil
    end
    len = 0
    for i = 1, n do
      len = len * 256 + data:byte(off + 1 + i)
    end
    hdr = 2 + n
  end
  if off + hdr + len - 1 > #data then
    return nil
  end
  return {
    tag = tag,
    len = len,
    hdr = hdr,
    content = data:sub(off + hdr, off + hdr + len - 1),
    next = off + hdr + len,
  }
end

local function tl_der_walk(data)
  local nodes = {}
  local function walk(off, depth)
    local t = tl_der_tlv(data, off)
    if t == nil then
      return nil
    end
    local idx = #nodes + 1
    nodes[idx] = {
      tag = t.tag, len = t.len, content = t.content,
      start = off, end_at = t.next, depth = depth, index = idx,
    }
    if t.tag == 0x30 or t.tag == 0x31 or (t.tag >= 0xa0 and t.tag <= 0xbf) then
      local i = off + t.hdr
      while i < t.next do
        i = walk(i, depth + 1)
        if i == nil then
          break
        end
      end
    end
    return t.next
  end
  walk(1, 0)
  return nodes
end

local function tl_child_list(nodes, parent)
  local list = {}
  local i = parent.index + 1
  while i <= #nodes do
    local n = nodes[i]
    if n == nil or n.start >= parent.end_at then
      break
    end
    if n.depth == parent.depth + 1 then
      list[#list + 1] = n
    end
    i = i + 1
  end
  return list
end

local TL_OID_NAMES = {
  ["1.2.840.113549.1.1.1"] = "rsaEncryption",
  ["1.2.840.113549.1.1.2"] = "md2WithRSAEncryption",
  ["1.2.840.113549.1.1.4"] = "md5WithRSAEncryption",
  ["1.2.840.113549.1.1.5"] = "sha1WithRSAEncryption",
  ["1.2.840.113549.1.1.11"] = "sha256WithRSAEncryption",
  ["1.2.840.113549.1.1.12"] = "sha384WithRSAEncryption",
  ["1.2.840.113549.1.1.13"] = "sha512WithRSAEncryption",
  ["1.2.840.113549.1.1.14"] = "sha224WithRSAEncryption",
  ["1.2.840.113549.1.1.15"] = "sha512-224WithRSAEncryption",
  ["1.2.840.113549.1.1.16"] = "sha512-256WithRSAEncryption",
  ["1.2.840.10045.2.1"] = "ecPublicKey",
  ["2.5.29.14"] = "keyUsage",
  ["2.5.29.15"] = "extendedKeyUsage",
  ["2.5.29.17"] = "subjectAltName",
  ["2.5.29.19"] = "basicConstraints",
  ["2.5.29.31"] = "crlDistributionPoints",
  ["1.3.6.1.5.5.7.1.1"] = "authorityInfoAccess",
  ["1.3.6.1.5.5.7.48.1"] = "ocsp",
  ["1.3.6.1.5.5.7.48.5"] = "caIssuers",
}

local TL_NAME_OIDS = {
  ["2.5.4.3"] = "CN",
  ["2.5.4.4"] = "SN",
  ["2.5.4.5"] = "serialNumber",
  ["2.5.4.6"] = "C",
  ["2.5.4.7"] = "L",
  ["2.5.4.8"] = "ST",
  ["2.5.4.9"] = "street",
  ["2.5.4.10"] = "O",
  ["2.5.4.11"] = "OU",
  ["0.9.2342.19200300.100.1.25"] = "DC",
  ["1.3.6.1.4.1.311.60.2.1.3"] = "jurisdictionC",
}

local function tl_der_oid_str(data)
  if data == nil or #data == 0 then
    return nil
  end
  local parts = {}
  local i = 1
  local function read_arc()
    local v = 0
    while i <= #data do
      local b = data:byte(i)
      i = i + 1
      v = v * 128 + (b & 0x7f)
      if (b & 0x80) == 0 then
        break
      end
    end
    return v
  end
  local first = data:byte(1)
  i = 2
  if first < 40 then
    parts[1] = "0." .. first
  elseif first < 80 then
    parts[1] = "1." .. (first - 40)
  else
    parts[1] = "2.5"
  end
  local rest = read_arc()
  parts[#parts + 1] = tostring(rest)
  while i <= #data do
    parts[#parts + 1] = tostring(read_arc())
  end
  return table.concat(parts, ".")
end

local function tl_der_name_str(nodes, parent)
  local parts = {}
  for _, rdn in ipairs(tl_child_list(nodes, parent)) do
    if rdn.tag == 0x31 then
      local attrs = {}
      for _, attr in ipairs(tl_child_list(nodes, rdn)) do
        if attr.tag == 0x30 then
          local ac = tl_child_list(nodes, attr)
          local oid_n = ac[1]
          local val_n = ac[2]
          if oid_n ~= nil and oid_n.tag == 0x06 and val_n ~= nil then
            local oid = tl_der_oid_str(oid_n.content)
            local label = TL_NAME_OIDS[oid] or oid
            attrs[#attrs + 1] = label .. "=" .. val_n.content
          end
        end
      end
      if #attrs > 0 then
        parts[#parts + 1] = table.concat(attrs, ", ")
      end
    end
  end
  return table.concat(parts, " / ")
end

local function tl_der_name_key(nodes, parent)
  local parts = {}
  for _, rdn in ipairs(tl_child_list(nodes, parent)) do
    if rdn.tag == 0x31 then
      local attrs = {}
      for _, attr in ipairs(tl_child_list(nodes, rdn)) do
        if attr.tag == 0x30 then
          local ac = tl_child_list(nodes, attr)
          local oid_n = ac[1]
          local val_n = ac[2]
          if oid_n ~= nil and oid_n.tag == 0x06 and val_n ~= nil then
            local oid = tl_der_oid_str(oid_n.content)
            local label = TL_NAME_OIDS[oid] or oid
            attrs[#attrs + 1] = label .. "=" .. val_n.content
          end
        end
      end
      if #attrs > 0 then
        table.sort(attrs)
        parts[#parts + 1] = table.concat(attrs, ",")
      end
    end
  end
  table.sort(parts)
  return table.concat(parts, "/")
end

local function tl_der_int_value(data)
  if data == nil or #data == 0 then
    return nil
  end
  local v = 0
  for i = 1, #data do
    v = v * 256 + data:byte(i)
  end
  return v
end

local function tl_utctime_to_epoch(s)
  if s == nil or #s < 12 then
    return nil
  end
  local yy = tonumber(s:sub(1, 2))
  local mm = tonumber(s:sub(3, 4))
  local dd = tonumber(s:sub(5, 6))
  local hh = tonumber(s:sub(7, 8))
  local mi = tonumber(s:sub(9, 10))
  local ss = tonumber(s:sub(11, 12))
  if yy == nil or mm == nil or dd == nil then
    return nil
  end
  hh = hh or 0
  mi = mi or 0
  ss = ss or 0
  if yy < 50 then
    yy = yy + 2000
  else
    yy = yy + 1900
  end
  local days = 0
  for y = 1970, yy - 1 do
    days = days + 365
    if (y % 4 == 0 and y % 100 ~= 0) or y % 400 == 0 then
      days = days + 1
    end
  end
  local mdays = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
  if (yy % 4 == 0 and yy % 100 ~= 0) or yy % 400 == 0 then
    mdays[2] = 29
  end
  for m = 1, mm - 1 do
    days = days + mdays[m]
  end
  days = days + dd - 1
  return days * 86400 + hh * 3600 + mi * 60 + ss
end

local function tl_gentime_to_epoch(s)
  if s == nil or #s < 14 then
    return nil
  end
  local yyyy = tonumber(s:sub(1, 4))
  local mm = tonumber(s:sub(5, 6))
  local dd = tonumber(s:sub(7, 8))
  local hh = tonumber(s:sub(9, 10))
  local mi = tonumber(s:sub(11, 12))
  local ss = tonumber(s:sub(13, 14))
  if yyyy == nil or mm == nil or dd == nil then
    return nil
  end
  hh = hh or 0
  mi = mi or 0
  ss = ss or 0
  local days = 0
  for y = 1970, yyyy - 1 do
    days = days + 365
    if (y % 4 == 0 and y % 100 ~= 0) or y % 400 == 0 then
      days = days + 1
    end
  end
  local mdays = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
  if (yyyy % 4 == 0 and yyyy % 100 ~= 0) or yyyy % 400 == 0 then
    mdays[2] = 29
  end
  for m = 1, mm - 1 do
    days = days + mdays[m]
  end
  days = days + dd - 1
  return days * 86400 + hh * 3600 + mi * 60 + ss
end

local function tl_parse_time(tag, content)
  if tag == 0x17 then
    return tl_utctime_to_epoch(content)
  end
  if tag == 0x18 then
    return tl_gentime_to_epoch(content)
  end
  return nil
end

local function tl_x509_parse(der)
  local cert = { raw_len = #der }
  local nodes = tl_der_walk(der)
  local root = nodes[1]
  if root == nil or root.tag ~= 0x30 or #nodes < 5 then
    return cert
  end
  local tbs = tl_child_list(nodes, root)[1]
  if tbs == nil or tbs.tag ~= 0x30 then
    return cert
  end
  local fields = tl_child_list(nodes, tbs)
  local pos = 1
  local function next_field()
    local n = fields[pos]
    if n == nil then
      return nil
    end
    pos = pos + 1
    return n
  end
  local n = next_field()
  if n ~= nil and n.tag == 0xa0 then
    cert.version = 2
  else
    cert.version = 1
    pos = pos - 1
  end
  n = next_field()
  if n ~= nil and n.tag == 0x02 then
    cert.serial = tl_der_int_value(n.content)
  end
  n = next_field()
  if n ~= nil and n.tag == 0x30 then
    local alg = tl_child_list(nodes, n)
    local oid = alg[1]
    if oid ~= nil and oid.tag == 0x06 then
      cert.sig_oid = tl_der_oid_str(oid.content)
      cert.sig_algorithm = TL_OID_NAMES[cert.sig_oid] or cert.sig_oid
    end
  end
  n = next_field()
  if n ~= nil and n.tag == 0x30 then
    cert.issuer = tl_der_name_str(nodes, n)
    cert.issuer_key = tl_der_name_key(nodes, n)
  end
  n = next_field()
  if n ~= nil and n.tag == 0x30 then
    local times = {}
    for _, c in ipairs(tl_child_list(nodes, n)) do
      if c.tag == 0x17 or c.tag == 0x18 then
        times[#times + 1] = c
      end
    end
    if #times >= 1 then
      cert.not_before = tl_parse_time(times[1].tag, times[1].content)
      cert.not_before_raw = times[1].content
    end
    if #times >= 2 then
      cert.not_after = tl_parse_time(times[#times].tag, times[#times].content)
      cert.not_after_raw = times[#times].content
    end
  end
  n = next_field()
  if n ~= nil and n.tag == 0x30 then
    cert.subject = tl_der_name_str(nodes, n)
    cert.subject_key = tl_der_name_key(nodes, n)
  end
  n = next_field()
  if n ~= nil and n.tag == 0x30 then
    cert.spki = {}
    local children = tl_child_list(nodes, n)
    local alg = children[1]
    if alg ~= nil and alg.tag == 0x30 then
      local oid = tl_child_list(nodes, alg)[1]
      if oid ~= nil and oid.tag == 0x06 then
        cert.spki.oid = tl_der_oid_str(oid.content)
        cert.spki.algorithm = TL_OID_NAMES[cert.spki.oid] or cert.spki.oid
      end
    end
    for _, c in ipairs(children) do
      if c.tag == 0x03 then
        local key_bytes = c.content:sub(2)
        local inner = tl_der_walk(key_bytes)
        local ints = {}
        for _, ic in ipairs(inner) do
          if ic.tag == 0x02 then
            ints[#ints + 1] = ic
          end
        end
        if cert.spki.algorithm == "rsaEncryption" and #ints >= 1 then
          local modulus = ints[1].content
          if #modulus > 0 and modulus:byte(1) == 0 then
            modulus = modulus:sub(2)
          end
          local rsa_bits = 0
          if #modulus > 0 then
            local first = modulus:byte(1)
            local top = 0
            while first > 0 do
              top = top + 1
              first = math.floor(first / 2)
            end
            rsa_bits = (#modulus - 1) * 8 + top
          end
          cert.spki.bits = rsa_bits
          cert.spki.type = "RSA"
        end
        if cert.spki.algorithm == "ecPublicKey" then
          cert.spki.type = "EC"
        end
        break
      end
    end
  end
  for _, c in ipairs(fields) do
    if c.tag == 0xa3 then
      cert.extensions = {}
      local list = tl_child_list(nodes, c)[1]
      if list ~= nil and list.tag == 0x30 then
        for _, e in ipairs(tl_child_list(nodes, list)) do
          if e.tag == 0x30 then
            local ec = tl_child_list(nodes, e)
            local oid_n = ec[1]
            local val_n = ec[2]
            if oid_n ~= nil and oid_n.tag == 0x06 and val_n ~= nil and val_n.tag == 0x04 then
              local oid = tl_der_oid_str(oid_n.content)
              local entry = { oid = oid, name = TL_OID_NAMES[oid] or oid, value = val_n.content }
              if oid == "2.5.29.17" then
                entry.sans = {}
                local san_nodes = tl_der_walk(val_n.content)
                for _, sn in ipairs(san_nodes) do
                  if sn.tag == 0x82 then
                    entry.sans[#entry.sans + 1] = { type = "DNS", value = sn.content }
                  elseif sn.tag == 0x87 then
                    entry.sans[#entry.sans + 1] = { type = "IP", value = sn.content }
                  elseif sn.tag == 0x84 then
                    entry.sans[#entry.sans + 1] = { type = "URI", value = sn.content }
                  elseif sn.tag == 0x88 then
                    entry.sans[#entry.sans + 1] = { type = "email", value = sn.content }
                  end
                end
              end
              cert.extensions[#cert.extensions + 1] = entry
            end
          end
        end
      end
      break
    end
  end
  cert.self_signed = (cert.issuer_key ~= nil and cert.subject_key ~= nil and cert.issuer_key == cert.subject_key)
  return cert
end

local function tl_hex(data)
  if data == nil then
    return ""
  end
  local out = {}
  for i = 1, #data do
    out[#out + 1] = string.format("%02x", data:byte(i))
  end
  return table.concat(out)
end

local function tl_days_between(a, b)
  if a == nil or b == nil then
    return nil
  end
  return math.floor(math.abs(b - a) / 86400)
end

local TL_VERSIONS = {
  [0x0300] = "SSLv3",
  [0x0301] = "TLS 1.0",
  [0x0302] = "TLS 1.1",
  [0x0303] = "TLS 1.2",
  [0x0304] = "TLS 1.3",
}

local TL_CIPHER_INFO = {
  [0x0001] = { name = "TLS_RSA_WITH_NULL_MD5", kx = "RSA", cipher = "NULL", mac = "MD5" },
  [0x0002] = { name = "TLS_RSA_WITH_NULL_SHA", kx = "RSA", cipher = "NULL", mac = "SHA1" },
  [0x0003] = { name = "TLS_RSA_WITH_RC4_128_MD5", kx = "RSA", cipher = "RC4", mac = "MD5" },
  [0x0005] = { name = "TLS_RSA_WITH_RC4_128_SHA", kx = "RSA", cipher = "RC4", mac = "SHA1" },
  [0x0006] = { name = "TLS_RSA_WITH_DES_CBC_SHA", kx = "RSA", cipher = "DES", mac = "SHA1" },
  [0x0004] = { name = "TLS_RSA_WITH_RC4_40_MD5", kx = "RSA", cipher = "RC4", mac = "MD5" },
  [0x0007] = { name = "TLS_RSA_WITH_3DES_EDE_CBC_SHA", kx = "RSA", cipher = "3DES", mac = "SHA1" },
  [0x000a] = { name = "TLS_RSA_WITH_3DES_EDE_CBC_SHA", kx = "RSA", cipher = "3DES", mac = "SHA1" },
  [0x0008] = { name = "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA", kx = "DH_d", cipher = "3DES", mac = "SHA1" },
  [0x0009] = { name = "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA", kx = "DH_s", cipher = "3DES", mac = "SHA1" },
  [0x000c] = { name = "TLS_EDH_RSA_WITH_3DES_EDE_CBC_SHA", kx = "DHE", cipher = "3DES", mac = "SHA1" },
  [0x000d] = { name = "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", kx = "DHE", cipher = "3DES", mac = "SHA1" },
  [0x0013] = { name = "TLS_RSA_WITH_IDEA_CBC_SHA", kx = "RSA", cipher = "IDEA", mac = "SHA1" },
  [0x0016] = { name = "TLS_KRB5_WITH_RC4_128_SHA", kx = "KRB5", cipher = "RC4", mac = "SHA1" },
  [0x0019] = { name = "TLS_KRB5_WITH_DES_CBC_SHA", kx = "KRB5", cipher = "DES", mac = "SHA1" },
  [0x001c] = { name = "TLS_KRB5_WITH_3DES_EDE_CBC_SHA", kx = "KRB5", cipher = "3DES", mac = "SHA1" },
  [0x002f] = { name = "TLS_RSA_WITH_AES_128_CBC_SHA", kx = "RSA", cipher = "AES128", mac = "SHA1" },
  [0x0033] = { name = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", kx = "DHE", cipher = "AES128", mac = "SHA1" },
  [0x0035] = { name = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", kx = "DHE", cipher = "AES256", mac = "SHA1" },
  [0x0039] = { name = "TLS_RSA_WITH_AES_128_GCM_SHA256", kx = "RSA", cipher = "AES128-GCM", mac = "SHA256" },
  [0x003c] = { name = "TLS_RSA_WITH_AES_256_CBC_SHA", kx = "RSA", cipher = "AES256", mac = "SHA1" },
  [0x0067] = { name = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", kx = "DHE", cipher = "AES128-GCM", mac = "SHA256" },
  [0x006b] = { name = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", kx = "DHE", cipher = "AES256-GCM", mac = "SHA384" },
  [0x009c] = { name = "TLS_RSA_WITH_AES_256_GCM_SHA384", kx = "RSA", cipher = "AES256-GCM", mac = "SHA384" },
  [0x009d] = { name = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", kx = "DHE", cipher = "AES128-GCM", mac = "SHA256" },
  [0xc008] = { name = "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", kx = "ECDHE", cipher = "3DES", mac = "SHA1" },
  [0xc009] = { name = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", kx = "ECDHE", cipher = "AES128", mac = "SHA1" },
  [0xc00a] = { name = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", kx = "ECDHE", cipher = "AES256", mac = "SHA1" },
  [0xc012] = { name = "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA", kx = "ECDHE", cipher = "3DES", mac = "SHA1" },
  [0xc023] = { name = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", kx = "ECDHE", cipher = "AES128", mac = "SHA1" },
  [0xc027] = { name = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", kx = "ECDHE", cipher = "AES256", mac = "SHA1" },
  [0xc02b] = { name = "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", kx = "ECDHE", cipher = "3DES", mac = "SHA1" },
  [0xc02f] = { name = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", kx = "ECDHE", cipher = "AES128-GCM", mac = "SHA256" },
  [0xc030] = { name = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", kx = "ECDHE", cipher = "AES256-GCM", mac = "SHA384" },
  [0xcc0a] = { name = "TLS_PSK_WITH_3DES_EDE_CBC_SHA", kx = "PSK", cipher = "3DES", mac = "SHA1" },
  [0x1301] = { name = "TLS_AES_128_GCM_SHA256", kx = "(1.3)", cipher = "AES128-GCM", mac = "SHA256" },
  [0x1302] = { name = "TLS_AES_256_GCM_SHA384", kx = "(1.3)", cipher = "AES256-GCM", mac = "SHA384" },
  [0x1303] = { name = "TLS_CHACHA20_POLY1305_SHA256", kx = "(1.3)", cipher = "CHACHA20", mac = "SHA256" },
}

local function tl_cipher_name(id)
  local info = TL_CIPHER_INFO[id]
  if info ~= nil then
    return info.name
  end
  return string.format("0x%04x", id or 0)
end

local function tl_cipher_class(id)
  local info = TL_CIPHER_INFO[id]
  if info == nil then
    return "unknown"
  end
  if info.cipher == "NULL" then
    return "null"
  end
  if info.cipher == "RC4" then
    return "rc4"
  end
  if info.cipher == "DES" then
    return "export-des"
  end
  if info.cipher == "3DES" then
    return "3des"
  end
  if info.mac == "MD5" then
    return "md5"
  end
  if info.kx == "KRB5" and (info.cipher == "RC4" or info.cipher == "DES" or info.cipher == "3DES") then
    return "krb5-legacy"
  end
  return "acceptable"
end

local function tl_connect(host, port)
  local sock = nmap.new_socket("tcp")
  local ok, err = sock:connect(host.ip, port)
  if not ok then
    return nil, err
  end
  sock:set_timeout(10)
  return sock, nil
end

local function tl_read_record(sock)
  local ok, hdr, rerr = sock:receive_bytes(5)
  if not ok or hdr == nil or #hdr < 5 then
    return nil, rerr or "TIMEOUT"
  end
  local rtype = hdr:byte(1)
  local rlen = hdr:byte(4) * 256 + hdr:byte(5)
  local ok2, payload, rerr2 = sock:receive_bytes(rlen)
  if not ok2 or payload == nil then
    return nil, rerr2 or "TIMEOUT"
  end
  return { type = rtype, version = hdr:byte(2) * 256 + hdr:byte(3), payload = payload }, nil
end

local function tl_collect_server_flight(sock, limit)
  local msgs = {}
  local alert = nil
  for _ = 1, limit or 12 do
    local rec, err = tl_read_record(sock)
    if rec == nil then
      return msgs, alert, err
    end
    if rec.type == 21 then
      local parsed = tl_parse_alert(rec.payload)
      alert = {
        level = parsed.level,
        code = parsed.code,
        name = tl_alert_name(parsed.level, parsed.code),
      }
      return msgs, alert, nil
    elseif rec.type == 22 then
      local hs = tl_parse_handshake_messages(rec.payload)
      for _, m in ipairs(hs) do
        msgs[#msgs + 1] = m
        if m.type == 14 then
          return msgs, alert, nil
        end
      end
    end
  end
  return msgs, alert, nil
end

local function tl_summarize_flight(msgs)
  local info = {}
  for _, m in ipairs(msgs) do
    if m.type == 2 then
      local sh = tl_parse_server_hello(m.body)
      info.version = sh.version
      info.cipher = sh.cipher
      info.cipher_name = tl_cipher_name(sh.cipher)
      info.compression = sh.compression
      local exts = sh.extensions or {}
      info.exts = exts
      local sv = exts[43]
      if sv ~= nil and #sv >= 2 then
        info.negotiated_version = sv:byte(1) * 256 + sv:byte(2)
      else
        info.negotiated_version = sh.version
      end
      info.version_name = TL_VERSIONS[info.negotiated_version]
        or tl_version_name(info.negotiated_version)
      local alpn = exts[16]
      if alpn ~= nil then
        info.alpn = tl_alpn_selected(alpn)
      end
      if exts[5] ~= nil then
        info.status_request_echo = true
      end
      if exts[0xff01] ~= nil then
        info.renegotiation_info = true
      end
    elseif m.type == 11 then
      local parsed = tl_parse_certificate(m.body)
      info.cert_count = #parsed.certs
      if parsed.certs[1] ~= nil then
        info.cert_der = parsed.certs[1]
        info.cert = tl_x509_parse(parsed.certs[1])
      end
    elseif m.type == 12 then
      info.ske = tl_parse_server_key_exchange(m.body)
      if info.ske.dh_prime ~= nil then
        info.dh_bits = info.ske.prime_bits or tl_dh_prime_bits(info.ske.dh_prime)
      end
    elseif m.type == 5 then
      info.ocsp = tl_parse_certificate_status(m.body)
    elseif m.type == 4 then
      info.session_ticket = true
    end
  end
  return info
end

local function tl_read_records_until(sock, wanted, limit)
  for _ = 1, limit or 8 do
    local rec, err = tl_read_record(sock)
    if rec == nil then
      return false, err
    end
    if rec.type == 21 then
      local parsed = tl_parse_alert(rec.payload)
      return false, "alert:" .. tl_alert_name(parsed.level, parsed.code)
    end
    if rec.type == 22 then
      local hs = tl_parse_handshake_messages(rec.payload)
      for _, m in ipairs(hs) do
        if m.type == wanted then
          return true, nil
        end
      end
    end
  end
  return false, "NO_MESSAGE"
end

local function tl_finish_client_flight(sock)
  local pre = string.rep("k", 32)
  local cke = tl_record(0x16, 0x0303, tl_handshake(0x10, tl_u16(#pre) .. pre))
  local ccs = tl_record(0x14, 0x0303, "")
  local fin = tl_record(0x16, 0x0303, tl_handshake(0x14, string.rep("f", 12)))
  sock:send(cke)
  sock:send(ccs)
  sock:send(fin)
  return tl_read_records_until(sock, 20)
end

local function tl_perform_handshake(host, port, opts)
  opts = opts or {}
  local sock, cerr = tl_connect(host, port)
  if sock == nil then
    return { status = "connect_error", error = cerr }
  end
  local hello_opts = {
    version = opts.version or 0x0303,
    ciphers = opts.ciphers or { 0xc02f, 0xc030, 0x009c, 0x0039 },
    comps = opts.comps or { 0 },
    sni = opts.sni,
    alpn = opts.alpn,
    status_request = opts.status_request,
    supported_versions = opts.supported_versions,
    heartbeat = opts.heartbeat,
    renegotiation_info = opts.renegotiation_info,
    ems = opts.ems ~= nil and opts.ems or false,
  }
  if opts.scsv then
    hello_opts.ciphers = { 0x0035, 0xc02f, 0x5600 }
    hello_opts.version = opts.version or 0x0302
  end
  local hello = tl_client_hello(hello_opts)
  local ok, serr = pcall(sock.send, sock, hello)
  if not ok then
    sock:close()
    return { status = "send_error", error = serr }
  end
  local msgs, alert = tl_collect_server_flight(sock)
  local server = tl_summarize_flight(msgs)
  local result = { status = "handshake", server = server, sock = sock }
  if alert ~= nil then
    result.status = "alert"
    result.alert = alert
    return result
  end
  if server.version == nil then
    sock:close()
    result.status = "no_server_hello"
    return result
  end
  local done, dterr = tl_finish_client_flight(sock)
  result.completed = done
  if not done then
    result.completion_error = dterr
  end
  return result
end

local function tl_close(result)
  if result ~= nil and result.sock ~= nil then
    local ok = pcall(result.sock.close, result.sock)
    if ok then
      result.sock = nil
    end
  end
  return result
end

local function tl_probe_version(host, port, version, supported, ciphers)
  local opts = { version = version, ciphers = ciphers }
  if supported ~= nil then
    opts.supported_versions = supported
  end
  return tl_close(tl_perform_handshake(host, port, opts))
end

local function tl_supported_versions(result)
  local server = result.server or {}
  local neg = server.negotiated_version
  local accepted = neg ~= nil and result.status == "handshake"
  return accepted, neg
end

local function tl_probe_cipher_set(host, port, ciphers, version)
  return tl_close(tl_perform_handshake(host, port, {
    version = version or 0x0303,
    ciphers = ciphers,
  }))
end

local function tl_cipher_accepted(result)
  if result.status ~= "handshake" then
    return false, nil
  end
  local server = result.server or {}
  return true, server.cipher
end

local function tl_renegotiation_probe(host, port, with_info)
  local first = tl_perform_handshake(host, port, {
    version = 0x0303,
    ciphers = { 0x0035, 0xc02f },
  })
  if first.status ~= "handshake" then
    return tl_close(first)
  end
  local hello = tl_client_hello({
    version = 0x0303,
    ciphers = { 0x0035, 0xc02f },
    renegotiation_info = with_info,
  })
  local ok, serr = pcall(first.sock.send, first.sock, hello)
  if not ok then
    first.status = "send_error"
    first.error = serr
    return tl_close(first)
  end
  local msgs, alert = tl_collect_server_flight(first.sock)
  local server = tl_summarize_flight(msgs)
  local result = {
    status = "renegotiated",
    server = server,
    base_version = first.server.negotiated_version,
  }
  if alert ~= nil then
    result.status = "alert"
    result.alert = alert
  elseif server.version == nil then
    result.status = "no_server_hello"
  end
  return tl_close(result)
end

local function tl_heartbeat_probe(host, port, payload)
  local first = tl_perform_handshake(host, port, {
    version = 0x0303,
    ciphers = { 0x0035, 0xc02f },
    heartbeat = true,
  })
  if first.status ~= "handshake" then
    return tl_close(first)
  end
  local p = payload or "tl-heartbeat-probe"
  local body = string.char(0) .. tl_u16(#p) .. string.rep("h", 16) .. p
    .. string.rep("\0", 16)
  local ok, serr = pcall(first.sock.send, first.sock, tl_record(0x18, 0x0303, body))
  if not ok then
    first.status = "send_error"
    first.error = serr
    return tl_close(first)
  end
  local rec, rerr = tl_read_record(first.sock)
  local result = { status = "no_response", error = rerr }
  if rec ~= nil then
    if rec.type == 21 then
      local parsed = tl_parse_alert(rec.payload)
      result.status = "alert"
      result.alert = {
        level = parsed.level,
        code = parsed.code,
        name = tl_alert_name(parsed.level, parsed.code),
      }
    elseif rec.type == 24 then
      local hb = tl_parse_heartbeat(rec.payload)
      result.status = "response"
      result.heartbeat = hb
      result.overread = hb.trailer > 0
    else
      result.status = "unexpected"
      result.record_type = rec.type
    end
  end
  return tl_close(result)
end

local function tl_read_all(sock)
  local parts = {}
  while true do
    local ok, chunk, err = sock:receive_bytes(65536)
    if not ok or chunk == nil or #chunk == 0 then
      return table.concat(parts), err
    end
    parts[#parts + 1] = chunk
    if #chunk < 65536 then
      break
    end
  end
  return table.concat(parts), nil
end

local function tl_parse_http_response(raw)
  local parsed = { raw = raw }
  local status = raw:match("^HTTP/1%.%d (%d%d%d)")
  parsed.status = tonumber(status)
  local headers_end = raw:find("\r\n\r\n", 1, true)
  if headers_end == nil then
    return parsed
  end
  parsed.headers = {}
  for line in raw:sub(1, headers_end - 1):gmatch("([^\r\n]+)") do
    local k, v = line:match("^([^:]+):%s*(.*)$")
    if k ~= nil then
      parsed.headers[k:lower()] = v
    end
  end
  parsed.body = raw:sub(headers_end + 4)
  return parsed
end

local function tl_http_over_tls(result, path)
  if result == nil or result.sock == nil or result.status ~= "handshake" then
    return nil, "no_open_session"
  end
  local req = "GET " .. (path or "/") .. " HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n"
  local ok, serr = pcall(result.sock.send, result.sock, req)
  if not ok then
    return nil, serr
  end
  local raw, rerr = tl_read_all(result.sock)
  if raw == nil or #raw == 0 then
    return nil, rerr or "EMPTY_RESPONSE"
  end
  return tl_parse_http_response(raw), nil
end

local function tl_classify_cert_window(cert, now, warndays)
  if cert == nil or cert.not_before == nil or cert.not_after == nil then
    return "unknown"
  end
  if now < cert.not_before then
    return "not_yet_valid"
  end
  if now > cert.not_after then
    return "expired"
  end
  local days = tl_days_between(now, cert.not_after)
  if days <= (warndays or 30) then
    return "expiring_soon"
  end
  return "valid"
end

local function tl_cert_days_to_expiry(cert, now)
  if cert == nil or cert.not_after == nil then
    return nil
  end
  return tl_days_between(now, cert.not_after)
end

local function tl_hostname_matches_pattern(pattern, hostname)
  if pattern == nil or hostname == nil then
    return false
  end
  pattern = pattern:lower()
  hostname = hostname:lower()
  if pattern == hostname then
    return true
  end
  if pattern:sub(1, 2) ~= "*." then
    return false
  end
  local suffix = pattern:sub(3)
  if #hostname <= #suffix then
    return false
  end
  if hostname:sub(-#suffix) ~= suffix then
    return false
  end
  local label = hostname:sub(1, #hostname - #suffix - 1)
  if label:find(".", 1, true) then
    return false
  end
  if #label == 0 then
    return false
  end
  return true
end

local function tl_extract_cn(subject)
  if subject == nil then
    return nil
  end
  for part in subject:gmatch("[^/]+") do
    local key, val = part:match("^%s*(%w+)%s*=%s*(.-)%s*$")
    if key ~= nil and key:upper() == "CN" then
      return val
    end
  end
  return nil
end

local function tl_hostname_check(cert, hostname)
  local result = { match = false, sources = {}, wildcards = 0 }
  if cert == nil then
    return result
  end
  local sans = {}
  for _, e in ipairs(cert.extensions or {}) do
    if e.name == "subjectAltName" then
      for _, s in ipairs(e.sans or {}) do
        if s.type == "DNS" then
          sans[#sans + 1] = s.value
        end
      end
    end
  end
  if #sans > 0 then
    for _, s in ipairs(sans) do
      if tl_hostname_matches_pattern(s, hostname) then
        result.match = true
        result.sources[#result.sources + 1] = "SAN:" .. s
        if s:find("^%*%.") then
          result.wildcards = result.wildcards + 1
        end
      end
    end
    result.uses_san = true
  end
  local cn = tl_extract_cn(cert.subject)
  if cn ~= nil and not result.match then
    if tl_hostname_matches_pattern(cn, hostname) then
      result.match = true
      result.sources[#result.sources + 1] = "CN:" .. cn
    end
  end
  return result
end

local TL_WEAK_SIG_ALGS = {
  ["md5WithRSAEncryption"] = "MD5",
  ["sha1WithRSAEncryption"] = "SHA-1",
  ["shaWithRSAEncryption"] = "SHA-0",
  ["md5WithRSA"] = "MD5",
  ["sha1WithRSA"] = "SHA-1",
}

local function tl_sig_algorithm_class(cert)
  if cert == nil or cert.sig_algorithm == nil then
    return "unknown", nil
  end
  local weak = TL_WEAK_SIG_ALGS[cert.sig_algorithm]
  if weak ~= nil then
    return "weak", weak
  end
  if cert.sig_oid ~= nil then
    local rsa_sig_weak = { "2", "4", "5" }
    for _, suffix in ipairs(rsa_sig_weak) do
      if cert.sig_oid == ("1.2.840.113549.1.1." .. suffix) then
        return "weak", cert.sig_algorithm
      end
    end
  end
  return "strong", nil
end

local function tl_known_dh_group(prime)
  if prime == nil or #prime < 16 then
    return nil
  end
  local head = ""
  for i = 1, 21 do
    if i > #prime then
      return nil
    end
    head = head .. string.format("%02x", prime:byte(i))
  end
  if #prime == 128 and head:sub(1, 40) == "ffffffffffffffffc90fdaa22168c234c4c6628b" then
    return "RFC 3526 group 14 (1024-bit MODP)"
  end
  if #prime == 256 and head == "04ffffffffffffffffc90fdaa22168c234c4c6628b" then
    return "RFC 7919 ffdhe2048"
  end
  return nil
end

local function tl_dh_strength(bits)
  if bits == nil then
    return "unknown"
  end
  if bits < 1024 then
    return "critically_weak"
  end
  if bits < 2048 then
    return "weak"
  end
  return "acceptable"
end

local function tl_scsv_probe(host, port)
  return tl_close(tl_perform_handshake(host, port, {
    scsv = true,
    version = 0x0302,
  }))
end

local function tl_weak_cipher_groups()
  return {
    null = { 0x0001, 0x0002 },
    rc4 = { 0x0005, 0x0004, 0x0016, 0x0013 },
    export_des = { 0x0006, 0x0007 },
    md5 = { 0x0003 },
    three_des = { 0x000a, 0x0008, 0x0009, 0x000c, 0x000d, 0xc008, 0xc012, 0xc02b },
  }
end

local function tl_probe_each_group(host, port, groups)
  local results = {}
  for group, ciphers in pairs(groups) do
    local result = tl_probe_cipher_set(host, port, ciphers)
    local accepted, cipher = tl_cipher_accepted(result)
    results[group] = {
      accepted = accepted,
      cipher = cipher,
      cipher_name = accepted and tl_cipher_name(cipher) or nil,
      status = result.status,
      alert = result.alert,
    }
  end
  return results
end

local function tl_version_probe_battery(host, port)
  local probes = {
    { label = "SSLv3", version = 0x0300, supported = nil },
    { label = "TLS 1.0", version = 0x0301, supported = nil },
    { label = "TLS 1.1", version = 0x0302, supported = nil },
    { label = "TLS 1.2", version = 0x0303, supported = nil },
    { label = "TLS 1.3", version = 0x0303, supported = { 0x0304 }, ciphers = { 0x1301, 0x1302, 0x1303, 0xc02f, 0xc030, 0x009c, 0x0039 } },
  }
  local out = {}
  for _, p in ipairs(probes) do
    local result = tl_probe_version(host, port, p.version, p.supported, p.ciphers)
    local ok, neg = tl_supported_versions(result)
    out[#out + 1] = {
      label = p.label,
      accepted = ok,
      negotiated = neg,
      status = result.status,
      alert = result.alert,
    }
  end
  return out
end

local function ft_drain(sock, maxbytes)
  local acc = ""
  local limit = maxbytes or 65536
  local guard = 0
  while #acc < limit and guard < 256 do
    local ok, chunk, rerr = sock:receive_bytes(4096)
    if not ok or chunk == nil or #chunk == 0 then
      break
    end
    acc = acc .. chunk
    guard = guard + 1
  end
  return acc
end

local function ft_find_final_line(buf)
  local pos = 1
  while true do
    local s, e = string.find(buf, "\r?\n", pos)
    if s == nil then
      local tail = string.sub(buf, pos)
      local head = string.match(tail, "^%s*(%d%d%d)[ ]")
      if head ~= nil then
        return head, #buf
      end
      return nil, nil
    end
    local line = string.sub(buf, pos, s - 1)
    local head = string.match(line, "^%s*(%d%d%d)[ ]")
    if head ~= nil then
      return head, e
    end
    pos = e + 1
    if pos > #buf then
      return nil, nil
    end
  end
end

local function ft_read_response(sock)
  local acc = sock._ft_pending or ""
  while true do
    local code, final = ft_find_final_line(acc)
    if final ~= nil then
      local consumed = string.sub(acc, 1, final)
      local rest = string.sub(acc, final + 1)
      sock._ft_pending = (rest == "" and nil) or rest
      return ft_parse_response(consumed)
    end
    local ok, chunk, rerr = sock:receive_bytes(4096)
    if not ok or chunk == nil or #chunk == 0 then
      if code ~= nil then
        sock._ft_pending = nil
        return ft_parse_response(acc)
      end
      return nil, rerr or "timeout waiting for response"
    end
    acc = acc .. chunk
    if #acc > 1048576 then
      sock._ft_pending = nil
      return nil, "response overflow"
    end
  end
end

local function ft_connect(host, port, timeout)
  local sock = nmap.new_socket("tcp")
  sock:set_timeout(timeout or 10)
  local ok, err = sock:connect(host.ip, port)
  if not ok then
    pcall(sock.close, sock)
    return nil, err
  end
  local banner, berr = ft_read_response(sock)
  if banner == nil then
    local banner_text = tostring(ft_drain(sock, 2048))
    if banner_text == "" then
      return nil, berr or "no banner"
    end
    banner = { code = nil, text = banner_text, lines = { banner_text } }
  end
  if banner.code ~= nil and banner.text ~= "" then
    banner.text = banner.code .. " " .. banner.text
  end
  return {
    sock = sock,
    host = host,
    port = port,
    banner = banner,
  }
end

local function ft_cmd(sock, line)
  local ok, err = sock:send(line .. "\r\n")
  if not ok then
    return nil, err
  end
  return ft_read_response(sock)
end

local function ft_login(sock, user, pass)
  local user_resp, uerr = ft_cmd(sock, "USER " .. user)
  if user_resp == nil then
    return nil, uerr
  end
  if user_resp.code == "230" then
    return {
      ok = true,
      kind = "success",
      user_code = user_resp.code,
      pass_code = user_resp.code,
      user_text = user_resp.text,
      pass_text = user_resp.text,
      welcome = user_resp.text,
    }
  end
  if user_resp.code ~= "331" then
    return {
      ok = false,
      kind = "rejected-at-user",
      user_code = user_resp.code,
      user_text = user_resp.text,
    }
  end
  local pass_resp, perr = ft_cmd(sock, "PASS " .. pass)
  if pass_resp == nil then
    return nil, perr
  end
  return {
    ok = (pass_resp.code == "230"),
    kind = (pass_resp.code == "230") and "success" or "rejected-at-pass",
    user_code = user_resp.code,
    pass_code = pass_resp.code,
    user_text = user_resp.text,
    pass_text = pass_resp.text,
    welcome = (pass_resp.code == "230") and pass_resp.text or nil,
  }
end

local function ft_pasv_data(session, prefer_epsv)
  local sock = session.sock
  local resp, err
  local mode = "PASV"
  if prefer_epsv == false then
    resp, err = ft_cmd(sock, "PASV")
    if resp == nil then
      return nil, err
    end
  end
  if prefer_epsv then
    mode = "EPSV"
    resp, err = ft_cmd(sock, "EPSV")
    if resp == nil then
      return nil, err
    end
    if resp.code == "229" then
      local parsed = ft_parse_epsv(resp.text)
      if parsed ~= nil then
        local datasock = nmap.new_socket("tcp")
        datasock:set_timeout(10)
        local dok = datasock:connect(session.host.ip, parsed.port)
        if dok then
          return { datasock = datasock, ip = nil, port = parsed.port, mode = mode, resp = resp }
        end
        pcall(datasock.close, datasock)
        return nil, "EPSV data connect refused on port " .. parsed.port
      end
    end
    resp, err = ft_cmd(sock, "PASV")
    if resp == nil then
      return nil, err
    end
    mode = "PASV"
  end
  if resp.code ~= "227" then
    return nil, "no passive address (server answered " .. tostring(resp.code) .. ")"
  end
  local parsed = ft_parse_pasv(resp.text)
  if parsed == nil then
    return nil, "could not parse PASV address from: " .. resp.text
  end
  local datasock = nmap.new_socket("tcp")
  datasock:set_timeout(10)
  local dok = datasock:connect(parsed.ip, parsed.port)
  if not dok then
    pcall(datasock.close, datasock)
    return nil, "data connect to " .. parsed.ip .. ":" .. parsed.port .. " refused"
  end
  return { datasock = datasock, ip = parsed.ip, port = parsed.port, mode = mode, resp = resp }
end

local function ft_data_exchange(session, control_cmd, use_epsv, maxbytes)
  local passive, perr = ft_pasv_data(session, use_epsv)
  if passive == nil then
    return nil, perr
  end
  local datasock = passive.datasock
  local ok, err = session.sock:send(control_cmd .. "\r\n")
  if not ok then
    pcall(datasock.close, datasock)
    return nil, err
  end
  local status_resp, rerr = ft_read_response(session.sock)
  if status_resp == nil then
    pcall(datasock.close, datasock)
    return nil, rerr
  end
  local is_transfer = (string.sub(status_resp.code, 1, 1) == "1")
    or status_resp.code == "125" or status_resp.code == "150"
  local content = ""
  local complete = nil
  if is_transfer then
    content = ft_drain(datasock, maxbytes or 65536)
    complete = ft_read_response(session.sock)
  end
  pcall(datasock.close, datasock)
  return {
    status = status_resp,
    complete = complete,
    content = content,
    passive = passive,
  }
end

local function ft_data_send(session, control_cmd, payload, use_epsv)
  local passive, perr = ft_pasv_data(session, use_epsv)
  if passive == nil then
    return nil, perr
  end
  local datasock = passive.datasock
  local sent, serr = datasock:send(payload)
  pcall(datasock.close, datasock)
  if not sent then
    return nil, serr or "data write failed"
  end
  local ok, err = session.sock:send(control_cmd .. "\r\n")
  if not ok then
    return nil, err
  end
  local resp, rerr = ft_read_response(session.sock)
  return { resp = resp }
end

local function ft_auth_tls(session)
  return ft_cmd(session.sock, "AUTH TLS")
end

local function ft_tls_upgrade(session, hello_opts)
  local sock = session.sock
  local opts = hello_opts or {}
  local hello = tl_client_hello({
    version = opts.version or 0x0303,
    ciphers = opts.ciphers or { 0xc02f, 0xc030, 0x009c, 0x0039 },
    comps = opts.comps or { 0 },
    sni = opts.sni,
    supported_versions = opts.supported_versions,
    ems = (opts.ems ~= nil) and opts.ems or false,
    renegotiation_info = opts.renegotiation_info,
  })
  local ok, err = sock:send(hello)
  if not ok then
    return nil, err
  end
  local msgs, alert = tl_collect_server_flight(sock, 12)
  local server = tl_summarize_flight(msgs)
  local result = { status = "handshake", server = server, msgs = msgs }
  if alert ~= nil then
    result.status = "alert"
    result.alert = alert
    return result
  end
  if server.version == nil then
    result.status = "no_server_hello"
    return result
  end
  return result
end

local function ft_tls_probe(host, port, timeout, hello_opts)
  local session, cerr = ft_connect(host, port, timeout)
  if session == nil then
    return { status = "connect_error", error = cerr }
  end
  local auth = ft_auth_tls(session)
  if auth == nil or tostring(auth.code) ~= "234" then
    pcall(session.sock.close, session.sock)
    return {
      status = "auth-rejected",
      code = auth and auth.code,
      text = auth and auth.text,
    }
  end
  local result = ft_tls_upgrade(session, hello_opts)
  result.auth = auth
  pcall(session.sock.close, session.sock)
  return result
end

local function ft_quit(session)
  if session ~= nil and session.sock ~= nil then
    pcall(session.sock.close, session.sock)
  end
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

local function run_probe(host, port_number, timeout, label, hello_opts, notes)
  local session, cerr = ft_connect(host, port_number, timeout)
  if session == nil then
    table.insert(notes, label .. ": connection failed (" .. tostring(cerr) .. ")")
    return "connect-error"
  end
  local auth = ft_cmd(session.sock, "AUTH TLS")
  if auth == nil or tostring(auth.code) ~= "234" then
    ft_quit(session)
    table.insert(notes, label .. ": AUTH TLS not accepted (code " .. tostring(auth and auth.code) .. ")")
    return "auth-refused"
  end
  local result = ft_tls_upgrade(session, hello_opts)
  ft_quit(session)
  if result == nil then
    table.insert(notes, label .. ": no response to the ClientHello")
    return "no-response"
  end
  if result.status == "alert" then
    table.insert(notes, label .. ": rejected (alert " .. tostring(result.alert and result.alert.name) .. ")")
    return "rejected", result
  end
  if result.server ~= nil and result.server.version ~= nil then
    table.insert(notes, label .. ": accepted (" .. tostring(result.server.version_name) .. "/" .. tostring(result.server.cipher_name) .. ")")
    return "accepted", result
  end
  table.insert(notes, label .. ": no usable server flight")
  return "no-response"
end

action = function(host, port)

  seed_random(port)
  reset_state()
  reset_findings()

  local args = read_args()
  local out = new_output(RISK_LEVEL, "AUDITED - FTPS (AUTH TLS) protocol and cipher audit.")
  local sections = {}
  local notes = {}
  local port_number = port and (port.number or port.port) or 21

  local session, cerr = ft_connect(host, port_number, args.timeout)
  if session == nil then
    add_finding("INFO",
      "could not open an FTP control connection to audit the FTPS TLS profile: " .. tostring(cerr),
      { subject = "conn-failed", evidence = tostring(cerr) })
    table.insert(sections, { key = "probe_notes", value = notes })
    local unique, counts = dedupe_findings()
    return finish_output(out, unique, counts, sections)
  end
  state.requests = state.requests + 1
  local auth = ft_cmd(session.sock, "AUTH TLS")
  ft_quit(session)
  table.insert(sections, { key = "banner", value = truncate(session.banner.text, 160) })

  if auth == nil or tostring(auth.code) ~= "234" then
    add_finding("INFO",
      "AUTH TLS was not accepted (code " .. tostring(auth and auth.code) .. "); there is no FTPS TLS profile to audit - see ftp-tls-support for the plaintext-only report",
      { subject = "ftps-unavailable",
        evidence = truncate(auth and auth.text or "", 120) })
    table.insert(sections, { key = "auth_tls_code", value = auth ~= nil and auth.code or "no-response" })
    table.insert(sections, { key = "probe_notes", value = notes })
    local unique, counts = dedupe_findings()
    return finish_output(out, unique, counts, sections)
  end
  table.insert(sections, { key = "auth_tls_code", value = auth.code })
  table.insert(notes, "AUTH TLS accepted; starting the probe set")

  local baseline, bres = run_probe(host, port_number, args.timeout, "baseline",
    { version = 0x0303, ciphers = DEFAULT_CIPHERS }, notes)
  if baseline == "accepted" and bres ~= nil then
    local server = bres.server
    table.insert(sections, { key = "baseline_protocol", value = server.version_name or tostring(server.negotiated_version) })
    table.insert(sections, { key = "baseline_cipher", value = server.cipher_name or tostring(server.cipher) })
    if server.dh_bits ~= nil then
      table.insert(sections, { key = "baseline_dh_bits", value = tostring(server.dh_bits) })
      if server.dh_bits <= 1024 then
        add_finding("HIGH",
          "the default FTPS negotiation uses " .. tostring(server.dh_bits) .. "-bit Diffie-Hellman; 1024-bit DH is within reach of sophisticated attackers (Logjam class)",
          { subject = "weak-dh",
            evidence = "DH " .. tostring(server.dh_bits) .. " bits" })
      end
    end
  end

  if not budget_exhausted(args) then
    local tls13, r13 = run_probe(host, port_number, args.timeout, "TLS 1.3",
      { version = 0x0303, ciphers = { 0x1301, 0x1302, 0x1303 }, supported_versions = { 0x0304 } }, notes)
    if tls13 == "accepted" and r13 ~= nil then
      add_finding("INFO",
        "TLS 1.3 is negotiable over FTPS; the newest protocol generation is available",
        { subject = "tls13-available",
          evidence = tostring(r13.server and r13.server.version_name) })
    elseif tls13 == "rejected" then
      table.insert(sections, { key = "tls13", value = "not offered" })
    end
  end

  for _, probe in ipairs(PROBE_VERSIONS) do
    if budget_exhausted(args) then
      table.insert(notes, "request budget exhausted; remaining version probes skipped")
      break
    end
    local status, result = run_probe(host, port_number, args.timeout, probe.name,
      { version = probe.version, ciphers = probe.ciphers }, notes)
    if status == "accepted" then
      add_finding(probe.risk == "high" and "HIGH" or "MEDIUM",
        probe.name .. " is negotiable over FTPS: " .. probe.note,
        { subject = "legacy-protocol-" .. probe.name:gsub("%s+", "-"):lower(),
          evidence = result ~= nil and result.server and (tostring(result.server.version_name) .. "/" .. tostring(result.server.cipher_name)) or nil })
    end
  end

  for _, family in ipairs(PROBE_CIPHER_FAMILIES) do
    if budget_exhausted(args) then
      table.insert(notes, "request budget exhausted; remaining cipher probes skipped")
      break
    end
    local status, result = run_probe(host, port_number, args.timeout, family.name,
      { version = 0x0303, ciphers = family.ciphers }, notes)
    if status == "accepted" then
      add_finding(family.risk == "high" and "HIGH" or "MEDIUM",
        family.name .. " is negotiable over FTPS (server picked " .. tostring(result and result.server and result.server.cipher_name) .. "): " .. family.note,
        { subject = "weak-cipher-" .. family.name:gsub("%s+", "-"):lower(),
          evidence = result ~= nil and result.server and tostring(result.server.cipher_name) or nil })
    end
  end

  table.insert(sections, { key = "probe_notes", value = notes })
  local unique, counts = dedupe_findings()
  return finish_output(out, unique, counts, sections)

end
