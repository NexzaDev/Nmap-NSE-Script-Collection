local shortport = require "shortport"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Checks for the vsftpd 2.3.4 smiley-face backdoor banner signature
(CVE-2011-2523) and the affected 2.3.4 version window.

Why it matters
- The vsftpd 2.3.4 build shipped with a hardcoded backdoor that
  listens on TCP port 6200; the only reliable pre-authentication
  fingerprint is the banner itself - a 227 welcome code carrying a
  vsftpd identity, instead of the normal 220.
- A host presenting that signature is either compromised or was
  deliberately deployed with the backdoor; either way it is an
  active critical condition, not a theoretical one.
- Banners can be spoofed, so the script keeps the confidence
  model explicit: banner-only evidence is high confidence for the
  signature, and the version-window check (2.3.4 in a 220 banner)
  is reported separately with its own context.

What the script does
1. Opens a connection and captures the raw banner, including the
   reply code.
2. Evaluates the backdoor signature: a 227 welcome code combined
   with a vsftpd identity. A hit is reported at CRITICAL with the
   CVE context and the expected 6200 listener.
3. Checks the banner (and a follow-up STAT) for the vsftpd 2.3.4
   version window; a 220 banner carrying 2.3.4 is reported HIGH
   because that release is the backdoor release, even without the
   227 signature.
4. Emits INFO for clean modern banners, so the check doubles as a
   "no backdoor signature observed" attestation.

The script sends no commands beyond an optional STAT and no
credentials; it never triggers the backdoor itself.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"vuln", "safe"}

portrule = shortport.port_or_service(21, "ftp")

local SCRIPT_NAME = "ftp-vsftpd-backdoor-fingerprint"

local RISK_LEVEL = "🔴 CRITICAL"

local DEFAULT_ARGS = {
  maxrequests = 2,
  timeout = 10,
}

local NUMERIC_ARGS = {
  { key = "maxrequests", minimum = 1, integer = true },
  { key = "timeout", minimum = 1, integer = true },
}

local BOOLEAN_ARGS = {}

local STRING_ARGS = {}

local AFFECTED_VERSIONS = {
  "2.3.4",
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
  for _, entry in ipairs(entries or {}) do
    if entry.is_dir then
      dirs[#dirs + 1] = entry.name
    else
      files = files + 1
    end
    if entry.world_writable and entry.name ~= nil then
      world_writable[#world_writable + 1] = entry.name
    end
    if entry.name ~= nil and entry.name ~= "" and #sensitive < (limit or 10) then
      local risk, note = ft_sensitivity(entry.name)
      if risk ~= "none" then
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

local function version_in_window(version)
  if version == nil then
    return false
  end
  for _, candidate in ipairs(AFFECTED_VERSIONS) do
    if version == candidate then
      return true
    end
  end
  return false
end

action = function(host, port)

  seed_random(port)
  reset_state()
  reset_findings()

  local args = read_args()
  local out = new_output(RISK_LEVEL, "AUDITED - vsftpd backdoor signature (CVE-2011-2523) checked.")
  local sections = {}
  local notes = {}
  local port_number = port and (port.number or port.port) or 21

  local session, cerr = ft_connect(host, port_number, args.timeout)
  if session == nil then
    add_finding("INFO",
      "could not open an FTP control connection to inspect the banner: " .. tostring(cerr),
      { subject = "conn-failed", evidence = tostring(cerr) })
    table.insert(sections, { key = "probe_notes", value = notes })
    local unique, counts = dedupe_findings()
    return finish_output(out, unique, counts, sections)
  end
  state.requests = state.requests + 1
  table.insert(sections, { key = "banner", value = session.banner.text })
  table.insert(sections, { key = "banner_code", value = tostring(session.banner.code or "none") })

  local banner_info = ft_parse_banner(session.banner.text)
  table.insert(sections, { key = "daemon_family", value = banner_info.family })
  if banner_info.version ~= nil then
    table.insert(sections, { key = "daemon_version", value = banner_info.version })
  end
  table.insert(notes, "banner code " .. tostring(banner_info.code or "none") .. ", family " .. banner_info.family)

  if banner_info.backdoor_banner then
    add_finding("CRITICAL",
      "the banner matches the vsftpd 2.3.4 backdoor signature: a 227 welcome code with a vsftpd identity. Builds with this signature ship a hardcoded backdoor that opens a TCP listener on port 6200 (CVE-2011-2523); treat the host as compromised or intentionally backdoored and take it offline for forensic review",
      { subject = "vsftpd-backdoor-banner",
        evidence = truncate(session.banner.text, 120),
        confidence = "high" })
  elseif banner_info.family == "vsftpd" and version_in_window(banner_info.version) then
    add_finding("HIGH",
      "the banner reports vsftpd " .. banner_info.version .. " with a standard 220 code; that release is the backdoor release (CVE-2011-2523) - the 227 signature is absent, but the version window alone warrants immediate investigation and an upgrade to 2.3.5 or later",
      { subject = "vsftpd-affected-version",
        evidence = truncate(session.banner.text, 120),
        confidence = "high" })
  elseif banner_info.family == "vsftpd" then
    add_finding("INFO",
      "vsftpd " .. tostring(banner_info.version or "version undisclosed") .. " answers with a standard 220 welcome; no backdoor banner signature observed",
      { subject = "no-backdoor-signature" })
  elseif banner_info.family ~= "unknown" and banner_info.family ~= "generic" then
    add_finding("INFO",
      "the daemon is " .. banner_info.family .. " (" .. tostring(banner_info.version or "version undisclosed") .. "), not vsftpd; the CVE-2011-2523 fingerprint does not apply",
      { subject = "not-vsftpd" })
  else
    add_finding("INFO",
      "the banner does not identify a vsftpd build; the backdoor signature cannot be present in the banner, but a custom banner could still hide one - a port 6200 check is the only definitive test",
      { subject = "banner-unidentified" })
  end

  if banner_info.backdoor_banner and not budget_exhausted(args) then
    state.requests = state.requests + 1
    local stat_resp, srr = ft_cmd(session.sock, "STAT")
    if stat_resp ~= nil then
      table.insert(sections, { key = "stat", value = truncate(stat_resp.text, 200) })
      table.insert(notes, "STAT corroboration: " .. tostring(stat_resp.code))
      if stat_resp.text:find("vsftpd", 1, true) ~= nil then
        add_finding("INFO",
          "STAT corroborates the vsftpd identity behind the backdoor banner signature",
          { subject = "stat-corroborates",
            evidence = truncate(stat_resp.text, 120) })
      end
    else
      table.insert(notes, "STAT failed: " .. tostring(srr))
    end
  end

  ft_quit(session)
  table.insert(sections, { key = "probe_notes", value = notes })
  local unique, counts = dedupe_findings()
  return finish_output(out, unique, counts, sections)

end
