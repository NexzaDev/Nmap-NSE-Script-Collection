local shortport = require "shortport"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Evaluates the host-level Docker daemon security options returned by the
/info endpoint. Audits whether hardening features are enabled or
missing:
1. AppArmor / SELinux mandatory access control
2. Default Seccomp system call filtering
3. User Namespace remapping (userns-remap / rootless mode)
4. Live restore capabilities (daemon reboot resilience)

Why it matters
- Without AppArmor or SELinux profiles, a compromised container has no
  MAC layer standing between it and the host.
- Seccomp is the daemon's default syscall filter; a daemon running with
  it disabled gives every container ~300+ syscalls instead of the ~44
  it needs.
- Without user namespace remapping, container root is host root, so
  any capability leak is an immediate root leak.
- Live restore keeps running containers alive across daemon restarts,
  which matters for availability during patching.

What the script does
1. Confirms the endpoint is a Docker API, then fetches /info.
2. Parses the SecurityOptions list (name=...,profile=... entries) and
   the CgroupDriver / LiveRestoreEnabled / Labels fields.
3. Builds a hardening matrix: seccomp (default profile present?),
   AppArmor (present?), SELinux (present or host-inapplicable),
   userns-remap (present?), live-restore (on/off).
4. Emits MEDIUM for each missing mandatory-access-control layer and
   for seccomp not on the default profile, LOW for missing
   userns-remap, and INFO notes for live-restore and cgroup driver
   choices.

Only GET requests are issued.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"vuln", "discovery", "safe"}

portrule = shortport.port_or_service(
  {2375, 2376, 4243, 4244},
  {"docker", "docker-s", "http", "https"},
  "tcp"
)

local SCRIPT_NAME = "docker-daemon-security-opts"

local RISK_LEVEL = "🟡 MEDIUM"

local DEFAULT_ARGS = {
  maxrequests = 8,
  timeout = 10,
}

local NUMERIC_ARGS = {
  { key = "maxrequests", minimum = 1, integer = true },
  { key = "timeout", minimum = 1, integer = true },
}

local BOOLEAN_ARGS = {}

local STRING_ARGS = { "path" }

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

local DK = {}

local json_null = setmetatable({}, { __tostring = function() return "null" end })

local json_ws = "^%s*"

local function json_peek(s, i)
  return s:sub(i, i)
end

local function json_skip_ws(s, i)
  local j = i
  while true do
    local c = s:sub(j, j)
    if c == " " or c == "\t" or c == "\n" or c == "\r" then
      j = j + 1
    else
      return j
    end
  end
end

local json_parse_value
local json_parse_string
local json_parse_object
local json_parse_array

local function json_parse_number(s, i)
  local num = s:match("^-?%d+%.?%d*[eE]?[+-]?%d*", i)
  if not num then
    return nil, "invalid number at position " .. tostring(i)
  end
  return tonumber(num), i + #num
end

json_parse_string = function(s, i)
  if s:sub(i, i) ~= '"' then
    return nil, "expected string at position " .. tostring(i)
  end
  local out = {}
  local j = i + 1
  while true do
    local c = s:sub(j, j)
    if c == "" then
      return nil, "unterminated string"
    end
    if c == '"' then
      return table.concat(out), j + 1
    end
    if c == "\\" then
      local esc = s:sub(j + 1, j + 1)
      if esc == "n" then table.insert(out, "\n")
      elseif esc == "t" then table.insert(out, "\t")
      elseif esc == "r" then table.insert(out, "\r")
      elseif esc == "b" then table.insert(out, "\b")
      elseif esc == "f" then table.insert(out, "\f")
      elseif esc == "/" then table.insert(out, "/")
      elseif esc == '"' then table.insert(out, '"')
      elseif esc == "\\" then table.insert(out, "\\")
      elseif esc == "u" then
        local hex = s:sub(j + 2, j + 5)
        if hex:match("^%x%x%x%x$") then
          local code = tonumber(hex, 16)
          if code < 0x80 then
            table.insert(out, string.char(code))
          elseif code < 0x800 then
            table.insert(out, string.char(0xC0 + math.floor(code / 64), 0x80 + (code % 64)))
          else
            table.insert(out, string.char(0xE0 + math.floor(code / 4096),
              0x80 + (math.floor(code / 64) % 64), 0x80 + (code % 64)))
          end
        else
          return nil, "invalid \\u escape at position " .. tostring(j)
        end
        j = j + 4
      else
        return nil, "invalid escape at position " .. tostring(j)
      end
      j = j + 2
    else
      table.insert(out, c)
      j = j + 1
    end
  end
end

json_parse_object = function(s, i)
  local obj = {}
  local j = i + 1
  local first = true
  while true do
    j = json_skip_ws(s, j)
    local c = s:sub(j, j)
    if c == "}" then
      return obj, j + 1
    end
    if not first then
      if c ~= "," then
        return nil, "expected ',' in object at position " .. tostring(j)
      end
      j = json_skip_ws(s, j + 1)
    end
    first = false
    local key, kerr = json_parse_string(s, j)
    if not key then
      return nil, kerr
    end
    j = json_skip_ws(s, kerr)
    if s:sub(j, j) ~= ":" then
      return nil, "expected ':' at position " .. tostring(j)
    end
    j = json_skip_ws(s, j + 1)
    local val, verr = json_parse_value(s, j)
    if val == nil then
      return nil, verr
    end
    if val ~= json_null then
      obj[key] = val
    end
    j = verr
  end
end

json_parse_array = function(s, i)
  local arr = {}
  local j = i + 1
  local first = true
  while true do
    j = json_skip_ws(s, j)
    local c = s:sub(j, j)
    if c == "]" then
      return arr, j + 1
    end
    if not first then
      if c ~= "," then
        return nil, "expected ',' in array at position " .. tostring(j)
      end
      j = json_skip_ws(s, j + 1)
    end
    first = false
    local val, verr = json_parse_value(s, j)
    if not val then
      return nil, verr
    end
    table.insert(arr, val)
    j = verr
  end
end

json_parse_value = function(s, i)
  local c = json_peek(s, i)
  if c == "{" then
    return json_parse_object(s, i)
  end
  if c == "[" then
    return json_parse_array(s, i)
  end
  if c == '"' then
    return json_parse_string(s, i)
  end
  if c == "t" and s:sub(i, i + 3) == "true" then
    return true, i + 4
  end
  if c == "f" and s:sub(i, i + 4) == "false" then
    return false, i + 5
  end
  if c == "n" and s:sub(i, i + 3) == "null" then
    return json_null, i + 4
  end
  if c:match("[%d%-]") then
    return json_parse_number(s, i)
  end
  return nil, "unexpected character '" .. c .. "' at position " .. tostring(i)
end

function DK.json_decode(text)
  if type(text) ~= "string" or text == "" then
    return nil, "empty input"
  end
  local s = text
  local i = json_skip_ws(s, 1)
  local val, pos = json_parse_value(s, i)
  if val == nil then
    return nil, pos
  end
  if val == json_null then
    return nil
  end
  return val
end

local function json_escape_str(v)
  v = v:gsub("\\", "\\\\")
  v = v:gsub('"', '\\"')
  v = v:gsub("\n", "\\n")
  v = v:gsub("\r", "\\r")
  v = v:gsub("\t", "\\t")
  return v
end

local json_encode_value

json_encode_value = function(v)
  local t = type(v)
  if v == nil then
    return "null"
  end
  if t == "boolean" then
    return v and "true" or "false"
  end
  if t == "number" then
    return tostring(v)
  end
  if t == "string" then
    return '"' .. json_escape_str(v) .. '"'
  end
  if t == "table" then
    local is_array = true
    local count = 0
    for _ in pairs(v) do
      count = count + 1
    end
    for k in pairs(v) do
      if type(k) ~= "number" then
        is_array = false
        break
      end
    end
    if is_array then
      local parts = {}
      for idx = 1, count do
        parts[idx] = json_encode_value(v[idx])
      end
      return "[" .. table.concat(parts, ",") .. "]"
    end
    local parts = {}
    for k, val in pairs(v) do
      table.insert(parts, '"' .. json_escape_str(tostring(k)) .. '":' .. json_encode_value(val))
    end
    table.sort(parts)
    return "{" .. table.concat(parts, ",") .. "}"
  end
  return "null"
end

function DK.json_encode(v)
  return json_encode_value(v)
end

function DK.parse_version(v)
  local parts = {}
  local nums = v:match("^(%d+%.%d+%.%d+)")
  local src = nums or v
  for piece in src:gmatch("%d+") do
    table.insert(parts, tonumber(piece))
  end
  if #parts == 0 then
    return nil
  end
  return parts
end

function DK.version_lt(a, b)
  local pa = DK.parse_version(a)
  local pb = DK.parse_version(b)
  if not pa or not pb then
    return false
  end
  local n = math.max(#pa, #pb)
  for i = 1, n do
    local x = pa[i] or 0
    local y = pb[i] or 0
    if x < y then
      return true
    end
    if x > y then
      return false
    end
  end
  return false
end

function DK.version_eq_or_gt(a, b)
  return not DK.version_lt(a, b)
end

DK.RISKY_CAPS = {
  CAP_SYS_ADMIN = { sev = "HIGH", note = "near-root: mount, cgroup and namespace control" },
  CAP_SYS_PTRACE = { sev = "HIGH", note = "can attach to and tamper with host processes" },
  CAP_SYS_RAWIO = { sev = "HIGH", note = "raw I/O: direct device and port manipulation" },
  CAP_SYS_MODULE = { sev = "HIGH", note = "can load kernel modules (full host takeover)" },
  CAP_NET_ADMIN = { sev = "MEDIUM", note = "can reconfigure networking and sniff interfaces" },
  CAP_SYS_BOOT = { sev = "MEDIUM", note = "can reboot the host" },
  CAP_DAC_READ_SEARCH = { sev = "MEDIUM", note = "bypasses file read permission checks" },
  CAP_DAC_OVERRIDE = { sev = "MEDIUM", note = "bypasses all file permission checks" },
  CAP_SETUID = { sev = "MEDIUM", note = "can forge user identity" },
  CAP_SETGID = { sev = "MEDIUM", note = "can forge group identity" },
  CAP_SYSLOG = { sev = "LOW", note = "can read kernel audit logs" },
  CAP_AUDIT_CONTROL = { sev = "LOW", note = "can disable the kernel audit subsystem" },
}

DK.HOST_DEVICES = {
  ["/dev/kmem"] = { sev = "HIGH", note = "kernel memory: arbitrary kernel read/write" },
  ["/dev/mem"] = { sev = "HIGH", note = "physical memory: full host memory access" },
  ["/dev/sda"] = { sev = "HIGH", note = "whole disk: overwrite boot blocks and partitions" },
  ["/dev/sdb"] = { sev = "MEDIUM", note = "secondary disk device" },
  ["/dev/nvme0n1"] = { sev = "MEDIUM", note = "NVMe whole disk device" },
  ["/dev/dri/card0"] = { sev = "LOW", note = "GPU card device" },
  ["/dev/fuse"] = { sev = "LOW", note = "FUSE: filesystem mounts from userspace" },
}

DK.SENSITIVE_HOST_PATHS = {
  ["/var/run/docker.sock"] = { sev = "CRITICAL", note = "Docker socket: full daemon control from inside the container" },
  ["/run/docker.sock"] = { sev = "CRITICAL", note = "Docker socket: full daemon control from inside the container" },
  ["/"] = { sev = "CRITICAL", note = "entire host root filesystem mounted into the container" },
  ["/boot"] = { sev = "HIGH", note = "boot partition: kernel and initrd tampering" },
  ["/etc"] = { sev = "HIGH", note = "host configuration: shadow, ssh keys, cron" },
  ["/root"] = { sev = "HIGH", note = "root home: ssh keys and credentials" },
  ["/home"] = { sev = "HIGH", note = "user homes: credentials and documents" },
  ["/var/lib"] = { sev = "HIGH", note = "state directory: databases and daemon state" },
  ["/var/run"] = { sev = "MEDIUM", note = "runtime sockets (ssh-agent, dbus, other daemons)" },
  ["/proc"] = { sev = "MEDIUM", note = "host /proc: process environment including secrets" },
  ["/sys"] = { sev = "MEDIUM", note = "host /sys: kernel and driver configuration" },
  ["/dev"] = { sev = "MEDIUM", note = "host device nodes" },
  ["/var/log"] = { sev = "LOW", note = "log files may embed credentials and tokens" },
  ["/usr"] = { sev = "LOW", note = "host binaries and libraries (read is lower risk)" },
}

DK.SECRET_RULES = {
  { name = "aws-access-key-id",   key = "^AWS_ACCESS_KEY_ID$",    val = "^AKIA[0-9A-Z]+$",        sev = "CRITICAL" },
  { name = "aws-secret-key",      key = "^AWS_SECRET_ACCESS_KEY$", val = ".+", min_len = 20,      sev = "CRITICAL" },
  { name = "google-service-key",  key = "^GOOGLE_.*$",            val = ".+", min_len = 16,       sev = "HIGH" },
  { name = "google-service-key",  key = "^GCLOUD_.*$",            val = ".+", min_len = 16,       sev = "HIGH" },
  { name = "github-token",        key = "^GITHUB_TOKEN$",         val = "^gh[pousr]_%x+$",        sev = "CRITICAL" },
  { name = "github-token",        key = "^GH_TOKEN$",             val = "^gh[pousr]_%x+$",        sev = "CRITICAL" },
  { name = "slack-token",         key = "^SLACK_TOKEN$",          val = "^xox[baprs]-",           sev = "HIGH" },
  { name = "slack-webhook",       key = "^SLACK_WEBHOOK$",        val = "^xox[baprs]-",           sev = "HIGH" },
  { name = "private-key-block",   key = ".*PRIVATE_KEY$",         val = "^-----BEGIN",            sev = "CRITICAL" },
  { name = "private-key-block",   key = ".*RSA_KEY$",             val = "^-----BEGIN",            sev = "CRITICAL" },
  { name = "private-key-block",   key = ".*PEM$",                 val = "^-----BEGIN",            sev = "CRITICAL" },
  { name = "bearer-jwt",          key = ".*TOKEN$",               val = "^eyJ[%w%-]+%.[%w%-]+%.", sev = "HIGH" },
  { name = "bearer-jwt",          key = ".*BEARER$",              val = "^eyJ[%w%-]+%.[%w%-]+%.", sev = "HIGH" },
  { name = "bearer-jwt",          key = ".*AUTH$",                val = "^eyJ[%w%-]+%.[%w%-]+%.", sev = "HIGH" },
  { name = "db-password",         key = "PASSWORD$",              val = ".+", min_len = 6,        sev = "HIGH" },
  { name = "generic-password",    key = "PASSWD$",                val = ".+", min_len = 8,        sev = "HIGH" },
  { name = "generic-password",    key = "PWD$",                   val = ".+", min_len = 8,        sev = "HIGH" },
  { name = "generic-secret",      key = "SECRET$",                val = ".+", min_len = 12,       sev = "HIGH" },
  { name = "generic-secret",      key = "API_KEY$",               val = ".+", min_len = 12,       sev = "HIGH" },
  { name = "generic-secret",      key = "APIKEY$",                val = ".+", min_len = 12,       sev = "HIGH" },
  { name = "generic-secret",      key = "ACCESS_KEY$",            val = ".+", min_len = 12,       sev = "HIGH" },
  { name = "connection-string",   key = "DSN$",                   val = "^%w+://[^%s:]+:%S+@",   sev = "HIGH" },
  { name = "connection-string",   key = "CONN_STRING$",           val = "^%w+://[^%s:]+:%S+@",   sev = "HIGH" },
}

DK.CVE_TABLE = {
  {
    id = "CVE-2024-21626",
    component = "runc",
    fixed = "1.1.12",
    sev = "HIGH",
    summary = "Leaky Vessels: runc workdir breakout lets a malicious image read host files from the working directory",
  },
  {
    id = "CVE-2023-25807",
    component = "runc",
    fixed = "1.1.12",
    sev = "MEDIUM",
    summary = "runc workdir breakout via a malicious image allowing read of host files",
  },
  {
    id = "CVE-2019-5736",
    component = "runc",
    fixed = "1.0-rc4",
    sev = "HIGH",
    summary = "runc container breakout: host files overwritten when container process terminates (setns TOCTOU)",
  },
  {
    id = "CVE-2019-14271",
    component = "engine",
    fixed = "19.03.8",
    sev = "HIGH",
    summary = "docker cp helper: library injection allowing root-level container-to-host breakout",
  },
  {
    id = "CVE-2020-13401",
    component = "engine",
    fixed = "20.10.8",
    sev = "MEDIUM",
    summary = "Docker Swarm bridge IPv6: rogue router advertisement spoofing on the host network",
  },
  {
    id = "CVE-2020-15228",
    component = "engine",
    fixed = "20.10.2",
    sev = "MEDIUM",
    summary = "Docker daemon: local user with access to the socket can read arbitrary files on the host",
  },
  {
    id = "CVE-2018-15664",
    component = "runc",
    fixed = "1.0-rc8",
    sev = "HIGH",
    summary = "runc: privileged container can read and write arbitrary files on the host via /proc escape",
  },
}

DK.PPROF_ENDPOINTS = {
  ["/debug/pprof"] = { kind = "index", desc = "profiling index (lists all exposed profiles)" },
  ["/debug/pprof/cmdline"] = { kind = "cmdline", desc = "daemon command line and flags" },
  ["/debug/pprof/flags"] = { kind = "flags", desc = "daemon runtime flags" },
  ["/debug/pprof/goroutine"] = { kind = "goroutine", desc = "live goroutine stack traces" },
  ["/debug/pprof/heap"] = { kind = "heap", desc = "heap allocation profile (memory contents)" },
  ["/debug/pprof/profile"] = { kind = "cpu", desc = "CPU profile generation (client-supplied duration)" },
  ["/debug/pprof/symbol"] = { kind = "symbol", desc = "symbol table lookup" },
  ["/debug/pprof/trace"] = { kind = "trace", desc = "execution trace" },
  ["/debug/vars"] = { kind = "expvar", desc = "expvar runtime statistics and counters" },
}

DK.BLOCKED_STATUSES = { [403] = true, [405] = true }
DK.AUTH_STATUSES = { [401] = true }

function DK.mask_secret(value)
  local s = tostring(value or "")
  local len = #s
  if len <= 8 then
    return "****"
  end
  return s:sub(1, 4) .. "****" .. s:sub(-4) .. " (len=" .. tostring(len) .. ")"
end

function DK.classify_caps(caps)
  local hits = {}
  local all = false
  for _, cap in ipairs(caps or {}) do
    local c = tostring(cap):upper()
    if c == "CAP_ALL" or c == "ALL" then
      all = true
      break
    end
    local meta = DK.RISKY_CAPS[c]
    if meta then
      table.insert(hits, { cap = c, sev = meta.sev, note = meta.note })
    end
  end
  return hits, all
end

function DK.classify_device(path)
  local p = tostring(path or "")
  local meta = DK.HOST_DEVICES[p]
  if meta then
    return meta.sev, meta.note
  end
  if p:match("^/dev/") then
    return "MEDIUM", "non-standard host device passthrough"
  end
  return nil
end

function DK.classify_host_path(path)
  local p = tostring(path or "")
  local meta = DK.SENSITIVE_HOST_PATHS[p]
  if meta then
    return meta.sev, meta.note
  end
  local base = p:match("^(/[^/]+)")
  if base and DK.SENSITIVE_HOST_PATHS[base] then
    local m = DK.SENSITIVE_HOST_PATHS[base]
    return m.sev, m.note
  end
  if p:match("^/var/run/.+sock$") or p:match("^/run/.+sock$") then
    return "HIGH", "daemon socket exposed to the container"
  end
  return nil
end

function DK.scan_env_pair(key, value)
  local k = tostring(key or "")
  local v = tostring(value or "")
  if v == "" then
    return nil
  end
  local ku = k:upper()
  for _, rule in ipairs(DK.SECRET_RULES) do
    if ku:match(rule.key) and v:match(rule.val) then
      if rule.min_len == nil or #v >= rule.min_len then
        return { rule = rule.name, sev = rule.sev, key = k, masked = DK.mask_secret(v) }
      end
    end
  end
  if v:match("^-----BEGIN [A-Z ]*PRIVATE KEY") then
    return { rule = "private-key-block", sev = "CRITICAL", key = k, masked = DK.mask_secret(v) }
  end
  return nil
end

function DK.parse_env_list(env_list)
  local env = {}
  for _, entry in ipairs(env_list or {}) do
    local k, v = tostring(entry):match("^([^=]+)=(.*)$")
    if k then
      env[k] = v
    end
  end
  return env
end

function DK.classify_mounts(mounts, binds)
  local findings = {}
  local seen = {}
  local function add(source, dest, mode, rw, origin)
    local key = source .. "=>" .. dest
    if seen[key] then
      return
    end
    seen[key] = true
    local source_path = source
    if source_path:match("^/var/run/docker.sock$") or source_path:match("^/run/docker.sock$") then
      table.insert(findings, {
        source = source, dest = dest, mode = mode, rw = rw, origin = origin,
        sev = "CRITICAL", note = "Docker daemon socket bind-mounted into the container",
      })
      return
    end
    local sev, note = DK.classify_host_path(source_path)
    if sev then
      if rw and sev == "LOW" then
        sev = "MEDIUM"
      end
      if rw and (sev == "MEDIUM") and (source_path:match("^/etc$") or source_path:match("^/root$")) then
        sev = "HIGH"
      end
      table.insert(findings, {
        source = source, dest = dest, mode = mode, rw = rw, origin = origin,
        sev = sev, note = note,
      })
    end
  end
  for _, b in ipairs(binds or {}) do
    local parts = {}
    for piece in tostring(b):gmatch("[^,]+") do
      table.insert(parts, piece)
    end
    if #parts >= 2 then
      local rw = true
      local mode = "rw"
      for i = 2, #parts do
        if parts[i] == "ro" then
          rw = false
          mode = "ro"
        elseif parts[i] == "rw" then
          rw = true
          mode = "rw"
        end
      end
      add(parts[1], parts[2], mode, rw, "bind")
    end
  end
  for _, m in ipairs(mounts or {}) do
    local source = m.Source or m.source
    local dest = m.Destination or m.destination
    local mode = m.Mode or "rw"
    local rw = (m.RW == nil) and true or (m.RW == true)
    if source and dest then
      add(source, dest, mode, rw, "mount")
    end
  end
  return findings
end

function DK.classify_limits(host_config)
  local hc = host_config or {}
  local findings = {}
  local memory = hc.Memory
  if memory == nil or memory == 0 then
    table.insert(findings, {
      field = "Memory", value = tostring(memory or 0), sev = "MEDIUM",
      note = "no memory limit: runaway allocations can OOM-kill host processes",
    })
  end
  local nano = hc.NanoCpus
  local shares = hc.CpuShares
  if (nano == nil or nano == 0) and (shares == nil or shares == 0) then
    table.insert(findings, {
      field = "NanoCpus/CpuShares", value = "0", sev = "MEDIUM",
      note = "no CPU limit: the container can starve host CPU",
    })
  end
  local pids = hc.PidsLimit
  if pids == nil or pids == 0 or pids == -1 then
    table.insert(findings, {
      field = "PidsLimit", value = tostring(pids or -1), sev = "MEDIUM",
      note = "no PID limit: fork-bomb inside the container can exhaust host PIDs",
    })
  end
  if hc.OomKillDisable == true then
    table.insert(findings, {
      field = "OomKillDisable", value = "true", sev = "LOW",
      note = "OOM killer disabled: memory overuse is no longer self-mitigating",
    })
  end
  return findings
end

function DK.classify_container(container)
  local findings = {}
  local hc = container.HostConfig or {}
  local nc = container.NetworkSettings or {}
  if hc.Privileged == true then
    table.insert(findings, {
      field = "HostConfig.Privileged", value = "true", sev = "CRITICAL",
      note = "privileged container: all capabilities and host devices available, trivial escape",
    })
  end
  local cap_hits, all = DK.classify_caps(hc.CapAdd)
  if all then
    table.insert(findings, {
      field = "HostConfig.CapAdd", value = "CAP_ALL", sev = "CRITICAL",
      note = "CAP_ALL grants every kernel capability",
    })
  end
  for _, hit in ipairs(cap_hits) do
    table.insert(findings, {
      field = "HostConfig.CapAdd", value = hit.cap, sev = hit.sev,
      note = hit.note,
    })
  end
  local seccomp = hc.SeccompProfileName
  if seccomp == "unconfined" then
    table.insert(findings, {
      field = "HostConfig.SeccompProfileName", value = "unconfined", sev = "HIGH",
      note = "seccomp syscall filtering disabled: every syscall is available",
    })
  end
  local apparmor = hc.AppArmorProfile
  if apparmor == "unconfined" then
    table.insert(findings, {
      field = "HostConfig.AppArmorProfile", value = "unconfined", sev = "MEDIUM",
      note = "AppArmor confinement disabled",
    })
  end
  for _, dev in ipairs(hc.Devices or {}) do
    local path = dev.PathOnHost or dev.path_on_host
    if path then
      local sev, note = DK.classify_device(path)
      if sev then
        table.insert(findings, {
          field = "HostConfig.Devices", value = path, sev = sev,
          note = note,
        })
      end
    end
  end
  for _, f in ipairs(DK.classify_limits(hc)) do
    table.insert(findings, f)
  end
  local mount_hits = DK.classify_mounts(container.Mounts, hc.Binds)
  for _, m in ipairs(mount_hits) do
    table.insert(findings, {
      field = "Mounts", value = m.source .. " => " .. m.dest .. " (" .. m.mode .. ")",
      sev = m.sev, note = m.note,
    })
  end
  local network_mode = hc.NetworkMode or nc.NetworkMode
  if network_mode == "host" then
    table.insert(findings, {
      field = "HostConfig.NetworkMode", value = "host", sev = "MEDIUM",
      note = "host networking: container shares the host network namespace and loopback",
    })
  end
  local ports = nc.Ports or {}
  local exposed = {}
  for _, pl in pairs(ports) do
    for _, binding in ipairs(pl or {}) do
      local ip = binding.HostIp or binding.HIP or "0.0.0.0"
      if ip ~= "127.0.0.1" and ip ~= "::1" then
        table.insert(exposed, { ip = ip, port = binding.HostPort or binding.HPORT })
      end
    end
  end
  table.sort(exposed, function(a, b) return tostring(a.port) < tostring(b.port) end)
  return findings, exposed
end

local HISTORY_RULES = {
  { name = "basic-auth-in-curl", pat = "curl[^;&]-u%s+[%w._%-]+:[%w!@#$%^&*()_.-]+", sev = "HIGH", note = "basic-auth credentials embedded in a build step" },
  { name = "basic-auth-arg", pat = "%-%-basic%-%-auth%s+[\"']?[%w._%-]+:[%w!@#$%^&*()_.%-]+", sev = "HIGH", note = "basic-auth credentials embedded in a build step" },
  { name = "bearer-in-build", pat = "Bearer%s+eyJ[%w%-]+%.[%w%-]+%.", sev = "HIGH", note = "JWT/bearer token embedded in a build step" },
  { name = "bearer-header-in-build", pat = "Authorization[%s:]+[\"']?Bearer%s+eyJ[%w%-]+%.[%w%-]+%.", sev = "HIGH", note = "JWT/bearer token embedded in a build step" },
  { name = "aws-key-in-build", pat = "AKIA[0-9A-Z]+", sev = "CRITICAL", note = "AWS access key id embedded in a build step" },
  { name = "aws-secret-in-build", pat = "AWS_SECRET_ACCESS_KEY=%S+", sev = "CRITICAL", min_len = 20, note = "AWS secret key embedded in image history" },
  { name = "github-token-in-build", pat = "ghp_%x+", sev = "CRITICAL", note = "GitHub token embedded in a build step" },
  { name = "slack-token-in-build", pat = "xox[baprs]-[%w%-]+", sev = "CRITICAL", note = "Slack token embedded in a build step" },
  { name = "stripe-token-in-build", pat = "sk_live_[%w%-]+", sev = "CRITICAL", note = "Stripe live token embedded in a build step" },
  { name = "private-key-in-build", pat = "-----BEGIN [A-Z ]*PRIVATE KEY", sev = "CRITICAL", note = "private key material embedded in a build step" },
  { name = "arg-leak-marker", pat = "^ARG%s+[A-Z_%d]+%s*=[%w!@#$%^&*()._-]+", sev = "MEDIUM", note = "ARG with a literal value persisted in image history" },
  { name = "pass-in-url", pat = "%w+://[%w._%-]+:[%w!@#$%^&*()_.%-]+@", sev = "HIGH", note = "credentials embedded in a URL inside a build step" },
}

function DK.scan_build_step(created_by)
  local s = tostring(created_by or "")
  if s == "" then
    return nil
  end
  local upper = s:upper()
  if upper:match("^CMD") or upper:match("^EXPOSE") or upper:match("^WORKDIR")
      or upper:match("^LABEL") or upper:match("^USER") or upper:match("^STOPSIGNAL") then
    return nil
  end
  for _, rule in ipairs(HISTORY_RULES) do
    local found = s:match(rule.pat)
    if found then
      if rule.min_len == nil or #found >= rule.min_len then
        return { rule = rule.name, sev = rule.sev, note = rule.note }
      end
    end
  end
  return nil
end

function DK.write_verdict(method, path, status)
  if status == nil then
    return "unknown", "request failed with no HTTP status"
  end
  if DK.BLOCKED_STATUSES[status] then
    return "blocked", "proxy/daemon rejected the mutating verb (" .. tostring(status) .. ")"
  end
  if DK.AUTH_STATUSES[status] then
    return "auth-required", "mutating endpoint demands credentials (401)"
  end
  return "open", "mutating endpoint reachable with no proxy filtering (" .. tostring(method) .. " " .. tostring(path) .. " -> " .. tostring(status) .. ")"
end

function DK.swarm_mask(token)
  local t = tostring(token or "")
  if #t <= 12 then
    return "****"
  end
  return t:sub(1, 12) .. "****"
end

function DK.event_count_by_action(events)
  local counts = {}
  local total = 0
  for _, ev in ipairs(events or {}) do
    local action = ev.Action or ev.action or "unknown"
    counts[action] = (counts[action] or 0) + 1
    total = total + 1
  end
  return counts, total
end

function DK.parse_http_response(raw)
  if type(raw) ~= "string" or raw == "" then
    return nil, "empty response"
  end
  local header_end = raw:find("\r\n\r\n", 1, true)
  if not header_end then
    header_end = raw:find("\n\n", 1, true)
    if not header_end then
      return nil, "no header/body separator"
    end
    local status_line = raw:sub(1, header_end)
    local status_code = status_line:match("^HTTP/%d%.%d%s+(%d%d%d)")
    if not status_code then
      return nil, "malformed status line"
    end
    return {
      status = tonumber(status_code),
      reason = status_line:match("^HTTP/%d%.%d%s+%d%d%d%s*(.*)$") or "",
      headers = {},
      body = "",
    }
  end
  local head = raw:sub(1, header_end - 2)
  local body = raw:sub(header_end + 4)
  local status_code = head:match("^HTTP/%d%.%d%s+(%d%d%d)")
  if not status_code then
    return nil, "malformed status line"
  end
  local reason = head:match("^HTTP/%d%.%d%s+%d%d%d%s*(.*)$") or ""
  local headers = {}
  for line in head:gmatch("\r?\n([^\r\n]+)") do
    local k, v = line:match("^([^:]+):%s*(.*)$")
    if k then
      headers[k:lower()] = v
    end
  end
  local resp = {
    status = tonumber(status_code),
    reason = reason,
    headers = headers,
    body = body,
  }
  if headers["transfer-encoding"] and headers["transfer-encoding"]:lower():find("chunked") then
    local decoded, derr = DK.chunked_decode(body)
    if decoded then
      resp.body = decoded
    end
  end
  return resp
end

function DK.chunked_decode(data)
  local out = {}
  local pos = 1
  local chunks = 0
  while true do
    local size_line_end = data:find("\r\n", pos)
    if not size_line_end then
      size_line_end = data:find("\n", pos)
      if not size_line_end then
        if pos > #data then
          break
        end
        return nil, "truncated chunk size line"
      end
    end
    local size_hex = data:sub(pos, size_line_end):match("^%s*(%x+)")
    if not size_hex then
      return nil, "bad chunk size"
    end
    local size = tonumber(size_hex, 16)
    if size == nil then
      return nil, "bad chunk size value"
    end
    if size == 0 then
      break
    end
    local data_start
    if data:sub(size_line_end, size_line_end) == "\n" then
      data_start = size_line_end + 1
    else
      data_start = size_line_end + 2
    end
    local chunk = data:sub(data_start, data_start + size - 1)
    if #chunk < size then
      return nil, "truncated chunk body"
    end
    table.insert(out, chunk)
    chunks = chunks + 1
    pos = data_start + size + 2
    if pos > #data and size > 0 then
      return nil, "trailing data missing"
    end
    if chunks > 4096 then
      break
    end
  end
  return table.concat(out)
end

function DK.session_open(host, port, timeout)
  local nmap_mod = nmap
  local sock, serr = nmap_mod.new_socket("tcp")
  if not sock then
    return nil, "socket creation failed: " .. tostring(serr)
  end
  sock:set_timeout(timeout or 5000)
  local ok, cerr = sock:connect(host.ip or host, port.number or port)
  if not ok then
    sock:close()
    return nil, "connect failed: " .. tostring(cerr)
  end
  return {
    sock = sock,
    host = host.ip or host,
    port = port.number or port,
    request_count = 0,
  }
end

function DK.session_request(sess, method, path, body, opts)
  opts = opts or {}
  local max_bytes = opts.max_bytes or 262144
  local req_parts = {
    method .. " " .. path .. " HTTP/1.1",
    "Host: " .. sess.host .. ":" .. tostring(sess.port),
    "User-Agent: NSE-Security-Audit/1.0",
    "Accept: */*",
  }
  if body and body ~= "" then
    table.insert(req_parts, "Content-Length: " .. tostring(#body))
  end
  if opts.header then
    for k, v in pairs(opts.header) do
      table.insert(req_parts, k .. ": " .. v)
    end
  end
  table.insert(req_parts, "Connection: close")
  table.insert(req_parts, "")
  local full = table.concat(req_parts, "\r\n")
  if body and body ~= "" then
    full = full .. "\r\n" .. body
  end
  sess.request_count = (sess.request_count or 0) + 1
  local sent, send_err = sess.sock:send(full)
  if not sent then
    return nil, "send failed: " .. tostring(send_err)
  end
  local collected = ""
  local got = 0
  local deadline = 6
  while got < deadline do
    local ok, chunk, rerr = sess.sock:receive_bytes(math.min(16384, max_bytes - #collected))
    if not ok or chunk == nil then
      if collected == "" then
        return nil, "read failed: " .. tostring(rerr)
      end
      break
    end
    collected = collected .. chunk
    if collected:find("\r\n\r\n", 1, true) then
      local resp = DK.parse_http_response(collected)
      if resp then
        local te = resp.headers["transfer-encoding"]
        local cl = resp.headers["content-length"]
        if te and te:lower():find("chunked") then
          if resp.body ~= nil and DK.chunked_decode(resp.body) ~= nil then
            return resp
          end
        elseif cl then
          local need = tonumber(cl) or 0
          if #resp.body >= need then
            return resp
          end
        else
          return resp
        end
      end
    end
    if collected:find("\r\n0\r\n\r\n", 1, true) or collected:find("\r\n0\n\n", 1, true) then
      local resp = DK.parse_http_response(collected)
      if resp then
        return resp
      end
    end
    got = got + 1
  end
  local resp = DK.parse_http_response(collected)
  if not resp then
    return nil, "incomplete HTTP response"
  end
  return resp
end

function DK.session_close(sess)
  if sess and sess.sock then
    sess.sock:close()
  end
end

function DK.status_is_auth(status)
  return DK.AUTH_STATUSES[status] == true
end

function DK.status_is_blocked(status)
  return DK.BLOCKED_STATUSES[status] == true
end

function DK.status_is_success(status)
  return status ~= nil and status >= 200 and status < 300
end

function DK.status_is_not_found(status)
  return status == 404
end

function DK.try_json(body)
  if type(body) ~= "string" or body == "" then
    return nil
  end
  local first = body:match("^%s*([%S])")
  if first == nil or (first ~= "{" and first ~= "[") then
    return nil
  end
  return DK.json_decode(body)
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

local function dk_request(sess, args, method, path, body, opts)
  if budget_exhausted(args) then
    return nil, "request budget exhausted"
  end
  state.requests = state.requests + 1
  local resp, err = DK.session_request(sess, method, path, body, opts)
  if not resp then
    state.errors = state.errors + 1
    return nil, err
  end
  if resp.status == 429 then
    state.rate_limited = state.rate_limited + 1
  end
  return resp
end

local function looks_like_docker_api(sess, args, base)
  local ping = dk_request(sess, args, "GET", base .. "/_ping", nil, { max_bytes = 4096 })
  if ping and ping.status == 200 and (tostring(ping.body or ""):match("^OK%s*$") or ping.headers["api-version"] ~= nil) then
    return true
  end
  local version = dk_request(sess, args, "GET", base .. "/version", nil, { max_bytes = 8192 })
  if version and version.status == 200 then
    local obj = DK.try_json(version.body)
    if type(obj) == "table" and obj.Version ~= nil then
      return true
    end
  end
  return false
end

local function parse_security_options(opts)
  local parsed = {}
  for _, entry in ipairs(opts or {}) do
    local s = tostring(entry)
    for piece in s:gmatch("[^,]+") do
      local name, value = piece:match("^name=([^,=]+)")
      local profile = piece:match("profile=([^,=]+)")
      if name then
        parsed[name] = profile or (value or "")
      end
    end
  end
  return parsed
end

action = function(host, port)

local args = read_args()
reset_findings()
reset_state()

local base = args.path or ""
base = base:gsub("/+$", "")

local sess, sess_err = DK.session_open(host, port, args.timeout * 1000)
if not sess then
  local fail_out = stdnse.output_table()
  fail_out["Risk Level"] = RISK_LEVEL
  fail_out["Status"] = "Could not open a TCP connection to the Docker API on port " .. tostring(port.number) .. ": " .. tostring(sess_err)
  return fail_out
end

local sections = {}

if not looks_like_docker_api(sess, args, base) then
  DK.session_close(sess)
  local fail_out = stdnse.output_table()
  fail_out["Risk Level"] = RISK_LEVEL
  fail_out["Status"] = "Target on port " .. tostring(port.number) .. " does not answer like a Docker Engine API; security-options check not applicable."
  return fail_out
end

local info_resp = dk_request(sess, args, "GET", base .. "/info", nil, { max_bytes = 32768 })

local status_text
if not info_resp or info_resp.status == 401 or info_resp.status == 403 then
  status_text = "NOT VULNERABLE - /info requires authentication; daemon security posture not enumerable"
  add_finding("INFO", "Daemon /info endpoint is authentication-gated", {
    subject = "/info",
    path = "/info",
    evidence = info_resp and ("status=" .. tostring(info_resp.status)) or "no response",
  })
  DK.session_close(sess)
  local unique, counts = dedupe_findings()
  return finish_output(new_output(RISK_LEVEL, status_text), unique, counts, sections)
end
if info_resp.status ~= 200 then
  status_text = "ERROR - /info returned status " .. tostring(info_resp.status)
  DK.session_close(sess)
  local unique, counts = dedupe_findings()
  return finish_output(new_output(RISK_LEVEL, status_text), unique, counts, sections)
end

local info = DK.try_json(info_resp.body)
if type(info) ~= "table" then
  status_text = "ERROR - could not parse /info JSON"
  DK.session_close(sess)
  local unique, counts = dedupe_findings()
  return finish_output(new_output(RISK_LEVEL, status_text), unique, counts, sections)
end

local opts = parse_security_options(info.SecurityOptions)
local matrix_rows = {}

local seccomp = opts["seccomp"]
if seccomp == nil then
  add_finding("MEDIUM", "No seccomp profile configured on the daemon", {
    subject = "seccomp",
    evidence = "SecurityOptions contains no name=seccomp entry",
  })
  table.insert(matrix_rows, { "seccomp", "absent", "MEDIUM", "daemon ships no default syscall filter" })
elseif seccomp == "disabled" or seccomp == "unconfined" then
  add_finding("MEDIUM", "Seccomp is explicitly disabled on the daemon", {
    subject = "seccomp",
    evidence = "profile=" .. seccomp,
  })
  table.insert(matrix_rows, { "seccomp", seccomp, "MEDIUM", "syscall filtering turned off" })
elseif seccomp ~= "default" then
  add_finding("MEDIUM", "Daemon uses a non-default seccomp profile (" .. seccomp .. ")", {
    subject = "seccomp",
    evidence = "profile=" .. seccomp,
  })
  table.insert(matrix_rows, { "seccomp", seccomp, "MEDIUM", "custom profile - verify it is not broader than default" })
else
  table.insert(matrix_rows, { "seccomp", "default", "OK", "default syscall filter active" })
end

local apparmor = opts["apparmor"]
local selinux = opts["selinux"]
if apparmor and apparmor ~= "" then
  table.insert(matrix_rows, { "apparmor", apparmor, "OK", "MAC profile active" })
elseif selinux and selinux ~= "" then
  table.insert(matrix_rows, { "selinux", selinux, "OK", "MAC profile active" })
else
  add_finding("MEDIUM", "No AppArmor or SELinux mandatory access control on the daemon", {
    subject = "mac",
    evidence = "SecurityOptions contains neither name=apparmor nor name=selinux",
  })
  table.insert(matrix_rows, { "apparmor/selinux", "absent", "MEDIUM", "no MAC layer between container and host" })
end

local userns = opts["userns-remap"]
if userns and userns ~= "" then
  table.insert(matrix_rows, { "userns-remap", userns, "OK", "container root is remapped" })
else
  add_finding("LOW", "No user namespace remapping (userns-remap) configured", {
    subject = "userns-remap",
    evidence = "SecurityOptions contains no name=userns-remap entry; container root maps to host root",
  })
  table.insert(matrix_rows, { "userns-remap", "absent", "LOW", "container root = host root" })
end

if info.LiveRestoreEnabled == true then
  table.insert(matrix_rows, { "live-restore", "on", "OK", "containers survive daemon restarts" })
else
  add_finding("INFO", "Live restore is disabled; daemon restarts stop running containers", {
    subject = "live-restore",
    evidence = "LiveRestoreEnabled=false",
  })
  table.insert(matrix_rows, { "live-restore", "off", "INFO", "availability gap during daemon restarts" })
end

if info.CgroupDriver then
  table.insert(matrix_rows, { "cgroup-driver", tostring(info.CgroupDriver), "INFO", "cgroup v1 driver choice noted" })
end

local gap_count = 0
for _, row in ipairs(matrix_rows) do
  if row[3] == "MEDIUM" or row[3] == "LOW" then
    gap_count = gap_count + 1
  end
end

if gap_count > 0 then
  status_text = "VULNERABLE - " .. tostring(gap_count) .. " daemon hardening gap(s) (seccomp/MAC/userns)"
  add_finding("MEDIUM", "Daemon hardening baseline is not met", {
    subject = "daemon",
    evidence = gap_count .. " gap(s) in the hardening matrix",
  })
else
  status_text = "NOT VULNERABLE - daemon security options meet the hardening baseline"
  add_finding("INFO", "Seccomp default, MAC and (optionally) userns-remap all present", {
    subject = "daemon",
    evidence = "matrix rows: " .. tostring(#matrix_rows),
  })
end

local tbl = stdnse.output_table()
tbl["header"] = "control | value | status | note"
for i, row in ipairs(matrix_rows) do
  tbl["row" .. i] = table.concat(row, " | ")
end
table.insert(sections, { key = "Hardening Matrix", value = tbl })

local guidance = stdnse.output_table()
guidance["1. MAC"] = "Enable AppArmor (default profile) or SELinux; add custom profiles for workloads that need more than the default."
guidance["2. Seccomp"] = "Keep seccomp=default; for unconfined containers, add an explicit profile instead of disabling the filter."
guidance["3. Userns-remap"] = "Set userns-remap in daemon.json (or run rootless Docker) so container root is not host root."
guidance["4. Live restore"] = "Enable live-restore to keep workloads running across daemon upgrades."
table.insert(sections, { key = "Remediation", value = guidance })

DK.session_close(sess)

local unique, counts = dedupe_findings()
local out = new_output(RISK_LEVEL, status_text)
return finish_output(out, unique, counts, sections)

end
