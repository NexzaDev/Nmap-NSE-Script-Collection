local shortport = require "shortport"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Checks the kubelet read-only port (10255): anonymous /pods listing
with full pod specs, volumes and container images.

Why it matters
- 10255 predates kubelet authentication; an open read-only port
  discloses the entire node workload inventory including secret
  volume mounts and environment variables.
- CIS Kubernetes Benchmark explicitly requires this port disabled.

What the script does
1. GET /pods on 10255 without credentials.
2. Summarises the disclosed pod inventory.
3. Grades the read-only port exposure.

Safe operation: one read-only GET.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"vuln", "safe"}

portrule = shortport.port_or_service(10255, "http", "tcp")

local SCRIPT_NAME = "k8s-kubelet-readonly-pods"

local RISK_LEVEL = "🔴 CRITICAL"

local DEFAULT_ARGS = {
  timeout = 8,
  maxrequests = 24,
  token = "",
}

local BOOLEAN_ARGS = {}
local STRING_ARGS = {
  "token",
}
local NUMERIC_ARGS = {
  { key = "timeout", minimum = 1, integer = true },
  { key = "maxrequests", minimum = 1, integer = true },
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

local K8 = {}

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

function K8.json_decode(text)
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

function K8.json_encode(v)
  return json_encode_value(v)
end

K8.API_PATHS = {
  version = "/version",
  api_root = "/api",
  pods = "/api/v1/pods",
  namespaces = "/api/v1/namespaces",
  nodes = "/api/v1/nodes",
  secrets = "/api/v1/secrets",
  serviceaccounts = "/api/v1/serviceaccounts",
  validating_webhooks = "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations",
  mutating_webhooks = "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations",
  selfsubject = "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
  openapi_v2 = "/openapi/v2",
  healthz = "/healthz",
  livez = "/livez",
  readyz = "/readyz",
}

K8.KUBELET_PATHS = {
  pods = "/pods",
  runningpods = "/runningpods/",
  metrics = "/metrics",
  healthz = "/healthz",
  stats_summary = "/stats/summary",
  exec_probe = "/exec",
  log_probe = "/logs/",
}

K8.ETCD_PATHS = {
  version = "/version",
  keys_prefix = "/v2/keys?prefix=true&sorted=true",
  health = "/health",
  metrics = "/metrics",
}

K8.PROXY_PATHS = {
  healthz = "/healthz",
  configz = "/configz",
  pprof = "/debug/pprof/",
  metrics = "/metrics",
}

K8.DASHBOARD_MARKERS = { "kubernetes-dashboard", "Kubernetes Dashboard", "dashboardHeaderOptions", "/login" }

K8.ETCD_VERSION_MARKER = "\"etcdserver\""

K8.VERSION_CVES = {
  { max_minor = 12, cves = { "CVE-2018-1002105 (API server proxy auth bypass)", "CVE-2019-11247 (custom resources via wrong scope)" } },
  { max_minor = 15, cves = { "CVE-2019-11250 (Bearer token logging at high verbosity)", "CVE-2019-11249 (incomplete fixes for symlink exchange)" } },
  { max_minor = 17, cves = { "CVE-2019-11253 (YAML bomb DoS via API requests)" } },
  { max_minor = 19, cves = { "CVE-2020-8554 (ClusterIP services external-IP injection)", "CVE-2020-8555 (SSRF via validated ephemeral containers)" } },
  { max_minor = 21, cves = { "CVE-2021-25735 (node admission bypass via old windows field)", "CVE-2021-25741 (symlink exchange subpath volumes)" } },
  { max_minor = 23, cves = { "CVE-2022-3172 (aggregated API server redirect leak)" } },
  { max_minor = 25, cves = { "CVE-2023-2431 (bypass of mountable secrets policy in JWT authenticator)" } },
}

K8.JWT_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

K8.SYSTEM_NAMESPACES = { "kube-system", "kube-public", "kube-node-lease" }

K8.SENSITIVE_VERBS = { "create", "update", "patch", "delete", "deletecollection", "escalate", "impersonate", "bind" }

K8.RISKY_POD_SIGNALS = {
  { key = "privileged", label = "privileged container" },
  { key = "hostPID", label = "host PID namespace" },
  { key = "hostNetwork", label = "host network namespace" },
  { key = "hostIPC", label = "host IPC namespace" },
}

K8.DANGEROUS_CAPS = {
  ["SYS_ADMIN"] = "full administrative capability - container escape primitives",
  ["NET_ADMIN"] = "network administration - packet interception and routing manipulation",
  ["SYS_PTRACE"] = "process inspection across containers",
  ["DAC_READ_SEARCH"] = "file read bypass - host file disclosure",
  ["SYS_TIME"] = "host clock manipulation",
  ["MKNOD"] = "device node creation on the host",
}

K8.PPC_LEVELS = { "privileged", "baseline", "restricted" }

local function b64_char_value(c)
  return string.find(K8.JWT_B64, c, 1, true) - 1
end

local function b64_decode_url(s)
  s = s:gsub("-", "+"):gsub("_", "/")
  local pad = (4 - #s % 4) % 4
  s = s .. string.rep("=", pad)
  return (s:gsub(".", function(c)
    if c == "=" then
      return ""
    end
    local v = b64_char_value(c)
    if v == nil then
      return ""
    end
    return string.char(math.floor(v / 4))
      .. (v % 4 >= 2 and string.char(math.floor(v / 16) * 16 + math.floor((v % 16) / 4) * 4) or "")
  end))
end

local function b64_decode_chunks(s)
  local out = {}
  local i = 1
  while i <= #s do
    local quad = s:sub(i, i + 3)
    quad = quad:gsub("%-", "/"):gsub("%%_", "/"):gsub("_", "/")
    local pad = (4 - #quad % 4) % 4
    quad = quad .. string.rep("A", pad)
    local n = 0
    for j = 1, 4 do
      local cv = string.find("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", quad:sub(j, j), 1, true)
      if cv == nil then
        cv = 1
      end
      n = n * 64 + (cv - 1)
    end
    out[#out + 1] = string.char(math.floor(n / 65536) % 256, math.floor(n / 256) % 256, n % 256)
    i = i + 4
  end
  return table.concat(out)
end

K8.b64url_decode = function(s)
  if type(s) ~= "string" or s == "" then
    return nil
  end
  local ok, out = pcall(b64_decode_chunks, s:gsub("=+$", ""))
  if not ok then
    return nil
  end
  return out
end

K8.parse_jwt = function(token)
  if type(token) ~= "string" then
    return nil, "token is not a string"
  end
  local head_b64, payload_b64, sig = token:match("^([%w%-%_]+)%.([%w%-%_]+)%.(.*)$")
  if not head_b64 or not payload_b64 then
    return nil, "not a JWT structure (header.payload.signature)"
  end
  local head_json = K8.b64url_decode(head_b64)
  local payload_json = K8.b64url_decode(payload_b64)
  if not head_json or not payload_json then
    return nil, "base64url segments do not decode"
  end
  local head = K8.json_decode(head_json)
  local payload = K8.json_decode(payload_json)
  if type(head) ~= "table" or type(payload) ~= "table" then
    return nil, "JWT segments are not JSON objects"
  end
  return {
    alg = head.alg,
    typ = head.typ,
    kubernetes_io = payload["kubernetes.io"],
    iss = payload.iss,
    sub = payload.sub,
    aud = payload.aud,
    exp = payload.exp,
    nbf = payload.nbf,
    signature_bytes = #sig,
  }
end

K8.analyze_token = function(token)
  local jwt, err = K8.parse_jwt(token)
  if jwt == nil then
    return { valid = false, reason = err }
  end
  local out = {
    valid = true,
    alg = jwt.alg,
    issuer = jwt.iss,
    subject = jwt.sub,
    audience = jwt.aud,
    expires = jwt.exp,
    signature_bytes = jwt.signature_bytes,
  }
  local now = os.time()
  if jwt.exp and jwt.exp < now then
    out.expired = true
  end
  if jwt.kubernetes_io then
    out.service_account = jwt.kubernetes_io.serviceaccount
      and jwt.kubernetes_io.serviceaccount.name or nil
    out.namespace = jwt.kubernetes_io.namespace
    out.node_name = jwt.kubernetes_io.node
      and jwt.kubernetes_io.node.name or nil
    out.pod_name = jwt.kubernetes_io.pod
      and jwt.kubernetes_io.pod.name or nil
  end
  if jwt.alg == "none" then
    out.unsafely_signed = true
  end
  return out
end

K8.list_items = function(doc)
  if type(doc) ~= "table" or type(doc.items) ~= "table" then
    return nil
  end
  return doc.items
end

K8.pod_summary = function(pod)
  if type(pod) ~= "table" then
    return nil
  end
  local meta = pod.metadata or {}
  local spec = pod.spec or {}
  local out = {
    namespace = meta.namespace or "default",
    name = meta.name or "-",
    host_network = spec.hostNetwork == true,
    host_pid = spec.hostPID == true,
    host_ipc = spec.hostIPC == true,
    containers = 0,
    privileged = 0,
    caps = {},
  }
  local specs = spec.containers or {}
  for _, c in ipairs(specs) do
    out.containers = out.containers + 1
    local sc = c.securityContext or {}
    if sc.privileged == true then
      out.privileged = out.privileged + 1
    end
    local caps = sc.capabilities or {}
    for _, cap in ipairs(caps.add or {}) do
      out.caps[cap] = true
    end
  end
  return out
end

K8.analyze_pod_security = function(items)
  local out = {
    total = 0,
    privileged_pods = {},
    host_ns_pods = {},
    dangerous_caps = {},
  }
  for _, pod in ipairs(items or {}) do
    local s = K8.pod_summary(pod)
    if s ~= nil then
      out.total = out.total + 1
      local ident = s.namespace .. "/" .. s.name
      if s.privileged > 0 then
        out.privileged_pods[#out.privileged_pods + 1] = ident .. " (" .. s.privileged .. " privileged container(s))"
      end
      local host_flags = {}
      if s.host_network then
        host_flags[#host_flags + 1] = "hostNetwork"
      end
      if s.host_pid then
        host_flags[#host_flags + 1] = "hostPID"
      end
      if s.host_ipc then
        host_flags[#host_flags + 1] = "hostIPC"
      end
      if #host_flags > 0 then
        out.host_ns_pods[#out.host_ns_pods + 1] = ident .. " [" .. table.concat(host_flags, ",") .. "]"
      end
      for cap in pairs(s.caps) do
        if K8.DANGEROUS_CAPS[cap] then
          out.dangerous_caps[cap] = ident
        end
      end
    end
  end
  return out
end

K8.webhook_summary = function(items)
  local out = {}
  for _, cfg in ipairs(items or {}) do
    local meta = cfg.metadata or {}
    local hooks = cfg.webhooks or {}
    for _, wh in ipairs(hooks) do
      out[#out + 1] = {
        configuration = meta.name or "-",
        webhook = wh.name or "-",
        failure_policy = wh.failurePolicy or "-",
        match_policy = wh.matchPolicy or "-",
        timeout = tostring(wh.timeoutSeconds or "-"),
        namespace_selector = (wh.namespaceSelector ~= nil) or false,
      }
    end
  end
  return out
end

K8.rbac_verbs = function(doc)
  local out = { allowed = {} }
  local status = doc and doc.status or nil
  if status == nil then
    return out
  end
  local rrs = status.resourceRules or {}
  for _, rule in ipairs(rrs) do
    for _, verb in ipairs(rule.verbs or {}) do
      out.allowed[verb] = (out.allowed[verb] or 0) + 1
    end
  end
  return out
end

K8.count_kind = function(doc, kind)
  if type(doc) ~= "table" then
    return nil
  end
  if doc.kind and kind and doc.kind ~= kind then
    return doc.kind
  end
  return doc.items and #doc.items or 0
end

K8.analyze_version = function(doc)
  if type(doc) ~= "table" then
    return nil
  end
  local gv = doc.gitVersion or ""
  local major = doc.major or "0"
  local minor_txt = tostring(doc.minor or "0")
  local minor = tonumber(minor_txt:match("^(%d+)")) or 0
  local out = {
    git_version = gv,
    major = major,
    minor = minor,
    platform = doc.platform or "-",
    go_version = doc.goVersion or "-",
    emitter = doc.gitCommit or "-",
  }
  local advisory = {}
  for _, e in ipairs(K8.VERSION_CVES) do
    if minor <= e.max_minor then
      for _, c in ipairs(e.cves) do
        advisory[#advisory + 1] = c
      end
    end
  end
  out.advisories = advisory
  return out
end

K8.analyze_etcd_version = function(doc)
  if type(doc) ~= "table" then
    return nil
  end
  return {
    etcdserver = doc.etcdserver or "-",
    etcdcluster = doc.etcdcluster or "-",
  }
end

K8.analyze_metrics = function(body)
  if type(body) ~= "string" or body == "" then
    return nil
  end
  local families = {}
  local samples = 0
  local interesting = {}
  for line in body:gmatch("[^\r\n]+") do
    local name = line:match("^([%w_:%.]+)%s*")
    if name then
      samples = samples + 1
      if families[name] == nil then
        families[name] = true
        if #interesting < 12 then
          interesting[#interesting + 1] = name
        end
      end
    end
  end
  return { sample_lines = samples, families = families, interesting = interesting }
end

K8.is_html_dashboard = function(body)
  if type(body) ~= "string" or body == "" then
    return false
  end
  for _, marker in ipairs(K8.DASHBOARD_MARKERS) do
    if body:find(marker, 1, true) then
      return true
    end
  end
  return false
end

K8.openapi_summary = function(doc)
  if type(doc) ~= "table" then
    return nil
  end
  local paths = doc.paths or {}
  local count = 0
  local sensitive = {}
  for path in pairs(paths) do
    count = count + 1
    if path:find("exec", 1, true) or path:find("secrets", 1, true) or path:find("token", 1, true) then
      sensitive[#sensitive + 1] = path
    end
  end
  return { info = doc.info and doc.info.title or "-", api_version = doc.info and doc.info.version or "-",
    path_count = count, sensitive_paths = sensitive }
end

function K8.parse_http_response(raw)
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
    local decoded, derr = K8.chunked_decode(body)
    if decoded then
      resp.body = decoded
    end
  end
  return resp
end

function K8.chunked_decode(data)
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

K8.selftest = function()
  local pass = 0
  local fail = 0
  local function expect_eq(got, want, label)
    if got == want then
      pass = pass + 1
    else
      fail = fail + 1
      stdnse.debug1("k8s selftest FAIL %s: got %s want %s", label, tostring(got), tostring(want))
    end
  end

  local doc = K8.json_decode('{"kind":"PodList","items":[{"metadata":{"name":"a","namespace":"ns1"},"spec":{"hostNetwork":true,"containers":[{"securityContext":{"privileged":true,"capabilities":{"add":["SYS_ADMIN","NET_ADMIN"]}}}]}}]}')
  expect_eq(doc ~= nil and doc.kind, "PodList", "json decode podlist")
  local sec = K8.analyze_pod_security(doc.items)
  expect_eq(sec.total, 1, "pod security total")
  expect_eq(#sec.privileged_pods, 1, "privileged pod flagged")
  expect_eq(sec.dangerous_caps.SYS_ADMIN ~= nil, true, "SYS_ADMIN flagged")

  local jwt_ok = K8.parse_jwt("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50IiwiZXhwIjo5OTk5OTk5OTk5fQ.c2ln")
  expect_eq(jwt_ok ~= nil and jwt_ok.iss, "kubernetes/serviceaccount", "jwt payload decode")

  local webhooks = K8.webhook_summary({ { metadata = { name = "cfg1" }, webhooks = { { name = "hook.one", failurePolicy = "Fail", timeoutSeconds = 10 } } } })
  expect_eq(#webhooks, 1, "webhook summary count")
  expect_eq(webhooks[1].failure_policy, "Fail", "webhook failure policy")

  local ver = K8.analyze_version({ gitVersion = "v1.19.3", major = "1", minor = "19", platform = "linux/amd64" })
  expect_eq(ver.minor, 19, "version minor")
  expect_eq(#ver.advisories > 0, true, "version advisories present")

  local etcd = K8.analyze_etcd_version({ etcdserver = "3.5.6", etcdcluster = "3.5.0" })
  expect_eq(etcd.etcdserver, "3.5.6", "etcd version")

  local metrics = K8.analyze_metrics("coredns_dns_requests_total 1\ncoredns_dns_responses_total 2\n")
  expect_eq(metrics ~= nil and metrics.sample_lines, 2, "metrics sample lines")

  expect_eq(K8.is_html_dashboard("<html>kubernetes-dashboard</html>"), true, "dashboard marker")
  expect_eq(K8.openapi_summary({ info = { title = "K8s API" }, paths = { ["/api/v1/pods"] = {}, ["/exec"] = {} } }).path_count, 2, "openapi paths")

  if fail > 0 then
    return false, fail .. " k8s codec selftest assertions failed"
  end
  return true, "Kubernetes HTTP/JSON codecs verified (" .. pass .. " assertions)"
end

K8T = {}

local function port_number(port)
  if type(port) == "table" then
    return port.number or 0
  end
  return port or 0
end

local function budget_of(args)
  return {
    timeout = args.timeout or 8,
    maxrequests = args.maxrequests or 24,
    token = args.token or "",
    insecure_ok = true,
  }
end

local function host_value(host)
  if type(host) == "table" then
    return host.ip or tostring(host)
  end
  return tostring(host)
end

local function new_session(host, port, args)
  return {
    host = host_value(host),
    port = port_number(port),
    budget = budget_of(args),
    sock = nil,
    connected = false,
    requests = 0,
    audit = {},
  }
end

K8T.session_new = new_session

function K8T.audit(sess, event, detail)
  sess.audit[#sess.audit + 1] = tostring(event) .. ":" .. tostring(detail)
end

local function is_tls_greeting(data)
  if type(data) ~= "string" or #data < 1 then
    return false
  end
  local b = string.byte(data, 1)
  return b == 0x16 or b == 0x15 or b == 0x30
end

function K8T.connect(sess)
  if sess.connected then
    return 1
  end
  if sess.requests >= sess.budget.maxrequests then
    return nil, "request budget exhausted"
  end
  local sock = nmap.new_socket()
  sock:set_timeout(math.floor((sess.budget.timeout or 8) * 1000))
  local ok, err = sock:connect(sess.host, sess.port, "tcp")
  if not ok then
    sock:close()
    return nil, "connect failed: " .. tostring(err or "unknown")
  end
  sess.sock = sock
  sess.connected = true
  K8T.audit(sess, "connect", sess.port)
  return 1
end

function K8T.close(sess)
  if sess and sess.sock and not sess.closed then
    pcall(sess.sock.close, sess.sock)
    sess.closed = true
    sess.connected = false
  end
end

function K8T.raw_request(sess, raw)
  if not sess.connected then
    local okc, cerr = K8T.connect(sess)
    if not okc then
      return nil, cerr
    end
  end
  if sess.requests >= sess.budget.maxrequests then
    return nil, "request budget exhausted"
  end
  sess.requests = sess.requests + 1
  local ok, err = sess.sock:send(raw)
  if not ok then
    return nil, "send failed: " .. tostring(err or "unknown")
  end
  K8T.audit(sess, "send", #raw .. "B")
  local collected = ""
  local spins = 0
  while spins < 6 do
    spins = spins + 1
    local okr, chunk = sess.sock:receive(262144)
    if okr then
      collected = collected .. chunk
      if collected:find("\r\n\r\n", 1, true) then
        break
      end
    elseif chunk == "TIMEOUT" or chunk == "EOF" then
      break
    else
      break
    end
  end
  if collected == "" then
    return nil, "empty response"
  end
  K8T.audit(sess, "recv", #collected .. "B")
  return collected
end

function K8T.request(sess, method, path, body, opts)
  opts = opts or {}
  local head = {
    method .. " " .. path .. " HTTP/1.1",
    "Host: " .. sess.host .. ":" .. tostring(sess.port),
    "User-Agent: NSE-Security-Audit/1.0",
    "Accept: */*",
    "Connection: close",
  }
  if opts.accept == "json" then
    head[#head] = "Accept: application/json"
  end
  if sess.budget.token ~= "" and not opts.no_token then
    head[#head + 1] = "Authorization: Bearer " .. sess.budget.token
  end
  if body and body ~= "" then
    head[#head + 1] = "Content-Type: " .. (opts.content_type or "application/json")
    head[#head + 1] = "Content-Length: " .. tostring(#body)
  end
  local raw = table.concat(head, "\r\n") .. "\r\n\r\n" .. (body or "")
  local resp_raw, err = K8T.raw_request(sess, raw)
  if resp_raw == nil then
    return nil, err
  end
  if is_tls_greeting(resp_raw) then
    return { status = nil, tls = true, raw = resp_raw }
  end
  local resp, perr = K8.parse_http_response(resp_raw)
  if resp == nil then
    return nil, perr or "HTTP parse failed"
  end
  local doc = K8.json_decode(resp.body or "")
  resp.json = doc
  return resp
end

local function wrap(host, port, args, fn)
  local sess = new_session(host, port, args)
  local out, err = fn(sess)
  K8T.close(sess)
  return out, err
end

K8T.wrap = wrap

K8T.get_json = function(host, port, args, path, opts)
  return wrap(host, port, args, function(sess)
    local resp, err = K8T.request(sess, "GET", path, nil, opts or { accept = "json" })
    if resp == nil then
      return nil, err
    end
    return resp
  end)
end

K8T.api_probe = function(host, port, args, path)
  return wrap(host, port, args, function(sess)
    local resp, err = K8T.request(sess, "GET", path, nil, { accept = "json" })
    if resp == nil then
      return nil, err
    end
    return {
      status = resp.status,
      tls = resp.tls or false,
      kind = resp.json and resp.json.kind or nil,
      items = resp.json and resp.json.items or nil,
      body = resp.body,
      reason = resp.reason,
    }
  end)
end

K8T.probe_all = function(host, port, args, probes)
  local results = {}
  for _, p in ipairs(probes or {}) do
    local r, err = K8T.api_probe(host, port, args, p.path)
    if r == nil then
      results[#results + 1] = { path = p.path, label = p.label, status = nil, error = tostring(err) }
    else
      results[#results + 1] = {
        path = p.path,
        label = p.label,
        status = r.status,
        tls = r.tls,
        kind = r.kind,
        items = r.items,
        body = r.body,
      }
    end
  end
  return results
end

K8T.status_open = function(status)
  return status ~= nil and status >= 200 and status < 300
end

K8T.status_auth_wall = function(status)
  return status == 401 or status == 403
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

local function k8s_incomplete(status_detail, sections, subject, evidence)
  local status_text = "INFORMATIONAL - Kubernetes audit incomplete: " .. tostring(status_detail)
  add_finding("INFO", "The Kubernetes audit did not complete against this endpoint", {
    subject = subject or "session",
    evidence = tostring(evidence or status_detail),
    confidence = "low",
  })
  local fail_out = new_output(RISK_LEVEL, status_text)
  local unique, counts = dedupe_findings()
  return finish_output(fail_out, unique, counts, sections or {})
end

local function run_audit(host, port, args)
  local sections = {}
  local resp = K8T.api_probe(host, port, args, K8.KUBELET_PATHS.pods)
  if resp == nil then
    local out = new_output(RISK_LEVEL, "SECURE - kubelet read-only port did not answer")
    add_finding("INFO", "Read-only port closed", {
      subject = "kubelet-ro",
      evidence = "no answer to GET /pods on 10255",
      confidence = "high",
    })
    sections[#sections + 1] = { key = "Read-Only Port", value = "closed or filtered" }
    local unique, counts = dedupe_findings()
    return finish_output(out, unique, counts, sections)
  end
  local pod_count = resp.items and #resp.items or 0
  sections[#sections + 1] = { key = "Read-Only Port /pods", value = {
    status = tostring(resp.status),
    kind = resp.kind or "-",
    pods_disclosed = pod_count,
  } }

  local remediation = {}
  local status_text
  if K8T.status_open(resp.status) then
    status_text = "VULNERABLE - kubelet read-only port discloses the pod inventory (" .. pod_count .. " pods)"
    add_finding("CRITICAL", "kubelet 10255 exposed", {
      subject = "kubelet-ro",
      evidence = "GET /pods on 10255 answered 200 with " .. pod_count .. " pods without credentials",
      confidence = "high",
      cvss = 8.6,
    })
    remediation["1. Disable"] = "Remove the read-only port (kubelet --read-only-port=0) and enforce webhook authorization."
  else
    status_text = "SECURE - read-only port refused the anonymous listing (" .. tostring(resp.status) .. ")"
    add_finding("INFO", "Read-only port walled", {
      subject = "kubelet-ro",
      evidence = "GET /pods answered " .. tostring(resp.status),
      confidence = "high",
    })
    remediation["1. Maintain"] = "Keep --read-only-port=0 across the node pool."
  end
  sections[#sections + 1] = { key = "Remediation", value = remediation }

  local out = new_output(RISK_LEVEL, status_text)
  local unique, counts = dedupe_findings()
  return finish_output(out, unique, counts, sections)
end

action = function(host, port)

local args = read_args()
reset_findings()
reset_state()
seed_random(port)

return run_audit(host, port, args)

end
