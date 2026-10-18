local shortport = require "shortport"

local http = require "http"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

local url = require "url"

description = [[

Determines whether a web service has a cross-origin resource sharing (CORS)
policy at all, and whether that policy can be abused to read authenticated
responses from another website.

The audit is evidence based: it does not report "Access-Control-Allow-Origin
present" as a finding, it proves which origins the server will accept and what
it lets them do.

Probes issued for every target path
* baseline request without an Origin header (records the natural ACAO/ACAC and
  the response hash),
* arbitrary unregistered origin (http://nsecors<random>.example),
* null origin (sandboxed iframe / file:// / data: navigations send Origin: null),
* prefix attack origins (https://<host>.attacker.example, https://attacker<host>),
* suffix attack origins (https://evil-<host>, https://<host>evil.example),
* substring origin (https://<host>.example.attacker.tld),
* the request host itself over the wrong scheme (http:// for an https service),
* a sibling subdomain (https://sibling.<registrable domain>),
* a wildcard literal Origin: *,
* a case-mangled and space-padded origin to test parser strictness,
* a full preflight (OPTIONS) with Access-Control-Request-Method and
  Access-Control-Request-Headers to enumerate the methods and headers the
  policy allows and to detect credentials allowed on preflight.

What is evaluated
* reflection of an arbitrary origin (CRITICAL when combined with
  Access-Control-Allow-Credentials: true — any website can read authenticated
  responses),
* Access-Control-Allow-Origin: * together with credentials (invalid per spec,
  but reveals broken logic and is honoured by some proxies/clients),
* null origin accepted (sandboxed iframes and data: URLs can read the
  response),
* prefix/suffix/substring origin accepted (the classic string-concatenation
  allowlist bug),
* wildcard in Access-Control-Allow-Methods or Access-Control-Allow-Headers,
* private or wildcard response headers exposed through
  Access-Control-Expose-Headers (Set-Cookie, Authorization, Cookie,
  WWW-Authenticate are meaningless but their exposure signals a copy-paste
  policy),
* max-age values that are absurd (> 24 h caches a preflight decision, 86400 is
  the browser cap) or negative,
* Vary: Origin missing on responses whose ACAO depends on the request Origin
  (cache poisoning: one user's ACAO gets served to another origin),
* credentialed CORS on sensitive paths (/api/*, /account, /graphql),
* policy inconsistency between paths and between HTTP and HTTPS listeners.

Every probe result is validated against the soft-404 baseline and WAF
interstitials, differences in the response body between the baseline and the
probed origin are compared so that "reflected origin" is only reported when
the header itself carries the value, and requests are budgeted, delayed and
retried with backoff.

Usage:
<code>
nmap -p 80,443 --script http-cors-config <target>
nmap -p 443 --script http-cors-config \
  --script-args http-cors-config.paths="/,/api/v1/me,/graphql" <target>
nmap -p 80 --script http-cors-config \
  --script-args http-cors-config.origin="https://trusted.example",\
http-cors-config.maxrequests=90 <target>
</code>

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "discovery", "vuln"}

portrule = shortport.http

local SCRIPT_NAME = "http-cors-config"

local RISK_LEVEL = "🟡 MEDIUM"

local PROBE_PATHS = {
  "/",
  "/api",
  "/api/v1",
  "/api/v1/me",
  "/api/user",
  "/api/users",
  "/api/account",
  "/api/profile",
  "/api/session",
  "/api/config",
  "/graphql",
  "/account",
  "/profile",
  "/dashboard",
  "/admin",
  "/login",
  "/oauth/token",
  "/static/js/app.js",
  "/health",
  "/status",
}

local SENSITIVE_PATH_KEYWORDS = {
  "api", "graphql", "account", "profile", "user", "me", "session", "admin",
  "dashboard", "oauth", "auth", "billing", "payment", "order", "internal",
}

local WAF_SIGNATURES = {
  { pattern = "cf-ray", where = "header", vendor = "Cloudflare" },
  { pattern = "cloudflare", where = "header", vendor = "Cloudflare" },
  { pattern = "attention required", where = "body", vendor = "Cloudflare" },
  { pattern = "akamai", where = "header", vendor = "Akamai" },
  { pattern = "reference #", where = "body", vendor = "Akamai" },
  { pattern = "x-iinfo", where = "header", vendor = "Imperva Incapsula" },
  { pattern = "incapsula", where = "body", vendor = "Imperva Incapsula" },
  { pattern = "sucuri", where = "header", vendor = "Sucuri" },
  { pattern = "aws waf", where = "body", vendor = "AWS WAF" },
  { pattern = "request blocked", where = "body", vendor = "generic WAF" },
  { pattern = "access denied", where = "body", vendor = "generic WAF" },
  { pattern = "web application firewall", where = "body", vendor = "generic WAF" },
  { pattern = "mod_security", where = "body", vendor = "ModSecurity" },
  { pattern = "fortiweb", where = "body", vendor = "Fortinet FortiWeb" },
  { pattern = "safeline", where = "body", vendor = "SafeLine WAF" },
}

local SOFT404_TEMPLATES = {
  "/nse-cors-probe-%s",
  "/api/%s/does-not-exist",
}

local EXPOSE_HEADERS_NEVER_MEANINGFUL = {
  "set-cookie", "set-cookie2", "cookie", "authorization",
  "www-authenticate", "proxy-authenticate", "proxy-authorization",
  "connection", "content-length", "transfer-encoding", "trailer",
  "upgrade", "keep-alive",
}

local PREFLIGHT_METHODS = {
  "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE",
  "CONNECT", "PROPFIND", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK",
}

local DEFAULT_ARGS = {
  paths = nil,
  maxpaths = 8,
  maxrequests = 110,
  retries = 2,
  timeout = 8000,
  delay = 0.05,
  soft404 = true,
  preflight = true,
  sibling = true,
  useragent = nil,
  maxbodysize = 262144,
}

local NUMERIC_ARGS = {
  { key = "maxpaths", minimum = 1, integer = true },
  { key = "maxrequests", minimum = 4, integer = true },
  { key = "retries", minimum = 0, integer = true },
  { key = "timeout", minimum = 500, integer = true },
  { key = "maxbodysize", minimum = 1024, integer = true },
}

local BOOLEAN_ARGS = { "soft404", "preflight", "sibling" }

local STRING_ARGS = { "useragent", "origin" }

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

local function build_options(args, extra_headers)
  local options = { header = {}, no_cache = true, timeout = args.timeout }
  options.header["User-Agent"] = args.useragent
    or ("Mozilla/5.0 (compatible; " .. SCRIPT_NAME .. "; security audit)")
  options.header["Accept"] = "*/*"
  options.header["Accept-Encoding"] = "identity"
  options.header["Connection"] = "close"
  options.header["Cache-Control"] = "no-cache"
  for name, value in pairs(extra_headers or {}) do
    options.header[name] = tostring(value)
  end
  return options
end

local function fetch(host, port, path, args, extra_headers, method)
  if budget_exhausted(args) then
    return nil, "request budget exhausted"
  end
  state.requests = state.requests + 1

  local options = build_options(args, extra_headers)
  local sender = http.get
  if method and method ~= "GET" then
    if method == "HEAD" then
      sender = http.head
    elseif method == "POST" then
      sender = function(h, p, u, o) return http.post(h, p, u, o, "") end
    elseif http.request then
      sender = function(h, p, u, o) return http.request(h, p, u, o, nil, method) end
    end
  end

  local attempt = 0
  local last_error = nil
  while attempt <= args.retries do
    attempt = attempt + 1
    local ok, response = pcall(sender, host, port, path, options)
    if ok and type(response) == "table" and response.status then
      if response.status == 429 then
        state.rate_limited = state.rate_limited + 1
        last_error = "HTTP 429 rate limiting"
        local retry_after = tonumber(response.header and response.header["retry-after"])
        sleep(clamp(retry_after or (attempt * 2), 1, 10))
      elseif response.status >= 500 and attempt <= args.retries then
        last_error = "HTTP " .. response.status
        sleep(0.5 * attempt)
      else
        sleep(args.delay)
        return response, nil
      end
    elseif ok then
      last_error = "malformed HTTP response"
      sleep(0.3 * attempt)
    else
      last_error = tostring(response)
      state.errors = state.errors + 1
      sleep(0.4 * attempt)
    end
  end

  sleep(args.delay)
  return nil, last_error
end

local function dechunk(body)
  local out = {}
  local position = 1
  while position <= #(body or "") do
    local size_hex, rest = string.match(body, "^([0-9a-fA-F]+)[^\r\n]*\r\n(.*)$", position)
    if not size_hex then
      local loose_hex, loose_rest = string.match(body, "^([0-9a-fA-F]+)[^\n]*\n(.*)$", position)
      if not loose_hex then
        break
      end
      size_hex, rest = loose_hex, loose_rest
    end
    local size = tonumber(size_hex, 16)
    if not size or size == 0 then
      break
    end
    table.insert(out, string.sub(rest, 1, size))
    position = position + (#body - #rest) + size
    local tail = string.sub(body, position)
    if starts_with(tail, "\r\n") then
      position = position + 2
    elseif starts_with(tail, "\n") then
      position = position + 1
    end
  end
  return table.concat(out)
end

local function parse_raw_response(raw)
  local head, body = string.match(raw or "", "^(.-)\r\n\r\n(.*)$")
  if not head then
    head, body = string.match(raw or "", "^(.-)\n\n(.*)$")
  end
  if not head then
    head = raw or ""
    body = ""
  end

  local response = { header = {}, rawheader = {}, body = body, raw = raw }
  local first = true
  for line in string.gmatch(head, "([^\r\n]*)") do
    if first then
      response["status-line"] = line
      response.status = tonumber(string.match(line, "^HTTP/[%d%.]+%s+(%d+)")) or 0
      response.version = string.match(line, "^HTTP/([%d%.]+)")
      first = false
    elseif #trim(line) > 0 then
      local name, value = string.match(line, "^([^:]+):%s*(.*)$")
      if name then
        table.insert(response.rawheader, line)
        local key = lower(name)
        if response.header[key] then
          local previous = response.header[key]
          if type(previous) == "table" then
            table.insert(previous, trim(value))
          else
            response.header[key] = { previous, trim(value) }
          end
        else
          response.header[key] = trim(value)
        end
      end
    end
  end

  local transfer_encoding = response.header["transfer-encoding"]
  if transfer_encoding and contains(lower(tostring(transfer_encoding)), "chunked") then
    response.body = dechunk(response.body)
  end

  return response
end

local function host_header_for(host, port)
  local name = host.targetname or host.name or host.ip or "localhost"
  local default_port = (port.number == 80 and not port.ssl) or (port.number == 443 and port.ssl)
  if default_port then
    return name
  end
  return string.format("%s:%d", name, port.number)
end

local function raw_request(host, port, method, path, header_pairs, args, body)
  if budget_exhausted(args) then
    return nil, "request budget exhausted"
  end
  state.requests = state.requests + 1

  local socket = nmap.new_socket()
  local ok, err = socket:connect(host, port)
  if not ok then
    state.errors = state.errors + 1
    return nil, tostring(err)
  end
  socket:set_timeout(args.timeout)

  local lines = {}
  table.insert(lines, string.format("%s %s HTTP/1.1", method, path))
  table.insert(lines, "Host: " .. host_header_for(host, port))
  table.insert(lines, "User-Agent: " .. (args.useragent
    or ("Mozilla/5.0 (compatible; " .. SCRIPT_NAME .. ")")))
  table.insert(lines, "Accept: */*")
  table.insert(lines, "Accept-Encoding: identity")
  table.insert(lines, "Connection: close")
  if body then
    table.insert(lines, "Content-Length: " .. tostring(#body))
  end
  for _, pair in ipairs(header_pairs or {}) do
    table.insert(lines, pair[1] .. ": " .. tostring(pair[2]))
  end

  local request = table.concat(lines, "\r\n") .. "\r\n\r\n" .. (body or "")
  local send_ok, send_err = socket:send(request)
  if not send_ok then
    socket:close()
    state.errors = state.errors + 1
    return nil, tostring(send_err)
  end

  local recv_ok, data = socket:receive_until_close()
  socket:close()
  sleep(args.delay)

  if (not data or #data == 0) and not recv_ok then
    state.errors = state.errors + 1
    return nil, "no response bytes"
  end

  return parse_raw_response(data or ""), nil
end

local function header_values(response, name)
  local values = {}
  local target = lower(name)
  for _, line in ipairs(response.rawheader or {}) do
    local key, value = string.match(line, "^([^:]+):%s*(.*)$")
    if key and lower(key) == target then
      table.insert(values, trim(value))
    end
  end
  if #values == 0 then
    local single = response.header and response.header[target]
    if type(single) == "table" then
      for _, value in ipairs(single) do
        table.insert(values, value)
      end
    elseif single then
      table.insert(values, trim(single))
    end
  end
  return values
end

local function header_value(response, name)
  local values = header_values(response, name)
  return values[1]
end

local function response_headers(response)
  local names = {}
  for _, line in ipairs(response.rawheader or {}) do
    local key = string.match(line, "^([^:]+):")
    if key then
      local normalized = lower(key)
      if not list_contains(names, normalized) then
        table.insert(names, normalized)
      end
    end
  end
  table.sort(names)
  return names
end

local function detect_waf(response)
  if not response then
    return nil
  end
  for _, line in ipairs(response.rawheader or {}) do
    local lowered = lower(line)
    for _, signature in ipairs(WAF_SIGNATURES) do
      if signature.where ~= "body" and string.find(lowered, signature.pattern, 1, true) then
        return signature.vendor
      end
    end
  end
  local body = lower(response.body or "")
  if #body > 0 and #body < 20000 then
    for _, signature in ipairs(WAF_SIGNATURES) do
      if signature.where ~= "header" and string.find(body, signature.pattern, 1, true) then
        return signature.vendor
      end
    end
  end
  return nil
end

local function build_soft404_baseline(host, port, args)
  local baseline = { enabled = args.soft404, samples = 0, statuses = {}, hashes = {} }
  if not args.soft404 then
    return baseline
  end
  for _, template in ipairs(SOFT404_TEMPLATES) do
    if budget_exhausted(args) then
      break
    end
    local response = fetch(host, port, string.format(template, random_token(12)), args)
    if response and response.status then
      baseline.samples = baseline.samples + 1
      local key = tostring(response.status)
      baseline.statuses[key] = (baseline.statuses[key] or 0) + 1
      local hash = fnv1a32(response.body or "")
      baseline.hashes[hash] = (baseline.hashes[hash] or 0) + 1
      baseline.example_status = baseline.example_status or response.status
      baseline.example_hash = baseline.example_hash or hash
      baseline.example_length = baseline.example_length or #(response.body or "")
    end
  end
  local dominant, count = nil, 0
  for status, hits in pairs(baseline.statuses) do
    if hits > count then
      dominant, count = status, hits
    end
  end
  baseline.dominant_status = tonumber(dominant)
  baseline.consistent = baseline.samples >= 2 and count == baseline.samples
  return baseline
end

local function looks_like_soft404(response, baseline)
  if not baseline.enabled or baseline.samples == 0 then
    return false, nil
  end
  if (response.status or 0) >= 500 then
    return false, nil
  end
  local body = response.body or ""
  if baseline.example_hash and fnv1a32(body) == baseline.example_hash and #body > 0 then
    return true, "byte-identical to the catch-all baseline"
  end
  if baseline.consistent and baseline.dominant_status == response.status
    and math.abs(#body - (baseline.example_length or #body)) <= 48 then
    return true, "status and length match the catch-all baseline"
  end
  return false, nil
end

local function classify_response(path, response, baseline)
  local info = {
    path = path,
    status = response.status or 0,
    length = #(response.body or ""),
    confidence = "high",
    notes = {},
  }

  local vendor = detect_waf(response)
  if vendor then
    info.confidence = "low"
    state.blocked = state.blocked + 1
    table.insert(info.notes, "WAF/CDN interstitial (" .. vendor .. ")")
    return info, vendor
  end

  local soft, reason = looks_like_soft404(response, baseline)
  if soft then
    info.confidence = "low"
    table.insert(info.notes, "soft-404: " .. tostring(reason))
    return info, nil
  end

  if info.status == 401 or info.status == 403 then
    info.confidence = "low"
    table.insert(info.notes, string.format("HTTP %d: access control layer answered, not the application", info.status))
  elseif info.status == 429 then
    info.confidence = "low"
    table.insert(info.notes, "HTTP 429: the service is rate limiting the audit")
  elseif info.status >= 500 then
    info.confidence = "low"
    table.insert(info.notes, string.format("HTTP %d: server error response", info.status))
  elseif info.status == 404 then
    table.insert(info.notes, "HTTP 404")
  end

  if info.length == 0 then
    table.insert(info.notes, "empty body")
  end

  return info, nil
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

local function registrable_domain(hostname)
  if type(hostname) ~= "string" then
    return nil
  end
  local cleaned = lower(string.gsub(hostname, "^%.", ""))
  if string.match(cleaned, "^%d+%.%d+%.%d+%.%d+$") then
    return cleaned
  end
  local shared_suffixes = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.nz", "co.za", "com.br", "com.mx", "co.in", "co.jp", "com.cn",
    "com.tr", "com.sg", "com.hk", "co.kr", "com.ar", "com.co", "com.pe",
  }
  local parts = {}
  for label in string.gmatch(cleaned, "[^%.]+") do
    table.insert(parts, label)
  end
  if #parts <= 2 then
    return cleaned
  end
  local last_two = parts[#parts - 1] .. "." .. parts[#parts]
  if list_contains(shared_suffixes, last_two) and #parts >= 3 then
    return parts[#parts - 2] .. "." .. last_two
  end
  return last_two
end

local function origin_variants(hostname, tls, extra_origin)
  local variants = {}
  local random_host = "nsecors" .. random_token(8) .. ".example"

  table.insert(variants, {
    name = "arbitrary",
    value = "http://" .. random_host,
    weight = SEVERITY.CRITICAL,
    note = "an unregistered origin is accepted",
  })
  table.insert(variants, {
    name = "arbitrary-https",
    value = "https://" .. random_host,
    weight = SEVERITY.CRITICAL,
    note = "an unregistered https origin is accepted",
  })
  table.insert(variants, {
    name = "null",
    value = "null",
    weight = SEVERITY.HIGH,
    note = "Origin: null is accepted (sandboxed iframes, file:// and data: navigations send it)",
  })
  table.insert(variants, {
    name = "wildcard",
    value = "*",
    weight = SEVERITY.MEDIUM,
    note = "a literal '*' Origin is accepted",
  })

  local bare_host = string.gsub(hostname or "", ":%d+$", "")
  if #bare_host > 0 then
    local scheme = tls and "https" or "http"
    local other_scheme = tls and "http" or "https"
    table.insert(variants, {
      name = "self",
      value = scheme .. "://" .. bare_host,
      weight = SEVERITY.INFO,
      note = "the service trusts its own origin",
    })
    table.insert(variants, {
      name = "wrong-scheme",
      value = other_scheme .. "://" .. bare_host,
      weight = tls and SEVERITY.MEDIUM or SEVERITY.LOW,
      note = tls and "the plain-HTTP origin of the same host is trusted (downgrade path)"
        or "the HTTPS origin of the same host is trusted",
    })
    table.insert(variants, {
      name = "prefix-subdomain",
      value = scheme .. "://" .. bare_host .. ".attacker.example",
      weight = SEVERITY.HIGH,
      note = "prefix-match allowlist bug: <host>.attacker.example is accepted",
    })
    table.insert(variants, {
      name = "prefix-nodot",
      value = scheme .. "://attacker" .. bare_host,
      weight = SEVERITY.HIGH,
      note = "prefix-match allowlist bug: attacker<host> is accepted",
    })
    table.insert(variants, {
      name = "suffix-dash",
      value = scheme .. "://evil-" .. bare_host,
      weight = SEVERITY.HIGH,
      note = "suffix-match allowlist bug: evil-<host> is accepted",
    })
    table.insert(variants, {
      name = "suffix-glued",
      value = scheme .. "://" .. bare_host .. "evil.example",
      weight = SEVERITY.HIGH,
      note = "suffix-match allowlist bug: <host>evil.example is accepted",
    })
    table.insert(variants, {
      name = "substring",
      value = scheme .. "://" .. string.gsub(bare_host, "%.", "-") .. ".attacker.tld",
      weight = SEVERITY.MEDIUM,
      note = "substring-match allowlist bug",
    })
    table.insert(variants, {
      name = "uppercase",
      value = scheme .. "://" .. string.upper(bare_host),
      weight = SEVERITY.LOW,
      note = "case-mangled origin accepted (parser strictness signal)",
    })
    table.insert(variants, {
      name = "trailing-space",
      value = scheme .. "://" .. bare_host .. " ",
      weight = SEVERITY.LOW,
      note = "origin with trailing whitespace accepted",
    })
    table.insert(variants, {
      name = "userinfo",
      value = scheme .. "://trusted@" .. bare_host .. ".attacker.example",
      weight = SEVERITY.MEDIUM,
      note = "origin carrying userinfo is accepted (URL parser confusion)",
    })

    local registrable = registrable_domain(bare_host)
    if registrable and registrable ~= bare_host then
      table.insert(variants, {
        name = "sibling",
        value = scheme .. "://nse-sibling." .. registrable,
        weight = SEVERITY.MEDIUM,
        note = "an arbitrary sibling subdomain of " .. registrable .. " is accepted",
      })
    end
  end

  if extra_origin and #extra_origin > 0 then
    table.insert(variants, {
      name = "operator-supplied",
      value = extra_origin,
      weight = SEVERITY.HIGH,
      note = "the operator supplied origin is accepted",
    })
  end

  return variants
end

local function parse_list(value)
  local items = {}
  for chunk in string.gmatch(value or "", "[^,]+") do
    local trimmed = trim(chunk)
    if #trimmed > 0 then
      table.insert(items, trimmed)
    end
  end
  return items
end

local function normalize_origin(value)
  local trimmed = trim(value or "")
  if lower(trimmed) == "null" then
    return "null"
  end
  trimmed = string.gsub(trimmed, "/+$", "")
  return trimmed
end

local function origins_match(allowed, requested)
  if not allowed then
    return false
  end
  local normalized_allowed = normalize_origin(allowed)
  local normalized_requested = normalize_origin(requested)
  if normalized_allowed == "*" then
    return true, true
  end
  if lower(normalized_allowed) == lower(normalized_requested) then
    return true, false
  end
  return false, false
end

local function is_sensitive_path(path)
  local lowered = lower(path or "")
  for _, keyword in ipairs(SENSITIVE_PATH_KEYWORDS) do
    if contains(lowered, keyword) then
      return true
    end
  end
  return false
end

local function select_paths(args)
  local selected = {}
  local seen = {}
  local source = args.paths or PROBE_PATHS
  for _, candidate in ipairs(source) do
    local normalized = trim(candidate)
    if #normalized == 0 then
      normalized = "/"
    end
    if not starts_with(normalized, "/") then
      normalized = "/" .. normalized
    end
    if unique_append(selected, seen, normalized) and #selected >= args.maxpaths then
      break
    end
  end
  if #selected == 0 then
    table.insert(selected, "/")
  end

  local prioritised = {}
  for _, path in ipairs(selected) do
    if is_sensitive_path(path) then
      table.insert(prioritised, path)
    end
  end
  for _, path in ipairs(selected) do
    if not is_sensitive_path(path) then
      table.insert(prioritised, path)
    end
  end

  return prioritised
end

local function evaluate_policy(path, response, origin_request, variant, baseline_body_hash, info)
  local acao_values = header_values(response, "access-control-allow-origin")
  local acac_values = header_values(response, "access-control-allow-credentials")
  local acam_values = header_values(response, "access-control-access-methods")
  local acam_fallback = header_values(response, "access-control-allow-methods")
  local acah_values = header_values(response, "access-control-allow-headers")
  local aceh_values = header_values(response, "access-control-expose-headers")
  local acma_values = header_values(response, "access-control-max-age")
  local vary_values = header_values(response, "vary")
  local acpn_values = header_values(response, "access-control-allow-private-network")

  for _, value in ipairs(acam_values) do
    table.insert(acam_fallback, value)
  end

  local credentials = false
  for _, value in ipairs(acac_values) do
    if lower(value) == "true" then
      credentials = true
    elseif lower(value) ~= "false" then
      add_finding("LOW", string.format(
        "Access-Control-Allow-Credentials carries the invalid value '%s' (only 'true' is honoured)", value),
        { path = path, subject = "Access-Control-Allow-Credentials", confidence = info.confidence, evidence = value })
    end
  end

  if #acao_values == 0 then
    if variant then
      add_finding("INFO", string.format("origin '%s' was not accepted (no Access-Control-Allow-Origin)",
        variant.value), { path = path, subject = variant.name, confidence = info.confidence })
    end
    return nil
  end

  local policy = {
    path = path,
    acao = acao_values,
    credentials = credentials,
    methods = {},
    headers = {},
    expose = {},
    max_age = nil,
    vary_origin = false,
    private_network = nil,
    variant = variant,
    origin_request = origin_request,
  }

  for _, value in ipairs(acam_fallback) do
    for _, method in ipairs(parse_list(value)) do
      table.insert(policy.methods, method)
    end
  end
  for _, value in ipairs(acah_values) do
    for _, header in ipairs(parse_list(value)) do
      table.insert(policy.headers, header)
    end
  end
  for _, value in ipairs(aceh_values) do
    for _, header in ipairs(parse_list(value)) do
      table.insert(policy.expose, header)
    end
  end
  for _, value in ipairs(vary_values) do
    for _, token in ipairs(parse_list(value)) do
      if lower(token) == "origin" then
        policy.vary_origin = true
      end
    end
  end
  for _, value in ipairs(acma_values) do
    policy.max_age = tonumber(value) or policy.max_age
  end
  for _, value in ipairs(acpn_values) do
    policy.private_network = lower(value)
  end

  local sensitive = is_sensitive_path(path)

  for _, acao in ipairs(acao_values) do
    local matched, wildcard = origins_match(acao, origin_request)
    if wildcard then
      if credentials then
        add_finding("HIGH", string.format(
          "Access-Control-Allow-Origin: * is combined with Access-Control-Allow-Credentials: true; "
          .. "the combination is invalid per the Fetch standard but reveals broken allowlist logic%s",
          sensitive and " on a sensitive path" or ""),
          { path = path, subject = "wildcard+credentials", confidence = info.confidence, evidence = acao })
      else
        add_finding(sensitive and "MEDIUM" or "LOW", string.format(
          "Access-Control-Allow-Origin: * allows any website to read this response%s",
          sensitive and " (sensitive path)" or ""),
          { path = path, subject = "wildcard", confidence = info.confidence, evidence = acao })
      end
    elseif matched and variant then
      local severity = "MEDIUM"
      local weight = variant.weight or SEVERITY.MEDIUM
      if credentials then
        if weight >= SEVERITY.HIGH then
          severity = "CRITICAL"
        else
          severity = "HIGH"
        end
      else
        if weight >= SEVERITY.HIGH then
          severity = "HIGH"
        elseif weight >= SEVERITY.MEDIUM then
          severity = "MEDIUM"
        else
          severity = "LOW"
        end
      end

      add_finding(severity, string.format("%s (Origin: %s -> Access-Control-Allow-Origin: %s%s)",
        variant.note, variant.value, acao,
        credentials and ", credentials allowed" or ""),
        { path = path, subject = variant.name, confidence = info.confidence, evidence = acao })
    elseif not matched and lower(acao) ~= "*" then
      add_finding("INFO", string.format(
        "server answered with a fixed Access-Control-Allow-Origin (%s) that does not reflect the request origin",
        acao), { path = path, subject = "static-policy", confidence = info.confidence, evidence = acao })
    end
  end

  if #acao_values > 1 then
    add_finding("MEDIUM", string.format(
      "multiple Access-Control-Allow-Origin headers are sent (%s); browsers reject the response but "
      .. "intermediaries may merge them", table.concat(acao_values, " | ")),
      { path = path, subject = "duplicate-acao", confidence = info.confidence })
  end

  local body_hash = fnv1a32(response.body or "")
  if baseline_body_hash and body_hash ~= baseline_body_hash and credentials then
    add_finding("INFO", string.format(
      "response body changes when an Origin header is supplied (%d byte delta)",
      #tostring(body_hash)),
      { path = path, subject = "origin-dependent-body", confidence = info.confidence })
  end

  if not policy.vary_origin and variant and #acao_values > 0 then
    local matched = origins_match(acao_values[1], origin_request)
    if matched and lower(acao_values[1]) ~= "*" then
      add_finding("HIGH", string.format(
        "origin-dependent Access-Control-Allow-Origin is served without 'Vary: Origin'; shared caches can "
        .. "hand one origin's CORS grant to another origin"),
        { path = path, subject = "vary-origin", confidence = info.confidence,
          evidence = table.concat(vary_values, ", ") })
    end
  end

  for _, method in ipairs(policy.methods) do
    if method == "*" then
      add_finding("HIGH", "Access-Control-Allow-Methods: * permits every HTTP method cross-origin",
        { path = path, subject = "methods", confidence = info.confidence, evidence = method })
    elseif list_contains({ "TRACE", "CONNECT", "PUT", "DELETE", "PATCH" }, string.upper(method)) then
      add_finding("MEDIUM", string.format(
        "Access-Control-Allow-Methods permits the state-changing method %s cross-origin", method),
        { path = path, subject = "methods", confidence = info.confidence, evidence = method })
    elseif not list_contains(PREFLIGHT_METHODS, string.upper(method)) then
      add_finding("LOW", string.format("Access-Control-Allow-Methods lists the unknown method '%s'", method),
        { path = path, subject = "methods", confidence = info.confidence, evidence = method })
    end
  end

  for _, header in ipairs(policy.headers) do
    if header == "*" then
      add_finding("MEDIUM", "Access-Control-Allow-Headers: * permits every request header cross-origin",
        { path = path, subject = "headers", confidence = info.confidence, evidence = header })
    elseif list_contains({ "authorization", "cookie", "x-forwarded-for", "x-forwarded-host",
      "x-original-url", "x-rewrite-url", "host" }, lower(header)) then
      add_finding("HIGH", string.format(
        "Access-Control-Allow-Headers permits the sensitive request header '%s' from any allowed origin",
        header), { path = path, subject = "headers", confidence = info.confidence, evidence = header })
    end
  end

  for _, header in ipairs(policy.expose) do
    if header == "*" then
      add_finding("MEDIUM", "Access-Control-Expose-Headers: * exposes every response header to cross-origin readers",
        { path = path, subject = "expose", confidence = info.confidence, evidence = header })
    elseif list_contains(EXPOSE_HEADERS_NEVER_MEANINGFUL, lower(header)) then
      add_finding("LOW", string.format(
        "Access-Control-Expose-Headers lists '%s', a forbidden/meaningless header name", header),
        { path = path, subject = "expose", confidence = info.confidence, evidence = header })
    elseif sensitive then
      add_finding("MEDIUM", string.format(
        "cross-origin readers can access the '%s' response header on a sensitive path", header),
        { path = path, subject = "expose", confidence = info.confidence, evidence = header })
    end
  end

  if policy.max_age then
    if policy.max_age < 0 then
      add_finding("LOW", string.format("Access-Control-Max-Age is negative (%d)", policy.max_age),
        { path = path, subject = "max-age", confidence = info.confidence })
    elseif policy.max_age > 86400 then
      add_finding("LOW", string.format(
        "Access-Control-Max-Age=%d exceeds the 86400 s browser cap; preflight decisions are cached a full day",
        policy.max_age), { path = path, subject = "max-age", confidence = info.confidence })
    elseif policy.max_age > 3600 then
      add_finding("INFO", string.format("Access-Control-Max-Age=%d caches preflight results for over an hour",
        policy.max_age), { path = path, subject = "max-age", confidence = info.confidence })
    end
  end

  if policy.private_network == "true" then
    add_finding("MEDIUM", "Access-Control-Allow-Private-Network: true lets public websites reach this "
      .. "(private network) endpoint through a browser",
      { path = path, subject = "private-network", confidence = info.confidence })
  end

  if credentials and sensitive then
    add_finding("HIGH", "credentialed CORS is enabled on a sensitive path: any allowed origin can read "
      .. "authenticated responses with the victim's cookies",
      { path = path, subject = "credentialed", confidence = info.confidence })
  end

  return policy
end

local function run_preflight(host, port, path, origin, args)
  local header_pairs = {
    { "Origin", origin },
    { "Access-Control-Request-Method", "PUT" },
    { "Access-Control-Request-Headers", "authorization,content-type,x-requested-with" },
  }
  local response, err = raw_request(host, port, "OPTIONS", path, header_pairs, args)
  if not response or not response.status then
    return nil, err
  end
  return response, nil
end

local function evaluate_preflight(path, response, origin, info)
  local status = response.status or 0
  if status == 405 or status == 501 then
    add_finding("INFO", string.format("preflight OPTIONS is rejected with HTTP %d (no CORS on this path)", status),
      { path = path, subject = "preflight", confidence = info.confidence })
    return nil
  end

  local acao = header_value(response, "access-control-allow-origin")
  if not acao then
    add_finding("LOW", "OPTIONS preflight answered HTTP " .. status .. " without Access-Control-Allow-Origin; "
      .. "cross-origin requests will fail in the browser",
      { path = path, subject = "preflight", confidence = info.confidence })
    return nil
  end

  local allow_methods = header_value(response, "access-control-allow-methods") or ""
  local allow_headers = header_value(response, "access-control-allow-headers") or ""

  add_finding("INFO", string.format("preflight grants methods '%s' and headers '%s' to origin '%s'",
    allow_methods, allow_headers, origin),
    { path = path, subject = "preflight-grant", confidence = info.confidence,
      evidence = allow_methods .. " / " .. allow_headers })

  if contains(lower(allow_headers), "*") then
    add_finding("MEDIUM", "preflight answers with Access-Control-Allow-Headers: * (any request header accepted)",
      { path = path, subject = "preflight", confidence = info.confidence })
  end
  if contains(lower(allow_methods), "*") then
    add_finding("HIGH", "preflight answers with Access-Control-Allow-Methods: * (any method accepted)",
      { path = path, subject = "preflight", confidence = info.confidence })
  end

  local acac = header_value(response, "access-control-allow-credentials")
  if lower(acac or "") == "true" and acao == "*" then
    add_finding("HIGH", "preflight allows credentials together with a wildcard origin",
      { path = path, subject = "preflight", confidence = info.confidence })
  end

  return { methods = allow_methods, headers = allow_headers, acao = acao }
end

local function audit_path(host, port, path, variants, args, baseline)
  local summary = {
    path = path,
    probes = 0,
    reflected = 0,
    credentials = false,
    policies = {},
    notes = {},
  }

  local base_response, base_err = fetch(host, port, path, args, { ["X-NSE-Probe"] = "baseline" })
  if not base_response then
    table.insert(summary.notes, "baseline request failed: " .. tostring(base_err))
    return summary
  end

  local base_info = classify_response(path, base_response, baseline)
  local base_hash = fnv1a32(base_response.body or "")
  local base_acao = header_value(base_response, "access-control-allow-origin")
  if base_acao then
    summary.static_acao = base_acao
    evaluate_policy(path, base_response, nil, nil, nil, base_info)
  end

  for _, variant in ipairs(variants) do
    if budget_exhausted(args) then
      table.insert(summary.notes, "request budget exhausted during origin probing")
      break
    end
    summary.probes = summary.probes + 1

    local response, err = fetch(host, port, path, args, { Origin = variant.value })
    if not response then
      table.insert(summary.notes, string.format("origin '%s' probe failed: %s", variant.value, tostring(err)))
      goto continue_variant
    end

    local info = classify_response(path, response, baseline)
    local policy = evaluate_policy(path, response, variant.value, variant, base_hash, info)
    if policy then
      table.insert(summary.policies, { origin = variant.value, name = variant.name, policy = policy })
      if policy.credentials then
        summary.credentials = true
      end
      local matched = origins_match(policy.acao[1], variant.value)
      if matched then
        summary.reflected = summary.reflected + 1
      end
    end

    ::continue_variant::
  end

  if args.preflight and not budget_exhausted(args) then
    local preflight_origin = variants[1] and variants[1].value or "https://nse.example"
    local response, err = run_preflight(host, port, path, preflight_origin, args)
    if response then
      local info = classify_response(path, response, baseline)
      local grant = evaluate_preflight(path, response, preflight_origin, info)
      summary.preflight = grant
    elseif err then
      table.insert(summary.notes, "preflight failed: " .. tostring(err))
    end
  end

  return summary
end

local function consistency_analysis(summaries)
  local weight = 0
  local credentialed_paths = {}
  local reflected_paths = {}
  local static_paths = {}

  for _, summary in ipairs(summaries) do
    if summary.credentials then
      table.insert(credentialed_paths, summary.path)
    end
    if summary.reflected > 0 then
      table.insert(reflected_paths, summary.path)
    end
    if summary.static_acao then
      table.insert(static_paths, summary.path .. "=" .. summary.static_acao)
    end
  end

  if #credentialed_paths > 0 and #reflected_paths > 0 then
    add_finding("CRITICAL", string.format(
      "origin reflection combined with credentials on %d path(s): any website can read authenticated "
      .. "responses (%s)", #credentialed_paths, table.concat(reflected_paths, ", ")),
      { subject = "cors-credentialed-reflection", path = credentialed_paths[1] })
    weight = weight + SEVERITY.CRITICAL
  end

  if #static_paths > 1 then
    local seen = {}
    for _, entry in ipairs(static_paths) do
      local value = string.match(entry, "=(.*)$")
      seen[value] = (seen[value] or 0) + 1
    end
    if table_size(seen) > 1 then
      local parts = {}
      for value, count in pairs(seen) do
        table.insert(parts, value .. " x" .. count)
      end
      table.sort(parts)
      add_finding("LOW", "the static Access-Control-Allow-Origin value differs between paths ("
        .. table.concat(parts, ", ") .. ") — the policy is not centrally managed",
        { subject = "consistency" })
      weight = weight + SEVERITY.LOW
    end
  end

  return weight, credentialed_paths, reflected_paths
end

action = function(host, port)

  seed_random(port)
  reset_state()
  reset_findings()

  local args = read_args()
  local hostname = host.targetname or host.name or host.ip or "localhost"
  local tls = port.ssl or (port.version and port.version.service_ssl) or false
  local variants = origin_variants(hostname, tls, args.origin)

  if not args.sibling then
    local filtered = {}
    for _, variant in ipairs(variants) do
      if variant.name ~= "sibling" then
        table.insert(filtered, variant)
      end
    end
    variants = filtered
  end

  local baseline = build_soft404_baseline(host, port, args)
  local paths = select_paths(args)
  local summaries = {}

  for _, path in ipairs(paths) do
    if budget_exhausted(args) then
      table.insert(summaries, { path = path, probes = 0, reflected = 0, policies = {},
        notes = { "request budget exhausted before this path was probed" } })
      break
    end
    table.insert(summaries, audit_path(host, port, path, variants, args, baseline))
  end

  local unique, counts = dedupe_findings()
  local consistency_weight, credentialed_paths, reflected_paths = consistency_analysis(summaries)
  local unique_after, counts_after = dedupe_findings()
  unique = unique_after
  counts = counts_after

  local out = new_output(RISK_LEVEL, "AUDITED - CORS policy evaluation completed.")
  if #summaries == 0 then
    out["Status"] = "AUDITED - no HTTP response was obtained; CORS posture unknown."
    out["Transport"] = tls and "HTTPS" or "HTTP"
    return finish_output(out, unique, counts, {})
  end

  local any_policy = false
  local credentialed = false
  for _, summary in ipairs(summaries) do
    if #(summary.policies or {}) > 0 or summary.static_acao then
      any_policy = true
    end
    if summary.credentials then
      credentialed = true
    end
  end

  if counts_after.CRITICAL > 0 then
    out["Status"] = "AUDITED - exploitable CORS misconfiguration: arbitrary origins can read credentialed responses."
  elseif counts_after.HIGH > 0 then
    out["Status"] = "AUDITED - CORS policy accepts unsafe origins or exposes sensitive headers."
  elseif any_policy and credentialed then
    out["Status"] = "AUDITED - credentialed CORS is enabled with an origin-dependent policy."
  elseif any_policy and #reflected_paths == 0 then
    out["Status"] = "AUDITED - a CORS policy is present and none of the tested unsafe origins was reflected."
  else
    out["Status"] = "AUDITED - no CORS policy is published on the probed paths."
  end

  local probe_lines = {}
  for _, summary in ipairs(summaries) do
    table.insert(probe_lines, string.format("%s -> %d origin probes, %d accepted, credentials=%s%s",
      summary.path, summary.probes or 0, summary.reflected or 0,
      summary.credentials == nil and "n/a" or tostring(summary.credentials),
      summary.static_acao and (" static ACAO=" .. summary.static_acao) or ""))
    for _, note in ipairs(summary.notes or {}) do
      table.insert(probe_lines, "    " .. summary.path .. ": " .. note)
    end
  end

  local sections = {
    { key = "Transport", value = tls and "HTTPS" or "HTTP" },
    { key = "Host", value = hostname },
    { key = "Paths probed", value = #summaries },
    { key = "Origin probes issued", value = tostring(state.requests) },
    { key = "Probe matrix", value = probe_lines },
  }

  if #credentialed_paths > 0 then
    table.insert(sections, { key = "Credentialed paths", value = credentialed_paths })
  end
  if #reflected_paths > 0 then
    table.insert(sections, { key = "Origin-reflecting paths", value = reflected_paths })
  end

  local exposed = {}
  for _, summary in ipairs(summaries) do
    for _, entry in ipairs(summary.policies or {}) do
      for _, header in ipairs(entry.policy.expose or {}) do
        local line = summary.path .. ": " .. header
        if not list_contains(exposed, line) then
          table.insert(exposed, line)
        end
      end
    end
  end
  if #exposed > 0 then
    table.insert(sections, { key = "Headers exposed cross-origin", value = exposed })
  end

  local preflight_lines = {}
  for _, summary in ipairs(summaries) do
    if summary.preflight then
      table.insert(preflight_lines, string.format("%s -> ACAO=%s methods='%s' headers='%s'",
        summary.path, tostring(summary.preflight.acao),
        tostring(summary.preflight.methods), tostring(summary.preflight.headers)))
    end
  end
  if #preflight_lines > 0 then
    table.insert(sections, { key = "Preflight grants", value = preflight_lines })
  end

  if baseline.enabled and baseline.samples > 0 then
    table.insert(sections, { key = "Soft-404 baseline", value = string.format(
      "%d probes, dominant status %s, %s", baseline.samples,
      tostring(baseline.dominant_status or "n/a"),
      baseline.consistent and "catch-all confirmed" or "no catch-all") })
  end

  if counts_after.CRITICAL > 0 then
    table.insert(sections, { key = "Remediation", value =
      "replace origin reflection with an exact-match allowlist, drop Access-Control-Allow-Credentials "
      .. "wherever cross-origin credentials are not strictly required, and add Vary: Origin" })
  elseif counts_after.HIGH > 0 then
    table.insert(sections, { key = "Remediation", value =
      "validate the Origin header against a closed list (exact match, no prefix/suffix logic), never "
      .. "answer null, and never combine '*' with credentials" })
  elseif counts_after.MEDIUM > 0 then
    table.insert(sections, { key = "Remediation", value =
      "narrow Access-Control-Allow-Methods/-Headers to what the API actually needs and remove wildcard "
      .. "exposure of response headers" })
  else
    table.insert(sections, { key = "Remediation", value =
      "CORS posture is sound; re-test after gateway or framework upgrades because defaults change" })
  end

  local total_weight = weighted_score(unique) + consistency_weight
  table.insert(sections, { key = "Consistency weight", value = tostring(consistency_weight) })
  table.insert(sections, { key = "Total weighted score", value = tostring(total_weight) })

  if nmap and nmap.verbosity and nmap.verbosity() > 1 then
    stdnse.debug1("%s: %d paths, %d probes, %d findings", SCRIPT_NAME,
      #summaries, state.requests, #findings)
  end

  return finish_output(out, unique, counts, sections)

end
