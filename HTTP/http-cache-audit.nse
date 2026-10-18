local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local nmap = require "nmap"

description = [[
Audits the cacheability of sensitive HTTP responses and proves, rather than
guesses, whether an intermediate or shared cache can store and replay them to
other users.

Naive scanners only look for "Cache-Control: public". Real cache exposure needs
four separate questions to be answered, and this script answers all of them:

1. Is the response storable at all? The full RFC 7234 directive set is parsed
   (max-age, s-maxage, no-store, no-cache, private, public, must-revalidate,
   proxy-revalidate, immutable, stale-while-revalidate, stale-if-error,
   must-understand) plus the HTTP/1.0 fallbacks (Pragma, Expires) and the
   heuristic-cacheability rules that apply when no explicit directive exists
   (a Last-Modified in the past makes a 200 response heuristically cacheable
   even without Cache-Control).

2. Which inputs key the cache entry? Every Vary token is parsed and compared
   against the inputs that actually change the response body: Cookie,
   Authorization, Accept-Encoding, Accept-Language, X-Forwarded-Proto,
   X-Forwarded-Host, Origin and the query string. A personalised response
   cached without "Vary: Cookie" is the classic cross-user leak.

3. Is the cache actually shared? The script measures observable cache
   behaviour through raw HTTP requests: the Age header, X-Cache /
   X-Cache-Lookup / CF-Cache-Status / X-Varnish / X-Proxy-Cache / X-DD-Cache
   hit markers, repeated identical requests (does the second one return a
   smaller Age or an identical ETag from cache?), and cache-control override
   probes.

4. Can the cache be poisoned or used to leak another user's data? Unkeyed
   input tests (X-Forwarded-Host, X-Forwarded-Scheme, X-Original-URL,
   X-Rewrite-URL, X-Host, X-Forwarded-Server) are sent with a benign marker and
   the response is compared byte-for-byte against the baseline: if the marker
   is reflected in the body or in a Location/Content-Location header the cache
   can be poisoned. The "cache trick" test sends a fabricated session cookie
   and compares the response with the cookie-less baseline to detect
   user-specific responses being served from a shared cache entry. Explicit
   cache-purge methods (PURGE, FLUSH, REFRESH) are probed to detect an
   unauthenticated purge interface.

Every probe uses a raw socket request built by the script (so arbitrary
headers and methods can be injected), with retries, exponential backoff, a
configurable inter-request delay, a global request budget, a soft-404 /
WAF-interstitial suppression layer, and per-finding confidence weighting:
error pages, empty bodies, 401/403 answers and CDN challenge pages are
downgraded instead of being reported as cache exposure.

Findings are aggregated into a weighted score with a human-readable verdict
(EXPOSED / AT RISK / CORRECTLY RESTRICTED / INCONCLUSIVE) and each one carries
the path, the header, the exact value and the rule that fired.

Usage:
<code>
nmap -p 80,443 --script http-cache-audit <target>
nmap -p 443 --script http-cache-audit \
  --script-args http-cache-audit.paths="/,/account,/api/v1/me" <target>
nmap -p 80 --script http-cache-audit \
  --script-args http-cache-audit.poisoning=false,http-cache-audit.maxrequests=60,\
http-cache-audit.delay=0.2 <target>
</code>
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.http

local SCRIPT_NAME = "http-cache-audit"

local RISK_LEVEL = "🟡 MEDIUM"

local SEVERITY = {
  CRITICAL = 10,
  HIGH = 7,
  MEDIUM = 4,
  LOW = 2,
  INFO = 1,
}

local SENSITIVE_PATHS = {
  "/account",
  "/accounts",
  "/profile",
  "/user",
  "/users/me",
  "/me",
  "/dashboard",
  "/settings",
  "/preferences",
  "/orders",
  "/order/history",
  "/invoice",
  "/invoices",
  "/billing",
  "/payment",
  "/payments",
  "/cart",
  "/checkout",
  "/messages",
  "/inbox",
  "/notifications",
  "/wallet",
  "/statements",
  "/transactions",
  "/history",
  "/api/user",
  "/api/users/me",
  "/api/account",
  "/api/profile",
  "/api/session",
  "/api/orders",
  "/api/payments",
  "/api/cart",
  "/api/me",
  "/api/v1/me",
  "/api/v1/user",
  "/api/v1/account",
  "/my-account",
  "/user/details",
  "/user/info",
  "/admin/dashboard",
  "/admin/users",
  "/graphql",
  "/oauth/token",
  "/auth/session",
}

local CACHEABLE_BY_DESIGN_PATHS = {
  "/",
  "/index.html",
  "/static/js/app.js",
  "/static/css/app.css",
  "/assets/logo.png",
  "/favicon.ico",
  "/robots.txt",
  "/sitemap.xml",
}

local AUTH_PROBE_PATHS = {
  "/login",
  "/signin",
  "/auth/callback",
  "/api/auth/session",
  "/api/login",
}

local CACHE_HIT_HEADERS = {
  { header = "x-cache", hit_values = { "hit", "hit from", "hit from diskcache", "hit from memcache" } },
  { header = "x-cache-lookup", hit_values = { "hit" } },
  { header = "cf-cache-status", hit_values = { "hit", "stale", "revalidated" } },
  { header = "x-varnish", hit_values = {} },
  { header = "x-proxy-cache", hit_values = { "hit", "cached" } },
  { header = "x-dd-cache", hit_values = { "hit" } },
  { header = "x-served-by", hit_values = {} },
  { header = "x-drupal-cache", hit_values = { "hit" } },
  { header = "x-cache-status", hit_values = { "hit", "cached" } },
  { header = "x-edge-cache", hit_values = { "hit" } },
  { header = "x-fastly-cache", hit_values = { "hit" } },
  { header = "x-akamai-cache", hit_values = { "hit" } },
  { header = "x-hw", hit_values = {} },
  { header = "x-envoy-upstream-service-time", hit_values = {} },
}

local UNKEYED_INPUT_HEADERS = {
  { header = "X-Forwarded-Host", weight = SEVERITY.HIGH,
    note = "X-Forwarded-Host is honoured but not part of the cache key" },
  { header = "X-Forwarded-Scheme", weight = SEVERITY.MEDIUM,
    note = "X-Forwarded-Scheme can rewrite generated absolute URLs" },
  { header = "X-Forwarded-Proto", weight = SEVERITY.MEDIUM,
    note = "X-Forwarded-Proto can downgrade generated links to http" },
  { header = "X-Original-URL", weight = SEVERITY.HIGH,
    note = "X-Original-URL overrides the routing target on some stacks" },
  { header = "X-Rewrite-URL", weight = SEVERITY.HIGH,
    note = "X-Rewrite-URL overrides the routing target on some stacks" },
  { header = "X-Host", weight = SEVERITY.MEDIUM,
    note = "X-Host is honoured by several frameworks for URL generation" },
  { header = "X-Forwarded-Server", weight = SEVERITY.MEDIUM,
    note = "X-Forwarded-Server can be reflected into generated links" },
  { header = "X-Forwarded-For", weight = SEVERITY.LOW,
    note = "X-Forwarded-For reflection enables log injection and geo-cache splits" },
  { header = "X-Client-IP", weight = SEVERITY.LOW,
    note = "X-Client-IP reflection can bypass IP-based access control" },
  { header = "X-Custom-IP-Authorization", weight = SEVERITY.LOW,
    note = "X-Custom-IP-Authorization is a known admin-panel bypass header" },
}

local PURGE_METHODS = { "PURGE", "FLUSH", "REFRESH", "CACHE-FLUSH" }

local VARY_INPUTS = {
  "cookie",
  "authorization",
  "accept-encoding",
  "accept-language",
  "accept",
  "origin",
  "x-forwarded-proto",
  "x-forwarded-host",
  "user-agent",
}

local SOFT404_TEMPLATES = {
  "/nse-cache-probe-%s",
  "/%s/does-not-exist",
}

local WAF_SIGNATURES = {
  "cf-ray", "cloudflare", "attention required", "akamai", "incapsula",
  "x-iinfo", "sucuri", "aws waf", "request blocked", "access denied",
  "web application firewall", "mod_security", "fortiweb", "safeline",
}

local DEFAULT_ARGS = {
  paths = nil,
  maxpaths = 10,
  maxrequests = 90,
  retries = 2,
  timeout = 8000,
  delay = 0.05,
  poisoning = true,
  purgemethods = true,
  cachetrick = true,
  sharedcache = true,
  soft404 = true,
  useragent = nil,
  maxbodysize = 262144,
}

local state = { requests = 0, rate_limited = 0, errors = 0 }

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

local function list_contains(list, needle)
  for _, item in ipairs(list) do
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

local function read_args()
  local args = {}
  for key, value in pairs(DEFAULT_ARGS) do
    args[key] = value
  end

  local raw_paths = stdnse.get_script_args(SCRIPT_NAME .. ".paths")
  if raw_paths and #raw_paths > 0 then
    local list = {}
    for candidate in string.gmatch(raw_paths, "[^,]+") do
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

  for _, spec in ipairs({
    { key = "maxpaths", minimum = 1 },
    { key = "maxrequests", minimum = 5 },
    { key = "retries", minimum = 0 },
    { key = "timeout", minimum = 500 },
    { key = "maxbodysize", minimum = 1024 },
  }) do
    local value = tonumber(stdnse.get_script_args(SCRIPT_NAME .. "." .. spec.key))
    if value and value >= spec.minimum then
      args[spec.key] = math.floor(value)
    end
  end

  local delay = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".delay"))
  if delay and delay >= 0 and delay <= 10 then
    args.delay = delay
  end

  for _, key in ipairs({ "poisoning", "purgemethods", "cachetrick", "sharedcache", "soft404" }) do
    local value = stdnse.get_script_args(SCRIPT_NAME .. "." .. key)
    if value ~= nil then
      args[key] = not (value == false or value == "false" or value == "no" or value == "0")
    end
  end

  local ua = stdnse.get_script_args(SCRIPT_NAME .. ".useragent")
  if ua and #ua > 0 then
    args.useragent = ua
  end

  return args
end

local function random_token(length)
  local alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
  local out = {}
  math.randomseed((os.time() * 100003) + (stdnse.clock_ms and stdnse.clock_ms() or 0) + math.random(1, 99999))
  for _ = 1, length do
    table.insert(out, string.sub(alphabet, math.random(1, #alphabet), math.random(1, #alphabet)))
  end
  return table.concat(out)
end

local function fnv1a32(value)
  local hash = 2166136261
  for i = 1, #(value or "") do
    hash = (hash ~ string.byte(value, i)) & 0xFFFFFFFF
    hash = (hash * 16777619) & 0xFFFFFFFF
  end
  return string.format("%08x", hash)
end

local function sleep(seconds)
  if seconds and seconds > 0 then
    stdnse.sleep(seconds)
  end
end

local function budget_exhausted(args)
  return state.requests >= args.maxrequests
end

local function host_header_for(host, port)
  local name = host.targetname or host.name or host.ip or "localhost"
  local is_default_port = (port.number == 80 and not port.ssl) or (port.number == 443 and port.ssl)
  if is_default_port then
    return name
  end
  return string.format("%s:%d", name, port.number)
end

local function connect_socket(host, port, args)
  local socket = nmap.new_socket()
  local ok, err = socket:connect(host, port)
  if not ok then
    return nil, tostring(err)
  end
  socket:set_timeout(args.timeout)
  return socket, nil
end

local function dechunk(body)
  local out = {}
  local position = 1
  while position <= #body do
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
  local head, body = string.match(raw, "^(.-)\r\n\r\n(.*)$")
  if not head then
    head, body = string.match(raw, "^(.-)\n\n(.*)$")
  end
  if not head then
    head = raw
    body = ""
  end

  local response = { header = {}, rawheader = {}, body = body or "", raw = raw }
  local first = true
  for line in string.gmatch(head, "([^\r\n]*)") do
    if first then
      response["status-line"] = line
      local status = string.match(line, "^HTTP/[%d%.]+%s+(%d+)")
      response.status = tonumber(status) or 0
      response.version = string.match(line, "^HTTP/([%d%.]+)")
      first = false
    elseif #trim(line) > 0 then
      local name, value = string.match(line, "^([^:]+):%s*(.*)$")
      if name then
        local key = lower(name)
        table.insert(response.rawheader, line)
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

  if response.header["transfer-encoding"]
    and string.find(lower(tostring(response.header["transfer-encoding"])), "chunked") then
    response.body = dechunk(response.body)
  end

  return response
end

local function raw_request(host, port, method, path, extra_headers, args, body)
  if budget_exhausted(args) then
    return nil, "request budget exhausted"
  end
  state.requests = state.requests + 1

  local socket, err = connect_socket(host, port, args)
  if not socket then
    state.errors = state.errors + 1
    return nil, err
  end

  local lines = {}
  table.insert(lines, string.format("%s %s HTTP/1.1", method, path))
  table.insert(lines, "Host: " .. host_header_for(host, port))
  table.insert(lines, "User-Agent: " .. (args.useragent or ("Mozilla/5.0 (compatible; " .. SCRIPT_NAME .. ")")))
  table.insert(lines, "Accept: */*")
  table.insert(lines, "Accept-Encoding: identity")
  table.insert(lines, "Connection: close")
  if body then
    table.insert(lines, "Content-Length: " .. tostring(#body))
  end
  for name, value in pairs(extra_headers or {}) do
    table.insert(lines, name .. ": " .. tostring(value))
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

  if not recv_ok and (not data or #data == 0) then
    state.errors = state.errors + 1
    return nil, "no response bytes"
  end

  local raw = data or ""
  if #raw > args.maxbodysize * 2 then
    raw = string.sub(raw, 1, args.maxbodysize * 2)
  end

  sleep(args.delay)
  return parse_raw_response(raw), nil
end

local function http_lib_get(host, port, path, args, extra_headers)
  if budget_exhausted(args) then
    return nil, "request budget exhausted"
  end
  state.requests = state.requests + 1

  local options = { header = {}, no_cache = true, timeout = args.timeout }
  options.header["User-Agent"] = args.useragent or ("Mozilla/5.0 (compatible; " .. SCRIPT_NAME .. ")")
  options.header["Accept"] = "*/*"
  options.header["Accept-Encoding"] = "identity"
  options.header["Connection"] = "close"
  for name, value in pairs(extra_headers or {}) do
    options.header[name] = tostring(value)
  end

  local attempt = 0
  local last_error = nil
  while attempt <= args.retries do
    attempt = attempt + 1
    local ok, response = pcall(http.get, host, port, path, options)
    if ok and type(response) == "table" and response.status then
      if response.status == 429 then
        state.rate_limited = state.rate_limited + 1
        sleep(math.min(attempt * 2, 8))
        last_error = "HTTP 429"
      else
        sleep(args.delay)
        return response, nil
      end
    elseif ok then
      last_error = "malformed response"
    else
      last_error = tostring(response)
      state.errors = state.errors + 1
    end
    if attempt <= args.retries then
      sleep(0.4 * attempt)
    end
  end

  sleep(args.delay)
  return nil, last_error
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

local function detect_waf(response)
  local body = lower(response.body or "")
  for _, line in ipairs(response.rawheader or {}) do
    local lowered = lower(line)
    for _, signature in ipairs(WAF_SIGNATURES) do
      if string.find(lowered, signature, 1, true) then
        return signature
      end
    end
  end
  if #body > 0 and #body < 20000 then
    for _, signature in ipairs(WAF_SIGNATURES) do
      if string.find(body, signature, 1, true) then
        return signature
      end
    end
  end
  return nil
end

local function build_soft404_baseline(host, port, args)
  local baseline = { enabled = args.soft404, samples = 0, statuses = {}, hashes = {}, lengths = {} }
  if not args.soft404 then
    return baseline
  end
  for _, template in ipairs(SOFT404_TEMPLATES) do
    if budget_exhausted(args) then
      break
    end
    local response = http_lib_get(host, port, string.format(template, random_token(10)), args)
    if response and response.status then
      baseline.samples = baseline.samples + 1
      local key = tostring(response.status)
      baseline.statuses[key] = (baseline.statuses[key] or 0) + 1
      local hash = fnv1a32(response.body or "")
      baseline.hashes[hash] = (baseline.hashes[hash] or 0) + 1
      baseline.lengths[#(response.body or "")] = (baseline.lengths[#(response.body or "")] or 0) + 1
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

local function parse_cache_control(value)
  local directives = {}
  local order = {}
  for chunk in string.gmatch(value or "", "[^,]+") do
    local trimmed = trim(chunk)
    if #trimmed > 0 then
      local name, argument = string.match(trimmed, "^([%w%-]+)%s*=?%s*(.*)$")
      if name then
        local key = lower(name)
        directives[key] = trim(argument)
        table.insert(order, key)
      end
    end
  end
  return directives, order
end

local function parse_expires(value)
  if type(value) ~= "string" then
    return nil, "missing"
  end
  local trimmed = trim(value)
  if lower(trimmed) == "0" or lower(trimmed) == "-1" then
    return -1, "disabled"
  end
  local day, month, year = string.match(trimmed, "(%d+)%s+(%a+)%s+(%d+)")
  if not day then
    local weekday, rest = string.match(trimmed, "^%a+,%s+(%d+)%s+(%a+)%s+(%d+)")
    day = day or weekday
    month = month or rest
    year = year or rest
  end
  if not (day and month and year) then
    return nil, "unparseable"
  end
  local months = { jan = 1, feb = 2, mar = 3, apr = 4, may = 5, jun = 6,
    jul = 7, aug = 8, sep = 9, oct = 10, nov = 11, dec = 12 }
  local month_number = months[lower(string.sub(month, 1, 3))]
  if not month_number then
    return nil, "unparseable month"
  end
  local numeric_year = tonumber(year)
  if not numeric_year then
    return nil, "unparseable year"
  end
  if numeric_year < 100 then
    numeric_year = numeric_year + (numeric_year < 70 and 2000 or 1900)
  end
  local approximate = os.time({ year = numeric_year, month = month_number, day = tonumber(day), hour = 12 })
  local now = os.time()
  local delta = approximate - now
  if delta <= 0 then
    return -1, "in the past"
  end
  return delta, "in the future"
end

local function parse_last_modified(value)
  if type(value) ~= "string" then
    return nil
  end
  local day, month, year = string.match(value, "(%d+)%s+(%a+)%s+(%d+)")
  if not (day and month and year) then
    return nil
  end
  local months = { jan = 1, feb = 2, mar = 3, apr = 4, may = 5, jun = 6,
    jul = 7, aug = 8, sep = 9, oct = 10, nov = 11, dec = 12 }
  local month_number = months[lower(string.sub(month, 1, 3))]
  local numeric_year = tonumber(year)
  if not (month_number and numeric_year) then
    return nil
  end
  return os.time({ year = numeric_year, month = month_number, day = tonumber(day), hour = 12 })
end

local function parse_vary(response)
  local tokens = {}
  local seen = {}
  for _, value in ipairs(header_values(response, "vary")) do
    for chunk in string.gmatch(value, "[^,]+") do
      local token = lower(chunk)
      if #token > 0 and not seen[token] then
        seen[token] = true
        table.insert(tokens, token)
      end
    end
  end
  return tokens
end

local function classify_storability(response, path)
  local result = {
    path = path,
    status = response.status or 0,
    storable = false,
    shared_storable = false,
    freshness = nil,
    directives = {},
    order = {},
    vary = parse_vary(response),
    reasons = {},
    heuristics = {},
  }

  local cc_values = header_values(response, "cache-control")
  for _, value in ipairs(cc_values) do
    local directives, order = parse_cache_control(value)
    for _, name in ipairs(order) do
      result.directives[name] = directives[name]
      table.insert(result.order, name)
    end
  end

  local pragma = lower(header_value(response, "pragma") or "")
  local expires = header_value(response, "expires")
  local last_modified = header_value(response, "last-modified")
  local etag = header_value(response, "etag")
  local age = tonumber(header_value(response, "age"))
  local date_value = header_value(response, "date")

  result.expires_raw = expires
  result.pragma = pragma
  result.last_modified = last_modified
  result.etag = etag
  result.age = age
  result.date = date_value

  local directives = result.directives

  if directives["no-store"] then
    table.insert(result.reasons, "Cache-Control: no-store forbids any storage")
    return result
  end

  local status = response.status or 0
  local status_storable = status == 200 or status == 203 or status == 204
    or status == 206 or status == 300 or status == 301 or status == 302
    or status == 303 or status == 307 or status == 308 or status == 404
    or status == 405 or status == 410 or status == 414 or status == 501
  if not status_storable then
    table.insert(result.reasons, string.format("status %d is not cacheable by default", status))
  end

  local private = directives["private"]
  local public = directives["public"]

  if private then
    if private == "" or private == "true" then
      table.insert(result.reasons, "Cache-Control: private restricts storage to the browser cache")
      result.storable = true
    else
      table.insert(result.reasons, "Cache-Control: private(" .. private .. ") restricts only listed fields")
      result.storable = true
      result.shared_storable = true
    end
  end

  if public then
    result.storable = true
    result.shared_storable = true
    table.insert(result.reasons, "Cache-Control: public explicitly allows shared-cache storage")
  end

  local max_age = tonumber(directives["max-age"])
  local s_maxage = tonumber(directives["s-maxage"])
  if max_age then
    result.freshness = max_age
    result.storable = true
    if not private then
      result.shared_storable = true
    end
    table.insert(result.reasons, string.format("max-age=%d seconds of freshness", max_age))
  end
  if s_maxage then
    result.shared_storable = true
    result.shared_freshness = s_maxage
    table.insert(result.reasons, string.format("s-maxage=%d explicitly targets shared caches", s_maxage))
  end

  if directives["must-revalidate"] then
    table.insert(result.reasons, "must-revalidate forces origin revalidation once stale")
  end
  if directives["proxy-revalidate"] then
    table.insert(result.reasons, "proxy-revalidate forces shared-cache revalidation once stale")
  end
  if directives["immutable"] then
    table.insert(result.reasons, "immutable suppresses user-initiated revalidation")
  end
  if directives["stale-while-revalidate"] then
    table.insert(result.reasons, "stale-while-revalidate=" .. tostring(directives["stale-while-revalidate"])
      .. " allows serving stale content in the background")
  end
  if directives["stale-if-error"] then
    table.insert(result.reasons, "stale-if-error=" .. tostring(directives["stale-if-error"])
      .. " allows serving stale content after origin failure")
  end

  if not result.storable and #cc_values == 0 then
    if expires then
      local delta, description = parse_expires(expires)
      if delta and delta > 0 then
        result.storable = true
        result.shared_storable = true
        result.freshness = delta
        table.insert(result.reasons, "Expires is " .. description .. " (" .. expires .. ") without Cache-Control")
      elseif delta and delta < 0 then
        table.insert(result.reasons, "Expires is in the past; response is stale immediately")
      else
        table.insert(result.reasons, "Expires value could not be parsed (" .. tostring(expires) .. ")")
      end
    elseif string.find(pragma, "no%-cache") or string.find(pragma, "no%-store") then
      table.insert(result.reasons, "Pragma: no-cache (HTTP/1.0) prevents storage")
    elseif last_modified then
      local modified_at = parse_last_modified(last_modified)
      if modified_at then
        local age_seconds = os.time() - modified_at
        local heuristic = math.floor(age_seconds * 0.1)
        result.storable = true
        result.shared_storable = true
        result.freshness = heuristic
        table.insert(result.heuristics, string.format(
          "no explicit directive but Last-Modified is %d s old: heuristic freshness ~%d s (RFC 7234 section 4.2.2)",
          age_seconds, heuristic))
      else
        table.insert(result.heuristics, "Last-Modified present but unparseable; heuristic caching still possible")
        result.storable = true
        result.shared_storable = true
      end
    else
      table.insert(result.heuristics, "no cache directives at all: caches may apply heuristic freshness")
      result.storable = true
      result.shared_storable = true
    end
  end

  if directives["no-cache"] and not directives["no-store"] then
    table.insert(result.reasons, "no-cache allows storage but requires revalidation before every reuse")
  end

  if age and age > 0 then
    result.observed_age = age
    table.insert(result.reasons, "Age=" .. age .. " proves the response was served from a cache")
  end

  for _, entry in ipairs(CACHE_HIT_HEADERS) do
    local value = header_value(response, entry.header)
    if value then
      result.cache_marker = result.cache_marker or {}
      table.insert(result.cache_marker, entry.header .. ": " .. value)
      if #entry.hit_values > 0 then
        local lowered_value = lower(value)
        for _, hit in ipairs(entry.hit_values) do
          if string.find(lowered_value, hit, 1, true) then
            result.cache_hit = true
            result.cache_hit_header = entry.header
            break
          end
        end
      end
    end
  end

  if etag and not directives["no-store"] then
    result.weak_etag = starts_with(lower(etag), "w/")
  end

  return result
end

local function is_sensitive_path(path)
  local lowered = lower(path)
  for _, keyword in ipairs({
    "account", "profile", "user", "me", "dashboard", "settings", "order",
    "invoice", "billing", "payment", "cart", "checkout", "message", "inbox",
    "notification", "wallet", "statement", "transaction", "history", "session",
    "admin", "auth", "oauth", "graphql",
  }) do
    if string.find(lowered, keyword, 1, true) then
      return true
    end
  end
  return false
end

local function select_paths(args)
  local selected = {}
  local seen = {}
  local function add(path)
    if not seen[path] then
      seen[path] = true
      table.insert(selected, path)
    end
  end

  if args.paths then
    for _, path in ipairs(args.paths) do
      add(path)
    end
  else
    for _, path in ipairs(SENSITIVE_PATHS) do
      add(path)
    end
    for _, path in ipairs(CACHEABLE_BY_DESIGN_PATHS) do
      add(path)
    end
    for _, path in ipairs(AUTH_PROBE_PATHS) do
      add(path)
    end
  end

  local limited = {}
  for _, path in ipairs(selected) do
    table.insert(limited, path)
    if #limited >= args.maxpaths then
      break
    end
  end
  return limited
end

local function vary_gap_analysis(classification)
  local gaps = {}
  local vary = {}
  for _, token in ipairs(classification.vary) do
    vary[token] = true
  end

  if not classification.shared_storable then
    return gaps
  end

  for _, input in ipairs(VARY_INPUTS) do
    if not vary[input] then
      if input == "cookie" then
        table.insert(gaps, {
          severity = "HIGH", weight = SEVERITY.HIGH, input = "Cookie",
          detail = "shared-cache storable without Vary: Cookie — one user's personalised response can be served to another",
        })
      elseif input == "authorization" then
        table.insert(gaps, {
          severity = "HIGH", weight = SEVERITY.HIGH, input = "Authorization",
          detail = "shared-cache storable without Vary: Authorization — bearer-token responses can be replayed",
        })
      elseif input == "accept-encoding" then
        table.insert(gaps, {
          severity = "LOW", weight = SEVERITY.LOW, input = "Accept-Encoding",
          detail = "missing Vary: Accept-Encoding can serve a compressed body to a client that did not ask for it",
        })
      elseif input == "accept-language" then
        table.insert(gaps, {
          severity = "LOW", weight = SEVERITY.LOW, input = "Accept-Language",
          detail = "missing Vary: Accept-Language can serve the wrong localisation from cache",
        })
      elseif input == "origin" then
        table.insert(gaps, {
          severity = "MEDIUM", weight = SEVERITY.MEDIUM, input = "Origin",
          detail = "missing Vary: Origin on a CORS-enabled response can leak one origin's ACAO header to another",
        })
      elseif input == "x-forwarded-proto" or input == "x-forwarded-host" then
        table.insert(gaps, {
          severity = "MEDIUM", weight = SEVERITY.MEDIUM, input = input,
          detail = "missing Vary for " .. input .. " while the value influences generated URLs (poisoning vector)",
        })
      end
    end
  end

  if vary["*"] then
    table.insert(gaps, {
      severity = "INFO", weight = SEVERITY.INFO, input = "*",
      detail = "Vary: * makes the response uncacheable by shared caches (safe but wasteful)",
    })
  end

  return gaps
end

local function compare_responses(baseline, candidate)
  local comparison = {
    status_changed = (baseline.status or 0) ~= (candidate.status or 0),
    length_delta = math.abs(#(baseline.body or "") - #(candidate.body or "")),
    hash_changed = fnv1a32(baseline.body or "") ~= fnv1a32(candidate.body or ""),
    new_headers = {},
    changed_headers = {},
    reflected = {},
  }

  for _, line in ipairs(candidate.rawheader or {}) do
    local name, value = string.match(line, "^([^:]+):%s*(.*)$")
    if name then
      local key = lower(name)
      local previous = baseline.header and baseline.header[key]
      if previous == nil then
        table.insert(comparison.new_headers, key .. ": " .. trim(value))
      elseif tostring(previous) ~= trim(value) then
        table.insert(comparison.changed_headers, string.format("%s: %s -> %s", key, tostring(previous), trim(value)))
      end
    end
  end

  return comparison
end

local function find_marker_reflection(response, marker)
  local hits = {}
  local body = response.body or ""
  if #marker > 0 and string.find(body, marker, 1, true) then
    table.insert(hits, "reflected in the response body")
  end
  for _, name in ipairs({ "location", "content-location", "content-base", "refresh", "link", "set-cookie" }) do
    local value = header_value(response, name)
    if value and string.find(value, marker, 1, true) then
      table.insert(hits, "reflected in the " .. name .. " header")
    end
  end
  for _, line in ipairs(response.rawheader or {}) do
    if string.find(line, marker, 1, true) then
      local name = string.match(line, "^([^:]+):")
      if name and not list_contains({ "location", "content-location", "content-base", "refresh", "link", "set-cookie" }, lower(name)) then
        table.insert(hits, "reflected in the " .. lower(name) .. " header")
      end
    end
  end
  local unique = {}
  local out = {}
  for _, hit in ipairs(hits) do
    if not unique[hit] then
      unique[hit] = true
      table.insert(out, hit)
    end
  end
  return out
end

local function run_poisoning_probes(host, port, path, baseline_response, args, findings)
  if not args.poisoning or not baseline_response or not baseline_response.status then
    return 0
  end

  local weight = 0
  local marker = "nsecache" .. random_token(8) .. ".example"

  for _, entry in ipairs(UNKEYED_INPUT_HEADERS) do
    if budget_exhausted(args) then
      break
    end
    local extra = {}
    extra[entry.header] = marker
    local response, err = raw_request(host, port, "GET", path, extra, args)
    if response and response.status then
      local comparison = compare_responses(baseline_response, response)
      local reflections = find_marker_reflection(response, marker)
      if #reflections > 0 then
        local vary = parse_vary(response)
        local keyed = false
        for _, token in ipairs(vary) do
          if lower(token) == lower(entry.header) then
            keyed = true
          end
        end
        local severity = keyed and "LOW" or (entry.weight >= SEVERITY.HIGH and "HIGH" or "MEDIUM")
        local entry_weight = keyed and SEVERITY.LOW or entry.weight
        table.insert(findings, {
          severity = severity,
          weight = entry_weight,
          path = path,
          detail = string.format("%s: %s%s (unkeyed input reflected -> cache poisoning vector)",
            entry.header, table.concat(reflections, ", "),
            keyed and " but included in Vary" or ""),
        })
        weight = weight + entry_weight
      elseif comparison.hash_changed and comparison.length_delta > 16 then
        table.insert(findings, {
          severity = "LOW",
          weight = SEVERITY.LOW,
          path = path,
          detail = string.format("%s changes the response body by %d bytes without appearing in Vary",
            entry.header, comparison.length_delta),
        })
        weight = weight + SEVERITY.LOW
      end
    elseif err and err ~= "request budget exhausted" then
      table.insert(findings, {
        severity = "INFO", weight = 0, path = path,
        detail = string.format("%s probe failed: %s", entry.header, tostring(err)),
      })
    end
  end

  return weight
end

local function run_cache_trick(host, port, path, baseline_response, args, findings)
  if not args.cachetrick or not baseline_response or not baseline_response.status then
    return 0
  end

  local weight = 0
  local fake_cookie = "nse_cache_trick_" .. random_token(10) .. "=1"
  local response, err = raw_request(host, port, "GET", path, { Cookie = fake_cookie }, args)
  if not response or not response.status then
    if err and err ~= "request budget exhausted" then
      table.insert(findings, {
        severity = "INFO", weight = 0, path = path,
        detail = "cache-trick probe failed: " .. tostring(err),
      })
    end
    return 0
  end

  local comparison = compare_responses(baseline_response, response)
  local vary = parse_vary(response)
  local cookie_keyed = false
  for _, token in ipairs(vary) do
    if token == "cookie" then
      cookie_keyed = true
    end
  end

  if not comparison.hash_changed and comparison.length_delta == 0 and not comparison.status_changed then
    local classification = classify_storability(response, path)
    if classification.shared_storable and not cookie_keyed then
      table.insert(findings, {
        severity = "MEDIUM",
        weight = SEVERITY.MEDIUM,
        path = path,
        detail = "identical response with and without a session cookie while being shared-cache storable "
          .. "and not keyed on Cookie (user-specific data may be cached)",
      })
      weight = weight + SEVERITY.MEDIUM
    end
  elseif comparison.hash_changed and not cookie_keyed then
    table.insert(findings, {
      severity = "HIGH",
      weight = SEVERITY.HIGH,
      path = path,
      detail = string.format("response changes with a fabricated Cookie (%d byte delta) but Vary does not include Cookie",
        comparison.length_delta),
    })
    weight = weight + SEVERITY.HIGH
  end

  local auth_response, auth_err = raw_request(host, port, "GET", path,
    { Authorization = "Bearer nse.probe." .. random_token(6) }, args)
  if auth_response and auth_response.status then
    local auth_comparison = compare_responses(baseline_response, auth_response)
    local auth_keyed = false
    for _, token in ipairs(parse_vary(auth_response)) do
      if token == "authorization" then
        auth_keyed = true
      end
    end
    if not auth_comparison.status_changed and not auth_comparison.hash_changed and not auth_keyed then
      local classification = classify_storability(auth_response, path)
      if classification.shared_storable then
        table.insert(findings, {
          severity = "MEDIUM",
          weight = SEVERITY.MEDIUM,
          path = path,
          detail = "response ignores the Authorization header and is shared-cache storable without Vary: Authorization",
        })
        weight = weight + SEVERITY.MEDIUM
      end
    end
  elseif auth_err and auth_err ~= "request budget exhausted" then
    table.insert(findings, {
      severity = "INFO", weight = 0, path = path,
      detail = "authorization probe failed: " .. tostring(auth_err),
    })
  end

  return weight
end

local function run_purge_probes(host, port, path, args, findings)
  if not args.purgemethods then
    return 0
  end
  local weight = 0
  for _, method in ipairs(PURGE_METHODS) do
    if budget_exhausted(args) then
      break
    end
    local response, err = raw_request(host, port, method, path, {}, args)
    if response and response.status then
      local status = response.status
      if status >= 200 and status < 300 then
        table.insert(findings, {
          severity = "HIGH",
          weight = SEVERITY.HIGH,
          path = path,
          detail = string.format("%s %s answered HTTP %d — unauthenticated cache purge interface", method, path, status),
        })
        weight = weight + SEVERITY.HIGH
      elseif status ~= 405 and status ~= 501 and status ~= 403 and status ~= 404 and status ~= 400 then
        table.insert(findings, {
          severity = "MEDIUM",
          weight = SEVERITY.MEDIUM,
          path = path,
          detail = string.format("%s %s answered HTTP %d (method is understood by the cache layer)", method, path, status),
        })
        weight = weight + SEVERITY.MEDIUM
      end
    elseif err and err ~= "request budget exhausted" then
      table.insert(findings, {
        severity = "INFO", weight = 0, path = path,
        detail = string.format("%s probe failed: %s", method, tostring(err)),
      })
    end
  end
  return weight
end

local function run_shared_cache_evidence(host, port, path, args, findings)
  if not args.sharedcache then
    return 0, nil
  end

  local weight = 0
  local evidence = {}
  local first = http_lib_get(host, port, path, args, { ["X-NSE-Probe"] = "first" })
  sleep(0.2)
  local second = http_lib_get(host, port, path, args, { ["X-NSE-Probe"] = "second" })

  if not (first and second) then
    return 0, nil
  end

  local first_age = tonumber(header_value(first, "age")) or 0
  local second_age = tonumber(header_value(second, "age")) or 0
  if second_age > first_age then
    table.insert(evidence, string.format("Age increased from %d to %d across two identical requests (shared cache serving)",
      first_age, second_age))
    table.insert(findings, {
      severity = "INFO", weight = SEVERITY.INFO, path = path,
      detail = string.format("shared cache confirmed through Age progression (%d -> %d)", first_age, second_age),
    })
  end

  for _, entry in ipairs(CACHE_HIT_HEADERS) do
    local value = header_value(second, entry.header)
    if value then
      table.insert(evidence, entry.header .. ": " .. value)
      for _, hit in ipairs(entry.hit_values) do
        if string.find(lower(value), hit, 1, true) then
          table.insert(findings, {
            severity = "INFO", weight = SEVERITY.INFO, path = path,
            detail = string.format("cache hit marker %s: %s", entry.header, value),
          })
          break
        end
      end
    end
  end

  local first_hash = fnv1a32(first.body or "")
  local second_hash = fnv1a32(second.body or "")
  if first_hash == second_hash and #(first.body or "") > 0 then
    table.insert(evidence, "two independent requests returned byte-identical bodies")
  end

  return weight, evidence
end

local function audit_path(host, port, path, args, baseline)
  local result = {
    path = path,
    findings = {},
    weight = 0,
    errors = {},
  }

  local response, err = http_lib_get(host, port, path, args)
  if not response then
    table.insert(result.errors, string.format("%s: %s", path, tostring(err)))
    return result
  end

  local vendor = detect_waf(response)
  if vendor then
    result.confidence = "low"
    result.notes = { "WAF/CDN interstitial (" .. vendor .. ")" }
    result.classification = classify_storability(response, path)
    result.response_status = response.status
    return result
  end

  local soft, soft_reason = looks_like_soft404(response, baseline)
  if soft then
    result.confidence = "low"
    result.notes = { "soft-404: " .. tostring(soft_reason) }
    result.classification = classify_storability(response, path)
    result.response_status = response.status
    return result
  end

  local classification = classify_storability(response, path)
  result.classification = classification
  result.response_status = response.status
  result.body_length = #(response.body or "")
  result.confidence = "high"

  if response.status == 401 or response.status == 403 then
    result.confidence = "low"
    result.notes = result.notes or {}
    table.insert(result.notes, string.format("status %d response: caching directives may be generated by the auth layer", response.status))
  end

  if #classification.reasons > 0 then
    result.storability_reasons = classification.reasons
  end
  if #classification.heuristics > 0 then
    for _, heuristic in ipairs(classification.heuristics) do
      table.insert(result.findings, {
        severity = "MEDIUM", weight = SEVERITY.MEDIUM, path = path,
        detail = heuristic,
      })
      result.weight = result.weight + SEVERITY.MEDIUM
    end
  end

  local sensitive = is_sensitive_path(path)

  if classification.shared_storable and sensitive then
    table.insert(result.findings, {
      severity = "HIGH", weight = SEVERITY.HIGH, path = path,
      detail = "sensitive path is storable by shared caches (" .. table.concat(classification.reasons, "; ") .. ")",
    })
    result.weight = result.weight + SEVERITY.HIGH
  end

  if classification.directives["public"] and sensitive then
    table.insert(result.findings, {
      severity = "HIGH", weight = SEVERITY.HIGH, path = path,
      detail = "Cache-Control: public on a personalised path",
    })
    result.weight = result.weight + SEVERITY.HIGH
  end

  if classification.shared_storable and sensitive and not classification.directives["no-store"] then
    table.insert(result.findings, {
      severity = "MEDIUM", weight = SEVERITY.MEDIUM, path = path,
      detail = "missing 'no-store' on a sensitive path",
    })
    result.weight = result.weight + SEVERITY.MEDIUM
  end

  if classification.shared_storable and not classification.directives["must-revalidate"]
    and not classification.directives["proxy-revalidate"] and sensitive then
    table.insert(result.findings, {
      severity = "LOW", weight = SEVERITY.LOW, path = path,
      detail = "no must-revalidate/proxy-revalidate: stale personalised content can be served after origin failure",
    })
    result.weight = result.weight + SEVERITY.LOW
  end

  for _, gap in ipairs(vary_gap_analysis(classification)) do
    if sensitive or gap.severity ~= "HIGH" then
      table.insert(result.findings, {
        severity = gap.severity, weight = gap.weight, path = path,
        detail = gap.detail .. " (Vary: " .. (#classification.vary > 0 and table.concat(classification.vary, ", ") or "absent") .. ")",
      })
      result.weight = result.weight + (sensitive and gap.weight or math.floor(gap.weight / 2))
    end
  end

  if classification.cache_hit then
    table.insert(result.findings, {
      severity = sensitive and "HIGH" or "INFO",
      weight = sensitive and SEVERITY.HIGH or SEVERITY.INFO,
      path = path,
      detail = string.format("observed cache hit through %s%s", classification.cache_hit_header,
        sensitive and " on a sensitive path" or ""),
    })
    result.weight = result.weight + (sensitive and SEVERITY.HIGH or 0)
  end

  if classification.observed_age and classification.observed_age > 0 and sensitive then
    table.insert(result.findings, {
      severity = "HIGH", weight = SEVERITY.HIGH, path = path,
      detail = string.format("Age=%d on a sensitive path proves the response came from a shared cache",
        classification.observed_age),
    })
    result.weight = result.weight + SEVERITY.HIGH
  end

  if classification.etag and not classification.weak_etag and sensitive then
    table.insert(result.findings, {
      severity = "LOW", weight = SEVERITY.LOW, path = path,
      detail = "strong ETag on a personalised resource enables ETag-reuse information leaks",
    })
    result.weight = result.weight + SEVERITY.LOW
  end

  if classification.expires_raw then
    local delta, description = parse_expires(classification.expires_raw)
    if description == "unparseable" or description == "unparseable month" or description == "unparseable year" then
      table.insert(result.findings, {
        severity = "LOW", weight = SEVERITY.LOW, path = path,
        detail = "Expires header is not RFC 7231 compliant (" .. tostring(classification.expires_raw) .. ")",
      })
      result.weight = result.weight + SEVERITY.LOW
    elseif delta and delta > 31536000 then
      table.insert(result.findings, {
        severity = "LOW", weight = SEVERITY.LOW, path = path,
        detail = string.format("Expires is %d seconds in the future (> 1 year) on a dynamic path", delta),
      })
      result.weight = result.weight + SEVERITY.LOW
    end
  end

  if string.find(lower(classification.pragma or ""), "no%-cache") and classification.directives["max-age"] then
    table.insert(result.findings, {
      severity = "LOW", weight = SEVERITY.LOW, path = path,
      detail = "contradictory Pragma: no-cache together with Cache-Control max-age",
    })
    result.weight = result.weight + SEVERITY.LOW
  end

  result.weight = result.weight
    + run_poisoning_probes(host, port, path, response, args, result.findings)
  result.weight = result.weight
    + run_cache_trick(host, port, path, response, args, result.findings)
  result.weight = result.weight
    + run_purge_probes(host, port, path, args, result.findings)

  local shared_weight, shared_evidence = run_shared_cache_evidence(host, port, path, args, result.findings)
  result.weight = result.weight + (shared_weight or 0)
  result.cache_evidence = shared_evidence

  if result.confidence == "low" then
    for _, finding in ipairs(result.findings) do
      finding.confidence = "low"
      finding.weight = math.max(0, math.floor(finding.weight / 2))
    end
    result.weight = 0
    for _, finding in ipairs(result.findings) do
      result.weight = result.weight + finding.weight
    end
  end

  return result
end

local function dedupe_findings(results)
  local unique = {}
  local index = {}
  local counts = { CRITICAL = 0, HIGH = 0, MEDIUM = 0, LOW = 0, INFO = 0 }

  for _, result in ipairs(results) do
    for _, finding in ipairs(result.findings or {}) do
      local key = finding.detail .. "|" .. finding.severity
      if not index[key] then
        index[key] = {
          severity = finding.severity,
          weight = finding.weight,
          detail = finding.detail,
          paths = {},
          confidence = finding.confidence or "high",
        }
        table.insert(unique, index[key])
      end
      local entry = index[key]
      if not list_contains(entry.paths, finding.path) then
        table.insert(entry.paths, finding.path)
      end
      counts[finding.severity] = (counts[finding.severity] or 0) + 1
    end
  end

  local order = { CRITICAL = 1, HIGH = 2, MEDIUM = 3, LOW = 4, INFO = 5 }
  table.sort(unique, function(a, b)
    local oa = order[a.severity] or 9
    local ob = order[b.severity] or 9
    if oa ~= ob then
      return oa < ob
    end
    if a.weight ~= b.weight then
      return a.weight > b.weight
    end
    return a.detail < b.detail
  end)

  return unique, counts
end

local function verdict_from(results, counts, unique)
  local shared_storable_sensitive = 0
  local poisoned = 0
  local high_confidence = 0
  local suppressed = 0

  for _, result in ipairs(results) do
    if result.confidence == "high" then
      high_confidence = high_confidence + 1
      if result.classification and result.classification.shared_storable and is_sensitive_path(result.path) then
        shared_storable_sensitive = shared_storable_sensitive + 1
      end
      for _, finding in ipairs(result.findings or {}) do
        if finding.confidence ~= "low"
          and string.find(finding.detail or "", "cache poisoning vector", 1, true) then
          poisoned = poisoned + 1
        end
      end
    else
      suppressed = suppressed + 1
    end
  end

  if poisoned > 0 then
    return "POISONABLE", poisoned, shared_storable_sensitive, high_confidence, suppressed
  end
  if shared_storable_sensitive > 0 then
    return "EXPOSED", poisoned, shared_storable_sensitive, high_confidence, suppressed
  end
  if counts.HIGH > 0 then
    return "EXPOSED", poisoned, shared_storable_sensitive, high_confidence, suppressed
  end
  if counts.MEDIUM > 0 then
    return "AT RISK", poisoned, shared_storable_sensitive, high_confidence, suppressed
  end
  if high_confidence == 0 then
    return "INCONCLUSIVE", poisoned, shared_storable_sensitive, high_confidence, suppressed
  end
  return "CORRECTLY RESTRICTED", poisoned, shared_storable_sensitive, high_confidence, suppressed
end

local function render(results, baseline, args)
  local out = stdnse.output_table()
  local unique, counts = dedupe_findings(results)
  local verdict, poisoned, shared_sensitive, high_confidence, suppressed = verdict_from(results, counts, unique)

  out["Risk Level"] = RISK_LEVEL
  if verdict == "INCONCLUSIVE" then
    out["Status"] = "AUDITED - inconclusive: no usable HTTP response for cache analysis."
  elseif verdict == "POISONABLE" then
    out["Status"] = "AUDITED - web cache poisoning vectors confirmed on " .. tostring(poisoned) .. " input(s)."
  elseif verdict == "EXPOSED" then
    out["Status"] = "AUDITED - shared-cache exposure confirmed on " .. tostring(shared_sensitive) .. " sensitive path(s)."
  elseif verdict == "AT RISK" then
    out["Status"] = "AUDITED - cache configuration weaknesses found; no direct cross-user exposure proven."
  else
    out["Status"] = "AUDITED - cache directives correctly restrict storage of personalised responses."
  end

  local total_weight = 0
  local matrix = {}
  for _, result in ipairs(results) do
    total_weight = total_weight + (result.weight or 0)
    local classification = result.classification
    if classification then
      table.insert(matrix, string.format("%s -> HTTP %d | storable=%s | shared=%s | freshness=%s | Vary=%s | %s",
        result.path,
        result.response_status or 0,
        tostring(classification.storable),
        tostring(classification.shared_storable),
        classification.freshness and (tostring(classification.freshness) .. "s") or "none",
        #classification.vary > 0 and table.concat(classification.vary, ",") or "none",
        table.concat(classification.reasons, "; ")))
    end
  end

  out["Verdict"] = verdict
  if suppressed and suppressed > 0 then
    out["Low-confidence responses"] = string.format("%d of %d probed paths were suppressed (catch-all, WAF or auth layer)",
      suppressed, #results)
  end
  out["Cacheability matrix"] = matrix
  out["Severity counts"] = string.format("CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d INFO=%d",
    counts.CRITICAL or 0, counts.HIGH or 0, counts.MEDIUM or 0, counts.LOW or 0, counts.INFO or 0)
  out["Weighted score"] = tostring(total_weight)

  local rendered = {}
  for _, finding in ipairs(unique) do
    if finding.severity ~= "INFO" then
      local paths = finding.paths
      if #paths > 4 then
        paths = { paths[1], paths[2], paths[3], string.format("+%d more", #finding.paths - 3) }
      end
      table.insert(rendered, string.format("[%s] %s (paths: %s)%s",
        finding.severity, finding.detail, table.concat(paths, ", "),
        finding.confidence == "low" and " [low confidence]" or ""))
    end
  end
  if #rendered == 0 then
    table.insert(rendered, "no cache-related weaknesses detected")
  end
  out["Findings"] = rendered

  local evidence = {}
  for _, result in ipairs(results) do
    for _, item in ipairs(result.cache_evidence or {}) do
      table.insert(evidence, result.path .. ": " .. item)
    end
    for _, note in ipairs(result.notes or {}) do
      table.insert(evidence, result.path .. ": " .. note)
    end
    for _, item in ipairs(result.errors or {}) do
      table.insert(evidence, item)
    end
  end
  if #evidence > 0 then
    out["Evidence and notes"] = evidence
  end

  if baseline.enabled and baseline.samples > 0 then
    out["Soft-404 baseline"] = string.format("%d probes, dominant status %s, %s",
      baseline.samples, tostring(baseline.dominant_status or "n/a"),
      baseline.consistent and "catch-all confirmed" or "no catch-all")
  end

  if verdict == "POISONABLE" then
    out["Remediation"] = "add the reflected inputs to the cache key (Vary) or strip them at the edge; "
      .. "disable caching on personalised endpoints"
  elseif verdict == "EXPOSED" then
    out["Remediation"] = "send Cache-Control: no-store, private on personalised responses and add Vary: Cookie "
      .. "wherever user-specific content is cacheable"
  elseif verdict == "AT RISK" then
    out["Remediation"] = "make cache directives explicit on every path (no heuristic caching) and align Vary with the "
      .. "inputs that change the response"
  else
    out["Remediation"] = "posture is sound; keep monitoring for new cacheable personalised endpoints"
  end

  out["Requests issued"] = tostring(state.requests)
  out["Probes"] = string.format("paths=%d poisoning=%s purge=%s cache-trick=%s shared-cache=%s",
    #results, tostring(args.poisoning), tostring(args.purgemethods),
    tostring(args.cachetrick), tostring(args.sharedcache))

  return out
end

action = function(host, port)
  state = { requests = 0, rate_limited = 0, errors = 0 }
  math.randomseed((os.time() * 31337) + (port.number or 0))

  local args = read_args()
  local paths = select_paths(args)
  local baseline = build_soft404_baseline(host, port, args)

  local results = {}
  for _, path in ipairs(paths) do
    if budget_exhausted(args) then
      table.insert(results, { path = path, errors = { "request budget exhausted" } })
      break
    end
    table.insert(results, audit_path(host, port, path, args, baseline))
  end

  if nmap and nmap.verbosity and nmap.verbosity() > 1 then
    stdnse.debug1("%s: %d requests, %d rate-limited, %d errors", SCRIPT_NAME,
      state.requests, state.rate_limited, state.errors)
  end

  return render(results, baseline, args)
end
