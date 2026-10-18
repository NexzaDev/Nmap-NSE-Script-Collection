local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local nmap = require "nmap"

description = [[
Performs a full cookie-security audit of a web service: it collects every
Set-Cookie header the application emits across a set of login, account, API
and error paths, parses each cookie against RFC 6265 / RFC 6265bis, and then
evaluates both the attributes and the values.

Attribute analysis
* Secure: missing on a TLS listener (HIGH), missing on a plain-HTTP listener
  where the same cookie name is also seen over TLS (CRITICAL, split-transport
  session), present but delivered over plain HTTP by the server itself
  (protocol confusion).
* HttpOnly: missing on cookies whose name matches a session, auth, token,
  CSRF or remember-me pattern (script-readable session = XSS to account
  takeover).
* SameSite: absent (browser defaults differ), Lax on a state-changing GET
  endpoint, None without Secure (rejected by browsers or sent cross-site),
  invalid tokens, and None+Secure on a cookie that does not need cross-site
  delivery (CSRF surface).
* Domain: absent (host-only, best), leading-dot scoping to the registrable
  domain, scoping to a public suffix or a parent domain shared with other
  tenants, Domain set to an IP literal or localhost (rejected by browsers),
  and Domain wider than the request host.
* Path: root scope for a session cookie, sibling-application scope, path
  traversal in the value.
* Expires / Max-Age: RFC 1123 parse with two-digit year handling, permanent
  sessions (year > 2100 or Max-Age > 10 years), negative Max-Age (immediate
  deletion, which breaks login flows), both attributes present and
  contradictory, session cookie on a "remember me" name.
* __Host- and __Secure- prefixes: validated per the specification (Secure
  required, no Domain, Path=/) and reported when the prefix is used but the
  requirements are violated, which makes the cookie silently dropped.

Value analysis
* length (browser drop above ~4096 bytes, header-size amplification),
  Shannon entropy per character, base64/hex/JWT detection with header and
  payload decode of JWT cookies (algorithm, expiry, issuer, subject reported
  with the signature redacted), session-id shape validation, detection of
  sequential or predictable identifiers across two consecutive logins,
  plaintext credentials or e-mail addresses stored in the cookie value, and
  detection of values that are identical for two different probe identities.

Transport and behaviour analysis
* TLS/plain split: the same cookie name observed with different attributes on
  the TLS and plain listeners (or with different values) is reported as a
  session-fixation/transport-downgrade indicator.
* Cookie churn: whether the application rotates the session identifier after
  an authenticated-looking request (two requests with different fabricated
  identities), which is the core session-fixation control.
* Total cookie weight: number of cookies and total Cookie header size, which
  is a real availability and cache-key problem above ~8 KB.
* Raw Set-Cookie header syntax errors (missing '=', folded headers, multiple
  cookies in one header, CR/LF inside the value) reported separately because
  they cause inconsistent parsing between browsers and proxies.

Every probe is retried with exponential backoff, counted against a request
budget, delayed to stay polite, and WAF/CDN interstitial responses plus
soft-404 catch-all pages are downgraded to low confidence so that they do not
inflate the finding count. Values are redacted in the output (head + tail)
except for structural metadata, so the report can be attached to a ticket.

Usage:
<code>
nmap -p 80,443 --script http-cookie-flags <target>
nmap -p 443 --script http-cookie-flags \
  --script-args http-cookie-flags.paths="/,/login,/api/v1/me" <target>
nmap -p 80 --script http-cookie-flags \
  --script-args http-cookie-flags.churn=false,http-cookie-flags.maxrequests=60,\
http-cookie-flags.showvalues=true <target>
</code>
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.http

local SCRIPT_NAME = "http-cookie-flags"

local RISK_LEVEL = "🟡 MEDIUM"

local SEVERITY = {
  CRITICAL = 10,
  HIGH = 7,
  MEDIUM = 4,
  LOW = 2,
  INFO = 1,
}

local PROBE_PATHS = {
  "/",
  "/index.html",
  "/login",
  "/signin",
  "/logout",
  "/signout",
  "/register",
  "/signup",
  "/account",
  "/profile",
  "/dashboard",
  "/settings",
  "/admin",
  "/api",
  "/api/v1",
  "/api/v1/me",
  "/api/session",
  "/api/auth/login",
  "/api/auth/session",
  "/graphql",
  "/oauth/authorize",
  "/auth/callback",
  "/cart",
  "/checkout",
  "/search",
  "/nonexistent-nse-cookie-probe",
}

local SESSION_NAME_PATTERNS = {
  "session", "sessionid", "session_id", "sess", "sid", "jsessionid",
  "phpsessid", "aspsessionid", "asp.net_sessionid", "cfid", "cftoken",
  "connect.sid", "laravel_session", "ci_session", "django_session",
  "symfony", "railo_session", "weblogic_session", "saplb_", "ts",
}

local AUTH_NAME_PATTERNS = {
  "auth", "token", "jwt", "access_token", "refresh_token", "id_token",
  "bearer", "api_key", "apikey", "credential", "login", "user", "userid",
  "user_id", "uid", "account", "sso", "oauth", "openid", "saml",
  "remember", "remember_me", "remember-me", "autologin", "persistent",
}

local CSRF_NAME_PATTERNS = {
  "csrf", "csrftoken", "csrf_token", "xsrf", "xsrf-token", "_xsrf",
  "antiforgery", "__requestverificationtoken", "authenticity_token",
}

local TRACKING_NAME_PATTERNS = {
  "_ga", "_gid", "_gat", "_fbp", "_fbc", "_pin_unauth", "_hj", "_hjid",
  "amp", "_uetmsclkid", "_tt_enable_cookie", "_dc_gtm", "optimizely",
  "mixpanel", "amplitude", "segment", "hubspot", "intercom",
  "_clck", "_clsk", "_uetmsclkid", "fr", "tr", "tw", "li_",
}

local PUBLIC_SUFFIXES = {
  "com", "org", "net", "edu", "gov", "mil", "int", "info", "biz", "dev",
  "app", "io", "co", "me", "tv", "cc", "xyz", "cloud", "online", "site",
  "shop", "store", "tech", "space", "website", "fun", "life", "world",
  "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
  "co.nz", "co.za", "com.br", "com.mx", "co.in", "co.jp", "com.cn",
  "com.tr", "com.sg", "com.hk", "co.kr", "com.ar", "com.co", "com.pe",
  "eu", "uk", "de", "fr", "es", "it", "nl", "be", "ch", "at", "se",
  "no", "dk", "fi", "pl", "cz", "gr", "pt", "ie", "ru", "ua", "br",
  "ar", "cl", "mx", "in", "pk", "bd", "id", "th", "vn", "ph", "my",
  "sg", "hk", "tw", "kr", "jp", "cn", "au", "nz", "za", "eg", "ng",
  "ke", "il", "ae", "sa", "qa", "kw", "bh", "om", "jo", "lb", "tr",
}

local SHARED_PLATFORM_SUFFIXES = {
  "github.io", "herokuapp.com", "azurewebsites.net", "cloudfront.net",
  "elasticbeanstalk.com", "s3.amazonaws.com", "firebaseapp.com",
  "appspot.com", "blogspot.com", "wordpress.com", "wixsite.com",
  "netlify.app", "vercel.app", "pages.dev", "workers.dev",
  "ngrok.io", "ngrok.app", "onrender.com", "fly.dev", "railway.app",
  "digitaloceanspaces.com", "storage.googleapis.com", "execute-api.amazonaws.com",
}

local JWT_ALGORITHMS = {
  HS256 = "HMAC using SHA-256",
  HS384 = "HMAC using SHA-384",
  HS512 = "HMAC using SHA-512",
  RS256 = "RSASSA-PKCS1-v1_5 using SHA-256",
  RS384 = "RSASSA-PKCS1-v1_5 using SHA-384",
  RS512 = "RSASSA-PKCS1-v1_5 using SHA-512",
  ES256 = "ECDSA using P-256 and SHA-256",
  ES384 = "ECDSA using P-384 and SHA-384",
  ES512 = "ECDSA using P-521 and SHA-512",
  PS256 = "RSASSA-PSS using SHA-256",
  PS384 = "RSASSA-PSS using SHA-384",
  PS512 = "RSASSA-PSS using SHA-512",
  none = "no digital signature (algorithm confusion risk)",
}

local MONTHS = {
  jan = 1, feb = 2, mar = 3, apr = 4, may = 5, jun = 6,
  jul = 7, aug = 8, sep = 9, oct = 10, nov = 11, dec = 12,
}

local WEEKDAYS = { "mon", "tue", "wed", "thu", "fri", "sat", "sun" }

local WAF_SIGNATURES = {
  "cf-ray", "cloudflare", "attention required", "akamai", "incapsula",
  "x-iinfo", "sucuri", "aws waf", "request blocked", "access denied",
  "web application firewall", "mod_security", "fortiweb", "safeline",
}

local DEFAULT_ARGS = {
  paths = nil,
  maxpaths = 14,
  maxrequests = 80,
  retries = 2,
  timeout = 8000,
  delay = 0.05,
  churn = true,
  showvalues = false,
  soft404 = true,
  entropyfloor = 3.0,
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

local function ends_with(value, suffix)
  if #suffix > #value then
    return false
  end
  return string.sub(value, -#suffix) == suffix
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
    { key = "maxrequests", minimum = 4 },
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

  local entropyfloor = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".entropyfloor"))
  if entropyfloor and entropyfloor >= 0 and entropyfloor <= 8 then
    args.entropyfloor = entropyfloor
  end

  for _, key in ipairs({ "churn", "showvalues", "soft404" }) do
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

local function random_token(length, uppercase)
  local alphabet = uppercase and "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    or "abcdefghijklmnopqrstuvwxyz0123456789"
  local out = {}
  for _ = 1, length do
    table.insert(out, string.sub(alphabet, math.random(1, #alphabet), math.random(1, #alphabet)))
  end
  return table.concat(out)
end

local function redact_value(value)
  if type(value) ~= "string" then
    return tostring(value)
  end
  local length = #value
  if length <= 6 then
    return string.rep("*", length)
  end
  if length <= 14 then
    return string.sub(value, 1, 2) .. string.rep("*", length - 4) .. string.sub(value, -2)
  end
  return string.format("%s%s%s(%d)", string.sub(value, 1, 4),
    string.rep("*", math.min(length - 10, 14)), string.sub(value, -6), length)
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

local function character_classes(value)
  local classes = 0
  if string.find(value, "%d") then classes = classes + 1 end
  if string.find(value, "%l") then classes = classes + 1 end
  if string.find(value, "%u") then classes = classes + 1 end
  if string.find(value, "[^%w]") then classes = classes + 1 end
  return classes
end

local function fnv1a32(value)
  local hash = 2166136261
  for i = 1, #(value or "") do
    hash = (hash ~ string.byte(value, i)) & 0xFFFFFFFF
    hash = (hash * 16777619) & 0xFFFFFFFF
  end
  return string.format("%08x", hash)
end

local BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

local function base64_decode(value)
  if type(value) ~= "string" then
    return nil
  end
  local normalized = string.gsub(value, "[^" .. BASE64_ALPHABET .. "=%-_]", "")
  normalized = string.gsub(normalized, "-", "+")
  normalized = string.gsub(normalized, "_", "/")
  local padding = (4 - (#normalized % 4)) % 4
  normalized = normalized .. string.rep("=", padding)
  if #normalized % 4 ~= 0 then
    return nil
  end

  local lookup = {}
  for i = 1, #BASE64_ALPHABET do
    lookup[string.sub(BASE64_ALPHABET, i, i)] = i - 1
  end

  local out = {}
  for i = 1, #normalized, 4 do
    local quad = string.sub(normalized, i, i + 3)
    local values = {}
    local valid = true
    for j = 1, 4 do
      local char = string.sub(quad, j, j)
      if char == "=" then
        table.insert(values, 0)
      elseif lookup[char] then
        table.insert(values, lookup[char])
      else
        valid = false
        break
      end
    end
    if not valid then
      break
    end
    local triple = values[1] * 262144 + values[2] * 4096 + values[3] * 64 + values[4]
    table.insert(out, string.char(math.floor(triple / 65536) % 256))
    if string.sub(quad, 3, 3) ~= "=" then
      table.insert(out, string.char(math.floor(triple / 256) % 256))
    end
    if string.sub(quad, 4, 4) ~= "=" then
      table.insert(out, string.char(triple % 256))
    end
  end

  local decoded = table.concat(out)
  if #decoded == 0 then
    return nil
  end
  return decoded
end

local function json_string_field(json_text, field)
  if type(json_text) ~= "string" then
    return nil
  end
  local value = string.match(json_text, '"' .. field .. '"%s*:%s*"([^"]*)"')
  if value then
    return value
  end
  local numeric = string.match(json_text, '"' .. field .. '"%s*:%s*(%-?%d+%.?%d*)')
  if numeric then
    return tonumber(numeric)
  end
  if string.find(json_text, '"' .. field .. '"%s*:%s*true') then
    return true
  end
  if string.find(json_text, '"' .. field .. '"%s*:%s*false') then
    return false
  end
  return nil
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
  local default_port = (port.number == 80 and not port.ssl) or (port.number == 443 and port.ssl)
  if default_port then
    return name
  end
  return string.format("%s:%d", name, port.number)
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
  if transfer_encoding and string.find(lower(tostring(transfer_encoding)), "chunked") then
    response.body = dechunk(response.body)
  end

  return response
end

local function raw_request(host, port, method, path, extra_headers, args, body)
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
  table.insert(lines, "User-Agent: " .. (args.useragent or ("Mozilla/5.0 (compatible; " .. SCRIPT_NAME .. ")")))
  table.insert(lines, "Accept: */*")
  table.insert(lines, "Accept-Encoding: identity")
  table.insert(lines, "Connection: close")
  if body then
    table.insert(lines, "Content-Length: " .. tostring(#body))
  end
  for _, pair in ipairs(extra_headers or {}) do
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

  if not data or #data == 0 then
    if not recv_ok then
      state.errors = state.errors + 1
      return nil, "no response bytes"
    end
  end

  return parse_raw_response(data or ""), nil
end

local function http_lib_request(host, port, path, args, extra_headers)
  if budget_exhausted(args) then
    return nil, "request budget exhausted"
  end
  state.requests = state.requests + 1

  local options = { header = {}, no_cache = true, timeout = args.timeout }
  options.header["User-Agent"] = args.useragent or ("Mozilla/5.0 (compatible; " .. SCRIPT_NAME .. ")")
  options.header["Accept"] = "*/*"
  options.header["Accept-Encoding"] = "identity"
  options.header["Connection"] = "close"
  for _, pair in ipairs(extra_headers or {}) do
    options.header[pair[1]] = tostring(pair[2])
  end

  local attempt = 0
  local last_error = nil
  while attempt <= args.retries do
    attempt = attempt + 1
    local ok, response = pcall(http.get, host, port, path, options)
    if ok and type(response) == "table" and response.status then
      if response.status == 429 then
        state.rate_limited = state.rate_limited + 1
        last_error = "HTTP 429 rate limiting"
        sleep(math.min(attempt * 2, 8))
      else
        sleep(args.delay)
        return response, nil
      end
    elseif ok then
      last_error = "malformed HTTP response"
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

local function detect_waf(response)
  for _, line in ipairs(response.rawheader or {}) do
    local lowered = lower(line)
    for _, signature in ipairs(WAF_SIGNATURES) do
      if string.find(lowered, signature, 1, true) then
        return signature
      end
    end
  end
  local body = lower(response.body or "")
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
  local baseline = { enabled = args.soft404, samples = 0, statuses = {}, hashes = {} }
  if not args.soft404 then
    return baseline
  end
  for _ = 1, 2 do
    if budget_exhausted(args) then
      break
    end
    local probe = "/nse-cookie-probe-" .. random_token(12)
    local response = http_lib_request(host, port, probe, args)
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

local function collect_set_cookie_headers(response)
  local values = {}
  for _, line in ipairs(response.rawheader or {}) do
    local name, value = string.match(line, "^([^:]+):%s*(.*)$")
    if name and lower(name) == "set-cookie" then
      table.insert(values, trim(value))
    end
  end
  if #values == 0 and response.header then
    local single = response.header["set-cookie"]
    if type(single) == "table" then
      for _, value in ipairs(single) do
        table.insert(values, value)
      end
    elseif single then
      table.insert(values, single)
    end
  end
  return values
end

local function parse_cookie(raw)
  local cookie = {
    raw = raw,
    attributes = {},
    attribute_order = {},
    flags = {},
    flag_order = {},
    syntax_errors = {},
  }

  local first, rest = string.match(raw or "", "^([^;]*);?(.*)$")
  if not first then
    table.insert(cookie.syntax_errors, "header has no content")
    return cookie
  end

  local name, value = string.match(first, "^%s*([^=]-)%s*=%s*(.*)$")
  if not name then
    name = trim(first)
    value = ""
    table.insert(cookie.syntax_errors, "cookie-pair has no '=' separator")
  end

  cookie.name = trim(name)
  cookie.value = value or ""
  cookie.value_trimmed = trim(cookie.value)

  if #cookie.name == 0 then
    table.insert(cookie.syntax_errors, "empty cookie name")
  end
  if string.find(cookie.name, "[\r\n\t ]") then
    table.insert(cookie.syntax_errors, "cookie name contains whitespace or control characters")
  end
  if string.find(cookie.name, '[%(%)<>%@%,;:\\"/%[%]?={} ]') then
    table.insert(cookie.syntax_errors, "cookie name contains an RFC 6265 separator character")
  end
  if string.find(cookie.value, "[\r\n]") then
    table.insert(cookie.syntax_errors, "cookie value contains CR/LF (header injection risk)")
  end
  if string.find(rest or "", ";%s*[^=;]+%s*=%s*[^;]*;") and string.find(rest or "", "^%s*[^=]-=[^=]*=[^=]*=") then
    table.insert(cookie.syntax_errors, "attribute list contains multiple '=' separators in one token")
  end

  for chunk in string.gmatch(rest or "", "[^;]+") do
    local trimmed_chunk = trim(chunk)
    if #trimmed_chunk > 0 then
      local key, val = string.match(trimmed_chunk, "^([%w%-]+)%s*=%s*(.*)$")
      if key then
        local normalized_key = lower(key)
        cookie.attributes[normalized_key] = trim(val)
        table.insert(cookie.attribute_order, normalized_key)
      else
        local flag = lower(trimmed_chunk)
        cookie.flags[flag] = true
        table.insert(cookie.flag_order, flag)
        if not list_contains({ "secure", "httponly" }, flag) then
          table.insert(cookie.syntax_errors, "unknown valueless attribute '" .. trimmed_chunk .. "'")
        end
      end
    end
  end

  local duplicates = {}
  local seen = {}
  for _, key in ipairs(cookie.attribute_order) do
    if seen[key] then
      duplicates[key] = true
    end
    seen[key] = true
  end
  for key in pairs(duplicates) do
    table.insert(cookie.syntax_errors, "duplicate attribute '" .. key .. "'")
  end

  cookie.secure = cookie.flags["secure"] and true or false
  cookie.httponly = cookie.flags["httponly"] and true or false
  cookie.samesite = cookie.attributes["samesite"]
  cookie.domain = cookie.attributes["domain"]
  cookie.path = cookie.attributes["path"]
  cookie.expires = cookie.attributes["expires"]
  cookie.max_age = cookie.attributes["max-age"]
  cookie.priority = cookie.attributes["priority"]
  cookie.partitioned = cookie.flags["partitioned"] and true or false
  cookie.sameparty = cookie.flags["sameparty"] and true or false

  return cookie
end

local function classify_cookie_name(name)
  local lowered = lower(name)
  local classes = {}

  for _, pattern in ipairs(SESSION_NAME_PATTERNS) do
    if lowered == pattern or string.find(lowered, pattern, 1, true) then
      table.insert(classes, "session")
      break
    end
  end
  for _, pattern in ipairs(AUTH_NAME_PATTERNS) do
    if lowered == pattern or string.find(lowered, pattern, 1, true) then
      table.insert(classes, "auth")
      break
    end
  end
  for _, pattern in ipairs(CSRF_NAME_PATTERNS) do
    if lowered == pattern or string.find(lowered, pattern, 1, true) then
      table.insert(classes, "csrf")
      break
    end
  end
  for _, pattern in ipairs(TRACKING_NAME_PATTERNS) do
    if lowered == pattern or string.find(lowered, pattern, 1, true) then
      table.insert(classes, "tracking")
      break
    end
  end

  local unique = {}
  local out = {}
  for _, item in ipairs(classes) do
    if not unique[item] then
      unique[item] = true
      table.insert(out, item)
    end
  end

  if #out == 0 then
    table.insert(out, "other")
  end

  return out
end

local function prefix_analysis(cookie)
  local result = { prefix = nil, violations = {} }
  local name = cookie.name or ""

  if starts_with(name, "__Host-") then
    result.prefix = "__Host-"
    if not cookie.secure then
      table.insert(result.violations, "__Host- requires the Secure attribute")
    end
    if cookie.domain then
      table.insert(result.violations, "__Host- must not set a Domain attribute")
    end
    if cookie.path and cookie.path ~= "/" then
      table.insert(result.violations, "__Host- requires Path=/")
    end
  elseif starts_with(name, "__Secure-") then
    result.prefix = "__Secure-"
    if not cookie.secure then
      table.insert(result.violations, "__Secure- requires the Secure attribute")
    end
  end

  return result
end

local function registrable_domain(hostname)
  if type(hostname) ~= "string" then
    return nil
  end
  local cleaned = lower(string.gsub(hostname, "^%.", ""))
  if string.match(cleaned, "^%d+%.%d+%.%d+%.%d+$") then
    return cleaned
  end
  for _, suffix in ipairs(SHARED_PLATFORM_SUFFIXES) do
    if ends_with(cleaned, "." .. suffix) then
      local remainder = string.sub(cleaned, 1, #cleaned - #suffix - 1)
      local last_label = string.match(remainder, "([^%.]+)$")
      if last_label then
        return last_label .. "." .. suffix
      end
      return suffix
    end
  end
  local parts = {}
  for label in string.gmatch(cleaned, "[^%.]+") do
    table.insert(parts, label)
  end
  if #parts <= 2 then
    return cleaned
  end
  local last_two = parts[#parts - 1] .. "." .. parts[#parts]
  if list_contains(PUBLIC_SUFFIXES, last_two) and #parts >= 3 then
    return parts[#parts - 2] .. "." .. last_two
  end
  return last_two
end

local function parse_expires(value)
  local result = { valid = false, timestamp = nil, problems = {} }
  if type(value) ~= "string" or #trim(value) == 0 then
    table.insert(result.problems, "Expires present but empty")
    return result
  end

  local trimmed = trim(value)
  local weekday, day, month, year, time, zone = string.match(trimmed,
    "^(%a+),%s+(%d+)%s+(%a+)%s+(%d+)%s+(%d+:%d+:%d+)%s*(%a+[%+%-%d]*)$")
  if not weekday then
    weekday, day, month, year, time = string.match(trimmed,
      "^(%a+),%s+(%d+)%s+(%a+)%s+(%d+)%s+(%d+:%d+:%d+)%s*$")
    zone = nil
  end
  if not weekday then
    day, month, year = string.match(trimmed, "^(%d+)%-(%a+)%-(%d+)")
    time = string.match(trimmed, "(%d+:%d+:%d+)")
  end
  if not weekday then
    weekday, day, month, time, zone, year = string.match(trimmed,
      "^(%a+)%s+(%a+)%s+(%d+)%s+(%d+:%d+:%d+)%s+(%a+)%s+(%d+)$")
  end

  if not (day and month and year) then
    table.insert(result.problems, "Expires '" .. trimmed .. "' does not match any RFC 1123/850/asctime format")
    return result
  end

  local lowered_weekday = weekday and lower(string.sub(weekday, 1, 3)) or nil
  if lowered_weekday and not list_contains(WEEKDAYS, lowered_weekday) then
    table.insert(result.problems, "Expires weekday '" .. tostring(weekday) .. "' is invalid")
  end

  local month_number = MONTHS[lower(string.sub(month, 1, 3))]
  if not month_number then
    table.insert(result.problems, "Expires month '" .. tostring(month) .. "' is invalid")
    return result
  end

  local numeric_year = tonumber(year)
  if not numeric_year then
    table.insert(result.problems, "Expires year '" .. tostring(year) .. "' is invalid")
    return result
  end
  if numeric_year < 100 then
    table.insert(result.problems, "two-digit year in Expires is interpreted inconsistently by clients")
    numeric_year = numeric_year + (numeric_year < 70 and 2000 or 1900)
  end

  local hour, minute, second = 12, 0, 0
  if time then
    hour, minute, second = string.match(time, "^(%d+):(%d+):(%d+)$")
    hour = tonumber(hour) or 12
    minute = tonumber(minute) or 0
    second = tonumber(second) or 0
    if hour > 23 or minute > 59 or second > 60 then
      table.insert(result.problems, "Expires time-of-day is out of range")
    end
  end

  if zone and zone ~= "GMT" and zone ~= "UTC" and not string.match(zone, "^[%+%-]%d%d%d%d$") then
    table.insert(result.problems, "Expires time zone '" .. zone .. "' is not GMT")
  end

  local ok, timestamp = pcall(os.time, {
    year = numeric_year, month = month_number, day = tonumber(day),
    hour = hour, min = minute, sec = second,
  })
  if ok and timestamp then
    result.valid = true
    result.timestamp = timestamp
    result.year = numeric_year
  else
    table.insert(result.problems, "Expires could not be converted to a timestamp")
  end

  return result
end

local function decode_jwt(value)
  local header_b64, payload_b64, signature = string.match(value,
    "^([A-Za-z0-9_%-]+)%.([A-Za-z0-9_%-]+)%.([A-Za-z0-9_%-]*)$")
  if not (header_b64 and payload_b64) then
    return nil
  end

  local header_json = base64_decode(header_b64)
  local payload_json = base64_decode(payload_b64)
  if not header_json or not payload_json then
    return nil
  end
  if not (starts_with(trim(header_json), "{") and starts_with(trim(payload_json), "{")) then
    return nil
  end

  local decoded = {
    header = header_json,
    payload = payload_json,
    algorithm = json_string_field(header_json, "alg"),
    token_type = json_string_field(header_json, "typ"),
    key_id = json_string_field(header_json, "kid"),
    issuer = json_string_field(payload_json, "iss"),
    subject = json_string_field(payload_json, "sub"),
    audience = json_string_field(payload_json, "aud"),
    expires_at = json_string_field(payload_json, "exp"),
    not_before = json_string_field(payload_json, "nbf"),
    issued_at = json_string_field(payload_json, "iat"),
    jwt_id = json_string_field(payload_json, "jti"),
    signature_length = #(signature or ""),
  }

  return decoded
end

local function analyse_cookie_value(cookie, args)
  local value = cookie.value or ""
  local analysis = {
    length = #value,
    entropy = entropy_bits(value),
    classes = character_classes(value),
    encodings = {},
    notes = {},
  }

  if string.match(value, "^eyJ[A-Za-z0-9_%-]+%.eyJ[A-Za-z0-9_%-]+%.[A-Za-z0-9_%-]*$") then
    table.insert(analysis.encodings, "JWT")
    local decoded = decode_jwt(value)
    if decoded then
      analysis.jwt = decoded
    else
      table.insert(analysis.notes, "JWT-shaped value could not be base64-decoded")
    end
  end

  if #value >= 16 and string.match(value, "^[%x]+$") and #value % 2 == 0 then
    table.insert(analysis.encodings, "hex")
  end

  if #value >= 16 and string.match(value, "^[A-Za-z0-9+/]+={0,2}$") then
    local decoded = base64_decode(value)
    if decoded then
      table.insert(analysis.encodings, "base64")
      analysis.decoded_preview = string.gsub(string.sub(decoded, 1, 24), "[\r\n\t]", " ")
      if string.find(decoded, "[\r\n]") then
        table.insert(analysis.notes, "base64-decoded cookie value contains newlines (multi-line state in a cookie)")
      end
      if string.match(decoded, "^{.*}$") then
        table.insert(analysis.notes, "base64-decoded cookie value is JSON (client-side state tampering surface)")
      end
    end
  end

  if string.find(lower(value), "@") and string.match(value, "[%w%.%-_]+@[%w%.%-]+%.[%a][%a]+") then
    table.insert(analysis.encodings, "email")
    table.insert(analysis.notes, "cookie value contains an e-mail address (PII in a cookie)")
  end

  if string.find(lower(value), "password") or string.find(lower(value), "passwd") then
    table.insert(analysis.notes, "cookie value references a password field")
  end

  if string.find(value, "%$2[aby]%$") then
    table.insert(analysis.notes, "cookie value contains a bcrypt hash")
  end

  if string.match(value, "^%d+$") and #value <= 10 then
    table.insert(analysis.encodings, "numeric")
    analysis.numeric = tonumber(value)
  end

  if string.match(value, "^[%w%-_%.]+$") and #value >= 16 then
    table.insert(analysis.encodings, "token-like")
  end

  if analysis.entropy < args.entropyfloor and #value >= 16 and not list_contains(analysis.encodings, "JWT") then
    table.insert(analysis.notes, string.format("low entropy for a %d character identifier (%.2f bits/char)",
      #value, analysis.entropy))
  end

  return analysis
end

local function collect_cookies(host, port, paths, args, baseline)
  local collected = {}
  local per_path = {}
  local suppressed = {}
  local errors = {}
  local syntax_errors = {}

  for _, path in ipairs(paths) do
    if budget_exhausted(args) then
      table.insert(errors, string.format("%s: request budget exhausted", path))
      break
    end

    local response, err = http_lib_request(host, port, path, args)
    if not response then
      table.insert(errors, string.format("%s: %s", path, tostring(err)))
      goto continue_path
    end

    local vendor = detect_waf(response)
    local soft, soft_reason = looks_like_soft404(response, baseline)
    local confidence = "high"
    if vendor then
      confidence = "low"
      table.insert(suppressed, string.format("%s: WAF/CDN interstitial (%s)", path, vendor))
    elseif soft then
      confidence = "low"
      table.insert(suppressed, string.format("%s: soft-404 (%s)", path, tostring(soft_reason)))
    elseif response.status == 401 or response.status == 403 or response.status == 404 then
      confidence = "low"
      table.insert(suppressed, string.format("%s: HTTP %d response (cookie set by an auth/error layer)",
        path, response.status))
    end

    local raw_cookies = collect_set_cookie_headers(response)
    if #raw_cookies == 0 then
      table.insert(per_path, { path = path, status = response.status, cookies = 0, confidence = confidence })
      goto continue_path
    end

    table.insert(per_path, { path = path, status = response.status, cookies = #raw_cookies, confidence = confidence })

    for _, raw in ipairs(raw_cookies) do
      local cookie = parse_cookie(raw)
      cookie.path_seen = path
      cookie.status = response.status
      cookie.confidence = confidence
      cookie.value_analysis = analyse_cookie_value(cookie, args)

      for _, problem in ipairs(cookie.syntax_errors) do
        table.insert(syntax_errors, string.format("%s [%s]: %s", path, cookie.name or "?", problem))
      end

      if string.find(raw, ",%s*[%w%-]+=") and not string.find(lower(raw), "expires=") then
        table.insert(syntax_errors, string.format(
          "%s: a single Set-Cookie header appears to carry multiple cookies (comma separated)", path))
      end

      table.insert(collected, cookie)
    end

    ::continue_path::
  end

  return collected, per_path, suppressed, errors, syntax_errors
end

local function run_churn_test(host, port, path, args, findings)
  if not args.churn then
    return 0
  end

  local weight = 0
  local first_identity = "nse_a_" .. random_token(8)
  local second_identity = "nse_b_" .. random_token(8)

  local first, err1 = raw_request(host, port, "GET", path,
    { { "Cookie", "identity=" .. first_identity }, { "X-NSE-Identity", "first" } }, args)
  local second, err2 = raw_request(host, port, "GET", path,
    { { "Cookie", "identity=" .. second_identity }, { "X-NSE-Identity", "second" } }, args)

  if not (first and second) then
    if err1 and err1 ~= "request budget exhausted" then
      table.insert(findings, {
        severity = "INFO", weight = 0, path = path,
        detail = "session churn probe failed: " .. tostring(err1),
      })
    end
    return weight
  end

  local first_cookies = collect_set_cookie_headers(first)
  local second_cookies = collect_set_cookie_headers(second)

  local first_session = nil
  local second_session = nil
  for _, raw in ipairs(first_cookies) do
    local cookie = parse_cookie(raw)
    for _, class in ipairs(classify_cookie_name(cookie.name or "")) do
      if class == "session" then
        first_session = cookie
      end
    end
  end
  for _, raw in ipairs(second_cookies) do
    local cookie = parse_cookie(raw)
    for _, class in ipairs(classify_cookie_name(cookie.name or "")) do
      if class == "session" then
        second_session = cookie
      end
    end
  end

  if first_session and second_session then
    if first_session.value == second_session.value then
      table.insert(findings, {
        severity = "MEDIUM",
        weight = SEVERITY.MEDIUM,
        path = path,
        detail = string.format("session cookie '%s' is identical for two distinct client identities "
          .. "(%d bytes, entropy %.2f) — the identifier is not per-session random",
          first_session.name, #first_session.value, entropy_bits(first_session.value)),
      })
      weight = weight + SEVERITY.MEDIUM
    else
      table.insert(findings, {
        severity = "INFO",
        weight = SEVERITY.INFO,
        path = path,
        detail = string.format("session cookie '%s' differs between two identities (rotation observed)",
          first_session.name),
      })
    end

    if first_session.value and string.match(first_session.value, "^%d+$")
      and second_session.value and string.match(second_session.value, "^%d+$") then
      local first_number = tonumber(first_session.value)
      local second_number = tonumber(second_session.value)
      if first_number and second_number and math.abs(second_number - first_number) <= 10 then
        table.insert(findings, {
          severity = "HIGH",
          weight = SEVERITY.HIGH,
          path = path,
          detail = string.format("session identifiers are sequential numbers (%d and %d): predictable session ids",
            first_number, second_number),
        })
        weight = weight + SEVERITY.HIGH
      end
    end
  elseif #first_cookies == 0 and #second_cookies == 0 then
    table.insert(findings, {
      severity = "INFO", weight = SEVERITY.INFO, path = path,
      detail = "no cookies were issued for either probe identity on this path",
    })
  end

  local first_body_hash = fnv1a32(first.body or "")
  local second_body_hash = fnv1a32(second.body or "")
  if first_body_hash == second_body_hash and #(first.body or "") > 0 then
    table.insert(findings, {
      severity = "INFO", weight = SEVERITY.INFO, path = path,
      detail = "response body is identical for both identities (endpoint is not personalised)",
    })
  end

  return weight
end

local function evaluate_cookie(cookie, context, findings, args)
  local weight = 0
  local name = cookie.name or ""
  local classes = classify_cookie_name(name)
  cookie.classes = classes
  cookie.is_session = list_contains(classes, "session")
  cookie.is_auth = list_contains(classes, "auth")
  cookie.is_csrf = list_contains(classes, "csrf")
  cookie.is_tracking = list_contains(classes, "tracking")
  local security_relevant = cookie.is_session or cookie.is_auth or cookie.is_csrf
  local low_confidence = cookie.confidence == "low"

  local function add(severity, detail, entry_weight)
    local resolved_weight = entry_weight or SEVERITY[severity]
    if low_confidence then
      resolved_weight = math.max(0, math.floor(resolved_weight / 2))
    end
    table.insert(findings, {
      severity = severity,
      weight = resolved_weight,
      path = cookie.path_seen,
      cookie = name,
      detail = detail .. (low_confidence and " [low confidence]" or ""),
    })
    return resolved_weight
  end

  for _, problem in ipairs(cookie.syntax_errors) do
    weight = weight + add("LOW", string.format("Set-Cookie syntax problem: %s", problem), SEVERITY.LOW)
  end

  if not cookie.secure then
    if context.tls then
      local severity = security_relevant and "CRITICAL" or "MEDIUM"
      weight = weight + add(severity,
        string.format("cookie '%s' is set without Secure on a TLS listener%s", name,
          security_relevant and " (session/auth cookie can be captured on any plain-HTTP request)" or ""),
        security_relevant and SEVERITY.CRITICAL or SEVERITY.MEDIUM)
    else
      weight = weight + add("MEDIUM",
        string.format("cookie '%s' is set without Secure over plain HTTP", name), SEVERITY.MEDIUM)
    end
  elseif not context.tls then
    weight = weight + add("MEDIUM",
      string.format("cookie '%s' is marked Secure but was served over plain HTTP (browser will drop it; "
        .. "indicates a mixed-transport deployment)", name), SEVERITY.MEDIUM)
  end

  if not cookie.httponly and (cookie.is_session or cookie.is_auth) then
    weight = weight + add("HIGH",
      string.format("session/auth cookie '%s' is readable by JavaScript (no HttpOnly)", name), SEVERITY.HIGH)
  elseif not cookie.httponly and cookie.is_csrf then
    weight = weight + add("MEDIUM",
      string.format("CSRF cookie '%s' without HttpOnly (double-submit patterns need it readable; "
        .. "verify it is not also the session)", name), SEVERITY.MEDIUM)
  end

  local samesite = cookie.samesite
  if not samesite then
    if security_relevant then
      weight = weight + add("HIGH",
        string.format("cookie '%s' has no SameSite attribute; cross-site requests will carry it "
          .. "(CSRF exposure)", name), SEVERITY.HIGH)
    else
      weight = weight + add("LOW",
        string.format("cookie '%s' has no SameSite attribute", name), SEVERITY.LOW)
    end
  else
    local normalized = lower(samesite)
    if normalized == "none" then
      if not cookie.secure then
        weight = weight + add("HIGH",
          string.format("cookie '%s' uses SameSite=None without Secure; browsers reject it or send it cross-site",
            name), SEVERITY.HIGH)
      elseif not security_relevant then
        weight = weight + add("LOW",
          string.format("cookie '%s' opts into cross-site delivery (SameSite=None) without an obvious need",
            name), SEVERITY.LOW)
      else
        weight = weight + add("MEDIUM",
          string.format("cookie '%s' is sent cross-site (SameSite=None); confirm the CSRF defence is not "
            .. "cookie-based only", name), SEVERITY.MEDIUM)
      end
    elseif normalized == "lax" then
      if cookie.is_session then
        weight = weight + add("LOW",
          string.format("session cookie '%s' uses SameSite=Lax; top-level GET navigations still carry it "
            .. "(login-CSRF and leakage through <img>/link prefetch is blocked, GET side effects are not)",
            name), SEVERITY.LOW)
      end
    elseif normalized == "strict" then
      weight = weight + add("INFO",
        string.format("cookie '%s' uses SameSite=Strict (strongest setting)", name), SEVERITY.INFO)
    else
      weight = weight + add("MEDIUM",
        string.format("cookie '%s' has an invalid SameSite token '%s'", name, samesite), SEVERITY.MEDIUM)
    end
  end

  local prefix_result = prefix_analysis(cookie)
  cookie.prefix = prefix_result.prefix
  if prefix_result.prefix then
    if #prefix_result.violations > 0 then
      for _, violation in ipairs(prefix_result.violations) do
        weight = weight + add("HIGH", string.format("cookie '%s': %s — browsers will drop the cookie",
          name, violation), SEVERITY.HIGH)
      end
    else
      weight = weight + add("INFO",
        string.format("cookie '%s' correctly satisfies the %s prefix requirements", name, prefix_result.prefix),
        SEVERITY.INFO)
    end
  end

  if cookie.domain then
    local domain = lower(cookie.domain)
    local cleaned = string.gsub(domain, "^%.", "")
    local host_name = lower(context.hostname)

    if string.match(cleaned, "^%d+%.%d+%.%d+%.%d+$") or cleaned == "localhost" then
      weight = weight + add("MEDIUM",
        string.format("cookie '%s' sets Domain=%s (an IP literal or localhost is rejected by browsers)",
          name, cookie.domain), SEVERITY.MEDIUM)
    end

    local suffix = registrable_domain(cleaned)
    local host_suffix = registrable_domain(host_name)
    if suffix and host_suffix and suffix ~= host_suffix then
      weight = weight + add("CRITICAL",
        string.format("cookie '%s' sets Domain=%s which is outside the request host's registrable domain (%s)",
          name, cookie.domain, host_suffix), SEVERITY.CRITICAL)
    elseif suffix and cleaned == suffix and #string.gsub(host_name, "^[^%.]+%.", "") > 0 then
      local host_labels = select(2, string.gsub(host_name, "%.", ""))
      local domain_labels = select(2, string.gsub(cleaned, "%.", ""))
      if host_labels > domain_labels then
        weight = weight + add("LOW",
          string.format("cookie '%s' scopes to the registrable domain %s, exposing it to every subdomain "
            .. "(%d label levels above the request host)", name, cleaned, host_labels - domain_labels),
          SEVERITY.LOW)
      end
    end

    for _, suffix_entry in ipairs(SHARED_PLATFORM_SUFFIXES) do
      if cleaned == suffix_entry then
        weight = weight + add("HIGH",
          string.format("cookie '%s' sets Domain=%s which is a shared public suffix; browsers reject it and "
            .. "it signals a misconfiguration", name, cookie.domain), SEVERITY.HIGH)
      end
    end

    if not starts_with(domain, ".") and domain ~= cleaned then
      weight = weight + add("INFO",
        string.format("cookie '%s' Domain has unexpected formatting", name), SEVERITY.INFO)
    end
  elseif security_relevant then
    weight = weight + add("INFO",
      string.format("cookie '%s' is host-only (no Domain attribute) — recommended", name), SEVERITY.INFO)
  end

  if cookie.path then
    if cookie.path ~= "/" and security_relevant then
      weight = weight + add("LOW",
        string.format("cookie '%s' restricts Path=%s; sibling applications on the same host cannot use it "
          .. "and path-scoped sessions are prone to fixation when the app moves", name, cookie.path),
        SEVERITY.LOW)
    end
    if string.find(cookie.path, "%.%.", 1, true) then
      weight = weight + add("LOW",
        string.format("cookie '%s' Path contains traversal sequences (%s)", name, cookie.path), SEVERITY.LOW)
    end
    if not starts_with(cookie.path, "/") then
      weight = weight + add("LOW",
        string.format("cookie '%s' Path='%s' is not absolute; clients derive it from the request URI",
          name, cookie.path), SEVERITY.LOW)
    end
  end

  if cookie.expires or cookie.max_age then
    local expires_result = cookie.expires and parse_expires(cookie.expires) or nil
    if expires_result then
      for _, problem in ipairs(expires_result.problems) do
        weight = weight + add("LOW", string.format("cookie '%s': %s", name, problem), SEVERITY.LOW)
      end
      if expires_result.valid and expires_result.timestamp then
        local lifetime = expires_result.timestamp - os.time()
        cookie.lifetime_seconds = lifetime
        if lifetime > 0 and lifetime > 315360000 then
          weight = weight + add("MEDIUM",
            string.format("cookie '%s' expires in %.1f years (permanent session on a security-relevant cookie)",
              name, lifetime / 31536000), SEVERITY.MEDIUM)
        elseif lifetime > 0 and lifetime > 2592000 and security_relevant then
          weight = weight + add("LOW",
            string.format("cookie '%s' lifetime is %d days; shorter session lifetimes reduce the replay window",
              name, math.floor(lifetime / 86400)), SEVERITY.LOW)
        elseif lifetime <= 0 then
          weight = weight + add("LOW",
            string.format("cookie '%s' Expires is in the past — the cookie is being deleted", name), SEVERITY.LOW)
        end
        if expires_result.year and expires_result.year > 2100 then
          weight = weight + add("LOW",
            string.format("cookie '%s' Expires year %d is effectively permanent", name, expires_result.year),
            SEVERITY.LOW)
        end
      end
    end

    if cookie.max_age then
      local max_age = tonumber(cookie.max_age)
      if not max_age then
        weight = weight + add("LOW",
          string.format("cookie '%s' Max-Age='%s' is not an integer", name, cookie.max_age), SEVERITY.LOW)
      else
        cookie.max_age_seconds = max_age
        if max_age < 0 then
          weight = weight + add("LOW",
            string.format("cookie '%s' Max-Age=%d deletes the cookie immediately", name, max_age), SEVERITY.LOW)
        elseif max_age > 315360000 then
          weight = weight + add("MEDIUM",
            string.format("cookie '%s' Max-Age=%d is more than ten years", name, max_age), SEVERITY.MEDIUM)
        elseif max_age == 0 then
          weight = weight + add("INFO",
            string.format("cookie '%s' Max-Age=0 removes the cookie", name), SEVERITY.INFO)
        end
        if cookie.expires and expires_result and expires_result.valid then
          local expires_delta = expires_result.timestamp - os.time()
          if max_age > 0 and expires_delta > 0 and math.abs(expires_delta - max_age) > 86400 then
            weight = weight + add("LOW",
              string.format("cookie '%s' Max-Age (%d s) and Expires (%d s from now) disagree; "
                .. "Max-Age wins in modern browsers", name, max_age, expires_delta), SEVERITY.LOW)
          end
        end
      end
    end

    if cookie.expires and not cookie.max_age then
      weight = weight + add("INFO",
        string.format("cookie '%s' uses Expires without Max-Age (HTTP/1.0 style; prefer Max-Age)", name),
        SEVERITY.INFO)
    end
  else
    if cookie.is_session or string.find(lower(name), "remember", 1, true) then
      weight = weight + add("INFO",
        string.format("cookie '%s' is a session cookie (deleted when the browser closes)", name), SEVERITY.INFO)
    end
  end

  local analysis = cookie.value_analysis
  if analysis then
    if analysis.length > 4096 then
      weight = weight + add("MEDIUM",
        string.format("cookie '%s' value is %d bytes; browsers drop cookies above ~4096 bytes",
          name, analysis.length), SEVERITY.MEDIUM)
    elseif analysis.length > 2048 then
      weight = weight + add("LOW",
        string.format("cookie '%s' value is %d bytes (header-size amplification on every request)",
          name, analysis.length), SEVERITY.LOW)
    end

    if analysis.length == 0 then
      weight = weight + add("INFO",
        string.format("cookie '%s' is set with an empty value", name), SEVERITY.INFO)
    end

    if analysis.length >= 16 and analysis.entropy < 2.0 then
      weight = weight + add("HIGH",
        string.format("cookie '%s' value has very low entropy (%.2f bits/char over %d characters): "
          .. "guessable identifier", name, analysis.entropy, analysis.length), SEVERITY.HIGH)
    elseif security_relevant and analysis.length >= 16 and analysis.entropy < args.entropyfloor then
      weight = weight + add("MEDIUM",
        string.format("cookie '%s' value entropy is %.2f bits/char (below %.2f) for a %d character session/auth id",
          name, analysis.entropy, args.entropyfloor, analysis.length), SEVERITY.MEDIUM)
    end

    if security_relevant and analysis.length < 16 then
      weight = weight + add("MEDIUM",
        string.format("cookie '%s' value is only %d characters; short identifiers are brute-forceable",
          name, analysis.length), SEVERITY.MEDIUM)
    end

    for _, note in ipairs(analysis.notes) do
      local severity = "LOW"
      local entry_weight = SEVERITY.LOW
      if string.find(note, "JSON") or string.find(note, "PII") or string.find(note, "password") then
        severity = "MEDIUM"
        entry_weight = SEVERITY.MEDIUM
      end
      weight = weight + add(severity, string.format("cookie '%s': %s", name, note), entry_weight)
    end

    if analysis.jwt then
      local jwt = analysis.jwt
      local algorithm = jwt.algorithm or "unknown"
      if lower(algorithm) == "none" then
        weight = weight + add("CRITICAL",
          string.format("cookie '%s' holds a JWT with alg=none (unsigned token accepted client-side)", name),
          SEVERITY.CRITICAL)
      elseif starts_with(lower(algorithm), "hs") then
        weight = weight + add("MEDIUM",
          string.format("cookie '%s' holds a symmetric JWT (%s); a leaked secret allows forging tokens",
            name, algorithm), SEVERITY.MEDIUM)
      end
      if jwt.expires_at and type(jwt.expires_at) == "number" then
        local lifetime = jwt.expires_at - os.time()
        if lifetime > 86400 * 7 then
          weight = weight + add("MEDIUM",
            string.format("cookie '%s' JWT lifetime is %d days", name, math.floor(lifetime / 86400)),
            SEVERITY.MEDIUM)
        elseif lifetime < 0 then
          weight = weight + add("LOW",
            string.format("cookie '%s' holds an expired JWT (exp %d)", name, jwt.expires_at), SEVERITY.LOW)
        end
      end
      if not jwt.expires_at then
        weight = weight + add("MEDIUM",
          string.format("cookie '%s' JWT has no exp claim (token never expires)", name), SEVERITY.MEDIUM)
      end
      local payload_preview = string.gsub(string.sub(jwt.payload or "", 1, 120), "[\r\n\t]", " ")
      cookie.jwt_summary = string.format("alg=%s typ=%s iss=%s sub=%s exp=%s payload=%.60s",
        tostring(jwt.algorithm), tostring(jwt.token_type), tostring(jwt.issuer),
        tostring(jwt.subject), tostring(jwt.expires_at), payload_preview)
    end
  end

  if cookie.partitioned then
    weight = weight + add("INFO",
      string.format("cookie '%s' is partitioned (CHIPS)", name), SEVERITY.INFO)
  end
  if cookie.sameparty then
    weight = weight + add("INFO",
      string.format("cookie '%s' uses the deprecated SameParty attribute", name), SEVERITY.INFO)
  end
  if cookie.priority then
    weight = weight + add("INFO",
      string.format("cookie '%s' sets Priority=%s (non-standard eviction hint)", name, cookie.priority),
      SEVERITY.INFO)
  end

  cookie.weight = weight
  return weight
end

local function cross_transport_analysis(cookies, context, findings)
  local by_name = {}
  for _, cookie in ipairs(cookies) do
    local key = lower(cookie.name or "")
    by_name[key] = by_name[key] or {}
    table.insert(by_name[key], cookie)
  end

  local weight = 0
  for _, name in ipairs(sorted_keys(by_name)) do
    local entries = by_name[name]
    if #entries > 1 then
      local secure_seen = false
      local insecure_seen = false
      local values = {}
      local attributes = {}
      for _, cookie in ipairs(entries) do
        if cookie.secure then
          secure_seen = true
        else
          insecure_seen = true
        end
        values[cookie.value or ""] = true
        local signature = string.format("secure=%s httponly=%s samesite=%s domain=%s path=%s",
          tostring(cookie.secure), tostring(cookie.httponly), tostring(cookie.samesite),
          tostring(cookie.domain), tostring(cookie.path))
        attributes[signature] = (attributes[signature] or 0) + 1
      end

      if secure_seen and insecure_seen then
        table.insert(findings, {
          severity = "CRITICAL",
          weight = SEVERITY.CRITICAL,
          path = "(cross-transport)",
          cookie = name,
          detail = string.format("cookie '%s' is set with Secure on some responses and without Secure on others "
            .. "(split-transport session hijacking)", name),
        })
        weight = weight + SEVERITY.CRITICAL
      end

      local distinct_values = table_size(values)
      if distinct_values > 1 and #entries > 1 then
        table.insert(findings, {
          severity = "LOW",
          weight = SEVERITY.LOW,
          path = "(cross-path)",
          cookie = name,
          detail = string.format("cookie '%s' is re-issued with %d different values across paths (rotation or "
            .. "conflicting issuers)", name, distinct_values),
        })
        weight = weight + SEVERITY.LOW
      end

      if table_size(attributes) > 1 then
        local signatures = {}
        for signature in pairs(attributes) do
          table.insert(signatures, signature)
        end
        table.sort(signatures)
        table.insert(findings, {
          severity = "MEDIUM",
          weight = SEVERITY.MEDIUM,
          path = "(cross-path)",
          cookie = name,
          detail = string.format("cookie '%s' is issued with inconsistent attributes: %s",
            name, table.concat(signatures, " || ")),
        })
        weight = weight + SEVERITY.MEDIUM
      end
    end
  end

  return weight
end

local function summarise_cookies(cookies, args)
  local groups = {}
  local group_order = {}
  local total_bytes = 0
  local by_class = { session = 0, auth = 0, csrf = 0, tracking = 0, other = 0 }
  local seen_names = {}
  local worst_bytes = {}

  for _, cookie in ipairs(cookies) do
    local name = cookie.name or "?"
    if not seen_names[name] then
      seen_names[name] = true
      for _, class in ipairs(cookie.classes or { "other" }) do
        by_class[class] = (by_class[class] or 0) + 1
      end
    end

    total_bytes = total_bytes + #name + #(cookie.value or "") + 4
    if not worst_bytes[name] or #(cookie.value or "") > worst_bytes[name] then
      worst_bytes[name] = #(cookie.value or "")
    end

    local signature = string.format("%s|%s|%s|%s|%s|%s|%s",
      name, table.concat(cookie.classes or {}, "/"),
      tostring(cookie.secure), tostring(cookie.httponly),
      tostring(cookie.samesite or "-"), tostring(cookie.domain or "host-only"),
      tostring(cookie.path or "-"))

    if not groups[signature] then
      groups[signature] = {
        name = name,
        classes = table.concat(cookie.classes or {}, "/"),
        secure = cookie.secure,
        httponly = cookie.httponly,
        samesite = cookie.samesite,
        domain = cookie.domain,
        path = cookie.path,
        lifetime = cookie.max_age_seconds
          or cookie.lifetime_seconds or "session",
        occurrences = 0,
        paths = {},
        value = cookie.value,
        jwt_summary = cookie.jwt_summary,
        entropy = cookie.value_analysis and cookie.value_analysis.entropy or 0,
      }
      table.insert(group_order, signature)
    end

    local group = groups[signature]
    group.occurrences = group.occurrences + 1
    if not list_contains(group.paths, cookie.path_seen or "?") then
      table.insert(group.paths, cookie.path_seen or "?")
    end
    if cookie.jwt_summary then
      group.jwt_summary = cookie.jwt_summary
    end
  end

  table.sort(group_order)
  local summary = {}
  for _, signature in ipairs(group_order) do
    local group = groups[signature]
    local lifetime = group.lifetime
    if type(lifetime) == "number" then
      lifetime = string.format("%ds", math.floor(lifetime))
    end
    local paths = group.paths
    if #paths > 3 then
      paths = { paths[1], paths[2], string.format("+%d paths", #group.paths - 2) }
    end
    local value = args.showvalues and (group.value or "") or redact_value(group.value or "")
    table.insert(summary, string.format(
      "%s=%s [%s] Secure=%s HttpOnly=%s SameSite=%s Domain=%s Path=%s Lifetime=%s "
      .. "len=%d entropy=%.2f x%d (%s)",
      group.name, value, group.classes,
      tostring(group.secure), tostring(group.httponly),
      tostring(group.samesite or "-"), tostring(group.domain or "host-only"),
      tostring(group.path or "-"), tostring(lifetime),
      worst_bytes[group.name] or 0, group.entropy, group.occurrences,
      table.concat(paths, ", ")))
    if group.jwt_summary then
      table.insert(summary, "    JWT: " .. group.jwt_summary)
    end
  end

  return summary, total_bytes, by_class, table_size(seen_names)
end

local function render(cookies, per_path, suppressed, errors, syntax_errors, findings, context, args)
  local out = stdnse.output_table()
  local counts = { CRITICAL = 0, HIGH = 0, MEDIUM = 0, LOW = 0, INFO = 0 }

  local unique = {}
  local index = {}
  for _, finding in ipairs(findings) do
    local key = tostring(finding.cookie or "-") .. "|" .. finding.severity .. "|" .. finding.detail
    if not index[key] then
      index[key] = {
        severity = finding.severity,
        weight = finding.weight,
        cookie = finding.cookie or "-",
        detail = finding.detail,
        paths = {},
      }
      table.insert(unique, index[key])
    end
    if not list_contains(index[key].paths, finding.path or "?") then
      table.insert(index[key].paths, finding.path or "?")
    end
    counts[finding.severity] = (counts[finding.severity] or 0) + 1
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
    return tostring(a.cookie) < tostring(b.cookie)
  end)

  local total_weight = 0
  for _, finding in ipairs(unique) do
    total_weight = total_weight + (finding.weight or 0)
  end

  local summary, total_bytes, by_class, distinct_names = summarise_cookies(cookies, args)

  out["Risk Level"] = RISK_LEVEL
  if #cookies == 0 then
    out["Status"] = "AUDITED - the service did not set any cookies on the probed paths."
  elseif counts.CRITICAL > 0 then
    out["Status"] = "AUDITED - critical cookie weaknesses confirmed; sessions are exposed to interception or forgery."
  elseif counts.HIGH > 0 then
    out["Status"] = "AUDITED - high severity cookie weaknesses confirmed."
  elseif counts.MEDIUM > 0 then
    out["Status"] = "AUDITED - cookie hygiene weaknesses found."
  elseif counts.LOW > 0 then
    out["Status"] = "AUDITED - minor cookie hardening opportunities found."
  else
    out["Status"] = "AUDITED - cookie attributes follow current best practice."
  end

  out["Transport"] = context.tls and "HTTPS" or "HTTP"
  out["Cookies observed"] = string.format("%d Set-Cookie headers, %d distinct names, %d bytes of Cookie payload",
    #cookies, distinct_names, total_bytes)
  out["Cookie classes"] = string.format("session=%d auth=%d csrf=%d tracking=%d other=%d",
    by_class.session or 0, by_class.auth or 0, by_class.csrf or 0,
    by_class.tracking or 0, by_class.other or 0)

  local path_lines = {}
  for _, entry in ipairs(per_path) do
    table.insert(path_lines, string.format("%s -> HTTP %s | %d cookie(s)%s",
      entry.path, tostring(entry.status), entry.cookies,
      entry.confidence == "low" and " [low confidence]" or ""))
  end
  if #path_lines > 0 then
    out["Paths probed"] = path_lines
  end

  if #summary > 0 then
    out["Cookie inventory"] = summary
  end

  local rendered = {}
  for _, finding in ipairs(unique) do
    if finding.severity ~= "INFO" then
      local paths = finding.paths
      if #paths > 3 then
        paths = { paths[1], paths[2], string.format("+%d more", #finding.paths - 2) }
      end
      table.insert(rendered, string.format("[%s] %s — %s (seen on %s)",
        finding.severity, tostring(finding.cookie or "?"), finding.detail, table.concat(paths, ", ")))
    end
  end
  if #rendered == 0 then
    table.insert(rendered, "no cookie weaknesses detected")
  end
  out["Findings"] = rendered

  if total_bytes > 8192 then
    out["Header weight"] = string.format(
      "total Cookie payload is %d bytes: above the ~8 KB limit several proxies and CDNs enforce", total_bytes)
  end

  out["Severity counts"] = string.format("CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d INFO=%d",
    counts.CRITICAL, counts.HIGH, counts.MEDIUM, counts.LOW, counts.INFO)
  out["Weighted score"] = tostring(total_weight)

  if #syntax_errors > 0 then
    local unique_syntax = {}
    local seen = {}
    for _, item in ipairs(syntax_errors) do
      if not seen[item] then
        seen[item] = true
        table.insert(unique_syntax, item)
      end
    end
    out["Set-Cookie syntax problems"] = unique_syntax
  end

  if #suppressed > 0 then
    out["Suppressed / low confidence"] = suppressed
  end

  if #errors > 0 then
    out["Probe errors"] = errors
  end

  if counts.CRITICAL > 0 then
    out["Remediation"] = "mark every session/auth cookie Secure + HttpOnly + SameSite=Lax|Strict, scope Domain to the "
      .. "exact host and rotate identifiers after authentication"
  elseif counts.HIGH > 0 then
    out["Remediation"] = "add HttpOnly to session cookies, set SameSite explicitly and fix __Host-/__Secure- prefix "
      .. "violations so browsers accept the hardened cookie"
  elseif counts.MEDIUM > 0 then
    out["Remediation"] = "align cookie lifetimes with the session model, use Max-Age instead of Expires and keep "
      .. "identifiers at >= 128 bits of entropy"
  else
    out["Remediation"] = "posture is solid; re-check after framework upgrades because defaults change"
  end

  out["Requests issued"] = tostring(state.requests)

  return out
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
    for _, path in ipairs(PROBE_PATHS) do
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

action = function(host, port)
  state = { requests = 0, rate_limited = 0, errors = 0 }
  math.randomseed((os.time() * 65537) + (port.number or 0))

  local args = read_args()
  local paths = select_paths(args)
  local context = {
    tls = port.ssl or (port.version and port.version.service_ssl) or false,
    hostname = host.targetname or host.name or host.ip or "",
  }

  local baseline = build_soft404_baseline(host, port, args)
  local cookies, per_path, suppressed, errors, syntax_errors = collect_cookies(host, port, paths, args, baseline)

  local findings = {}
  local weight = 0
  for _, cookie in ipairs(cookies) do
    weight = weight + evaluate_cookie(cookie, context, findings, args)
  end
  weight = weight + cross_transport_analysis(cookies, context, findings)

  for _, path in ipairs(paths) do
    if budget_exhausted(args) then
      table.insert(errors, string.format("%s: churn probe skipped (budget exhausted)", path))
      break
    end
    if list_contains({ "/login", "/signin", "/api/auth/login", "/", "/api/session" }, path) then
      weight = weight + run_churn_test(host, port, path, args, findings)
    end
  end

  if nmap and nmap.verbosity and nmap.verbosity() > 1 then
    stdnse.debug1("%s: %d requests, %d cookies, %d findings", SCRIPT_NAME,
      state.requests, #cookies, #findings)
  end

  return render(cookies, per_path, suppressed, errors, syntax_errors, findings, context, args)
end
