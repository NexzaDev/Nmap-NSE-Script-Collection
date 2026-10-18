local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local nmap = require "nmap"
local url = require "url"

description = [[
Performs a deep, evidence-based audit of the HTTP security header posture of a
web service instead of a simple presence check.

The script fetches a configurable set of application paths (login, account,
API, admin, static asset and error paths) and, for every response, evaluates:

* Strict-Transport-Security: parses max-age, includeSubDomains, preload,
  rejects negative/huge/quoted values, verifies the header only appears on
  TLS responses (RFC 6797 section 7.2 forbids honouring it over plain HTTP).
* Content-Security-Policy: full directive level parsing with source-list
  validation, wildcard and scheme-source detection, unsafe-inline /
  unsafe-eval / strict-dynamic / unsafe-hashes detection, nonce and hash
  presence, report-uri / report-to validation, frame-ancestors vs
  X-Frame-Options conflicts, plugin/object restrictions, base-uri and
  form-action coverage, deprecated directives and CSP Level 1 fallbacks.
* Content-Security-Policy-Report-Only: verifies that a report endpoint is
  configured, otherwise the policy is inert.
* X-Frame-Options / X-Content-Type-Options / Referrer-Policy /
  Permissions-Policy / Feature-Policy: value whitelisting against the
  published specification grammars with per-token validation.
* Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy,
  Cross-Origin-Resource-Policy, Cross-Origin-Opener-Policy-Report-Only:
  enumerates the valid token sets and flags experimental values.
* NEL (Network Error Logging) and Reporting-API: parses the JSON payloads,
  validates endpoints, group names and expiry windows.
* Server / X-Powered-By / X-AspNet-Version / X-AspNetMvc-Version /
  X-Generator / X-Runtime / X-Drupal-Cache / X-Varnish / Via / X-Proxy-*:
  detects stack and version disclosure that defeats header hardening.
* Cookie hygiene that interacts with the headers above: Set-Cookie missing
  Secure on a TLS listener, missing HttpOnly on session-looking cookies and
  missing/None SameSite without Secure.
* Cache exposure of authenticated responses (Cache-Control public, missing
  no-store, Vary missing Cookie) which silently defeats header protection
  through shared caches.
* Cross-path consistency: a header that is present on the landing page but
  missing on /login or /api is reported separately because it is the most
  common real-world breakage pattern (reverse proxy vs. origin routing).
* Redirect handling: 3xx responses are followed and re-evaluated so that a
  Location header pointing to plain HTTP is reported as an HSTS downgrade.

Every finding carries a severity weight; the aggregated score is mapped onto
the risk scale used by this collection and the raw evidence (path, header,
value, rule that fired) is returned so results can be triaged without
re-running the scan.

False-positive suppression is built in: error pages served by the web server
itself, WAF interstitials, responses with empty bodies and 401/403 answers are
tagged as low-confidence, and any header observed on fewer than two paths is
reported as "inconsistent" rather than "missing".

Usage:
<code>
nmap -p 80,443 --script http-security-headers <target>
nmap -p 443 --script http-security-headers \
  --script-args http-security-headers.paths="/,/login,/api/v1/me" <target>
nmap -p 80 --script http-security-headers \
  --script-args http-security-headers.maxpaths=6,http-security-headers.minhsts=31536000 \
  <target>
</code>
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.http

local SCRIPT_NAME = "http-security-headers"

local SEVERITY = {
  CRITICAL = 10,
  HIGH = 7,
  MEDIUM = 4,
  LOW = 2,
  INFO = 1,
}

local RISK_LEVEL = "🟡 MEDIUM"

local STATUS_LINE = "AUDITED - HTTP security header posture evaluated across all reachable paths."

local DEFAULT_PATHS = {
  "/",
  "/index.html",
  "/login",
  "/signin",
  "/logout",
  "/account",
  "/profile",
  "/dashboard",
  "/admin",
  "/api",
  "/api/v1",
  "/api/v1/me",
  "/api/health",
  "/graphql",
  "/oauth/authorize",
  "/auth/callback",
  "/settings",
  "/search",
  "/static/js/app.js",
  "/favicon.ico",
  "/assets/logo.png",
  "/nonexistent-nse-probe-404",
}

local SENSITIVE_PATH_PATTERNS = {
  "login", "signin", "auth", "oauth", "sso", "account", "profile",
  "dashboard", "admin", "settings", "payment", "billing", "checkout",
  "api", "graphql", "internal", "console", "manage",
}

local STATIC_PATH_PATTERNS = {
  "%.js$", "%.css$", "%.png$", "%.jpe?g$", "%.gif$", "%.svg$",
  "%.woff2?$", "%.ttf$", "%.ico$", "%.map$", "%.webp$",
}

local CSP_FETCH_DIRECTIVES = {
  "default-src", "script-src", "script-src-elem", "script-src-attr",
  "style-src", "style-src-elem", "style-src-attr", "img-src", "font-src",
  "connect-src", "media-src", "object-src", "frame-src", "child-src",
  "worker-src", "manifest-src", "prefetch-src",
}

local CSP_DOCUMENT_DIRECTIVES = {
  "base-uri", "form-action", "frame-ancestors", "navigate-to",
  "sandbox", "plugin-types",
}

local CSP_OTHER_DIRECTIVES = {
  "report-uri", "report-to", "require-trusted-types-for",
  "trusted-types", "upgrade-insecure-requests", "block-all-mixed-content",
}

local CSP_ALL_KNOWN_DIRECTIVES = {}
for _, name in ipairs(CSP_FETCH_DIRECTIVES) do
  CSP_ALL_KNOWN_DIRECTIVES[name] = "fetch"
end
for _, name in ipairs(CSP_DOCUMENT_DIRECTIVES) do
  CSP_ALL_KNOWN_DIRECTIVES[name] = "document"
end
for _, name in ipairs(CSP_OTHER_DIRECTIVES) do
  CSP_ALL_KNOWN_DIRECTIVES[name] = "other"
end

local CSP_DEPRECATED_DIRECTIVES = {
  "block-all-mixed-content", "referrer", "require-sri-for",
  "plugin-types", "navigate-to",
}

local CSP_DANGEROUS_SOURCES = {
  { token = "'unsafe-inline'", weight = SEVERITY.HIGH,
    note = "permits inline <script>/<style>, negating most XSS protection" },
  { token = "'unsafe-eval'", weight = SEVERITY.HIGH,
    note = "permits eval()/new Function(), enabling dynamic code execution" },
  { token = "'unsafe-hashes'", weight = SEVERITY.MEDIUM,
    note = "allows hash based matching for inline event handlers" },
  { token = "'strict-dynamic'", weight = SEVERITY.LOW,
    note = "trust propagation; safe only together with nonces or hashes" },
  { token = "'wasm-unsafe-eval'", weight = SEVERITY.LOW,
    note = "permits WebAssembly compilation without full eval" },
}

local CSP_SCHEME_SOURCES = {
  { scheme = "data:", weight = SEVERITY.MEDIUM,
    note = "data: URIs can smuggle script or SVG payloads" },
  { scheme = "blob:", weight = SEVERITY.LOW,
    note = "blob: URIs are origin-scoped but bypass host allowlists" },
  { scheme = "filesystem:", weight = SEVERITY.LOW,
    note = "filesystem: URIs are rarely required and widen the trust boundary" },
  { scheme = "http:", weight = SEVERITY.HIGH,
    note = "explicit http: source allows mixed-content script/style loading" },
  { scheme = "ws:", weight = SEVERITY.MEDIUM,
    note = "unencrypted websocket source allowed" },
  { scheme = "*", weight = SEVERITY.CRITICAL,
    note = "bare wildcard allows loading resources from any origin" },
}

local PERMISSIONS_POLICY_FEATURES = {
  "accelerometer", "ambient-light-sensor", "autoplay", "battery",
  "camera", "display-capture", "document-domain", "encrypted-media",
  "execution-while-not-rendered", "execution-while-out-of-viewport",
  "fullscreen", "gamepad", "geolocation", "gyroscope", "hid",
  "idle-detection", "interest-cohort", "keyboard-map", "local-fonts",
  "magnetometer", "microphone", "midi", "navigation-override", "payment",
  "picture-in-picture", "publickey-credentials-create",
  "publickey-credentials-get", "screen-wake-lock", "serial",
  "speaker-selection", "storage-access", "sync-xhr", "usb", "web-share",
  "window-management", "window-placement", "xr-spatial-tracking",
  "attribution-reporting", "bluetooth", "browsing-topics", "clipboard-read",
  "clipboard-write", "compute-pressure", "digital-credentials-get",
  "fenced-unpartitioned-storage-read", "join-ad-interest-group",
  "run-ad-auction", "shared-storage", "shared-storage-select-url",
  "storage-access-for", "unload",
}

local REFERRER_POLICIES = {
  "no-referrer", "no-referrer-when-downgrade", "origin",
  "origin-when-cross-origin", "same-origin", "strict-origin",
  "strict-origin-when-cross-origin", "unsafe-url",
}

local WEAK_REFERRER_POLICIES = {
  ["no-referrer-when-downgrade"] = SEVERITY.MEDIUM,
  ["unsafe-url"] = SEVERITY.HIGH,
  ["strict-origin"] = SEVERITY.LOW,
}

local COOP_VALUES = {
  ["unsafe-none"] = SEVERITY.MEDIUM,
  ["same-origin-allow-popups"] = SEVERITY.LOW,
  ["same-origin"] = 0,
}

local COEP_VALUES = {
  ["unsafe-none"] = SEVERITY.LOW,
  ["require-corp"] = 0,
  ["credentialless"] = SEVERITY.LOW,
}

local CORP_VALUES = {
  ["same-site"] = SEVERITY.LOW,
  ["same-origin"] = 0,
  ["cross-origin"] = SEVERITY.MEDIUM,
}

local XFO_VALUES = {
  deny = 0,
  sameorigin = 0,
}

local KNOWN_HEADER_SET = {
  "strict-transport-security",
  "content-security-policy",
  "content-security-policy-report-only",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
  "feature-policy",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "x-xss-protection",
  "x-permitted-cross-domain-policies",
  "x-download-options",
  "nel",
  "reporting-api",
  "report-to",
  "public-key-pins",
  "expect-ct",
  "cache-control",
  "pragma",
  "vary",
  "set-cookie",
  "server",
  "x-powered-by",
  "x-aspnet-version",
  "x-aspnetmvc-version",
  "x-generator",
  "x-runtime",
  "x-drupal-cache",
  "x-varnish",
  "via",
  "x-cache",
  "x-amz-cf-id",
  "x-served-by",
  "x-request-id",
  "timing-allow-origin",
  "access-control-allow-origin",
  "access-control-allow-credentials",
}

local DISCLOSURE_HEADERS = {
  { header = "server", label = "Server", weight = SEVERITY.LOW,
    note = "Server header discloses software and often exact version" },
  { header = "x-powered-by", label = "X-Powered-By", weight = SEVERITY.MEDIUM,
    note = "X-Powered-By discloses the application framework/stack" },
  { header = "x-aspnet-version", label = "X-AspNet-Version", weight = SEVERITY.MEDIUM,
    note = "X-AspNet-Version discloses the exact ASP.NET runtime version" },
  { header = "x-aspnetmvc-version", label = "X Aspnetmvc Version", weight = SEVERITY.MEDIUM,
    note = "X-AspNetMvc-Version discloses the exact MVC framework version" },
  { header = "x-generator", label = "X-Generator", weight = SEVERITY.LOW,
    note = "X-Generator discloses the CMS or site builder" },
  { header = "x-runtime", label = "X-Runtime", weight = SEVERITY.LOW,
    note = "X-Runtime discloses server-side processing time (timing oracle)" },
  { header = "x-drupal-cache", label = "X-Drupal-Cache", weight = SEVERITY.LOW,
    note = "X-Drupal-Cache confirms Drupal and its cache state" },
  { header = "x-varnish", label = "X-Varnish", weight = SEVERITY.LOW,
    note = "X-Varnish discloses the Varnish caching layer and request ids" },
  { header = "via", label = "Via", weight = SEVERITY.LOW,
    note = "Via discloses intermediate proxy software/versions" },
  { header = "x-served-by", label = "X-Served-By", weight = SEVERITY.LOW,
    note = "X-Served-By discloses backend host names" },
  { header = "x-amz-cf-id", label = "X-Amz-Cf-Id", weight = SEVERITY.LOW,
    note = "X-Amz-Cf-Id confirms CloudFront in front of the origin" },
  { header = "public-key-pins", label = "Public-Key-Pins", weight = SEVERITY.HIGH,
    note = "HPKP is deprecated and a wrong pin set causes permanent outage" },
  { header = "expect-ct", label = "Expect-CT", weight = SEVERITY.LOW,
    note = "Expect-CT is obsolete (CT is enforced by browsers directly)" },
}

local SESSION_COOKIE_NAMES = {
  "jsessionid", "phpsessid", "aspsessionid", "asp.net_sessionid",
  "sid", "session", "sessionid", "session_id", "sess", "connect.sid",
  "auth", "auth0", "auth_token", "token", "access_token", "id_token",
  "refresh_token", "jwt", "user_token", "csrftoken", "csrf_token",
  "xsrf-token", "_xsrf", "oauth", "sso", "remember", "remember_me",
  "remember-me", "login", "user", "userid", "user_id", "account",
  "laravel_session", "ci_session", "symfony", "django_session",
  "railo_session", "coldfusionid", "cfid", "cftoken", "weblogic_session",
  "j_username", "saplb_", "ts", "ga", "_ga", "_gid", "amp",
}

local LOW_CONFIDENCE_STATUS = {
  [400] = true, [401] = true, [403] = true, [404] = true,
  [405] = true, [406] = true, [408] = true, [410] = true,
  [429] = true, [500] = true, [501] = true, [502] = true,
  [503] = true, [504] = true,
}

local WAF_SIGNATURES = {
  "attention required", "cloudflare", "cf-ray", "request blocked",
  "access denied", "web application firewall", "incapsula",
  "akamai", "sucuri", "barracuda", "f5 big-ip", "mod_security",
  "aws waf", "imperva", "fortiweb", "safeline",
}

local DEFAULT_ARGS = {
  paths = nil,
  maxpaths = 12,
  minhsts = 15768000,
  retries = 2,
  timeout = 8000,
  followredirect = true,
  useragent = nil,
  includestatic = true,
  scoreverbose = false,
}

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
        if string.sub(normalized, 1, 1) ~= "/" then
          normalized = "/" .. normalized
        end
        table.insert(list, normalized)
      end
    end
    if #list > 0 then
      args.paths = list
    end
  end

  local maxpaths = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".maxpaths"))
  if maxpaths and maxpaths > 0 then
    args.maxpaths = math.floor(maxpaths)
  end

  local minhsts = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".minhsts"))
  if minhsts and minhsts >= 0 then
    args.minhsts = math.floor(minhsts)
  end

  local retries = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".retries"))
  if retries and retries >= 0 then
    args.retries = math.floor(retries)
  end

  local timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
  if timeout and timeout > 100 then
    args.timeout = math.floor(timeout)
  end

  local follow = stdnse.get_script_args(SCRIPT_NAME .. ".followredirect")
  if follow ~= nil then
    args.followredirect = not (follow == false or follow == "false" or follow == "no")
  end

  local ua = stdnse.get_script_args(SCRIPT_NAME .. ".useragent")
  if ua and #ua > 0 then
    args.useragent = ua
  end

  local includestatic = stdnse.get_script_args(SCRIPT_NAME .. ".includestatic")
  if includestatic ~= nil then
    args.includestatic = not (includestatic == false or includestatic == "false")
  end

  local scoreverbose = stdnse.get_script_args(SCRIPT_NAME .. ".scoreverbose")
  if scoreverbose ~= nil then
    args.scoreverbose = not (scoreverbose == false or scoreverbose == "false")
  end

  return args
end

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

local function split(value, separator)
  local parts = {}
  if type(value) ~= "string" or #value == 0 then
    return parts
  end
  local pattern = "([^" .. separator .. "]+)"
  for chunk in string.gmatch(value, pattern) do
    table.insert(parts, trim(chunk))
  end
  return parts
end

local function list_contains(list, needle)
  local lowered = lower(needle)
  for _, item in ipairs(list) do
    if lower(item) == lowered then
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

local function unique_insert(list, seen, value)
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

local function is_sensitive_path(path)
  local lowered = lower(path)
  for _, pattern in ipairs(SENSITIVE_PATH_PATTERNS) do
    if string.find(lowered, pattern, 1, true) then
      return true
    end
  end
  return false
end

local function is_static_path(path)
  local lowered = lower(path)
  for _, pattern in ipairs(STATIC_PATH_PATTERNS) do
    if string.find(lowered, pattern) then
      return true
    end
  end
  return false
end

local function select_paths(args)
  local source = args.paths
  if not source then
    source = {}
    for _, path in ipairs(DEFAULT_PATHS) do
      if args.includestatic or not is_static_path(path) then
        table.insert(source, path)
      end
    end
  end

  local selected = {}
  local seen = {}
  for _, path in ipairs(source) do
    local normalized = trim(path)
    if #normalized == 0 then
      normalized = "/"
    end
    if string.sub(normalized, 1, 1) ~= "/" then
      normalized = "/" .. normalized
    end
    normalized = string.gsub(normalized, "//+", "/")
    if unique_insert(selected, seen, normalized) and #selected >= args.maxpaths then
      break
    end
  end

  if #selected == 0 then
    table.insert(selected, "/")
  end

  local prioritized = {}
  for _, path in ipairs(selected) do
    if is_sensitive_path(path) then
      table.insert(prioritized, path)
    end
  end
  for _, path in ipairs(selected) do
    if not is_sensitive_path(path) then
      table.insert(prioritized, path)
    end
  end

  return prioritized
end

local function build_options(args)
  local options = {
    header = {},
    no_cache = true,
    bypass_cache = false,
    timeout = args.timeout,
  }
  if args.useragent then
    options.header["User-Agent"] = args.useragent
  else
    options.header["User-Agent"] = "Mozilla/5.0 (compatible; NSE " .. SCRIPT_NAME .. ")"
  end
  options.header["Accept"] = "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"
  options.header["Accept-Language"] = "en-US,en;q=0.9"
  options.header["Connection"] = "close"
  return options
end

local function sleep(seconds)
  if seconds <= 0 then
    return
  end
  stdnse.sleep(seconds)
end

local function raw_header_values(response, name)
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
    if single then
      table.insert(values, trim(single))
    end
  end
  return values
end

local function header_value(response, name)
  local values = raw_header_values(response, name)
  if #values == 0 then
    return nil
  end
  return values[1]
end

local function detect_waf_interstitial(response)
  local body = lower(response.body or "")
  if #body > 0 and #body < 4096 then
    for _, signature in ipairs(WAF_SIGNATURES) do
      if string.find(body, signature, 1, true) then
        return true, signature
      end
    end
  end
  local server = lower(header_value(response, "server") or "")
  for _, signature in ipairs(WAF_SIGNATURES) do
    if string.find(server, signature, 1, true) then
      return true, signature
    end
  end
  return false, nil
end

local function classify_response(path, response)
  local info = {
    path = path,
    status = response.status or 0,
    length = #(response.body or ""),
    usable = true,
    confidence = "high",
    notes = {},
  }

  if not response.status then
    info.usable = false
    info.confidence = "none"
    table.insert(info.notes, "no HTTP status line received")
    return info
  end

  if LOW_CONFIDENCE_STATUS[info.status] then
    info.confidence = "low"
    table.insert(info.notes, string.format("status %d responses often bypass application header logic", info.status))
  end

  local waf, signature = detect_waf_interstitial(response)
  if waf then
    info.confidence = "low"
    table.insert(info.notes, "response looks like a WAF/CDN interstitial (" .. signature .. ")")
  end

  if info.length == 0 and info.status < 300 then
    table.insert(info.notes, "empty body; header set may come from an edge cache")
  end

  return info
end

local function fetch_path(host, port, path, args)
  local options = build_options(args)
  local attempt = 0
  local last_error = nil

  while attempt <= args.retries do
    attempt = attempt + 1
    local ok, response = pcall(http.get, host, port, path, options)
    if ok and response and response.status then
      return response, nil
    end
    if ok and response and response["status-line"] then
      return response, nil
    end
    last_error = tostring(response or "no response")
    if attempt <= args.retries then
      sleep(0.4 * attempt)
    end
  end

  return nil, last_error
end

local function parse_directive_pairs(value)
  local pairs = {}
  for chunk in string.gmatch(value or "", "([^;]+)") do
    local name, rest = string.match(chunk, "^%s*([%w%-]+)%s*(.*)$")
    if name then
      table.insert(pairs, { name = lower(name), value = trim(rest) })
    end
  end
  return pairs
end

local function parse_hsts(value)
  local result = {
    raw = value,
    max_age = nil,
    include_subdomains = false,
    preload = false,
    malformed = {},
    directives = {},
  }

  if type(value) ~= "string" or #trim(value) == 0 then
    table.insert(result.malformed, "header present but empty")
    return result
  end

  local seen_directives = {}
  for _, pair in ipairs(parse_directive_pairs(value)) do
    local name = pair.name
    local raw_value = pair.value
    if string.sub(raw_value, 1, 1) == "=" then
      raw_value = trim(string.sub(raw_value, 2))
    end

    if seen_directives[name] then
      table.insert(result.malformed, "duplicate directive '" .. name .. "'")
    end
    seen_directives[name] = true
    result.directives[name] = raw_value

    if name == "max-age" then
      if string.match(raw_value, "^%-?%d+$") then
        local age = tonumber(raw_value)
        if age and age < 0 then
          table.insert(result.malformed, "negative max-age is invalid and ignored by browsers")
          result.max_age = 0
        else
          result.max_age = age or 0
        end
      else
        table.insert(result.malformed, "max-age value '" .. raw_value .. "' is not an integer")
      end
    elseif name == "includesubdomains" then
      if #raw_value > 0 then
        table.insert(result.malformed, "includeSubDomains must not carry a value")
      end
      result.include_subdomains = true
    elseif name == "preload" then
      if #raw_value > 0 then
        table.insert(result.malformed, "preload must not carry a value")
      end
      result.preload = true
    else
      table.insert(result.malformed, "unknown directive '" .. name .. "'")
    end
  end

  return result
end

local function evaluate_hsts(parsed, context, findings)
  local weight = 0

  if #parsed.malformed > 0 then
    for _, problem in ipairs(parsed.malformed) do
      table.insert(findings, {
        severity = "MEDIUM",
        weight = SEVERITY.MEDIUM,
        header = "Strict-Transport-Security",
        path = context.path,
        value = parsed.raw,
        detail = problem,
      })
      weight = weight + SEVERITY.MEDIUM
    end
  end

  if not parsed.max_age then
    table.insert(findings, {
      severity = "HIGH",
      weight = SEVERITY.HIGH,
      header = "Strict-Transport-Security",
      path = context.path,
      value = parsed.raw,
      detail = "no valid max-age directive; browsers will ignore the header entirely",
    })
    return weight + SEVERITY.HIGH
  end

  if parsed.max_age == 0 then
    table.insert(findings, {
      severity = "HIGH",
      weight = SEVERITY.HIGH,
      header = "Strict-Transport-Security",
      path = context.path,
      value = parsed.raw,
      detail = "max-age=0 removes HSTS protection for this host",
    })
    weight = weight + SEVERITY.HIGH
  elseif parsed.max_age < context.minhsts then
    local months = math.floor(parsed.max_age / 2592000)
    table.insert(findings, {
      severity = "MEDIUM",
      weight = SEVERITY.MEDIUM,
      header = "Strict-Transport-Security",
      path = context.path,
      value = parsed.raw,
      detail = string.format("max-age=%d (~%d months) is below the recommended minimum of %d",
        parsed.max_age, months, context.minhsts),
    })
    weight = weight + SEVERITY.MEDIUM
  end

  if parsed.max_age > 63072000 then
    table.insert(findings, {
      severity = "LOW",
      weight = SEVERITY.LOW,
      header = "Strict-Transport-Security",
      path = context.path,
      value = parsed.raw,
      detail = string.format("max-age=%d exceeds two years; recovery from a TLS outage becomes impossible",
        parsed.max_age),
    })
    weight = weight + SEVERITY.LOW
  end

  if not parsed.include_subdomains then
    table.insert(findings, {
      severity = "LOW",
      weight = SEVERITY.LOW,
      header = "Strict-Transport-Security",
      path = context.path,
      value = parsed.raw,
      detail = "includeSubDomains missing; subdomains remain reachable over plain HTTP",
    })
    weight = weight + SEVERITY.LOW
  end

  if not parsed.preload then
    table.insert(findings, {
      severity = "INFO",
      weight = SEVERITY.INFO,
      header = "Strict-Transport-Security",
      path = context.path,
      value = parsed.raw,
      detail = "preload directive absent; first-visit TLS downgrade still possible",
    })
    weight = weight + SEVERITY.INFO
  end

  if not context.tls then
    table.insert(findings, {
      severity = "MEDIUM",
      weight = SEVERITY.MEDIUM,
      header = "Strict-Transport-Security",
      path = context.path,
      value = parsed.raw,
      detail = "HSTS delivered over plain HTTP is ignored by browsers (RFC 6797 section 7.2)",
    })
    weight = weight + SEVERITY.MEDIUM
  end

  return weight
end

local function split_csp(value)
  local policies = {}
  for chunk in string.gmatch(value or "", "([^,]+)") do
    local trimmed = trim(chunk)
    if #trimmed > 0 then
      table.insert(policies, trimmed)
    end
  end
  if #policies == 0 and value and #trim(value) > 0 then
    table.insert(policies, trim(value))
  end
  return policies
end

local function parse_csp_policy(policy)
  local parsed = {
    raw = policy,
    directives = {},
    order = {},
    unknown = {},
    duplicates = {},
    sources = {},
    has_nonce = false,
    has_hash = false,
  }

  for raw_token in string.gmatch(policy, "([^;]+)") do
    local token = trim(raw_token)
    if #token > 0 then
      local name, rest = string.match(token, "^([%w%-]+)%s*(.*)$")
      if not name then
        table.insert(parsed.unknown, token)
      else
        name = lower(name)
        local sources = {}
        for source in string.gmatch(rest or "", "%S+") do
          table.insert(sources, source)
          if string.match(source, "^'nonce%-[A-Za-z0-9%+/=_%-]+'$") then
            parsed.has_nonce = true
          end
          if string.match(source, "^'sha256%-[A-Za-z0-9%+/=]+'$")
            or string.match(source, "^'sha384%-[A-Za-z0-9%+/=]+'$")
            or string.match(source, "^'sha512%-[A-Za-z0-9%+/=]+'$") then
            parsed.has_hash = true
          end
        end
        if parsed.directives[name] then
          table.insert(parsed.duplicates, name)
        end
        parsed.directives[name] = sources
        parsed.sources[name] = sources
        table.insert(parsed.order, name)
      end
    end
  end

  return parsed
end

local function csp_source_is_host(source)
  if starts_with(source, "'") then
    return false
  end
  for _, entry in ipairs(CSP_SCHEME_SOURCES) do
    if source == entry.scheme then
      return false
    end
  end
  return true
end

local function csp_host_is_wildcard(source)
  return starts_with(source, "*.") or source == "*"
end

local function csp_host_is_ip(source)
  local host = string.gsub(source, "^https?://", "")
  host = string.gsub(host, ":%d+$", "")
  return string.match(host, "^%d+%.%d+%.%d+%.%d+$") ~= nil
    or string.match(host, "^%[?[%x:]+%]?$") ~= nil
end

local function evaluate_csp(parsed, context, findings)
  local weight = 0
  local directives = parsed.directives

  if table_size(directives) == 0 then
    table.insert(findings, {
      severity = "MEDIUM",
      weight = SEVERITY.MEDIUM,
      header = context.header_label,
      path = context.path,
      value = parsed.raw,
      detail = "policy contains no parseable directives",
    })
    return weight + SEVERITY.MEDIUM
  end

  for _, duplicate in ipairs(parsed.duplicates) do
    table.insert(findings, {
      severity = "LOW",
      weight = SEVERITY.LOW,
      header = context.header_label,
      path = context.path,
      value = parsed.raw,
      detail = "directive '" .. duplicate .. "' appears more than once; browsers keep only the first occurrence",
    })
    weight = weight + SEVERITY.LOW
  end

  for _, unknown in ipairs(parsed.unknown) do
    table.insert(findings, {
      severity = "LOW",
      weight = SEVERITY.LOW,
      header = context.header_label,
      path = context.path,
      value = unknown,
      detail = "unparseable policy fragment",
    })
    weight = weight + SEVERITY.LOW
  end

  for name in pairs(directives) do
    if not CSP_ALL_KNOWN_DIRECTIVES[name] then
      table.insert(findings, {
        severity = "LOW",
        weight = SEVERITY.LOW,
        header = context.header_label,
        path = context.path,
        value = parsed.raw,
        detail = "unknown directive '" .. name .. "' (typo or non-standard extension)",
      })
      weight = weight + SEVERITY.LOW
    end
  end

  for _, deprecated in ipairs(CSP_DEPRECATED_DIRECTIVES) do
    if directives[deprecated] then
      table.insert(findings, {
        severity = "LOW",
        weight = SEVERITY.LOW,
        header = context.header_label,
        path = context.path,
        value = parsed.raw,
        detail = "deprecated directive '" .. deprecated .. "' still in use",
      })
      weight = weight + SEVERITY.LOW
    end
  end

  if not directives["default-src"] and not directives["script-src"] then
    table.insert(findings, {
      severity = "HIGH",
      weight = SEVERITY.HIGH,
      header = context.header_label,
      path = context.path,
      value = parsed.raw,
      detail = "neither default-src nor script-src is defined; script loading is unrestricted",
    })
    weight = weight + SEVERITY.HIGH
  end

  if directives["default-src"] and not directives["script-src"] then
    table.insert(findings, {
      severity = "INFO",
      weight = SEVERITY.INFO,
      header = context.header_label,
      path = context.path,
      value = parsed.raw,
      detail = "script-src falls back to default-src; verify that fallback is intentional",
    })
    weight = weight + SEVERITY.INFO
  end

  for name, sources in pairs(directives) do
    for _, source in ipairs(sources) do
      for _, entry in ipairs(CSP_DANGEROUS_SOURCES) do
        if lower(source) == entry.token then
          if not (entry.token == "'strict-dynamic'" and (parsed.has_nonce or parsed.has_hash)) then
            table.insert(findings, {
              severity = entry.weight >= SEVERITY.HIGH and "HIGH" or "MEDIUM",
              weight = entry.weight,
              header = context.header_label,
              path = context.path,
              value = name .. " " .. source,
              detail = entry.note,
            })
            weight = weight + entry.weight
          end
        end
      end

      for _, entry in ipairs(CSP_SCHEME_SOURCES) do
        if lower(source) == entry.scheme then
          local applies = true
          if entry.scheme == "data:" and name ~= "img-src" and name ~= "font-src"
            and name ~= "default-src" and name ~= "script-src" and name ~= "object-src"
            and name ~= "media-src" then
            applies = false
          end
          if applies then
            table.insert(findings, {
              severity = entry.weight >= SEVERITY.HIGH and "HIGH" or "MEDIUM",
              weight = entry.weight,
              header = context.header_label,
              path = context.path,
              value = name .. " " .. source,
              detail = entry.note,
            })
            weight = weight + entry.weight
          end
        end
      end

      if csp_source_is_host(source) then
        if csp_host_is_wildcard(source) then
          local severity = source == "*" and "CRITICAL" or "MEDIUM"
          local entry_weight = source == "*" and SEVERITY.CRITICAL or SEVERITY.MEDIUM
          table.insert(findings, {
            severity = severity,
            weight = entry_weight,
            header = context.header_label,
            path = context.path,
            value = name .. " " .. source,
            detail = "wildcard host source allows attacker-controlled subdomains/origins",
          })
          weight = weight + entry_weight
        elseif source == "*" then
          table.insert(findings, {
            severity = "CRITICAL",
            weight = SEVERITY.CRITICAL,
            header = context.header_label,
            path = context.path,
            value = name .. " " .. source,
            detail = "bare wildcard source in a fetch directive",
          })
          weight = weight + SEVERITY.CRITICAL
        elseif csp_host_is_ip(source) then
          table.insert(findings, {
            severity = "LOW",
            weight = SEVERITY.LOW,
            header = context.header_label,
            path = context.path,
            value = name .. " " .. source,
            detail = "IP literal source; brittle across environments and often a staging leftover",
          })
          weight = weight + SEVERITY.LOW
        end
      end

      if name == "object-src" then
        if lower(source) ~= "'none'" then
          table.insert(findings, {
            severity = "HIGH",
            weight = SEVERITY.HIGH,
            header = context.header_label,
            path = context.path,
            value = name .. " " .. source,
            detail = "object-src must be 'none' to block plugin based script execution",
          })
          weight = weight + SEVERITY.HIGH
        end
      end

      if name == "base-uri" and (lower(source) == "'unsafe-inline'" or source == "*") then
        table.insert(findings, {
          severity = "HIGH",
          weight = SEVERITY.HIGH,
          header = context.header_label,
          path = context.path,
          value = name .. " " .. source,
          detail = "permissive base-uri enables <base> tag injection attacks",
        })
        weight = weight + SEVERITY.HIGH
      end
    end
  end

  if not directives["base-uri"] then
    table.insert(findings, {
      severity = "MEDIUM",
      weight = SEVERITY.MEDIUM,
      header = context.header_label,
      path = context.path,
      value = parsed.raw,
      detail = "base-uri is not restricted (default-src does not cover it)",
    })
    weight = weight + SEVERITY.MEDIUM
  end

  if not directives["form-action"] then
    table.insert(findings, {
      severity = "LOW",
      weight = SEVERITY.LOW,
      header = context.header_label,
      path = context.path,
      value = parsed.raw,
      detail = "form-action is not restricted; forms can be redirected to attacker origins",
    })
    weight = weight + SEVERITY.LOW
  end

  if not directives["frame-ancestors"] then
    if context.xfo_missing then
      table.insert(findings, {
        severity = "MEDIUM",
        weight = SEVERITY.MEDIUM,
        header = context.header_label,
        path = context.path,
        value = parsed.raw,
        detail = "no frame-ancestors and no X-Frame-Options: clickjacking is unmitigated",
      })
      weight = weight + SEVERITY.MEDIUM
    else
      table.insert(findings, {
        severity = "INFO",
        weight = SEVERITY.INFO,
        header = context.header_label,
        path = context.path,
        value = parsed.raw,
        detail = "frame-ancestors absent; relying on X-Frame-Options only (ignored by modern CSP-aware browsers)",
      })
      weight = weight + SEVERITY.INFO
    end
  end

  local report_uri = directives["report-uri"]
  local report_to = directives["report-to"]
  if not report_uri and not report_to then
    table.insert(findings, {
      severity = "INFO",
      weight = SEVERITY.INFO,
      header = context.header_label,
      path = context.path,
      value = parsed.raw,
      detail = "no reporting endpoint (report-uri/report-to); violations are invisible to operators",
    })
    weight = weight + SEVERITY.INFO
  end

  if report_uri then
    for _, endpoint in ipairs(report_uri) do
      if not string.match(endpoint, "^https?://") and endpoint ~= "'none'" then
        table.insert(findings, {
          severity = "LOW",
          weight = SEVERITY.LOW,
          header = context.header_label,
          path = context.path,
          value = endpoint,
          detail = "report-uri must be an absolute URI; relative values are dropped",
        })
        weight = weight + SEVERITY.LOW
      elseif starts_with(endpoint, "http://") then
        table.insert(findings, {
          severity = "MEDIUM",
          weight = SEVERITY.MEDIUM,
          header = context.header_label,
          path = context.path,
          value = endpoint,
          detail = "report-uri uses plain HTTP; violation reports leak page metadata in clear text",
        })
        weight = weight + SEVERITY.MEDIUM
      end
    end
  end

  if parsed.has_nonce and parsed.has_hash then
    table.insert(findings, {
      severity = "LOW",
      weight = SEVERITY.LOW,
      header = context.header_label,
      path = context.path,
      value = parsed.raw,
      detail = "nonces and hashes are mixed; browsers supporting nonces will ignore the hashes",
    })
    weight = weight + SEVERITY.LOW
  end

  if directives["script-src"] and not parsed.has_nonce and not parsed.has_hash then
    for _, source in ipairs(directives["script-src"]) do
      if csp_source_is_host(source) and not csp_host_is_wildcard(source) then
        local parts = split(source, ".")
        if #parts <= 2 then
          table.insert(findings, {
            severity = "INFO",
            weight = SEVERITY.INFO,
            header = context.header_label,
            path = context.path,
            value = "script-src " .. source,
            detail = "host based allowlisting without nonces/hashes is bypassable through open redirects or JSONP endpoints on " .. source,
          })
          weight = weight + SEVERITY.INFO
        end
      end
    end
  end

  return weight
end

local function evaluate_csp_header(response, context, findings)
  local weight = 0
  local header_names = {
    { name = "content-security-policy", label = "Content-Security-Policy", enforced = true },
    { name = "content-security-policy-report-only", label = "Content-Security-Policy-Report-Only", enforced = false },
    { name = "x-content-security-policy", label = "X-Content-Security-Policy", enforced = true },
    { name = "x-webkit-csp", label = "X-WebKit-CSP", enforced = true },
  }

  local xfo_missing = not header_value(response, "x-frame-options")
  local saw_enforced = false

  for _, entry in ipairs(header_names) do
    local values = raw_header_values(response, entry.name)
    if #values > 0 then
      if entry.enforced then
        saw_enforced = true
      end
      for _, value in ipairs(values) do
        for _, policy in ipairs(split_csp(value)) do
          local parsed = parse_csp_policy(policy)
          local sub_context = {
            path = context.path,
            header_label = entry.label,
            xfo_missing = xfo_missing,
            tls = context.tls,
          }
          weight = weight + evaluate_csp(parsed, sub_context, findings)
          if not entry.enforced then
            local has_report = parsed.directives["report-uri"] or parsed.directives["report-to"]
            if not has_report then
              table.insert(findings, {
                severity = "LOW",
                weight = SEVERITY.LOW,
                header = entry.label,
                path = context.path,
                value = policy,
                detail = "report-only policy without a reporting endpoint is inert",
              })
              weight = weight + SEVERITY.LOW
            end
          end
        end
      end
    elseif entry.name == "x-content-security-policy" or entry.name == "x-webkit-csp" then
      table.insert(context.legacy_absent, entry.label)
    end
  end

  if not saw_enforced then
    table.insert(findings, {
      severity = "HIGH",
      weight = SEVERITY.HIGH,
      header = "Content-Security-Policy",
      path = context.path,
      value = "(absent)",
      detail = "no enforced Content-Security-Policy on this response",
    })
    weight = weight + SEVERITY.HIGH
  end

  return weight
end

local function evaluate_xfo(response, context, findings)
  local values = raw_header_values(response, "x-frame-options")
  if #values == 0 then
    if not context.csp_frame_ancestors then
      table.insert(findings, {
        severity = "MEDIUM",
        weight = SEVERITY.MEDIUM,
        header = "X-Frame-Options",
        path = context.path,
        value = "(absent)",
        detail = "no X-Frame-Options and no CSP frame-ancestors; page can be framed by any origin",
      })
      return SEVERITY.MEDIUM
    end
    return 0
  end

  local weight = 0
  for _, value in ipairs(values) do
    local lowered = lower(value)
    local token, argument = string.match(lowered, "^([%w%-]+)%s*(.*)$")
    token = token or lowered

    if token == "allow-from" then
      table.insert(findings, {
        severity = "HIGH",
        weight = SEVERITY.HIGH,
        header = "X-Frame-Options",
        path = context.path,
        value = value,
        detail = "ALLOW-FROM is unsupported by modern browsers and leaves the page frameable",
      })
      weight = weight + SEVERITY.HIGH
    elseif token == "allowall" or token == "allow" then
      table.insert(findings, {
        severity = "HIGH",
        weight = SEVERITY.HIGH,
        header = "X-Frame-Options",
        path = context.path,
        value = value,
        detail = "non-standard permissive value treated as 'no protection' by browsers",
      })
      weight = weight + SEVERITY.HIGH
    elseif not XFO_VALUES[token] then
      table.insert(findings, {
        severity = "MEDIUM",
        weight = SEVERITY.MEDIUM,
        header = "X-Frame-Options",
        path = context.path,
        value = value,
        detail = "value is not one of DENY / SAMEORIGIN and may be ignored",
      })
      weight = weight + SEVERITY.MEDIUM
    else
      if token == "sameorigin" and context.is_public_landing then
        table.insert(findings, {
          severity = "INFO",
          weight = SEVERITY.INFO,
          header = "X-Frame-Options",
          path = context.path,
          value = value,
          detail = "SAMEORIGIN is acceptable; DENY is preferred for pages without embedding needs",
        })
        weight = weight + SEVERITY.INFO
      end
      if argument and #argument > 0 then
        table.insert(findings, {
          severity = "LOW",
          weight = SEVERITY.LOW,
          header = "X-Frame-Options",
          path = context.path,
          value = value,
          detail = "trailing data after the token makes the header invalid per RFC 7034",
        })
        weight = weight + SEVERITY.LOW
      end
    end

    if #values > 1 then
      table.insert(findings, {
        severity = "LOW",
        weight = SEVERITY.LOW,
        header = "X-Frame-Options",
        path = context.path,
        value = table.concat(values, " | "),
        detail = "header sent multiple times; browsers use the most restrictive interpretation inconsistently",
      })
      weight = weight + SEVERITY.LOW
      break
    end
  end

  return weight
end

local function evaluate_xcto(response, context, findings)
  local values = raw_header_values(response, "x-content-type-options")
  if #values == 0 then
    table.insert(findings, {
      severity = "MEDIUM",
      weight = SEVERITY.MEDIUM,
      header = "X-Content-Type-Options",
      path = context.path,
      value = "(absent)",
      detail = "MIME sniffing is enabled; uploaded content can be executed as script",
    })
    return SEVERITY.MEDIUM
  end

  local weight = 0
  for _, value in ipairs(values) do
    if lower(value) ~= "nosniff" then
      table.insert(findings, {
        severity = "MEDIUM",
        weight = SEVERITY.MEDIUM,
        header = "X-Content-Type-Options",
        path = context.path,
        value = value,
        detail = "only 'nosniff' is a valid value; anything else is ignored",
      })
      weight = weight + SEVERITY.MEDIUM
    end
  end
  return weight
end

local function evaluate_referrer_policy(response, context, findings)
  local values = raw_header_values(response, "referrer-policy")
  if #values == 0 then
    table.insert(findings, {
      severity = "LOW",
      weight = SEVERITY.LOW,
      header = "Referrer-Policy",
      path = context.path,
      value = "(absent)",
      detail = "browser default (strict-origin-when-cross-origin) applies; explicit policy recommended",
    })
    return SEVERITY.LOW
  end

  local weight = 0
  for _, value in ipairs(values) do
    for _, token in ipairs(split(lower(value), ",")) do
      local matched = false
      for _, allowed in ipairs(REFERRER_POLICIES) do
        if token == allowed then
          matched = true
          break
        end
      end
      if not matched then
        table.insert(findings, {
          severity = "LOW",
          weight = SEVERITY.LOW,
          header = "Referrer-Policy",
          path = context.path,
          value = token,
          detail = "not a recognised Referrer-Policy token",
        })
        weight = weight + SEVERITY.LOW
      else
        local penalty = WEAK_REFERRER_POLICIES[token]
        if penalty then
          table.insert(findings, {
            severity = penalty >= SEVERITY.MEDIUM and "MEDIUM" or "LOW",
            weight = penalty,
            header = "Referrer-Policy",
            path = context.path,
            value = token,
            detail = "policy leaks URL/referrer information beyond the origin boundary",
          })
          weight = weight + penalty
        end
      end
    end
  end
  return weight
end

local function parse_permissions_policy(value)
  local result = { features = {}, malformed = {}, raw = value }
  for raw_chunk in string.gmatch(value or "", "([^,]+)") do
    local chunk = trim(raw_chunk)
    if #chunk > 0 then
      local name, allowlist = string.match(chunk, "^([%w%-]+)%s*=%s*(.*)$")
      if not name then
        table.insert(result.malformed, chunk)
      else
        local targets = {}
        allowlist = trim(allowlist)
        if starts_with(allowlist, "(") and ends_with(allowlist, ")") then
          for target in string.gmatch(string.sub(allowlist, 2, -2), "([^%s]+)") do
            table.insert(targets, trim(target))
          end
        else
          for target in string.gmatch(allowlist, "([^%s]+)") do
            table.insert(targets, trim(target))
          end
          table.insert(result.malformed, "value for '" .. lower(name) .. "' is not parenthesised")
        end
        result.features[lower(name)] = targets
      end
    end
  end
  return result
end

local function evaluate_permissions_policy(response, context, findings)
  local legacy_values = raw_header_values(response, "feature-policy")
  local values = raw_header_values(response, "permissions-policy")

  if #values == 0 and #legacy_values == 0 then
    table.insert(findings, {
      severity = "LOW",
      weight = SEVERITY.LOW,
      header = "Permissions-Policy",
      path = context.path,
      value = "(absent)",
      detail = "browser features (camera, microphone, geolocation, payment) are not restricted",
    })
    return SEVERITY.LOW
  end

  local weight = 0

  if #legacy_values > 0 then
    table.insert(findings, {
      severity = "LOW",
      weight = SEVERITY.LOW,
      header = "Feature-Policy",
      path = context.path,
      value = legacy_values[1],
      detail = "legacy Feature-Policy header served; migrate to Permissions-Policy syntax",
    })
    weight = weight + SEVERITY.LOW
  end

  local sensitive_features = {
    camera = true, microphone = true, geolocation = true, payment = true,
    usb = true, serial = true, hid = true, bluetooth = true, midi = true,
    ["interest-cohort"] = true, ["screen-wake-lock"] = true,
    ["publickey-credentials-get"] = true, ["clipboard-read"] = true,
  }

  for _, value in ipairs(values) do
    local parsed = parse_permissions_policy(value)
    for _, fragment in ipairs(parsed.malformed) do
      table.insert(findings, {
        severity = "LOW",
        weight = SEVERITY.LOW,
        header = "Permissions-Policy",
        path = context.path,
        value = fragment,
        detail = "malformed Permissions-Policy entry",
      })
      weight = weight + SEVERITY.LOW
    end

    for feature, targets in pairs(parsed.features) do
      local known = false
      for _, candidate in ipairs(PERMISSIONS_POLICY_FEATURES) do
        if candidate == feature then
          known = true
          break
        end
      end
      if not known then
        table.insert(findings, {
          severity = "INFO",
          weight = SEVERITY.INFO,
          header = "Permissions-Policy",
          path = context.path,
          value = feature,
          detail = "feature name is not in the published Permissions Policy registry",
        })
        weight = weight + SEVERITY.INFO
      end

      for _, target in ipairs(targets) do
        if target == "*" then
          local entry_weight = sensitive_features[feature] and SEVERITY.HIGH or SEVERITY.MEDIUM
          table.insert(findings, {
            severity = sensitive_features[feature] and "HIGH" or "MEDIUM",
            weight = entry_weight,
            header = "Permissions-Policy",
            path = context.path,
            value = feature .. "=*",
            detail = "feature enabled for all origins including cross-origin iframes",
          })
          weight = weight + entry_weight
        elseif not list_contains({ "self", "src", "none" }, string.gsub(target, "[()'\"]", ""))
          and not starts_with(target, "https://") then
          table.insert(findings, {
            severity = "LOW",
            weight = SEVERITY.LOW,
            header = "Permissions-Policy",
            path = context.path,
            value = feature .. "=" .. target,
            detail = "allowlist entry is not self/src/none or an absolute https origin",
          })
          weight = weight + SEVERITY.LOW
        end
      end

      if sensitive_features[feature] and #targets == 0 then
        table.insert(findings, {
          severity = "INFO",
          weight = SEVERITY.INFO,
          header = "Permissions-Policy",
          path = context.path,
          value = feature .. "=()",
          detail = "sensitive feature explicitly disabled (good practice)",
        })
      end
    end

    for _, sensitive in ipairs({ "camera", "microphone", "geolocation", "payment" }) do
      if not parsed.features[sensitive] then
        table.insert(findings, {
          severity = "LOW",
          weight = SEVERITY.LOW,
          header = "Permissions-Policy",
          path = context.path,
          value = value,
          detail = "sensitive feature '" .. sensitive .. "' is not explicitly restricted",
        })
        weight = weight + SEVERITY.LOW
      end
    end
  end

  return weight
end

local function evaluate_single_token_header(response, context, findings, name, label, allowed, absent_detail, absent_severity)
  local values = raw_header_values(response, name)
  if #values == 0 then
    if absent_detail then
      table.insert(findings, {
        severity = absent_severity or "LOW",
        weight = SEVERITY[absent_severity or "LOW"],
        header = label,
        path = context.path,
        value = "(absent)",
        detail = absent_detail,
      })
      return SEVERITY[absent_severity or "LOW"]
    end
    return 0
  end

  local weight = 0
  for _, value in ipairs(values) do
    local token = lower(string.gsub(value, "^%s*([%w%-]+)%s*.*$", "%1"))
    local penalty = allowed[token]
    if penalty == nil then
      table.insert(findings, {
        severity = "MEDIUM",
        weight = SEVERITY.MEDIUM,
        header = label,
        path = context.path,
        value = value,
        detail = "value is not part of the specification token set",
      })
      weight = weight + SEVERITY.MEDIUM
    elseif penalty > 0 then
      table.insert(findings, {
        severity = penalty >= SEVERITY.MEDIUM and "MEDIUM" or "LOW",
        weight = penalty,
        header = label,
        path = context.path,
        value = value,
        detail = "weak token in use",
      })
      weight = weight + penalty
    end
  end
  return weight
end

local function evaluate_xss_protection(response, context, findings)
  local values = raw_header_values(response, "x-xss-protection")
  if #values == 0 then
    return 0
  end
  local weight = 0
  for _, value in ipairs(values) do
    local trimmed = trim(value)
    if trimmed ~= "0" then
      table.insert(findings, {
        severity = "LOW",
        weight = SEVERITY.LOW,
        header = "X-XSS-Protection",
        path = context.path,
        value = trimmed,
        detail = "legacy auditor enabled; it introduces XSS bypass primitives, '0' is recommended",
      })
      weight = weight + SEVERITY.LOW
      if string.find(lower(trimmed), "report=") then
        table.insert(findings, {
          severity = "LOW",
          weight = SEVERITY.LOW,
          header = "X-XSS-Protection",
          path = context.path,
          value = trimmed,
          detail = "report= directive leaks victim URLs to the reporting endpoint",
        })
        weight = weight + SEVERITY.LOW
      end
    end
  end
  return weight
end

local function parse_json_arrayish(value)
  local entries = {}
  if type(value) ~= "string" then
    return entries, "value is not a string"
  end
  local trimmed = trim(value)
  if #trimmed == 0 then
    return entries, "header present but empty"
  end
  if not starts_with(trimmed, "[") or not ends_with(trimmed, "]") then
    return entries, "expected a JSON array"
  end
  local depth = 0
  local current = ""
  local in_string = false
  local escaped = false
  for i = 1, #trimmed do
    local char = string.sub(trimmed, i, i)
    if in_string then
      current = current .. char
      if escaped then
        escaped = false
      elseif char == "\\" then
        escaped = true
      elseif char == "\"" then
        in_string = false
      end
    else
      if char == "\"" then
        in_string = true
        current = current .. char
      elseif char == "{" or char == "[" then
        depth = depth + 1
        current = current .. char
      elseif char == "}" or char == "]" then
        depth = depth - 1
        current = current .. char
        if depth == 0 and #trim(current) > 0 then
          table.insert(entries, trim(current))
          current = ""
        end
      elseif char == "," and depth == 1 then
        if #trim(current) > 0 then
          table.insert(entries, trim(current))
        end
        current = ""
      else
        if depth > 0 then
          current = current .. char
        end
      end
    end
  end
  if #trim(current) > 0 and depth == 0 then
    table.insert(entries, trim(current))
  end
  return entries, nil
end

local function json_field(entry, field)
  local pattern = "\"" .. field .. "\"%s*:%s*\"([^\"]*)\""
  local value = string.match(entry, pattern)
  if value then
    return value
  end
  local numeric = string.match(entry, "\"" .. field .. "\"%s*:%s*(%-?%d+%.?%d*)")
  if numeric then
    return tonumber(numeric)
  end
  if string.find(entry, "\"" .. field .. "\"%s*:%s*true") then
    return true
  end
  if string.find(entry, "\"" .. field .. "\"%s*:%s*false") then
    return false
  end
  return nil
end

local function evaluate_nel(response, context, findings)
  local values = raw_header_values(response, "nel")
  if #values == 0 then
    return 0
  end
  local weight = 0
  for _, value in ipairs(values) do
    local entries, err = parse_json_arrayish(value)
    if err then
      table.insert(findings, {
        severity = "LOW",
        weight = SEVERITY.LOW,
        header = "NEL",
        path = context.path,
        value = value,
        detail = err,
      })
      weight = weight + SEVERITY.LOW
    end
    for _, entry in ipairs(entries) do
      local report_to = json_field(entry, "report_to")
      local max_age = json_field(entry, "max_age")
      local include_subdomains = json_field(entry, "include_subdomains")
      local failure_fraction = json_field(entry, "failure_fraction")
      local success_fraction = json_field(entry, "success_fraction")

      if not report_to then
        table.insert(findings, {
          severity = "LOW",
          weight = SEVERITY.LOW,
          header = "NEL",
          path = context.path,
          value = entry,
          detail = "policy without report_to is ignored",
        })
        weight = weight + SEVERITY.LOW
      end
      if type(max_age) == "number" then
        if max_age <= 0 then
          table.insert(findings, {
            severity = "LOW",
            weight = SEVERITY.LOW,
            header = "NEL",
            path = context.path,
            value = entry,
            detail = "max_age <= 0 disables the policy",
          })
          weight = weight + SEVERITY.LOW
        elseif max_age > 604800 then
          table.insert(findings, {
            severity = "LOW",
            weight = SEVERITY.LOW,
            header = "NEL",
            path = context.path,
            value = entry,
            detail = "max_age beyond seven days is capped by browsers",
          })
          weight = weight + SEVERITY.LOW
        end
      end
      if success_fraction and type(success_fraction) == "number" and success_fraction > 0 then
        table.insert(findings, {
          severity = "MEDIUM",
          weight = SEVERITY.MEDIUM,
          header = "NEL",
          path = context.path,
          value = entry,
          detail = string.format("success_fraction=%s reports successful requests (privacy exposure)", tostring(success_fraction)),
        })
        weight = weight + SEVERITY.MEDIUM
      end
      if failure_fraction and type(failure_fraction) == "number" and failure_fraction > 1 then
        table.insert(findings, {
          severity = "LOW",
          weight = SEVERITY.LOW,
          header = "NEL",
          path = context.path,
          value = entry,
          detail = "failure_fraction > 1 is invalid",
        })
        weight = weight + SEVERITY.LOW
      end
      if include_subdomains == true and not context.tls then
        table.insert(findings, {
          severity = "LOW",
          weight = SEVERITY.LOW,
          header = "NEL",
          path = context.path,
          value = entry,
          detail = "NEL with include_subdomains served over plain HTTP is ignored",
        })
        weight = weight + SEVERITY.LOW
      end
    end
  end
  return weight
end

local function evaluate_reporting_api(response, context, findings)
  local values = raw_header_values(response, "reporting-api")
  if #values == 0 then
    return 0
  end
  local weight = 0
  for _, value in ipairs(values) do
    local entries, err = parse_json_arrayish(value)
    if err then
      table.insert(findings, {
        severity = "LOW",
        weight = SEVERITY.LOW,
        header = "Reporting-API",
        path = context.path,
        value = value,
        detail = err,
      })
      weight = weight + SEVERITY.LOW
    end
    for _, entry in ipairs(entries) do
      local group = json_field(entry, "group")
      local endpoints = json_field(entry, "endpoints")
      if not group then
        table.insert(findings, {
          severity = "LOW",
          weight = SEVERITY.LOW,
          header = "Reporting-API",
          path = context.path,
          value = entry,
          detail = "endpoint group without a name",
        })
        weight = weight + SEVERITY.LOW
      end
      if endpoints and type(endpoints) == "string" then
        for endpoint in string.gmatch(endpoints, "https?://[^\"%s,]+") do
          if starts_with(endpoint, "http://") then
            table.insert(findings, {
              severity = "MEDIUM",
              weight = SEVERITY.MEDIUM,
              header = "Reporting-API",
              path = context.path,
              value = endpoint,
              detail = "reporting endpoint uses plain HTTP",
            })
            weight = weight + SEVERITY.MEDIUM
          end
        end
      end
    end
  end
  return weight
end

local function evaluate_disclosure_headers(response, context, findings)
  local weight = 0
  for _, entry in ipairs(DISCLOSURE_HEADERS) do
    local values = raw_header_values(response, entry.header)
    for _, value in ipairs(values) do
      if entry.header == "x-xss-protection" and trim(value) == "0" then
        goto continue_disclosure
      end
      local detail = entry.note
      local severity = entry.weight >= SEVERITY.HIGH and "HIGH" or (entry.weight >= SEVERITY.MEDIUM and "MEDIUM" or "LOW")
      local version = string.match(value, "(%d+%.%d+[%.%d%w%-]*)")
      if version then
        detail = detail .. " (version token observed: " .. version .. ")"
      end
      table.insert(findings, {
        severity = severity,
        weight = entry.weight,
        header = entry.label,
        path = context.path,
        value = value,
        detail = detail,
      })
      weight = weight + entry.weight
      ::continue_disclosure::
    end
  end
  return weight
end

local function parse_cookie_attributes(raw)
  local cookie = { raw = raw, attributes = {}, flags = {} }
  local first, rest = string.match(raw or "", "^([^;]*);?(.*)$")
  local name, value = string.match(first or "", "^%s*([^=]-)%s*=%s*(.*)$")
  if not name then
    name = trim(first or "")
    value = ""
    cookie.malformed = true
  end
  cookie.name = trim(name)
  cookie.value = trim(value or "")

  for raw_chunk in string.gmatch(rest or "", "[^;]+") do
    local chunk = trim(raw_chunk)
    if #chunk > 0 then
      local key, val = string.match(chunk, "^([%w%-]+)%s*=%s*(.*)$")
      if key then
        cookie.attributes[lower(key)] = trim(val)
      else
        cookie.flags[lower(chunk)] = true
      end
    end
  end

  return cookie
end

local function cookie_looks_sensitive(name)
  local lowered = lower(name)
  for _, candidate in ipairs(SESSION_COOKIE_NAMES) do
    if lowered == candidate then
      return true, candidate
    end
    if string.find(lowered, candidate, 1, true) then
      return true, candidate
    end
  end
  if string.find(lowered, "token") or string.find(lowered, "auth")
    or string.find(lowered, "session") or string.find(lowered, "jwt")
    or string.find(lowered, "csrf") or string.find(lowered, "xsrf")
    or string.find(lowered, "sid") or string.find(lowered, "login") then
    return true, "pattern"
  end
  return false, nil
end

local function evaluate_cookies(response, context, findings)
  local values = raw_header_values(response, "set-cookie")
  if #values == 0 then
    return 0
  end

  local weight = 0
  local sensitive_seen = false
  for _, raw in ipairs(values) do
    local cookie = parse_cookie_attributes(raw)
    if cookie.malformed then
      table.insert(findings, {
        severity = "LOW",
        weight = SEVERITY.LOW,
        header = "Set-Cookie",
        path = context.path,
        value = raw,
        detail = "cookie string has no name=value pair",
      })
      weight = weight + SEVERITY.LOW
    end

    local sensitive, matched = cookie_looks_sensitive(cookie.name or "")
    if sensitive then
      sensitive_seen = true
    end

    if not cookie.flags["secure"] then
      local entry_weight = context.tls and SEVERITY.HIGH or SEVERITY.MEDIUM
      table.insert(findings, {
        severity = context.tls and "HIGH" or "MEDIUM",
        weight = entry_weight,
        header = "Set-Cookie",
        path = context.path,
        value = cookie.name or "(unnamed)",
        detail = (sensitive and "session/auth cookie '" .. tostring(matched) .. "'" or "cookie")
          .. " is set without the Secure attribute" .. (context.tls and " on a TLS listener" or ""),
      })
      weight = weight + entry_weight
    end

    if not cookie.flags["httponly"] and sensitive then
      table.insert(findings, {
        severity = "MEDIUM",
        weight = SEVERITY.MEDIUM,
        header = "Set-Cookie",
        path = context.path,
        value = cookie.name or "(unnamed)",
        detail = "session-looking cookie without HttpOnly is readable by injected script",
      })
      weight = weight + SEVERITY.MEDIUM
    end

    local samesite = cookie.attributes["samesite"]
    if not samesite then
      if sensitive then
        table.insert(findings, {
          severity = "MEDIUM",
          weight = SEVERITY.MEDIUM,
          header = "Set-Cookie",
          path = context.path,
          value = cookie.name or "(unnamed)",
          detail = "no SameSite attribute; browser default varies and CSRF exposure increases",
        })
        weight = weight + SEVERITY.MEDIUM
      end
    else
      local normalized = lower(samesite)
      if normalized == "none" and not cookie.flags["secure"] then
        table.insert(findings, {
          severity = "HIGH",
          weight = SEVERITY.HIGH,
          header = "Set-Cookie",
          path = context.path,
          value = cookie.name or "(unnamed)",
          detail = "SameSite=None requires Secure; browsers reject this cookie or send it cross-site",
        })
        weight = weight + SEVERITY.HIGH
      elseif normalized == "lax" and sensitive and not cookie.flags["secure"] then
        table.insert(findings, {
          severity = "LOW",
          weight = SEVERITY.LOW,
          header = "Set-Cookie",
          path = context.path,
          value = cookie.name or "(unnamed)",
          detail = "SameSite=Lax still allows top-level GET navigations to carry the cookie",
        })
        weight = weight + SEVERITY.LOW
      elseif not list_contains({ "strict", "lax", "none" }, normalized) then
        table.insert(findings, {
          severity = "LOW",
          weight = SEVERITY.LOW,
          header = "Set-Cookie",
          path = context.path,
          value = cookie.name or "(unnamed)",
          detail = "SameSite='" .. samesite .. "' is not a valid token",
        })
        weight = weight + SEVERITY.LOW
      end
    end

    local domain = cookie.attributes["domain"]
    if domain then
      local cleaned = string.gsub(lower(domain), "^%.", "")
      local parts = split(cleaned, ".")
      if #parts <= 2 and sensitive then
        table.insert(findings, {
          severity = "LOW",
          weight = SEVERITY.LOW,
          header = "Set-Cookie",
          path = context.path,
          value = cookie.name or "(unnamed)",
          detail = "Domain=" .. domain .. " scopes the session cookie to the registrable domain and every subdomain",
        })
        weight = weight + SEVERITY.LOW
      end
      if cleaned == "localhost" or string.match(cleaned, "^%d+%.%d+%.%d+%.%d+$") then
        table.insert(findings, {
          severity = "LOW",
          weight = SEVERITY.LOW,
          header = "Set-Cookie",
          path = context.path,
          value = cookie.name or "(unnamed)",
          detail = "Domain attribute set to a host/IP value is rejected by browsers",
        })
        weight = weight + SEVERITY.LOW
      end
    end

    local path_attribute = cookie.attributes["path"]
    if path_attribute and path_attribute ~= "/" and sensitive then
      table.insert(findings, {
        severity = "INFO",
        weight = SEVERITY.INFO,
        header = "Set-Cookie",
        path = context.path,
        value = cookie.name or "(unnamed)",
        detail = "Path=" .. path_attribute .. " limits cookie scope; ensure no sibling app relies on it",
      })
      weight = weight + SEVERITY.INFO
    end

    local expires = cookie.attributes["expires"]
    local max_age = cookie.attributes["max-age"]
    if expires and not max_age then
      local day, month, year = string.match(expires, "(%d+)%s+(%a+)%s+(%d+)")
      if not (day and month and year) then
        table.insert(findings, {
          severity = "LOW",
          weight = SEVERITY.LOW,
          header = "Set-Cookie",
          path = context.path,
          value = cookie.name or "(unnamed)",
          detail = "Expires value '" .. expires .. "' is not in RFC 1123 format",
        })
        weight = weight + SEVERITY.LOW
      else
        local months = { jan = 1, feb = 2, mar = 3, apr = 4, may = 5, jun = 6,
          jul = 7, aug = 8, sep = 9, oct = 10, nov = 11, dec = 12 }
        local month_number = months[lower(month:sub(1, 3))]
        if not month_number then
          table.insert(findings, {
            severity = "LOW",
            weight = SEVERITY.LOW,
            header = "Set-Cookie",
            path = context.path,
            value = cookie.name or "(unnamed)",
            detail = "Expires month '" .. month .. "' is invalid",
          })
          weight = weight + SEVERITY.LOW
        elseif tonumber(year) and tonumber(year) > 2100 then
          table.insert(findings, {
            severity = "LOW",
            weight = SEVERITY.LOW,
            header = "Set-Cookie",
            path = context.path,
            value = cookie.name or "(unnamed)",
            detail = "session cookie lifetime effectively permanent (expires " .. expires .. ")",
          })
          weight = weight + SEVERITY.LOW
        end
      end
    end
    if max_age and tonumber(max_age) and tonumber(max_age) < 0 then
      table.insert(findings, {
        severity = "LOW",
        weight = SEVERITY.LOW,
        header = "Set-Cookie",
        path = context.path,
        value = cookie.name or "(unnamed)",
        detail = "negative Max-Age deletes the cookie immediately",
      })
      weight = weight + SEVERITY.LOW
    end

    if #(cookie.value or "") == 0 and not cookie.malformed then
      table.insert(findings, {
        severity = "INFO",
        weight = SEVERITY.INFO,
        header = "Set-Cookie",
        path = context.path,
        value = cookie.name or "(unnamed)",
        detail = "cookie set with an empty value (possible deletion or broken session bootstrap)",
      })
      weight = weight + SEVERITY.INFO
    end

    if cookie.value and #cookie.value > 4096 then
      table.insert(findings, {
        severity = "LOW",
        weight = SEVERITY.LOW,
        header = "Set-Cookie",
        path = context.path,
        value = cookie.name or "(unnamed)",
        detail = string.format("cookie value is %d bytes; browsers may drop cookies above ~4096 bytes", #cookie.value),
      })
      weight = weight + SEVERITY.LOW
    end
  end

  if sensitive_seen and not context.tls then
    table.insert(findings, {
      severity = "HIGH",
      weight = SEVERITY.HIGH,
      header = "Set-Cookie",
      path = context.path,
      value = "(listener)",
      detail = "session cookies are exchanged over plain HTTP; HSTS on the TLS side cannot compensate",
    })
    weight = weight + SEVERITY.HIGH
  end

  return weight
end

local function parse_cache_control(value)
  local directives = {}
  local order = {}
  for raw_chunk in string.gmatch(value or "", "[^,]+") do
    local chunk = trim(raw_chunk)
    if #chunk > 0 then
      local name, argument = string.match(chunk, "^([%w%-]+)%s*=?%s*(.*)$")
      if name then
        name = lower(name)
        directives[name] = trim(argument)
        table.insert(order, name)
      end
    end
  end
  return directives, order
end

local function evaluate_cache_exposure(response, context, findings)
  if not is_sensitive_path(context.path) then
    return 0
  end

  local cc_values = raw_header_values(response, "cache-control")
  local pragma = lower(header_value(response, "pragma") or "")
  local vary = lower(header_value(response, "vary") or "")
  local etag = header_value(response, "etag")
  local age = header_value(response, "age")
  local weight = 0

  if #cc_values == 0 then
    table.insert(findings, {
      severity = "MEDIUM",
      weight = SEVERITY.MEDIUM,
      header = "Cache-Control",
      path = context.path,
      value = "(absent)",
      detail = "sensitive path without Cache-Control is heuristically cacheable by shared caches",
    })
    weight = weight + SEVERITY.MEDIUM
  end

  for _, value in ipairs(cc_values) do
    local directives, order = parse_cache_control(value)
    for _, name in ipairs(order) do
      if name == "public" then
        table.insert(findings, {
          severity = "HIGH",
          weight = SEVERITY.HIGH,
          header = "Cache-Control",
          path = context.path,
          value = value,
          detail = "'public' marks an authenticated/personal response as storable by shared caches",
        })
        weight = weight + SEVERITY.HIGH
      end
      if name == "max-age" then
        local seconds = tonumber(directives[name])
        if seconds and seconds > 0 and not directives["private"] and not directives["no-store"] then
          table.insert(findings, {
            severity = "MEDIUM",
            weight = SEVERITY.MEDIUM,
            header = "Cache-Control",
            path = context.path,
            value = value,
            detail = string.format("max-age=%d on a sensitive path without private/no-store", seconds),
          })
          weight = weight + SEVERITY.MEDIUM
        end
      end
      if name == "s-maxage" then
        table.insert(findings, {
          severity = "MEDIUM",
          weight = SEVERITY.MEDIUM,
          header = "Cache-Control",
          path = context.path,
          value = value,
          detail = "s-maxage explicitly enables shared-cache storage of this response",
        })
        weight = weight + SEVERITY.MEDIUM
      end
      if name == "immutable" and not directives["private"] then
        table.insert(findings, {
          severity = "LOW",
          weight = SEVERITY.LOW,
          header = "Cache-Control",
          path = context.path,
          value = value,
          detail = "'immutable' on a dynamic path prevents revalidation of personalised content",
        })
        weight = weight + SEVERITY.LOW
      end
    end

    if not directives["no-store"] then
      table.insert(findings, {
        severity = "MEDIUM",
        weight = SEVERITY.MEDIUM,
        header = "Cache-Control",
        path = context.path,
        value = value,
        detail = "'no-store' missing on a sensitive path",
      })
      weight = weight + SEVERITY.MEDIUM
    end
  end

  if #pragma > 0 and not string.find(pragma, "no%-cache") and not string.find(pragma, "no%-store") then
    table.insert(findings, {
      severity = "LOW",
      weight = SEVERITY.LOW,
      header = "Pragma",
      path = context.path,
      value = pragma,
      detail = "Pragma present without no-cache (HTTP/1.0 caches may store the response)",
    })
    weight = weight + SEVERITY.LOW
  end

  if vary and not string.find(vary, "cookie") and #cc_values > 0 then
    local directives = parse_cache_control(cc_values[1])
    if directives["private"] or directives["public"] then
      table.insert(findings, {
        severity = "LOW",
        weight = SEVERITY.LOW,
        header = "Vary",
        path = context.path,
        value = vary,
        detail = "Vary does not include Cookie; personalised responses can be served to other users",
      })
      weight = weight + SEVERITY.LOW
    end
  end

  if etag and is_sensitive_path(context.path) then
    local weak = starts_with(lower(etag), "w/")
    if not weak then
      table.insert(findings, {
        severity = "INFO",
        weight = SEVERITY.INFO,
        header = "ETag",
        path = context.path,
        value = etag,
        detail = "strong ETag on a personalised resource can leak data through cache validation (ETag reuse attacks)",
      })
      weight = weight + SEVERITY.INFO
    end
  end

  if age and tonumber(age) and tonumber(age) > 0 and is_sensitive_path(context.path) then
    table.insert(findings, {
      severity = "HIGH",
      weight = SEVERITY.HIGH,
      header = "Age",
      path = context.path,
      value = age,
      detail = "response was served from a shared cache (Age=" .. age .. ") on a sensitive path",
    })
    weight = weight + SEVERITY.HIGH
  end

  return weight
end

local function evaluate_cors_side_effects(response, context, findings)
  local acao = header_value(response, "access-control-allow-origin")
  local acac = header_value(response, "access-control-allow-credentials")
  if not acao then
    return 0
  end
  local weight = 0
  if acao == "*" then
    if acac and lower(acac) == "true" then
      table.insert(findings, {
        severity = "HIGH",
        weight = SEVERITY.HIGH,
        header = "Access-Control-Allow-Origin",
        path = context.path,
        value = acao,
        detail = "wildcard origin combined with Access-Control-Allow-Credentials: true (invalid but signals broken CORS logic)",
      })
      weight = weight + SEVERITY.HIGH
    else
      table.insert(findings, {
        severity = "LOW",
        weight = SEVERITY.LOW,
        header = "Access-Control-Allow-Origin",
        path = context.path,
        value = acao,
        detail = "wildcard CORS origin on a sensitive path exposes the resource to any website",
      })
      weight = weight + SEVERITY.LOW
    end
  elseif is_sensitive_path(context.path) and acac and lower(acac) == "true" then
    table.insert(findings, {
      severity = "MEDIUM",
      weight = SEVERITY.MEDIUM,
      header = "Access-Control-Allow-Credentials",
      path = context.path,
      value = acao,
      detail = "credentialed CORS response on a sensitive path; verify the origin allowlist is exact",
    })
    weight = weight + SEVERITY.MEDIUM
  end
  return weight
end

local function evaluate_redirect_target(response, context, findings)
  if not response.status or response.status < 300 or response.status > 399 then
    return 0
  end
  local location = header_value(response, "location")
  if not location then
    return 0
  end
  local weight = 0
  if starts_with(lower(location), "http://") and context.tls then
    table.insert(findings, {
      severity = "HIGH",
      weight = SEVERITY.HIGH,
      header = "Location",
      path = context.path,
      value = location,
      detail = "TLS response redirects to plain HTTP; HSTS cannot protect the first hop",
    })
    weight = weight + SEVERITY.HIGH
  end
  if string.find(lower(location), "%%0d%%0a") or string.find(location, "\r") or string.find(location, "\n") then
    table.insert(findings, {
      severity = "HIGH",
      weight = SEVERITY.HIGH,
      header = "Location",
      path = context.path,
      value = location,
      detail = "Location header contains CR/LF sequences (response splitting indicator)",
    })
    weight = weight + SEVERITY.HIGH
  end
  local parsed = url.parse(location)
  if parsed and parsed.host and parsed.host ~= context.hostname then
    table.insert(findings, {
      severity = "MEDIUM",
      weight = SEVERITY.MEDIUM,
      header = "Location",
      path = context.path,
      value = location,
      detail = "redirect leaves the scanned host (" .. tostring(parsed.host) .. "); header posture of the target is not audited",
    })
    weight = weight + SEVERITY.MEDIUM
  end
  return weight
end

local function evaluate_body_leaks(response, context, findings)
  local body = response.body or ""
  if #body == 0 then
    return 0
  end
  local weight = 0
  local lowered = lower(body)

  local meta_refresh = string.match(body, "<meta[^>]+http%-equiv%s*=%s*[\"']?refresh[\"']?[^>]*>", 1)
  if meta_refresh then
    table.insert(findings, {
      severity = "LOW",
      weight = SEVERITY.LOW,
      header = "Body",
      path = context.path,
      value = trim(meta_refresh),
      detail = "meta refresh navigation cannot be constrained by CSP frame-ancestors or HSTS",
    })
    weight = weight + SEVERITY.LOW
  end

  if string.find(lowered, "<form", 1, true) and context.tls then
    for action in string.gmatch(body, "<form[^>]+action%s*=%s*[\"'](http://[^\"']+)[\"']") do
      table.insert(findings, {
        severity = "HIGH",
        weight = SEVERITY.HIGH,
        header = "Body",
        path = context.path,
        value = action,
        detail = "TLS page posts a form to a plain HTTP endpoint (credential interception)",
      })
      weight = weight + SEVERITY.HIGH
    end
  end

  for script in string.gmatch(body, "<script[^>]+src%s*=%s*[\"'](http://[^\"']+)[\"']") do
    table.insert(findings, {
      severity = "MEDIUM",
      weight = SEVERITY.MEDIUM,
      header = "Body",
      path = context.path,
      value = script,
      detail = "mixed content: script loaded over plain HTTP",
    })
    weight = weight + SEVERITY.MEDIUM
  end

  if string.find(lowered, "debug", 1, true) and string.find(lowered, "stack trace", 1, true) then
    table.insert(findings, {
      severity = "INFO",
      weight = SEVERITY.INFO,
      header = "Body",
      path = context.path,
      value = "(excerpt)",
      detail = "response body appears to contain a debug stack trace",
    })
    weight = weight + SEVERITY.INFO
  end

  return weight
end

local function collect_response_headers(response)
  local present = {}
  for _, name in ipairs(KNOWN_HEADER_SET) do
    local values = raw_header_values(response, name)
    if #values > 0 then
      present[name] = values
    end
  end
  return present
end

local function analyse_response(host, port, path, response, args)
  local context = {
    path = path,
    tls = port.ssl or (port.version and port.version.service_ssl) or false,
    minhsts = args.minhsts,
    hostname = host.targetname or host.name or (host.ip or ""),
    is_public_landing = path == "/" or path == "/index.html",
    legacy_absent = {},
    csp_frame_ancestors = false,
  }

  local info = classify_response(path, response)
  local findings = {}
  local weight = 0

  local present = collect_response_headers(response)
  local csp_value = header_value(response, "content-security-policy")
  if csp_value and string.find(lower(csp_value), "frame%-ancestors", 1) then
    context.csp_frame_ancestors = true
  end

  weight = weight + evaluate_hsts(parse_hsts(header_value(response, "strict-transport-security") or ""), context, findings)
  if not header_value(response, "strict-transport-security") and context.tls then
    table.insert(findings, {
      severity = "HIGH",
      weight = SEVERITY.HIGH,
      header = "Strict-Transport-Security",
      path = path,
      value = "(absent)",
      detail = "TLS listener does not advertise HSTS",
    })
    weight = weight + SEVERITY.HIGH
  end

  weight = weight + evaluate_csp_header(response, context, findings)
  weight = weight + evaluate_xfo(response, context, findings)
  weight = weight + evaluate_xcto(response, context, findings)
  weight = weight + evaluate_referrer_policy(response, context, findings)
  weight = weight + evaluate_permissions_policy(response, context, findings)
  weight = weight + evaluate_xss_protection(response, context, findings)

  weight = weight + evaluate_single_token_header(response, context, findings,
    "cross-origin-opener-policy", "Cross-Origin-Opener-Policy", COOP_VALUES,
    nil, nil)
  weight = weight + evaluate_single_token_header(response, context, findings,
    "cross-origin-embedder-policy", "Cross-Origin-Embedder-Policy", COEP_VALUES,
    nil, nil)
  weight = weight + evaluate_single_token_header(response, context, findings,
    "cross-origin-resource-policy", "Cross-Origin-Resource-Policy", CORP_VALUES,
    "cross-origin resources are not explicitly declared; browsers may block legitimate embedding", "INFO")
  weight = weight + evaluate_single_token_header(response, context, findings,
    "x-permitted-cross-domain-policies", "X-Permitted-Cross-Domain-Policies",
    { ["none"] = 0, ["master-only"] = SEVERITY.LOW, ["by-content-type"] = SEVERITY.MEDIUM,
      ["by-ftp-filename"] = SEVERITY.MEDIUM, ["all"] = SEVERITY.HIGH },
    nil, nil)
  weight = weight + evaluate_single_token_header(response, context, findings,
    "x-download-options", "X-Download-Options", { ["noopen"] = 0 }, nil, nil)

  weight = weight + evaluate_nel(response, context, findings)
  weight = weight + evaluate_reporting_api(response, context, findings)
  weight = weight + evaluate_disclosure_headers(response, context, findings)
  weight = weight + evaluate_cookies(response, context, findings)
  weight = weight + evaluate_cache_exposure(response, context, findings)
  weight = weight + evaluate_cors_side_effects(response, context, findings)
  weight = weight + evaluate_redirect_target(response, context, findings)
  weight = weight + evaluate_body_leaks(response, context, findings)

  if #context.legacy_absent > 0 then
    table.insert(info.notes, "legacy header aliases not present: " .. table.concat(context.legacy_absent, ", "))
  end

  if info.confidence == "low" then
    for _, finding in ipairs(findings) do
      finding.confidence = "low"
      finding.weight = math.max(1, math.floor(finding.weight / 2))
    end
    weight = 0
    for _, finding in ipairs(findings) do
      weight = weight + finding.weight
    end
  end

  return {
    path = path,
    info = info,
    findings = findings,
    weight = weight,
    present = present,
  }
end

local function gather_results(host, port, args)
  local paths = select_paths(args)
  local results = {}
  local errors = {}

  for _, path in ipairs(paths) do
    local response, err = fetch_path(host, port, path, args)
    if response then
      table.insert(results, analyse_response(host, port, path, response, args))
    else
      table.insert(errors, string.format("%s: %s", path, tostring(err)))
    end
    sleep(0.05)
  end

  return results, errors
end

local function follow_redirects(host, port, args, results)
  if not args.followredirect then
    return results
  end

  local extra = {}
  local seen = {}
  for _, result in ipairs(results) do
    seen[result.path] = true
  end

  for _, result in ipairs(results) do
    local location = result.present["location"]
    if location and location[1] then
      local target = location[1]
      local parsed = url.parse(target)
      local path = parsed and parsed.path or nil
      if path and #path > 0 and not seen[path] and starts_with(path, "/") then
        seen[path] = true
        local response, err = fetch_path(host, port, path, args)
        if response then
          table.insert(extra, analyse_response(host, port, path, response, args))
        elseif err then
          table.insert(extra, { path = path, error = err })
        end
      end
    end
  end

  for _, item in ipairs(extra) do
    table.insert(results, item)
  end

  return results
end

local function consistency_report(results)
  local header_paths = {}
  local inconsistencies = {}

  for _, result in ipairs(results) do
    if result.present then
      for name in pairs(result.present) do
        header_paths[name] = header_paths[name] or {}
        table.insert(header_paths[name], result.path)
      end
    end
  end

  local total = #results
  for _, name in ipairs(KNOWN_HEADER_SET) do
    local paths = header_paths[name]
    if paths and #paths > 0 and #paths < total and total > 1 then
      table.insert(inconsistencies, string.format("%s present on %d/%d paths (%s)",
        name, #paths, total, table.concat(paths, ", ")))
    end
  end

  table.sort(inconsistencies)
  return inconsistencies, header_paths
end

local function deduplicate_findings(results)
  local unique = {}
  local index = {}
  local per_severity = { CRITICAL = 0, HIGH = 0, MEDIUM = 0, LOW = 0, INFO = 0 }

  for _, result in ipairs(results) do
    for _, finding in ipairs(result.findings or {}) do
      local key = string.format("%s|%s|%s", finding.header, finding.severity, finding.detail)
      if not index[key] then
        index[key] = {
          header = finding.header,
          severity = finding.severity,
          detail = finding.detail,
          paths = {},
          examples = {},
          weight = finding.weight,
          count = 0,
          confidence = finding.confidence or "high",
        }
        table.insert(unique, index[key])
      end
      local entry = index[key]
      entry.count = entry.count + 1
      if not list_contains(entry.paths, finding.path) then
        table.insert(entry.paths, finding.path)
      end
      if #entry.examples < 3 and finding.value then
        local sample = tostring(finding.value)
        if #sample > 96 then
          sample = string.sub(sample, 1, 96) .. "..."
        end
        if not list_contains(entry.examples, sample) then
          table.insert(entry.examples, sample)
        end
      end
      per_severity[finding.severity] = (per_severity[finding.severity] or 0) + 1
    end
  end

  local order = { CRITICAL = 1, HIGH = 2, MEDIUM = 3, LOW = 4, INFO = 5 }
  table.sort(unique, function(a, b)
    if order[a.severity] ~= order[b.severity] then
      return order[a.severity] < order[b.severity]
    end
    if a.weight ~= b.weight then
      return a.weight > b.weight
    end
    return a.header < b.header
  end)

  return unique, per_severity
end

local function score_findings(unique, per_severity)
  local score = 0
  for _, finding in ipairs(unique) do
    local multiplier = 1
    if finding.count > 1 then
      multiplier = 1 + math.min(finding.count - 1, 5) * 0.1
    end
    if finding.confidence == "low" then
      multiplier = multiplier * 0.5
    end
    score = score + finding.weight * multiplier
  end

  local grade
  if per_severity.CRITICAL > 0 or score >= 60 then
    grade = "POOR"
  elseif per_severity.HIGH >= 3 or score >= 35 then
    grade = "WEAK"
  elseif per_severity.HIGH > 0 or score >= 15 then
    grade = "PARTIAL"
  elseif score >= 5 then
    grade = "ACCEPTABLE"
  else
    grade = "HARDENED"
  end

  return math.floor(score + 0.5), grade
end

local function format_finding(finding, verbose)
  local line = string.format("[%s] %s — %s", finding.severity, finding.header, finding.detail)
  if #finding.paths > 0 then
    local shown = finding.paths
    if #shown > 4 and not verbose then
      shown = { shown[1], shown[2], shown[3], string.format("+%d more", #finding.paths - 3) }
    end
    line = line .. " (paths: " .. table.concat(shown, ", ") .. ")"
  end
  if #finding.examples > 0 and verbose then
    line = line .. " [value: " .. table.concat(finding.examples, " | ") .. "]"
  end
  if finding.confidence == "low" then
    line = line .. " [low confidence]"
  end
  return line
end

local function summarise_coverage(results, errors)
  local coverage = {}
  local ok_count = 0
  for _, result in ipairs(results) do
    if result.info then
      ok_count = ok_count + 1
      table.insert(coverage, string.format("%s -> %d (%d bytes, %s confidence)",
        result.path, result.info.status, result.info.length, result.info.confidence))
    end
  end
  for _, err in ipairs(errors or {}) do
    table.insert(coverage, err)
  end
  return ok_count, coverage
end

action = function(host, port)
  local args = read_args()
  local out = stdnse.output_table()

  out["Risk Level"] = RISK_LEVEL
  out["Status"] = STATUS_LINE

  local results, errors = gather_results(host, port, args)
  if #results == 0 then
    out["Status"] = "AUDITED - no HTTP response could be obtained; header posture unknown."
    out["Transport"] = port.ssl and "HTTPS" or "HTTP"
    out["Probe errors"] = errors
    out["Note"] = "increase http-security-headers.timeout / retries, or verify the service answers HTTP on this port"
    return out
  end

  results = follow_redirects(host, port, args, results)

  local unique, per_severity = deduplicate_findings(results)
  local score, grade = score_findings(unique, per_severity)
  local inconsistencies = consistency_report(results)
  local ok_count, coverage = summarise_coverage(results, errors)

  out["Transport"] = port.ssl and "HTTPS" or "HTTP"
  out["Paths probed"] = string.format("%d requested, %d answered", #coverage, ok_count)
  out["Header posture grade"] = grade
  out["Weighted score"] = tostring(score)
  out["Findings"] = string.format("CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d INFO=%d",
    per_severity.CRITICAL, per_severity.HIGH, per_severity.MEDIUM, per_severity.LOW, per_severity.INFO)

  local rendered = {}
  for _, finding in ipairs(unique) do
    if finding.severity ~= "INFO" or args.scoreverbose then
      table.insert(rendered, format_finding(finding, args.scoreverbose))
    end
  end
  if #rendered == 0 then
    table.insert(rendered, "no header weaknesses detected on the probed paths")
  end
  out["Details"] = rendered

  if #inconsistencies > 0 then
    out["Cross-path inconsistencies"] = inconsistencies
  end

  if args.scoreverbose then
    out["Coverage"] = coverage
  end

  if #errors > 0 then
    out["Probe errors"] = errors
  end

  if per_severity.CRITICAL > 0 then
    out["Recommendation"] = "treat as blocking: wildcard/none policies and credentialed CORS expose user data to arbitrary origins"
  elseif per_severity.HIGH > 0 then
    out["Recommendation"] = "enforce CSP script-src/object-src/base-uri restrictions, add HSTS with max-age >= " .. tostring(args.minhsts) .. " and Secure cookies"
  elseif per_severity.MEDIUM > 0 then
    out["Recommendation"] = "close the medium findings: complete the CSP directive set, add X-Content-Type-Options: nosniff and restrict cacheability of personalised paths"
  else
    out["Recommendation"] = "posture is solid; keep monitoring Permissions-Policy coverage and remove disclosure headers"
  end

  return out
end
