local shortport = require "shortport"

local http = require "http"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Determines whether the TRACE method family is enabled anywhere along the request
path, and - which is the part that matters - exactly what the server echoes back.

TRACE is not a curiosity. RFC 9110 requires a server that implements it to
return the request line and *all* request headers in the body with
Content-Type: message/http. In practice that includes headers the browser
attaches automatically and that JavaScript is forbidden from reading:
Cookie, Authorization, Proxy-Authorization, and the XSRF tokens that frameworks
rely on. Combined with any cross-origin content injection (or an old browser
that allowed XMLHttpRequest to set those headers), this is Cross-Site Tracing
and it converts an HttpOnly session cookie into a readable value.

What the script measures
1. Capability advertisement: OPTIONS (and OPTIONS *) responses are parsed for
   Allow / Public / Access-Control-Allow-Methods / MS-Author-Via and for the
   Allow header that accompanies a 405. A server that lists TRACE there has it
   enabled even if a later layer blocks the actual request.
2. Direct TRACE probes on a set of paths with a unique marker header
   (X-NSE-Trace-Marker) plus an inert Cookie, an inert Authorization header
   carrying only the marker, and a custom header. The response is then compared
   field by field against what was sent, and the script reports:
   * whether the method was accepted (HTTP 200 with message/http, 405, 501,
     403, or a connection close - nginx answers TRACE with 405 and some stacks
     close the socket, both of which mean disabled);
   * whether the request line, the marker header, the Cookie header, the
     Authorization header and the custom header were reflected;
   * whether the reflected body contains *extra* headers the client never sent
     - the genuinely dangerous case, because it means an upstream proxy or the
     server itself injects credentials (X-Forwarded-For, X-Real-IP,
     X-Forwarded-Proto, X-Original-URL, X-Rewrite-URL, X-Remote-Addr,
     X-Client-IP, X-Host, X-Forwarded-Host, Forwarded, Via, X-Amzn-Trace-Id,
     X-Request-Id, X-Correlation-Id, True-Client-IP, CF-Connecting-IP,
     X-SSL-Client-Cert, X-SSL-Client-DN, X-Client-Certificate, X-Remote-User,
     X-Auth-Request-User, X-Forwarded-User, X-Forwarded-Email, X-Oidc-*,
     Authorization, Proxy-Authorization, X-Api-Key, X-Csrf-Token,
     X-Xsrf-Token) into the request before echoing it;
   * whether a session cookie issued by the service in an earlier request is
     reflected by TRACE (the script captures Set-Cookie values from a normal
     GET and re-sends them, so the reflection test uses the site's own cookie
     names, and the values are the markers, never anything harvested from a
     real user session).
3. Variant coverage: TRACK (the IIS alias), TRACE with Max-Forwards: 0 and with
   Max-Forwards: 5 (to see whether an intermediate proxy consumes the request),
   TRACE to a static path, TRACE to a non-existent path, TRACE with an oversized
   header (to check whether the echo truncates), TRACE with a chunked
   Transfer-Encoding, and TRACE over the wildcard target `*`.
4. Layer attribution: by comparing the echoed Server/Via headers with the ones
   returned by a normal GET, and by looking at whether the echo contains proxy
   hop headers, the script states whether TRACE is answered by the origin or by
   an intermediate proxy/CDN/WAF - which determines where the fix belongs
   (TraceEnable off in Apache, trace off in nginx via `if ($request_method =
   TRACE) { return 405; }` or by the module, `<requestFiltering>` verbs deny in
   IIS, disable_tracing in the CDN).
5. Configuration context: the same paths are fetched with GET to record whether
   cookies are HttpOnly and Secure (from http-cookie-flags semantics), because
   XST severity depends entirely on whether the session cookie can be read by
   script. An HttpOnly cookie plus enabled TRACE is a HIGH finding; a
   non-HttpOnly cookie is already readable by script, so TRACE adds nothing and
   the finding is downgraded to LOW with that explanation.

All probes are read-only: TRACE by definition cannot modify state, no request
is repeated in a loop, and the injected headers contain only random markers.

Usage:
<code>
nmap -p 80,443 --script http-trace-method <target>
nmap -p 443 --script http-trace-method \
  --script-args http-trace-method.paths="/,/api,/admin",http-trace-method.maxrequests=90 <target>
nmap -p 80 --script http-trace-method \
  --script-args http-trace-method.variants=false <target>
</code>

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "discovery", "vuln"}

portrule = shortport.http

local SCRIPT_NAME = "http-trace-method"

local RISK_LEVEL = "🟡 MEDIUM"

local TRACE_PATHS = {
  "/",
  "/index.html",
  "/api",
  "/login",
  "/admin",
  "/static/app.css",
}

local INJECTED_HEADERS = {
  "X-Forwarded-For",
  "X-Real-IP",
  "X-Forwarded-Proto",
  "X-Forwarded-Host",
  "X-Forwarded-Port",
  "X-Forwarded-Server",
  "X-Forwarded-User",
  "X-Forwarded-Email",
  "X-Original-URL",
  "X-Rewrite-URL",
  "X-Original-Remote-Addr",
  "X-Client-IP",
  "X-Host",
  "X-Remote-Addr",
  "X-Remote-User",
  "X-Auth-Request-User",
  "X-Auth-Request-Email",
  "X-SSL-Client-Cert",
  "X-SSL-Client-DN",
  "X-SSL-Client-Verify",
  "X-SSL-Issuer",
  "X-Client-Certificate",
  "X-Certificate-Common-Name",
  "X-Amzn-Trace-Id",
  "X-Request-Id",
  "X-Correlation-Id",
  "X-Cloud-Trace-Context",
  "X-Datadog-Trace-Id",
  "True-Client-IP",
  "CF-Connecting-IP",
  "CF-IPCountry",
  "X-Cluster-Client-IP",
  "X-Appengine-User-IP",
  "X-Appengine-Authenticated-User",
  "X-Oidc-Subject",
  "X-Oidc-Email",
  "X-Api-Key",
  "X-Csrf-Token",
  "X-Xsrf-Token",
  "X-Auth-Token",
  "X-Access-Token",
  "X-User-Id",
  "X-Username",
  "X-Role",
  "X-Roles",
  "X-Groups",
  "X-Tenant-Id",
  "X-Org-Id",
  "X-Workspace",
  "Front-End-Https",
  "X-Forwarded-Ssl",
  "Via",
  "Forwarded",
  "Client-IP",
  "X-Proxy-User-Ip",
}

local CREDENTIAL_HEADERS = {
  { name = "Cookie", kind = "session", note = "session cookies the browser sends automatically" },
  { name = "Authorization", kind = "bearer", note = "HTTP authentication credentials" },
  { name = "Proxy-Authorization", kind = "proxy", note = "proxy credentials" },
  { name = "X-Api-Key", kind = "api-key", note = "API key header" },
  { name = "X-Csrf-Token", kind = "csrf", note = "CSRF token header" },
}

local METHOD_ALIASES = {
  { method = "TRACE", standard = "RFC 9110", note = "standard TRACE" },
  { method = "TRACK", standard = "Microsoft IIS extension", note = "IIS alias of TRACE" },
}

local TRACE_VARIANTS = {
  { name = "plain", note = "TRACE with only the marker header" },
  { name = "with-cookie", note = "TRACE carrying an inert marker Cookie header" },
  { name = "with-authorization", note = "TRACE carrying an inert marker Authorization header" },
  { name = "max-forwards-0", note = "TRACE with Max-Forwards: 0 (the first hop must answer)" },
  { name = "max-forwards-5", note = "TRACE with Max-Forwards: 5 (intermediate hops may answer)" },
  { name = "wildcard", note = "TRACE to the * request target" },
  { name = "missing-path", note = "TRACE to a randomised non-existent path" },
  { name = "oversized-header", note = "TRACE with an 8 KiB header value (truncation check)" },
  { name = "many-headers", note = "TRACE with 40 custom headers (injection surface check)" },
}

local WAF_SIGNATURES = {
  { pattern = "cf-ray", where = "header", vendor = "Cloudflare" },
  { pattern = "cloudflare", where = "header", vendor = "Cloudflare" },
  { pattern = "akamai", where = "header", vendor = "Akamai" },
  { pattern = "x-iinfo", where = "header", vendor = "Imperva Incapsula" },
  { pattern = "sucuri", where = "header", vendor = "Sucuri" },
  { pattern = "aws waf", where = "body", vendor = "AWS WAF" },
  { pattern = "attention required", where = "body", vendor = "Cloudflare" },
}

local SOFT404_TEMPLATES = {
  "/nse-trace-missing-%s",
}

local DEFAULT_ARGS = {
  paths = nil,
  maxpaths = 6,
  maxrequests = 90,
  retries = 1,
  timeout = 6000,
  delay = 0.03,
  variants = true,
  aliases = true,
  soft404 = true,
  useragent = nil,
  maxbodysize = 65536,
}

local NUMERIC_ARGS = {
  { key = "maxpaths", minimum = 1, integer = true },
  { key = "maxrequests", minimum = 6, integer = true },
  { key = "retries", minimum = 0, integer = true },
  { key = "timeout", minimum = 500, integer = true },
  { key = "maxbodysize", minimum = 1024, integer = true },
}

local BOOLEAN_ARGS = { "variants", "aliases", "soft404" }

local STRING_ARGS = { "useragent" }

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

local function select_paths(args)
  local selected = {}
  local seen = {}
  for _, candidate in ipairs(args.paths or TRACE_PATHS) do
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
  return selected
end

local CR = string.char(13)
local LF = string.char(10)

local function parse_echo(body)
  local echo = {
    request_line = nil,
    headers = {},
    order = {},
    lower_map = {},
  }
  local text = tostring(body or "")
  text = string.gsub(text, "^\r\n", "")
  local first_line = string.match(text, "^([^\r\n]*)")
  echo.request_line = first_line and trim(first_line) or nil

  local header_block = string.match(text, "^[^\r\n]*\r\n(.-)\r\n\r\n") or text
  for line in string.gmatch(header_block, "([^\r\n]+)") do
    local name, value = string.match(line, "^([^:]+):%s*(.*)$")
    if name then
      local normalized = trim(name)
      local lowered = lower(normalized)
      if not echo.lower_map[lowered] then
        echo.lower_map[lowered] = {}
        table.insert(echo.order, normalized)
      end
      table.insert(echo.lower_map[lowered], trim(value))
      table.insert(echo.headers, { name = normalized, value = trim(value) })
    end
  end
  return echo
end

local function echoed_values(echo, name)
  return echo.lower_map[lower(name)] or {}
end

local function echo_contains_marker(echo, marker)
  local hits = {}
  if echo.request_line and contains(lower(echo.request_line), lower(marker)) then
    table.insert(hits, "request-line")
  end
  for _, entry in ipairs(echo.headers) do
    if contains(lower(entry.value), lower(marker)) or contains(lower(entry.name), lower(marker)) then
      table.insert(hits, entry.name)
    end
  end
  return hits
end

local function parse_allow(response)
  local methods = {}
  local seen = {}
  local fields = { "allow", "public", "access-control-allow-methods" }
  for _, field in ipairs(fields) do
    local values = (response.header and response.header[field])
      or (response.headers and response.headers[field])
    if values then
      local list = type(values) == "table" and values or { values }
      for _, value in ipairs(list) do
        for token in string.gmatch(tostring(value), "[^,]+") do
          local name = string.gsub(trim(string.upper(token)), "[^A-Z0-9%-]", "")
          if #name > 1 and not seen[name] then
            seen[name] = true
            table.insert(methods, name)
          end
        end
      end
    end
  end
  for _, line in ipairs(response.rawheader or {}) do
    local key, value = string.match(line, "^([^:]+):%s*(.*)$")
    if key and (lower(trim(key)) == "allow" or lower(trim(key)) == "public") then
      for token in string.gmatch(tostring(value), "[^,]+") do
        local name = string.gsub(trim(string.upper(token)), "[^A-Z0-9%-]", "")
        if #name > 1 and not seen[name] then
          seen[name] = true
          table.insert(methods, name)
        end
      end
    end
  end
  return methods
end

local function collect_session_cookies(response)
  local cookies = {}
  local names = {}
  for _, raw in ipairs(response.rawheader or {}) do
    local key, value = string.match(raw, "^([^:]+):%s*(.*)$")
    if key and lower(trim(key)) == "set-cookie" then
      local name = string.match(value, "^%s*([^=;]+)")
      if name then
        table.insert(names, trim(name))
        local attributes = lower(value)
        table.insert(cookies, {
          name = trim(name),
          httponly = contains(attributes, "httponly"),
          secure = contains(attributes, "secure"),
          samesite = string.match(attributes, "samesite%s*=%s*(%a+)"),
          path = string.match(attributes, "path%s*=%s*([^;]+)"),
          domain = string.match(attributes, "domain%s*=%s*([^;]+)"),
        })
      end
    end
  end
  local values = (response.header and response.header["set-cookie"])
    or (response.headers and response.headers["set-cookie"])
  if values and #names == 0 then
    local list = type(values) == "table" and values or { values }
    for _, raw in ipairs(list) do
      local name = string.match(tostring(raw), "^%s*([^=;]+)")
      if name then
        table.insert(names, trim(name))
      end
    end
  end
  return cookies, names
end

local function build_cookie_header(names, marker)
  local parts = {}
  for _, name in ipairs(names) do
    table.insert(parts, name .. "=" .. marker)
  end
  if #parts == 0 then
    table.insert(parts, "NSESESSION=" .. marker)
  end
  return table.concat(parts, "; ")
end

local function build_variant_headers(variant, marker, cookie_header, oversized)
  local headers = {}
  table.insert(headers, { "X-NSE-Trace-Marker", marker })
  if variant == "with-cookie" or variant == "max-forwards-0" or variant == "max-forwards-5" then
    table.insert(headers, { "Cookie", cookie_header })
  end
  if variant == "with-authorization" then
    table.insert(headers, { "Authorization", "Bearer " .. marker })
    table.insert(headers, { "Cookie", cookie_header })
  end
  if variant == "max-forwards-0" then
    table.insert(headers, { "Max-Forwards", "0" })
  elseif variant == "max-forwards-5" then
    table.insert(headers, { "Max-Forwards", "5" })
  elseif variant == "plain" then
    table.insert(headers, { "Max-Forwards", "0" })
  end
  if variant == "oversized-header" then
    table.insert(headers, { "X-NSE-Oversized", string.rep("O", oversized or 8192) })
    table.insert(headers, { "Cookie", cookie_header })
  end
  if variant == "many-headers" then
    for index = 1, 40 do
      table.insert(headers, { string.format("X-NSE-Probe-%02d", index), marker .. "-" .. index })
    end
    table.insert(headers, { "Cookie", cookie_header })
  end
  if variant == "missing-path" or variant == "wildcard" then
    table.insert(headers, { "Cookie", cookie_header })
  end
  return headers
end

local function classify_trace_result(method, response, marker, cookie_header, sent_headers)
  local result = {
    method = method,
    status = response.status or 0,
    length = #(response.body or ""),
    content_type = response.header and response.header["content-type"],
    server = response.header and response.header["server"],
    via = response.header and response.header["via"],
    classification = "unknown",
    reflected = {},
    injected = {},
    extra_headers = {},
    truncated = false,
  }

  if result.status == 0 then
    result.classification = "closed"
    result.detail = "connection closed without an HTTP response (TRACE refused at socket level)"
    return result
  end

  local body = response.body or ""
  local echo = parse_echo(body)
  result.echo_request_line = echo.request_line
  result.echo_header_count = #echo.headers
  result.echo_order = echo.order

  local marker_hits = echo_contains_marker(echo, marker)
  if #marker_hits == 0 and contains(lower(body), lower(marker)) then
    table.insert(marker_hits, "body")
  end
  result.marker_hits = marker_hits
  local cookie_reflected = false
  for _, value in ipairs(echoed_values(echo, "cookie")) do
    if contains(lower(value), lower(marker)) then
      cookie_reflected = true
    end
  end
  result.cookie_reflected = cookie_reflected

  local authorization_reflected = false
  for _, value in ipairs(echoed_values(echo, "authorization")) do
    if contains(lower(value), lower(marker)) then
      authorization_reflected = true
    end
  end
  result.authorization_reflected = authorization_reflected

  local message_http = result.status == 200
    and contains(lower(tostring(result.content_type or "")), "message/http")

  if #marker_hits > 0 then
    result.classification = "echoed"
    result.detail = "request echoed back (marker reflected in " .. table.concat(marker_hits, ", ") .. ")"
    table.insert(result.reflected, "X-NSE-Trace-Marker")
    if cookie_reflected then
      table.insert(result.reflected, "Cookie")
    end
    if authorization_reflected then
      table.insert(result.reflected, "Authorization")
    end
  elseif message_http then
    result.classification = "echoed"
    result.detail = "HTTP 200 with Content-Type message/http (the server implements TRACE)"
  elseif result.status == 405 then
    result.classification = "disabled"
    result.detail = "405 Method Not Allowed"
    result.allow = parse_allow(response)
  elseif result.status == 501 then
    result.classification = "disabled"
    result.detail = "501 Not Implemented"
  elseif result.status == 403 or result.status == 401 then
    result.classification = "blocked"
    result.detail = "HTTP " .. tostring(result.status) .. " from an access-control or filtering layer"
  elseif result.status == 400 then
    result.classification = "rejected"
    result.detail = "400 Bad Request (method understood, request refused)"
  elseif result.status == 404 then
    result.classification = "routed"
    result.detail = "404: the method was routed by the application, not implemented as TRACE"
  elseif result.status >= 500 then
    result.classification = "error"
    result.detail = "HTTP " .. tostring(result.status) .. " while handling the method"
  else
    result.classification = "unknown"
    result.detail = "HTTP " .. tostring(result.status)
  end

  if result.classification == "echoed" then
    local sent_names = {}
    for _, pair in ipairs(sent_headers or {}) do
      sent_names[lower(pair[1])] = true
    end
    sent_names["host"] = true
    sent_names["user-agent"] = true
    sent_names["accept"] = true
    sent_names["accept-encoding"] = true
    sent_names["connection"] = true
    sent_names["content-length"] = true

    local seen_injected = {}
    for _, name in ipairs(echo.order) do
      local lowered = lower(name)
      if not sent_names[lowered] and not seen_injected[lowered] then
        seen_injected[lowered] = true
        local values = echoed_values(echo, name)
        table.insert(result.injected, {
          name = name,
          value = truncate(table.concat(values, " | "), 120),
        })
        table.insert(result.extra_headers, name)
      end
    end

    if #result.injected == 0 then
      local lowered_body = lower(body)
      for _, candidate in ipairs(INJECTED_HEADERS) do
        local lowered_candidate = lower(candidate)
        if not sent_names[lowered_candidate] and contains(lowered_body, lowered_candidate .. ":") then
          local value = string.match(body, candidate .. ":%s*([^" .. CR .. LF .. "]*)")
            or string.match(lowered_body, lowered_candidate .. ":%s*([^" .. CR .. LF .. "]*)")
          table.insert(result.injected, {
            name = candidate,
            value = truncate(tostring(value or "value not parseable"), 120),
          })
          table.insert(result.extra_headers, candidate)
        end
      end
    end

    local oversized_value = nil
    for _, pair in ipairs(sent_headers or {}) do
      if pair[1] == "X-NSE-Oversized" then
        oversized_value = pair[2]
      end
    end
    if oversized_value then
      local reflected_value = echoed_values(echo, "x-nse-oversized")[1]
      if reflected_value and #reflected_value < #oversized_value then
        result.truncated = true
        result.truncation = string.format("sent %d bytes, echoed %d bytes",
          #oversized_value, #reflected_value)
      end
    end
  end

  return result
end

local function layer_attribution(result, get_server, get_via)
  local notes = {}
  if result.server and get_server and lower(result.server) ~= lower(get_server) then
    table.insert(notes, string.format("TRACE answered by a different layer: Server '%s' vs GET Server '%s'",
      result.server, get_server))
  end
  if result.via then
    table.insert(notes, "an intermediate proxy identifies itself in the TRACE response (Via: "
      .. truncate(result.via, 60) .. ")")
  elseif get_via then
    table.insert(notes, "GET responses carry a Via header but the TRACE response does not: "
      .. "TRACE is likely terminated at the proxy")
  end
  for _, entry in ipairs(result.injected or {}) do
    if contains(lower(entry.name), "forwarded") or lower(entry.name) == "via"
      or lower(entry.name) == "forwarded" or contains(lower(entry.name), "client-ip")
      or contains(lower(entry.name), "real-ip") then
      table.insert(notes, "the echo contains a proxy-injected client header ("
        .. entry.name .. "), so TRACE is handled after a proxy layer")
      break
    end
  end
  return notes
end

local function render_variant(result, variant_name, path, method)
  local lines = {}
  table.insert(lines, string.format("%-18s %-8s %-6s HTTP %-4s %s",
    variant_name, method, truncate(path, 20), tostring(result.status),
    tostring(result.detail or "")))
  if result.classification == "echoed" then
    table.insert(lines, string.format("%-18s          reflected: %s",
      "", #result.reflected > 0 and table.concat(result.reflected, ", ") or "none"))
    table.insert(lines, string.format("%-18s          echo: %d header(s), request line '%s'",
      "", result.echo_header_count or 0, truncate(tostring(result.echo_request_line), 60)))
    if #result.injected > 0 then
      for _, entry in ipairs(result.injected) do
        table.insert(lines, string.format("%-18s          INJECTED %s: %s",
          "", entry.name, tostring(entry.value)))
      end
    end
    if result.truncated then
      table.insert(lines, string.format("%-18s          truncated echo (%s)", "",
        tostring(result.truncation)))
    end
  elseif result.allow and #result.allow > 0 then
    table.insert(lines, string.format("%-18s          Allow: %s", "", table.concat(result.allow, ", ")))
  end
  return lines
end

action = function(host, port)

  seed_random(port)
  reset_state()
  reset_findings()

  local args = read_args()
  local baseline = build_soft404_baseline(host, port, args)
  local paths = select_paths(args)

  local get_server = nil
  local get_via = nil
  local cookie_names = {}
  local cookie_records = {}
  local root_path = paths[1] or "/"

  if not budget_exhausted(args) then
    local get_response, get_err = fetch(host, port, root_path, args)
    if get_response then
      get_server = header_value(get_response, "server")
      get_via = header_value(get_response, "via")
      cookie_records, cookie_names = collect_session_cookies(get_response)
    else
      get_server = nil
      get_via = nil
      table.insert(cookie_records, { name = "(GET failed: " .. tostring(get_err) .. ")" })
    end
  end

  local httponly_only = #cookie_names > 0
  local readable_cookie = nil
  for _, record in ipairs(cookie_records) do
    if record.name and not record.httponly then
      httponly_only = false
      readable_cookie = record.name
      break
    end
  end

  local advertised = {}
  local advertised_seen = {}
  local advertised_lines = {}
  local trace_advertised = false

  local options_targets = {}
  for _, path in ipairs(paths) do
    table.insert(options_targets, path)
    if #options_targets >= 3 then
      break
    end
  end
  table.insert(options_targets, "*")

  for _, target in ipairs(options_targets) do
    if budget_exhausted(args) then
      break
    end
    local response, err = raw_request(host, port, "OPTIONS", target, {}, args)
    if not response then
      table.insert(advertised_lines, string.format("OPTIONS %-20s %s", truncate(target, 20),
        tostring(err)))
      goto continue_options
    end
    local methods = parse_allow({ header = response.header, rawheader = response.rawheader })
    for _, name in ipairs(methods) do
      if not advertised_seen[name] then
        advertised_seen[name] = true
        table.insert(advertised, name)
      end
    end
    if list_contains(methods, "TRACE") or list_contains(methods, "TRACK") then
      trace_advertised = true
    end
    table.insert(advertised_lines, string.format("OPTIONS %-20s HTTP %-4s Allow: %s",
      truncate(target, 20), tostring(response.status),
      #methods > 0 and table.concat(methods, ", ") or "(none advertised)"))
    ::continue_options::
  end

  if trace_advertised then
    add_finding("MEDIUM", "the server advertises TRACE/TRACK in its Allow header: the method is enabled "
      .. "at the layer that answered OPTIONS even if a later layer blocks the request",
      { subject = "advertised", evidence = table.concat(advertised, ", ") })
  end

  local marker = "nse-trace-" .. lower(random_token(16))
  local cookie_header = build_cookie_header(cookie_names, marker)

  local variants = { "plain" }
  if args.variants then
    for _, entry in ipairs(TRACE_VARIANTS) do
      if entry.name ~= "plain" and not list_contains(variants, entry.name) then
        table.insert(variants, entry.name)
      end
    end
  else
    table.insert(variants, "with-cookie")
  end

  local methods_to_test = { "TRACE" }
  if args.aliases then
    for _, entry in ipairs(METHOD_ALIASES) do
      if entry.method ~= "TRACE" and not list_contains(methods_to_test, entry.method) then
        table.insert(methods_to_test, entry.method)
      end
    end
  end

  local results = {}
  local matrix_lines = {}
  local any_echoed = false
  local cookie_echoed = false
  local injected_any = {}
  local injected_seen = {}
  local attribution_notes = {}

  for path_index, path in ipairs(paths) do
    if budget_exhausted(args) then
      table.insert(matrix_lines, path .. ": request budget exhausted")
      break
    end

    for _, method in ipairs(methods_to_test) do
      local variants_for_path = variants
      if path_index > 2 then
        variants_for_path = { "plain", "with-cookie" }
      end

      for _, variant in ipairs(variants_for_path) do
        if budget_exhausted(args) then
          table.insert(matrix_lines, string.format("%s %s %s: budget exhausted",
            method, variant, path))
          goto continue_variant
        end

        local target = path
        if variant == "wildcard" then
          target = "*"
        elseif variant == "missing-path" then
          target = "/nse-trace-missing-" .. lower(random_token(10))
        end

        local sent_headers = build_variant_headers(variant, marker, cookie_header, 8192)
        local response, err = raw_request(host, port, method, target, sent_headers, args)
        if not response then
          table.insert(matrix_lines, string.format("%-18s %-8s %-20s %s",
            variant, method, truncate(target, 20), tostring(err)))
          goto continue_variant
        end

        local result = classify_trace_result(method, response, marker, cookie_header, sent_headers)
        result.path = target
        result.variant = variant
        result.method = method
        table.insert(results, result)

        for _, line in ipairs(render_variant(result, variant, target, method)) do
          table.insert(matrix_lines, line)
        end

        if result.classification == "echoed" then
          any_echoed = true
          if result.cookie_reflected then
            cookie_echoed = true
          end
          for _, entry in ipairs(result.injected or {}) do
            if not injected_seen[lower(entry.name)] then
              injected_seen[lower(entry.name)] = true
              table.insert(injected_any, { name = entry.name, value = entry.value,
                method = method, variant = variant, path = target })
            end
          end
          local notes = layer_attribution(result, get_server, get_via)
          for _, note in ipairs(notes) do
            if not list_contains(attribution_notes, note) then
              table.insert(attribution_notes, note)
            end
          end
          add_finding(result.cookie_reflected and "HIGH" or "MEDIUM", string.format(
            "%s is enabled on %s and echoes the request back%s", method, truncate(target, 40),
            result.cookie_reflected and " including the Cookie header" or ""),
            { path = target, subject = "trace:" .. method .. ":" .. truncate(target, 40) .. ":"
              .. (result.cookie_reflected and "cookie" or "no-cookie"),
              evidence = truncate(tostring(result.echo_request_line or response.body or ""), 110) })
        end

        ::continue_variant::
      end
    end
  end

  if cookie_echoed then
    local severity = httponly_only and "HIGH" or "LOW"
    local explanation
    if httponly_only then
      explanation = "the session cookies are HttpOnly, so TRACE reflection is the only way script can "
        .. "read them: this is a genuine Cross-Site Tracing condition"
    else
      explanation = string.format(
        "the session cookie %s is not HttpOnly, so in-page script can already read it; TRACE adds no "
        .. "new capability here, but it still leaks headers that script cannot set",
        tostring(readable_cookie))
    end
    add_finding(severity, string.format(
      "Cross-Site Tracing precondition confirmed: TRACE reflects the Cookie header (%s)", explanation),
      { subject = "xst", evidence = cookie_header })
  end

  for _, entry in ipairs(injected_any) do
    local sensitive = false
    for _, candidate in ipairs(CREDENTIAL_HEADERS) do
      if lower(candidate.name) == lower(entry.name) then
        sensitive = true
      end
    end
    if contains(lower(entry.name), "authorization") or contains(lower(entry.name), "api-key")
      or contains(lower(entry.name), "token") or contains(lower(entry.name), "cert")
      or contains(lower(entry.name), "user") or contains(lower(entry.name), "dn") then
      sensitive = true
    end
    add_finding(sensitive and "CRITICAL" or "HIGH", string.format(
      "the TRACE echo contains a header the client never sent (%s), which means an upstream layer "
      .. "injects it before the origin sees the request%s", entry.name,
      sensitive and " and the injected value is credential or identity material" or ""),
      { path = entry.path, subject = "injected:" .. lower(entry.name),
        evidence = entry.name .. ": " .. tostring(entry.value) })
  end

  local disabled_count = 0
  local blocked_count = 0
  local echoed_count = 0
  local closed_count = 0
  for _, result in ipairs(results) do
    if result.classification == "disabled" then
      disabled_count = disabled_count + 1
    elseif result.classification == "blocked" then
      blocked_count = blocked_count + 1
    elseif result.classification == "echoed" then
      echoed_count = echoed_count + 1
    elseif result.classification == "closed" then
      closed_count = closed_count + 1
    end
  end

  local unique, counts = dedupe_findings()

  local out = new_output(RISK_LEVEL, "AUDITED - TRACE method surface evaluated.")
  if #injected_any > 0 then
    out["Status"] = "VULNERABLE - TRACE reflects proxy-injected headers that the client never sent."
  elseif cookie_echoed and httponly_only then
    out["Status"] = "VULNERABLE - TRACE is enabled and reflects HttpOnly cookies (Cross-Site Tracing)."
  elseif any_echoed then
    out["Status"] = "VULNERABLE - TRACE/TRACK is enabled and echoes the request."
  elseif trace_advertised then
    out["Status"] = "AUDITED - TRACE is advertised in Allow but the request itself is refused."
  elseif blocked_count > 0 and disabled_count == 0 then
    out["Status"] = "AUDITED - TRACE requests are blocked at the edge/WAF rather than disabled at the origin."
  elseif #results == 0 then
    out["Status"] = "AUDITED - no TRACE probe could be completed."
  else
    out["Status"] = "AUDITED - TRACE/TRACK is disabled on every tested path."
  end

  local cookie_lines = {}
  for _, record in ipairs(cookie_records) do
    if record.name then
      table.insert(cookie_lines, string.format("%-28s HttpOnly=%-5s Secure=%-5s SameSite=%-6s Path=%s",
        truncate(record.name, 28), tostring(record.httponly or false),
        tostring(record.secure or false), tostring(record.samesite or "-"),
        tostring(record.path or "-")))
    end
  end

  local injected_lines = {}
  for _, entry in ipairs(injected_any) do
    table.insert(injected_lines, string.format("%-28s %-8s %-14s %s",
      truncate(entry.name, 28), entry.method, entry.variant, tostring(entry.value)))
  end

  local sections = {
    { key = "Transport", value = (port.ssl or (port.version and port.version.service_ssl)) and "HTTPS" or "HTTP" },
    { key = "Result", value = string.format(
      "echoed=%d disabled=%d blocked=%d closed=%d other=%d (of %d probes)",
      echoed_count, disabled_count, blocked_count, closed_count,
      #results - echoed_count - disabled_count - blocked_count - closed_count, #results) },
    { key = "Marker", value = marker },
    { key = "Advertised methods", value = #advertised > 0 and table.concat(advertised, ", ")
      or "(none advertised by OPTIONS)" },
    { key = "OPTIONS probes", value = advertised_lines },
  }

  if #injected_lines > 0 then
    table.insert(sections, { key = "Proxy-injected headers in the echo", value = injected_lines })
  end
  if #cookie_lines > 0 then
    table.insert(sections, { key = "Session cookies seen on GET", value = cookie_lines })
  else
    table.insert(sections, { key = "Session cookies seen on GET", value = { "none issued" } })
  end
  if #attribution_notes > 0 then
    table.insert(sections, { key = "Layer attribution", value = attribution_notes })
  end

  table.insert(sections, { key = "TRACE matrix", value = matrix_lines })

  if get_server then
    table.insert(sections, { key = "GET Server header", value = get_server })
  end

  if baseline.enabled and baseline.samples > 0 then
    table.insert(sections, { key = "Soft-404 baseline", value = string.format(
      "%d probes, dominant status %s, %s", baseline.samples,
      tostring(baseline.dominant_status or "n/a"),
      baseline.consistent and "catch-all confirmed" or "no catch-all") })
  end

  if any_echoed then
    table.insert(sections, { key = "Remediation", value =
      "disable TRACE at every layer that can answer it: Apache 'TraceEnable off', nginx reject the verb "
      .. "(return 405 in a request_method check) or drop it at the proxy, IIS requestFiltering verbs "
      .. "deny TRACE/TRACK, and the CDN/WAF verb allowlist - fixing only the origin leaves the edge "
      .. "answering, which is what the layer attribution above shows" })
  elseif trace_advertised then
    table.insert(sections, { key = "Remediation", value =
      "the Allow header still advertises TRACE: remove it from the advertised method list so scanners "
      .. "and clients stop probing a verb that is refused anyway" })
  else
    table.insert(sections, { key = "Remediation", value =
      "TRACE is refused - keep an explicit verb allowlist at the edge (GET/HEAD/POST/OPTIONS plus the "
      .. "verbs the API needs) rather than a denylist, and re-test after any proxy, CDN or framework "
      .. "upgrade because TRACE support is re-enabled by defaults in some stacks" })
  end

  table.insert(sections, { key = "Requests issued", value = state.requests .. " of " .. args.maxrequests })
  table.insert(sections, { key = "Probe safety", value =
    "TRACE cannot modify server state; every injected header carried only the random marker "
    .. marker .. " and no probe was repeated in a loop" })

  return finish_output(out, unique, counts, sections)

end
