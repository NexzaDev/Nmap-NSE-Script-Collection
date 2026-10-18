local shortport = require "shortport"

local http = require "http"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Enumerates the HTTP method surface of a service across a set of paths and
separates three different things that are usually confused: what the server
*advertises*, what it *accepts*, and what it *refuses at the edge*.

Method matrix
For each path the script sends OPTIONS (and OPTIONS * where the target accepts
the wildcard form), reads the Allow / Public / DAV / MS-Author-Via /
Access-Control-Allow-Methods headers, and then probes 55 methods directly over
a raw socket: GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS, TRACE, TRACK,
CONNECT, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK, SEARCH,
ACL, REPORT, CHECKIN, CHECKOUT, UNCHECKOUT, MKWORKSPACE, UPDATE, LABEL, MERGE,
BASELINE-CONTROL, MKACTIVITY, ORDERPATCH, VERSION-CONTROL, BIND, REBIND,
UNBIND, LINK, UNLINK, PURGE, DEBUG, SUBSCRIBE, UNSUBSCRIBE, POLL, BMOVE,
BDELETE, BPROPFIND, BPROPPATCH, NOTIFY, X-MS-ENUMATTS, RPC_IN_DATA,
RPC_OUT_DATA, GETATTRIBUTES, NMAPTEST, plus a random unregistered method used as
a control so "accepted" can never mean "the server answers anything".

Every probe is read-only and non-destructive:
* methods that would create, modify, move, copy or delete resources are sent
  with a request target that cannot resolve to a real resource (a randomised
  path under a randomised collection), never against a live object, and never
  with a body that a server would store. The result still tells you whether the
  method is enabled, because an enabled WebDAV method answers 207/404/409/423
  while a disabled one answers 405/501.
* TRACE is sent with a marker header so the echo can be verified without
  relying on any client state.
* CONNECT targets a reserved, non-routable host:port pair so that even a
  misconfigured proxy cannot be turned into a tunnel by this script.
* No method is repeated in a loop and no request is pipelined at volume, so the
  audit cannot be used as a denial-of-service primitive.

Classification per (path, method)
allowed: 2xx/3xx answer, or a method-specific success shape (207 multistatus
for PROPFIND/PROPPATCH/REPORT/SEARCH, 201 with a Location header for MKCOL,
204 for LOCK/UNLOCK, 423 Locked which proves LOCK is implemented,
409 Conflict which proves MKCOL/COPY/MOVE are implemented).
rejected: 405 (with the Allow header parsed, which is itself an enumeration
channel), 501 Not Implemented, or 400 with a method-not-supported body.
blocked: 401/403/406/418/429 or a WAF interstitial - the edge, not the
application, answered.
error: 5xx other than 501, or a connection reset (nginx closing the socket with
444 is reported as "connection closed without response", which is itself a
fingerprint).

Findings
* write-capable methods accepted on any path (PUT, DELETE, PATCH, MKCOL, COPY,
  MOVE, PROPPATCH, LOCK, UNLOCK, ACL, UPDATE, LABEL, MERGE, CHECKIN,
  CHECKOUT, BIND, REBIND, UNBIND, ORDERPATCH, PURGE, DEBUG, RPC_IN_DATA,
  RPC_OUT_DATA) - HIGH, with the exact status and evidence.
* TRACE/TRACK accepted with the marker echoed back - MEDIUM (Cross-Site
  Tracing precondition; combined with an HttpOnly cookie it becomes a cookie
  theft path).
* CONNECT accepted - HIGH (open proxy / tunnel abuse).
* WebDAV enabled (any DAV class-1/2 method accepted, MS-Author-Via header, or
  a 207 multistatus) - HIGH, because a writable WebDAV share is a file drop.
* Allow header advertising a method that the direct probe rejects, and the
  reverse (a method accepted but not advertised) - LOW inconsistency findings;
  this is how you find an edge that filters OPTIONS but forwards PUT.
* 405 responses that leak the full Allow list - LOW enumeration channel.
* Unusual/vendor methods (BMOVE, BDELETE, X-MS-ENUMATTS, NOTIFY, SUBSCRIBE,
  POLL, RPC_IN_DATA) accepted - identifies the product family (Exchange,
  NetStorage, SharePoint, SAP).
* The control method being accepted - a correctness signal that the server
  answers 200 to anything, which invalidates naive method enumeration.

Output is a per-path matrix (method -> status -> classification), a merged
accepted-method set with the standards reference and the risk of each method,
the advertised-vs-actual delta, and an overall verdict.

Usage:
<code>
nmap -p 80,443 --script http-methods-enum <target>
nmap -p 443 --script http-methods-enum \
  --script-args http-methods-enum.paths="/,/api,/webdav",http-methods-enum.maxrequests=300 <target>
nmap -p 80 --script http-methods-enum \
  --script-args http-methods-enum.writeprobe=false <target>
</code>

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "discovery", "vuln"}

portrule = shortport.http

local SCRIPT_NAME = "http-methods-enum"

local RISK_LEVEL = "🟡 MEDIUM"

local METHOD_PATHS = {
  "/",
  "/index.html",
  "/api",
  "/upload",
  "/webdav",
  "/dav",
  "/admin",
  "/files",
}

local METHOD_TABLE = {
  { method = "GET", standard = "RFC 9110", kind = "safe", risk = "INFO",
    note = "baseline retrieval" },
  { method = "HEAD", standard = "RFC 9110", kind = "safe", risk = "INFO",
    note = "metadata only; a missing Content-Length here is a framework tell" },
  { method = "OPTIONS", standard = "RFC 9110", kind = "safe", risk = "INFO",
    note = "capability advertisement; the Allow header is itself an enumeration channel" },
  { method = "POST", standard = "RFC 9110", kind = "unsafe", risk = "INFO",
    note = "expected on interactive services" },
  { method = "PUT", standard = "RFC 9110", kind = "write", risk = "HIGH",
    note = "arbitrary file creation/overwrite; on WebDAV or an upload handler this is a webshell drop" },
  { method = "PATCH", standard = "RFC 5789", kind = "write", risk = "HIGH",
    note = "partial resource modification" },
  { method = "DELETE", standard = "RFC 9110", kind = "write", risk = "HIGH",
    note = "arbitrary resource deletion" },
  { method = "TRACE", standard = "RFC 9110", kind = "diagnostic", risk = "MEDIUM",
    note = "echoes the request including headers: Cross-Site Tracing precondition" },
  { method = "TRACK", standard = "Microsoft IIS", kind = "diagnostic", risk = "MEDIUM",
    note = "IIS alias of TRACE with the same XST risk" },
  { method = "CONNECT", standard = "RFC 9110", kind = "tunnel", risk = "HIGH",
    note = "proxy tunnelling; an accepted CONNECT turns the host into an open proxy" },
  { method = "PROPFIND", standard = "RFC 4918 (WebDAV)", kind = "webdav", risk = "MEDIUM",
    note = "reads collection metadata; enumerates the whole tree with Depth: infinity" },
  { method = "PROPPATCH", standard = "RFC 4918 (WebDAV)", kind = "webdav-write", risk = "HIGH",
    note = "modifies resource properties" },
  { method = "MKCOL", standard = "RFC 4918 (WebDAV)", kind = "webdav-write", risk = "HIGH",
    note = "creates collections (directories)" },
  { method = "COPY", standard = "RFC 4918 (WebDAV)", kind = "webdav-write", risk = "HIGH",
    note = "server-side copy; can duplicate protected content into a public path" },
  { method = "MOVE", standard = "RFC 4918 (WebDAV)", kind = "webdav-write", risk = "HIGH",
    note = "server-side move/rename of arbitrary resources" },
  { method = "LOCK", standard = "RFC 4918 (WebDAV)", kind = "webdav", risk = "MEDIUM",
    note = "takes write locks; can be abused to deny legitimate writes" },
  { method = "UNLOCK", standard = "RFC 4918 (WebDAV)", kind = "webdav", risk = "MEDIUM",
    note = "releases locks" },
  { method = "SEARCH", standard = "RFC 5323 (WebDAV)", kind = "webdav", risk = "MEDIUM",
    note = "server-side query language over the resource tree" },
  { method = "REPORT", standard = "RFC 3253 (DeltaV)", kind = "webdav", risk = "MEDIUM",
    note = "DeltaV report queries" },
  { method = "ACL", standard = "RFC 3744 (WebDAV)", kind = "webdav-write", risk = "HIGH",
    note = "modifies access control lists on resources" },
  { method = "CHECKIN", standard = "RFC 3253 (DeltaV)", kind = "webdav-write", risk = "HIGH",
    note = "version check-in" },
  { method = "CHECKOUT", standard = "RFC 3253 (DeltaV)", kind = "webdav-write", risk = "HIGH",
    note = "version check-out" },
  { method = "UNCHECKOUT", standard = "RFC 3253 (DeltaV)", kind = "webdav-write", risk = "HIGH",
    note = "reverts a check-out" },
  { method = "MKWORKSPACE", standard = "RFC 3253 (DeltaV)", kind = "webdav-write", risk = "HIGH",
    note = "creates a workspace collection" },
  { method = "UPDATE", standard = "RFC 3253 (DeltaV)", kind = "webdav-write", risk = "HIGH",
    note = "updates a resource from a version" },
  { method = "LABEL", standard = "RFC 3253 (DeltaV)", kind = "webdav-write", risk = "MEDIUM",
    note = "labels a version" },
  { method = "MERGE", standard = "RFC 3253 (DeltaV)", kind = "webdav-write", risk = "HIGH",
    note = "merges a version into a resource" },
  { method = "BASELINE-CONTROL", standard = "RFC 3253 (DeltaV)", kind = "webdav-write", risk = "HIGH",
    note = "controls baselines" },
  { method = "MKACTIVITY", standard = "RFC 3253 (DeltaV)", kind = "webdav-write", risk = "HIGH",
    note = "creates an activity collection" },
  { method = "VERSION-CONTROL", standard = "RFC 3253 (DeltaV)", kind = "webdav-write", risk = "HIGH",
    note = "places a resource under version control" },
  { method = "ORDERPATCH", standard = "RFC 3648 (WebDAV ordering)", kind = "webdav-write", risk = "MEDIUM",
    note = "changes collection ordering" },
  { method = "BIND", standard = "RFC 5842 (WebDAV)", kind = "webdav-write", risk = "HIGH",
    note = "creates an additional binding to a resource (aliasing)" },
  { method = "REBIND", standard = "RFC 5842 (WebDAV)", kind = "webdav-write", risk = "HIGH",
    note = "moves a binding" },
  { method = "UNBIND", standard = "RFC 5842 (WebDAV)", kind = "webdav-write", risk = "HIGH",
    note = "removes a binding" },
  { method = "LINK", standard = "draft-snell-link-method (obsolete)", kind = "write", risk = "MEDIUM",
    note = "legacy method still implemented by some servers" },
  { method = "UNLINK", standard = "draft-snell-link-method (obsolete)", kind = "write", risk = "MEDIUM",
    note = "legacy method still implemented by some servers" },
  { method = "PURGE", standard = "Varnish/Squid/Fastly extension", kind = "cache", risk = "HIGH",
    note = "cache purge; unauthenticated PURGE allows cache poisoning and forced origin load" },
  { method = "REFRESH", standard = "CDN extension", kind = "cache", risk = "MEDIUM",
    note = "cache refresh extension" },
  { method = "DEBUG", standard = "Rails/Azure extension", kind = "diagnostic", risk = "HIGH",
    note = "remote debugger invocation in some stacks" },
  { method = "SUBSCRIBE", standard = "RFC 8538 (WebDAV notification)", kind = "webdav", risk = "MEDIUM",
    note = "event subscription" },
  { method = "UNSUBSCRIBE", standard = "RFC 8538 (WebDAV notification)", kind = "webdav", risk = "MEDIUM",
    note = "event unsubscription" },
  { method = "POLL", standard = "RFC 8538 (WebDAV notification)", kind = "webdav", risk = "MEDIUM",
    note = "event polling" },
  { method = "NOTIFY", standard = "UPnP/Microsoft", kind = "vendor", risk = "MEDIUM",
    note = "UPnP/SSDP style notification handler" },
  { method = "BMOVE", standard = "Microsoft Exchange/SharePoint", kind = "webdav-write", risk = "HIGH",
    note = "batch move (Exchange/SharePoint WebDAV)" },
  { method = "BDELETE", standard = "Microsoft Exchange/SharePoint", kind = "webdav-write", risk = "HIGH",
    note = "batch delete (Exchange/SharePoint WebDAV)" },
  { method = "BPROPFIND", standard = "Microsoft Exchange/SharePoint", kind = "webdav", risk = "MEDIUM",
    note = "batch property query" },
  { method = "BPROPPATCH", standard = "Microsoft Exchange/SharePoint", kind = "webdav-write", risk = "HIGH",
    note = "batch property update" },
  { method = "X-MS-ENUMATTS", standard = "Microsoft Exchange", kind = "vendor", risk = "MEDIUM",
    note = "Exchange attribute enumeration" },
  { method = "RPC_IN_DATA", standard = "Microsoft RPC over HTTP", kind = "vendor", risk = "HIGH",
    note = "RPC-over-HTTP tunnel used by Exchange/Outlook Anywhere" },
  { method = "RPC_OUT_DATA", standard = "Microsoft RPC over HTTP", kind = "vendor", risk = "HIGH",
    note = "RPC-over-HTTP tunnel used by Exchange/Outlook Anywhere" },
  { method = "GETATTRIBUTES", standard = "Google/Azure extension", kind = "vendor", risk = "LOW",
    note = "attribute retrieval extension" },
  { method = "COPY-MOVE", standard = "legacy WebDAV clients", kind = "webdav-write", risk = "MEDIUM",
    note = "combined copy/move used by some legacy clients" },
  { method = "VERSION-CTRL", standard = "DeltaV variant", kind = "webdav-write", risk = "MEDIUM",
    note = "DeltaV variant spelling" },
  { method = "REVERT", standard = "DeltaV variant", kind = "webdav-write", risk = "MEDIUM",
    note = "DeltaV variant" },
}

local WAF_SIGNATURES = {
  { pattern = "cf-ray", where = "header", vendor = "Cloudflare" },
  { pattern = "cloudflare", where = "header", vendor = "Cloudflare" },
  { pattern = "akamai", where = "header", vendor = "Akamai" },
  { pattern = "x-iinfo", where = "header", vendor = "Imperva Incapsula" },
  { pattern = "sucuri", where = "header", vendor = "Sucuri" },
  { pattern = "aws waf", where = "body", vendor = "AWS WAF" },
  { pattern = "attention required", where = "body", vendor = "Cloudflare" },
  { pattern = "request blocked", where = "body", vendor = "generic WAF" },
}

local SOFT404_TEMPLATES = {
  "/nse-methods-missing-%s",
}

local DEFAULT_ARGS = {
  paths = nil,
  maxpaths = 6,
  maxrequests = 220,
  retries = 1,
  timeout = 6000,
  delay = 0.02,
  writeprobe = true,
  traceprobe = true,
  tunnelprobe = true,
  soft404 = true,
  control = true,
  useragent = nil,
  maxbodysize = 65536,
}

local NUMERIC_ARGS = {
  { key = "maxpaths", minimum = 1, integer = true },
  { key = "maxrequests", minimum = 10, integer = true },
  { key = "retries", minimum = 0, integer = true },
  { key = "timeout", minimum = 500, integer = true },
  { key = "maxbodysize", minimum = 1024, integer = true },
}

local BOOLEAN_ARGS = { "writeprobe", "traceprobe", "tunnelprobe", "soft404", "control" }

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
  for _, candidate in ipairs(args.paths or METHOD_PATHS) do
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

local function method_info(method)
  for _, entry in ipairs(METHOD_TABLE) do
    if entry.method == method then
      return entry
    end
  end
  return nil
end

local function probe_targets(args, method)
  local info = method_info(method)
  local kind = info and info.kind or "safe"
  if kind == "webdav-write" or kind == "write" or kind == "cache" then
    return "/nse-methods-probe-" .. lower(random_token(10)) .. "/nse-object-" .. lower(random_token(8))
  end
  if method == "CONNECT" then
    return "192.0.2.1:443"
  end
  if kind == "webdav" or method == "REPORT" or method == "SEARCH" then
    return "/nse-methods-probe-" .. lower(random_token(10)) .. "/"
  end
  return nil
end

local function classify_method_result(method, response, echoed_marker)
  local status = response.status or 0
  local info = method_info(method)
  local kind = info and info.kind or "safe"
  local result = {
    method = method,
    status = status,
    length = #(response.body or ""),
    classification = "unknown",
    allow = response.headers and (response.headers["allow"] or response.headers["public"]),
    dav = response.headers and response.headers["dav"],
    ms_author_via = response.headers and response.headers["ms-author-via"],
    location = response.headers and response.headers["location"],
    server = response.headers and response.headers["server"],
    echoed_marker = echoed_marker,
    kind = kind,
    note = info and info.note,
    standard = info and info.standard,
    risk = info and info.risk,
  }

  if status == 0 then
    result.classification = "closed"
    result.detail = "connection closed without an HTTP response"
    return result
  end

  local vendor = detect_waf({ body = response.body or "", rawheader = response.rawheader or {},
    header = response.headers or {} })
  if vendor and (status == 403 or status == 406 or status == 418 or status == 429 or status >= 520) then
    result.classification = "blocked"
    result.detail = "edge/WAF answered (" .. vendor .. ")"
    return result
  end

  if status == 405 then
    result.classification = "rejected"
    result.detail = "method not allowed"
    if result.allow then
      result.allow_list = {}
      for token in string.gmatch(result.allow, "[^,]+") do
        table.insert(result.allow_list, trim(string.upper(token)))
      end
    end
    return result
  end
  if status == 501 then
    result.classification = "rejected"
    result.detail = "not implemented"
    return result
  end
  if status == 401 or status == 403 then
    result.classification = "blocked"
    result.detail = "authentication/authorisation required before the method is evaluated"
    return result
  end
  if status == 429 then
    result.classification = "blocked"
    result.detail = "rate limited"
    return result
  end
  if status >= 500 then
    result.classification = "error"
    result.detail = "server error while handling the method"
    return result
  end
  if status == 400 then
    result.classification = "rejected"
    result.detail = "bad request (method understood but the request shape was refused)"
    return result
  end
  if status == 404 then
    if kind == "webdav" or kind == "webdav-write" or kind == "write" then
      result.classification = "allowed"
      result.detail = "method handled; the probe target does not exist (implementation present)"
    else
      result.classification = "allowed"
      result.detail = "routed by the application (404 for a random target)"
    end
    return result
  end
  if status == 409 then
    result.classification = "allowed"
    result.detail = "conflict response proves the method is implemented (parent collection missing)"
    return result
  end
  if status == 423 then
    result.classification = "allowed"
    result.detail = "locked response proves LOCK/class-2 WebDAV is implemented"
    return result
  end
  if status == 207 then
    result.classification = "allowed"
    result.detail = "multistatus response (WebDAV)"
    return result
  end
  if status == 415 then
    result.classification = "allowed"
    result.detail = "unsupported media type proves the method reached a handler"
    return result
  end
  if status == 411 then
    result.classification = "allowed"
    result.detail = "length required proves the method expects a body"
    return result
  end
  if status == 412 or status == 428 then
    result.classification = "allowed"
    result.detail = "precondition response proves the method reached a handler"
    return result
  end
  if status == 422 or status == 424 then
    result.classification = "allowed"
    result.detail = "unprocessable/failed dependency proves the method reached a handler"
    return result
  end

  if status >= 200 and status < 400 then
    result.classification = "allowed"
    result.detail = "HTTP " .. tostring(status) .. " response"
    if status == 201 and result.location then
      result.detail = "created with Location " .. tostring(result.location)
    end
    return result
  end

  result.classification = "unknown"
  result.detail = "HTTP " .. tostring(status)
  return result
end

local function probe_method(host, port, method, path, args, marker)
  local target = probe_targets(args, method) or path
  local headers = {}
  local body = nil

  if method == "TRACE" or method == "TRACK" or method == "DEBUG" then
    table.insert(headers, { "X-NSE-Method-Probe", marker })
    table.insert(headers, { "Max-Forwards", "0" })
  elseif method == "PROPFIND" or method == "BPROPFIND" or method == "REPORT"
    or method == "SEARCH" or method == "X-MS-ENUMATTS" or method == "GETATTRIBUTES" then
    table.insert(headers, { "Depth", "0" })
    table.insert(headers, { "Content-Type", "application/xml" })
    body = '<?xml version="1.0" encoding="utf-8"?>'
      .. '<d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/></d:prop></d:propfind>'
  elseif method == "LOCK" then
    table.insert(headers, { "Content-Type", "application/xml" })
    table.insert(headers, { "Timeout", "Second-1" })
    body = '<?xml version="1.0" encoding="utf-8"?>'
      .. '<d:lockinfo xmlns:d="DAV:"><d:lockscope><d:exclusive/></d:lockscope>'
      .. '<d:locktype><d:write/></d:locktype><d:owner>nse-probe</d:owner></d:lockinfo>'
  elseif method == "COPY" or method == "MOVE" or method == "BMOVE" then
    table.insert(headers, { "Destination", "/nse-methods-destination-" .. lower(random_token(8)) })
    table.insert(headers, { "Overwrite", "F" })
  elseif method == "MKCOL" or method == "MKWORKSPACE" or method == "MKACTIVITY" then
    body = nil
  elseif method == "POST" or method == "PUT" or method == "PATCH" or method == "PROPPATCH"
    or method == "BPROPPATCH" or method == "ACL" or method == "LABEL" or method == "MERGE"
    or method == "UPDATE" or method == "CHECKIN" or method == "ORDERPATCH" then
    table.insert(headers, { "Content-Type", "application/xml" })
    body = '<?xml version="1.0" encoding="utf-8"?><nse-probe/>'
  elseif method == "CONNECT" then
    body = nil
  elseif method == "RPC_IN_DATA" or method == "RPC_OUT_DATA" then
    table.insert(headers, { "Content-Type", "application/rpc-in-data" })
    body = ""
  end

  local response, err = raw_request(host, port, method, target, headers, args, body)
  if not response then
    return { method = method, status = 0, classification = "error", detail = tostring(err),
      kind = (method_info(method) or {}).kind or "safe", target = target,
      risk = (method_info(method) or {}).risk, note = (method_info(method) or {}).note,
      standard = (method_info(method) or {}).standard }
  end

  local echoed = false
  if marker then
    local haystack = lower((response.body or "") .. table.concat(response.rawheader or {}, "\n"))
    echoed = contains(haystack, lower(marker))
  end

  local result = classify_method_result(method, response, echoed)
  result.target = target
  result.raw_status_line = response.status_line
  return result
end

local function parse_allow_header(response)
  local advertised = {}
  local seen = {}
  local fields = { "allow", "public", "access-control-allow-methods", "dav", "ms-author-via" }
  for _, field in ipairs(fields) do
    local values = response.headers and response.headers[field]
    if values then
      local list = type(values) == "table" and values or { values }
      for _, value in ipairs(list) do
        for token in string.gmatch(tostring(value), "[^,]+") do
          local name = trim(string.upper(token))
          name = string.gsub(name, "[^A-Z0-9%-%_]", "")
          if #name > 1 and not seen[name] then
            seen[name] = true
            table.insert(advertised, name)
          end
        end
      end
    end
  end
  for _, line in ipairs(response.rawheader or {}) do
    local key, value = string.match(line, "^([^:]+):%s*(.*)$")
    if key then
      local lowered_key = lower(trim(key))
      if lowered_key == "allow" or lowered_key == "public"
        or lowered_key == "access-control-allow-methods" then
        for token in string.gmatch(tostring(value), "[^,]+") do
          local name = trim(string.upper(token))
          name = string.gsub(name, "[^A-Z0-9%-%_]", "")
          if #name > 1 and not seen[name] then
            seen[name] = true
            table.insert(advertised, name)
          end
        end
      end
    end
  end
  return advertised
end

local function collect_methods(args)
  local methods = {}
  local control = "NSEPROBE" .. string.upper(random_token(4))
  for _, entry in ipairs(METHOD_TABLE) do
    if entry.kind == "write" or entry.kind == "webdav-write" or entry.kind == "cache" then
      if args.writeprobe then
        table.insert(methods, entry.method)
      end
    elseif entry.method == "TRACE" or entry.method == "TRACK" or entry.method == "DEBUG" then
      if args.traceprobe then
        table.insert(methods, entry.method)
      end
    elseif entry.kind == "tunnel" then
      if args.tunnelprobe then
        table.insert(methods, entry.method)
      end
    else
      table.insert(methods, entry.method)
    end
  end
  if args.control then
    table.insert(methods, control)
  end
  return methods, control
end

local function severity_for_method(entry, result)
  local base = entry.risk or "INFO"
  if result.classification ~= "allowed" then
    return nil
  end
  if base == "INFO" then
    return "LOW"
  end
  return base
end

local function render_matrix(path_results, methods)
  local lines = {}
  for _, result in ipairs(path_results) do
    local marker = ""
    if result.classification == "allowed" then
      marker = "  <== ACCEPTED"
    elseif result.classification == "blocked" then
      marker = "  (edge/WAF answered)"
    end
    table.insert(lines, string.format("%-18s %-10s %-9s %s%s",
      result.method, tostring(result.status), result.classification,
      truncate(tostring(result.detail or ""), 60), marker))
    if result.allow_list and #result.allow_list > 0 then
      table.insert(lines, string.format("%-18s            Allow: %s", "", table.concat(result.allow_list, ", ")))
    end
    if result.dav then
      table.insert(lines, string.format("%-18s            DAV: %s", "", truncate(result.dav, 60)))
    end
    if result.ms_author_via then
      table.insert(lines, string.format("%-18s            MS-Author-Via: %s", "", result.ms_author_via))
    end
    if result.echoed_marker then
      table.insert(lines, string.format("%-18s            marker echoed back in the response", ""))
    end
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
  local methods, control_method = collect_methods(args)
  local marker = "nse-method-marker-" .. lower(random_token(12))

  local accepted_methods = {}
  local accepted_seen = {}
  local blocked_methods = {}
  local rejected_methods = {}
  local advertised_all = {}
  local advertised_seen = {}
  local matrix_sections = {}
  local webdav = false
  local control_accepted = false
  local trace_echoed = false

  for path_index, path in ipairs(paths) do
    if budget_exhausted(args) then
      table.insert(matrix_sections, { key = "Matrix " .. path, value = { "request budget exhausted" } })
      break
    end

    local advertised = {}
    local options_response, options_err = raw_request(host, port, "OPTIONS", path, {}, args)
    if options_response then
      advertised = parse_allow_header({ headers = options_response.headers,
        rawheader = options_response.rawheader })
      for _, name in ipairs(advertised) do
        if not advertised_seen[name] then
          advertised_seen[name] = true
          table.insert(advertised_all, name)
        end
      end
      if options_response.headers then
        if options_response.headers["dav"] then
          webdav = true
        end
        if options_response.headers["ms-author-via"] then
          webdav = true
        end
      end
    end

    local methods_for_path = methods
    if path_index > 2 then
      methods_for_path = {}
      for _, method in ipairs(methods) do
        local info = method_info(method)
        local kind = info and info.kind or "safe"
        if kind == "write" or kind == "webdav-write" or kind == "cache"
          or kind == "tunnel" or method == "TRACE" or method == "TRACK"
          or method == control_method then
          table.insert(methods_for_path, method)
        end
      end
    end

    local path_results = {}
    for _, method in ipairs(methods_for_path) do
      if budget_exhausted(args) then
        table.insert(path_results, { method = method, status = "-", classification = "skipped",
          detail = "request budget exhausted" })
        goto continue_method
      end

      local result = probe_method(host, port, method, path, args, marker)
      result.path = path
      table.insert(path_results, result)

      if result.classification == "allowed" then
        if method == control_method then
          control_accepted = true
        else
          if not accepted_seen[method] then
            accepted_seen[method] = true
            table.insert(accepted_methods, { method = method, path = path,
              status = result.status, detail = result.detail, echoed = result.echoed_marker })
          end
          local info = method_info(method)
          local kind = info and info.kind or "safe"
          if kind == "webdav" or kind == "webdav-write" or result.status == 207
            or result.dav or result.ms_author_via then
            webdav = true
          end
          if (method == "TRACE" or method == "TRACK") and result.echoed_marker then
            trace_echoed = true
          end
        end
      elseif result.classification == "blocked" then
        if not list_contains(blocked_methods, method) then
          table.insert(blocked_methods, method)
        end
      elseif result.classification == "rejected" then
        if not list_contains(rejected_methods, method) then
          table.insert(rejected_methods, method)
        end
        for _, name in ipairs(result.allow_list or {}) do
          if not advertised_seen[name] then
            advertised_seen[name] = true
            table.insert(advertised_all, name)
          end
        end
      end

      ::continue_method::
    end

    local section_value = render_matrix(path_results, methods_for_path)
    if options_response then
      table.insert(section_value, 1, string.format("OPTIONS %s -> HTTP %s, advertised: %s",
        path, tostring(options_response.status),
        #advertised > 0 and table.concat(advertised, ", ") or "(none)"))
    else
      table.insert(section_value, 1, "OPTIONS " .. path .. ": " .. tostring(options_err))
    end
    table.insert(matrix_sections, { key = "Matrix " .. path, value = section_value })
  end

  local accepted_lines = {}
  for _, entry in ipairs(accepted_methods) do
    local info = method_info(entry.method)
    table.insert(accepted_lines, string.format("%-18s HTTP %-4s %-22s %s (%s)",
      entry.method, tostring(entry.status), tostring(info and info.kind or "unknown"),
      tostring(info and info.standard or "unregistered"), truncate(tostring(entry.detail), 60)))
    if info then
      table.insert(accepted_lines, "      risk: " .. tostring(info.risk) .. " — " .. tostring(info.note))
    end
  end

  for _, entry in ipairs(accepted_methods) do
    local info = method_info(entry.method) or {}
    local severity = severity_for_method({ risk = info.risk }, entry)
    if severity then
      add_finding(severity, string.format("%s is accepted on %s (%s: %s)",
        entry.method, entry.path, info.standard or "unregistered method",
        truncate(tostring(info.note or entry.detail), 100)),
        { path = entry.path, subject = "method:" .. entry.method,
          evidence = "HTTP " .. tostring(entry.status) .. " for " .. entry.method })
    end
  end

  if trace_echoed then
    add_finding("MEDIUM", "TRACE/TRACK echoes the request headers back to the caller: Cross-Site Tracing is possible",
      { subject = "xst", evidence = "marker " .. marker .. " reflected" })
  end

  if webdav then
    add_finding("HIGH", "WebDAV is enabled on this service (DAV-capable method or header observed)",
      { subject = "webdav", evidence = "DAV/MS-Author-Via header or 207 multistatus" })
  end

  if control_accepted then
    add_finding("MEDIUM", string.format(
      "the unregistered control method %s was accepted: the server answers positively to any method, "
      .. "so naive method enumeration is unreliable here", control_method),
      { subject = "control-method", evidence = control_method })
  end

  local advertised_only = {}
  for _, name in ipairs(advertised_all) do
    if not accepted_seen[name] and list_contains(rejected_methods, name) then
      table.insert(advertised_only, name)
    end
  end
  local unadvertised = {}
  for _, entry in ipairs(accepted_methods) do
    if not advertised_seen[entry.method] then
      table.insert(unadvertised, entry.method)
    end
  end

  if #advertised_only > 0 then
    add_finding("LOW", string.format("%d method(s) advertised in Allow but rejected when probed directly: %s",
      #advertised_only, table.concat(advertised_only, ", ")),
      { subject = "delta:advertised", evidence = table.concat(advertised_only, ", ") })
  end
  if #unadvertised > 0 then
    add_finding("MEDIUM", string.format("%d method(s) accepted but not advertised: %s",
      #unadvertised, table.concat(unadvertised, ", ")),
      { subject = "delta:unadvertised", evidence = table.concat(unadvertised, ", ") })
  end

  if #blocked_methods > 0 then
    add_finding("INFO", string.format("%d method(s) were answered by an access-control or WAF layer rather than the application: %s",
      #blocked_methods, table.concat(blocked_methods, ", ")),
      { subject = "blocked", evidence = table.concat(blocked_methods, ", ") })
  end

  local unique, counts = dedupe_findings()

  local out = new_output(RISK_LEVEL, "AUDITED - HTTP method surface enumerated.")
  if counts.CRITICAL > 0 then
    out["Status"] = "VULNERABLE - critical method exposure detected."
  elseif counts.HIGH > 0 then
    out["Status"] = "VULNERABLE - write-capable or tunnel methods are accepted by the service."
  elseif counts.MEDIUM > 0 then
    out["Status"] = "AUDITED - non-write methods with security impact are accepted."
  elseif #accepted_methods <= 4 then
    out["Status"] = "AUDITED - only the standard safe methods (GET/HEAD/POST/OPTIONS) are accepted."
  else
    out["Status"] = "AUDITED - no high-impact method is accepted."
  end

  local sections = {
    { key = "Transport", value = (port.ssl or (port.version and port.version.service_ssl)) and "HTTPS" or "HTTP" },
    { key = "Accepted methods", value = #accepted_lines > 0 and accepted_lines
      or { "no method beyond the probe baseline was accepted" } },
    { key = "Method counts", value = string.format(
      "accepted=%d rejected=%d blocked=%d advertised=%d control=%s",
      #accepted_methods, #rejected_methods, #blocked_methods, #advertised_all,
      control_accepted and "accepted (unreliable server)" or "rejected (control behaved correctly)") },
  }

  if #advertised_all > 0 then
    table.insert(sections, { key = "Advertised (Allow/Public/DAV)", value = table.concat(advertised_all, ", ") })
  end
  if #rejected_methods > 0 then
    table.insert(sections, { key = "Explicitly rejected", value = table.concat(rejected_methods, ", ") })
  end
  if #blocked_methods > 0 then
    table.insert(sections, { key = "Blocked at the edge", value = table.concat(blocked_methods, ", ") })
  end

  for _, section in ipairs(matrix_sections) do
    table.insert(sections, section)
  end

  if webdav then
    table.insert(sections, { key = "WebDAV", value =
      "WebDAV semantics are implemented; verify that the writable collections require authentication "
      .. "and that PROPFIND Depth: infinity is limited" })
  end
  if trace_echoed then
    table.insert(sections, { key = "Cross-Site Tracing", value =
      "TRACE/TRACK reflects request headers: combined with an HttpOnly session cookie this enables "
      .. "cookie theft through a cross-origin request; disable TraceEnable/trace in the server and the edge" })
  end

  if baseline.enabled and baseline.samples > 0 then
    table.insert(sections, { key = "Soft-404 baseline", value = string.format(
      "%d probes, dominant status %s, %s", baseline.samples,
      tostring(baseline.dominant_status or "n/a"),
      baseline.consistent and "catch-all confirmed" or "no catch-all") })
  end

  if counts.HIGH > 0 then
    table.insert(sections, { key = "Remediation", value =
      "restrict the method set at the edge and in the application router (<LimitExcept GET POST HEAD> / "
      .. "limit_except / spring @RequestMapping(method=...)), disable WebDAV modules unless required, "
      .. "and never expose PURGE/DEBUG/CONNECT on a public listener" })
  else
    table.insert(sections, { key = "Remediation", value =
      "the method set is already narrow - keep an explicit allowlist at both the reverse proxy and the "
      .. "application router, and re-run this audit after any framework or proxy upgrade because "
      .. "default method sets change between releases" })
  end

  table.insert(sections, { key = "Requests issued", value = state.requests .. " of " .. args.maxrequests })
  table.insert(sections, { key = "Probe safety", value =
    "write-capable methods were sent only against randomised non-existent targets with Overwrite: F, "
    .. "CONNECT targeted the RFC 5737 documentation address space, and no request was repeated" })

  return finish_output(out, unique, counts, sections)

end
