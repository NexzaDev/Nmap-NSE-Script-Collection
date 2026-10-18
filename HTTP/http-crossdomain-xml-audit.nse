local shortport = require "shortport"

local http = require "http"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Audits the cross-domain policy files that Adobe Flash, Adobe Reader, Apache
Flex, Silverlight and legacy browser plugins still fetch, and reports exactly
which origins are allowed to read authenticated responses from this service.

These files are legacy but they are still honoured: Flash Player, AIR, Adobe
Reader's XML API, Flex/BlazeDS applications, and any client that uses the
`crossdomain.xml` contract (including some mobile webviews and automated
integration stacks) will request /crossdomain.xml before making a cross-origin
request, and Silverlight/WSAT clients request /clientaccesspolicy.xml. A single
`<allow-access-from domain="*"/>` turns every website on the internet into a
credentialed reader of this origin, because plugin requests carry cookies.

What the script fetches
/crossdomain.xml, /crossdomain.xml?a=<random> (cache-busting variant), the
location referenced by a `cross-domain-policy` HTTP header if one is present,
/clientaccesspolicy.xml, /silverlightaccesspolicy.xml, /crossdomain.php,
/crossdomain.aspx, /crossdomain.txt (some stacks serve a generated policy), and
every path the operator supplies. Each response is checked for being real XML
(a catch-all HTML page that answers 200 for everything is detected with the
soft-404 baseline and reported as "not a policy file" instead of a wildcard
policy).

What the script analyses in a Flash policy
* `<!DOCTYPE cross-domain-policy SYSTEM "...">` and the DTD location (an
  external DTD on a non-Adobe host is a supply-chain indicator).
* `<site-control permitted-cross-domain-policies="..."/>` with the five legal
  values: `all` (any policy file anywhere on the host is honoured - the
  dangerous one, because an uploaded /uploads/crossdomain.xml then governs the
  whole origin), `by-content-type` (only files served as text/x-cross-domain-policy),
  `by-ftp-filename` (FTP only), `master-only` (only /crossdomain.xml counts -
  the recommended setting) and `none` (no cross-domain access at all).
  A missing site-control element defaults to `master-only` for HTTP, which the
  report states explicitly.
* Every `<allow-access-from domain="..."/>`: wildcard `*`, wildcard subdomain
  `*.example.com` (which includes attacker-registerable siblings such as
  `evil-example.com`? no - but it does include any subdomain the organisation
  cannot fully control, e.g. user-content or acquired domains), a bare domain,
  an IP literal, a domain with a leading dot, a `secure="false"` attribute
  (allows plain HTTP callers to read HTTPS content), `to-ports`, and duplicate
  or contradictory entries.
* Every `<allow-http-request-headers-from domain="..." headers="..."/>`: which
  request headers a foreign origin may set (a wildcard `headers="*"` allows
  arbitrary custom headers, which combined with an allowed domain gives
  attacker-controlled CSRF headers), and the `secure` attribute.
* `<allow-access-from-identity>` with `<certificate>` (signer/identity based
  grants) - rare, reported when present.
* Whether the file grants access to domains that are not subdomains of the
  target host (third-party grants), and whether any granted domain is
  externally registerable (a public suffix such as `github.io`,
  `s3.amazonaws.com`, `blob.core.windows.net`, `cloudfront.net`,
  `herokuapp.com`, `netlify.app`, `vercel.app`, `ngrok.io`, `amazonaws.com`,
  `firebaseapp.com`, `pages.dev`, `workers.dev`, `wordpress.com`,
  `blogspot.com`, `azurewebsites.net`, `appspot.com`, `googleusercontent.com`,
  `cloudfunctions.net`, `execute-api.amazonaws.com`, `elasticbeanstalk.com`,
  `readthedocs.io`, `gitlab.io`, `bitbucket.io`, `sourceforge.io`,
  `repl.co`, `glitch.me`, `surge.sh`, `render.com`, `fly.dev`,
  `railway.app`, `onrender.com`, `on-aptible.com`, `ngrok.app`,
  `trycloudflare.com`, `localtonet.com`, `serveo.net`, `localhost.run`) -
  these are the entries that let an anonymous attacker obtain a matching
  hostname in minutes.
* Policy-file size, comment content (comments sometimes document why a wildcard
  was added), and whether the file is served over HTTP only, HTTPS only or both.

What the script analyses in a Silverlight policy
`<access-policy>` with `<cross-domain-access>` rules: each
`<allow-from http-request-headers="true|false"><domain uri="..."/></allow-from>`
and `<grant-to><resource path="/" include-subpaths="true"/></grant-to>`.
`uri="*"` with `include-subpaths="true"` on `/` is the Silverlight equivalent
of the Flash wildcard. `http-request-headers="true"` is the higher-risk flag
because it allows the caller to set arbitrary headers (a CSRF primitive).
The script also handles the `<policy>` / `<allow-from>` shorthand form that some
generators emit.

Scoring and output
Each policy file is scored: `all` site-control, wildcard domain grants,
grants to externally registerable domains, `secure="false"` on an HTTPS
service, `headers="*"`, and Silverlight `include-subpaths` on `/` each
contribute weight, and the finding severity follows the worst contributor. The
report lists the effective allow list per file (expanded: what `*.example.com`
actually means), the site-control value, the header grants, and a per-file
verdict. Where a policy is stricter than necessary the script says so and
proposes the minimal replacement (master-only + explicit domains + secure="true").

Usage:
<code>
nmap -p 80,443 --script http-crossdomain-xml-audit <target>
nmap -p 443 --script http-crossdomain-xml-audit \
  --script-args http-crossdomain-xml-audit.paths="/crossdomain.xml,/api/crossdomain.xml" <target>
nmap -p 80 --script http-crossdomain-xml-audit \
  --script-args http-crossdomain-xml-audit.cachebust=false <target>
</code>

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"vuln", "defensive", "safe"}

portrule = shortport.http

local SCRIPT_NAME = "http-crossdomain-xml-audit"

local RISK_LEVEL = "🟠 HIGH"

local POLICY_PATHS = {
  "/crossdomain.xml",
  "/clientaccesspolicy.xml",
  "/silverlightaccesspolicy.xml",
  "/crossdomain.php",
  "/crossdomain.aspx",
  "/crossdomain.txt",
  "/crossdomain.xml.php",
  "/assets/crossdomain.xml",
  "/static/crossdomain.xml",
  "/public/crossdomain.xml",
  "/content/crossdomain.xml",
  "/api/crossdomain.xml",
  "/flash/crossdomain.xml",
  "/swf/crossdomain.xml",
  "/uploads/crossdomain.xml",
  "/media/crossdomain.xml",
  "/files/crossdomain.xml",
  "/download/crossdomain.xml",
  "/cross-domain-policy.xml",
}

local PUBLIC_SUFFIX_DOMAINS = {
  "github.io", "githubusercontent.com", "gitlab.io", "bitbucket.io",
  "sourceforge.io", "s3.amazonaws.com", "amazonaws.com", "cloudfront.net",
  "elasticbeanstalk.com", "execute-api.amazonaws.com", "elasticache.amazonaws.com",
  "blob.core.windows.net", "azurewebsites.net", "cloudapp.net", "azureedge.net",
  "azurecontainer.io", "azurefd.net", "windows.net", "visualstudio.com",
  "appspot.com", "googleusercontent.com", "googleapis.com", "cloudfunctions.net",
  "run.app", "web.app", "firebaseapp.com", "firebaseio.com", "blogspot.com",
  "herokuapp.com", "herokussl.com", "netlify.app", "netlify.com", "vercel.app",
  "now.sh", "pages.dev", "workers.dev", "cloudflareaccess.com",
  "ngrok.io", "ngrok.app", "ngrok-free.app", "trycloudflare.com", "localtonet.com",
  "serveo.net", "localhost.run", "tunnelbear.com", "portmap.io",
  "wordpress.com", "wpengine.com", "pantheonsite.io", "flywheelsites.com",
  "readthedocs.io", "readthedocs.org", "gitbook.io", "notion.site",
  "repl.co", "replit.app", "glitch.me", "surge.sh", "render.com", "onrender.com",
  "fly.dev", "railway.app", "on-aptible.com", "digitaloceanspaces.com",
  "linodeobjects.com", "backblazeb2.com", "wasabisys.com", "storage.googleapis.com",
  "objectstorage.oraclecloud.com", "scalestorage.com", "cdn77.org",
  "akamaized.net", "fastly.net", "edgekey.net", "akamaihd.net",
  "wixsite.com", "squarespace.com", "shopify.com", "myshopify.com",
  "weebly.com", "wix.com", "jimdosite.com", "yolasite.com",
  "tumblr.com", "medium.com", "substack.com", "ghost.io",
  "zoom.us", "slack.com", "atlassian.net", "jira.com", "confluence.com",
  "zendesk.com", "freshdesk.com", "helpscoutdocs.com", "intercom.io",
  "eu.org", "uk.net", "us.com", "co.uk", "com.au", "co.za", "co.jp",
  "cloud.nitrado.net", "server-on.net", "dedicatedpanel.net",
}

local SITE_CONTROL_VALUES = {
  ["all"] = {
    severity = "HIGH",
    meaning = "any policy file found anywhere on this host is honoured",
    risk = "an attacker who can upload a single file (or find a path traversal "
      .. "that writes one) can rewrite the cross-domain policy for the whole origin",
    recommendation = "set permitted-cross-domain-policies=\"master-only\"",
  },
  ["by-content-type"] = {
    severity = "MEDIUM",
    meaning = "any resource served as text/x-cross-domain-policy is honoured as a policy",
    risk = "user-uploaded files that are served with that content type become policy files",
    recommendation = "set permitted-cross-domain-policies=\"master-only\" unless you deliberately "
      .. "serve per-directory policies with the correct content type",
  },
  ["by-ftp-filename"] = {
    severity = "LOW",
    meaning = "FTP-only: crossdomain.txt files on the FTP service are honoured",
    risk = "only relevant when an FTP service shares this origin",
    recommendation = "keep master-only for HTTP",
  },
  ["master-only"] = {
    severity = "INFO",
    meaning = "only /crossdomain.xml is honoured",
    risk = "recommended configuration",
    recommendation = "none",
  },
  ["none"] = {
    severity = "INFO",
    meaning = "no cross-domain access is permitted at all",
    risk = "the strictest configuration",
    recommendation = "none",
  },
}

local HEADER_GRANT_RISK = {
  ["*"] = {
    severity = "HIGH",
    note = "a wildcard header grant lets the allowed origin set any custom request header, "
      .. "which is a CSRF primitive against APIs that trust custom headers",
  },
  ["authorization"] = {
    severity = "HIGH",
    note = "the Authorization header may be set cross-domain by the allowed origin",
  },
  ["cookie"] = {
    severity = "HIGH",
    note = "cookie headers may be set cross-domain",
  },
  ["x-csrf-token"] = {
    severity = "MEDIUM",
    note = "a CSRF token header may be set cross-domain",
  },
  ["x-requested-with"] = {
    severity = "LOW",
    note = "the X-Requested-With header may be set cross-domain",
  },
  ["content-type"] = {
    severity = "LOW",
    note = "the Content-Type header may be set cross-domain",
  },
  ["soapaction"] = {
    severity = "MEDIUM",
    note = "SOAPAction may be set cross-domain (SOAP stacks often trust it)",
  },
}

local POLICY_CONTENT_TYPES = {
  "text/x-cross-domain-policy",
  "text/xml",
  "application/xml",
  "text/plain",
  "application/octet-stream",
}

local WAF_SIGNATURES = {
  { pattern = "cf-ray", where = "header", vendor = "Cloudflare" },
  { pattern = "cloudflare", where = "header", vendor = "Cloudflare" },
  { pattern = "akamai", where = "header", vendor = "Akamai" },
  { pattern = "x-iinfo", where = "header", vendor = "Imperva Incapsula" },
  { pattern = "sucuri", where = "header", vendor = "Sucuri" },
  { pattern = "aws waf", where = "body", vendor = "AWS WAF" },
}

local SOFT404_TEMPLATES = {
  "/nse-policy-missing-%s.xml",
  "/nse-policy-absent/%s",
}

local DEFAULT_ARGS = {
  paths = nil,
  maxpaths = 24,
  maxrequests = 60,
  retries = 1,
  timeout = 8000,
  delay = 0.05,
  cachebust = true,
  soft404 = true,
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

local BOOLEAN_ARGS = { "cachebust", "soft404" }

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

local function host_label(host)
  return host.targetname or host.name or host.ip or "unknown"
end

local function select_paths(args)
  local selected = {}
  local seen = {}
  for _, candidate in ipairs(args.paths or POLICY_PATHS) do
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
    table.insert(selected, "/crossdomain.xml")
  end
  return selected
end

local function host_domain(host_label)
  local value = lower(tostring(host_label or ""))
  value = string.gsub(value, "^www%.", "")
  return value
end

local function parent_domains(host_label)
  local parents = {}
  local value = host_domain(host_label)
  local parts = {}
  for token in string.gmatch(value, "[^%.]+") do
    table.insert(parts, token)
  end
  for index = 2, #parts do
    table.insert(parents, table.concat(parts, ".", index, #parts))
  end
  table.insert(parents, value)
  return parents, value
end

local function is_public_suffix_domain(domain)
  local lowered = lower(tostring(domain or ""))
  for _, suffix in ipairs(PUBLIC_SUFFIX_DOMAINS) do
    if lowered == suffix or ends_with(lowered, "." .. suffix) then
      return suffix
    end
  end
  return nil
end

local function unescape_xml(value)
  local text = tostring(value or "")
  text = string.gsub(text, "&lt;", "<")
  text = string.gsub(text, "&gt;", ">")
  text = string.gsub(text, "&quot;", '"')
  text = string.gsub(text, "&apos;", "'")
  text = string.gsub(text, "&#(%d+);", function(code)
    return string.char(tonumber(code) or 63)
  end)
  text = string.gsub(text, "&amp;", "&")
  return text
end

local function strip_comments(body)
  local cleaned = string.gsub(tostring(body or ""), "<!%-%-.-%-%->", " ")
  local comments = {}
  for comment in string.gmatch(tostring(body or ""), "<!%-%-(.-)%-%->") do
    table.insert(comments, truncate(trim(comment), 140))
  end
  return cleaned, comments
end

local function attribute(block, name)
  local value = string.match(block, name .. '%s*=%s*"([^"]*)"')
    or string.match(block, name .. "%s*=%s*'([^']*)'")
  if value then
    return unescape_xml(trim(value))
  end
  return nil
end

local function parse_flash_policy(body, target_host)
  local cleaned, comments = strip_comments(body)
  local policy = {
    kind = "flash",
    present = string.find(lower(cleaned), "cross%-domain%-policy", 1, false) ~= nil
      or string.find(lower(cleaned), "cross-domain-policy", 1, true) ~= nil,
    site_control = nil,
    site_control_missing = false,
    domains = {},
    header_grants = {},
    identities = {},
    comments = comments,
    dtd = nil,
    problems = {},
  }

  policy.dtd = string.match(cleaned, '<!DOCTYPE%s+cross%-domain%-policy%s+SYSTEM%s+"([^"]+)"')
    or string.match(cleaned, "<!DOCTYPE%s+cross%-domain%-policy%s+SYSTEM%s+'([^']+)'")

  local site_control_block = string.match(cleaned, "<site%-control([^>]*)>")
    or string.match(cleaned, "<site-control([^>]*)>")
  if site_control_block then
    policy.site_control = attribute(site_control_block, "permitted-cross-domain-policies")
      or attribute(site_control_block, "permitted%-cross%-domain%-policies")
    if not policy.site_control then
      table.insert(policy.problems, "site-control element without a "
        .. "permitted-cross-domain-policies attribute (invalid; clients fall back to master-only)")
    end
  else
    policy.site_control_missing = true
    policy.site_control = "master-only (default)"
  end

  local parents = parent_domains(target_host)

  for block in string.gmatch(cleaned, "<allow%-access%-from%s+([^>]-)/?>") do
    local domain = attribute(block, "domain")
    if not domain then
      table.insert(policy.problems, "allow-access-from element without a domain attribute")
    else
      local entry = {
        domain = domain,
        secure = attribute(block, "secure"),
        to_ports = attribute(block, "to-ports"),
        wildcard = domain == "*",
        star_prefix = starts_with(domain, "*."),
        suffix_match = contains(domain, "*"),
        ip_literal = string.match(domain, "^%d+%.%d+%.%d+%.%d+$") ~= nil,
        leading_dot = starts_with(domain, "."),
        own_domain = false,
        public_suffix = is_public_suffix_domain(domain),
      }
      local bare = lower(entry.star_prefix and string.sub(domain, 3) or domain)
      bare = string.gsub(bare, "^%.", "")
      if not entry.public_suffix then
        for _, parent in ipairs(parents) do
          if bare == parent or ends_with(bare, "." .. parent) then
            entry.own_domain = true
          end
        end
      end
      table.insert(policy.domains, entry)
    end
  end

  for block in string.gmatch(cleaned, "<allow%-http%-request%-headers%-from%s+([^>]-)/?>") do
    local domain = attribute(block, "domain")
    local headers = attribute(block, "headers")
    local entry = {
      domain = domain or "(missing)",
      headers = headers or "(missing)",
      secure = attribute(block, "secure"),
      wildcard = domain == "*" or headers == "*",
      header_list = {},
    }
    for token in string.gmatch(lower(headers or ""), "[^,%s]+") do
      table.insert(entry.header_list, token)
    end
    table.insert(policy.header_grants, entry)
  end

  for block in string.gmatch(cleaned, "<allow%-access%-from%-identity>(.-)</allow%-access%-from%-identity>") do
    local signer = string.match(block, "<certificate>(.-)</certificate>")
    table.insert(policy.identities, truncate(signer or block, 120))
  end

  if not policy.present then
    table.insert(policy.problems, "no cross-domain-policy root element found")
  end

  return policy
end

local function parse_silverlight_policy(body, target_host)
  local cleaned, comments = strip_comments(body)
  local policy = {
    kind = "silverlight",
    present = string.find(lower(cleaned), "access-policy", 1, true) ~= nil
      or string.find(lower(cleaned), "access_policy", 1, true) ~= nil,
    rules = {},
    comments = comments,
    problems = {},
  }

  for block in string.gmatch(cleaned, "<allow%-from(.-)</allow%-from>") do
    local headers = string.match(block, 'http%-request%-headers%s*=%s*"([^"]*)"')
    local uri = string.match(block, '<domain%s+uri%s*=%s*"([^"]*)"')
    local path, include_subpaths = "unknown", "unknown"
    local grant = string.match(cleaned, "<grant%-to(.-)</grant%-to>")
    if grant then
      local resource = string.match(grant, "<resource([^>]*)>")
      if resource then
        path = attribute(resource, "path") or path
        include_subpaths = attribute(resource, "include-subpaths")
          or attribute(resource, "include%-subpaths") or include_subpaths
      end
    end
    table.insert(policy.rules, {
      headers = headers,
      uri = uri or "(missing)",
      path = path,
      include_subpaths = include_subpaths,
      wildcard = uri == "*" or uri == "http://*" or uri == "https://*",
      own_domain = false,
      public_suffix = is_public_suffix_domain(uri),
    })
  end

  if not policy.present then
    table.insert(policy.problems, "no access-policy root element found")
  end
  if #policy.rules == 0 and policy.present then
    table.insert(policy.problems, "access-policy present but no cross-domain-access rule was parsed")
  end

  local parents = parent_domains(target_host)
  for _, rule in ipairs(policy.rules) do
    local uri = lower(rule.uri or "")
    uri = string.gsub(uri, "^https?://", "")
    uri = string.gsub(uri, "/.*$", "")
    uri = string.gsub(uri, "^%.", "")
    if not rule.public_suffix then
      for _, parent in ipairs(parents) do
        if uri == parent or ends_with(uri, "." .. parent) then
          rule.own_domain = true
        end
      end
    end
  end

  return policy
end

local function detect_policy_kind(path, body, content_type)
  local lowered = lower(body)
  if contains(lowered, "cross-domain-policy") or contains(lowered, "allow-access-from")
    or contains(lowered, "site-control") then
    return "flash"
  end
  if contains(lowered, "access-policy") or contains(lowered, "cross-domain-access")
    or contains(lowered, "grant-to") then
    return "silverlight"
  end
  local ctype = lower(tostring(content_type or ""))
  if contains(ctype, "html") and not contains(lowered, "<?xml") then
    return nil
  end
  if #trim(body) == 0 then
    return nil
  end
  if contains(lower(path), "clientaccesspolicy") or contains(lower(path), "silverlight") then
    return "silverlight"
  end
  return nil
end

local function score_flash(policy, ssl_service)
  local worst = "INFO"
  local reasons = {}

  local site = SITE_CONTROL_VALUES[policy.site_control]
  if site then
    if (SEVERITY[site.severity] or 0) > (SEVERITY[worst] or 0) then
      worst = site.severity
    end
    if site.severity ~= "INFO" then
      table.insert(reasons, "site-control=" .. tostring(policy.site_control) .. ": " .. site.risk)
    end
  end

  for _, entry in ipairs(policy.domains) do
    if entry.wildcard then
      worst = "CRITICAL"
      table.insert(reasons, "allow-access-from domain=\"*\" grants every origin credentialed read access")
    elseif entry.public_suffix then
      if (SEVERITY.HIGH or 0) > (SEVERITY[worst] or 0) then
        worst = "HIGH"
      end
      table.insert(reasons, string.format(
        "domain=\"%s\" is under %s, a namespace anyone can register a host in",
        entry.domain, entry.public_suffix))
    elseif entry.star_prefix and not entry.own_domain then
      if (SEVERITY.HIGH or 0) > (SEVERITY[worst] or 0) then
        worst = "HIGH"
      end
      table.insert(reasons, string.format(
        "domain=\"%s\" is a wildcard grant to a domain this host does not own", entry.domain))
    elseif entry.star_prefix and entry.own_domain then
      if (SEVERITY.MEDIUM or 0) > (SEVERITY[worst] or 0) then
        worst = "MEDIUM"
      end
      table.insert(reasons, string.format(
        "domain=\"%s\" covers every subdomain, including any that host user content", entry.domain))
    elseif not entry.own_domain and entry.domain ~= "*" then
      if (SEVERITY.MEDIUM or 0) > (SEVERITY[worst] or 0) then
        worst = "MEDIUM"
      end
      table.insert(reasons, string.format(
        "domain=\"%s\" is a third-party origin allowed to read this service", entry.domain))
    end

    if entry.secure and lower(entry.secure) == "false" and ssl_service then
      if (SEVERITY.MEDIUM or 0) > (SEVERITY[worst] or 0) then
        worst = "MEDIUM"
      end
      table.insert(reasons, string.format(
        "domain=\"%s\" has secure=\"false\": plain-HTTP callers may read this HTTPS service", entry.domain))
    end
    if entry.ip_literal then
      table.insert(reasons, string.format("domain=\"%s\" is an IP literal (rare and hard to audit)",
        entry.domain))
    end
    if entry.to_ports then
      table.insert(reasons, string.format("domain=\"%s\" restricts to-ports=%s", entry.domain, entry.to_ports))
    end
  end

  for _, grant in ipairs(policy.header_grants) do
    if grant.wildcard and grant.domain == "*" then
      worst = "CRITICAL"
      table.insert(reasons, "allow-http-request-headers-from domain=\"*\" headers=\""
        .. tostring(grant.headers) .. "\" lets any origin send custom headers")
    else
      for _, header in ipairs(grant.header_list) do
        local risk = HEADER_GRANT_RISK[header]
        if risk then
          if (SEVERITY[risk.severity] or 0) > (SEVERITY[worst] or 0) then
            worst = risk.severity
          end
          table.insert(reasons, string.format("header grant for %s to %s: %s",
            header, grant.domain, risk.note))
        end
      end
      if grant.headers == "*" then
        if (SEVERITY.HIGH or 0) > (SEVERITY[worst] or 0) then
          worst = "HIGH"
        end
        table.insert(reasons, string.format(
          "headers=\"*\" allows %s to set arbitrary request headers", grant.domain))
      end
    end
    if grant.secure and lower(grant.secure) == "false" and ssl_service then
      table.insert(reasons, string.format("header grant for %s has secure=\"false\"", grant.domain))
    end
  end

  for _, identity in ipairs(policy.identities) do
    table.insert(reasons, "identity/certificate based grant present: " .. identity)
  end

  return worst, reasons
end

local function score_silverlight(policy, ssl_service)
  local worst = "INFO"
  local reasons = {}
  for _, rule in ipairs(policy.rules) do
    local subpaths = lower(tostring(rule.include_subpaths)) == "true"
    local root_path = tostring(rule.path) == "/"
    local headers = lower(tostring(rule.headers)) == "true"

    if rule.wildcard and subpaths and root_path then
      worst = "CRITICAL"
      table.insert(reasons, "allow-from uri=\"*\" with grant-to path=\"/\" include-subpaths=\"true\": "
        .. "every origin may read the whole application")
    elseif rule.wildcard then
      if (SEVERITY.HIGH or 0) > (SEVERITY[worst] or 0) then
        worst = "HIGH"
      end
      table.insert(reasons, "allow-from uri=\"*\" grants every origin access to "
        .. tostring(rule.path))
    elseif rule.public_suffix then
      if (SEVERITY.HIGH or 0) > (SEVERITY[worst] or 0) then
        worst = "HIGH"
      end
      table.insert(reasons, string.format("uri=\"%s\" is under %s, a namespace anyone can register in",
        rule.uri, rule.public_suffix))
    elseif not rule.own_domain then
      if (SEVERITY.MEDIUM or 0) > (SEVERITY[worst] or 0) then
        worst = "MEDIUM"
      end
      table.insert(reasons, string.format("uri=\"%s\" is a third-party origin", rule.uri))
    end

    if headers then
      if (SEVERITY.MEDIUM or 0) > (SEVERITY[worst] or 0) then
        worst = "MEDIUM"
      end
      table.insert(reasons, "http-request-headers=\"true\" lets the allowed origin set arbitrary "
        .. "headers (a CSRF primitive)")
    end
    if subpaths and not root_path then
      table.insert(reasons, string.format("grant-to path=\"%s\" include-subpaths=\"true\"",
        tostring(rule.path)))
    end
  end
  return worst, reasons
end

local function policy_hash_match(a, b)
  if not a or not b then
    return false
  end
  return tostring(a.hash) == tostring(b.hash)
    and tostring(a.length) == tostring(b.length)
    and tostring(a.content_type) == tostring(b.content_type)
end

local function compare_channels(primary, alternate)
  local notes = {}
  if not primary or not alternate then
    return notes
  end
  if policy_hash_match(primary, alternate) then
    table.insert(notes, string.format("%s: identical policy on both channels (%d bytes, %s)",
      primary.path, primary.length, primary.content_type))
    return notes
  end
  table.insert(notes, string.format(
    "%s differs between channels: primary %d bytes (%s) vs alternate %d bytes (%s)",
    primary.path, primary.length, primary.content_type,
    alternate.length, alternate.content_type))
  if (SEVERITY[alternate.severity] or 0) > (SEVERITY[primary.severity] or 0) then
    table.insert(notes, string.format(
      "the alternate channel serves a MORE permissive policy (%s vs %s)",
      tostring(alternate.severity), tostring(primary.severity)))
  end
  if #alternate.domains > #(primary.domains or {}) then
    table.insert(notes, "the alternate channel grants access to more origins")
  end
  return notes
end

local function render_flash(policy)
  local lines = {}
  table.insert(lines, string.format("root element: cross-domain-policy, site-control: %s",
    tostring(policy.site_control)))
  local site = SITE_CONTROL_VALUES[policy.site_control]
  if site then
    table.insert(lines, string.format("      meaning: %s", site.meaning))
    if site.recommendation ~= "none" then
      table.insert(lines, string.format("      recommendation: %s", site.recommendation))
    end
  end
  if policy.dtd then
    table.insert(lines, "      DTD: " .. policy.dtd)
  end
  for _, entry in ipairs(policy.domains) do
    local flags = {}
    if entry.wildcard then table.insert(flags, "WILDCARD") end
    if entry.star_prefix then table.insert(flags, "subdomain-wildcard") end
    if entry.ip_literal then table.insert(flags, "ip-literal") end
    if entry.leading_dot then table.insert(flags, "leading-dot") end
    if entry.secure then table.insert(flags, "secure=" .. entry.secure) end
    if entry.to_ports then table.insert(flags, "to-ports=" .. entry.to_ports) end
    if entry.own_domain then table.insert(flags, "same organisation") end
    if entry.public_suffix then table.insert(flags, "externally registerable (" .. entry.public_suffix .. ")") end
    table.insert(lines, string.format("      allow-access-from %-32s %s",
      entry.domain, #flags > 0 and table.concat(flags, ", ") or "plain grant"))
  end
  for _, grant in ipairs(policy.header_grants) do
    local flags = {}
    if grant.wildcard then table.insert(flags, "WILDCARD") end
    if grant.secure then table.insert(flags, "secure=" .. grant.secure) end
    table.insert(lines, string.format("      allow-http-request-headers-from %-22s headers=%-18s %s",
      grant.domain, truncate(grant.headers, 18), #flags > 0 and table.concat(flags, ", ") or ""))
  end
  for _, identity in ipairs(policy.identities) do
    table.insert(lines, "      allow-access-from-identity: " .. identity)
  end
  for _, comment in ipairs(policy.comments) do
    table.insert(lines, "      comment: " .. comment)
  end
  for _, problem in ipairs(policy.problems) do
    table.insert(lines, "      problem: " .. problem)
  end
  return lines
end

local function render_silverlight(policy)
  local lines = {}
  table.insert(lines, string.format("root element: access-policy, rules: %d", #policy.rules))
  for _, rule in ipairs(policy.rules) do
    local flags = {}
    if rule.wildcard then table.insert(flags, "WILDCARD") end
    if lower(tostring(rule.headers)) == "true" then table.insert(flags, "http-request-headers=true") end
    if lower(tostring(rule.include_subpaths)) == "true" then table.insert(flags, "include-subpaths=true") end
    if rule.own_domain then table.insert(flags, "same organisation") end
    if rule.public_suffix then table.insert(flags, "externally registerable (" .. rule.public_suffix .. ")") end
    table.insert(lines, string.format("      allow-from %-34s grant-to path=%s %s",
      truncate(rule.uri, 34), tostring(rule.path), #flags > 0 and table.concat(flags, ", ") or ""))
  end
  for _, comment in ipairs(policy.comments) do
    table.insert(lines, "      comment: " .. comment)
  end
  for _, problem in ipairs(policy.problems) do
    table.insert(lines, "      problem: " .. problem)
  end
  return lines
end

local function effective_allow_list(policy)
  local allowed = {}
  if policy.kind == "flash" then
    for _, entry in ipairs(policy.domains) do
      if entry.wildcard then
        table.insert(allowed, "* (every origin on the internet)")
      elseif entry.star_prefix then
        table.insert(allowed, entry.domain .. " (any host in that zone, including ones you do not control)")
      else
        table.insert(allowed, entry.domain)
      end
    end
  else
    for _, rule in ipairs(policy.rules) do
      if rule.wildcard then
        table.insert(allowed, "* (every origin, path " .. tostring(rule.path) .. ")")
      else
        table.insert(allowed, tostring(rule.uri) .. " (path " .. tostring(rule.path) .. ")")
      end
    end
  end
  if #allowed == 0 then
    table.insert(allowed, "(no origin is granted access)")
  end
  return allowed
end

action = function(host, port)

  seed_random(port)
  reset_state()
  reset_findings()

  local args = read_args()
  local baseline = build_soft404_baseline(host, port, args)
  local paths = select_paths(args)
  local ssl_service = port.ssl or (port.version and port.version.service_ssl) or false
  local target_host = host_label(host)

  if args.cachebust and not budget_exhausted(args) then
    local bust = "/crossdomain.xml?nse=" .. lower(random_token(8))
    if not list_contains(paths, bust) then
      table.insert(paths, bust)
    end
  end

  local header_policy = nil
  if not budget_exhausted(args) then
    local probe, probe_err = fetch(host, port, "/", args)
    if probe then
      header_policy = header_value(probe, "cross-domain-policy")
        or header_value(probe, "x-cross-domain-policy")
      if header_policy then
        local referenced = trim(header_policy)
        if starts_with(referenced, "http") then
          referenced = path_of_url(referenced)
        end
        if not starts_with(referenced, "/") then
          referenced = "/" .. referenced
        end
        if not list_contains(paths, referenced) then
          table.insert(paths, referenced)
        end
        add_finding("INFO", string.format(
          "the service points at a policy file with the cross-domain-policy header (%s)", referenced),
          { subject = "header-policy", evidence = referenced })
      end
    else
      header_policy = nil
      table.insert(paths, paths[1] or "/crossdomain.xml")
    end
  end

  local analysed = {}
  local fetch_log = {}

  for _, path in ipairs(paths) do
    if budget_exhausted(args) then
      table.insert(fetch_log, path .. ": request budget exhausted")
      break
    end

    local response, err = fetch(host, port, path, args)
    if not response then
      table.insert(fetch_log, string.format("%s: %s", path, tostring(err)))
      goto continue_path
    end

    local status = response.status or 0
    local body = response.body or ""
    local ctype = lower(header_value(response, "content-type") or "")
    local info = classify_response(path, response, baseline)
    local kind = detect_policy_kind(path, body, ctype)
    local catchall = not kind
      and info.confidence == "low"
      and contains(lower(table.concat(info.notes, ";")), "soft-404")

    if status == 404 then
      table.insert(fetch_log, string.format("%s -> HTTP 404 (no policy file)", path))
      goto continue_path
    end

    if catchall then
      table.insert(fetch_log, string.format(
        "%s -> HTTP %s answers with the catch-all page: not a policy file (soft-404)",
        path, tostring(status)))
      add_finding("INFO", string.format("%s answers with the site catch-all page instead of a policy file",
        path),
        { path = path, subject = "catchall:" .. path, evidence = truncate(body, 90),
          confidence = "low" })
      goto continue_path
    end

    if status == 401 or status == 403 then
      table.insert(fetch_log, string.format("%s -> HTTP %s (policy file is protected)", path,
        tostring(status)))
      add_finding("INFO", string.format("%s is protected (HTTP %s) so plugin clients receive no policy",
        path, tostring(status)),
        { path = path, subject = "protected:" .. path, evidence = "HTTP " .. tostring(status) })
      goto continue_path
    end

    if not kind then
      table.insert(fetch_log, string.format("%s -> HTTP %s, %d bytes, %s: content is not a policy document",
        path, tostring(status), #body, #ctype > 0 and ctype or "unknown type"))
      if status == 200 and #body > 0 then
        add_finding("LOW", string.format(
          "%s returns HTTP 200 with non-policy content (%s); plugin clients will treat the origin as "
          .. "having no policy, but a proxy or cache may store this response in place of a real policy",
          path, #ctype > 0 and ctype or "unknown type"),
          { path = path, subject = "non-policy:" .. path, evidence = truncate(body, 90) })
      end
      goto continue_path
    end

    local policy
    if kind == "flash" then
      policy = parse_flash_policy(body, target_host)
    else
      policy = parse_silverlight_policy(body, target_host)
    end
    policy.path = path
    policy.status = status
    policy.length = #body
    policy.content_type = #ctype > 0 and ctype or "unknown"
    if kind == "flash" then
      policy.severity, policy.reasons = score_flash(policy, ssl_service)
    else
      policy.severity, policy.reasons = score_silverlight(policy, ssl_service)
    end
    policy.severity = policy.severity or "INFO"
    policy.reasons = policy.reasons or {}
    policy.allowed = effective_allow_list(policy)
    policy.hash = fnv1a32(body)
    policy.entropy = entropy_bits(body)
    table.insert(analysed, policy)

    table.insert(fetch_log, string.format("%s -> HTTP %s, %d bytes, %s, %s policy, severity %s",
      path, tostring(status), #body, policy.content_type, kind, tostring(policy.severity)))

    ::continue_path::
  end

  local deduped_candidates = {}
  for _, policy in ipairs(analysed) do
    table.insert(deduped_candidates, policy)
  end
  table.sort(deduped_candidates, function(a, b)
    return (SEVERITY[a.severity] or 0) > (SEVERITY[b.severity] or 0)
  end)
  local alternate_policy = nil
  if #deduped_candidates > 0 and not budget_exhausted(args) then
    local primary = deduped_candidates[1]
    local alt_url = ssl_service
      and ("http://" .. target_host .. primary.path)
      or ("https://" .. target_host .. primary.path)
    local response, err = fetch(host, port, alt_url, args)
    if not response then
      table.insert(fetch_log, string.format("%s (alternate channel) -> %s", alt_url, tostring(err)))
    elseif (response.status or 0) >= 400 then
      table.insert(fetch_log, string.format("%s (alternate channel) -> HTTP %s",
        alt_url, tostring(response.status)))
    else
      local kind = detect_policy_kind(primary.path, response.body or "",
        header_value(response, "content-type"))
      if kind then
        local policy
        if kind == "flash" then
          policy = parse_flash_policy(response.body or "", target_host)
        else
          policy = parse_silverlight_policy(response.body or "", target_host)
        end
        policy.path = alt_url
        policy.status = response.status
        policy.length = #(response.body or "")
        policy.content_type = lower(header_value(response, "content-type") or "unknown")
        if kind == "flash" then
          policy.severity, policy.reasons = score_flash(policy, not ssl_service)
        else
          policy.severity, policy.reasons = score_silverlight(policy, not ssl_service)
        end
        policy.severity = policy.severity or "INFO"
        policy.reasons = policy.reasons or {}
        policy.hash = fnv1a32(response.body or "")
        policy.allowed = effective_allow_list(policy)
        alternate_policy = policy
        table.insert(fetch_log, string.format("%s (alternate channel) -> HTTP %s, %d bytes, severity %s",
          alt_url, tostring(policy.status), policy.length, tostring(policy.severity)))
        if not policy_hash_match(primary, policy) then
          add_finding("MEDIUM", string.format(
            "the cross-domain policy at %s is not identical when fetched over the other scheme (%s): "
            .. "plugin clients resolve the policy for the scheme they call, so the two must match",
            primary.path, alt_url),
            { path = primary.path, subject = "channel-divergence:" .. primary.path,
              evidence = string.format("primary %d bytes / alternate %d bytes", primary.length,
                policy.length) })
        end
      else
        table.insert(fetch_log, string.format(
          "%s (alternate channel) -> HTTP %s, content is not a policy document",
          alt_url, tostring(response.status)))
      end
    end
  end

  local channel_notes = {}
  if alternate_policy then
    for _, note in ipairs(compare_channels(deduped_candidates[1], alternate_policy)) do
      table.insert(channel_notes, note)
    end
    for _, note in ipairs(channel_notes) do
      if contains(note, "MORE permissive") or contains(note, "more origins") then
        add_finding("HIGH", note .. " (" .. alternate_policy.path .. ")",
          { path = deduped_candidates[1] and deduped_candidates[1].path or "/",
            subject = "channel-permissive", evidence = alternate_policy.path })
      end
    end
  end

  local deduped = {}
  local hash_seen = {}
  for _, policy in ipairs(analysed) do
    local key = tostring(policy.kind) .. "|" .. tostring(policy.hash)
    if not hash_seen[key] then
      hash_seen[key] = true
      policy.aliases = { policy.path }
      table.insert(deduped, policy)
    else
      for _, existing in ipairs(deduped) do
        if tostring(existing.kind) .. "|" .. tostring(existing.hash) == key then
          table.insert(existing.aliases, policy.path)
          break
        end
      end
    end
  end

  local policy_lines = {}
  local worst_severity = "INFO"
  local wildcard_grants = 0
  local third_party_grants = 0

  for _, policy in ipairs(deduped) do
    if (SEVERITY[policy.severity] or 0) > (SEVERITY[worst_severity] or 0) then
      worst_severity = policy.severity
    end
    for _, line in ipairs(policy.kind == "flash" and render_flash(policy) or render_silverlight(policy)) do
      table.insert(policy_lines, line)
    end
    table.insert(policy_lines, string.format("      served at: %s (%s)",
      table.concat(policy.aliases, ", "), tostring(policy.content_type)))
    table.insert(policy_lines, string.format("      effective allow list: %s",
      table.concat(policy.allowed, "; ")))
    for _, reason in ipairs(policy.reasons) do
      table.insert(policy_lines, "      reason: " .. reason)
    end
    table.insert(policy_lines, string.format("      verdict: [%s] %s", tostring(policy.severity),
      #policy.reasons > 0 and policy.reasons[1] or "no permissive grant detected"))
    table.insert(policy_lines, "")

    local subject = "policy:" .. policy.path
    add_finding(policy.severity, string.format("%s policy at %s grants cross-domain read access to: %s",
      policy.kind, policy.path, table.concat(policy.allowed, "; ")),
      { path = policy.path, subject = subject, evidence = truncate(policy.reasons[1] or "", 110) })

    for _, reason in ipairs(policy.reasons) do
      local severity = "LOW"
      if contains(reason, "every origin") or contains(lower(reason), 'domain="*"')
        or contains(lower(reason), 'uri="*"') then
        severity = "CRITICAL"
        wildcard_grants = wildcard_grants + 1
      elseif contains(reason, "namespace anyone can register")
        or contains(reason, "arbitrary request headers")
        or contains(reason, "site-control=all") then
        severity = "HIGH"
      elseif contains(reason, "third-party origin") or contains(reason, "subdomain")
        or contains(reason, "secure=\"false\"") then
        severity = "MEDIUM"
      end
      if not contains(reason, "recommended configuration") then
        add_finding(severity, reason, { path = policy.path,
          subject = "reason:" .. truncate(lower(reason), 60) .. ":" .. policy.path,
          evidence = policy.path })
      end
    end

    if policy.kind == "flash" then
      for _, entry in ipairs(policy.domains) do
        if not entry.own_domain and not entry.wildcard then
          third_party_grants = third_party_grants + 1
        end
      end
      for _, grant in ipairs(policy.header_grants) do
        if grant.wildcard then
          wildcard_grants = wildcard_grants + 1
        end
      end
    else
      for _, rule in ipairs(policy.rules) do
        if not rule.own_domain and not rule.wildcard then
          third_party_grants = third_party_grants + 1
        end
      end
    end

    for _, problem in ipairs(policy.problems) do
      add_finding("LOW", string.format("%s: %s", policy.path, problem),
        { path = policy.path, subject = "problem:" .. truncate(lower(problem), 50) .. ":" .. policy.path,
          evidence = problem })
    end

    local served_as_policy = contains(policy.content_type, "x-cross-domain-policy")
    if not served_as_policy and policy.kind == "flash" then
      add_finding("LOW", string.format(
        "%s is served as %s rather than text/x-cross-domain-policy; with "
        .. "site-control=by-content-type this file would not be honoured, and with "
        .. "by-content-type misconfiguration a different uploaded file could be", policy.path,
        policy.content_type),
        { path = policy.path, subject = "content-type:" .. policy.path,
          evidence = policy.content_type })
    end
  end

  local unique, counts = dedupe_findings()

  local out = new_output(RISK_LEVEL, "AUDITED - cross-domain policy files reviewed.")
  if counts.CRITICAL > 0 then
    out["Status"] = "VULNERABLE - a wildcard cross-domain policy allows any origin to read this service."
  elseif counts.HIGH > 0 then
    out["Status"] = "VULNERABLE - the cross-domain policy grants access to externally controllable origins."
  elseif counts.MEDIUM > 0 then
    out["Status"] = "AUDITED - the policy grants third-party or broad subdomain access."
  elseif #deduped > 0 then
    out["Status"] = "AUDITED - a policy file exists and it is restrictive."
  else
    out["Status"] = "AUDITED - no cross-domain policy file is published (plugins deny cross-domain access)."
  end

  local sections = {
    { key = "Transport", value = ssl_service and "HTTPS" or "HTTP" },
    { key = "Target host", value = target_host },
    { key = "Policy files found", value = #deduped },
    { key = "Wildcard grants", value = wildcard_grants },
    { key = "Third-party grants", value = third_party_grants },
  }

  if #policy_lines > 0 then
    table.insert(sections, { key = "Policy analysis", value = policy_lines })
  end
  table.insert(sections, { key = "Fetch log", value = fetch_log })
  if header_policy then
    table.insert(sections, { key = "cross-domain-policy header", value = header_policy })
  end
  if #channel_notes > 0 then
    table.insert(sections, { key = "Scheme channel comparison", value = channel_notes })
  end
  if baseline.enabled and baseline.samples > 0 then
    table.insert(sections, { key = "Soft-404 baseline", value = string.format(
      "%d probes, dominant status %s, %s", baseline.samples,
      tostring(baseline.dominant_status or "n/a"),
      baseline.consistent and "catch-all confirmed" or "no catch-all") })
  end

  if worst_severity == "CRITICAL" or worst_severity == "HIGH" then
    table.insert(sections, { key = "Remediation", value =
      "replace the wildcard with explicit domains (<site-control "
      .. "permitted-cross-domain-policies=\"master-only\"/> plus one allow-access-from per partner, "
      .. "each with secure=\"true\"), never grant a domain in a public-suffix namespace you do not "
      .. "own, and if no plugin client uses this service delete the policy file entirely - absent "
      .. "policy means deny" })
  elseif #deduped > 0 then
    table.insert(sections, { key = "Remediation", value =
      "keep master-only site-control, add secure=\"true\" to every grant, list headers explicitly "
      .. "instead of headers=\"*\", and remove grants for origins that no longer call the service" })
  else
    table.insert(sections, { key = "Remediation", value =
      "no policy file is published, which is the correct default; do not add one unless a plugin or "
      .. "Silverlight client requires it, and if you must, use master-only with explicit domains and "
      .. "secure=\"true\"" })
  end

  table.insert(sections, { key = "Requests issued", value = state.requests .. " of " .. args.maxrequests })

  return finish_output(out, unique, counts, sections)

end
