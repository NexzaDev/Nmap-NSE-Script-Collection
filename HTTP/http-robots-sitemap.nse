local shortport = require "shortport"

local http = require "http"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Treats robots.txt and the sitemap family as the reconnaissance document they
are, and reports the exposure that document creates.

robots.txt and sitemap.xml are published for crawlers, but they are read by
attackers first: every Disallow entry is a pointer to a path the operator
considered sensitive enough to hide, and every sitemap URL is a free inventory
of the application surface. This script does not stop at listing them.

What it does
1. Fetches /robots.txt and parses it as RFC 9309 requires: case-insensitive
   field names, group semantics keyed by User-agent (including the * group and
   multiple agent tokens per line), Allow and Disallow with longest-match
   precedence, wildcards (*) and end anchors ($) in path patterns, Crawl-delay,
   Request-rate, Visit-time, Sitemap (absolute and relative forms),
   Host, Clean-param (Yandex), Noindex (deprecated), Comment lines, and
   BOM/whitespace/line-ending tolerance. Malformed syntax is reported as a
   finding because a mis-parsed robots.txt silently changes crawler behaviour.
2. Classifies the robots.txt response itself: absent (404 - no restriction),
   denied (401/403 - RFC 9309 says an inaccessible robots.txt means "allow
   all", which is a real security consequence, not a curiosity), catch-all
   (200 with the site's HTML body - detected with the soft-404 baseline),
   empty Disallow (explicit allow-all), and disallow-everything
   (`Disallow: /`, which is not a security control and often hides a
   misconfigured reverse proxy).
3. Scores every Disallow/Allow path against 90+ sensitivity patterns
   (admin panels, backups, configuration, credentials, version control,
   database dumps, logs, internal tooling, API documentation, CI/CD, cloud
   metadata paths, WordPress/Drupal/Laravel/Spring/Django/Rails internals,
   WebDAV, file managers, monitoring stacks) and reports which of them are the
   "hidden treasure map" entries.
4. Parses the sitemap family: /sitemap.xml, /sitemap_index.xml, /sitemap.xml.gz
   (gzip detection), /sitemap.txt, /sitemap/sitemap.xml, /wp-sitemap.xml,
   /post-sitemap.xml, /news-sitemap.xml, /image-sitemap.xml, /video-sitemap.xml,
   /mobile-sitemap.xml, plus every <sitemap> child reference found in an index
   (bounded by a request budget). URL sets are extracted from <urlset>/<url>/
   <loc>, <sitemapindex>/<sitemap>/<loc>, image: and video: extensions, and
   plain-text one-URL-per-line sitemaps.
5. Audits the sitemap content: total URL count, unique path count, off-origin
   URLs (a sitemap pointing at another host is a data leak or a hijack
   indicator), http:// URLs on an HTTPS service (mixed content / downgrade),
   URLs with embedded credentials or session identifiers in the query string,
   URLs that 404 (stale sitemap), lastmod dates in the future or before 2000
   (broken generation), and duplicate loc entries.
6. Follows up on the interesting paths: each sensitive robots entry and a
   bounded sample of sitemap URLs are requested live, and the actual HTTP
   status, response length and whether the page is a soft-404 is reported. A
   Disallow entry that answers 200 with real content is the actionable finding;
   one that answers 403 is defence working; one that answers the catch-all page
   is noise.
7. Checks the crawler-facing headers and meta tags on the same responses:
   X-Robots-Tag (noindex, nofollow, noarchive, nosnippet, unavailable_after,
   max-snippet, max-image-preview), <meta name="robots">, and whether
   X-Robots-Tag is present on non-HTML content (PDF, JSON, images) where the
   meta tag cannot be used.

Output includes the parsed rule set as a rule table (agent, type, pattern,
literal/wildcard/anchored), the sensitive-entry list with live status, the
sitemap statistics, and a verdict that states whether the published crawler
documents disclose anything that is not otherwise reachable.

Usage:
<code>
nmap -p 80,443 --script http-robots-sitemap <target>
nmap -p 443 --script http-robots-sitemap \
  --script-args http-robots-sitemap.follow=true,http-robots-sitemap.maxfollow=40 <target>
nmap -p 80 --script http-robots-sitemap \
  --script-args http-robots-sitemap.sitemaps="/sitemap.xml,/custom-map.xml" <target>
</code>

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"safe", "discovery"}

portrule = shortport.http

local SCRIPT_NAME = "http-robots-sitemap"

local RISK_LEVEL = "🟡 MEDIUM"

local ROBOTS_PATHS = {
  "/robots.txt",
  "/ROBOTS.TXT",
  "/robot.txt",
}

local SITEMAP_PATHS = {
  "/sitemap.xml",
  "/sitemap_index.xml",
  "/sitemap-index.xml",
  "/sitemapindex.xml",
  "/sitemap/sitemap.xml",
  "/sitemaps/sitemap.xml",
  "/sitemap.xml.gz",
  "/sitemap.txt",
  "/sitemap.html",
  "/wp-sitemap.xml",
  "/post-sitemap.xml",
  "/page-sitemap.xml",
  "/news-sitemap.xml",
  "/image-sitemap.xml",
  "/video-sitemap.xml",
  "/mobile-sitemap.xml",
  "/news_sitemap.xml",
  "/sitemap.php",
  "/feed/sitemap",
  "/sitemap1.xml",
}

local SENSITIVE_PATTERNS = {
  { pattern = "admin", category = "administration", severity = "HIGH",
    note = "administrative interface" },
  { pattern = "administrator", category = "administration", severity = "HIGH",
    note = "CMS administrator path" },
  { pattern = "manager", category = "administration", severity = "HIGH",
    note = "manager console (Tomcat manager is a classic RCE entry point)" },
  { pattern = "console", category = "administration", severity = "HIGH",
    note = "console/debug surface" },
  { pattern = "cpanel", category = "administration", severity = "HIGH",
    note = "hosting control panel" },
  { pattern = "panel", category = "administration", severity = "MEDIUM",
    note = "management panel" },
  { pattern = "dashboard", category = "administration", severity = "MEDIUM",
    note = "internal dashboard" },
  { pattern = "internal", category = "internal", severity = "HIGH",
    note = "path explicitly labelled internal" },
  { pattern = "private", category = "internal", severity = "HIGH",
    note = "path explicitly labelled private" },
  { pattern = "restricted", category = "internal", severity = "HIGH",
    note = "path explicitly labelled restricted" },
  { pattern = "secret", category = "secret-material", severity = "HIGH",
    note = "path labelled secret" },
  { pattern = "backup", category = "backup", severity = "HIGH",
    note = "backup storage" },
  { pattern = "bak", category = "backup", severity = "HIGH",
    note = "backup file extension/path" },
  { pattern = "old", category = "backup", severity = "MEDIUM",
    note = "legacy copy of the application" },
  { pattern = "archive", category = "backup", severity = "MEDIUM",
    note = "archived content" },
  { pattern = "dump", category = "database", severity = "HIGH",
    note = "database or memory dump" },
  { pattern = "sql", category = "database", severity = "HIGH",
    note = "SQL material" },
  { pattern = "db", category = "database", severity = "HIGH",
    note = "database path" },
  { pattern = "database", category = "database", severity = "HIGH",
    note = "database path" },
  { pattern = "phpmyadmin", category = "database-admin", severity = "HIGH",
    note = "phpMyAdmin" },
  { pattern = "adminer", category = "database-admin", severity = "HIGH",
    note = "Adminer" },
  { pattern = "config", category = "configuration", severity = "HIGH",
    note = "configuration material" },
  { pattern = "conf", category = "configuration", severity = "MEDIUM",
    note = "configuration material" },
  { pattern = "settings", category = "configuration", severity = "MEDIUM",
    note = "settings file" },
  { pattern = "env", category = "configuration", severity = "HIGH",
    note = "environment file" },
  { pattern = "credential", category = "secret-material", severity = "HIGH",
    note = "credential material" },
  { pattern = "password", category = "secret-material", severity = "HIGH",
    note = "password material" },
  { pattern = "passwd", category = "secret-material", severity = "HIGH",
    note = "password material" },
  { pattern = "token", category = "secret-material", severity = "HIGH",
    note = "token material" },
  { pattern = "key", category = "secret-material", severity = "HIGH",
    note = "key material" },
  { pattern = "cert", category = "secret-material", severity = "MEDIUM",
    note = "certificate material" },
  { pattern = "pem", category = "secret-material", severity = "HIGH",
    note = "PEM key material" },
  { pattern = "ssh", category = "secret-material", severity = "HIGH",
    note = "SSH material" },
  { pattern = "git", category = "version-control", severity = "HIGH",
    note = "git repository internals" },
  { pattern = "svn", category = "version-control", severity = "HIGH",
    note = "subversion internals" },
  { pattern = "cvs", category = "version-control", severity = "MEDIUM",
    note = "CVS internals" },
  { pattern = "log", category = "logs", severity = "HIGH",
    note = "log files (session tokens, request parameters)" },
  { pattern = "tmp", category = "transient", severity = "MEDIUM",
    note = "temporary storage" },
  { pattern = "temp", category = "transient", severity = "MEDIUM",
    note = "temporary storage" },
  { pattern = "cache", category = "transient", severity = "LOW",
    note = "cache storage" },
  { pattern = "upload", category = "user-content", severity = "MEDIUM",
    note = "upload directory" },
  { pattern = "userfiles", category = "user-content", severity = "MEDIUM",
    note = "user file storage" },
  { pattern = "attachment", category = "user-content", severity = "MEDIUM",
    note = "attachment storage" },
  { pattern = "media", category = "user-content", severity = "LOW",
    note = "media storage" },
  { pattern = "filemanager", category = "user-content", severity = "HIGH",
    note = "web file manager" },
  { pattern = "elfinder", category = "user-content", severity = "HIGH",
    note = "elFinder file manager" },
  { pattern = "test", category = "non-production", severity = "MEDIUM",
    note = "test/staging material" },
  { pattern = "dev", category = "non-production", severity = "MEDIUM",
    note = "development material" },
  { pattern = "staging", category = "non-production", severity = "MEDIUM",
    note = "staging environment" },
  { pattern = "debug", category = "non-production", severity = "HIGH",
    note = "debug surface" },
  { pattern = "trace", category = "non-production", severity = "MEDIUM",
    note = "trace endpoint" },
  { pattern = "status", category = "monitoring", severity = "MEDIUM",
    note = "status endpoint" },
  { pattern = "health", category = "monitoring", severity = "LOW",
    note = "health endpoint" },
  { pattern = "metrics", category = "monitoring", severity = "MEDIUM",
    note = "metrics endpoint (Prometheus)" },
  { pattern = "actuator", category = "monitoring", severity = "HIGH",
    note = "Spring Boot Actuator" },
  { pattern = "grafana", category = "monitoring", severity = "MEDIUM",
    note = "Grafana" },
  { pattern = "kibana", category = "monitoring", severity = "MEDIUM",
    note = "Kibana" },
  { pattern = "swagger", category = "api-documentation", severity = "MEDIUM",
    note = "API documentation" },
  { pattern = "api-docs", category = "api-documentation", severity = "MEDIUM",
    note = "API documentation" },
  { pattern = "openapi", category = "api-documentation", severity = "MEDIUM",
    note = "OpenAPI specification" },
  { pattern = "graphql", category = "api-documentation", severity = "MEDIUM",
    note = "GraphQL endpoint" },
  { pattern = "api", category = "api", severity = "LOW",
    note = "API namespace" },
  { pattern = "jenkins", category = "ci-cd", severity = "HIGH",
    note = "Jenkins" },
  { pattern = "hudson", category = "ci-cd", severity = "HIGH",
    note = "Hudson" },
  { pattern = "gitlab", category = "ci-cd", severity = "HIGH",
    note = "GitLab" },
  { pattern = "teamcity", category = "ci-cd", severity = "HIGH",
    note = "TeamCity" },
  { pattern = "build", category = "ci-cd", severity = "MEDIUM",
    note = "build output" },
  { pattern = "deploy", category = "ci-cd", severity = "MEDIUM",
    note = "deployment material" },
  { pattern = "release", category = "ci-cd", severity = "LOW",
    note = "release artefacts" },
  { pattern = "vendor", category = "dependencies", severity = "MEDIUM",
    note = "dependency directory" },
  { pattern = "node_modules", category = "dependencies", severity = "MEDIUM",
    note = "Node dependency directory" },
  { pattern = "includes", category = "source", severity = "MEDIUM",
    note = "server-side include directory" },
  { pattern = "inc", category = "source", severity = "MEDIUM",
    note = "include directory" },
  { pattern = "lib", category = "source", severity = "LOW",
    note = "library directory" },
  { pattern = "cgi-bin", category = "source", severity = "MEDIUM",
    note = "CGI directory" },
  { pattern = "wp-admin", category = "cms", severity = "HIGH",
    note = "WordPress administration" },
  { pattern = "wp-content", category = "cms", severity = "LOW",
    note = "WordPress content" },
  { pattern = "wp-includes", category = "cms", severity = "LOW",
    note = "WordPress core" },
  { pattern = "wp-config", category = "cms", severity = "HIGH",
    note = "WordPress configuration (database credentials)" },
  { pattern = "xmlrpc", category = "cms", severity = "MEDIUM",
    note = "WordPress XML-RPC (brute force amplification)" },
  { pattern = "administrator/components", category = "cms", severity = "HIGH",
    note = "Joomla administration" },
  { pattern = "sites/default", category = "cms", severity = "MEDIUM",
    note = "Drupal site directory" },
  { pattern = "storage", category = "framework", severity = "MEDIUM",
    note = "framework storage directory (Laravel)" },
  { pattern = "bootstrap/cache", category = "framework", severity = "MEDIUM",
    note = "framework cache directory" },
  { pattern = "solr", category = "search", severity = "HIGH",
    note = "Apache Solr" },
  { pattern = "elasticsearch", category = "search", severity = "HIGH",
    note = "Elasticsearch" },
  { pattern = "webdav", category = "file-transfer", severity = "HIGH",
    note = "WebDAV share" },
  { pattern = "dav", category = "file-transfer", severity = "HIGH",
    note = "WebDAV share" },
  { pattern = "ftp", category = "file-transfer", severity = "MEDIUM",
    note = "FTP gateway path" },
  { pattern = "phpinfo", category = "diagnostics", severity = "HIGH",
    note = "phpinfo() page" },
  { pattern = "info.php", category = "diagnostics", severity = "HIGH",
    note = "diagnostic script" },
  { pattern = "server-status", category = "diagnostics", severity = "HIGH",
    note = "Apache mod_status" },
  { pattern = "server-info", category = "diagnostics", severity = "HIGH",
    note = "Apache mod_info" },
  { pattern = "install", category = "non-production", severity = "HIGH",
    note = "installer (often re-runnable)" },
  { pattern = "setup", category = "non-production", severity = "MEDIUM",
    note = "setup script" },
  { pattern = "shell", category = "administration", severity = "HIGH",
    note = "web shell path" },
  { pattern = "export", category = "data", severity = "MEDIUM",
    note = "data export" },
  { pattern = "import", category = "data", severity = "MEDIUM",
    note = "data import" },
  { pattern = "report", category = "data", severity = "MEDIUM",
    note = "reporting output" },
  { pattern = "invoice", category = "data", severity = "HIGH",
    note = "financial documents" },
  { pattern = "customer", category = "data", severity = "HIGH",
    note = "customer data" },
  { pattern = "employee", category = "data", severity = "HIGH",
    note = "employee data" },
  { pattern = "hr", category = "data", severity = "HIGH",
    note = "human resources data" },
  { pattern = "finance", category = "data", severity = "HIGH",
    note = "financial data" },
  { pattern = "payment", category = "data", severity = "HIGH",
    note = "payment data" },
  { pattern = "metadata", category = "cloud", severity = "HIGH",
    note = "cloud metadata path" },
  { pattern = "latest/meta-data", category = "cloud", severity = "HIGH",
    note = "EC2 instance metadata path" },
}

local CRAWLER_DIRECTIVES = {
  "user-agent",
  "disallow",
  "allow",
  "sitemap",
  "crawl-delay",
  "request-rate",
  "visit-time",
  "host",
  "clean-param",
  "noindex",
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
  "/nse-robots-missing-%s",
  "/nse-robots-absent/%s.txt",
}

local DEFAULT_ARGS = {
  robots = nil,
  sitemaps = nil,
  maxsitemaps = 8,
  maxrules = 200,
  maxurls = 400,
  maxfollow = 25,
  maxrequests = 120,
  retries = 1,
  timeout = 8000,
  delay = 0.05,
  follow = true,
  soft404 = true,
  useragent = nil,
  maxbodysize = 524288,
}

local NUMERIC_ARGS = {
  { key = "maxsitemaps", minimum = 1, integer = true },
  { key = "maxrules", minimum = 10, integer = true },
  { key = "maxurls", minimum = 10, integer = true },
  { key = "maxfollow", minimum = 0, integer = true },
  { key = "maxrequests", minimum = 5, integer = true },
  { key = "retries", minimum = 0, integer = true },
  { key = "timeout", minimum = 500, integer = true },
  { key = "maxbodysize", minimum = 1024, integer = true },
}

local BOOLEAN_ARGS = { "follow", "soft404" }

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
  if type(host) == "table" then
    return tostring(host.targetname or host.name or host.ip or "unknown")
  end
  return tostring(host or "unknown")
end

local function normalize_origin(host, port)
  local ssl = port.ssl or (port.version and port.version.service_ssl)
  local scheme = ssl and "https" or "http"
  local default_port = ssl and 443 or 80
  local authority = host_label(host)
  if port.number and port.number ~= default_port then
    authority = authority .. ":" .. tostring(port.number)
  end
  return scheme .. "://" .. authority
end

local function path_of(url)
  local path = string.match(tostring(url or ""), "^https?://[^/]+(/.*)$")
  if path then
    return path
  end
  if starts_with(tostring(url or ""), "/") then
    return tostring(url)
  end
  return "/" .. tostring(url or "")
end

local function origin_of(url)
  local scheme, authority = string.match(tostring(url or ""), "^(https?)://([^/]+)")
  if not scheme then
    return nil
  end
  return scheme .. "://" .. lower(authority)
end

local function parse_robots(body, args)
  local rules = {}
  local sitemaps = {}
  local agents = {}
  local problems = {}
  local extras = {}
  local current_agents = {}
  local line_number = 0
  local limit = args.maxrules

  local text = string.gsub(tostring(body or ""), "^\239\187\191", "")
  text = string.gsub(text, "\r\n", "\n")
  text = string.gsub(text, "\r", "\n")

  for line in string.gmatch(text .. "\n", "(.-)\n") do
    line_number = line_number + 1
    local stripped = trim(line)
    if #stripped > 0 then
      local comment_start = string.find(stripped, "#", 1, true)
      if comment_start == 1 then
        goto continue_line
      end
      local content = stripped
      if comment_start then
        content = trim(string.sub(stripped, 1, comment_start - 1))
      end

      local field, value = string.match(content, "^([^:]+):%s*(.*)$")
      if not field then
        if #rules + #problems < 200 then
          table.insert(problems, string.format("line %d: malformed directive (%s)", line_number,
            truncate(stripped, 70)))
        end
        goto continue_line
      end

      local key = lower(trim(field))
      local val = trim(value)
      local known = false
      for _, directive in ipairs(CRAWLER_DIRECTIVES) do
        if key == directive then
          known = true
        end
      end
      if not known then
        table.insert(problems, string.format("line %d: unknown field '%s' (ignored by conforming crawlers)",
          line_number, key))
      end

      if key == "user-agent" then
        if #val == 0 then
          table.insert(problems, string.format("line %d: empty User-agent value", line_number))
        else
          local inserted = false
          for token in string.gmatch(val, "[^%s,]+") do
            if not list_contains(agents, token) then
              table.insert(agents, token)
            end
            table.insert(current_agents, token)
            inserted = true
          end
          if not inserted then
            table.insert(current_agents, val)
          end
        end
      elseif key == "disallow" or key == "allow" or key == "noindex" then
        if #current_agents == 0 then
          table.insert(problems, string.format(
            "line %d: %s rule appears before any User-agent group (applies to no crawler)",
            line_number, key))
          current_agents = { "*" }
        end
        local pattern = val
        local wildcard = contains(pattern, "*")
        local anchored = ends_with(pattern, "$")
        if anchored then
          pattern = string.sub(pattern, 1, #pattern - 1)
        end
        for _, agent in ipairs(current_agents) do
          if #rules < limit then
            table.insert(rules, {
              agent = agent,
              type = key,
              pattern = pattern,
              raw = val,
              wildcard = wildcard,
              anchored = anchored,
              empty = #val == 0,
              line = line_number,
            })
          end
        end
        if key == "noindex" then
          table.insert(problems, string.format(
            "line %d: Noindex in robots.txt is not supported by Google since 2007 - use X-Robots-Tag",
            line_number))
        end
      elseif key == "sitemap" then
        if #val > 0 then
          if not starts_with(val, "http") then
            table.insert(problems, string.format(
              "line %d: Sitemap value must be an absolute URL (got '%s')", line_number,
              truncate(val, 60)))
          end
          if not list_contains(sitemaps, val) then
            table.insert(sitemaps, val)
          end
        end
      elseif key == "crawl-delay" then
        local seconds = tonumber(val)
        table.insert(extras, string.format("Crawl-delay: %s%s", tostring(val),
          seconds and seconds > 0 and string.format(" (%.1f s between requests)", seconds) or ""))
      elseif key == "request-rate" then
        table.insert(extras, "Request-rate: " .. val)
      elseif key == "visit-time" then
        table.insert(extras, "Visit-time: " .. val)
      elseif key == "host" then
        table.insert(extras, "Host: " .. val)
      elseif key == "clean-param" then
        table.insert(extras, "Clean-param: " .. truncate(val, 80))
      end

      ::continue_line::
    end
  end

  return {
    rules = rules,
    sitemaps = sitemaps,
    agents = agents,
    problems = problems,
    extras = extras,
    lines = line_number,
  }
end

local function matches_rule(rule, path)
  if rule.empty then
    return true
  end
  local pattern = rule.pattern
  if rule.wildcard then
    local lua_pattern = "^"
    for index = 1, #pattern do
      local character = string.sub(pattern, index, index)
      if character == "*" then
        lua_pattern = lua_pattern .. ".*"
      else
        lua_pattern = lua_pattern .. string.gsub(character, "([%(%)%.%%%+%-%?%[%]%^%$])", "%%%1")
      end
    end
    if rule.anchored then
      lua_pattern = lua_pattern .. "$"
    end
    local ok, matched = pcall(string.find, path, lua_pattern)
    if not ok then
      return false
    end
    return matched ~= nil
  end
  if rule.anchored then
    return path == pattern
  end
  return starts_with(path, pattern)
end

local function effective_rule(rules, agent, path)
  local best = nil
  local best_length = -1
  for _, rule in ipairs(rules) do
    if (rule.agent == "*" or lower(rule.agent) == lower(agent or "*")) and matches_rule(rule, path) then
      local length = #rule.pattern
      if length > best_length then
        best_length = length
        best = rule
      end
    end
  end
  return best
end

local function sensitivity_of(path)
  local lowered = lower(path_of(path))
  local hits = {}
  for _, entry in ipairs(SENSITIVE_PATTERNS) do
    if contains(lowered, entry.pattern) then
      table.insert(hits, entry)
    end
  end
  local worst = nil
  for _, hit in ipairs(hits) do
    if not worst or (SEVERITY[hit.severity] or 0) > (SEVERITY[worst.severity] or 0) then
      worst = hit
    end
  end
  return hits, worst
end

local function parse_sitemap_urls(body, args)
  local urls = {}
  local seen = {}
  local child_sitemaps = {}
  local lastmods = {}
  local images = 0
  local videos = 0
  local limit = args.maxurls

  local text = tostring(body or "")
  if string.find(lower(text), "<sitemapindex", 1, true) then
    for block in string.gmatch(text, "<sitemap>(.-)</sitemap>") do
      local loc = string.match(block, "<loc>%s*([^<%s]+)%s*</loc>")
      if loc then
        loc = trim(string.gsub(loc, "&amp;", "&"))
        if #child_sitemaps < args.maxsitemaps and not list_contains(child_sitemaps, loc) then
          table.insert(child_sitemaps, loc)
        end
        local lastmod = string.match(block, "<lastmod>%s*([^<%s]+)%s*</lastmod>")
        if lastmod then
          table.insert(lastmods, { url = loc, lastmod = trim(lastmod) })
        end
      end
    end
  end

  for block in string.gmatch(text, "<url>(.-)</url>") do
    local loc = string.match(block, "<loc>%s*([^<%s]+)%s*</loc>")
    if loc then
      loc = trim(string.gsub(loc, "&amp;", "&"))
      if #urls < limit and not seen[loc] then
        seen[loc] = true
        table.insert(urls, loc)
      end
      local lastmod = string.match(block, "<lastmod>%s*([^<%s]+)%s*</lastmod>")
      if lastmod then
        table.insert(lastmods, { url = loc, lastmod = trim(lastmod) })
      end
    end
    for _ in string.gmatch(block, "<image:image>") do
      images = images + 1
    end
    for _ in string.gmatch(block, "<video:video>") do
      videos = videos + 1
    end
  end

  if #urls == 0 and #child_sitemaps == 0 and not string.find(lower(text), "<?xml", 1, true) then
    for line in string.gmatch(text, "([^\r\n]+)") do
      local candidate = trim(line)
      if starts_with(candidate, "http") and #urls < limit and not seen[candidate] then
        seen[candidate] = true
        table.insert(urls, candidate)
      end
    end
  end

  return {
    urls = urls,
    child_sitemaps = child_sitemaps,
    lastmods = lastmods,
    images = images,
    videos = videos,
  }
end

local function validate_lastmod(value)
  local year = tonumber(string.match(tostring(value), "^(%d%d%d%d)"))
  if not year then
    return false, "unparseable date"
  end
  if year < 1995 then
    return false, "date before the web (1995)"
  end
  local current_year = tonumber(os.date("%Y")) or year
  if year > current_year + 1 then
    return false, "date in the future"
  end
  return true, nil
end

local function classify_crawler_headers(response, path)
  local notes = {}
  local x_robots = header_values(response, "x-robots-tag")
  for _, value in ipairs(x_robots) do
    local lowered = lower(value)
    for _, directive in ipairs({ "noindex", "nofollow", "noarchive", "nosnippet", "nocache",
      "notranslate", "noimageindex", "unavailable_after", "max-snippet", "max-image-preview",
      "max-video-preview", "index", "follow", "all" }) do
      if contains(lowered, directive) then
        table.insert(notes, "X-Robots-Tag: " .. directive)
      end
    end
    if contains(lowered, "unavailable_after") then
      local when = string.match(lowered, "unavailable_after:%s*([^,;]+)")
      table.insert(notes, "content expires from the index after " .. tostring(when))
    end
  end

  local body = lower(response.body or "")
  local meta_robots = '<meta%s+name%s*=%s*' .. string.char(34) .. 'robots' .. string.char(34)
    .. '%s+content%s*=%s*' .. string.char(34) .. '([^' .. string.char(34) .. ']*)' .. string.char(34)
  local meta_robots_reverse = '<meta%s+content%s*=%s*' .. string.char(34)
    .. '([^' .. string.char(34) .. ']*)' .. string.char(34) .. '%s+name%s*=%s*' .. string.char(34)
    .. 'robots' .. string.char(34)
  local meta_googlebot = '<meta%s+name%s*=%s*' .. string.char(34) .. 'googlebot' .. string.char(34)
  local content = string.match(body, meta_robots) or string.match(body, meta_robots_reverse)
  if content then
    table.insert(notes, "meta robots: " .. content)
  end
  if string.find(body, meta_googlebot) then
    table.insert(notes, "meta googlebot directive present")
  end

  return notes
end

local function follow_path(host, port, path, args, baseline, origin)
  local result = { path = path }
  if budget_exhausted(args) then
    result.status = "budget"
    result.note = "request budget exhausted"
    return result
  end

  local response, err = fetch(host, port, path, args)
  if not response then
    result.status = "error"
    result.note = tostring(err)
    return result
  end

  result.status = response.status or 0
  result.length = #(response.body or "")
  result.content_type = header_value(response, "content-type")
  result.soft404 = looks_like_soft404(response, baseline)
  result.crawler_notes = classify_crawler_headers(response, path)
  result.location = header_value(response, "location")
  result.origin = origin_of(result.location)

  local info = classify_response(path, response, baseline)
  result.confidence = info.confidence
  if info.confidence == "low" then
    result.note = table.concat(info.notes, "; ")
  end
  return result
end

local function render_follow(result)
  local status = tostring(result.status)
  local verdict
  if result.status == "budget" or result.status == "error" then
    verdict = result.note or "not requested"
  elseif result.status == 404 then
    verdict = "not found"
  elseif result.status == 401 or result.status == 403 then
    verdict = "protected by authentication/authorisation"
  elseif result.soft404 then
    verdict = "answers with the catch-all page (soft-404)"
  elseif result.status >= 500 then
    verdict = "server error"
  elseif result.status >= 300 and result.status < 400 then
    verdict = "redirects to " .. tostring(result.location)
  elseif result.status == 200 then
    verdict = string.format("LIVE content, %d bytes, %s", result.length or 0,
      tostring(result.content_type or "unknown type"))
  else
    verdict = "HTTP " .. status
  end
  return string.format("%-46s %s -> %s", truncate(result.path, 46), status, verdict)
end

action = function(host, port)

  seed_random(port)
  reset_state()
  reset_findings()

  local args = read_args()
  local baseline = build_soft404_baseline(host, port, args)
  local origin = normalize_origin(host, port)

  local robots_list = {}
  local robots_seen = {}
  for _, candidate in ipairs(args.robots or ROBOTS_PATHS) do
    unique_append(robots_list, robots_seen, trim(candidate))
  end

  local parsed = nil
  local parsed_path = nil
  local robots_path = nil
  local robots_status = nil
  local robots_note = nil
  local robots_lines = {}

  for _, candidate in ipairs(robots_list) do
    if budget_exhausted(args) then
      break
    end
    local response, err = fetch(host, port, candidate, args)
    if not response then
      table.insert(robots_lines, string.format("%s: %s", candidate, tostring(err)))
      goto continue_robots
    end

    robots_status = response.status or 0
    robots_path = candidate
    local info = classify_response(candidate, response, baseline)
    local body = response.body or ""

    if info.confidence == "low" and contains(lower(table.concat(info.notes, ";")), "soft-404") then
      robots_note = "robots.txt answers with the catch-all page - no crawler policy is actually published"
      add_finding("MEDIUM", robots_note, { path = candidate, subject = "robots:catchall",
        evidence = truncate(body, 100), confidence = info.confidence })
      table.insert(robots_lines, string.format("%s -> HTTP %s, %d bytes: %s",
        candidate, tostring(robots_status), #body, robots_note))
      goto continue_robots
    end

    if robots_status == 404 then
      robots_note = "no robots.txt published: every crawler is allowed to fetch every path"
      add_finding("LOW", robots_note, { path = candidate, subject = "robots:absent",
        evidence = "HTTP 404" })
      table.insert(robots_lines, string.format("%s -> HTTP 404: %s", candidate, robots_note))
      goto continue_robots
    end

    if robots_status == 401 or robots_status == 403 then
      robots_note = "robots.txt is protected (HTTP " .. tostring(robots_status)
        .. "): RFC 9309 requires crawlers to treat this as 'no restrictions', so the intended "
        .. "hiding does not happen and the paths stay crawlable"
      add_finding("MEDIUM", robots_note, { path = candidate, subject = "robots:denied",
        evidence = "HTTP " .. tostring(robots_status) })
      table.insert(robots_lines, string.format("%s -> HTTP %s: %s", candidate,
        tostring(robots_status), robots_note))
      goto continue_robots
    end

    if robots_status >= 400 then
      robots_note = "robots.txt returned HTTP " .. tostring(robots_status)
      table.insert(robots_lines, string.format("%s -> HTTP %s", candidate, tostring(robots_status)))
      goto continue_robots
    end

    local candidate_rules = parse_robots(body, args)
    if parsed == nil or (#candidate_rules.rules > #parsed.rules and parsed_path ~= candidate) then
      parsed = candidate_rules
      parsed_path = candidate
    end
    robots_note = string.format("parsed %d rules for %d user-agents in %d lines",
      #candidate_rules.rules, #candidate_rules.agents, candidate_rules.lines)
    table.insert(robots_lines, string.format("%s -> HTTP %s, %d bytes: %s",
      candidate, tostring(robots_status), #body, robots_note))

    if #candidate_rules.problems > 0 then
      add_finding("LOW", string.format("robots.txt contains %d syntax/specification problem(s)",
        #candidate_rules.problems),
        { path = candidate, subject = "robots:syntax:" .. candidate,
          evidence = candidate_rules.problems[1] })
    end

    local disallow_all = false
    local allow_all = false
    for _, rule in ipairs(candidate_rules.rules) do
      if rule.type == "disallow" and rule.pattern == "/" then
        disallow_all = true
      end
      if rule.type == "disallow" and rule.empty then
        allow_all = true
      end
    end
    if disallow_all then
      add_finding("LOW", "robots.txt disallows everything (Disallow: /) - this is not an access control "
        .. "and the paths remain reachable; anything sensitive must be protected by authentication",
        { path = candidate, subject = "robots:disallow-all", evidence = "Disallow: /" })
    end
    if #candidate_rules.rules == 0 then
      add_finding("INFO", "robots.txt is present but defines no rules",
        { path = candidate, subject = "robots:empty", evidence = tostring(#body) .. " bytes" })
    elseif allow_all then
      add_finding("INFO", "robots.txt contains an empty Disallow (explicit allow-all)",
        { path = candidate, subject = "robots:allow-all", evidence = "Disallow:" })
    end

    ::continue_robots::
  end

  local rule_lines = {}
  local sensitive_entries = {}
  local sensitive_seen = {}
  local disallow_paths = {}
  local disallow_seen = {}

  if parsed then
    for _, rule in ipairs(parsed.rules) do
      local kind = rule.type
      local flags = {}
      if rule.wildcard then
        table.insert(flags, "wildcard")
      end
      if rule.anchored then
        table.insert(flags, "anchored")
      end
      if rule.empty then
        table.insert(flags, "empty (allow-all)")
      end
      table.insert(rule_lines, string.format("%-14s %-9s %-46s %s",
        truncate(rule.agent, 14), kind, truncate(rule.raw, 46),
        #flags > 0 and table.concat(flags, ",") or "literal prefix"))

      if rule.type == "disallow" and not rule.empty then
        local normalized = rule.pattern
        if not starts_with(normalized, "/") then
          normalized = "/" .. normalized
        end
        if unique_append(disallow_paths, disallow_seen, normalized) then
          local hits, worst = sensitivity_of(normalized)
          if worst and not sensitive_seen[normalized] then
            sensitive_seen[normalized] = true
            table.insert(sensitive_entries, {
              path = normalized,
              category = worst.category,
              severity = worst.severity,
              note = worst.note,
              patterns = hits,
            })
          end
        end
      end
    end

    for _, entry in ipairs(sensitive_entries) do
      add_finding(entry.severity, string.format(
        "robots.txt advertises a %s path: %s (%s)", entry.category, entry.path, entry.note),
        { path = entry.path, subject = "robots-sensitive:" .. entry.category,
          evidence = entry.note })
    end

    if #sensitive_entries == 0 and #disallow_paths > 0 then
      add_finding("INFO", string.format(
        "%d Disallow entries found, none matching a sensitive-path pattern", #disallow_paths),
        { subject = "robots-sensitive:none", evidence = table.concat(disallow_paths, ", ") })
    end
  end

  local sitemap_list = {}
  local sitemap_seen = {}
  for _, candidate in ipairs(args.sitemaps or SITEMAP_PATHS) do
    unique_append(sitemap_list, sitemap_seen, trim(candidate))
  end
  if parsed then
    for _, declared in ipairs(parsed.sitemaps) do
      local path = declared
      if starts_with(declared, "http") then
        local declared_origin = origin_of(declared)
        if declared_origin and lower(declared_origin) ~= lower(origin) then
          add_finding("MEDIUM", string.format(
            "robots.txt declares a sitemap on a different origin (%s)", declared_origin),
            { subject = "sitemap:foreign-origin", evidence = declared })
        end
        path = path_of(declared)
      end
      if not list_contains(sitemap_list, path) then
        table.insert(sitemap_list, path)
      end
    end
  end

  local sitemap_stats = {
    fetched = 0,
    found = 0,
    urls = {},
    url_seen = {},
    child_sitemaps = {},
    lastmods = {},
    images = 0,
    videos = 0,
    off_origin = {},
    insecure = {},
    credentialed = {},
    bad_dates = {},
    notes = {},
  }

  local queue = {}
  for _, candidate in ipairs(sitemap_list) do
    table.insert(queue, candidate)
  end
  local processed = 0

  while #queue > 0 and processed < args.maxsitemaps do
    local candidate = table.remove(queue, 1)
    if budget_exhausted(args) then
      table.insert(sitemap_stats.notes, "request budget exhausted; " .. #queue
        .. " sitemap(s) left unprocessed")
      break
    end
    processed = processed + 1

    local response, err = fetch(host, port, candidate, args)
    if not response then
      table.insert(sitemap_stats.notes, string.format("%s: %s", candidate, tostring(err)))
      goto continue_sitemap
    end

    local status = response.status or 0
    if status == 404 or status == 403 or status == 401 then
      table.insert(sitemap_stats.notes, string.format("%s -> HTTP %s (not published)", candidate,
        tostring(status)))
      goto continue_sitemap
    end

    local info = classify_response(candidate, response, baseline)
    if info.confidence == "low" and contains(lower(table.concat(info.notes, ";")), "soft-404") then
      table.insert(sitemap_stats.notes, string.format(
        "%s -> HTTP %s answers with the catch-all page (not a real sitemap)", candidate,
        tostring(status)))
      goto continue_sitemap
    end

    local body = response.body or ""
    local ctype = lower(header_value(response, "content-type") or "")
    local encoding = lower(header_value(response, "content-encoding") or "")
    local gzipped = contains(encoding, "gzip")
      or string.sub(body, 1, 2) == string.char(31) .. string.char(139)
    if gzipped and not contains(encoding, "gzip") then
      table.insert(sitemap_stats.notes, string.format(
        "%s -> HTTP %s: gzip-compressed body served without Content-Encoding: gzip (%d bytes); "
        .. "conforming crawlers will fail to parse it", candidate, tostring(status), #body))
      add_finding("LOW", string.format("%s serves gzip content without the Content-Encoding header",
        candidate),
        { path = candidate, subject = "sitemap:gzip-mismatch", evidence = ctype })
      goto continue_sitemap
    end

    if not contains(body, "<urlset") and not contains(body, "<sitemapindex")
      and not contains(lower(body), "http") then
      table.insert(sitemap_stats.notes, string.format(
        "%s -> HTTP %s: body is not a sitemap (%s, %d bytes)", candidate, tostring(status),
        #ctype > 0 and ctype or "unknown type", #body))
      goto continue_sitemap
    end

    sitemap_stats.fetched = sitemap_stats.fetched + 1
    local parsed_sitemap = parse_sitemap_urls(body, args)
    sitemap_stats.found = sitemap_stats.found + 1
    sitemap_stats.images = sitemap_stats.images + parsed_sitemap.images
    sitemap_stats.videos = sitemap_stats.videos + parsed_sitemap.videos

    for _, url in ipairs(parsed_sitemap.urls) do
      if not sitemap_stats.url_seen[url] then
        sitemap_stats.url_seen[url] = true
        table.insert(sitemap_stats.urls, url)
      end
      local url_origin = origin_of(url)
      if url_origin and lower(url_origin) ~= lower(origin) then
        if not list_contains(sitemap_stats.off_origin, url_origin) then
          table.insert(sitemap_stats.off_origin, url_origin)
        end
      end
      if starts_with(url, "http://") and (port.ssl or (port.version and port.version.service_ssl)) then
        if not list_contains(sitemap_stats.insecure, url) then
          table.insert(sitemap_stats.insecure, url)
        end
      end
      if string.find(url, [[://[^/]*:[^/@]*@]]) or contains(lower(url), "sessionid=")
        or contains(lower(url), "sid=") or contains(lower(url), "token=")
        or contains(lower(url), "auth=") or contains(lower(url), "api_key=") then
        if not list_contains(sitemap_stats.credentialed, url) then
          table.insert(sitemap_stats.credentialed, url)
        end
      end
    end

    for _, child in ipairs(parsed_sitemap.child_sitemaps) do
      if not list_contains(sitemap_stats.child_sitemaps, child) then
        table.insert(sitemap_stats.child_sitemaps, child)
      end
      if not list_contains(queue, path_of(child)) and processed + #queue < args.maxsitemaps then
        table.insert(queue, path_of(child))
      end
    end

    for _, entry in ipairs(parsed_sitemap.lastmods) do
      local valid, reason = validate_lastmod(entry.lastmod)
      if not valid then
        table.insert(sitemap_stats.bad_dates, string.format("%s: %s (%s)",
          truncate(entry.url, 60), entry.lastmod, reason))
      end
      table.insert(sitemap_stats.lastmods, entry)
    end

    table.insert(sitemap_stats.notes, string.format("%s -> HTTP %s: %d URL(s), %d child sitemap(s)",
      candidate, tostring(status), #parsed_sitemap.urls, #parsed_sitemap.child_sitemaps))

    ::continue_sitemap::
  end

  if #sitemap_stats.off_origin > 0 then
    add_finding("MEDIUM", string.format("sitemap references %d foreign origin(s): %s",
      #sitemap_stats.off_origin, table.concat(sitemap_stats.off_origin, ", ")),
      { subject = "sitemap:off-origin", evidence = table.concat(sitemap_stats.off_origin, ", ") })
  end
  if #sitemap_stats.insecure > 0 then
    add_finding("LOW", string.format("%d sitemap URL(s) use http:// on an HTTPS service",
      #sitemap_stats.insecure),
      { subject = "sitemap:insecure", evidence = sitemap_stats.insecure[1] })
  end
  if #sitemap_stats.credentialed > 0 then
    add_finding("HIGH", string.format(
      "%d sitemap URL(s) embed credentials, session or token parameters", #sitemap_stats.credentialed),
      { subject = "sitemap:credentials", evidence = truncate(sitemap_stats.credentialed[1], 120) })
  end
  if #sitemap_stats.bad_dates > 0 then
    add_finding("LOW", string.format("%d sitemap lastmod value(s) are invalid",
      #sitemap_stats.bad_dates),
      { subject = "sitemap:lastmod", evidence = sitemap_stats.bad_dates[1] })
  end
  if sitemap_stats.found == 0 then
    add_finding("INFO", "no sitemap document was found at the tested locations",
      { subject = "sitemap:none", evidence = tostring(processed) .. " candidates requested" })
  end

  local follow_results = {}
  local follow_candidates = {}
  for _, entry in ipairs(sensitive_entries) do
    table.insert(follow_candidates, entry.path)
  end
  if parsed then
    for _, path in ipairs(disallow_paths) do
      if not list_contains(follow_candidates, path) then
        table.insert(follow_candidates, path)
      end
    end
  end
  for _, url in ipairs(sitemap_stats.urls) do
    local hits, worst = sensitivity_of(url)
    if worst and #follow_candidates < args.maxfollow * 2 then
      local candidate = path_of(url)
      if not list_contains(follow_candidates, candidate) then
        table.insert(follow_candidates, candidate)
      end
    end
  end

  if args.follow then
    local followed = 0
    for _, candidate in ipairs(follow_candidates) do
      if followed >= args.maxfollow or budget_exhausted(args) then
        break
      end
      followed = followed + 1
      table.insert(follow_results, follow_path(host, port, candidate, args, baseline, origin))
    end
  end

  for _, result in ipairs(follow_results) do
    if result.status == 200 and not result.soft404 then
      local hits, worst = sensitivity_of(result.path)
      local severity = worst and worst.severity or "MEDIUM"
      add_finding(severity, string.format(
        "a path hidden by robots.txt is publicly reachable (HTTP 200, %d bytes): %s",
        result.length or 0, result.path),
        { path = result.path, subject = "reachable:" .. result.path,
          evidence = tostring(result.content_type or "unknown type") })
    elseif result.status == 403 or result.status == 401 then
      add_finding("INFO", string.format("%s is protected (HTTP %s)", result.path, tostring(result.status)),
        { path = result.path, subject = "protected:" .. result.path,
          evidence = "HTTP " .. tostring(result.status) })
    end
    for _, note in ipairs(result.crawler_notes or {}) do
      add_finding("INFO", string.format("%s publishes crawler directive: %s", result.path, note),
        { path = result.path, subject = "crawler:" .. lower(note) .. ":" .. result.path,
          evidence = note })
    end
  end

  local follow_lines = {}
  for _, result in ipairs(follow_results) do
    table.insert(follow_lines, render_follow(result))
  end

  local sitemap_url_lines = {}
  for index, url in ipairs(sitemap_stats.urls) do
    if index > 60 then
      table.insert(sitemap_url_lines, string.format("... and %d more URLs",
        #sitemap_stats.urls - 60))
      break
    end
    local hits, worst = sensitivity_of(url)
    table.insert(sitemap_url_lines, string.format("%-64s %s", truncate(url, 64),
      worst and ("sensitive: " .. worst.category) or ""))
  end

  local unique, counts = dedupe_findings()

  local out = new_output(RISK_LEVEL, "AUDITED - crawler documents reviewed.")
  if counts.HIGH > 0 then
    out["Status"] = "VULNERABLE - published crawler documents expose sensitive, reachable paths."
  elseif counts.MEDIUM > 0 then
    out["Status"] = "AUDITED - crawler documents disclose sensitive paths or inconsistent policy."
  elseif parsed and #parsed.rules > 0 then
    out["Status"] = "AUDITED - robots.txt is published and no sensitive path is advertised."
  elseif sitemap_stats.found > 0 then
    out["Status"] = "AUDITED - sitemap published, robots.txt absent or empty."
  else
    out["Status"] = "AUDITED - no robots.txt policy and no sitemap document were found."
  end

  local sections = {
    { key = "Transport", value = (port.ssl or (port.version and port.version.service_ssl)) and "HTTPS" or "HTTP" },
    { key = "Origin", value = origin },
    { key = "robots.txt", value = robots_lines },
  }

  if #rule_lines > 0 then
    table.insert(sections, { key = "Parsed rules", value = rule_lines })
  end
  if parsed and #parsed.extras > 0 then
    table.insert(sections, { key = "Crawler directives", value = parsed.extras })
  end
  if parsed and #parsed.problems > 0 then
    table.insert(sections, { key = "robots.txt problems", value = parsed.problems })
  end
  if parsed and #parsed.agents > 0 then
    table.insert(sections, { key = "Addressed user-agents", value = table.concat(parsed.agents, ", ") })
  end

  local sensitive_lines = {}
  for _, entry in ipairs(sensitive_entries) do
    table.insert(sensitive_lines, string.format("[%s] %-14s %s (%s)",
      entry.severity, entry.category, entry.path, entry.note))
  end
  if #sensitive_lines > 0 then
    table.insert(sections, { key = "Sensitive robots entries", value = sensitive_lines })
  end

  table.insert(sections, { key = "Sitemap summary", value = string.format(
    "documents found: %d, URLs: %d, child sitemaps: %d, image entries: %d, video entries: %d, off-origin: %d, insecure: %d",
    sitemap_stats.found, #sitemap_stats.urls, #sitemap_stats.child_sitemaps,
    sitemap_stats.images, sitemap_stats.videos, #sitemap_stats.off_origin,
    #sitemap_stats.insecure) })

  if #sitemap_url_lines > 0 then
    table.insert(sections, { key = "Sitemap URLs", value = sitemap_url_lines })
  end
  if #sitemap_stats.notes > 0 then
    table.insert(sections, { key = "Sitemap fetch log", value = sitemap_stats.notes })
  end
  if #sitemap_stats.bad_dates > 0 then
    table.insert(sections, { key = "Invalid lastmod values", value = sitemap_stats.bad_dates })
  end
  if #follow_lines > 0 then
    table.insert(sections, { key = "Live status of hidden paths", value = follow_lines })
  end
  if baseline.enabled and baseline.samples > 0 then
    table.insert(sections, { key = "Soft-404 baseline", value = string.format(
      "%d probes, dominant status %s, %s", baseline.samples,
      tostring(baseline.dominant_status or "n/a"),
      baseline.consistent and "catch-all confirmed" or "no catch-all") })
  end

  if #sensitive_entries > 0 then
    table.insert(sections, { key = "Remediation", value =
      "robots.txt is a hint file, not an access control: remove sensitive paths from Disallow (that "
      .. "is what advertises them) and protect them with authentication, an authorisation check or by "
      .. "moving them off the public listener" })
  else
    table.insert(sections, { key = "Remediation", value =
      "keep robots.txt minimal, publish only the paths crawlers must not index, express indexing "
      .. "policy with X-Robots-Tag on non-HTML responses, and review the sitemap after every release "
      .. "so stale and credentialed URLs are not published" })
  end

  table.insert(sections, { key = "Requests issued", value = state.requests .. " of " .. args.maxrequests })

  return finish_output(out, unique, counts, sections)

end
