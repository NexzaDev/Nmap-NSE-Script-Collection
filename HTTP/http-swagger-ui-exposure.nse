local shortport = require "shortport"

local http = require "http"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Finds publicly reachable Swagger / OpenAPI API specifications and the
interactive documentation UIs (Swagger UI, ReDoc, Scalar, Stoplight Elements,
GraphiQL) that render them, then parses what the document actually contains.

Why it matters
An exposed API specification is a free attack map: every endpoint path, every
HTTP method, every parameter name, the data models, the authentication model
and, in many cases, internal server addresses and OAuth token endpoints.
Administrative, internal, export, upload, backup and token endpoints that a
developer documented for the team become a checklist for anyone who can reach
the document - and the interactive UI lets a visitor call the endpoints with
one click, which lowers the barrier to abuse considerably.

What the script fetches
80+ candidate paths covering the common locations: Swagger UI entry points
(swagger-ui.html, swagger-ui/, swagger-ui-dist, static and asset variants),
the Spring API-docs family (v2/api-docs, v3/api-docs and the Springdoc/Springfox
grouped variants under /api/ prefixes), the OpenAPI family (openapi.json,
openapi.yaml, /api/spec, versioned variants), API-docs HTML (api/docs,
api/documentation, apidocs, doc, docs), ReDoc, Scalar and Stoplight entry
points, GraphiQL, GraphQL endpoints, drf-yasg and drf-spectacular (Django)
locations, WCF doc.json, and the Springfox swagger-resources group registry
including its configuration sub-paths.

How documents are confirmed
A response only counts as an API specification when it carries strong document
markers (openapi/swagger version field, info block, paths block, security
block) AND parses as JSON or YAML into a table that actually has an openapi or
swagger key - so a catch-all JSON page or an HTML error page cannot masquerade
as a spec. The script carries its own compact JSON parser and a YAML subset
parser (nested maps, block and flow lists, quoted scalars, booleans, numbers)
because Nmap has no JSON library. Interactive UIs are confirmed by HTML
bootstrap markers (SwaggerUIBundle, OpenAPIInitOas, Redoc.init, Scalar,
Stoplight, GraphiQL) on an HTML response. Responses with partial markers that
do not parse are reported as suspected and left to manual review.

What is extracted from a confirmed specification
The document identity (title, service version, contact, license, tags, vendor
x- extensions), the declared servers plus host/basePath/schemes for Swagger 2
plus every http(s) URL embedded anywhere in the document, classified against
internal topology patterns (loopback, RFC1918, link-local/metadata, .internal,
.corp, .local, 172.16/12, staging/dev/uat/sandbox names). Every path is scored
against a sensitive-endpoint policy (administrative, internal, debug,
backup/restore, execute/eval, export/import, upload/download, password,
token, payment/wallet/transfer, config, keys/certificates, git, lifecycle,
user data and more). The security model is analysed: each declared scheme
(http basic/bearer, apiKey, oauth2 flows, openid), whether a global security
requirement exists, and how many operations carry no security requirement at
all. Sensitive data field names in the component schemas and sensitive request
parameter names are collected.

What is extracted from a confirmed UI
The UI flavour, its library version when present, and the specification URL
it is configured to load (url/configUrl/oasURL/specUrl/spec attributes and the
Redoc.init argument). Referenced specification URLs on the same host are
fetched and analysed with the same pipeline; external hosts are reported
instead of being followed. Springfox swagger-resources registries are parsed
and every listed group location is followed the same way. If the base
v2/api-docs or v3/api-docs location does not serve a specification, common
group names (default, v1, v2, v3, api, admin, internal, public, private,
management, deprecated, store, user, core, system, debug) are probed on top of
it.

Output and limits
Output is grouped per document (identity, servers, security model, sensitive
endpoints, sensitive fields and parameters), plus an aggregated sensitive API
surface, infrastructure disclosure and version disclosure sections, a fetch
log and a remediation summary. Every duplicate document (same content hash at
several paths) is collapsed to one analysis. The script is strictly passive:
GET requests only, no authentication bypass attempts, no interaction with the
documented endpoints themselves, bounded by maxrequests and a soft-404
baseline that suppresses catch-all pages.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"vuln", "discovery", "safe"}

portrule = shortport.http

local SCRIPT_NAME = "http-swagger-ui-exposure"

local RISK_LEVEL = "🟡 MEDIUM"

local CANDIDATE_PATHS = {
  "/swagger-ui.html", "/swagger-ui/", "/swagger-ui/index.html",
  "/swagger-ui-dist/index.html", "/static/swagger-ui/index.html",
  "/assets/swagger-ui.html", "/docs/swagger-ui.html", "/api/swagger-ui.html",
  "/api/swagger-ui/", "/api/swagger-ui/index.html",
  "/swagger-ui-bundle.js", "/swagger-ui.css",
  "/swagger.json", "/swagger.yaml", "/swagger.v1.json", "/swagger.v2.json",
  "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
  "/swagger/docs", "/swagger/doc.json", "/api/swagger.json", "/api/swagger.yaml",
  "/api/doc.json",
  "/api-docs", "/api-docs/default", "/api-docs/deprecated",
  "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
  "/v3/api-docs/default", "/v3/api-docs/deprecated",
  "/api/v2/api-docs", "/api/v3/api-docs", "/api/api-docs",
  "/openapi.json", "/openapi.yaml", "/openapi/v1.json", "/openapi/v1.yaml",
  "/openapi/1.0.json", "/openapi/1.0.yaml", "/api/openapi.json",
  "/api/openapi.yaml", "/api/spec.json", "/api/spec.yaml",
  "/api/docs", "/api/docs/", "/api/docs/swagger.json", "/api/docs/openapi.json",
  "/api/docs/interactive", "/api/documentation",
  "/apidocs", "/apidocs/index.html", "/apidocs/swagger.json",
  "/doc", "/docs", "/docs/api", "/docs/openapi.json",
  "/redoc", "/redoc/index.html", "/api/redoc",
  "/scalar", "/api/scalar", "/stoplight",
  "/graphiql", "/api/graphiql", "/graphql", "/api/graphql",
  "/api-explorer", "/api/developer", "/developer/api", "/developer/docs",
  "/drf-yasg", "/drf-yasg/swagger.json", "/drf-yasg/swagger-ui.html",
  "/drf-yasg/redoc/", "/drf-spectacular", "/api/schema/", "/schema/openapi.yaml",
  "/swagger-resources", "/swagger-resources/configuration/security",
  "/swagger-resources/configuration/ui", "/api/swagger-resources",
  "/swaggerhub.json", "/api/swaggerhub.json",
}

local GROUP_NAMES = {
  "default", "v1", "v2", "v3", "api", "admin", "internal", "public",
  "private", "management", "deprecated", "store", "user", "core", "system", "debug",
}

local HTTP_METHODS = {
  get = true, post = true, put = true, delete = true,
  options = true, head = true, patch = true, trace = true,
}

local SPEC_MARKERS = {
  { pattern = "\"openapi\"", weight = 5, note = "OpenAPI 3 document field" },
  { pattern = "\"swagger\"", weight = 5, note = "Swagger 2.0 document field" },
  { pattern = "openapi: 3", weight = 3, note = "OpenAPI 3 YAML field" },
  { pattern = "openapi: \"3", weight = 3, note = "OpenAPI 3 YAML field" },
  { pattern = "swagger: \"2.0\"", weight = 4, note = "Swagger 2.0 YAML field" },
  { pattern = "swagger: 2.0", weight = 3, note = "Swagger 2.0 YAML field" },
  { pattern = "\"info\"", weight = 1, note = "info block" },
  { pattern = "\"paths\"", weight = 2, note = "paths block" },
  { pattern = "paths:", weight = 1, note = "paths block (YAML)" },
  { pattern = "\"securitySchemes\"", weight = 2, note = "securitySchemes block" },
  { pattern = "\"securityDefinitions\"", weight = 2, note = "securityDefinitions block" },
  { pattern = "\"servers\"", weight = 1, note = "servers block" },
  { pattern = "\"components\"", weight = 1, note = "components block" },
  { pattern = "\"definitions\"", weight = 1, note = "definitions block" },
  { pattern = "\"schemas\"", weight = 1, note = "schemas block" },
  { pattern = "\"tags\"", weight = 1, note = "tags block" },
  { pattern = "\"externalDocs\"", weight = 1, note = "externalDocs block" },
}

local UI_MARKERS = {
  { pattern = "Swagger UI", weight = 2, note = "Swagger UI title" },
  { pattern = "swagger-ui", weight = 2, note = "swagger-ui asset reference" },
  { pattern = "SwaggerUIBundle", weight = 3, note = "SwaggerUIBundle bootstrap" },
  { pattern = "OpenAPIInitOas", weight = 3, note = "OpenAPIInitOas bootstrap" },
  { pattern = "swagger-ui-bundle", weight = 2, note = "swagger-ui bundle script" },
  { pattern = "swagger-ui.css", weight = 2, note = "swagger-ui stylesheet" },
  { pattern = "Redoc.init", weight = 3, note = "ReDoc bootstrap" },
  { pattern = "redoc", weight = 1, note = "ReDoc asset reference" },
  { pattern = "scalar-api-reference", weight = 3, note = "Scalar API reference element" },
  { pattern = "scalar_api_reference", weight = 2, note = "Scalar API reference element" },
  { pattern = "@stoplight/elements", weight = 2, note = "Stoplight Elements asset" },
  { pattern = "stoplight-elements", weight = 2, note = "Stoplight Elements asset" },
  { pattern = "graphiql", weight = 3, note = "GraphiQL explorer" },
  { pattern = "__schema", weight = 2, note = "GraphQL introspection field" },
  { pattern = "oas-init", weight = 2, note = "OpenAPI init element" },
}

local SENSITIVE_PATH_RULES = {
  { pattern = "admin", severity = "CRITICAL", note = "administrative endpoint" },
  { pattern = "administrator", severity = "CRITICAL", note = "administrative endpoint" },
  { pattern = "admins", severity = "CRITICAL", note = "administrative endpoint" },
  { pattern = "internal", severity = "CRITICAL", note = "internal-only endpoint" },
  { pattern = "debug", severity = "CRITICAL", note = "debug endpoint" },
  { pattern = "debugger", severity = "CRITICAL", note = "debug endpoint" },
  { pattern = "secret", severity = "CRITICAL", note = "endpoint named after stored secrets" },
  { pattern = "secrets", severity = "CRITICAL", note = "endpoint named after stored secrets" },
  { pattern = "backup", severity = "CRITICAL", note = "backup endpoint" },
  { pattern = "backups", severity = "CRITICAL", note = "backup endpoint" },
  { pattern = "restore", severity = "CRITICAL", note = "restore endpoint" },
  { pattern = "restores", severity = "CRITICAL", note = "restore endpoint" },
  { pattern = "execute", severity = "CRITICAL", note = "code execution endpoint" },
  { pattern = "exec", severity = "CRITICAL", note = "code execution endpoint" },
  { pattern = "eval", severity = "CRITICAL", note = "code execution endpoint" },
  { pattern = "evaluate", severity = "CRITICAL", note = "code execution endpoint" },
  { pattern = "export", severity = "HIGH", note = "bulk data export endpoint" },
  { pattern = "exports", severity = "HIGH", note = "bulk data export endpoint" },
  { pattern = "import", severity = "HIGH", note = "bulk data import endpoint" },
  { pattern = "imports", severity = "HIGH", note = "bulk data import endpoint" },
  { pattern = "upload", severity = "HIGH", note = "file upload endpoint" },
  { pattern = "uploads", severity = "HIGH", note = "file upload endpoint" },
  { pattern = "download", severity = "HIGH", note = "file download endpoint" },
  { pattern = "downloads", severity = "HIGH", note = "file download endpoint" },
  { pattern = "password", severity = "HIGH", note = "password management endpoint" },
  { pattern = "passwords", severity = "HIGH", note = "password management endpoint" },
  { pattern = "passwd", severity = "HIGH", note = "password management endpoint" },
  { pattern = "token", severity = "HIGH", note = "token issuance or refresh endpoint" },
  { pattern = "tokens", severity = "HIGH", note = "token issuance or refresh endpoint" },
  { pattern = "payment", severity = "HIGH", note = "financial endpoint" },
  { pattern = "payments", severity = "HIGH", note = "financial endpoint" },
  { pattern = "wallet", severity = "HIGH", note = "financial endpoint" },
  { pattern = "wallets", severity = "HIGH", note = "financial endpoint" },
  { pattern = "transfer", severity = "HIGH", note = "financial endpoint" },
  { pattern = "transfers", severity = "HIGH", note = "financial endpoint" },
  { pattern = "config", severity = "HIGH", note = "configuration endpoint" },
  { pattern = "configuration", severity = "HIGH", note = "configuration endpoint" },
  { pattern = "certificate", severity = "HIGH", note = "certificate handling endpoint" },
  { pattern = "certificates", severity = "HIGH", note = "certificate handling endpoint" },
  { pattern = "key", severity = "HIGH", note = "key handling endpoint" },
  { pattern = "keys", severity = "HIGH", note = "key handling endpoint" },
  { pattern = "git", severity = "HIGH", note = "repository disclosure endpoint" },
  { pattern = "setup", severity = "HIGH", note = "lifecycle endpoint" },
  { pattern = "install", severity = "HIGH", note = "lifecycle endpoint" },
  { pattern = "maintenance", severity = "HIGH", note = "lifecycle endpoint" },
  { pattern = "upgrade", severity = "HIGH", note = "lifecycle endpoint" },
  { pattern = "webhook", severity = "MEDIUM", note = "webhook registration endpoint" },
  { pattern = "webhooks", severity = "MEDIUM", note = "webhook registration endpoint" },
  { pattern = "login", severity = "MEDIUM", note = "authentication endpoint" },
  { pattern = "logout", severity = "MEDIUM", note = "authentication endpoint" },
  { pattern = "auth", severity = "MEDIUM", note = "authentication endpoint" },
  { pattern = "authentication", severity = "MEDIUM", note = "authentication endpoint" },
  { pattern = "reset", severity = "MEDIUM", note = "account reset endpoint" },
  { pattern = "resets", severity = "MEDIUM", note = "account reset endpoint" },
  { pattern = "user", severity = "MEDIUM", note = "user data endpoint" },
  { pattern = "users", severity = "MEDIUM", note = "user data endpoint" },
  { pattern = "account", severity = "MEDIUM", note = "account data endpoint" },
  { pattern = "accounts", severity = "MEDIUM", note = "account data endpoint" },
  { pattern = "profile", severity = "MEDIUM", note = "user profile endpoint" },
  { pattern = "file", severity = "MEDIUM", note = "file handling endpoint" },
  { pattern = "files", severity = "MEDIUM", note = "file handling endpoint" },
  { pattern = "env", severity = "MEDIUM", note = "environment endpoint" },
  { pattern = "environment", severity = "MEDIUM", note = "environment endpoint" },
  { pattern = "manage", severity = "MEDIUM", note = "management endpoint" },
  { pattern = "management", severity = "MEDIUM", note = "management endpoint" },
  { pattern = "query", severity = "LOW", note = "raw query interface" },
  { pattern = "queries", severity = "LOW", note = "raw query interface" },
}

local SENSITIVE_FIELD_PATTERNS = {
  "password", "passwd", "secret", "apikey", "api_key", "api-key",
  "access_token", "refresh_token", "auth_token", "session_id",
  "ssn", "cvv", "private_key", "passphrase", "credit_card",
  "client_secret", "signature",
}

local SENSITIVE_PARAM_PATTERNS = {
  "password", "passwd", "secret", "apikey", "api_key", "api-key",
  "token", "auth", "session", "internal", "debug", "admin",
  "override", "force", "signature", "nonce",
}

local INTERNAL_HOST_MARKERS = {
  { pattern = "127.0.0.1", note = "loopback address" },
  { pattern = "0.0.0.0", note = "unspecified address (0.0.0.0)" },
  { pattern = "localhost", note = "localhost name" },
  { pattern = "10.", note = "private 10/8 address" },
  { pattern = "192.168.", note = "private 192.168/16 address" },
  { pattern = "169.254.", note = "link-local or cloud metadata address" },
  { pattern = ".internal", note = "internal hostname" },
  { pattern = ".local", note = "local hostname" },
  { pattern = ".corp", note = "corporate hostname" },
  { pattern = ".lan", note = "LAN hostname" },
  { pattern = ".home", note = "home network hostname" },
}

local STAGING_HINTS = {
  "staging", "stg", "uat", "sandbox", "demo", "dev", "test", "qa",
}

local SPEC_URL_PATTERNS = {
  "configUrl: *\"([^\"]+)\"",
  "configUrl: *'([^']+)'",
  "oasURL: *\"([^\"]+)\"",
  "oasURL: *'([^']+)'",
  "specUrl: *\"([^\"]+)\"",
  "specUrl: *'([^']+)'",
  "spec=\"([^\"]+)\"",
  "spec='([^']+)'",
  "spec: *\"([^\"]+)\"",
  "spec: *'([^']+)'",
  "url: *\"([^\"]+)\"",
  "url: *'([^']+)'",
  "url:\"([^\"]+)\"",
  "url:'([^']+)'",
  "Redoc.init[\"']([^\"']+)",
}

local UI_SUBTYPE_MARKERS = {
  { name = "swagger-ui", patterns = {
    "SwaggerUIBundle", "OpenAPIInitOas", "swagger-ui-bundle", "swagger-ui.css", "swagger-ui.js",
  } },
  { name = "redoc", patterns = { "Redoc.init", "redoc.min.js", "redoc.standalone" } },
  { name = "scalar", patterns = { "scalar-api-reference", "scalar_api_reference" } },
  { name = "stoplight", patterns = { "@stoplight/elements", "stoplight-elements" } },
  { name = "graphiql", patterns = { "graphiql", "__schema" } },
}

local UI_VERSION_PATTERNS = {
  "swagger-ui-(%d+%.%d+%.%d+)",
  "swagger-ui-dist/(%d+%.%d+%.%d+)",
  "SwaggerUIBundle v(%d+%.%d+%.%d+)",
  "swagger-ui-bundle%.(%d+%.%d+%.%d+)",
}

local SEVERITY_ORDER = {
  CRITICAL = 1, HIGH = 2, MEDIUM = 3, LOW = 4, INFO = 5,
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
  "/nse-swagger-missing-%s.json",
  "/nse-swagger-absent/%s/openapi.yaml",
}

local DEFAULT_ARGS = {
  paths = nil,
  maxpaths = 90,
  maxrequests = 160,
  retries = 1,
  timeout = 10000,
  delay = 0.05,
  soft404 = true,
  maxbodysize = 1048576,
  useragent = nil,
}

local NUMERIC_ARGS = {
  { key = "maxpaths", minimum = 1, integer = true },
  { key = "maxrequests", minimum = 4, integer = true },
  { key = "retries", minimum = 0, integer = true },
  { key = "timeout", minimum = 500, integer = true },
  { key = "maxbodysize", minimum = 4096, integer = true },
}

local BOOLEAN_ARGS = { "soft404" }

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
  for _, candidate in ipairs(args.paths or CANDIDATE_PATHS) do
    local normalized = trim(tostring(candidate))
    if #normalized == 0 then
      normalized = "/"
    end
    if not starts_with(normalized, "/") then
      normalized = "/" .. normalized
    end
    if unique_append(selected, seen, normalized) then
      if #selected >= args.maxpaths then
        break
      end
    end
  end
  if #selected == 0 then
    table.insert(selected, "/swagger-ui.html")
  end
  return selected
end

local function as_string(value)
  if type(value) == "string" and #value > 0 then
    return value
  end
  if type(value) == "number" then
    return tostring(value)
  end
  return nil
end

local function is_map(value)
  return type(value) == "table" and value.__map == true
end

local function is_seq(value)
  return type(value) == "table" and value.__map ~= true
end

local function boundary_hit(haystack, pattern)
  local from = 1
  local size = #haystack
  while true do
    local start_pos, stop_pos = string.find(haystack, pattern, from, true)
    if not start_pos then
      return false
    end
    local before_ok = true
    local after_ok = true
    if start_pos > 1 then
      local prev = string.sub(haystack, start_pos - 1, start_pos - 1)
      if string.match(prev, "[%a0-9]") then
        before_ok = false
      end
    end
    if stop_pos < size then
      local next_char = string.sub(haystack, stop_pos + 1, stop_pos + 1)
      if string.match(next_char, "[%a0-9]") then
        after_ok = false
      end
    end
    if before_ok and after_ok then
      return true
    end
    from = stop_pos + 1
  end
end

local function json_parse(text)
  local pos = 1
  local size = #text

  local function skip_ws()
    local next_pos = string.find(text, "[^ \t\r\n]", pos)
    if next_pos then
      pos = next_pos
    else
      pos = size + 1
    end
  end

  local parse_value

  local function parse_string()
    pos = pos + 1
    local chunks = {}
    while pos <= size do
      local ch = string.sub(text, pos, pos)
      if ch == "\"" then
        pos = pos + 1
        return table.concat(chunks)
      elseif ch == "\\" then
        local esc = string.sub(text, pos + 1, pos + 1)
        if esc == "\"" then
          table.insert(chunks, "\"")
        elseif esc == "\\" then
          table.insert(chunks, "\\")
        elseif esc == "/" then
          table.insert(chunks, "/")
        elseif esc == "b" then
          table.insert(chunks, string.char(8))
        elseif esc == "f" then
          table.insert(chunks, string.char(12))
        elseif esc == "n" then
          table.insert(chunks, string.char(10))
        elseif esc == "r" then
          table.insert(chunks, string.char(13))
        elseif esc == "t" then
          table.insert(chunks, string.char(9))
        elseif esc == "u" then
          local code = tonumber(string.sub(text, pos + 2, pos + 5), 16)
          if code and code < 128 then
            table.insert(chunks, string.char(code))
          else
            table.insert(chunks, "?")
          end
          pos = pos + 4
        else
          table.insert(chunks, esc)
        end
        pos = pos + 2
      else
        table.insert(chunks, ch)
        pos = pos + 1
      end
    end
    pos = size + 1
    return table.concat(chunks)
  end

  local function parse_number()
    local number = string.match(text, "-?%d+%.?%d*[eE]?[+-]?%d*", pos)
    if not number then
      error("json: invalid number at position " .. tostring(pos))
    end
    pos = pos + #number
    return tonumber(number)
  end

  local function parse_object()
    pos = pos + 1
    local obj = {}
    obj.__map = true
    skip_ws()
    if string.sub(text, pos, pos) == "}" then
      pos = pos + 1
      return obj
    end
    while true do
      skip_ws()
      if string.sub(text, pos, pos) ~= "\"" then
        error("json: expected string key at position " .. tostring(pos))
      end
      local key = parse_string()
      skip_ws()
      if string.sub(text, pos, pos) ~= ":" then
        error("json: expected colon at position " .. tostring(pos))
      end
      pos = pos + 1
      obj[key] = parse_value()
      skip_ws()
      local tail = string.sub(text, pos, pos)
      if tail == "," then
        pos = pos + 1
      elseif tail == "}" then
        pos = pos + 1
        return obj
      else
        error("json: expected comma or closing brace at position " .. tostring(pos))
      end
    end
  end

  local function parse_array()
    pos = pos + 1
    local arr = {}
    skip_ws()
    if string.sub(text, pos, pos) == "]" then
      pos = pos + 1
      return arr
    end
    while true do
      table.insert(arr, parse_value())
      skip_ws()
      local tail = string.sub(text, pos, pos)
      if tail == "," then
        pos = pos + 1
      elseif tail == "]" then
        pos = pos + 1
        return arr
      else
        error("json: expected comma or closing bracket at position " .. tostring(pos))
      end
    end
  end

  parse_value = function()
    skip_ws()
    local ch = string.sub(text, pos, pos)
    if ch == "{" then
      return parse_object()
    elseif ch == "[" then
      return parse_array()
    elseif ch == "\"" then
      return parse_string()
    elseif ch == "t" then
      if string.sub(text, pos, pos + 3) == "true" then
        pos = pos + 4
        return true
      end
      error("json: bad literal at position " .. tostring(pos))
    elseif ch == "f" then
      if string.sub(text, pos, pos + 4) == "false" then
        pos = pos + 5
        return false
      end
      error("json: bad literal at position " .. tostring(pos))
    elseif ch == "n" then
      if string.sub(text, pos, pos + 3) == "null" then
        pos = pos + 4
        return nil
      end
      error("json: bad literal at position " .. tostring(pos))
    end
    return parse_number()
  end

  skip_ws()
  return parse_value()
end

local function yaml_parse(text)
  local lines = {}
  for line in string.gmatch(text, "([^\r\n]+)") do
    local stripped = trim(line)
    if #stripped > 0 and stripped:sub(1, 1) ~= "#" and stripped ~= "---" and stripped ~= "..." then
      table.insert(lines, line)
    end
  end
  if #lines == 0 then
    return nil
  end

  local function indent_of(line)
    local found, last = string.find(line, "^ *")
    if found then
      return last
    end
    return 0
  end

  local function parse_scalar(raw)
    local s = trim(tostring(raw or ""))
    if #s == 0 then
      return nil
    end
    if s:sub(1, 1) == "\"" and s:sub(-1) == "\"" and #s >= 2 then
      return s:sub(2, -2)
    end
    if s:sub(1, 1) == "'" and s:sub(-1) == "'" and #s >= 2 then
      return s:sub(2, -2):gsub("''", "'")
    end
    if s:sub(1, 1) == "[" and s:sub(-1) == "]" then
      local items = {}
      for part in string.gmatch(s:sub(2, -2), "([^,]+)") do
        table.insert(items, parse_scalar(part))
      end
      return items
    end
    if s:sub(1, 1) == "{" and s:sub(-1) == "}" then
      local obj = {}
      obj.__map = true
      for key, value in string.gmatch(s:sub(2, -2), "([^,}]+)[%s]*:[%s]*([^,}]*)") do
        obj[trim(key)] = parse_scalar(value)
      end
      return obj
    end
    if s == "true" or s == "True" or s == "TRUE" then
      return true
    end
    if s == "false" or s == "False" or s == "FALSE" then
      return false
    end
    if s == "null" or s == "Null" or s == "NULL" or s == "~" then
      return nil
    end
    local num = tonumber(s)
    if num then
      return num
    end
    return s
  end

  local function parse_block(idx, indent)
    local result = nil
    while idx <= #lines do
      local line = lines[idx]
      local ind = indent_of(line)
      if ind < indent then
        break
      end
      if ind > indent then
        idx = idx + 1
        break
      end
      local content = line:sub(ind + 1)
      if content:sub(1, 1) == "-" then
        if type(result) ~= "table" or result.__map then
          result = {}
        end
        local rest = content:match("^%-[%s]+(.*)$") or content:match("^%-$(.*)$") or ""
        rest = trim(rest)
        if #rest == 0 then
          local value, next_idx = parse_block(idx + 1, ind + 1)
          table.insert(result, value)
          idx = next_idx
        else
          local key, inline = rest:match("^(%S+)[%s]*:[%s]*(.*)$")
          if key then
            local item = {}
            item.__map = true
            item[key] = parse_scalar(inline)
            while idx + 1 <= #lines and indent_of(lines[idx + 1]) > ind do
              local next_line = lines[idx + 1]
              local next_ind = indent_of(next_line)
              local next_content = next_line:sub(next_ind + 1)
              local sub_key, sub_inline = next_content:match("^(%S+)[%s]*:[%s]*(.*)$")
              if sub_key and next_ind >= ind + 1 and next_ind <= ind + 4 then
                item[sub_key] = parse_scalar(sub_inline)
                idx = idx + 1
              else
                break
              end
            end
            table.insert(result, item)
            idx = idx + 1
          else
            table.insert(result, parse_scalar(rest))
            idx = idx + 1
          end
        end
      else
        if type(result) ~= "table" then
          result = {}
          result.__map = true
        end
        local key, inline = content:match("^(%S+)[%s]*:[%s]*(.*)$")
        if key then
          inline = trim(inline)
          if #inline > 0 then
            result[key] = parse_scalar(inline)
            idx = idx + 1
          else
            local next_line = lines[idx + 1]
            if next_line and indent_of(next_line) > ind then
              local value, next_idx = parse_block(idx + 1, indent_of(next_line))
              result[key] = value
              idx = next_idx
            else
              result[key] = nil
              idx = idx + 1
            end
          end
        else
          idx = idx + 1
        end
      end
    end
    if result == nil then
      result = {}
      result.__map = true
    end
    return result, idx
  end

  return parse_block(1, indent_of(lines[1]))
end

local function parse_document(body)
  local trimmed = trim(body)
  if starts_with(trimmed, "{") or starts_with(trimmed, "[") then
    local ok, value = pcall(json_parse, trimmed)
    if ok and type(value) == "table" then
      return value, "json"
    end
  end
  if starts_with(trimmed, "---") or contains(trimmed, "openapi:") or contains(trimmed, "swagger:") then
    local ok, value = pcall(yaml_parse, trimmed)
    if ok and type(value) == "table" then
      return value, "yaml"
    end
  end
  local ok, value = pcall(json_parse, trimmed)
  if ok and type(value) == "table" then
    return value, "json"
  end
  return nil, nil
end

local function marker_hits(body, markers)
  local hits = {}
  local seen = {}
  local score = 0
  for _, marker in ipairs(markers) do
    if contains(body, marker.pattern) then
      score = score + marker.weight
      unique_append(hits, seen, marker.note)
    end
  end
  return score, hits
end

local function parse_resource_list(parsed)
  local items = {}
  if is_seq(parsed) then
    for _, item in ipairs(parsed) do
      if is_map(item) and type(item.location) == "string" then
        table.insert(items, {
          name = as_string(item.name) or "unnamed",
          location = item.location,
        })
      end
    end
  end
  return items
end

local function classify_document(body, ctype, is_html)
  local lowered_ctype = lower(ctype)
  local spec_score, spec_hits = marker_hits(body, SPEC_MARKERS)
  local ui_score, ui_hits = marker_hits(body, UI_MARKERS)

  local looks_doc_ct = contains(lowered_ctype, "json") or contains(lowered_ctype, "yaml")
    or contains(lowered_ctype, "yml") or contains(lowered_ctype, "plain")
    or starts_with(trim(body), "{") or starts_with(trim(body), "[")
    or starts_with(trim(body), "---")
  if looks_doc_ct then
    local parsed, fmt = parse_document(body)
    if parsed and is_seq(parsed) then
      local resources = parse_resource_list(parsed)
      if #resources > 0 then
        return "resources", spec_score, ui_score, spec_hits, parsed, fmt
      end
    end
    if spec_score >= 4 and parsed and is_map(parsed)
      and (as_string(parsed.openapi) or as_string(parsed.swagger)) then
      return "spec", spec_score, ui_score, spec_hits, parsed, fmt
    end
  end

  if is_html and ui_score >= 3 then
    return "ui", spec_score, ui_score, ui_hits, nil, nil
  end

  if spec_score >= 2 or ui_score >= 3 then
    if spec_score >= ui_score then
      return "suspected", spec_score, ui_score, spec_hits, nil, nil
    end
    return "suspected", spec_score, ui_score, ui_hits, nil, nil
  end

  return nil, spec_score, ui_score, {}, nil, nil
end

local function find_header(response, name)
  local target = lower(name)
  local headers = response.header or {}
  for key, value in pairs(headers) do
    if lower(tostring(key)) == target then
      if type(value) == "table" then
        return value[1] or ""
      end
      return tostring(value)
    end
  end
  return ""
end

local function classify_server_url(url)
  local lowered = lower(url)
  for _, marker in ipairs(INTERNAL_HOST_MARKERS) do
    if contains(lowered, marker.pattern) then
      return { severity = "MEDIUM", note = marker.note, url = url }
    end
  end
  local second_octet = tonumber(string.match(lowered, "172%.(%d+)%.?"))
  if second_octet and second_octet >= 16 and second_octet <= 31 then
    return { severity = "MEDIUM", note = "private 172.16/12 address", url = url }
  end
  if boundary_hit(lowered, "internal") then
    return { severity = "MEDIUM", note = "internal hostname", url = url }
  end
  for _, hint in ipairs(STAGING_HINTS) do
    if boundary_hit(lowered, hint) then
      return { severity = "LOW", note = "non-production environment name (" .. hint .. ")", url = url }
    end
  end
  return nil
end

local function collect_servers(parsed)
  local urls = {}
  local raw = parsed.servers
  if is_seq(raw) then
    for _, server in ipairs(raw) do
      if is_map(server) then
        local url = as_string(server.url)
        if url and not list_contains(urls, url) then
          table.insert(urls, url)
        end
      end
    end
  end
  local host = as_string(parsed.host)
  if host then
    local base = as_string(parsed.basePath) or "/"
    if not starts_with(base, "/") then
      base = "/" .. base
    end
    local scheme_list = { "http" }
    if is_seq(parsed.schemes) then
      scheme_list = {}
      for _, scheme in ipairs(parsed.schemes) do
        local s = as_string(scheme)
        if s then
          table.insert(scheme_list, s)
        end
      end
    end
    for _, scheme in ipairs(scheme_list) do
      local url = scheme .. "://" .. host .. base
      if not list_contains(urls, url) then
        table.insert(urls, url)
      end
    end
  end
  return urls
end

local function collect_embedded_urls(parsed)
  local urls = {}
  local budget = 0
  local function walk(node)
    if budget > 4000 or node == nil then
      return
    end
    if type(node) == "string" then
      if string.match(node, "^https?://") then
        if not list_contains(urls, node) then
          table.insert(urls, node)
        end
      end
      return
    end
    if type(node) == "table" then
      budget = budget + 1
      if is_map(node) then
        for _, value in pairs(node) do
          walk(value)
        end
      else
        for _, value in ipairs(node) do
          walk(value)
        end
      end
    end
  end
  walk(parsed)
  return urls
end

local function collect_paths(parsed)
  local entries = {}
  local raw = parsed.paths
  if is_map(raw) then
    for p, item in pairs(raw) do
      if p ~= "__map" and is_map(item) then
        local entry = { path = p, methods = {}, method_seen = {}, op_ids = {}, opid_seen = {} }
        for method, op in pairs(item) do
          local method_name = lower(tostring(method))
          if method ~= "__map" and HTTP_METHODS[method_name] and is_map(op) then
            unique_append(entry.methods, entry.method_seen, method_name)
            local op_id = as_string(op.operationId)
            if op_id then
              unique_append(entry.op_ids, entry.opid_seen, op_id)
            end
          end
        end
        table.insert(entries, entry)
      end
    end
    table.sort(entries, function(a, b) return a.path < b.path end)
  end
  return entries
end

local function sensitive_scan(entries)
  local hits = {}
  local seen = {}
  for _, entry in ipairs(entries) do
    local lowered = lower(entry.path)
    for _, rule in ipairs(SENSITIVE_PATH_RULES) do
      if boundary_hit(lowered, rule.pattern) then
        local key = entry.path .. "|" .. rule.severity .. "|" .. rule.note
        if not seen[key] then
          seen[key] = true
          table.insert(hits, {
            severity = rule.severity, path = entry.path, note = rule.note,
            methods = table.concat(entry.methods, ","),
          })
        end
      end
    end
  end
  table.sort(hits, function(a, b)
    if SEVERITY_ORDER[a.severity] ~= SEVERITY_ORDER[b.severity] then
      return SEVERITY_ORDER[a.severity] < SEVERITY_ORDER[b.severity]
    end
    return a.path < b.path
  end)
  return hits
end

local function collect_sensitive_fields(parsed)
  local hits = {}
  local seen = {}
  local budget = 0
  local function walk(node, context)
    if budget > 4000 or type(node) ~= "table" then
      return
    end
    if is_map(node) then
      for key, value in pairs(node) do
        if key ~= "__map" then
          budget = budget + 1
          local key_str = tostring(key)
          if not contains(key_str, "/") and not contains(key_str, "{")
            and not contains(key_str, "}") and not contains(key_str, " ") then
            for _, pattern in ipairs(SENSITIVE_FIELD_PATTERNS) do
              if boundary_hit(lower(key_str), pattern) then
                local key_id = context .. "." .. key_str
                if not seen[key_id] then
                  seen[key_id] = true
                  table.insert(hits, { field = key_str, context = context, pattern = pattern })
                end
              end
            end
          end
          walk(value, context .. "." .. key_str)
        end
      end
    else
      for _, value in ipairs(node) do
        budget = budget + 1
        walk(value, context)
      end
    end
  end
  walk(parsed, "")
  table.sort(hits, function(a, b) return (a.context .. a.field) < (b.context .. b.field) end)
  return hits
end

local function collect_sensitive_params(parsed)
  local hits = {}
  local seen = {}
  local budget = 0
  local function walk(node, context)
    if budget > 4000 or type(node) ~= "table" then
      return
    end
    if is_map(node) then
      local param_name = as_string(node.name)
      if param_name
        and (node["in"] ~= nil or node.schema ~= nil or node.description ~= nil or node.required ~= nil) then
        budget = budget + 1
        for _, pattern in ipairs(SENSITIVE_PARAM_PATTERNS) do
          if boundary_hit(lower(param_name), pattern) then
            local key_id = context .. "|" .. param_name
            if not seen[key_id] then
              seen[key_id] = true
              table.insert(hits, { name = param_name, context = context, pattern = pattern })
            end
          end
        end
      end
      for key, value in pairs(node) do
        if key ~= "__map" and key ~= "name" then
          budget = budget + 1
          walk(value, context)
        end
      end
    else
      for _, value in ipairs(node) do
        budget = budget + 1
        walk(value, context)
      end
    end
  end
  walk(parsed, "")
  table.sort(hits, function(a, b) return (a.context .. a.name) < (b.context .. b.name) end)
  return hits
end

local function collect_security(parsed)
  local schemes = {}
  local schemes_map = nil
  local components = parsed.components
  if is_map(components) and is_map(components.securitySchemes) then
    schemes_map = components.securitySchemes
  elseif is_map(parsed.securityDefinitions) then
    schemes_map = parsed.securityDefinitions
  end
  if schemes_map then
    for name, def in pairs(schemes_map) do
      if name ~= "__map" and is_map(def) then
        local entry = {
          name = name, type = as_string(def.type) or "unknown",
          scheme = nil, in_field = nil, flow = nil,
        }
        if entry.type == "http" then
          entry.scheme = as_string(def.scheme) or "basic"
        elseif entry.type == "apikey" then
          entry.in_field = as_string(def["in"]) or "header"
        elseif entry.type == "oauth2" then
          local flow_names = {}
          local flow_seen = {}
          local flows = def.flows
          if is_map(flows) then
            for flow_name in pairs(flows) do
              if flow_name ~= "__map" then
                unique_append(flow_names, flow_seen, flow_name)
              end
            end
          end
          table.sort(flow_names)
          entry.flow = table.concat(flow_names, ",")
        end
        table.insert(schemes, entry)
      end
    end
    table.sort(schemes, function(a, b) return a.name < b.name end)
  end

  local global = false
  if is_seq(parsed.security) and #parsed.security > 0 then
    global = true
  end

  local total = 0
  local unsecured = 0
  local raw_paths = parsed.paths
  if is_map(raw_paths) then
    for p, item in pairs(raw_paths) do
      if p ~= "__map" and is_map(item) then
        for method, op in pairs(item) do
          if method ~= "__map" and HTTP_METHODS[lower(tostring(method))] and is_map(op) then
            total = total + 1
            local op_secured = is_seq(op.security) and #op.security > 0
            if not op_secured and not global then
              unsecured = unsecured + 1
            end
          end
        end
      end
    end
  end
  return schemes, unsecured, total
end

local function collect_tags(parsed)
  local tags = {}
  local seen = {}
  local raw = parsed.tags
  if is_seq(raw) then
    for _, tag in ipairs(raw) do
      local name = nil
      if is_map(tag) then
        name = as_string(tag.name)
      elseif type(tag) == "string" then
        name = tag
      end
      if name then
        unique_append(tags, seen, name)
      end
    end
  end
  return tags
end

local function collect_extensions(parsed)
  local found = {}
  for key in pairs(parsed) do
    local ks = tostring(key)
    if starts_with(ks, "x-") and not list_contains(found, ks) then
      table.insert(found, ks)
    end
  end
  table.sort(found)
  return found
end

local function analyse_spec_document(path, parsed, fmt)
  local doc = {
    path = path,
    fmt = fmt,
    kind = "swagger2",
    spec_version = nil,
    service_version = nil,
    title = nil,
    contact = nil,
    license = nil,
    servers = {},
    infra = {},
    paths = {},
    sensitive = {},
    param_hits = {},
    field_hits = {},
    security = {},
    unsecured_ops = 0,
    ops_total = 0,
    tags = {},
    extensions = {},
    external_docs = nil,
    score = 0,
    marker_hits = {},
  }
  local openapi_version = as_string(parsed.openapi)
  local swagger_version = as_string(parsed.swagger)
  if openapi_version then
    doc.kind = "openapi3"
    doc.spec_version = openapi_version
  elseif swagger_version then
    doc.kind = "swagger2"
    doc.spec_version = swagger_version
  end

  local info = is_map(parsed.info) and parsed.info or {}
  doc.title = as_string(info.title)
  doc.service_version = as_string(info.version)
  local contact = is_map(info.contact) and info.contact or {}
  doc.contact = as_string(contact.name) or as_string(contact.email)
  local license = is_map(info.license) and info.license or {}
  doc.license = as_string(license.name)

  doc.servers = collect_servers(parsed)
  for _, url in ipairs(doc.servers) do
    local note = classify_server_url(url)
    if note then
      table.insert(doc.infra, note)
    end
  end
  local embedded = collect_embedded_urls(parsed)
  for _, url in ipairs(embedded) do
    local duplicate = false
    for _, known in ipairs(doc.servers) do
      if known == url then
        duplicate = true
      end
    end
    if not duplicate then
      local note = classify_server_url(url)
      if note then
        table.insert(doc.infra, note)
      end
    end
  end

  doc.paths = collect_paths(parsed)
  for _, entry in ipairs(doc.paths) do
    doc.ops_total = doc.ops_total + #entry.methods
  end
  doc.sensitive = sensitive_scan(doc.paths)
  doc.param_hits = collect_sensitive_params(parsed)
  doc.field_hits = collect_sensitive_fields(parsed)

  local schemes, unsecured, total = collect_security(parsed)
  doc.security = schemes
  doc.unsecured_ops = unsecured
  if total > 0 then
    doc.ops_total = total
  end

  doc.tags = collect_tags(parsed)
  doc.extensions = collect_extensions(parsed)
  local external = is_map(parsed.externalDocs) and parsed.externalDocs or {}
  doc.external_docs = as_string(external.url)
  return doc
end

local function is_plausible_spec_url(value)
  local v = trim(value)
  if #v == 0 or #v > 200 then
    return false
  end
  local lowered = lower(v)
  if starts_with(lowered, "javascript:") or starts_with(lowered, "data:") then
    return false
  end
  if ends_with(lowered, ".css") or ends_with(lowered, ".js") or ends_with(lowered, ".png") then
    return false
  end
  if not (starts_with(v, "/") or contains(v, "://")) then
    return false
  end
  return true
end

local function extract_spec_urls(body)
  local urls = {}
  local seen = {}
  for _, pattern in ipairs(SPEC_URL_PATTERNS) do
    for value in string.gmatch(body, pattern) do
      if is_plausible_spec_url(value) then
        unique_append(urls, seen, trim(value))
      end
    end
  end
  return urls
end

local function extract_ui_version(body)
  for _, pattern in ipairs(UI_VERSION_PATTERNS) do
    local version = string.match(body, pattern)
    if version then
      return version
    end
  end
  return nil
end

local function analyse_ui_document(path, body)
  local doc = {
    path = path,
    subtype = "unknown",
    spec_urls = {},
    asset_version = nil,
    score = 0,
    marker_hits = {},
  }
  local lowered = lower(body)
  local best = 0
  for _, candidate in ipairs(UI_SUBTYPE_MARKERS) do
    local score = 0
    for _, pattern in ipairs(candidate.patterns) do
      if contains(lowered, lower(pattern)) then
        score = score + 1
      end
    end
    if score > best then
      best = score
      doc.subtype = candidate.name
    end
  end
  doc.spec_urls = extract_spec_urls(body)
  doc.asset_version = extract_ui_version(body)
  return doc
end

local function normalize_location(location, target_host)
  local v = trim(tostring(location or ""))
  if v == "" then
    return nil, false
  end
  if starts_with(lower(v), "http://") or starts_with(lower(v), "https://") then
    local authority, path_part = string.match(v, "^https?://([^/]+)(/.*)$")
    if authority and path_part then
      if authority == target_host or authority == target_host .. ":80"
        or authority == target_host .. ":443" then
        return path_part, false
      end
      return nil, true
    end
    return nil, false
  end
  if starts_with(v, "/") then
    return v, false
  end
  return "/" .. v, false
end

action = function(host, port)

  seed_random(port)
  reset_state()
  reset_findings()

  local args = read_args()
  local baseline = build_soft404_baseline(host, port, args)
  local paths = select_paths(args)
  local target_host = host_label(host)

  local documents = {}
  local ui_documents = {}
  local registries = {}
  local fetch_log = {}
  local seen_hashes = {}
  local tested = 0
  local group_base = nil
  local group_tried = false
  local pending_urls = {}
  local pending_url_seen = {}
  local pending_locations = {}
  local pending_loc_seen = {}

  local function register_spec(path, parsed, fmt, score, hits, body)
    local digest = fnv1a32(body)
    if seen_hashes[digest] then
      table.insert(fetch_log, string.format(
        "%s -> duplicate of an earlier specification (same content hash %s)", path, digest))
      return false
    end
    seen_hashes[digest] = true
    local doc = analyse_spec_document(path, parsed, fmt)
    doc.score = score
    doc.marker_hits = hits
    table.insert(documents, doc)
    table.insert(fetch_log, string.format(
      "%s -> CONFIRMED %s specification (%s, marker score %d): %d paths, %d operations, title %s",
      path, doc.kind, fmt, score, #doc.paths, doc.ops_total, tostring(doc.title or "untitled")))
    add_finding("HIGH", string.format(
      "an API specification at %s discloses the complete API surface: %d operations across %d paths (title: %s, version: %s)",
      path, doc.ops_total, #doc.paths, tostring(doc.title or "untitled"),
      tostring(doc.service_version or "unknown")),
      { path = path, subject = "spec:" .. path,
        evidence = truncate(table.concat(doc.marker_hits, ", "), 110) })
    if doc.title then
      add_finding("LOW", string.format(
        "the specification identifies the service as '%s' version %s",
        doc.title, tostring(doc.service_version or "unknown")),
        { path = path, subject = "title:" .. path, evidence = doc.title })
    end
    for _, hit in ipairs(doc.sensitive) do
      add_finding(hit.severity, string.format(
        "the specification lists the sensitive endpoint %s (%s, methods: %s)",
        hit.path, hit.note, hit.methods),
        { path = hit.path, subject = "endpoint:" .. hit.path .. "via:" .. path,
          evidence = "disclosed in " .. path })
    end
    if #doc.security == 0 then
      add_finding("HIGH", string.format(
        "the specification at %s defines no security scheme: every documented operation is reachable without credentials",
        path),
        { path = path, subject = "unauthenticated-spec:" .. path,
          evidence = "no securitySchemes/securityDefinitions block" })
    elseif doc.unsecured_ops > 0 then
      add_finding("MEDIUM", string.format(
        "%d of %d operations in the specification at %s carry no security requirement",
        doc.unsecured_ops, doc.ops_total, path),
        { path = path, subject = "unsecured-ops:" .. path,
          evidence = tostring(doc.unsecured_ops) .. " operations" })
    end
    if #doc.security > 0 then
      local scheme_lines = {}
      for _, scheme in ipairs(doc.security) do
        local detail = scheme.type
        if scheme.scheme then
          detail = detail .. " " .. scheme.scheme
        end
        if scheme.in_field then
          detail = detail .. " in " .. scheme.in_field
        end
        if scheme.flow then
          detail = detail .. " flows: " .. scheme.flow
        end
        table.insert(scheme_lines, scheme.name .. " (" .. detail .. ")")
      end
      add_finding("MEDIUM", string.format(
        "the specification discloses the authentication model: %s", table.concat(scheme_lines, "; ")),
        { path = path, subject = "auth-model:" .. path,
          evidence = truncate(table.concat(scheme_lines, "; "), 110) })
    end
    for _, note in ipairs(doc.infra) do
      add_finding(note.severity, string.format(
        "the specification publishes a URL that reveals internal topology: %s (%s)",
        note.url, note.note),
        { path = path, subject = "infra-url:" .. note.url, evidence = note.url })
    end
    if #doc.param_hits > 0 then
      local names = {}
      local seen_names = {}
      for _, hit in ipairs(doc.param_hits) do
        if #names < 8 then
          unique_append(names, seen_names, hit.name)
        end
      end
      add_finding("LOW", string.format(
        "the specification documents %d sensitive request parameter names (%s)",
        #doc.param_hits, table.concat(names, ", ")),
        { path = path, subject = "params:" .. path,
          evidence = truncate(table.concat(names, ", "), 90) })
    end
    if #doc.field_hits > 0 then
      local names = {}
      local seen_names = {}
      for _, hit in ipairs(doc.field_hits) do
        if #names < 8 then
          unique_append(names, seen_names, hit.field)
        end
      end
      add_finding("LOW", string.format(
        "the specification documents %d sensitive data field names (%s)",
        #doc.field_hits, table.concat(names, ", ")),
        { path = path, subject = "fields:" .. path,
          evidence = truncate(table.concat(names, ", "), 90) })
    end
    if #doc.extensions > 0 then
      add_finding("INFO", string.format(
        "the specification carries vendor extensions: %s", table.concat(doc.extensions, ", ")),
        { path = path, subject = "extensions:" .. path,
          evidence = table.concat(doc.extensions, ", ") })
    end
    return true
  end

  local function register_ui(path, body, spec_score, ui_score, hits)
    local digest = fnv1a32(body)
    if seen_hashes[digest] then
      table.insert(fetch_log, string.format(
        "%s -> duplicate of an earlier document (same content hash %s)", path, digest))
      return
    end
    seen_hashes[digest] = true
    local doc = analyse_ui_document(path, body)
    doc.score = ui_score
    doc.marker_hits = hits
    table.insert(ui_documents, doc)
    table.insert(fetch_log, string.format(
      "%s -> CONFIRMED interactive %s API documentation UI (marker score %d)",
      path, doc.subtype, ui_score))
    add_finding("HIGH", string.format(
      "an interactive API documentation UI (%s) is publicly served at %s",
      doc.subtype, path),
      { path = path, subject = "ui:" .. path,
        evidence = truncate(table.concat(doc.marker_hits, ", "), 110) })
    if doc.asset_version then
      add_finding("LOW", string.format(
        "the documentation UI discloses its library version: %s", doc.asset_version),
        { path = path, subject = "ui-version:" .. path, evidence = doc.asset_version })
    end
    for _, url in ipairs(doc.spec_urls) do
      local normalized, external = normalize_location(url, target_host)
      if external then
        add_finding("MEDIUM", string.format(
          "the documentation UI at %s references a specification on an external host (%s): the full API surface may be readable without authentication there",
          path, url),
          { path = path, subject = "external-spec:" .. url, evidence = url })
      elseif normalized then
        unique_append(pending_urls, pending_url_seen, normalized)
      end
    end
  end

  local function register_registry(path, parsed, body)
    local items = parse_resource_list(parsed)
    local digest = fnv1a32(body)
    if seen_hashes[digest] then
      table.insert(fetch_log, string.format("%s -> duplicate of an earlier document", path))
      return false
    end
    seen_hashes[digest] = true
    table.insert(registries, { path = path, items = items })
    table.insert(fetch_log, string.format(
      "%s -> CONFIRMED API group registry (%d groups)", path, #items))
    add_finding("MEDIUM", string.format(
      "the API group registry at %s lists %d separate API documentation groups, exposing the API inventory",
      path, #items),
      { path = path, subject = "registry:" .. path, evidence = tostring(#items) .. " groups" })
    for _, item in ipairs(items) do
      local normalized, external = normalize_location(item.location, target_host)
      if external then
        add_finding("MEDIUM", string.format(
          "the registry at %s references a documentation group on an external host (%s)",
          path, item.location),
          { path = path, subject = "external-group:" .. item.location, evidence = item.location })
      elseif normalized then
        unique_append(pending_locations, pending_loc_seen, normalized)
      end
    end
    return true
  end

  local function classify_fetched(url, referer)
    if budget_exhausted(args) then
      table.insert(fetch_log, string.format("%s (referenced by %s) -> request budget exhausted",
        url, referer))
      return
    end
    local response, err = fetch(host, port, url, args)
    if not response then
      table.insert(fetch_log, string.format("%s (referenced by %s) -> %s", url, referer,
        tostring(err)))
      return
    end
    local body = response.body or ""
    local status = response.status or 0
    local ctype = lower(find_header(response, "Content-Type"))
    local is_html = contains(ctype, "html") or contains(body, "<html") or contains(body, "<!doctype")
    local kind, spec_score, ui_score, hits, parsed, fmt = classify_document(body, ctype, is_html)
    if kind == "spec" then
      local registered = register_spec(url, parsed, fmt, spec_score, hits, body)
      if not registered then
        table.insert(fetch_log, string.format(
          "%s (referenced by %s) -> duplicate of an earlier document", url, referer))
      end
    elseif kind == "resources" then
      local registered = register_registry(url, parsed, body)
      if not registered then
        table.insert(fetch_log, string.format(
          "%s (referenced by %s) -> duplicate of an earlier document", url, referer))
      end
    else
      table.insert(fetch_log, string.format(
        "%s (referenced by %s) -> HTTP %s, not a specification document (spec %d, ui %d)",
        url, referer, tostring(status), spec_score, ui_score))
    end
  end

  for _, path in ipairs(paths) do
    if budget_exhausted(args) then
      table.insert(fetch_log, "request budget exhausted, remaining candidates skipped")
      break
    end
    local response, err = fetch(host, port, path, args)
    tested = tested + 1
    if not response then
      table.insert(fetch_log, string.format("%s -> %s", path, tostring(err)))
      goto continue_swagger
    end

    local status = response.status or 0
    local body = response.body or ""
    local info, vendor = classify_response(path, response, baseline)
    if vendor then
      table.insert(fetch_log, string.format("%s -> WAF/CDN interstitial (%s), body not trusted",
        path, vendor))
      goto continue_swagger
    end
    for _, note in ipairs(info.notes) do
      if contains(note, "access control layer") then
        table.insert(fetch_log, string.format("%s -> HTTP %s (protected)", path, tostring(status)))
      end
    end

    local ctype = lower(find_header(response, "Content-Type"))
    local is_html = contains(ctype, "html") or contains(body, "<html") or contains(body, "<!doctype")
    local kind, spec_score, ui_score, hits, parsed, fmt = classify_document(body, ctype, is_html)

    if kind == "spec" then
      register_spec(path, parsed, fmt, spec_score, hits, body)
      group_base = nil
    elseif kind == "resources" then
      register_registry(path, parsed, body)
    elseif kind == "ui" then
      register_ui(path, body, spec_score, ui_score, hits)
    elseif kind == "suspected" then
      local subject_kind = "API specification"
      if ui_score > spec_score then
        subject_kind = "API documentation UI"
      end
      add_finding("MEDIUM", string.format(
        "%s carries %s markers (%s) but the document could not be parsed; verify manually",
        path, subject_kind, truncate(table.concat(hits, ", "), 90)),
        { path = path, subject = "suspected:" .. path,
          evidence = truncate(table.concat(hits, ", "), 90) })
      table.insert(fetch_log, string.format(
        "%s -> suspected %s (spec score %d, ui score %d, unparseable)",
        path, lower(subject_kind), spec_score, ui_score))
    else
      if status == 200 and #body > 0 then
        table.insert(fetch_log, string.format("%s -> HTTP %s, %d bytes, not an API document",
          path, tostring(status), #body))
      else
        table.insert(fetch_log, string.format("%s -> HTTP %s", path, tostring(status)))
      end
    end

    if (path == "/v2/api-docs" or path == "/v3/api-docs") and not kind and not group_tried then
      group_base = path
    end
    ::continue_swagger::
  end

  if group_base and not group_tried then
    group_tried = true
    for _, group in ipairs(GROUP_NAMES) do
      if budget_exhausted(args) then
        table.insert(fetch_log, "request budget exhausted, group enumeration stopped early")
        break
      end
      local group_path = group_base .. "/" .. group
      local response, err = fetch(host, port, group_path, args)
      tested = tested + 1
      if not response then
        table.insert(fetch_log, string.format("%s -> %s", group_path, tostring(err)))
      else
        local body = response.body or ""
        local status = response.status or 0
        local ctype = lower(find_header(response, "Content-Type"))
        local is_html = contains(ctype, "html") or contains(body, "<html") or contains(body, "<!doctype")
        local kind, spec_score, ui_score, hits, parsed, fmt = classify_document(body, ctype, is_html)
        if kind == "spec" then
          register_spec(group_path, parsed, fmt, spec_score, hits, body)
        else
          table.insert(fetch_log, string.format("%s -> HTTP %s, no group specification",
            group_path, tostring(status)))
        end
      end
    end
  end

  for _, url in ipairs(pending_urls) do
    classify_fetched(url, "documentation UI")
  end
  for _, url in ipairs(pending_locations) do
    classify_fetched(url, "API group registry")
  end

  local unique, counts = dedupe_findings()

  local total_ops = 0
  local total_paths = 0
  for _, doc in ipairs(documents) do
    total_ops = total_ops + doc.ops_total
    total_paths = total_paths + #doc.paths
  end

  local out = new_output(RISK_LEVEL, "AUDITED - Swagger/OpenAPI exposure probe completed.")
  if counts.CRITICAL > 0 then
    out["Status"] = "VULNERABLE - the exposed API specification lists administrative or internal endpoints."
  elseif counts.HIGH > 0 then
    out["Status"] = "VULNERABLE - Swagger/OpenAPI documentation exposes the complete API surface."
  elseif counts.MEDIUM > 0 then
    out["Status"] = "AUDITED - partial API documentation exposure found (registry or referenced document)."
  elseif tested > 0 then
    out["Status"] = "AUDITED - no Swagger/OpenAPI document or interactive UI is reachable at the tested paths."
  else
    out["Status"] = "AUDITED - no request could be completed."
  end

  local sections = {}
  table.insert(sections, { key = "Target host", value = target_host })
  table.insert(sections, { key = "Candidates tested", value = tested })
  table.insert(sections, { key = "Specification documents found", value = #documents })
  table.insert(sections, { key = "Interactive documentation UIs found", value = #ui_documents })
  table.insert(sections, { key = "API group registries found", value = #registries })
  table.insert(sections, { key = "Total documented operations", value = total_ops })

  for _, doc in ipairs(documents) do
    local block = {}
    table.insert(block, string.format("document: %s (CONFIRMED %s, %s, marker score %d)",
      doc.path, doc.kind, doc.fmt, doc.score))
    table.insert(block, string.format("      markers: %s",
      truncate(table.concat(doc.marker_hits, ", "), 150)))
    if doc.title then
      table.insert(block, string.format("      title: %s (service version %s, spec version %s)",
        doc.title, tostring(doc.service_version or "?"), tostring(doc.spec_version or "?")))
    end
    if doc.contact then
      table.insert(block, "      contact: " .. doc.contact)
    end
    if doc.license then
      table.insert(block, "      license: " .. doc.license)
    end
    table.insert(block, string.format(
      "      surface: %d paths, %d operations, %d without security requirement",
      #doc.paths, doc.ops_total, doc.unsecured_ops))
    if #doc.tags > 0 then
      table.insert(block, "      tags: " .. truncate(table.concat(doc.tags, ", "), 120))
    end
    if #doc.servers > 0 then
      table.insert(block, "      declared servers:")
      for _, url in ipairs(doc.servers) do
        table.insert(block, "        " .. url)
      end
    end
    if #doc.security > 0 then
      local scheme_lines = {}
      for _, scheme in ipairs(doc.security) do
        local detail = scheme.type
        if scheme.scheme then
          detail = detail .. " " .. scheme.scheme
        end
        if scheme.in_field then
          detail = detail .. " in " .. scheme.in_field
        end
        if scheme.flow then
          detail = detail .. " flows: " .. scheme.flow
        end
        table.insert(scheme_lines, scheme.name .. " (" .. detail .. ")")
      end
      table.insert(block, "      security schemes: " .. truncate(table.concat(scheme_lines, "; "), 160))
    end
    if #doc.sensitive > 0 then
      table.insert(block, string.format("      sensitive endpoints (%d):", #doc.sensitive))
      for _, hit in ipairs(doc.sensitive) do
        table.insert(block, string.format("        [%s] %s - %s (methods: %s)",
          hit.severity, hit.path, hit.note, hit.methods))
      end
    end
    if #doc.param_hits > 0 then
      local names = {}
      local seen_names = {}
      for _, hit in ipairs(doc.param_hits) do
        if #names < 12 then
          unique_append(names, seen_names, hit.name)
        end
      end
      table.insert(block, "      sensitive parameters: " .. truncate(table.concat(names, ", "), 120))
    end
    if #doc.field_hits > 0 then
      local names = {}
      local seen_names = {}
      for _, hit in ipairs(doc.field_hits) do
        if #names < 12 then
          unique_append(names, seen_names, hit.field)
        end
      end
      table.insert(block, string.format(
        "      sensitive fields (%d): %s", #doc.field_hits, truncate(table.concat(names, ", "), 120)))
    end
    if #doc.extensions > 0 then
      table.insert(block, "      vendor extensions: " .. truncate(table.concat(doc.extensions, ", "), 120))
    end
    if doc.external_docs then
      table.insert(block, "      external docs: " .. doc.external_docs)
    end
    table.insert(sections, { key = "Document " .. doc.path, value = block })
  end

  for _, doc in ipairs(ui_documents) do
    local block = {}
    table.insert(block, string.format("ui: %s (CONFIRMED %s, marker score %d)",
      doc.path, doc.subtype, doc.score))
    table.insert(block, string.format("      markers: %s",
      truncate(table.concat(doc.marker_hits, ", "), 150)))
    if doc.asset_version then
      table.insert(block, "      library version: " .. doc.asset_version)
    end
    if #doc.spec_urls > 0 then
      table.insert(block, "      referenced specification urls: " .. truncate(
        table.concat(doc.spec_urls, ", "), 120))
    end
    table.insert(sections, { key = "UI " .. doc.path, value = block })
  end

  for _, registry in ipairs(registries) do
    local block = {}
    table.insert(block, string.format("registry: %s (%d groups)", registry.path, #registry.items))
    for _, item in ipairs(registry.items) do
      table.insert(block, string.format("      group %s -> %s", item.name, item.location))
    end
    table.insert(sections, { key = "Registry " .. registry.path, value = block })
  end

  local surface = {}
  local surface_seen = {}
  for _, doc in ipairs(documents) do
    for _, hit in ipairs(doc.sensitive) do
      if not surface_seen[hit.path] then
        surface_seen[hit.path] = true
        table.insert(surface, string.format("      [%s] %s - %s (methods: %s, in %s)",
          hit.severity, hit.path, hit.note, hit.methods, doc.path))
      end
    end
  end
  if #surface > 0 then
    table.sort(surface)
    table.insert(sections, { key = "Sensitive API surface", value = surface })
  end

  local infra = {}
  local infra_seen = {}
  for _, doc in ipairs(documents) do
    for _, note in ipairs(doc.infra) do
      if not infra_seen[note.url] then
        infra_seen[note.url] = true
        table.insert(infra, string.format("      [%s] %s - %s (in %s)",
          note.severity, note.url, note.note, doc.path))
      end
    end
  end
  if #infra > 0 then
    table.sort(infra)
    table.insert(sections, { key = "Infrastructure disclosure", value = infra })
  end

  local versions = {}
  for _, doc in ipairs(documents) do
    table.insert(versions, string.format(
      "      %s at %s: specification %s, service '%s' %s",
      doc.kind, doc.path, tostring(doc.spec_version or "?"),
      tostring(doc.title or "untitled"), tostring(doc.service_version or "?")))
  end
  for _, doc in ipairs(ui_documents) do
    if doc.asset_version then
      table.insert(versions, string.format("      %s UI at %s: %s",
        doc.subtype, doc.path, doc.asset_version))
    end
  end
  if #versions > 0 then
    table.sort(versions)
    table.insert(sections, { key = "Version disclosure", value = versions })
  end

  table.insert(sections, { key = "Fetch log", value = fetch_log })
  if baseline.enabled and baseline.samples > 0 then
    table.insert(sections, { key = "Soft-404 baseline", value = string.format(
      "%d probes, dominant status %s, %s", baseline.samples,
      tostring(baseline.dominant_status or "n/a"),
      baseline.consistent and "catch-all confirmed" or "no catch-all") })
  end

  if #documents > 0 or #ui_documents > 0 then
    table.insert(sections, { key = "Remediation", value =
      "remove public access to the API documentation: delete the swagger-ui/ReDoc/Scalar entry "
      .. "points from the public vhost and serve raw specifications (api-docs, openapi.json) only "
      .. "to authenticated, authorized consumers, or not at all in production. If the documentation "
      .. "must stay public, treat the document as an attack map: confirm that every endpoint it "
      .. "lists - especially administrative, internal, export, upload, backup and token endpoints - "
      .. "is actually protected in the implementation, and that the declared security schemes are "
      .. "enforced for every operation. Rotate any credentials, tokens or API keys that appeared in "
      .. "the specification or were used to reach the document." })
  else
    table.insert(sections, { key = "Remediation", value =
      "no Swagger/OpenAPI document or interactive UI was reachable at the tested paths; keep "
      .. "generated specifications out of the production vhost, bind swagger-ui/ReDoc to "
      .. "development environments, and re-run this probe after any deployment that adds API "
      .. "documentation endpoints." })
  end

  table.insert(sections, { key = "Requests issued", value = state.requests .. " of " .. args.maxrequests })

  return finish_output(out, unique, counts, sections)

end
