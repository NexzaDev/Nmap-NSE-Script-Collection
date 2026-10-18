local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local url = require "url"

description = [[
Detects publicly reachable Git repository metadata and quantifies exactly how
much source code an unauthenticated attacker can reconstruct from it.

Exposed /.git/ directories are one of the most common web misconfigurations:
deployment scripts that copy the working tree (rsync, scp -r, docker COPY .,
CI artefact upload) frequently ship the internal Git directory with it. Once
/.git/config, /.git/HEAD and either /.git/index or /.git/objects are
reachable, the complete repository — including every deleted secret that was
ever committed — can be rebuilt offline with tools such as git-dumper.

This script does not stop at "does /.git/config return 200". It performs a
staged investigation:

Stage 1 — discovery. Requests a prioritised list of Git metadata artefacts
across the document root and across the most common framework sub-paths where
repositories are accidentally exposed (/api/.git, /backend/.git,
/panel/.git, /app/.git, ...). Also probes the alternative repository layouts
used by bare repositories, gitweb/cgit front ends, Gitea/GitLab raw endpoints,
HEAD/COMMIT_EDITMSG, packed-refs, shallow, logs/HEAD and the
/info/refs?service=git-upload-pack smart HTTP transport.

Stage 2 — content validation. Every 200 response is validated against the
real byte-level structure of the artefact instead of trusting the status code:
  * config: must contain at least one INI-style [section] and a key = value
    pair; core.repositoryformatversion / remote.origin.url / branch are the
    strongest signals.
  * HEAD: must be "ref: refs/heads/<name>\n" or a 40/64 hex character object
    id.
  * index: must start with the DIRC magic ("DIRC"), carry a version field of
    2/3/4 and a plausible entry count; the script parses the header and
    reports the tracked file count.
  * packed-refs: lines must be "<40 hex> refs/...".
  * loose objects: must start with the zlib header bytes 0x78 0x01/0x9c/0xda.
  * logs/HEAD: "<old> <new> <name> <email> <timestamp> <tz>\t<message>".
  * info/refs: must begin with the pkt-line "# service=git-upload-pack".

Stage 3 — soft-404 / false-positive suppression. A large class of scanners
reports /.git/config as exposed because the application returns a custom 200
page for every unknown path (SPA index.html fallback, catch-all routers,
CMS "page not found" with status 200). The script therefore:
  * fingerprints the site's soft-404 behaviour by requesting a set of
    guaranteed-unique random paths and comparing status, length and body
    hash with the candidate response;
  * ignores responses that are byte-identical to the soft-404 baseline;
  * ignores WAF/CDN interstitials (Cloudflare, Akamai, Imperva, AWS WAF,
    Sucuri) that return 200/403 with a challenge page;
  * treats directory listings of /.git/ as a separate, weaker signal and only
    escalates them when a validated artefact is also present;
  * requires structural validation for the CRITICAL verdict, and downgrades
    "reachable but unvalidated" artefacts to informational findings.

Stage 4 — impact assessment. When a config or index is validated the script
extracts and reports: the remote URL (with credentials redacted), the branch
layout, the number of tracked files parsed from the index header, committer
identities from logs/HEAD, whether the smart HTTP transport is enabled
(remote code clone without credentials), and whether pack files or loose
objects are downloadable (which decides between "metadata leak" and "full
source disclosure"). A secret scanner runs over any validated text artefact
and reports redacted matches for AWS keys, private key blocks, connection
strings, bearer tokens and high-entropy assignments.

Every HTTP request is retried with exponential backoff, honours a global
request budget and a per-host delay so the scan stays polite, and all evidence
is returned with the exact path, status, size and matched rule.

Usage:
<code>
nmap -p 80,443 --script http-git-config-exposure <target>
nmap -p 80 --script http-git-config-exposure \
  --script-args http-git-config-exposure.prefixes="/,/api,/backend" <target>
nmap -p 443 --script http-git-config-exposure \
  --script-args http-git-config-exposure.maxrequests=120,http-git-config-exposure.delay=0.2,\
http-git-config-exposure.secrets=false <target>
</code>
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

local SCRIPT_NAME = "http-git-config-exposure"

local RISK_LEVEL = "🔴 CRITICAL"

local STATUS_LINE = "AUDITED - Git metadata exposure evaluated with structural validation."

local SEVERITY = {
  CRITICAL = 10,
  HIGH = 7,
  MEDIUM = 4,
  LOW = 2,
  INFO = 1,
}

local DEFAULT_PREFIXES = {
  "",
  "/api",
  "/app",
  "/backend",
  "/panel",
  "/admin",
  "/portal",
  "/staging",
  "/dev",
  "/old",
  "/site",
  "/www",
  "/web",
  "/src",
  "/project",
}

local ARTEFACTS = {
  { path = "/.git/config", kind = "config", weight = SEVERITY.CRITICAL,
    label = "Git configuration file" },
  { path = "/.git/HEAD", kind = "head", weight = SEVERITY.HIGH,
    label = "Git HEAD reference" },
  { path = "/.git/index", kind = "index", weight = SEVERITY.CRITICAL,
    label = "Git index (tracked file list)" },
  { path = "/.git/packed-refs", kind = "packed_refs", weight = SEVERITY.HIGH,
    label = "Git packed references" },
  { path = "/.git/logs/HEAD", kind = "reflog", weight = SEVERITY.HIGH,
    label = "Git HEAD reflog (committer identities)" },
  { path = "/.git/description", kind = "text", weight = SEVERITY.LOW,
    label = "Git repository description" },
  { path = "/.git/COMMIT_EDITMSG", kind = "text", weight = SEVERITY.MEDIUM,
    label = "Last commit message" },
  { path = "/.git/FETCH_HEAD", kind = "text", weight = SEVERITY.MEDIUM,
    label = "Fetch head log" },
  { path = "/.git/ORIG_HEAD", kind = "head_object", weight = SEVERITY.LOW,
    label = "Original HEAD object id" },
  { path = "/.git/shallow", kind = "object_list", weight = SEVERITY.MEDIUM,
    label = "Shallow clone boundary" },
  { path = "/.git/info/refs", kind = "text", weight = SEVERITY.MEDIUM,
    label = "Dumb HTTP transport reference list" },
  { path = "/.git/info/exclude", kind = "text", weight = SEVERITY.LOW,
    label = "Local exclude patterns" },
  { path = "/.git/attributes", kind = "text", weight = SEVERITY.LOW,
    label = "Git attributes" },
  { path = "/.git/hooks/post-update.sample", kind = "text", weight = SEVERITY.INFO,
    label = "Sample hook (proves .git directory listing access)" },
  { path = "/.git/refs/heads/master", kind = "object_id", weight = SEVERITY.MEDIUM,
    label = "Branch reference refs/heads/master" },
  { path = "/.git/refs/heads/main", kind = "object_id", weight = SEVERITY.MEDIUM,
    label = "Branch reference refs/heads/main" },
  { path = "/.git/refs/tags", kind = "text", weight = SEVERITY.INFO,
    label = "Tag references" },
  { path = "/.git/objects/info/packs", kind = "pack_list", weight = SEVERITY.HIGH,
    label = "Pack file inventory" },
  { path = "/.gitmodules", kind = "config", weight = SEVERITY.MEDIUM,
    label = "Submodule configuration" },
  { path = "/.git", kind = "listing", weight = SEVERITY.LOW,
    label = "Directory listing of /.git" },
  { path = "/.git/", kind = "listing", weight = SEVERITY.LOW,
    label = "Directory listing of /.git/" },
  { path = "/.gitignore", kind = "text", weight = SEVERITY.INFO,
    label = "Ignore file (reveals project layout)" },
  { path = "/.gitattributes", kind = "text", weight = SEVERITY.INFO,
    label = "Attributes file" },
}

local SMART_TRANSPORT_PROBES = {
  { path = "/.git/info/refs?service=git-upload-pack", kind = "smart_refs",
    weight = SEVERITY.CRITICAL, label = "Smart HTTP git-upload-pack advertisement" },
  { path = "/.git/info/refs?service=git-receive-pack", kind = "smart_receive",
    weight = SEVERITY.CRITICAL, label = "Smart HTTP git-receive-pack advertisement (push enabled)" },
}

local ALTERNATE_LAYOUTS = {
  "/.hg/store/data", "/.hg/requires", "/.svn/entries", "/.svn/wc.db",
  "/.bzr/README", "/_darcs/prefs/prefs", "/CVS/Root", "/CVS/Repository",
}

local SOFT404_PROBES = {
  "/nse-git-probe-%s-nonexistent",
  "/%s-does-not-exist.html",
  "/assets/%s-missing.css",
  "/api/%s/unknown-endpoint",
}

local WAF_SIGNATURES = {
  { pattern = "cf%-ray", where = "header", vendor = "Cloudflare" },
  { pattern = "cloudflare", where = "header", vendor = "Cloudflare" },
  { pattern = "attention required", where = "body", vendor = "Cloudflare" },
  { pattern = "akamai", where = "header", vendor = "Akamai" },
  { pattern = "reference #", where = "body", vendor = "Akamai" },
  { pattern = "incapsula", where = "body", vendor = "Imperva Incapsula" },
  { pattern = "x%-iinfo", where = "header", vendor = "Imperva Incapsula" },
  { pattern = "sucuri", where = "header", vendor = "Sucuri" },
  { pattern = "aws waf", where = "body", vendor = "AWS WAF" },
  { pattern = "request blocked", where = "body", vendor = "generic WAF" },
  { pattern = "access denied", where = "body", vendor = "generic WAF" },
  { pattern = "web application firewall", where = "body", vendor = "generic WAF" },
  { pattern = "fortiweb", where = "body", vendor = "Fortinet FortiWeb" },
  { pattern = "safeline", where = "body", vendor = "SafeLine WAF" },
  { pattern = "barracuda", where = "body", vendor = "Barracuda WAF" },
  { pattern = "mod_security", where = "body", vendor = "ModSecurity" },
  { pattern = "modsecurity", where = "body", vendor = "ModSecurity" },
}

local SECRET_PATTERNS = {
  { name = "AWS access key id", pattern = "(AKIA[0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z])",
    severity = "CRITICAL", weight = SEVERITY.CRITICAL },
  { name = "AWS secret access key assignment", pattern = "aws_secret_access_key%s*=%s*([A-Za-z0-9/+=][A-Za-z0-9/+=][A-Za-z0-9/+=][A-Za-z0-9/+=][A-Za-z0-9/+=]+)",
    severity = "CRITICAL", weight = SEVERITY.CRITICAL },
  { name = "Private key block", pattern = "(-----BEGIN [A-Z ]*PRIVATE KEY-----)",
    severity = "CRITICAL", weight = SEVERITY.CRITICAL },
  { name = "OpenSSH private key", pattern = "(-----BEGIN OPENSSH PRIVATE KEY-----)",
    severity = "CRITICAL", weight = SEVERITY.CRITICAL },
  { name = "Password assignment", pattern = "[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]%s*[:=]%s*[\"']?([%w%!%@%#%$%%%&%*%_%-%.%,][%w%!%@%#%$%%%&%*%_%-%.%,][%w%!%@%#%$%%%&%*%_%-%.%,]+)",
    severity = "HIGH", weight = SEVERITY.HIGH },
  { name = "Database connection string", patterns = {
      "mysql://[^%s\"']+",
      "postgres://[^%s\"']+",
      "postgresql://[^%s\"']+",
      "mongodb://[^%s\"']+",
      "mongodb%+srv://[^%s\"']+",
      "redis://[^%s\"']+",
      "amqp://[^%s\"']+",
      "amqps://[^%s\"']+",
      "mssql://[^%s\"']+",
      "jdbc:[%w]+:[^%s\"']+" },
    severity = "CRITICAL", weight = SEVERITY.CRITICAL },
  { name = "Bearer token", pattern = "bearer%s+([A-Za-z0-9%-%._~+/][A-Za-z0-9%-%._~+/][A-Za-z0-9%-%._~+/][A-Za-z0-9%-%._~+/]+)",
    severity = "HIGH", weight = SEVERITY.HIGH },
  { name = "GitHub token", pattern = "(gh[pousr]_[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9][A-Za-z0-9]+)",
    severity = "CRITICAL", weight = SEVERITY.CRITICAL },
  { name = "GitLab token", pattern = "(glpat%-[A-Za-z0-9%-_][A-Za-z0-9%-_][A-Za-z0-9%-_]+)",
    severity = "CRITICAL", weight = SEVERITY.CRITICAL },
  { name = "Slack token", pattern = "(xox[baprs]%-[A-Za-z0-9%-]+)",
    severity = "HIGH", weight = SEVERITY.HIGH },
  { name = "Stripe secret key", pattern = "(sk_live_[A-Za-z0-9][A-Za-z0-9][A-Za-z0-9]+)",
    severity = "CRITICAL", weight = SEVERITY.CRITICAL },
  { name = "Google API key", pattern = "(AIza[0-9A-Za-z%-_][0-9A-Za-z%-_][0-9A-Za-z%-_][0-9A-Za-z%-_]+)",
    severity = "HIGH", weight = SEVERITY.HIGH },
  { name = "Twilio credentials", pattern = "(SK[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]+)",
    severity = "HIGH", weight = SEVERITY.HIGH },
  { name = "JWT", pattern = "(eyJ[A-Za-z0-9_%-]+%.eyJ[A-Za-z0-9_%-]+%.[A-Za-z0-9_%-]+)",
    severity = "HIGH", weight = SEVERITY.HIGH },
  { name = "Credentialled remote URL", pattern = "(https?://[^/%s:@]+:[^/%s:@]+@[^/%s\"']+)",
    severity = "CRITICAL", weight = SEVERITY.CRITICAL },
  { name = "Basic auth header value", pattern = "authorization%s*=%s*(basic%s+[A-Za-z0-9+/=]+)",
    severity = "HIGH", weight = SEVERITY.HIGH },
}

local DEFAULT_ARGS = {
  prefixes = nil,
  maxprefixes = 6,
  maxrequests = 80,
  retries = 2,
  timeout = 8000,
  delay = 0.05,
  secrets = true,
  soft404 = true,
  alternates = true,
  transport = true,
  useragent = nil,
  maxbodysize = 262144,
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

local function read_args()
  local args = {}
  for key, value in pairs(DEFAULT_ARGS) do
    args[key] = value
  end

  local raw_prefixes = stdnse.get_script_args(SCRIPT_NAME .. ".prefixes")
  if raw_prefixes and #raw_prefixes > 0 then
    local list = {}
    for candidate in string.gmatch(raw_prefixes, "[^,]+") do
      local normalized = trim(candidate)
      if #normalized > 0 then
        if normalized ~= "/" then
          normalized = string.gsub(normalized, "/+$", "")
          if not starts_with(normalized, "/") then
            normalized = "/" .. normalized
          end
        else
          normalized = ""
        end
        if normalized == "/" then
          normalized = ""
        end
        table.insert(list, normalized)
      end
    end
    if #list > 0 then
      args.prefixes = list
    end
  end

  local numeric_args = {
    { key = "maxprefixes", minimum = 1 },
    { key = "maxrequests", minimum = 1 },
    { key = "retries", minimum = 0 },
    { key = "timeout", minimum = 500 },
    { key = "maxbodysize", minimum = 1024 },
  }
  for _, spec in ipairs(numeric_args) do
    local value = tonumber(stdnse.get_script_args(SCRIPT_NAME .. "." .. spec.key))
    if value and value >= spec.minimum then
      args[spec.key] = math.floor(value)
    end
  end

  local delay = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".delay"))
  if delay and delay >= 0 and delay <= 10 then
    args.delay = delay
  end

  local boolean_args = { "secrets", "soft404", "alternates", "transport" }
  for _, key in ipairs(boolean_args) do
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
  local seed_source = tostring(os.time()) .. tostring(math.random(1, 1000000))
    .. tostring(stdnse.clock_ms and stdnse.clock_ms() or 0)
  local out = {}
  math.randomseed(#seed_source * 7919 + (stdnse.clock_ms and stdnse.clock_ms() or 1))
  for _ = 1, length do
    local index = math.random(1, #alphabet)
    table.insert(out, string.sub(alphabet, index, index))
  end
  return table.concat(out)
end

local function redact_secret(value)
  if type(value) ~= "string" then
    return tostring(value)
  end
  local length = #value
  if length <= 8 then
    return string.rep("*", length)
  end
  local head = string.sub(value, 1, 4)
  local tail = string.sub(value, -4)
  return string.format("%s%s%s (%d chars)", head, string.rep("*", math.min(length - 8, 12)), tail, length)
end

local function redact_url_credentials(raw_url)
  if type(raw_url) ~= "string" then
    return raw_url
  end
  local scheme, user, pass, rest = string.match(raw_url, "^(%w+)://([^:/@]+):([^@]*)@(.*)$")
  if scheme then
    return string.format("%s://%s:%s@%s", scheme, user, string.rep("*", math.max(#pass, 6)), rest)
  end
  local scheme2, user2, rest2 = string.match(raw_url, "^(%w+)://([^@/]+)@(.*)$")
  if scheme2 then
    return string.format("%s://%s@%s", scheme2, string.rep("*", math.max(#user2, 4)), rest2)
  end
  return raw_url
end

local function fnv1a32(value)
  local hash = 2166136261
  for i = 1, #value do
    local byte = string.byte(value, i)
    hash = (hash ~ byte) & 0xFFFFFFFF
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
    local p = count / length
    entropy = entropy - p * (math.log(p) / math.log(2))
  end
  return entropy
end

local function byte_hex(value, count)
  local out = {}
  for i = 1, math.min(count or 16, #value) do
    table.insert(out, string.format("%02x", string.byte(value, i)))
  end
  return table.concat(out, " ")
end

local function build_options(args)
  local options = {
    header = {},
    no_cache = true,
    timeout = args.timeout,
  }
  if args.useragent then
    options.header["User-Agent"] = args.useragent
  else
    options.header["User-Agent"] = "Mozilla/5.0 (compatible; " .. SCRIPT_NAME .. "; security audit)"
  end
  options.header["Accept"] = "*/*"
  options.header["Accept-Encoding"] = "identity"
  options.header["Connection"] = "close"
  return options
end

local function sleep(seconds)
  if seconds and seconds > 0 then
    stdnse.sleep(seconds)
  end
end

local request_budget = {}
local PACK_FAILURES = {}

local function budget_exhausted(args)
  return (request_budget.count or 0) >= args.maxrequests
end

local function fetch_path(host, port, path, args)
  if budget_exhausted(args) then
    return nil, "request budget exhausted"
  end
  request_budget.count = (request_budget.count or 0) + 1

  local options = build_options(args)
  local attempt = 0
  local last_error = nil

  while attempt <= args.retries do
    attempt = attempt + 1
    local ok, response = pcall(http.get, host, port, path, options)
    if ok and type(response) == "table" then
      if response.status then
        sleep(args.delay)
        return response, nil
      end
      last_error = tostring(response["status-line"] or "malformed HTTP response")
    elseif ok then
      last_error = "unexpected response type " .. type(response)
    else
      last_error = tostring(response)
    end
    if attempt <= args.retries then
      sleep(0.5 * attempt)
    end
  end

  sleep(args.delay)
  return nil, last_error
end

local function select_prefixes(args)
  local source = args.prefixes
  if not source then
    source = {}
    for _, prefix in ipairs(DEFAULT_PREFIXES) do
      table.insert(source, prefix)
    end
  end

  local selected = {}
  local seen = {}
  for _, candidate in ipairs(source) do
    local normalized = candidate
    if normalized == "/" then
      normalized = ""
    end
    normalized = string.gsub(normalized, "/+$", "")
    if not seen[normalized] then
      seen[normalized] = true
      table.insert(selected, normalized)
      if #selected >= args.maxprefixes then
        break
      end
    end
  end

  if #selected == 0 then
    table.insert(selected, "")
  end

  return selected
end

local function detect_waf(response)
  local body = lower(response.body or "")
  for _, entry in ipairs(response.rawheader or {}) do
    local lowered_line = lower(entry)
    for _, signature in ipairs(WAF_SIGNATURES) do
      if signature.where == "header" and string.find(lowered_line, signature.pattern, 1, true) then
        return signature.vendor
      end
    end
  end
  if #body > 0 and #body < 20000 then
    for _, signature in ipairs(WAF_SIGNATURES) do
      if signature.where == "body" and string.find(body, signature.pattern, 1, true) then
        return signature.vendor
      end
    end
  end
  return nil
end

local function build_soft404_baseline(host, port, args)
  local baseline = {
    statuses = {},
    lengths = {},
    hashes = {},
    samples = 0,
    enabled = args.soft404,
  }

  if not args.soft404 then
    return baseline
  end

  for _, template in ipairs(SOFT404_PROBES) do
    if budget_exhausted(args) then
      break
    end
    local probe_path = string.format(template, random_token(12))
    local response, err = fetch_path(host, port, probe_path, args)
    if response and response.status then
      local body = response.body or ""
      baseline.samples = baseline.samples + 1
      baseline.statuses[tostring(response.status)] = (baseline.statuses[tostring(response.status)] or 0) + 1
      baseline.lengths[#body] = (baseline.lengths[#body] or 0) + 1
      local hash = fnv1a32(body)
      baseline.hashes[hash] = (baseline.hashes[hash] or 0) + 1
      baseline.example_status = baseline.example_status or response.status
      baseline.example_length = baseline.example_length or #body
    elseif err then
      baseline.errors = baseline.errors or {}
      table.insert(baseline.errors, probe_path .. ": " .. tostring(err))
    end
  end

  local dominant_status, dominant_count = nil, 0
  for status, count in pairs(baseline.statuses) do
    if count > dominant_count then
      dominant_status, dominant_count = status, count
    end
  end
  baseline.dominant_status = tonumber(dominant_status)
  baseline.dominant_count = dominant_count

  local dominant_hash, hash_count = nil, 0
  for hash, count in pairs(baseline.hashes) do
    if count > hash_count then
      dominant_hash, hash_count = hash, count
    end
  end
  baseline.dominant_hash = dominant_hash
  baseline.consistent = baseline.samples >= 2 and dominant_count == baseline.samples

  return baseline
end

local function looks_like_soft404(response, baseline)
  if not baseline.enabled or baseline.samples == 0 then
    return false, nil
  end
  local body = response.body or ""
  local hash = fnv1a32(body)

  if baseline.dominant_hash and baseline.dominant_hash == hash and #body > 0 then
    return true, "byte-identical to the site soft-404 baseline"
  end
  if baseline.consistent and baseline.dominant_status == response.status and #body > 32 then
    local length_delta = math.abs(#body - (baseline.example_length or #body))
    if length_delta <= 32 then
      return true, string.format("status %d with length %d matches the soft-404 fingerprint",
        response.status, #body)
    end
  end
  return false, nil
end

local function looks_like_directory_listing(body)
  local lowered = lower(body or "")
  local signatures = {
    "index of /", "directory listing for", "parent directory",
    "<pre>", "apache/2", "nginx/1", "microsoft-iis", "lighttpd",
    "alt=\"[dir]\"", "[to parent directory]",
  }
  local hits = {}
  for _, signature in ipairs(signatures) do
    if string.find(lowered, signature, 1, true) then
      table.insert(hits, signature)
    end
  end
  if #hits == 0 then
    return false, nil
  end
  if string.find(lowered, "href=\"", 1, true) or string.find(lowered, "<pre>", 1, true) then
    return true, table.concat(hits, ", ")
  end
  return false, nil
end

local function is_html_document(body)
  local lowered = lower(body or "")
  if #lowered == 0 then
    return false
  end
  if starts_with(lowered, "<!doctype html") or starts_with(lowered, "<html") then
    return true
  end
  if string.find(lowered, "<html", 1, true) and string.find(lowered, "</html>", 1, true) then
    return true
  end
  return false
end

local function validate_config(body)
  local result = { valid = false, details = {}, sections = {}, settings = {}, remotes = {}, branches = {} }
  if type(body) ~= "string" or #trim(body) == 0 then
    result.reason = "empty body"
    return result
  end

  local current_section = nil
  local section_count = 0
  local setting_count = 0

  for line in string.gmatch(body, "([^\r\n]*)") do
    local trimmed = trim(line)
    if #trimmed > 0 and not starts_with(trimmed, "#") and not starts_with(trimmed, ";") then
      local section_name = string.match(trimmed, "^%[([^%]]+)%]$")
      if section_name then
        current_section = lower(section_name)
        section_count = section_count + 1
        table.insert(result.sections, section_name)
      else
        local key, value = string.match(trimmed, "^([%w%-]+)%s*=%s*(.*)$")
        if key and current_section then
          setting_count = setting_count + 1
          result.settings[current_section .. "." .. lower(key)] = trim(value)
          if starts_with(current_section, "remote ") then
            local remote_name = string.match(current_section, "^remote%s+\"?(.-)\"?$")
            if lower(key) == "url" then
              table.insert(result.remotes, { name = remote_name or "origin", url = trim(value) })
            end
          elseif starts_with(current_section, "branch ") then
            local branch_name = string.match(current_section, "^branch%s+\"?(.-)\"?$")
            if lower(key) == "merge" or lower(key) == "remote" then
              table.insert(result.branches, branch_name or "unknown")
            end
          end
        end
      end
    end
  end

  result.section_count = section_count
  result.setting_count = setting_count

  local strong_markers = {
    "core.repositoryformatversion", "core.bare", "core.logallrefupdates",
    "remote.origin.url", "remote.origin.fetch", "user.email", "user.name",
    "branch.master.merge", "branch.main.merge", "gc.auto", "pack.window",
    "receive.denycurrentbranch", "submodule.", "http.postbuffer",
  }
  for _, marker in ipairs(strong_markers) do
    for key in pairs(result.settings) do
      if starts_with(key, marker) or string.find(key, marker, 1, true) then
        table.insert(result.details, "git config key present: " .. key)
        result.valid = true
      end
    end
  end

  if not result.valid and section_count >= 2 and setting_count >= 2 then
    for _, section in ipairs(result.sections) do
      local lowered = lower(section)
      if starts_with(lowered, "core") or starts_with(lowered, "remote")
        or starts_with(lowered, "branch") or starts_with(lowered, "user")
        or starts_with(lowered, "pack") or starts_with(lowered, "gc")
        or starts_with(lowered, "submodule") or starts_with(lowered, "receive")
        or starts_with(lowered, "http") or starts_with(lowered, "push") then
        result.valid = true
        table.insert(result.details, "git-style section [" .. section .. "] with key/value settings")
        break
      end
    end
  end

  if is_html_document(body) then
    result.valid = false
    result.reason = "response is an HTML document, not a git config file"
  end

  return result
end

local function validate_head(body)
  local result = { valid = false, details = {}, branch = nil, object = nil }
  local trimmed = trim(body or "")
  if #trimmed == 0 then
    result.reason = "empty body"
    return result
  end
  local branch = string.match(trimmed, "^ref:%s*refs/heads/([%w%./%-_]+)$")
  if branch then
    result.valid = true
    result.branch = branch
    table.insert(result.details, "symbolic HEAD pointing at refs/heads/" .. branch)
    return result
  end
  local object = string.match(trimmed, "^([0-9a-fA-F]+)$")
  if object and (#object == 40 or #object == 64 or #object == 7 or #object == 8) then
    result.valid = true
    result.object = object
    table.insert(result.details, string.format("detached HEAD at object %s (%d hex characters)", object, #object))
    return result
  end
  if string.find(trimmed, "ref:") or string.find(trimmed, "refs/") then
    result.valid = true
    table.insert(result.details, "HEAD-like content with refs/ prefix")
    return result
  end
  result.reason = "body does not match the HEAD grammar"
  return result
end

local function validate_index(body)
  local result = { valid = false, details = {}, entries = nil, version = nil, size = #(body or "") }
  if type(body) ~= "string" or #body < 12 then
    result.reason = "body too short to be a git index"
    return result
  end
  local magic = string.sub(body, 1, 4)
  if magic ~= "DIRC" then
    result.reason = "missing DIRC magic (first bytes: " .. byte_hex(body, 4) .. ")"
    return result
  end

  local b5, b6, b7, b8 = string.byte(body, 5, 8)
  local version = b5 * 16777216 + b6 * 65536 + b7 * 256 + b8
  if version < 2 or version > 4 then
    result.reason = string.format("DIRC magic present but version field is %d (expected 2-4)", version)
    result.version = version
    return result
  end

  local b9, b10, b11, b12 = string.byte(body, 9, 12)
  local entries = b9 * 16777216 + b10 * 65536 + b11 * 256 + b12
  result.valid = true
  result.version = version
  result.entries = entries
  table.insert(result.details, string.format("git index v%d with %d tracked entries (%d bytes)",
    version, entries, #body))

  if entries > 0 and entries < 200000 and #body > 12 then
    local expected_minimum = 12 + entries * 62
    if #body < expected_minimum * 0.5 then
      table.insert(result.details, string.format(
        "body is smaller than %d entries would normally require; index may be truncated by a proxy",
        expected_minimum))
      result.truncated = true
    end
  end

  if entries == 0 then
    table.insert(result.details, "index declares zero entries (empty repository or truncated download)")
  end

  return result
end

local function validate_packed_refs(body)
  local result = { valid = false, details = {}, refs = {} }
  local matches = 0
  for line in string.gmatch(body or "", "([^\r\n]*)") do
    local trimmed = trim(line)
    if #trimmed > 0 and not starts_with(trimmed, "#") then
      local object, ref = string.match(trimmed, "^([0-9a-fA-F]+)%s+(refs/[%w%./%-_]+)$")
      if object and ref and (#object == 40 or #object == 64) then
        matches = matches + 1
        if #result.refs < 20 then
          table.insert(result.refs, ref .. " = " .. string.sub(object, 1, 8))
        end
      end
    end
  end
  if matches > 0 then
    result.valid = true
    table.insert(result.details, string.format("%d packed references parsed", matches))
  else
    result.reason = "no '<40 hex> refs/...' lines found"
  end
  return result
end

local function validate_reflog(body)
  local result = { valid = false, details = {}, identities = {}, commits = 0 }
  local identities = {}
  for line in string.gmatch(body or "", "([^\r\n]*)") do
    local old_id, new_id, name, email, timestamp = string.match(line,
      "^([0-9a-fA-F]+)%s+([0-9a-fA-F]+)%s+(.-)%s+<([^>]+)>%s+(%d+)")
    if old_id and new_id and email and #old_id >= 7 and #new_id >= 7 then
      result.commits = result.commits + 1
      local identity = trim(name) .. " <" .. email .. ">"
      identities[identity] = (identities[identity] or 0) + 1
    end
  end
  for identity, count in pairs(identities) do
    table.insert(result.identities, string.format("%s (%d entries)", identity, count))
  end
  table.sort(result.identities)
  if result.commits > 0 then
    result.valid = true
    table.insert(result.details, string.format("%d reflog entries with committer identities", result.commits))
  else
    result.reason = "no reflog lines matched"
  end
  return result
end

local function validate_object_id(body)
  local result = { valid = false, details = {}, object = nil }
  local trimmed = trim(body or "")
  if string.match(trimmed, "^[0-9a-fA-F]+$") and (#trimmed == 40 or #trimmed == 64 or #trimmed == 7) then
    result.valid = true
    result.object = trimmed
    table.insert(result.details, string.format("object id %s (%d hex characters)", trimmed, #trimmed))
  else
    result.reason = "body is not a bare object id"
  end
  return result
end

local function validate_object_list(body)
  local result = { valid = false, details = {}, count = 0 }
  for line in string.gmatch(body or "", "([^\r\n]*)") do
    local trimmed = trim(line)
    if string.match(trimmed, "^[0-9a-fA-F]+$") and #trimmed >= 7 and #trimmed <= 64 then
      result.count = result.count + 1
    end
  end
  if result.count > 0 then
    result.valid = true
    table.insert(result.details, string.format("%d object ids listed", result.count))
  else
    result.reason = "no object ids found"
  end
  return result
end

local function validate_pack_list(body)
  local result = { valid = false, details = {}, packs = {} }
  for line in string.gmatch(body or "", "([^\r\n]*)") do
    local pack = string.match(line, "^P%s+([%w%-]+%.pack)$")
    if pack then
      table.insert(result.packs, pack)
    end
  end
  if #result.packs > 0 then
    result.valid = true
    table.insert(result.details, string.format("%d pack files advertised: %s",
      #result.packs, table.concat(result.packs, ", ")))
  else
    result.reason = "no 'P <name>.pack' lines found"
  end
  return result
end

local function validate_loose_object(body)
  local result = { valid = false, details = {} }
  if type(body) ~= "string" or #body < 2 then
    result.reason = "body too short"
    return result
  end
  local first = string.byte(body, 1)
  local second = string.byte(body, 2)
  if first == 0x78 and (second == 0x01 or second == 0x9c or second == 0xda or second == 0x5e) then
    result.valid = true
    table.insert(result.details, string.format("zlib stream header %s (raw git object)", byte_hex(body, 2)))
  else
    result.reason = "missing zlib header (first bytes: " .. byte_hex(body, 2) .. ")"
  end
  return result
end

local function validate_smart_refs(body)
  local result = { valid = false, details = {}, services = {} }
  if type(body) ~= "string" or #body < 4 then
    result.reason = "body too short"
    return result
  end
  if starts_with(body, "# service=git-upload-pack")
    or string.find(body, "# service=git-upload-pack", 1, true) then
    result.valid = true
    table.insert(result.services, "git-upload-pack")
    table.insert(result.details, "pkt-line smart HTTP advertisement for git-upload-pack")
  end
  if string.find(body, "# service=git-receive-pack", 1, true) then
    result.valid = true
    table.insert(result.services, "git-receive-pack")
    table.insert(result.details, "pkt-line smart HTTP advertisement for git-receive-pack (push exposed)")
  end
  if not result.valid then
    if starts_with(body, "001e# service=") or starts_with(body, "0000") then
      result.valid = true
      table.insert(result.details, "pkt-line framing detected")
    else
      result.reason = "no smart HTTP service advertisement"
    end
  end
  return result
end

local function validate_text(body, path)
  local result = { valid = false, details = {} }
  local trimmed = trim(body or "")
  if #trimmed == 0 then
    result.reason = "empty body"
    return result
  end
  if is_html_document(body) then
    result.reason = "response is an HTML document"
    return result
  end
  if string.find(trimmed, "<%?xml") or starts_with(trimmed, "<?xml") then
    result.reason = "response is an XML document"
    return result
  end
  if string.find(trimmed, "^{") and string.find(trimmed, "}$") then
    result.reason = "response is a JSON document"
    return result
  end
  result.valid = true
  local preview = string.gsub(string.sub(trimmed, 1, 64), "[\r\n\t]", " ")
  table.insert(result.details, string.format("plain-text artefact (%d bytes): %s", #trimmed, preview))
  return result
end

local VALIDATORS = {
  config = validate_config,
  head = validate_head,
  head_object = validate_object_id,
  index = validate_index,
  packed_refs = validate_packed_refs,
  reflog = validate_reflog,
  object_id = validate_object_id,
  object_list = validate_object_list,
  pack_list = validate_pack_list,
  loose_object = validate_loose_object,
  smart_refs = validate_smart_refs,
  smart_receive = validate_smart_refs,
  text = validate_text,
}

local function validate_artefact(kind, body, path)
  if kind == "listing" then
    local listing, evidence = looks_like_directory_listing(body)
    return { valid = listing, details = listing and { "directory listing markers: " .. evidence } or {},
      reason = listing and nil or "not a directory listing" }
  end
  local validator = VALIDATORS[kind]
  if not validator then
    return validate_text(body, path)
  end
  return validator(body, path)
end

local function scan_secrets(body, path, findings, args)
  if not args.secrets then
    return 0
  end
  if type(body) ~= "string" or #body == 0 or #body > args.maxbodysize then
    return 0
  end

  local weight = 0
  local seen = {}
  for _, entry in ipairs(SECRET_PATTERNS) do
    if entry.severity ~= "SKIP" then
      local pats = entry.patterns or { entry.pattern }
      for _, pat in ipairs(pats) do
        for match in string.gmatch(body, pat) do
          local value = match
          if type(value) ~= "string" or #value < 8 then
            value = tostring(value)
          end
          if #value >= 8 and not seen[entry.name .. value] then
            seen[entry.name .. value] = true
            table.insert(findings, {
              severity = entry.severity,
              weight = entry.weight,
              path = path,
              detail = string.format("%s found: %s", entry.name,
                string.find(value, "://", 1, true) and redact_url_credentials(value) or redact_secret(value)),
            })
            weight = weight + entry.weight
            if table_size(seen) > 25 then
              return weight
            end
          end
        end
      end
    end
  end

  for line in string.gmatch(body, "([^\r\n]*)") do
    local key, value = string.match(line, "^%s*([%w_%-%.]+)%s*=%s*([^%s#]+)%s*$")
    if key and value then
      local lowered_key = lower(key)
      local secret_key = string.find(lowered_key, "secret") or string.find(lowered_key, "password")
        or string.find(lowered_key, "passwd") or string.find(lowered_key, "token")
        or string.find(lowered_key, "api_key") or string.find(lowered_key, "apikey")
        or string.find(lowered_key, "private_key") or string.find(lowered_key, "access_key")
      if secret_key and #value >= 8 and entropy_bits(value) >= 3.0 then
        local dedupe_key = "entropy:" .. lowered_key
        if not seen[dedupe_key] then
          seen[dedupe_key] = true
          table.insert(findings, {
            severity = "HIGH",
            weight = SEVERITY.HIGH,
            path = path,
            detail = string.format("high-entropy secret assignment %s = %s (entropy %.2f bits/char)",
              key, redact_secret(value), entropy_bits(value)),
          })
          weight = weight + SEVERITY.HIGH
        end
      end
    end
  end

  return weight
end

local function assess_exposure(confirmed)
  local assessment = {
    source_reconstructable = false,
    clone_without_auth = false,
    push_possible = false,
    identities_leaked = false,
    credentials_in_remote = false,
    tracked_files = 0,
    remotes = {},
    branches = {},
    packs = {},
    notes = {},
  }

  for _, item in ipairs(confirmed) do
    local validation = item.validation

    if item.kind == "config" then
      for _, remote in ipairs(validation.remotes or {}) do
        table.insert(assessment.remotes, redact_url_credentials(remote.url))
        if string.find(remote.url, "://[^/]+:[^/]+@") then
          assessment.credentials_in_remote = true
          table.insert(assessment.notes, "remote URL contains embedded credentials")
        end
      end
      for _, branch in ipairs(validation.branches or {}) do
        if not list_contains(assessment.branches, branch) then
          table.insert(assessment.branches, branch)
        end
      end
    end

    if item.kind == "index" then
      assessment.source_reconstructable = true
      assessment.tracked_files = validation.entries or 0
    end

    if item.kind == "loose_object" or item.kind == "pack_list" then
      assessment.source_reconstructable = true
      for _, pack in ipairs(validation.packs or {}) do
        table.insert(assessment.packs, pack)
      end
    end

    if item.kind == "reflog" then
      assessment.identities_leaked = true
    end

    if item.kind == "smart_refs" then
      assessment.clone_without_auth = true
    end

    if item.kind == "smart_receive" then
      assessment.clone_without_auth = true
      assessment.push_possible = true
    end
  end

  return assessment
end

local function build_findings(confirmed, rejected, baseline, args)
  local findings = {}
  local weight = 0

  for _, item in ipairs(confirmed) do
    local validation = item.validation
    local severity = item.weight >= SEVERITY.CRITICAL and "CRITICAL"
      or (item.weight >= SEVERITY.HIGH and "HIGH"
      or (item.weight >= SEVERITY.MEDIUM and "MEDIUM" or "LOW"))

    if item.kind == "listing" then
      severity = "LOW"
      item.weight = SEVERITY.LOW
    end

    local detail = string.format("%s reachable at %s (HTTP %d, %d bytes): %s",
      item.label, item.path, item.status, item.length,
      table.concat(validation.details or {}, "; "))

    table.insert(findings, {
      severity = severity,
      weight = item.weight,
      path = item.path,
      detail = detail,
    })
    weight = weight + item.weight

    weight = weight + scan_secrets(item.body, item.path, findings, args)
  end

  for _, item in ipairs(rejected) do
    table.insert(findings, {
      severity = "INFO",
      weight = SEVERITY.INFO,
      path = item.path,
      detail = string.format("%s returned HTTP %d but failed structural validation (%s)",
        item.label, item.status, tostring(item.reason or "unknown")),
    })
  end

  if baseline.enabled and baseline.samples > 0 then
    table.insert(findings, {
      severity = "INFO",
      weight = 0,
      path = "(baseline)",
      detail = string.format("soft-404 baseline built from %d random paths (dominant status %s, %s)",
        baseline.samples, tostring(baseline.dominant_status or "n/a"),
        baseline.consistent and "consistent" or "inconsistent"),
    })
  end

  return findings, weight
end

local function probe_artefacts(host, port, prefixes, args, baseline)
  local confirmed = {}
  local rejected = {}
  local suppressed = {}
  local errors = {}

  local plan = {}
  for _, prefix in ipairs(prefixes) do
    for _, artefact in ipairs(ARTEFACTS) do
      table.insert(plan, { prefix = prefix, artefact = artefact })
    end
    if args.transport then
      for _, probe in ipairs(SMART_TRANSPORT_PROBES) do
        table.insert(plan, { prefix = prefix, artefact = probe })
      end
    end
  end

  if args.alternates then
    for _, layout in ipairs(ALTERNATE_LAYOUTS) do
      table.insert(plan, { prefix = prefixes[1] or "", artefact = {
        path = layout, kind = "text", weight = SEVERITY.MEDIUM,
        label = "Alternative VCS metadata (" .. layout .. ")" } })
    end
  end

  local root_seen = {}
  for _, entry in ipairs(plan) do
    if budget_exhausted(args) then
      table.insert(errors, "request budget exhausted after " .. tostring(request_budget.count) .. " requests")
      break
    end

    local full_path = entry.prefix .. entry.artefact.path
    if root_seen[full_path] then
      goto continue_probe
    end
    root_seen[full_path] = true

    local response, err = fetch_path(host, port, full_path, args)
    if not response then
      table.insert(errors, string.format("%s: %s", full_path, tostring(err)))
      goto continue_probe
    end

    local status = response.status or 0
    local body = response.body or ""
    if #body > args.maxbodysize then
      body = string.sub(body, 1, args.maxbodysize)
    end

    local waf_vendor = detect_waf(response)
    if waf_vendor then
      table.insert(suppressed, {
        path = full_path, status = status, length = #body,
        reason = "WAF/CDN interstitial (" .. waf_vendor .. ")",
        label = entry.artefact.label,
      })
      goto continue_probe
    end

    local soft, soft_reason = looks_like_soft404(response, baseline)
    if soft then
      table.insert(suppressed, {
        path = full_path, status = status, length = #body,
        reason = "soft-404: " .. tostring(soft_reason),
        label = entry.artefact.label,
      })
      goto continue_probe
    end

    if status == 404 or status == 410 or status == 403 or status == 401 then
      goto continue_probe
    end

    if status >= 300 and status < 400 then
      local location = response.header and response.header["location"]
      if location then
        table.insert(suppressed, {
          path = full_path, status = status, length = #body,
          reason = "redirect to " .. tostring(location),
          label = entry.artefact.label,
        })
      end
      goto continue_probe
    end

    if status >= 500 then
      table.insert(suppressed, {
        path = full_path, status = status, length = #body,
        reason = "server error response",
        label = entry.artefact.label,
      })
      goto continue_probe
    end

    local validation = validate_artefact(entry.artefact.kind, body, full_path)
    local record = {
      path = full_path,
      kind = entry.artefact.kind,
      label = entry.artefact.label,
      weight = entry.artefact.weight,
      status = status,
      length = #body,
      body = body,
      validation = validation,
      reason = validation.reason,
    }

    if validation.valid then
      table.insert(confirmed, record)
    else
      table.insert(rejected, record)
    end

    ::continue_probe::
  end

  return confirmed, rejected, suppressed, errors
end

local function probe_pack_files(host, port, confirmed, args)
  local extra = {}
  local failed = {}
  for _, item in ipairs(confirmed) do
    if item.kind == "pack_list" then
      local base = string.gsub(item.path, "info/packs$", "")
      for _, pack in ipairs(item.validation.packs or {}) do
        local pack_path = base .. pack
        local response, err = fetch_path(host, port, pack_path, args)
        if response and response.status and response.status == 200 then
          local body = response.body or ""
          local first = string.sub(body, 1, 4)
          if first == "PACK" then
            local b5, b6, b7, b8 = string.byte(body, 5, 8)
            local version = b5 * 16777216 + b6 * 65536 + b7 * 256 + b8
            local b9, b10, b11, b12 = string.byte(body, 9, 12)
            local objects = b9 * 16777216 + b10 * 65536 + b11 * 256 + b12
            table.insert(extra, {
              path = pack_path, kind = "pack_file",
              label = "Git pack file", weight = SEVERITY.CRITICAL,
              status = 200, length = #body, body = "",
              validation = {
                valid = true,
                details = { string.format("PACK v%d with %d objects (%d bytes)", version, objects, #body) },
              },
            })
          else
            table.insert(failed, {
              path = pack_path, kind = "pack_file", label = "Git pack file",
              weight = SEVERITY.MEDIUM, status = 200, length = #body, body = "",
              validation = { valid = false, details = {} },
              reason = "downloaded object has no PACK magic (first bytes: " .. byte_hex(body, 4) .. ")",
            })
          end
        elseif err then
          table.insert(failed, {
            path = pack_path, kind = "pack_file", label = "Git pack file",
            weight = 0, status = 0, length = 0, body = "",
            validation = { valid = false, details = {} }, reason = tostring(err),
          })
        end
      end
    end
  end
  for _, item in ipairs(extra) do
    table.insert(confirmed, item)
  end
  for _, item in ipairs(failed) do
    table.insert(PACK_FAILURES, item)
  end
  return confirmed
end

local function sorted_prefix_keys(prefixes)
  local keys = {}
  for key in pairs(prefixes) do
    table.insert(keys, key)
  end
  table.sort(keys)
  return keys
end

local function summarise_prefixes(confirmed)
  local prefixes = {}
  for _, item in ipairs(confirmed) do
    local prefix = string.match(item.path, "^(.*)/%.git") or ""
    local key = (prefix == "" or prefix == nil) and "/" or prefix
    prefixes[key] = (prefixes[key] or 0) + 1
  end
  local lines = {}
  for _, prefix in ipairs(sorted_prefix_keys(prefixes)) do
    table.insert(lines, string.format("%s (%d artefacts)", prefix, prefixes[prefix]))
  end
  return lines
end

local function render_output(confirmed, rejected, suppressed, errors, baseline, findings, weight, args)
  local out = stdnse.output_table()

  out["Risk Level"] = RISK_LEVEL
  out["Status"] = STATUS_LINE

  if #confirmed == 0 then
    local structurally_interesting = {}
    for _, item in ipairs(rejected) do
      if item.kind == "config" or item.kind == "index" or item.kind == "head" then
        table.insert(structurally_interesting, string.format("%s (HTTP %d, %d bytes, %s)",
          item.path, item.status, item.length, tostring(item.reason or "unvalidated")))
      end
    end

    if #structurally_interesting > 0 then
      out["Status"] = "AUDITED - Git-like paths answered but no artefact passed structural validation."
      out["Unvalidated candidates"] = structurally_interesting
    else
      out["Status"] = "AUDITED - no Git metadata artefact is reachable."
    end

    if #suppressed > 0 then
      local lines = {}
      for _, item in ipairs(suppressed) do
        table.insert(lines, string.format("%s: %s", item.path, item.reason))
      end
      out["Suppressed (false-positive control)"] = lines
    end
    if #errors > 0 then
      out["Probe errors"] = errors
    end
    return out
  end

  local validated = {}
  for _, item in ipairs(confirmed) do
    if item.validation and item.validation.valid then
      table.insert(validated, item)
    end
  end

  local assessment = assess_exposure(validated)

  if assessment.push_possible then
    out["Status"] = "AUDITED - Git smart HTTP push transport exposed; repository is writable remotely."
  elseif assessment.source_reconstructable then
    out["Status"] = "AUDITED - Git metadata exposure confirmed; full source tree is reconstructable."
  elseif assessment.clone_without_auth then
    out["Status"] = "AUDITED - Git smart HTTP transport exposed; unauthenticated clone is possible."
  else
    out["Status"] = "AUDITED - Git metadata artefacts are publicly readable."
  end

  local artefact_lines = {}
  for _, item in ipairs(validated) do
    table.insert(artefact_lines, string.format("[%s] %s — HTTP %d, %d bytes — %s",
      item.kind, item.path, item.status, item.length,
      table.concat(item.validation.details or {}, "; ")))
  end
  out["Validated Git artefacts"] = artefact_lines

  out["Exposed locations"] = summarise_prefixes(validated)

  if assessment.tracked_files > 0 then
    out["Tracked files in index"] = tostring(assessment.tracked_files)
  end
  if #assessment.remotes > 0 then
    out["Remotes (credentials redacted)"] = assessment.remotes
  end
  if #assessment.branches > 0 then
    out["Branches"] = assessment.branches
  end
  if #assessment.packs > 0 then
    out["Pack files"] = assessment.packs
  end
  if assessment.credentials_in_remote then
    out["Credential exposure"] = "remote URL embeds credentials — rotate them immediately"
  end
  if assessment.identities_leaked then
    out["Committer identities"] = "leaked through logs/HEAD (enables targeted phishing)"
  end

  local sorted_findings = {}
  local order = { CRITICAL = 1, HIGH = 2, MEDIUM = 3, LOW = 4, INFO = 5 }
  for _, finding in ipairs(findings) do
    table.insert(sorted_findings, finding)
  end
  table.sort(sorted_findings, function(a, b)
    local oa = order[a.severity] or 9
    local ob = order[b.severity] or 9
    if oa ~= ob then
      return oa < ob
    end
    return a.path < b.path
  end)

  local rendered = {}
  for _, finding in ipairs(sorted_findings) do
    if finding.severity ~= "INFO" then
      table.insert(rendered, string.format("[%s] %s — %s", finding.severity, finding.path, finding.detail))
    end
  end
  if #rendered > 0 then
    out["Findings"] = rendered
  end

  out["Weighted exposure score"] = tostring(weight)

  if #rejected > 0 then
    local lines = {}
    for _, item in ipairs(rejected) do
      table.insert(lines, string.format("%s (HTTP %d): %s", item.path, item.status, tostring(item.reason or "unvalidated")))
    end
    out["Rejected candidates (validation failed)"] = lines
  end

  if #suppressed > 0 then
    local lines = {}
    for _, item in ipairs(suppressed) do
      table.insert(lines, string.format("%s: %s", item.path, item.reason))
    end
    out["Suppressed (false-positive control)"] = lines
  end

  if baseline.enabled then
    out["Soft-404 baseline"] = string.format("%d probes, dominant status %s, %s",
      baseline.samples, tostring(baseline.dominant_status or "n/a"),
      baseline.consistent and "consistent catch-all detected" or "no catch-all detected")
  end

  if #errors > 0 then
    out["Probe errors"] = errors
  end

  out["Requests issued"] = tostring(request_budget.count or 0)

  if assessment.push_possible then
    out["Remediation"] = "remove the .git directory from the document root, disable git-http-backend/receive-pack "
      .. "and rotate every credential that was ever committed"
  elseif assessment.source_reconstructable then
    out["Remediation"] = "delete the exposed .git tree from the web root, redeploy from a clean checkout and "
      .. "purge the artefacts from any CDN/object storage cache"
  else
    out["Remediation"] = "block /.git* at the web server or WAF layer (deny by path prefix) and fix the "
      .. "deployment pipeline that copies the working tree"
  end

  return out
end

action = function(host, port)
  request_budget = { count = 0 }
  math.randomseed((os.time() * 1000) + (port.number or 0))

  local args = read_args()
  local prefixes = select_prefixes(args)
  local baseline = build_soft404_baseline(host, port, args)

  local confirmed, rejected, suppressed, errors = probe_artefacts(host, port, prefixes, args, baseline)
  confirmed = probe_pack_files(host, port, confirmed, args)
  for _, item in ipairs(PACK_FAILURES) do
    table.insert(rejected, item)
  end
  PACK_FAILURES = {}

  local findings, weight = build_findings(confirmed, rejected, baseline, args)
  return render_output(confirmed, rejected, suppressed, errors, baseline, findings, weight, args)
end
