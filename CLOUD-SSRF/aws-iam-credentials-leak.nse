local shortport = require "shortport"

local stdnse = require "stdnse"

local string = require "string"

local table = require "table"

local nmap = require "nmap"

description = [[

Reads the AWS IAM role list and each role's credential document from
IMDS without a token; secret values are masked, lengths are reported.

Why it matters
- The credential document IS the cloud compromise: AccessKeyId plus
  session token authenticates as the instance role within seconds.
- Role names alone already map workload permissions for an attacker.

What the script does
1. Lists /latest/meta-data/iam/security-credentials/.
2. Fetches each role's document and parses code, type, key ids.
3. Masks secrets and session tokens; reports lengths and expiry.
4. Grades the leak.

Safe operation: read-only GETs; the audit never prints secret values
and never uses the credentials it sees.

]]

author = "custom"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"vuln", "safe"}

portrule = shortport.http

local SCRIPT_NAME = "aws-iam-credentials-leak"

local RISK_LEVEL = "🔴 CRITICAL"

local DEFAULT_ARGS = {
  timeout = 8,
  maxrequests = 48,
}

local BOOLEAN_ARGS = {}
local STRING_ARGS = {}
local NUMERIC_ARGS = {
  { key = "timeout", minimum = 1, integer = true },
  { key = "maxrequests", minimum = 1, maximum = 96, integer = true },
}

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

SS = {}

SS.METADATA_IPV4 = "169.254.169.254"
SS.ALIBABA_IPV4 = "100.100.100.200"
SS.GCP_METADATA_HOST = "metadata.google.internal"
SS.AZURE_METADATA_HOST = "metadata.azure.com"

SS.PROVIDERS = {
  { name = "AWS EC2 (IMDS)", ip = SS.METADATA_IPV4, root = "/latest/meta-data/",
    credential_root = "/latest/meta-data/iam/security-credentials/",
    token_path = "/latest/api/token", token_method = "PUT",
    required_header = nil, header_name = "X-aws-ec2-metadata-token" },
  { name = "Alibaba Cloud (ECS)", ip = SS.ALIBABA_IPV4, root = "/latest/meta-data/",
    credential_root = "/latest/meta-data/ram/security-credentials/",
    token_path = nil, token_method = nil,
    required_header = nil, header_name = nil },
  { name = "GCP (IMDS)", ip = SS.METADATA_IPV4, root = "/computeMetadata/v1/",
    credential_root = "/computeMetadata/v1/instance/service-accounts/",
    token_path = "/computeMetadata/v1/instance/service-accounts/default/token",
    token_method = "GET", required_header = "Metadata-Flavor: Google",
    header_name = "Metadata-Flavor" },
  { name = "Azure (IMDS)", ip = SS.METADATA_IPV4, root = "/metadata/instance",
    credential_root = "/metadata/identity/oauth2/token",
    token_path = "/metadata/identity/oauth2/token",
    token_method = "GET", required_header = "Metadata: true",
    header_name = "Metadata" },
  { name = "Oracle Cloud (OCI)", ip = SS.METADATA_IPV4, root = "/opc/v2/instance/",
    credential_root = "/opc/v2/instance/",
    token_path = nil, token_method = nil,
    required_header = "Authorization: Bearer Oracle",
    header_name = "Authorization" },
  { name = "DigitalOcean", ip = SS.METADATA_IPV4, root = "/metadata/v1.json",
    credential_root = nil, token_path = nil, token_method = nil,
    required_header = nil, header_name = nil },
  { name = "OpenStack", ip = SS.METADATA_IPV4, root = "/openstack/latest/meta_data.json",
    credential_root = nil, token_path = nil, token_method = nil,
    required_header = nil, header_name = nil },
}

SS.LINK_LOCAL_FIRST = 169
SS.LINK_LOCAL_SECOND = 254

SS.ipv4_to_bytes = function(ip)
  local a, b, c, d = tostring(ip or ""):match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if a == nil then
    return nil
  end
  return tonumber(a), tonumber(b), tonumber(c), tonumber(d)
end

SS.is_link_local = function(ip)
  local a, b = SS.ipv4_to_bytes(ip)
  if a == nil then
    return false
  end
  return a == SS.LINK_LOCAL_FIRST and b == SS.LINK_LOCAL_SECOND
end

SS.is_private_ipv4 = function(ip)
  local a, b = SS.ipv4_to_bytes(ip)
  if a == nil then
    return false
  end
  if a == 10 then
    return true
  end
  if a == 172 and b >= 16 and b <= 31 then
    return true
  end
  if a == 192 and b == 168 then
    return true
  end
  if a == 127 then
    return true
  end
  if a == 169 and b == 254 then
    return true
  end
  return false
end

SS.ip_encodings = function(ip)
  local a, b, c, d = SS.ipv4_to_bytes(ip)
  if a == nil then
    return {}
  end
  local u32 = a * 16777216 + b * 65536 + c * 256 + d
  return {
    dotted = ip,
    decimal = tostring(u32),
    hex = string.format("0x%08x", u32),
    octal_a = string.format("0%o.%d.%d.%d", a, b, c, d),
    octal_full = string.format("0%o.0%o.0%o.0%o", a, b, c, d),
    short = a .. "." .. tostring(b * 65536 + c * 256 + d),
  }
end

SS.decode_obfuscated_target = function(value)
  if type(value) ~= "string" or value == "" then
    return { kind = "invalid", ip = nil, metadata = false }
  end
  local v = value
  if v:find("^0x") then
    local n = tonumber(v:sub(3), 16)
    if n == nil then
      return { kind = "invalid", ip = nil, metadata = false }
    end
    return { kind = "hex-decoded",
      ip = string.format("%d.%d.%d.%d", math.floor(n / 16777216) % 256,
        math.floor(n / 65536) % 256, math.floor(n / 256) % 256, n % 256),
      metadata = false }
  end
  if v:find("^%d+$") and #v >= 8 then
    local n = tonumber(v)
    if n == nil then
      return { kind = "invalid", ip = nil, metadata = false }
    end
    return { kind = "decimal-decoded",
      ip = string.format("%d.%d.%d.%d", math.floor(n / 16777216) % 256,
        math.floor(n / 65536) % 256, math.floor(n / 256) % 256, n % 256),
      metadata = false }
  end
  local a, rest = v:match("^(0%d+)%.(.+)$")
  if a ~= nil then
    local first = tonumber(a, 8)
    if first ~= nil then
      v = tostring(first) .. "." .. rest
    end
  end
  local x1, x2, x3, x4 = v:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if x1 == nil then
    return { kind = "hostname", ip = nil, metadata = false }
  end
  local ip = x1 .. "." .. x2 .. "." .. x3 .. "." .. x4
  return { kind = "dotted", ip = ip, metadata = SS.is_link_local(ip) }
end

SS.http_get = function(host_header, path, headers)
  local h = headers or {}
  local req = "GET " .. path .. " HTTP/1.1\r\nHost: " .. (host_header or SS.METADATA_IPV4) .. "\r\n"
  if h.token ~= nil then
    req = req .. "X-aws-ec2-metadata-token: " .. h.token .. "\r\n"
  end
  if h.flavor ~= nil then
    req = req .. "Metadata-Flavor: " .. h.flavor .. "\r\n"
  end
  if h.azure ~= nil then
    req = req .. "Metadata: true\r\n"
  end
  if h.oracle ~= nil then
    req = req .. "Authorization: Bearer Oracle\r\n"
  end
  req = req .. "User-Agent: nse-audit\r\nAccept: */*\r\nConnection: close\r\n\r\n"
  return req
end

SS.http_put = function(host_header, path, body, headers)
  local h = headers or {}
  local req = "PUT " .. path .. " HTTP/1.1\r\nHost: " .. (host_header or SS.METADATA_IPV4) .. "\r\n"
  req = req .. "X-aws-ec2-metadata-token-ttl-seconds: " .. tostring(h.ttl or 21600) .. "\r\n"
  req = req .. "User-Agent: nse-audit\r\nContent-Length: " .. #(body or "") .. "\r\n"
  req = req .. "Connection: close\r\n\r\n" .. (body or "")
  return req
end

SS.http_put_custom = function(host_header, path, headers, body)
  local h = headers or {}
  local req = "PUT " .. path .. " HTTP/1.1\r\nHost: " .. (host_header or SS.METADATA_IPV4) .. "\r\n"
  for _, line in ipairs(h.lines or {}) do
    req = req .. line .. "\r\n"
  end
  req = req .. "Content-Length: " .. #(body or "") .. "\r\nConnection: close\r\n\r\n" .. (body or "")
  return req
end

SS.parse_http_response = function(raw)
  local out = { status = nil, reason = nil, headers = {}, body = "", is_http = false }
  if type(raw) ~= "string" or #raw < 12 then
    return out
  end
  local sep = raw:find("\r\n\r\n", 1, true)
  if sep == nil then
    out.status = tonumber(raw:match("^HTTP/%d%.%d%s+(%d+)"))
    if out.status ~= nil then
      out.is_http = true
    end
    return out
  end
  local head = raw:sub(1, sep + 3)
  out.body = raw:sub(sep + 4)
  out.status = tonumber(head:match("^HTTP/%d%.%d%s+(%d+)"))
  out.reason = head:match("^HTTP/%d%.%d%s+%d+%s+([^\r\n]+)")
  out.is_http = out.status ~= nil
  for line in head:gmatch("([^\r\n]+)") do
    local k, v = line:match("^([%w%-%_]+):%s*(.-)%s*$")
    if k ~= nil then
      out.headers[k:lower()] = v
    end
  end
  local clen = tonumber(out.headers["content-length"])
  if clen ~= nil and #out.body > clen then
    out.body = out.body:sub(1, clen)
  end
  if tostring(out.headers["transfer-encoding"]):lower() == "chunked" then
    local decoded = {}
    local pos = 1
    while pos <= #out.body do
      local hex = out.body:match("([%x]+)\r\n", pos)
      if hex == nil then
        break
      end
      local n = tonumber(hex, 16)
      local chunk = out.body:sub(pos + #hex + 2, pos + #hex + 1 + n)
      decoded[#decoded + 1] = chunk
      pos = pos + #hex + 2 + n + 2
    end
    out.body = table.concat(decoded)
  end
  return out
end

SS.parse_imdsv2_token_response = function(resp)
  local out = { token = nil, error = nil, ttl = nil }
  if resp == nil or resp.status ~= 200 then
    out.error = resp and ("HTTP " .. tostring(resp.status)) or "no answer"
    return out
  end
  out.token = resp.body:match("^([%w%-%_%=%+%/]+)%s*$")
  if out.token == nil or #out.token < 16 then
    out.error = "token body did not match token charset"
    out.token = nil
    return out
  end
  out.ttl = tonumber(resp.headers["x-aws-ec2-metadata-token-ttl-seconds"])
  return out
end

SS.aws_roles = function(body)
  local out = {}
  for line in (body or ""):gmatch("([^\r\n]+)") do
    local role = line:match("^([%w%-%_%.%=%+%@%/]+)%s*$")
    if role ~= nil and role ~= "" then
      out[#out + 1] = role
    end
  end
  return out
end

SS.parse_aws_credential_doc = function(body)
  local out = { code = nil, access_key_id = nil, secret_masked = nil, token_masked = nil,
    expiration = nil, type = nil, last_updated = nil, secret_len = nil, token_len = nil }
  if type(body) ~= "string" then
    return out
  end
  out.code = body:match('"Code"%s*:%s*"([^"]*)"')
  out.access_key_id = body:match('"AccessKeyId"%s*:%s*"([^"]*)"')
  local secret = body:match('"SecretAccessKey"%s*:%s*"([^"]*)"')
  if secret ~= nil then
    out.secret_len = #secret
    out.secret_masked = secret:sub(1, 4) .. string.rep("*", 12)
  end
  local token = body:match('"Token"%s*:%s*"([^"]*)"')
  if token ~= nil then
    out.token_len = #token
    out.token_masked = token:sub(1, 6) .. string.rep("*", 16)
  end
  out.expiration = body:match('"Expiration"%s*:%s*"([^"]*)"')
  out.type = body:match('"Type"%s*:%s*"([^"]*)"')
  out.last_updated = body:match('"LastUpdated"%s*:%s*"([^"]*)"')
  return out
end

SS.parse_identity_document = function(body)
  local out = { account_id = nil, instance_id = nil, region = nil, az = nil,
    architecture = nil, image_id = nil, instance_type = nil }
  if type(body) ~= "string" then
    return out
  end
  out.account_id = body:match('"accountId"%s*:%s*"([^"]*)"')
  out.instance_id = body:match('"instanceId"%s*:%s*"([^"]*)"')
  out.region = body:match('"region"%s*:%s*"([^"]*)"')
  out.az = body:match('"availabilityZone"%s*:%s*"([^"]*)"')
  out.architecture = body:match('"architecture"%s*:%s*"([^"]*)"')
  out.image_id = body:match('"imageId"%s*:%s*"([^"]*)"')
  out.instance_type = body:match('"instanceType"%s*:%s*"([^"]*)"')
  return out
end

SS.parse_gcp_token = function(body)
  local out = { access_masked = nil, access_len = nil, token_type = nil, expires_in = nil }
  if type(body) ~= "string" then
    return out
  end
  local access = body:match('"access_token"%s*:%s*"([^"]*)"')
  if access ~= nil then
    out.access_len = #access
    out.access_masked = access:sub(1, 8) .. string.rep("*", 16)
  end
  out.token_type = body:match('"token_type"%s*:%s*"([^"]*)"')
  out.expires_in = tonumber(body:match('"expires_in"%s*:%s*(%d+)'))
  return out
end

SS.parse_azure_instance = function(body)
  local out = { subscription_masked = nil, vm_id = nil, rg = nil, location = nil,
    os_type = nil, subscription_len = nil }
  if type(body) ~= "string" then
    return out
  end
  local sub = body:match('"subscriptionId"%s*:%s*"([^"]*)"')
  if sub ~= nil then
    out.subscription_len = #sub
    out.subscription_masked = sub:sub(1, 8) .. string.rep("*", 16)
  end
  out.vm_id = body:match('"vmId"%s*:%s*"([^"]*)"')
  out.rg = body:match('"resourceGroupName"%s*:%s*"([^"]*)"')
  out.location = body:match('"location"%s*:%s*"([^"]*)"')
  out.os_type = body:match('"osType"%s*:%s*"([^"]*)"')
  return out
end

SS.parse_do_metadata = function(body)
  local out = { droplet_id = nil, region = nil, hostname = nil, features = {}, flags = {} }
  if type(body) ~= "string" then
    return out
  end
  out.droplet_id = tonumber(body:match('"droplet_id"%s*:%s*(%d+)'))
  out.region = body:match('"region"%s*:%s*"([^"]*)"')
  out.hostname = body:match('"hostname"%s*:%s*"([^"]*)"')
  for f in body:gmatch('"([^"]+)"%s*:%s*true') do
    out.features[#out.features + 1] = f
  end
  for f in body:gmatch('"public_ipv4"%s*:%s*"([^"]*)"') do
    out.flags[#out.flags + 1] = f
  end
  return out
end

SS.parse_openstack_metadata = function(body)
  local out = { uuid = nil, project_id = nil, hostname = nil, availability_zone = nil,
    meta_keys = 0 }
  if type(body) ~= "string" then
    return out
  end
  out.uuid = body:match('"uuid"%s*:%s*"([^"]*)"')
  out.project_id = body:match('"project_id"%s*:%s*"([^"]*)"')
  out.hostname = body:match('"hostname"%s*:%s*"([^"]*)"')
  out.availability_zone = body:match('"availability_zone"%s*:%s*"([^"]*)"')
  local meta_block = body:match('"meta"%s*:%s*{(.-)}')
  if meta_block ~= nil then
    for _ in meta_block:gmatch('":"') do
      out.meta_keys = out.meta_keys + 1
    end
  end
  return out
end

SS.parse_oci_instance = function(body)
  local out = { compartment_masked = nil, region = nil, canonical_region = nil,
    display_name = nil, shape = nil, agent_config = false }
  if type(body) ~= "string" then
    return out
  end
  local ocid = body:match('"compartmentId"%s*:%s*"([^"]*)"')
  if ocid ~= nil then
    out.compartment_masked = ocid:sub(1, 20) .. string.rep("*", 12)
  end
  out.region = body:match('"region"%s*:%s*"([^"]*)"')
  out.canonical_region = body:match('"canonicalRegionName"%s*:%s*"([^"]*)"')
  out.display_name = body:match('"displayName"%s*:%s*"([^"]*)"')
  out.shape = body:match('"shape"%s*:%s*"([^"]*)"')
  out.agent_config = body:find('"agentConfig"', 1, true) ~= nil
  return out
end

SS.SECRET_PATTERNS = {
  { label = "AWS access key id", pattern = "AKIA[0-9A-Z]{16}" },
  { label = "AWS secret key context", pattern = "aws_secret_access_key" },
  { label = "private key header", pattern = "PRIVATE KEY-----" },
  { label = "generic password assignment", pattern = "[Pp]assword%s*[=:]%s*%S+" },
  { label = "bearer token assignment", pattern = "[Bb]earer%s+[A-Za-z0-9%-%_%.]+" },
  { label = "slack webhook", pattern = "hooks%.slack%.com" },
  { label = "github token", pattern = "gh[pousr]_[A-Za-z0-9]+" },
  { label = "curl to metadata", pattern = "169%.254%.169%.254" },
}

SS.classify_user_data = function(body)
  local out = { present = false, bytes = 0, shebang = nil, interpreter_hint = nil,
    secrets = {}, fetch_commands = 0, metadata_calls = 0, lines = 0 }
  if type(body) ~= "string" or #body == 0 then
    return out
  end
  out.present = true
  out.bytes = #body
  for line in body:gmatch("([^\r\n]+)") do
    out.lines = out.lines + 1
  end
  out.shebang = body:match("^#!([^\r\n]+)")
  if out.shebang ~= nil then
    out.interpreter_hint = out.shebang:match("([%w%-%_]+)%s*$")
  end
  local lowered = body:lower()
  for _, p in ipairs(SS.SECRET_PATTERNS) do
    local s, e = lowered:find(p.pattern)
    if s ~= nil then
      local raw = lowered:sub(s, e)
      local masked = raw:sub(1, math.min(6, #raw)) .. string.rep("*", 8)
      out.secrets[#out.secrets + 1] = { kind = p.label, sample_masked = masked }
    end
  end
  for cmd in body:gmatch("[Cc][Uu][Rr][Ll]") do
    out.fetch_commands = out.fetch_commands + 1
  end
  for cmd in body:gmatch("[Ww][Gg][Ee][Tt]") do
    out.fetch_commands = out.fetch_commands + 1
  end
  for _ in lowered:gmatch("169%.254%.169%.254") do
    out.metadata_calls = out.metadata_calls + 1
  end
  return out
end

SS.classify_cloud_init_log = function(body)
  local out = { present = false, bytes = 0, stages = {}, datasource = nil,
    instance_id = nil, curl_lines = 0, token_hits = 0, errors = 0 }
  if type(body) ~= "string" or #body == 0 then
    return out
  end
  out.present = true
  out.bytes = #body
  for stage in body:gmatch("cloud%-init%[[%w%-%_]+%]%s*([A-Z]+)") do
    out.stages[#out.stages + 1] = stage
  end
  out.datasource = body:match("[Dd]atasource%s+([A-Za-z0-9%-%_%.]+)")
  out.instance_id = body:match("ii%-[%w%-]+") or body:match("instance%-id[:%s]+([%w%-]+)")
  for _ in body:gmatch("[Cc][Uu][Rr][Ll]") do
    out.curl_lines = out.curl_lines + 1
  end
  for _ in body:gmatch("[Tt]oken[:%s]+[A-Za-z0-9%-%_%.]+") do
    out.token_hits = out.token_hits + 1
  end
  for _ in body:gmatch("%[ERROR%]") do
    out.errors = out.errors + 1
  end
  return out
end

SS.mask_secret = function(value, keep)
  if type(value) ~= "string" or value == "" then
    return nil
  end
  local head = math.min(keep or 4, #value)
  return value:sub(1, head) .. string.rep("*", 12)
end

SS.parse_proxy_fetch = function(resp, expected_marker)
  local out = { status = resp and resp.status or nil, reachable = false,
    marker_seen = false, blocked = false, content_type = nil, via_header = nil }
  if resp == nil then
    return out
  end
  out.content_type = resp.headers["content-type"]
  out.via_header = resp.headers["via"] or resp.headers["x-proxy"]
  if resp.status == 403 or resp.status == 401 then
    out.blocked = true
  elseif resp.status == 200 then
    out.reachable = true
    if expected_marker ~= nil and resp.body:find(expected_marker, 1, true) ~= nil then
      out.marker_seen = true
    end
  end
  return out
end

SS.SSRF_SCHEME_RISKS = {
  { scheme = "gopher", risk = "critical", note = "arbitrary TCP stream replay - full HTTP request forgery toward metadata" },
  { scheme = "file", risk = "high", note = "local file read (keys, tokens on disk)" },
  { scheme = "dict", risk = "medium", note = "service banner grabbing and command smuggling on some stacks" },
  { scheme = "ftp", risk = "low", note = "outbound protocol smuggling" },
  { scheme = "http", risk = "context", note = "expected scheme; risk depends on target IP allowlisting" },
  { scheme = "https", risk = "context", note = "expected scheme; risk depends on target IP allowlisting" },
}

SS.scheme_risk = function(scheme)
  for _, e in ipairs(SS.SSRF_SCHEME_RISKS) do
    if e.scheme == tostring(scheme or ""):lower() then
      return e
    end
  end
  return { scheme = scheme, risk = "unknown", note = "unrecognized scheme" }
end

SS.parse_redirect_chain = function(headers_list)
  local out = { hops = 0, final_ip = nil, reaches_metadata = false, locations = {} }
  for _, h in ipairs(headers_list or {}) do
    local loc = h["location"]
    if loc ~= nil then
      out.hops = out.hops + 1
      out.locations[#out.locations + 1] = loc
      local host = loc:match("^%a+://([^/%?]+)")
      local ip = host and host:match("^%d+%.%d+%.%d+%.%d+$")
      if ip ~= nil then
        out.final_ip = ip
        if SS.is_link_local(ip) then
          out.reaches_metadata = true
        end
      elseif host ~= nil and host:find("169.254.169.254", 1, true) then
        out.final_ip = SS.METADATA_IPV4
        out.reaches_metadata = true
      end
    end
  end
  return out
end

SS.DNS_REBIND_CLASSES = {
  consistent_public = "first and second lookups identical public IP - no rebinding behavior observed",
  rebound_to_metadata = "second lookup switched into the link-local metadata range - classic rebinding",
  rebound_to_private = "second lookup switched into a private range - internal network rebinding",
  inconsistent_other = "lookups disagree but neither is private - suspicious resolver behavior",
}

SS.classify_rebinding = function(first_ip, second_ip)
  local first_private = SS.is_private_ipv4(first_ip or "")
  local second_private = SS.is_private_ipv4(second_ip or "")
  local second_link = SS.is_link_local(second_ip or "")
  if first_ip == second_ip and not first_private then
    return { klass = "consistent_public", risk = "none" }
  end
  if second_link then
    return { klass = "rebound_to_metadata", risk = "critical" }
  end
  if second_private then
    return { klass = "rebound_to_private", risk = "high" }
  end
  return { klass = "inconsistent_other", risk = "medium" }
end

SS.parse_k8s_proxy_list = function(body)
  local out = { pods = 0, namespaces = {}, service_accounts = 0 }
  if type(body) ~= "string" then
    return out
  end
  for name in body:gmatch('"name"%s*:%s*"([^"]+)"') do
    if name:find("^kube%-") or name:find("%-pod") or name:find("%-ns$") then
      out.namespaces[#out.namespaces + 1] = name
    end
    out.pods = out.pods + 1
  end
  for _ in body:gmatch('"kind"%s*:%s*"ServiceAccount"') do
    out.service_accounts = out.service_accounts + 1
  end
  return out
end

SS.metadata_target_verdict = function(url_value)
  local out = { scheme = nil, host = nil, ip = nil, link_local = false, private = false,
    encoding = "plain", verdict = nil }
  if type(url_value) ~= "string" or url_value == "" then
    out.verdict = "empty"
    return out
  end
  out.scheme, out.host = url_value:match("^(%a+)://([^/%?]+)")
  if out.host == nil then
    out.host = url_value:match("^([^/%?]+)")
    out.scheme = "relative"
  end
  local decoded = SS.decode_obfuscated_target(out.host or "")
  out.ip = decoded.ip
  out.encoding = decoded.kind
  if out.ip ~= nil then
    out.link_local = SS.is_link_local(out.ip)
    out.private = SS.is_private_ipv4(out.ip)
  elseif decoded.metadata then
    out.link_local = true
  end
  if out.link_local then
    out.verdict = "metadata-service"
  elseif out.private then
    out.verdict = "internal-network"
  else
    out.verdict = "external"
  end
  return out
end

SS.IMDSV2_ADVICE = {
  enforced = "IMDSv2 token requirement is active: session tokens with hop-limit protection block SSRF metadata reads.",
  not_enforced = "IMDSv1 answers without a session token: any SSRF primitive on the host becomes cloud credential theft.",
}

SS.evaluate_imdsv2 = function(get_no_token_status, token_status, get_with_token_status)
  local out = { token_issued = false, v1_open = false, enforced = nil, notes = {} }
  if token_status ~= nil and token_status.status == 200 then
    out.token_issued = true
  end
  if get_no_token_status ~= nil and get_no_token_status.status == 200 then
    out.v1_open = true
    out.enforced = false
    out.notes[#out.notes + 1] = "GET without token returned 200"
  elseif get_no_token_status ~= nil and get_no_token_status.status == 401 then
    out.enforced = true
    out.notes[#out.notes + 1] = "GET without token rejected with 401"
  end
  if out.enforced == true and get_with_token_status ~= nil and get_with_token_status.status == 200 then
    out.notes[#out.notes + 1] = "GET with session token succeeded - enforcement is token-based, not path-based"
  end
  if out.enforced == nil then
    out.enforced = out.token_issued
  end
  return out
end

SS.CLOUD_INIT_LOCATIONS = {
  "/cloud-init/output.log",
  "/latest/meta-data/cloud-init/",
  "/cloud-init/status.json",
}

SS.KUBERNETES_PROBE_PATHS = {
  "/api/v1/namespaces/default/pods",
  "/api/v1/namespaces/kube-system/pods",
  "/api/v1/namespaces/default/serviceaccounts",
}

SS.aws_metadata_paths = function()
  return {
    { path = "/latest/meta-data/", label = "metadata index" },
    { path = "/latest/meta-data/instance-id", label = "instance-id" },
    { path = "/latest/meta-data/iam/security-credentials/", label = "iam role list" },
    { path = "/latest/user-data", label = "user-data" },
    { path = "/latest/dynamic/instance-identity/document", label = "identity document" },
  }
end

SS.provider_for_path = function(path)
  if path == nil then
    return nil
  end
  if path:find("^/computeMetadata/v1") then
    return "GCP"
  end
  if path:find("^/metadata/instance") or path:find("^/metadata/identity") then
    return "Azure"
  end
  if path:find("^/opc/v%d") then
    return "OCI"
  end
  if path:find("^/metadata/v1") then
    return "DigitalOcean"
  end
  if path:find("^/openstack/") then
    return "OpenStack"
  end
  if path:find("^/cloud%-init") then
    return "cloud-init"
  end
  if path:find("^/latest/") then
    return "AWS"
  end
  if path:find("^/fetch") then
    return "proxy"
  end
  if path:find("^/resolve") then
    return "resolver"
  end
  return "unknown"
end

SS.METADATA_HEADER_MATRIX = {
  { provider = "AWS", header = "X-aws-ec2-metadata-token", required_for = "IMDSv2 session" },
  { provider = "GCP", header = "Metadata-Flavor: Google", required_for = "every request" },
  { provider = "Azure", header = "Metadata: true", required_for = "every request" },
  { provider = "OCI", header = "Authorization: Bearer Oracle", required_for = "every request" },
  { provider = "DigitalOcean", header = "(none)", required_for = "-" },
  { provider = "OpenStack", header = "(none)", required_for = "-" },
}

SS.mask_arn = function(arn)
  if type(arn) ~= "string" or arn == "" then
    return nil
  end
  local head, tail = arn:match("^(arn:aws:iam::%d+):role/(.+)$")
  if head == nil then
    return SS.mask_secret(arn, 8)
  end
  return head .. ":role/" .. tail:sub(1, 2) .. string.rep("*", 10)
end

SS.selftest = function()
  local results = {}
  local failures = 0
  local expect_eq = function(a, b, label)
    if a == b then
      results[#results + 1] = "ok - " .. label
    else
      failures = failures + 1
      results[#results + 1] = "FAIL - " .. label
    end
  end
  expect_eq(SS.is_link_local("169.254.169.254"), true, "link local check")
  expect_eq(SS.is_link_local("10.0.0.1"), false, "non link local")
  expect_eq(SS.is_private_ipv4("10.1.2.3"), true, "private 10/8")
  expect_eq(SS.is_private_ipv4("172.16.0.1"), true, "private 172.16/12")
  expect_eq(SS.is_private_ipv4("192.168.1.1"), true, "private 192.168/16")
  expect_eq(SS.is_private_ipv4("8.8.8.8"), false, "public not private")
  local enc = SS.ip_encodings("169.254.169.254")
  expect_eq(enc.decimal, "2852039166", "decimal encoding")
  local dec = SS.decode_obfuscated_target("2852039166")
  expect_eq(dec.ip, "169.254.169.254", "decimal decode back")
  local hexd = SS.decode_obfuscated_target("0xa9fea9fe")
  expect_eq(hexd.ip, "169.254.169.254", "hex decode")
  local octd = SS.decode_obfuscated_target("0251.0254.0251.0254")
  expect_eq(octd.metadata, true, "octal decode metadata")
  local plain = SS.decode_obfuscated_target("169.254.169.254")
  expect_eq(plain.kind, "dotted", "plain dotted kind")
  expect_eq(plain.metadata, true, "plain dotted metadata")
  local req = SS.http_get("169.254.169.254", "/latest/meta-data/", { token = "TOK" })
  expect_eq(req:find("X%-aws%-ec2%-metadata%-token: TOK", 1, false) ~= nil, true, "token header")
  local put = SS.http_put("169.254.169.254", "/latest/api/token", "", { ttl = 300 })
  expect_eq(put:find("ttl%-seconds: 300") ~= nil, true, "ttl header")
  expect_eq(put:sub(1, 4), "PUT ", "put method")
  local resp = SS.parse_http_response("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
  expect_eq(resp.status, 401, "http parse status")
  local chunked = SS.parse_http_response("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\niam/\r\n0\r\n\r\n")
  expect_eq(chunked.body, "iam/", "chunked decode")
  local tok = SS.parse_imdsv2_token_response({ status = 200,
    headers = { ["x-aws-ec2-metadata-token-ttl-seconds"] = "21600" },
    body = "AQAAABxxxxxxxx-yyyy-zzzz==" })
  expect_eq(tok.token ~= nil, true, "token parse ok")
  expect_eq(tok.ttl, 21600, "token ttl parse")
  local roles = SS.aws_roles("app-role\nnode-role\r\n")
  expect_eq(#roles, 2, "aws role list")
  expect_eq(roles[1], "app-role", "aws role name")
  local doc = SS.parse_aws_credential_doc('{"Code":"Success","AccessKeyId":"AKIAIOSFODNN7EXAMPLE","SecretAccessKey":"wJalrXUtnFEMI","Token":"FwoGZXIvYXdzE","Expiration":"2030-01-01T00:00:00Z","Type":"AWS-HMAC"}')
  expect_eq(doc.code, "Success", "cred doc code")
  expect_eq(doc.access_key_id, "AKIAIOSFODNN7EXAMPLE", "cred doc key id")
  expect_eq(doc.secret_len, 13, "cred doc secret length")
  expect_eq(doc.secret_masked:sub(1, 4), "wJal", "secret masked prefix")
  expect_eq(doc.token_len, 13, "token length")
  local ident = SS.parse_identity_document('{"accountId":"123456789012","instanceId":"i-0abc","region":"eu-west-1","availabilityZone":"eu-west-1a"}')
  expect_eq(ident.account_id, "123456789012", "identity account")
  expect_eq(ident.region, "eu-west-1", "identity region")
  local gcp = SS.parse_gcp_token('{"access_token":"ya29.c.b0A","token_type":"Bearer","expires_in":3599}')
  expect_eq(gcp.access_len, 10, "gcp token length")
  expect_eq(gcp.token_type, "Bearer", "gcp token type")
  expect_eq(gcp.expires_in, 3599, "gcp expiry")
  local az = SS.parse_azure_instance('{"compute":{"subscriptionId":"ea42f556","vmId":"7c9b","resourceGroupName":"prod-rg","location":"westeurope","osType":"Linux"}}')
  expect_eq(az.subscription_masked:sub(1, 8), "ea42f556", "azure subscription masked")
  expect_eq(az.rg, "prod-rg", "azure rg")
  local dobj = SS.parse_do_metadata('{"droplet_id":3164444,"region":"fra1","hostname":"web1","features":{"backups":true}}')
  expect_eq(dobj.droplet_id, 3164444, "do droplet id")
  expect_eq(dobj.region, "fra1", "do region")
  local osd = SS.parse_openstack_metadata('{"uuid":"ec49c10a","project_id":"7b5","hostname":"os-node","availability_zone":"nova","meta":{"key":"value"}}')
  expect_eq(osd.uuid, "ec49c10a", "openstack uuid")
  expect_eq(osd.meta_keys, 1, "openstack meta keys")
  local oci = SS.parse_oci_instance('{"compartmentId":"ocid1.compartment.oc1..aaaa","region":"eu-frankfurt-1","canonicalRegionName":"eu-frankfurt-1","displayName":"app-1","shape":"VM.Standard"}')
  expect_eq(oci.compartment_masked:sub(1, 20), "ocid1.compartment.oc", "oci compartment masked")
  expect_eq(oci.region, "eu-frankfurt-1", "oci region")
  local ud = SS.classify_user_data("#!/bin/bash\ncurl http://169.254.169.254/latest/meta-data/\nexport AWS_SECRET_ACCESS_KEY=wJalr\nPASSWORD=hunter2\n")
  expect_eq(ud.present, true, "user-data present")
  expect_eq(ud.interpreter_hint, "bash", "user-data shebang")
  expect_eq(ud.metadata_calls, 1, "user-data metadata calls")
  expect_eq(#ud.secrets >= 2, true, "user-data secret hits")
  local log = SS.classify_cloud_init_log("cloud-init[Local] init finished\nDatasource DataSourceEc2Local\ncurl -H Token: ABCDEF http://169.254.169.254/\n[ERROR] failed")
  expect_eq(log.present, true, "cloud-init log present")
  expect_eq(log.datasource, "DataSourceEc2Local", "cloud-init datasource")
  expect_eq(log.token_hits, 1, "cloud-init token hits")
  expect_eq(log.errors, 1, "cloud-init errors")
  expect_eq(SS.mask_secret("AKIAIOSFODNN7EXAMPLE", 4), "AKIA************", "mask secret")
  expect_eq(SS.mask_arn("arn:aws:iam::123456789012:role/admin-role"):find("arn:aws:iam::123456789012", 1, true) ~= nil, true, "mask arn prefix")
  local ev = SS.evaluate_imdsv2({ status = 401 }, { status = 200 }, { status = 200 })
  expect_eq(ev.enforced, true, "imdsv2 enforced")
  expect_eq(ev.token_issued, true, "imdsv2 token issued")
  local ev2 = SS.evaluate_imdsv2({ status = 200 }, nil, nil)
  expect_eq(ev2.v1_open, true, "imdsv1 open")
  expect_eq(ev2.enforced, false, "imdsv1 not enforced")
  local proxy = SS.parse_proxy_fetch({ status = 200, headers = { ["content-type"] = "text/plain" }, body = "ami-id: ami-123" }, "ami-id: ami-123")
  expect_eq(proxy.reachable, true, "proxy fetch reachable")
  expect_eq(proxy.marker_seen, true, "proxy marker seen")
  local blocked = SS.parse_proxy_fetch({ status = 403, headers = {}, body = "blocked" })
  expect_eq(blocked.blocked, true, "proxy blocked")
  expect_eq(SS.scheme_risk("gopher").risk, "critical", "gopher risk")
  expect_eq(SS.scheme_risk("GOPHER").risk, "critical", "gopher case")
  local chain = SS.parse_redirect_chain({ { location = "http://169.254.169.254/latest/meta-data/" } })
  expect_eq(chain.reaches_metadata, true, "redirect to metadata")
  expect_eq(chain.hops, 1, "redirect hop count")
  local reb = SS.classify_rebinding("8.8.8.8", "169.254.169.254")
  expect_eq(reb.klass, "rebound_to_metadata", "rebind class")
  expect_eq(reb.risk, "critical", "rebind risk")
  local reb2 = SS.classify_rebinding("8.8.8.8", "8.8.8.8")
  expect_eq(reb2.klass, "consistent_public", "consistent dns")
  local k8s = SS.parse_k8s_proxy_list('{"kind":"PodList","items":[{"metadata":{"name":"web-1"}}]}')
  expect_eq(k8s.pods, 1, "k8s pod count")
  local verdict = SS.metadata_target_verdict("http://2852039166/latest/meta-data/")
  expect_eq(verdict.encoding, "decimal-decoded", "metadata verdict encoding")
  expect_eq(verdict.verdict, "metadata-service", "metadata verdict")
  expect_eq(#SS.PROVIDERS == 7, true, "provider count")
  return failures == 0, table.concat(results, "\n")
end

SST = {}

function SST.session_new(host, port, args)
  local s = {
    host = host, port = port,
    socket = nmap.new_socket(),
    requests = 0,
    audit_log = {},
    budget = {
      timeout = (args and args.timeout) or 8,
      maxrequests = (args and args.maxrequests) or 48,
    },
  }
  s.socket:set_timeout(s.budget.timeout * 1000)
  return s
end

function SST.audit(sess, event, detail)
  sess.audit_log[#sess.audit_log + 1] = { event = event, detail = detail }
end

function SST.connect(sess)
  if sess.connected then
    return true
  end
  local ok, err = sess.socket:connect(sess.host, sess.port)
  if not ok then
    return false, "connect failed: " .. tostring(err or "unknown")
  end
  sess.connected = true
  SST.audit(sess, "connect", tostring(sess.host.ip) .. ":" .. tostring(sess.port.number))
  return true
end

function SST.close(sess)
  if sess ~= nil and sess.socket ~= nil then
    sess.socket:close()
  end
  if sess ~= nil then
    sess.connected = false
  end
end

function SST.status_open(status)
  return status == "open" or status == "open|filtered"
end

function SST.raw_http(sess, request_bytes)
  local ok, err = SST.connect(sess)
  if not ok then
    return nil, err
  end
  if sess.requests >= sess.budget.maxrequests then
    return nil, "request budget exhausted"
  end
  sess.requests = sess.requests + 1
  local sent, serr = sess.socket:send(request_bytes)
  if not sent then
    return nil, "send failed: " .. tostring(serr or "unknown")
  end
  SST.audit(sess, "send", request_bytes:sub(1, request_bytes:find("\r\n", 1, true) or 40))
  local collected = ""
  local spins = 0
  while spins < 8 do
    spins = spins + 1
    local okr, chunk = sess.socket:receive()
    if not okr then
      break
    end
    collected = collected .. chunk
    if collected:find("\r\n0\r\n") or (collected:find("Content%-Length:") and
      collected:find("\r\n\r\n", 1, true) and
      #collected >= (#collected:match("Content%-Length:%s*(%d+)") or 0)) then
      break
    end
  end
  if collected == "" then
    return nil, "empty response"
  end
  SST.audit(sess, "recv", #collected .. "B")
  return SS.parse_http_response(collected), collected
end

function SST.get(sess, host_header, path, headers)
  return SST.raw_http(sess, SS.http_get(host_header, path, headers))
end

function SST.put_token(sess, host_header, path, ttl)
  return SST.raw_http(sess, SS.http_put(host_header, path, "", { ttl = ttl or 21600 }))
end

function SST.get_follow_redirects(sess, host_header, path, headers, max_hops)
  local statuses = {}
  local headers_chain = {}
  local current_path = path
  local current_host = host_header
  local final = nil
  for hop = 1, (max_hops or 3) + 1 do
    local resp = SST.get(sess, current_host, current_path, headers)
    if resp == nil then
      return nil, statuses, headers_chain
    end
    statuses[#statuses + 1] = resp.status
    if resp.status == 301 or resp.status == 302 or resp.status == 307 then
      local loc = resp.headers["location"]
      if loc == nil then
        final = resp
        break
      end
      headers_chain[#headers_chain + 1] = resp.headers
      local scheme, hostpart, rest = loc:match("^(%a+)://([^/]+)(/.*)$")
      if scheme ~= nil then
        current_host = hostpart
        current_path = rest
      else
        current_path = loc
      end
    else
      final = resp
      break
    end
  end
  return final, statuses, headers_chain
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

local function ss_incomplete(status_detail, sections, subject, evidence)
  local status_text = "INFORMATIONAL - cloud metadata audit incomplete: " .. tostring(status_detail)
  add_finding("INFO", "The metadata audit did not complete against this endpoint", {
    subject = subject or "session",
    evidence = tostring(evidence or status_detail),
    confidence = "low",
  })
  local fail_out = new_output(RISK_LEVEL, status_text)
  local unique, counts = dedupe_findings()
  return finish_output(fail_out, unique, counts, sections or {})
end

local function bump_counters()
  local bump = function(fn)
    return function(...)
      state.requests = state.requests + 1
      return fn(...)
    end
  end
  SST.get = bump(SST.get)
  SST.put_token = bump(SST.put_token)
  SST.get_follow_redirects = bump(SST.get_follow_redirects)
end

local function run_audit(host, port, args)
  local sections = {}
  bump_counters()
  local sess = SST.session_new(host, port, args)
  local roles_resp = SST.get(sess, SS.METADATA_IPV4, "/latest/meta-data/iam/security-credentials/", {})
  if roles_resp == nil then
    SST.close(sess)
    return ss_incomplete("no answer from IAM credentials path", sections, "iam-roles",
      "endpoint silent on role listing")
  end
  if roles_resp.status ~= 200 then
    sections[#sections + 1] = { key = "Role Listing", value = {
      status = roles_resp.status,
      note = "listing refused - IMDSv2 enforcement or instance profile absent",
    } }
    add_finding("INFO", "IAM role listing not readable without token", {
      subject = "iam/security-credentials/",
      evidence = "HTTP " .. tostring(roles_resp.status),
      confidence = "high",
    })
    sections[#sections + 1] = { key = "Remediation", value = {
      keep = "Keep IMDSv2 required; role names should stay invisible to unauthenticated probes.",
    } }
    local out = new_output(RISK_LEVEL, "SECURE - IAM credential path refused the token-less probe")
    local unique, counts = dedupe_findings()
    return finish_output(out, unique, counts, sections)
  end
  local roles = SS.aws_roles(roles_resp.body)
  sections[#sections + 1] = { key = "Attached IAM Roles (anonymous listing)", value = {
    count = #roles,
    roles = roles,
  } }
  local docs = {}
  local leaked = 0
  for _, role in ipairs(roles) do
    local doc_resp = SST.get(sess, SS.METADATA_IPV4,
      "/latest/meta-data/iam/security-credentials/" .. role, {})
    if doc_resp ~= nil and doc_resp.status == 200 then
      leaked = leaked + 1
      local doc = SS.parse_aws_credential_doc(doc_resp.body)
      docs[#docs + 1] = {
        role = role,
        code = doc.code,
        credential_type = doc.type,
        access_key_id = doc.access_key_id,
        secret_masked = doc.secret_masked,
        session_token_masked = doc.token_masked,
        expiration = doc.expiration,
        last_updated = doc.last_updated,
      }
    end
  end
  sections[#sections + 1] = { key = "Credential Documents (secrets masked by the audit)", value = docs }
  sections[#sections + 1] = { key = "Cross-Provider Context (this endpoint vs the metadata family)", value = (function()
    local rows = {}
    for _, h in ipairs(SS.METADATA_HEADER_MATRIX) do
      rows[#rows + 1] = {
        provider = h.provider,
        required_header = h.header,
        required_for = h.required_for,
      }
    end
    return rows
  end)() }
  sections[#sections + 1] = { key = "Target Address Classification", value = {
    canonical_metadata_ip = SS.METADATA_IPV4,
    is_link_local = SS.is_link_local(SS.METADATA_IPV4),
    is_rfc1918 = SS.is_private_ipv4(SS.METADATA_IPV4),
    encodings_seen_in_the_wild = SS.ip_encodings(SS.METADATA_IPV4),
    note = "filters that string-match the dotted form miss every encoding above",
  } }
  sections[#sections + 1] = { key = "Provider Inventory (same link-local IP, different gates)", value = (function()
    local rows = {}
    for _, p in ipairs(SS.PROVIDERS) do
      rows[#rows + 1] = {
        provider = p.name,
        metadata_ip = p.ip,
        api_root = p.root,
        credential_root = p.credential_root or "-",
        session_token_endpoint = p.token_path or "-",
      }
    end
    return rows
  end)() }
  local status_text
  if leaked > 0 then
    status_text = "VULNERABLE - full IAM credential documents readable without authentication"
    add_finding("CRITICAL", "AWS IAM role credential documents exposed via IMDSv1", {
      subject = SS.METADATA_IPV4 .. ":" .. tostring(port.number),
      evidence = leaked .. " of " .. #roles .. " roles returned AccessKeyId/Secret/Token documents",
      confidence = "high",
    })
    for _, d in ipairs(docs) do
      if d.access_key_id ~= nil then
        add_finding("HIGH", "Live access key pair available for role " .. tostring(d.role), {
          subject = SS.mask_arn and d.role or d.role,
          evidence = "AccessKeyId " .. tostring(d.access_key_id) ..
            "; secret length " .. tostring(d.secret_len) .. " (value masked)",
          confidence = "high",
        })
        break
      end
    end
  else
    status_text = "SECURE - roles visible but credential documents refused"
    add_finding("INFO", "Role names readable but documents refused", {
      subject = "iam/security-credentials/",
      evidence = #roles .. " roles listed; documents returned non-200",
      confidence = "medium",
    })
  end
  sections[#sections + 1] = { key = "Remediation", value = {
    enforce = "Require IMDSv2 tokens and lower the hop limit to 1 so container SSRF cannot reach IMDS.",
    rotate = "Treat any exposed key as compromised: rotate immediately and audit CloudTrail for abuse.",
  } }
  local out = new_output(RISK_LEVEL, status_text)
  local unique, counts = dedupe_findings()
  return finish_output(out, unique, counts, sections)
end

action = function(host, port)

local args = read_args()
reset_findings()
reset_state()
seed_random(port)

return run_audit(host, port, args)

end
