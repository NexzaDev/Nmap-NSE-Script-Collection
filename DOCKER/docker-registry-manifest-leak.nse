local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"

description = [[
Connects to an accessible Docker Registry v2, enumerates image tags
via /v2/<repo>/tags/list, and downloads image manifests (/v2/<repo>/manifests/<tag>)
to inspect container layer history, Dockerfile build commands, exposed
environment variables, and embedded build secrets.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "discovery", "safe"}

portrule = shortport.port_or_service(
  {5000, 443, 80, 8080, 8443},
  {"docker-registry", "http", "https"},
  "tcp"
)

local SECRET_PATTERNS = {
  "PASS", "PWD", "SECRET", "KEY", "TOKEN", "AUTH", "PRIVATE",
  "API_KEY", "AWS_SECRET", "DB_PASS", "SSH_KEY"
}

local function check_secret(str)
  local upper = string.upper(str)
  for _, p in ipairs(SECRET_PATTERNS) do
    if string.find(upper, p, 1, true) then
      return true
    end
  end
  return false
end

action = function(host, port)
  local out = stdnse.output_table()
  local target_repo = stdnse.get_script_args(SCRIPT_NAME .. ".repo")

  -- If repo not supplied, try discovering one from _catalog
  if not target_repo then
    local cat_resp = http.get(host, port, "/v2/_catalog?n=5")
    if cat_resp and cat_resp.status == 200 and cat_resp.body then
      target_repo = string.match(cat_resp.body, '"repositories"%s*:%s*%[%s*"([^"]+)"')
    end
  end

  if not target_repo then
    return stdnse.format_output(false, "No repository specified and unable to auto-discover repository from /v2/_catalog. Specify using --script-args docker-registry-manifest-leak.repo=<name>")
  end

  -- Query tags for the repository
  local tags_resp = http.get(host, port, string.format("/v2/%s/tags/list", target_repo))
  if not tags_resp or tags_resp.status ~= 200 or not tags_resp.body then
    return stdnse.format_output(false, string.format("Could not retrieve tag list for repository '%s'", target_repo))
  end

  local first_tag = string.match(tags_resp.body, '"tags"%s*:%s*%[%s*"([^"]+)"') or "latest"

  -- Request manifest with v1Compatibility headers
  local custom_headers = {
    ["Accept"] = "application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.v1+json, */*"
  }

  local manifest_resp = http.generic_request(host, port, "GET", string.format("/v2/%s/manifests/%s", target_repo, first_tag), { header = custom_headers })
  if not manifest_resp or manifest_resp.status ~= 200 or not manifest_resp.body then
    return stdnse.format_output(false, string.format("Could not retrieve manifest for '%s:%s'", target_repo, first_tag))
  end

  out["Risk Level"] = "🟡 MEDIUM"
  out["Repository"] = target_repo
  out["Inspected Tag"] = first_tag

  local findings = {}
  local body = manifest_resp.body

  -- Extract environment variables and commands from v1Compatibility JSON blocks
  for v1_json in string.gmatch(body, '"v1Compatibility"%s*:%s*"({.-})"') do
    local unescaped = string.gsub(v1_json, '\\"', '"')
    unescaped = string.gsub(unescaped, '\\\\', '\\')

    -- Check Env
    for env_val in string.gmatch(unescaped, '"Env"%s*:%s*%[([^%]]+)%]') do
      for item in string.gmatch(env_val, '"([^"]+)"') do
        if check_secret(item) then
          table.insert(findings, "EXPOSED SECRET IN LAYER ENV: " .. item)
        end
      end
    end

    -- Check Build Commands
    for cmd in string.gmatch(unescaped, '"container_config"%s*:%s*{.-"Cmd"%s*:%s*%[([^%]]+)%]') do
      if check_secret(cmd) then
        table.insert(findings, "EXPOSED SECRET IN BUILD CMD: " .. cmd)
      end
    end
  end

  if #findings > 0 then
    out["Status"] = "VULNERABLE - Sensitive environment variables or secrets discovered in manifest metadata."
    out["Manifest Leak Findings"] = findings
    out["Remediation"] = "Do not include secrets in Dockerfiles or RUN commands. Use multi-stage builds and BuildKit secret mounts (--mount=type=secret)."
  else
    out["Status"] = "AUDITED - Manifest successfully retrieved; no obvious secret patterns identified in layer definitions."
  end

  return out
end
