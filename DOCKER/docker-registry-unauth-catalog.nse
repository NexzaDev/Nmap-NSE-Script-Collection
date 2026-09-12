local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"

description = [[
Detects unauthenticated Docker Registry v2 services and enumerates
hosted private container repositories via the /v2/_catalog endpoint.
An open Docker registry allows unauthenticated users to download proprietary
application source code, secrets, container layers, and potentially push
malicious backdoored images.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "discovery", "safe"}

portrule = shortport.port_or_service(
  {5000, 443, 80, 8080, 8443},
  {"docker-registry", "http", "https"},
  "tcp"
)

action = function(host, port)
  local out = stdnse.output_table()
  local custom_path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or ""
  local max_repos = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".max_repos")) or 50

  -- Probe base /v2/ endpoint
  local v2_base = http.get(host, port, custom_path .. "/v2/")
  if not v2_base or not v2_base.status then
    return stdnse.format_output(false, "Could not reach target on port " .. port.number)
  end

  local docker_header = v2_base.header and (v2_base.header["docker-distribution-api-version"] or v2_base.header["Docker-Distribution-Api-Version"])

  -- If status is 401, authentication is properly enforced
  if v2_base.status == 401 then
    out["Status"] = "SECURE - Docker Registry v2 requires authentication (HTTP 401 Unauthorized)"
    if docker_header then out["Registry API Version"] = docker_header end
    if v2_base.header and v2_base.header["www-authenticate"] then
      out["Auth Challenge"] = v2_base.header["www-authenticate"]
    end
    return out
  end

  -- If status is 200, registry base is open
  if v2_base.status ~= 200 and not docker_header then
    return stdnse.format_output(false, "Target does not appear to be a Docker Registry v2 service.")
  end

  -- Probe /v2/_catalog endpoint
  local catalog_url = string.format("%s/v2/_catalog?n=%d", custom_path, max_repos)
  local cat_resp = http.get(host, port, catalog_url)

  if not cat_resp or cat_resp.status ~= 200 or not cat_resp.body then
    if v2_base.status == 200 then
      out["Status"] = "WARNING - /v2/ is accessible without auth, but /v2/_catalog returned status " .. tostring(cat_resp and cat_resp.status or "nil")
      out["Risk Level"] = "🟡 MEDIUM"
      return out
    end
    return stdnse.format_output(false, "Failed to retrieve catalog from Docker Registry.")
  end

  -- Extract repositories from JSON response
  local repos_raw = string.match(cat_resp.body, '"repositories"%s*:%s*%[([^%]]+)%]')
  local repo_list = {}

  if repos_raw then
    for repo in string.gmatch(repos_raw, '"([^"]+)"') do
      table.insert(repo_list, repo)
    end
  end

  out["Status"] = "VULNERABLE - Unauthenticated Docker Registry v2 Catalog Access"
  out["Risk Level"] = "🔴 CRITICAL"
  out["CVSS Score"] = "9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)"
  out["Total Repositories Discovered"] = #repo_list

  if #repo_list > 0 then
    local sample_repos = {}
    for i = 1, math.min(#repo_list, 20) do
      table.insert(sample_repos, repo_list[i])
    end
    if #repo_list > 20 then
      table.insert(sample_repos, string.format("... and %d more repositories", #repo_list - 20))
    end
    out["Exposed Repositories"] = sample_repos
  else
    out["Exposed Repositories"] = "Catalog is accessible without credentials (0 repositories currently populated)."
  end

  out["Remediation"] = "Configure token or htpasswd authentication for Docker Registry. Protect /v2/ behind an authenticated reverse proxy (Nginx/Traefik) with TLS client certificates or basic authentication."

  return out
end
