local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"

description = [[
Evaluates whether a Docker Registry v2 endpoint permits unauthenticated
DELETE requests on manifests and image tags. If deletion is enabled
(REGISTRY_STORAGE_DELETE_ENABLED=true) without strict authentication,
unauthorized actors can wipe images and layer blobs from the registry,
causing denial-of-service to CI/CD systems and production deployments.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(
  {5000, 443, 80, 8080, 8443},
  {"docker-registry", "http", "https"},
  "tcp"
)

action = function(host, port)
  local out = stdnse.output_table()
  local repo = stdnse.get_script_args(SCRIPT_NAME .. ".repo") or "audit-probe-nonexistent-repo"

  -- Send probe DELETE request for a non-existent dummy digest
  local probe_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
  local path = string.format("/v2/%s/manifests/%s", repo, probe_digest)

  local resp = http.generic_request(host, port, "DELETE", path)
  if not resp or not resp.status then
    return stdnse.format_output(false, "No response received to DELETE probe request.")
  end

  out["Risk Level"] = "🟠 HIGH"
  out["DELETE Probe Status Code"] = tostring(resp.status)

  if resp.status == 405 then
    out["Status"] = "SECURE - DELETE method is disabled on Registry (HTTP 405 Method Not Allowed)"
    out["Assessment"] = "Image deletion is turned off on the storage backend."
  elseif resp.status == 401 or resp.status == 403 then
    out["Status"] = "SECURE - DELETE requests require authentication (HTTP " .. resp.status .. ")"
    out["Assessment"] = "Access controls protect the registry against unauthenticated deletions."
  elseif resp.status == 404 then
    out["Status"] = "VULNERABLE - Unauthenticated DELETE accepted by router (HTTP 404 Not Found)"
    out["Assessment"] = "The registry evaluated the DELETE method without requiring authentication. If an attacker knows or queries legitimate image digests, they can delete them remotely."
    out["Remediation"] = "Disable storage delete (REGISTRY_STORAGE_DELETE_ENABLED=false) or require strong authentication for all non-GET HTTP methods."
  elseif resp.status == 202 or resp.status == 200 then
    out["Status"] = "VULNERABLE - Unauthenticated DELETE succeeded (HTTP " .. resp.status .. ")"
    out["Remediation"] = "Enforce authentication immediately on Docker Registry endpoints."
  else
    out["Status"] = "INFORMATIONAL - Unexpected status code returned: " .. resp.status
  end

  return out
end
