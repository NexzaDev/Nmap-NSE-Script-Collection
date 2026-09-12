local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"

description = [[
Tests Docker socket security proxies (such as tecnativa/docker-socket-proxy,
HAProxy, or Nginx Docker reverse proxies) for method-filtering misconfigurations.
Socket proxies are intended to expose safe, read-only Docker endpoints (GET /version,
GET /containers/json) while strictly blocking mutating HTTP verbs (POST, PUT, DELETE).
This script sends safe dummy probe requests to write endpoints (e.g., POST /containers/create,
POST /build, DELETE /containers/dummy) and verifies if the proxy properly blocks them
with HTTP 403 Forbidden / 405 Method Not Allowed.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(
  {2375, 2376, 4243, 80, 8080, 8000, 9000},
  {"docker", "docker-s", "http", "https"},
  "tcp"
)

action = function(host, port)
  local out = stdnse.output_table()

  -- Verify if GET /version is reachable
  local ver_resp = http.get(host, port, "/version")
  if not ver_resp or ver_resp.status ~= 200 or not ver_resp.body or not string.find(ver_resp.body, "ApiVersion") then
    return stdnse.format_output(false, "Target endpoint does not appear to be an active Docker API or socket proxy.")
  end

  out["Risk Level"] = "🔴 CRITICAL"

  -- Test POST /containers/create with empty JSON object (safe probe)
  local post_probe = http.generic_request(host, port, "POST", "/containers/create", {
    header = { ["Content-Type"] = "application/json" },
    content = "{}"
  })

  -- Test POST /build probe
  local build_probe = http.generic_request(host, port, "POST", "/build", {
    header = { ["Content-Type"] = "application/tar" },
    content = ""
  })

  -- Test DELETE /containers/probe-dummy
  local delete_probe = http.generic_request(host, port, "DELETE", "/containers/probe-dummy-audit-check")

  local post_allowed = post_probe and (post_probe.status == 400 or post_probe.status == 201 or post_probe.status == 404)
  local build_allowed = build_probe and (build_probe.status == 400 or build_probe.status == 200 or build_probe.status == 500)
  local delete_allowed = delete_probe and (delete_probe.status == 404 or delete_probe.status == 200 or delete_probe.status == 204)

  local results = stdnse.output_table()
  results["POST /containers/create (Container Spawning)"] = post_allowed and "🔴 PERMITTED (Proxy forwards POST)" or "BLOCKED / PROTECTED (HTTP " .. tostring(post_probe and post_probe.status or "err") .. ")"
  results["POST /build (Image Compilation)"] = build_allowed and "🔴 PERMITTED (Proxy forwards POST)" or "BLOCKED / PROTECTED (HTTP " .. tostring(build_probe and build_probe.status or "err") .. ")"
  results["DELETE /containers (Resource Deletion)"] = delete_allowed and "🔴 PERMITTED (Proxy forwards DELETE)" or "BLOCKED / PROTECTED (HTTP " .. tostring(delete_probe and delete_probe.status or "err") .. ")"

  out["Method Filter Evaluation"] = results

  if post_allowed or build_allowed or delete_allowed then
    out["Status"] = "VULNERABLE - Socket proxy permits mutating HTTP verbs (POST/DELETE) to Docker daemon"
    out["Assessment"] = "The reverse proxy failed to block mutating API calls. An attacker can create arbitrary root containers, mount the host root directory, or trigger arbitrary builds on the host."
    out["Remediation"] = "Configure the socket proxy with POST=0, DELETE=0, BUILD=0 (e.g. in docker-socket-proxy environment variables) to enforce strict read-only access."
  else
    out["Status"] = "SECURE - Socket proxy successfully blocks all tested mutating HTTP verbs (POST, DELETE, BUILD)."
  end

  return out
end
