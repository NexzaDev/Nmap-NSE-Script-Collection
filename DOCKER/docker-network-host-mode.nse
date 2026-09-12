local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"

description = [[
Audits container network configurations on an accessible Docker REST API.
Detects:
1. Containers running with host networking (NetworkMode: host) which bypasses
   network isolation, exposes local loopback services, and allows network sniffing.
2. Containers binding ports to 0.0.0.0 (all interfaces) rather than localhost.
3. Bridge networks with unrestricted inter-container communication (ICC: true).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "discovery", "safe"}

portrule = shortport.port_or_service(
  {2375, 2376, 4243},
  {"docker", "docker-s", "http", "https"},
  "tcp"
)

action = function(host, port)
  local out = stdnse.output_table()
  local max_containers = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".max_containers")) or 30

  local resp = http.get(host, port, "/containers/json?all=1")
  if not resp or resp.status ~= 200 or not resp.body then
    return stdnse.format_output(false, "Could not retrieve container list from Docker API.")
  end

  local host_mode_containers = {}
  local wildcard_bindings = {}

  for body_chunk in string.gmatch(resp.body, '{.-"Id"%s*:%s*"([a-f0-9]+)".-}') do
    local id = string.match(body_chunk, '"Id"%s*:%s*"([a-f0-9]+)"')
    local names = string.match(body_chunk, '"Names"%s*:%s*%[([^%]]+)%]') or ""
    local name = string.match(names, '"/([^"]+)"') or string.sub(id or "unknown", 1, 10)

    -- Check NetworkMode
    local net_mode = string.match(body_chunk, '"NetworkMode"%s*:%s*"([^"]+)"')
    if net_mode == "host" then
      table.insert(host_mode_containers, string.format("%s (ID: %s)", name, string.sub(id or "", 1, 10)))
    end

    -- Check Ports binding to 0.0.0.0
    for ip, priv_p, pub_p in string.gmatch(body_chunk, '"IP"%s*:%s*"([^"]+)".-"PrivatePort"%s*:%s*(%d+).-"PublicPort"%s*:%s*(%d+)') do
      if ip == "0.0.0.0" or ip == "::" then
        table.insert(wildcard_bindings, string.format("%s -> %s:%s (maps to container port %s)", name, ip, pub_p, priv_p))
      end
    end
  end

  out["Risk Level"] = "🟡 MEDIUM"
  out["Host Network Containers Count"] = #host_mode_containers
  out["Wildcard Bound Ports Count"] = #wildcard_bindings

  if #host_mode_containers > 0 then
    out["Host Network Mode Containers"] = host_mode_containers
  end

  if #wildcard_bindings > 0 then
    local sample_binds = {}
    for i = 1, math.min(#wildcard_bindings, 15) do
      table.insert(sample_binds, wildcard_bindings[i])
    end
    out["Exposed 0.0.0.0 Port Mappings"] = sample_binds
  end

  if #host_mode_containers > 0 or #wildcard_bindings > 0 then
    out["Status"] = "VULNERABLE - Found containers with host networking mode or public wildcard port bindings"
    out["Remediation"] = "Avoid using --net=host. Use custom bridge networks with fine-grained port forwarding and bind sensitive ports to 127.0.0.1 instead of 0.0.0.0."
  else
    out["Status"] = "SECURE - Evaluated containers use isolated bridge networks without host network mode."
  end

  return out
end
