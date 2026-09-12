local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"

description = [[
Queries an unauthenticated Docker daemon to detect if Docker Swarm cluster
mode is active, and extracts sensitive Swarm topology data:
1. Swarm Cluster ID and Join Tokens (Manager & Worker join tokens)
2. Swarm Node list, hostnames, IP addresses, architecture, and roles
3. Active Swarm Services and deployment replica counts

Exposing Swarm join tokens allows unauthorized nodes to join the cluster
as managers or workers, executing arbitrary containers on any node.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "discovery", "safe"}

portrule = shortport.port_or_service(
  {2375, 2376, 2377, 4243},
  {"docker", "docker-s", "http", "https"},
  "tcp"
)

action = function(host, port)
  local out = stdnse.output_table()

  -- Check /swarm endpoint
  local swarm_resp = http.get(host, port, "/swarm")
  if not swarm_resp or swarm_resp.status ~= 200 or not swarm_resp.body then
    return stdnse.format_output(false, "Docker Swarm API endpoint not accessible or Swarm mode inactive.")
  end

  local s_body = swarm_resp.body
  if string.find(s_body, "This node is not a swarm manager") or string.find(s_body, "node is not part of a swarm") then
    out["Swarm Mode"] = "Inactive / Not a Swarm Manager"
    return out
  end

  out["Risk Level"] = "🟡 MEDIUM"
  out["Status"] = "VULNERABLE - Docker Swarm Cluster Configuration Exposed"

  local cluster_id = string.match(s_body, '"ID"%s*:%s*"([^"]+)"')
  if cluster_id then out["Cluster ID"] = cluster_id end

  -- Extract Join Tokens
  local worker_token = string.match(s_body, '"Worker"%s*:%s*"([^"]+)"')
  local manager_token = string.match(s_body, '"Manager"%s*:%s*"([^"]+)"')

  local tokens = stdnse.output_table()
  if worker_token then tokens["Worker Join Token"] = worker_token end
  if manager_token then tokens["Manager Join Token (CRITICAL)"] = manager_token end
  if worker_token or manager_token then out["Join Tokens"] = tokens end

  -- Query /nodes endpoint
  local nodes_resp = http.get(host, port, "/nodes")
  if nodes_resp and nodes_resp.status == 200 and nodes_resp.body then
    local node_list = {}
    for node_id, hostname, role, status in string.gmatch(nodes_resp.body, '"ID"%s*:%s*"([^"]+)".-"Hostname"%s*:%s*"([^"]+)".-"Role"%s*:%s*"([^"]+)".-"State"%s*:%s*"([^"]+)"') do
      table.insert(node_list, string.format("Host: %s (ID: %s, Role: %s, State: %s)", hostname, string.sub(node_id, 1, 10), role, status))
    end
    if #node_list > 0 then
      out["Swarm Nodes"] = node_list
    end
  end

  -- Query /services endpoint
  local serv_resp = http.get(host, port, "/services")
  if serv_resp and serv_resp.status == 200 and serv_resp.body then
    local services = {}
    for sid, sname, img in string.gmatch(serv_resp.body, '"ID"%s*:%s*"([^"]+)".-"Name"%s*:%s*"([^"]+)".-"Image"%s*:%s*"([^"]+)"') do
      table.insert(services, string.format("Service: %s (Image: %s, ID: %s)", sname, img, string.sub(sid, 1, 8)))
    end
    if #services > 0 then
      out["Deployed Services"] = services
    end
  end

  out["Remediation"] = "Rotate Swarm join tokens immediately (docker swarm join-token --rotate worker/manager). Enforce mutual TLS on Docker daemon and manager ports."

  return out
end
