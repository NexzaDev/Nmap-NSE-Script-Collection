local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"

description = [[
Probes Neo4j Graph Database HTTP management interface on port 7474 for unauthenticated discovery endpoints.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(7474, "neo4j", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  local resp = http.get(host, port, "/db/data/")
  out["Risk Level"] = "🟠 HIGH"
  if resp and resp.status == 200 and resp.body then
    out["Status"] = "VULNERABLE - Neo4j /db/data/ discovery interface exposed without auth"
  else
    out["Status"] = "SECURE - Neo4j interface requires authentication."
  end
  return out
end
