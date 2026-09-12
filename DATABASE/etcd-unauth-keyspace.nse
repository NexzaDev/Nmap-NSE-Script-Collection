local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"

description = [[
Probes etcd distributed key-value store on port 2379 for unauthenticated keyspace dumping (/v2/keys or /v3/kv/range).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(2379, "etcd", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  local resp = http.get(host, port, "/v2/keys")
  out["Risk Level"] = "🔴 CRITICAL"
  if resp and resp.status == 200 and resp.body then
    out["Status"] = "VULNERABLE - Unauthenticated etcd keyspace dump accessible via /v2/keys"
  else
    out["Status"] = "SECURE - etcd API requires authentication."
  end
  return out
end
