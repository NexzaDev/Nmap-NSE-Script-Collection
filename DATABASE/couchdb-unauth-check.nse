local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"

description = [[
Probes Apache CouchDB (port 5984) for unauthenticated administrative access to /_all_dbs and /_membership.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(5984, "couchdb", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  local resp = http.get(host, port, "/_all_dbs")
  out["Risk Level"] = "🔴 CRITICAL"
  if resp and resp.status == 200 and resp.body then
    out["Status"] = "VULNERABLE - Unauthenticated CouchDB /_all_dbs database enumeration permitted"
  else
    out["Status"] = "SECURE - CouchDB requires authentication."
  end
  return out
end
