local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"

description = [[
Probes ClickHouse HTTP interface on port 8123 for unauthenticated query execution.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(8123, "clickhouse", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  local resp = http.get(host, port, "/?query=SELECT%20version()")
  out["Risk Level"] = "🟠 HIGH"
  if resp and resp.status == 200 and resp.body then
    out["Status"] = "VULNERABLE - ClickHouse unauthenticated HTTP query execution permitted"
  else
    out["Status"] = "SECURE - ClickHouse HTTP interface requires credentials."
  end
  return out
end
