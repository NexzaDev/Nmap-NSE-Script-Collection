local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"

description = [[
Probes InfluxDB API (port 8086) for unauthenticated query execution (/query?q=SHOW+DATABASES).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(8086, "influxdb", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  local resp = http.get(host, port, "/query?q=SHOW%20DATABASES")
  out["Risk Level"] = "🔴 CRITICAL"
  if resp and resp.status == 200 and resp.body then
    out["Status"] = "VULNERABLE - InfluxDB allows unauthenticated SHOW DATABASES query execution"
  else
    out["Status"] = "SECURE - InfluxDB query API requires authentication."
  end
  return out
end
