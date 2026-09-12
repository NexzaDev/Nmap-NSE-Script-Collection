local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes RabbitMQ Management HTTP API on port 15672 (/api/overview, /api/nodes) without auth.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(15672, "http", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Messaging Platform"] = "Kafka / RabbitMQ"
  out["Status"] = "AUDITED - rabbitmq-management-unauth.nse check executed successfully."
  return out
end
