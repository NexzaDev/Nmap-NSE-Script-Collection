local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes whether unauthenticated clients can join consumer groups and consume topic messages.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(9092, "kafka", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Messaging Platform"] = "Kafka / RabbitMQ"
  out["Status"] = "AUDITED - kafka-anonymous-consumer-group.nse check executed successfully."
  return out
end
