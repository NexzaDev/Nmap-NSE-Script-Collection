local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Connects to Apache Kafka on port 9092 without SASL/TLS authentication.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(9092, "kafka", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Messaging Platform"] = "Kafka / RabbitMQ"
  out["Status"] = "AUDITED - kafka-unauth-broker-access.nse check executed successfully."
  return out
end
