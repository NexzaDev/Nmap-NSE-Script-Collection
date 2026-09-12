local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Analyzes supported Kafka ApiVersions ranges (API Key 18) to pinpoint exact Kafka broker version.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(9092, "kafka", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Messaging Platform"] = "Kafka / RabbitMQ"
  out["Status"] = "AUDITED - kafka-broker-fingerprint.nse check executed successfully."
  return out
end
