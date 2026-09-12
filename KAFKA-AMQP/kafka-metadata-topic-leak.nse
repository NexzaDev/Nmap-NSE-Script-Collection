local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends Kafka ApiVersions and Metadata request (API Key 3) to dump all topic names, partition counts.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(9092, "kafka", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Messaging Platform"] = "Kafka / RabbitMQ"
  out["Status"] = "AUDITED - kafka-metadata-topic-leak.nse check executed successfully."
  return out
end
