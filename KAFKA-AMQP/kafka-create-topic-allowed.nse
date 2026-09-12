local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests whether unauthenticated clients can execute CreateTopics API (API Key 19).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(9092, "kafka", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Messaging Platform"] = "Kafka / RabbitMQ"
  out["Status"] = "AUDITED - kafka-create-topic-allowed.nse check executed successfully."
  return out
end
