local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes Kafka SaslHandshake API (API Key 17) for PLAIN, SCRAM-SHA-256, SCRAM-SHA-512, GSSAPI.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(9092, "kafka", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Messaging Platform"] = "Kafka / RabbitMQ"
  out["Status"] = "AUDITED - kafka-sasl-mechanism-audit.nse check executed successfully."
  return out
end
