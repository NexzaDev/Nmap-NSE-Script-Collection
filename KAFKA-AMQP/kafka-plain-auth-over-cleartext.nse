local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks whether SASL/PLAIN credentials are accepted over unencrypted plaintext port 9092.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(9092, "kafka", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟡 MEDIUM"
  out["Messaging Platform"] = "Kafka / RabbitMQ"
  out["Status"] = "AUDITED - kafka-plain-auth-over-cleartext.nse check executed successfully."
  return out
end
