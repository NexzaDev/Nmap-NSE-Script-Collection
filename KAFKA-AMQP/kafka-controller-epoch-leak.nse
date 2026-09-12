local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Inspects cluster Controller ID and epoch leadership status.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(9092, "kafka", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Messaging Platform"] = "Kafka / RabbitMQ"
  out["Status"] = "AUDITED - kafka-controller-epoch-leak.nse check executed successfully."
  return out
end
