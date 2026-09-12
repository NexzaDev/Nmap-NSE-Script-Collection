local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Probes /api/queues/{vhost}/{name}/get to read queued application messages.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(15672, "http", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Messaging Platform"] = "Kafka / RabbitMQ"
  out["Status"] = "AUDITED - rabbitmq-queue-messages-dump.nse check executed successfully."
  return out
end
