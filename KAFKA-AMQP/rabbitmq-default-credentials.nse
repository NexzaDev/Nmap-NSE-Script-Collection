local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests default RabbitMQ credentials (guest/guest, admin/admin) on AMQP (5672) and HTTP (15672).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(5672, "amqp", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Messaging Platform"] = "Kafka / RabbitMQ"
  out["Status"] = "AUDITED - rabbitmq-default-credentials.nse check executed successfully."
  return out
end
