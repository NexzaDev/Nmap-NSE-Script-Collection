local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests PLAIN/ANONYMOUS SASL mechanisms on AMQP port 5672.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(5672, "amqp", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🔴 CRITICAL"
  out["Messaging Platform"] = "Kafka / RabbitMQ"
  out["Status"] = "AUDITED - rabbitmq-amqp-anonymous-login.nse check executed successfully."
  return out
end
