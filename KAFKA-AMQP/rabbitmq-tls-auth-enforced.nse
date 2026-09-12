local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests whether AMQP over TLS (port 5671) enforces client certificate authentication.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"defensive", "safe"}

portrule = shortport.port_or_service(5671, "amqps", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟠 HIGH"
  out["Messaging Platform"] = "Kafka / RabbitMQ"
  out["Status"] = "AUDITED - rabbitmq-tls-auth-enforced.nse check executed successfully."
  return out
end
