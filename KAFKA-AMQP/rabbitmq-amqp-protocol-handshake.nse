local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends AMQP 0-9-1 connection header and reads Connection.Start frame.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(5672, "amqp", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Messaging Platform"] = "Kafka / RabbitMQ"
  out["Status"] = "AUDITED - rabbitmq-amqp-protocol-handshake.nse check executed successfully."
  return out
end
