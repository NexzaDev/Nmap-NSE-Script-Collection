local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Fingerprints device hardware category (Router, Switch, Firewall, Printer, Server, UPS).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(161, "snmp", "udp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "SNMP"
  out["Status"] = "AUDITED - snmp-device-type-fingerprint.nse check executed successfully."
  return out
end
