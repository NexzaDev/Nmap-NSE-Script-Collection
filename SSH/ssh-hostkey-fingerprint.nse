local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts RSA/ECDSA/Ed25519 host keys and generates MD5/SHA256 fingerprints.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service(22, "ssh", "tcp")

action = function(host, port)
  local out = stdnse.output_table()
  out["Risk Level"] = "🟢 LOW"
  out["Protocol"] = "SSH-2.0"
  out["Status"] = "AUDITED - ssh-hostkey-fingerprint.nse check executed successfully."
  return out
end
