local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Evaluates whether an MQTT TLS endpoint (typically TCP port 8883) strictly
enforces Mutual TLS (mTLS / client certificate authentication) or allows
anonymous TLS handshakes without client certificates.
In IoT deployments, client certificate authentication ensures that only
physically provisioned devices with hardware-stored certificates can establish
a session with the central message broker.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "defensive", "safe"}

portrule = shortport.port_or_service(
  {8883, 8884, 8885},
  {"mqtt-s", "ssl/mqtt", "mqtt"},
  "tcp"
)

action = function(host, port)
  local out = stdnse.output_table()

  -- Connect using standard SSL socket without providing a client cert
  local sock = nmap.new_socket("ssl")
  sock:set_timeout(5000)

  local ok, err = sock:connect(host, port, "ssl")

  out["Risk Level"] = "🟠 HIGH"
  out["Port"] = port.number

  if ok then
    sock:close()
    out["Status"] = "VULNERABLE - Mutual TLS (mTLS) is NOT Enforced on Secure MQTT Port"
    out["Client Certificate Enforcement"] = "OPTIONAL / DISABLED (Anonymous TLS Handshake Succeeded)"
    out["Assessment"] = "The broker completed the TLS handshake without demanding or validating a client certificate. Unless strong application-level credentials are required, any client on the network can connect."
    out["Remediation"] = "Enforce mutual TLS on port 8883. In Mosquitto set 'require_certificate true'; in EMQX set 'ssl.listener.ssl.external.verify = verify_peer'."
  else
    local err_str = tostring(err or "")
    if string.find(err_str, "certificate required") or string.find(err_str, "bad certificate") or string.find(err_str, "handshake failure") or string.find(err_str, "unknown ca") then
      out["Status"] = "SECURE - Mutual TLS (mTLS) is Strictly Enforced"
      out["Client Certificate Enforcement"] = "REQUIRED (TLS Handshake rejected client without certificate)"
      out["Risk Level"] = "🟢 LOW"
    else
      out["Status"] = "AUDITED - TLS connection failed with error: " .. err_str
    end
  end

  return out
end
