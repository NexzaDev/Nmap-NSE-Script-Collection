local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"

description = [[
Probes web and DNS endpoints for DNS-over-HTTPS (DoH) support via /dns-query.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  local resp = http.get(host, port, "/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB")
  out["Risk Level"] = "🟢 LOW"
  if resp and (resp.status == 200 or resp.status == 400) then
    out["Status"] = "IDENTIFIED - DNS-over-HTTPS (DoH) endpoint active on /dns-query"
  else
    out["Status"] = "NOT DETECTED - /dns-query endpoint not active."
  end
  return out
end
