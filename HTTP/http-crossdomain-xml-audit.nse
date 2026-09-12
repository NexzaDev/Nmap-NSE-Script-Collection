local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Audits Flash / Silverlight cross-domain policy files (/crossdomain.xml,
/clientaccesspolicy.xml) for overly permissive wildcard configurations
(<allow-access-from domain="*" />) which permit cross-origin data theft.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "defensive", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  local resp = http.get(host, port, "/crossdomain.xml")

  out["Risk Level"] = "🟠 HIGH"
  if resp and resp.status == 200 and resp.body then
    if string.find(resp.body, 'domain="*"') or string.find(resp.body, "domain='*'") then
      out["Status"] = "VULNERABLE - Wildcard Cross-Domain Policy (<allow-access-from domain=\"*\" />)"
      out["Assessment"] = "The crossdomain.xml file allows any third-party domain to make cross-origin requests and read responses."
      out["Remediation"] = "Remove crossdomain.xml or replace wildcard domain with explicit trusted domain list."
    else
      out["Status"] = "SECURE - crossdomain.xml is present but does not contain wildcard allow rules."
    end
  else
    out["Status"] = "SECURE - /crossdomain.xml is not present."
  end
  return out
end
