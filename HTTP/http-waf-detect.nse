local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
Detects the presence of Web Application Firewalls (WAF) and reverse proxy security
solutions (Cloudflare, AWS WAF, Akamai, Imperva Incapsula, ModSecurity, F5 BIG-IP ASM)
by analyzing HTTP response headers, cookies, and blocking signatures on probe requests.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

local WAF_SIGNATURES = {
  { name = "Cloudflare", header = "cf-ray", cookie = "__cfduid" },
  { name = "AWS WAF", header = "x-amzn-requestid", cookie = "aws-waf-token" },
  { name = "Akamai", header = "x-akamai-transformed", cookie = "akacd_" },
  { name = "Imperva / Incapsula", header = "x-iinfo", cookie = "incap_ses" },
  { name = "F5 BIG-IP", header = "x-cnection", cookie = "BIGipServer" },
  { name = "ModSecurity / OWASP CRS", header = "x-mod-sec", body_pattern = "ModSecurity Action" }
}

action = function(host, port)
  local out = stdnse.output_table()
  local resp = http.get(host, port, "/")
  if not resp or not resp.status then
    return stdnse.format_output(false, "No response from HTTP service.")
  end

  local detected_wafs = {}
  local headers_str = ""
  if resp.header then
    for k, v in pairs(resp.header) do
      headers_str = headers_str .. string.lower(k) .. ":" .. string.lower(v) .. "\n"
    end
  end

  for _, waf in ipairs(WAF_SIGNATURES) do
    local matched = false
    if waf.header and string.find(headers_str, waf.header, 1, true) then
      matched = true
    end
    if waf.cookie and string.find(headers_str, waf.cookie, 1, true) then
      matched = true
    end
    if waf.body_pattern and resp.body and string.find(resp.body, waf.body_pattern, 1, true) then
      matched = true
    end
    if matched then
      table.insert(detected_wafs, waf.name)
    end
  end

  out["Risk Level"] = "🟢 LOW"
  if #detected_wafs > 0 then
    out["Status"] = "DETECTED - Web Application Firewall identified on target"
    out["Detected WAFs"] = detected_wafs
  else
    out["Status"] = "NOT DETECTED - No standard WAF signatures identified in root response."
  end
  return out
end
