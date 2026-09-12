local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
Detects exposed phpinfo() diagnostic scripts (/phpinfo.php, /info.php, /test.php,
/php_info.php). phpinfo() reveals PHP versions, extensions, compilation flags,
server environment variables, and filesystem paths.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "discovery", "safe"}

portrule = shortport.http

local PHPINFO_PATHS = { "/phpinfo.php", "/info.php", "/test.php", "/php_info.php", "/pi.php" }

action = function(host, port)
  local out = stdnse.output_table()
  local exposed = {}

  for _, p in ipairs(PHPINFO_PATHS) do
    local resp = http.get(host, port, p)
    if resp and resp.status == 200 and resp.body then
      if string.find(resp.body, "<title>phpinfo()</title>") or (string.find(resp.body, "PHP Version") and string.find(resp.body, "System")) then
        table.insert(exposed, p .. " (HTTP 200 - phpinfo output)")
      end
    end
  end

  out["Risk Level"] = "🟠 HIGH"
  if #exposed > 0 then
    out["Status"] = "VULNERABLE - Exposed phpinfo() Diagnostic Scripts Detected"
    out["Exposed Scripts"] = exposed
    out["Remediation"] = "Delete all phpinfo() diagnostic scripts from production web servers."
  else
    out["Status"] = "SECURE - No phpinfo() scripts found on standard paths."
  end
  return out
end
