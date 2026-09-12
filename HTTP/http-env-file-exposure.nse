local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
Probes for publicly accessible environment configuration files (/.env, /.env.local,
/.env.production, /.env.backup). These files frequently expose production database
credentials, API secret keys, SMTP passwords, and cloud access tokens.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

local ENV_PATHS = { "/.env", "/.env.local", "/.env.production", "/.env.backup", "/.env.stage" }

action = function(host, port)
  local out = stdnse.output_table()
  local exposed = {}

  for _, path in ipairs(ENV_PATHS) do
    local resp = http.get(host, port, path)
    if resp and resp.status == 200 and resp.body then
      local b = resp.body
      if (string.find(b, "DB_PASSWORD") or string.find(b, "APP_KEY") or string.find(b, "DATABASE_URL") or string.find(b, "AWS_SECRET")) and not string.find(b, "<html") then
        table.insert(exposed, path .. " (HTTP 200, contains secret keys)")
      end
    end
  end

  out["Risk Level"] = "🔴 CRITICAL"
  if #exposed > 0 then
    out["Status"] = "VULNERABLE - Exposed Environment Configuration Files Detected"
    out["Exposed Files"] = exposed
    out["Remediation"] = "Remove .env files from the web document root and configure web server to deny access to all dotfiles."
  else
    out["Status"] = "SECURE - No exposed .env files identified on tested paths."
  end
  return out
end
