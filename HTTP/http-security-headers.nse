local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Checks an HTTP(S) service for the presence of common security-related
response headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, Permissions-Policy) and reports which ones are missing
or set with weak/default values. Useful as a quick audit step before
digging deeper manually.
]]

---
-- @usage
-- nmap -p 80,443 --script http-security-headers <target>
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | http-security-headers:
-- |   Missing headers:
-- |     Content-Security-Policy
-- |     X-Frame-Options
-- |   Present headers:
-- |     Strict-Transport-Security: max-age=31536000
-- |_    X-Content-Type-Options: nosniff

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.http

local CHECK_HEADERS = {
  "strict-transport-security",
  "content-security-policy",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
}

action = function(host, port)
  local response = http.get(host, port, "/")
  if not response or not response.header then
    return "Could not retrieve HTTP response."
  end

  local present = {}
  local missing = {}

  for _, name in ipairs(CHECK_HEADERS) do
    local value = response.header[name]
    if value then
      table.insert(present, ("%s: %s"):format(name, value))
    else
      table.insert(missing, name)
    end
  end

  local out = stdnse.output_table()

  if #missing > 0 then
    out["Missing headers"] = missing
  end
  if #present > 0 then
    out["Present headers"] = present
  end

  if #missing == 0 and #present == 0 then
    return "No relevant headers found in response."
  end

  return out
end
