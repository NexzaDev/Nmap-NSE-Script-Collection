local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
Detects exposed interactive Swagger / OpenAPI documentation endpoints
(/swagger-ui.html, /openapi.json, /v2/api-docs, /api/docs).
Exposed API specifications reveal complete private API route schemas, parameter
formats, data structures, and authorization models.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "discovery", "safe"}

portrule = shortport.http

local SWAGGER_PATHS = {
  "/swagger-ui.html", "/swagger-ui/", "/v2/api-docs", "/v3/api-docs",
  "/openapi.json", "/openapi.yaml", "/api/docs", "/api/swagger"
}

action = function(host, port)
  local out = stdnse.output_table()
  local exposed = {}

  for _, p in ipairs(SWAGGER_PATHS) do
    local resp = http.get(host, port, p)
    if resp and resp.status == 200 and resp.body then
      if string.find(resp.body, "Swagger UI") or string.find(resp.body, "swagger-ui") or string.find(resp.body, '"openapi":') or string.find(resp.body, '"swagger":') then
        table.insert(exposed, p .. " (HTTP 200)")
      end
    end
  end

  out["Risk Level"] = "🟡 MEDIUM"
  if #exposed > 0 then
    out["Status"] = "VULNERABLE - Interactive Swagger / OpenAPI Documentation Exposed"
    out["Discovered Documentation Endpoints"] = exposed
    out["Remediation"] = "Disable or restrict Swagger UI in production environments behind authentication."
  else
    out["Status"] = "SECURE - No exposed Swagger UI or OpenAPI specs discovered on standard paths."
  end
  return out
end
