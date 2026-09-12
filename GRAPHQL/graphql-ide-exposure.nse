local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"

description = [[
Detects whether interactive GraphQL web development consoles and IDEs
(GraphiQL, GraphQL Playground, Altair GraphQL Client, Apollo Sandbox, Prisma Studio)
are exposed to external networks.
Leaving interactive developer IDE interfaces exposed in production increases the
attack surface, exposes automated query builders, schema explorers, and history logs.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "discovery", "safe"}

portrule = shortport.http

local IDE_PROBES = {
  { path = "/graphql", desc = "GraphQL default endpoint" },
  { path = "/graphiql", desc = "GraphiQL IDE" },
  { path = "/playground", desc = "GraphQL Playground" },
  { path = "/altair", desc = "Altair GraphQL Client" },
  { path = "/api/graphql", desc = "API GraphQL endpoint" },
  { path = "/explorer", desc = "GraphQL Explorer" },
  { path = "/console", desc = "GraphQL Console" }
}

local function detect_ide_type(body)
  if string.find(body, "GraphQL Playground") or string.find(body, "graphql-playground") then
    return "GraphQL Playground (Prisma)"
  elseif string.find(body, "GraphiQL") or string.find(body, "graphiql.min.js") or string.find(body, "graphiql.js") then
    return "GraphiQL (Official IDE)"
  elseif string.find(body, "Altair GraphQL") or string.find(body, "altair-static") then
    return "Altair GraphQL Client"
  elseif string.find(body, "Apollo Studio") or string.find(body, "embeddable-sandbox") then
    return "Apollo Studio Sandbox"
  elseif string.find(body, "GraphQL") and string.find(body, "query") and string.find(body, "<html") then
    return "Generic GraphQL Interactive Web UI"
  end
  return nil
end

action = function(host, port)
  local out = stdnse.output_table()
  local custom_path = stdnse.get_script_args(SCRIPT_NAME .. ".path")

  local probes = custom_path and { { path = custom_path, desc = "Custom path" } } or IDE_PROBES
  local discovered_ides = {}

  for _, probe in ipairs(probes) do
    local resp = http.generic_request(host, port, "GET", probe.path, {
      header = {
        ["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
      }
    })

    if resp and resp.status == 200 and resp.body then
      local ide_name = detect_ide_type(resp.body)
      if ide_name then
        table.insert(discovered_ides, string.format("%s -> %s (HTTP 200)", probe.path, ide_name))
      end
    end
  end

  out["Risk Level"] = "🟡 MEDIUM"

  if #discovered_ides > 0 then
    out["Status"] = "VULNERABLE - Interactive GraphQL IDE Interface Exposed in Production"
    out["Exposed Interfaces"] = discovered_ides
    out["Assessment"] = "Interactive GraphQL IDEs provide web-based schema browsing, interactive query builders, and autocompletion to unauthenticated users."
    out["Remediation"] = "Disable GraphiQL/Playground IDEs in production environments. Set NODE_ENV=production, playground: false, and graphiql: false."
  else
    out["Status"] = "SECURE - No interactive GraphQL IDEs detected on tested standard paths."
  end

  return out
end
