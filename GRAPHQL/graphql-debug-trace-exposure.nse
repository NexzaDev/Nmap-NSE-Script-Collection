local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"

description = [[
Detects whether a GraphQL server returns sensitive debugging extensions
(Apollo Tracing, GraphQL-Java tracing, debug exceptions, or execution metrics)
in HTTP responses. These debug extensions expose internal database query
timings, microservice RPC latency, resolver call graphs, and full stack traces.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "discovery", "safe"}

portrule = shortport.http

local CANDIDATE_PATHS = {
  "/graphql", "/api/graphql", "/v1/graphql", "/query", "/api/query", "/gql"
}

action = function(host, port)
  local out = stdnse.output_table()
  local custom_path = stdnse.get_script_args(SCRIPT_NAME .. ".path")
  local paths_to_test = custom_path and { custom_path } or CANDIDATE_PATHS

  local active_path = nil
  local leaked_extensions = {}

  for _, p in ipairs(paths_to_test) do
    local resp = http.generic_request(host, port, "POST", p, {
      header = {
        ["Content-Type"] = "application/json",
        ["Accept"] = "application/json"
      },
      content = '{"query":"query DebugProbe { __typename }"}'
    })

    if resp and resp.status == 200 and resp.body then
      local b = resp.body
      local has_ext = string.find(b, '"extensions"') ~= nil

      if has_ext then
        active_path = p
        if string.find(b, '"tracing"') then
          table.insert(leaked_extensions, "Apollo Tracing Extension (Execution timings, duration, and resolver paths exposed)")
        end
        if string.find(b, '"exception"') or string.find(b, '"stacktrace"') then
          table.insert(leaked_extensions, "Debug Exception / Stack Trace Extension exposed")
        end
        if string.find(b, '"queryPlan"') or string.find(b, '"serviceName"') then
          table.insert(leaked_extensions, "Apollo Federation / Subgraph Query Plan exposed")
        end
        if string.find(b, '"metrics"') or string.find(b, '"profile"') then
          table.insert(leaked_extensions, "Internal Performance Profiling metrics exposed")
        end
        break
      end
    end
  end

  out["Risk Level"] = "🟡 MEDIUM"

  if #leaked_extensions > 0 then
    out["Status"] = "VULNERABLE - Sensitive GraphQL Debugging Extensions Exposed in Responses"
    out["Endpoint"] = active_path
    out["Exposed Extensions"] = leaked_extensions
    out["Remediation"] = "Disable Apollo Tracing and debug extensions in production. In Apollo Server set 'tracing: false, debug: false' and ensure NODE_ENV=production."
  else
    out["Status"] = "SECURE - No debug tracing extensions detected in GraphQL responses."
  end

  return out
end
