local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"

description = [[
Detects whether GraphQL schema introspection (__schema, __type) is enabled
on the target web service. In production environments, introspection allows
unauthenticated attackers to download the entire API schema, including all
query fields, mutations, hidden administrative objects, custom scalar types,
arguments, and internal documentation.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "discovery", "safe"}

portrule = shortport.http

local CANDIDATE_PATHS = {
  "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
  "/query", "/api/query", "/gql", "/api/gql", "/graphql/v1"
}

local INTROSPECTION_QUERY = '{"query":"query SchemaAudit { __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind description } } }"}'

action = function(host, port)
  local out = stdnse.output_table()
  local custom_path = stdnse.get_script_args(SCRIPT_NAME .. ".path")
  local paths_to_test = custom_path and { custom_path } or CANDIDATE_PATHS

  local active_endpoint = nil
  local introspect_body = nil

  for _, p in ipairs(paths_to_test) do
    local resp = http.generic_request(host, port, "POST", p, {
      header = {
        ["Content-Type"] = "application/json",
        ["Accept"] = "application/json"
      },
      content = INTROSPECTION_QUERY
    })

    if resp and resp.status == 200 and resp.body then
      if string.find(resp.body, "__schema") or string.find(resp.body, "queryType") then
        active_endpoint = p
        introspect_body = resp.body
        break
      end
    end
  end

  if not active_endpoint then
    return stdnse.format_output(false, "No active GraphQL endpoint with enabled introspection detected on common paths.")
  end

  out["Status"] = "VULNERABLE - GraphQL Introspection is ENABLED in Production"
  out["Risk Level"] = "🔴 CRITICAL"
  out["CVSS Score"] = "7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)"
  out["Endpoint"] = active_endpoint

  -- Extract Schema details
  local query_type = string.match(introspect_body, '"queryType"%s*:%s*{%s*"name"%s*:%s*"([^"]+)"')
  local mutation_type = string.match(introspect_body, '"mutationType"%s*:%s*{%s*"name"%s*:%s*"([^"]+)"')
  local subscription_type = string.match(introspect_body, '"subscriptionType"%s*:%s*{%s*"name"%s*:%s*"([^"]+)"')

  local schema_info = stdnse.output_table()
  if query_type then schema_info["Query Root Type"] = query_type end
  if mutation_type then schema_info["Mutation Root Type (Mutating APIs available)"] = mutation_type end
  if subscription_type then schema_info["Subscription Root Type (Real-time active)"] = subscription_type end

  -- Count types and extract custom types
  local types = {}
  for tname in string.gmatch(introspect_body, '{"name"%s*:%s*"([^"]+)"%s*,%s*"kind"') do
    if not string.match(tname, "^__") then
      table.insert(types, tname)
    end
  end

  schema_info["Total Custom Types Discovered"] = #types
  if #types > 0 then
    local sample = {}
    for i = 1, math.min(#types, 15) do
      table.insert(sample, types[i])
    end
    if #types > 15 then
      table.insert(sample, string.format("... and %d more types", #types - 15))
    end
    schema_info["Sample Exposed Types"] = sample
  end

  out["Schema Architecture"] = schema_info
  out["Remediation"] = "Disable introspection in production deployments. In Apollo Server set 'introspection: false', in GraphQL Java set 'maxQueryDepth' and disable Introspection, in GraphQL Yoga set 'plugins: [useDisableIntrospection()]'."

  return out
end
