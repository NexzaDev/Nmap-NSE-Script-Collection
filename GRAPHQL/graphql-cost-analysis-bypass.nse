local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"

description = [[
Evaluates whether a GraphQL server implements Query Cost Analysis (Complexity
Calculation) or allows computationally heavy, multi-field, and multi-argument
expansion queries to execute unrestricted. Without cost analysis, an attacker
can craft expensive nested join queries that consume excessive CPU and memory on
the database layer (Algorithmic Complexity / GraphQL DoS).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

local CANDIDATE_PATHS = {
  "/graphql", "/api/graphql", "/v1/graphql", "/query", "/api/query", "/gql"
}

action = function(host, port)
  local out = stdnse.output_table()
  local custom_path = stdnse.get_script_args(SCRIPT_NAME .. ".path")
  local paths_to_test = custom_path and { custom_path } or CANDIDATE_PATHS

  local active_path = nil

  for _, p in ipairs(paths_to_test) do
    local probe = http.generic_request(host, port, "POST", p, {
      header = { ["Content-Type"] = "application/json" },
      content = '{"query":"{ __typename }"}'
    })
    if probe and probe.status == 200 and probe.body and string.find(probe.body, "__typename") then
      active_path = p
      break
    end
  end

  if not active_path then
    return stdnse.format_output(false, "No active GraphQL endpoint identified on tested paths.")
  end

  out["Risk Level"] = "🟡 MEDIUM"
  out["Endpoint"] = active_path

  -- Construct a wide query requesting multiple root type fields repeatedly
  local query_fields = {}
  for i = 1, 40 do
    table.insert(query_fields, string.format("f%d: __type(name: \"String\") { name kind description }", i))
  end
  local wide_query = string.format('{"query":"query CostProbe { %s }"}', table.concat(query_fields, " "))

  local resp = http.generic_request(host, port, "POST", active_path, {
    header = { ["Content-Type"] = "application/json" },
    content = wide_query
  })

  local cost_blocked = false
  local cost_error_message = nil

  if resp and resp.body then
    if string.find(resp.body, "Query cost") or string.find(resp.body, "complexity") or string.find(resp.body, "ComplexityError") or string.find(resp.body, "max_cost") or string.find(resp.body, "exceeded") then
      cost_blocked = true
      cost_error_message = string.match(resp.body, '"message"%s*:%s*"([^"]+)"')
    end
  end

  if cost_blocked then
    out["Status"] = "SECURE - Query Complexity / Cost Analysis is Enforced"
    if cost_error_message then out["Server Cost Rejection Message"] = cost_error_message end
  elseif resp and resp.status == 200 and string.find(resp.body or "", '"data"') then
    out["Status"] = "VULNERABLE - No Query Cost / Complexity Analysis Enforced"
    out["Assessment"] = "The server executed a multi-field heavy query without calculating complexity or enforcing cost limits. Attackers can execute expensive database queries to exhaust backend computing capacity."
    out["Remediation"] = "Implement query cost analysis plugins (e.g. graphql-cost-analysis, graphql-armor cost-limit, or GraphQL-Java MaxQueryComplexityInstrumentation)."
  else
    out["Status"] = "AUDITED - Query execution completed with non-standard status."
  end

  return out
end
