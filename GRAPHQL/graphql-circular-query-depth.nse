local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"

description = [[
Evaluates whether a GraphQL server enforces maximum query depth limits.
Sends progressively deeper nested queries using the built-in introspection
type tree (__schema { types { fields { type { fields { type { fields ... } } } } } })
to determine if the server limits query recursion or processes arbitrarily deep
AST trees, which creates severe Denial of Service (DoS) and memory exhaustion risks.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

local CANDIDATE_PATHS = {
  "/graphql", "/api/graphql", "/v1/graphql", "/query", "/api/query", "/gql"
}

-- Build a nested schema query with specified depth
local function build_depth_query(depth)
  local q = "__schema { types { name "
  local close = " } }"
  for _ = 1, depth do
    q = q .. "fields { name type { name "
    close = close .. " } }"
  end
  return string.format('{"query":"query DepthAudit { %s %s }"}', q, close)
end

action = function(host, port)
  local out = stdnse.output_table()
  local custom_path = stdnse.get_script_args(SCRIPT_NAME .. ".path")
  local max_test_depth = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".max_depth")) or 12
  local paths_to_test = custom_path and { custom_path } or CANDIDATE_PATHS

  local active_path = nil

  -- Find active endpoint
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

  out["Risk Level"] = "🟠 HIGH"
  out["Endpoint"] = active_path

  local highest_accepted_depth = 0
  local depth_limit_enforced = false

  local test_depths = { 3, 6, 9, max_test_depth }
  for _, d in ipairs(test_depths) do
    local payload = build_depth_query(d)
    local resp = http.generic_request(host, port, "POST", active_path, {
      header = { ["Content-Type"] = "application/json" },
      content = payload
    })

    if resp and resp.status == 200 and resp.body then
      if string.find(resp.body, '"data"') and not string.find(resp.body, "maxQueryDepth") and not string.find(resp.body, "exceeds maximum operation depth") and not string.find(resp.body, "DepthLimitError") then
        highest_accepted_depth = d
      elseif string.find(resp.body, "depth") or string.find(resp.body, "Depth") or string.find(resp.body, "too complex") then
        depth_limit_enforced = true
        break
      end
    end
  end

  if highest_accepted_depth >= 9 then
    out["Status"] = string.format("VULNERABLE - Deep Query Nesting Accepted (Depth %d resolved without restriction)", highest_accepted_depth)
    out["Assessment"] = "The GraphQL engine does not enforce query depth limiting. Attackers can execute deeply nested circular queries causing exponential resolver execution and server CPU/memory exhaustion."
    out["Remediation"] = "Implement query depth validation middleware (e.g. graphql-depth-limit for JavaScript, MaxQueryDepthInstrumentation for Java, or graphql-ruby query_max_depth)."
  elseif depth_limit_enforced then
    out["Status"] = "SECURE - Query depth limiting is actively enforced by server."
  else
    out["Status"] = "AUDITED - Query depth test inconclusive or moderate depth handled normally."
  end

  return out
end
