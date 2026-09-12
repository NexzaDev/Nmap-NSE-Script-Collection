local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"

description = [[
Evaluates whether a GraphQL server limits the number of field aliases in a
single request. By defining hundreds of field aliases (e.g. { a1: user, a2: user, ... }),
an attacker can force the GraphQL runtime and underlying database to execute
hundreds or thousands of parallel data resolver queries within a single HTTP request,
leading to severe server resource exhaustion and Denial of Service (DoS).
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
  local alias_count = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".alias_count")) or 50
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
    return stdnse.format_output(false, "No active GraphQL endpoint identified.")
  end

  out["Risk Level"] = "🔴 CRITICAL"
  out["Endpoint"] = active_path
  out["Alias Count Tested"] = alias_count

  -- Construct aliased query
  local alias_elements = {}
  for i = 1, alias_count do
    table.insert(alias_elements, string.format("a%d: __typename", i))
  end
  local query_str = "query AliasAudit { " .. table.concat(alias_elements, " ") .. " }"
  local payload = string.format('{"query":"%s"}', query_str)

  local resp = http.generic_request(host, port, "POST", active_path, {
    header = {
      ["Content-Type"] = "application/json",
      ["Accept"] = "application/json"
    },
    content = payload
  })

  if not resp or not resp.status then
    return stdnse.format_output(false, "No response received to alias overload test.")
  end

  local returned_alias_count = 0
  if resp.status == 200 and resp.body then
    for _ in string.gmatch(resp.body, '"a%d+"%s*:') do
      returned_alias_count = returned_alias_count + 1
    end
  end

  if returned_alias_count >= alias_count - 5 then
    out["Status"] = string.format("VULNERABLE - Server resolved %d aliased fields without restriction", returned_alias_count)
    out["Assessment"] = "The GraphQL engine does not limit alias definitions. Attackers can amplify database backend workload by 100x-1000x per HTTP request using alias multiplier attacks."
    out["Remediation"] = "Enforce max-alias validation rules (e.g. maxAliases directive or graphql-armor max-aliases limit set to 15)."
  elseif string.find(resp.body or "", "alias") or string.find(resp.body or "", "too many") or (resp.status ~= 200 and resp.status ~= 500) then
    out["Status"] = "SECURE - Field alias limit is actively enforced by server."
  else
    out["Status"] = "AUDITED - Server did not return expected aliased response."
  end

  return out
end
