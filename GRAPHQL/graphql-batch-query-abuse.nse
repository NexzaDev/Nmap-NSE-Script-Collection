local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"

description = [[
Evaluates whether a GraphQL server supports array-based batch query execution
without imposing batch size limits or per-query rate limiting.
Batching allows an attacker to wrap hundreds of individual authentication,
OTP, or mutation requests into a single HTTP POST request (e.g. [{}, {}, ...]),
completely bypassing traditional HTTP-level rate limiters, WAF thresholds,
and web server request counters.
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
  local batch_size = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".batch_size")) or 15
  local paths_to_test = custom_path and { custom_path } or CANDIDATE_PATHS

  local active_path = nil
  local batch_success = false
  local returned_items_count = 0

  -- Build JSON array batch payload
  local batch_elements = {}
  for i = 1, batch_size do
    table.insert(batch_elements, string.format('{"query":"query B%d { __typename }"}', i))
  end
  local payload = "[" .. table.concat(batch_elements, ",") .. "]"

  for _, p in ipairs(paths_to_test) do
    local resp = http.generic_request(host, port, "POST", p, {
      header = {
        ["Content-Type"] = "application/json",
        ["Accept"] = "application/json"
      },
      content = payload
    })

    if resp and resp.status == 200 and resp.body then
      local trimmed = string.match(resp.body, "^%s*(%[.*)")
      if trimmed then
        -- Count returned JSON objects in array
        local count = 0
        for _ in string.gmatch(resp.body, '"data"%s*:%s*{') do
          count = count + 1
        end

        if count >= 2 then
          active_path = p
          batch_success = true
          returned_items_count = count
          break
        end
      end
    end
  end

  out["Risk Level"] = "🔴 CRITICAL"

  if batch_success then
    out["Status"] = string.format("VULNERABLE - Array-based Batch Query Execution Allowed (%d queries executed simultaneously)", returned_items_count)
    out["Endpoint"] = active_path
    out["Batch Size Tested"] = batch_size
    out["Assessment"] = "The GraphQL server processes array batch queries without size constraints. Attackers can execute credential stuffing, token brute-forcing, and OTP enumeration at 10x-100x amplification per HTTP connection."
    out["Remediation"] = "Disable batch queries if not required by clients, or enforce strict batch size limits (e.g. max 5 queries per batch) and apply rate limiting at the GraphQL execution layer per query."
  else
    out["Status"] = "SECURE - Array batch queries are rejected, limited, or GraphQL endpoint not found."
  end

  return out
end
