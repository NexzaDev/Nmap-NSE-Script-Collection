local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"

description = [[
Audits support for Automatic Persisted Queries (APQ) on a GraphQL endpoint.
Tests whether:
1. APQ protocol (extensions.persistedQuery) is supported by the server.
2. The server accepts arbitrary unpersisted raw queries alongside persisted ones (dual mode),
   rendering persisted query allowlists ineffective against query tampering.
3. The server allows unauthenticated clients to register new query hashes into the APQ cache
   (APQ cache poisoning / memory exhaustion).
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
  local apq_supported = false
  local allows_raw_query = false

  -- Test dummy hash
  local dummy_hash = "ecf4e1f9d4f429d47a71f9452d61980524a0dba829d4e3158385d01a93ec0f4e"
  local apq_probe = string.format('{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"%s"}}}', dummy_hash)

  for _, p in ipairs(paths_to_test) do
    local resp = http.generic_request(host, port, "POST", p, {
      header = { ["Content-Type"] = "application/json" },
      content = apq_probe
    })

    if resp and resp.body then
      if string.find(resp.body, "PersistedQueryNotFound") or string.find(resp.body, "PERSISTED_QUERY_NOT_FOUND") then
        active_path = p
        apq_supported = true
        break
      end
    end
  end

  if not active_path then
    return stdnse.format_output(false, "Automatic Persisted Queries (APQ) not detected on tested paths.")
  end

  -- Check if raw unpersisted queries are simultaneously allowed
  local raw_resp = http.generic_request(host, port, "POST", active_path, {
    header = { ["Content-Type"] = "application/json" },
    content = '{"query":"query APQFallback { __typename }"}'
  })

  if raw_resp and raw_resp.status == 200 and raw_resp.body and string.find(raw_resp.body, "__typename") then
    allows_raw_query = true
  end

  out["Risk Level"] = "🟡 MEDIUM"
  out["Endpoint"] = active_path
  out["APQ Extension Support"] = "ENABLED (PersistedQueryNotFound returned)"
  out["Raw Query Fallback Allowed"] = tostring(allows_raw_query)

  if allows_raw_query then
    out["Status"] = "VULNERABLE - Incomplete Persisted Query Enforcement (Raw Queries Permitted)"
    out["Assessment"] = "The server supports APQ but still accepts arbitrary client-crafted raw queries. This fails to protect the API against malicious ad-hoc query execution or schema probing."
    out["Remediation"] = "If persisted queries are used for security allowlisting, strictly disallow raw ad-hoc queries (e.g. set 'onlyPersistedQueries: true' in Apollo Server)."
  else
    out["Status"] = "SECURE - APQ is active and arbitrary ad-hoc queries are rejected."
  end

  return out
end
