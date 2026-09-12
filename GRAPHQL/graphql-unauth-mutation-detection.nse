local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"

description = [[
Discovers exposed mutating root operations (Mutation schema type) on a
GraphQL endpoint and evaluates whether state-altering operations (such as user
creation, password reset, configuration updates, or deletions) are exposed
without requiring an Authorization header or authentication cookie.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "discovery", "safe"}

portrule = shortport.http

local CANDIDATE_PATHS = {
  "/graphql", "/api/graphql", "/v1/graphql", "/query", "/api/query", "/gql"
}

local MUTATION_INTROSPECTION = '{"query":"query MutationProbe { __schema { mutationType { fields { name description args { name type { name kind } } } } } }"}'

local SENSITIVE_MUTATION_PATTERNS = {
  "CREATE", "UPDATE", "DELETE", "REMOVE", "DROP", "INSERT",
  "RESET", "PASSWORD", "REGISTER", "ADMIN", "ROLE", "GRANT",
  "TOKEN", "TRANSFER", "PAYMENT", "ORDER", "EXEC", "CONFIG"
}

local function is_sensitive_mutation(name)
  local upper = string.upper(name)
  for _, pat in ipairs(SENSITIVE_MUTATION_PATTERNS) do
    if string.find(upper, pat, 1, true) then
      return true
    end
  end
  return false
end

action = function(host, port)
  local out = stdnse.output_table()
  local custom_path = stdnse.get_script_args(SCRIPT_NAME .. ".path")
  local paths_to_test = custom_path and { custom_path } or CANDIDATE_PATHS

  local active_path = nil
  local mutations_found = {}
  local sensitive_mutations = {}

  for _, p in ipairs(paths_to_test) do
    local resp = http.generic_request(host, port, "POST", p, {
      header = {
        ["Content-Type"] = "application/json",
        ["Accept"] = "application/json"
      },
      content = MUTATION_INTROSPECTION
    })

    if resp and resp.status == 200 and resp.body and string.find(resp.body, "mutationType") then
      active_path = p
      for m_name in string.gmatch(resp.body, '"name"%s*:%s*"([^"]+)"') do
        if m_name ~= "mutationType" and m_name ~= "Mutation" and m_name ~= "fields" and not string.match(m_name, "^__") then
          table.insert(mutations_found, m_name)
          if is_sensitive_mutation(m_name) then
            table.insert(sensitive_mutations, m_name)
          end
        end
      end
      break
    end
  end

  if not active_path then
    return stdnse.format_output(false, "No accessible GraphQL mutation schema discovered on tested paths.")
  end

  out["Risk Level"] = "🔴 CRITICAL"
  out["Endpoint"] = active_path
  out["Total Exposed Mutations Discovered"] = #mutations_found
  out["Sensitive High-Risk Mutations"] = #sensitive_mutations

  if #sensitive_mutations > 0 then
    local sample = {}
    for i = 1, math.min(#sensitive_mutations, 15) do
      table.insert(sample, sensitive_mutations[i])
    end
    out["Sample High-Impact Operations"] = sample
    out["Status"] = "VULNERABLE - Unauthenticated Access to GraphQL Mutation Schema"
    out["Assessment"] = "The endpoint allows unauthenticated clients to inspect and invoke state-altering GraphQL mutations. Ensure all mutating resolvers enforce strict session token or JWT validation."
    out["Remediation"] = "Implement field-level and resolver-level authorization middleware (e.g. GraphQL Shield, declarative @auth directives, or context-based user verification) before resolving mutation logic."
  else
    out["Status"] = "AUDITED - Mutations discovered, but none matched high-risk administrative patterns."
  end

  return out
end
