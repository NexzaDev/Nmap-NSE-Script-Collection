local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"

description = [[
Tests whether a GraphQL endpoint leaks schema fields via didactic field
suggestions (e.g. "Cannot query field 'passwrd' on type 'Query'. Did you mean 'password'?").
Even when schema introspection (__schema) is disabled, enabled field suggestions
allow automated wordlist-based tools (such as Clairvoyance) to reverse-engineer
and reconstruct the entire private GraphQL schema.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "discovery", "safe"}

portrule = shortport.http

local CANDIDATE_PATHS = {
  "/graphql", "/api/graphql", "/v1/graphql", "/query", "/api/query", "/gql"
}

-- Typo queries to trigger field suggestion engine
local PROBE_QUERIES = {
  { query = '{"query":"query { usrs { id } }"}', probe = "usrs" },
  { query = '{"query":"query { accont { id } }"}', probe = "accont" },
  { query = '{"query":"query { passwrd }"}', probe = "passwrd" },
  { query = '{"query":"query { auth_tkn }"}', probe = "auth_tkn" }
}

action = function(host, port)
  local out = stdnse.output_table()
  local custom_path = stdnse.get_script_args(SCRIPT_NAME .. ".path")
  local paths_to_test = custom_path and { custom_path } or CANDIDATE_PATHS

  local suggestions_found = {}
  local active_path = nil

  for _, p in ipairs(paths_to_test) do
    for _, probe in ipairs(PROBE_QUERIES) do
      local resp = http.generic_request(host, port, "POST", p, {
        header = { ["Content-Type"] = "application/json" },
        content = probe.query
      })

      if resp and resp.status and resp.body then
        local suggestion = string.match(resp.body, "Did you mean ([^%?%\n]+)%?")
        if suggestion then
          active_path = p
          table.insert(suggestions_found, string.format("Probe '%s' triggered suggestion: %s", probe.probe, suggestion))
        end
      end
    end
    if active_path then break end
  end

  out["Risk Level"] = "🟡 MEDIUM"

  if #suggestions_found > 0 then
    out["Status"] = "VULNERABLE - GraphQL Field Suggestions Leakage Detected"
    out["Endpoint"] = active_path
    out["Observed Suggestions"] = suggestions_found
    out["Assessment"] = "The server leaks valid schema field names in error messages despite introspection restrictions. Attackers can brute-force the schema using dictionary tools."
    out["Remediation"] = "Disable field suggestions in production (e.g. use @escape.tech/graphql-armor-block-field-suggestions or formatError to sanitize 'Did you mean' messages)."
  else
    out["Status"] = "SECURE - Field suggestions are disabled or no GraphQL endpoint detected on standard paths."
  end

  return out
end
