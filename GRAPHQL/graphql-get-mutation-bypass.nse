local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"

description = [[
Evaluates whether a GraphQL server permits executing GraphQL mutations over
HTTP GET requests (e.g. GET /graphql?query=mutation+Probe{__typename}).
According to GraphQL over HTTP specifications, mutations MUST NOT be executed
via GET requests because GET requests are idempotent and lack CSRF token
requirements in web browsers. Allowing mutations via GET exposes the API to
Cross-Site Request Forgery (CSRF) via simple <img>, <script>, or <a> tags.
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
  local get_mutation_allowed = false
  local status_code = nil

  for _, p in ipairs(paths_to_test) do
    local test_url = string.format("%s?query=mutation%%20GetMutationCheck%%7B__typename%%7D", p)
    local resp = http.get(host, port, test_url)

    if resp and resp.status then
      if resp.status == 200 and resp.body and (string.find(resp.body, '"data"') or string.find(resp.body, "__typename")) then
        active_path = p
        get_mutation_allowed = true
        status_code = resp.status
        break
      elseif resp.status == 405 or resp.status == 400 then
        if resp.body and (string.find(resp.body, "GET") or string.find(resp.body, "mutation")) then
          active_path = p
          status_code = resp.status
          break
        end
      end
    end
  end

  if not active_path then
    return stdnse.format_output(false, "No active GraphQL endpoint detected on tested paths.")
  end

  out["Risk Level"] = "🟠 HIGH"
  out["Endpoint"] = active_path

  if get_mutation_allowed then
    out["Status"] = "VULNERABLE - GraphQL Mutations Accepted via HTTP GET"
    out["Assessment"] = "The GraphQL engine successfully processed a 'mutation' operation submitted over HTTP GET. This completely breaks CSRF defenses and violates HTTP protocol semantics."
    out["Remediation"] = "Enforce that only 'query' operations are accepted over HTTP GET, and strictly require HTTP POST with 'Content-Type: application/json' for all 'mutation' and 'subscription' operations."
  else
    out["Status"] = string.format("SECURE - Server rejected mutation via HTTP GET (Status: %s)", tostring(status_code or "Rejected"))
  end

  return out
end
