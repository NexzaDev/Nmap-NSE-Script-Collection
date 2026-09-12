local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"

description = [[
Evaluates whether a GraphQL server parses and executes GraphQL queries sent
with non-standard HTTP Content-Type headers (text/plain, application/x-www-form-urlencoded,
or missing Content-Type).
If a server accepts GraphQL requests with 'text/plain', browsers will NOT issue a
CORS preflight (OPTIONS) request, allowing malicious cross-origin websites to execute
arbitrary authenticated GraphQL operations from victims' browsers (Cross-Site GraphQL Execution).
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

  -- Test 1: text/plain
  local resp_plain = http.generic_request(host, port, "POST", active_path, {
    header = { ["Content-Type"] = "text/plain" },
    content = '{"query":"query PlainTest { __typename }"}'
  })
  local accepts_plain = resp_plain and resp_plain.status == 200 and resp_plain.body and string.find(resp_plain.body, "__typename") ~= nil

  -- Test 2: urlencoded
  local resp_url = http.generic_request(host, port, "POST", active_path, {
    header = { ["Content-Type"] = "application/x-www-form-urlencoded" },
    content = "query=%7B__typename%7D"
  })
  local accepts_url = resp_url and resp_url.status == 200 and resp_url.body and string.find(resp_url.body, "__typename") ~= nil

  -- Test 3: missing content-type
  local resp_none = http.generic_request(host, port, "POST", active_path, {
    content = '{"query":"query NoneTest { __typename }"}'
  })
  local accepts_none = resp_none and resp_none.status == 200 and resp_none.body and string.find(resp_none.body, "__typename") ~= nil

  local findings = stdnse.output_table()
  findings["text/plain (CORS Preflight Bypass)"] = accepts_plain and "🔴 ACCEPTED (Vulnerable to Cross-Origin Simple Request CSRF)" or "BLOCKED / REJECTED"
  findings["application/x-www-form-urlencoded"] = accepts_url and "🔴 ACCEPTED (HTML Form Submission Attack Vector)" or "BLOCKED / REJECTED"
  findings["Missing Content-Type header"] = accepts_none and "🔴 ACCEPTED" or "BLOCKED / REJECTED"

  out["Content-Type Acceptance Matrix"] = findings

  if accepts_plain or accepts_url or accepts_none then
    out["Status"] = "VULNERABLE - Permissive Content-Type Parsing Enables Cross-Origin Bypass"
    out["Assessment"] = "The server executes GraphQL requests that do not declare 'application/json' or 'application/graphql+json'. Attackers can trigger cross-origin state modifications from user browsers without triggering CORS preflights."
    out["Remediation"] = "Strictly reject any POST request that does not supply 'Content-Type: application/json' (or application/graphql+json) with HTTP 415 Unsupported Media Type."
  else
    out["Status"] = "SECURE - Server strictly enforces 'application/json' Content-Type."
  end

  return out
end
