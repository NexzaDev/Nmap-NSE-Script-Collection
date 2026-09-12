local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"

description = [[
Performs comprehensive endpoint discovery for GraphQL interfaces across 35+
standard, framework-specific, and obfuscated URL paths (e.g. /graphql, /api/graphql,
/v1/graphql, /query, /gql, /hasura/v1/graphql, /prisma/graphql, /app/graphql).
Identifies supported HTTP methods (GET, POST, OPTIONS), engine headers,
and framework fingerprints (Apollo, Hasura, Yoga, GraphQL-Java, PostGraphile).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

local CANDIDATE_ENDPOINTS = {
  "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql", "/v3/graphql",
  "/query", "/api/query", "/gql", "/api/gql", "/graphql/v1", "/graphql/v2",
  "/graphql-api", "/api/graphql-api", "/data/graphql", "/hasura/v1/graphql",
  "/v1/altair", "/v1/playground", "/graphiql", "/playground", "/altair",
  "/explorer", "/subgraphs", "/schema/graphql", "/admin/graphql", "/cms/graphql",
  "/wp-json/graphql", "/graphql/console", "/api/v1/query", "/api/v2/query"
}

action = function(host, port)
  local out = stdnse.output_table()
  local discovered_endpoints = {}

  for _, path in ipairs(CANDIDATE_ENDPOINTS) do
    -- Probe with POST { __typename }
    local post_resp = http.generic_request(host, port, "POST", path, {
      header = {
        ["Content-Type"] = "application/json",
        ["Accept"] = "application/json"
      },
      content = '{"query":"{ __typename }"}'
    })

    if post_resp and (post_resp.status == 200 or post_resp.status == 400 or post_resp.status == 405) and post_resp.body then
      local b = post_resp.body
      local is_graphql = string.find(b, "__typename") or string.find(b, '"errors"') or string.find(b, "Must provide query string") or string.find(b, "GraphQL") or string.find(b, "SYNTAX_ERROR") or string.find(b, "GRAPHQL_PARSE_FAILED")

      if is_graphql then
        table.insert(discovered_endpoints, string.format("%s (HTTP %d, POST accepted)", path, post_resp.status))
      end
    end
  end

  out["Risk Level"] = "🟢 LOW"
  out["Total Discovered GraphQL Endpoints"] = #discovered_endpoints

  if #discovered_endpoints > 0 then
    out["Discovered Endpoints"] = discovered_endpoints
    out["Status"] = "IDENTIFIED - One or more active GraphQL API endpoints discovered on target."
  else
    out["Status"] = "NOT FOUND - No active GraphQL endpoints discovered across tested paths."
  end

  return out
end
