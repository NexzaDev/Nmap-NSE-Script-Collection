local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"

description = [[
Audits GraphQL custom schema directives (__schema { directives { ... } })
to detect exposed internal authorization policies, role definitions, and
sensitive annotations (@auth, @hasRole, @admin, @rateLimit, @internal, @deprecated).
Directives reveal the server's internal authorization architecture, roles hierarchy,
and hidden permission flags.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "discovery", "safe"}

portrule = shortport.http

local CANDIDATE_PATHS = {
  "/graphql", "/api/graphql", "/v1/graphql", "/query", "/api/query", "/gql"
}

local DIRECTIVES_QUERY = '{"query":"query DirectivesAudit { __schema { directives { name description locations args { name type { name } } } } }"}'

-- Default built-in standard GraphQL specification directives
local STANDARD_DIRECTIVES = {
  ["include"] = true,
  ["skip"] = true,
  ["deprecated"] = true,
  ["specifiedBy"] = true,
  ["oneOf"] = true
}

action = function(host, port)
  local out = stdnse.output_table()
  local custom_path = stdnse.get_script_args(SCRIPT_NAME .. ".path")
  local paths_to_test = custom_path and { custom_path } or CANDIDATE_PATHS

  local active_path = nil
  local custom_directives = {}
  local auth_directives = {}

  for _, p in ipairs(paths_to_test) do
    local resp = http.generic_request(host, port, "POST", p, {
      header = {
        ["Content-Type"] = "application/json",
        ["Accept"] = "application/json"
      },
      content = DIRECTIVES_QUERY
    })

    if resp and resp.status == 200 and resp.body and string.find(resp.body, "directives") then
      active_path = p
      for dname in string.gmatch(resp.body, '"name"%s*:%s*"([^"]+)"') do
        if not STANDARD_DIRECTIVES[dname] and not string.match(dname, "^__") then
          table.insert(custom_directives, dname)
          local upper = string.upper(dname)
          if string.find(upper, "AUTH") or string.find(upper, "ROLE") or string.find(upper, "PERM") or string.find(upper, "ADMIN") or string.find(upper, "GUARD") then
            table.insert(auth_directives, dname)
          end
        end
      end
      break
    end
  end

  if not active_path then
    return stdnse.format_output(false, "No accessible GraphQL directives schema found on tested paths.")
  end

  out["Risk Level"] = "🟡 MEDIUM"
  out["Endpoint"] = active_path
  out["Total Custom Directives Discovered"] = #custom_directives

  if #custom_directives > 0 then
    out["Custom Directives"] = custom_directives
  end

  if #auth_directives > 0 then
    out["Security & RBAC Directives"] = auth_directives
    out["Status"] = "VULNERABLE - Internal Access Control & Authorization Directives Exposed"
    out["Assessment"] = "The schema exposes custom authorization directives (@" .. table.concat(auth_directives, ", @") .. ") revealing internal access control mechanisms to unauthenticated clients."
    out["Remediation"] = "Filter out internal security directives from public schemas or disable introspection in production environments."
  else
    out["Status"] = "AUDITED - Standard or generic custom directives discovered."
  end

  return out
end
