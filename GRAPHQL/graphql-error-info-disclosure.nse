local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"

description = [[
Probes GraphQL endpoints with malformed syntax, invalid types, and unexpected
arguments to audit the structure of returned error messages. Detects information
leakage including:
1. Database error messages (SQL syntax errors, PostgreSQL, MySQL, SQLite, MongoDB errors)
2. ORM and framework traces (Prisma, Sequelize, TypeORM, Hibernate, Mongoose)
3. Internal server filesystem paths (/var/www, /home/app, C:\inetpub)
4. Unhandled runtime exception stack traces
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "discovery", "safe"}

portrule = shortport.http

local CANDIDATE_PATHS = {
  "/graphql", "/api/graphql", "/v1/graphql", "/query", "/api/query", "/gql"
}

local ERROR_PROBES = {
  { name = "Syntax Error", payload = '{"query":"query { syntax_error_probe((("}' },
  { name = "Invalid Field & Argument", payload = '{"query":"query { user(id: \\"\' OR 1=1--\\") { id } }"}' },
  { name = "Null Type Violation", payload = '{"query":"query { __type(name: null) { name } }"}' }
}

local LEAK_PATTERNS = {
  ["SQL Syntax / Database"] = { "syntax error at or near", "mysql_fetch", "ORA-", "sqlite3.OperationalError", "MongoServerError", "sqlstate" },
  ["ORM / Framework"] = { "PrismaClient", "SequelizeDatabaseError", "TypeORM", "HibernateException", "MongooseError", "ApolloServer" },
  ["Filesystem Path"] = { "/home/", "/var/www/", "/node_modules/", "C:\\\\", "D:\\\\", "/usr/src/app" },
  ["Stack Trace"] = { "at Module._compile", "at Object.<anonymous>", "Traceback (most recent call last)", "at java.lang.Thread.run" }
}

action = function(host, port)
  local out = stdnse.output_table()
  local custom_path = stdnse.get_script_args(SCRIPT_NAME .. ".path")
  local paths_to_test = custom_path and { custom_path } or CANDIDATE_PATHS

  local active_path = nil
  local findings = {}

  for _, p in ipairs(paths_to_test) do
    for _, probe in ipairs(ERROR_PROBES) do
      local resp = http.generic_request(host, port, "POST", p, {
        header = { ["Content-Type"] = "application/json" },
        content = probe.payload
      })

      if resp and resp.body and string.find(resp.body, '"errors"') then
        active_path = p
        local body = resp.body

        for category, patterns in pairs(LEAK_PATTERNS) do
          for _, pat in ipairs(patterns) do
            if string.find(body, pat, 1, true) then
              table.insert(findings, string.format("[%s] Matched pattern '%s' during %s", category, pat, probe.name))
              break
            end
          end
        end
      end
    end
    if active_path then break end
  end

  if not active_path then
    return stdnse.format_output(false, "No active GraphQL error handling endpoint discovered.")
  end

  out["Risk Level"] = "🟡 MEDIUM"
  out["Endpoint"] = active_path

  if #findings > 0 then
    out["Status"] = "VULNERABLE - Sensitive Backend Technology Stack Leaked in Error Responses"
    out["Disclosed Details"] = findings
    out["Assessment"] = "The server returns verbose debugging, stack trace, or database dialect details in GraphQL error payloads."
    out["Remediation"] = "Implement custom error masking in the GraphQL server (e.g. formatError in Apollo Server or custom ErrorHandler) to return generic error messages in production."
  else
    out["Status"] = "SECURE - GraphQL error responses are properly masked without leaking internal paths or stack traces."
  end

  return out
end
