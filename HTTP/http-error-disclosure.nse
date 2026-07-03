local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
Sends a set of malformed and non-existent requests designed to trigger
default framework/server error pages, then scans the response bodies
against a large set of language/framework-specific signatures (PHP,
Java stack traces, ASP.NET, Python tracebacks, Ruby, Node.js, SQL
errors) to detect verbose information disclosure.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.http

local TRIGGER_PATHS = {
  "/this-path-should-not-exist-9f31c2",
  "/..%2f..%2f..%2fetc%2fpasswd",
  "/%00",
  "/'",
  "/\"",
  "/<script>alert(1)</script>",
  "/api/../../etc/passwd",
  "/index.php?id=" .. string.rep("A", 500),
  "/index.php?id=1'",
  "/search?q=" .. string.rep("%27", 5),
  "/redirect?url=javascript:alert(1)",
  "/upload/../../../windows/win.ini",
  "/console/../../../../etc/shadow",
  "/wp-content/uploads/../../wp-config.php",
  "/?debug=true",
  "/?test=1&debug=1&verbose=1",
  "/api/v1/9999999999999999999999",
  "/api/user/-1",
  "/api/user/0",
  "/file?name=../../../../etc/passwd",
}

local ERROR_SIGNATURES = {
  { pattern = "fatal error", label = "PHP Fatal Error" },
  { pattern = "warning:%s*include", label = "PHP include() warning" },
  { pattern = "warning:%s*require", label = "PHP require() warning" },
  { pattern = "undefined index", label = "PHP undefined index notice" },
  { pattern = "undefined variable", label = "PHP undefined variable notice" },
  { pattern = "stack trace", label = "Generic stack trace" },
  { pattern = "java%.lang%.", label = "Java exception (java.lang.*)" },
  { pattern = "java%.sql%.", label = "Java SQL exception" },
  { pattern = "javax%.servlet", label = "Java Servlet exception" },
  { pattern = "org%.springframework", label = "Spring Framework exception" },
  { pattern = "org%.hibernate", label = "Hibernate ORM exception" },
  { pattern = "system%.web%.httpexception", label = "ASP.NET HttpException" },
  { pattern = "microsoft%.aspnet", label = "ASP.NET Core exception" },
  { pattern = "at system%.", label = "ASP.NET .NET stack frame" },
  { pattern = "traceback %(most recent call last%)", label = "Python traceback" },
  { pattern = "django%.core", label = "Django framework exception" },
  { pattern = "flask%.app", label = "Flask framework exception" },
  { pattern = "werkzeug%.exceptions", label = "Werkzeug exception" },
  { pattern = "actionview::template", label = "Ruby on Rails ActionView exception" },
  { pattern = "activerecord::", label = "Ruby on Rails ActiveRecord exception" },
  { pattern = "nomethoderror", label = "Ruby NoMethodError" },
  { pattern = "at node:", label = "Node.js internal stack frame" },
  { pattern = "unhandledpromiserejection", label = "Node.js unhandled promise rejection" },
  { pattern = "you have an error in your sql syntax", label = "MySQL syntax error disclosure" },
  { pattern = "mysqli?_", label = "MySQL/mysqli function name disclosure" },
  { pattern = "pg_query%(%)", label = "PostgreSQL query function disclosure" },
  { pattern = "ora%-%d%d%d%d%d", label = "Oracle database error code" },
  { pattern = "sqlstate%[", label = "PDO SQLSTATE error disclosure" },
  { pattern = "unclosed quotation mark", label = "MSSQL syntax error disclosure" },
  { pattern = "microsoft ole db provider", label = "MSSQL OLE DB provider error" },
  { pattern = "warning: mysql", label = "MySQL warning disclosure" },
  { pattern = "on line %d+", label = "Source line number disclosure" },
  { pattern = "/var/www/", label = "Server filesystem path disclosure (/var/www/)" },
  { pattern = "c:\\inetpub", label = "Server filesystem path disclosure (C:\\inetpub)" },
  { pattern = "c:\\\\users\\\\", label = "Server filesystem path disclosure (C:\\Users\\)" },
  { pattern = "root:.*:0:0:", label = "Possible /etc/passwd content disclosure" },
}

local function scan_body(body)
  local hits = {}
  if not body then return hits end
  local lbody = string.lower(body)
  for _, sig in ipairs(ERROR_SIGNATURES) do
    if string.find(lbody, sig.pattern) then
      table.insert(hits, sig.label)
    end
  end
  return hits
end

action = function(host, port)
  local out = stdnse.output_table()
  local findings = {}
  local tested = 0

  for _, path in ipairs(TRIGGER_PATHS) do
    tested = tested + 1
    local ok, response = pcall(http.get, host, port, path)
    if ok and response and response.body then
      local hits = scan_body(response.body)
      if #hits > 0 then
        table.insert(findings, string.format(
          "%s (HTTP %s) -> %s",
          path, tostring(response.status), table.concat(hits, ", ")
        ))
      end
    end
  end

  out["Trigger requests sent"] = tostring(tested)

  if #findings > 0 then
    out["Information disclosure signatures matched"] = findings
  else
    out["Information disclosure signatures matched"] = "No known error/disclosure signatures detected."
  end

  return out
end
