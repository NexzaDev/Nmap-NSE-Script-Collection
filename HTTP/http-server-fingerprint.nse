local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
Fingerprints the underlying web server and application stack by
inspecting Server, X-Powered-By, X-AspNet-Version, X-AspNetMvc-Version,
X-Generator, X-Drupal-Cache, X-Varnish and Via headers, and by probing
a set of technology-specific marker paths (phpinfo, wp-login, actuator
endpoints, server-status, etc.) to corroborate the header-based guess.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.http

local HEADER_FIELDS = {
  "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
  "x-generator", "x-drupal-cache", "x-drupal-dynamic-cache", "x-varnish",
  "via", "x-runtime", "x-version", "x-request-id", "x-served-by",
  "x-cache", "x-turbo-charged-by", "x-sourcemap",
}

local TECH_SIGNATURES = {
  { pattern = "apache", label = "Apache HTTP Server" },
  { pattern = "nginx", label = "nginx" },
  { pattern = "microsoft%-iis", label = "Microsoft IIS" },
  { pattern = "litespeed", label = "LiteSpeed" },
  { pattern = "openresty", label = "OpenResty" },
  { pattern = "cloudflare", label = "Cloudflare" },
  { pattern = "gunicorn", label = "Gunicorn (Python)" },
  { pattern = "werkzeug", label = "Werkzeug (Flask dev server)" },
  { pattern = "express", label = "Express (Node.js)" },
  { pattern = "kestrel", label = "Kestrel (ASP.NET Core)" },
  { pattern = "tomcat", label = "Apache Tomcat" },
  { pattern = "jetty", label = "Eclipse Jetty" },
  { pattern = "php", label = "PHP" },
  { pattern = "asp%.net", label = "ASP.NET" },
  { pattern = "jboss", label = "JBoss/WildFly" },
  { pattern = "wildfly", label = "WildFly" },
  { pattern = "glassfish", label = "GlassFish" },
  { pattern = "weblogic", label = "Oracle WebLogic" },
  { pattern = "websphere", label = "IBM WebSphere" },
  { pattern = "varnish", label = "Varnish Cache" },
  { pattern = "squid", label = "Squid Proxy" },
  { pattern = "phusion passenger", label = "Phusion Passenger (Ruby)" },
  { pattern = "puma", label = "Puma (Ruby)" },
  { pattern = "unicorn", label = "Unicorn (Ruby)" },
  { pattern = "drupal", label = "Drupal" },
  { pattern = "wordpress", label = "WordPress" },
}

local MARKER_PATHS = {
  { path = "/phpinfo.php", label = "PHP phpinfo() exposure" },
  { path = "/info.php", label = "PHP info exposure" },
  { path = "/wp-login.php", label = "WordPress login endpoint" },
  { path = "/wp-admin/", label = "WordPress admin panel" },
  { path = "/wp-json/", label = "WordPress REST API" },
  { path = "/xmlrpc.php", label = "WordPress XML-RPC endpoint" },
  { path = "/administrator/", label = "Joomla administrator panel" },
  { path = "/sites/default/", label = "Drupal default site path" },
  { path = "/CHANGELOG.txt", label = "Drupal changelog disclosure" },
  { path = "/actuator/health", label = "Spring Boot Actuator health endpoint" },
  { path = "/actuator/env", label = "Spring Boot Actuator env endpoint" },
  { path = "/server-status", label = "Apache mod_status page" },
  { path = "/server-info", label = "Apache mod_info page" },
  { path = "/nginx_status", label = "nginx stub_status page" },
  { path = "/.well-known/security.txt", label = "security.txt policy file" },
  { path = "/web.config", label = "IIS/ASP.NET web.config exposure" },
  { path = "/elmah.axd", label = "ELMAH error log (ASP.NET) exposure" },
  { path = "/trace.axd", label = "ASP.NET trace.axd exposure" },
  { path = "/console", label = "Application/debug console exposure" },
  { path = "/swagger-ui.html", label = "Swagger UI exposure" },
  { path = "/swagger.json", label = "Swagger/OpenAPI definition exposure" },
  { path = "/api-docs", label = "API documentation exposure" },
  { path = "/.git/HEAD", label = "Exposed .git repository" },
  { path = "/.env", label = "Exposed .env configuration file" },
  { path = "/composer.json", label = "PHP Composer manifest exposure" },
  { path = "/package.json", label = "Node.js package manifest exposure" },
}

local function match_signature(value)
  local lval = string.lower(value)
  local matches = {}
  for _, sig in ipairs(TECH_SIGNATURES) do
    if string.find(lval, sig.pattern) then
      table.insert(matches, sig.label)
    end
  end
  return matches
end

action = function(host, port)
  local out = stdnse.output_table()
  local response = http.get(host, port, "/")

  local header_findings = {}
  local tech_matches = {}

  if response and response.header then
    for _, field in ipairs(HEADER_FIELDS) do
      local value = response.header[field]
      if value then
        table.insert(header_findings, field .. ": " .. value)
        local matches = match_signature(value)
        for _, m in ipairs(matches) do
          tech_matches[m] = true
        end
      end
    end
  end

  if #header_findings > 0 then
    out["Fingerprinting headers observed"] = header_findings
  else
    out["Fingerprinting headers observed"] = "No fingerprinting headers present in response."
  end

  local tech_list = {}
  for t in pairs(tech_matches) do
    table.insert(tech_list, t)
  end
  table.sort(tech_list)
  if #tech_list > 0 then
    out["Identified technologies (from headers)"] = tech_list
  end

  local marker_hits = {}
  for _, marker in ipairs(MARKER_PATHS) do
    local mresp = http.get(host, port, marker.path)
    if mresp and mresp.status and mresp.status < 400 then
      table.insert(marker_hits, string.format(
        "%s -> HTTP %s (%s)", marker.path, tostring(mresp.status), marker.label
      ))
    end
  end

  if #marker_hits > 0 then
    out["Technology marker paths reachable"] = marker_hits
  else
    out["Technology marker paths reachable"] = "None of the known marker paths were reachable."
  end

  return out
end
