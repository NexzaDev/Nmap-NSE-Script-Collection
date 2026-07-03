local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
Probes HTTP(S) endpoints with a set of crafted Origin headers to detect
common CORS misconfigurations: reflected arbitrary origins, wildcard
origin combined with credentials, null-origin acceptance, and subdomain
suffix-matching flaws.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.http

local TEST_PATHS = {
  "/", "/api", "/api/v1", "/api/v2", "/api/data", "/api/user",
  "/api/users", "/api/account", "/data", "/graphql", "/rest",
  "/v1", "/v2", "/service", "/services", "/auth", "/login",
}

local function build_origin_tests(host)
  local hostname = host.targetname or host.ip
  return {
    { label = "reflect-arbitrary", origin = "https://evil-attacker-test.example" },
    { label = "reflect-arbitrary-http", origin = "http://evil-attacker-test.example" },
    { label = "null-origin", origin = "null" },
    { label = "subdomain-prefix-trick", origin = "https://" .. tostring(hostname) .. ".evil-attacker-test.example" },
    { label = "subdomain-suffix-trick", origin = "https://evil-attacker-test.example." .. tostring(hostname) },
    { label = "wildcard-probe", origin = "*" },
    { label = "localhost-origin", origin = "http://localhost" },
    { label = "trailing-dot", origin = "https://" .. tostring(hostname) .. "." },
    { label = "case-variant", origin = "https://" .. string.upper(tostring(hostname)) },
  }
end

local function analyze_response(test_label, origin_sent, response)
  local findings = {}
  if not response or not response.header then
    return findings
  end

  local acao = response.header["access-control-allow-origin"]
  local acac = response.header["access-control-allow-credentials"]
  local acam = response.header["access-control-allow-methods"]
  local acah = response.header["access-control-allow-headers"]

  if not acao then
    return findings
  end

  local reflected = (acao == origin_sent)
  local wildcard = (acao == "*")
  local credentials_true = (acac and string.lower(acac) == "true")

  if reflected and origin_sent ~= "*" then
    table.insert(findings, string.format(
      "[%s] server reflected Origin '%s' back verbatim in Access-Control-Allow-Origin",
      test_label, origin_sent
    ))
  end

  if wildcard and credentials_true then
    table.insert(findings, string.format(
      "[%s] wildcard ACAO='*' combined with Access-Control-Allow-Credentials=true (invalid/dangerous combo)",
      test_label
    ))
  end

  if reflected and credentials_true then
    table.insert(findings, string.format(
      "[%s] arbitrary origin reflected AND credentials allowed -> full cross-origin credentialed access",
      test_label
    ))
  end

  if origin_sent == "null" and (acao == "null" or reflected) then
    table.insert(findings, string.format(
      "[%s] null origin explicitly permitted (sandboxed iframe/file:// origin bypass risk)",
      test_label
    ))
  end

  if acam and string.find(string.lower(acam), "*") then
    table.insert(findings, string.format(
      "[%s] Access-Control-Allow-Methods is wildcarded",
      test_label
    ))
  end

  if acah and string.find(string.lower(acah), "*") then
    table.insert(findings, string.format(
      "[%s] Access-Control-Allow-Headers is wildcarded",
      test_label
    ))
  end

  return findings
end

action = function(host, port)
  local origin_tests = build_origin_tests(host)
  local all_findings = {}
  local tested_paths = 0
  local paths_with_cors = 0

  for _, path in ipairs(TEST_PATHS) do
    tested_paths = tested_paths + 1
    local baseline = http.get(host, port, path)
    if baseline and baseline.header and baseline.header["access-control-allow-origin"] then
      paths_with_cors = paths_with_cors + 1
      for _, test in ipairs(origin_tests) do
        local options = {
          header = { ["Origin"] = test.origin }
        }
        local response = http.get(host, port, path, options)
        local findings = analyze_response(test.label, test.origin, response)
        for _, f in ipairs(findings) do
          table.insert(all_findings, path .. " :: " .. f)
        end
      end
    end
  end

  local out = stdnse.output_table()
  out["Paths tested"] = tostring(tested_paths)
  out["Paths returning CORS headers"] = tostring(paths_with_cors)

  if #all_findings > 0 then
    out["Misconfigurations detected"] = all_findings
  else
    out["Result"] = "No CORS misconfiguration patterns detected on tested paths."
  end

  return out
end
