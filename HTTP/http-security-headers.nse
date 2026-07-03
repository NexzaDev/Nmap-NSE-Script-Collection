local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
Audits HTTP response security headers across multiple common paths.
Checks for presence of Strict-Transport-Security, Content-Security-Policy,
X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
Permissions-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy,
Cross-Origin-Resource-Policy and X-XSS-Protection, and evaluates the
quality of the values present (weak HSTS max-age, CSP allowing
unsafe-inline/unsafe-eval or wildcard sources, permissive X-Frame-Options,
etc.), not just their presence.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.http

local TEST_PATHS = {
  "/", "/login", "/signin", "/account", "/dashboard", "/admin",
  "/api", "/api/v1", "/home", "/index.html", "/app", "/portal",
  "/settings", "/profile", "/search", "/user", "/checkout",
}

local MIN_HSTS_MAX_AGE = 15768000

local function evaluate_hsts(value)
  local issues = {}
  local lval = string.lower(value)
  local age = tonumber(string.match(lval, "max%-age=(%d+)"))
  if not age then
    table.insert(issues, "missing max-age directive")
  elseif age < MIN_HSTS_MAX_AGE then
    table.insert(issues, string.format("max-age=%d is below recommended minimum of %d (6 months)", age, MIN_HSTS_MAX_AGE))
  end
  if not string.find(lval, "includesubdomains") then
    table.insert(issues, "missing includeSubDomains directive")
  end
  if not string.find(lval, "preload") then
    table.insert(issues, "missing preload directive (optional, but recommended for full protection)")
  end
  return issues
end

local function evaluate_csp(value)
  local issues = {}
  local lval = string.lower(value)
  if string.find(lval, "unsafe%-inline") then
    table.insert(issues, "allows 'unsafe-inline' (mitigates XSS protection)")
  end
  if string.find(lval, "unsafe%-eval") then
    table.insert(issues, "allows 'unsafe-eval' (mitigates XSS protection)")
  end
  if string.find(lval, "default%-src%s+%*") or string.find(lval, "script%-src%s+%*") then
    table.insert(issues, "uses wildcard '*' source (overly permissive)")
  end
  if not string.find(lval, "object%-src") and not string.find(lval, "default%-src") then
    table.insert(issues, "no object-src or default-src restriction (Flash/plugin injection risk)")
  end
  if not string.find(lval, "frame%-ancestors") then
    table.insert(issues, "no frame-ancestors directive (clickjacking not covered by CSP)")
  end
  return issues
end

local function evaluate_xfo(value)
  local issues = {}
  local lval = string.lower(value)
  if not (string.find(lval, "deny") or string.find(lval, "sameorigin")) then
    table.insert(issues, "value '" .. value .. "' is neither DENY nor SAMEORIGIN")
  end
  return issues
end

local function evaluate_xcto(value)
  local issues = {}
  if string.lower(value) ~= "nosniff" then
    table.insert(issues, "value '" .. value .. "' is not 'nosniff'")
  end
  return issues
end

local function evaluate_referrer_policy(value)
  local issues = {}
  local lval = string.lower(value)
  local weak = { "unsafe%-url", "no%-referrer%-when%-downgrade" }
  for _, w in ipairs(weak) do
    if string.find(lval, w) then
      table.insert(issues, "policy '" .. value .. "' leaks referrer data across origins/protocols")
    end
  end
  return issues
end

local function evaluate_permissions_policy(value)
  local issues = {}
  if value == "" then
    table.insert(issues, "header present but empty")
  end
  return issues
end

local CHECKS = {
  { header = "strict-transport-security", label = "Strict-Transport-Security", evaluator = evaluate_hsts },
  { header = "content-security-policy", label = "Content-Security-Policy", evaluator = evaluate_csp },
  { header = "x-frame-options", label = "X-Frame-Options", evaluator = evaluate_xfo },
  { header = "x-content-type-options", label = "X-Content-Type-Options", evaluator = evaluate_xcto },
  { header = "referrer-policy", label = "Referrer-Policy", evaluator = evaluate_referrer_policy },
  { header = "permissions-policy", label = "Permissions-Policy", evaluator = evaluate_permissions_policy },
  { header = "cross-origin-opener-policy", label = "Cross-Origin-Opener-Policy", evaluator = nil },
  { header = "cross-origin-embedder-policy", label = "Cross-Origin-Embedder-Policy", evaluator = nil },
  { header = "cross-origin-resource-policy", label = "Cross-Origin-Resource-Policy", evaluator = nil },
  { header = "x-xss-protection", label = "X-XSS-Protection", evaluator = nil },
}

action = function(host, port)
  local out = stdnse.output_table()
  local missing_union = {}
  local present_union = {}
  local weak_findings = {}
  local checked_paths = 0
  local seen_missing = {}
  local seen_weak = {}

  for _, path in ipairs(TEST_PATHS) do
    local ok, response = pcall(http.get, host, port, path)
    if ok and response and response.header and response.status and response.status < 500 then
      checked_paths = checked_paths + 1
      for _, check in ipairs(CHECKS) do
        local value = response.header[check.header]
        if value then
          if not present_union[check.label] then
            present_union[check.label] = value
          end
          if check.evaluator then
            local issues = check.evaluator(value)
            for _, issue in ipairs(issues) do
              local key = check.label .. "::" .. issue
              if not seen_weak[key] then
                seen_weak[key] = true
                table.insert(weak_findings, string.format("%s (seen at %s): %s", check.label, path, issue))
              end
            end
          end
        else
          local key = check.label .. "::" .. path
          if not seen_missing[check.label] then
            seen_missing[check.label] = {}
          end
        end
      end
    end
  end

  for _, check in ipairs(CHECKS) do
    if not present_union[check.label] then
      table.insert(missing_union, check.label)
    end
  end

  out["Paths checked"] = tostring(checked_paths)

  if #missing_union > 0 then
    out["Headers missing on all checked paths"] = missing_union
  else
    out["Headers missing on all checked paths"] = "All checked headers were present on at least one path."
  end

  local present_list = {}
  for label, value in pairs(present_union) do
    table.insert(present_list, label .. ": " .. value)
  end
  table.sort(present_list)
  if #present_list > 0 then
    out["Headers present (first observed value)"] = present_list
  end

  if #weak_findings > 0 then
    out["Weak or incomplete configurations"] = weak_findings
  else
    out["Weak or incomplete configurations"] = "No weak configurations detected among present headers."
  end

  return out
end
