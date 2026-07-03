local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
Audits Set-Cookie headers returned across a set of common application paths
and evaluates each cookie against Secure, HttpOnly, SameSite, Domain, Path
and expiry attributes. Flags cookies whose names match session/auth/token
patterns but lack the corresponding protective attributes.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.http

local TEST_PATHS = {
  "/", "/login", "/signin", "/account", "/accounts", "/user", "/users",
  "/profile", "/dashboard", "/admin", "/administrator", "/panel",
  "/api", "/api/v1", "/api/v2", "/auth", "/authenticate", "/session",
  "/sessions", "/oauth", "/oauth2", "/sso", "/portal", "/home",
  "/cart", "/checkout", "/settings", "/preferences", "/logout",
  "/register", "/signup", "/reset", "/password", "/forgot-password",
  "/verify", "/confirm", "/2fa", "/mfa", "/token", "/refresh",
}

local SENSITIVE_KEYWORDS = {
  "sess", "session", "sid", "auth", "token", "jwt", "bearer", "csrf",
  "xsrf", "remember", "rememberme", "login", "user", "uid", "account",
  "credential", "secret", "key", "access", "refresh", "identity",
  "sso", "saml", "oauth", "ticket", "grant", "verify", "otp", "2fa",
  "phpsessid", "jsessionid", "aspsessionid", "connect.sid", "laravel_session",
}

local function is_sensitive_name(name)
  local lname = string.lower(name)
  for _, kw in ipairs(SENSITIVE_KEYWORDS) do
    if string.find(lname, kw, 1, true) then
      return true
    end
  end
  return false
end

local function parse_cookie_attrs(raw)
  local attrs = {}
  local parts = stdnse.strsplit(";%s*", raw)
  if #parts == 0 then return attrs end
  local first = parts[1]
  local eq = string.find(first, "=")
  if eq then
    attrs.name = string.sub(first, 1, eq - 1)
    attrs.value = string.sub(first, eq + 1)
  else
    attrs.name = first
    attrs.value = ""
  end
  attrs.secure = false
  attrs.httponly = false
  attrs.samesite = nil
  attrs.domain = nil
  attrs.path = nil
  attrs.expires = nil
  attrs.maxage = nil
  for i = 2, #parts do
    local p = parts[i]
    local lp = string.lower(p)
    if lp == "secure" then
      attrs.secure = true
    elseif lp == "httponly" then
      attrs.httponly = true
    elseif string.find(lp, "^samesite=") then
      attrs.samesite = string.sub(p, 10)
    elseif string.find(lp, "^domain=") then
      attrs.domain = string.sub(p, 8)
    elseif string.find(lp, "^path=") then
      attrs.path = string.sub(p, 6)
    elseif string.find(lp, "^expires=") then
      attrs.expires = string.sub(p, 9)
    elseif string.find(lp, "^max%-age=") then
      attrs.maxage = string.sub(p, 9)
    end
  end
  return attrs
end

local function evaluate_cookie(attrs)
  local issues = {}
  local sensitive = is_sensitive_name(attrs.name)

  if not attrs.secure then
    table.insert(issues, "missing Secure flag")
  end
  if not attrs.httponly then
    table.insert(issues, "missing HttpOnly flag")
  end
  if not attrs.samesite then
    table.insert(issues, "missing SameSite attribute")
  elseif string.lower(attrs.samesite) == "none" and not attrs.secure then
    table.insert(issues, "SameSite=None without Secure flag")
  end
  if attrs.domain and string.find(attrs.domain, "^%.") then
    table.insert(issues, "broad Domain scope (" .. attrs.domain .. ")")
  end
  if (attrs.expires or attrs.maxage) and sensitive then
    table.insert(issues, "persistent expiry set on sensitive cookie")
  end

  return sensitive, issues
end

local function collect_cookies_for_path(host, port, path, seen, results)
  local response = http.get(host, port, path)
  if not response then return end
  local headers = response.rawheader
  if not headers then return end
  for _, line in ipairs(headers) do
    if string.find(string.lower(line), "^set%-cookie:") then
      local raw = string.gsub(line, "^[Ss][Ee][Tt]%-[Cc][Oo][Oo][Kk][Ii][Ee]:%s*", "")
      local attrs = parse_cookie_attrs(raw)
      if attrs.name and not seen[attrs.name] then
        seen[attrs.name] = true
        local sensitive, issues = evaluate_cookie(attrs)
        table.insert(results, {
          name = attrs.name,
          path_seen = path,
          sensitive = sensitive,
          secure = attrs.secure,
          httponly = attrs.httponly,
          samesite = attrs.samesite or "none-set",
          domain = attrs.domain or "default",
          issues = issues,
        })
      end
    end
  end
end

action = function(host, port)
  local seen = {}
  local results = {}

  for _, path in ipairs(TEST_PATHS) do
    collect_cookies_for_path(host, port, path, seen, results)
  end

  if #results == 0 then
    return "No Set-Cookie headers observed across tested paths."
  end

  local out = stdnse.output_table()
  local flagged = {}
  local clean = {}

  for _, c in ipairs(results) do
    local line
    if #c.issues > 0 then
      line = string.format(
        "%s (seen at %s, sensitive=%s) -> %s",
        c.name, c.path_seen, tostring(c.sensitive), table.concat(c.issues, "; ")
      )
      table.insert(flagged, line)
    else
      line = string.format(
        "%s (seen at %s) -> Secure=%s HttpOnly=%s SameSite=%s Domain=%s",
        c.name, c.path_seen, tostring(c.secure), tostring(c.httponly), c.samesite, c.domain
      )
      table.insert(clean, line)
    end
  end

  if #flagged > 0 then
    out["Flagged cookies"] = flagged
  end
  if #clean > 0 then
    out["Cookies with adequate flags"] = clean
  end

  out["Total cookies inspected"] = tostring(#results)

  return out
end
