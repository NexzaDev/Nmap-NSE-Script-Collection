local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
Requests a set of paths that typically return authenticated, personal
or otherwise sensitive content and inspects Cache-Control, Pragma,
Expires, ETag and Vary headers to flag responses that are cacheable
by shared/intermediate caches despite likely containing sensitive
data.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.http

local SENSITIVE_PATHS = {
  "/account", "/accounts", "/profile", "/dashboard", "/settings",
  "/preferences", "/orders", "/order", "/invoice", "/invoices",
  "/billing", "/payment", "/payments", "/cart", "/checkout",
  "/messages", "/message", "/inbox", "/notifications", "/api/user",
  "/api/users/me", "/api/account", "/api/profile", "/api/session",
  "/api/orders", "/api/payments", "/api/cart", "/my-account",
  "/user/details", "/user/info", "/admin/dashboard", "/admin/users",
  "/wallet", "/statements", "/statement", "/history", "/transactions",
}

local WEAK_CACHE_PATTERNS = {
  "public",
}

local function has_header(headers, name)
  return headers and headers[name]
end

local function evaluate_caching(headers)
  local issues = {}
  local cc = headers["cache-control"]
  local pragma = headers["pragma"]
  local expires = headers["expires"]
  local vary = headers["vary"]

  if not cc then
    table.insert(issues, "no Cache-Control header present")
  else
    local lcc = string.lower(cc)
    if string.find(lcc, "public") then
      table.insert(issues, "Cache-Control includes 'public' (shared-cache storable)")
    end
    if not string.find(lcc, "no%-store") then
      table.insert(issues, "Cache-Control missing 'no-store'")
    end
    if not string.find(lcc, "no%-cache") and not string.find(lcc, "private") then
      table.insert(issues, "Cache-Control missing 'no-cache'/'private' directive")
    end
    if string.find(lcc, "max%-age=(%d+)") then
      local age = tonumber(string.match(lcc, "max%-age=(%d+)"))
      if age and age > 0 then
        table.insert(issues, string.format("positive max-age=%d allows caching for %d seconds", age, age))
      end
    end
  end

  if not pragma then
  elseif string.lower(pragma) ~= "no-cache" then
    table.insert(issues, "Pragma header present but not set to 'no-cache'")
  end

  if expires then
    local lexp = string.lower(expires)
    if lexp ~= "0" and not string.find(lexp, "1970") then
      table.insert(issues, "Expires header sets a future/absolute expiry: " .. expires)
    end
  end

  if not vary or not string.find(string.lower(vary), "cookie") then
    table.insert(issues, "Vary header does not include 'Cookie' (risk of cross-user cache poisoning if cached)")
  end

  return issues
end

action = function(host, port)
  local out = stdnse.output_table()
  local flagged = {}
  local clean = {}
  local not_found = {}
  local tested = 0

  for _, path in ipairs(SENSITIVE_PATHS) do
    tested = tested + 1
    local ok, response = pcall(http.get, host, port, path)
    if ok and response and response.status then
      if response.status >= 400 then
        table.insert(not_found, path .. " -> HTTP " .. tostring(response.status))
      else
        local headers = response.header or {}
        local issues = evaluate_caching(headers)
        if #issues > 0 then
          table.insert(flagged, string.format(
            "%s (HTTP %s) -> %s", path, tostring(response.status), table.concat(issues, "; ")
          ))
        else
          table.insert(clean, string.format("%s (HTTP %s) -> caching directives look adequate", path, tostring(response.status)))
        end
      end
    end
  end

  out["Sensitive paths tested"] = tostring(tested)
  out["Paths not reachable (4xx/5xx)"] = tostring(#not_found)

  if #flagged > 0 then
    out["Weak caching controls detected"] = flagged
  else
    out["Weak caching controls detected"] = "No caching issues found on reachable sensitive paths."
  end

  if #clean > 0 then
    out["Paths with adequate caching directives"] = clean
  end

  return out
end
