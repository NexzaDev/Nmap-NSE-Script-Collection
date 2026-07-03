local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
Fetches /robots.txt and /sitemap.xml, extracts Disallow entries and
sitemap URLs, flags entries whose paths match sensitive keyword
patterns (admin, backup, config, internal, etc.), and follows up by
requesting each flagged path to report its live HTTP status.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.http

local SENSITIVE_KEYWORDS = {
  "admin", "administrator", "backup", "bak", "config", "conf",
  "internal", "private", "secret", "staging", "dev", "test",
  "debug", "console", "manage", "management", "panel", "cpanel",
  "credentials", "secrets", "key", "keys", "token", "tokens",
  "db", "database", "sql", "dump", "export", "import", "log",
  "logs", "old", "temp", "tmp", "cache", "install", "setup",
  "phpmyadmin", "adminer", "shell", "cgi-bin", "api-docs", "swagger",
}

local function is_sensitive(path)
  local lpath = string.lower(path)
  for _, kw in ipairs(SENSITIVE_KEYWORDS) do
    if string.find(lpath, kw, 1, true) then
      return true, kw
    end
  end
  return false, nil
end

local function parse_robots(body)
  local disallow_entries = {}
  local allow_entries = {}
  local sitemap_refs = {}
  if not body then return disallow_entries, allow_entries, sitemap_refs end

  for line in string.gmatch(body, "[^\r\n]+") do
    local trimmed = string.gsub(line, "^%s+", "")
    trimmed = string.gsub(trimmed, "%s+$", "")
    local dpath = string.match(trimmed, "^[Dd]isallow:%s*(.+)$")
    local apath = string.match(trimmed, "^[Aa]llow:%s*(.+)$")
    local smap = string.match(trimmed, "^[Ss]itemap:%s*(.+)$")
    if dpath and dpath ~= "" then
      table.insert(disallow_entries, dpath)
    end
    if apath and apath ~= "" then
      table.insert(allow_entries, apath)
    end
    if smap and smap ~= "" then
      table.insert(sitemap_refs, smap)
    end
  end

  return disallow_entries, allow_entries, sitemap_refs
end

local function parse_sitemap_urls(body)
  local urls = {}
  if not body then return urls end
  for url in string.gmatch(body, "<loc>%s*([^<%s]+)%s*</loc>") do
    table.insert(urls, url)
  end
  return urls
end

local function extract_path_from_url(url)
  local path = string.match(url, "^https?://[^/]+(/.*)$")
  return path or url
end

action = function(host, port)
  local out = stdnse.output_table()

  local robots_resp = http.get(host, port, "/robots.txt")
  local sitemap_resp = http.get(host, port, "/sitemap.xml")

  if not robots_resp or not robots_resp.status or robots_resp.status >= 400 then
    out["robots.txt"] = "Not found or inaccessible."
  else
    local disallow, allow, sitemap_refs = parse_robots(robots_resp.body)

    out["Disallow entries found"] = tostring(#disallow)
    out["Allow entries found"] = tostring(#allow)

    local flagged = {}
    local verified = {}
    for _, dpath in ipairs(disallow) do
      local sensitive, kw = is_sensitive(dpath)
      if sensitive then
        table.insert(flagged, dpath .. " (matched keyword: " .. kw .. ")")
        local check_ok, check_resp = pcall(http.get, host, port, dpath)
        if check_ok and check_resp and check_resp.status then
          table.insert(verified, string.format("%s -> HTTP %s", dpath, tostring(check_resp.status)))
        end
      end
    end

    if #flagged > 0 then
      out["Sensitive-looking Disallow paths"] = flagged
      out["Live status of sensitive paths"] = verified
    else
      out["Sensitive-looking Disallow paths"] = "None of the disallowed paths matched sensitive keywords."
    end

    if #sitemap_refs > 0 then
      out["Sitemap references inside robots.txt"] = sitemap_refs
    end
  end

  if not sitemap_resp or not sitemap_resp.status or sitemap_resp.status >= 400 then
    out["sitemap.xml"] = "Not found or inaccessible."
  else
    local urls = parse_sitemap_urls(sitemap_resp.body)
    out["URLs found in sitemap.xml"] = tostring(#urls)

    local flagged_urls = {}
    for _, url in ipairs(urls) do
      local path = extract_path_from_url(url)
      local sensitive, kw = is_sensitive(path)
      if sensitive then
        table.insert(flagged_urls, url .. " (matched keyword: " .. kw .. ")")
      end
    end

    if #flagged_urls > 0 then
      out["Sensitive-looking sitemap URLs"] = flagged_urls
    else
      out["Sensitive-looking sitemap URLs"] = "None of the sitemap URLs matched sensitive keywords."
    end
  end

  return out
end
