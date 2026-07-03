local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
Checks a broad list of common directory paths for enabled directory
listing (Apache "Index of /", nginx autoindex, or IIS-style listings)
by requesting each path and matching the response body against known
listing-page signatures.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.http

local TEST_DIRS = {
  "/", "/images/", "/img/", "/css/", "/js/", "/scripts/", "/assets/",
  "/static/", "/media/", "/uploads/", "/upload/", "/files/", "/file/",
  "/docs/", "/doc/", "/documents/", "/download/", "/downloads/",
  "/backup/", "/backups/", "/bak/", "/old/", "/tmp/", "/temp/",
  "/logs/", "/log/", "/data/", "/db/", "/database/", "/config/",
  "/conf/", "/admin/", "/administrator/", "/private/", "/protected/",
  "/includes/", "/include/", "/lib/", "/libs/", "/vendor/",
  "/node_modules/", "/test/", "/tests/", "/testing/", "/dev/",
  "/development/", "/staging/", "/archive/", "/archives/", "/export/",
  "/exports/", "/import/", "/imports/", "/reports/", "/report/",
  "/resources/", "/res/", "/public/", "/shared/", "/share/",
  "/wp-content/uploads/", "/wp-content/plugins/", "/cgi-bin/",
}

local LISTING_SIGNATURES = {
  "index of /",
  "<title>index of",
  "directory listing for",
  "parent directory</a>",
  "%[to parent directory%]",
  "<h1>index of",
  "directory: /",
  "folder listing",
}

local function looks_like_listing(body)
  if not body then return false, nil end
  local lbody = string.lower(body)
  for _, sig in ipairs(LISTING_SIGNATURES) do
    if string.find(lbody, sig) then
      return true, sig
    end
  end
  return false, nil
end

local function count_links(body)
  if not body then return 0 end
  local n = 0
  for _ in string.gmatch(body, "<a href") do
    n = n + 1
  end
  return n
end

action = function(host, port)
  local out = stdnse.output_table()
  local exposed = {}
  local tested = 0

  for _, dir in ipairs(TEST_DIRS) do
    tested = tested + 1
    local ok, response = pcall(http.get, host, port, dir)
    if ok and response and response.status and response.status < 400 and response.body then
      local is_listing, sig = looks_like_listing(response.body)
      if is_listing then
        local links = count_links(response.body)
        table.insert(exposed, string.format(
          "%s (HTTP %s) -> matched signature '%s', approx. %d links found",
          dir, tostring(response.status), sig, links
        ))
      end
    end
  end

  out["Directories tested"] = tostring(tested)

  if #exposed > 0 then
    out["Directory listing exposed"] = exposed
  else
    out["Directory listing exposed"] = "No directory listing detected on tested paths."
  end

  return out
end
