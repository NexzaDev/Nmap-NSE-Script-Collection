local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
Enumerates HTTP methods accepted by a web server across multiple paths.
Sends an OPTIONS request to read the Allow header, then directly probes
a set of potentially risky methods (PUT, DELETE, PATCH, TRACE, TRACK,
CONNECT, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK, SEARCH)
and reports which ones return non-error status codes.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.http

local TEST_PATHS = {
  "/", "/api", "/api/v1", "/upload", "/uploads", "/files", "/file",
  "/webdav", "/dav", "/admin", "/data", "/resource", "/resources",
  "/document", "/documents", "/media", "/assets", "/content",
}

local RISKY_METHODS = {
  "PUT", "DELETE", "PATCH", "TRACE", "TRACK", "CONNECT",
  "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE",
  "LOCK", "UNLOCK", "SEARCH", "REPORT", "CHECKOUT",
}

local RISK_NOTES = {
  PUT = "may allow arbitrary file upload/overwrite",
  DELETE = "may allow arbitrary resource deletion",
  PATCH = "may allow partial resource modification",
  TRACE = "can enable Cross-Site Tracing (XST)",
  TRACK = "IIS variant of TRACE, same XST risk",
  CONNECT = "may allow proxy tunneling abuse",
  PROPFIND = "WebDAV method, can expose directory structure",
  PROPPATCH = "WebDAV method, can modify resource properties",
  MKCOL = "WebDAV method, may allow directory creation",
  COPY = "WebDAV method, may allow resource duplication",
  MOVE = "WebDAV method, may allow resource relocation",
  LOCK = "WebDAV method, may allow resource locking abuse",
  UNLOCK = "WebDAV method, may allow lock removal",
  SEARCH = "WebDAV/IIS method, may expose indexing internals",
  REPORT = "WebDAV/versioning method, may expose metadata",
  CHECKOUT = "versioning method, may allow resource checkout",
}

local function generic_request(host, port, method, path)
  local options = { header = {} }
  local ok, response = pcall(http.generic_request, host, port, method, path, options)
  if ok then
    return response
  end
  return nil
end

local function probe_options(host, port, path)
  local response = http.generic_request(host, port, "OPTIONS", path)
  if response and response.header and response.header["allow"] then
    return response.header["allow"]
  end
  return nil
end

local function probe_method(host, port, path, method)
  local response = generic_request(host, port, method, path)
  if not response then
    return nil
  end
  return response.status
end

local function status_is_interesting(status)
  if not status then return false end
  if status >= 200 and status < 400 then return true end
  if status == 401 or status == 403 then return true end
  return false
end

action = function(host, port)
  local out = stdnse.output_table()
  local per_path_allow = {}
  local risky_findings = {}
  local allow_union = {}

  for _, path in ipairs(TEST_PATHS) do
    local allow_header = probe_options(host, port, path)
    if allow_header then
      per_path_allow[path] = allow_header
      for method in string.gmatch(allow_header, "[%a]+") do
        allow_union[string.upper(method)] = true
      end
    end

    for _, method in ipairs(RISKY_METHODS) do
      local status = probe_method(host, port, path, method)
      if status_is_interesting(status) then
        local note = RISK_NOTES[method] or "non-standard method accepted"
        table.insert(risky_findings, string.format(
          "%s %s -> HTTP %s (%s)", method, path, tostring(status), note
        ))
      end
    end
  end

  local allow_summary = {}
  for path, allow in pairs(per_path_allow) do
    table.insert(allow_summary, path .. ": " .. allow)
  end

  if #allow_summary > 0 then
    out["OPTIONS Allow header by path"] = allow_summary
  else
    out["OPTIONS Allow header by path"] = "No server responded with an Allow header."
  end

  local union_list = {}
  for m in pairs(allow_union) do
    table.insert(union_list, m)
  end
  table.sort(union_list)
  if #union_list > 0 then
    out["Union of advertised methods"] = union_list
  end

  if #risky_findings > 0 then
    out["Risky methods confirmed active"] = risky_findings
  else
    out["Risky methods confirmed active"] = "None of the tested risky methods returned an accepted status."
  end

  return out
end
