local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
Tests for Cross-Site Tracing (XST) exposure by sending TRACE and TRACK
requests with a distinctive marker header across multiple paths, then
checking whether the response body/headers echo the request back
verbatim. Also checks whether the OPTIONS Allow header advertises
TRACE/TRACK even if the direct probe is blocked by a front-end proxy.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.http

local TEST_PATHS = {
  "/", "/index.html", "/api", "/login", "/admin", "/test",
  "/console", "/status", "/health", "/app", "/service",
}

local MARKER_HEADER = "X-XST-Probe-Marker"
local MARKER_VALUE = "nse-xst-check-9f31c2"

local function probe_trace(host, port, path, method)
  local options = {
    header = { [MARKER_HEADER] = MARKER_VALUE }
  }
  local ok, response = pcall(http.generic_request, host, port, method, path, options)
  if not ok or not response then
    return nil
  end
  return response
end

local function response_echoes_marker(response)
  if not response then return false end
  if response.body and string.find(response.body, MARKER_VALUE, 1, true) then
    return true
  end
  if response.rawheader then
    for _, line in ipairs(response.rawheader) do
      if string.find(line, MARKER_VALUE, 1, true) then
        return true
      end
    end
  end
  return false
end

action = function(host, port)
  local out = stdnse.output_table()
  local vulnerable_paths = {}
  local advertised_only = {}
  local blocked_paths = {}

  for _, path in ipairs(TEST_PATHS) do
    local trace_resp = probe_trace(host, port, path, "TRACE")
    local track_resp = probe_trace(host, port, path, "TRACK")

    local trace_echo = response_echoes_marker(trace_resp)
    local track_echo = response_echoes_marker(track_resp)

    if trace_echo or track_echo then
      local which = {}
      if trace_echo then table.insert(which, "TRACE") end
      if track_echo then table.insert(which, "TRACK") end
      table.insert(vulnerable_paths, string.format(
        "%s -> request marker reflected via %s (XST likely exploitable)",
        path, table.concat(which, "/")
      ))
    else
      local allow_resp = http.generic_request(host, port, "OPTIONS", path)
      if allow_resp and allow_resp.header and allow_resp.header["allow"] then
        local allow = string.lower(allow_resp.header["allow"])
        if string.find(allow, "trace") or string.find(allow, "track") then
          table.insert(advertised_only, string.format(
            "%s -> TRACE/TRACK advertised in Allow header but not reflecting marker (possibly filtered upstream)",
            path
          ))
        end
      end

      if trace_resp and trace_resp.status and trace_resp.status >= 400 and trace_resp.status < 500 then
        table.insert(blocked_paths, string.format(
          "%s -> TRACE returned HTTP %s (likely blocked)", path, tostring(trace_resp.status)
        ))
      end
    end
  end

  if #vulnerable_paths > 0 then
    out["XST-vulnerable paths (marker reflected)"] = vulnerable_paths
  else
    out["XST-vulnerable paths (marker reflected)"] = "No path reflected the TRACE/TRACK probe marker."
  end

  if #advertised_only > 0 then
    out["TRACE/TRACK advertised but not confirmed"] = advertised_only
  end

  if #blocked_paths > 0 then
    out["Paths where TRACE appears blocked"] = blocked_paths
  end

  return out
end
