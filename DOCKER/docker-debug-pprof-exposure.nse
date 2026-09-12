local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"

description = [[
Probes Docker daemon and container management endpoints for exposed Go runtime
profiling endpoints (/debug/pprof, /debug/vars). These debug interfaces expose:
1. Active Goroutine stack traces and execution states (/debug/pprof/goroutine)
2. Daemon command-line arguments and internal flags (/debug/pprof/cmdline)
3. Heap memory profiles and allocations (/debug/pprof/heap)
4. Expvar runtime statistics and counters (/debug/vars)

Exposed profiling endpoints can leak memory contents and allow CPU exhaustion
attacks by requesting CPU profile generation.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "discovery", "safe"}

portrule = shortport.port_or_service(
  {2375, 2376, 4243, 8080, 80},
  {"docker", "docker-s", "http", "https"},
  "tcp"
)

local DEBUG_ENDPOINTS = {
  { path = "/debug/pprof/", desc = "Pprof Index (profiling menu)" },
  { path = "/debug/pprof/cmdline", desc = "Process command line arguments" },
  { path = "/debug/pprof/goroutine?debug=1", desc = "Goroutine execution stack traces" },
  { path = "/debug/pprof/heap?debug=1", desc = "Memory heap allocation profile" },
  { path = "/debug/vars", desc = "Expvar internal runtime variables" }
}

action = function(host, port)
  local out = stdnse.output_table()
  local custom_path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or ""

  local exposed = {}
  local cmdline_leak = nil

  for _, ep in ipairs(DEBUG_ENDPOINTS) do
    local url = custom_path .. ep.path
    local resp = http.get(host, port, url)
    if resp and resp.status == 200 and resp.body and #resp.body > 0 then
      if ep.path == "/debug/pprof/cmdline" then
        cmdline_leak = string.gsub(resp.body, "%z", " ")
      end
      table.insert(exposed, string.format("%s (HTTP 200) - %s", ep.path, ep.desc))
    end
  end

  out["Risk Level"] = "🟠 HIGH"

  if #exposed > 0 then
    out["Status"] = string.format("VULNERABLE - %d Go debug profiling endpoint(s) exposed to untrusted requests", #exposed)
    out["Exposed Endpoints"] = exposed
    if cmdline_leak and #cmdline_leak > 0 then
      out["Leaked Command Line"] = cmdline_leak
    end
    out["Remediation"] = "Disable debug profiling endpoints in production by removing net/http/pprof import handlers or binding the debug socket to localhost only."
  else
    out["Status"] = "SECURE - No /debug/pprof or /debug/vars endpoints are accessible."
  end

  return out
end
