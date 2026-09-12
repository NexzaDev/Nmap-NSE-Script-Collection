local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"

description = [[
Audits Docker containers on an accessible REST API for missing cgroup
resource limits. Identifies containers with:
1. No memory limits (Memory: 0) — allows runaway processes to trigger host Out-Of-Memory kernel panics.
2. No CPU limits (CpuShares: 0, NanoCpus: 0) — allows 100% host CPU starvation.
3. No process limits (PidsLimit: 0 or -1) — leaves the host vulnerable to fork-bomb attacks.
4. OOM killer disabled (OomKillDisable: true) — prevents kernel mitigation during memory crises.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(
  {2375, 2376, 4243},
  {"docker", "docker-s", "http", "https"},
  "tcp"
)

action = function(host, port)
  local out = stdnse.output_table()
  local max_containers = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".max_containers")) or 25

  local resp = http.get(host, port, "/containers/json?all=1")
  if not resp or resp.status ~= 200 or not resp.body then
    return stdnse.format_output(false, "Could not retrieve container list from Docker API.")
  end

  local containers = {}
  for id, names in string.gmatch(resp.body, '"Id"%s*:%s*"([a-f0-9]+)".-"Names"%s*:%s*%[([^%]]+)%]') do
    local first_name = string.match(names, '"/([^"]+)"') or string.match(names, '"([^"]+)"') or id
    table.insert(containers, { id = id, name = first_name })
    if #containers >= max_containers then break end
  end

  if #containers == 0 then
    for id in string.gmatch(resp.body, '"Id"%s*:%s*"([a-f0-9]+)"') do
      table.insert(containers, { id = id, name = string.sub(id, 1, 12) })
      if #containers >= max_containers then break end
    end
  end

  if #containers == 0 then
    out["Summary"] = "No containers found on target Docker daemon."
    return out
  end

  out["Risk Level"] = "🟡 MEDIUM"
  out["Total Containers Evaluated"] = #containers

  local unconstrained = stdnse.output_table()
  local unconstrained_count = 0

  for _, c in ipairs(containers) do
    local c_resp = http.get(host, port, "/containers/" .. c.id .. "/json")
    if c_resp and c_resp.status == 200 and c_resp.body then
      local body = c_resp.body
      local missing_limits = {}

      local mem = tonumber(string.match(body, '"Memory"%s*:%s*(%d+)')) or 0
      local pids = tonumber(string.match(body, '"PidsLimit"%s*:%s*([%-%d]+)')) or 0
      local cpu = tonumber(string.match(body, '"NanoCpus"%s*:%s*(%d+)')) or 0
      local shares = tonumber(string.match(body, '"CpuShares"%s*:%s*(%d+)')) or 0
      local oom_disabled = string.match(body, '"OomKillDisable"%s*:%s*true') ~= nil

      if mem == 0 then
        table.insert(missing_limits, "No Memory Limit (Memory: 0 MB)")
      end
      if pids <= 0 then
        table.insert(missing_limits, "No Process Limit (PidsLimit: unbounded - vulnerable to fork-bomb)")
      end
      if cpu == 0 and shares == 0 then
        table.insert(missing_limits, "No CPU Ceiling (CpuShares: 0, NanoCpus: 0)")
      end
      if oom_disabled then
        table.insert(missing_limits, "OOM Killer Disabled (OomKillDisable: true - high kernel crash risk)")
      end

      if #missing_limits > 0 then
        unconstrained_count = unconstrained_count + 1
        unconstrained[string.format("%s (ID: %s)", c.name, string.sub(c.id, 1, 10))] = missing_limits
      end
    end
  end

  if unconstrained_count > 0 then
    out["Status"] = string.format("VULNERABLE - %d container(s) lack critical cgroup resource constraints", unconstrained_count)
    out["Unconstrained Containers"] = unconstrained
    out["Remediation"] = "Enforce memory limits (--memory), CPU limits (--cpus), and PID limits (--pids-limit 100-1000) for all containers in production."
  else
    out["Status"] = "SECURE - All evaluated containers enforce memory, CPU, and PID limits."
  end

  return out
end
