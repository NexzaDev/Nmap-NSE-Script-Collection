local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Detects unauthenticated access to the Docker Engine REST API (typically
exposed on TCP ports 2375 or 2376). When the API is accessible without
client TLS certificates or bearer authentication, the script queries the
system information endpoints (/version, /info, /_ping), extracts daemon
metadata (engine version, OS, kernel, storage driver, container counts,
security options), and alerts on the critical security risk: unauthenticated
access to the Docker daemon grants complete root-level control over the host.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "auth", "safe"}

portrule = shortport.port_or_service(
  {2375, 2376, 4243, 4244},
  {"docker", "docker-s", "http", "https"},
  "tcp"
)

-- Helper function to safely extract JSON string values with simple regex
local function extract_json_string(body, key)
  local pattern = '"' .. key .. '"%s*:%s*"([^"]+)"'
  return string.match(body, pattern)
end

-- Helper function to safely extract JSON numeric/boolean values
local function extract_json_value(body, key)
  local pattern = '"' .. key .. '"%s*:%s*([%w%d%._%-]+)'
  return string.match(body, pattern)
end

-- Helper function to extract array items
local function extract_json_array_strings(body, key)
  local pattern = '"' .. key .. '"%s*:%s*%[([^%]]+)%]'
  local raw = string.match(body, pattern)
  if not raw then return {} end
  local items = {}
  for item in string.gmatch(raw, '"([^"]+)"') do
    table.insert(items, item)
  end
  return items
end

action = function(host, port)
  local out = stdnse.output_table()
  local custom_path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or ""

  -- Step 1: Probe /_ping endpoint
  local ping_path = custom_path .. "/_ping"
  local ping_resp = http.get(host, port, ping_path)
  if not ping_resp or not ping_resp.status then
    return stdnse.format_output(false, "Could not reach Docker API endpoint on " .. port.number)
  end

  local is_docker_ping = (ping_resp.status == 200 and string.match(ping_resp.body or "", "^OK"))

  -- Step 2: Probe /version endpoint
  local version_path = custom_path .. "/version"
  local version_resp = http.get(host, port, version_path)
  if not version_resp or not version_resp.status then
    return stdnse.format_output(false, "Failed to query Docker /version endpoint.")
  end

  local is_docker_version = (version_resp.status == 200 and
    (string.find(version_resp.body or "", "ApiVersion") ~= nil or
     string.find(version_resp.body or "", "Docker") ~= nil or
     string.find(version_resp.body or "", "Engine") ~= nil))

  if not is_docker_ping and not is_docker_version then
    return stdnse.format_output(false, "Target does not appear to be an accessible unauthenticated Docker daemon.")
  end

  -- Record unauthenticated status
  out["Status"] = "VULNERABLE - Unauthenticated Docker Daemon API Exposed"
  out["Risk Level"] = "🔴 CRITICAL"
  out["CVSS Score"] = "9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"

  -- Parse /version response
  local v_body = version_resp.body or ""
  local engine_version = extract_json_string(v_body, "Version")
  local api_version = extract_json_string(v_body, "ApiVersion")
  local min_api_version = extract_json_string(v_body, "MinAPIVersion")
  local git_commit = extract_json_string(v_body, "GitCommit")
  local go_version = extract_json_string(v_body, "GoVersion")
  local os_type = extract_json_string(v_body, "Os")
  local arch = extract_json_string(v_body, "Arch")
  local kernel_ver = extract_json_string(v_body, "KernelVersion")

  local version_info = stdnse.output_table()
  if engine_version then version_info["Docker Engine Version"] = engine_version end
  if api_version then version_info["Docker API Version"] = api_version end
  if min_api_version then version_info["Min API Version"] = min_api_version end
  if git_commit then version_info["Git Commit"] = git_commit end
  if go_version then version_info["Go Runtime Version"] = go_version end
  if os_type then version_info["Operating System"] = os_type end
  if arch then version_info["Architecture"] = arch end
  if kernel_ver then version_info["Kernel Version"] = kernel_ver end
  out["Daemon Details"] = version_info

  -- Step 3: Probe /info endpoint
  local info_path = custom_path .. "/info"
  local info_resp = http.get(host, port, info_path)
  if info_resp and info_resp.status == 200 and info_resp.body then
    local i_body = info_resp.body
    local sys_info = stdnse.output_table()

    local containers_total = extract_json_value(i_body, "Containers")
    local containers_running = extract_json_value(i_body, "ContainersRunning")
    local containers_paused = extract_json_value(i_body, "ContainersPaused")
    local containers_stopped = extract_json_value(i_body, "ContainersStopped")
    local images_count = extract_json_value(i_body, "Images")
    local driver = extract_json_string(i_body, "Driver")
    local root_dir = extract_json_string(i_body, "DockerRootDir")
    local server_version = extract_json_string(i_body, "ServerVersion")
    local os_version = extract_json_string(i_body, "OperatingSystem")
    local cpus = extract_json_value(i_body, "NCPU")
    local total_mem = extract_json_value(i_body, "MemTotal")
    local sec_opts = extract_json_array_strings(i_body, "SecurityOptions")

    if containers_total then sys_info["Total Containers"] = containers_total end
    if containers_running then sys_info["Running Containers"] = containers_running end
    if containers_paused then sys_info["Paused Containers"] = containers_paused end
    if containers_stopped then sys_info["Stopped Containers"] = containers_stopped end
    if images_count then sys_info["Stored Images"] = images_count end
    if driver then sys_info["Storage Driver"] = driver end
    if root_dir then sys_info["Docker Root Directory"] = root_dir end
    if server_version then sys_info["Server Version"] = server_version end
    if os_version then sys_info["OS Distribution"] = os_version end
    if cpus then sys_info["CPU Cores"] = cpus end
    if total_mem then
      local mem_mb = tonumber(total_mem) and math.floor(tonumber(total_mem) / (1024 * 1024)) or total_mem
      sys_info["Total Memory (MB)"] = tostring(mem_mb)
    end
    if #sec_opts > 0 then
      sys_info["Security Options"] = table.concat(sec_opts, ", ")
    end

    out["Host & Cluster Metrics"] = sys_info
  end

  -- Step 4: Add Remediation Guidance
  local remediation = stdnse.output_table()
  remediation["1. TLS Authentication"] = "Enable mutual TLS (mTLS) with --tlsverify, --tlscacert, --tlscert, and --tlskey."
  remediation["2. Network Binding"] = "Never bind TCP port 2375/2376 to 0.0.0.0. Bind to unix:///var/run/docker.sock or 127.0.0.1 behind an authenticated proxy."
  remediation["3. Firewall"] = "Restrict ingress access to the Docker API port with host and network firewalls."
  out["Remediation"] = remediation

  return out
end
