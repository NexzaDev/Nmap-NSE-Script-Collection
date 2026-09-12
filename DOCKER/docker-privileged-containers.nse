local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"

description = [[
Audits containers on an accessible Docker REST API to identify instances
running with dangerous execution privileges, including:
1. Privileged mode (HostConfig.Privileged: true)
2. High-risk Linux capabilities (CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_NET_ADMIN,
   CAP_SYS_RAWIO, CAP_SYS_MODULE, ALL)
3. Disabled Seccomp or AppArmor containment profiles (unconfined)
4. Direct host device mappings (/dev/kmem, /dev/mem, /dev/sda)

These misconfigurations allow full container escape (breakout) directly to
root privileges on the host operating system.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(
  {2375, 2376, 4243},
  {"docker", "docker-s", "http", "https"},
  "tcp"
)

local DANGEROUS_CAPS = {
  ["SYS_ADMIN"] = "Allows mounting filesystems, cgroups manipulation, and direct container breakout",
  ["CAP_SYS_ADMIN"] = "Allows mounting filesystems, cgroups manipulation, and direct container breakout",
  ["SYS_PTRACE"] = "Allows process tracing and code injection into host processes",
  ["CAP_SYS_PTRACE"] = "Allows process tracing and code injection into host processes",
  ["SYS_RAWIO"] = "Allows raw I/O operations and direct disk access",
  ["CAP_SYS_RAWIO"] = "Allows raw I/O operations and direct disk access",
  ["SYS_MODULE"] = "Allows loading arbitrary kernel modules into host kernel",
  ["CAP_SYS_MODULE"] = "Allows loading arbitrary kernel modules into host kernel",
  ["NET_ADMIN"] = "Allows modifying host network routes, iptables, and interface configurations",
  ["CAP_NET_ADMIN"] = "Allows modifying host network routes, iptables, and interface configurations",
  ["DAC_READ_SEARCH"] = "Allows bypassing file read permission checks across the entire host",
  ["CAP_DAC_READ_SEARCH"] = "Allows bypassing file read permission checks across the entire host",
  ["ALL"] = "Grants all Linux root capabilities to container processes"
}

action = function(host, port)
  local out = stdnse.output_table()
  local max_containers = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".max_containers")) or 30

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

  out["Risk Level"] = "🔴 CRITICAL"
  out["Total Containers Evaluated"] = #containers

  local vulnerable_containers = stdnse.output_table()
  local vuln_count = 0

  for _, c in ipairs(containers) do
    local c_resp = http.get(host, port, "/containers/" .. c.id .. "/json")
    if c_resp and c_resp.status == 200 and c_resp.body then
      local body = c_resp.body
      local issues = {}

      -- Check Privileged flag
      local is_privileged = string.match(body, '"Privileged"%s*:%s*true')
      if is_privileged then
        table.insert(issues, "🔴 CRITICAL: Privileged mode is ENABLED (HostConfig.Privileged: true)")
      end

      -- Check CapAdd
      local cap_add_sec = string.match(body, '"CapAdd"%s*:%s*%[([^%]]+)%]')
      if cap_add_sec then
        for cap in string.gmatch(cap_add_sec, '"([^"]+)"') do
          local upper_cap = string.upper(cap)
          if DANGEROUS_CAPS[upper_cap] then
            table.insert(issues, string.format("🔴 CAPABILITY: %s (%s)", upper_cap, DANGEROUS_CAPS[upper_cap]))
          end
        end
      end

      -- Check SecurityOpt (AppArmor / Seccomp unconfined)
      local sec_opt_sec = string.match(body, '"SecurityOpt"%s*:%s*%[([^%]]+)%]')
      if sec_opt_sec then
        if string.find(sec_opt_sec, "apparmor=unconfined") then
          table.insert(issues, "🟠 CONFINEMENT: AppArmor profile disabled (unconfined)")
        end
        if string.find(sec_opt_sec, "seccomp=unconfined") then
          table.insert(issues, "🟠 CONFINEMENT: Seccomp syscall filtering disabled (unconfined)")
        end
      end

      -- Check Devices
      local devices_sec = string.match(body, '"Devices"%s*:%s*%[(.-)%]')
      if devices_sec and (string.find(devices_sec, "/dev/mem") or string.find(devices_sec, "/dev/kmem") or string.find(devices_sec, "/dev/sd") or string.find(devices_sec, "/dev/nvme")) then
        table.insert(issues, "🔴 DEVICE: Raw host disk/memory device mapped into container")
      end

      if #issues > 0 then
        vuln_count = vuln_count + 1
        vulnerable_containers[string.format("%s (ID: %s)", c.name, string.sub(c.id, 1, 12))] = issues
      end
    end
  end

  if vuln_count > 0 then
    out["Status"] = string.format("VULNERABLE - %d container(s) running with excessive privileges or dangerous capabilities", vuln_count)
    out["Over-Privileged Containers"] = vulnerable_containers
    out["Remediation"] = "Disable privileged mode (run without --privileged). Drop unnecessary Linux capabilities (--cap-drop ALL, add only required). Enforce default Seccomp and AppArmor profiles."
  else
    out["Status"] = "SECURE - None of the evaluated containers run with privileged mode or flagged dangerous capabilities."
  end

  return out
end
