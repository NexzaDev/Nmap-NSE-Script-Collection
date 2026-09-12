local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"

description = [[
Inspects storage mounts and host filesystem binds across containers on an
accessible Docker REST API. Flags dangerous host path exposures, including:
1. Docker daemon socket mounts (/var/run/docker.sock, /run/docker.sock)
2. Host root filesystem mounts (/)
3. Sensitive host OS directories (/etc, /root, /home, /var/log, /proc, /sys)
4. Read-Write (RW) permissions on sensitive paths

Mounting the Docker socket or host root directory into a container allows
an attacker inside the container to completely compromise the underlying host.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "discovery", "safe"}

portrule = shortport.port_or_service(
  {2375, 2376, 4243},
  {"docker", "docker-s", "http", "https"},
  "tcp"
)

local SENSITIVE_HOST_PATHS = {
  ["/var/run/docker.sock"] = { risk = "🔴 CRITICAL", desc = "Docker socket mount allows full host takeover via daemon control" },
  ["/run/docker.sock"]     = { risk = "🔴 CRITICAL", desc = "Docker socket mount allows full host takeover via daemon control" },
  ["/"]                    = { risk = "🔴 CRITICAL", desc = "Root filesystem mount grants access to entire host OS" },
  ["/etc"]                 = { risk = "🔴 CRITICAL", desc = "Host /etc mount exposes shadow passwords and system configurations" },
  ["/etc/shadow"]          = { risk = "🔴 CRITICAL", desc = "Host /etc/shadow mount exposes encrypted user credentials" },
  ["/root"]                = { risk = "🟠 HIGH",     desc = "Host /root directory mount exposes root SSH keys and shell history" },
  ["/home"]                = { risk = "🟠 HIGH",     desc = "Host /home directory mount exposes user SSH keys and documents" },
  ["/proc"]                = { risk = "🟠 HIGH",     desc = "Host /proc mount allows process injection and kernel memory inspection" },
  ["/sys"]                 = { risk = "🟠 HIGH",     desc = "Host /sys mount allows modifying kernel parameters and hardware state" },
  ["/var/log"]             = { risk = "🟡 MEDIUM",   desc = "Host /var/log mount allows tampering with system audit trails" },
  ["/boot"]                = { risk = "🟠 HIGH",     desc = "Host /boot mount allows bootloader and kernel tampering" }
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

  local container_findings = stdnse.output_table()
  local risky_containers_count = 0

  for _, c in ipairs(containers) do
    local c_resp = http.get(host, port, "/containers/" .. c.id .. "/json")
    if c_resp and c_resp.status == 200 and c_resp.body then
      local body = c_resp.body
      local mounts = {}

      -- Check Mounts array
      for src, dst, rw in string.gmatch(body, '"Source"%s*:%s*"([^"]+)".-"Destination"%s*:%s*"([^"]+)".-"RW"%s*:%s*([%w]+)') do
        local is_rw = (rw == "true")
        local mode_str = is_rw and "Read-Write (RW)" or "Read-Only (RO)"

        -- Exact or prefix match against sensitive paths
        for path_prefix, info in pairs(SENSITIVE_HOST_PATHS) do
          if src == path_prefix or (path_prefix ~= "/" and string.sub(src, 1, #path_prefix) == path_prefix) then
            local finding = string.format("%s [%s] Host '%s' -> Container '%s' (%s)", info.risk, mode_str, src, dst, info.desc)
            table.insert(mounts, finding)
            break
          end
        end
      end

      -- Check Binds array fallback
      local binds_sec = string.match(body, '"Binds"%s*:%s*%[([^%]]+)%]')
      if binds_sec and #mounts == 0 then
        for bind in string.gmatch(binds_sec, '"([^"]+)"') do
          local src, dst, mode = string.match(bind, "^([^:]+):([^:]+):?(.*)$")
          if src then
            for path_prefix, info in pairs(SENSITIVE_HOST_PATHS) do
              if src == path_prefix or (path_prefix ~= "/" and string.sub(src, 1, #path_prefix) == path_prefix) then
                local finding = string.format("%s [%s] Host '%s' -> Container '%s' (%s)", info.risk, mode or "default", src, dst, info.desc)
                table.insert(mounts, finding)
                break
              end
            end
          end
        end
      end

      if #mounts > 0 then
        risky_containers_count = risky_containers_count + 1
        container_findings[string.format("%s (ID: %s)", c.name, string.sub(c.id, 1, 12))] = mounts
      end
    end
  end

  if risky_containers_count > 0 then
    out["Status"] = string.format("VULNERABLE - %d container(s) mount critical host filesystem paths or Docker socket", risky_containers_count)
    out["Dangerous Mounts"] = container_findings
    out["Remediation"] = "Remove sensitive host binds. Never mount /var/run/docker.sock into untrusted containers. Use named Docker volumes or read-only tmpfs mounts instead of direct host root mounts."
  else
    out["Status"] = "SECURE - None of the evaluated containers mount sensitive host directories or Docker daemon sockets."
  end

  return out
end
