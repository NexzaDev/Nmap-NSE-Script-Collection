local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"

description = [[
Evaluates the host-level Docker daemon security options returned by the
/info endpoint. Audits whether hardening features are enabled or missing:
1. AppArmor / SELinux mandatory access control
2. Default Seccomp system call filtering
3. User Namespace remapping (userns-remap / rootless mode)
4. Live restore capabilities (daemon reboot resilience)
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "discovery", "safe"}

portrule = shortport.port_or_service(
  {2375, 2376, 4243},
  {"docker", "docker-s", "http", "https"},
  "tcp"
)

action = function(host, port)
  local out = stdnse.output_table()

  local resp = http.get(host, port, "/info")
  if not resp or resp.status ~= 200 or not resp.body then
    return stdnse.format_output(false, "Could not retrieve /info from Docker API.")
  end

  local body = resp.body
  out["Risk Level"] = "🟡 MEDIUM"

  local sec_options_raw = string.match(body, '"SecurityOptions"%s*:%s*%[([^%]]+)%]') or ""
  local sec_opts = {}
  for opt in string.gmatch(sec_options_raw, '"([^"]+)"') do
    table.insert(sec_opts, opt)
  end

  local has_apparmor = string.find(sec_options_raw, "name=apparmor") ~= nil
  local has_selinux = string.find(sec_options_raw, "name=selinux") ~= nil
  local has_seccomp = string.find(sec_options_raw, "name=seccomp") ~= nil
  local has_userns = string.find(sec_options_raw, "name=userns") ~= nil
  local is_rootless = string.find(sec_options_raw, "name=rootless") ~= nil

  local findings = {}
  if not has_apparmor and not has_selinux then
    table.insert(findings, "MISSING: No Mandatory Access Control (neither AppArmor nor SELinux is active on daemon)")
  end

  if not has_seccomp then
    table.insert(findings, "MISSING: Seccomp default system call filtering is DISABLED on daemon")
  end

  if not has_userns and not is_rootless then
    table.insert(findings, "MISSING: User Namespaces (userns-remap / rootless) not active; container root is real host root (UID 0)")
  end

  local live_restore = string.match(body, '"LiveRestoreEnabled"%s*:%s*(%w+)')
  if live_restore == "false" then
    table.insert(findings, "CONFIGURATION: LiveRestoreEnabled is FALSE (daemon restarts kill running containers)")
  end

  out["Active Security Options"] = #sec_opts > 0 and table.concat(sec_opts, ", ") or "None detected"

  if #findings > 0 then
    out["Status"] = "VULNERABLE / HARDENING DEFICIENT - Missing critical daemon security profiles"
    out["Identified Weaknesses"] = findings
    out["Remediation"] = "Enable userns-remap in /etc/docker/daemon.json, enforce default AppArmor/SELinux profiles, and ensure seccomp profile is default."
  else
    out["Status"] = "SECURE - Daemon has active mandatory access control and seccomp filtering enabled."
  end

  return out
end
