local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"

description = [[
Queries an accessible Docker REST API for all active and stopped
containers (/containers/json?all=1) and inspects their configuration
metadata (/containers/{id}/json) to detect plaintext secrets, passwords,
API tokens, and private keys exposed in environment variables (Config.Env)
and container labels. Masks sensitive values in the output to prevent
accidental data exposure during assessment.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "discovery", "safe"}

portrule = shortport.port_or_service(
  {2375, 2376, 4243},
  {"docker", "docker-s", "http", "https"},
  "tcp"
)

-- Secret keywords to search for in environment variables and labels
local SECRET_PATTERNS = {
  "PASS", "PWD", "SECRET", "KEY", "TOKEN", "AUTH", "PRIVATE",
  "CREDENTIAL", "API_KEY", "ACCESS_KEY", "AWS_SECRET", "DB_PASS",
  "MYSQL_ROOT_PASSWORD", "POSTGRES_PASSWORD", "MONGO_INITDB_ROOT_PASSWORD",
  "REDIS_PASSWORD", "DATABASE_URL", "JWT_SECRET", "SSH_KEY"
}

local function is_sensitive_key(key_name)
  local upper = string.upper(key_name)
  for _, pat in ipairs(SECRET_PATTERNS) do
    if string.find(upper, pat, 1, true) then
      return true
    end
  end
  return false
end

local function mask_secret(val)
  if not val or #val == 0 then return "<empty>" end
  if #val <= 4 then return string.rep("*", #val) end
  return string.sub(val, 1, 2) .. string.rep("*", #val - 4) .. string.sub(val, -2)
end

action = function(host, port)
  local out = stdnse.output_table()
  local max_containers = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".max_containers")) or 25

  -- Query containers list
  local resp = http.get(host, port, "/containers/json?all=1")
  if not resp or resp.status ~= 200 or not resp.body then
    return stdnse.format_output(false, "Could not retrieve container list from Docker API.")
  end

  -- Extract container IDs and Names
  local containers = {}
  for id, names in string.gmatch(resp.body, '"Id"%s*:%s*"([a-f0-9]+)".-"Names"%s*:%s*%[([^%]]+)%]') do
    local first_name = string.match(names, '"/([^"]+)"') or string.match(names, '"([^"]+)"') or id
    table.insert(containers, { id = id, name = first_name })
    if #containers >= max_containers then break end
  end

  if #containers == 0 then
    -- Try basic ID extraction fallback
    for id in string.gmatch(resp.body, '"Id"%s*:%s*"([a-f0-9]+)"') do
      table.insert(containers, { id = id, name = string.sub(id, 1, 12) })
      if #containers >= max_containers then break end
    end
  end

  if #containers == 0 then
    out["Container Count"] = "0 containers found on target daemon."
    return out
  end

  out["Risk Level"] = "🔴 CRITICAL"
  out["Total Containers Evaluated"] = #containers

  local exposed_secrets_table = stdnse.output_table()
  local total_leaked_variables = 0

  for _, c in ipairs(containers) do
    local c_resp = http.get(host, port, "/containers/" .. c.id .. "/json")
    if c_resp and c_resp.status == 200 and c_resp.body then
      local body = c_resp.body
      local c_findings = {}

      -- Extract Config.Env array
      local env_section = string.match(body, '"Env"%s*:%s*%[([^%]]+)%]')
      if env_section then
        for env_entry in string.gmatch(env_section, '"([^"]+)"') do
          local k, v = string.match(env_entry, "^([^=]+)=(.*)$")
          if k and is_sensitive_key(k) then
            total_leaked_variables = total_leaked_variables + 1
            table.insert(c_findings, string.format("ENV: %s = %s", k, mask_secret(v)))
          end
        end
      end

      -- Extract Config.Labels
      local labels_section = string.match(body, '"Labels"%s*:%s*{(.-)}')
      if labels_section then
        for lk, lv in string.gmatch(labels_section, '"([^"]+)"%s*:%s*"([^"]+)"') do
          if is_sensitive_key(lk) or is_sensitive_key(lv) then
            total_leaked_variables = total_leaked_variables + 1
            table.insert(c_findings, string.format("LABEL: %s = %s", lk, mask_secret(lv)))
          end
        end
      end

      if #c_findings > 0 then
        exposed_secrets_table[string.format("%s (ID: %s)", c.name, string.sub(c.id, 1, 12))] = c_findings
      end
    end
  end

  if total_leaked_variables > 0 then
    out["Status"] = string.format("VULNERABLE - %d sensitive variables discovered across inspected containers", total_leaked_variables)
    out["Leaked Container Secrets"] = exposed_secrets_table
    out["Remediation"] = "Do not pass secrets via container environment variables (Config.Env) or labels. Use Docker Secrets, HashiCorp Vault, Kubernetes Secrets, or encrypted volume mounts."
  else
    out["Status"] = "SECURE - No cleartext secrets detected matching sensitive patterns across evaluated containers."
  end

  return out
end
