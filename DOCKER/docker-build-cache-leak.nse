local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local table = require "table"
local string = require "string"

description = [[
Connects to an accessible Docker REST API, enumerates intermediate build
images and dangling layers (/images/json?all=1), and inspects image history
(/images/{id}/history) for residual build arguments (ARG), temporary
environment variables, embedded curl/wget commands with API keys, and
abandoned build stages.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "discovery", "safe"}

portrule = shortport.port_or_service(
  {2375, 2376, 4243},
  {"docker", "docker-s", "http", "https"},
  "tcp"
)

local SENSITIVE_KEYWORDS = {
  "ARG ", "TOKEN", "SECRET", "PASS", "KEY", "SSH", "NPM_TOKEN", "GITHUB_TOKEN", "AWS"
}

action = function(host, port)
  local out = stdnse.output_table()
  local max_images = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".max_images")) or 20

  local resp = http.get(host, port, "/images/json?all=1")
  if not resp or resp.status ~= 200 or not resp.body then
    return stdnse.format_output(false, "Could not query images list from Docker API.")
  end

  local image_ids = {}
  for id in string.gmatch(resp.body, '"Id"%s*:%s*"sha256:([a-f0-9]+)"') do
    table.insert(image_ids, id)
    if #image_ids >= max_images then break end
  end

  if #image_ids == 0 then
    out["Summary"] = "No images found on daemon."
    return out
  end

  out["Risk Level"] = "🟡 MEDIUM"
  out["Total Images Evaluated"] = #image_ids

  local leaked_build_steps = {}
  for _, id in ipairs(image_ids) do
    local hist_resp = http.get(host, port, "/images/sha256:" .. id .. "/history")
    if hist_resp and hist_resp.status == 200 and hist_resp.body then
      for created_by in string.gmatch(hist_resp.body, '"CreatedBy"%s*:%s*"([^"]+)"') do
        local upper = string.upper(created_by)
        for _, kw in ipairs(SENSITIVE_KEYWORDS) do
          if string.find(upper, kw, 1, true) then
            local clean_cmd = string.gsub(created_by, '\\"', '"')
            table.insert(leaked_build_steps, string.format("[%s] %s", string.sub(id, 1, 10), clean_cmd))
            break
          end
        end
      end
    end
  end

  if #leaked_build_steps > 0 then
    out["Status"] = string.format("VULNERABLE - %d suspicious build layer commands discovered containing potential secrets", #leaked_build_steps)
    local sample_steps = {}
    for i = 1, math.min(#leaked_build_steps, 15) do
      table.insert(sample_steps, leaked_build_steps[i])
    end
    out["Exposed Build History"] = sample_steps
    out["Remediation"] = "Use multi-stage Docker builds to discard intermediate build layers. Avoid ARG for secret values; use BuildKit --secret instead."
  else
    out["Status"] = "AUDITED - No sensitive build arguments or secret patterns detected in evaluated image layers."
  end

  return out
end
