local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Detects exposed Git repository configurations and metadata (/.git/config, /.git/HEAD,
/.git/index) on web servers. Publicly accessible .git folders permit attackers to
download the full source code repository, history, commit logs, and embedded secrets.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local out = stdnse.output_table()
  local head_resp = http.get(host, port, "/.git/HEAD")
  local config_resp = http.get(host, port, "/.git/config")

  local is_git_head = head_resp and head_resp.status == 200 and head_resp.body and string.match(head_resp.body, "^ref:%s+refs/")
  local is_git_config = config_resp and config_resp.status == 200 and config_resp.body and string.find(config_resp.body, "[core]", 1, true)

  out["Risk Level"] = "🔴 CRITICAL"
  if is_git_head or is_git_config then
    out["Status"] = "VULNERABLE - Exposed .git Repository Discovered"
    out["Assessment"] = "The .git directory is accessible without authentication. Attackers can reconstruct the complete source code repository and commit history."
    out["Remediation"] = "Deny web access to /.git/ and all dotfiles in web server configuration."
  else
    out["Status"] = "SECURE - /.git/ directory is not exposed."
  end
  return out
end
