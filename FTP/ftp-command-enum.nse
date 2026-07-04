local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Enumerates supported FTP extended features via the FEAT command and
probes for a set of individually risky or notable commands (SITE
EXEC, SITE CHMOD, SITE, MDTM, SIZE, REST, RNFR/RNTO) to determine
which are implemented, flagging SITE EXEC specifically as historically
associated with remote command execution vulnerabilities in some FTP
daemons.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.port_or_service(21, "ftp")

local PROBE_COMMANDS = {
  { cmd = "SITE HELP", label = "SITE HELP" },
  { cmd = "SITE EXEC /bin/true", label = "SITE EXEC" },
  { cmd = "SITE CHMOD 644 nonexistent-nse-probe-file", label = "SITE CHMOD" },
  { cmd = "MDTM nonexistent-nse-probe-file", label = "MDTM" },
  { cmd = "SIZE nonexistent-nse-probe-file", label = "SIZE" },
  { cmd = "REST 0", label = "REST" },
  { cmd = "RNFR nonexistent-nse-probe-file", label = "RNFR" },
  { cmd = "STAT", label = "STAT" },
  { cmd = "SYST", label = "SYST" },
  { cmd = "OPTS UTF8 ON", label = "OPTS" },
}

local function read_response(socket)
  local full = ""
  local code = nil
  while true do
    local status, line = socket:receive_lines(1)
    if not status then break end
    full = full .. line
    local c, sep = string.match(line, "^(%d%d%d)(.)")
    if c and sep == " " then
      code = c
      break
    end
  end
  return full, code
end

local function send_cmd(socket, cmd)
  return socket:send(cmd .. "\r\n")
end

local function is_implemented(code)
  if not code then return false end
  local first = string.sub(code, 1, 1)
  return first == "1" or first == "2" or first == "3"
end

action = function(host, port)
  local out = stdnse.output_table()

  local socket = nmap.new_socket()
  socket:set_timeout(6000)
  local ok = socket:connect(host, port, "tcp")
  if not ok then
    socket:close()
    return "Could not establish a TCP connection to the FTP service."
  end

  read_response(socket)

  send_cmd(socket, "FEAT")
  local feat_resp = read_response(socket)

  local feat_list = {}
  if feat_resp then
    for line in string.gmatch(feat_resp, "[^\r\n]+") do
      local trimmed = string.gsub(line, "^%s+", "")
      if trimmed ~= "" and not string.match(trimmed, "^%d%d%d") then
        table.insert(feat_list, trimmed)
      end
    end
  end

  if #feat_list > 0 then
    out["FEAT extensions advertised"] = feat_list
  else
    out["FEAT extensions advertised"] = "None advertised or FEAT not supported."
  end

  local implemented = {}
  local not_implemented = {}
  local risky_findings = {}

  for _, probe in ipairs(PROBE_COMMANDS) do
    send_cmd(socket, probe.cmd)
    local resp, code = read_response(socket)
    if is_implemented(code) then
      table.insert(implemented, probe.label .. " -> HTTP-style code " .. tostring(code))
      if probe.label == "SITE EXEC" then
        table.insert(risky_findings, "SITE EXEC appears to be implemented - historically linked to remote command execution vulnerabilities in some FTP daemons; verify version-specific advisories.")
      end
    else
      table.insert(not_implemented, probe.label)
    end
  end

  send_cmd(socket, "QUIT")
  socket:close()

  if #implemented > 0 then
    out["Commands implemented"] = implemented
  end
  if #not_implemented > 0 then
    out["Commands not implemented / rejected"] = not_implemented
  end
  if #risky_findings > 0 then
    out["Notable risk findings"] = risky_findings
  end

  return out
end
