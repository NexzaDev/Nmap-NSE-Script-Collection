local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Uses the read-only COMMAND INFO subcommand to check whether a set of
high-risk administrative Redis commands (FLUSHALL, FLUSHDB, CONFIG,
SHUTDOWN, DEBUG, SLAVEOF, REPLICAOF, MODULE, SCRIPT) are present and
not renamed/disabled, without ever invoking those commands
destructively.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.port_or_service(6379, "redis")

local RISKY_COMMANDS = {
  "flushall", "flushdb", "config", "shutdown", "debug",
  "slaveof", "replicaof", "module", "script", "eval",
}

local function build_multibulk(args)
  local out = "*" .. tostring(#args) .. "\r\n"
  for _, arg in ipairs(args) do
    out = out .. "$" .. tostring(#arg) .. "\r\n" .. arg .. "\r\n"
  end
  return out
end

local function read_line(socket)
  local status, line = socket:receive_lines(1)
  if not status then return nil end
  return line
end

local function skip_reply(socket)
  local line = read_line(socket)
  if not line then return nil end
  local prefix = string.sub(line, 1, 1)

  if prefix == "+" or prefix == "-" or prefix == ":" then
    return line
  elseif prefix == "$" then
    local len = tonumber(string.match(line, "^%$(%-?%d+)"))
    if not len or len < 0 then return line end
    local remaining = len + 2
    local data = ""
    while #data < remaining do
      local status, chunk = socket:receive()
      if not status then break end
      data = data .. chunk
    end
    return line .. data
  elseif prefix == "*" then
    local count = tonumber(string.match(line, "^%*(%-?%d+)"))
    local combined = line
    if count and count > 0 then
      for i = 1, count do
        combined = combined .. (skip_reply(socket) or "")
      end
    end
    return combined
  end

  return line
end

action = function(host, port)
  local out = stdnse.output_table()

  local socket = nmap.new_socket()
  socket:set_timeout(6000)
  local ok = socket:connect(host, port, "tcp")
  if not ok then
    socket:close()
    return "Could not establish a TCP connection to the Redis service."
  end

  socket:send("PING\r\n")
  local ping_resp = read_line(socket)
  if not ping_resp then
    socket:close()
    return "No response received to PING."
  end
  if string.find(ping_resp, "NOAUTH", 1, true) then
    socket:close()
    out["Result"] = "Server requires authentication; command exposure could not be tested unauthenticated."
    return out
  end

  local present = {}
  local absent = {}

  for _, cmd in ipairs(RISKY_COMMANDS) do
    local request = build_multibulk({ "COMMAND", "INFO", cmd })
    socket:send(request)
    local reply = skip_reply(socket)
    if reply and not string.find(reply, "^%*1\r\n%$%-1", 1) and string.find(reply, "%$") then
      table.insert(present, cmd)
    else
      table.insert(absent, cmd)
    end
  end

  socket:close()

  if #present > 0 then
    out["High-risk commands present and callable"] = present
    out["Assessment"] = "One or more administrative commands remain enabled under the current (lack of) authentication - consider renaming or disabling them via rename-command, and enforcing requirepass/ACLs."
  else
    out["High-risk commands present and callable"] = "None of the tested commands appear present (may be renamed, disabled, or ACL-restricted)."
  end

  if #absent > 0 then
    out["Commands not detected"] = absent
  end

  return out
end
