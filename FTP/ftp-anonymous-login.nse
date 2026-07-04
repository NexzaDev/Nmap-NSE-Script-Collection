local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Attempts anonymous FTP login using a set of common anonymous
credential pairs (anonymous/anonymous, anonymous/anonymous@example.com,
ftp/ftp, and blank password) and reports whether unauthenticated
access is permitted, along with the post-login welcome message.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.port_or_service(21, "ftp")

local CREDENTIAL_PAIRS = {
  { user = "anonymous", pass = "anonymous@example.com" },
  { user = "anonymous", pass = "anonymous" },
  { user = "ftp", pass = "ftp" },
  { user = "anonymous", pass = "" },
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

local function try_login(host, port, user, pass)
  local socket = nmap.new_socket()
  socket:set_timeout(6000)
  local ok = socket:connect(host, port, "tcp")
  if not ok then
    socket:close()
    return nil, "connect failed"
  end

  read_response(socket)

  send_cmd(socket, "USER " .. user)
  local resp1, code1 = read_response(socket)

  if code1 == "230" then
    send_cmd(socket, "QUIT")
    socket:close()
    return true, resp1
  end

  if code1 ~= "331" then
    socket:close()
    return false, resp1
  end

  send_cmd(socket, "PASS " .. pass)
  local resp2, code2 = read_response(socket)
  send_cmd(socket, "QUIT")
  socket:close()

  return (code2 == "230"), resp2
end

action = function(host, port)
  local out = stdnse.output_table()
  local attempts = {}
  local success_found = false

  for _, cred in ipairs(CREDENTIAL_PAIRS) do
    local ok, response = try_login(host, port, cred.user, cred.pass)
    local label = string.format("%s / %s", cred.user, (cred.pass == "" and "<blank>" or cred.pass))
    if ok then
      table.insert(attempts, label .. " -> SUCCESS")
      if not success_found then
        out["Welcome message on success"] = response or "unavailable"
      end
      success_found = true
    else
      table.insert(attempts, label .. " -> rejected")
    end
    if success_found then
      break
    end
  end

  out["Credential attempts"] = attempts

  if success_found then
    out["Result"] = "VULNERABLE - anonymous/unauthenticated FTP access is permitted."
  else
    out["Result"] = "Anonymous login was rejected for all tested credential pairs."
  end

  return out
end
