local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Checks whether the FTP server accepts a PORT command specifying an IP
address other than the client's own control-connection address. This
script only tests whether the PORT command is syntactically accepted
(a necessary precondition for the classic FTP bounce issue); it does
not follow up with a data-transfer command, so it never causes the
server to actually open a connection toward the address used in the
test.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.port_or_service(21, "ftp")

local TEST_ADDRESSES = {
  "10,0,0,1,4,1",
  "192,168,0,1,4,1",
  "172,16,0,1,4,1",
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

  send_cmd(socket, "USER anonymous")
  local _, code1 = read_response(socket)
  if code1 == "331" then
    send_cmd(socket, "PASS anonymous@example.com")
    read_response(socket)
  end

  local accepted_any = false
  local results = {}

  for _, addr in ipairs(TEST_ADDRESSES) do
    send_cmd(socket, "PORT " .. addr)
    local resp, code = read_response(socket)
    local human_ip = string.gsub(addr, "^(%d+,%d+,%d+,%d+),.*$", "%1")
    human_ip = string.gsub(human_ip, ",", ".")
    if code == "200" then
      accepted_any = true
      table.insert(results, human_ip .. " -> ACCEPTED (200)")
    else
      table.insert(results, human_ip .. " -> rejected (" .. tostring(code) .. ")")
    end
  end

  send_cmd(socket, "QUIT")
  socket:close()

  out["PORT command tests"] = results

  if accepted_any then
    out["Assessment"] = "POTENTIALLY VULNERABLE - server accepted PORT commands referencing addresses unrelated to the control connection. This is a precondition for FTP bounce abuse; a full bounce attack was not attempted."
  else
    out["Assessment"] = "Server rejected PORT commands referencing unrelated addresses - bounce precondition not present."
  end

  return out
end
