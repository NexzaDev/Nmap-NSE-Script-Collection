local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Attempts a plaintext USER/PASS login without first negotiating TLS
and reports whether the server processes the credentials in the
clear or refuses login until AUTH TLS/AUTH SSL has been performed.
A server that accepts plaintext credentials transmits usernames and
passwords unencrypted over the network.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.port_or_service(21, "ftp")

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
  local resp1, code1 = read_response(socket)

  local enforced_tls = false
  local login_processed_in_clear = false

  if code1 and (string.find(code1, "^5") or string.find(string.lower(resp1 or ""), "tls")) then
    enforced_tls = true
  elseif code1 == "331" then
    send_cmd(socket, "PASS invalid-probe-password-9f31c2")
    local resp2, code2 = read_response(socket)
    if code2 == "530" and string.find(string.lower(resp2 or ""), "tls") then
      enforced_tls = true
    else
      login_processed_in_clear = true
    end
  elseif code1 == "230" then
    login_processed_in_clear = true
  end

  send_cmd(socket, "QUIT")
  socket:close()

  out["USER command response code"] = code1 or "no response"

  if enforced_tls then
    out["Cleartext login enforcement"] = "TLS appears to be required before authentication - the server referenced TLS when rejecting the plaintext attempt."
  elseif login_processed_in_clear then
    out["Cleartext login enforcement"] = "Server processed a plaintext authentication attempt without requiring TLS first - credentials sent over this control channel would be transmitted unencrypted."
  else
    out["Cleartext login enforcement"] = "Could not conclusively determine enforcement behavior from this probe."
  end

  return out
end
