local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Checks whether the FTP server supports explicit FTPS by sending AUTH
TLS and AUTH SSL commands, and inspects the FEAT command response for
advertised AUTH, PBSZ and PROT mechanisms. A server offering none of
these only supports plaintext FTP sessions.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

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

  send_cmd(socket, "FEAT")
  local feat_resp = read_response(socket)

  local lfeat = string.lower(feat_resp or "")
  local feat_lines = {}
  for _, mech in ipairs({ "auth tls", "auth ssl", "pbsz", "prot", "ccc" }) do
    if string.find(lfeat, mech, 1, true) then
      table.insert(feat_lines, mech)
    end
  end

  send_cmd(socket, "AUTH TLS")
  local _, auth_tls_code = read_response(socket)

  local supports_auth_tls = (auth_tls_code == "234")

  local supports_auth_ssl = false
  if not supports_auth_tls then
    socket:close()
    socket = nmap.new_socket()
    socket:set_timeout(6000)
    local ok2 = socket:connect(host, port, "tcp")
    if ok2 then
      read_response(socket)
      send_cmd(socket, "AUTH SSL")
      local _, auth_ssl_code = read_response(socket)
      supports_auth_ssl = (auth_ssl_code == "234")
    end
  end

  socket:close()

  out["FEAT mechanisms mentioning TLS/SSL"] = (#feat_lines > 0) and feat_lines or "None found in FEAT response."
  out["AUTH TLS accepted"] = tostring(supports_auth_tls)
  out["AUTH SSL accepted"] = tostring(supports_auth_ssl)

  if supports_auth_tls or supports_auth_ssl then
    out["Assessment"] = "Explicit FTPS is supported - credentials and data CAN be protected if the client negotiates TLS."
  else
    out["Assessment"] = "No explicit FTPS support detected - this server likely only supports plaintext FTP sessions."
  end

  return out
end
