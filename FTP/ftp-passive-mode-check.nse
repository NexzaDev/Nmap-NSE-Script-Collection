local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Sends PASV and EPSV commands and inspects the returned data-channel
address. Flags cases where the PASV response advertises a private/
internal IP address different from the control connection's public
address, which typically breaks passive-mode transfers for external
clients behind NAT and is a common FTP server misconfiguration.
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

local function parse_pasv(resp)
  local a, b, c, d, p1, p2 = string.match(resp, "(%d+),(%d+),(%d+),(%d+),(%d+),(%d+)")
  if not a then return nil end
  local ip = string.format("%s.%s.%s.%s", a, b, c, d)
  local port = tonumber(p1) * 256 + tonumber(p2)
  return ip, port
end

local function parse_epsv(resp)
  local port = string.match(resp, "%(|||(%d+)|%)")
  if not port then
    port = string.match(resp, "%(%s*|%s*|%s*|%s*(%d+)%s*|%s*%)")
  end
  return port
end

local function is_private_ip(ip)
  if string.match(ip, "^10%.") then return true end
  if string.match(ip, "^192%.168%.") then return true end
  if string.match(ip, "^172%.(%d+)%.") then
    local second = tonumber(string.match(ip, "^172%.(%d+)%."))
    if second and second >= 16 and second <= 31 then return true end
  end
  if string.match(ip, "^127%.") then return true end
  if string.match(ip, "^169%.254%.") then return true end
  return false
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

  send_cmd(socket, "PASV")
  local pasv_resp = read_response(socket)
  local pasv_ip, pasv_port = parse_pasv(pasv_resp)

  if pasv_ip then
    out["PASV advertised address"] = pasv_ip .. ":" .. tostring(pasv_port)
    local control_ip = tostring(host.ip)
    if is_private_ip(pasv_ip) and not is_private_ip(control_ip) then
      out["PASV misconfiguration"] = string.format(
        "Server advertised a private/internal address (%s) over a connection made to a non-private control address (%s) - passive mode will likely fail for external clients unless a NAT-aware FTP proxy rewrites this.",
        pasv_ip, control_ip
      )
    else
      out["PASV misconfiguration"] = "No obvious private-IP mismatch detected."
    end
  else
    out["PASV advertised address"] = "PASV command was not accepted or returned an unparseable response."
  end

  send_cmd(socket, "EPSV")
  local epsv_resp = read_response(socket)
  local epsv_port = parse_epsv(epsv_resp)

  if epsv_port then
    out["EPSV supported"] = "YES - extended passive mode port " .. epsv_port
  else
    out["EPSV supported"] = "NO - server did not return a usable EPSV response (may only support legacy PASV)."
  end

  send_cmd(socket, "QUIT")
  socket:close()

  return out
end
