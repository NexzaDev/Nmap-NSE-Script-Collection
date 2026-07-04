local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Logs in anonymously and attempts to upload a small harmless test file
into a set of common directories to determine which are writable by
unauthenticated users. Any successfully uploaded test file is deleted
immediately afterward. Anonymous-writable FTP directories are a
common vector for malware staging and defacement.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.port_or_service(21, "ftp")

local TEST_DIRS = {
  "/", "/incoming", "/upload", "/uploads", "/pub", "/pub/incoming",
  "/tmp", "/public", "/files", "/drop", "/dropbox",
}

local TEST_FILENAME = "nse-write-test-9f31c2.txt"
local TEST_CONTENT = "nse write permission probe\r\n"

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

local function try_upload(host, port, dir)
  local socket = nmap.new_socket()
  socket:set_timeout(6000)
  local ok = socket:connect(host, port, "tcp")
  if not ok then
    socket:close()
    return false, "connect failed"
  end

  read_response(socket)
  send_cmd(socket, "USER anonymous")
  local _, code1 = read_response(socket)
  if code1 == "331" then
    send_cmd(socket, "PASS anonymous@example.com")
    local _, code2 = read_response(socket)
    if code2 ~= "230" then
      send_cmd(socket, "QUIT")
      socket:close()
      return false, "login failed"
    end
  elseif code1 ~= "230" then
    send_cmd(socket, "QUIT")
    socket:close()
    return false, "login failed"
  end

  if dir ~= "/" then
    send_cmd(socket, "CWD " .. dir)
    local _, cwd_code = read_response(socket)
    if cwd_code ~= "250" then
      send_cmd(socket, "QUIT")
      socket:close()
      return false, "directory not accessible"
    end
  end

  send_cmd(socket, "PASV")
  local pasv_resp = read_response(socket)
  local data_ip, data_port = parse_pasv(pasv_resp)
  if not data_ip then
    send_cmd(socket, "QUIT")
    socket:close()
    return false, "PASV failed"
  end

  local data_socket = nmap.new_socket()
  data_socket:set_timeout(6000)
  local data_ok = data_socket:connect(data_ip, data_port, "tcp")
  if not data_ok then
    send_cmd(socket, "QUIT")
    socket:close()
    return false, "data connection failed"
  end

  send_cmd(socket, "STOR " .. TEST_FILENAME)
  local _, stor_code = read_response(socket)

  if stor_code == "150" or stor_code == "125" then
    data_socket:send(TEST_CONTENT)
    data_socket:close()
    local _, final_code = read_response(socket)
    if final_code == "226" or final_code == "250" then
      send_cmd(socket, "DELE " .. TEST_FILENAME)
      read_response(socket)
      send_cmd(socket, "QUIT")
      socket:close()
      return true, "upload succeeded"
    end
  end

  data_socket:close()
  send_cmd(socket, "QUIT")
  socket:close()
  return false, "upload rejected"
end

action = function(host, port)
  local out = stdnse.output_table()
  local writable = {}
  local not_writable = {}

  for _, dir in ipairs(TEST_DIRS) do
    local ok, reason = try_upload(host, port, dir)
    if ok then
      table.insert(writable, dir)
    else
      table.insert(not_writable, dir .. " (" .. reason .. ")")
    end
  end

  if #writable > 0 then
    out["Anonymous-writable directories"] = writable
    out["Assessment"] = "VULNERABLE - one or more directories accept anonymous file uploads."
  else
    out["Anonymous-writable directories"] = "None of the tested directories accepted an anonymous upload."
  end

  out["Directories tested without write access"] = not_writable

  return out
end
