local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Logs in anonymously and lists the root directory plus a set of
common subdirectories, then scans the returned filenames against a
set of sensitive keyword patterns (backup, config, password, .sql,
.bak, id_rsa, .env, and others) to flag files that may warrant closer
inspection.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(21, "ftp")

local TEST_DIRS = {
  "/", "/pub", "/incoming", "/upload", "/uploads", "/backup",
  "/backups", "/data", "/files", "/home", "/etc", "/config",
}

local SENSITIVE_KEYWORDS = {
  "backup", "bak", "config", "conf", "password", "passwd", "secret",
  "credential", "private", "id_rsa", "id_dsa", "pem", "key", "env",
  "sql", "db", "database", "dump", "old", "confidential", "internal",
}

local function is_sensitive(filename)
  local lname = string.lower(filename)
  for _, kw in ipairs(SENSITIVE_KEYWORDS) do
    if string.find(lname, kw, 1, true) then
      return true, kw
    end
  end
  return false, nil
end

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

local function list_dir(control_socket, host, dir)
  if dir ~= "/" then
    send_cmd(control_socket, "CWD " .. dir)
    local _, cwd_code = read_response(control_socket)
    if cwd_code ~= "250" then
      return nil
    end
  end

  send_cmd(control_socket, "PASV")
  local pasv_resp = read_response(control_socket)
  local data_ip, data_port = parse_pasv(pasv_resp)
  if not data_ip then return nil end

  local data_socket = nmap.new_socket()
  data_socket:set_timeout(6000)
  local ok = data_socket:connect(data_ip, data_port, "tcp")
  if not ok then return nil end

  send_cmd(control_socket, "NLST")
  local _, list_code = read_response(control_socket)

  local listing = ""
  if list_code == "150" or list_code == "125" then
    while true do
      local status, chunk = data_socket:receive()
      if not status then break end
      listing = listing .. chunk
    end
    read_response(control_socket)
  end

  data_socket:close()
  send_cmd(control_socket, "CWD /")
  read_response(control_socket)

  return listing
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
    local _, code2 = read_response(socket)
    if code2 ~= "230" then
      socket:close()
      return "Anonymous login was rejected; directory listing could not be performed unauthenticated."
    end
  elseif code1 ~= "230" then
    socket:close()
    return "Anonymous login was rejected; directory listing could not be performed unauthenticated."
  end

  local flagged = {}
  local dirs_listed = 0
  local total_files = 0

  for _, dir in ipairs(TEST_DIRS) do
    local listing = list_dir(socket, host, dir)
    if listing then
      dirs_listed = dirs_listed + 1
      for filename in string.gmatch(listing, "[^\r\n]+") do
        if filename ~= "" then
          total_files = total_files + 1
          local sensitive, kw = is_sensitive(filename)
          if sensitive then
            table.insert(flagged, dir .. "/" .. filename .. " (matched keyword: " .. kw .. ")")
          end
        end
      end
    end
  end

  send_cmd(socket, "QUIT")
  socket:close()

  out["Directories successfully listed"] = tostring(dirs_listed)
  out["Total filenames observed"] = tostring(total_files)

  if #flagged > 0 then
    out["Sensitive-looking files found"] = flagged
  else
    out["Sensitive-looking files found"] = "None of the observed filenames matched sensitive keyword patterns."
  end

  return out
end
