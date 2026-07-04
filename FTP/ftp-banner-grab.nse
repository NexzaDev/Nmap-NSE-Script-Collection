local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Grabs the FTP welcome banner and attempts to fingerprint the server
software and version from it (vsftpd, ProFTPD, Pure-FTPd, FileZilla
Server, Microsoft FTP Service, WU-FTPD, glFTPd, Serv-U, and others),
flagging known end-of-life or notably outdated version strings.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "version"}

portrule = shortport.port_or_service(21, "ftp")

local SIGNATURES = {
  { pattern = "vsftpd%s*([%d%.]*)", label = "vsftpd" },
  { pattern = "proftpd%s*([%d%.]*)", label = "ProFTPD" },
  { pattern = "pure%-?ftpd", label = "Pure-FTPd" },
  { pattern = "filezilla server%s*([%d%.]*)", label = "FileZilla Server" },
  { pattern = "microsoft ftp service", label = "Microsoft FTP Service" },
  { pattern = "wu%-ftpd%s*([%d%.]*)", label = "WU-FTPD" },
  { pattern = "glftpd", label = "glFTPd" },
  { pattern = "serv%-u%s*([%d%.]*)", label = "Serv-U" },
  { pattern = "bftpd%s*([%d%.]*)", label = "bftpd" },
  { pattern = "titan ftp", label = "Titan FTP Server" },
  { pattern = "gene6 ftp", label = "Gene6 FTP Server" },
  { pattern = "crushftp", label = "CrushFTP" },
}

local OLD_VERSION_THRESHOLDS = {
  ["vsftpd"] = "3.0.0",
  ["ProFTPD"] = "1.3.6",
  ["FileZilla Server"] = "1.0.0",
  ["Serv-U"] = "15.0",
}

local function version_is_older(v1, v2)
  local function parts(v)
    local t = {}
    for n in string.gmatch(v, "%d+") do
      table.insert(t, tonumber(n))
    end
    return t
  end
  local p1, p2 = parts(v1), parts(v2)
  for i = 1, math.max(#p1, #p2) do
    local a, b = p1[i] or 0, p2[i] or 0
    if a < b then return true end
    if a > b then return false end
  end
  return false
end

local function read_banner(socket)
  local full = ""
  while true do
    local status, line = socket:receive_lines(1)
    if not status then break end
    full = full .. line
    local code, sep = string.match(line, "^(%d%d%d)(.)")
    if code and sep == " " then break end
  end
  return full
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

  local banner = read_banner(socket)
  socket:close()

  if not banner or banner == "" then
    return "No banner received from the FTP service."
  end

  out["Raw banner"] = banner

  local lbanner = string.lower(banner)
  local identified = nil
  local version = nil

  for _, sig in ipairs(SIGNATURES) do
    local captured = string.match(lbanner, sig.pattern)
    if captured ~= nil or string.find(lbanner, string.gsub(sig.pattern, "%%s.*", "")) then
      identified = sig.label
      if captured and captured ~= "" then
        version = captured
      end
      break
    end
  end

  if identified then
    out["Identified server software"] = identified
    if version then
      out["Detected version"] = version
      local threshold = OLD_VERSION_THRESHOLDS[identified]
      if threshold and version_is_older(version, threshold) then
        out["Version assessment"] = string.format(
          "Version %s is older than the %s baseline (%s) - check for known CVEs against this release.",
          version, identified, threshold
        )
      end
    else
      out["Detected version"] = "Not present in banner"
    end
  else
    out["Identified server software"] = "Could not be identified from banner signatures."
  end

  return out
end
