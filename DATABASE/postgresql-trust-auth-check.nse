local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Sends a PostgreSQL StartupMessage for the "postgres" user/database and
inspects the server's authentication request to determine the
configured authentication method. An immediate AuthenticationOk
response indicates "trust" authentication, allowing login without any
credentials.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.port_or_service(5432, "postgresql")

local function u32be(n)
  return string.char(
    math.floor(n / 16777216) % 256,
    math.floor(n / 65536) % 256,
    math.floor(n / 256) % 256,
    n % 256
  )
end

local AUTH_TYPES = {
  [0] = "AuthenticationOk (no password required - trust/peer-equivalent)",
  [2] = "AuthenticationKerberosV5",
  [3] = "AuthenticationCleartextPassword",
  [5] = "AuthenticationMD5Password",
  [6] = "AuthenticationSCMCredential",
  [7] = "AuthenticationGSS",
  [8] = "AuthenticationGSSContinue",
  [9] = "AuthenticationSSPI",
  [10] = "AuthenticationSASL",
  [11] = "AuthenticationSASLContinue",
  [12] = "AuthenticationSASLFinal",
}

local function recv_atleast(socket, buf, n)
  while #buf < n do
    local status, data = socket:receive_bytes(n - #buf)
    if not status then
      return nil, buf
    end
    buf = buf .. data
  end
  return buf
end

action = function(host, port)
  local out = stdnse.output_table()

  local socket = nmap.new_socket()
  socket:set_timeout(6000)
  local ok = socket:connect(host, port, "tcp")
  if not ok then
    socket:close()
    return "Could not establish a TCP connection to the PostgreSQL service."
  end

  local params = "user\0postgres\0database\0postgres\0application_name\0nse-audit\0\0"
  local body = u32be(196608) .. params
  local packet = u32be(4 + #body) .. body

  local sent = socket:send(packet)
  if not sent then
    socket:close()
    return "Failed to send StartupMessage."
  end

  local buf = ""
  local ok2
  ok2, buf = pcall(function() return recv_atleast(socket, buf, 5) end)
  socket:close()

  if not ok2 or not buf or #buf < 5 then
    return "No usable response received to the startup message."
  end

  local msg_type = string.sub(buf, 1, 1)
  local msg_len = string.byte(buf, 2) * 16777216 + string.byte(buf, 3) * 65536
    + string.byte(buf, 4) * 256 + string.byte(buf, 5)

  if msg_type == "R" then
    if #buf < 9 then
      out["Result"] = "Authentication response truncated before the auth type code could be read."
      return out
    end
    local auth_code = string.byte(buf, 6) * 16777216 + string.byte(buf, 7) * 65536
      + string.byte(buf, 8) * 256 + string.byte(buf, 9)

    out["Authentication method requested"] = AUTH_TYPES[auth_code] or ("Unknown auth code " .. tostring(auth_code))

    if auth_code == 0 then
      out["Assessment"] = "CRITICAL - server granted AuthenticationOk immediately for the postgres user with no credentials supplied (trust authentication)."
    elseif auth_code == 3 then
      out["Assessment"] = "Server requests a cleartext password - credentials would be sent unencrypted unless the connection is TLS-wrapped."
    else
      out["Assessment"] = "Server requires a non-trivial authentication exchange for this user/database combination."
    end
  elseif msg_type == "E" then
    local field_data = string.sub(buf, 6)
    local message = string.match(field_data, "M([^%z]*)")
    out["Result"] = "Server returned an error instead of an authentication request."
    out["Error detail"] = message or "unavailable"
  else
    out["Result"] = "Unexpected message type '" .. tostring(msg_type) .. "' received."
  end

  return out
end
