local smb = require "smb"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Attempts to establish an SMB session using the built-in "guest"
account with a blank password. Reports whether guest access is
permitted, which can expose shares and files not intended for
unauthenticated users if guest access is not properly restricted.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

hostrule = function(host)
  local ok, port = pcall(smb.get_port, host)
  return ok and port ~= nil
end

action = function(host)
  local out = stdnse.output_table()

  local status, state = pcall(smb.start, host)
  if not status or not state then
    return "Could not open an SMB connection to this host."
  end

  local neg_status = pcall(smb.negotiate_protocol, state, {})
  if not neg_status then
    pcall(smb.stop, state)
    return "SMB protocol negotiation failed."
  end

  local session_ok, session_err = pcall(smb.start_session, state, {
    username = "guest",
    password = "",
    domain = "",
  })

  local success = false
  if session_ok then
    if type(session_err) == "boolean" then
      success = session_err
    else
      success = true
    end
  end

  pcall(smb.stop, state)

  if not session_ok then
    out["Guest session established"] = "Could not be determined - session setup call failed unexpectedly."
    return out
  end

  out["Guest session established"] = tostring(success)

  if success then
    out["Assessment"] = "Guest account access is permitted with a blank password - review which shares/resources guest can reach."
  else
    out["Assessment"] = "Guest account access was rejected."
  end

  return out
end
