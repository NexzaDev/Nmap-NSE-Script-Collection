local smb = require "smb"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
Negotiates the SMB protocol and reports which dialect the server
selected (SMBv1 "NT LM 0.12" through SMB 3.1.1). Flags SMBv1 as a
deprecated, legacy dialect that should be disabled on modern systems.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

hostrule = function(host)
  local ok, port = pcall(smb.get_port, host)
  return ok and port ~= nil
end

local function safe_dialect_name(dialect)
  if not dialect then return "unknown" end
  local ok, name = pcall(smb.get_dialect_name, dialect)
  if ok and name then
    return name
  end
  return tostring(dialect)
end

action = function(host)
  local out = stdnse.output_table()

  local status, state = pcall(smb.start, host)
  if not status or not state then
    return "Could not open an SMB connection to this host."
  end

  local neg_status, neg_err = pcall(smb.negotiate_protocol, state, {})
  if not neg_status then
    pcall(smb.stop, state)
    return "SMB protocol negotiation failed or the smb library call signature differs from what this script expects."
  end

  local dialect = state and state["dialect"]
  local dialect_name = safe_dialect_name(dialect)

  out["Negotiated dialect"] = dialect_name

  local lname = string.lower(dialect_name)
  if string.find(lname, "nt lm") or string.find(lname, "lanman") or string.find(lname, "smbv1") or string.find(lname, "1%.0") then
    out["Assessment"] = "SMBv1 negotiated - this dialect is deprecated and should be disabled (associated with legacy worm-class vulnerabilities such as EternalBlue/WannaCry)."
  elseif string.find(lname, "2%.") then
    out["Assessment"] = "SMBv2 negotiated - acceptable on most modern networks, prefer SMBv3 where available."
  elseif string.find(lname, "3%.") then
    out["Assessment"] = "SMBv3 negotiated - current recommended dialect family."
  else
    out["Assessment"] = "Dialect family could not be classified from the reported name."
  end

  pcall(smb.stop, state)
  return out
end
