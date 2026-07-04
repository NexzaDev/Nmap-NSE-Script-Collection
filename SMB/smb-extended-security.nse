local smb = require "smb"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
Checks whether the server supports SMB extended security negotiation
(SPNEGO, enabling NTLMv2 and Kerberos authentication) versus legacy
authentication only. Servers limited to legacy authentication are
restricted to weaker LM/NTLMv1 mechanisms.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

hostrule = function(host)
  local ok, port = pcall(smb.get_port, host)
  return ok and port ~= nil
end

local EXTENDED_SECURITY_BIT = 0x80000000

local function has_bit(value, mask)
  if not value then return false end
  local a, b = value, mask
  local result = 0
  local bitval = 1
  while a > 0 or b > 0 do
    if (a % 2 == 1) and (b % 2 == 1) then
      result = result + bitval
    end
    a = math.floor(a / 2)
    b = math.floor(b / 2)
    bitval = bitval * 2
  end
  return result > 0
end

action = function(host)
  local out = stdnse.output_table()

  local status, state = pcall(smb.start, host)
  if not status or not state then
    return "Could not open an SMB connection to this host."
  end

  local neg_status = pcall(smb.negotiate_protocol, state, { request_extended_security = true })
  if not neg_status then
    pcall(smb.stop, state)
    return "SMB protocol negotiation failed."
  end

  local capabilities = state and state["capabilities"]
  local extended_flag_field = state and state["extended_security"]
  pcall(smb.stop, state)

  local supports_extended = false
  local determination_method = ""

  if extended_flag_field ~= nil then
    supports_extended = (extended_flag_field == true or extended_flag_field == 1)
    determination_method = "state.extended_security field"
  elseif capabilities then
    supports_extended = has_bit(capabilities, EXTENDED_SECURITY_BIT)
    determination_method = "capabilities bitfield"
  else
    out["Result"] = "Could not determine extended security support from this response."
    return out
  end

  out["Determined via"] = determination_method
  out["Extended security (SPNEGO/NTLMv2) supported"] = tostring(supports_extended)

  if supports_extended then
    out["Assessment"] = "Server supports modern authentication negotiation (NTLMv2/Kerberos via SPNEGO)."
  else
    out["Assessment"] = "Server did not advertise extended security - may be restricted to legacy LM/NTLMv1 authentication, which is significantly weaker."
  end

  return out
end
