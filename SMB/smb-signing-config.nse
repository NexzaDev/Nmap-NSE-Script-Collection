local smb = require "smb"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
Reports the SMB message signing configuration advertised in the
negotiate response security_mode field: whether signing is enabled,
and whether it is required. A server that allows unsigned sessions is
exposed to SMB relay attacks.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

hostrule = function(host)
  local ok, port = pcall(smb.get_port, host)
  return ok and port ~= nil
end

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

  local neg_status = pcall(smb.negotiate_protocol, state, {})
  if not neg_status then
    pcall(smb.stop, state)
    return "SMB protocol negotiation failed."
  end

  local security_mode = state and state["security_mode"]
  local dialect_name = "unknown"
  local ok_name, name = pcall(smb.get_dialect_name, state and state["dialect"])
  if ok_name and name then dialect_name = name end

  pcall(smb.stop, state)

  if not security_mode then
    out["Result"] = "Server did not return a usable security_mode field for this dialect."
    return out
  end

  out["Negotiated dialect"] = dialect_name
  out["Raw security_mode value"] = tostring(security_mode)

  local lname = string.lower(dialect_name)
  local is_smb1 = string.find(lname, "nt lm") or string.find(lname, "lanman")

  local signing_enabled, signing_required

  if is_smb1 then
    signing_enabled = has_bit(security_mode, 0x04)
    signing_required = has_bit(security_mode, 0x08)
  else
    signing_enabled = has_bit(security_mode, 0x01)
    signing_required = has_bit(security_mode, 0x02)
  end

  out["Signing enabled"] = tostring(signing_enabled)
  out["Signing required"] = tostring(signing_required)

  if not signing_enabled then
    out["Assessment"] = "Signing is not enabled - sessions are fully exposed to SMB relay attacks."
  elseif signing_enabled and not signing_required then
    out["Assessment"] = "Signing is enabled but not required - relay attacks remain possible against clients that do not enforce signing."
  else
    out["Assessment"] = "Signing is enabled and required - relay attack surface is significantly reduced."
  end

  return out
end
