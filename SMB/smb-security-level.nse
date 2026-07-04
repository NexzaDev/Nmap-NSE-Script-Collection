local smb = require "smb"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
For SMB1 (NT LM 0.12) negotiations, reports whether the server uses
user-level or share-level security and whether it accepts plaintext
passwords instead of challenge/response authentication. Not
applicable to SMB2/3, which always use user-level security.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

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

  local dialect_name = "unknown"
  local ok_name, name = pcall(smb.get_dialect_name, state and state["dialect"])
  if ok_name and name then dialect_name = name end

  local security_mode = state and state["security_mode"]
  pcall(smb.stop, state)

  local lname = string.lower(dialect_name)
  local is_smb1 = string.find(lname, "nt lm") or string.find(lname, "lanman")

  out["Negotiated dialect"] = dialect_name

  if not is_smb1 then
    out["Result"] = "Not applicable - negotiated dialect is SMB2/3, which always uses user-level security."
    return out
  end

  if not security_mode then
    out["Result"] = "Server did not return a usable security_mode field."
    return out
  end

  local user_level = has_bit(security_mode, 0x01)
  local encrypt_passwords = has_bit(security_mode, 0x02)

  out["Security level"] = user_level and "User-level security" or "Share-level security"
  out["Password authentication"] = encrypt_passwords and "Challenge/response (encrypted)" or "Plaintext passwords accepted"

  if not encrypt_passwords then
    out["Assessment"] = "Server accepts plaintext passwords over SMB1 - credentials can be captured in transit."
  else
    out["Assessment"] = "Server requires challenge/response authentication for SMB1."
  end

  return out
end
