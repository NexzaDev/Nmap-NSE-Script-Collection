local smb = require "smb"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
Decodes the capability flags returned in the SMB negotiate response
(raw mode, unicode, large files, NT SMBs, DFS, extended security,
Unix extensions, compression, persistent handles, and others) into a
readable list to aid in fingerprinting server functionality and
identifying legacy or unusual configurations.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

hostrule = function(host)
  local ok, port = pcall(smb.get_port, host)
  return ok and port ~= nil
end

local CAPABILITY_FLAGS = {
  { mask = 0x00000001, label = "Raw mode supported" },
  { mask = 0x00000002, label = "MPX mode supported" },
  { mask = 0x00000004, label = "Unicode strings supported" },
  { mask = 0x00000008, label = "Large files supported" },
  { mask = 0x00000010, label = "NT SMBs supported" },
  { mask = 0x00000020, label = "RPC remote APIs supported" },
  { mask = 0x00000040, label = "NT-style status codes (STATUS32)" },
  { mask = 0x00000080, label = "Level II oplocks supported" },
  { mask = 0x00000100, label = "Lock-and-read supported" },
  { mask = 0x00000200, label = "NT find supported" },
  { mask = 0x00001000, label = "DFS supported" },
  { mask = 0x00002000, label = "Info level passthru supported" },
  { mask = 0x00004000, label = "Large ReadX supported" },
  { mask = 0x00008000, label = "Large WriteX supported" },
  { mask = 0x00010000, label = "LWIO supported" },
  { mask = 0x00800000, label = "Unix extensions supported" },
  { mask = 0x02000000, label = "Compressed data supported" },
  { mask = 0x20000000, label = "Dynamic reauthentication supported" },
  { mask = 0x40000000, label = "Persistent handles supported" },
  { mask = 0x80000000, label = "Extended security (SPNEGO/NTLMv2) supported" },
}

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

  local capabilities = state and state["capabilities"]
  pcall(smb.stop, state)

  if not capabilities then
    out["Result"] = "Server did not return a usable capabilities field for this dialect."
    return out
  end

  out["Raw capabilities value"] = tostring(capabilities)

  local active = {}
  for _, flag in ipairs(CAPABILITY_FLAGS) do
    if has_bit(capabilities, flag.mask) then
      table.insert(active, flag.label)
    end
  end

  if #active > 0 then
    out["Active capabilities"] = active
  else
    out["Active capabilities"] = "None of the known capability flags were set (or dialect does not expose this field)."
  end

  return out
end
