local smb = require "smb"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
Reports the buffer and transaction size limits negotiated during the
SMB handshake (max buffer size, max multiplex count, max raw size,
max transaction size where available). Useful recon context and can
highlight unusually restrictive or permissive server tuning.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

hostrule = function(host)
  local ok, port = pcall(smb.get_port, host)
  return ok and port ~= nil
end

local FIELDS_OF_INTEREST = {
  { key = "max_buffer_size", label = "Max buffer size" },
  { key = "max_mpx_count", label = "Max multiplexed pending requests" },
  { key = "max_raw_size", label = "Max raw size" },
  { key = "max_transact_size", label = "Max transaction size" },
  { key = "session_key", label = "Session key present" },
}

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

  local reported = {}
  local any_found = false

  for _, field in ipairs(FIELDS_OF_INTEREST) do
    local value = state and state[field.key]
    if value ~= nil then
      any_found = true
      reported[field.label] = tostring(value)
    end
  end

  pcall(smb.stop, state)

  out["Negotiated dialect"] = dialect_name

  if any_found then
    local lines = {}
    for label, value in pairs(reported) do
      table.insert(lines, label .. ": " .. value)
    end
    table.sort(lines)
    out["Negotiated limits"] = lines
  else
    out["Negotiated limits"] = "No buffer/transaction size fields were exposed for this dialect/response."
  end

  return out
end
