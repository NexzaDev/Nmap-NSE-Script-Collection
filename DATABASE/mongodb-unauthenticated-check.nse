local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Sends an OP_MSG "hello" (legacy alias "isMaster") command to a
MongoDB instance without authenticating and inspects the BSON
response for maxWireVersion and the isWritablePrimary/ismaster fields
to determine whether unauthenticated command execution is permitted.
This constructs and parses BSON by hand; treat results as best-effort
and verify manually against unusual deployments.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.port_or_service(27017, "mongodb")

local function u32le(n)
  return string.char(
    n % 256,
    math.floor(n / 256) % 256,
    math.floor(n / 65536) % 256,
    math.floor(n / 16777216) % 256
  )
end

local function bson_int32_element(name, value)
  return string.char(0x10) .. name .. "\0" .. u32le(value)
end

local function bson_string_element(name, value)
  local data = value .. "\0"
  return string.char(0x02) .. name .. "\0" .. u32le(#data) .. data
end

local function build_bson_document(elements)
  local body = table.concat(elements)
  local total_len = 4 + #body + 1
  return u32le(total_len) .. body .. "\0"
end

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

local function read_le_uint32(data, pos)
  return string.byte(data, pos) + string.byte(data, pos + 1) * 256
    + string.byte(data, pos + 2) * 65536 + string.byte(data, pos + 3) * 16777216
end

local TYPE_FIXED_LEN = {
  [0x01] = 8, [0x07] = 12, [0x08] = 1, [0x09] = 8,
  [0x0A] = 0, [0x10] = 4, [0x11] = 8, [0x12] = 8, [0x13] = 16,
}

local function skip_bson_element(data, pos, etype)
  if etype == 0x02 or etype == 0x0D or etype == 0x0E then
    local len = read_le_uint32(data, pos)
    return pos + 4 + len
  elseif etype == 0x03 or etype == 0x04 then
    local len = read_le_uint32(data, pos)
    return pos + len
  elseif etype == 0x05 then
    local len = read_le_uint32(data, pos)
    return pos + 4 + 1 + len
  elseif TYPE_FIXED_LEN[etype] ~= nil then
    return pos + TYPE_FIXED_LEN[etype]
  else
    return nil
  end
end

local function parse_bson_top_level(data)
  local results = {}
  if #data < 5 then return results end
  local pos = 5
  while pos < #data do
    local etype = string.byte(data, pos)
    if etype == 0x00 then break end
    pos = pos + 1
    local nul = string.find(data, "\0", pos, true)
    if not nul then break end
    local name = string.sub(data, pos, nul - 1)
    pos = nul + 1

    if etype == 0x08 then
      local val = string.byte(data, pos)
      results[name] = (val == 1)
      pos = pos + 1
    elseif etype == 0x10 then
      results[name] = read_le_uint32(data, pos)
      pos = pos + 4
    elseif etype == 0x02 then
      local len = read_le_uint32(data, pos)
      results[name] = string.sub(data, pos + 4, pos + 4 + len - 2)
      pos = pos + 4 + len
    else
      local newpos = skip_bson_element(data, pos, etype)
      if not newpos then break end
      pos = newpos
    end
  end
  return results
end

action = function(host, port)
  local out = stdnse.output_table()

  local socket = nmap.new_socket()
  socket:set_timeout(6000)
  local ok = socket:connect(host, port, "tcp")
  if not ok then
    socket:close()
    return "Could not establish a TCP connection to the MongoDB service."
  end

  local cmd_doc = build_bson_document({
    bson_int32_element("hello", 1),
    bson_string_element("$db", "admin"),
  })

  local section = string.char(0x00) .. cmd_doc
  local body = u32le(0) .. section
  local message_length = 16 + #body
  local header = u32le(message_length) .. u32le(1) .. u32le(0) .. u32le(2013)
  local full_message = header .. body

  local sent = socket:send(full_message)
  if not sent then
    socket:close()
    return "Failed to send the hello command."
  end

  local buf = ""
  local ok2
  ok2, buf = pcall(function() return recv_atleast(socket, buf, 16) end)
  if not ok2 or not buf or #buf < 16 then
    socket:close()
    return "No usable response header received."
  end

  local resp_len = read_le_uint32(buf, 1)

  local ok3
  ok3, buf = pcall(function() return recv_atleast(socket, buf, resp_len) end)
  socket:close()

  if not ok3 or not buf or #buf < resp_len then
    return "Response truncated before it could be fully read."
  end

  local body_data = string.sub(buf, 17)
  local flag_bits = read_le_uint32(body_data, 1)
  local doc_data = string.sub(body_data, 6)

  local fields = parse_bson_top_level(doc_data)

  if fields["ismaster"] ~= nil or fields["isWritablePrimary"] ~= nil or fields["maxWireVersion"] ~= nil then
    out["Unauthenticated hello/isMaster accepted"] = "true"
    if fields["maxWireVersion"] then
      out["maxWireVersion"] = tostring(fields["maxWireVersion"])
    end
    if fields["ismaster"] ~= nil then
      out["ismaster"] = tostring(fields["ismaster"])
    end
    if fields["isWritablePrimary"] ~= nil then
      out["isWritablePrimary"] = tostring(fields["isWritablePrimary"])
    end
    out["Assessment"] = "Server processed an unauthenticated hello/isMaster command. Confirm separately whether unauthenticated data-bearing commands (find, etc.) are also permitted, since some deployments allow the handshake but enforce auth afterward."
  else
    out["Unauthenticated hello/isMaster accepted"] = "Could not confirm from parsed fields - response may use an unexpected structure."
  end

  return out
end
