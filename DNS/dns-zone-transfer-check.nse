local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Attempts a full zone transfer (AXFR) against the target DNS server for
a domain supplied via script-arg. A successful transfer indicates the
server is misconfigured to allow unauthenticated zone transfers,
exposing the complete set of records for the zone to any client.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.port_or_service(53, "domain", {"tcp", "udp"})

local function u16(n)
  return string.char(math.floor(n / 256) % 256, n % 256)
end

local function encode_name(name)
  local encoded = ""
  for label in string.gmatch(name, "[^%.]+") do
    encoded = encoded .. string.char(#label) .. label
  end
  return encoded .. string.char(0)
end

local function build_query(id, qname, qtype, qclass)
  local flags = 0x0000
  local header = u16(id) .. u16(flags) .. u16(1) .. u16(0) .. u16(0) .. u16(0)
  local question = encode_name(qname) .. u16(qtype) .. u16(qclass)
  return header .. question
end

local function read_u32(data, pos)
  return string.byte(data, pos) * 16777216 + string.byte(data, pos + 1) * 65536
       + string.byte(data, pos + 2) * 256 + string.byte(data, pos + 3)
end

local function skip_name(data, pos)
  while true do
    local len = string.byte(data, pos)
    if not len then return pos end
    if len == 0 then
      return pos + 1
    elseif len >= 0xC0 then
      return pos + 2
    else
      pos = pos + 1 + len
    end
  end
end

local function parse_header(data)
  if #data < 12 then return nil end
  local flags = string.byte(data, 3) * 256 + string.byte(data, 4)
  local rcode = flags % 16
  local ancount = string.byte(data, 7) * 256 + string.byte(data, 8)
  return { rcode = rcode, ancount = ancount }
end

local function count_answer_types(data, pos, count)
  local types = {}
  for i = 1, count do
    pos = skip_name(data, pos)
    if not pos or pos + 10 > #data + 1 then break end
    local rtype = string.byte(data, pos) * 256 + string.byte(data, pos + 1)
    local rdlen = string.byte(data, pos + 8) * 256 + string.byte(data, pos + 9)
    types[rtype] = (types[rtype] or 0) + 1
    pos = pos + 10 + rdlen
  end
  return types
end

local TYPE_NAMES = {
  [1] = "A", [2] = "NS", [5] = "CNAME", [6] = "SOA", [12] = "PTR",
  [15] = "MX", [16] = "TXT", [28] = "AAAA", [33] = "SRV",
}

action = function(host, port)
  local domain = stdnse.get_script_args(SCRIPT_NAME .. ".domain") or host.targetname

  if not domain then
    return "No domain specified. Set with --script-args " .. SCRIPT_NAME .. ".domain=example.com"
  end

  local id = math.random(0, 65535)
  local query = build_query(id, domain, 252, 1)
  local length_prefixed = u16(#query) .. query

  local socket = nmap.new_socket()
  socket:set_timeout(6000)
  local ok = socket:connect(host, port, "tcp")
  if not ok then
    socket:close()
    return "Could not establish a TCP connection to attempt the zone transfer."
  end

  local sent = socket:send(length_prefixed)
  if not sent then
    socket:close()
    return "Failed to send AXFR query."
  end

  local status1, len_bytes = socket:receive_bytes(2)
  if not status1 or #len_bytes < 2 then
    socket:close()
    return string.format("No response received for AXFR query against domain '%s' (likely refused or connection closed).", domain)
  end

  local msg_len = string.byte(len_bytes, 1) * 256 + string.byte(len_bytes, 2)
  local buf = string.sub(len_bytes, 3)
  while #buf < msg_len do
    local status2, more = socket:receive_bytes(msg_len - #buf)
    if not status2 then break end
    buf = buf .. more
  end
  socket:close()

  local header = parse_header(buf)
  if not header then
    return "Received a malformed response to the AXFR query."
  end

  local out = stdnse.output_table()
  out["Domain tested"] = domain
  out["DNS response code"] = tostring(header.rcode)

  if header.rcode ~= 0 then
    out["Result"] = "Zone transfer REFUSED or errored (rcode=" .. tostring(header.rcode) .. "). Server appears correctly configured."
    return out
  end

  if header.ancount == 0 then
    out["Result"] = "Server returned rcode=0 but no answer records; zone transfer likely not permitted."
    return out
  end

  local qend = skip_name(buf, 13) + 4
  local types = count_answer_types(buf, qend, header.ancount)
  local type_summary = {}
  for tcode, cnt in pairs(types) do
    table.insert(type_summary, (TYPE_NAMES[tcode] or ("TYPE" .. tostring(tcode))) .. ": " .. tostring(cnt))
  end

  out["Result"] = string.format(
    "ZONE TRANSFER SUCCEEDED - %d record(s) returned in first response message. This is a misconfiguration.",
    header.ancount
  )
  out["Record types observed (first message only)"] = type_summary

  return out
end
