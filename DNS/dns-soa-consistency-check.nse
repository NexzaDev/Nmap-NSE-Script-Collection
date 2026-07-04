local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Queries the SOA record for a domain supplied via script-arg and
reports its serial, refresh, retry, expire and minimum values,
flagging parameter combinations that fall outside commonly recommended
ranges (e.g. refresh shorter than retry, very long expire times, or a
very low negative-caching minimum).
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(53, "domain", {"udp", "tcp"})

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

local function build_query(id, qname, qtype, qclass, rd)
  local flags = rd and 0x0100 or 0x0000
  local header = u16(id) .. u16(flags) .. u16(1) .. u16(0) .. u16(0) .. u16(0)
  local question = encode_name(qname) .. u16(qtype) .. u16(qclass)
  return header .. question
end

local function read_name(data, pos, depth)
  depth = depth or 0
  if depth > 10 then return "", pos end
  local labels = {}
  while true do
    local len = string.byte(data, pos)
    if not len then break end
    if len == 0 then
      pos = pos + 1
      break
    elseif len >= 0xC0 then
      local b2 = string.byte(data, pos + 1)
      local ptr = (len - 0xC0) * 256 + b2
      local sub = read_name(data, ptr + 1, depth + 1)
      table.insert(labels, sub)
      pos = pos + 2
      break
    else
      table.insert(labels, string.sub(data, pos + 1, pos + len))
      pos = pos + 1 + len
    end
  end
  return table.concat(labels, "."), pos
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

local function read_u32(data, pos)
  return string.byte(data, pos) * 16777216 + string.byte(data, pos + 1) * 65536
       + string.byte(data, pos + 2) * 256 + string.byte(data, pos + 3)
end

local function parse_header(data)
  if #data < 12 then return nil end
  local flags = string.byte(data, 3) * 256 + string.byte(data, 4)
  local rcode = flags % 16
  local ancount = string.byte(data, 7) * 256 + string.byte(data, 8)
  return { rcode = rcode, ancount = ancount }
end

local function find_soa(data, pos, count)
  for i = 1, count do
    pos = skip_name(data, pos)
    if not pos or pos + 10 > #data + 1 then break end
    local rtype = string.byte(data, pos) * 256 + string.byte(data, pos + 1)
    local rdlen = string.byte(data, pos + 8) * 256 + string.byte(data, pos + 9)
    local rdata_pos = pos + 10
    if rtype == 6 then
      local mname, p2 = read_name(data, rdata_pos)
      local rname, p3 = read_name(data, p2)
      local serial = read_u32(data, p3)
      local refresh = read_u32(data, p3 + 4)
      local retry = read_u32(data, p3 + 8)
      local expire = read_u32(data, p3 + 12)
      local minimum = read_u32(data, p3 + 16)
      return {
        mname = mname, rname = rname, serial = serial,
        refresh = refresh, retry = retry, expire = expire, minimum = minimum,
      }
    end
    pos = rdata_pos + rdlen
  end
  return nil
end

local function evaluate_soa(soa)
  local issues = {}
  if soa.retry >= soa.refresh then
    table.insert(issues, string.format(
      "retry (%d) is >= refresh (%d); secondary servers may retry too infrequently relative to refresh", soa.retry, soa.refresh
    ))
  end
  if soa.expire < soa.refresh * 2 then
    table.insert(issues, string.format(
      "expire (%d) is less than twice refresh (%d); secondaries may expire the zone too quickly during an outage", soa.expire, soa.refresh
    ))
  end
  if soa.minimum < 60 then
    table.insert(issues, string.format(
      "minimum/negative-cache TTL (%d) is very low, increasing load from repeated NXDOMAIN lookups", soa.minimum
    ))
  end
  if soa.minimum > 86400 then
    table.insert(issues, string.format(
      "minimum/negative-cache TTL (%d) is very high (>24h), slowing propagation of newly created records", soa.minimum
    ))
  end
  if soa.refresh < 1200 then
    table.insert(issues, string.format(
      "refresh (%d) is quite low (<20 min), causing frequent unnecessary zone transfer checks", soa.refresh
    ))
  end
  return issues
end

action = function(host, port)
  local domain = stdnse.get_script_args(SCRIPT_NAME .. ".domain") or host.targetname
  if not domain then
    return "No domain specified. Set with --script-args " .. SCRIPT_NAME .. ".domain=example.com"
  end

  local id = math.random(0, 65535)
  local query = build_query(id, domain, 6, 1, true)

  local socket = nmap.new_socket()
  socket:set_timeout(4000)
  local ok = socket:connect(host, port, "udp")
  if not ok then
    socket:close()
    return "Could not establish a UDP connection to query the SOA record."
  end

  socket:send(query)
  local status, response = socket:receive()
  socket:close()

  if not status or not response or #response < 12 then
    return "No response received for SOA query."
  end

  local header = parse_header(response)
  if not header or header.rcode ~= 0 or header.ancount == 0 then
    return string.format("SOA query for '%s' returned rcode=%s, no usable SOA record.", domain, header and tostring(header.rcode) or "?")
  end

  local qend = skip_name(response, 13) + 4
  local soa = find_soa(response, qend, header.ancount)

  if not soa then
    return "SOA record could not be parsed from the response."
  end

  local out = stdnse.output_table()
  out["Domain tested"] = domain
  out["Primary nameserver (MNAME)"] = soa.mname
  out["Responsible party (RNAME)"] = soa.rname
  out["Serial"] = tostring(soa.serial)
  out["Refresh (seconds)"] = tostring(soa.refresh)
  out["Retry (seconds)"] = tostring(soa.retry)
  out["Expire (seconds)"] = tostring(soa.expire)
  out["Minimum/negative-cache TTL (seconds)"] = tostring(soa.minimum)

  local issues = evaluate_soa(soa)
  if #issues > 0 then
    out["Parameter concerns"] = issues
  else
    out["Parameter concerns"] = "SOA parameters fall within commonly recommended ranges."
  end

  return out
end
