local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Queries a set of common SRV record names under a domain supplied via
script-arg to enumerate advertised internal/external services such as
SIP, LDAP, Kerberos, Autodiscover and XMPP, which can reveal internal
network topology and technology choices to an external observer.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(53, "domain", {"udp", "tcp"})

local SRV_NAMES = {
  "_sip._tcp", "_sip._udp", "_sips._tcp", "_ldap._tcp",
  "_kerberos._tcp", "_kerberos._udp", "_kpasswd._tcp",
  "_xmpp-client._tcp", "_xmpp-server._tcp", "_autodiscover._tcp",
  "_caldav._tcp", "_caldavs._tcp", "_carddav._tcp", "_imap._tcp",
  "_imaps._tcp", "_submission._tcp", "_pop3._tcp", "_pop3s._tcp",
  "_ntp._udp", "_ftp._tcp", "_h323cs._tcp", "_matrix._tcp",
  "_minecraft._tcp", "_stun._udp", "_turn._udp",
}

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

local function parse_header(data)
  if #data < 12 then return nil end
  local flags = string.byte(data, 3) * 256 + string.byte(data, 4)
  local rcode = flags % 16
  local ancount = string.byte(data, 7) * 256 + string.byte(data, 8)
  return { rcode = rcode, ancount = ancount }
end

local function collect_srv_records(data, pos, count)
  local records = {}
  for i = 1, count do
    pos = skip_name(data, pos)
    if not pos or pos + 10 > #data + 1 then break end
    local rtype = string.byte(data, pos) * 256 + string.byte(data, pos + 1)
    local rdlen = string.byte(data, pos + 8) * 256 + string.byte(data, pos + 9)
    local rdata_pos = pos + 10
    if rtype == 33 and rdlen >= 6 then
      local priority = string.byte(data, rdata_pos) * 256 + string.byte(data, rdata_pos + 1)
      local weight = string.byte(data, rdata_pos + 2) * 256 + string.byte(data, rdata_pos + 3)
      local srv_port = string.byte(data, rdata_pos + 4) * 256 + string.byte(data, rdata_pos + 5)
      local target = read_name(data, rdata_pos + 6)
      table.insert(records, {
        priority = priority, weight = weight, port = srv_port, target = target,
      })
    end
    pos = rdata_pos + rdlen
  end
  return records
end

action = function(host, port)
  local domain = stdnse.get_script_args(SCRIPT_NAME .. ".domain") or host.targetname
  if not domain then
    return "No domain specified. Set with --script-args " .. SCRIPT_NAME .. ".domain=example.com"
  end

  local out = stdnse.output_table()
  local found = {}

  for _, srv_name in ipairs(SRV_NAMES) do
    local qname = srv_name .. "." .. domain
    local id = math.random(0, 65535)
    local query = build_query(id, qname, 33, 1, true)

    local socket = nmap.new_socket()
    socket:set_timeout(3000)
    local ok = socket:connect(host, port, "udp")
    if ok then
      socket:send(query)
      local status, response = socket:receive()
      socket:close()

      if status and response and #response >= 12 then
        local header = parse_header(response)
        if header and header.rcode == 0 and header.ancount > 0 then
          local qend = skip_name(response, 13) + 4
          local records = collect_srv_records(response, qend, header.ancount)
          for _, rec in ipairs(records) do
            table.insert(found, string.format(
              "%s -> target=%s port=%d priority=%d weight=%d",
              qname, rec.target, rec.port, rec.priority, rec.weight
            ))
          end
        end
      end
    else
      socket:close()
    end
  end

  out["Domain tested"] = domain
  out["SRV names tried"] = tostring(#SRV_NAMES)

  if #found > 0 then
    out["SRV records found"] = found
  else
    out["SRV records found"] = "None of the tested SRV names resolved."
  end

  return out
end
