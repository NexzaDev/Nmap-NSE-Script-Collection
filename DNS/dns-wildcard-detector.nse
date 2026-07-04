local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Queries several randomly generated subdomain labels under a domain
supplied via script-arg. If most or all random, non-existent labels
resolve to an IP address, the zone is using a wildcard DNS record,
which significantly affects the reliability of subdomain enumeration
results and can itself be a misconfiguration.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(53, "domain", {"udp", "tcp"})

local CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789"

local function random_label(length)
  local chars = {}
  for i = 1, length do
    local idx = math.random(1, #CHARSET)
    table.insert(chars, string.sub(CHARSET, idx, idx))
  end
  return table.concat(chars)
end

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

local function first_a_record(data, pos, count)
  for i = 1, count do
    pos = skip_name(data, pos)
    if not pos or pos + 10 > #data + 1 then break end
    local rtype = string.byte(data, pos) * 256 + string.byte(data, pos + 1)
    local rdlen = string.byte(data, pos + 8) * 256 + string.byte(data, pos + 9)
    local rdata_pos = pos + 10
    if rtype == 1 and rdlen == 4 then
      return string.format(
        "%d.%d.%d.%d",
        string.byte(data, rdata_pos), string.byte(data, rdata_pos + 1),
        string.byte(data, rdata_pos + 2), string.byte(data, rdata_pos + 3)
      )
    end
    pos = rdata_pos + rdlen
  end
  return nil
end

action = function(host, port)
  local domain = stdnse.get_script_args(SCRIPT_NAME .. ".domain") or host.targetname
  if not domain then
    return "No domain specified. Set with --script-args " .. SCRIPT_NAME .. ".domain=example.com"
  end

  local out = stdnse.output_table()
  local resolved = {}
  local unresolved_count = 0
  local resolved_ips = {}

  for i = 1, 5 do
    local label = random_label(12)
    local qname = label .. "." .. domain
    local id = math.random(0, 65535)
    local query = build_query(id, qname, 1, 1, true)

    local socket = nmap.new_socket()
    socket:set_timeout(4000)
    local ok = socket:connect(host, port, "udp")
    if ok then
      socket:send(query)
      local status, response = socket:receive()
      socket:close()

      if status and response and #response >= 12 then
        local header = parse_header(response)
        if header and header.rcode == 0 and header.ancount > 0 then
          local qend = skip_name(response, 13) + 4
          local ip = first_a_record(response, qend, header.ancount)
          table.insert(resolved, qname .. " -> " .. (ip or "resolved, non-A answer"))
          if ip then
            resolved_ips[ip] = true
          end
        else
          unresolved_count = unresolved_count + 1
        end
      else
        unresolved_count = unresolved_count + 1
      end
    else
      socket:close()
    end
  end

  out["Domain tested"] = domain
  out["Random labels resolved"] = tostring(#resolved) .. " of 5"

  if #resolved >= 3 then
    out["Result"] = "WILDCARD DNS DETECTED - most random subdomains resolved successfully."
    out["Resolved examples"] = resolved
    local distinct_ips = {}
    for ip in pairs(resolved_ips) do table.insert(distinct_ips, ip) end
    if #distinct_ips > 0 then
      out["Wildcard target IP(s)"] = distinct_ips
    end
  else
    out["Result"] = "No wildcard DNS pattern detected; subdomain enumeration results should be reliable."
  end

  return out
end
