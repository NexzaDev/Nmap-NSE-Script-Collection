local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Sends a small ANY-type query for a domain supplied via script-arg and
compares the size of the query sent against the size of the response
received to estimate the amplification factor. Resolvers that return
a response many times larger than the request can be abused as
reflectors in DNS amplification denial-of-service attacks.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

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

local function parse_header(data)
  if #data < 12 then return nil end
  local flags = string.byte(data, 3) * 256 + string.byte(data, 4)
  local rcode = flags % 16
  local ancount = string.byte(data, 7) * 256 + string.byte(data, 8)
  return { rcode = rcode, ancount = ancount }
end

local QUERY_TYPES = {
  { label = "ANY", code = 255 },
  { label = "TXT", code = 16 },
  { label = "DNSKEY", code = 48 },
}

action = function(host, port)
  local domain = stdnse.get_script_args(SCRIPT_NAME .. ".domain") or host.targetname
  if not domain then
    return "No domain specified. Set with --script-args " .. SCRIPT_NAME .. ".domain=example.com"
  end

  local out = stdnse.output_table()
  local results = {}
  local max_factor = 0

  for _, qt in ipairs(QUERY_TYPES) do
    local id = math.random(0, 65535)
    local query = build_query(id, domain, qt.code, 1, true)

    local socket = nmap.new_socket()
    socket:set_timeout(4000)
    local ok = socket:connect(host, port, "udp")
    if ok then
      socket:send(query)
      local status, response = socket:receive()
      socket:close()

      if status and response then
        local header = parse_header(response)
        local ancount = header and header.ancount or 0
        local factor = #response / #query
        if factor > max_factor then
          max_factor = factor
        end
        table.insert(results, string.format(
          "%s query -> request %d bytes, response %d bytes, factor %.1fx, %d answer(s)",
          qt.label, #query, #response, factor, ancount
        ))
      else
        table.insert(results, qt.label .. " query -> no response (query type likely blocked/unsupported)")
      end
    else
      socket:close()
    end
  end

  out["Domain tested"] = domain
  out["Amplification probe results"] = results
  out["Largest observed amplification factor"] = string.format("%.1fx", max_factor)

  if max_factor >= 10 then
    out["Risk assessment"] = "HIGH - this server can be abused as a significant DNS amplification reflector."
  elseif max_factor >= 3 then
    out["Risk assessment"] = "MODERATE - some amplification potential observed."
  else
    out["Risk assessment"] = "LOW - limited amplification potential observed in this probe."
  end

  return out
end
