local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Sends a recursive query (RD=1) for a domain the target server is very
unlikely to be authoritative for, and inspects whether the server sets
RA=1 and returns a resolved answer. A server that recurses on behalf
of arbitrary clients is an open resolver, which can be abused for DNS
amplification/reflection attacks and cache poisoning exposure.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.port_or_service(53, "domain", {"udp", "tcp"})

local PROBE_DOMAINS = {
  "www.iana.org", "a.root-servers.net", "www.icann.org",
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

local function parse_header(data)
  if #data < 12 then return nil end
  local flags = string.byte(data, 3) * 256 + string.byte(data, 4)
  local ra = math.floor(flags / 128) % 2
  local rcode = flags % 16
  local ancount = string.byte(data, 7) * 256 + string.byte(data, 8)
  return { ra = ra, rcode = rcode, ancount = ancount }
end

action = function(host, port)
  local out = stdnse.output_table()
  local open_evidence = {}
  local closed_evidence = {}

  for _, domain in ipairs(PROBE_DOMAINS) do
    local id = math.random(0, 65535)
    local query = build_query(id, domain, 1, 1, true)

    local socket = nmap.new_socket()
    socket:set_timeout(4000)
    local ok = socket:connect(host, port, "udp")
    if ok then
      socket:send(query)
      local status, response = socket:receive()
      socket:close()

      if status and response and #response >= 12 then
        local header = parse_header(response)
        if header then
          if header.ra == 1 and header.rcode == 0 and header.ancount > 0 then
            table.insert(open_evidence, string.format(
              "%s -> RA=1, rcode=0, %d answer(s) returned (server resolved externally)",
              domain, header.ancount
            ))
          else
            table.insert(closed_evidence, string.format(
              "%s -> RA=%d, rcode=%d, ancount=%d", domain, header.ra, header.rcode, header.ancount
            ))
          end
        end
      else
        table.insert(closed_evidence, domain .. " -> no response")
      end
    else
      socket:close()
    end
  end

  if #open_evidence > 0 then
    out["Open resolver behavior"] = "LIKELY OPEN RESOLVER - server recursed and resolved external domains for this client."
    out["Evidence"] = open_evidence
  else
    out["Open resolver behavior"] = "Not confirmed as an open resolver from this vantage point."
    out["Details"] = closed_evidence
  end

  return out
end
