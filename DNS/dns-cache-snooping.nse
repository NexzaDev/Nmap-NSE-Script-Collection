local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Performs non-recursive queries (RD=0) for a list of popular domains
against the target resolver. A non-recursive query only succeeds if
the answer is already present in the resolver's cache, so a positive
answer reveals that some other client recently resolved that domain
through this server - a cache snooping information disclosure issue.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.port_or_service(53, "domain", {"udp", "tcp"})

local PROBE_DOMAINS = {
  "google.com", "facebook.com", "youtube.com", "amazon.com",
  "microsoft.com", "apple.com", "netflix.com", "instagram.com",
  "twitter.com", "linkedin.com", "wikipedia.org", "paypal.com",
  "github.com", "dropbox.com", "zoom.us", "slack.com",
  "salesforce.com", "office.com", "gmail.com", "whatsapp.com",
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
  local aa = math.floor(flags / 1024) % 2
  local rcode = flags % 16
  local ancount = string.byte(data, 7) * 256 + string.byte(data, 8)
  return { aa = aa, rcode = rcode, ancount = ancount }
end

action = function(host, port)
  local out = stdnse.output_table()
  local cached_hits = {}
  local not_cached = {}

  for _, domain in ipairs(PROBE_DOMAINS) do
    local id = math.random(0, 65535)
    local query = build_query(id, domain, 1, 1, false)

    local socket = nmap.new_socket()
    socket:set_timeout(3000)
    local ok = socket:connect(host, port, "udp")
    if ok then
      socket:send(query)
      local status, response = socket:receive()
      socket:close()

      if status and response and #response >= 12 then
        local header = parse_header(response)
        if header and header.rcode == 0 and header.ancount > 0 and header.aa == 0 then
          table.insert(cached_hits, domain .. " -> answer returned without recursion (cached)")
        else
          table.insert(not_cached, domain)
        end
      else
        table.insert(not_cached, domain)
      end
    else
      socket:close()
    end
  end

  out["Domains tested"] = tostring(#PROBE_DOMAINS)

  if #cached_hits > 0 then
    out["Cache snooping possible - cached domains detected"] = cached_hits
    out["Risk"] = "Other clients' browsing patterns can be partially inferred by any user of this resolver."
  else
    out["Cache snooping possible - cached domains detected"] = "None of the tested domains returned a non-recursive cached answer."
  end

  return out
end
