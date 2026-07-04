local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local nmap = require "nmap"

description = [[
Queries TXT records at the domain root for an SPF policy and at
_dmarc.<domain> for a DMARC policy, then evaluates the strength of
each: SPF mechanisms ending in a permissive "all" qualifier, and
DMARC policies set to "none" or missing entirely, both of which
weaken protection against email spoofing.
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

local function parse_txt_rdata(rdata)
  local out = ""
  local p = 1
  while p <= #rdata do
    local len = string.byte(rdata, p)
    if not len then break end
    out = out .. string.sub(rdata, p + 1, p + len)
    p = p + 1 + len
  end
  return out
end

local function collect_txt_records(data, pos, count)
  local records = {}
  for i = 1, count do
    pos = skip_name(data, pos)
    if not pos or pos + 10 > #data + 1 then break end
    local rtype = string.byte(data, pos) * 256 + string.byte(data, pos + 1)
    local rdlen = string.byte(data, pos + 8) * 256 + string.byte(data, pos + 9)
    local rdata_pos = pos + 10
    if rtype == 16 then
      local rdata = string.sub(data, rdata_pos, rdata_pos + rdlen - 1)
      table.insert(records, parse_txt_rdata(rdata))
    end
    pos = rdata_pos + rdlen
  end
  return records
end

local function query_txt(host, port, qname)
  local id = math.random(0, 65535)
  local query = build_query(id, qname, 16, 1, true)

  local socket = nmap.new_socket()
  socket:set_timeout(4000)
  local ok = socket:connect(host, port, "udp")
  if not ok then
    socket:close()
    return nil
  end

  socket:send(query)
  local status, response = socket:receive()
  socket:close()

  if not status or not response or #response < 12 then
    return nil
  end

  local header = parse_header(response)
  if not header or header.rcode ~= 0 or header.ancount == 0 then
    return {}
  end

  local qend = skip_name(response, 13) + 4
  return collect_txt_records(response, qend, header.ancount)
end

local function evaluate_spf(txt)
  local issues = {}
  local ltxt = string.lower(txt)
  if string.find(ltxt, "%+all") then
    table.insert(issues, "uses '+all' (explicitly allows any sender - effectively no protection)")
  elseif string.find(ltxt, "~all") then
    table.insert(issues, "uses '~all' (softfail - spoofed mail is flagged, not rejected)")
  elseif string.find(ltxt, "%?all") then
    table.insert(issues, "uses '?all' (neutral - provides no meaningful protection)")
  elseif not string.find(ltxt, "%-all") then
    table.insert(issues, "no explicit 'all' mechanism found; policy end-state is unclear")
  end
  return issues
end

local function evaluate_dmarc(txt)
  local issues = {}
  local ltxt = string.lower(txt)
  local policy = string.match(ltxt, "p=([a-z]+)")
  if not policy then
    table.insert(issues, "no 'p=' policy tag found in DMARC record")
  elseif policy == "none" then
    table.insert(issues, "policy is 'p=none' (monitoring only, spoofed mail is not blocked)")
  end
  if not string.find(ltxt, "rua=") then
    table.insert(issues, "no 'rua=' aggregate reporting address configured")
  end
  return issues
end

action = function(host, port)
  local domain = stdnse.get_script_args(SCRIPT_NAME .. ".domain") or host.targetname
  if not domain then
    return "No domain specified. Set with --script-args " .. SCRIPT_NAME .. ".domain=example.com"
  end

  local out = stdnse.output_table()

  local root_txt = query_txt(host, port, domain)
  local spf_record = nil
  if root_txt then
    for _, txt in ipairs(root_txt) do
      if string.find(string.lower(txt), "v=spf1") then
        spf_record = txt
        break
      end
    end
  end

  if spf_record then
    out["SPF record"] = spf_record
    local spf_issues = evaluate_spf(spf_record)
    if #spf_issues > 0 then
      out["SPF issues"] = spf_issues
    else
      out["SPF issues"] = "None detected."
    end
  else
    out["SPF record"] = "Not found."
  end

  local dmarc_txt = query_txt(host, port, "_dmarc." .. domain)
  local dmarc_record = nil
  if dmarc_txt then
    for _, txt in ipairs(dmarc_txt) do
      if string.find(string.lower(txt), "v=dmarc1") then
        dmarc_record = txt
        break
      end
    end
  end

  if dmarc_record then
    out["DMARC record"] = dmarc_record
    local dmarc_issues = evaluate_dmarc(dmarc_record)
    if #dmarc_issues > 0 then
      out["DMARC issues"] = dmarc_issues
    else
      out["DMARC issues"] = "None detected."
    end
  else
    out["DMARC record"] = "Not found at _dmarc." .. domain
  end

  return out
end
