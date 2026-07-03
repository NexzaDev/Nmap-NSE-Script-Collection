local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
Compares the target hostname (or an explicitly supplied name via the
ssl-cert-hostname-mismatch.name script argument) against the
certificate's CommonName and Subject Alternative Names, including
wildcard matching, and reports whether the certificate is valid for
that hostname.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.ssl

local function extract_names(cert)
  local names = {}
  if cert.subject and cert.subject.commonName then
    table.insert(names, cert.subject.commonName)
  end
  if cert.extensions then
    for _, ext in ipairs(cert.extensions) do
      local name = ext.name or ""
      if string.find(string.lower(name), "subject alternative name") then
        local value = ext.value or ""
        for entry in string.gmatch(value, "DNS:([^,%s]+)") do
          table.insert(names, entry)
        end
      end
    end
  end
  return names
end

local function wildcard_to_pattern(pattern_name)
  local escaped = string.gsub(pattern_name, "([%.%-%+%[%]%(%)%$%^%%%?])", "%%%1")
  escaped = string.gsub(escaped, "%%%*", "[^%.]+")
  return "^" .. escaped .. "$"
end

local function matches(cert_name, target)
  local lname = string.lower(cert_name)
  local ltarget = string.lower(target)
  if lname == ltarget then
    return true
  end
  if string.find(lname, "%*") then
    local pattern = wildcard_to_pattern(lname)
    if string.find(ltarget, pattern) then
      return true
    end
  end
  return false
end

action = function(host, port)
  local status, cert = sslcert.getCertificate(host, port)
  if not status or not cert then
    return "Could not retrieve a certificate from this port."
  end

  local target = stdnse.get_script_args("ssl-cert-hostname-mismatch.name")
  if not target then
    target = host.targetname or (host.name ~= "" and host.name) or tostring(host.ip)
  end

  local names = extract_names(cert)

  local out = stdnse.output_table()
  out["Target hostname evaluated"] = target
  out["Certificate names found"] = (#names > 0) and names or {"none"}

  local matched_name = nil
  for _, n in ipairs(names) do
    if matches(n, target) then
      matched_name = n
      break
    end
  end

  if matched_name then
    out["Result"] = "MATCH - certificate is valid for this hostname (matched: " .. matched_name .. ")"
  else
    out["Result"] = "MISMATCH - certificate does not cover this hostname; browsers/clients will show a warning"
  end

  return out
end
