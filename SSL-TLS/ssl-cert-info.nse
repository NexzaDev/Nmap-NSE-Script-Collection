local shortport = require "shortport"
local sslcert = require "sslcert"
local datetime = require "datetime"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
Retrieves the X.509 certificate presented during the TLS handshake and
reports subject, issuer, serial number, validity window, signature
algorithm, public key details, Subject Alternative Names, and whether
the certificate appears to be self-signed.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "default"}

portrule = shortport.ssl

local function format_name(nametable)
  if not nametable then return "unknown" end
  local parts = {}
  if nametable.commonName then
    table.insert(parts, "CN=" .. nametable.commonName)
  end
  if nametable.organizationName then
    table.insert(parts, "O=" .. nametable.organizationName)
  end
  if nametable.countryName then
    table.insert(parts, "C=" .. nametable.countryName)
  end
  if #parts == 0 then
    return "unknown"
  end
  return table.concat(parts, ", ")
end

local function format_validity(validity)
  local out = {}
  if not validity then return out end
  for field, value in pairs(validity) do
    if type(value) == "string" then
      out[field] = value
    else
      local ok, formatted = pcall(datetime.format_timestamp, value)
      out[field] = ok and formatted or tostring(value)
    end
  end
  return out
end

local function extract_sans(cert)
  local sans = {}
  if not cert.extensions then return sans end
  for _, ext in ipairs(cert.extensions) do
    local name = ext.name or ""
    if string.find(string.lower(name), "subject alternative name") then
      local value = ext.value or ""
      for entry in string.gmatch(value, "DNS:([^,%s]+)") do
        table.insert(sans, "DNS:" .. entry)
      end
      for entry in string.gmatch(value, "IP Address:([^,%s]+)") do
        table.insert(sans, "IP:" .. entry)
      end
    end
  end
  return sans
end

local function looks_self_signed(cert)
  if not cert.subject or not cert.issuer then return false end
  local s_cn = cert.subject.commonName
  local i_cn = cert.issuer.commonName
  local s_o = cert.subject.organizationName
  local i_o = cert.issuer.organizationName
  return s_cn == i_cn and s_o == i_o
end

action = function(host, port)
  local status, cert = sslcert.getCertificate(host, port)
  if not status or not cert then
    return "Could not retrieve a certificate from this port."
  end

  local out = stdnse.output_table()

  out["Subject"] = format_name(cert.subject)
  out["Issuer"] = format_name(cert.issuer)

  if cert.serial then
    out["Serial number"] = tostring(cert.serial)
  end

  local validity = format_validity(cert.validity)
  if validity.notBefore then
    out["Valid from"] = validity.notBefore
  end
  if validity.notAfter then
    out["Valid until"] = validity.notAfter
  end

  if cert.sig_algorithm then
    out["Signature algorithm"] = cert.sig_algorithm
  end

  if cert.pubkey then
    local keyinfo = {}
    if cert.pubkey.type then
      table.insert(keyinfo, "type=" .. tostring(cert.pubkey.type))
    end
    if cert.pubkey.bits then
      table.insert(keyinfo, "bits=" .. tostring(cert.pubkey.bits))
    end
    if #keyinfo > 0 then
      out["Public key"] = table.concat(keyinfo, ", ")
    end
  end

  local sans = extract_sans(cert)
  if #sans > 0 then
    out["Subject Alternative Names"] = sans
  else
    out["Subject Alternative Names"] = "None present."
  end

  out["Appears self-signed"] = tostring(looks_self_signed(cert))

  if cert.pem then
    out["PEM available"] = "yes (use ssl-cert-weak-signature / other scripts for deeper analysis)"
  end

  return out
end
