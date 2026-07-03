local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

description = [[
Inspects the certificate's signature algorithm and public key strength
for known-weak configurations: MD5 or SHA-1 signatures, RSA/DSA keys
under 2048 bits, EC keys under 224 bits, and self-signed certificates
presented on a public-facing service.
]]

author = "custom"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "vuln"}

portrule = shortport.ssl

local WEAK_SIG_PATTERNS = {
  "md5", "sha1", "md2", "md4",
}

local function looks_self_signed(cert)
  if not cert.subject or not cert.issuer then return false end
  return cert.subject.commonName == cert.issuer.commonName
     and cert.subject.organizationName == cert.issuer.organizationName
end

local function evaluate_signature(sig_algorithm)
  if not sig_algorithm then return nil end
  local lsig = string.lower(sig_algorithm)
  for _, weak in ipairs(WEAK_SIG_PATTERNS) do
    if string.find(lsig, weak, 1, true) then
      return weak
    end
  end
  return nil
end

local function evaluate_key(pubkey)
  local issues = {}
  if not pubkey then return issues end
  local ktype = pubkey.type and string.lower(pubkey.type) or nil
  local bits = tonumber(pubkey.bits)

  if not bits then
    return issues
  end

  if ktype == "rsa" and bits < 2048 then
    table.insert(issues, string.format("RSA key size %d bits is below the recommended 2048-bit minimum", bits))
  elseif ktype == "dsa" and bits < 2048 then
    table.insert(issues, string.format("DSA key size %d bits is below the recommended 2048-bit minimum", bits))
  elseif ktype == "ec" and bits < 224 then
    table.insert(issues, string.format("EC key size %d bits is below the recommended 224-bit minimum", bits))
  end

  return issues
end

action = function(host, port)
  local status, cert = sslcert.getCertificate(host, port)
  if not status or not cert then
    return "Could not retrieve a certificate from this port."
  end

  local out = stdnse.output_table()
  local findings = {}

  local weak_hash = evaluate_signature(cert.sig_algorithm)
  if weak_hash then
    table.insert(findings, string.format(
      "Weak signature hash algorithm in use: %s (%s)", cert.sig_algorithm, weak_hash
    ))
  end

  local key_issues = evaluate_key(cert.pubkey)
  for _, issue in ipairs(key_issues) do
    table.insert(findings, issue)
  end

  if looks_self_signed(cert) then
    table.insert(findings, "Certificate appears to be self-signed")
  end

  if cert.extensions then
    local has_san = false
    for _, ext in ipairs(cert.extensions) do
      if ext.name and string.find(string.lower(ext.name), "subject alternative name") then
        has_san = true
      end
    end
    if not has_san then
      table.insert(findings, "No Subject Alternative Name extension present (legacy CN-only validation)")
    end
  end

  if cert.sig_algorithm then
    out["Signature algorithm"] = cert.sig_algorithm
  end
  if cert.pubkey and cert.pubkey.type then
    out["Public key type"] = cert.pubkey.type
  end
  if cert.pubkey and cert.pubkey.bits then
    out["Public key size (bits)"] = tostring(cert.pubkey.bits)
  end

  if #findings > 0 then
    out["Weaknesses found"] = findings
  else
    out["Weaknesses found"] = "None of the checked weaknesses were detected."
  end

  return out
end
