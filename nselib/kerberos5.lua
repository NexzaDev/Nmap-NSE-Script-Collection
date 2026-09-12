--[[
  nselib/kerberos5.lua - reusable Kerberos V5 (RFC 4120) engine for the
  Nmap-NSE-Script-Collection KERBEROS scripts.

  This module is the single maintained implementation of the protocol
  primitives every Kerberos audit script needs:

    * der        - an ASN.1 DER encoder (explicit *and* implicit tagging)
    * decoder    - a tolerant DER decoder that accepts both tagging styles
    * krb        - KRB-ERROR / AS-REP / METHOD-DATA / ETYPE-INFO[2] codec
    * transport  - UDP/88 and TCP/88 with RFC 4120 length framing, retries
                   and automatic UDP -> TCP fallback on KRB_ERR_RESPONSE_TOO_BIG
    * timeutil   - KerberosTime helpers
    * registries - KRB5 error codes, encryption types, PA-DATA types,
                   KDCOptions and TicketFlags bit maps

  Installation: the module resolves through the normal NSE module path, so it
  must be installed next to the other nselib modules, e.g.

      cp nselib/kerberos5.lua  "$(nmap --datadir)/nselib/"
      # or: nmap --datadir ./ ...

  Scripts detect a missing installation with pcall(require, ...) and report it
  as an installation problem instead of failing obscurely.

  Licence: same as Nmap - see https://nmap.org/book/man-legal.html
]]

local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"
local math = require "math"
local os = require "os"
local bit = require "bit"

local M = {}
M.VERSION = "2.0.0"

-- ---------------------------------------------------------------------------
-- 1. Version and tuning constants
-- ---------------------------------------------------------------------------

local SCRIPT_VERSION = "2.0.0"
local KRB5_PROTOCOL_VERSION = 5

-- Kerberos message types (RFC 4120 section 7.5.7 and MsgType ASN.1 set).
local MSG = {
  AS_REQ = 10,
  AS_REP = 11,
  TGS_REQ = 12,
  TGS_REP = 13,
  AP_REQ = 14,
  AP_REP = 15,
  KRB_ERROR = 30,
}

-- APPLICATION tags used by the Kerberos ASN.1 module.
local APP = {
  AS_REQ = 10,
  AS_REP = 11,
  TGS_REQ = 12,
  TGS_REP = 13,
  AP_REQ = 14,
  AP_REP = 15,
  KRB_ERROR = 30,
}

-- ASN.1 universal tags that this script has to produce and consume.
local TAG = {
  INTEGER = 0x02,
  BITSTRING = 0x03,
  OCTETSTRING = 0x04,
  NULL = 0x05,
  OID = 0x06,
  SEQUENCE = 0x30,
  SET = 0x31,
  GENERALSTRING = 0x1B,
  GENERALIZEDTIME = 0x18,
}

-- The decoder exposes the tag *number* (the low five bits of the tag byte),
-- while the encoder needs the complete tag byte. The two are only identical
-- for tags below 0x1F, so they are kept in separate tables to make a
-- comparison against the wrong one impossible.
local TAGNO = {
  INTEGER = TAG.INTEGER & 0x1F,
  BITSTRING = TAG.BITSTRING & 0x1F,
  OCTETSTRING = TAG.OCTETSTRING & 0x1F,
  SEQUENCE = TAG.SEQUENCE & 0x1F,
  GENERALSTRING = TAG.GENERALSTRING & 0x1F,
  GENERALIZEDTIME = TAG.GENERALIZEDTIME & 0x1F,
}

local CLASS_UNIVERSAL = 0
local CLASS_APPLICATION = 1
local CLASS_CONTEXT = 2

-- Principal name types (RFC 4120 section 6.2 and RFC 6806 section 5).
local NT = {
  UNKNOWN = 0,
  PRINCIPAL = 1,
  SRV_INST = 2,
  SRV_HST = 3,
  SRV_XHST = 4,
  UID = 5,
  X500_PRINCIPAL = 6,
  SMTP_NAME = 7,
  ENTERPRISE = 10,
  WELLKNOWN = 11,
  SRV_HST_DOMAIN = 12,
}

-- ---------------------------------------------------------------------------
-- 2. KRB5 error registry
--
-- Every code the KDC can return for our probe, together with the audit
-- meaning of that code. The classification engine in section 10 consumes the
-- three flags:
--   * roastable : the answer proves pre-authentication is not required
--   * preauth   : the answer proves pre-authentication IS required
--   * nomatch   : the answer proves the principal does not exist
--   * fatal     : stop probing immediately (lockout / trust / transport)
-- ---------------------------------------------------------------------------

local KRB5_ERR = {
  [0]  = { name = "KDC_ERR_NONE", note = "no error; the KDC returned a service reply" },
  [1]  = { name = "KDC_ERR_NAME_EXP", note = "principal's database entry expired" },
  [2]  = { name = "KDC_ERR_SERVICE_EXP", note = "service's database entry expired" },
  [3]  = { name = "KDC_ERR_BAD_PVNO", note = "protocol version mismatch; not a Kerberos V5 KDC" },
  [4]  = { name = "KDC_ERR_C_OLD_MAST_KVNO", note = "client key version too old for the master key" },
  [5]  = { name = "KDC_ERR_S_OLD_MAST_KVNO", note = "server key version too old for the master key" },
  [6]  = { name = "KDC_ERR_C_PRINCIPAL_UNKNOWN", note = "principal does not exist in the realm",
           nomatch = true },
  [7]  = { name = "KDC_ERR_S_PRINCIPAL_UNKNOWN", note = "service principal does not exist",
           nomatch = true },
  [8]  = { name = "KDC_ERR_PRINCIPAL_NOT_UNIQUE", note = "principal name resolves to several entries" },
  [9]  = { name = "KDC_ERR_NULL_KEY", note = "principal has no key (cannot complete authentication)" },
  [10] = { name = "KDC_ERR_CANNOT_POSTDATE", note = "requested postdating is not permitted" },
  [11] = { name = "KDC_ERR_NEVER_VALID", note = "requested ticket lifetime is zero" },
  [12] = { name = "KDC_ERR_POLICY", note = "request denied by realm policy (KDC policy, not client)" },
  [13] = { name = "KDC_ERR_BADOPTION", note = "unsupported KDC option requested" },
  [14] = { name = "KDC_ERR_ETYPE_NOSUPP", note = "no common encryption type between client and KDC",
           weak_crypto = true },
  [15] = { name = "KDC_ERR_SUMTYPE_NOSUPP", note = "unsupported checksum type" },
  [16] = { name = "KDC_ERR_PADATA_TYPE_NOSUPP", note = "unsupported pre-authentication data type" },
  [17] = { name = "KDC_ERR_TRTYPE_NOSUPP", note = "unsupported transited encoding type" },
  [18] = { name = "KDC_ERR_CLIENT_REVOKED", note = "account disabled or locked out; probing aborted",
           fatal = true },
  [19] = { name = "KDC_ERR_SERVICE_REVOKED", note = "service account disabled or locked out" },
  [20] = { name = "KDC_ERR_TGT_REVOKED", note = "TGT rejected by the KDC (revoked)" },
  [21] = { name = "KDC_ERR_CLIENT_NOTYET", note = "account is not yet valid (start time in the future)" },
  [22] = { name = "KDC_ERR_SERVICE_NOTYET", note = "service is not yet valid" },
  [23] = { name = "KDC_ERR_KEY_EXPIRED", note = "password/key expired; the account must rotate it",
           preauth = true },
  [24] = { name = "KDC_ERR_PREAUTH_FAILED", note = "pre-authentication data supplied was rejected",
           preauth = true },
  [25] = { name = "KDC_ERR_PREAUTH_REQUIRED", note = "KDC demands pre-authentication (PA-ENC-TIMESTAMP)",
           preauth = true },
  [26] = { name = "KDC_ERR_SERVER_NOMATCH", note = "KDC does not serve the requested service" },
  [27] = { name = "KDC_ERR_MUST_USE_USER2USER", note = "ticket must be obtained via U2U (user-to-user)" },
  [28] = { name = "KDC_ERR_PATH_NOT_ACCEPTED", note = "transited path rejected" },
  [29] = { name = "KDC_ERR_SVC_UNAVAILABLE", note = "a required KDC service is unavailable" },
  [31] = { name = "KRB_AP_ERR_BAD_INTEGRITY", note = "integrity check failed (wrong key or corrupted data)" },
  [32] = { name = "KRB_AP_ERR_TKT_EXPIRED", note = "ticket expired" },
  [33] = { name = "KRB_AP_ERR_TKT_NYV", note = "ticket not yet valid; clock or policy mismatch" },
  [34] = { name = "KRB_AP_ERR_REPEAT", note = "replay detected" },
  [35] = { name = "KRB_AP_ERR_NOT_US", note = "ticket was not issued for this service" },
  [36] = { name = "KRB_AP_ERR_BADMATCH", note = "authenticator does not match the ticket" },
  [37] = { name = "KRB_AP_ERR_SKEW", note = "clock skew between client and KDC exceeds the limit",
           skew = true },
  [38] = { name = "KRB_AP_ERR_BADADDR", note = "address mismatch between ticket and request" },
  [39] = { name = "KRB_AP_ERR_BADVERSION", note = "protocol version mismatch" },
  [40] = { name = "KRB_AP_ERR_MSG_TYPE", note = "unexpected message type" },
  [41] = { name = "KRB_AP_ERR_MODIFIED", note = "message was modified in transit (or wrong key)" },
  [42] = { name = "KRB_AP_ERR_BADORDER", note = "messages arrived out of sequence" },
  [44] = { name = "KRB_AP_ERR_BADKEYVER", note = "unknown key version" },
  [45] = { name = "KRB_AP_ERR_NOKEY", note = "no service key available to the KDC" },
  [46] = { name = "KRB_AP_ERR_MUT_FAIL", note = "mutual authentication requirement not met" },
  [47] = { name = "KRB_AP_ERR_BADDIRECTION", note = "wrong message direction" },
  [48] = { name = "KRB_AP_ERR_METHOD", note = "unsupported authentication method" },
  [49] = { name = "KRB_AP_ERR_BADSEQ", note = "sequence number mismatch" },
  [50] = { name = "KRB_AP_ERR_INAPP_CKSUM", note = "inappropriate checksum type for the key" },
  [51] = { name = "KRB_AP_PATH_NOT_ACCEPTED", note = "transited path rejected by policy" },
  [52] = { name = "KRB_ERR_RESPONSE_TOO_BIG", note = "UDP reply truncated; retry over TCP",
           retry_tcp = true },
  [60] = { name = "KRB_ERR_GENERIC", note = "unspecified KDC error" },
  [61] = { name = "KRB_ERR_FIELD_TOOLONG", note = "implementation limit on a field length" },
  [62] = { name = "KDC_ERROR_CLIENT_NOT_TRUSTED", note = "client certificate not trusted (PKINIT)" },
  [63] = { name = "KDC_ERROR_KDC_NOT_TRUSTED", note = "KDC certificate not trusted (PKINIT)" },
  [64] = { name = "KDC_ERROR_INVALID_SIG", note = "PKINIT signature validation failed" },
  [65] = { name = "KDC_ERR_KEY_TOO_WEAK", note = "offered key is too weak for realm policy",
           weak_crypto = true },
  [66] = { name = "KDC_ERR_CERTIFICATE_MISMATCH", note = "certificate does not match the principal" },
  [67] = { name = "KRB_AP_ERR_NO_TGT", note = "no TGT available for the requested operation" },
  [68] = { name = "KDC_ERR_WRONG_REALM", note = "principal belongs to a different realm",
           wrong_realm = true },
  [69] = { name = "KRB_AP_ERR_USER_TO_USER_REQUIRED", note = "U2U authentication required" },
  [70] = { name = "KDC_ERR_CANT_VERIFY_CERTIFICATE", note = "KDC cannot verify the client certificate" },
  [71] = { name = "KDC_ERR_INVALID_CERTIFICATE", note = "client certificate is invalid" },
  [72] = { name = "KDC_ERR_REVOKED_CERTIFICATE", note = "client certificate has been revoked" },
  [73] = { name = "KDC_ERR_REVOCATION_STATUS_UNKNOWN", note = "revocation status unavailable" },
  [74] = { name = "KDC_ERR_REVOCATION_STATUS_UNAVAILABLE", note = "revocation service unreachable" },
  [75] = { name = "KDC_ERR_CLIENT_NAME_MISMATCH", note = "certificate name does not match the principal" },
  [76] = { name = "KDC_ERR_KDC_NAME_MISMATCH", note = "certificate KDC name mismatch" },
  [77] = { name = "KDC_ERR_INCONSISTENT_KEY_PURPOSE", note = "MS-KILE: key purpose mismatch" },
  [78] = { name = "KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED", note = "certificate digest algorithm refused" },
  [79] = { name = "KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED", note = "required PA checksum missing" },
  [80] = { name = "KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED", note = "signed-data digest refused" },
  [81] = { name = "KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED", note = "public key encryption unsupported" },
}

-- ---------------------------------------------------------------------------
-- 3. Encryption type registry
--
-- We never use these keys, but the etype of the AS-REP (and of the
-- PA-ETYPE-INFO2 entries) tells the operator how expensive the offline crack
-- will be, and whether the realm still honours retired crypto.
-- ---------------------------------------------------------------------------

local ETYPE = {
  [1]  = { name = "des-cbc-crc", retired = true, keysize = 8,  family = "des",
           crack = "instant (DES, 2^56)", cve = "CVE-2016-2183 class weakness; long removed from modern KDCs" },
  [2]  = { name = "des-cbc-md4", retired = true, keysize = 8,  family = "des",
           crack = "instant (DES, 2^56)" },
  [3]  = { name = "des-cbc-md5", retired = true, keysize = 8,  family = "des",
           crack = "instant (DES, 2^56)" },
  [5]  = { name = "des3-cbc-md5", retired = true, keysize = 24, family = "des3",
           crack = "historical, no known cheap attack" },
  [6]  = { name = "des3-cbc-sha1", retired = true, keysize = 24, family = "des3",
           crack = "historical, superseded by etype 16" },
  [7]  = { name = "des3-cbc-sha1-old", retired = true, keysize = 24, family = "des3",
           crack = "RFC 1510 era, no key derivation function" },
  [8]  = { name = "des-hmac-sha1", retired = true, keysize = 8,  family = "des",
           crack = "instant (DES, 2^56)" },
  [16] = { name = "des3-cbc-sha1-kd", deprecated = true, keysize = 24, family = "des3",
           crack = "not practical to brute force; still deprecated by MS hardening" },
  [17] = { name = "aes128-cts-hmac-sha1-96", keysize = 16, family = "aes",
           crack = "expensive (~10^6 GPU-hours for a random 14-char password)" },
  [18] = { name = "aes256-cts-hmac-sha1-96", keysize = 32, family = "aes",
           crack = "expensive (slightly costlier than etype 17 due to key length)" },
  [19] = { name = "aes128-cts-hmac-sha256-128", keysize = 16, family = "aes",
           crack = "expensive; RFC 8009 profile" },
  [20] = { name = "aes256-cts-hmac-sha384-192", keysize = 32, family = "aes",
           crack = "expensive; RFC 8009 profile" },
  [23] = { name = "rc4-hmac", keysize = 16, family = "rc4", weak = true,
           crack = "FAST: ~10 GPU-hours per account; RC4-HMAC is the roastable etype of choice",
           cve = "CVE-2022-33679 (RC4-MD4 downgrade), KB5021131 (RC4 deprecation)" },
  [24] = { name = "rc4-hmac-exp", keysize = 16, family = "rc4", weak = true, export = true,
           crack = "FAST: 40-bit export cipher, trivial difficulty" },
  [25] = { name = "camellia128-cts-cmac", keysize = 16, family = "camellia",
           crack = "expensive; rarely deployed" },
  [26] = { name = "camellia256-cts-cmac", keysize = 32, family = "camellia",
           crack = "expensive; rarely deployed" },
}

local ETYPE_DEFAULT = { name = "unknown", crack = "undetermined cost", family = "unknown" }

-- Etypes offered in our AS-REQ. AES first (the healthy path) followed by
-- RC4-HMAC, which is what makes an unauthenticated roast cheap. DES is
-- deliberately not offered in the default set: a realm that only answers to
-- DES is a finding in itself and is reported by kerberos-weak-encryption.nse.
local ETYPE_OFFER_DEFAULT = { 18, 17, 20, 19, 16, 23, 24 }
local ETYPE_OFFER_WEAK    = { 23, 24, 18, 17 }
local ETYPE_OFFER_STRONG  = { 20, 19, 18, 17 }

-- ---------------------------------------------------------------------------
-- 4. Pre-authentication data type registry (PA-DATA)
-- ---------------------------------------------------------------------------

local PADATA = {
  [1]   = "PA-TGS-REQ",
  [2]   = "PA-ENC-TIMESTAMP",
  [3]   = "PA-PW-SALT",
  [5]   = "PA-ENC-UNIX-TIME",
  [11]  = "PA-ETYPE-INFO",
  [12]  = "PA-SAM-CHALLENGE",
  [13]  = "PA-SAM-RESPONSE",
  [14]  = "PA-PK-AS-REQ (old)",
  [15]  = "PA-PK-AS-REP (old)",
  [16]  = "PA-PK-AS-REQ",
  [17]  = "PA-PK-AS-REP",
  [18]  = "PA-ETYPE-INFO2",
  [19]  = "PA-USE-SPECIFIED-KVNO",
  [20]  = "PA-SVR-REFERRAL-INFO",
  [128] = "PA-PAC-REQUEST (MS-KILE)",
  [129] = "PA-FOR-USER (MS-SFU S4U2self)",
  [130] = "PA-FOR-X509-USER (MS-SFU)",
  [131] = "PA-REQ-ENC-PA-REP (RFC 6806)",
  [132] = "PA-AS-CHECKSUM (RFC 6806)",
  [133] = "PA-FX-COOKIE (RFC 6113)",
  [136] = "PA-FX-FAST (RFC 6113)",
  [137] = "PA-FX-ERROR (RFC 6113)",
  [138] = "PA-ENCRYPTED-CHALLENGE (RFC 6113)",
  [141] = "PA-OTP-CHALLENGE (RFC 6560)",
  [142] = "PA-OTP-REQUEST (RFC 6560)",
  [143] = "PA-OTP-CONFIRM (RFC 6560)",
  [144] = "PA-OTP-ACK (RFC 6560)",
  [165] = "PA-SUPPORTED-ENCTYPES (MS-KILE)",
  [166] = "PA-EXTENDED-ERROR (MS-KILE)",
}

-- ---------------------------------------------------------------------------
-- 5. KDCOptions and TicketFlags bit maps (RFC 4120 section 5.4.1 / 5.3)
-- ---------------------------------------------------------------------------

local KDCOPT = {
  { 0x80000000, "reserved" },
  { 0x40000000, "forwardable" },
  { 0x20000000, "forwarded" },
  { 0x10000000, "proxiable" },
  { 0x08000000, "proxy" },
  { 0x04000000, "allow-postdate" },
  { 0x02000000, "postdated" },
  { 0x01000000, "renewable" },
  { 0x00800000, "opt-hardware-auth" },
  { 0x00010000, "canonicalize" },
  { 0x00008000, "request-anonymous" },
  { 0x00004000, "name-canonicalize" },
  { 0x00000020, "disable-transited-check" },
  { 0x00000010, "renewable-ok" },
  { 0x00000008, "enc-tkt-in-skey" },
  { 0x00000002, "renew" },
  { 0x00000001, "validate" },
}

local TKTFLAG = {
  { 0x40000000, "forwardable" },
  { 0x20000000, "forwarded" },
  { 0x10000000, "proxiable" },
  { 0x08000000, "proxy" },
  { 0x04000000, "may-postdate" },
  { 0x02000000, "postdated" },
  { 0x01000000, "invalid" },
  { 0x00800000, "renewable" },
  { 0x00400000, "initial" },
  { 0x00200000, "pre-authent" },
  { 0x00100000, "hw-authent" },
  { 0x00080000, "transited-policy-checked" },
  { 0x00040000, "ok-as-delegate" },
  { 0x00020000, "anonymous" },
  { 0x00000002, "enc-pa-rep" },
}

-- ---------------------------------------------------------------------------
-- 6. ASN.1 DER encoder
--
-- Kerberos (RFC 4120) uses a DER subset with explicit tagging for the
-- KDC-REQ/KDC-REP structures: field [n] wraps the full TLV of the underlying
-- type. The encoder below therefore exposes ctx() as an explicit tag wrapper
-- and ctx_raw() for the (rare) implicitly tagged fields such as the entries
-- of ETYPE-INFO2, giving the decoder a chance to handle both forms.
-- ---------------------------------------------------------------------------

local der = {}

local function der_length(n)
  if n < 0x80 then
    return string.char(n)
  end
  local parts = {}
  while n > 0 do
    table.insert(parts, 1, string.char(n % 256))
    n = math.floor(n / 256)
  end
  return string.char(0x80 + #parts) .. table.concat(parts)
end

local function der_tlv(tagnum, content)
  return string.char(tagnum) .. der_length(#content) .. content
end

function der.integer(value)
  if value < 0 then
    -- Two's complement, minimal length.
    local bytes = {}
    local v = value
    repeat
      table.insert(bytes, 1, string.char(bit.band(v, 0xFF)))
      v = math.floor(v / 256)
    until v == -1 and bit.band(string.byte(bytes[1]), 0x80) == 0x80
    if bit.band(string.byte(bytes[1]), 0x80) == 0 then
      table.insert(bytes, 1, string.char(0xFF))
    end
    return der_tlv(TAG.INTEGER, table.concat(bytes))
  end
  local bytes = {}
  local v = value
  repeat
    table.insert(bytes, 1, string.char(v % 256))
    v = math.floor(v / 256)
  until v == 0
  if bit.band(string.byte(bytes[1]), 0x80) ~= 0 then
    table.insert(bytes, 1, string.char(0))
  end
  return der_tlv(TAG.INTEGER, table.concat(bytes))
end

function der.bitstring(hexmask, nbits)
  nbits = nbits or 32
  local nbytes = math.floor((nbits + 7) / 8)
  local unused = (nbytes * 8) - nbits
  local bytes = {}
  for i = 1, nbytes do
    local shift = (nbytes - i) * 8
    bytes[i] = string.char(bit.band(math.floor(hexmask / 2 ^ shift), 0xFF))
  end
  return der_tlv(TAG.BITSTRING, string.char(unused) .. table.concat(bytes))
end

function der.octetstring(value)
  return der_tlv(TAG.OCTETSTRING, value)
end

function der.generalstring(value)
  return der_tlv(TAG.GENERALSTRING, value)
end

function der.generalizedtime(value)
  return der_tlv(TAG.GENERALIZEDTIME, value)
end

function der.sequence(...)
  local parts = { ... }
  return der_tlv(TAG.SEQUENCE, table.concat(parts))
end

function der.app(tagnum, ...)
  local parts = { ... }
  return der_tlv(0x60 + tagnum, table.concat(parts))
end

-- Explicit context tag: [n] wrapping the complete TLV of `inner`.
function der.ctx(n, inner)
  return der_tlv(0xA0 + n, inner)
end

-- Implicit context tag: [n] replacing the tag of `inner` (content reused).
function der.ctx_raw(n, inner)
  local content = der.content_of(inner)
  return der_tlv(0xA0 + n, content)
end

-- Strip tag and length from a complete TLV, returning the content octets.
function der.content_of(tlv)
  local len_byte = string.byte(tlv, 2)
  local header = 1
  if len_byte < 0x80 then
    header = 2
  else
    header = 2 + bit.band(len_byte, 0x7F)
  end
  return string.sub(tlv, header + 1)
end

-- ---------------------------------------------------------------------------
-- 7. ASN.1 DER decoder
--
-- Tolerant by design: KDCs in the wild produce long-form lengths, high tag
-- numbers in the APPLICATION class, optional/absent fields and (for some
-- vendor dialects) implicitly tagged integers. The decoder therefore keeps
-- the raw content octets of every node and offers unwrap() so field access
-- works regardless of which tagging convention the KDC used.
-- ---------------------------------------------------------------------------

local decoder = {}

decoder.MAX_DEPTH = 24

local function decode_node(data, pos, depth)
  if depth > decoder.MAX_DEPTH then
    return nil, "ASN.1 nesting too deep"
  end
  if pos > #data then
    return nil, "truncated ASN.1 stream"
  end

  local tagbyte = string.byte(data, pos)
  pos = pos + 1
  local cls = bit.rshift(bit.band(tagbyte, 0xC0), 6)
  local cons = bit.band(tagbyte, 0x20) ~= 0
  local num = bit.band(tagbyte, 0x1F)

  if num == 0x1F then
    num = 0
    local more = true
    while more do
      if pos > #data then
        return nil, "truncated high-tag ASN.1 header"
      end
      local b = string.byte(data, pos)
      pos = pos + 1
      num = num * 128 + bit.band(b, 0x7F)
      more = bit.band(b, 0x80) ~= 0
      if num > 0xFFFFFF then
        return nil, "implausible ASN.1 tag number"
      end
    end
  end

  if pos > #data then
    return nil, "truncated ASN.1 length"
  end
  local lenbyte = string.byte(data, pos)
  pos = pos + 1
  local len
  if lenbyte < 0x80 then
    len = lenbyte
  elseif lenbyte == 0x80 then
    return nil, "indefinite length is not valid DER"
  else
    local nbytes = bit.band(lenbyte, 0x7F)
    if nbytes > 4 then
      return nil, "ASN.1 length field too long"
    end
    len = 0
    for _ = 1, nbytes do
      if pos > #data then
        return nil, "truncated ASN.1 long length"
      end
      len = len * 256 + string.byte(data, pos)
      pos = pos + 1
    end
  end

  if len > #data - pos + 1 then
    return nil, string.format("ASN.1 length %d exceeds remaining %d bytes", len, #data - pos + 1)
  end

  local node = {
    cls = cls,
    cons = cons,
    num = num,
    len = len,
    value = string.sub(data, pos, pos + len - 1),
    start = pos - 1,
  }
  local nextpos = pos + len

  if cons then
    node.children = {}
    local child_pos = pos
    while child_pos < nextpos do
      local child, err = decode_node(data, child_pos, depth + 1)
      if not child then
        -- Keep the blob decodable: store the remainder as an opaque child so
        -- a single malformed field cannot destroy an otherwise valid parse.
        table.insert(node.children, {
          cls = CLASS_UNIVERSAL, cons = false, num = -1,
          len = nextpos - child_pos,
          value = string.sub(data, child_pos, nextpos - 1),
          raw_error = err,
        })
        break
      end
      table.insert(node.children, child)
      child_pos = child.next_offset
    end
  end

  node.next_offset = nextpos
  return node
end

function decoder.parse(data)
  local node, err = decode_node(data, 1, 0)
  if not node then
    return nil, err
  end
  return node
end

-- Locate a child by class and tag number.
function decoder.child(node, cls, num)
  if not node or not node.children then
    return nil
  end
  for _, child in ipairs(node.children) do
    if child.cls == cls and child.num == num then
      return child
    end
  end
  return nil
end

-- Context field access that tolerates both explicit and implicit tagging.
-- Returned value is the *content* of the underlying universal type.
function decoder.unwrap(node, num)
  local field = decoder.child(node, CLASS_CONTEXT, num)
  if not field then
    return nil
  end
  if field.cons then
    if field.children and #field.children == 1 then
      return field.children[1]
    end
    -- A constructed context tag can also be an implicit SEQUENCE OF.
    return field
  end
  -- Primitive context tag: the content octets *are* the value (implicit form).
  return { cls = CLASS_UNIVERSAL, cons = false, num = nil, value = field.value, implicit = true }
end

function decoder.integer_value(node)
  if not node or not node.value or #node.value == 0 then
    return nil
  end
  local value = 0
  local negative = bit.band(string.byte(node.value, 1), 0x80) ~= 0
  for i = 1, #node.value do
    value = value * 256 + string.byte(node.value, i)
  end
  if negative and #node.value < 8 then
    value = value - 2 ^ (8 * #node.value)
  end
  return value
end

function decoder.string_value(node)
  if not node then
    return nil
  end
  return node.value
end

function decoder.find_deep(node, cls, num, depth)
  depth = depth or 0
  if depth > decoder.MAX_DEPTH or not node then
    return nil
  end
  if node.cls == cls and node.num == num then
    return node
  end
  if node.children then
    for _, child in ipairs(node.children) do
      local found = decoder.find_deep(child, cls, num, depth + 1)
      if found then
        return found
      end
    end
  end
  return nil
end

-- ---------------------------------------------------------------------------
-- 8. Time helpers
--
-- Kerberos is a time-sensitive protocol: a skewed clock produces
-- KRB_AP_ERR_SKEW instead of a useful answer, so every request records the
-- client side timestamp and every response (stime/ctime) is compared to it.
-- ---------------------------------------------------------------------------

local timeutil = {}

function timeutil.os_utc(offset_seconds)
  return os.date("!%Y%m%d%H%M%SZ", os.time() + (offset_seconds or 0))
end

function timeutil.now_ms()
  if nmap and nmap.clock_ms then
    return nmap.clock_ms()
  end
  return math.floor(os.clock() * 1000)
end

function timeutil.mono_ms()
  if nmap and nmap.clock_mono_ms then
    return nmap.clock_mono_ms()
  end
  return timeutil.now_ms()
end

-- Parse the "YYYYMMDDHHMMSSZ" form used by KerberosTime.
function timeutil.parse_krbtime(s)
  if not s or #s < 15 then
    return nil
  end
  local y, mo, d, h, mi, sec = string.match(s, "^(%d%d%d%d)(%d%d)(%d%d)(%d%d)(%d%d)(%d%d)")
  if not y then
    return nil
  end
  return os.time({
    year = tonumber(y), month = tonumber(mo), day = tonumber(d),
    hour = tonumber(h), min = tonumber(mi), sec = tonumber(sec),
    isdst = false,
  })
end

-- ---------------------------------------------------------------------------
-- 9. Kerberos message codec
--
-- Encoder side: AS-REQ construction for three probe shapes
--   * bare AS-REQ (no PA-DATA) - the AS-REP roasting probe
--   * AS-REQ with PA-PAC-REQUEST / PA-SUPPORTED-ENCTYPES hints (vendor probes)
-- Decoder side: KRB-ERROR, AS-REP, METHOD-DATA, ETYPE-INFO/INFO2 and
-- EncryptedData extraction, all tolerant of explicit *and* implicit tagging.
-- ---------------------------------------------------------------------------

local krb = {}

function krb.principal(name_type, parts)
  local encoded = {}
  for _, part in ipairs(parts) do
    encoded[#encoded + 1] = der.generalstring(part)
  end
  return der.sequence(der.integer(name_type), der.sequence(table.concat(encoded)))
end

function krb.padata(ptype, value)
  return der.sequence(
    der.ctx(1, der.integer(ptype)),
    der.ctx(2, der.octetstring(value))
  )
end

-- Build a complete AS-REQ ([APPLICATION 10] KDC-REQ).
-- opts fields: realm, cname, etypes, nonce, kdc_options, padata, till, sname
function krb.build_as_req(opts)
  local padata_blob = {}
  if opts.padata then
    for _, entry in ipairs(opts.padata) do
      padata_blob[#padata_blob + 1] = entry
    end
  end

  local body = {
    der.ctx(0, der.bitstring(opts.kdc_options or 0, 32)),
    der.ctx(1, krb.principal(NT.PRINCIPAL, { opts.cname })),
    der.ctx(2, der.generalstring(opts.realm)),
    der.ctx(3, krb.principal(NT.SRV_INST, opts.sname or { "krbtgt", opts.realm })),
    der.ctx(5, der.generalizedtime(opts.till or timeutil.os_utc(0))),
    der.ctx(7, der.integer(opts.nonce)),
  }

  local etypes = {}
  for _, e in ipairs(opts.etypes) do
    etypes[#etypes + 1] = der.integer(e)
  end
  body[#body + 1] = der.ctx(8, der.sequence(table.concat(etypes)))

  local fields = {
    der.ctx(1, der.integer(KRB5_PROTOCOL_VERSION)),
    der.ctx(2, der.integer(MSG.AS_REQ)),
  }
  if #padata_blob > 0 then
    fields[#fields + 1] = der.ctx(3, der.sequence(table.concat(padata_blob)))
  end
  fields[#fields + 1] = der.ctx(4, der.sequence(table.concat(body)))

  return der.app(APP.AS_REQ, der.sequence(table.concat(fields)))
end

-- Return the SEQUENCE body of an [APPLICATION n] message, tolerating KDCs
-- that emit the body without the extra SEQUENCE wrapper.
function krb.body(root, appnum)
  if not root then
    return nil
  end
  if root.cls ~= CLASS_APPLICATION or root.num ~= appnum then
    return nil
  end
  local first = root.children and root.children[1]
  if first and first.cls == CLASS_UNIVERSAL and first.num == TAGNO.SEQUENCE then
    return first
  end
  return root
end

function krb.error_info(code)
  local entry = KRB5_ERR[code]
  if entry then
    return entry
  end
  return { name = string.format("UNKNOWN_KRB5_ERROR_%d", code), note = "not in the RFC 4120 / MS-KILE registry" }
end

function krb.parse_krb_error(root)
  local seq = krb.body(root, APP.KRB_ERROR)
  if not seq then
    return nil, "not a KRB-ERROR message"
  end
  local out = {
    pvno = decoder.integer_value(decoder.unwrap(seq, 0)),
    msg_type = decoder.integer_value(decoder.unwrap(seq, 1)),
    ctime = decoder.string_value(decoder.unwrap(seq, 2)),
    stime = decoder.string_value(decoder.unwrap(seq, 3)),
    susec = decoder.integer_value(decoder.unwrap(seq, 4)),
    code = decoder.integer_value(decoder.unwrap(seq, 5)),
    crealm = decoder.string_value(decoder.unwrap(seq, 6)),
    realm = decoder.string_value(decoder.unwrap(seq, 8)),
    e_text = decoder.string_value(decoder.unwrap(seq, 10)),
    e_data = decoder.string_value(decoder.unwrap(seq, 11)),
  }
  local cname = decoder.unwrap(seq, 7)
  if cname then
    out.cname = krb.parse_principal(cname)
  end
  local sname = decoder.unwrap(seq, 9)
  if sname then
    out.sname = krb.parse_principal(sname)
  end
  if out.code then
    local info = krb.error_info(out.code)
    out.code_name = info.name
    out.code_note = info.note
    out.roastable = info.roastable
    out.preauth = info.preauth
    out.nomatch = info.nomatch
    out.fatal = info.fatal
    out.retry_tcp = info.retry_tcp
    out.wrong_realm = info.wrong_realm
    out.weak_crypto = info.weak_crypto
  end
  return out
end

function krb.parse_principal(node)
  local seq = node
  if node.cls == CLASS_CONTEXT then
    seq = node.children and node.children[1] or node
  end
  if not seq or not seq.children then
    return nil
  end
  local name_type, names = nil, {}
  if seq.children[1] and seq.children[1].cls ~= CLASS_UNIVERSAL then
    name_type = decoder.integer_value(decoder.unwrap(seq, 0))
    local arr = decoder.unwrap(seq, 1)
    if arr and arr.children then
      for _, c in ipairs(arr.children) do
        names[#names + 1] = c.value
      end
    elseif arr then
      names[#names + 1] = arr.value
    end
  else
    name_type = decoder.integer_value(seq.children[1])
    local arr = seq.children[2]
    if arr and arr.children then
      for _, c in ipairs(arr.children) do
        names[#names + 1] = c.value
      end
    end
  end
  return { name_type = name_type, names = names, text = table.concat(names, "/") }
end

-- EncryptedData ::= SEQUENCE { etype [0], kvno [1] OPTIONAL, cipher [2] }
function krb.parse_encrypted_data(node)
  local seq = node
  if node and node.cls == CLASS_CONTEXT and node.children and node.children[1] then
    seq = node.children[1]
  end
  if not seq then
    return nil
  end
  if seq.cls == CLASS_UNIVERSAL and seq.num == TAGNO.OCTETSTRING then
    -- Some fields carry EncryptedData inside an OCTET STRING.
    local inner = decoder.parse(seq.value)
    if inner then
      seq = inner
    end
  end
  local out = {
    etype = decoder.integer_value(decoder.unwrap(seq, 0)),
    kvno = decoder.integer_value(decoder.unwrap(seq, 1)),
    cipher = decoder.string_value(decoder.unwrap(seq, 2)),
  }
  if out.cipher then
    out.cipher_len = #out.cipher
    out.cipher_head = string.sub(out.cipher, 1, 32)
  end
  return out
end

function krb.parse_as_rep(root)
  local seq = krb.body(root, APP.AS_REP)
  if not seq then
    return nil, "not an AS-REP message"
  end
  local out = {
    pvno = decoder.integer_value(decoder.unwrap(seq, 0)),
    msg_type = decoder.integer_value(decoder.unwrap(seq, 1)),
    crealm = decoder.string_value(decoder.unwrap(seq, 3)),
  }
  local cname = decoder.unwrap(seq, 4)
  if cname then
    out.cname = krb.parse_principal(cname)
  end
  out.ticket = krb.parse_ticket_summary(decoder.unwrap(seq, 5))
  out.enc_part = krb.parse_encrypted_data(decoder.unwrap(seq, 6))
  local padata = decoder.unwrap(seq, 2)
  if padata and padata.children then
    out.padata = {}
    for _, entry in ipairs(padata.children) do
      local parsed = krb.parse_padata_entry(entry)
      if parsed then
        out.padata[#out.padata + 1] = parsed
      end
    end
  end
  return out
end

-- Ticket ::= [APPLICATION 1] SEQUENCE { tkt-vno [0], realm [1], sname [2],
--                                       enc-part [3] EncryptedData }
function krb.parse_ticket_summary(root)
  local seq = root
  if root and root.cls == CLASS_APPLICATION then
    seq = root.children and root.children[1] or root
  end
  if not seq then
    return nil
  end
  local out = {
    tkt_vno = decoder.integer_value(decoder.unwrap(seq, 0)),
    realm = decoder.string_value(decoder.unwrap(seq, 1)),
  }
  local sname = decoder.unwrap(seq, 2)
  if sname then
    out.sname = krb.parse_principal(sname)
  end
  local enc = decoder.unwrap(seq, 3)
  if enc then
    out.enc_part = krb.parse_encrypted_data(enc)
  end
  return out
end

function krb.parse_padata_entry(entry)
  if not entry.children then
    return nil
  end
  local ptype = decoder.integer_value(decoder.unwrap(entry, 1))
  local value = decoder.string_value(decoder.unwrap(entry, 2))
  if not ptype then
    return nil
  end
  return { type = ptype, value = value, name = PADATA[ptype] or string.format("PA-TYPE-%d", ptype) }
end

-- e-data of a KDC_ERR_PREAUTH_REQUIRED is METHOD-DATA ::= SEQUENCE OF PA-DATA.
function krb.parse_method_data(blob)
  if not blob or #blob == 0 then
    return {}
  end
  local root = decoder.parse(blob)
  if not root then
    return {}
  end
  local seq = root
  if root.cls ~= CLASS_UNIVERSAL or root.num ~= TAGNO.SEQUENCE then
    seq = decoder.find_deep(root, CLASS_UNIVERSAL, TAG.SEQUENCE)
  end
  local entries = {}
  if not seq or not seq.children then
    return entries
  end
  -- Two shapes occur in the wild: SEQUENCE OF PA-DATA, or a single PA-DATA.
  local candidates = seq
  if seq.children[1] and seq.children[1].num ~= TAGNO.SEQUENCE then
    candidates = seq
  end
  local function consume(node)
    for _, child in ipairs(node.children) do
      if child.cls == CLASS_UNIVERSAL and child.num == TAGNO.SEQUENCE then
        local parsed = krb.parse_padata_entry(child)
        if parsed then
          entries[#entries + 1] = parsed
        end
      end
    end
  end
  consume(candidates)
  if #entries == 0 then
    local parsed = krb.parse_padata_entry(seq)
    if parsed then
      entries[#entries + 1] = parsed
    end
  end
  return entries
end

-- ETYPE-INFO2 ::= SEQUENCE OF ETYPE-INFO2-ENTRY
-- ETYPE-INFO2-ENTRY ::= SEQUENCE { etype [0], salt [1] KerberosString OPTIONAL,
--                                  s2kparams [2] OCTET STRING OPTIONAL }
function krb.parse_etype_info2(blob)
  local entries = {}
  if not blob or #blob == 0 then
    return entries
  end
  local root = decoder.parse(blob)
  if not root then
    return entries
  end
  local list = root
  if not (root.cls == CLASS_UNIVERSAL and root.num == TAGNO.SEQUENCE and root.children) then
    return entries
  end
  for _, entry in ipairs(list.children) do
    if entry.cls == CLASS_UNIVERSAL and entry.num == TAGNO.SEQUENCE then
      local etype = decoder.integer_value(decoder.unwrap(entry, 0))
      local salt = decoder.string_value(decoder.unwrap(entry, 1))
      local s2k = decoder.string_value(decoder.unwrap(entry, 2))
      if etype then
        entries[#entries + 1] = { etype = etype, salt = salt, s2kparams = s2k }
      end
    end
  end
  return entries
end

-- PA-ETYPE-INFO (type 11) uses the same shape but the salt is an OCTET STRING.
function krb.parse_etype_info(blob)
  local entries = {}
  if not blob or #blob == 0 then
    return entries
  end
  local root = decoder.parse(blob)
  if not root or not root.children then
    return entries
  end
  for _, entry in ipairs(root.children) do
    if entry.cls == CLASS_UNIVERSAL and entry.num == TAG.SEQUENCE then
      local etype = decoder.integer_value(decoder.unwrap(entry, 0))
      local salt = decoder.string_value(decoder.unwrap(entry, 1))
      if etype then
        entries[#entries + 1] = { etype = etype, salt = salt }
      end
    end
  end
  return entries
end

-- PA-SUPPORTED-ENCTYPES (MS-KILE, type 165) carries a 32-bit little-endian
-- bitmask in which bit (etype - 1) marks support for that encryption type.
function krb.parse_supported_etypes(blob)
  local supported = {}
  if not blob or #blob < 4 then
    return supported
  end
  local v = 0
  for i = 1, 4 do
    v = v + string.byte(blob, i) * 2 ^ (8 * (i - 1))
  end
  for etype = 1, 32 do
    if bit.band(math.floor(v / 2 ^ (etype - 1)), 1) == 1 then
      supported[#supported + 1] = etype
    end
  end
  return supported, v
end

function krb.etype_info(id)
  local entry = ETYPE[id]
  if entry then
    return entry
  end
  return ETYPE_DEFAULT
end

function krb.is_kerberos_message(data)
  if type(data) ~= "string" or #data < 8 then
    return false
  end
  local first = string.byte(data, 1)
  if first ~= 0x6A and first ~= 0x6B and first ~= 0x6C and first ~= 0x6D
     and first ~= 0x6E and first ~= 0x7E and first ~= 0x78 then
    return false
  end
  local root = decoder.parse(data)
  return root ~= nil
end

function krb.message_label(data)
  if type(data) ~= "string" or #data == 0 then
    return "empty"
  end
  local first = string.byte(data, 1)
  local labels = {
    [0x6A] = "AS-REQ",
    [0x6B] = "AS-REP",
    [0x6C] = "TGS-REQ",
    [0x6D] = "TGS-REP",
    [0x6E] = "AP-REQ",
    [0x6F] = "AP-REP",
    [0x78] = "KRB-ERROR",
  }
  return labels[first] or string.format("non-Kerberos byte 0x%02X", first)
end

-- ---------------------------------------------------------------------------
-- 10. Transport layer
--
-- Kerberos runs on both UDP/88 and TCP/88 with different framings:
--   UDP: one datagram per message, no framing, truncation signalled by
--        KRB_ERR_RESPONSE_TOO_BIG (code 52) which forces a TCP retry.
--   TCP: each message is prefixed with a 4-byte big-endian length.
-- NSE sockets historically exposed two return conventions, so the wrappers
-- below normalise (true|nil, payload|err) and ("EOF"/"TIMEOUT", data) into a
-- single payload-or-nil contract before any protocol code sees the bytes.
-- ---------------------------------------------------------------------------

local transport = {}

local function sock_send(sock, data)
  local ok, err = sock:send(data)
  if ok == nil or ok == false then
    return false, err or "socket send failed"
  end
  return true
end

-- Normalised receive: returns payload string, or nil plus a reason token that
-- is one of "timeout", "closed", "error", or a socket error message.
local function sock_recv(sock, timeout_ms)
  if timeout_ms then
    sock:set_timeout(timeout_ms)
  end
  local a, b = sock:receive()
  if a == true then
    return b
  end
  if a == nil or a == false then
    return nil, (type(b) == "string" and b) or "error"
  end
  if type(a) == "string" then
    local low = string.lower(a)
    if low == "timeout" then
      return nil, "timeout"
    elseif low == "eof" then
      return nil, "closed"
    elseif low == "error" then
      return nil, (type(b) == "string" and b) or "error"
    end
    if #a > 0 then
      return a
    end
    return nil, "empty"
  end
  if type(a) == "number" then
    return b
  end
  return nil, "unexpected receive result"
end

local function sock_recv_bytes(sock, n, timeout_ms)
  if timeout_ms then
    sock:set_timeout(timeout_ms)
  end
  local a, b = sock:receive_bytes(n)
  if a == true then
    return b
  end
  if a == nil or a == false then
    return nil, (type(b) == "string" and b) or "error"
  end
  if type(a) == "string" then
    local low = string.lower(a)
    if low == "timeout" then
      return nil, "timeout"
    elseif low == "eof" then
      return nil, "closed"
    elseif low == "error" then
      return nil, (type(b) == "string" and b) or "error"
    end
    if #a == n then
      return a
    end
    return nil, "short"
  end
  if type(a) == "number" then
    return b
  end
  return nil, "unexpected receive result"
end

function transport.new_udp()
  local sock = nmap.new_socket("udp")
  sock:set_timeout(1000)
  return sock
end

function transport.new_tcp()
  local sock = nmap.new_socket()
  sock:set_timeout(1000)
  return sock
end

-- UDP probe. Stray datagrams (duplicates from a previous run, ICMP-triggered
-- errors) are discarded until the deadline; only a DER-decodable Kerberos
-- message is accepted.
function transport.udp_exchange(host, port, payload, opts)
  local sock, err = transport.new_udp()
  if not sock then
    return nil, err or "cannot create UDP socket"
  end
  local ok, cerr = sock:connect(host, port)
  if not ok then
    sock:close()
    return nil, string.format("udp connect failed: %s", tostring(cerr))
  end
  local result, rtt
  local attempts = 0
  local max_attempts = (opts.retries or 2) + 1
  local deadline = timeutil.mono_ms() + (opts.timeout_ms * max_attempts) + 500

  while attempts < max_attempts and timeutil.mono_ms() < deadline do
    attempts = attempts + 1
    local sent_ok, serr = sock_send(sock, payload)
    if not sent_ok then
      sock:close()
      return nil, string.format("udp send failed: %s", tostring(serr))
    end
    local send_ms = timeutil.mono_ms()
    local per_try_deadline = send_ms + opts.timeout_ms
    while timeutil.mono_ms() < per_try_deadline do
      local remaining = math.max(200, per_try_deadline - timeutil.mono_ms())
      local data, reason = sock_recv(sock, remaining)
      if data then
        if krb.is_kerberos_message(data) then
          rtt = timeutil.mono_ms() - send_ms
          result = data
          break
        end
        -- Not Kerberos: keep listening until this attempt's deadline.
      elseif reason == "closed" or reason == "error" then
        break
      end
    end
    if result then
      break
    end
    if opts.delay_ms and opts.delay_ms > 0 and attempts < max_attempts then
      stdnse.sleep(opts.delay_ms / 1000)
    end
  end

  sock:close()
  if not result then
    return nil, "timeout", { attempts = attempts }
  end
  return result, nil, { attempts = attempts, rtt_ms = rtt }
end

-- TCP framing reader. NSE's receive_bytes(n) returns *everything* currently
-- buffered (which can exceed n) and may return fewer bytes than requested when
-- the peer is slow, so the reader maintains its own accumulator until the
-- 4-byte big-endian length prefix and the announced body have both arrived.
local function tcp_read_message(sock, timeout_ms)
  local buf = ""
  local deadline = timeutil.mono_ms() + timeout_ms
  while timeutil.mono_ms() < deadline do
    if #buf >= 4 then
      local n = string.byte(buf, 1) * 16777216 + string.byte(buf, 2) * 65536
                + string.byte(buf, 3) * 256 + string.byte(buf, 4)
      if n == 0 or n > 1048576 then
        return nil, string.format("implausible TCP length prefix (%d bytes)", n)
      end
      if #buf >= 4 + n then
        return string.sub(buf, 5, 4 + n)
      end
    end
    local chunk, reason = sock_recv_bytes(sock, 4, math.max(200, deadline - timeutil.mono_ms()))
    if chunk then
      buf = buf .. chunk
      if #buf > 2097152 then
        return nil, "TCP response exceeded 2 MiB sanity limit"
      end
    elseif reason == "timeout" or reason == "error" or reason == "short" then
      return nil, "timeout"
    elseif reason == "closed" then
      return nil, "closed"
    else
      return nil, reason
    end
  end
  return nil, "timeout"
end

-- TCP probe with the RFC 4120 four byte length prefix in both directions.
function transport.tcp_exchange(host, port, payload, opts)
  local sock = transport.new_tcp()
  local ok, cerr = sock:connect(host, port)
  if not ok then
    sock:close()
    return nil, string.format("tcp connect failed: %s", tostring(cerr))
  end

  local attempts = 0
  local max_attempts = (opts.retries or 2) + 1
  local result, rtt, last_err

  while attempts < max_attempts and not result do
    attempts = attempts + 1
    local len = #payload
    local framed = string.char(
      math.floor(len / 16777216) % 256,
      math.floor(len / 65536) % 256,
      math.floor(len / 256) % 256,
      len % 256
    ) .. payload

    local sent_ok, serr = sock_send(sock, framed)
    if not sent_ok then
      sock:close()
      return nil, string.format("tcp send failed: %s", tostring(serr))
    end
    local send_ms = timeutil.mono_ms()

    local body, reason = tcp_read_message(sock, opts.timeout_ms)
    if body then
      if krb.is_kerberos_message(body) then
        rtt = timeutil.mono_ms() - send_ms
        result = body
      else
        last_err = "response on TCP is not a Kerberos message"
      end
    else
      last_err = reason
      if reason == "closed" or reason == "error" then
        -- A KDC that closes the connection after (or instead of) answering is
        -- normal for TCP; reconnect before the next attempt.
        sock:close()
        sock = transport.new_tcp()
        local ok2 = sock:connect(host, port)
        if not ok2 then
          sock:close()
          return nil, "tcp reconnect failed"
        end
      end
    end
  end

  sock:close()
  if not result then
    return nil, last_err or "timeout", { attempts = attempts }
  end
  return result, nil, { attempts = attempts, rtt_ms = rtt }
end

-- Transport selection policy: "auto" starts on UDP and retries over TCP when
-- the KDC signals truncation (KRB_ERR_RESPONSE_TOO_BIG) or when the UDP answer
-- never arrives - the classic symptom of a KDC whose realm database produces
-- a reply larger than the client's UDP buffer.
function transport.exchange(host, port, payload, opts)
  local mode = opts.transport or "auto"
  local meta = { transport = mode, attempts = 0 }

  if mode == "tcp" then
    local data, err, info = transport.tcp_exchange(host, port, payload, opts)
    meta.attempts = (info and info.attempts) or 0
    meta.rtt_ms = info and info.rtt_ms
    meta.transport = "tcp"
    return data, err, meta
  end

  local data, err, info = transport.udp_exchange(host, port, payload, opts)
  meta.attempts = (info and info.attempts) or 0
  meta.rtt_ms = info and info.rtt_ms
  meta.transport = "udp"

  if data then
    local root = decoder.parse(data)
    local parsed_err = root and krb.parse_krb_error(root)
    if parsed_err and parsed_err.code == 52 then
      if mode == "auto" then
        local tdata, terr, tinfo = transport.tcp_exchange(host, port, payload, opts)
        meta.tcp_retry = true
        meta.transport = "tcp"
        meta.tcp_attempts = (tinfo and tinfo.attempts) or 0
        if tdata then
          return tdata, nil, meta
        end
        return nil, terr or "tcp retry failed", meta
      end
      return nil, "response too big for UDP and transport is fixed to udp", meta
    end
    return data, nil, meta
  end

  if mode == "auto" then
    local tdata, terr, tinfo = transport.tcp_exchange(host, port, payload, opts)
    meta.tcp_retry = true
    meta.transport = "tcp"
    meta.tcp_attempts = (tinfo and tinfo.attempts) or 0
    if tdata then
      return tdata, nil, meta
    end
    return nil, err or terr, meta
  end

  return nil, err, meta
end

-- Send one AS-REQ and decode whatever comes back into a normalised record.
function transport.as_req(host, port, req_opts, probe_opts)
  local payload = krb.build_as_req(req_opts)
  local data, err, meta = transport.exchange(host, port, payload, probe_opts)
  local record = {
    request_bytes = #payload,
    transport = meta and meta.transport,
    attempts = meta and meta.attempts,
    rtt_ms = meta and meta.rtt_ms,
    tcp_retry = meta and meta.tcp_retry,
  }
  if not data then
    record.error = err or "no response"
    return record
  end
  record.response_bytes = #data
  record.response_label = krb.message_label(data)

  local root = decoder.parse(data)
  if not root then
    record.error = "response is not decodable ASN.1"
    return record
  end

  local as_rep = krb.parse_as_rep(root)
  if as_rep then
    record.kind = "as_rep"
    record.as_rep = as_rep
    return record
  end

  local krb_err = krb.parse_krb_error(root)
  if krb_err then
    record.kind = "krb_error"
    record.krb_error = krb_err
    return record
  end

  record.kind = "other"
  record.error = "Kerberos message that is neither AS-REP nor KRB-ERROR"
  return record
end


-- ---------------------------------------------------------------------------
-- TGS-REQ / AP-REQ construction
--
-- A TGS request is what a client sends once it holds a TGT: the ticket travels
-- inside PA-TGS-REQ as an [APPLICATION 14] AP-REQ whose authenticator is
-- encrypted with the TGT session key. Audit scripts have two legitimate uses:
--
--   * with an operator supplied ticket (kerberos.ticket=hex) it observes the
--     encryption type the KDC picks for a service principal, which is the
--     authoritative answer to "is this SPN kerberoastable with RC4";
--   * with a deliberately malformed ticket it exercises the KDC *lookup* path.
--     The service principal is resolved before the ticket can be decrypted, so
--     KDC_ERR_S_PRINCIPAL_UNKNOWN (7) versus a decryption error
--     (KRB_AP_ERR_MODIFIED / KRB_AP_ERR_TKT_EXPIRED) discloses whether a
--     service principal exists, without any credential.
--
-- Neither use modifies KDC state, obtains a usable ticket, or authenticates.
-- ---------------------------------------------------------------------------

-- Ticket ::= [APPLICATION 1] SEQUENCE { tkt-vno [0], realm [1], sname [2],
--                                       enc-part [3] EncryptedData }
function krb.build_ticket(opts)
  return der.app(1, der.sequence(
    der.ctx(0, der.integer(KRB5_PROTOCOL_VERSION)),
    der.ctx(1, der.generalstring(opts.realm)),
    der.ctx(2, krb.principal(opts.sname_type or NT.SRV_INST, opts.sname)),
    der.ctx(3, der.sequence(
      der.ctx(0, der.integer(opts.etype or 18)),
      der.ctx(1, der.integer(opts.kvno or 2)),
      der.ctx(2, der.octetstring(opts.cipher or string.rep("Z", 64)))
    ))
  ))
end

-- AP-REQ ::= [APPLICATION 14] SEQUENCE { pvno [0], msg-type [1],
--                                        ap-options [2], ticket [3],
--                                        authenticator [4] EncryptedData }
function krb.build_ap_req(opts)
  return der.app(APP.AP_REQ, der.sequence(
    der.ctx(0, der.integer(KRB5_PROTOCOL_VERSION)),
    der.ctx(1, der.integer(MSG.AP_REQ)),
    der.ctx(2, der.bitstring(opts.ap_options or 0, 32)),
    der.ctx(3, opts.ticket),
    der.ctx(4, der.sequence(
      der.ctx(0, der.integer(opts.auth_etype or 18)),
      der.ctx(1, der.integer(opts.auth_kvno or 2)),
      der.ctx(2, der.octetstring(opts.authenticator or string.rep("A", 48)))
    ))
  ))
end

-- KDC-REQ for a service ticket. opts: realm, sname, sname_type, etypes, nonce,
-- ap_req, kdc_options, till, cname (omitted when a ticket is presented).
function krb.build_tgs_req(opts)
  local body = {
    der.ctx(0, der.bitstring(opts.kdc_options or 0, 32)),
    der.ctx(2, der.generalstring(opts.realm)),
    der.ctx(3, krb.principal(opts.sname_type or NT.SRV_INST, opts.sname)),
    der.ctx(5, der.generalizedtime(opts.till or timeutil.os_utc(0))),
    der.ctx(7, der.integer(opts.nonce)),
  }
  local etypes = {}
  for _, e in ipairs(opts.etypes or { 18, 17, 23 }) do
    etypes[#etypes + 1] = der.integer(e)
  end
  body[#body + 1] = der.ctx(8, der.sequence(table.concat(etypes)))
  if opts.cname then
    table.insert(body, 2, der.ctx(1, krb.principal(NT.PRINCIPAL, { opts.cname })))
  end

  local fields = {
    der.ctx(1, der.integer(KRB5_PROTOCOL_VERSION)),
    der.ctx(2, der.integer(MSG.TGS_REQ)),
    der.ctx(3, der.sequence(krb.padata(1, opts.ap_req))),
    der.ctx(4, der.sequence(table.concat(body))),
  }
  return der.app(APP.TGS_REQ, der.sequence(table.concat(fields)))
end

-- TGS-REP ::= [APPLICATION 13] KDC-REP: same layout as AS-REP, addressed to
-- the requested service.
function krb.parse_tgs_rep(root)
  local seq = krb.body(root, APP.TGS_REP)
  if not seq then
    return nil, "not a TGS-REP message"
  end
  local out = {
    pvno = decoder.integer_value(decoder.unwrap(seq, 0)),
    msg_type = decoder.integer_value(decoder.unwrap(seq, 1)),
    crealm = decoder.string_value(decoder.unwrap(seq, 3)),
  }
  local cname = decoder.unwrap(seq, 4)
  if cname then
    out.cname = krb.parse_principal(cname)
  end
  out.ticket = krb.parse_ticket_summary(decoder.unwrap(seq, 5))
  out.enc_part = krb.parse_encrypted_data(decoder.unwrap(seq, 6))
  return out
end

-- Send a TGS-REQ and normalise the answer.
function transport.tgs_req(host, port, req_opts, probe_opts)
  local payload = krb.build_tgs_req(req_opts)
  local data, err, meta = transport.exchange(host, port, payload, probe_opts)
  local record = {
    request_bytes = #payload,
    transport = meta and meta.transport,
    attempts = meta and meta.attempts,
    rtt_ms = meta and meta.rtt_ms,
    tcp_retry = meta and meta.tcp_retry,
  }
  if not data then
    record.error = err or "no response"
    return record
  end
  record.response_bytes = #data
  record.response_label = krb.message_label(data)
  local root = decoder.parse(data)
  if not root then
    record.error = "response is not decodable ASN.1"
    return record
  end
  local tgs_rep = krb.parse_tgs_rep(root)
  if tgs_rep then
    record.kind = "tgs_rep"
    record.tgs_rep = tgs_rep
    return record
  end
  local krb_err = krb.parse_krb_error(root)
  if krb_err then
    record.kind = "krb_error"
    record.krb_error = krb_err
    return record
  end
  record.kind = "other"
  record.error = "Kerberos message that is neither TGS-REP nor KRB-ERROR"
  return record
end

-- ---------------------------------------------------------------------------
-- msDS-SupportedEncryptionTypes helpers (MS-KILE / MS-ADTS)
--
-- The directory attribute that decides which long-term keys an account can
-- use. Decoding it explains *why* a KDC refused or accepted an etype, and it
-- is what the remediation advice tells the operator to change.
-- ---------------------------------------------------------------------------

function krb.decode_ms_etypes(value)
  local out = {}
  local function add(etype)
    for _, existing in ipairs(out) do
      if existing == etype then return end
    end
    out[#out + 1] = etype
  end
  if value == nil or value == 0 then
    -- Documented as "unset": the account inherits the domain default, which
    -- historically offers RC4 alongside AES.
    return out
  end
  if bit.band(value, 0x0001) ~= 0 then add(1) end
  if bit.band(value, 0x0002) ~= 0 then add(3) end
  if bit.band(value, 0x0004) ~= 0 then add(23) end
  -- Bit 0x0008 is documented as "AES128 and AES256 together"; 0x0010 and
  -- 0x0020 select a single AES strength.
  if bit.band(value, 0x0008) ~= 0 then add(17); add(18) end
  if bit.band(value, 0x0010) ~= 0 then add(18) end
  if bit.band(value, 0x0020) ~= 0 then add(17) end
  if bit.band(value, 0x0040) ~= 0 then add(19) end
  if bit.band(value, 0x0080) ~= 0 then add(20) end
  table.sort(out)
  return out
end

function krb.describe_ms_etypes(value)
  if value == nil then
    return "unset (account inherits the domain default, which historically includes RC4)"
  end
  if value == 0 then
    return "0 (explicitly unset: the account follows the domain default)"
  end
  local names = {}
  for _, etype in ipairs(krb.decode_ms_etypes(value)) do
    names[#names + 1] = string.format("%d %s", etype, krb.etype_info(etype).name)
  end
  return string.format("0x%04X (%s)", value, table.concat(names, ", "))
end

M.ETYPE = ETYPE
M.ETYPE_DEFAULT = ETYPE_DEFAULT
M.ETYPE_OFFER_DEFAULT = ETYPE_OFFER_DEFAULT
M.ETYPE_OFFER_WEAK = ETYPE_OFFER_WEAK
M.ETYPE_OFFER_STRONG = ETYPE_OFFER_STRONG
M.KRB5_ERR = KRB5_ERR
M.PADATA = PADATA
M.KDCOPT = KDCOPT
M.TKTFLAG = TKTFLAG
M.MSG = MSG
M.APP = APP
M.NT = NT
M.TAG = TAG
M.TAGNO = TAGNO
M.SCRIPT_VERSION = SCRIPT_VERSION
M.KRB5_PROTOCOL_VERSION = KRB5_PROTOCOL_VERSION
M.der = der
M.decoder = decoder
M.timeutil = timeutil
M.krb = krb
M.transport = transport

return M
