local stdnse = require "stdnse"
local kafka = require "kafka"
local shortport = require "shortport"

-- Internal fixture: pins the crypto primitives the Kafka engine builds on
-- (SHA-256, SHA-512, HMAC, PBKDF2, CRC-32C, base64) against published test
-- vectors, so a regression in the wire code cannot hide behind a passing
-- protocol test.
description = [[Internal crypto self-test fixture for nselib/kafka.lua.]]
author = "internal"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe"}

portrule = function() return true end

action = function()
  local out = stdnse.output_table()
  local function hex(s)
    local t = {}
    for i = 1, #s do t[#t + 1] = string.format("%02x", string.byte(s, i)) end
    return table.concat(t)
  end
  out.sha256_abc = hex(kafka.hash.sha256("abc"))
  out.sha256_empty = hex(kafka.hash.sha256(""))
  out.sha256_long = hex(kafka.hash.sha256(string.rep("a", 1000)))
  out.sha512_abc = hex(kafka.hash.sha512("abc"))
  out.sha512_empty = hex(kafka.hash.sha512(""))
  out.rotr = kafka.int(kafka.rotr32(1, 1)) .. "/" .. kafka.int(kafka.rotr32(2147483648, 31))
  out.band = kafka.int(kafka.band32(4042322160, 4278255360))
  out.bxor = kafka.int(kafka.bxor32(4294967295, 65535))
  out.bnot = kafka.int(kafka.bnot32(0))
  out.addwrap = kafka.int(kafka.add32(4294967295, 1))
  out.crc32c = kafka.hex(kafka.crc32c("123456789"))
  out.b64 = kafka.base64_encode("Kafka!") .. "/" .. kafka.base64_decode("S2Fma2Eh")
  out.hmac = hex(kafka.hmac(kafka.HASH["SHA-256"], "key", "The quick brown fox jumps over the lazy dog"))
  out.pbkdf2 = hex(kafka.pbkdf2(kafka.HASH["SHA-256"], "password", "salt", 1, 32))
  return out
end
