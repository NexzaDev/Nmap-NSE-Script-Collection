local stdnse = require "stdnse"
local kafka = require "kafka"
local shortport = require "shortport"
description = [[Internal 64-bit helper probe.]]
author = "internal"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe"}
portrule = function() return true end
action = function()
  local out = stdnse.output_table()
  local X = { 0x12345678, 0x9ABCDEF0 }
  local Y = { 0xFEDCBA98, 0x76543210 }
  local function f(n)
    local hi, lo = kafka._u64_rotr(X[1], X[2], n)
    local hi2, lo2 = kafka._u64_rotr(Y[1], Y[2], n)
    return kafka.hex(hi, 8) .. kafka.hex(lo, 8) .. " " .. kafka.hex(hi2, 8) .. kafka.hex(lo2, 8)
  end
  for _, n in ipairs({1, 8, 14, 18, 19, 28, 34, 39, 41, 61}) do
    local hi, lo = kafka._u64_rotr(X[1], X[2], n)
    local hi2, lo2 = kafka._u64_rotr(Y[1], Y[2], n)
    out["rotr" .. n .. "x"] = kafka.hex(hi, 8) .. kafka.hex(lo, 8)
    out["rotr" .. n .. "y"] = kafka.hex(hi2, 8) .. kafka.hex(lo2, 8)
  end
  for _, n in ipairs({6, 7}) do
    local hi, lo = kafka._u64_shr(X[1], X[2], n)
    out["shr" .. n .. "x"] = kafka.hex(hi, 8) .. kafka.hex(lo, 8)
  end
  local hi, lo = kafka._u64_add(X[1], X[2], Y[1], Y[2])
  out.add = kafka.hex(hi, 8) .. kafka.hex(lo, 8)
  local h2, l2 = kafka._u64_add(0xFFFFFFFF, 0xFFFFFFFF, 0, 1)
  out.add0 = kafka.hex(h2, 8) .. kafka.hex(l2, 8)
  return out
end
