"""Protocol mock prelude, part 3, for the NSE smoke-test harness.

SMB, DB, FTP, TLS mocks, the mock socket and the run_script runner.
Concatenated last at runtime; see smoke_nse.py.
"""

MOCK_PRELUDE_EXTRA2 = r"""
local function smb_mock_reply(scenario, data, port, sock)
  if scenario ~= "smb" and scenario ~= "smb-hardened" then
    return nil
  end
  local hardened = (scenario == "smb-hardened")
  local st = sock.smbstate
  if st == nil then
    st = { dialect = nil, session = nil, ntlem_offered = nil }
    sock.smbstate = st
  end
  local payload = tostring(data)
  local netbios = false
  if port == 139 and #payload >= 17 then
    if smbb(payload, 0) == 0 or smbb(payload, 0) == 0x80 then
      netbios = true
      payload = real_string.sub(payload, 18)
    end
  end
  if #payload < 32 then
    return nil
  end
  local is_s1 = (smbb(payload, 0) == 0xff and payload:sub(2, 4) == "SMB")
  local is_s2 = (smbb(payload, 0) == 0xfe and payload:sub(2, 4) == "SMB")
  if not is_s1 and not is_s2 then
    return nil
  end
  local function wrap(resp)
    if netbios then
      local hdr = string.char(0) .. smb_u16(#resp) .. string.char(0, 0x80)
        .. smb_u16(0x1f0) .. string.char(0, 0) .. "CORP\0\0\0\0"
      return hdr .. resp
    end
    return resp
  end

  if is_s1 then
    local cmd = smbb(payload, 4)
    local mid = smb32(payload, 12)
    if cmd == 0x00 then
      local offered = smb_parse_s1_dialects(payload)
      local has_smb2or3 = false
      for _, d in ipairs(offered) do
        if real_string.sub(d, 1, 3) == "SMB" then
          has_smb2or3 = true
        end
      end
      if has_smb2or3 then
        st.dialect = "SMB 3.1.1"
        return wrap(smb_negotiate_s2_reply(0x0311, hardened and 3 or 1))
      end
      if hardened then
        st.dialect = "SMB 3.1.1"
        return wrap(smb_negotiate_s1_reply(offered, true))
      end
      st.dialect = "NT LM 0.12"
      return wrap(smb_negotiate_s1_reply(offered, false))
    end
    if st.dialect == nil or real_string.sub(st.dialect, 1, 3) == "SMB" then
      return wrap(smb_s1_header(cmd, 0x0005, 0x51, mid))
    end
    if cmd == 0x0f then
      local bloblen = smb16(payload, 39)
      local blob = real_string.sub(payload, 44, 43 + bloblen)
      local mech = "none"
      local user, domain = "", ""
      if real_string.sub(blob, 1, 7) == "NTLMSSP" and #blob >= 16 then
        local mtype = smbb(blob, 8)
        if mtype == 1 then
          local flags = smb32(blob, 12)
          mech = "ntlm"
          if math.floor(flags / 33554432) % 2 == 1 then
            mech = "ntlmv2"
          end
          st.ntlem_offered = mech
        elseif mtype == 3 then
          mech = st.ntlem_offered or "ntlm"
          user, domain = smb_ntlm_auth_user(blob)
        end
        st.msg_type = mtype
      end
      if st.msg_type == 1 then
        st.msg_type = nil
        local challenge = string.char(0x5a, 0x42, 0x11, 0x9c, 0x77, 0x3d, 0xe0, 0x8f)
        return wrap(smb_s1_session_setup_reply(0, 0,
          smb_ntlm_challenge(challenge, 0x1b0201, "CORP")))
      end
      st.last_user = user
      local ok, action, status = smb_session_decision(user, mech, hardened)
      if ok then
        st.session = { user = user, action = action, mech = mech, domain = domain }
        local challenge = string.char(0x5a, 0x42, 0x11, 0x9c, 0x77, 0x3d, 0xe0, 0x8f)
        return wrap(smb_s1_session_setup_reply(0, action,
          smb_ntlm_challenge(challenge, 0x1b0201, "CORP")))
      end
      return wrap(smb_s1_session_setup_reply(status, nil, ""))
    end
    if cmd == 0x75 or cmd == 0x03 then
      if not st.session then
        return wrap(smb_s1_header(cmd, 0xc000006d, 0x51, mid))
      end
      local plen = smb16(payload, 41)
      local p = real_string.sub(payload, 45, 44 + plen)
      local ppath = real_string.gsub(p, "\\", "/")
      local name = real_string.match(ppath, "/([^/]*)$") or ppath
      name = real_string.lower(name)
      local status, service, access = smb_tree_decision(name, st.session, hardened)
      if status == 0x0016 then
        return wrap(smb_s1_tree_connect_reply(status, service, access, nil, smb_dfs_referral()))
      end
      if status > 0 then
        return wrap(smb_s1_tree_connect_reply(status))
      end
      return wrap(smb_s1_tree_connect_reply(0, service, access, "\\" .. name))
    end
    if cmd == 0x07 then
      local dlen = smb16(payload, 35)
      local d = real_string.sub(payload, 38, 37 + dlen)
      local params = smb_u16(65536) .. string.char(0) .. smb_u16(#d)
      return wrap(smb_s1_header(0x07, 0, 0x51, mid) .. params .. d)
    end
    return wrap(smb_s1_header(cmd, 0xc00000cc, 0x51, mid))
  end

  local cmd = smb16(payload, 16)
  local mid = smb32(payload, 20)
  if cmd == 0x0000 then
    local dcount = smb16(payload, 66)
    local pos = 91
    local best = 0
    for i = 1, dcount do
      local code = smb16(payload, pos)
      if code > best then best = code end
      pos = pos + 6
    end
    local codes = { [0x0202] = "SMB 2.002", [0x0210] = "SMB 2.1.0", [0x0300] = "SMB 3.0.0", [0x0302] = "SMB 3.0.2", [0x0311] = "SMB 3.1.1" }
    if best == 0x0202 then best = 0x0210 end
    st.dialect = codes[best] or "SMB 3.1.1"
    return wrap(smb_negotiate_s2_reply(best, hardened and 3 or 1))
  end
  if st.dialect == nil then
    return wrap(smb_s2_header(cmd, 0xc0000121, 0, mid))
  end
  if cmd == 0x0002 then
    local bloboff = smb16(payload, 116)
    local bloblen = smb16(payload, 118)
    local blob = real_string.sub(payload, 112 + bloboff + 1, 111 + bloboff + bloblen)
    local mech = "none"
    local user, domain = "", ""
    if real_string.sub(blob, 1, 7) == "NTLMSSP" and #blob >= 16 then
      local mtype = smbb(blob, 8)
      if mtype == 1 then
        local flags = smb32(blob, 12)
        mech = "ntlm"
        if math.floor(flags / 33554432) % 2 == 1 then
          mech = "ntlmv2"
        end
        st.ntlem_offered = mech
      elseif mtype == 3 then
        mech = st.ntlem_offered or "ntlm"
        user, domain = smb_ntlm_auth_user(blob)
      end
      st.msg_type = mtype
    end
    if st.msg_type == 1 then
      st.msg_type = nil
      local challenge = string.char(0x5a, 0x42, 0x11, 0x9c, 0x77, 0x3d, 0xe0, 0x8f)
      local sig = smb_ntlm_challenge(challenge, 0x1b0201, "CORP")
      local params = smb_u16(9) .. string.char(0x00) .. smb_u16(170) .. smb_u16(#sig) .. sig
      return wrap(smb_s2_header(0x0002, 0, 0, mid) .. params)
    end
    st.last_user = user
    local ok, action, status = smb_session_decision(user, mech, hardened)
    if ok then
      st.session = { user = user, action = action, mech = mech, domain = domain }
      local sig = "NTLMSSP\0"
      local params = smb_u16(9) .. string.char(0x00) .. smb_u16(170) .. smb_u16(#sig) .. sig
      return wrap(smb_s2_header(0x0002, 0, 0, mid) .. params)
    end
    return wrap(smb_s2_header(0x0002, status, 0, mid))
  end
  if cmd == 0x0003 then
    if not st.session then
      return wrap(smb_s2_header(0x0003, 0xc000006d, 0, mid))
    end
    local off = smb16(payload, 116)
    local l = smb16(payload, 118)
    local p = real_string.sub(payload, 112 + off + 1, 111 + off + l)
    p = real_string.gsub(real_string.lower(smb_utf16le_to_ascii(p)), "\\", "/")
    local name = real_string.match(p, "/?([^/]*)$") or p
    local status, service, access = smb_tree_decision(name, st.session, hardened)
    local function s2_tree(svc, acc, sharename)
      local sn = ""
      for i = 1, #sharename do
        sn = sn .. real_string.char(sharename:byte(i), 0)
      end
      local params = smb_u16(16) .. string.char(svc or 1, 0)
        .. smb_u32(0) .. smb_u32(0) .. smb_u32(acc or 0x001f01ff)
        .. smb_u64(132000000000000000)
        .. smb_u64(132000000000000000)
        .. smb_u64(132000000000000000)
        .. smb_u32(1)
        .. smb_u16(#sn) .. sn
      return wrap(smb_s2_header(0x0003, 0, 0, mid) .. params)
    end
    if status == 0x0016 then
      local ref = smb_dfs_referral()
      local params = smb_u16(16) .. string.char(0x01, 0) .. smb_u32(0) .. smb_u32(0)
        .. smb_u32(0)
        .. smb_u64(132000000000000000)
        .. smb_u64(132000000000000000)
        .. smb_u64(132000000000000000)
        .. smb_u32(1) .. smb_u16(0)
        .. ref
      return wrap(smb_s2_header(0x0003, 0x0016, 0, mid) .. params)
    end
    if status > 0 then
      return wrap(smb_s2_header(0x0003, status, 0, mid))
    end
    return s2_tree(service, access, name)
  end
  if cmd == 0x0012 then
    return wrap(smb_s2_header(0x0012, 0, 0, mid) .. smb_u16(4))
  end
  return wrap(smb_s2_header(cmd, 0xc00000cc, 0, mid))
end

TLS_CERT_MODERN_B64 = ""
TLS_CERT_LEGACY_B64 = ""
TLS_DH_2048_HEX = ""
TLS_DH_1024_HEX = ""

local TLS_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

local function tls_b64decode(s)
  s = s:gsub("[^%w%/%+=]", "")
  local pad = s:find("%=$", 1, true)
  if pad then
    s = s:sub(1, pad - 1)
  end
  local out = {}
  for i = 1, #s, 4 do
    local chunk = s:sub(i, i + 3)
    local n = 0
    for j = 1, #chunk do
      local c = chunk:sub(j, j)
      local v = TLS_B64_ALPHABET:find(c) or 0
      n = n * 64 + (v - 1)
    end
    out[#out + 1] = string.char(math.floor(n / 65536) % 256)
    out[#out + 1] = string.char(math.floor(n / 256) % 256)
    out[#out + 1] = string.char(n % 256)
  end
  return table.concat(out)
end

local function tls_hex2bin(h)
  h = h:gsub("[^%x]", "")
  if #h % 2 == 1 then
    h = "0" .. h
  end
  local out = {}
  for i = 1, #h, 2 do
    out[#out + 1] = string.char(tonumber(h:sub(i, i + 1), 16))
  end
  return table.concat(out)
end

local tls_asset_cache = {}

local function tls_cert_der(scenario)
  if tls_asset_cache.cert == nil then
    tls_asset_cache.modern = tls_b64decode(TLS_CERT_MODERN_B64)
    tls_asset_cache.legacy = tls_b64decode(TLS_CERT_LEGACY_B64)
    tls_asset_cache.dh2048 = tls_hex2bin(TLS_DH_2048_HEX)
    tls_asset_cache.dh1024 = tls_hex2bin(TLS_DH_1024_HEX)
    tls_asset_cache.cert = true
  end
  if scenario == "tls" then
    return tls_asset_cache.modern
  end
  return tls_asset_cache.legacy
end

local function tls_dh_prime(scenario)
  tls_cert_der(scenario)
  if scenario == "tls" then
    return tls_asset_cache.dh2048
  end
  return tls_asset_cache.dh1024
end

local function tls_u16(n)
  return string.char(math.floor(n / 256) % 256, n % 256)
end

local function tls_u24(n)
  return string.char(math.floor(n / 65536) % 256, math.floor(n / 256) % 256, n % 256)
end

local function tls_rec(rtype, version, payload)
  return string.char(rtype, math.floor(version / 256) % 256, version % 256)
    .. tls_u16(#payload) .. payload
end

local function tls_hs(rtype, body)
  return string.char(rtype) .. tls_u24(#body) .. body
end

local function tls_alert(level, code, version)
  return tls_rec(21, version or 0x0303, string.char(level, code))
end

local function tls_parse_client_hello(body)
  local info = {}
  local off = 1
  if #body < 4 or body:byte(off) ~= 1 then
    return nil
  end
  off = off + 4
  if #body < off + 2 then
    return nil
  end
  info.legacy_version = body:byte(off) * 256 + body:byte(off + 1)
  off = off + 2
  info.random = body:sub(off, off + 31)
  off = off + 32
  if off > #body then
    return nil
  end
  local sidlen = body:byte(off)
  off = off + 1
  if off + sidlen - 1 > #body then
    return nil
  end
  info.session_id = body:sub(off, off + sidlen - 1)
  off = off + sidlen
  if off + 1 > #body then
    info.ciphers = {}
    info.comps = { 0 }
    return info
  end
  local cslen = body:byte(off) * 256 + body:byte(off + 1)
  if off + cslen - 1 > #body then
    return nil
  end
  off = off + 2
  info.ciphers = {}
  local ci = off
  local ci_end = off + cslen - 1
  while ci <= ci_end - 1 do
    local hi = body:byte(ci)
    local lo = body:byte(ci + 1)
    info.ciphers[#info.ciphers + 1] = hi * 256 + lo
    ci = ci + 2
  end
  off = off + cslen
  if off > #body then
    return nil
  end
  local clen = body:byte(off)
  off = off + 1
  if off + clen - 1 > #body then
    return nil
  end
  info.comps = {}
  for i = 0, clen - 1 do
    info.comps[#info.comps + 1] = body:byte(off + i)
  end
  off = off + clen
  if off + 1 <= #body then
    local elen = body:byte(off) * 256 + body:byte(off + 1)
    off = off + 2
    info.exts = {}
    local end_off = off + elen
    if end_off > #body then
      end_off = #body
    end
    while off + 3 <= end_off do
      local eid = body:byte(off) * 256 + body:byte(off + 1)
      local el = body:byte(off + 2) * 256 + body:byte(off + 3)
      off = off + 4
      if off + el - 1 > #body then
        return nil
      end
      info.exts[eid] = body:sub(off, off + el - 1)
      off = off + el
    end
  end
  return info
end

function tls_debug_parse(body)
  if #body < 4 then
    return "short " .. #body
  end
  if body:byte(1) ~= 1 then
    return "type=" .. body:byte(1)
  end
  local declared = body:byte(2) * 65536 + body:byte(3) * 256 + body:byte(4)
  local actual = #body - 4
  local ok, ch = pcall(tls_parse_client_hello, body)
  if not ok or ch == nil then
    return "declared=" .. declared .. " actual=" .. actual .. " parse failed"
  end
  local ncs = #ch.ciphers
  local ncomps = #ch.comps
  local nex = 0
  if ch.exts then
    for _ in pairs(ch.exts) do
      nex = nex + 1
    end
  end
  return string.format("declared=%d actual=%d ver=0x%04x cs=%d comps=%d exts=%d",
    declared, actual, ch.legacy_version, ncs, ncomps, nex)
end

local function tls_ocsp_response()
  local function tlv(tag, content)
    local ln = #content
    local lenb
    if ln < 0x80 then
      lenb = string.char(ln)
    else
      lenb = string.char(0x81, ln)
    end
    return string.char(tag) .. lenb .. content
  end
  local hash_alg = tlv(0x30, tlv(0x06,
    string.char(0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05)) .. tlv(0x05, ""))
  local certid = tlv(0x30, tlv(0x30, hash_alg)
    .. tlv(0x04, string.rep("a", 20))
    .. tlv(0x04, string.rep("b", 20))
    .. tlv(0x02, string.char(0, 1, 0xab, 0)))
  local this_update = tlv(0x17, "260901000000Z")
  local next_update = tlv(0x17, "260922000000Z")
  local single = tlv(0x30, certid .. tlv(0x30, tlv(0x0a, "")) .. this_update .. next_update)
  local responses = tlv(0x31, single)
  local data = tlv(0x30, certid .. this_update .. next_update .. responses)
  return tlv(0x30, string.char(0) .. tlv(0xa1, data))
end

local TLS_MODERN_PREF = {
  0x1301, 0x1302, 0x1303,
  0xC02F, 0xC030,
  0xCCA8, 0xCCA9,
  0xC00A, 0xC009,
  0x009C, 0x0039,
  0x006B, 0x0067,
  0x0035, 0x0033,
}

local TLS_DHE_SUITES = {
  [0x0033] = true,
  [0x0034] = true,
  [0x0035] = true,
  [0x0036] = true,
  [0x0038] = true,
  [0x003A] = true,
  [0x0067] = true,
  [0x006B] = true,
}

local TLS_LEGACY_PREF = {
  0x0035, 0x009E, 0x009D, 0x0033, 0x0032,
  0x000A, 0x0016, 0x0013, 0x0005, 0x0004,
  0x0001, 0x0002, 0x0003, 0x0006, 0x0007,
  0x000C, 0x000D, 0x0009, 0x002F,
  0x0034, 0x0036, 0x0037, 0x0038, 0x0039,
  0x003A, 0x003B, 0x0067, 0x006B,
  0x009C, 0x009F,
  0xC008, 0xC009, 0xC00A,
  0xC02B, 0xC02C, 0xC02F, 0xC030,
}

local function tls_cipher_key_exchange(cipher)
  if TLS_DHE_SUITES[cipher] then
    return "dhe"
  end
  return "static"
end

local function tls_build_server_hello(scenario, ch, sel)
  local exts = {}
  if ch.exts ~= nil and ch.exts[0x0000] ~= nil then
    local sni = ch.exts[0x0000]
    exts[#exts + 1] = tls_u16(0x0000) .. tls_u16(#sni) .. sni
  end
  if scenario == "tls" and ch.exts ~= nil and ch.exts[0x0010] ~= nil then
    local alpn = ch.exts[0x0010]
    local chosen = "http/1.1"
    if alpn:find("ntske/1", 1, true) then
      chosen = "ntske/1"
    elseif alpn:find("h2", 1, true) then
      chosen = "h2"
    end
    local payload = tls_u16(#chosen) .. chosen
    exts[#exts + 1] = tls_u16(0x0010) .. tls_u16(#payload) .. payload
  end
  if scenario == "tls" and ch.exts ~= nil and ch.exts[0x0005] ~= nil then
    local sr = ch.exts[0x0005]
    exts[#exts + 1] = tls_u16(0x0005) .. tls_u16(#sr) .. sr
  end
  if sel.version == 0x0304 then
    exts[#exts + 1] = tls_u16(0x002b) .. tls_u16(2) .. string.char(0x03, 0x04)
  end
  if ch.exts ~= nil and ch.exts[0xff01] ~= nil then
    local ri = ch.exts[0xff01]
    exts[#exts + 1] = tls_u16(0xff01) .. tls_u16(#ri) .. ri
  end
  local ext_block = ""
  if #exts > 0 then
    local ext_data = table.concat(exts, "")
    ext_block = tls_u16(#ext_data) .. ext_data
  end
  local body = tls_u16(sel.version) .. string.rep("R", 32)
    .. string.char(#ch.session_id) .. ch.session_id
    .. tls_u16(sel.cipher) .. string.char(sel.comp) .. ext_block
  return tls_rec(22, 0x0303, tls_hs(2, body))
end

local function tls_build_reply(scenario, ch)
  local legacy = (scenario ~= "tls")
  local offers_13 = ch.exts ~= nil
    and ch.exts[0x002b] ~= nil
    and ch.exts[0x002b]:find(string.char(0x03, 0x04), 1, true) ~= nil
  local sv
  if legacy then
    if ch.legacy_version >= 0x0303 then
      sv = 0x0303
    elseif ch.legacy_version >= 0x0302 then
      sv = 0x0302
    elseif ch.legacy_version >= 0x0301 then
      sv = 0x0301
    elseif ch.legacy_version >= 0x0300 then
      sv = 0x0300
    else
      return nil, tls_alert(2, 70, 0x0303), nil
    end
  else
    if offers_13 then
      sv = 0x0304
    elseif ch.legacy_version >= 0x0303 then
      sv = 0x0303
    else
      return nil, tls_alert(2, 70, 0x0303), nil
    end
  end
  local offered = ch.ciphers or {}
  local chosen = nil
  if sv == 0x0304 then
    for _, have in ipairs(offered) do
      if have >= 0x1301 and have <= 0x1303 then
        chosen = have
        break
      end
    end
    if chosen == nil then
      sv = 0x0303
    end
  end
  if chosen == nil then
    local pref = legacy and TLS_LEGACY_PREF or TLS_MODERN_PREF
    for _, want in ipairs(pref) do
      for _, have in ipairs(offered) do
        if have == want then
          chosen = want
          break
        end
      end
      if chosen ~= nil then
        break
      end
    end
  end
  if chosen == nil then
    return nil, tls_alert(2, 120, 0x0303), nil
  end
  local comp = 0
  if legacy then
    for _, c in ipairs(ch.comps or {}) do
      if c == 1 then
        comp = 1
        break
      end
    end
  end
  local recv = 0x0303
  if sv ~= 0x0304 then
    recv = sv
  end
  local out = {}
  out[#out + 1] = tls_build_server_hello(scenario, ch,
    { version = sv, cipher = chosen, comp = comp })
  local cert = tls_cert_der(scenario)
  out[#out + 1] = tls_rec(22, recv, tls_hs(11, tls_u24(3 + #cert) .. tls_u24(#cert) .. cert))
  if not legacy and sv == 0x0303 and ch.exts ~= nil and ch.exts[0x0005] ~= nil then
    local ocsp = tls_ocsp_response()
    out[#out + 1] = tls_rec(22, recv, tls_hs(5, string.char(1) .. tls_u24(#ocsp) .. ocsp))
  end
  if sv ~= 0x0304 and tls_cipher_key_exchange(chosen) == "dhe" then
    local prime = tls_dh_prime(scenario)
    local ske = tls_u16(#prime) .. prime .. string.char(1, 2)
    out[#out + 1] = tls_rec(22, recv, tls_hs(12, ske))
  end
  out[#out + 1] = tls_rec(22, recv, tls_hs(14, ""))
  return table.concat(out), nil, { version = sv, cipher = chosen, comp = comp, kx = tls_cipher_key_exchange(chosen) }
end

function tls_mock_reply(scenario, data, sock)
  local st = sock.tlsstate
  if st == nil then
    st = { phase = "start" }
    sock.tlsstate = st
  end
  local legacy = (scenario ~= "tls")
  local out = ""
  local off = 1
  while off + 5 <= #data do
    local rtype = data:byte(off)
    local rlen = data:byte(off + 3) * 256 + data:byte(off + 4)
    local payload = data:sub(off + 5, off + 4 + rlen)
    off = off + 5 + rlen
    if st.phase == "closed" then
      return nil
    end
    if rtype == 22 and #payload > 0 and payload:byte(1) == 1 then
      if st.phase == "open" then
        if not legacy then
          local probe = tls_parse_client_hello(payload)
          if probe == nil or probe.exts == nil or probe.exts[0xff01] == nil then
            st.phase = "closed"
            return tls_alert(2, 100, 0x0303)
          end
        end
        st.phase = "start"
      end
      local ch = tls_parse_client_hello(payload)
      if ch == nil then
        st.phase = "closed"
        return tls_alert(2, 80, 0x0303)
      end
      if not legacy then
        for _, c in ipairs(ch.ciphers or {}) do
          if c == 0x5600 then
            st.phase = "closed"
            return tls_alert(2, 86, 0x0303)
          end
        end
      end
      local reply, err, meta = tls_build_reply(scenario, ch)
      if err ~= nil then
        st.phase = "closed"
        return err
      end
      st.phase = "awaiting_cdx"
      st.selected_version = meta.version
      st.selected_cipher = meta.cipher
      st.selected_comp = meta.comp
      st.kx = meta.kx
      out = out .. reply
    elseif rtype == 22 or rtype == 20 then
      if st.phase == "awaiting_cdx" then
        st.phase = "open"
        if st.selected_version == 0x0304 then
          out = out .. tls_rec(22, 0x0303, tls_hs(4, tls_u16(32) .. string.rep("t", 32)))
          out = out .. tls_rec(22, 0x0303, tls_hs(20, string.rep("F", 12)))
        else
          out = out .. tls_rec(20, st.selected_version, "")
          out = out .. tls_rec(22, st.selected_version, tls_hs(20, string.rep("F", 12)))
        end
      end
    elseif rtype == 24 then
      if legacy then
        local plen = payload:byte(2) * 256 + payload:byte(3)
        local p = payload:sub(20, 19 + plen)
        local resp = string.char(1) .. tls_u16(#p) .. string.rep("r", 16) .. p .. string.rep("A", 64)
        out = out .. tls_rec(24, 0x0303, resp)
      else
        st.phase = "closed"
        return tls_alert(2, 10, 0x0303)
      end
    end
  end
  if out == "" then
    return nil
  end
  return out
end

local function tls_http_reply(scenario, request)
  local text = tostring(request or "")
  local target = string.match(text, "^[A-Z]+ ([^ ]+) HTTP/") or "/"
  local body = "<html><body><h1>Mock TLS Service</h1><p>path: " .. target .. "</p></body></html>"
  local lines = {}
  lines[#lines + 1] = "HTTP/1.1 200 OK\r\n"
  lines[#lines + 1] = "Server: nginx/1.24.0\r\n"
  lines[#lines + 1] = "Date: Tue, 22 Sep 2026 10:00:00 GMT\r\n"
  if scenario == "tls" then
    lines[#lines + 1] = "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\r\n"
  end
  lines[#lines + 1] = "Content-Type: text/html\r\n"
  lines[#lines + 1] = "Content-Length: " .. #body .. "\r\n"
  lines[#lines + 1] = "Connection: close\r\n"
  lines[#lines + 1] = "\r\n"
  lines[#lines + 1] = body
  return table.concat(lines, "")
end

local function db_u16be(n)
  return string.char(math.floor(n / 256) % 256, n % 256)
end

local function db_u16le(n)
  return string.char(n % 256, math.floor(n / 256) % 256)
end

local function db_u24be(n)
  return string.char(math.floor(n / 65536) % 256, math.floor(n / 256) % 256, n % 256)
end

local function db_u32be(n)
  return string.char(math.floor(n / 16777216) % 256, math.floor(n / 65536) % 256,
    math.floor(n / 256) % 256, n % 256)
end

local function db_u32le(n)
  return string.char(n % 256, math.floor(n / 256) % 256, math.floor(n / 65536) % 256,
    math.floor(n / 16777216) % 256)
end

local function db_b16be(b)
  return b:byte(1) * 256 + b:byte(2)
end

local function db_b32be(b)
  return b:byte(1) * 16777216 + b:byte(2) * 65536 + b:byte(3) * 256 + b:byte(4)
end

local function db_pack_double_be(value)
  local negative = 0
  if value < 0 then
    negative = 0x80000000
    value = -value
  end
  local exponent = 0
  local mantissa = value
  while mantissa >= 2 and exponent < 1023 do
    mantissa = mantissa / 2
    exponent = exponent + 1
  end
  while mantissa < 1 and exponent > -1022 do
    mantissa = mantissa * 2
    exponent = exponent - 1
  end
  local biased = exponent + 1023
  local frac = math.floor((mantissa - 1) * 4503599627370496 + 0.5)
  local hi = (negative + biased * 1048576 + math.floor(frac / 4294967296)) % 4294967296
  local lo = frac % 4294967296
  return db_u32le(lo) .. db_u32le(hi)
end

local function db_bson_doc(pairs_list)
  local inner = ""
  for _, p in ipairs(pairs_list) do
    if p[1] == "i32" then
      inner = inner .. string.char(0x10) .. p[2] .. "\0" .. db_u32le(p[3])
    elseif p[1] == "s" then
      local data = p[3] .. "\0"
      inner = inner .. string.char(0x02) .. p[2] .. "\0" .. db_u32le(#data) .. data
    elseif p[1] == "d" then
      inner = inner .. string.char(0x01) .. p[2] .. "\0" .. db_pack_double_be(p[3])
    elseif p[1] == "b" then
      inner = inner .. string.char(0x08) .. p[2] .. "\0" .. string.char(p[3] and 1 or 0)
    end
  end
  return db_u32le(5 + #inner) .. inner .. "\0"
end

local function db_opmsg_reply(doc_bytes)
  local body = string.char(0, 0) .. doc_bytes
  return db_u32be(16 + #body) .. db_u32le(2) .. db_u32le(1) .. db_u32be(2013) .. body
end

local function db_opreply_error(doc_bytes)
  return db_u32be(16 + #doc_bytes) .. db_u32le(2) .. db_u32le(1) .. db_u32be(1) .. doc_bytes
end

local function db_cass_frame_reply(opcode, body)
  return string.char(4, 0) .. db_u16be(0) .. string.char(opcode) .. db_u32be(#body) .. body
end

local function db_cass_ready()
  return db_cass_frame_reply(2, "")
end

local function db_cass_error(code, message)
  local body = db_u32be(code) .. db_u16be(#message) .. message .. db_u16be(0)
  return db_cass_frame_reply(0, body)
end

local function db_cass_result_rows(cells)
  local meta = string.char(0, 0, 0) .. db_u16be(1)
  local rows_body = db_u16be(#cells)
  for _, c in ipairs(cells) do
    if c == nil then
      rows_body = rows_body .. db_u32be(4294967295)
    else
      rows_body = rows_body .. db_u32be(#c) .. c
    end
  end
  local body = string.char(1) .. db_u24be(#meta) .. meta .. rows_body
  return db_cass_frame_reply(4, body)
end

local function db_mysql_server_handshake(scenario)
  local secure = (scenario == "db-secure")
  local version = secure and "8.0.32" or "5.7.42-log"
  local caps = 0x8A201
  if not secure then
    caps = caps + 0x0800
  end
  local auth1 = string.char(0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88)
  local auth2 = string.char(0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
    0x10, 0x20, 0x30, 0x40) .. "\0"
  local payload = string.char(10) .. version .. "\0"
  payload = payload .. db_u32le(7)
  payload = payload .. auth1
  payload = payload .. string.char(0)
  payload = payload .. db_u16le(caps % 65536)
  payload = payload .. string.char(0x21)
  payload = payload .. db_u16le(0x0002)
  payload = payload .. db_u16le(math.floor(caps / 65536) % 65536)
  payload = payload .. string.char(21)
  payload = payload .. string.rep("\0", 10)
  payload = payload .. auth2
  payload = payload .. "mysql_native_password\0"
  return db_u24be(#payload) .. string.char(0) .. payload
end

local function db_redis_info_body()
  return "redis_version:6.2.7\r\nredis_git_sha1:00000000\r\n"
    .. "redis_mode:standalone\r\nos:Linux 5.15.0-generic x86_64\r\n"
    .. "arch_bits:64\r\nmultiplexing_api:epoll\r\n"
    .. "process_id:12345\r\nrun_id:ab12cd34ef56\r\n"
    .. "tcp_port:6379\r\nuptime_in_seconds:86400\r\n"
    .. "uptime_in_days:1\r\nconnected_clients:4\r\n"
    .. "used_memory:1048576\r\nused_memory_human:1.00M\r\n"
    .. "maxmemory:0\r\nmaxmemory_human:0B\r\n"
    .. "total_connections_received:42\r\n"
    .. "keyspace_hits:1234\r\nkeyspace_misses:56\r\n"
end

local function db_redis_command_info_reply(names)
  local out = "*" .. #names .. "\r\n"
  for _, name in ipairs(names) do
    out = out .. "*7\r\n$" .. #name .. "\r\n" .. name
      .. "\r\n:-1\r\n+admin\r\n+deny-oom\r\n:1\r\n:1\r\n:1\r\n"
  end
  return out
end

local function db_http_response(status, reason, body, headers, content_type)
  local lines = {}
  lines[#lines + 1] = "HTTP/1.1 " .. tostring(status) .. " " .. reason .. "\r\n"
  lines[#lines + 1] = "Server: mock-db/1.0\r\n"
  lines[#lines + 1] = "Date: Tue, 22 Sep 2026 12:00:00 GMT\r\n"
  if headers ~= nil then
    for _, h in ipairs(headers) do
      lines[#lines + 1] = h .. "\r\n"
    end
  end
  if content_type ~= nil then
    lines[#lines + 1] = "Content-Type: " .. content_type .. "\r\n"
  end
  lines[#lines + 1] = "Content-Length: " .. #tostring(body) .. "\r\n"
  lines[#lines + 1] = "Connection: close\r\n"
  lines[#lines + 1] = "\r\n"
  lines[#lines + 1] = tostring(body)
  return table.concat(lines, "")
end

local DB_PORTS = {
  [6379] = true, [11211] = true, [3306] = true, [5432] = true,
  [27017] = true, [9042] = true, [1433] = true, [5984] = true,
  [8123] = true, [2379] = true, [8086] = true, [7474] = true,
}

local function db_mock_reply(scenario, data, port, sock)
  local secure = (scenario == "db-secure")
  if port == 6379 then
    local cmd = string.match(data, "^%*%d+\r\n%$%d+\r\n(%S+)\r\n")
    if cmd == nil then
      return nil
    end
    if secure then
      return "-NOAUTH Authentication required.\r\n"
    end
    if cmd == "PING" then
      return "+PONG\r\n"
    end
    if cmd == "INFO" then
      local info = db_redis_info_body()
      return "$" .. #info .. "\r\n" .. info .. "\r\n"
    end
    if cmd == "COMMAND" then
      local names = {}
      local seen_info = false
      for part in string.gmatch(data, "%$%d+\r\n([A-Za-z]+)") do
        if part == "COMMAND" then
        elseif part == "INFO" then
          seen_info = true
        elseif seen_info then
          names[#names + 1] = part
        end
      end
      return db_redis_command_info_reply(names)
    end
    if cmd == "SET" then
      return "+OK\r\n"
    end
    if cmd == "GET" then
      return "$14\r\nnse-audit-probe\r\n"
    end
    if cmd == "DEL" then
      return ":1\r\n"
    end
    if cmd == "AUTH" then
      return "+OK\r\n"
    end
    return "-ERR unknown command '" .. cmd .. "'\r\n"
  end
  if port == 11211 then
    local line = string.match(data, "^([^\r\n]+)")
    if secure then
      return "ERROR\r\n"
    end
    if line == "stats" then
      return "STAT pid 12345\r\nSTAT uptime 86400\r\nSTAT time 1758000000\r\n"
        .. "STAT version 1.6.20\r\nSTAT rusage_user 1.25\r\nSTAT rusage_system 0.75\r\n"
        .. "STAT curr_connections 8\r\nSTAT total_connections 42\r\n"
        .. "STAT cmd_get 5000\r\nSTAT cmd_set 300\r\n"
        .. "STAT get_hits 4500\r\nSTAT get_misses 500\r\n"
        .. "STAT bytes 10485760\r\nSTAT curr_items 1200\r\n"
        .. "STAT limit_maxbytes 67108864\r\nSTAT evictions 0\r\n"
        .. "STAT expired 12\r\nSTAT listening_on_tcp true\r\nEND\r\n"
    end
    if line ~= nil and line:find("stats", 1, true) then
      return "STAT number 0\r\nEND\r\n"
    end
    if line == "version" then
      return "VERSION 1.6.20\r\n"
    end
    if line ~= nil and line:find("get ", 1, true) then
      return "END\r\n"
    end
    return "ERROR\r\n"
  end
  if port == 3306 then
    if #data < 4 then
      return ""
    end
    local plen = data:byte(1) * 65536 + data:byte(2) * 256 + data:byte(3)
    if plen + 4 > #data then
      return ""
    end
    local seq = data:byte(4)
    local body
    if secure then
      local msg = "Access denied for user 'root'@'192.0.2.10' (using password: NO)"
      body = string.char(255) .. db_u16le(1045) .. "#" .. "28000" .. msg
    else
      body = string.char(0) .. db_u16le(0) .. db_u16le(0) .. db_u16le(2) .. db_u16le(0)
    end
    return db_u24be(#body) .. string.char((seq or 0) + 1) .. body
  end
  if port == 5432 then
    if #data == 8 then
      local code = data:byte(5) * 16777216 + data:byte(6) * 65536 + data:byte(7) * 256 + data:byte(8)
      if code == 80877103 then
        if secure then
          return "N"
        end
        return "S"
      end
    end
    local user = string.match(data, "user\0([^\0]+)\0")
    if user == nil then
      return ""
    end
    if secure then
      local body = db_u32be(12) .. db_u32be(1) .. "SCRAM-SHA-256\0"
      return string.char(82) .. db_u32be(4 + #body) .. body
    end
    return string.char(82) .. db_u32be(8) .. db_u32be(0)
  end
  if port == 27017 then
    if #data >= 17 then
      local len = db_b32be(data:sub(1, 4))
      local opcode = db_b32be(data:sub(13, 16))
      if opcode == 2013 and len >= 16 and #data >= len then
        local doc = data:sub(18, 16 + len)
        if doc:find("hello", 1, true) then
          local mwv = secure and 17 or 13
          local d = db_bson_doc({
            { "s", "host", "mock-mongo:27017" },
            { "i32", "maxWireVersion", mwv },
            { "i32", "minWireVersion", 0 },
            { "b", "isWritablePrimary", true },
            { "s", "mongodbVersion", secure and "7.0.3" or "4.4.29" },
            { "d", "ok", 1 },
          })
          return db_opmsg_reply(d)
        end
        if doc:find("ping", 1, true) then
          if secure then
            local d = db_bson_doc({
              { "i32", "code", 13 },
              { "s", "errmsg", "not authorized on admin to execute command { ping: 1, $db: \"admin\" }" },
              { "s", "codeName", "Unauthorized" },
              { "d", "ok", 0 },
            })
            return db_opreply_error(d)
          end
          local d = db_bson_doc({
            { "s", "info", "ping requires no arguments" },
            { "d", "ok", 1 },
          })
          return db_opmsg_reply(d)
        end
      end
    end
    return nil
  end
  if port == 9042 then
    if #data < 10 then
      return nil
    end
    local op = data:byte(5)
    if op == 1 then
      if secure then
        return db_cass_error(0x0000, "Authentication required")
      end
      return db_cass_ready()
    end
    if op == 7 then
      if secure then
        return db_cass_error(0x0000, "Authentication required")
      end
      local blen = db_b32be(data:sub(6, 9))
      local body = data:sub(10, 9 + blen)
      if #body >= 4 then
        local qlen = db_b16be(body:sub(2, 3))
        local q = body:sub(4, 3 + qlen)
        if q:find("release_version", 1, true) then
          return db_cass_result_rows({ "4.1.3" })
        end
        if q:find("cluster_name", 1, true) then
          return db_cass_result_rows({ "MockCluster" })
        end
        if q:find("keyspaces", 1, true) then
          return db_cass_result_rows({ "system", "application_db", "metrics" })
        end
      end
      return db_cass_result_rows({ "" })
    end
    return nil
  end
  if port == 1433 then
    if data:byte(1) == 0x12 then
      local enc
      local ver
      if secure then
        enc = 3
        ver = { 16, 0, 4105, 2 }
      else
        enc = 0
        ver = { 15, 0, 4332, 0 }
      end
      local vb = string.char(ver[1], ver[2], math.floor(ver[3] / 256) % 256,
        ver[3] % 256, ver[4])
      local body = string.char(0) .. db_u16be(#vb) .. vb
        .. string.char(1) .. db_u16be(1) .. string.char(enc)
        .. string.char(255) .. db_u16be(0)
      local header = string.char(0x12, 1) .. db_u16be(8 + #body)
        .. db_u16be(0) .. db_u16be(1) .. db_u16be(0)
      return header .. body
    end
    return nil
  end
  local method = string.match(data, "^%S+ %S+ HTTP/") and string.match(data, "^([A-Z]+)")
  local path = string.match(data, "^%S+ (%S+) HTTP/")
  if method == nil or path == nil then
    return nil
  end
  local path_only = path:match("^([^?]*)")
  local query = path:match("[?](.*)$")
  if port == 5984 then
    if secure then
      return db_http_response(401, "Unauthorized",
        '{"error":"unauthorized","reason":"You are not authorized to perform this operation."}',
        nil, "application/json")
    end
    if path_only == "/_all_dbs" then
      return db_http_response(200, "OK", '["appdb","logdb"]',
        { "X-Couch-DB: CouchDB", "CouchDB: Elixir 3.3.2" }, "application/json")
    end
    if path_only == "/_membership" then
      return db_http_response(200, "OK",
        '{"all_nodes":["couchdb@10.0.0.1","couchdb@10.0.0.2"],"cluster_nodes":[["couchdb@10.0.0.1",1],["couchdb@10.0.0.2",1]],"active_users":["admin@couchdb@10.0.0.1"],"partitioned_dbs":[],"cookie_hash":"b7e2c9","admin_party":["admin@couchdb@10.0.0.1"]}',
        { "CouchDB: Elixir 3.3.2" }, "application/json")
    end
    if path_only == "/" or path_only == "" then
      return db_http_response(200, "OK", '{"couchdb":"Welcome","version":"3.3.2"}',
        { "CouchDB: Elixir 3.3.2" }, "application/json")
    end
    return db_http_response(404, "Not Found",
      '{"error":"not_found","reason":"missing"}', nil, "application/json")
  end
  if port == 8123 then
    if secure then
      if query ~= nil and query:find("query", 1, true) then
        return db_http_response(401, "Unauthorized",
          "AuthPassword: Authentication failed for user 'default': password is incorrect, authentication is not enabled",
          nil, "text/html; charset=utf-8")
      end
      return db_http_response(200, "OK", "<html><body>ClickHouse</body></html>",
        nil, "text/html")
    end
    if query ~= nil and query:find("query", 1, true) then
      if query:find("version()", 1, true) then
        return db_http_response(200, "OK", "23.8.12.14\n",
          { "X-ClickHouse-Server-Display-Name: ch-mock" }, "text/plain; charset=UTF-8")
      end
      return db_http_response(200, "OK", "",
        { "X-ClickHouse-Server-Display-Name: ch-mock" }, "text/plain; charset=UTF-8")
    end
    return db_http_response(200, "OK", "<html><body>ClickHouse</body></html>",
      nil, "text/html")
  end
  if port == 2379 then
    if path_only == "/health" then
      return db_http_response(200, "OK", '{"health":true,"reason":""}',
        nil, "application/json")
    end
    if path_only == "/v2/keys" then
      if secure then
        return db_http_response(401, "Unauthorized",
          '{"error":"etcdserver: user name or password is required"}',
          nil, "application/json")
      end
      return db_http_response(200, "OK",
        '{"action":"get","node":{"createdIndex":20,"modifiedIndex":21,"key":"/config","value":"database_url=postgres://admin:secret@10.0.0.5:5432/app","nodes":[{"key":"/config/db","value":""}]}}',
        nil, "application/json")
    end
    if path_only == "/v3/kv/range" then
      if secure then
        return db_http_response(403, "Forbidden",
          '{"code":6,"message":"etcdserver: authentication is required for the requested operation"}',
          nil, "application/json")
      end
      if method == "POST" then
        return db_http_response(200, "OK",
          '{"header":{"revision":21},"kvs":[{"create_revision":5,"mod_revision":21,"version":1,"key":"L2NvbmZpZw==","value":"ZGF0YWJhc2VfdXJsPXBvc3RncmVzOi8vYWRtaW46c2VjcmV0QDEwLjAuMC41OjU0MzIvYXBw"}],"more":false,"count":1}',
          nil, "application/json")
      end
      return db_http_response(405, "Method Not Allowed",
        '{"grpc_code":12,"http_code":405,"message":"etcdserver: mvcc: unsupported range call"}',
        nil, "application/json")
    end
    return db_http_response(404, "Not Found",
      '{"grpc_code":5,"http_code":404,"message":"etcdserver: key not found"}',
      nil, "application/json")
  end
  if port == 8086 then
    if path_only == "/ping" then
      return db_http_response(204, "No Content", "",
        { "X-InfluxDB-Version: 1.8.10" }, nil)
    end
    if path_only == "/query" then
      if secure then
        return db_http_response(401, "Unauthorized",
          "The request requires user authentication", nil, "text/plain")
      end
      return db_http_response(200, "OK", "name,timestamp\nmetrics,",
        { "X-InfluxDB-Version: 1.8.10" }, "text/csv; charset=utf-8")
    end
    return db_http_response(200, "OK", "<html><body>InfluxDB</body></html>",
      { "X-InfluxDB-Version: 1.8.10" }, "text/html")
  end
  if port == 7474 then
    if secure then
      return db_http_response(403, "Forbidden",
        '{"code":"Neo.Server.Forbidden","message":"Access is forbidden"}',
        nil, "application/json")
    end
    if path_only == "/db/" or path_only == "/db" then
      return db_http_response(200, "OK",
        '{"dbms":{"version":"3.5.39","edition":"enterprise","address":"192.0.2.10:7687"},"databases":[{"name":"system","state":"online"},{"name":"neo4j","state":"online"}]}',
        nil, "application/json; charset=utf-8")
    end
    return db_http_response(302, "Found", "", { "Location: /browser/" }, "text/html")
  end
  return nil
end

local function ftp_data_listing(scenario)
  local listing = table.concat({
    "drwxrwxrwx    2 0        0            4096 May 15  2019 public_html",
    "drwxrwxr-x    2 ftp      ftp          4096 May 15  2019 uploads",
    "drwxr-xr-x    2 root     root         4096 Jan 01  2011 bin",
    "-rw-r--r--    1 ftp      ftp          1024 May 15  2019 backup.tar.gz",
    "-rw-r--r--    1 ftp      ftp           234 May 15  2019 index.html",
    "-rw-r--r--    1 ftp      ftp            45 May 15  2019 .htaccess",
    "-rw-rw-rw-    1 ftp      ftp           512 May 15  2019 readme.txt",
    "drwxrwxr-x    2 ftp      ftp          4096 May 15  2019 www",
    "-rw-r--r--    1 ftp      ftp        1048576 May 15  2019 database.sql",
  }, "\r\n")
  if scenario == "ftp" then
    return listing .. "\r\n"
  end
  return table.concat({
    "drwxr-xr-x    2 ftp      ftp          4096 Jan 20  2024 pub",
    "-rw-r--r--    1 ftp      ftp            45 Jan 20  2024 index.html",
  }, "\r\n") .. "\r\n"
end

local function ftp_banner(scenario)
  if scenario == "ftp" then
    return "227 Welcome to the vsftpd FTP daemon\r\n"
  end
  return "220 (vsFTPd 3.0.5)\r\n"
end

local function ftp_mock_reply(scenario, data, sock)
  if sock.ftpstate == nil then
    sock.ftpstate = { dead = false, fails = 0, tls = false, logged = false, user = nil }
  end
  local st = sock.ftpstate
  if st.dead then
    return "__FTPDROP__"
  end
  if st.tls then
    local first = data:byte(1)
    if first ~= nil and first >= 0x14 and first <= 0x18 then
      local mapped = (scenario == "ftp") and "tls-legacy" or "tls"
      return tls_mock_reply(mapped, data, sock)
    end
    return "530 TLS session closed unexpectedly.\r\n"
  end
  local line = data:match("^(.-)\r?\n") or data
  local cmd = string.upper((line:match("^(%S+)") or ""))
  local arg = line:match("^%S+%s*(.*)$") or ""
  local ok = (scenario == "ftp")
  if cmd == "NOOP" then
    return "200 NOOP ok.\r\n"
  elseif cmd == "QUIT" then
    st.dead = true
    return "221 Goodbye.\r\n"
  elseif cmd == "SYST" then
    return "215 UNIX Type: L8\r\n"
  elseif cmd == "STAT" then
    if ok then
      return "211-Status:\r\n vsftpd 2.3.4 (backdoored build)\r\n target.example.com\r\n211 End of status\r\n"
    end
    return "211-Status:\r\n vsftpd 3.0.5\r\n target.example.com\r\n211 End of status\r\n"
  elseif cmd == "FEAT" then
    if ok then
      return "211-Features:\r\n AUTH TLS\r\n PASV\r\n EPSV\r\n SIZE\r\n MDTM\r\n MLST size,modify,unix.mode;type;perm;\r\n UTF8\r\n SITE\r\n211 End\r\n"
    end
    return "211-Features:\r\n AUTH TLS\r\n PASV\r\n EPSV\r\n SIZE\r\n MDTM\r\n MLST size,modify,unix.mode;type;perm;\r\n UTF8\r\n211 End\r\n"
  elseif cmd == "HELP" then
    if ok then
      return "214-Commands supported:\r\n NOOP QUIT USER PASS PWD CWD CDUP MKD RMD LIST NLST STOR RETR DELE RENAM PASV EPSV PORT EPRT SIZE MDTM MLST SITE CPFR CPTO AUTH PBSZ PROT\r\n214 End\r\n"
    end
    return "214-Commands supported:\r\n NOOP QUIT USER PASS PWD CWD CDUP MKD RMD LIST NLST STOR RETR DELE PASV EPSV SIZE MDTM MLST AUTH PBSZ PROT\r\n214 End\r\n"
  elseif cmd == "USER" then
    st.user = arg
    if not ok then
      st.fails = st.fails + 1
      if st.fails >= 3 then
        st.dead = true
        return "421 Too many failed login attempts. Closing control connection.\r\n"
      end
      return "534 Please use AUTH before proceeding.\r\n"
    end
    return "331 Password required for " .. arg .. ".\r\n"
  elseif cmd == "PASS" then
    if not ok then
      return "534 Please use AUTH before proceeding.\r\n"
    end
    if st.user == "anonymous" then
      st.logged = true
      return "230 Login successful. Restrictions apply.\r\n"
    end
    st.fails = st.fails + 1
    return "530 Login incorrect.\r\n"
  elseif cmd == "PWD" then
    return "257 \"/pub/ftp\" is the current directory.\r\n"
  elseif cmd == "CWD" then
    if ok then
      return "250 CWD command successful.\r\n"
    end
    return "550 Access denied.\r\n"
  elseif cmd == "CDUP" then
    if ok then
      return "250 CDUP command successful.\r\n"
    end
    return "550 Access denied.\r\n"
  elseif cmd == "MKD" then
    if ok then
      return "257 \"" .. arg .. "\" directory created successfully.\r\n"
    end
    return "550 Access denied.\r\n"
  elseif cmd == "RMD" then
    if ok then
      return "250 RMD command successful.\r\n"
    end
    return "550 Access denied.\r\n"
  elseif cmd == "STOR" then
    if ok then
      return "226 Transfer complete.\r\n"
    end
    return "550 Access denied.\r\n"
  elseif cmd == "DELE" then
    if ok then
      return "250 DELE command successful.\r\n"
    end
    return "550 Access denied.\r\n"
  elseif cmd == "SIZE" then
    if ok then
      return "213 1048576\r\n"
    end
    return "550 Access denied.\r\n"
  elseif cmd == "MDTM" then
    if ok then
      return "213 20190515120000\r\n"
    end
    return "550 Access denied.\r\n"
  elseif cmd == "MLST" then
    if ok and arg == "/etc" then
      return "250 /etc: type=dir;size=4096;modify=20110101000000;\r\n"
    end
    if ok and arg == "/etc/passwd" then
      return "250 /etc/passwd: type=file;size=1359;modify=20110101000000;\r\n"
    end
    return "550 Access denied.\r\n"
  elseif cmd == "NLST" or cmd == "LIST" then
    if not ok then
      return "530 Please log in first.\r\n"
    end
    return "150 Opening data channel for transfer.\r\n226 Transfer complete.\r\n"
  elseif cmd == "PASV" then
    if ok then
      return "227 Entering Passive Mode (0,0,0,0,195,128)\r\n"
    end
    return "227 Entering Passive Mode (192,0,2,10,192,64)\r\n"
  elseif cmd == "EPSV" then
    if ok then
      return "229 Entering Extended Passive Mode (|||50001|)\r\n"
    end
    return "229 Entering Extended Passive Mode (|||49153|)\r\n"
  elseif cmd == "PORT" then
    if ok then
      return "200 PORT command successful.\r\n"
    end
    return "501 PORT not permitted.\r\n"
  elseif cmd == "EPRT" then
    if ok then
      return "200 EPRT command successful.\r\n"
    end
    return "501 EPRT not permitted.\r\n"
  elseif cmd == "CPFR" then
    if ok then
      return "250 CPFR " .. arg .. " accepted.\r\n"
    end
    return "502 CPFR not recognized.\r\n"
  elseif cmd == "CPTO" then
    if ok then
      return "250 CPTO " .. arg .. " accepted.\r\n"
    end
    return "502 CPTO not recognized.\r\n"
  elseif cmd == "SITE" then
    if ok then
      if string.upper(arg):match("^FXPT") then
        return "250 Third-party transfer initiated.\r\n"
      end
      return "200 SITE command ok.\r\n"
    end
    return "502 SITE not recognized.\r\n"
  elseif cmd == "AUTH" then
    if string.upper(arg):match("^TLS") then
      st.tls = true
      return "234 Switching to TLS encryption.\r\n"
    end
    return "504 AUTH " .. arg .. " not supported.\r\n"
  elseif cmd == "PBSZ" then
    if st.tls then
      return "200 PBSZ set to " .. arg .. ".\r\n"
    end
    return "503 PBSZ only valid after AUTH.\r\n"
  elseif cmd == "PROT" then
    if st.tls then
      return "200 PROT " .. arg .. " set.\r\n"
    end
    return "503 PROT only valid after AUTH.\r\n"
  elseif cmd == "CLNT" or cmd == "HOST" or cmd == "LANG" then
    if ok then
      return "200 " .. cmd .. " ok.\r\n"
    end
    return "502 " .. cmd .. " not recognized.\r\n"
  end
  if ok then
    return "200 " .. cmd .. " ok.\r\n"
  end
  return "502 Command not implemented.\r\n"
end

local docker_container_json = {
  ["0001"] = '{"Id":"aaaaaaaaaaaaaaaa0001","Name":"/web-frontend","State":{"Status":"running","Running":true},"Image":"docker.io/library/nginx:1.21","Config":{"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Labels":{"maintainer":"ops@example.com"},"Image":"docker.io/library/nginx:1.21"},"HostConfig":{"NetworkMode":"host","Memory":536870912,"NanoCpus":500000000,"CpuShares":512,"PidsLimit":128,"OomKillDisable":false,"Privileged":false,"SeccompProfileName":"default","AppArmorProfile":"docker-default"},"Mounts":[],"NetworkSettings":{"Networks":{"host":{"EndpointID":"ep1"}},"Ports":{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"80"},{"HostIp":"0.0.0.0","HostPort":"443"}]}}}',
  ["0002"] = '{"Id":"bbbbbbbbbbbbbbbb0002","Name":"/api-gateway","State":{"Status":"running","Running":true},"Image":"docker.io/library/golang:1.17","Config":{"Env":["PATH=/usr/local/go/bin"],"Labels":{"com.example.service":"api-gateway"}},"HostConfig":{"NetworkMode":"bridge","Memory":0,"NanoCpus":0,"CpuShares":0,"PidsLimit":0,"OomKillDisable":false,"Privileged":true,"CapAdd":["SYS_PTRACE","NET_ADMIN"],"SeccompProfileName":"unconfined","AppArmorProfile":"unconfined","Devices":[{"PathOnHost":"/dev/mem","PathInContainer":"/dev/mem","CgroupPermissions":"rwm"}]},"Mounts":[],"NetworkSettings":{"Networks":{"bridge":{"IPAddress":"172.17.0.2"}},"Ports":{"8080/tcp":[{"HostIp":"0.0.0.0","HostPort":"8080"}]}}}',
  ["0003"] = '{"Id":"cccccccccccccccc0003","Name":"/payment-db","State":{"Status":"running","Running":true},"Image":"docker.io/library/postgres:13","Config":{"Env":["POSTGRES_DB=payments"]},"HostConfig":{"NetworkMode":"bridge","Memory":0,"NanoCpus":0,"CpuShares":0,"PidsLimit":-1,"OomKillDisable":true,"Privileged":false,"SeccompProfileName":"default","AppArmorProfile":"docker-default"},"Mounts":[{"Type":"volume","Source":"pgdata","Destination":"/var/lib/postgresql/data","RW":true,"Mode":""}],"NetworkSettings":{"Networks":{"bridge":{"IPAddress":"172.17.0.3"}},"Ports":{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"5432"}]}}}',
  ["0004"] = '{"Id":"dddddddddddddddd0004","Name":"/internal-builder","State":{"Status":"exited","Running":false},"Image":"docker.io/library/golang:1.17-builder","Config":{"Env":["PATH=/usr/local/go/bin","AWS_ACCESS_KEY_ID=AKIAIOSFODNN7example","AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","DB_PASSWORD=Pr0d!Passw0rd#2024","GITHUB_TOKEN=ghp_9f8e7d6c5b4a39281706f5e4d3c2b1a098","SPRING_DATASOURCE_DSN=postgres://admin:Hunter22!@db.internal:5432/payments"],"Labels":{"git-commit":"deadbeef1234","team":"platform"}},"HostConfig":{"NetworkMode":"bridge","Memory":2147483648,"NanoCpus":1000000000,"CpuShares":1024,"PidsLimit":256,"OomKillDisable":false,"Privileged":false,"CapAdd":["SYS_ADMIN"],"SeccompProfileName":"default","AppArmorProfile":"docker-default","Binds":["/var/run/docker.sock:/var/run/docker.sock"]},"Mounts":[{"Type":"bind","Source":"/var/run/docker.sock","Destination":"/var/run/docker.sock","RW":true,"Mode":"rw"}],"NetworkSettings":{"Networks":{"bridge":{"IPAddress":"172.17.0.5"}},"Ports":{}}}',
  ["0005"] = '{"Id":"eeeeeeeeeeeeeeee0005","Name":"/legacy-cache","State":{"Status":"running","Running":true},"Image":"docker.io/library/redis:6","Config":{"Env":["REDIS_VERSION=6.2.7"]},"HostConfig":{"NetworkMode":"bridge","Memory":0,"NanoCpus":0,"CpuShares":0,"PidsLimit":0,"OomKillDisable":false,"Privileged":false,"SeccompProfileName":"default","AppArmorProfile":"docker-default","Binds":["/:/host-root:ro","/etc:/host-etc"]},"Mounts":[{"Type":"bind","Source":"/","Destination":"/host-root","RW":false,"Mode":"ro"},{"Type":"bind","Source":"/etc","Destination":"/host-etc","RW":true,"Mode":"rw"}],"NetworkSettings":{"Networks":{"bridge":{"IPAddress":"172.17.0.6"}},"Ports":{"6379/tcp":[{"HostIp":"0.0.0.0","HostPort":"6379"}]}}}',
  ["0006"] = '{"Id":"ffffffffffffffff0006","Name":"/monitoring-agent","State":{"Status":"running","Running":true},"Image":"docker.io/prom/prometheus:v2.33.0","Config":{"Env":["PATH=/usr/local/bin"]},"HostConfig":{"NetworkMode":"bridge","Memory":536870912,"NanoCpus":500000000,"CpuShares":512,"PidsLimit":128,"OomKillDisable":false,"Privileged":false,"SeccompProfileName":"default","AppArmorProfile":"docker-default"},"Mounts":[{"Type":"bind","Source":"/var/lib/monitoring","Destination":"/data","RW":true,"Mode":"rw"}],"NetworkSettings":{"Networks":{"bridge":{"IPAddress":"172.17.0.7"}},"Ports":{"9090/tcp":[{"HostIp":"127.0.0.1","HostPort":"9090"}]}}}',
}

function docker_mock_reply(scenario, data, sock)
  if type(data) ~= "string" or data == "" then
    return nil
  end
  local method, full_path = data:match("^([%w]+)%s+(%S+)")
  if not method or not full_path then
    return nil
  end
  local path = full_path:match("^([^?]+)")
  local open = (scenario ~= "docker-secure")

  local function json_resp(code, reason, body, extra_hdr)
    local hdr = extra_hdr or ""
    return ("HTTP/1.1 %s %s\r\n%sContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s"):format(
      code, reason, hdr, #body, body)
  end

  local function text_resp(code, reason, body, ctype)
    return ("HTTP/1.1 %s %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s"):format(
      code, reason, ctype or "text/plain", #body, body)
  end

  local function unauthorized()
    return json_resp("401", "Unauthorized", '{"message":"unauthorized: authentication required"}',
      'WWW-Authenticate: Basic realm="docker", service="registry"\r\n')
  end

  local function forbidden_write()
    return json_resp("403", "Forbidden", '{"message":"proxy: mutating verbs are blocked for this endpoint"}')
  end

  local function not_found()
    return json_resp("404", "Not Found", '{"message":"page not found"}')
  end

  if method == "GET" or method == "HEAD" then
    if path == "/_ping" then
      return text_resp("200", "OK", "OK", "text/plain; charset=utf-8")
    end
    if path == "/version" then
      local body = '{"Platform":{"Name":"Docker Engine - Community"},"Components":[{"Name":"Engine","Version":"20.10.7","ApiVersion":"1.41","MinAPIVersion":"1.12","GitCommit":"5f91894","GoVersion":"go1.16.6","Os":"linux","Arch":"amd64"},{"Name":"containerd","Version":"1.5.13","GitCommit":"872a9cf","GoVersion":"go1.16.6"},{"Name":"runc","Version":"1.0.1","GitCommit":"v1.0.1"}],"Version":"20.10.7","ApiVersion":"1.41","MinAPIVersion":"1.12","GitCommit":"5f91894","GoVersion":"go1.16.6","Os":"linux","Arch":"amd64","KernelVersion":"5.4.0-190-generic","BuildTime":"2024-01-19T16:04:38.000000000+00:00"}'
      return json_resp("200", "OK", body, "Api-Version: 1.41\r\n")
    end
    if path == "/info" then
      if not open then
        return unauthorized()
      end
      local body = '{"ID":"a1b2c3d4e5f6:0123456789ab","Containers":6,"ContainersRunning":4,"ContainersPaused":0,"ContainersStopped":2,"Images":14,"Driver":"overlay2","DockerRootDir":"/var/lib/docker","NCPU":8,"MemTotal":16777216000,"ServerVersion":"20.10.7","OperatingSystem":"Ubuntu 20.04.6 LTS","OSType":"linux","Architecture":"x86_64","KernelVersion":"5.4.0-190-generic","GoVersion":"go1.16.6","RuncVersion":"1.0.1","ContainerdVersion":"1.5.13","CgroupDriver":"cgroupfs","LiveRestoreEnabled":false,"SecurityOptions":["name=seccomp,profile=default"],"Swarm":{"LocalNodeState":"active","NodeID":"n0000000000000000001","ControlAvailable":true,"Error":"","RemoteManagers":null},"Name":"exposed-docker-node-01","Labels":{"env":"staging"}}'
      return json_resp("200", "OK", body)
    end
    if path:match("^/containers/%x+json$") or path:match("^/containers/%x+/json$") then
      if not open then
        return unauthorized()
      end
      local cid = path:match("^/containers/(%x+)/json$")
      if not cid then
        cid = path:match("^/containers/(%x+)json$")
      end
      local key = cid:match("(%x%x%x%x)$")
      local det = docker_container_json[key]
      if det then
        return json_resp("200", "OK", det)
      end
      return not_found()
    end
    if path == "/containers/json" then
      if not open then
        return unauthorized()
      end
      local body = '[{"Id":"aaaaaaaaaaaaaaaa0001","Names":["/web-frontend"],"Image":"nginx:1.21","State":"running","Status":"Up 3 days"},{"Id":"bbbbbbbbbbbbbbbb0002","Names":["/api-gateway"],"Image":"golang:1.17","State":"running","Status":"Up 3 days"},{"Id":"cccccccccccccccc0003","Names":["/payment-db"],"Image":"postgres:13","State":"running","Status":"Up 3 days"},{"Id":"dddddddddddddddd0004","Names":["/internal-builder"],"Image":"golang:1.17-builder","State":"exited","Status":"Exited (0) 2 hours ago"},{"Id":"eeeeeeeeeeeeeeee0005","Names":["/legacy-cache"],"Image":"redis:6","State":"running","Status":"Up 12 days"},{"Id":"ffffffffffffffff0006","Names":["/monitoring-agent"],"Image":"prom/prometheus:v2.33.0","State":"running","Status":"Up 3 days"}]'
      return json_resp("200", "OK", body)
    end
    if path == "/images/json" then
      if not open then
        return unauthorized()
      end
      local body = '[{"Id":"sha256:aaa111bbb222ccc333ddd444eee555fff666aaa777bbb888ccc999ddd0001111","RepoTags":null,"Size":44040192,"Created":1699999900},{"Id":"sha256:bbb222ccc333ddd444eee555fff666aaa777bbb888ccc999ddd000111222233334444","RepoTags":["golang:1.17-builder"],"Size":734003200,"Created":1699000100},{"Id":"sha256:ccc333ddd444eee555fff666aaa777bbb888ccc999ddd0001112222333344445555","RepoTags":["nginx:1.21"],"Size":142241280,"Created":1698000100},{"Id":"sha256:ddd444eee555fff666aaa777bbb888ccc999ddd00011122223333444455556666","RepoTags":["postgres:13"],"Size":423778816,"Created":1697000100},{"Id":"sha256:eee555fff666aaa777bbb888ccc999ddd000111222233334444555566667777","RepoTags":["acme/internal-builder:latest"],"Size":734503200,"Created":1699900100}]'
      return json_resp("200", "OK", body)
    end
    if path:match("^/images/sha256:%x+/history$") then
      if not open then
        return unauthorized()
      end
      local body = '[{"Created":1699999900,"CreatedBy":"CMD [\\"sh\\"]","Tag":""},{"Created":1699900100,"CreatedBy":"RUN /bin/sh -c echo \\"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiY2kifQ.c2lnbmF0dXJl\\" > /tmp/.tok","Tag":""},{"Created":1699800100,"CreatedBy":"ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","Tag":""},{"Created":1699700100,"CreatedBy":"RUN curl -u deploy:R00tpass!9 https://internal.example.com/pkg.tgz -o /tmp/pkg.tgz","Tag":""},{"Created":1699600100,"CreatedBy":"ARG API_KEY=sk_live_4eC39HqLyjWDarjtT1zd-p7dc","Tag":""},{"Created":1699500100,"CreatedBy":"RUN apt-get update && apt-get install -y ca-certificates","Tag":""},{"Created":1699400100,"CreatedBy":"FROM golang:1.17 AS build","Tag":"golang:1.17"}]'
      return json_resp("200", "OK", body)
    end
    if path == "/events" then
      if not open then
        return unauthorized()
      end
      local ev1 = '{"Type":"container","Action":"start","Actor":{"ID":"aaaaaaaaaaaaaaaa0001","Attributes":{"name":"web-frontend","image":"nginx:1.21"}},"time":1696000000}'
      local ev2 = '{"Type":"image","Action":"pull","Actor":{"ID":"sha256:eee555fff666","Attributes":{"tag":"acme/internal-builder:latest","name":"acme/internal-builder"}},"time":1696000100}'
      local ev3 = '{"Type":"container","Action":"exec_create","Actor":{"ID":"cccccccccccccccc0003","Attributes":{"name":"payment-db","execID":"0f1e2d3c4b5a"}},"time":1696000200}'
      local ev4 = '{"Type":"network","Action":"connect","Actor":{"ID":"b1c2d3e4f5a6","Attributes":{"name":"bridge","container":"bbbbbbbbbbbbbbbb0002"}},"time":1696000300}'
      local head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
      local body_parts = {}
      for _, ev in ipairs({ ev1, ev2, ev3, ev4 }) do
        table.insert(body_parts, ("%x\r\n%s\r\n"):format(#ev, ev))
      end
      table.insert(body_parts, "0\r\n\r\n")
      return head .. table.concat(body_parts)
    end
    if path == "/networks" then
      if not open then
        return unauthorized()
      end
      local body = '[{"Name":"bridge","ID":"b1c2d3e4f5a6","Driver":"bridge","Options":{"com.docker.network.bridge.icc":"true","com.docker.network.driver.mtu":"1500"},"Internal":false},{"Name":"host","ID":"h0s7t8n9e1o2","Driver":"host","Options":{},"Internal":false},{"Name":"none","ID":"n3x4y5z6a7b8","Driver":"null","Options":{},"Internal":false}]'
      return json_resp("200", "OK", body)
    end
    if path == "/swarm" then
      if not open then
        return unauthorized()
      end
      local body = '{"ID":"s1w2a3r4m5i6d7e8","LocalNodeState":"active","NodeID":"n0000000000000000001","Nodes":[{"ID":"n0000000000000000001","Hostname":"exposed-docker-node-01","Manager":{"Reachability":"reachable","Leader":true},"Status":"ready","ManagerAddr":"10.0.1.11"},{"ID":"n0000000000000000002","Hostname":"exposed-docker-node-02","Status":"ready","ManagerAddr":"10.0.1.12"},{"ID":"n0000000000000000003","Hostname":"exposed-docker-node-03","Status":"ready","ManagerAddr":"10.0.1.13"}],"Services":[{"ID":"s0000000000000000001","Name":"web-frontend","TaskCount":"3"},{"ID":"s0000000000000000002","Name":"payment-db","TaskCount":"1"}],"JoinTokens":{"Worker":"SWMTKN-1-3z1i6j8t7v5x0e9a2c4d6f8g0h1j3k5m7o9q1s3u5w","Manager":"SWMTKN-1-9x8w7v6u5t4s3r2q1p0o9n8m7l6k5j4i3h2g1f0e9d8c"}}'
      return json_resp("200", "OK", body)
    end
    if path == "/debug/pprof" then
      if not open then
        return not_found()
      end
      return text_resp("200", "OK", "<html><head><title>/debug/pprof</title></head><body><p>Available Profiles:</p><a href=\"/debug/pprof/cmdline\">cmdline</a><a href=\"/debug/pprof/flags\">flags</a><a href=\"/debug/pprof/goroutine\">goroutine</a><a href=\"/debug/pprof/heap\">heap</a><a href=\"/debug/pprof/profile\">profile</a><a href=\"/debug/pprof/symbol\">symbol</a><a href=\"/debug/pprof/trace\">trace</a></body></html>", "text/html; charset=utf-8")
    end
    if path == "/debug/pprof/cmdline" then
      if not open then
        return not_found()
      end
      return text_resp("200", "OK", "dockerd\0--host\0tcp://0.0.0.0:2375\0--iptables\0true\0--debug\0")
    end
    if path == "/debug/pprof/flags" then
      if not open then
        return not_found()
      end
      return json_resp("200", "OK", '{"debug":{"type":"bool","value":"true"},"host":{"type":"string","value":"tcp://0.0.0.0:2375"},"log-level":{"type":"string","value":"debug"}}')
    end
    if path == "/debug/pprof/goroutine" then
      if not open then
        return not_found()
      end
      return text_resp("200", "OK", "goroutine profile: total 42\n34 @ 0x48b2a0 0x47f3a4 0x47f39e 0x46f1e5 0x46fb04 0x46e56d 0x47116b 0x4717b6 0x4717c1 0x4717c7 0x6\n4 @ 0x430101 0x46f1e5 0x49d2f6 0x49d35b 0x46e56d 0x47116b 0x4717b6 0x4717c1 0x4717c7 0x6\n3 @ 0x430101 0x46f1e5 0x4a1c99 0x4a1ce7 0x46e56d 0x47116b 0x4717b6 0x4717c1 0x4717c7 0x6\n1 @ 0x46e56d 0x47116b 0x4717b6 0x4717c1 0x4717c7 0x6")
    end
    if path == "/debug/vars" then
      if not open then
        return not_found()
      end
      return json_resp("200", "OK", '{"gin":{"default":["200","404","405","500"]},"memstats":{"Alloc":52428800,"TotalAlloc":1677721600,"HeapAlloc":52428800,"NumGC":42}}')
    end
    if path == "/v2" or path == "/v2/" then
      return json_resp("200", "OK", '{"Docker-Distribution-Api-Version":"registry/2.0"}')
    end
    if path == "/v2/_catalog" then
      if not open then
        return unauthorized()
      end
      return json_resp("200", "OK", '{"repositories":["acme/api-gateway","acme/internal-builder","acme/legacy-cache","acme/payment-db","acme/web-frontend"]}')
    end
    if path:match("^/v2/.+/tags/list$") then
      if not open then
        return unauthorized()
      end
      local repo = path:match("^/v2/(.+)/tags/list$")
      local body = ('{"name":"%s","tags":["latest","v1.2.3","v1.2.4"]}'):format(repo)
      return json_resp("200", "OK", body)
    end
    if path:match("^/v2/.+/manifests/[^/]+$") then
      if not open then
        return unauthorized()
      end
      local manifest = '{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"digest":"sha256:cfg111111111111111111111111111111111111111111111111111111111111","size":7023},"layers":[{"digest":"sha256:layer11111111111111111111111111111111111111111111111111111111","size":10485760},{"digest":"sha256:layer222222222222222222222222222222222222222222222222222222222","size":44040192}],"history":[{"v1Compatibility":"{\\"created\\":\\"2024-01-01T00:00:00Z\\",\\"created_by\\":\\"FROM golang:1.17 AS build\\",\\"config\\":{\\"Env\\":[\\"PATH=/usr/local/go/bin\\"]}}"},{"v1Compatibility":"{\\"created\\":\\"2024-01-02T00:00:00Z\\",\\"created_by\\":\\"RUN curl -u deploy:R00tpass!9 https://internal.example.com/pkg.tgz\\",\\"config\\":{\\"Env\\":[\\"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7example\\",\\"DB_PASSWORD=Pr0d!Passw0rd#2024\\"]}}"},{"v1Compatibility":"{\\"created\\":\\"2024-01-03T00:00:00Z\\",\\"created_by\\":\\"CMD [\\\"/app/server\\\"]\\",\\"config\\":{}}"}]}'
      return json_resp("200", "OK", manifest, "Docker-Content-Digest: sha256:manifestdigest111\r\n")
    end
    return not_found()
  end

  if method == "POST" or method == "PUT" then
    if not open then
      return forbidden_write()
    end
    if path == "/containers/create" then
      return json_resp("201", "Created", '{"Id":"n9n8n7n6n5n4n3n2n1n0","Warnings":[]}')
    end
    if path == "/build" then
      return text_resp("200", "OK", "stream:Step 1/1 : FROM scratch\nstream:Successfully built 000000000000\n")
    end
    if path == "/auth" then
      return json_resp("200", "OK", '{"Status":"Authored"}')
    end
    if path == "/images/create" then
      return text_resp("200", "OK", "Pulling from library/scratch\n")
    end
    return text_resp("200", "OK", "ok\n")
  end

  if method == "DELETE" then
    if not open then
      if path:match("^/v2/") then
        return json_resp("405", "Method Not Allowed", '{"message":"deletion of the repository is disabled"}')
      end
      return forbidden_write()
    end
    if path:match("^/containers/%x+$") then
      return "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
    end
    if path:match("^/v2/.+/manifests/[^/]+$") then
      local repo = path:match("^/v2/(.+)/manifests/")
      local known = {
        ["acme/api-gateway"] = true, ["acme/internal-builder"] = true,
        ["acme/legacy-cache"] = true, ["acme/payment-db"] = true,
        ["acme/web-frontend"] = true,
      }
      if known[repo] then
        return "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n"
      end
      local body = '{"errors":[{"code":"NAME_UNKNOWN","message":"repository name not known to registry"}]}'
      return json_resp("404", "Not Found", body)
    end
    return forbidden_write()
  end

  return not_found()
end

local function mock_mqtt_topic_matches(filter, topic)
  local f_levels = {}
  for lvl in real_string.gmatch(tostring(filter or ""), "[^/]+") do
    f_levels[#f_levels + 1] = lvl
  end
  local t_levels = {}
  for lvl in real_string.gmatch(tostring(topic or ""), "[^/]+") do
    t_levels[#t_levels + 1] = lvl
  end
  if #f_levels == 0 or #t_levels == 0 then
    return false
  end
  if f_levels[#f_levels] == "#" then
    for i = 1, #f_levels - 1 do
      if f_levels[i] ~= t_levels[i] then
        return false
      end
    end
    return true
  end
  if #f_levels ~= #t_levels then
    return false
  end
  for i = 1, #f_levels do
    if f_levels[i] ~= "#" and f_levels[i] ~= "+" and f_levels[i] ~= t_levels[i] then
      return false
    end
  end
  return true
end

local function mock_mqtt_encode_str(value)
  local len = #tostring(value or "")
  return real_string.char(math.floor(len / 256) % 256, len % 256) .. tostring(value or "")
end

local function mock_mqtt_encode_remlen(length)
  local bytes = ""
  repeat
    local digit = length % 128
    length = math.floor(length / 128)
    if length > 0 then
      digit = digit + 128
    end
    bytes = bytes .. real_string.char(digit)
  until length == 0
  return bytes
end

local function mock_mqtt_parse_body(data)
  local pos = 2
  local value = 0
  local multiplier = 1
  local byte_val
  repeat
    byte_val = real_string.byte(data, pos)
    value = value + (byte_val % 128) * multiplier
    multiplier = multiplier * 128
    pos = pos + 1
  until (byte_val & 0x80) == 0
  return real_string.sub(data, pos)
end

local function mock_mqtt_read_str(data, position)
  if position + 1 > #data then
    return nil
  end
  local len = real_string.byte(data, position) * 256 + real_string.byte(data, position + 1)
  if position + 1 + len > #data then
    return nil
  end
  return real_string.sub(data, position + 2, position + 1 + len), position + 2 + len
end

local function mqtt_profile_for(scenario)
  local profile = {
    level3_ok = true,
    level4_ok = true,
    anonymous_ok = true,
    anon_rc = 0x00,
    bad_cred_rc = 0x04,
    max_qos = 1,
    max_packet = 268435455,
    enforce_packet_size = false,
    mtls_required = false,
    good_creds = { ["admin"] = "admin" },
    deny_anon = {},
    deny_auth = {},
    retained = {},
    sys = {},
  }
  if scenario == "mqtt-secure" then
    profile.anonymous_ok = false
    profile.anon_rc = 0x05
    profile.max_qos = 2
    profile.max_packet = 4096
    profile.enforce_packet_size = true
    profile.mtls_required = true
    profile.deny_auth = { "admin/#", "commands/#" }
  end
  profile.sys = {
    [ "$SYS/broker/version" ] = "2.0.18",
    [ "$SYS/broker/clients/connected" ] = "3",
    [ "$SYS/broker/clients/total" ] = "12",
    [ "$SYS/broker/messages/received" ] = "512",
    [ "$SYS/broker/messages/sent" ] = "498",
    [ "$SYS/broker/messages/stored" ] = "6",
    [ "$SYS/broker/bytes/received" ] = "81920",
    [ "$SYS/broker/bytes/sent" ] = "78000",
    [ "$SYS/broker/heap/size" ] = "156000",
    [ "$SYS/broker/uptime" ] = "3600",
  }
  profile.retained = {
    { topic = "devices/kitchen/temperature", payload = "21.5" },
    { topic = "devices/kitchen/humidity", payload = "55" },
    { topic = "home/livingroom/door", payload = "open" },
    { topic = "security/camera/front/uri", payload = "rtsp://192.168.1.50:554/stream1" },
    { topic = "admin/config/broker", payload = "allow_anonymous: true" },
  }
  return profile
end

local MQTT_SESSION_TABLE = {}
local MOCK_MQTT_SUBS = {}

local function mock_mqtt_fanout(session, topic, payload, qos)
  for i = #MOCK_MQTT_SUBS, 1, -1 do
    local entry = MOCK_MQTT_SUBS[i]
    local esock = entry.sock
    if esock.closed == false and esock._mqtt ~= nil and esock._mqtt.connected == true
      and esock._mqtt.kicked == false
      and mock_mqtt_topic_matches(entry.filter, topic) then
      local body = mock_mqtt_encode_str(topic) .. tostring(payload)
      esock.buffer = esock.buffer .. real_string.char(0x30 + (qos or 0) * 2)
        .. mock_mqtt_encode_remlen(#body) .. body
    end
  end
end

local function mock_mqtt_prune_subscriber(session, filter)
  for i = #MOCK_MQTT_SUBS, 1, -1 do
    if MOCK_MQTT_SUBS[i].sock == session and (filter == nil or MOCK_MQTT_SUBS[i].filter == filter) then
      table.remove(MOCK_MQTT_SUBS, i)
    end
  end
end

local function mqtt_tls_flight(profile)
  local body = real_string.char(0x02)
    .. real_string.char(0, 0, 32)
    .. real_string.rep("H", 32)
  if profile.mtls_required then
    body = body .. real_string.char(0x0D)
      .. real_string.char(0, 0, 12)
      .. real_string.rep("R", 12)
  end
  body = body .. real_string.char(0x0E)
    .. real_string.char(0, 0, 0)
  local record = real_string.char(0x16, 0x03, 0x01)
    .. real_string.char(math.floor(#body / 256) % 256, #body % 256)
    .. body
  return record
end

local function mqtt_session_init(sock, scenario)
  local profile = mqtt_profile_for(scenario)
  local session = {
    profile = profile,
    connected = false,
    authenticated = false,
    client_id = nil,
    username = nil,
    keepalive = nil,
    level = nil,
    protocol_name = nil,
    will = nil,
    has_password = false,
    subs = {},
    pub_log = {},
    retained_store = {},
    tls_probe_done = false,
    kicked = false,
  }
  for _, entry in ipairs(profile.retained) do
    session.retained_store[entry.topic] = { topic = entry.topic, payload = entry.payload }
  end
  return session
end

local function mqtt_deliver_subscribed(session, filters, reply)
  for i, f in ipairs(filters) do
    local granted = f.granted
    if granted == 0x80 then
      goto continue_sub
    end
    local qos = math.min(granted or 0, 1)
    for topic, value in pairs(session.retained_store) do
      if mock_mqtt_topic_matches(f.topic, topic) then
        local body = mock_mqtt_encode_str(topic)
        body = body .. value.payload
        local qos_flags = qos * 2 + 1
        reply = reply .. real_string.char(0x30 + qos_flags) .. mock_mqtt_encode_remlen(#body) .. body
      end
    end
    for topic, payload in pairs(session.profile.sys) do
      if mock_mqtt_topic_matches(f.topic, topic) then
        local body = mock_mqtt_encode_str(topic) .. payload
        local qos_flags = math.min(granted or 0, 1) * 2 + 1
        reply = reply .. real_string.char(0x30 + qos_flags) .. mock_mqtt_encode_remlen(#body) .. body
      end
    end
    ::continue_sub::
  end
  return reply
end

local function mqtt_topic_denied(session, filter)
  local list = session.authenticated and session.profile.deny_auth or session.profile.deny_anon
  if not session.connected and not session.profile.anonymous_ok then
    return true
  end
  for _, deny in ipairs(list or {}) do
    if mock_mqtt_topic_matches(deny, filter) then
      return true
    end
  end
  return false
end

function mqtt_mock_reply(scenario, data, sock)
  local m = sock._mqtt
  if m == nil then
    m = mqtt_session_init(sock, scenario)
    sock._mqtt = m
  end
  local first = real_string.byte(data, 1) or 0
  if first == 0x16 then
    m.tls_probe_done = true
    return mqtt_tls_flight(m.profile)
  end
  local packet_type = first & 0xF0
  local flags = first & 0x0F
  local body = mock_mqtt_parse_body(data)

  if packet_type == 0x10 then
    local proto_name, pos = mock_mqtt_read_str(body, 1)
    if not proto_name then
      return real_string.char(0x20, 2, 0, 0x01)
    end
    local level = real_string.byte(body, pos)
    local connect_flags = real_string.byte(body, pos + 1) or 0
    local keepalive = real_string.byte(body, pos + 2) * 256 + real_string.byte(body, pos + 3)
    pos = pos + 4
    local client_id, p2 = mock_mqtt_read_str(body, pos)
    if not client_id then
      client_id = ""
    end
    pos = p2
    local will = nil
    if (connect_flags & 4) ~= 0 then
      local wtopic, p3 = mock_mqtt_read_str(body, pos)
      pos = p3
      local wlen = real_string.byte(body, pos) * 256 + real_string.byte(body, pos + 1)
      pos = pos + 2
      local wpayload = real_string.sub(body, pos, pos + wlen - 1)
      pos = pos + wlen
      will = {
        topic = wtopic,
        payload = wpayload,
        qos = ((connect_flags & 8) ~= 0 and 1 or 0) + ((connect_flags & 16) ~= 0 and 1 or 0),
        retain = (connect_flags & 0x20) ~= 0,
      }
    end
    local username
    local password
    if (connect_flags & 0x80) ~= 0 then
      username, pos = mock_mqtt_read_str(body, pos)
    end
    if (connect_flags & 0x40) ~= 0 then
      password, pos = mock_mqtt_read_str(body, pos)
    end

    if level ~= nil and m.protocol_name == nil then
      m.protocol_name = proto_name
    end
    m.client_id = client_id
    m.keepalive = keepalive
    m.level = level
    m.will = will
    m.username = username
    m.has_password = (connect_flags & 0x40) ~= 0

    if (level == 3 and not m.profile.level3_ok) or (level == 4 and not m.profile.level4_ok) then
      return real_string.char(0x20, 2, 0, 0x01)
    end
    if proto_name ~= "MQTT" and proto_name ~= "MQIsdp" then
      return real_string.char(0x20, 2, 0, 0x01)
    end

    local rc
    if username ~= nil and password ~= nil then
      if m.profile.good_creds[username] == password then
        m.authenticated = true
        rc = 0x00
      else
        rc = m.profile.bad_cred_rc
      end
    else
      if m.profile.anonymous_ok then
        rc = 0x00
      else
        rc = m.profile.anon_rc
      end
    end

    if rc == 0x00 then
      m.connected = true
      if client_id ~= "" and MQTT_SESSION_TABLE[client_id] ~= nil and MQTT_SESSION_TABLE[client_id] ~= sock then
        local old = MQTT_SESSION_TABLE[client_id]
        old._mqtt.kicked = true
        old.buffer = ""
        mock_mqtt_prune_subscriber(old)
      end
      MQTT_SESSION_TABLE[client_id] = sock
    end
    return real_string.char(0x20, 2, 0, rc)
  end

  if not m.connected then
    return ""
  end

  if packet_type == 0x80 then
    local pid = real_string.byte(body, 1) * 256 + real_string.byte(body, 2)
    local pos = 3
    local filters = {}
    while pos + 1 <= #body do
      local topic, p2 = mock_mqtt_read_str(body, pos)
      if not topic then
        break
      end
      local qos = real_string.byte(body, p2) or 0
      pos = p2 + 1
      local granted = qos
      if qos > m.profile.max_qos then
        granted = m.profile.max_qos
      end
      if mqtt_topic_denied(m, topic) then
        granted = 0x80
      end
      if granted ~= 0x80 then
        m.subs[#m.subs + 1] = topic
        MOCK_MQTT_SUBS[#MOCK_MQTT_SUBS + 1] = { sock = sock, filter = topic }
      end
      filters[#filters + 1] = { topic = topic, granted = granted }
    end
    local ack_body = real_string.char(math.floor(pid / 256) % 256, pid % 256)
    for _, f in ipairs(filters) do
      ack_body = ack_body .. real_string.char(f.granted)
    end
    local reply = real_string.char(0x90) .. mock_mqtt_encode_remlen(#ack_body) .. ack_body
    reply = mqtt_deliver_subscribed(m, filters, reply)
    return reply
  end

  if packet_type == 0x30 then
    local publish_qos = math.floor((flags & 0x06) / 2)
    local retain = (flags & 0x01) ~= 0
    local topic, pos = mock_mqtt_read_str(body, 1)
    if not topic then
      return ""
    end
    local packet_id
    if publish_qos > 0 then
      packet_id = real_string.byte(body, pos) * 256 + real_string.byte(body, pos + 1)
      pos = pos + 2
    end
    local payload = real_string.sub(body, pos)
    m.pub_log[#m.pub_log + 1] = {
      topic = topic,
      payload = payload,
      qos = publish_qos,
      retain = retain,
      denied = mqtt_topic_denied(m, topic),
    }
    if retain then
      m.retained_store[topic] = { topic = topic, payload = payload }
    end
    if m.pub_log[#m.pub_log].denied == false then
      mock_mqtt_fanout(m, topic, payload, publish_qos)
    end
    if #payload > m.profile.max_packet and m.profile.enforce_packet_size then
      m.connected = false
      MQTT_SESSION_TABLE[m.client_id or ""] = nil
      return ""
    end
    if publish_qos == 1 then
      return real_string.char(0x40, 2, math.floor(packet_id / 256) % 256, packet_id % 256)
    end
    if publish_qos == 2 then
      return real_string.char(0x50, 2, math.floor(packet_id / 256) % 256, packet_id % 256)
    end
    return ""
  end

  if packet_type == 0x60 then
    local pid = real_string.byte(body, 1) * 256 + real_string.byte(body, 2)
    return real_string.char(0x70, 2, math.floor(pid / 256) % 256, pid % 256)
  end

  if packet_type == 0xA0 then
    local pid = real_string.byte(body, 1) * 256 + real_string.byte(body, 2)
    local pos = 3
    while pos + 1 <= #body do
      local t, p2 = mock_mqtt_read_str(body, pos)
      if not t then
        break
      end
      mock_mqtt_prune_subscriber(sock, t)
      pos = p2
    end
    return real_string.char(0xB0, 2, math.floor(pid / 256) % 256, pid % 256)
  end

  if packet_type == 0xC0 then
    return real_string.char(0xD0, 0)
  end

  if packet_type == 0xE0 then
    m.connected = false
    MQTT_SESSION_TABLE[m.client_id or ""] = nil
    mock_mqtt_prune_subscriber(sock)
    return ""
  end

  return ""
end

local function ssh_mock_enc(value)
  local text = tostring(value or "")
  local n = #text
  return real_string.char(math.floor(n / 16777216) % 256, math.floor(n / 65536) % 256,
    math.floor(n / 256) % 256, n % 256) .. text
end

local function ssh_mock_frame(inner)
  local pad_len = 8 - (#inner % 8)
  if pad_len < 4 then
    pad_len = pad_len + 8
  end
  local total = 1 + #inner + pad_len
  local padding = real_string.rep(real_string.char(0), pad_len)
  return real_string.char(math.floor(total / 16777216) % 256, math.floor(total / 65536) % 256,
    math.floor(total / 256) % 256, total % 256) .. real_string.char(pad_len) .. inner .. padding
end

local function ssh_hostkey_blob_for(profile)
  local e = real_string.char(1, 0, 1)
  local nlen = math.floor(profile.hostkey_bits / 8)
  local n = real_string.rep("\xAB", nlen)
  return ssh_mock_enc(profile.hostkey_type) .. ssh_mock_enc(e) .. ssh_mock_enc(n)
end

local function ssh_profile_for(scenario)
  local profile = {
    banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
    kex = "diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,curve25519-sha256",
    host_key = "ssh-rsa,ecdsa-sha2-nistp256,ssh-ed25519",
    cipher_c2s = "3des-cbc,arcfour128,aes128-cbc,aes256-cbc,aes128-ctr,aes256-ctr,chacha20-poly1305@openssh.com",
    cipher_s2c = "3des-cbc,arcfour128,aes128-cbc,aes256-cbc,aes128-ctr,aes256-ctr,chacha20-poly1305@openssh.com",
    mac_c2s = "hmac-md5,hmac-sha1,hmac-sha2-256,hmac-sha2-256-etm@openssh.com",
    mac_s2c = "hmac-md5,hmac-sha1,hmac-sha2-256,hmac-sha2-256-etm@openssh.com",
    comp_c2s = "none,zlib,zlib@openssh.com",
    comp_s2c = "none,zlib,zlib@openssh.com",
    lang_c2s = "",
    lang_s2c = "",
    hostkey_type = "ssh-rsa",
    hostkey_bits = 1024,
    auth_methods = "publickey,password",
    users = { ["root"] = true, ["audit"] = true },
    test_password = "AuditPass123",
    max_auth_tries = 6,
    agent_forwarding_ok = true,
    services_ok = true,
    kb_instructions = "",
    kb_prompts = { { text = "Username:", echo = true }, { text = "Password:", echo = false } },
  }
  if scenario == "ssh-secure" then
    profile.banner = "SSH-2.0-OpenSSH_9.8p1\r\n"
    profile.kex = "curve25519-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256"
    profile.host_key = "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256"
    profile.cipher_c2s = "aes256-gcm@openssh.com,aes256-ctr,aes128-ctr"
    profile.cipher_s2c = "aes256-gcm@openssh.com,aes256-ctr,aes128-ctr"
    profile.mac_c2s = "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com"
    profile.mac_s2c = "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com"
    profile.comp_c2s = "none,zlib@openssh.com"
    profile.comp_s2c = "none,zlib@openssh.com"
    profile.hostkey_type = "rsa-sha2-512"
    profile.hostkey_bits = 3072
    profile.auth_methods = "publickey"
    profile.users = { ["audit"] = true }
    profile.max_auth_tries = 3
    profile.agent_forwarding_ok = false
    profile.services_ok = false
    profile.kb_instructions = ""
    profile.kb_prompts = { { text = "Password:", echo = false } }
  end
  return profile
end

function ssh_mock_reply(scenario, data, sock)
  local st = sock._ssh
  if st == nil then
    st = { profile = ssh_profile_for(scenario), fail_count = 0, authenticated = false, channel = false }
    sock._ssh = st
  end
  local frame = ssh_mock_frame
  local enc = ssh_mock_enc
  local payload = tostring(data)
  local msg = ""
  if #payload >= 5 then
    local plen = payload:byte(1) * 16777216 + payload:byte(2) * 65536
      + payload:byte(3) * 256 + payload:byte(4)
    if plen >= 5 and plen <= #payload then
      local padlen = payload:byte(5)
      if padlen >= 4 and 1 + padlen <= plen then
        msg = real_string.sub(payload, 6, 5 + plen)
      end
    end
  end
  local mtype = msg:byte(1) or 0
  local body = real_string.sub(msg, 2)
  local function readstr(pos)
    if pos + 4 > #body then
      return nil, pos
    end
    local n = body:byte(pos) * 16777216 + body:byte(pos + 1) * 65536
      + body:byte(pos + 2) * 256 + body:byte(pos + 3)
    if pos + 4 + n > #body then
      return nil, pos
    end
    return real_string.sub(body, pos + 4, pos + 3 + n), pos + 4 + n
  end
  local function auth_failure(user)
    return frame(real_string.char(51) .. enc(user) .. enc(st.profile.auth_methods))
  end
  local function maybe_drop()
    st.fail_count = st.fail_count + 1
    if st.fail_count > st.profile.max_auth_tries then
      sock.closed = true
      return true
    end
    return false
  end

  if mtype == 20 then
    local lists = { st.profile.kex, st.profile.host_key, st.profile.cipher_c2s,
      st.profile.cipher_s2c, st.profile.mac_c2s, st.profile.mac_s2c,
      st.profile.comp_c2s, st.profile.comp_s2c, st.profile.lang_c2s, st.profile.lang_s2c }
    local cookie = ""
    for i = 1, 16 do
      cookie = cookie .. real_string.char((i * 7 + 3) % 256)
    end
    local kexbody = cookie
    for _, list in ipairs(lists) do
      kexbody = kexbody .. enc(list)
    end
    local hk = ssh_hostkey_blob_for(st.profile)
    local sig = enc("ssh-rsa") .. enc(real_string.rep("g", 64))
    local reply = frame(real_string.char(20) .. kexbody)
      .. frame(real_string.char(32) .. enc(hk) .. enc(real_string.rep("S", 32)) .. sig)
    return reply
  end

  if mtype == 50 then
    local pos = 1
    local service, np = readstr(pos)
    if service == nil then
      return ""
    end
    pos = np
    local user, np = readstr(pos)
    if user == nil then
      return ""
    end
    pos = np
    local method, np = readstr(pos)
    if method == nil then
      return ""
    end
    pos = np
    if st.profile.users[user] == nil then
      sock.closed = true
      return ""
    end
    if method == "none" then
      return auth_failure(user)
    end
    if method == "publickey" then
      if maybe_drop() then
        return ""
      end
      return auth_failure(user)
    end
    if method == "password" then
      local password = ""
      if body:byte(pos) == 1 then
        local pw, np2 = readstr(pos + 1)
        if pw then
          password = pw
        end
      end
      if password == st.profile.test_password then
        st.authenticated = true
        return frame(real_string.char(52))
      end
      if maybe_drop() then
        return ""
      end
      return auth_failure(user)
    end
    if method == "keyboard-interactive" then
      local kb = real_string.char(53) .. enc(user) .. enc(st.profile.kb_instructions)
      kb = kb .. real_string.char(0, 0, 0, #st.profile.kb_prompts)
      for _, pr in ipairs(st.profile.kb_prompts) do
        kb = kb .. enc(pr.text)
      end
      for _, pr in ipairs(st.profile.kb_prompts) do
        kb = kb .. real_string.char(pr.echo and 1 or 0)
      end
      return frame(kb)
    end
    if maybe_drop() then
      return ""
    end
    return frame(real_string.char(51) .. enc(user) .. enc(""))
  end

  if mtype == 54 then
    local pos = 1
    if pos + 4 > #body then
      return ""
    end
    local count = body:byte(pos) * 16777216 + body:byte(pos + 1) * 65536
      + body:byte(pos + 2) * 256 + body:byte(pos + 3)
    pos = pos + 4
    local matched = false
    for _ = 1, count do
      local value, np = readstr(pos)
      if value == nil then
        break
      end
      pos = np
      if value == st.profile.test_password then
        matched = true
      end
    end
    if matched then
      st.authenticated = true
      return frame(real_string.char(52))
    end
    if maybe_drop() then
      return ""
    end
    return auth_failure("audit")
  end

  if mtype == 90 then
    st.channel = true
    local body91 = real_string.char(91)
      .. real_string.char(0, 0, 0, 0)
      .. real_string.char(0, 0, 0, 0)
      .. real_string.char(0, 2, 0, 0)
      .. real_string.char(0, 0, 8, 0)
    return frame(body91)
  end

  if mtype == 98 then
    local pos = 5
    local rtype, np = readstr(pos)
    if rtype == "agent-foreground-openssh" then
      if st.profile.agent_forwarding_ok then
        return frame(real_string.char(99) .. real_string.char(0, 0, 0, 0))
      end
      return frame(real_string.char(100) .. real_string.char(0, 0, 0, 0) .. real_string.char(1))
    end
    if st.profile.services_ok then
      return frame(real_string.char(99) .. real_string.char(0, 0, 0, 0))
    end
    return frame(real_string.char(100) .. real_string.char(0, 0, 0, 0) .. real_string.char(1))
  end

  if mtype == 5 then
    local service, np = readstr(1)
    if service == nil then
      return ""
    end
    if st.profile.services_ok then
      return frame(real_string.char(6) .. enc(service))
    end
    return frame(real_string.char(7) .. enc(service))
  end

  return ""
end

local function snmp_mock_oids_split(oid)
  local parts = {}
  for n in oid:gmatch("(%d+)") do
    parts[#parts + 1] = tonumber(n)
  end
  return parts
end

local function snmp_mock_oid_lt(a, b)
  local A = snmp_mock_oids_split(a)
  local B = snmp_mock_oids_split(b)
  local n = math.min(#A, #B)
  for i = 1, n do
    if A[i] ~= B[i] then
      return A[i] < B[i]
    end
  end
  return #A < #B
end

local function snmp_mock_oid_bytes(oid)
  local parts = snmp_mock_oids_split(oid)
  local subs = {}
  local function encode_sub(v)
    if v < 128 then
      return string.char(v)
    end
    local groups = {}
    local first = v % 128
    v = math.floor(v / 128)
    while v > 0 do
      table.insert(groups, 1, v % 128)
      v = math.floor(v / 128)
    end
    table.insert(groups, first)
    local out = {}
    for i = 1, #groups - 1 do
      out[#out + 1] = string.char(groups[i] + 128)
    end
    out[#out + 1] = string.char(groups[#groups])
    return table.concat(out)
  end
  local lead = string.char(parts[1] * 40 + parts[2])
  for i = 3, #parts do
    lead = lead .. encode_sub(parts[i])
  end
  return string.char(6, #lead) .. lead
end

local function snmp_mock_int_tlv(n)
  if n >= 0 and n < 128 then
    return string.char(2, 1, n)
  end
  local v = n
  local out = {}
  while v > 0 do
    out[#out + 1] = string.char(v % 256)
    v = math.floor(v / 256)
  end
  local bytes = table.concat(out):reverse()
  if bytes:byte(1) >= 128 then
    bytes = string.char(0) .. bytes
  end
  return string.char(2, #bytes) .. bytes
end

local function snmp_mock_octet_tlv(v)
  return string.char(4, #v) .. v
end

local function snmp_mock_ip_bytes(s)
  local a, b, c, d = s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if a == nil then
    return string.char(0, 0, 0, 0)
  end
  return string.char(tonumber(a), tonumber(b), tonumber(c), tonumber(d))
end

local function snmp_mock_mac_bytes(s)
  local out = {}
  for h in s:gmatch("(%x%x)") do
    local hi = tonumber(h:sub(1, 1), 16)
    local lo = tonumber(h:sub(2, 2), 16)
    out[#out + 1] = string.char(hi * 16 + lo)
  end
  return table.concat(out)
end

local function snmp_mock_ip_key(s)
  local b = snmp_mock_ip_bytes(s)
  return tostring(b:byte(1)) .. "." .. tostring(b:byte(2)) .. "." .. tostring(b:byte(3)) .. "." .. tostring(b:byte(4))
end

local function snmp_mock_build_rows(scenario)
  local rows = {}
  local function add(oid, typ, value)
    rows[#rows + 1] = { oid = oid, typ = typ, value = value }
  end
  add("1.3.6.1.2.1.1.1.0", "string", "NETGEAR GS724Tv2 Gigabit Smart Web Managed Switch 6.12.22")
  add("1.3.6.1.2.1.1.2.0", "oid", "1.3.6.1.4.1.3798.1.1.5.1")
  add("1.3.6.1.2.1.1.3.0", "integer", 1234567)
  add("1.3.6.1.2.1.1.4.0", "string", "admin@corp.example")
  add("1.3.6.1.2.1.1.5.0", "string", "core-switch-01")
  add("1.3.6.1.2.1.1.6.0", "string", "DC1 Rack A U12")
  local ifrows = {
    { 1, "eth0", 6, 1000000000, "00:1a:2b:3c:4d:5e", 1, 1 },
    { 2, "eth1", 6, 1000000000, "00:1a:2b:3c:4d:5f", 1, 1 },
    { 3, "br0", 23, 1000000000, "00:1a:2b:3c:4d:60", 1, 1 },
    { 4, "lo", 24, 10000000000, "00:00:00:00:00:00", 1, 1 },
  }
  for _, r in ipairs(ifrows) do
    add("1.3.6.1.2.1.2.2.1.1." .. r[1], "string", r[2])
    add("1.3.6.1.2.1.2.2.1.2." .. r[1], "integer", r[3])
    add("1.3.6.1.2.1.2.2.1.5." .. r[1], "integer", r[4])
    add("1.3.6.1.2.1.2.2.1.6." .. r[1], "string", snmp_mock_mac_bytes(r[5]))
    add("1.3.6.1.2.1.2.2.1.7." .. r[1], "integer", r[6])
    add("1.3.6.1.2.1.2.2.1.8." .. r[1], "integer", r[7])
  end
  local routes = {
    { 1, "0.0.0.0", 1, 0, "192.168.1.1" },
    { 2, "192.168.1.0", 1, 0, "0.0.0.0" },
    { 3, "10.10.0.0", 2, 1, "192.168.1.2" },
  }
  for _, r in ipairs(routes) do
    add("1.3.6.1.2.1.4.21.1.1." .. r[1], "ip", snmp_mock_ip_bytes(r[2]))
    add("1.3.6.1.2.1.4.21.1.2." .. r[1], "integer", r[3])
    add("1.3.6.1.2.1.4.21.1.3." .. r[1], "integer", r[4])
    add("1.3.6.1.2.1.4.21.1.7." .. r[1], "ip", snmp_mock_ip_bytes(r[5]))
  end
  local arp = {
    { 1, "192.168.1.10", "aa:bb:cc:dd:ee:01" },
    { 1, "192.168.1.20", "aa:bb:cc:dd:ee:02" },
    { 2, "192.168.1.30", "aa:bb:cc:dd:ee:03" },
  }
  for _, r in ipairs(arp) do
    local suffix = "." .. snmp_mock_ip_key(r[2])
    add("1.3.6.1.2.1.4.22.1.1." .. r[1] .. suffix, "integer", r[1])
    add("1.3.6.1.2.1.4.22.1.2." .. r[1] .. suffix, "ip", snmp_mock_ip_bytes(r[2]))
    add("1.3.6.1.2.1.4.22.1.3." .. r[1] .. suffix, "string", snmp_mock_mac_bytes(r[3]))
  end
  local procs = {
    { 101, "snmpd", "/usr/sbin/snmpd", "-LS3Df -C -c /etc/snmpd.conf", 1 },
    { 102, "sshd", "/usr/sbin/sshd", "-D", 1 },
    { 103, "cron", "/usr/sbin/cron", "", 1 },
    { 104, "nginx", "/usr/sbin/nginx", "-g daemon off", 1 },
  }
  for _, r in ipairs(procs) do
    add("1.3.6.1.2.1.25.4.2.1.1." .. r[1], "integer", r[1])
    add("1.3.6.1.2.1.25.4.2.1.2." .. r[1], "string", r[2])
    add("1.3.6.1.2.1.25.4.2.1.3." .. r[1], "string", r[3])
    add("1.3.6.1.2.1.25.4.2.1.4." .. r[1], "string", r[4])
    add("1.3.6.1.2.1.25.4.2.1.5." .. r[1], "integer", r[5])
  end
  local stor = {
    { 1, "1.3.6.1.2.1.25.2.1.1", "/dev/sda1", 1024, 512000, 263000 },
    { 2, "1.3.6.1.2.1.25.2.1.1", "ramdisk", 1, 1048576, 524288 },
    { 3, "1.3.6.1.2.1.25.2.1.2", "/tmp", 1024, 204800, 10240 },
  }
  for _, r in ipairs(stor) do
    add("1.3.6.1.2.1.25.2.3.1.1." .. r[1], "integer", r[1])
    add("1.3.6.1.2.1.25.2.3.1.2." .. r[1], "oid", r[2])
    add("1.3.6.1.2.1.25.2.3.1.3." .. r[1], "string", r[3])
    add("1.3.6.1.2.1.25.2.3.1.4." .. r[1], "integer", r[4])
    add("1.3.6.1.2.1.25.2.3.1.5." .. r[1], "integer", r[5])
    add("1.3.6.1.2.1.25.2.3.1.6." .. r[1], "integer", r[6])
  end
  local tcp = {
    { 2, "0.0.0.0", 22, "0.0.0.0", 0 },
    { 2, "0.0.0.0", 80, "0.0.0.0", 0 },
    { 2, "0.0.0.0", 443, "0.0.0.0", 0 },
    { 1, "192.168.1.50", 51234, "10.0.0.5", 443 },
  }
  for i, r in ipairs(tcp) do
    local lkey = snmp_mock_ip_key(r[2])
    local l4 = snmp_mock_ip_bytes(r[2])
    local r4 = snmp_mock_ip_bytes(r[4])
    add("1.3.6.1.2.1.6.13.1.1.1." .. lkey .. "." .. r[3], "integer", r[1])
    add("1.3.6.1.2.1.6.13.1.1.2." .. lkey .. "." .. r[3], "ip", l4)
    add("1.3.6.1.2.1.6.13.1.1.3." .. lkey .. "." .. r[3], "integer", r[3])
    add("1.3.6.1.2.1.6.13.1.1.4." .. lkey .. "." .. r[3], "ip", r4)
    add("1.3.6.1.2.1.6.13.1.1.5." .. lkey .. "." .. r[3], "integer", r[5])
  end
  local udps = {
    { "0.0.0.0", 161 },
    { "0.0.0.0", 53 },
  }
  for i, r in ipairs(udps) do
    local ukey = snmp_mock_ip_key(r[1])
    add("1.3.6.1.2.1.7.5.1.1.2." .. ukey .. "." .. r[2], "ip", snmp_mock_ip_bytes(r[1]))
    add("1.3.6.1.2.1.7.5.1.1.3." .. ukey .. "." .. r[2], "integer", r[2])
  end
  local installed = {
    { 1, "Ubuntu", "22.04.4 LTS", "20240702" },
    { 2, "OpenSSH", "9.6p1", "20240411" },
    { 3, "nginx", "1.24.0-2ubuntu7.3", "20240601" },
    { 4, "snmpd", "5.9.1+dfsg-1ubuntu5.4", "20240315" },
  }
  for _, r in ipairs(installed) do
    add("1.3.6.1.2.1.25.4.1.1.1." .. r[1], "string", r[2])
    add("1.3.6.1.2.1.25.4.1.1.2." .. r[1], "string", r[3])
    add("1.3.6.1.2.1.25.4.1.1.3." .. r[1], "string", r[4])
  end
  add("1.3.6.1.4.1.9.9.96.1.1.1.1.1", "integer", 1)
  add("1.3.6.1.4.1.9.9.96.1.1.1.1.2", "integer", 1)
  add("1.3.6.1.4.1.9.9.96.1.1.1.1.1.1", "oid", "1.3.6.1.2.1.1.2.0")
  add("1.3.6.1.4.1.9.9.96.1.1.1.1.1.2", "oid", "1.3.6.1.2.1.1.2.0")
  add("1.3.6.1.4.1.9.9.96.1.1.1.1.2.1.1.1.1.1.1.1.1", "oid", "1.3.6.1.2.1.1.2.0")
  if scenario == "snmp" then
    add("1.3.6.1.6.3.15.1.1.1.1", "string", "operator")
    add("1.3.6.1.6.3.15.1.1.2.1", "string", "0102030405060708090a0b0c0d0e0f10")
    add("1.3.6.1.6.3.15.1.1.4.1", "oid", "1.3.6.1.6.3.10.1.1.1.0")
    add("1.3.6.1.6.3.15.1.1.5.1", "oid", "1.3.6.1.6.3.10.1.2.1.0")
    add("1.3.6.1.6.3.15.1.1.6.1", "integer", 1)
    add("1.3.6.1.6.3.15.1.1.1.2", "string", "audit")
    add("1.3.6.1.6.3.15.1.1.4.2", "oid", "1.3.6.1.6.3.10.1.1.2.0")
    add("1.3.6.1.6.3.15.1.1.5.2", "oid", "1.2.840.113549.1.12.15.1.0")
    add("1.3.6.1.6.3.15.1.1.6.2", "integer", 1)
  else
    add("1.3.6.1.6.3.15.1.1.1.1", "string", "admin")
    add("1.3.6.1.6.3.15.1.1.4.1", "oid", "1.3.6.1.6.3.10.1.1.3.0")
    add("1.3.6.1.6.3.15.1.1.5.1", "oid", "1.2.840.113549.1.12.15.1.0")
    add("1.3.6.1.6.3.15.1.1.6.1", "integer", 1)
  end
  table.sort(rows, function(a, b)
    return snmp_mock_oid_lt(a.oid, b.oid)
  end)
  return rows
end

local function snmp_mock_ber_len(n)
  if n < 128 then
    return string.char(n)
  end
  local out = {}
  local v = n
  local tmp = {}
  while v > 0 do
    tmp[#tmp + 1] = string.char(v % 256)
    v = math.floor(v / 256)
  end
  local bytes = table.concat(tmp):reverse()
  for i = 1, #bytes do
    out[#out + 1] = string.char(bytes:byte(i))
  end
  return string.char(128 + #bytes) .. table.concat(out)
end

local function snmp_mock_value_tlv(typ, value)
  if typ == "string" then
    return snmp_mock_octet_tlv(value)
  elseif typ == "integer" then
    return snmp_mock_int_tlv(value)
  elseif typ == "oid" then
    return snmp_mock_oid_bytes(value)
  elseif typ == "ip" then
    return string.char(0x40, #value) .. value
  elseif typ == "nosuch" then
    return string.char(0xA0, 0)
  elseif typ == "endofmib" then
    return string.char(0xA2, 0)
  end
  return string.char(5, 0)
end

local function snmp_mock_varbind(oid, typ, value)
  local inner = snmp_mock_oid_bytes(oid) .. snmp_mock_value_tlv(typ, value)
  return string.char(0x30) .. snmp_mock_ber_len(#inner) .. inner
end

local function snmp_mock_response_pdu(pdu_tag, request_id, varbinds, error_status)
  local body = snmp_mock_int_tlv(request_id)
  if error_status == nil then
    error_status = 0
  end
  body = body .. snmp_mock_int_tlv(error_status) .. snmp_mock_int_tlv(0)
  if varbinds ~= nil and #varbinds > 0 then
    body = body .. string.char(0x30) .. snmp_mock_ber_len(#varbinds) .. varbinds
  end
  return string.char(pdu_tag) .. snmp_mock_ber_len(#body) .. body
end

local function snmp_mock_tlv_next(data, pos)
  if data == nil or pos == nil or pos > #data then
    return nil, nil, nil
  end
  local tag = data:byte(pos)
  local len = data:byte(pos + 1)
  if len == nil then
    return nil, nil, nil
  end
  local start
  local nlen = 0
  if len < 128 then
    start = pos + 2
  else
    nlen = len - 128
    start = pos + 2 + nlen
  end
  local v
  if len < 128 then
    v = len
  else
    v = 0
    for k = 1, nlen do
      v = v * 256 + data:byte(pos + 1 + k)
    end
  end
  return tag, data:sub(start, start + v - 1), start + v
end

local function snmp_mock_oid_decode_string(raw)
  local parts = {}
  if #raw == 0 then
    return nil
  end
  local v = raw:byte(1)
  parts[1] = math.floor(v / 40)
  parts[2] = v % 40
  local i = 2
  local cur = 0
  local have = false
  while i <= #raw do
    local b = raw:byte(i)
    cur = cur * 128 + (b % 128)
    have = true
    if b < 128 then
      parts[#parts + 1] = cur
      cur = 0
      have = false
    end
    i = i + 1
  end
  local out = {}
  for k = 1, #parts do
    out[k] = tostring(parts[k])
  end
  return table.concat(out, ".")
end

local function snmp_mock_int_value(vint)
  local n = 0
  for k = 1, #vint do
    n = n * 256 + vint:byte(k)
  end
  return n
end

local function snmp_mock_v1v2c_reply(scenario, rows, community, pdu_tag, request_id, varbinds_bytes, max_rep, non_rep)
  local function request_oid(varbind)
    local ntag, nval, _ = snmp_mock_tlv_next(varbind, 1)
    if ntag == 6 then
      local oid = snmp_mock_oid_decode_string(nval)
      if oid == nil then
        return nil
      end
      return oid
    end
    return nil
  end
  local function find_next(oid, limit)
    for i = 1, #rows do
      if snmp_mock_oid_lt(oid, rows[i].oid) then
        if limit ~= nil and i > limit then
          break
        end
        return rows[i].oid, rows[i].typ, rows[i].value, i
      end
    end
    return nil
  end
  local function find_exact(oid)
    for i = 1, #rows do
      if rows[i].oid == oid then
        return i
      end
    end
    return nil
  end
  local varbinds = {}
  local vp = 1
  while vp <= #varbinds_bytes do
    local tag, inner, nxt = snmp_mock_tlv_next(varbinds_bytes, vp)
    if tag == nil or tag ~= 0x30 then
      break
    end
    local oid = request_oid(inner)
    if oid == nil then
      break
    end
    if pdu_tag == 0xA0 then
      local idx = find_exact(oid)
      if idx ~= nil then
        varbinds[#varbinds + 1] = snmp_mock_varbind(oid, rows[idx].typ, rows[idx].value)
      else
        varbinds[#varbinds + 1] = snmp_mock_varbind(oid, "nosuch", "")
      end
    elseif pdu_tag == 0xA1 then
      local o, t, v = find_next(oid)
      if o ~= nil then
        varbinds[#varbinds + 1] = snmp_mock_varbind(o, t, v)
      else
        varbinds[#varbinds + 1] = snmp_mock_varbind(oid, "endofmib", "")
      end
    elseif pdu_tag == 0xA5 then
      local rep = max_rep or 1
      if rep < 1 then
        rep = 1
      end
      local seen = 0
      while seen < rep do
        local o2, t2, v2 = find_next(oid)
        if o2 == nil then
          varbinds[#varbinds + 1] = snmp_mock_varbind(oid, "endofmib", "")
          break
        end
        varbinds[#varbinds + 1] = snmp_mock_varbind(o2, t2, v2)
        seen = seen + 1
        oid = o2
      end
    elseif pdu_tag == 0xA2 then
      local idx = find_exact(oid)
      local write_ok = (community == "private")
      if write_ok then
        varbinds[#varbinds + 1] = snmp_mock_varbind(oid, "string", "snmp-audit-write-test")
        if idx ~= nil then
          rows[idx].value = "snmp-audit-write-test"
        end
      else
        varbinds[#varbinds + 1] = snmp_mock_varbind(oid, "nosuch", "")
        return snmp_mock_response_pdu(0xA2, request_id, table.concat(varbinds), 2)
      end
    else
      varbinds[#varbinds + 1] = snmp_mock_varbind(oid, "nosuch", "")
    end
    vp = nxt
  end
  return snmp_mock_response_pdu(0xA2, request_id, table.concat(varbinds), nil)
end

local SNMOCK_ENGINE = string.char(0x01, 0x00, 0x00, 0x00, 0x09, 0x06, 0x02, 0x01, 0x2B, 0x11)

local function snmp_mock_v3_response(user, level, request_id, varbinds_str)
  local auth = ""
  if level ~= 0 then
    auth = string.rep(string.char(0x00), 16)
  end
  local sp_inner = snmp_mock_octet_tlv(user) .. snmp_mock_octet_tlv(SNMOCK_ENGINE) .. snmp_mock_int_tlv(level) .. snmp_mock_octet_tlv(auth) .. snmp_mock_octet_tlv("") .. snmp_mock_octet_tlv("")
  local sp = string.char(0x30) .. snmp_mock_ber_len(#sp_inner) .. sp_inner
  local pdu_body = snmp_mock_int_tlv(request_id) .. snmp_mock_int_tlv(0) .. snmp_mock_int_tlv(0) .. string.char(0x30) .. snmp_mock_ber_len(#varbinds_str) .. varbinds_str
  local scoped = string.char(0x82) .. snmp_mock_ber_len(#pdu_body) .. pdu_body
  local model = snmp_mock_int_tlv(3)
  local msgdata_inner = model .. sp .. scoped
  local msgdata = string.char(0x30) .. snmp_mock_ber_len(#msgdata_inner) .. msgdata_inner
  local verseq = string.char(0x30) .. snmp_mock_ber_len(3) .. snmp_mock_int_tlv(3)
  local outer = verseq .. msgdata
  return string.char(0x30) .. snmp_mock_ber_len(#outer) .. outer
end

local function snmp_mock_reply(scenario, data, sock)
  if sock._snmp_rows == nil then
    sock._snmp_rows = snmp_mock_build_rows(scenario)
  end
  local rows = sock._snmp_rows
  local tag, body, _ = snmp_mock_tlv_next(data, 1)
  if tag == nil or tag ~= 0x30 then
    return ""
  end
  local vtag, vint, p = snmp_mock_tlv_next(body, 1)
  if vtag == nil then
    return ""
  end
  local version
  if vtag == 0x02 then
    version = snmp_mock_int_value(vint)
  elseif vtag == 0x30 then
    local ivtag, ivint, _ = snmp_mock_tlv_next(vint, 1)
    if ivtag ~= 0x02 then
      return ""
    end
    version = snmp_mock_int_value(ivint)
  else
    return ""
  end
  if version == 0 or version == 1 then
    local ctag, cval, p2 = snmp_mock_tlv_next(body, p)
    if ctag ~= 0x04 then
      return ""
    end
    local ok_comm = (scenario == "snmp") and (cval == "public" or cval == "private")
    if not ok_comm then
      return ""
    end
    local pdutag, pdubody, _ = snmp_mock_tlv_next(body, p2)
    if pdutag == nil or pdubody == nil then
      return ""
    end
    local fp = 1
    local fields = {}
    while fp <= #pdubody do
      local ftag, fval, fnxt = snmp_mock_tlv_next(pdubody, fp)
      if ftag == nil then
        break
      end
      fields[#fields + 1] = { tag = ftag, value = fval }
      fp = fnxt
    end
    if #fields < 1 then
      return ""
    end
    local request_id = snmp_mock_int_value(fields[1].value)
    local non_rep = 0
    local max_rep = 0
    local varbinds_bytes = ""
    if pdutag == 0xA5 then
      if #fields >= 2 then
        non_rep = snmp_mock_int_value(fields[2].value)
      end
      if #fields >= 3 then
        max_rep = snmp_mock_int_value(fields[3].value)
      end
      varbinds_bytes = fields[#fields].value
    else
      varbinds_bytes = fields[#fields].value
    end
    local pdu = snmp_mock_v1v2c_reply(scenario, rows, cval, pdutag, request_id, varbinds_bytes, max_rep, non_rep)
    local msgbody = snmp_mock_int_tlv(version) .. snmp_mock_octet_tlv(cval) .. pdu
    return string.char(0x30) .. snmp_mock_ber_len(#msgbody) .. msgbody
  end
  if version == 3 then
    local dtag, dval, _ = snmp_mock_tlv_next(body, p)
    if dtag ~= 0x30 then
      return ""
    end
    local mtag, mint, dp = snmp_mock_tlv_next(dval, 1)
    if mtag ~= 0x02 then
      return ""
    end
    local sptag, spval, dpp = snmp_mock_tlv_next(dval, dp)
    if sptag ~= 0x30 then
      return ""
    end
    local utag, uval, sp2 = snmp_mock_tlv_next(spval, 1)
    if utag ~= 0x04 then
      return ""
    end
    local user = uval
    local etag, eval, sp3 = snmp_mock_tlv_next(spval, sp2)
    if etag ~= 0x04 then
      return ""
    end
    local engine = eval
    local ltag, lval, _ = snmp_mock_tlv_next(spval, sp3)
    if ltag ~= 0x02 then
      return ""
    end
    local level = snmp_mock_int_value(lval)
    local user_ok
    if scenario == "snmp" then
      user_ok = (user == "operator" or user == "audit")
    else
      user_ok = (user == "admin")
    end
    if not user_ok then
      return ""
    end
    if scenario == "snmp-secure" and level == 0 then
      return ""
    end
    local datatag, dataval, _ = snmp_mock_tlv_next(dval, dpp)
    if datatag ~= 0x81 and datatag ~= 0x82 then
      return ""
    end
    local pdubody = dataval
    local fp = 1
    local fields = {}
    while fp <= #pdubody do
      local ftag, fval, fnxt = snmp_mock_tlv_next(pdubody, fp)
      if ftag == nil then
        break
      end
      fields[#fields + 1] = { tag = ftag, value = fval }
      fp = fnxt
    end
    if #fields < 2 then
      return ""
    end
    local request_id = snmp_mock_int_value(fields[1].value)
    local varbinds_bytes = fields[#fields].value
    local varbinds = {}
    local vp = 1
    while vp <= #varbinds_bytes do
      local vtag2, inner, vnxt = snmp_mock_tlv_next(varbinds_bytes, vp)
      if vtag2 == nil or vtag2 ~= 0x30 then
        break
      end
      local ntag, nval, _ = snmp_mock_tlv_next(inner, 1)
      if ntag ~= 6 then
        break
      end
      local oid = snmp_mock_oid_decode_string(nval)
      if oid == nil then
        break
      end
      local found
      for i = 1, #rows do
        if rows[i].oid == oid then
          found = rows[i]
          break
        end
      end
      if found ~= nil then
        varbinds[#varbinds + 1] = snmp_mock_varbind(oid, found.typ, found.value)
      else
        varbinds[#varbinds + 1] = snmp_mock_varbind(oid, "nosuch", "")
      end
      vp = vnxt
    end
    return snmp_mock_v3_response(user, level, request_id, table.concat(varbinds))
  end
  return ""
end

local LDAP_MOCK_NC = "dc=corp,dc=example,dc=com"

local function ldap_mock_ber_len(n)
  if n < 128 then
    return string.char(n)
  end
  local bytes = {}
  local v = math.floor(n)
  while v > 0 do
    table.insert(bytes, 1, string.char(v % 256))
    v = math.floor(v / 256)
  end
  return string.char(128 + #bytes) .. table.concat(bytes)
end

local function ldap_mock_int_tlv(v)
  if v >= 0 and v < 128 then
    return string.char(0x02, 0x01, v)
  end
  local bytes = {}
  local x = math.abs(v)
  while x > 0 do
    table.insert(bytes, 1, string.char(x % 256))
    x = math.floor(x / 256)
  end
  if #bytes == 0 then
    bytes = { string.char(0) }
  end
  if v < 0 then
    if bytes[1] < 128 then
      table.insert(bytes, 1, string.char(0xFF))
    end
  else
    if bytes[1] >= 128 then
      table.insert(bytes, 1, string.char(0x00))
    end
  end
  return string.char(0x02) .. ldap_mock_ber_len(#bytes) .. table.concat(bytes)
end

local function ldap_mock_octet_tlv(s)
  return string.char(0x04) .. ldap_mock_ber_len(#tostring(s)) .. tostring(s)
end

local function ldap_mock_null_tlv()
  return string.char(0x05, 0x00)
end

local function ldap_mock_seq(body)
  return string.char(0x30) .. ldap_mock_ber_len(#body) .. body
end

local function ldap_mock_set(body)
  return string.char(0x31) .. ldap_mock_ber_len(#body) .. body
end

local function ldap_mock_ctx(index, body)
  return string.char(0x80 + index) .. ldap_mock_ber_len(#body) .. body
end

local function ldap_mock_oid_bytes(oid_str)
  local arcs = {}
  for a in tostring(oid_str):gmatch("%d+") do
    arcs[#arcs + 1] = tonumber(a)
  end
  local out = { string.char(arcs[1] * 40 + arcs[2]) }
  for i = 3, #arcs do
    local v = arcs[i]
    local chunks = { string.char(v % 128) }
    v = math.floor(v / 128)
    while v > 0 do
      table.insert(chunks, 1, string.char(0x80 + (v % 128)))
      v = math.floor(v / 128)
    end
    out[#out + 1] = table.concat(chunks)
  end
  return table.concat(out)
end

local function ldap_mock_oid_tlv(oid_str)
  local body = ldap_mock_oid_bytes(oid_str)
  return string.char(0x06) .. ldap_mock_ber_len(#body) .. body
end

local function ldap_mock_tlv_next(data, pos)
  if data == nil or pos == nil or pos > #data then
    return nil, nil, nil
  end
  local tag = data:byte(pos)
  local lenb = data:byte(pos + 1)
  if lenb == nil then
    return nil, nil, nil
  end
  local body_start
  local vlen
  if lenb < 128 then
    body_start = pos + 2
    vlen = lenb
  else
    local nlen = lenb - 128
    if pos + 2 + nlen > #data then
      return nil, nil, nil
    end
    vlen = 0
    for k = 1, nlen do
      vlen = vlen * 256 + data:byte(pos + 1 + k)
    end
    body_start = pos + 2 + nlen
  end
  if body_start + vlen - 1 > #data then
    return nil, nil, nil
  end
  return tag, data:sub(body_start, body_start + vlen - 1), body_start + vlen
end

local function ldap_mock_tlv_list(body)
  local items = {}
  local p = 1
  while p <= #body do
    local tag, value, nxt = ldap_mock_tlv_next(body, p)
    if tag == nil then
      break
    end
    items[#items + 1] = { tag = tag, value = value }
    p = nxt
  end
  return items
end

local function ldap_mock_int_value(body)
  if body == nil or #body == 0 then
    return 0
  end
  local n = 0
  for k = 1, #body do
    n = n * 256 + body:byte(k)
  end
  if body:byte(1) >= 128 then
    n = n - 256 ^ #body
  end
  return n
end

local function ldap_mock_oid_value(body)
  if body == nil or #body == 0 then
    return ""
  end
  local arcs = { math.floor(body:byte(1) / 40), body:byte(1) % 40 }
  local i = 2
  while i <= #body do
    local b = body:byte(i)
    local v = b % 128
    i = i + 1
    while b >= 128 and i <= #body do
      b = body:byte(i)
      v = v * 128 + (b % 128)
      i = i + 1
    end
    arcs[#arcs + 1] = v
  end
  local parts = {}
  for _, a in ipairs(arcs) do
    parts[#parts + 1] = tostring(a)
  end
  return table.concat(parts, ".")
end

local function ldap_mock_build_rootdse(scenario)
  if scenario == "ldap" then
    return {
      ["namingContexts"] = { LDAP_MOCK_NC },
      ["defaultNamingContext"] = { LDAP_MOCK_NC },
      ["dnsHostName"] = { "dc01.corp.example.com" },
      ["domainFunctionality"] = { "7" },
      ["supportedLDAPVersion"] = { "3" },
      ["supportedSASLMechanisms"] = { "GSSAPI", "EXTERNAL", "DIGEST-MD5" },
      ["supportedControl"] = { "1.2.840.113556.1.4.319", "1.2.840.113556.1.4.528", "1.2.840.113556.1.4.841" },
      ["supportedExtension"] = { "1.3.6.1.4.1.1466.20036", "1.3.6.1.4.1.1466.20037" },
      ["isGlobalCatalogReady"] = { "true" },
      ["serverName"] = { "cn=NTDS," .. LDAP_MOCK_NC },
      ["schemaNamingContext"] = { "cn=schema," .. LDAP_MOCK_NC },
      ["configurationNamingContext"] = { "cn=configuration," .. LDAP_MOCK_NC },
      ["objectClass"] = { "rootDSE" },
    }
  end
  return {
    ["namingContexts"] = { LDAP_MOCK_NC },
    ["defaultNamingContext"] = { LDAP_MOCK_NC },
    ["supportedLDAPVersion"] = { "3" },
    ["supportedExtension"] = { "1.3.6.1.4.1.1466.20036", "1.3.6.1.4.1.1466.20037" },
    ["objectClass"] = { "rootDSE" },
  }
end

local function ldap_mock_build_entries()
  local nc = LDAP_MOCK_NC
  local users = "cn=users," .. nc
  return {
    { dn = "cn=Administrator," .. users, attrs = {
      ["cn"] = { "Administrator" },
      ["sAMAccountName"] = { "Administrator" },
      ["objectClass"] = { "top", "person", "organizationalPerson", "user" },
      ["userAccountControl"] = { "512" },
      ["objectSid"] = { "S-1-5-21-2101895584-905427869-1137394760-500" },
      ["userPassword"] = { "Administrator#2023" },
    } },
    { dn = "cn=jsmith," .. users, attrs = {
      ["cn"] = { "jsmith" },
      ["sAMAccountName"] = { "jsmith" },
      ["objectClass"] = { "top", "person", "organizationalPerson", "user" },
      ["userAccountControl"] = { "512" },
      ["description"] = { "Finance - Q3 budget owner" },
      ["unicodePwd"] = { "{unicode}41756469746F7223393738" },
      ["mail"] = { "jsmith@corp.example.com" },
    } },
    { dn = "cn=jdoe," .. users, attrs = {
      ["cn"] = { "jdoe" },
      ["sAMAccountName"] = { "jdoe" },
      ["objectClass"] = { "top", "person", "organizationalPerson", "user" },
      ["userAccountControl"] = { "512" },
      ["description"] = { "Sales - EMEA region" },
      ["mail"] = { "jdoe@corp.example.com" },
    } },
    { dn = "cn=svcbackup," .. users, attrs = {
      ["cn"] = { "svcbackup" },
      ["sAMAccountName"] = { "svcbackup" },
      ["objectClass"] = { "top", "person", "organizationalPerson", "user" },
      ["userAccountControl"] = { "4194816" },
      ["description"] = { "Backup service account" },
    } },
    { dn = "cn=svcdb," .. users, attrs = {
      ["cn"] = { "svcdb" },
      ["sAMAccountName"] = { "svcdb" },
      ["objectClass"] = { "top", "person", "organizationalPerson", "user" },
      ["userAccountControl"] = { "512" },
      ["servicePrincipalName"] = { "MSSQLSvc/dc01.corp.example.com:1433" },
    } },
    { dn = "cn=svcweb," .. users, attrs = {
      ["cn"] = { "svcweb" },
      ["sAMAccountName"] = { "svcweb" },
      ["objectClass"] = { "top", "person", "organizationalPerson", "user" },
      ["userAccountControl"] = { "512" },
      ["servicePrincipalName"] = { "HTTP/dc01" },
    } },
    { dn = "cn=Domain Admins," .. users, attrs = {
      ["cn"] = { "Domain Admins" },
      ["sAMAccountName"] = { "DOMAIN ADMINS" },
      ["objectClass"] = { "top", "group" },
      ["objectSid"] = { "S-1-5-32-512" },
    } },
    { dn = "cn=Accounting,cn=Corp," .. nc, attrs = {
      ["cn"] = { "Accounting" },
      ["sAMAccountName"] = { "ACCOUNTING" },
      ["objectClass"] = { "top", "group" },
    } },
    { dn = "cn=Corp IT,cn=Corp," .. nc, attrs = {
      ["cn"] = { "Corp IT" },
      ["sAMAccountName"] = { "CORP IT" },
      ["objectClass"] = { "top", "group" },
    } },
    { dn = "cn=Corp," .. nc, attrs = {
      ["cn"] = { "Corp" },
      ["objectClass"] = { "top", "organizationalUnit" },
    } },
    { dn = "cn=Finance,cn=Corp," .. nc, attrs = {
      ["cn"] = { "Finance" },
      ["objectClass"] = { "top", "organizationalUnit" },
    } },
    { dn = "cn=Workstations,cn=Corp," .. nc, attrs = {
      ["cn"] = { "Workstations" },
      ["objectClass"] = { "top", "organizationalUnit" },
    } },
    { dn = "cn=WORKSTATION01,cn=Workstations,cn=Corp," .. nc, attrs = {
      ["cn"] = { "WORKSTATION01" },
      ["sAMAccountName"] = { "WORKSTATION01$" },
      ["objectClass"] = { "top", "computer" },
      ["userAccountControl"] = { "4096" },
      ["ms-Mcs-AdmPwd"] = { "L@psW0rd-01x" },
      ["dNSHostName"] = { "workstation01.corp.example.com" },
    } },
    { dn = "cn=DC01,cn=Domain Controllers," .. nc, attrs = {
      ["cn"] = { "DC01" },
      ["sAMAccountName"] = { "DC01$" },
      ["objectClass"] = { "top", "computer" },
      ["userAccountControl"] = { "12288" },
      ["servicePrincipalName"] = { "host/dc01.corp.example.com", "host/DC01" },
      ["dNSHostName"] = { "dc01.corp.example.com" },
    } },
    { dn = "cn=FILESRV01,cn=Workstations,cn=Corp," .. nc, attrs = {
      ["cn"] = { "FILESRV01" },
      ["sAMAccountName"] = { "FILESRV01$" },
      ["objectClass"] = { "top", "computer" },
      ["userAccountControl"] = { "4096" },
    } },
    { dn = "cn=Domain Controllers Policy,cn=Policies,cn=System," .. nc, attrs = {
      ["cn"] = { "Domain Controllers Policy" },
      ["gPCMachineQuotas"] = { "3145728 3145728" },
      ["gPOptions"] = { "1" },
    } },
    { dn = "cn=Corp Standard,cn=Policies,cn=System," .. nc, attrs = {
      ["cn"] = { "Corp Standard" },
      ["gPCMachineQuotas"] = { "1048576 1048576" },
      ["gPOptions"] = { "2" },
    } },
    { dn = "cn=corp," .. nc, attrs = {
      ["cn"] = { "corp" },
      ["objectClass"] = { "top", "domainDNS" },
      ["defaultNamingContext"] = { nc },
    } },
    { dn = "cn=pKIEnrollmentService=corp," .. nc, attrs = {
      ["cn"] = { "pKIEnrollmentService=corp" },
      ["objectClass"] = { "top", "msPKI-EnrollmentService" },
      ["pKIEnrollmentService"] = { "corp" },
    } },
    { dn = "cn=WebServer,cn=Certificate Templates,cn=Public Key Services,cn=Services,cn=System," .. nc, attrs = {
      ["cn"] = { "WebServer" },
      ["objectClass"] = { "top", "msPKI-CertificateTemplate" },
      ["pKIExtendedKeyUsage"] = { "1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.1" },
    } },
    { dn = "cn=User,cn=Certificate Templates,cn=Public Key Services,cn=Services,cn=System," .. nc, attrs = {
      ["cn"] = { "User" },
      ["objectClass"] = { "top", "msPKI-CertificateTemplate" },
      ["pKIExtendedKeyUsage"] = { "1.3.6.1.5.5.7.3.2" },
    } },
    { dn = "cn=Machine,cn=Certificate Templates,cn=Public Key Services,cn=Services,cn=System," .. nc, attrs = {
      ["cn"] = { "Machine" },
      ["objectClass"] = { "top", "msPKI-CertificateTemplate" },
      ["pKIExtendedKeyUsage"] = { "1.3.6.1.4.1.311.80.1" },
    } },
  }
end

local function ldap_mock_filter_from(tag, content)
  if tag == 0xA0 then
    local children = {}
    local p = 1
    while p <= #content do
      local ctag, cval, nxt = ldap_mock_tlv_next(content, p)
      if ctag == nil then
        break
      end
      children[#children + 1] = ldap_mock_filter_from(ctag, cval)
      p = nxt
    end
    return { kind = "and", children = children }
  end
  if tag == 0xA1 then
    local children = {}
    local p = 1
    while p <= #content do
      local ctag, cval, nxt = ldap_mock_tlv_next(content, p)
      if ctag == nil then
        break
      end
      children[#children + 1] = ldap_mock_filter_from(ctag, cval)
      p = nxt
    end
    return { kind = "or", children = children }
  end
  if tag == 0xA2 then
    local sub_tag, sub_val, _ = ldap_mock_tlv_next(content, 1)
    if sub_tag == nil then
      return { kind = "not", child = { kind = "present", attr = "objectClass" } }
    end
    return { kind = "not", child = ldap_mock_filter_from(sub_tag, sub_val) }
  end
  if tag == 0xA3 or tag == 0xA5 or tag == 0xA6 or tag == 0xA8 then
    local fields = ldap_mock_tlv_list(content)
    if #fields < 2 then
      return { kind = "present", attr = "objectClass" }
    end
    local kind = "eq"
    if tag == 0xA5 then
      kind = "ge"
    elseif tag == 0xA6 then
      kind = "le"
    elseif tag == 0xA8 then
      kind = "approx"
    end
    return { kind = kind, attr = fields[1].value, value = fields[2].value }
  end
  if tag == 0x87 then
    return { kind = "present", attr = content }
  end
  if tag == 0xA4 then
    local attr = ""
    local initial = ""
    local final = ""
    local any = {}
    local fields = ldap_mock_tlv_list(content)
    for i = 1, #fields do
      local f = fields[i]
      if f.tag == 0x04 then
        if attr == "" then
          attr = f.value
        end
      elseif f.tag == 0x30 then
        local subs = ldap_mock_tlv_list(f.value)
        for j = 1, #subs do
          local s = subs[j]
          if s.tag == 0x80 then
            initial = s.value
          elseif s.tag == 0x81 then
            any[#any + 1] = s.value
          elseif s.tag == 0x82 then
            final = s.value
          end
        end
      end
    end
    return { kind = "substring", attr = attr, initial = initial, any = any, final = final }
  end
  return { kind = "present", attr = "objectClass" }
end

local function ldap_mock_parse_filter(body)
  local tag, value, _ = ldap_mock_tlv_next(body, 1)
  if tag == nil then
    return { kind = "present", attr = "objectClass" }
  end
  return ldap_mock_filter_from(tag, value)
end

local function ldap_mock_attr_value(entry, attr)
  local values = entry.attrs[attr]
  if values == nil then
    values = entry.attrs[attr:lower()]
  end
  if values == nil then
    for k, v in pairs(entry.attrs) do
      if k:lower() == tostring(attr):lower() then
        values = v
        break
      end
    end
  end
  return values
end

local function ldap_mock_match(entry, filter)
  if filter.kind == "and" then
    for _, c in ipairs(filter.children) do
      if not ldap_mock_match(entry, c) then
        return false
      end
    end
    return true
  end
  if filter.kind == "or" then
    for _, c in ipairs(filter.children) do
      if ldap_mock_match(entry, c) then
        return true
      end
    end
    return false
  end
  if filter.kind == "not" then
    return not ldap_mock_match(entry, filter.child)
  end
  if filter.kind == "present" then
    return ldap_mock_attr_value(entry, filter.attr) ~= nil
  end
  if filter.kind == "eq" then
    local values = ldap_mock_attr_value(entry, filter.attr)
    if values == nil then
      return false
    end
    for _, v in ipairs(values) do
      if tostring(v):lower() == tostring(filter.value):lower() then
        return true
      end
    end
    return false
  end
  if filter.kind == "substring" then
    local values = ldap_mock_attr_value(entry, filter.attr)
    if values == nil then
      return false
    end
    for _, v in ipairs(values) do
      local lower = tostring(v):lower()
      if filter.initial ~= nil and filter.initial ~= "" and lower:sub(1, #filter.initial) == filter.initial:lower() then
        return true
      end
      if filter.final ~= nil and filter.final ~= "" and #lower >= #filter.final and lower:sub(#lower - #filter.final + 1) == filter.final:lower() then
        return true
      end
      for _, chunk in ipairs(filter.any) do
        if lower:find(tostring(chunk):lower(), 1, true) ~= nil then
          return true
        end
      end
    end
    return false
  end
  if filter.kind == "ge" or filter.kind == "le" then
    local values = ldap_mock_attr_value(entry, filter.attr)
    if values == nil then
      return false
    end
    local a = tonumber(tostring(values[1]))
    local b = tonumber(tostring(filter.value))
    if a == nil or b == nil then
      return false
    end
    if filter.kind == "ge" then
      return a >= b
    end
    return a <= b
  end
  return false
end

local function ldap_mock_rdn_depth(dn)
  local count = 0
  for _ in tostring(dn):gmatch(",") do
    count = count + 1
  end
  return count
end

local function ldap_mock_entry_bytes(entry, requested_attrs)
  local include_all = true
  if requested_attrs ~= nil and #requested_attrs > 0 then
    include_all = false
    for _, a in ipairs(requested_attrs) do
      if tostring(a) == "*" then
        include_all = true
      end
    end
  end
  local attr_parts = {}
  for name, values in pairs(entry.attrs) do
    local keep = include_all
    if not keep and requested_attrs ~= nil then
      for _, a in ipairs(requested_attrs) do
        if tostring(a):lower() == tostring(name):lower() then
          keep = true
        end
      end
    end
    if keep then
      local set_parts = {}
      for _, v in ipairs(values) do
        set_parts[#set_parts + 1] = ldap_mock_octet_tlv(v)
      end
      attr_parts[#attr_parts + 1] = ldap_mock_seq(ldap_mock_octet_tlv(name) .. ldap_mock_set(table.concat(set_parts)))
    end
  end
  return ldap_mock_octet_tlv(entry.dn) .. ldap_mock_seq(table.concat(attr_parts))
end

local function ldap_mock_entry_message(msgid, entry, requested_attrs)
  local content = ldap_mock_entry_bytes(entry, requested_attrs)
  return ldap_mock_seq(ldap_mock_int_tlv(msgid) .. string.char(0x64) .. ldap_mock_ber_len(#content) .. content)
end

local function ldap_mock_bind_response(msgid, result, diagnostic)
  local body = ldap_mock_int_tlv(result) .. ldap_mock_octet_tlv("") .. ldap_mock_octet_tlv(diagnostic or "")
  return ldap_mock_seq(ldap_mock_int_tlv(msgid) .. string.char(0x61) .. ldap_mock_ber_len(#body) .. body)
end

local function ldap_mock_paged_control_value(page_size, cookie)
  local inner = ldap_mock_int_tlv(page_size) .. ldap_mock_octet_tlv(cookie or "")
  return ldap_mock_seq(ldap_mock_oid_tlv("1.2.840.113556.1.4.319") .. ldap_mock_ctx(3, ldap_mock_seq(inner)))
end

local function ldap_mock_done_message(msgid, result, diagnostic, paged_ctrl)
  local body = ldap_mock_int_tlv(result) .. ldap_mock_octet_tlv("") .. ldap_mock_octet_tlv(diagnostic or "")
  if paged_ctrl ~= nil then
    body = body .. paged_ctrl
  end
  return ldap_mock_seq(ldap_mock_int_tlv(msgid) .. string.char(0x65) .. ldap_mock_ber_len(#body) .. body)
end

local function ldap_mock_extended_response(msgid, result, diagnostic)
  local body = ldap_mock_int_tlv(result) .. ldap_mock_octet_tlv("") .. ldap_mock_octet_tlv(diagnostic or "")
  return ldap_mock_seq(ldap_mock_int_tlv(msgid) .. string.char(0x78) .. ldap_mock_ber_len(#body) .. body)
end

local function ldap_mock_search(scenario, st, msgid, base, scope, size_limit, filter, requested_attrs, paged_size, paged_cookie)
  local rootdse = { dn = "", attrs = ldap_mock_build_rootdse(scenario) }
  local entries = ldap_mock_build_entries()
  local matched = {}
  local is_rootdse = (tostring(base):lower() == "")
  if is_rootdse then
    if ldap_mock_match(rootdse, filter) then
      matched[#matched + 1] = rootdse
    end
  else
    for _, e in ipairs(entries) do
      local lower_dn = e.dn:lower()
      local lower_base = tostring(base):lower()
      local inside = false
      if lower_dn == lower_base then
        inside = (scope == 0)
      elseif lower_dn:sub(#lower_dn - #lower_base) == "," .. lower_base then
        if scope == 2 then
          inside = true
        elseif scope == 1 then
          local depth = ldap_mock_rdn_depth(e.dn) - ldap_mock_rdn_depth(base)
          inside = (depth == 1)
        end
      end
      if inside and ldap_mock_match(e, filter) then
        matched[#matched + 1] = e
      end
    end
  end

  local diag = nil
  if scenario == "ldap-secure" and not is_rootdse then
    local code, diagnostic
    if st.bound and st.tls then
      code = 50
      diagnostic = "80090305: LdapErr: DSID-0C09042C, comment: AcceptSecurityContext error, data 531, v2580"
    else
      code = 50
      diagnostic = "80090305: LdapErr: DSID-0C09042C, comment: Access Denied, data 0, v2580"
    end
    return ldap_mock_done_message(msgid, code, diagnostic)
  end

  local paged = (paged_size ~= nil)
  local out = ""
  if paged then
    local cursor = 1
    if paged_cookie ~= nil and paged_cookie ~= "" then
      local c = paged_cookie:match("page:(%d+)")
      if c ~= nil then
        cursor = tonumber(c)
      end
    end
    local chunk = {}
    for i = cursor, math.min(cursor + paged_size - 1, #matched) do
      chunk[#chunk + 1] = matched[i]
    end
    local next_cookie = ""
    if cursor + paged_size - 1 < #matched then
      next_cookie = "page:" .. tostring(cursor + paged_size)
    end
    for _, e in ipairs(chunk) do
      out = out .. ldap_mock_entry_message(msgid, e, requested_attrs)
    end
    return out .. ldap_mock_done_message(msgid, 0, "", ldap_mock_paged_control_value(paged_size, next_cookie))
  end

  local limit = size_limit
  if limit == nil or limit < 1 then
    limit = #matched
  end
  local truncated = false
  local count = 0
  for _, e in ipairs(matched) do
    if count >= limit then
      truncated = true
      break
    end
    count = count + 1
    out = out .. ldap_mock_entry_message(msgid, e, requested_attrs)
  end
  local result = 0
  if truncated then
    result = 4
    diag = "LdapErr: DSID-0C09041A, comment: Size limit exceeded, data 0, v1db1"
  end
  return out .. ldap_mock_done_message(msgid, result, diag)
end

local function ldap_mock_reply(scenario, data, sock)
  if scenario ~= "ldap" and scenario ~= "ldap-secure" then
    return nil
  end
  local st = sock._ldap
  if st == nil then
    st = { bound = false, tls = false }
    sock._ldap = st
  end
  local tag, body, _ = ldap_mock_tlv_next(data, 1)
  if tag == nil or tag ~= 0x30 then
    return ""
  end
  local fields = ldap_mock_tlv_list(body)
  if #fields < 2 then
    return ""
  end
  local msgid = ldap_mock_int_value(fields[1].value)
  local op = fields[2].tag
  local opbody = fields[2].value

  if op == 0x60 then
    local inner = ldap_mock_tlv_list(opbody)
    local dn = ""
    local simple_pw = nil
    local is_null_auth = false
    for i = 2, #inner do
      if inner[i].tag == 0x04 then
        dn = inner[i].value
      elseif inner[i].tag == 0x80 then
        local atag, aval, _ = ldap_mock_tlv_next(inner[i].value, 1)
        if atag == 0x05 then
          is_null_auth = true
        elseif atag == 0x04 then
          simple_pw = aval
        end
      end
    end
    if scenario == "ldap" then
      st.bound = true
      return ldap_mock_bind_response(msgid, 0, "")
    end
    local anonymous = (tostring(dn):lower() == "") and (is_null_auth or (simple_pw == nil) or (simple_pw == ""))
    if anonymous then
      st.bound = true
      return ldap_mock_bind_response(msgid, 0, "")
    end
    if st.tls then
      st.bound = true
      return ldap_mock_bind_response(msgid, 0, "")
    end
    return ldap_mock_bind_response(msgid, 49,
      "80090305: LdapErr: DSID-0C09042C, comment: AcceptSecurityContext error, data 533, v553")
  end

  if op == 0x63 then
    local inner = ldap_mock_tlv_list(opbody)
    local base = ""
    local scope = 0
    local size_limit = 0
    local scope_set = false
    local size_set = false
    local filter = nil
    local requested_attrs = {}
    local paged_size = nil
    local paged_cookie = nil
    for i = 1, #inner do
      local f = inner[i]
      if f.tag == 0x04 then
        base = f.value
      elseif f.tag == 0x0A then
        if not scope_set then
          scope = ldap_mock_int_value(f.value)
          scope_set = true
        end
      elseif f.tag == 0x02 then
        if not size_set then
          size_limit = ldap_mock_int_value(f.value)
          size_set = true
        end
      elseif f.tag == 0xB0 then
        filter = ldap_mock_parse_filter(f.value)
      elseif f.tag == 0xB1 then
        local ap = 1
        while ap <= #f.value do
          local at, av, anxt = ldap_mock_tlv_next(f.value, ap)
          if at == nil then
            break
          end
          if at == 0x04 then
            requested_attrs[#requested_attrs + 1] = av
          end
          ap = anxt
        end
      elseif f.tag == 0x00 then
        local ctrls = ldap_mock_tlv_list(f.value)
        for _, c in ipairs(ctrls) do
          if c.tag == 0x30 then
            local cfields = ldap_mock_tlv_list(c.value)
            for _, cf in ipairs(cfields) do
              if cf.tag == 0x06 then
                local oid = ldap_mock_oid_value(cf.value)
                if oid == "1.2.840.113556.1.4.319" then
                  for _, cv in ipairs(cfields) do
                    if cv.tag == 0x83 then
                      local pvals = ldap_mock_tlv_list(cv.value)
                      if #pvals >= 1 then
                        paged_size = ldap_mock_int_value(pvals[1].value)
                      end
                      if #pvals >= 2 and pvals[2].tag == 0x04 then
                        paged_cookie = pvals[2].value
                      end
                    end
                  end
                end
              end
            end
          end
        end
      end
    end
    if filter == nil then
      filter = { kind = "present", attr = "objectClass" }
    end
    return ldap_mock_search(scenario, st, msgid, base, scope, size_limit, filter, requested_attrs, paged_size, paged_cookie)
  end

  if op == 0x77 then
    local inner = ldap_mock_tlv_list(opbody)
    local oid = ""
    for _, f in ipairs(inner) do
      if f.tag == 0x06 then
        oid = ldap_mock_oid_value(f.value)
      end
    end
    if oid == "1.3.6.1.4.1.1466.20037" then
      st.tls = true
      return ldap_mock_extended_response(msgid, 0, "")
    end
    if oid == "1.3.6.1.4.1.1466.20036" then
      return ldap_mock_extended_response(msgid, 0, "")
    end
    return ldap_mock_extended_response(msgid, 52, "unsupportedCriticalExtension")
  end

  if op == 0x42 then
    return ""
  end

  return ""
end

function new_mock_socket(proto)
  local sock = { buffer = BANNER or "", closed = false, proto = proto or "tcp" }
  function sock:connect(host, port, protocol, opts)
    local pnum = port
    if type(port) == "table" then
      pnum = port.number or port.port
    end
    self.connect_port = pnum
    if SCENARIO == "mqtt" or SCENARIO == "mqtt-secure" then
      self._mqtt = nil
      self.buffer = ""
      self.connected = true
      self.connect_proto = protocol or self.proto
      return 1
    end
    if SCENARIO == "ssh" or SCENARIO == "ssh-secure" then
      self._ssh = nil
      local ident = nil
      if BANNER ~= nil and real_string.find(BANNER, "SSH-", 1, true) == 1 then
        ident = BANNER
      end
      if ident == nil then
        if SCENARIO == "ssh-secure" then
          ident = "SSH-2.0-OpenSSH_9.8p1\r\n"
        else
          ident = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
        end
      end
      self.buffer = ident
      self.connected = true
      self.connect_proto = protocol or self.proto
      return 1
    end
    if SCENARIO == "docker" or SCENARIO == "docker-secure" then
      self._docker = true
      self.buffer = ""
      self.connected = true
      self.connect_proto = protocol or self.proto
      return 1
    end
    if SCENARIO == "snmp" or SCENARIO == "snmp-secure" then
      self._snmp = true
      self._snmp_rows = nil
      self.buffer = ""
      self.connected = true
      self.connect_proto = protocol or self.proto
      return 1
    end
    if SCENARIO == "ldap" or SCENARIO == "ldap-secure" then
      self.buffer = ""
      self.connected = true
      self.connect_proto = protocol or self.proto
      return 1
    end
    if SCENARIO == "ntp" or SCENARIO == "ntp-secure" then
      self.buffer = ""
      self._ntp = nil
      self.connected = true
      self.connect_proto = protocol or self.proto
      return 1
    end
    if SCENARIO == "telnet" or SCENARIO == "telnet-secure" then
      self._tel = nil
      self.buffer = ""
      self.connected = true
      self.connect_proto = protocol or self.proto
      TEL_CONN_SEQ = TEL_CONN_SEQ + 1
      self.buffer = TELNET_MOCK.connect_flight(SCENARIO)
      return 1
    end
    if SCENARIO == "sip" or SCENARIO == "sip-secure" then
      self._sip = nil
      self._sip_opts = 0
      self.buffer = ""
      self.connected = true
      self.connect_proto = protocol or self.proto
      SIP_CONN_SEQ = (SIP_CONN_SEQ or 0) + 1
      return 1
    end
    if SCENARIO == "smtp" or SCENARIO == "smtp-secure" then
      self._smtp = { phase = "command", mail_from = nil, mail_null = false, pipelined = 0, in_data = false }
      self.buffer = ""
      self.connected = true
      self.connect_proto = protocol or self.proto
      self.buffer = SMTP_MOCK.connect_banner(SCENARIO)
      return 1
    end
    if SCENARIO == "kerberos" or SCENARIO == "kerberos-secure" then
      self._krb = nil
      self.buffer = ""
      self.connected = true
      self.connect_proto = protocol or self.proto
      return 1
    end
    if SCENARIO == "nfs" or SCENARIO == "nfs-secure" then
      self.buffer = ""
      self.connected = true
      self.connect_proto = protocol or self.proto
      return 1
    end
    if SCENARIO == "ics" or SCENARIO == "ics-secure" then
      self.buffer = ""
      self.connected = true
      self.connect_proto = protocol or self.proto
      return 1
    end
    if SCENARIO == "k8s" or SCENARIO == "k8s-secure" then
      self.buffer = ""
      self.connected = true
      self.connect_proto = protocol or self.proto
      return 1
    end
    if SCENARIO == "es" or SCENARIO == "es-secure" then
      self.buffer = ""
      self.connected = true
      self.connect_proto = protocol or self.proto
      return 1
    end
    if SCENARIO == "mc" or SCENARIO == "mc-secure" or SCENARIO == "mc-udp" or SCENARIO == "mc-udp-secure" then
      self.buffer = ""
      self.connected = true
      self.connect_proto = protocol or self.proto
      return 1
    end
    if SCENARIO == "vnc" or SCENARIO == "vnc-secure" then
      self.buffer = ""
      self._vnc = nil
      self._vnc_seq = nil
      self.connected = true
      self.connect_proto = protocol or self.proto
      local vnc_banner = VNC_MOCK.connect_banner(SCENARIO, pnum)
      if vnc_banner ~= nil and vnc_banner ~= "" then
        self.buffer = vnc_banner
        if pnum == 5900 then
          VNC_CONN_SEQ = VNC_CONN_SEQ + 1
          self._vnc_seq = VNC_CONN_SEQ
        end
      end
      return 1
    end
    SOCKET_LOG[#SOCKET_LOG + 1] = "connect:" .. tostring(pnum)
    self.connected = true
    if pnum == 21 and (SCENARIO == "ftp" or SCENARIO == "ftp-secure") then
      self.buffer = ftp_banner(SCENARIO)
    elseif (SCENARIO == "ftp" or SCENARIO == "ftp-secure") and pnum ~= 21 then
      self.buffer = ftp_data_listing(SCENARIO)
    elseif pnum == 3306 and (SCENARIO == "db" or SCENARIO == "db-secure") then
      self.buffer = db_mysql_server_handshake(SCENARIO)
    elseif pnum == 443 or pnum == 8443 or DB_PORTS[pnum] == true then
      self.buffer = ""
    else
      self.buffer = BANNER or ""
    end
    self.connect_proto = protocol or self.proto
    return 1
  end
  function sock:send(data)
    SOCKET_LOG[#SOCKET_LOG + 1] = "send:" .. tostring(data):sub(1, 60)
    self.sent = tostring(data)
    local dns_reply = dns_mock_reply(SCENARIO, self.sent, self.connect_port, self.proto)
    if dns_reply == "__DNSMOCK_DROP__" then
      self.buffer = ""
      return 1, real_string.len(self.sent)
    end
    if dns_reply then
      self.buffer = dns_reply
      return 1, real_string.len(self.sent)
    end
    if (SCENARIO == "snmp" or SCENARIO == "snmp-secure") and self.connect_port == 161 then
      local snmp_reply = snmp_mock_reply(SCENARIO, self.sent, self)
      self.buffer = snmp_reply
      return 1, real_string.len(self.sent)
    end
    if (self.connect_port == 445 or self.connect_port == 139) then
      local smb_reply = smb_mock_reply(SCENARIO, self.sent, self.connect_port, self)
      if smb_reply == "__SMBMOCK_DROP__" then
        self.buffer = ""
        return 1, real_string.len(self.sent)
      end
      if smb_reply then
        self.buffer = smb_reply
        return 1, real_string.len(self.sent)
      end
    end
    if (SCENARIO == "db" or SCENARIO == "db-secure") and DB_PORTS[self.connect_port] == true then
      local db_reply = db_mock_reply(SCENARIO, self.sent, self.connect_port, self)
      if db_reply ~= nil then
        self.buffer = db_reply
        return 1, real_string.len(self.sent)
      end
    end
    if (SCENARIO == "ftp" or SCENARIO == "ftp-secure") and self.connect_port == 21 then
      local ftp_reply = ftp_mock_reply(SCENARIO, self.sent, self)
      if ftp_reply == "__FTPDROP__" then
        self.buffer = ""
        return 1, real_string.len(self.sent)
      end
      if ftp_reply ~= nil then
        self.buffer = ftp_reply
        return 1, real_string.len(self.sent)
      end
    end
    if (SCENARIO == "graphql" or SCENARIO == "graphql-secure") and #self.sent > 0 then
      local ws_reply = gql_ws_reply(SCENARIO, self.sent, self)
      if ws_reply ~= nil then
        self.buffer = ws_reply
        return 1, real_string.len(self.sent)
      end
    end
    if (SCENARIO == "docker" or SCENARIO == "docker-secure") and #self.sent > 0 then
      local docker_reply = docker_mock_reply(SCENARIO, self.sent, self)
      if docker_reply == nil then
        self.buffer = ""
        return 1, real_string.len(self.sent)
      end
      self.buffer = docker_reply
      return 1, real_string.len(self.sent)
    end
    if (SCENARIO == "mqtt" or SCENARIO == "mqtt-secure") and #self.sent > 0 then
      local mqtt_reply = mqtt_mock_reply(SCENARIO, self.sent, self)
      self.buffer = mqtt_reply
      return 1, real_string.len(self.sent)
    end
    if (SCENARIO == "ldap" or SCENARIO == "ldap-secure") and self.connect_port == 389 then
      local ldap_reply = ldap_mock_reply(SCENARIO, self.sent, self)
      if ldap_reply ~= nil then
        self.buffer = ldap_reply
        return 1, real_string.len(self.sent)
      end
    end
    if (SCENARIO == "rdp" or SCENARIO == "rdp-secure") and self.connect_port == 3389 then
      if self.connect_proto == "udp" then
        local udp_reply = string.char(0x00) .. db_u16le(9) .. db_u16le(3389) .. db_u32le(0x0A0B0C0D)
        self.buffer = udp_reply
        return 1, real_string.len(self.sent)
      end
      local rdp_reply = RDP_MOCK.rdp_mock_reply(SCENARIO, self.sent, self)
      if rdp_reply ~= nil then
        self.buffer = rdp_reply
        return 1, real_string.len(self.sent)
      end
    end
    if SCENARIO == "vnc" or SCENARIO == "vnc-secure" then
      local vnc_reply = VNC_MOCK.vnc_mock_reply(SCENARIO, self.sent, self)
      if vnc_reply ~= nil then
        self.buffer = (self.buffer or "") .. vnc_reply
        return 1, real_string.len(self.sent)
      end
    end
    if SCENARIO == "ntp" or SCENARIO == "ntp-secure" then
      if self.connect_port == 123 and self.connect_proto == "udp" then
        self.buffer = NTP_MOCK.ntp_reply(SCENARIO, self.sent, self)
        return 1, real_string.len(self.sent)
      end
      if self.connect_port == 4460 and self.connect_proto == "tcp" then
        if SCENARIO == "ntp-secure" then
          local nts_reply = tls_mock_reply("tls", self.sent, self)
          self.buffer = (self.buffer or "") .. (nts_reply or "")
        else
          self.buffer = ""
        end
        return 1, real_string.len(self.sent)
      end
    end
    if SCENARIO == "telnet" or SCENARIO == "telnet-secure" then
      if self.connect_port == 23 and self.connect_proto == "tcp" then
        local tel_reply = TELNET_MOCK.telnet_reply(SCENARIO, self.sent, self)
        self.buffer = (self.buffer or "") .. (tel_reply or "")
        return 1, real_string.len(self.sent)
      end
    end
    if SCENARIO == "sip" or SCENARIO == "sip-secure" then
      if self.connect_port == 5060 then
        local sip_reply = SIP_MOCK.sip_reply(SCENARIO, self.sent, self)
        self.buffer = (self.buffer or "") .. (sip_reply or "")
        return 1, real_string.len(self.sent)
      end
      if self.connect_port == 5061 and self.connect_proto == "tcp" then
        if SCENARIO == "sip-secure" then
          local tls_reply = tls_mock_reply("tls", self.sent, self)
          self.buffer = (self.buffer or "") .. (tls_reply or "")
        else
          self.buffer = ""
        end
        return 1, real_string.len(self.sent)
      end
    end
    if SCENARIO == "smtp" or SCENARIO == "smtp-secure" then
      if self.connect_port == 25 or self.connect_port == 587 then
        if self._smtp ~= nil and self._smtp.phase == "tls" then
          if SCENARIO == "smtp-secure" then
            local tls_reply = tls_mock_reply("tls", self.sent, self)
            self.buffer = (self.buffer or "") .. (tls_reply or "")
          else
            self.buffer = ""
          end
          return 1, real_string.len(self.sent)
        end
        local smtp_reply = SMTP_MOCK.smtp_reply(SCENARIO, self.sent, self)
        self.buffer = (self.buffer or "") .. (smtp_reply or "")
        return 1, real_string.len(self.sent)
      end
    end
    if SCENARIO == "nfs" or SCENARIO == "nfs-secure" then
      local nfs_reply = NFS_MOCK.rpc_send(SCENARIO, self.sent, self)
      self.buffer = (self.buffer or "") .. (nfs_reply or "")
      return 1, real_string.len(self.sent)
    end
    if SCENARIO == "ics" or SCENARIO == "ics-secure" then
      local ics_reply = ICS_MOCK.ics_send(SCENARIO, self.sent, self)
      self.buffer = (self.buffer or "") .. (ics_reply or "")
      return 1, real_string.len(self.sent)
    end
    if SCENARIO == "k8s" or SCENARIO == "k8s-secure" then
      local k8s_reply = K8S_MOCK.https_send(SCENARIO, self.sent, self)
      self.buffer = (self.buffer or "") .. (k8s_reply or "")
      return 1, real_string.len(self.sent)
    end
    if SCENARIO == "es" or SCENARIO == "es-secure" then
      local es_reply = ES_MOCK.http_send(SCENARIO, self.sent, self)
      self.buffer = (self.buffer or "") .. (es_reply or "")
      return 1, real_string.len(self.sent)
    end
    if SCENARIO == "ws" or SCENARIO == "ws-secure" then
      local ws_reply = WS_MOCK.tcp_send(SCENARIO, self.sent, self)
      self.buffer = (self.buffer or "") .. (ws_reply or "")
      return 1, real_string.len(self.sent)
    end
    if SCENARIO == "cloud" or SCENARIO == "cloud-secure" then
      local ssrf_reply = SSRF_MOCK.http_send(SCENARIO, self.sent, self)
      self.buffer = (self.buffer or "") .. (ssrf_reply or "")
      return 1, real_string.len(self.sent)
    end
    if SCENARIO == "kafka" or SCENARIO == "kafka-secure" then
      local ka_reply = KA_MOCK.kafka_send(SCENARIO, self.sent, self)
      self.buffer = (self.buffer or "") .. (ka_reply or "")
      return 1, real_string.len(self.sent)
    end
    if SCENARIO == "amqp" or SCENARIO == "amqp-secure" or SCENARIO == "amqps" or SCENARIO == "amqps-secure" then
      local amqp_reply = AMQP_MOCK.handle(SCENARIO, self.sent, self)
      self.buffer = (self.buffer or "") .. (amqp_reply or "")
      return 1, real_string.len(self.sent)
    end
    if SCENARIO == "mq-mgmt" or SCENARIO == "mq-mgmt-secure" then
      local mq_reply = MQ_MGMT.http_send(SCENARIO, self.sent, self)
      self.buffer = (self.buffer or "") .. (mq_reply or "")
      return 1, real_string.len(self.sent)
    end
    if SCENARIO == "mc" or SCENARIO == "mc-secure" then
      local mc_reply
      if string.byte(self.sent, 1) == MC.BINARY_MAGIC_REQ then
        mc_reply = MC_MOCK.binary_send(SCENARIO, self.sent, self)
      else
        mc_reply = MC_MOCK.tcp_send(SCENARIO, self.sent, self)
      end
      self.buffer = (self.buffer or "") .. (mc_reply or "")
      return 1, real_string.len(self.sent)
    end
    if SCENARIO == "mc-udp" or SCENARIO == "mc-udp-secure" then
      local mc_reply = MC_MOCK.udp_send(SCENARIO, self.sent, self)
      self.buffer = (self.buffer or "") .. (mc_reply or "")
      return 1, real_string.len(self.sent)
    end
    if SCENARIO == "kerberos" or SCENARIO == "kerberos-secure" then
      if self.connect_port == 88 or self.connect_port == 464 then
        local krb_reply = KRB_MOCK.krb_reply(SCENARIO, self.sent)
        self.buffer = (self.buffer or "") .. (krb_reply or "")
        return 1, real_string.len(self.sent)
      end
      if self.connect_port == 443 then
        if self.sent:byte(1) ~= nil and self.sent:byte(1) >= 0x14 and self.sent:byte(1) <= 0x18 then
          if SCENARIO == "kerberos-secure" then
            local tls_reply = tls_mock_reply("tls", self.sent, self)
            self.buffer = (self.buffer or "") .. (tls_reply or "")
          else
            self.buffer = ""
          end
          return 1, real_string.len(self.sent)
        end
        local http_status = (SCENARIO == "kerberos-secure") and "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nKKDCP-REPLY!"
          or "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
        self.buffer = http_status
        return 1, real_string.len(self.sent)
      end
    end
    if SCENARIO == "ssh" or SCENARIO == "ssh-secure" then
      if self.closed then
        self.buffer = ""
        return 1, real_string.len(self.sent)
      end
      local ssh_reply = ssh_mock_reply(SCENARIO, self.sent, self)
      self.buffer = ssh_reply
      return 1, real_string.len(self.sent)
    end
    if (self.connect_port == 443 or self.connect_port == 8443) and #self.sent > 0 then
      local first_byte = self.sent:byte(1)
      if first_byte ~= nil and first_byte >= 0x14 and first_byte <= 0x18 then
        local tls_reply = tls_mock_reply(SCENARIO, self.sent, self)
        if tls_reply ~= nil then
          self.buffer = self.buffer .. tls_reply
        end
        return 1, real_string.len(self.sent)
      end
      if self.tlsstate ~= nil and self.tlsstate.phase == "open" then
        self.buffer = tls_http_reply(SCENARIO, self.sent)
        return 1, real_string.len(self.sent)
      end
    end
    if SCENARIO == "methods" or SCENARIO == "plain" then
      self.pending = build_method_response(self.sent)
    else
      self.pending = BANNER or ""
    end
    return 1, real_string.len(tostring(data))
  end
  function sock:receive(pattern)
    if self.buffer == nil or #self.buffer == 0 then
      return nil, "TIMEOUT", ""
    end
    if type(pattern) == "number" then
      local out = real_string.sub(self.buffer, 1, pattern)
      self.buffer = real_string.sub(self.buffer, pattern + 1)
      return 1, out, ""
    end
    local out = self.buffer
    self.buffer = ""
    return 1, out, ""
  end
  function sock:receive_lines(count) return 1, (BANNER or "") .. "\n" end
  function sock:receive_until_close()
    if self.pending ~= nil then
      local value = self.pending
      self.pending = nil
      return 1, value
    end
    return 1, BANNER or ""
  end
  function sock:receive_buf(pattern, keep) return 1, BANNER or "" end
  function sock:receive_bytes(n)
    if self.buffer == nil or #self.buffer == 0 then
      return nil, "TIMEOUT", ""
    end
    local count = n or 1
    local available = real_string.len(self.buffer)
    if available < count then
      local out = self.buffer
      self.buffer = ""
      return 1, out, ""
    end
    local out = real_string.sub(self.buffer, 1, count)
    self.buffer = real_string.sub(self.buffer, count + 1)
    return 1, out, ""
  end
  function sock:close() self.closed = true return 1 end
  function sock:set_timeout(value) return 1 end
  function sock:get_info() return 1, { address = "127.0.0.1", port = 12345 } end
  function sock:reattach_ssl() return nil end
  function sock:start_tls() return nil end
  function sock:ssl_dowgrade() return nil end
  return sock
end

mocklib.socket = { new = function(proto) return new_mock_socket(proto) end }
mocklib.dnet = { new = function() return mocklib.nmap.new_dnet() end }

local real_require = require
require = function(name)
  if mocklib[name] then return mocklib[name] end
  local ok, mod = pcall(real_require, name)
  if ok then return mod end
  local stub = {}
  setmetatable(stub, { __index = function(self, key)
      local placeholder = function() return nil end
      rawset(self, key, placeholder)
      return placeholder
    end })
  return stub
end

SCRIPT_ARGS = {}

function to_lua_table(value)
  local result = {}
  if value == nil then return result end
  if type(value) == "table" then
    for k, v in pairs(value) do result[tostring(k)] = v end
    return result
  end
  local ok, items = pcall(function() return value.items() end)
  if ok and items then
    local iter_ok, iterator = pcall(function() return items end)
    if iter_ok then
      for entry in python_iter(iterator) do
        local k = python_get(entry, 0)
        local v = python_get(entry, 1)
        result[tostring(k)] = v
      end
    end
  end
  return result
end

function python_iter(obj)
  local state = { index = 0, obj = obj }
  return function()
    state.index = state.index + 1
    local ok, item = pcall(function() return obj[state.index - 1] end)
    if ok and item ~= nil then return item end
    return nil
  end
end

function python_get(obj, index)
  local ok, value = pcall(function() return obj[index] end)
  if ok then return value end
  return nil
end

function reset_sandbox()
  description = nil
  author = nil
  license = nil
  categories = nil
  usage = nil
  portrule = nil
  prerule = nil
  hostrule = nil
  action = nil
  SOCKET_LOG = {}
  VNC_CONN_SEQ = 0
  VNC_FAIL_COUNT = 0
  NTP_CLIENT_Q = 0
  NTP_MODE6_Q = 0
  TEL_FAIL_COUNT = 0
  TEL_CONN_SEQ = 0
  SIP_CONN_SEQ = 0
  SIP_CALLS = {}
  SMTP_CONN_SEQ = 0
end

function render_output(value, indent)
  indent = indent or ""
  if type(value) ~= "table" then return tostring(value) end
  local keys = {}
  for k in real_pairs(value) do keys[#keys + 1] = k end
  real_table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
  local parts = {}
  for i = 1, #keys do
    local k = keys[i]
    parts[#parts + 1] = indent .. "  " .. tostring(k) .. ": " .. render_output(value[k], indent .. "  ")
  end
  if #parts == 0 then return "{}" end
  return "\n" .. real_table.concat(parts, "\n")
end

RDP_MOCK = {}

local RDP_M_T = {
  X224_CR = 0xE0,
  X224_CC = 0xD0,
  NEG_REQ = 0x01,
  NEG_RSP = 0x02,
  NEG_FAILURE = 0x03,
  PROTO_SSL = 0x01,
  PROTO_HYBRID = 0x02,
  PROTO_RDSTLS = 0x04,
  PROTO_HYBRID_EX = 0x08,
}


function RDP_MOCK.rdp_m_der_len(n)
  if n < 128 then
    return string.char(n)
  end
  local bytes = {}
  local v = n
  while v > 0 do
    table.insert(bytes, 1, string.char(v % 256))
    v = math.floor(v / 256)
  end
  return string.char(0x80 + #bytes) .. table.concat(bytes)
end

function RDP_MOCK.rdp_m_der(tag, content)
  return string.char(tag) .. RDP_MOCK.rdp_m_der_len(#content) .. content
end

function RDP_MOCK.rdp_m_u32be(n)
  return string.char(math.floor(n / 16777216) % 256, math.floor(n / 65536) % 256, math.floor(n / 256) % 256, n % 256)
end

function RDP_MOCK.rdp_m_x224_cc(extra, is_failure, code)
  local tail
  if extra ~= nil then
    tail = extra
  elseif is_failure then
    tail = string.char(RDP_M_T.NEG_FAILURE, 0x00, 0x00, 0x09) .. RDP_MOCK.rdp_m_u32be(0) .. string.char(code)
  else
    tail = ""
  end
  local body = db_u16le(0x1234) .. db_u16le(0x4321) .. string.char(0x00) .. tail
  local total = #body + 6
  return "\x03\x00" .. string.char(math.floor(total / 256) % 256, total % 256) .. string.char(RDP_M_T.X224_CC, #body + 6) .. body
end

function RDP_MOCK.rdp_m_ntlm_challenge(opts)
  opts = opts or {}
  local target_name = opts.target_name or ""
  local info = ""
  local av = opts.av or {}
  for _, item in ipairs(av) do
    info = info .. db_u16le(item[1]) .. db_u16le(#item[2]) .. item[2]
  end
  info = info .. db_u16le(0) .. db_u16le(0)
  local ti_off = 56 + #target_name
  local msg = "NTLMSSP\0"
    .. db_u32le(2)
    .. db_u16le(#target_name) .. db_u16le(#target_name) .. db_u32le(56)
    .. db_u32le(opts.flags or 0x00008201)
    .. (opts.challenge or "\x11\x22\x33\x44\x55\x66\x77\x88")
    .. string.rep("\0", 8)
    .. db_u16le(#info) .. db_u16le(#info) .. db_u32le(ti_off)
    .. string.char(opts.os_major or 0x05, opts.os_minor or 0x01) .. db_u16le(opts.os_build or 2600)
    .. "\x00\x00\x00\x0f"
    .. target_name
    .. info
  return msg
end

function RDP_MOCK.rdp_m_tsrequest(version, ntlm_bytes)
  local version_field = "\xa0\x03\x02\x01" .. string.char(version)
  local tok = ""
  if ntlm_bytes ~= nil then
    tok = RDP_MOCK.rdp_m_der(0xA1, RDP_MOCK.rdp_m_der(0x30, RDP_MOCK.rdp_m_der(0xA0, RDP_MOCK.rdp_m_der(0x04, ntlm_bytes))))
  end
  return RDP_MOCK.rdp_m_der(0x30, version_field .. tok)
end

function RDP_MOCK.rdp_m_spnego_challenge(ntlm_bytes)
  local mech = RDP_MOCK.rdp_m_der(0x06, "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a")
  local tok = RDP_MOCK.rdp_m_der(0xA1, RDP_MOCK.rdp_m_der(0x30, RDP_MOCK.rdp_m_der(0xA0, RDP_MOCK.rdp_m_der(0x30, mech)) .. RDP_MOCK.rdp_m_der(0xA2, RDP_MOCK.rdp_m_der(0x04, ntlm_bytes))))
  return RDP_MOCK.rdp_m_der(0x30, tok)
end

function RDP_MOCK.rdp_m_gcc_connect_response(opts)
  opts = opts or {}
  local core = db_u32le(opts.version or 0x0500)
  if opts.with_neg ~= nil then
    core = core .. "\x01" .. db_u32le(opts.with_neg)
  end
  if opts.early_caps ~= nil then
    core = core .. db_u32le(opts.early_caps)
  end
  local security = db_u32le(opts.encryption or 0x00000003) .. db_u32le(0)
  local chans = ""
  local defs = opts.channels or {}
  for _, name in ipairs(defs) do
    local nm = name
    while #nm < 8 do
      nm = nm .. "\0"
    end
    chans = chans .. nm .. db_u32le(0x00200000)
  end
  local net = db_u32le(#defs) .. chans
  local blocks = db_u16le(0x0C01) .. db_u32le(#core + 6) .. core
    .. db_u16le(0x0C02) .. db_u32le(#security + 6) .. security
    .. db_u16le(0x0C03) .. db_u32le(#net + 6) .. net
  local gcc = "\x01" .. db_u16le(7 + #blocks) .. "\x00" .. "\x74\x44" .. db_u16le(#blocks)
    .. blocks
  local body = RDP_MOCK.rdp_m_der(0x02, "\x00\x00") .. RDP_MOCK.rdp_m_der(0x04, "\x00\x00\x00") .. RDP_MOCK.rdp_m_der(0x04, gcc)
  local mcs = string.char(0x66) .. RDP_MOCK.rdp_m_der_len(#body) .. body
  return "\x03\x00" .. string.char(math.floor((4 + 3 + #mcs) / 256) % 256, (4 + 3 + #mcs) % 256)
    .. string.char(0x02, 0xF0, 0x80) .. mcs
end

function RDP_MOCK.rdp_m_handle_tsrequest(tsreq, legacy)
  local tsver = tsreq:byte(7)
  local ntlm
  if legacy then
    ntlm = RDP_MOCK.rdp_m_ntlm_challenge({
      target_name = "TS01",
      os_major = 0x05,
      os_minor = 0x01,
      os_build = 2600,
      flags = 0x02808289,
      av = {
        { 0x01, "TS01" },
        { 0x02, "CORP" },
        { 0x03, "ts01.corp.example.local" },
        { 0x04, "corp.example.local" },
        { 0x06, "\x01\x00\x00\x00" },
        { 0x07, "\xa1\xb2\xc3\xd4\xe5\xf6\xa7\xb8" },
      },
    })
  else
    ntlm = RDP_MOCK.rdp_m_ntlm_challenge({
      target_name = "",
      os_major = 0x0A,
      os_minor = 0x00,
      os_build = 19041,
      flags = 0x02028201,
      av = {
        { 0x06, "\x02\x00\x00\x00" },
      },
    })
  end
  local version
  if legacy then
    version = math.min(tsver or 5, 5)
    if version < 1 then
      version = 5
    end
  else
    version = 6
  end
  local payload = RDP_MOCK.rdp_m_tsrequest(version, RDP_MOCK.rdp_m_spnego_challenge(ntlm))
  local body = string.char(0x02, 0xF0, 0x80) .. payload
  return "\x03\x00" .. string.char(math.floor((4 + #body) / 256) % 256, (4 + #body) % 256) .. body
end

function RDP_MOCK.rdp_mock_reply(scenario, data, sock)
  if scenario ~= "rdp" and scenario ~= "rdp-secure" then
    return nil
  end
  local legacy = (scenario == "rdp")
  local st = sock._rdp
  if st == nil then
    st = { selected = nil, tls = false }
    sock._rdp = st
  end
  if st.tls then
    local mapped = legacy and "tls-legacy" or "tls"
    return tls_mock_reply(mapped, data, sock)
  end
  if data:byte(1) >= 0x14 and data:byte(1) <= 0x18 then
    st.tls = true
    local mapped = legacy and "tls-legacy" or "tls"
    return tls_mock_reply(mapped, data, sock)
  end
  if data:byte(1) ~= 0x03 or data:byte(2) ~= 0x00 then
    return ""
  end
  local plen = data:byte(3) * 256 + data:byte(4)
  if #data < plen then
    return ""
  end
  local ptype = data:byte(5)
  if ptype == RDP_M_T.X224_CR then
    local req = nil
    if plen >= 12 then
      local tail = plen - 8
      if data:byte(tail + 1) == RDP_M_T.NEG_REQ then
        req = data:byte(tail + 5) * 16777216 + data:byte(tail + 6) * 65536 + data:byte(tail + 7) * 256 + data:byte(tail + 8)
      end
    end
    st.requested = req
    if legacy then
      return RDP_MOCK.rdp_m_x224_cc(nil)
    end
    if req == nil then
      return RDP_MOCK.rdp_m_x224_cc(nil, true, 0x05)
    end
    if math.floor(req / RDP_M_T.PROTO_HYBRID) % 2 == 1 then
      st.selected = RDP_M_T.PROTO_HYBRID
      return RDP_MOCK.rdp_m_x224_cc(string.char(RDP_M_T.NEG_RSP, 0x00, 0x00, 0x08) .. RDP_MOCK.rdp_m_u32be(RDP_M_T.PROTO_HYBRID))
    end
    if math.floor(req / RDP_M_T.PROTO_SSL) % 2 == 1 then
      st.selected = RDP_M_T.PROTO_SSL
      return RDP_MOCK.rdp_m_x224_cc(string.char(RDP_M_T.NEG_RSP, 0x00, 0x00, 0x08) .. RDP_MOCK.rdp_m_u32be(RDP_M_T.PROTO_SSL))
    end
    return RDP_MOCK.rdp_m_x224_cc(nil, true, 0x05)
  end
  if ptype == 0x02 and data:byte(6) == 0xF0 then
    if data:byte(8) == 0x30 then
      return RDP_MOCK.rdp_m_handle_tsrequest(data:sub(8), legacy)
    end
    if data:byte(8) ~= 0x65 then
      return ""
    end
    if not legacy then
      return ""
    end
    return RDP_MOCK.rdp_m_gcc_connect_response({
      version = 0x0500,
      encryption = 0x0000000B,
      channels = { "rdpdr", "cliprdr", "rdpsnd", "MS_T120" },
    })
  end
  if data:byte(1) == 0x30 then
    local tsver = data:byte(7)
    local ntlm
    if legacy then
      ntlm = RDP_MOCK.rdp_m_ntlm_challenge({
        target_name = "TS01",
        os_major = 0x05,
        os_minor = 0x01,
        os_build = 2600,
        flags = 0x00008289,
        av = {
          { 0x01, "TS01" },
          { 0x02, "CORP" },
          { 0x03, "ts01.corp.example.local" },
          { 0x04, "corp.example.local" },
          { 0x06, "\x01\x00\x00\x00" },
          { 0x07, "\xa1\xb2\xc3\xd4\xe5\xf6\xa7\xb8" },
        },
      })
    else
      ntlm = RDP_MOCK.rdp_m_ntlm_challenge({
        target_name = "",
        os_major = 0x0A,
        os_minor = 0x00,
        os_build = 19041,
        flags = 0x00028201,
        av = {
          { 0x06, "\x02\x00\x00\x00" },
        },
      })
    end
    local version
    if legacy then
      version = math.min(tsver or 5, 5)
      if version < 1 then
        version = 5
      end
    else
      version = 6
    end
    return RDP_MOCK.rdp_m_tsrequest(version, RDP_MOCK.rdp_m_spnego_challenge(ntlm))
  end
  if data:byte(1) >= 0x14 and data:byte(1) <= 0x18 then
    st.tls = true
    local mapped = legacy and "tls-legacy" or "tls"
    return tls_mock_reply(mapped, data, sock)
  end
  return ""
end

VNC_MOCK = {}

VNC_CONN_SEQ = 0
VNC_FAIL_COUNT = 0

VNC_MOCK.AUTH_EXPECT = {
  "c638469eca6da1d9b4c77306c57eca1e",
  "ffc8bc6ee626dbad348a4da7524c78c3",
  "e55ab8fc888da6a0bc096d47c708ce95",
  "0c8e8a5d8f0ff5d4b5b5d29e3e57b935",
  "8cfcfc19b30a824cb3f3a32e9919e32f",
  "49703fe73170968788cca09f75b0d051",
  "125ee02cc149a7e2a86a327bd2851af4",
  "c8f7ea8568abc5c34e22b561f4b985bd",
  "10c1448a3d961a0091053f20741368df",
  "494c061f8b23131705a6adbbb7757f01",
  "cee7d9b1e2cb1cc69671008af9ef858f",
  "a9920a2c06500c994adcaf7f090695bf",
  "07eafbcd586a320b303ef3de56071d46",
  "0de1302113980afeb30814c1f658846e",
  "7b8e29b680cf8bf433a8ba3cb01bd4c5",
  "b7e996c7f7e7e8d7246f2be7e4f96c4c",
}

local VNC_M_CFG = {
  ["vnc"] = {
    banner = "RFB 003.008\n",
    sec_types = { 1, 2 },
    auth_expect = VNC_MOCK.AUTH_EXPECT,
    lockout = 0,
    server_name = "legacy-vnc",
    width = 1024,
    height = 768,
    down33_type = 1,
    premature_accept = true,
    http_5800 = true,
    ws_6080 = true,
    repeater = true,
    cut_text = "CORP\\svc-backup:P@ssw0rd2011",
  },
  ["vnc-secure"] = {
    banner = "RFB 003.008\n",
    sec_types = { 2, 18 },
    auth_expect = {},
    lockout = 3,
    server_name = "corp-vnc01.example.local",
    width = 1920,
    height = 1080,
    down33_type = 2,
    premature_accept = false,
    http_5800 = false,
    ws_6080 = false,
    repeater = false,
    cut_text = nil,
  },
}


function VNC_MOCK.u16be(v)
  return string.char(math.floor(v / 256) % 256, v % 256)
end

function VNC_MOCK.u32be(v)
  return string.char(math.floor(v / 16777216) % 256, math.floor(v / 65536) % 256, math.floor(v / 256) % 256, v % 256)
end

function VNC_MOCK.binhex(data)
  local out = {}
  for i = 1, #data do
    out[#out + 1] = string.format("%02x", data:byte(i))
  end
  return table.concat(out, "")
end

function VNC_MOCK.challenge_for(seq)
  local parts = {}
  for j = 1, 16 do
    parts[#parts + 1] = string.char((seq * 37 + j * 13 + 11) % 256)
  end
  return table.concat(parts, "")
end

function VNC_MOCK.has_type(cfg, t)
  for i = 1, #cfg.sec_types do
    if cfg.sec_types[i] == t then
      return true
    end
  end
  return false
end

function VNC_MOCK.server_init_bytes(cfg)
  local pix = string.char(32, 24, 0, 1) .. VNC_MOCK.u16be(255) .. VNC_MOCK.u16be(255) .. VNC_MOCK.u16be(255)
    .. string.char(16, 8, 0) .. "\x00\x00\x00"
  return VNC_MOCK.u16be(cfg.width) .. VNC_MOCK.u16be(cfg.height) .. pix
    .. VNC_MOCK.u32be(#cfg.server_name) .. cfg.server_name
end

function VNC_MOCK.offer_bytes(cfg)
  local parts = { string.char(#cfg.sec_types) }
  for i = 1, #cfg.sec_types do
    parts[#parts + 1] = string.char(cfg.sec_types[i])
  end
  return table.concat(parts, "")
end

function VNC_MOCK.locked(cfg)
  return cfg.lockout > 0 and VNC_FAIL_COUNT >= cfg.lockout
end

function VNC_MOCK.connect_banner(scenario, pnum)
  local cfg = VNC_M_CFG[scenario]
  if cfg == nil then
    return ""
  end
  if pnum == 5900 then
    if VNC_MOCK.locked(cfg) then
      return ""
    end
    return cfg.banner
  end
  if pnum == 5500 and cfg.repeater then
    return "RFB 000.000.000\n"
  end
  return ""
end

function VNC_MOCK.rfb_reply(cfg, scenario, sent, sock)
  if sock._vnc == nil then
    sock._vnc = { stage = "await_client_version", cut_sent = false }
  end
  local st = sock._vnc
  if VNC_MOCK.locked(cfg) then
    st.stage = "dropped"
    return ""
  end
  if st.stage == "await_client_version" then
    if #sent < 12 or sent:sub(1, 3) ~= "RFB" then
      st.stage = "dropped"
      return ""
    end
    if #sent > 12 then
      local premature = sent:byte(13)
      if cfg.premature_accept and premature == 1 then
        st.stage = "await_client_init"
        return VNC_MOCK.u32be(0)
      end
      st.stage = "dropped"
      return VNC_MOCK.u32be(1)
    end
    local minor = tonumber(sent:sub(9, 12))
    if minor ~= nil and minor <= 3 then
      if cfg.down33_type == 2 then
        st.stage = "await_auth_response"
        st.challenge = VNC_MOCK.challenge_for(sock._vnc_seq or 1)
        return VNC_MOCK.u32be(2) .. st.challenge
      end
      st.stage = "await_client_init"
      return VNC_MOCK.u32be(1)
    end
    st.stage = "await_choice"
    return VNC_MOCK.offer_bytes(cfg)
  end
  if st.stage == "await_choice" then
    local choice = sent:byte(1)
    if choice == 1 then
      if VNC_MOCK.has_type(cfg, 1) then
        st.stage = "await_client_init"
        return VNC_MOCK.u32be(0)
      end
      st.stage = "dropped"
      return VNC_MOCK.u32be(1)
    end
    if choice == 2 then
      if VNC_MOCK.has_type(cfg, 2) then
        st.stage = "await_auth_response"
        st.challenge = VNC_MOCK.challenge_for(sock._vnc_seq or 1)
        return st.challenge
      end
      st.stage = "dropped"
      return VNC_MOCK.u32be(1)
    end
    st.stage = "dropped"
    return VNC_MOCK.u32be(1)
  end
  if st.stage == "await_auth_response" then
    local resp = sent:sub(1, 16)
    local expect_list = cfg.auth_expect or {}
    local expect = expect_list[sock._vnc_seq or 1]
    if expect ~= nil and VNC_MOCK.binhex(resp) == expect then
      st.stage = "await_client_init"
      return VNC_MOCK.u32be(0)
    end
    VNC_FAIL_COUNT = VNC_FAIL_COUNT + 1
    st.stage = "dropped"
    return VNC_MOCK.u32be(1)
  end
  if st.stage == "await_client_init" then
    st.stage = "open"
    return VNC_MOCK.server_init_bytes(cfg)
  end
  if st.stage == "open" then
    if cfg.cut_text ~= nil and not st.cut_sent then
      st.cut_sent = true
      return "\x03\x00\x00\x00" .. VNC_MOCK.u32be(#cfg.cut_text) .. cfg.cut_text
    end
    return ""
  end
  return ""
end

VNC_MOCK.HTTP_PAGE = "<html><head><title>TightVNC desktop viewer - legacy-vnc</title></head><body><h1>TightVNC Java viewer</h1><p>Connect with the vncviewer archive applet.</p></body></html>"

VNC_MOCK.WS_PAGE = "<html><head><title>noVNC</title></head><body><h1>noVNC ready</h1><p>Launch vnc.html?host=target for the websockify bridge.</p></body></html>"

function VNC_MOCK.http_reply(cfg, scenario, sent, sock)
  if not cfg.http_5800 then
    return ""
  end
  if sent:find("GET /", 1, true) or sent:find("HEAD /", 1, true) then
    return "HTTP/1.0 200 OK\r\nServer: TightVNC-Web/1.3.10\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n" .. VNC_MOCK.HTTP_PAGE
  end
  return "HTTP/1.0 405 Method Not Allowed\r\nServer: TightVNC-Web/1.3.10\r\nConnection: close\r\n\r\n"
end

function VNC_MOCK.ws_reply(cfg, scenario, sent, sock)
  if not cfg.ws_6080 then
    return ""
  end
  if sent:find("Upgrade: websocket", 1, true) then
    return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
  end
  if sent:find("GET /", 1, true) then
    return "HTTP/1.1 200 OK\r\nServer: websockify/0.10.0\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n" .. VNC_MOCK.WS_PAGE
  end
  return "HTTP/1.1 405 Method Not Allowed\r\nServer: websockify/0.10.0\r\nConnection: close\r\n\r\n"
end

function VNC_MOCK.repeater_reply(cfg, scenario, sent, sock)
  if not cfg.repeater then
    return ""
  end
  if sent:sub(1, 3) == "ID:" or #sent >= 24 then
    return "RFB 003.008\n"
  end
  return ""
end

function VNC_MOCK.vnc_mock_reply(scenario, sent, sock)
  local cfg = VNC_M_CFG[scenario]
  if cfg == nil then
    return ""
  end
  if sock.connect_port == 5900 then
    return VNC_MOCK.rfb_reply(cfg, scenario, sent, sock)
  end
  if sock.connect_port == 5800 then
    return VNC_MOCK.http_reply(cfg, scenario, sent, sock)
  end
  if sock.connect_port == 6080 then
    return VNC_MOCK.ws_reply(cfg, scenario, sent, sock)
  end
  if sock.connect_port == 5500 then
    return VNC_MOCK.repeater_reply(cfg, scenario, sent, sock)
  end
  return ""
end


NTP_MOCK = {}

NTP_CLIENT_Q = 0
NTP_MODE6_Q = 0

local NTP_M_CFG = {
  ["ntp"] = {
    server_vn = 3,
    stratum = 3,
    poll = 6,
    precision = 0xEC,
    rootdelay = 0.06,
    rootdisp = 0.35,
    refid = { 10, 0, 0, 1 },
    skew = 5,
    kod_after = 1,
    mode6_allowed = true,
    monlist = true,
    restrict = true,
    traps = true,
    authinfo = true,
    nts = false,
    version = "ntpd 4.2.6p5@1.2349-o Fri Jul 17 06:17:34 UTC 2015 (1)",
    processor = "x86_64",
    system = "Linux/4.4.0-142-generic",
  },
  ["ntp-secure"] = {
    server_vn = 4,
    stratum = 2,
    poll = 7,
    precision = 0xE9,
    rootdelay = 0.01,
    rootdisp = 0.05,
    refid = { 10, 0, 0, 2 },
    skew = 0,
    kod_after = nil,
    mode6_allowed = false,
    monlist = false,
    restrict = false,
    traps = false,
    authinfo = false,
    nts = true,
    version = "ntpd 4.2.8p18@1.3846-o Mon Jun 03 09:12:41 UTC 2024 (1)",
    processor = "x86_64",
    system = "Linux/6.8.0-45-generic",
  },
}

function NTP_MOCK.u16be(v)
  return string.char(math.floor(v / 256) % 256, v % 256)
end

function NTP_MOCK.u32be(v)
  return string.char(math.floor(v / 16777216) % 256, math.floor(v / 65536) % 256, math.floor(v / 256) % 256, v % 256)
end

function NTP_MOCK.short_bytes(value)
  local whole = math.floor(value)
  local frac = math.floor((value - whole) * 65536)
  return NTP_MOCK.u16be(whole) .. NTP_MOCK.u16be(frac)
end

function NTP_MOCK.ts_bytes(sec_offset, frac)
  local sec = os.time() + (sec_offset or 0) + 2208988800
  return NTP_MOCK.u32be(sec) .. NTP_MOCK.u32be(frac or 0)
end

function NTP_MOCK.ip_bytes(octets)
  return string.char(octets[1], octets[2], octets[3], octets[4])
end

function NTP_MOCK.mode4_normal(cfg, sent)
  local now_frac_recv = cfg.skew > 0 and 0x20000000 or 0x20000000
  local now_frac_tx = cfg.skew > 0 and 0x60000000 or 0x30000000
  local hdr = string.char(0 * 64 + cfg.server_vn * 8 + 4)
  local out = hdr
    .. string.char(cfg.stratum, cfg.poll, cfg.precision)
    .. NTP_MOCK.short_bytes(cfg.rootdelay)
    .. NTP_MOCK.short_bytes(cfg.rootdisp)
    .. NTP_MOCK.ip_bytes(cfg.refid)
    .. NTP_MOCK.ts_bytes(-8, 0x10000000)
    .. sent:sub(41, 48)
    .. NTP_MOCK.ts_bytes(0, now_frac_recv)
    .. NTP_MOCK.ts_bytes(cfg.skew, now_frac_tx)
  return out
end

function NTP_MOCK.kod_response(cfg, sent)
  local hdr = string.char(0 * 64 + cfg.server_vn * 8 + 4)
  local rate = string.byte("R") * 16777216 + string.byte("A") * 65536 + string.byte("T") * 256 + string.byte("E")
  local refid = string.char(math.floor(rate / 16777216) % 256, math.floor(rate / 65536) % 256, math.floor(rate / 256) % 256, rate % 256)
  return hdr
    .. string.char(0, 10, 0xEC)
    .. NTP_MOCK.short_bytes(0)
    .. NTP_MOCK.short_bytes(0)
    .. refid
    .. NTP_MOCK.ts_bytes(-8, 0x10000000)
    .. sent:sub(41, 48)
    .. NTP_MOCK.ts_bytes(0, 0x20000000)
    .. NTP_MOCK.ts_bytes(0, 0x20000000)
end

function NTP_MOCK.mode6_response(cfg, sent, error_flag, data)
  local op = sent:byte(2) % 32
  local flags = 0x80 + op
  if error_flag then
    flags = flags + 0x20
  end
  local seq = sent:byte(3) * 256 + sent:byte(4)
  local assoc = sent:byte(7) * 256 + sent:byte(8)
  local status = 0x0614
  return string.char(0 * 64 + 2 * 8 + 6)
    .. string.char(flags)
    .. NTP_MOCK.u16be(seq)
    .. NTP_MOCK.u16be(status)
    .. NTP_MOCK.u16be(assoc)
    .. NTP_MOCK.u16be(0)
    .. NTP_MOCK.u16be(data and #data or 0)
    .. (data or "")
end

function NTP_MOCK.peer_vars(cfg, assoc)
  if assoc == 0 then
    return "version=" .. cfg.version .. ",processor=" .. cfg.processor .. ",system=" .. cfg.system
      .. ",stratum=" .. tostring(cfg.stratum) .. ",refid=" .. table.concat(cfg.refid, ".")
      .. ",leap=0,precision=" .. tostring(-((256 - cfg.precision) % 256))
  end
  if assoc == 1 then
    return "srcadr=192.0.2.50,srcport=123,stratum=2,flags=f024,peerflags=sys.peer,auth"
  end
  if assoc == 2 then
    return "srcadr=192.0.2.51,srcport=123,stratum=2,flags=f005,peerflags=backup,client"
  end
  if assoc == 3 then
    return "srcadr=10.0.0.9,srcport=123,stratum=2,flags=b815,peerflags=autokey,broadcast"
  end
  return nil
end

function NTP_MOCK.mon_entry(ip, port, name)
  local entry = NTP_MOCK.ip_bytes(ip) .. NTP_MOCK.u16be(port) .. string.rep("\x00", 40)
  entry = entry .. NTP_MOCK.ip_bytes({ 192, 0, 2, 10 }) .. NTP_MOCK.u16be(123) .. string.rep("\x00", 16)
  if name ~= nil then
    entry = entry .. name
  end
  while #entry < 72 do
    entry = entry .. "\x00"
  end
  return entry:sub(1, 72)
end

function NTP_MOCK.mode7_header(cfg, sent, err, nitems, item_size)
  local seq = sent:byte(2) % 128
  return string.char(0x80 + 0 * 64 + 2 * 8 + 7)
    .. string.char(seq)
    .. string.char(sent:byte(3))
    .. string.char(sent:byte(4))
    .. NTP_MOCK.u16be(err * 4096 + nitems)
    .. NTP_MOCK.u16be(item_size)
end

function NTP_MOCK.mode7_response(cfg, sent)
  local impl = sent:byte(3)
  local req = sent:byte(4)
  if cfg.monlist and (req == 42 or req == 20) then
    local entries = NTP_MOCK.mon_entry({ 192, 0, 2, 50 }, 123, "client050.corp.example")
      .. NTP_MOCK.mon_entry({ 192, 0, 2, 51 }, 123, "client051.corp.example")
      .. NTP_MOCK.mon_entry({ 198, 51, 100, 77 }, 4460, "relay77.example.net")
    return NTP_MOCK.mode7_header(cfg, sent, 0, 3, 72) .. entries
  end
  if cfg.restrict and req == 16 then
    local e1 = NTP_MOCK.ip_bytes({ 10, 0, 0, 0 }) .. NTP_MOCK.ip_bytes({ 255, 0, 0, 0 }) .. NTP_MOCK.u32be(0x10) .. NTP_MOCK.u32be(3)
    local e2 = NTP_MOCK.ip_bytes({ 0, 0, 0, 0 }) .. NTP_MOCK.ip_bytes({ 0, 0, 0, 0 }) .. NTP_MOCK.u32be(0x14) .. NTP_MOCK.u32be(7)
    return NTP_MOCK.mode7_header(cfg, sent, 0, 2, 16) .. e1 .. e2
  end
  if cfg.traps and req == 29 then
    local e1 = NTP_MOCK.ip_bytes({ 10, 0, 0, 5 }) .. NTP_MOCK.ip_bytes({ 198, 51, 100, 9 }) .. NTP_MOCK.u16be(5678) .. NTP_MOCK.u16be(1)
    while #e1 < 16 do
      e1 = e1 .. "\x00"
    end
    return NTP_MOCK.mode7_header(cfg, sent, 0, 1, 16) .. e1
  end
  if cfg.authinfo and req == 28 then
    local data = NTP_MOCK.u32be(42) .. NTP_MOCK.u32be(0) .. NTP_MOCK.u32be(7) .. NTP_MOCK.u32be(3) .. NTP_MOCK.u32be(2) .. NTP_MOCK.u32be(5)
    return NTP_MOCK.mode7_header(cfg, sent, 0, 1, 24) .. data
  end
  if req == 4 then
    local data = "version=" .. cfg.version .. ",processor=" .. cfg.processor .. ",system=" .. cfg.system
    return NTP_MOCK.mode7_header(cfg, sent, 0, 1, #data) .. data
  end
  return NTP_MOCK.mode7_header(cfg, sent, 2, 0, 0)
end

function NTP_MOCK.ntp_reply(scenario, sent, sock)
  local cfg = NTP_M_CFG[scenario]
  if cfg == nil or sent == nil or #sent < 12 then
    return ""
  end
  local hb = sent:byte(1)
  local mode = hb % 8
  local vn = math.floor(hb / 8) % 8
  if (mode == 3 or mode == 7) and #sent < 48 then
    return ""
  end
  if mode == 3 then
    NTP_CLIENT_Q = NTP_CLIENT_Q + 1
    if cfg.kod_after ~= nil and NTP_CLIENT_Q > cfg.kod_after then
      return NTP_MOCK.kod_response(cfg, sent)
    end
    return NTP_MOCK.mode4_normal(cfg, sent)
  end
  if mode == 6 then
    local op = sent:byte(2) % 32
    NTP_MODE6_Q = NTP_MODE6_Q + 1
    if not cfg.mode6_allowed then
      return NTP_MOCK.mode6_response(cfg, sent, true, nil)
    end
    if op == 1 then
      return NTP_MOCK.mode6_response(cfg, sent, false, "1=f024,2=f005,3=b815")
    end
    if op == 2 then
      local assoc = sent:byte(7) * 256 + sent:byte(8)
      local data = NTP_MOCK.peer_vars(cfg, assoc)
      if data == nil then
        return NTP_MOCK.mode6_response(cfg, sent, true, nil)
      end
      return NTP_MOCK.mode6_response(cfg, sent, false, data)
    end
    return NTP_MOCK.mode6_response(cfg, sent, true, nil)
  end
  if mode == 7 then
    if cfg.monlist or cfg.restrict or cfg.traps or cfg.authinfo then
      return NTP_MOCK.mode7_response(cfg, sent)
    end
    return NTP_MOCK.mode7_header(cfg, sent, 1, 0, 0)
  end
  return ""
end


SIP_MOCK = {}

SIP_CONN_SEQ = 0

SIP_MOCK.CFG = {
  ["sip"] = {
    server = "Asterisk PBX 18.10.0",
    realm = "asterisk",
    nonce = "1a2b3c4d5e6f7081",
    contact_ip = "192.168.1.100",
    allow = "INVITE, ACK, CANCEL, OPTIONS, BYE, SUBSCRIBE, NOTIFY, INFO, MESSAGE",
    supported = "replaces, timer",
    rate_after = nil,
    per_conn_200 = nil,
    blind_bye = true,
  },
  ["sip-secure"] = {
    server = "Kamailio 5.7.2 (x86_64/linux)",
    realm = "corp.sip",
    nonce = "77aa88bb22cc44dd",
    contact_ip = "203.0.113.10",
    allow = "INVITE, ACK, CANCEL, OPTIONS, BYE, SUBSCRIBE, NOTIFY",
    supported = "timer, path, replaces",
    rate_after = 3,
    per_conn_200 = 3,
    blind_bye = false,
  },
}

SIP_CALLS = {}

SIP_MOCK.PRESENCE_BODY = '<?xml version="1.0" encoding="UTF-8"?><presence entity="sip:100@pbx.example"><tuple id="1"><status><basic>open</basic></status></tuple></presence>'

SIP_MOCK.SDP_BODY = "v=0\r\no=asterisk 1 2 IN IP4 192.168.1.100\r\ns=-\r\nc=IN IP4 192.168.1.100\r\nt=0 0\r\nm=audio 18044 RTP/AVP 0 8 18 3 9 96\r\na=rtpmap:96 opus/48000/2\r\na=sendrecv\r\n"

function SIP_MOCK.response(cfg, status, reason, extra, body)
  extra = extra or {}
  local lines = { "SIP/2.0 " .. tostring(status) .. " " .. reason }
  lines[#lines + 1] = "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bKmock;received=192.0.2.10"
  lines[#lines + 1] = "From: <sip:nse-audit@nse-audit.invalid>;tag=nsetag"
  lines[#lines + 1] = "To: " .. (extra.to or "<sip:100@pbx.example>")
  lines[#lines + 1] = "Call-ID: " .. (extra.callid or "mockcall")
  lines[#lines + 1] = "CSeq: " .. (extra.cseq or "1 OPTIONS")
  lines[#lines + 1] = "Contact: <sip:pbx@" .. cfg.contact_ip .. ":5060>"
  if extra.server then
    lines[#lines + 1] = "Server: " .. cfg.server
  end
  for _, h in ipairs(extra.headers or {}) do
    lines[#lines + 1] = h
  end
  if extra.auth then
    lines[#lines + 1] = extra.auth
  end
  lines[#lines + 1] = "Content-Length: " .. tostring(body and #body or 0)
  lines[#lines + 1] = ""
  lines[#lines + 1] = body or ""
  lines[#lines + 1] = ""
  return table.concat(lines, "\r\n")
end

function SIP_MOCK.sip_reply(scenario, sent, sock)
  local cfg = SIP_MOCK.CFG[scenario]
  if cfg == nil then
    return ""
  end
  local method = string.match(sent, "^([%a]+)")
  local callid = string.match(sent, "Call%-ID:%s*(%S+)") or "mockcall"
  local cseq = string.match(sent, "CSeq:%s*(%d+%s+[%a]+)") or ("1 " .. (method or "OPTIONS"))
  local to_hdr = string.match(sent, "To:%s*([^\r\n]+)") or "<sip:100@pbx.example>"
  local to_user = string.match(to_hdr, "sip:([^@;>]+)") or "100"
  local from_user = string.match(sent, "From:%s*<sip:([^@;>]+)") or "nse-audit"
  local has_auth = string.find(sent, "Authorization:%s*Digest") ~= nil
  local digest_user = string.match(sent, 'username="([^"]*)"')
  if method == "ACK" then
    return ""
  end
  if method == "OPTIONS" then
    local allowed200 = true
    if cfg.rate_after ~= nil and (sock._sip_opts or 0) >= cfg.rate_after then
      allowed200 = false
    end
    if cfg.per_conn_200 ~= nil and (SIP_CONN_SEQ or 0) > cfg.per_conn_200 then
      allowed200 = false
    end
    sock._sip_opts = (sock._sip_opts or 0) + 1
    if allowed200 then
      return SIP_MOCK.response(cfg, 200, "OK", {
        callid = callid, cseq = cseq, server = true,
        headers = {
          "Allow: " .. cfg.allow,
          "Supported: " .. cfg.supported,
          "Accept: application/sdp, application/pidf+xml, application/dialog-info+xml",
        },
      })
    end
    return SIP_MOCK.response(cfg, 503, "Service Unavailable", { callid = callid, cseq = cseq })
  end
  if method == "REGISTER" then
    local extnum = tonumber(to_user)
    local exists = extnum ~= nil and ((extnum >= 100 and extnum <= 110) or (extnum >= 1000 and extnum <= 1010))
    if scenario == "sip" then
      if not has_auth then
        if not exists then
          return SIP_MOCK.response(cfg, 404, "Not Found", { callid = callid, cseq = cseq, to = to_hdr })
        end
        return SIP_MOCK.response(cfg, 200, "OK", {
          callid = callid, cseq = cseq, to = to_hdr .. ";tag=pbx100",
          headers = { "Expires: 300" },
        })
      end
      local creds_ok = (digest_user == "100" or digest_user == "admin")
      if creds_ok then
        return SIP_MOCK.response(cfg, 200, "OK", {
          callid = callid, cseq = cseq, to = to_hdr .. ";tag=pbx100",
          headers = { "Expires: 300" },
        })
      end
      return SIP_MOCK.response(cfg, 403, "Forbidden", { callid = callid, cseq = cseq, to = to_hdr })
    end
    if not has_auth then
      return SIP_MOCK.response(cfg, 401, "Unauthorized", {
        callid = callid, cseq = cseq, to = to_hdr,
        auth = 'WWW-Authenticate: Digest realm="' .. cfg.realm .. '", nonce="' .. cfg.nonce .. '", algorithm=MD5, qop="auth"',
      })
    end
    return SIP_MOCK.response(cfg, 403, "Forbidden", { callid = callid, cseq = cseq, to = to_hdr })
  end
  if method == "INVITE" then
    if scenario == "sip" then
      SIP_CALLS[callid] = true
      return SIP_MOCK.response(cfg, 200, "OK", {
        callid = callid, cseq = cseq, to = to_hdr .. ";tag=pbxring1",
        headers = {
          "Allow: " .. cfg.allow,
          "Supported: " .. cfg.supported,
          "Content-Type: application/sdp",
          "Session-Expires: 1800;refresher=uas",
        },
      }, SIP_MOCK.SDP_BODY)
    end
    return SIP_MOCK.response(cfg, 407, "Proxy Authentication Required", {
      callid = callid, cseq = cseq, to = to_hdr,
      auth = 'Proxy-Authenticate: Digest realm="' .. cfg.realm .. '", nonce="' .. cfg.nonce .. '", algorithm=MD5, qop="auth"',
    })
  end
  if method == "BYE" then
    if SIP_CALLS[callid] then
      return SIP_MOCK.response(cfg, 200, "OK", { callid = callid, cseq = cseq, to = to_hdr .. ";tag=pbxring1" })
    end
    if cfg.blind_bye then
      return SIP_MOCK.response(cfg, 200, "OK", { callid = callid, cseq = cseq, to = to_hdr })
    end
    return SIP_MOCK.response(cfg, 481, "Call/Transaction Does Not Exist", { callid = callid, cseq = cseq, to = to_hdr })
  end
  if method == "MESSAGE" then
    if scenario == "sip" then
      return SIP_MOCK.response(cfg, 200, "OK", { callid = callid, cseq = cseq, to = to_hdr })
    end
    return SIP_MOCK.response(cfg, 403, "Forbidden", { callid = callid, cseq = cseq, to = to_hdr })
  end
  if method == "SUBSCRIBE" then
    if scenario == "sip" then
      return SIP_MOCK.response(cfg, 200, "OK", {
        callid = callid, cseq = cseq, to = to_hdr .. ";tag=pbxpres1",
        headers = { "Expires: 300", "Content-Type: application/pidf+xml" },
      }, SIP_MOCK.PRESENCE_BODY)
    end
    return SIP_MOCK.response(cfg, 401, "Unauthorized", {
      callid = callid, cseq = cseq, to = to_hdr,
      auth = 'WWW-Authenticate: Digest realm="' .. cfg.realm .. '", nonce="' .. cfg.nonce .. '", algorithm=MD5, qop="auth"',
    })
  end
  if method == "CANCEL" then
    return SIP_MOCK.response(cfg, 200, "OK", { callid = callid, cseq = cseq, to = to_hdr })
  end
  return SIP_MOCK.response(cfg, 501, "Not Implemented", { callid = callid, cseq = cseq, to = to_hdr })
end


NFS_MOCK = {}

NFS_M_CFG = {
  ["nfs"] = {
    dump = {
      { 100000, 2, 6, 111 }, { 100003, 2, 6, 2049 }, { 100003, 3, 6, 2049 }, { 100003, 3, 6, 4000 },
      { 100005, 1, 6, 20048 }, { 100005, 3, 6, 20048 }, { 100021, 4, 6, 4045 }, { 100024, 1, 6, 662 },
      { 100011, 1, 6, 875 }, { 100002, 2, 6, 938 }, { 100007, 2, 6, 944 }, { 100012, 1, 6, 780 },
    },
    exports = {
      { dir = "/export/public", groups = {}, opts = "rw,insecure,sec=sys" },
      { dir = "/export/data", groups = { "*.corp.example.com" }, opts = "rw,no_root_squash,sec=sys" },
      { dir = "/export/backup", groups = { "@admins" }, opts = "ro,sec=sys" },
      { dir = "/export/home", groups = {}, opts = "rw,insecure,root_squash" },
    },
    active_mounts = { { "10.10.10.66", "/export/public" }, { "10.10.10.66", "/export/data" } },
    mnt_ok = { ["/export/public"] = true, ["/export/data"] = true, ["/export/backup"] = true, ["/export/home"] = true },
    mnt_tag = { ["/export/public"] = "PUB", ["/export/data"] = "DATA", ["/export/backup"] = "BKUP", ["/export/home"] = "HOME" },
    mnt_flavors = { 1 },
    fh_entropy_secure = false,
    attrs = {
      ["FH:PUB"] = { ftype = 2, mode = 493, uid = 0, gid = 0, size = 4096 },
      ["FH:DATA"] = { ftype = 2, mode = 511, uid = 0, gid = 0, size = 4096 },
      ["FH:BKUP"] = { ftype = 2, mode = 504, uid = 0, gid = 0, size = 4096 },
      ["FH:HOME"] = { ftype = 2, mode = 511, uid = 0, gid = 0, size = 4096 },
      ["FH:PUB:readme.txt"] = { ftype = 1, mode = 420, uid = 0, gid = 0, size = 512 },
      ["FH:DATA:shadow"] = { ftype = 5, mode = 420, uid = 0, gid = 0, size = 96 },
    },
    lookup = { ["FH:PUB"] = { ["readme.txt"] = "FH:PUB:readme.txt" }, ["FH:DATA"] = { ["shadow"] = "FH:DATA:shadow" } },
    readlink = { ["FH:DATA:shadow"] = "../../etc/shadow" },
    no_root_squash = { ["FH:DATA"] = true },
    rusers = {
      { uid = 0, name = "root", host = "nfs01.corp.example.com", tty = "pts/0" },
      { uid = 1521, name = "oracle", host = "db01.corp.example.com", tty = "pts/1" },
      { uid = 9001, name = "svc-backup", host = "nfs01.corp.example.com", tty = "" },
    },
    rquota = { status = 1, bhard = 0, bsoft = 976562, cur = 1000000, fhard = 0, fsoft = 0, fcur = 0, btime = 0, ftime = 0 },
    ypbind = { bound = true, addr = "10.10.10.5", port = 834 },
    statd = { stat = 1, state = 7 },
    spray_counter = 6,
    nlm_locked = false,
  },
  ["nfs-secure"] = {
    dump = {
      { 100000, 2, 6, 111 }, { 100003, 3, 6, 2049 }, { 100003, 4, 6, 2049 },
      { 100005, 3, 6, 20048 }, { 100021, 4, 6, 4045 }, { 100011, 1, 6, 875 }, { 100002, 2, 6, 938 },
    },
    exports = {
      { dir = "/export/public", groups = {}, opts = "ro,root_squash,sec=sys" },
      { dir = "/export/data", groups = { "*.corp.example.com" }, opts = "rw,root_squash,sec=krb5p" },
      { dir = "/export/backup", groups = { "@admins" }, opts = "ro,sec=krb5p" },
    },
    active_mounts = {},
    mnt_ok = { ["/export/public"] = true },
    mnt_tag = { ["/export/public"] = "PUB", ["/export/data"] = "DATA", ["/export/backup"] = "BKUP" },
    mnt_flavors = { 1 },
    fh_entropy_secure = true,
    attrs = {
      ["FH:PUB"] = { ftype = 2, mode = 493, uid = 0, gid = 0, size = 4096 },
      ["FH:DATA"] = { ftype = 2, mode = 488, uid = 0, gid = 0, size = 4096 },
      ["FH:BKUP"] = { ftype = 2, mode = 504, uid = 0, gid = 0, size = 4096 },
      ["FH:PUB:readme.txt"] = { ftype = 1, mode = 416, uid = 0, gid = 0, size = 512 },
    },
    lookup = { ["FH:PUB"] = { ["readme.txt"] = "FH:PUB:readme.txt" } },
    readlink = {},
    no_root_squash = {},
    rusers = {},
    rquota = { status = 2, bhard = 0, bsoft = 0, cur = 0, fhard = 0, fsoft = 0, fcur = 0, btime = 0, ftime = 0 },
    ypbind = { bound = false },
    statd = nil,
    spray_counter = nil,
    nlm_locked = false,
  },
}

function NFS_MOCK.n_u32(buf, off)
  local a, b, c, d = string.byte(buf, off, off + 3)
  if a == nil then
    return nil
  end
  return a * 16777216 + b * 65536 + c * 256 + d
end

function NFS_MOCK.n_u32_at(buf, off)
  local v = NFS_MOCK.n_u32(buf, off)
  if v == nil then
    return nil, off
  end
  return v, off + 4
end

function NFS_MOCK.w_u32(v)
  return string.char(math.floor(v / 16777216) % 256, math.floor(v / 65536) % 256, math.floor(v / 256) % 256, v % 256)
end

function NFS_MOCK.w_str(s)
  s = s or ""
  local pad = (4 - (#s % 4)) % 4
  return NFS_MOCK.w_u32(#s) .. s .. string.rep("\0", pad)
end

function NFS_MOCK.rm(payload)
  return NFS_MOCK.w_u32(2147483648 + #payload) .. payload
end

function NFS_MOCK.reply_ok(xid, payload)
  return NFS_MOCK.rm(NFS_MOCK.w_u32(xid) .. NFS_MOCK.w_u32(1) .. NFS_MOCK.w_u32(0) ..
    NFS_MOCK.w_u32(0) .. NFS_MOCK.w_u32(0) .. NFS_MOCK.w_u32(0) .. (payload or ""))
end

function NFS_MOCK.reply_accept_err(xid, stat)
  return NFS_MOCK.rm(NFS_MOCK.w_u32(xid) .. NFS_MOCK.w_u32(1) .. NFS_MOCK.w_u32(0) ..
    NFS_MOCK.w_u32(0) .. NFS_MOCK.w_u32(0) .. NFS_MOCK.w_u32(stat))
end

function NFS_MOCK.reply_auth_reject(xid, astat)
  return NFS_MOCK.rm(NFS_MOCK.w_u32(xid) .. NFS_MOCK.w_u32(1) .. NFS_MOCK.w_u32(1) .. NFS_MOCK.w_u32(1) ..
    NFS_MOCK.w_u32(astat))
end

function NFS_MOCK.parse_call(buf)
  local xid = NFS_MOCK.n_u32(buf, 1)
  local mtype = NFS_MOCK.n_u32(buf, 5)
  if xid == nil or mtype ~= 0 then
    return nil
  end
  local rpcvers, o1 = NFS_MOCK.n_u32_at(buf, 9)
  local prog, o2 = NFS_MOCK.n_u32_at(buf, o1)
  local vers, o3 = NFS_MOCK.n_u32_at(buf, o2)
  local proc, o4 = NFS_MOCK.n_u32_at(buf, o3)
  local cred_flavor, o5 = NFS_MOCK.n_u32_at(buf, o4)
  local cred_len, o6 = NFS_MOCK.n_u32_at(buf, o5)
  if rpcvers == nil or cred_len == nil then
    return nil
  end
  local cred_body = string.sub(buf, o6, o6 + cred_len - 1)
  local o7 = o6 + cred_len + ((4 - (cred_len % 4)) % 4)
  local verf_flavor, o8 = NFS_MOCK.n_u32_at(buf, o7)
  local verf_len, o9 = NFS_MOCK.n_u32_at(buf, o8)
  if verf_len == nil then
    return nil
  end
  local args_off = o9 + verf_len + ((4 - (verf_len % 4)) % 4)
  local uid = nil
  if cred_flavor == 1 and cred_len >= 12 then
    local mlen = NFS_MOCK.n_u32(cred_body, 5)
    local m = mlen or 0
    local mpad = (4 - (m % 4)) % 4
    uid = NFS_MOCK.n_u32(cred_body, 5 + 4 + m + mpad)
  end
  return { xid = xid, rpcvers = rpcvers, prog = prog, vers = vers, proc = proc,
    cred_flavor = cred_flavor, uid = uid, args_off = args_off }
end

function NFS_MOCK.fh_key(fh)
  return string.gsub(fh or "", "%z", "")
end

function NFS_MOCK.fattr3(cfg, fh)
  local a = cfg.attrs[NFS_MOCK.resolve_key(cfg, fh)]
  if a == nil then
    return nil
  end
  return NFS_MOCK.w_u32(a.ftype) .. NFS_MOCK.w_u32(a.mode) .. NFS_MOCK.w_u32(1) ..
    NFS_MOCK.w_u32(a.uid) .. NFS_MOCK.w_u32(a.gid) ..
    NFS_MOCK.w_u32(0) .. NFS_MOCK.w_u32(a.size or 0) ..
    NFS_MOCK.w_u32(0) .. NFS_MOCK.w_u32(a.size or 0) ..
    NFS_MOCK.w_u32(0) .. NFS_MOCK.w_u32(0) ..
    NFS_MOCK.w_u32(0) .. NFS_MOCK.w_u32(1) .. NFS_MOCK.w_u32(0) .. NFS_MOCK.w_u32(1) ..
    NFS_MOCK.w_u32(1700000000) .. NFS_MOCK.w_u32(0) ..
    NFS_MOCK.w_u32(1700000000) .. NFS_MOCK.w_u32(0) ..
    NFS_MOCK.w_u32(1700000000) .. NFS_MOCK.w_u32(0)
end

function NFS_MOCK.fhandle_for(cfg, tag, salt)
  cfg._fh_map = cfg._fh_map or {}
  local seed = salt or 1
  for i = 1, #(tag or "") do
    seed = seed + string.byte(tag, i) * i * 131
  end
  local key = "FH:" .. (tag or "?")
  if cfg.fh_entropy_secure then
    local out = { "FH:" }
    local state = seed % 2147483647
    for _ = 1, 28 do
      state = (state * 1103515245 + 12345) % 2147483648
      out[#out + 1] = string.char(33 + (state % 90))
    end
    local handle = table.concat(out)
    cfg._fh_map[handle] = key
    return handle
  end
  local padded = key
  while #padded < 32 do
    padded = padded .. "\0"
  end
  cfg._fh_map[padded] = key
  return padded
end

function NFS_MOCK.resolve_key(cfg, fh)
  if cfg._fh_map and cfg._fh_map[fh] then
    return cfg._fh_map[fh]
  end
  return NFS_MOCK.fh_key(fh)
end

function NFS_MOCK.read_fh(buf, off)
  local n = NFS_MOCK.n_u32(buf, off)
  if n == nil or n > 128 then
    return nil, off
  end
  local fh = string.sub(buf, off + 4, off + 4 + n - 1)
  local pad = (4 - (n % 4)) % 4
  return fh, off + 4 + n + pad
end

NFS_MOCK.read_str = NFS_MOCK.read_fh

function NFS_MOCK.cfg_of(scenario)
  return NFS_M_CFG[scenario] or NFS_M_CFG["nfs-secure"]
end

function NFS_MOCK.pmap_reply(cfg, call)
  local payload = ""
  for _, t in ipairs(cfg.dump) do
    payload = payload .. NFS_MOCK.w_u32(t[1]) .. NFS_MOCK.w_u32(t[2]) .. NFS_MOCK.w_u32(t[3]) .. NFS_MOCK.w_u32(t[4])
  end
  payload = payload .. NFS_MOCK.w_u32(0)
  return NFS_MOCK.reply_ok(call.xid, payload)
end

function NFS_MOCK.pmap_getport(cfg, call, buf)
  local prog = NFS_MOCK.n_u32(buf, call.args_off)
  local vers = NFS_MOCK.n_u32(buf, call.args_off + 4)
  local prot = NFS_MOCK.n_u32(buf, call.args_off + 8)
  for _, t in ipairs(cfg.dump) do
    if t[1] == prog and t[2] == vers and (prot == nil or prot == 0 or t[3] == prot) then
      return NFS_MOCK.reply_ok(call.xid, NFS_MOCK.w_u32(t[4]))
    end
  end
  return NFS_MOCK.reply_ok(call.xid, NFS_MOCK.w_u32(0))
end

function NFS_MOCK.mount_export_reply(cfg, call)
  local payload = ""
  for _, e in ipairs(cfg.exports) do
    payload = payload .. NFS_MOCK.w_u32(1) .. NFS_MOCK.w_str(e.dir)
    for _, g in ipairs(e.groups) do
      payload = payload .. NFS_MOCK.w_u32(1) .. NFS_MOCK.w_str(g)
    end
    payload = payload .. NFS_MOCK.w_u32(0)
  end
  payload = payload .. NFS_MOCK.w_u32(0)
  return NFS_MOCK.reply_ok(call.xid, payload)
end

function NFS_MOCK.mount_dump_reply(cfg, call)
  local payload = ""
  for _, m in ipairs(cfg.active_mounts) do
    payload = payload .. NFS_MOCK.w_u32(1) .. NFS_MOCK.w_str(m[1]) .. NFS_MOCK.w_str(m[2])
  end
  payload = payload .. NFS_MOCK.w_u32(0)
  return NFS_MOCK.reply_ok(call.xid, payload)
end

function NFS_MOCK.mount_mnt_reply(cfg, call, buf)
  local dir = NFS_MOCK.read_str(buf, call.args_off)
  if cfg.mnt_ok[dir] then
    local tag = (cfg.mnt_tag and cfg.mnt_tag[dir]) or string.gsub(dir, "/export/", "")
    local fh = NFS_MOCK.fhandle_for(cfg, tag, 7)
    local flavors = cfg.mnt_flavors or { 1 }
    local fbuf = NFS_MOCK.w_u32(#flavors)
    for _, f in ipairs(flavors) do
      fbuf = fbuf .. NFS_MOCK.w_u32(f)
    end
    return NFS_MOCK.reply_ok(call.xid, NFS_MOCK.w_u32(0) .. NFS_MOCK.w_str(fh) .. fbuf)
  end
  return NFS_MOCK.reply_ok(call.xid, NFS_MOCK.w_u32(13))
end

function NFS_MOCK.nfs_reply(cfg, call, buf, port_4000)
  if call.proc == 0 then
    return NFS_MOCK.reply_ok(call.xid, "")
  end
  if call.proc == 1 then
    local fh = NFS_MOCK.read_fh(buf, call.args_off)
    local attr = NFS_MOCK.fattr3(cfg, fh)
    if attr == nil then
      return NFS_MOCK.reply_ok(call.xid, NFS_MOCK.w_u32(10008))
    end
    return NFS_MOCK.reply_ok(call.xid, NFS_MOCK.w_u32(0) .. attr)
  end
  if call.proc == 3 then
    local fh, o2 = NFS_MOCK.read_fh(buf, call.args_off)
    local name = NFS_MOCK.read_str(buf, o2)
    local lkey = NFS_MOCK.resolve_key(cfg, fh)
    local child = cfg.lookup[lkey] and cfg.lookup[lkey][name] or nil
    if child == nil then
      return NFS_MOCK.reply_ok(call.xid, NFS_MOCK.w_u32(2))
    end
    local attr = NFS_MOCK.fattr3(cfg, child)
    if attr ~= nil then
      return NFS_MOCK.reply_ok(call.xid, NFS_MOCK.w_u32(0) .. NFS_MOCK.w_str(child) .. NFS_MOCK.w_u32(1) .. attr)
    end
    return NFS_MOCK.reply_ok(call.xid, NFS_MOCK.w_u32(0) .. NFS_MOCK.w_str(child) .. NFS_MOCK.w_u32(0))
  end
  if call.proc == 5 then
    local fh = NFS_MOCK.read_fh(buf, call.args_off)
    if cfg.readlink[NFS_MOCK.resolve_key(cfg, fh)] == nil then
      return NFS_MOCK.reply_ok(call.xid, NFS_MOCK.w_u32(22))
    end
    return NFS_MOCK.reply_ok(call.xid, NFS_MOCK.w_u32(0) .. NFS_MOCK.w_str(cfg.readlink[NFS_MOCK.resolve_key(cfg, fh)]))
  end
  if call.proc == 14 then
    local fh = NFS_MOCK.read_fh(buf, call.args_off)
    if NFS_MOCK.fattr3(cfg, fh) == nil then
      return NFS_MOCK.reply_ok(call.xid, NFS_MOCK.w_u32(10008))
    end
    return NFS_MOCK.reply_ok(call.xid, NFS_MOCK.w_u32(0) ..
      NFS_MOCK.w_u32(32768) .. NFS_MOCK.w_u32(32768) .. NFS_MOCK.w_u32(8192) ..
      NFS_MOCK.w_u32(32768) .. NFS_MOCK.w_u32(32768) .. NFS_MOCK.w_u32(8192) ..
      NFS_MOCK.w_u32(32768) .. NFS_MOCK.w_u32(32768) .. NFS_MOCK.w_u32(8192) ..
      NFS_MOCK.w_u32(1) .. NFS_MOCK.w_u32(0) .. NFS_MOCK.w_u32(1048576))
  end
  if call.proc == 23 then
    local fh = NFS_MOCK.read_fh(buf, call.args_off)
    local uid = call.uid
    local rights = 0
    if uid == 0 and cfg.no_root_squash[NFS_MOCK.resolve_key(cfg, fh)] then
      rights = 63
    elseif uid ~= nil and uid ~= 0 then
      rights = 33
    end
    return NFS_MOCK.reply_ok(call.xid, NFS_MOCK.w_u32(0) .. NFS_MOCK.w_u32(0) .. NFS_MOCK.w_u32(rights))
  end
  return NFS_MOCK.reply_accept_err(call.xid, 3)
end

function NFS_MOCK.nlm_reply(cfg, call, buf)
  if call.proc == 0 then
    return NFS_MOCK.reply_ok(call.xid, "")
  end
  if call.proc == 1 then
    return NFS_MOCK.reply_ok(call.xid, NFS_MOCK.w_u32(cfg.nlm_locked and 1 or 0) ..
      NFS_MOCK.w_u32(0) .. NFS_MOCK.w_u32(0) .. NFS_MOCK.w_str("nfs01") .. NFS_MOCK.w_u32(1234) ..
      NFS_MOCK.w_str("TESTFH"))
  end
  return NFS_MOCK.reply_accept_err(call.xid, 3)
end

function NFS_MOCK.rusers_reply(cfg, call)
  local payload = NFS_MOCK.w_u32(#cfg.rusers)
  for _, u in ipairs(cfg.rusers) do
    payload = payload .. NFS_MOCK.w_u32(u.uid) .. NFS_MOCK.w_str(u.name) .. NFS_MOCK.w_str(u.host) ..
      NFS_MOCK.w_str(u.tty) .. NFS_MOCK.w_u32(1700000000)
  end
  return NFS_MOCK.reply_ok(call.xid, payload)
end

function NFS_MOCK.rquota_reply(cfg, call, buf)
  local q = cfg.rquota
  if q.status ~= 1 then
    return NFS_MOCK.reply_ok(call.xid, NFS_MOCK.w_u32(q.status))
  end
  return NFS_MOCK.reply_ok(call.xid, NFS_MOCK.w_u32(1) ..
    NFS_MOCK.w_u32(q.bhard) .. NFS_MOCK.w_u32(q.bsoft) .. NFS_MOCK.w_u32(q.cur) ..
    NFS_MOCK.w_u32(q.fhard) .. NFS_MOCK.w_u32(q.fsoft) .. NFS_MOCK.w_u32(q.fcur) ..
    NFS_MOCK.w_u32(q.btime) .. NFS_MOCK.w_u32(q.ftime))
end

function NFS_MOCK.ypbind_reply(cfg, call, buf)
  if not cfg.ypbind.bound then
    return NFS_MOCK.reply_ok(call.xid, NFS_MOCK.w_u32(0))
  end
  local ip = {}
  for part in string.gmatch(cfg.ypbind.addr, "%d+") do
    ip[#ip + 1] = string.char(tonumber(part) or 0)
  end
  local addr = table.concat(ip)
  return NFS_MOCK.reply_ok(call.xid, NFS_MOCK.w_u32(1) ..
    NFS_MOCK.w_str(addr) .. NFS_MOCK.w_u32(0) .. NFS_MOCK.w_u32(cfg.ypbind.port))
end

function NFS_MOCK.statd_reply(cfg, call, buf)
  if cfg.statd == nil then
    return NFS_MOCK.reply_auth_reject(call.xid, 1)
  end
  return NFS_MOCK.reply_ok(call.xid, NFS_MOCK.w_u32(cfg.statd.stat) .. NFS_MOCK.w_u32(cfg.statd.state))
end

function NFS_MOCK.spray_reply(cfg, call)
  if call.proc == 1 then
    return NFS_MOCK.reply_ok(call.xid, "")
  end
  if call.proc == 2 then
    return NFS_MOCK.reply_ok(call.xid, NFS_MOCK.w_u32(cfg.spray_counter or 0) .. NFS_MOCK.w_u32(12))
  end
  return NFS_MOCK.reply_accept_err(call.xid, 3)
end

function NFS_MOCK.rpc_send(scenario, sent, self)
  local cfg = NFS_MOCK.cfg_of(scenario)
  local body = NFS_MOCK.n_u32(sent, 1)
  local last = body ~= nil and body >= 2147483648
  if body == nil then
    return ""
  end
  local blen = body - (last and 2147483648 or 0)
  local buf = string.sub(sent, 5, 5 + blen - 1)
  local call = NFS_MOCK.parse_call(buf)
  if call == nil then
    return ""
  end
  local port = self.connect_port
  if port == 111 then
    if call.proc == 3 then
      return NFS_MOCK.pmap_getport(cfg, call, buf)
    elseif call.proc == 4 then
      return NFS_MOCK.pmap_reply(cfg, call)
    end
    return NFS_MOCK.reply_accept_err(call.xid, 3)
  end
  if port == 2049 or port == 4000 then
    if call.prog ~= 100003 then
      return NFS_MOCK.reply_accept_err(call.xid, 1)
    end
    return NFS_MOCK.nfs_reply(cfg, call, buf, port == 4000)
  end
  if port == 20048 or port == 42471 then
    if call.prog ~= 100005 then
      return NFS_MOCK.reply_accept_err(call.xid, 1)
    end
    if call.proc == 0 then
      return NFS_MOCK.reply_ok(call.xid, "")
    end
    if call.proc == 1 then
      return NFS_MOCK.mount_mnt_reply(cfg, call, buf)
    end
    if call.proc == 2 then
      return NFS_MOCK.mount_dump_reply(cfg, call)
    end
    if call.proc == 5 then
      return NFS_MOCK.mount_export_reply(cfg, call)
    end
    return NFS_MOCK.reply_accept_err(call.xid, 3)
  end
  if port == 4045 then
    if call.prog ~= 100021 then
      return NFS_MOCK.reply_accept_err(call.xid, 1)
    end
    return NFS_MOCK.nlm_reply(cfg, call, buf)
  end
  if port == 938 then
    if call.prog ~= 100002 then
      return NFS_MOCK.reply_accept_err(call.xid, 1)
    end
    return NFS_MOCK.rusers_reply(cfg, call)
  end
  if port == 875 then
    if call.prog ~= 100011 then
      return NFS_MOCK.reply_accept_err(call.xid, 1)
    end
    return NFS_MOCK.rquota_reply(cfg, call, buf)
  end
  if port == 944 then
    if call.prog ~= 100007 then
      return NFS_MOCK.reply_accept_err(call.xid, 1)
    end
    return NFS_MOCK.ypbind_reply(cfg, call, buf)
  end
  if port == 662 then
    if call.prog ~= 100024 then
      return NFS_MOCK.reply_accept_err(call.xid, 1)
    end
    return NFS_MOCK.statd_reply(cfg, call, buf)
  end
  if port == 780 then
    if call.prog ~= 100012 then
      return NFS_MOCK.reply_accept_err(call.xid, 1)
    end
    return NFS_MOCK.spray_reply(cfg, call)
  end
  return NFS_MOCK.reply_accept_err(call.xid, 1)
end


ICS_MOCK = {}

ICS_M_CFG = {
  ["ics"] = {
    modbus_units = { [1] = true, [2] = true, [17] = true },
    modbus_device_id = { vendor = "Schneider Electric", product = "BMXP342020", revision = "2.80" },
    modbus_reads_ok = true,
    modbus_coils = { true, false, true, true, false, false, true, true },
    modbus_registers = { 1234, 5678, 0, 4321 },
    modbus_write_open = true,
    bacnet_i_am = { instance = 56832, vendor = 5 },
    bacnet_object_name = "AHU-01-Master-Controller",
    dnp3_link_ok = true,
    eip_identity = { vendor = 1, product_code = 68, revision = "28.11", product_name = "1769-L16ER/B NET LINX" },
    fins_read_ok = true,
    fins_words = { 4660, 22136 },
    fox_ok = true,
    fox_version = 35,
    fox_host = "niagara-ax-supervisor",
    fox_brand = "tridium",
    hart_ok = true,
    hart_device_type = 782,
    hart_uid = "a1:b2:c3:d4:e5",
    iec104_ok = true,
    melsec_ok = true,
    melsec_words = { 30583, 12345 },
    profinet_ok = true,
    profinet_name = "pn-io-station-01",
    s7_ok = true,
    s7_pdu = 480,
  },
  ["ics-secure"] = {
    modbus_units = { [1] = true },
    modbus_device_id = { vendor = "Schneider Electric", product = "BMXP342020", revision = "2.80" },
    modbus_reads_ok = false,
    modbus_write_open = false,
    bacnet_i_am = nil,
    bacnet_object_name = nil,
    dnp3_link_ok = false,
    eip_identity = nil,
    fins_read_ok = false,
    fox_ok = false,
    hart_ok = false,
    iec104_ok = false,
    melsec_ok = false,
    profinet_ok = false,
    s7_ok = false,
  },
}

function ICS_MOCK.cfg_of(scenario)
  return ICS_M_CFG[scenario] or ICS_M_CFG["ics-secure"]
end

function ICS_MOCK.w_u16(v)
  return string.char(math.floor(v / 256) % 256, v % 256)
end

function ICS_MOCK.w_u32(v)
  return string.char(math.floor(v / 16777216) % 256, math.floor(v / 65536) % 256,
    math.floor(v / 256) % 256, v % 256)
end

function ICS_MOCK.modbus_reply(cfg, sent)
  local frame = ICS_MB.parse_mbap(sent)
  if frame == nil then
    return ""
  end
  if not cfg.modbus_units[frame.unit] then
    return ICS_MB.mbap(frame.tid, frame.unit, string.char(0x80 + (string.byte(frame.pdu, 1) or 0), 11))
  end
  local fc = string.byte(frame.pdu, 1) or 0
  if fc == ICS_T.MODBUS_FC_READ_DEVICE_ID then
    local d = cfg.modbus_device_id
    if d == nil then
      return ICS_MB.mbap(frame.tid, frame.unit, string.char(0x80 + fc, 1))
    end
    local objs = "\x00" .. ICS_MOCK.w_u16(3) .. "\x83"
      .. "\x00\x04" .. "Schneider" .. "\x01\x08" .. "BMXP342020" .. "\x02\x04" .. "2.80"
    if cfg.modbus_units[1] == nil or d.product ~= "BMXP342020" then
      objs = "\x00\x00\x01\x81\x00\x00\x01\x00\x04" .. "NONE"
    end
    return ICS_MB.mbap(frame.tid, frame.unit, string.char(fc, 0x0e, 0x01, 0x81, 0x00, 0x00, 0x03) ..
      "\x00\x09" .. "Schneider" .. "\x01\x0a" .. "BMXP342020" .. "\x02\x04" .. "2.80")
  end
  if fc == ICS_T.MODBUS_FC_READ_COILS then
    if not cfg.modbus_reads_ok then
      return ICS_MB.mbap(frame.tid, frame.unit, string.char(0x80 + fc, 1))
    end
    local byte = 0
    for i, v in ipairs(cfg.modbus_coils or {}) do
      if v then
        byte = byte + 2 ^ (i - 1)
      end
    end
    return ICS_MB.mbap(frame.tid, frame.unit, string.char(fc, 1) .. string.char(byte))
  end
  if fc == ICS_T.MODBUS_FC_READ_HOLDING then
    if not cfg.modbus_reads_ok then
      return ICS_MB.mbap(frame.tid, frame.unit, string.char(0x80 + fc, 1))
    end
    local regs = cfg.modbus_registers or {}
    local out = ""
    for _, r in ipairs(regs) do
      out = out .. ICS_MOCK.w_u16(r)
    end
    return ICS_MB.mbap(frame.tid, frame.unit, string.char(fc, #regs * 2) .. out)
  end
  if fc == ICS_T.MODBUS_FC_WRITE_COIL then
    if not cfg.modbus_write_open then
      return ICS_MB.mbap(frame.tid, frame.unit, string.char(0x80 + fc, 1))
    end
    return ICS_MB.mbap(frame.tid, frame.unit, string.char(0x80 + fc, 2))
  end
  return ICS_MB.mbap(frame.tid, frame.unit, string.char(0x80 + fc, 1))
end

function ICS_MOCK.bacnet_reply(cfg, sent)
  if string.byte(sent, 2) == ICS_T.BACNET_BVLC_ORIGINAL_BROADCAST then
    if cfg.bacnet_i_am == nil then
      return ""
    end
    local iam = ICS_T.BACNET_NPDU .. "\x10\x00\xc4\x00\xde\x00\x05\x22\x00\x05"
    return "\x81\x0b" .. ICS_MOCK.w_u16(#iam) .. iam
  end
  if string.byte(sent, 2) == ICS_T.BACNET_BVLC_ORIGINAL_UNICAST then
    if cfg.bacnet_object_name == nil then
      local err = ICS_T.BACNET_NPDU .. "\x50\x01\x0c\x81\x00\x91\x02"
      return "\x81\x0a" .. ICS_MOCK.w_u16(#err) .. err
    end
    local name = cfg.bacnet_object_name
    local ack = ICS_T.BACNET_NPDU .. "\x30\x01\x0c\x0c\x08\xc4\x00\xde\x00\x19\x4d\x3e" ..
      string.char(#name) .. name
    return "\x81\x0a" .. ICS_MOCK.w_u16(#ack) .. ack
  end
  return ""
end

function ICS_MOCK.dnp3_reply(cfg, sent)
  if not cfg.dnp3_link_ok then
    return ""
  end
  local frame = ICS_D3.decode_frame(sent)
  if frame == nil or frame.func ~= 9 then
    return ""
  end
  return ICS_D3.frame(ICS_T.DNP3_CTRL_LINK_STATUS, frame.src, frame.dst, "")
end

function ICS_MOCK.eip_reply(cfg, sent)
  if cfg.eip_identity == nil then
    return ""
  end
  if string.byte(sent, 1) ~= ICS_T.EIP_CMD_LIST_IDENTITY then
    return ICS_EI.header(ICS_T.EIP_CMD_REGISTER_SESSION, 0, "")
  end
  local ident = "\x01\x00\x50\x00\x0a\x0a\x01\x32\x00\x00" ..
    ICS_MOCK.w_u16(1) .. ICS_MOCK.w_u16(14) .. ICS_MOCK.w_u16(68) ..
    "\x00\xfb\x0a\x00" ..
    ICS_MOCK.w_u16(23) .. "1769-L16ER/B NET LINX"
  local payload = ICS_MOCK.w_u16(1) .. ICS_MOCK.w_u16(#ident + 2) .. "\x0c\x00" .. ident
  return ICS_EI.header(ICS_T.EIP_CMD_LIST_IDENTITY, 0, payload) .. payload
end

function ICS_MOCK.fins_reply(cfg, sent)
  if not cfg.fins_read_ok then
    return ""
  end
  if #sent >= 20 then
    local fins_req = string.sub(sent, 13, 22)
    local words = cfg.fins_words or {}
    local data = ""
    for _, w in ipairs(words) do
      data = data .. ICS_MOCK.w_u16(w)
    end
    local resp = "\xc0" .. string.sub(fins_req, 2, 10) .. string.sub(sent, 23, 24) .. "\x00\x00" .. data
    return "FINS" .. ICS_MOCK.w_u32(#resp) .. "\x00\x02\x00\x00" .. resp
  end
  return ""
end

function ICS_MOCK.fox_reply(cfg, sent)
  if not cfg.fox_ok then
    return ""
  end
  return "fox a 0 -1 s:hello r:1 {\nfox.version=" .. tostring(cfg.fox_version) ..
    "\nid=1\nhost=" .. tostring(cfg.fox_host) .. "\nsys=native\nbrand=" .. tostring(cfg.fox_brand) ..
    "\n}\n\0"
end

function ICS_MOCK.hart_reply(cfg, sent)
  if not cfg.hart_ok then
    return ""
  end
  local body = "\x82\x00\x00\x06\x00\x03\x0e\xa1" .. "\xb2\xc3\xd4\xe5"
  return "\x01\x02\x00\x00\x00\x01" .. ICS_MOCK.w_u16(#body + 8) .. body
end

function ICS_MOCK.iec104_reply(cfg, sent)
  if not cfg.iec104_ok then
    return ""
  end
  if string.byte(sent, 3) == ICS_T.IEC104_TESTFR_ACT then
    return "\x68\x04\x83\x00\x00\x00"
  end
  if string.byte(sent, 3) == ICS_T.IEC104_STARTDT_ACT then
    return "\x68\x04\x0b\x00\x00\x00"
  end
  return ""
end

function ICS_MOCK.melsec_reply(cfg, sent)
  if not cfg.melsec_ok then
    return ""
  end
  local words = cfg.melsec_words or {}
  local data = ""
  for _, w in ipairs(words) do
    data = data .. ICS_MOCK.w_u16(w)
  end
  return "\x00\x50\x00\x00\xff\x40\x00\x08\x00\x10\x00\x00" .. data
end

function ICS_MOCK.profinet_reply(cfg, sent)
  if not cfg.profinet_ok then
    return ""
  end
  local name = cfg.profinet_name or "pn-device"
  local block1 = "\x02\x02" .. ICS_MOCK.w_u16(#name + 2) .. "\x00\x01" .. name
  local block2 = "\x01\x02" .. ICS_MOCK.w_u16(14) .. "\x00\x01\x00\x00\x00\x00\x0a\x0a\x01\x64\xff\xff\xff\x00"
  return "\xfe\xfe" .. string.sub(sent, 3, 6) .. "\x00\x00\x05\x06" .. block1 .. block2
end

function ICS_MOCK.s7_reply(cfg, sent, self)
  if not cfg.s7_ok then
    return ""
  end
  local off = 8
  local pfunc = string.byte(sent, off + 11) or 0
  if pfunc == ICS_T.S7_FUNC_SETUP then
    return "\x03\x00\x00\x17\x03\xf0\x80\x03\x00\x00\x00\x01\x00\x05\x00\x00\x00\x00\xf0\x00\x01\x01\xe0"
  end
  if pfunc == ICS_T.S7_FUNC_READ_VAR then
    local ident = "CPU 315-2 PN/DP v3.15"
    local data = "\xff\x00\x0a\x32\x01\x00\x00\xf9\x03\x05\x94" ..
      ICS_MOCK.w_u16(#ident) .. ident
    return "\x03\x00" .. ICS_MOCK.w_u16(31 + #data) .. "\x03\xf0\x80" ..
      "\x03\x00\x00\x00\x02\x00\x0c" .. ICS_MOCK.w_u16(#data) .. "\x00\x00" ..
      "\x04\x01\x01\x12\x08\x11\x84\x00\x01\x00\x00\x14" .. data
  end
  return ""
end

function ICS_MOCK.ics_send(scenario, sent, self)
  local cfg = ICS_MOCK.cfg_of(scenario)
  local port = self.connect_port
  if port == 502 then
    return ICS_MOCK.modbus_reply(cfg, sent)
  end
  if port == 47808 then
    return ICS_MOCK.bacnet_reply(cfg, sent)
  end
  if port == 20000 then
    return ICS_MOCK.dnp3_reply(cfg, sent)
  end
  if port == 44818 then
    return ICS_MOCK.eip_reply(cfg, sent)
  end
  if port == 9600 then
    return ICS_MOCK.fins_reply(cfg, sent)
  end
  if port == 1911 then
    return ICS_MOCK.fox_reply(cfg, sent)
  end
  if port == 5094 then
    return ICS_MOCK.hart_reply(cfg, sent)
  end
  if port == 2404 then
    return ICS_MOCK.iec104_reply(cfg, sent)
  end
  if port == 5007 then
    return ICS_MOCK.melsec_reply(cfg, sent)
  end
  if port == 34964 then
    return ICS_MOCK.profinet_reply(cfg, sent)
  end
  if port == 102 then
    return ICS_MOCK.s7_reply(cfg, sent, self)
  end
  return ""
end


K8S_MOCK = {}

K8S_M_CFG = {
  ["k8s"] = {
    version = { major = "1", minor = "25", git = "v1.25.16", platform = "linux/amd64" },
    anon_namespaces = { "default", "kube-system", "kube-public", "kube-node-lease", "monitoring" },
    anon_pods = true,
    privileged_pod = true,
    nodes = 3,
    secrets_open = false,
    webhooks = { { name = "policy-webhook", failure = "Fail" }, { name = "audit-webhook", failure = "Ignore" } },
    openapi = true,
    node_proxy = true,
    etcd_version = "3.5.6",
    etcd_keys = true,
    kubelet_ro_pods = true,
    kubelet_metrics = true,
    kubelet_exec_surface = true,
    dashboard_overview = true,
    coredns_metrics = true,
    proxy_pprof = true,
    proxy_configz = true,
  },
  ["k8s-secure"] = {
    version = { major = "1", minor = "29", git = "v1.29.4", platform = "linux/amd64" },
    anon_namespaces = nil,
    anon_pods = false,
    secrets_open = false,
    etcd_version = "3.5.12",
    etcd_keys = false,
    kubelet_ro_pods = false,
    kubelet_metrics = false,
    kubelet_exec_surface = false,
    dashboard_overview = false,
    coredns_metrics = false,
    proxy_pprof = false,
    proxy_configz = false,
  },
}

function K8S_MOCK.cfg_of(scenario)
  return K8S_M_CFG[scenario] or K8S_M_CFG["k8s-secure"]
end

function K8S_MOCK.http_split(sent)
  local line = sent:match("^([^\r\n]+)")
  if line == nil then
    return nil, nil
  end
  local method, path = line:match("^(%u+)%s+(%S+)")
  return method, path
end

K8S_MOCK.enc_value = function(v)
  local t = type(v)
  if t == "boolean" then
    return v and "true" or "false"
  end
  if t == "number" then
    return tostring(v)
  end
  if t == "table" then
    local is_arr = #v > 0
    local parts = {}
    if is_arr then
      for i = 1, #v do
        parts[#parts + 1] = K8S_MOCK.enc_value(v[i])
      end
      return "[" .. table.concat(parts, ",") .. "]"
    end
    for k, val in pairs(v) do
      parts[#parts + 1] = '"' .. tostring(k) .. '":' .. K8S_MOCK.enc_value(val)
    end
    return "{" .. table.concat(parts, ",") .. "}"
  end
  return '"' .. tostring(v) .. '"'
end

function K8S_MOCK.resp_json(status, doc)
  local body = doc
  if type(doc) == "table" then
    body = K8S_MOCK.enc_value(doc)
  end
  return "HTTP/1.1 " .. status .. " OK\r\nContent-Type: application/json\r\nContent-Length: " ..
    #body .. "\r\nConnection: close\r\n\r\n" .. body
end

function K8S_MOCK.resp_text(status, ctype, body)
  return "HTTP/1.1 " .. status .. " OK\r\nContent-Type: " .. ctype ..
    "\r\nContent-Length: " .. #body .. "\r\nConnection: close\r\n\r\n" .. body
end

function K8S_MOCK.apiserver(cfg, method, path)
  if path == "/version" then
    return K8S_MOCK.resp_json(200, { major = cfg.version.major, minor = cfg.version.minor,
      gitVersion = cfg.version.git, gitCommit = "abc1234", platform = cfg.version.platform })
  end
  if cfg.anon_namespaces == nil and path ~= "/version" then
    return K8S_MOCK.resp_json(401, { kind = "Status", message = "Unauthorized", code = 401 })
  end
  if path == "/api/v1/namespaces" then
    local items = {}
    for _, ns in ipairs(cfg.anon_namespaces) do
      items[#items + 1] = { metadata = { name = ns } }
    end
    return K8S_MOCK.resp_json(200, { kind = "NamespaceList", items = items })
  end
  if path == "/api/v1/pods" then
    if not cfg.anon_pods then
      return K8S_MOCK.resp_json(403, { kind = "Status", message = "pods is forbidden", code = 403 })
    end
    local pods = {
      { metadata = { name = "coredns-66b8c5", namespace = "kube-system" },
        spec = { hostNetwork = false, hostPID = false, hostIPC = false,
          containers = { { securityContext = { privileged = false, capabilities = { add = {} } } } } } },
      { metadata = { name = "node-exporter-x7", namespace = "monitoring" },
        spec = { hostNetwork = true, hostPID = true, hostIPC = false,
          containers = { { securityContext = { privileged = true, capabilities = { add = { "SYS_ADMIN", "NET_ADMIN" } } } } } } },
      { metadata = { name = "log-collector", namespace = "default" },
        spec = { hostNetwork = false, hostPID = true, hostIPC = false,
          containers = { { securityContext = { privileged = false, capabilities = { add = {} } } } } } },
    }
    return K8S_MOCK.resp_json(200, { kind = "PodList", items = pods })
  end
  if path == "/api/v1/nodes" then
    if cfg.anon_namespaces == nil then
      return K8S_MOCK.resp_json(401, { kind = "Status", code = 401 })
    end
    local items = {}
    for i = 1, cfg.nodes do
      items[#items + 1] = { metadata = { name = "node-0" .. i } }
    end
    return K8S_MOCK.resp_json(200, { kind = "NodeList", items = items })
  end
  if path == "/api/v1/secrets" then
    return K8S_MOCK.resp_json(403, { kind = "Status", message = "secrets is forbidden: cannot list", code = 403 })
  end
  if path == "/api/v1/serviceaccounts" then
    if cfg.anon_namespaces == nil then
      return K8S_MOCK.resp_json(401, { kind = "Status", code = 401 })
    end
    return K8S_MOCK.resp_json(200, { kind = "ServiceAccountList", items = {
      { metadata = { name = "default", namespace = "default" } },
      { metadata = { name = "coredns", namespace = "kube-system" } },
      { metadata = { name = "metrics-agent", namespace = "monitoring" } } } })
  end
  if path == "/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations"
    or path == "/apis/admissionregistration.k8s.io/v1/mutatingwebhookconfigurations" then
    if cfg.anon_namespaces == nil or cfg.webhooks == nil then
      return K8S_MOCK.resp_json(401, { kind = "Status", code = 401 })
    end
    local items = {}
    for _, wh in ipairs(cfg.webhooks) do
      items[#items + 1] = { metadata = { name = wh.name .. "-cfg" },
        webhooks = { { name = wh.name .. ".example.com", failurePolicy = wh.failure,
          matchPolicy = "Exact", timeoutSeconds = 10, namespaceSelector = { matchLabels = { team = "platform" } } } } }
    end
    return K8S_MOCK.resp_json(200, { kind = "ValidatingWebhookConfigurationList", items = items })
  end
  if path == "/openapi/v2" then
    if cfg.anon_namespaces == nil or not cfg.openapi then
      return K8S_MOCK.resp_json(401, { kind = "Status", code = 401 })
    end
    return K8S_MOCK.resp_json(200, { info = { title = "Kubernetes", version = "v1.25.0" },
      paths = { ["/api/v1/pods"] = {}, ["/api/v1/secrets"] = {}, ["/exec"] = {}, ["/version"] = {} } })
  end
  if path:find("/proxy/healthz", 1, true) then
    if cfg.anon_namespaces == nil or not cfg.node_proxy then
      return K8S_MOCK.resp_json(401, { kind = "Status", code = 401 })
    end
    return K8S_MOCK.resp_text(200, "text/plain", "ok")
  end
  if path == "/healthz" or path == "/livez" or path == "/readyz" then
    return K8S_MOCK.resp_text(200, "text/plain", "ok")
  end
  return K8S_MOCK.resp_json(404, { kind = "Status", message = "not found", code = 404 })
end

function K8S_MOCK.kubelet(cfg, method, path)
  if cfg.kubelet_ro_pods == false and cfg.kubelet_metrics == false then
    return K8S_MOCK.resp_json(401, { kind = "Status", message = "Unauthorized", code = 401 })
  end
  if path == "/pods" and cfg.kubelet_ro_pods then
    local pods = {
      { metadata = { name = "nginx", namespace = "default" },
        spec = { hostNetwork = false, containers = { {} } } },
    }
    return K8S_MOCK.resp_json(200, { kind = "PodList", items = pods })
  end
  if path == "/metrics" and cfg.kubelet_metrics then
    return K8S_MOCK.resp_text(200, "text/plain", "kubelet_running_pods 5\nkubelet_volume_stats_used_bytes 1024\n")
  end
  if path == "/runningpods/" and cfg.kubelet_ro_pods then
    return K8S_MOCK.resp_json(200, { kind = "PodList", items = { { metadata = { name = "nginx", namespace = "default" } } } })
  end
  if path == "/healthz" then
    return K8S_MOCK.resp_text(200, "text/plain", "ok")
  end
  return K8S_MOCK.resp_json(401, { kind = "Status", code = 401 })
end

function K8S_MOCK.https_send(scenario, sent, self)
  local cfg = K8S_MOCK.cfg_of(scenario)
  local method, path = K8S_MOCK.http_split(sent)
  if method == nil then
    return ""
  end
  local port = self.connect_port
  if port == 6443 then
    return K8S_MOCK.apiserver(cfg, method, path)
  end
  if port == 8443 then
    if cfg.dashboard_overview then
      return K8S_MOCK.resp_text(200, "text/html", "<html><head><title>kubernetes-dashboard</title></head><body>Overview Workloads</body></html>")
    end
    if path:find("/login", 1, true) then
      return K8S_MOCK.resp_text(200, "text/html", "<html><body>Kubernetes Dashboard login</body></html>")
    end
    return "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: 60\r\nConnection: close\r\n\r\n<html><body>Kubernetes Dashboard login required</body></html>"
  end
  if port == 2379 then
    if path == "/version" then
      return K8S_MOCK.resp_json(200, { etcdserver = cfg.etcd_version, etcdcluster = "3.5.0" })
    end
    if path:find("/v2/keys", 1, true) then
      if cfg.etcd_keys then
        return K8S_MOCK.resp_json(200, { action = "get", node = { dir = true,
          nodes = { { key = "/registry/pods", dir = true }, { key = "/registry/secrets", dir = true } } } })
      end
      return K8S_MOCK.resp_json(403, { message = "auth: permission denied", code = 403 })
    end
    if path == "/health" then
      return K8S_MOCK.resp_json(200, { health = "true" })
    end
    return ""
  end
  if port == 9153 then
    if cfg.coredns_metrics then
      return K8S_MOCK.resp_text(200, "text/plain", "coredns_dns_requests_total 123\ncoredns_dns_responses_total 120\n")
    end
    return "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
  end
  if port == 10255 then
    if cfg.kubelet_ro_pods then
      return K8S_MOCK.kubelet(cfg, method, path)
    end
    return ""
  end
  if port == 10250 then
    return K8S_MOCK.kubelet(cfg, method, path)
  end
  if port == 10256 then
    if path == "/healthz" then
      return K8S_MOCK.resp_text(200, "text/plain", "ok")
    end
    if path == "/configz" then
      if cfg.proxy_configz then
        return K8S_MOCK.resp_text(200, "application/json", '{"kube-proxy":{"mode":"iptables"}}')
      end
      return "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
    end
    if path:find("/debug/pprof", 1, true) then
      if cfg.proxy_pprof then
        return K8S_MOCK.resp_text(200, "text/html", "<html><body>profiles:</body></html>")
      end
      return "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
    end
    return ""
  end
  return ""
end


ES_MOCK = {}

ES_M_CFG = {
  ["es"] = {
    root = { cluster = "elasticsearch", uuid = "cdea-1234", version = "1.4.2", lucene = "4.10.4" },
    health = "yellow",
    nodes = 2,
    indices = { { index = "logs-2015", health = "yellow", docs = 1337, size = "9.1mb" },
      { index = "customers", health = "green", docs = 88, size = "1.2mb" } },
    aliases = { { alias = "logs", index = "logs-2015", filter = "-" } },
    field_caps = { message = { types = { "text" }, searchable = true }, id = { types = { "keyword" } } },
    tasks_running = 1,
    license = { status = "active", kind = "basic" },
    nodes_settings = { { name = "node-0", http = "10.66.0.10:9200" } },
    templates = { { name = "logs-template", patterns = "logs-*", order = 1 } },
    repos = { { repo = "backup-s3", kind = "s3", location = "s3://bucket-1337" } },
    search_total = 1337,
    script_engine = true,
    delete_open = true,
    kibana = true,
    kibana_version = "4.3.0",
  },
  ["es-secure"] = {
    root = { cluster = "prod-cluster", uuid = "ffff-9999", version = "8.14.1", lucene = "9.10.0" },
    auth_wall = true,
  },
}

function ES_MOCK.cfg_of(scenario)
  return ES_M_CFG[scenario] or ES_M_CFG["es-secure"]
end

function ES_MOCK.enc_value(v)
  local t = type(v)
  if t == "boolean" then
    return v and "true" or "false"
  end
  if t == "number" then
    return tostring(v)
  end
  if t == "table" then
    local is_arr = #v > 0
    local parts = {}
    if is_arr then
      for i = 1, #v do
        parts[#parts + 1] = ES_MOCK.enc_value(v[i])
      end
      return "[" .. table.concat(parts, ",") .. "]"
    end
    for k, val in pairs(v) do
      parts[#parts + 1] = '"' .. tostring(k) .. '":' .. ES_MOCK.enc_value(val)
    end
    return "{" .. table.concat(parts, ",") .. "}"
  end
  if v == nil then
    return "null"
  end
  return '"' .. tostring(v) .. '"'
end

function ES_MOCK.resp_json(status, doc)
  local body = doc
  if type(doc) == "table" then
    body = ES_MOCK.enc_value(doc)
  end
  return "HTTP/1.1 " .. status .. " OK\r\nContent-Type: application/json\r\nContent-Length: " ..
    #body .. "\r\nConnection: close\r\n\r\n" .. body
end

function ES_MOCK.resp_text(status, ctype, body)
  return "HTTP/1.1 " .. status .. " OK\r\nContent-Type: " .. ctype ..
    "\r\nContent-Length: " .. #body .. "\r\nConnection: close\r\n\r\n" .. body
end

function ES_MOCK.unauth()
  return ES_MOCK.resp_json(401, { error = { root_cause = { { type = "security_exception" } },
    type = "security_exception", reason = "missing authentication credentials" }, status = 401 })
end

function ES_MOCK.handle(cfg, method, path, body)
  if cfg.auth_wall then
    if path == "/" then
      return ES_MOCK.resp_json(401, { error = "Unauthorized" })
    end
    return ES_MOCK.unauth()
  end
  if path == "/" then
    return ES_MOCK.resp_json(200, { name = "node-0", cluster_name = cfg.root.cluster,
      cluster_uuid = cfg.root.uuid, version = { number = cfg.root.version, lucene_version = cfg.root.lucene,
        build_flavor = "oss" }, tagline = "You Know, for Search" })
  end
  if path == "/_cluster/health" then
    return ES_MOCK.resp_json(200, { cluster_name = cfg.root.cluster, status = cfg.health,
      timed_out = false, number_of_nodes = cfg.nodes, number_of_data_nodes = cfg.nodes,
      active_primary_shards = 10, unassigned_shards = cfg.health == "yellow" and 4 or 0 })
  end
  if path == "/_cat/indices?format=json" then
    local rows = {}
    for _, idx in ipairs(cfg.indices) do
      rows[#rows + 1] = { health = idx.health, status = "open", index = idx.index,
        ["docs.count"] = tostring(idx.docs), ["store.size"] = idx.size }
    end
    return ES_MOCK.resp_json(200, rows)
  end
  if path == "/_cat/aliases?format=json" then
    local rows = {}
    for _, al in ipairs(cfg.aliases) do
      rows[#rows + 1] = { alias = al.alias, index = al.index, filter = al.filter }
    end
    return ES_MOCK.resp_json(200, rows)
  end
  if path == "/_field_caps?fields=*" then
    return ES_MOCK.resp_json(200, { fields = cfg.field_caps })
  end
  if path == "/_tasks" then
    return ES_MOCK.resp_json(200, { nodes = { n0 = { name = "node-0",
      tasks = { t1 = { action = "indices:monitor/stats", running_time_in_nanos = 12000000 } } } } })
  end
  if path == "/_license" then
    return ES_MOCK.resp_json(200, { license = { status = cfg.license.status, uid = "lic-1",
      type = cfg.license.kind, issued_to = cfg.root.cluster } })
  end
  if path == "/_nodes/settings" then
    local nodes = {}
    for _, n in ipairs(cfg.nodes_settings) do
      nodes["n_" .. n.name] = { name = n.name, http = { publish_address = n.http },
        settings = { network = { host = "0.0.0.0" }, http = { enabled = "true", bind_host = "0.0.0.0" } },
        attributes = { "master", "data" } }
    end
    return ES_MOCK.resp_json(200, { nodes = nodes })
  end
  if path == "/_template" then
    local t = {}
    for _, tpl in ipairs(cfg.templates) do
      t[tpl.name] = { index_patterns = { tpl.patterns }, order = tpl.order,
        settings = { ["index.number_of_shards"] = "5" } }
    end
    return ES_MOCK.resp_json(200, t)
  end
  if path == "/_snapshot" then
    local r = {}
    for _, repo in ipairs(cfg.repos) do
      r[repo.repo] = { type = repo.kind, settings = { location = repo.location, compress = "true" } }
    end
    return ES_MOCK.resp_json(200, r)
  end
  if path:find("/_search", 1, true) then
    local script_lang = body and body:match('"lang":"([%w_]+)"')
    if script_lang ~= nil and not cfg.script_engine then
      return ES_MOCK.resp_json(400, { error = { root_cause = { { type = "script_lang_not_supported" } },
        type = "script_lang_not_supported" }, status = 400 })
    end
    local fields = nil
    if script_lang ~= nil then
      fields = { nse_probe = { 2 } }
    end
    return ES_MOCK.resp_json(200, { took = 5, hits = { total = { value = cfg.search_total },
      hits = { { _index = cfg.indices[1].index, _id = "1", fields = fields,
        _source = { user = "kimchy", message = "secret payload XYZ" } } } } })
  end
  if path:find("/" .. ES.SENTINEL_INDEX, 1, true) then
    if method == "DELETE" then
      if cfg.delete_open then
        return ES_MOCK.resp_json(404, { error = { root_cause = { { type = "index_not_found_exception",
          reason = "no such index" } }, type = "index_not_found_exception", reason = "no such index" }, status = 404 })
      end
      return ES_MOCK.unauth()
    end
  end
  if path == "/health" then
    return ES_MOCK.resp_text(200, "text/plain", "ok")
  end
  return ES_MOCK.resp_json(404, { error = { root_cause = { { type = "index_not_found_exception" } },
    type = "index_not_found_exception" }, status = 404 })
end

function ES_MOCK.http_send(scenario, sent, self)
  local cfg = ES_MOCK.cfg_of(scenario)
  local method, path = K8S_MOCK.http_split(sent)
  if method == nil then
    return ""
  end
  local body = sent:match("\r\n\r\n(.*)$")
  local port = self.connect_port
  if port == 9200 then
    return ES_MOCK.handle(cfg, method, path, body)
  end
  if port == 5601 then
    if not cfg.kibana then
      return "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html\r\nContent-Length: 90\r\nConnection: close\r\n\r\n<html><body>kibana login required</body></html>"
    end
    if path == "/app/kibana" or path == "/" then
      local page = "<html><head><meta kbn-name='kibana' kbn-version='" .. cfg.kibana_version ..
        "'></head><body>Welcome Overview /app/discover anonymous workspace</body></html>"
      return ES_MOCK.resp_text(200, "text/html", page)
    end
    return ES_MOCK.resp_text(200, "text/html", "<html><body>kibana login page kbn-name</body></html>")
  end
  return ""
end


MC_MOCK = {}

MC_M_CFG = {
  ["mc"] = {
    version = "1.6.22",
    auth_wall = false,
    stats = { curr_items = 137, total_items = 8111, bytes = 10485760, curr_connections = 6,
      total_connections = 42, get_hits = 5122, get_misses = 777, delete_hits = 3,
      cmd_set = 900, limit_maxbytes = 67108864, evictions = 0, uptime = 864000, threads = 4 },
    settings = { maxbytes = "67108864", maxconns = "1024", tcpport = "11211", udpport = "11211",
      inter = "NULL", verbosity = "0", oldest = "0", evictions = "on", domain_socket = "NULL",
      umask = "700", maxconns_fast = "false", lru_crawler = "false", slab_reassign = "true",
      slab_automove = "1", automove_threshold = "no", item_size_max = "1048576", num_threads = "4" },
    slabs = { [1] = { chunk_size = "96", total_chunks = "10922", used_chunks = "80", get_hits = "400" },
      [2] = { chunk_size = "120", total_chunks = "8738", used_chunks = "57", get_hits = "120" } },
    items = { [1] = { number = "80", age = "3600" }, [2] = { number = "57", age = "1200" } },
    sizes = { [96] = 80, [120] = 57 },
    cachedump = { "user:session:4471", "cart:991", "token:a91f", "flag:config", "rate:guest" },
    keys_work = true,
    flush_accepted = true,
    verbosity_ok = true,
    watch_ok = true,
    udp_enabled = true,
    udp_response_bytes = 1500,
    binary_version = "1.6.22",
    sasl_mechs = "",
  },
  ["mc-secure"] = {
    version = "1.6.22",
    auth_wall = true,
    binary_version = "1.6.22",
    sasl_mechs = "PLAIN SCRAM-SHA-1",
    udp_enabled = false,
  },
}

MC_M_CFG["mc-udp"] = MC_M_CFG["mc"]
MC_M_CFG["mc-udp-secure"] = MC_M_CFG["mc-secure"]

function MC_MOCK.cfg_of(scenario)
  return MC_M_CFG[scenario] or MC_M_CFG["mc-secure"]
end

function MC_MOCK.handle_ascii(cfg, command)
  if cfg.auth_wall then
    return { "ERROR" }
  end
  if command == "version\r\n" then
    return { "VERSION " .. cfg.version }
  end
  if command == "stats\r\n" then
    local out = {}
    for k, v in pairs(cfg.stats) do
      out[#out + 1] = "STAT " .. k .. " " .. v
    end
    out[#out + 1] = "END"
    return out
  end
  if command == "stats settings\r\n" then
    local out = {}
    for k, v in pairs(cfg.settings) do
      out[#out + 1] = "STAT " .. k .. " " .. v
    end
    out[#out + 1] = "END"
    return out
  end
  if command == "stats slabs\r\n" then
    local out = {}
    for sid, fields in pairs(cfg.slabs) do
      for k, v in pairs(fields) do
        out[#out + 1] = "STAT " .. sid .. ":" .. k .. " " .. v
      end
    end
    out[#out + 1] = "STAT total_malloced 2097152"
    out[#out + 1] = "END"
    return out
  end
  if command == "stats items\r\n" then
    local out = {}
    for sid, fields in pairs(cfg.items) do
      for k, v in pairs(fields) do
        out[#out + 1] = "STAT " .. sid .. ":" .. k .. " " .. v
      end
    end
    out[#out + 1] = "END"
    return out
  end
  if command == "stats sizes\r\n" then
    local out = {}
    for size, count in pairs(cfg.sizes) do
      out[#out + 1] = "STAT " .. size .. " " .. count
    end
    out[#out + 1] = "END"
    return out
  end
  local slab = command:match("^stats cachedump (%d+) (%d+)\r\n$")
  if slab ~= nil then
    local out = {}
    local limit = tonumber(command:match("^stats cachedump %d+ (%d+)\r\n$")) or 5
    for i, key in ipairs(cfg.cachedump) do
      if i > limit then
        break
      end
      out[#out + 1] = "ITEM " .. key .. " [12 b; 0 s]"
    end
    out[#out + 1] = "END"
    return out
  end
  if command == "verbosity 0\r\n" then
    if cfg.verbosity_ok then
      return { "OK" }
    end
    return { "ERROR" }
  end
  if command == "watch fetchers\r\n" then
    if cfg.watch_ok then
      return { "OK" }
    end
    return { "ERROR" }
  end
  if command:find("^flush_all ") then
    if cfg.flush_accepted then
      return { "OK" }
    end
    return { "ERROR" }
  end
  local setkey = command:match("^set ([%w:_%-]+) ")
  if setkey ~= nil then
    if cfg.keys_work then
      return { "STORED" }
    end
    return { "ERROR" }
  end
  local getkey = command:match("^get ([%w:_%-]+)\r\n$")
  if getkey ~= nil then
    if cfg.keys_work and getkey == MC.SENTINEL_KEY then
      return { "VALUE " .. getkey .. " 0 " .. #MC.SENTINEL_VALUE, MC.SENTINEL_VALUE, "END" }
    end
    return { "END" }
  end
  local delkey = command:match("^delete ([%w:_%-]+)\r\n$")
  if delkey ~= nil then
    if cfg.keys_work and delkey == MC.SENTINEL_KEY then
      return { "DELETED" }
    end
    return { "NOT_FOUND" }
  end
  local touchkey = command:match("^touch ([%w:_%-]+) ")
  if touchkey ~= nil then
    if cfg.keys_work then
      return { "NOT_FOUND" }
    end
    return { "ERROR" }
  end
  if command == "mn\r\n" then
    if cfg.keys_work then
      return { "HD" }
    end
    return { "ERROR" }
  end
  local mgkey = command:match("^mg ([%w:_%-]+) ")
  if mgkey ~= nil then
    if cfg.keys_work then
      return { "EN" }
    end
    return { "ERROR" }
  end
  local mskey = command:match("^ms ([%w:_%-]+) ")
  if mskey ~= nil then
    if cfg.keys_work then
      return { "HD" }
    end
    return { "ERROR" }
  end
  local mdkey = command:match("^md ([%w:_%-]+) ")
  if mdkey ~= nil then
    if cfg.keys_work then
      return { "HD" }
    end
    return { "ERROR" }
  end
  if command:find("^lru_crawler metadump") then
    if cfg.keys_work then
      return { "key=user:session:4471 exp=-1 la=6400 cas=91 fetch=no", "key=cart:991 exp=-1 la=6100 cas=77 fetch=yes", "END" }
    end
    return { "ERROR" }
  end
  return { "ERROR" }
end

MC_MOCK.bin_res = function(opcode, status, extras, key, body)
  extras = extras or ""
  key = key or ""
  body = body or ""
  return string.char(MC.BINARY_MAGIC_RES, opcode) ..
    string.char(math.floor(#key / 256) % 256, #key % 256) ..
    string.char(#extras, 0) ..
    string.char(math.floor(status / 256) % 256, status % 256) ..
    string.char(math.floor(#body / 16777216) % 256, math.floor(#body / 65536) % 256,
      math.floor(#body / 256) % 256, #body % 256) ..
    string.char(0, 0, 0, 0) .. "\0\0\0\0\0\0\0\0" .. extras .. key .. body
end

function MC_MOCK.handle_binary(cfg, data)
  if type(data) ~= "string" or #data < 24 then
    return ""
  end
  local opcode = string.byte(data, 2)
  local key_len = string.byte(data, 3) * 256 + string.byte(data, 4)
  local extras_len = string.byte(data, 5)
  local body = data:sub(25 + extras_len + key_len)
  local bkey = data:sub(25 + extras_len, 24 + extras_len + key_len)
  if opcode == MC.BINARY_OPCODE_SET then
    if cfg.keys_work and bkey == MC.SENTINEL_KEY then
      cfg.bin_set = true
      return MC_MOCK.bin_res(opcode, 0, "\0\0\0\0", "", "")
    end
    if cfg.auth_wall then
      return MC_MOCK.bin_res(opcode, 0x0020, "", "", "")
    end
    return MC_MOCK.bin_res(opcode, 0x0004, "", "", "")
  end
  if opcode == MC.BINARY_OPCODE_GET then
    if cfg.auth_wall then
      return MC_MOCK.bin_res(opcode, 0x0020, "", "", "")
    end
    if cfg.bin_set and bkey == MC.SENTINEL_KEY then
      return MC_MOCK.bin_res(opcode, 0, "\0\0\0\0", "", MC.SENTINEL_VALUE)
    end
    return MC_MOCK.bin_res(opcode, 0x0001, "", "", "")
  end
  if opcode == MC.BINARY_OPCODE_DELETE then
    if cfg.auth_wall then
      return MC_MOCK.bin_res(opcode, 0x0020, "", "", "")
    end
    if cfg.keys_work and bkey == MC.SENTINEL_KEY then
      return MC_MOCK.bin_res(opcode, 0, "", "", "")
    end
    return MC_MOCK.bin_res(opcode, 0x0001, "", "", "")
  end
  if opcode == MC.BINARY_OPCODE_TOUCH then
    if cfg.auth_wall then
      return MC_MOCK.bin_res(opcode, 0x0020, "", "", "")
    end
    return MC_MOCK.bin_res(opcode, 0x0001, "", "", "")
  end
  if opcode == MC.BINARY_OPCODE_SASL_AUTH then
    if cfg.sasl_mechs ~= nil and cfg.sasl_mechs ~= "" then
      return MC_MOCK.bin_res(opcode, 0x0007, "", "", "auth failure for the supplied credentials")
    end
    return MC_MOCK.bin_res(opcode, 0x0081, "", "", "")
  end
  if opcode == MC.BINARY_OPCODE_VERSION then
    local body = cfg.binary_version or "1.6.22"
    return string.char(MC.BINARY_MAGIC_RES, opcode) ..
      string.char(0, 0) .. string.char(0, 0, 0, 0) ..
      string.char(0, 0, 0, #body) ..
      string.char(0, 0, 0, 0) .. "\0\0\0\0\0\0\0\0" .. body
  end
  if opcode == MC.BINARY_OPCODE_SASL_LIST then
    local body = cfg.sasl_mechs or ""
    return string.char(MC.BINARY_MAGIC_RES, opcode) ..
      string.char(0, 0) .. string.char(0, 0, 0, 0) ..
      string.char(0, 0, 0, #body) ..
      string.char(0, 0, 0, 0) .. "\0\0\0\0\0\0\0\0" .. body
  end
  return ""
end

function MC_MOCK.tcp_send(scenario, sent, self)
  local cfg = MC_MOCK.cfg_of(scenario)
  return table.concat(MC_MOCK.handle_ascii(cfg, sent), "\r\n") .. "\r\n"
end

function MC_MOCK.binary_send(scenario, sent, self)
  local cfg = MC_MOCK.cfg_of(scenario)
  return MC_MOCK.handle_binary(cfg, sent)
end

function MC_MOCK.udp_send(scenario, sent, self)
  local cfg = MC_MOCK.cfg_of(scenario)
  if not cfg.udp_enabled then
    return ""
  end
  local parsed = MC.udp_parse(sent)
  if parsed == nil then
    return ""
  end
  local payload = parsed.payload or ""
  local body
  if payload == "stats\r\n" then
    local filler = string.rep("x", cfg.udp_response_bytes - 30)
    body = "STAT udp_filler " .. filler .. "\r\nEND"
  elseif payload == "version\r\n" then
    body = "VERSION " .. (cfg.version or "1.6.22")
  else
    body = "ERROR"
  end
  return MC.udp_frame(parsed.request_id, 0, 1, body)
end


KA_MOCK = {}

KA_M_CFG = {
  ["kafka"] = {
    sasl_required = false,
    apiversions = {
      { 0, 0, 7 }, { 1, 0, 10 }, { 2, 0, 6 }, { 3, 0, 9 }, { 8, 0, 7 },
      { 9, 0, 7 }, { 10, 0, 3 }, { 11, 0, 5 }, { 12, 0, 3 }, { 13, 0, 2 },
      { 14, 0, 3 }, { 15, 0, 3 }, { 16, 0, 2 }, { 17, 0, 1 }, { 18, 0, 2 },
    },
    brokers = { { 1, "kafka-1.example.internal", 9092 }, { 2, "kafka-2.example.internal", 9092 } },
    controller = 1,
    topics = {
      { "orders", 0, { { 0, 0, 1, 2, 1 }, { 0, 1, 2, 1, 1 }, { 0, 2, 1, 1, 2 } } },
      { "payments", 0, { { 0, 0, 2, 2, 2 }, { 0, 1, 1, 1, 1 } } },
      { "__consumer_offsets", 0, { { 0, 0, 1, 2, 2 } } },
    },
    groups = { { "order-processor", "consumer" }, { "payment-sync", "consumer" } },
    describe = {
      { 0, "order-processor", "Stable", "consumer", "range",
        { { "member-1", "order-worker-1", "/10.20.0.11" } } },
      { 0, "payment-sync", "Stable", "consumer", "roundrobin",
        { { "member-2", "payment-worker-2", "/10.20.0.12" } } },
    },
    create_allowed = true,
    delete_allowed = true,
    sasl_mechs = {},
    wildcard_topics_withheld = false,
  },
  ["kafka-secure"] = {
    sasl_required = true,
    apiversions = {
      { 0, 0, 12 }, { 1, 0, 13 }, { 2, 0, 8 }, { 3, 0, 12 }, { 8, 0, 9 },
      { 15, 0, 5 }, { 16, 0, 4 }, { 17, 0, 1 }, { 18, 0, 3 }, { 33, 0, 0 },
      { 34, 0, 0 }, { 39, 0, 2 }, { 45, 0, 0 },
    },
    brokers = { { 1, "kafka-1.example.internal", 9092 } },
    controller = 1,
    topics = {},
    groups = {},
    describe = {},
    create_allowed = false,
    delete_allowed = false,
    sasl_mechs = { "PLAIN", "SCRAM-SHA-256" },
    wildcard_topics_withheld = true,
  },
}

function KA_MOCK.cfg_of(scenario)
  local cfg = KA_M_CFG[scenario]
  if cfg == nil then
    cfg = { sasl_required = false, apiversions = {}, brokers = {}, topics = {}, groups = {} }
  end
  return cfg
end

k_i16 = function(n) return KA.w_i16(n) end
k_i32 = function(n) return KA.w_i32(n) end
k_str = function(s) return KA.kafka_str(s) end

k_array = function(items, encode)
  local parts = {}
  for _, item in ipairs(items) do
    parts[#parts + 1] = encode(item)
  end
  return k_i32(#items) .. table.concat(parts)
end

function KA_MOCK.apiversions_response(cfg, correlation)
  local arr = k_array(cfg.apiversions, function(a)
    return k_i16(a[1]) .. k_i16(a[2]) .. k_i16(a[3])
  end)
  return k_i32(2 + 4 + #arr) .. k_i32(correlation) .. k_i16(0) .. arr
end

function KA_MOCK.metadata_response(cfg, correlation)
  local brokers = k_array(cfg.brokers, function(b)
    return k_i32(b[1]) .. k_str(b[2]) .. k_i32(b[3])
  end)
  local topics = k_array(cfg.topics, function(t)
    local parts = k_array(t[3], function(p)
      return k_i16(p[1]) .. k_i32(p[2]) .. k_i32(p[3]) ..
        k_i32(1) .. k_i32(p[4]) .. k_i32(1) .. k_i32(p[5])
    end)
    return k_i16(t[2]) .. k_str(t[1]) .. parts
  end)
  local body = brokers .. k_i32(cfg.controller) .. topics
  return k_i32(4 + #body) .. k_i32(correlation) .. body
end

function KA_MOCK.listgroups_response(cfg, correlation)
  if cfg.groups == nil or #cfg.groups == 0 then
    local body = k_i16(30) .. k_i32(0)
    return k_i32(4 + #body) .. k_i32(correlation) .. body
  end
  local groups = k_array(cfg.groups, function(g)
    return k_str(g[1]) .. k_str(g[2])
  end)
  local body = k_i16(0) .. groups
  return k_i32(4 + #body) .. k_i32(correlation) .. body
end

function KA_MOCK.describegroups_response(cfg, correlation, requested)
  local rows = {}
  for _, want in ipairs(requested or {}) do
    local found = nil
    for _, g in ipairs(cfg.describe or {}) do
      if g[2] == want then
        found = g
        break
      end
    end
    if found == nil then
      if cfg.sasl_required then
        rows[#rows + 1] = k_i16(30) .. k_str(want) .. k_str("") .. k_str("") .. k_str("") .. k_i32(0)
      else
        rows[#rows + 1] = k_i16(24) .. k_str(want) .. k_str("Dead") .. k_str("") .. k_str("") .. k_i32(0)
      end
    else
      local members = k_array(found[6], function(m)
        return k_str(m[1]) .. k_str(m[2]) .. k_str(m[3]) .. k_i32(0) .. k_i32(0)
      end)
      rows[#rows + 1] = k_i16(found[1]) .. k_str(found[2]) .. k_str(found[3]) ..
        k_str(found[4]) .. k_str(found[5]) .. members
    end
  end
  local body = k_array(rows, function(r) return r end)
  return k_i32(4 + #body) .. k_i32(correlation) .. body
end

function KA_MOCK.sasl_handshake_response(cfg, correlation)
  if cfg.sasl_mechs == nil or #cfg.sasl_mechs == 0 then
    local body = k_i16(34) .. k_i32(0)
    return k_i32(4 + #body) .. k_i32(correlation) .. body
  end
  local mechs = k_array(cfg.sasl_mechs, function(m) return k_str(m) end)
  local body = k_i16(0) .. mechs
  return k_i32(4 + #body) .. k_i32(correlation) .. body
end

function KA_MOCK.sasl_auth_response(cfg, correlation)
  if cfg.sasl_required then
    return ""
  end
  local body = k_i16(34) .. k_str("SASL not enabled on this listener") .. k_i32(0)
  return k_i32(4 + #body) .. k_i32(correlation) .. body
end

function KA_MOCK.create_response(cfg, correlation, topic)
  local code = cfg.create_allowed and 0 or 31
  local body = k_i32(1) .. k_i16(code) .. k_str(topic)
  return k_i32(4 + #body) .. k_i32(correlation) .. body
end

function KA_MOCK.delete_response(cfg, correlation, topic)
  local exists = false
  if cfg.topics ~= nil and topic ~= nil then
    for i, t in ipairs(cfg.topics) do
      if t[1] == topic then
        table.remove(cfg.topics, i)
        exists = true
        break
      end
    end
  end
  local code
  if not cfg.delete_allowed then
    code = 31
  elseif exists then
    code = 0
  else
    code = 3
  end
  local body = k_i32(1) .. k_i16(code) .. k_str(topic)
  return k_i32(4 + #body) .. k_i32(correlation) .. body
end

function KA_MOCK.kafka_send(scenario, sent, self)
  local cfg = KA_MOCK.cfg_of(scenario)
  if type(sent) ~= "string" or #sent < 14 then
    return ""
  end
  local api_key = KA.b16s(sent:sub(5, 6))
  local correlation = KA.b32(sent:sub(9, 12))
  if api_key == 18 then
    return KA_MOCK.apiversions_response(cfg, correlation)
  elseif api_key == 3 then
    local n = KA.b32s(sent:sub(24, 27))
    if n == -1 or n == 0 then
      if cfg.wildcard_topics_withheld then
        local body = k_array(cfg.brokers, function(b)
          return k_i32(b[1]) .. k_str(b[2]) .. k_i32(b[3])
        end) .. k_i32(cfg.controller) .. k_i32(0)
        return k_i32(4 + #body) .. k_i32(correlation) .. body
      end
      return KA_MOCK.metadata_response(cfg, correlation)
    end
    local names = {}
    local off = 28
    for _ = 1, n do
      local name, next_off = KA.read_kafka_str(sent, off)
      names[#names + 1] = name
      off = next_off
    end
    if cfg.sasl_required then
      local rows = {}
      for _, name in ipairs(names) do
        rows[#rows + 1] = k_i16(29) .. k_str(name) .. k_i32(0)
      end
      local body = k_array(cfg.brokers, function(b)
        return k_i32(b[1]) .. k_str(b[2]) .. k_i32(b[3])
      end) .. k_i32(cfg.controller) .. k_array(rows, function(r) return r end)
      return k_i32(4 + #body) .. k_i32(correlation) .. body
    end
    local rows = {}
    for _, name in ipairs(names) do
      local matched = nil
      for _, t in ipairs(cfg.topics) do
        if t[1] == name then
          matched = t
          break
        end
      end
      if matched == nil then
        rows[#rows + 1] = k_i16(3) .. k_str(name) .. k_i32(0)
      else
        local parts = k_array(matched[3], function(p)
          return k_i16(p[1]) .. k_i32(p[2]) .. k_i32(p[3]) ..
            k_i32(1) .. k_i32(p[4]) .. k_i32(1) .. k_i32(p[5])
        end)
        rows[#rows + 1] = k_i16(matched[2]) .. k_str(matched[1]) .. parts
      end
    end
    local body = k_array(cfg.brokers, function(b)
      return k_i32(b[1]) .. k_str(b[2]) .. k_i32(b[3])
    end) .. k_i32(cfg.controller) .. k_array(rows, function(r) return r end)
    return k_i32(4 + #body) .. k_i32(correlation) .. body
  elseif api_key == 16 then
    return KA_MOCK.listgroups_response(cfg, correlation)
  elseif api_key == 15 then
    local n = KA.b32s(sent:sub(24, 27))
    local names = {}
    local off = 28
    for _ = 1, math.max(n, 0) do
      local name, next_off = KA.read_kafka_str(sent, off)
      names[#names + 1] = name
      off = next_off
    end
    return KA_MOCK.describegroups_response(cfg, correlation, names)
  elseif api_key == 17 then
    return KA_MOCK.sasl_handshake_response(cfg, correlation)
  elseif api_key == 33 then
    return KA_MOCK.sasl_auth_response(cfg, correlation)
  elseif api_key == 19 then
    local topic, _ = KA.read_kafka_str(sent, 28)
    if cfg.create_allowed and topic ~= nil then
      cfg.topics = cfg.topics or {}
      cfg.topics[#cfg.topics + 1] = { topic, 0, { { 0, 0, 1, 1, 1 } } }
    end
    return KA_MOCK.create_response(cfg, correlation, topic or "?")
  elseif api_key == 20 then
    local n = KA.b32(sent:sub(24, 27))
    local topic, _ = KA.read_kafka_str(sent, 28)
    if cfg.delete_allowed and topic ~= nil and cfg.topics ~= nil then
      for i, t in ipairs(cfg.topics) do
        if t[1] == topic then
          table.remove(cfg.topics, i)
          break
        end
      end
    end
    return KA_MOCK.delete_response(cfg, correlation, topic or "?")
  end
  return ""
end

AMQP_MOCK = {}

AMQP_M_CFG = {
  ["amqp"] = {
    version = "3.12.14",
    anonymous_allowed = true,
    guest_allowed = true,
    vhost_open_ok = true,
  },
  ["amqp-secure"] = {
    version = "3.12.14",
    anonymous_allowed = false,
    guest_allowed = false,
    vhost_open_ok = false,
  },
  ["amqps"] = {
    version = "3.12.14",
    anonymous_allowed = true,
    guest_allowed = true,
    vhost_open_ok = true,
    tls_version = 0x0301,
    cleartext_fallback = true,
  },
  ["amqps-secure"] = {
    version = "3.12.14",
    anonymous_allowed = false,
    guest_allowed = false,
    vhost_open_ok = false,
    tls_version = 0x0303,
    cleartext_fallback = false,
  },
}

function AMQP_MOCK.cfg_of(scenario)
  return AMQP_M_CFG[scenario] or AMQP_M_CFG["amqp"]
end

AMQP_MOCK.frame = function(class_id, method_id, payload)
  return KA.amqp_frame(1, 0, KA.w_i16(class_id) .. KA.w_i16(method_id) .. (payload or ""))
end

function AMQP_MOCK.start_frame(cfg)
  local props = KA.encode_field_table({
    product = "RabbitMQ", version = cfg.version, platform = "Erlang/OTP 26",
    capabilities = "{table}",
  })
  local payload = "\0\x09" .. props ..
    KA.w_i32(13) .. "PLAIN AMQPLAIN" ..
    KA.w_i32(5) .. "en_US"
  return AMQP_MOCK.frame(10, 10, payload)
end

function AMQP_MOCK.handle(scenario, sent, self)
  local cfg = AMQP_MOCK.cfg_of(scenario)
  if type(sent) ~= "string" or #sent < 8 then
    return ""
  end
  if sent:sub(1, 4) == "AMQP" then
    if cfg.cleartext_fallback == false then
      return "\x15\x03\x03\x00\x02\x02\x28"
    end
    self.amqp_stage = 1
    return AMQP_MOCK.start_frame(cfg)
  end
  if sent:byte(1) == 0x16 then
    local v = cfg.tls_version or 0x0303
    local body = KA.w_i16(v) .. string.rep("\0", 32) .. "\0" ..
      KA.w_i16(0x002f) .. "\0" .. string.rep("\0", 36)
    local hs = "\x02" .. string.char(math.floor(#body / 65536) % 256,
      math.floor(#body / 256) % 256, #body % 256) .. body
    return "\x16" .. KA.w_i16(v) .. KA.w_i16(#hs) .. hs
  end
  if sent:byte(1) == 0x41 then
    if cfg.cleartext_fallback then
      self.amqp_stage = 1
      return AMQP_MOCK.start_frame(cfg)
    end
    return "\x15\x03\x03\x00\x02\x02\x28"
  end
  local ftype = sent:byte(1)
  local payload = sent:sub(8, #sent - 1)
  local cls, mid = KA.method_ids(payload)
  if cls == 10 and mid == 11 then
    local ok = KA.parse_start_ok(payload)
    self.amqp_stage = 2
    if not cfg.guest_allowed then
      return AMQP_MOCK.frame(10, 50, KA.w_i16(403) ..
        KA.kafka_str("ACCESS_REFUSED - Login was refused using authentication mechanism PLAIN. For details see the broker logfile.") ..
        KA.w_i16(0) .. KA.w_i16(0))
    end
    return AMQP_MOCK.frame(10, 30, KA.w_i16(2047) .. KA.w_i32(131072) .. KA.w_i16(60))
  elseif cls == 10 and mid == 40 then
    local vhost, _ = KA.read_shortstr(payload, 5)
    if cfg.vhost_open_ok then
      self.amqp_stage = 3
      return AMQP_MOCK.frame(10, 41, KA.kafka_str(""))
    end
    return AMQP_MOCK.frame(10, 50, KA.w_i16(403) ..
      KA.kafka_str("ACCESS_REFUSED - access to vhost '" .. (vhost or "/") .. "' refused for user 'guest'") ..
      KA.w_i16(0) .. KA.w_i16(0))
  elseif cls == 20 and mid == 10 then
    if cfg.vhost_open_ok then
      return AMQP_MOCK.frame(20, 11, KA.kafka_str("\0\0\0\0"))
    end
    return AMQP_MOCK.frame(10, 50, KA.w_i16(504) .. KA.kafka_str("CHANNEL_ERROR") .. KA.w_i16(20) .. KA.w_i16(10))
  elseif cls == 50 and mid == 10 then
    local queue, _ = KA.read_shortstr(payload, 7)
    if cfg.vhost_open_ok then
      return AMQP_MOCK.frame(10, 50, KA.w_i16(404) ..
        KA.kafka_str("NOT_FOUND - no queue '" .. (queue or "?") .. "' in vhost '/'") ..
        KA.w_i16(20) .. KA.w_i16(10))
    end
    return AMQP_MOCK.frame(10, 50, KA.w_i16(403) .. KA.kafka_str("ACCESS_REFUSED") .. KA.w_i16(20) .. KA.w_i16(10))
  elseif cls == 10 and mid == 50 then
    return AMQP_MOCK.frame(10, 51, "")
  end
  return ""
end

MQ_MGMT = {}

MQ_MGMT_CFG = {
  ["mq-mgmt"] = {
    auth_required = false,
    version = "3.12.14",
    node = "rabbit@mq-1",
    overview = {
      management_version = "3.12.14",
      rabbitmq_version = "3.12.14",
      node = "rabbit@mq-1",
      listeners = { { protocol = "amqp", ip_address = "0.0.0.0", port = 5672 },
        { protocol = "http", ip_address = "0.0.0.0", port = 15672 } },
      queue_totals = { messages = 42, messages_ready = 18, messages_unacknowledged = 7 },
      object_totals = { connections = 9, channels = 22, queues = 5, exchanges = 14, consumers = 15 },
    },
    definitions = {
      rabbitmq_version = "3.12.14",
      users = { { name = "mq-admin", tags = "administrator" }, { name = "app-writer", tags = "management" } },
      vhosts = { { name = "/" }, { name = "billing" } },
      permissions = { { user = "mq-admin", vhost = "/" }, { user = "app-writer", vhost = "/" },
        { user = "mq-admin", vhost = "billing" }, { user = "app-writer", vhost = "billing" } },
      queues = { { name = "orders.input", vhost = "/", durable = true },
        { name = "billing.retry", vhost = "billing", durable = true },
        { name = "payments.audit", vhost = "/", durable = true },
        { name = "orders.reject", vhost = "/", durable = false },
        { name = "metrics.pipe", vhost = "/", durable = false } },
      exchanges = { {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {} },
      bindings = { {}, {}, {}, {}, {}, {}, {}, {}, {} },
      policies = { {}, {} },
    },
    queues = {
      { name = "orders.input", vhost = "/", durable = true, auto_delete = false,
        messages = 18, messages_ready = 18, messages_unacknowledged = 0, consumers = 2 },
      { name = "billing.retry", vhost = "billing", durable = true, auto_delete = false,
        messages = 24, messages_ready = 12, messages_unacknowledged = 12, consumers = 0 },
      { name = "payments.audit", vhost = "/", durable = true, auto_delete = false,
        messages = 0, messages_ready = 0, messages_unacknowledged = 0, consumers = 4 },
      { name = "orders.reject", vhost = "/", durable = false, auto_delete = false,
        messages = 0, messages_ready = 0, messages_unacknowledged = 0, consumers = 0 },
      { name = "metrics.pipe", vhost = "/", durable = false, auto_delete = true,
        messages = 3, messages_ready = 3, messages_unacknowledged = 0, consumers = 1 },
    },
  },
  ["mq-mgmt-secure"] = {
    auth_required = true,
  },
}

function MQ_MGMT.cfg_of(scenario)
  return MQ_MGMT_CFG[scenario] or MQ_MGMT_CFG["mq-mgmt"]
end

function MQ_MGMT.json(cfg, key)
  return KA.json_encode(cfg[key])
end

function MQ_MGMT.http_send(scenario, sent, self)
  local cfg = MQ_MGMT.cfg_of(scenario)
  local path = tostring(sent):match("^GET%s+(%S+)")
  if cfg.auth_required then
    return "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"RabbitMQ Management\"\r\n" ..
      "Content-Type: text/plain\r\nContent-Length: 12\r\n\r\nUnauthorized\n"
  end
  if path == nil then
    return "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
  end
  local body
  if path:find("^/api/overview") then
    body = MQ_MGMT.json(cfg, "overview")
  elseif path:find("^/api/definitions") then
    body = MQ_MGMT.json(cfg, "definitions")
  elseif path:find("^/api/queues") then
    body = MQ_MGMT.json(cfg, "queues")
  else
    return "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
  end
  return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-cache\r\n" ..
    "Content-Length: " .. #body .. "\r\n\r\n" .. body
end


SSRF_MOCK = {}

SSRF_M_CFG = {
  ["cloud"] = {
    imdsv2_enforced = false,
    proxy_blocks_metadata = false,
    dns_rebinds = true,
    user_data_present = true,
    cloudinit_present = true,
  },
  ["cloud-secure"] = {
    imdsv2_enforced = true,
    proxy_blocks_metadata = true,
    dns_rebinds = false,
    user_data_present = false,
    cloudinit_present = false,
  },
}

function SSRF_MOCK.cfg_of(scenario)
  return SSRF_M_CFG[scenario] or SSRF_M_CFG["cloud"]
end

SSRF_MOCK.TOKEN = "AQAAAEauAAABAAAAAAAAAAA nse-mock-token"

SSRF_MOCK.resp = function(status, ctype, body, extra)
  local h = "HTTP/1.1 " .. tostring(status) .. " S\r\nServer: mock-imds\r\n" ..
    "Content-Type: " .. (ctype or "text/plain") .. "\r\n" ..
    "Content-Length: " .. #body .. "\r\n"
  for _, line in ipairs(extra or {}) do
    h = h .. line .. "\r\n"
  end
  return h .. "\r\n" .. body
end

SSRF_MOCK.aws_meta_index =
  "ami-id\nami-launch-index\ninstance-id\ninstance-type\nlocal-ipv4\nplacement/\npublic-ipv4\nsecurity-groups\n"

SSRF_MOCK.cred_doc = '{"Code":"Success","LastUpdated":"2026-09-24T10:00:00Z",' ..
  '"Type":"AWS-HMAC","AccessKeyId":"ASIAMOCKKEYEXAMPLE00",' ..
  '"SecretAccessKey":"wJalrXUtnFEMImockSecretK5bEHrExample",' ..
  '"Token":"FwoGZXIvYXdzEBYaHmocktoken","Expiration":"2026-09-24T16:00:00Z"}'

SSRF_MOCK.identity_doc = '{"accountId":"123456789012","architecture":"x86_64",' ..
  '"imageId":"ami-0abc123","instanceId":"i-0abc123def456","instanceType":"m5.large",' ..
  '"region":"eu-west-1","availabilityZone":"eu-west-1a","privateIp":"10.20.0.5"}'

SSRF_MOCK.user_data = '#!/bin/bash\n' ..
  'curl http://169.254.169.254/latest/meta-data/iam/security-credentials/\n' ..
  'export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIfromUserData\n' ..
  'export DB_PASSWORD=hunter2secret\n' ..
  'wget -q https://internal.corp/bootstrap.sh\n'

SSRF_MOCK.cloudinit_log = 'cloud-init[Local] init finished at Fri Sep 24\n' ..
  'Datasource DataSourceEc2Local\n' ..
  'instance-id: i-0abc123def456\n' ..
  'curl -H "X-aws-ec2-metadata-token: AAAAexample" http://169.254.169.254/\n' ..
  '[ERROR] runner failed for module ssh\n'

SSRF_MOCK.gcp_token = '{"access_token":"ya29.mock.GCPTOKEN123","token_type":"Bearer","expires_in":3599}'

SSRF_MOCK.azure_instance = '{"compute":{"subscriptionId":"ea42f556-1111-2222-3333",' ..
  '"vmId":"7c9bmock","resourceGroupName":"prod-rg","location":"westeurope","osType":"Linux"}}'

SSRF_MOCK.azure_token = '{"access_token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Im1vY2sifQ",' ..
  '"client_id":"system-assigned-managed-identity","expires_in":"85999","token_type":"Bearer"}'

SSRF_MOCK.do_meta = '{"droplet_id":3164444,"region":"fra1","hostname":"web1",' ..
  '"public_ipv4":"203.0.113.10","features":{"backups":true,"monitoring":true}}'

SSRF_MOCK.os_meta = '{"uuid":"ec49c10a-1111","project_id":"7b5mock","hostname":"os-node",' ..
  '"availability_zone":"nova","meta":{"launch-index":"0"}}'

SSRF_MOCK.oci_instance = '{"compartmentId":"ocid1.compartment.oc1..aaaaaaamock",' ..
  '"region":"eu-frankfurt-1","canonicalRegionName":"eu-frankfurt-1",' ..
  '"displayName":"app-1","shape":"VM.Standard.A1","agentConfig":{"monitoring":true}}'

SSRF_MOCK.oci_creds = '{"access_token":"oci-mock-token","expires_in":3600,"token_type":"Bearer"}'

SSRF_MOCK.k8s_pods = '{"kind":"PodList","items":[{"metadata":{"name":"web-1","namespace":"default"}}]}'

function SSRF_MOCK.aws_guard(cfg, self, body_fn)
  if cfg.imdsv2_enforced then
    return SSRF_MOCK.resp(401, "text/plain", "")
  end
  return body_fn()
end

function SSRF_MOCK.handle_get(cfg, self, path, headers)
  if path:find("^/latest/api/token") then
    return SSRF_MOCK.resp(405, "text/plain", "")
  end
  if path == "/latest/meta-data/" then
    return SSRF_MOCK.aws_guard(cfg, self, function()
      return SSRF_MOCK.resp(200, "text/plain", SSRF_MOCK.aws_meta_index)
    end)
  end
  if path == "/latest/meta-data/instance-id" then
    return SSRF_MOCK.aws_guard(cfg, self, function()
      return SSRF_MOCK.resp(200, "text/plain", "i-0abc123def456")
    end)
  end
  if path == "/latest/meta-data/iam/security-credentials/" then
    return SSRF_MOCK.aws_guard(cfg, self, function()
      return SSRF_MOCK.resp(200, "text/plain", "app-server-role\nnode-instance-role")
    end)
  end
  if path:find("^/latest/meta%-data/iam/security%-credentials/.+") then
    return SSRF_MOCK.aws_guard(cfg, self, function()
      return SSRF_MOCK.resp(200, "application/json", SSRF_MOCK.cred_doc)
    end)
  end
  if path == "/latest/user-data" then
    if not cfg.user_data_present then
      return SSRF_MOCK.resp(404, "text/plain", "")
    end
    return SSRF_MOCK.aws_guard(cfg, self, function()
      return SSRF_MOCK.resp(200, "text/x-shellscript", SSRF_MOCK.user_data)
    end)
  end
  if path == "/latest/dynamic/instance-identity/document" then
    return SSRF_MOCK.aws_guard(cfg, self, function()
      return SSRF_MOCK.resp(200, "application/json", SSRF_MOCK.identity_doc)
    end)
  end
  if path:find("^/computeMetadata/v1/instance/service%-accounts/default/token") then
    if not headers.flavor then
      return SSRF_MOCK.resp(403, "text/plain", "")
    end
    return SSRF_MOCK.resp(200, "application/json", SSRF_MOCK.gcp_token)
  end
  if path:find("^/computeMetadata/v1") then
    if not headers.flavor then
      return SSRF_MOCK.resp(403, "text/plain", "")
    end
    return SSRF_MOCK.resp(200, "text/plain", "mock-gcp-instance\nprojects/123456789012/zones/europe-west1-b")
  end
  if path:find("^/metadata/identity/oauth2/token") then
    if not headers.azure then
      return SSRF_MOCK.resp(403, "text/plain", "")
    end
    return SSRF_MOCK.resp(200, "application/json", SSRF_MOCK.azure_token)
  end
  if path:find("^/metadata/instance") then
    if not headers.azure then
      return SSRF_MOCK.resp(403, "text/plain", "")
    end
    return SSRF_MOCK.resp(200, "application/json", SSRF_MOCK.azure_instance)
  end
  if path == "/opc/v2/instance/" or path == "/opc/v2/instance" then
    if not headers.oracle then
      return SSRF_MOCK.resp(401, "text/plain", "")
    end
    return SSRF_MOCK.resp(200, "application/json", SSRF_MOCK.oci_instance)
  end
  if path == "/opc/v2/instance/canonicalRegionName" then
    if not headers.oracle then
      return SSRF_MOCK.resp(401, "text/plain", "")
    end
    return SSRF_MOCK.resp(200, "text/plain", "eu-frankfurt-1")
  end
  if path:find("^/opc/v1/instance/auth") then
    return SSRF_MOCK.resp(200, "application/json", SSRF_MOCK.oci_creds)
  end
  if path == "/metadata/v1.json" then
    return SSRF_MOCK.resp(200, "application/json", SSRF_MOCK.do_meta)
  end
  if path:find("^/openstack/latest/meta_data") then
    return SSRF_MOCK.resp(200, "application/json", SSRF_MOCK.os_meta)
  end
  if path == "/cloud-init/output.log" then
    if not cfg.cloudinit_present then
      return SSRF_MOCK.resp(404, "text/plain", "")
    end
    return SSRF_MOCK.resp(200, "text/plain", SSRF_MOCK.cloudinit_log)
  end
  if path:find("^/fetch") then
    local target = path:match("[?&]url=([^&]+)")
    if target == nil then
      return SSRF_MOCK.resp(400, "text/plain", "missing url")
    end
    target = target:gsub("%%%x%x", function(h)
      return string.char(tonumber(h, 16))
    end)
    local ip = target:match("^https?://(%d+%.%d+%.%d+%.%d+)")
    if cfg.proxy_blocks_metadata and ip and SS.is_link_local(ip) then
      return SSRF_MOCK.resp(403, "text/plain", "blocked: link-local target")
    end
    if ip and SS.is_link_local(ip) then
      if target:find("security%-credentials") then
        return SSRF_MOCK.resp(200, "text/plain", "app-server-role\nnode-instance-role")
      end
      if target:find("token") or target:find("identity") then
        return SSRF_MOCK.resp(200, "application/json", SSRF_MOCK.identity_doc)
      end
      return SSRF_MOCK.resp(200, "text/plain", SSRF_MOCK.aws_meta_index)
    end
    if cfg.proxy_blocks_metadata then
      return SSRF_MOCK.resp(200, "text/plain", "external fetch ok")
    end
    if target:find("^https?://kubernetes") or target:find("^https?://10%.96") then
      return SSRF_MOCK.resp(200, "application/json", SSRF_MOCK.k8s_pods)
    end
    return SSRF_MOCK.resp(200, "text/plain", "external fetch ok")
  end
  if path:find("^/resolve") then
    local host = path:match("[?&]host=([^&]+)")
    if cfg.dns_rebinds then
      if self.resolve_count == nil then
        self.resolve_count = 0
      end
      self.resolve_count = self.resolve_count + 1
      if self.resolve_count >= 2 then
        return SSRF_MOCK.resp(200, "application/json",
          '{"A":["169.254.169.254"],"TTL":1}')
      end
    end
    return SSRF_MOCK.resp(200, "application/json", '{"A":["203.0.113.77"],"TTL":300}')
  end
  return SSRF_MOCK.resp(404, "text/plain", "")
end

function SSRF_MOCK.http_send(scenario, sent, self)
  local cfg = SSRF_MOCK.cfg_of(scenario)
  local method, path = tostring(sent):match("^(%u+)%s+(%S+)%s+HTTP")
  if method == nil then
    return ""
  end
  local headers = {}
  for line in tostring(sent):gmatch("([^\r\n]+)") do
    local k, v = line:match("^([%w%-%_]+):%s*(.-)%s*$")
    if k ~= nil then
      headers[k:lower()] = v
    end
  end
  if method == "PUT" and path == "/latest/api/token" then
    return SSRF_MOCK.resp(200, "text/plain", "AQAAAEauAAABmocksessiontoken000000",
      { ["X-aws-ec2-metadata-token-ttl-seconds"] = "21600" })
  end
  if method == "GET" then
    if cfg.imdsv2_enforced and path:find("^/latest/") and not headers["x-aws-ec2-metadata-token"] then
      return SSRF_MOCK.resp(401, "text/plain", "")
    end
    if cfg.imdsv2_enforced and headers["x-aws-ec2-metadata-token"] and path:find("^/latest/meta%-data/$") then
      return SSRF_MOCK.resp(200, "text/plain", SSRF_MOCK.aws_meta_index)
    end
    return SSRF_MOCK.handle_get(cfg, self, path, headers)
  end
  return SSRF_MOCK.resp(400, "text/plain", "")
end


WS_MOCK = {}

WS_M_CFG = {
  ["ws"] = {
    upgrade_ok = true,
    echo_all = true,
    cross_site_ok = true,
    unmasked_ok = true,
    auth_required = false,
    max_frame = 0,
    deflate = true,
    subprotocols = { "chat", "json" },
    stack = "Rocket",
    socketio_sid = "lv_V0iMock",
    chat_echo = true,
    stomp_ok = true,
  },
  ["ws-secure"] = {
    upgrade_ok = true,
    echo_all = false,
    cross_site_ok = false,
    unmasked_ok = false,
    auth_required = true,
    max_frame = 262144,
    deflate = false,
    subprotocols = {},
    stack = "ws (Node.js)",
    socketio_sid = nil,
    chat_echo = false,
    stomp_ok = false,
  },
}

function WS_MOCK.cfg_of(scenario)
  return WS_M_CFG[scenario] or WS_M_CFG["ws"]
end

WS_MOCK.resp = function(status, extra, body)
  local h = "HTTP/1.1 " .. tostring(status) .. " S\r\nServer: mock-ws\r\n"
  for _, line in ipairs(extra or {}) do
    h = h .. line .. "\r\n"
  end
  if body ~= nil then
    h = h .. "Content-Type: application/json\r\nContent-Length: " .. #body .. "\r\n"
  end
  return h .. "\r\n" .. (body or "")
end

WS_MOCK.accept_value = function(key)
  return key .. "-mock-accept"
end

WS_MOCK.accept101 = function(cfg, sent)
  local key = sent:match("Sec%-WebSocket%-Key:%s*([%w%+%/%=]+)")
  local extra = {
    "Upgrade: websocket",
    "Connection: Upgrade",
    "Sec-WebSocket-Accept: " .. WS_MOCK.accept_value(key or "?"),
  }
  if cfg.subprotocols and #cfg.subprotocols > 0 then
    extra[#extra + 1] = "Sec-WebSocket-Protocol: " .. table.concat(cfg.subprotocols, ", ")
  end
  if cfg.deflate then
    extra[#extra + 1] = "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover"
  end
  extra[#extra + 1] = "Server: " .. cfg.stack
  return WS_MOCK.resp(101, extra, nil)
end

WS_MOCK.handle_http = function(cfg, sent, self)
  local method, path = tostring(sent):match("^(%u+)%s+(%S+)%s+HTTP")
  if method == nil then
    return ""
  end
  local headers = {}
  for line in tostring(sent):gmatch("([^\r\n]+)") do
    local k, v = line:match("^([%w%-%_]+):%s*(.-)%s*$")
    if k ~= nil then
      headers[k:lower()] = v
    end
  end
  if headers["upgrade"] ~= nil then
    self.ws_open = true
    self.ws_origin = headers["origin"]
    self.ws_protocols = headers["sec-websocket-protocol"]
    self.ws_masked_client = true
    if not cfg.upgrade_ok then
      return WS_MOCK.resp(403, { "Content-Length: 0" })
    end
    if cfg.auth_required and headers["authorization"] == nil and headers["cookie"] == nil then
      return WS_MOCK.resp(401, { "WWW-Authenticate: Bearer", "Content-Length: 0" })
    end
    if not cfg.cross_site_ok and headers["origin"] ~= nil and
      not headers["origin"]:find("target.corp", 1, true) then
      return WS_MOCK.resp(403, { "X-CSP: origin-denied", "Content-Length: 0" })
    end
    if headers["sec-websocket-key"] == nil then
      return WS_MOCK.resp(400, { "Sec-WebSocket-Version: 13", "Content-Length: 0" })
    end
    return WS_MOCK.accept101(cfg, sent)
  end
  if path:find("^/socket%.io/") then
    if cfg.socketio_sid == nil then
      return WS_MOCK.resp(404, { "Content-Length: 0" })
    end
    local body = '0{"sid":"' .. cfg.socketio_sid .. '","upgrades":["websocket"],' ..
      '"pingInterval":25000,"pingTimeout":20000}'
    return WS_MOCK.resp(200, {}, body)
  end
  if path:find("^/signalr/negotiate") then
    local body = '{"connectionId":"mock-conn","negotiateVersion":1}'
    return WS_MOCK.resp(200, {}, body)
  end
  if path:find("^/cable") then
    local body = '{"type":"welcome"}'
    return WS_MOCK.resp(200, {}, body)
  end
  if path:find("^/graphql") then
    return WS_MOCK.resp(426, { "Sec-WebSocket-Version: 13", "Content-Length: 0" })
  end
  return WS_MOCK.resp(404, { "Content-Length: 0" })
end

WS_MOCK.unmask = function(frame_bytes)
  local f = WSW.parse_frame(frame_bytes)
  return f
end

function WS_MOCK.frames_answer(cfg, self, sent)
  local frames = WSW.parse_frames(sent)
  local answers = {}
  for _, f in ipairs(frames) do
    if f.opcode == 0x9 then
      answers[#answers + 1] = WSW.frame(0xA, f.payload or "", { masked = false })
    elseif f.opcode == 0x8 then
      answers[#answers + 1] = WSW.close_frame(f.close_code or 1000, nil)
    elseif f.opcode == 0x1 or f.opcode == 0x2 then
      if not f.masked and not cfg.unmasked_ok then
        answers[#answers + 1] = WSW.close_frame(1002, "unmasked client frame")
        break
      end
      if f.payload and #f.payload > cfg.max_frame and cfg.max_frame > 0 then
        answers[#answers + 1] = WSW.close_frame(1009, "message too big")
        break
      end
      if f.payload and f.payload:find("^CONNECT") then
        if cfg.stomp_ok then
          answers[#answers + 1] = WSW.frame(0x1, "CONNECTED\nversion:1.2\nheart-beat:0,0\n\n\0", { masked = false })
        else
          answers[#answers + 1] = WSW.close_frame(1008, "stomp refused")
        end
      elseif f.payload and f.payload:find('"command"%s*:%s*"subscribe"') then
        if cfg.chat_echo then
          answers[#answers + 1] = WSW.frame(0x1,
            '{"type":"confirm_subscription","identifier":"' ..
            (f.payload:match('"identifier"%s*:%s*"(.*)"}$') or "") .. '"}', { masked = false })
        else
          answers[#answers + 1] = WSW.close_frame(1008, "policy")
        end
      elseif f.payload and f.payload:find('"type"%s*:%s*"message"') then
        if cfg.chat_echo then
          answers[#answers + 1] = WSW.frame(0x1,
            '{"type":"message","room":"lobby","from":"stranger-7","text":"echo:' ..
            (f.payload:match('"text"%s*:%s*"([^"]*)"') or "") .. '"}', { masked = false })
        else
          answers[#answers + 1] = WSW.close_frame(1008, "policy")
        end
      elseif f.payload and f.payload:find('"query"') then
        answers[#answers + 1] = WSW.frame(0x1,
          '{"type":"next","payload":{"data":null}}', { masked = false })
      elseif cfg.echo_all then
        answers[#answers + 1] = WSW.frame(f.opcode, f.payload or "", { masked = false })
      else
        answers[#answers + 1] = WSW.close_frame(1008, "policy")
      end
    else
      answers[#answers + 1] = WSW.close_frame(1002, "bad opcode")
    end
  end
  return table.concat(answers)
end

function WS_MOCK.tcp_send(scenario, sent, self)
  local cfg = WS_MOCK.cfg_of(scenario)
  if tostring(sent):match("^%u+%s+%S+%s+HTTP") then
    return WS_MOCK.handle_http(cfg, sent, self)
  end
  if sent:byte(1) == 0x16 or sent:byte(1) == 0x15 then
    return "\x15\x03\x03\x00\x02\x02\x28"
  end
  if self.ws_open then
    return WS_MOCK.frames_answer(cfg, self, sent)
  end
  return ""
end

SMTP_MOCK = {}

SMTP_M_CFG = {
  ["smtp"] = {
    hostname = "mail.corp.example.com",
    banner = "220 mail.corp.example.com ESMTP Postfix (Ubuntu)",
    ehlo_lines = { "250-mail.corp.example.com", "250-PIPELINING", "250-SIZE 20480000", "250-STARTTLS", "250 AUTH PLAIN LOGIN" },
    auth_before_tls = true,
    vrfy_state = "disclosure",
    expn_code = 502,
    help_code = 502,
    relay_open = true,
    rcpt_oracle = true,
    null_data_ok = true,
    known_users = { root = true, admin = true, postmaster = true, info = true, sales = true },
    auth_users = { admin = "admin", postmaster = "postmaster" },
    tls_ready = false,
    starttls_code = 220,
  },
  ["smtp-secure"] = {
    hostname = "mail1.corp.example.com",
    banner = "220 mail1.corp.example.com ESMTP Postfix (hardened)",
    ehlo_25 = { "250-mail1.corp.example.com", "250-SIZE 35882577", "250-8BITMIME", "250-ENHANCEDSTATUSCODES", "250-DSN", "250-SMTPUTF8", "250-STARTTLS" },
    ehlo_587 = { "250-mail1.corp.example.com", "250-SIZE 35882577", "250-8BITMIME", "250-ENHANCEDSTATUSCODES", "250-STARTTLS", "250 AUTH PLAIN LOGIN" },
    auth_before_tls = false,
    vrfy_state = "disabled",
    expn_code = 502,
    help_code = 502,
    relay_open = false,
    rcpt_oracle = false,
    null_data_ok = false,
    known_users = { root = true, admin = true, postmaster = true },
    auth_users = {},
    tls_ready = true,
    starttls_code = 220,
  },
}

function SMTP_MOCK.reply(code, text)
  return tostring(code) .. " " .. text .. "\r\n"
end

function SMTP_MOCK.smtp_reply(scenario, sent, sock)
  local cfg = SMTP_M_CFG[scenario]
  if cfg == nil then
    return ""
  end
  local st = sock._smtp
  if st == nil then
    st = { phase = "command", mail_from = nil, mail_null = false, pipelined = 0, in_data = false }
    sock._smtp = st
  end
  local port = sock.connect_port or 25
  if st.in_data then
    local done = false
    for line in string.gmatch(sent, "([^\r\n]+)\r\n") do
      if line == "." then
        done = true
        break
      end
    end
    if done then
      st.in_data = false
      st.mail_from = nil
      st.mail_null = false
      st.pipelined = st.pipelined + 1
      return SMTP_MOCK.reply(250, "2.0.0 Ok: queued as " .. tostring(7000 + st.pipelined * 13) .. "AABB")
    end
    return ""
  end
  local first = string.match(sent, "^([A-Za-z]+)")
  local lines = {}
  for line in string.gmatch(sent, "([^\r\n]+)\r\n") do
    lines[#lines + 1] = line
  end
  local ncmd = #lines
  local out = ""
  local idx = 1
  while idx <= ncmd do
    local line = lines[idx]
    local verb = string.match(line, "^([A-Za-z]+)") or ""
    verb = string.upper(verb)
    local arg = string.match(line, "^[A-Za-z]+[:%s]?(.*)$") or ""
    if verb == "EHLO" then
      local set = (scenario == "smtp-secure" and port == 587) and cfg.ehlo_587
        or (scenario == "smtp-secure") and cfg.ehlo_25 or cfg.ehlo_lines
      for _, l in ipairs(set) do
        out = out .. l .. "\r\n"
      end
    elseif verb == "HELO" then
      out = out .. "250 " .. cfg.hostname .. "\r\n"
    elseif verb == "MAIL" then
      st.mail_from = string.match(arg, "<([^>]*)>") or ""
      st.mail_null = st.mail_from == ""
      if scenario == "smtp-secure" and port == 25 and not st.tls_done then
        out = out .. SMTP_MOCK.reply(530, "5.7.0 Must issue a STARTTLS command first")
      else
        out = out .. SMTP_MOCK.reply(250, "2.1.0 Ok")
      end
    elseif verb == "RCPT" then
      local rcpt = string.match(arg, "<([^>]*)>") or ""
      local user, domain = string.match(rcpt, "([^@]*)@(.*)")
      local local_known = user ~= nil and cfg.known_users[string.lower(user)] == true
      local external = domain ~= nil and domain ~= "corp.example.com"
      if scenario == "smtp" then
        if external then
          out = out .. SMTP_MOCK.reply(250, "2.1.5 Ok (relay accepted)")
        elseif local_known then
          out = out .. SMTP_MOCK.reply(250, "2.1.5 Ok")
        else
          out = out .. SMTP_MOCK.reply(550, "5.1.1 <" .. rcpt .. ">: Recipient address rejected: User unknown in local recipient table")
        end
      else
        if external then
          out = out .. SMTP_MOCK.reply(554, "5.7.1 <" .. rcpt .. ">: Relay access denied")
        else
          out = out .. SMTP_MOCK.reply(550, "5.1.1 <" .. rcpt .. ">: Recipient address rejected: User unknown in local recipient table")
        end
      end
    elseif verb == "DATA" then
      if scenario == "smtp-secure" and st.mail_null then
        out = out .. SMTP_MOCK.reply(554, "5.7.1 Bounce messages rejected by policy")
      else
        out = out .. SMTP_MOCK.reply(354, "End data with <CR><LF>.<CR><LF>")
        st.in_data = true
      end
    elseif line == "." then
      out = out .. SMTP_MOCK.reply(250, "2.0.0 Ok: queued as " .. tostring(7000 + (st.pipelined or 0) * 13) .. "AABB")
      st.pipelined = (st.pipelined or 0) + 1
      st.mail_from = nil
      st.mail_null = false
    elseif verb == "RSET" then
      st.mail_from = nil
      st.mail_null = false
      out = out .. SMTP_MOCK.reply(250, "2.0.0 Ok")
    elseif verb == "VRFY" then
      if cfg.vrfy_state == "disabled" then
        out = out .. SMTP_MOCK.reply(502, "5.5.1 VRFY command is disabled")
      else
        local user = string.lower(arg)
        if cfg.known_users[user] then
          out = out .. SMTP_MOCK.reply(250, "2.1.5 <" .. arg .. "@" .. cfg.hostname .. ">")
        else
          out = out .. SMTP_MOCK.reply(550, "5.1.1 <" .. arg .. ">: User unknown")
        end
      end
    elseif verb == "EXPN" then
      out = out .. SMTP_MOCK.reply(cfg.expn_code, cfg.expn_code == 502 and "5.5.2 EXPN disabled" or "list")
    elseif verb == "HELP" then
      out = out .. SMTP_MOCK.reply(cfg.help_code, "5.5.2 Help not provided")
    elseif verb == "NOOP" then
      out = out .. SMTP_MOCK.reply(250, "2.0.0 Ok")
    elseif verb == "QUIT" then
      out = out .. SMTP_MOCK.reply(221, "2.0.0 Bye")
    elseif verb == "STARTTLS" then
      out = out .. SMTP_MOCK.reply(cfg.starttls_code, "2.0.0 Ready to start TLS")
      st.tls_done = true
      st.phase = "tls"
      return out
    elseif verb == "AUTH" then
      local mech = string.upper(string.match(arg, "^(%S+)") or "")
      local blob = string.match(arg, "^%S+%s+(.*)$") or (lines[idx + 1] or "")
      if not string.find(blob, "=") and mech ~= "LOGIN" and #lines > idx then
      end
      local user = nil
      local pass = nil
      local b64 = string.match(blob, "^([%w%+%/=]+)")
      if mech == "PLAIN" and b64 then
        local raw = SMTP_MOCK.b64d(b64)
        local u, p = string.match(raw, "^%z([^%z]*)%z([^%z]*)$")
        user = u
        pass = p
      elseif mech == "LOGIN" then
        user = SMTP_MOCK.b64d(lines[idx + 1] or "")
        pass = SMTP_MOCK.b64d(lines[idx + 2] or "")
        idx = idx + 2
        out = out .. SMTP_MOCK.reply(334, "VXNlcm5hbWU6") .. SMTP_MOCK.reply(334, "UGFzc3dvcmQ6")
      end
      if user ~= nil and cfg.auth_users[user] ~= nil and cfg.auth_users[user] == pass then
        out = out .. SMTP_MOCK.reply(235, "2.7.0 Authentication successful")
      else
        out = out .. SMTP_MOCK.reply(535, "5.7.8 Error: authentication failed")
      end
    else
      out = out .. SMTP_MOCK.reply(502, "5.5.2 Error: command not recognized")
    end
    idx = idx + 1
  end
  return out
end

function SMTP_MOCK.b64d(data)
  local lookup = {}
  local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  for i = 1, #alphabet do
    lookup[string.sub(alphabet, i, i)] = i - 1
  end
  local clean = string.gsub(data or "", "[^%w%+%/]", "")
  local out = {}
  for i = 1, #clean - 3, 4 do
    local n = (lookup[string.sub(clean, i, i)] or 0) * 262144 + (lookup[string.sub(clean, i + 1, i + 1)] or 0) * 4096
      + (lookup[string.sub(clean, i + 2, i + 2)] or 0) * 64 + (lookup[string.sub(clean, i + 3, i + 3)] or 0)
    out[#out + 1] = string.char(math.floor(n / 65536) % 256, math.floor(n / 256) % 256, n % 256)
  end
  return table.concat(out)
end

function SMTP_MOCK.connect_banner(scenario)
  local cfg = SMTP_M_CFG[scenario]
  if cfg == nil then
    return ""
  end
  return cfg.banner .. "\r\n"
end

KRB_MOCK = {}

KRB_M_CFG = {
  ["kerberos"] = {
    realm = "CORP.EXAMPLE.COM",
    roastable = { ["svc-sql"] = true, ["svc-backup"] = true },
    preauth_users = { ["administrator"] = true, ["krbtgt"] = true, ["dc$"] = true },
    uniform_errors = false,
    weak_etype_ok = true,
    info2_etype = 23,
    skew = 430,
    tgs_rc4 = true,
  },
  ["kerberos-secure"] = {
    realm = "CORP.EXAMPLE.COM",
    roastable = {},
    preauth_users = { ["administrator"] = true, ["krbtgt"] = true, ["dc$"] = true,
      ["svc-sql"] = true, ["svc-backup"] = true },
    uniform_errors = true,
    weak_etype_ok = false,
    info2_etype = 18,
    skew = 0,
    tgs_rc4 = false,
  },
}

function KRB_MOCK.k_tlv(tag, content)
  local n = #content
  local lenb
  if n < 128 then
    lenb = string.char(n)
  elseif n < 256 then
    lenb = string.char(0x81, n)
  else
    lenb = string.char(0x82, math.floor(n / 256), n % 256)
  end
  return string.char(tag) .. lenb .. content
end

function KRB_MOCK.k_int(v)
  if v == 0 then
    return KRB_MOCK.k_tlv(2, "\0")
  end
  local bytes = {}
  local x = v
  while x > 0 do
    table.insert(bytes, 1, x % 256)
    x = math.floor(x / 256)
  end
  if bytes[1] >= 128 then
    table.insert(bytes, 1, 0)
  end
  return KRB_MOCK.k_tlv(2, string.char(table.unpack(bytes)))
end

function KRB_MOCK.k_ctx(n, content)
  return KRB_MOCK.k_tlv(0xA0 + n, content)
end

function KRB_MOCK.k_read_tlv(buf, pos)
  pos = pos or 1
  if pos + 1 > #buf then
    return nil, pos
  end
  local len = string.byte(buf, pos + 1)
  local need = (len == 0x82) and 4 or (len >= 0x80 and 3 or 2)
  if pos + need > #buf then
    return nil, pos
  end
  local tag = string.byte(buf, pos)
  pos = pos + 1
  local len = string.byte(buf, pos)
  pos = pos + 1
  if len == 0x81 then
    len = string.byte(buf, pos)
    pos = pos + 1
  elseif len == 0x82 then
    len = string.byte(buf, pos) * 256 + string.byte(buf, pos + 1)
    pos = pos + 2
  end
  if pos + len - 1 > #buf then
    return nil, pos
  end
  return { tag = tag, content = string.sub(buf, pos, pos + len - 1) }, pos + len
end

function KRB_MOCK.k_children(buf)
  local out = {}
  local pos = 1
  while pos and pos <= #buf do
    local child, nxt = KRB_MOCK.k_read_tlv(buf, pos)
    if child == nil then
      break
    end
    out[#out + 1] = child
    pos = nxt
  end
  return out
end

function KRB_MOCK.k_tagnum(node)
  return node.tag % 32
end

function KRB_MOCK.k_strip(buf)
  if #buf < 5 then
    return buf
  end
  local b1 = string.byte(buf, 1)
  if b1 == 0x6A or b1 == 0x6B or b1 == 0x6C or b1 == 0x6D or b1 == 0x7E or b1 == 0x6E or b1 == 0x6F then
    return buf
  end
  local n = b1 * 16777216 + string.byte(buf, 2) * 65536 + string.byte(buf, 3) * 256 + string.byte(buf, 4)
  if n > 0 and n <= #buf - 4 then
    return string.sub(buf, 5)
  end
  return buf
end

function KRB_MOCK.parse_req(sent)
  local der = KRB_MOCK.k_strip(sent)
  local top = KRB_MOCK.k_read_tlv(der)
  if top == nil then
    return nil
  end
  local req = { msg_type = top.tag - 0x60, etypes = {}, pa_types = {} }
  local body = KRB_MOCK.k_read_tlv(top.content)
  if body == nil then
    return req
  end
  for _, node in ipairs(KRB_MOCK.k_children(body.content)) do
    local tn = KRB_MOCK.k_tagnum(node)
    if tn == 3 then
      local pa_seq = KRB_MOCK.k_read_tlv(node.content)
      if pa_seq then
        for _, pa in ipairs(KRB_MOCK.k_children(pa_seq.content)) do
          local tnode = KRB_MOCK.k_read_tlv(pa.content)
          if tnode and KRB_MOCK.k_tagnum(tnode) == 1 then
            local inner = KRB_MOCK.k_read_tlv(tnode.content)
            if inner then
              local v = 0
              for i = 1, #inner.content do
                v = v * 256 + string.byte(inner.content, i)
              end
              req.pa_types[#req.pa_types + 1] = v
            end
          end
        end
      end
    elseif tn == 4 then
      local bseq = KRB_MOCK.k_read_tlv(node.content)
      if bseq then
        for _, item in ipairs(KRB_MOCK.k_children(bseq.content)) do
          local m = KRB_MOCK.k_tagnum(item)
          if m == 1 then
            local pname = KRB_MOCK.k_read_tlv(item.content)
            if pname then
              for _, c in ipairs(KRB_MOCK.k_children(pname.content)) do
                if KRB_MOCK.k_tagnum(c) == 1 then
                  local strs = KRB_MOCK.k_read_tlv(c.content)
                  if strs then
                    local parts = {}
                    for _, s in ipairs(KRB_MOCK.k_children(strs.content)) do
                      parts[#parts + 1] = s.content
                    end
                    req.cname = table.concat(parts, "/")
                  end
                end
              end
            end
          elseif m == 2 then
            local sfield = KRB_MOCK.k_read_tlv(item.content)
            req.realm = sfield and sfield.content or item.content
          elseif m == 3 then
            local pname = KRB_MOCK.k_read_tlv(item.content)
            if pname then
              for _, c in ipairs(KRB_MOCK.k_children(pname.content)) do
                if KRB_MOCK.k_tagnum(c) == 1 then
                  local strs = KRB_MOCK.k_read_tlv(c.content)
                  if strs then
                    local parts = {}
                    for _, s in ipairs(KRB_MOCK.k_children(strs.content)) do
                      parts[#parts + 1] = s.content
                    end
                    req.sname = table.concat(parts, "/")
                  end
                end
              end
            end
          elseif m == 8 then
            local etseq = KRB_MOCK.k_read_tlv(item.content)
            if etseq then
              for _, e in ipairs(KRB_MOCK.k_children(etseq.content)) do
                local v = 0
                for i = 1, #e.content do
                  v = v * 256 + string.byte(e.content, i)
                end
                req.etypes[#req.etypes + 1] = v
              end
            end
          end
        end
      end
    end
  end
  return req
end

function KRB_MOCK.k_str(s)
  return KRB_MOCK.k_tlv(0x1B, s)
end

function KRB_MOCK.k_padata(ptype, value)
  return KRB_MOCK.k_tlv(0x30, KRB_MOCK.k_ctx(1, KRB_MOCK.k_int(ptype)) .. KRB_MOCK.k_ctx(2, KRB_MOCK.k_tlv(4, value)))
end

function KRB_MOCK.k_etype_info2(etype, salt)
  local inner = KRB_MOCK.k_ctx(0, KRB_MOCK.k_int(etype)) .. KRB_MOCK.k_ctx(1, KRB_MOCK.k_str(salt or ""))
  return KRB_MOCK.k_padata(19, KRB_MOCK.k_tlv(0x30, inner))
end

function KRB_MOCK.error_reply(cfg, code, etext, padata)
  local body = KRB_MOCK.k_int(5) .. KRB_MOCK.k_int(30)
  body = body .. KRB_MOCK.k_ctx(4, KRB_MOCK.k_int(os.time() + (cfg.skew or 0)))
  body = body .. KRB_MOCK.k_ctx(6, KRB_MOCK.k_int(code))
  body = body .. KRB_MOCK.k_ctx(9, KRB_MOCK.k_str(cfg.realm))
  if etext then
    body = body .. KRB_MOCK.k_ctx(11, KRB_MOCK.k_str(etext))
  end
  if padata and #padata > 0 then
    body = body .. KRB_MOCK.k_ctx(12, KRB_MOCK.k_tlv(0x30, table.concat(padata)))
  end
  return KRB_MOCK.k_tlv(0x7E, KRB_MOCK.k_tlv(0x30, body))
end

function KRB_MOCK.as_rep(cfg, cname)
  local ticket = KRB_MOCK.k_tlv(0x30, KRB_MOCK.k_int(2) .. KRB_MOCK.k_ctx(1, KRB_MOCK.k_tlv(0x30, KRB_MOCK.k_int(2) .. KRB_MOCK.k_tlv(0x30, KRB_MOCK.k_str("krbtgt/" .. cfg.realm))))
    .. KRB_MOCK.k_ctx(3, KRB_MOCK.k_tlv(0x30, KRB_MOCK.k_ctx(0, KRB_MOCK.k_int(23)) .. KRB_MOCK.k_ctx(2, KRB_MOCK.k_tlv(4, "PACPACGET"))))) 
  local enc = KRB_MOCK.k_ctx(3, KRB_MOCK.k_tlv(0x30, KRB_MOCK.k_ctx(0, KRB_MOCK.k_int(23)) .. KRB_MOCK.k_ctx(2, KRB_MOCK.k_tlv(4, string.rep("K", 16)))))
  local body = KRB_MOCK.k_ctx(0, KRB_MOCK.k_str(cfg.realm)) .. KRB_MOCK.k_ctx(1, KRB_MOCK.k_tlv(0x30, KRB_MOCK.k_int(1) .. KRB_MOCK.k_tlv(0x30, KRB_MOCK.k_str(cname))))
    .. KRB_MOCK.k_ctx(2, ticket) .. enc
  return KRB_MOCK.k_tlv(0x6B, KRB_MOCK.k_tlv(0x30, body))
end

function KRB_MOCK.tgs_rep(cfg, sname)
  local ticket = KRB_MOCK.k_tlv(0x30, KRB_MOCK.k_int(2) .. KRB_MOCK.k_ctx(1, KRB_MOCK.k_tlv(0x30, KRB_MOCK.k_int(3) .. KRB_MOCK.k_tlv(0x30, KRB_MOCK.k_str(sname or "cifs/dc"))))
    .. KRB_MOCK.k_ctx(3, KRB_MOCK.k_tlv(0x30, KRB_MOCK.k_ctx(0, KRB_MOCK.k_int(23)) .. KRB_MOCK.k_ctx(2, KRB_MOCK.k_tlv(4, "SRVTKT")))))
  local body = KRB_MOCK.k_ctx(2, ticket) .. KRB_MOCK.k_ctx(3, KRB_MOCK.k_tlv(0x30, KRB_MOCK.k_ctx(0, KRB_MOCK.k_int(23)) .. KRB_MOCK.k_ctx(2, KRB_MOCK.k_tlv(4, string.rep("T", 16)))))
  return KRB_MOCK.k_tlv(0x6D, KRB_MOCK.k_tlv(0x30, body))
end

function KRB_MOCK.krb_reply(scenario, sent)
  local cfg = KRB_M_CFG[scenario]
  if cfg == nil then
    return ""
  end
  local der = KRB_MOCK.k_strip(sent)
  local b1 = string.byte(der, 1) or 0
  if b1 == 0xFF then
    return KRB_MOCK.error_reply(cfg, 3, "kpasswd version header accepted")
  end
  local req = KRB_MOCK.parse_req(sent)
  if req == nil then
    return ""
  end
  if req.msg_type == 14 or b1 == 0x6E then
    return KRB_MOCK.error_reply(cfg, 3, "kpasswd AP-REQ accepted")
  end
  local has_ts_pa = false
  local has_fast_pa = false
  local has_pkinit_pa = false
  for _, t in ipairs(req.pa_types or {}) do
    if t == 2 then
      has_ts_pa = true
    elseif t == 136 then
      has_fast_pa = true
    elseif t == 16 then
      has_pkinit_pa = true
    end
  end
  local realm_ok = req.realm == nil or string.upper(req.realm) == cfg.realm
  if not realm_ok then
    return KRB_MOCK.error_reply(cfg, 68, "KDC_ERR_WRONG_REALM")
  end
  if has_ts_pa then
    return KRB_MOCK.error_reply(cfg, 37, "KRB_AP_ERR_SKEW")
  end
  if has_fast_pa then
    if cfg.weak_etype_ok then
      return KRB_MOCK.error_reply(cfg, 14, "KDC_ERR_PADATA_TYPE_NOSUPP: FAST not supported")
    end
    return KRB_MOCK.error_reply(cfg, 23, "PREAUTH REQUIRED",
      { KRB_MOCK.k_etype_info2(18, cfg.realm .. "administrator"), KRB_MOCK.k_padata(133, "FAST-COOKIE-01") })
  end
  local anon = string.lower(req.cname or "")
  if anon == "wellknown/anonymous" then
    if not has_pkinit_pa or cfg.weak_etype_ok then
      return KRB_MOCK.error_reply(cfg, 14, "KDC_ERR_PADATA_TYPE_NOSUPP: anonymous PKINIT not supported")
    end
    return KRB_MOCK.as_rep(cfg, "WELLKNOWN/ANONYMOUS")
  end
  if req.msg_type == 12 then
    if cfg.tgs_rc4 then
      return KRB_MOCK.tgs_rep(cfg, req.sname)
    end
    return KRB_MOCK.error_reply(cfg, 11, "KDC_ERR_BADOPTION: TGT required for service tickets")
  end
  local weak_only = true
  for _, e in ipairs(req.etypes or {}) do
    if e == 17 or e == 18 or e == 24 or e == 25 then
      weak_only = false
    end
  end
  if weak_only and not cfg.weak_etype_ok then
    return KRB_MOCK.error_reply(cfg, 12, "KDC_ERR_ETYPE_NOTSUPP: weak etypes rejected")
  end
  local cname = string.lower(req.cname or "")
  if cname == "" or cname == "wellknown/anonymous" then
    return KRB_MOCK.error_reply(cfg, 4, "Client not found in Kerberos database")
  end
  if cfg.roastable[cname] then
    return KRB_MOCK.as_rep(cfg, req.cname)
  end
  if cfg.preauth_users[cname] then
    local pa = { KRB_MOCK.k_etype_info2(cfg.info2_etype, cfg.realm .. req.cname) }
    if not cfg.weak_etype_ok then
      pa[#pa + 1] = KRB_MOCK.k_padata(149, "ENC-PA-REP-SUPPORTED")
    end
    return KRB_MOCK.error_reply(cfg, 23, "PREAUTH REQUIRED", pa)
  end
  if cfg.uniform_errors then
    return KRB_MOCK.error_reply(cfg, 4, "Client not found in Kerberos database")
  end
  return KRB_MOCK.error_reply(cfg, 4, "Client not found in Kerberos database")
end

TELNET_MOCK = {}

TEL_FAIL_COUNT = 0
TEL_CONN_SEQ = 0

local TEL_M_CFG = {
  ["telnet"] = {
    echo = true,
    auth_required = false,
    encrypt = false,
    env_leak = true,
    ttype_query = true,
    lock_after = nil,
    refuse_after = nil,
    user_prompt = "login: ",
    banner = "\r\nNPort 5650-8-DT Terminal Server\r\nFirmware F3.2 Build 20200813\r\nBusyBox v1.20.2 (2020-07-31) built-in shell\r\n\r\nlogin: ",
    flight = string.char(255, 251, 1) .. string.char(255, 253, 3) .. string.char(255, 251, 3)
      .. string.char(255, 253, 31) .. string.char(255, 250, 24, 1) .. string.char(255, 240),
    success_banner = "\r\nNPort admin shell ready\r\nNPort> ",
    fail_banner = "\r\nLogin incorrect\r\n\r\nlogin: ",
    password_prompt = "Password: ",
    secureauth = nil,
  },
  ["telnet-secure"] = {
    echo = false,
    auth_required = true,
    encrypt = true,
    env_leak = false,
    ttype_query = false,
    lock_after = nil,
    refuse_after = 3,
    user_prompt = "login: ",
    banner = "\r\nAuthorized Users Only\r\nLeapOS 9.1 secure terminal service\r\n\r\nlogin: ",
    flight = string.char(255, 253, 37) .. string.char(255, 251, 37)
      .. string.char(255, 250, 37, 1, 2, 1) .. string.char(255, 240)
      .. string.char(255, 251, 38) .. string.char(255, 253, 3) .. string.char(255, 251, 3),
    success_banner = nil,
    fail_banner = nil,
    password_prompt = nil,
    secureauth = "\r\nSECUREAUTH required. Disconnecting.\r\n",
  },
}

function TELNET_MOCK.connect_flight(scenario)
  local cfg = TEL_M_CFG[scenario]
  if cfg == nil then
    return ""
  end
  if cfg.refuse_after ~= nil and TEL_CONN_SEQ > cfg.refuse_after then
    return ""
  end
  return cfg.flight .. cfg.banner
end

function TELNET_MOCK.parse_sent(sent)
  local out = { lines = {}, cmds = {} }
  local text = {}
  local pos = 1
  local n = #sent
  while pos <= n do
    local b = sent:byte(pos)
    if b ~= 255 then
      text[#text + 1] = sent:sub(pos, pos)
      pos = pos + 1
    else
      local cmd = sent:byte(pos + 1)
      if cmd == nil then
        break
      end
      if cmd == 255 then
        text[#text + 1] = "\255"
        pos = pos + 2
      elseif cmd == 250 then
        local opt = sent:byte(pos + 2)
        local inner = pos + 3
        local payload = {}
        while inner <= n do
          local ib = sent:byte(inner)
          if ib == 255 then
            local nb = sent:byte(inner + 1)
            if nb == 240 then
              inner = inner + 1
              break
            elseif nb == 255 then
              payload[#payload + 1] = "\255"
              inner = inner + 2
            else
              payload[#payload + 1] = "\255"
              inner = inner + 1
            end
          else
            payload[#payload + 1] = sent:sub(inner, inner)
            inner = inner + 1
          end
        end
        out.cmds[#out.cmds + 1] = { kind = "SB", opt = opt, payload = table.concat(payload, "") }
        pos = inner + 1
      elseif cmd >= 251 and cmd <= 254 then
        local kinds = { [251] = "WILL", [252] = "WONT", [253] = "DO", [254] = "DONT" }
        out.cmds[#out.cmds + 1] = { kind = kinds[cmd], opt = sent:byte(pos + 2) }
        pos = pos + 3
      else
        out.cmds[#out.cmds + 1] = { kind = "CMD", opt = cmd }
        pos = pos + 2
      end
    end
  end
  local full = table.concat(text, "")
  for line in full:gmatch("[^\r\n]+") do
    out.lines[#out.lines + 1] = line
  end
  return out
end

function TELNET_MOCK.sb_bytes(option, payload)
  return string.char(255, 250, option) .. payload .. string.char(255, 240)
end

function TELNET_MOCK.reply_commands(cfg, sent, sock)
  local replies = {}
  local env_reply = nil
  for _, cmd in ipairs(TELNET_MOCK.parse_sent(sent).cmds) do
    if cmd.kind == "DO" then
      if cmd.opt == 3 or (cmd.opt == 1 and cfg.echo) then
        replies[#replies + 1] = string.char(255, 251, cmd.opt)
      elseif cmd.opt == 38 and cfg.encrypt then
        replies[#replies + 1] = string.char(255, 251, 38)
          .. TELNET_MOCK.sb_bytes(38, string.char(1, 3, 4))
      elseif cfg.auth_required and cmd.opt == 37 then
        replies[#replies + 1] = string.char(255, 251, 37)
      else
        replies[#replies + 1] = string.char(255, 252, cmd.opt)
      end
    elseif cmd.kind == "WILL" then
      if cmd.opt == 3 then
        replies[#replies + 1] = string.char(255, 253, 3)
      else
        replies[#replies + 1] = string.char(255, 254, cmd.opt)
      end
    elseif cmd.kind == "SB" then
      if cmd.opt == 39 and cfg.env_leak and cmd.payload:byte(1) == 1 then
        env_reply = TELNET_MOCK.sb_bytes(39, string.char(0)
          .. string.char(3) .. "USER" .. string.char(4) .. "admin"
          .. string.char(3) .. "HOME" .. string.char(4) .. "/root"
          .. string.char(3) .. "PATH" .. string.char(4) .. "/bin:/sbin"
          .. string.char(3) .. "SHELL" .. string.char(4) .. "/bin/sh")
      end
      if cmd.opt == 24 and cfg.ttype_query and cmd.payload:byte(1) == 0 then
        replies[#replies + 1] = TELNET_MOCK.sb_bytes(24, string.char(0) .. "XTERM")
      end
    elseif cmd.kind == "CMD" and cmd.opt == 246 then
      replies[#replies + 1] = "\r\n[Yes]\r\n"
    end
  end
  return table.concat(replies, ""), env_reply
end

function TELNET_MOCK.telnet_reply(scenario, sent, sock)
  local cfg = TEL_M_CFG[scenario]
  if cfg == nil or sent == nil or #sent == 0 then
    return ""
  end
  if sock._tel == nil then
    sock._tel = { phase = "await_user", user = nil }
  end
  if cfg.refuse_after ~= nil and sock._vnc_seq == nil and TEL_CONN_SEQ > cfg.refuse_after then
    return ""
  end
  local replies, env_reply = TELNET_MOCK.reply_commands(cfg, sent, sock)
  local parsed = TELNET_MOCK.parse_sent(sent)
  local out = replies
  if env_reply ~= nil then
    out = out .. env_reply
  end
  for _, line in ipairs(parsed.lines) do
    if sock._tel.phase == "await_user" then
      if cfg.secureauth ~= nil then
        out = out .. cfg.secureauth
        sock._tel.phase = "closed"
        sock.buffer = ""
        return out
      end
      sock._tel.user = line
      sock._tel.phase = "await_pass"
      out = out .. "\r\n" .. cfg.password_prompt
    elseif sock._tel.phase == "await_pass" then
      if cfg.lock_after ~= nil and TEL_FAIL_COUNT >= cfg.lock_after then
        out = out .. "\r\nAccount locked. Disconnecting.\r\n"
        sock._tel.phase = "closed"
        sock.buffer = ""
        return out
      end
      if sock._tel.user == "admin" and line == "admin" then
        out = out .. cfg.success_banner
        sock._tel.phase = "shell"
      else
        TEL_FAIL_COUNT = TEL_FAIL_COUNT + 1
        out = out .. cfg.fail_banner
        sock._tel.phase = "await_user"
      end
    end
  end
  return out
end

function run_script(code, chunkname, scenario, banner, port_number, port_service, port_ssl, script_args)
  SCENARIO = scenario or "plain"
  BANNER = banner
  PORT_NUMBER = port_number or 80
  PORT_SERVICE = port_service or "http"
  PORT_SSL = port_ssl or false
  SCRIPT_ARGS = to_lua_table(script_args)

  reset_sandbox()

  local chunk, err = load(code, chunkname, "t")
  if not chunk then
    return nil, "LOAD ERROR: " .. tostring(err), SOCKET_LOG
  end

  local ok, run_err = pcall(chunk)
  if not ok then
    return nil, "RUN ERROR: " .. tostring(run_err), SOCKET_LOG
  end

  local host = {
    ip = "192.0.2.10",
    name = "target.example.com",
    targetname = "target.example.com",
    registry = {},
  }
  local port = {
    number = PORT_NUMBER,
    protocol = "tcp",
    state = "open",
    service = PORT_SERVICE,
    ssl = PORT_SSL,
    version = { name = PORT_SERVICE, product = "Apache", version = "2.4.49" },
  }

  if type(portrule) == "function" then
    local rule_ok, rule_res = pcall(portrule, host, port)
    if not rule_ok then
      return nil, "PORTRULE ERROR: " .. tostring(rule_res), SOCKET_LOG
    end
    if not rule_res then
      return nil, "PORTRULE rejected the synthetic target", SOCKET_LOG
    end
  end

  if type(action) ~= "function" then
    return nil, "NO ACTION FUNCTION", SOCKET_LOG
  end

  local action_ok, result = pcall(action, host, port)
  if not action_ok then
    return nil, "ACTION ERROR: " .. tostring(result), SOCKET_LOG
  end

  return render_output(result), nil, SOCKET_LOG
end
"""
