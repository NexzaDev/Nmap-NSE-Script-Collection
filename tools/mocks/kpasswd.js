"use strict";
/*
 * tools/mocks/kpasswd.js
 * ---------------------------------------------------------------------------
 * A scenario driven mock of the Kerberos password-change service (RFC 3244) on
 * port 464.
 *
 * The mock is deliberately independent of the Lua code under test: it decodes
 * the two byte length prefix, the Kerberos message type and, for a change
 * request, the version field of the KRB-PRIV payload with its own parser. That
 * is what makes a scenario an assertion about the wire rather than about the
 * script's own view of the wire.
 *
 * Scenario knobs
 *   version                      0xff80 by default; a request carrying any
 *                                other value is answered with BAD_VERSION (6)
 *   acceptsUnauthenticatedChange false -> KRB5_KPASSWD_AUTHERROR (3);
 *                                true  -> KRB5_KPASSWD_SUCCESS (0), which is
 *                                the service defect the script must catch
 *   apRep                        false -> a synthetic AP-REQ is refused with
 *                                KRB-ERROR 31 (KRB_AP_ERR_BAD_INTEGRITY);
 *                                true  -> an AP-REP is returned instead
 *   apErrorCode                  override the KRB-ERROR code (default 31)
 *   tcpOnly / udpOnly            answer one transport only
 *   dropFirst                    drop the first N messages (timeout/retry)
 *   silent                       never answer
 *   noFraming                    answer without the two byte length prefix
 *   badPrefix                    declare a length that is not what follows
 *   malformedAnswer              answer with bytes that are not ASN.1
 *   changeNoAnswer               answer AP-REQs but drop change requests
 */

const { der } = require("./kdc");

const STATE = { requests: [], messages: [], drops: 0, tcpRequests: 0, udpRequests: 0, protocolErrors: [] };

function tlv(tag, body) {
  if (body.length < 0x80) return Buffer.concat([Buffer.from([tag, body.length]), body]);
  const bytes = [];
  let len = body.length;
  while (len > 0) { bytes.unshift(len & 0xFF); len >>= 8; }
  return Buffer.concat([Buffer.from([tag, 0x80 | bytes.length, ...bytes]), body]);
}

// The reply to a change request: KRB-PRIV with an encrypted part whose first
// bytes carry the version, the length and then the result code.
function kpasswdReply(version, code) {
  const blob = Buffer.alloc(6);
  blob.writeUInt16BE(version, 0);
  blob.writeUInt16BE(2, 2);
  blob.writeUInt16BE(code, 4);
  return der.app(21, der.sequence(
    der.ctx(0, der.integer(5)),
    der.ctx(1, der.integer(21)),
    der.ctx(3, der.sequence(
      der.ctx(0, der.integer(18)),
      der.ctx(1, der.integer(2)),
      der.ctx(2, der.octetstring(blob)),
    )),
  ));
}

function apRep() {
  return der.app(15, der.sequence(
    der.ctx(0, der.integer(5)),
    der.ctx(1, der.integer(15)),
    der.ctx(2, der.sequence(
      der.ctx(0, der.integer(18)),
      der.ctx(1, der.integer(2)),
      der.ctx(2, der.octetstring(Buffer.alloc(32, 0x5a))),
    )),
  ));
}

function krbError(code, eText) {
  return der.app(30, der.sequence(
    der.ctx(0, der.integer(5)),
    der.ctx(1, der.integer(30)),
    der.ctx(4, der.integer(0)),
    der.ctx(5, der.integer(code)),
    der.ctx(8, der.generalstring("EXAMPLE.COM")),
    der.ctx(10, der.generalstring(eText || "probe refused")),
  ));
}

// Walk to the cipher of a KRB-PRIV's EncryptedData without re-implementing the
// whole ASN.1 module: the structure is fixed, so a small reader is enough and
// it keeps the mock honest about what it can and cannot see.
function readPrivVersion(buf) {
  const marker = Buffer.from([0x04]);
  for (let i = 0; i < buf.length - 8; i++) {
    if (buf[i] !== 0x04) continue;
    const declared = buf[i + 1];
    if (declared < 6 || declared > 0x40) continue;
    const version = buf.readUInt16BE(i + 2);
    if (version === 0xff80 || version === 0xff81) return version;
  }
  return null;
}

function createMockKpasswd(scenario) {
  scenario = scenario || {};
  const state = Object.assign({}, STATE, {
    requests: [], messages: [], drops: 0, tcpRequests: 0, udpRequests: 0, protocolErrors: [],
  });

  function frame(raw, proto) {
    if (!raw) return null;
    if (scenario.noFraming) return raw;
    const header = Buffer.alloc(2);
    header.writeUInt16BE(scenario.badPrefix ? raw.length + 7 : raw.length, 0);
    return Buffer.concat([header, raw]);
  }

  function handle(payload, proto) {
    state.requests.push({ proto, bytes: payload.length, at: Date.now() });
    if (proto === "udp") state.udpRequests += 1; else state.tcpRequests += 1;

    if (payload.length < 2) {
      state.protocolErrors.push("message shorter than the two byte length prefix");
      return { raw: null };
    }
    const declared = payload.readUInt16BE(0);
    const body = payload.subarray(2);
    if (declared !== body.length) {
      state.protocolErrors.push(`length prefix declares ${declared} byte(s), ${body.length} followed`);
      return { raw: null };
    }

    if (scenario.dropFirst && state.drops < scenario.dropFirst) {
      state.drops += 1;
      return null;
    }
    if (scenario.silent) return null;
    if (scenario.tcpOnly && proto === "udp") return null;
    if (scenario.udpOnly && proto === "tcp") return null;

    const first = body[0];
    if (first === 0x6e || first === 0x6a || first === 0x6c) {
      // AP-REQ (application 14, 0x6e) or an AS/TGS request on the wrong port.
      state.messages.push({ type: "ap_req", proto, ticketBytes: body.length - 20 });
      if (scenario.apRep) return { raw: frame(apRep(), proto) };
      if (scenario.malformedAnswer) return { raw: frame(Buffer.from([0x00, 0x01, 0x02, 0x03]), proto) };
      return { raw: frame(krbError(scenario.apErrorCode || 31, "KRB_AP_ERR_BAD_INTEGRITY"), proto) };
    }
    if (first === 0x75) {
      // KRB-PRIV (application 21).
      const version = readPrivVersion(body);
      state.messages.push({ type: "krb_priv", proto, version });
      if (scenario.changeNoAnswer) return null;
      if (scenario.malformedAnswer) return { raw: frame(Buffer.from([0x00, 0x01, 0x02, 0x03]), proto) };
      const expected = scenario.version !== undefined ? scenario.version : 0xff80;
      if (version !== expected) {
        return { raw: frame(kpasswdReply(version === null ? 0 : version, 6), proto) };
      }
      const code = scenario.acceptsUnauthenticatedChange ? 0 : 3;
      return { raw: frame(kpasswdReply(expected, code), proto) };
    }

    state.protocolErrors.push(`unexpected message tag 0x${first.toString(16)}`);
    return { raw: frame(krbError(31, "unexpected message"), proto) };
  }

  return { handle, state };
}

module.exports = { createMockKpasswd, readPrivVersion, kpasswdReply };
