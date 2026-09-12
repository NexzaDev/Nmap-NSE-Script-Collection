"use strict";
/*
 * tools/mocks/kdc.js
 * ---------------------------------------------------------------------------
 * A scenario driven mock Kerberos KDC used by tools/nse-sim.js.
 *
 * It is deliberately written as an *independent* ASN.1 implementation: the
 * encoder/parser below shares no code with the NSE scripts under test, so a
 * mistake in a script's DER encoder cannot be mirrored by a matching mistake
 * in the mock. If the script produces malformed ASN.1 the mock will say so.
 *
 * Behaviour is driven by a scenario object:
 *   {
 *     realm: "EXAMPLE.COM",
 *     accounts: {
 *       "svc-backup": { preauth: false, etype: 23, kvno: 2 },
 *       "jsmith":     { preauth: true,  etypes: [18, 17], salt: "EXAMPLE.COM" },
 *       "locked":     { state: "disabled" }
 *     },
 *     unknownAccounts: true,        // answer unknown principals with error 6
 *     leakRealm: true,              // answer foreign realms with error 68 + the real realm
 *     tcpOnly: false,               // refuse UDP (simulates a truncated/dropped path)
 *     dropFirst: 0,                 // drop the first N datagrams (timeout/retry tests)
 *     errorCode: null               // force a specific KRB-ERROR for every request
 *   }
 */

const CLASS_UNIVERSAL = 0, CLASS_APPLICATION = 1, CLASS_CONTEXT = 2;

// Tag *numbers* (the low five bits) are what the parser exposes; the full tag
// byte is only used when encoding.
const TAG_INTEGER = 0x02;
const TAG_BITSTRING = 0x03;
const TAG_OCTETSTRING = 0x04;
const TAG_SEQUENCE = 0x10;           // universal 16, tag byte 0x30
const TAG_GENERALSTRING = 0x1B & 0x1F; // 27, tag byte 0x1B
const TAG_GENERALIZEDTIME = 0x18 & 0x1F; // 24, tag byte 0x18

const BYTE_INTEGER = 0x02, BYTE_BITSTRING = 0x03, BYTE_OCTETSTRING = 0x04;
const BYTE_SEQUENCE = 0x30, BYTE_GENERALSTRING = 0x1B, BYTE_GENERALIZEDTIME = 0x18;

function derLen(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  let v = n;
  while (v > 0) { bytes.unshift(v & 0xFF); v = Math.floor(v / 256); }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag, content) {
  if (!Buffer.isBuffer(content)) content = Buffer.from(content, "binary");
  return Buffer.concat([Buffer.from([tag]), derLen(content.length), content]);
}

const der = {
  integer(value) {
    if (value === 0) return tlv(BYTE_INTEGER, Buffer.from([0]));
    const bytes = [];
    let v = value;
    while (v > 0) { bytes.unshift(v & 0xFF); v = Math.floor(v / 256); }
    if (bytes[0] & 0x80) bytes.unshift(0);
    return tlv(BYTE_INTEGER, Buffer.from(bytes));
  },
  bitstring(mask, bits = 32) {
    const nbytes = Math.ceil(bits / 8);
    const bytes = [0];
    for (let i = 0; i < nbytes; i++) {
      const shift = (nbytes - 1 - i) * 8;
      bytes.push(Math.floor(mask / 2 ** shift) & 0xFF);
    }
    return tlv(BYTE_BITSTRING, Buffer.from(bytes));
  },
  octetstring(value) {
    return tlv(BYTE_OCTETSTRING, Buffer.isBuffer(value) ? value : Buffer.from(value, "binary"));
  },
  generalstring(value) { return tlv(BYTE_GENERALSTRING, Buffer.from(value, "ascii")); },
  generalizedtime(value) { return tlv(BYTE_GENERALIZEDTIME, Buffer.from(value, "ascii")); },
  sequence(...parts) { return tlv(BYTE_SEQUENCE, Buffer.concat(parts.map((p) => Buffer.from(p)))); },
  app(num, ...parts) { return tlv(0x60 + num, Buffer.concat(parts.map((p) => Buffer.from(p)))); },
  ctx(num, inner) { return tlv(0xA0 + num, Buffer.from(inner)); },
};

function parseDer(buf, pos = 0) {
  const tag = buf[pos];
  pos += 1;
  const cls = (tag & 0xC0) >> 6;
  const cons = (tag & 0x20) !== 0;
  const num = tag & 0x1F;
  let len = buf[pos];
  pos += 1;
  if (len & 0x80) {
    const n = len & 0x7F;
    len = 0;
    for (let i = 0; i < n; i++) { len = len * 256 + buf[pos]; pos += 1; }
  }
  const value = buf.subarray(pos, pos + len);
  const node = { cls, cons, num, value, children: [], next: pos + len };
  if (cons) {
    let p = pos;
    while (p < pos + len) {
      const child = parseDer(buf, p);
      node.children.push(child);
      p = child.next;
    }
  }
  return node;
}

function child(node, cls, num) {
  for (const c of node.children || []) if (c.cls === cls && c.num === num) return c;
  return null;
}

// Field access that accepts explicit tagging (context wrapper around the TLV)
// and implicit tagging (context tag replacing the universal tag).
function field(node, num) {
  const f = child(node, CLASS_CONTEXT, num);
  if (!f) return null;
  if (f.cons && f.children.length === 1) return f.children[0];
  return { cls: CLASS_UNIVERSAL, cons: false, num: null, value: f.value, children: [], implicit: true };
}

function intVal(node) {
  if (!node) return null;
  let v = 0;
  for (const b of node.value) v = v * 256 + b;
  return v;
}

function strVal(node) { return node ? Buffer.from(node.value).toString("binary") : null; }

// PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string [1] SEQUENCE OF KerberosString }
// The inner fields may be explicitly or implicitly tagged, and the SEQUENCE OF
// KerberosString often arrives as a plain universal SEQUENCE.
function principal(node) {
  let seq = node;
  if (!seq) return null;
  if (seq.cls === CLASS_CONTEXT && seq.cons && seq.children && seq.children.length === 1) {
    seq = seq.children[0];
  }
  if (!seq || !seq.children) return null;

  const names = [];
  const collect = (container) => {
    if (!container || !container.children) return;
    for (const c of container.children) {
      if (c.cons && c.children && c.children.length) collect(c);
      else if (c.value && c.value.length) names.push(Buffer.from(c.value).toString("binary"));
    }
  };
  for (const child of seq.children) {
    if (!child.cons) continue; // the name-type INTEGER
    collect(child);
  }
  return names.join("/");
}

function parseAsReq(buf) {
  if (buf[0] !== 0x6A) return { error: `expected [APPLICATION 10] AS-REQ, got 0x${buf[0].toString(16)}` };
  const root = parseDer(buf);
  if (!root.children.length) return { error: "AS-REQ has no body" };
  const body = root.children[0].num === TAG_SEQUENCE ? root.children[0] : root;
  const reqBodyWrapper = field(body, 4);
  if (!reqBodyWrapper) return { error: "AS-REQ without req-body [4]" };
  const reqBody = reqBodyWrapper.cons && reqBodyWrapper.children.length === 1
    ? reqBodyWrapper.children[0] : reqBodyWrapper;

  const out = {
    pvno: intVal(field(body, 1)),
    msgType: intVal(field(body, 2)),
    realm: strVal(field(reqBody, 2)),
    cname: principal(field(reqBody, 1)),
    sname: principal(field(reqBody, 3)),
    nonce: intVal(field(reqBody, 7)),
    etypes: [],
    padataTypes: [],
    kdcOptions: field(reqBody, 0) ? field(reqBody, 0).value : null,
    parsedOk: true,
  };
  const etypeSeq = field(reqBody, 8);
  if (etypeSeq && etypeSeq.children) for (const c of etypeSeq.children) out.etypes.push(intVal(c));
  const padata = field(body, 3);
  if (padata && padata.children) {
    for (const entry of padata.children) {
      const seq = entry.num === TAG_SEQUENCE ? entry : (entry.children[0] || entry);
      out.padataTypes.push(intVal(field(seq, 1)));
    }
  }
  return out;
}

function principalTlv(nameType, names) {
  return der.sequence(der.integer(nameType), der.sequence(...names.map((n) => der.generalstring(n))));
}

function encryptedData(etype, kvno, cipher) {
  const parts = [der.ctx(0, der.integer(etype))];
  if (kvno) parts.push(der.ctx(1, der.integer(kvno)));
  parts.push(der.ctx(2, der.octetstring(cipher)));
  return der.sequence(...parts);
}

function krbError(scenario, code, eText, eData) {
  const parts = [
    der.ctx(0, der.integer(5)),
    der.ctx(1, der.integer(30)),
    der.ctx(3, der.generalizedtime(utcNow())),
    der.ctx(4, der.integer(123456)),
    der.ctx(5, der.integer(code)),
    der.ctx(8, der.generalstring(scenario.realm || "EXAMPLE.COM")),
    der.ctx(9, principalTlv(2, ["krbtgt", scenario.realm || "EXAMPLE.COM"])),
  ];
  if (eText) parts.push(der.ctx(10, der.generalstring(eText)));
  if (eData) parts.push(der.ctx(11, der.octetstring(eData)));
  return der.app(30, der.sequence(...parts));
}

function methodData(entries) {
  const blob = entries.map((e) => der.sequence(der.ctx(1, der.integer(e.type)), der.ctx(2, der.octetstring(e.value))));
  return der.sequence(...blob);
}

function etypeInfo2(entries) {
  const list = entries.map((e) => {
    const parts = [der.ctx(0, der.integer(e.etype))];
    if (e.salt) parts.push(der.ctx(1, der.generalstring(e.salt)));
    return der.sequence(...parts);
  });
  return der.sequence(...list);
}

function asRep(scenario, req, account) {
  const etype = account.etype || 23;
  const cipher = Buffer.alloc(etype === 23 || etype === 24 ? 16 + 32 : 48).fill(0x41);
  const ticketEnc = encryptedData(account.ticketEtype || 18, 2, Buffer.alloc(64).fill(0x42));
  const ticket = der.app(1, der.sequence(
    der.ctx(0, der.integer(5)),
    der.ctx(1, der.generalstring(scenario.realm)),
    der.ctx(2, principalTlv(2, ["krbtgt", scenario.realm])),
    der.ctx(3, ticketEnc),
  ));
  return der.app(11, der.sequence(
    der.ctx(0, der.integer(5)),
    der.ctx(1, der.integer(11)),
    der.ctx(3, der.generalstring(scenario.realm)),
    der.ctx(4, principalTlv(1, [req.cname])),
    der.ctx(5, ticket),
    der.ctx(6, encryptedData(etype, account.kvno || 1, cipher)),
  ));
}

function preauthRequired(scenario, account) {
  const etypes = account.etypes || [18, 17, 23];
  const entries = etypes.map((etype) => ({ etype, salt: account.salt || scenario.realm }));
  const blob = methodData([
    { type: 18, value: etypeInfo2(entries) },
    { type: 165, value: Buffer.from([0x60, 0x00, 0x00, 0x00]) },
  ]);
  return krbError(scenario, 25, "NEEDED_PREAUTH", blob);
}

function utcNow() {
  const d = new Date();
  const p = (n, w = 2) => String(n).padStart(w, "0");
  return `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
}

function createMockKdc(scenario) {
  const state = { requests: [], drops: 0, udpRequests: 0, tcpRequests: 0 };

  function frame(raw, proto) {
    if (!raw || proto !== "tcp") return raw;
    const header = Buffer.alloc(4);
    header.writeUInt32BE(raw.length, 0);
    return Buffer.concat([header, raw]);
  }

  function handle(payload, proto) {
    state.requests.push({ proto, bytes: payload.length, at: Date.now() });
    if (proto === "udp") state.udpRequests += 1; else state.tcpRequests += 1;

    // TCP carries a 4-byte big-endian length prefix (RFC 4120 section 7.2.2).
    if (proto === "tcp") {
      if (payload.length < 4) return { error: "TCP frame shorter than its length prefix" };
      const declared = payload.readUInt32BE(0);
      if (declared !== payload.length - 4) {
        return { error: `TCP length prefix says ${declared} bytes, frame carries ${payload.length - 4}` };
      }
      payload = payload.subarray(4);
    }

    if (scenario.dropFirst && state.drops < scenario.dropFirst) {
      state.drops += 1;
      return null;
    }
    if (scenario.tcpOnly && proto === "udp") return null;

    const req = parseAsReq(payload);
    if (req.error) {
      return { error: req.error, raw: null };
    }
    if (scenario.errorCode) {
      return { raw: frame(krbError(scenario, scenario.errorCode, `forced error ${scenario.errorCode}`), proto) };
    }

    const reqRealm = (req.realm || "").toUpperCase();
    const scenarioRealm = (scenario.realm || "EXAMPLE.COM").toUpperCase();
    if (reqRealm !== scenarioRealm) {
      if (scenario.leakRealm === false) return null;
      const parts = [
        der.ctx(0, der.integer(5)),
        der.ctx(1, der.integer(30)),
        der.ctx(5, der.integer(68)),
        der.ctx(6, der.generalstring(scenario.realm)),
        der.ctx(8, der.generalstring(scenario.realm)),
        der.ctx(10, der.generalstring("WRONG_REALM")),
      ];
      return { raw: frame(der.app(30, der.sequence(...parts)), proto) };
    }

    const name = (req.cname || "").toLowerCase();
    const account = scenario.accounts[name];
    if (!account) {
      return { raw: frame(krbError(scenario, 6, "PRINCIPAL_UNKNOWN"), proto) };
    }
    if (account.state === "disabled") {
      return { raw: frame(krbError(scenario, 18, "CLIENT_REVOKED"), proto) };
    }
    if (account.preauth === false) {
      return { raw: frame(asRep(scenario, req, account), proto) };
    }
    return { raw: frame(preauthRequired(scenario, account), proto) };
  }

  return { handle, state };
}

module.exports = { createMockKdc, parseAsReq, parseDer, der, utcNow };
