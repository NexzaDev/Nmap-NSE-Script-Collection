"use strict";
/*
 * tools/mocks/netlogon.js
 * ---------------------------------------------------------------------------
 * A scenario driven mock domain controller for the Netlogon secure channel
 * probe used by KERBEROS/kerberos-cve-2020-1472-prep.nse.
 *
 * It speaks the same three protocol layers as the script under test - SMB2,
 * DCE/RPC connection oriented PDUs, and MS-NRPC - and it is written from the
 * specification independently: no helper in this file is shared with
 * nselib/netlogon.lua, and every field the script encodes is checked here
 * against the byte layout the specifications prescribe. If the Lua encoder
 * gets referent offsets, alignment, string maximum counts or structure sizes
 * wrong, this mock answers with a protocol error instead of a verdict, and the
 * scenario fails.
 *
 * Scenario knobs (all optional):
 *   {
 *     serverName: "DC01",                  // the DC's computer name
 *     domainName: "EXAMPLE.COM",
 *     dnsDomain: "example.com",
 *     dialect: 0x0210,                     // highest dialect to accept
 *     signingRequired: false,
 *     allowNullSession: true,              // false -> STATUS_ACCESS_DENIED
 *     anonymousAuthenticateRequired: true, // reject a type 3 with responses
 *     pipeAvailable: true,                 // false -> STATUS_PIPE_NOT_AVAILABLE
 *     pipeAccessDenied: false,
 *     bindRejected: false,                 // false|number -> bind result code
 *     acceptTransferSyntax: true,
 *     zerologon: "vulnerable"|"patched"|"enforced"|"accepts-any",
 *     aesSupported: true,                  // bit W in the negotiated flags
 *     requireZeroCredential: true,         // reject a non-zero credential
 *     serverChallenge: "1122334455667788",
 *     negotiatedFlags: 0x212fffff,         // overrides the computed set
 *     dropFirstSends: 0,                   // no answer at all for the first N
 *     silent: false,                       // never answer
 *     idleAfter: null,                     // stop answering after N sends
 *     coalesceFrames: false,               // send an extra stray frame first
 *     faultOnOpnum: null,                  // { opnum: 26, status: 0x000006ba }
 *     maxReadChunk: null,                  // split pipe reads into chunks
 *   }
 *
 * Verdict semantics mirror the published analysis of CVE-2020-1472:
 *   vulnerable  - the zero client credential is accepted (STATUS_SUCCESS)
 *   patched     - the zero client credential is refused (STATUS_ACCESS_DENIED)
 *   enforced    - the insecure channel is refused by policy
 *                 (STATUS_DOWNGRADE_DETECTED)
 *   accepts-any - every credential is accepted, the "no credential check at
 *                 all" shape a control probe is meant to expose
 */

const SMB2_PROTOCOL_ID = Buffer.from([0xfe, 0x53, 0x4d, 0x42]);
const STATUS = {
  SUCCESS: 0x00000000,
  MORE_PROCESSING_REQUIRED: 0xc0000016,
  ACCESS_DENIED: 0xc0000022,
  DOWNGRADE_DETECTED: 0xc0000388,
  PIPE_NOT_AVAILABLE: 0xc00000ac,
  OBJECT_NAME_NOT_FOUND: 0xc0000034,
  BAD_NETWORK_NAME: 0xc00000cc,
  INVALID_PARAMETER: 0xc000000d,
  NOT_SUPPORTED: 0xc00000bb,
  LOGON_FAILURE: 0xc000006d,
  NO_MORE_FILES: 0x80000006,
  BUFFER_OVERFLOW: 0x80000005,
};

const CMD = { NEGOTIATE: 0, SESSION_SETUP: 1, LOGOFF: 2, TREE_CONNECT: 3, TREE_DISCONNECT: 4, CREATE: 5, CLOSE: 6, READ: 8, WRITE: 9, ECHO: 13 };
const CMD_NAME = {};
for (const [name, value] of Object.entries(CMD)) CMD_NAME[value] = name;

const PDU = { REQUEST: 0, RESPONSE: 2, FAULT: 3, BIND: 11, BIND_ACK: 12, BIND_NAK: 13, AUTH3: 16 };
const PDU_NAME = {};
for (const [name, value] of Object.entries(PDU)) PDU_NAME[value] = name;

const PFC_FIRST_FRAG = 0x01;
const PFC_LAST_FRAG = 0x02;
const NDR_REFERENT_BASE = 0x00020000;

const NETLOGON_UUID = "12345678-1234-abcd-ef00-01234567cffb";
const NDR_UUID = "8a885d04-1ceb-11c9-9fe8-08002b104860";

/* ------------------------------------------------------------------ byte IO */

class Reader {
  constructor(buf) {
    this.buf = buf;
    this.pos = 0;
  }
  get remaining() {
    return this.buf.length - this.pos;
  }
  u8() {
    if (this.remaining < 1) throw new Error(`truncated at offset ${this.pos}: u8`);
    return this.buf[this.pos++];
  }
  u16() {
    if (this.remaining < 2) throw new Error(`truncated at offset ${this.pos}: u16`);
    const value = this.buf.readUInt16LE(this.pos);
    this.pos += 2;
    return value;
  }
  u32() {
    if (this.remaining < 4) throw new Error(`truncated at offset ${this.pos}: u32`);
    const value = this.buf.readUInt32LE(this.pos);
    this.pos += 4;
    return value;
  }
  u64() {
    const low = this.u32();
    const high = this.u32();
    return high * 4294967296 + low;
  }
  bytes(n) {
    if (this.remaining < n) throw new Error(`truncated at offset ${this.pos}: wanted ${n}, have ${this.remaining}`);
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return Buffer.from(out);
  }
  align4(label = "field") {
    const pad = (4 - (this.pos % 4)) % 4;
    if (pad > 0) {
      const padding = this.bytes(pad);
      if (padding.some((b) => b !== 0)) {
        throw new Error(`non-zero padding before ${label} at offset ${this.pos - pad}`);
      }
    }
  }
}

function u16(value) {
  const buf = Buffer.alloc(2);
  buf.writeUInt16LE(value & 0xffff, 0);
  return buf;
}

function u32(value) {
  const buf = Buffer.alloc(4);
  buf.writeUInt32LE(value >>> 0, 0);
  return buf;
}

function u64(value) {
  const low = value % 4294967296;
  const high = Math.floor(value / 4294967296);
  return Buffer.concat([u32(low), u32(high)]);
}

function utf16le(text) {
  return Buffer.from(text, "utf16le");
}

function uuidBytes(text) {
  const compact = text.replace(/[-{}]/g, "").toLowerCase();
  if (compact.length !== 32) throw new Error(`bad uuid ${text}`);
  const raw = Buffer.from(compact, "hex");
  // First three groups little endian, last two big endian.
  return Buffer.concat([
    Buffer.from([raw[3], raw[2], raw[1], raw[0]]),
    Buffer.from([raw[5], raw[4]]),
    Buffer.from([raw[7], raw[6]]),
    raw.subarray(8, 16),
  ]);
}

function uuidText(buf) {
  const b = buf;
  const hex = (i) => b[i].toString(16).padStart(2, "0");
  return `${hex(3)}${hex(2)}${hex(1)}${hex(0)}-${hex(5)}${hex(4)}-${hex(7)}${hex(6)}-` +
    `${hex(8)}${hex(9)}-${hex(10)}${hex(11)}${hex(12)}${hex(13)}${hex(14)}${hex(15)}`;
}

function filetime(date = new Date()) {
  return Math.round((date.getTime() / 1000 + 11644473600) * 10000000);
}

/* ---------------------------------------------------------------- SMB2 wire */

function smb2Frame(message) {
  const header = Buffer.alloc(4);
  header.writeUInt32BE(message.length, 0);
  return Buffer.concat([header, message]);
}

function smb2Header(opts) {
  const buf = Buffer.alloc(64);
  SMB2_PROTOCOL_ID.copy(buf, 0);
  buf.writeUInt16LE(64, 4);                             // StructureSize
  buf.writeUInt16LE(opts.creditCharge || 1, 6);
  buf.writeUInt32LE(opts.status >>> 0, 8);
  buf.writeUInt16LE(opts.command, 12);
  buf.writeUInt16LE(opts.credits === undefined ? 1 : opts.credits, 14);
  buf.writeUInt32LE(opts.flags || 0, 16);
  buf.writeUInt32LE(0, 20);                             // NextCommand
  buf.writeUInt32LE(opts.messageId >>> 0, 24);
  buf.writeUInt32LE(0, 28);                             // MessageId high
  buf.writeUInt32LE(0, 32);                             // Reserved / AsyncId
  buf.writeUInt32LE(opts.treeId || 0, 36);
  buf.writeUInt32LE((opts.sessionId || 0) >>> 0, 40);
  buf.writeUInt32LE(0, 44);                             // SessionId high
  return buf;
}

function parseSMB2Header(buf) {
  if (buf.length < 64) throw new Error("SMB2 header shorter than 64 bytes");
  if (!buf.subarray(0, 4).equals(SMB2_PROTOCOL_ID)) throw new Error("bad SMB2 protocol id");
  const structureSize = buf.readUInt16LE(4);
  if (structureSize !== 64) throw new Error(`SMB2 StructureSize is ${structureSize}, expected 64`);
  return {
    status: buf.readUInt32LE(8),
    command: buf.readUInt16LE(12),
    credits: buf.readUInt16LE(14),
    flags: buf.readUInt32LE(16),
    messageId: buf.readUInt32LE(24) + buf.readUInt32LE(28) * 4294967296,
    treeId: buf.readUInt32LE(36),
    sessionId: buf.readUInt32LE(40) + buf.readUInt32LE(44) * 4294967296,
    body: buf.subarray(64),
  };
}

/* ------------------------------------------------------------- NTLMSSP wire */

const NTLMSSP_SIGNATURE = Buffer.from("NTLMSSP\0", "binary");
const NTLM_FLAGS = {
  NEGOTIATE_UNICODE: 0x00000001,
  NEGOTIATE_OEM: 0x00000002,
  REQUEST_TARGET: 0x00000004,
  NEGOTIATE_NTLM: 0x00000200,
  NEGOTIATE_ALWAYS_SIGN: 0x00008000,
  NEGOTIATE_EXTENDED_SESSIONSECURITY: 0x00080000,
  NEGOTIATE_TARGET_INFO: 0x00800000,
  NEGOTIATE_128: 0x20000000,
};

function parseNTLMSSP(buf, expectedType) {
  if (buf.length < 32) throw new Error("NTLMSSP message shorter than 32 bytes");
  if (!buf.subarray(0, 8).equals(NTLMSSP_SIGNATURE)) throw new Error("NTLMSSP signature mismatch");
  const type = buf.readUInt32LE(8);
  if (type !== expectedType) throw new Error(`expected NTLMSSP type ${expectedType}, got ${type}`);
  const readField = (offset) => ({
    length: buf.readUInt16LE(offset),
    maximum: buf.readUInt16LE(offset + 2),
    offset: buf.readUInt32LE(offset + 4),
  });
  const message = { type };
  if (expectedType === 1) {
    message.flags = buf.readUInt32LE(12);
    message.domain = readField(16);
    message.workstation = readField(24);
    message.payloadStart = 32;
  } else if (expectedType === 3) {
    message.lm = readField(12);
    message.nt = readField(20);
    message.domain = readField(28);
    message.user = readField(36);
    message.workstation = readField(44);
    message.sessionKey = readField(52);
    message.flags = buf.readUInt32LE(60);
    message.payloadStart = 64;
    for (const [name, field] of Object.entries({
      lm: message.lm, nt: message.nt, domain: message.domain,
      user: message.user, workstation: message.workstation, sessionKey: message.sessionKey,
    })) {
      if (field.length > 0) {
        field.value = buf.subarray(field.offset, field.offset + field.length);
        if (name === "domain" || name === "user" || name === "workstation") {
          field.text = field.value.toString("utf16le");
        }
      }
    }
  }
  return message;
}

function ntlmChallengeMessage(scenario, flags, serverChallenge) {
  const target = utf16le((scenario.domainName || "EXAMPLE.COM").toUpperCase());
  const avPairs = [];
  const pushAv = (id, value) => {
    avPairs.push(u16(id), u16(value.length), value);
  };
  pushAv(1, utf16le(scenario.serverName || "DC01"));
  pushAv(2, utf16le((scenario.domainName || "EXAMPLE.COM").split(".")[0]));
  pushAv(3, utf16le(`${(scenario.serverName || "DC01").toLowerCase()}.${scenario.dnsDomain || "example.com"}`));
  pushAv(4, utf16le(scenario.dnsDomain || "example.com"));
  pushAv(5, utf16le(scenario.dnsDomain || "example.com"));
  pushAv(7, Buffer.concat([u64(Math.floor(Date.now() / 1000) * 10000000 + 116444736000000000)]).subarray(0, 8));
  pushAv(0, Buffer.alloc(0));
  const targetInfo = Buffer.concat(avPairs);
  const headerSize = 48;
  const targetOffset = headerSize;
  const infoOffset = targetOffset + target.length;
  const msg = Buffer.alloc(headerSize + target.length + targetInfo.length);
  NTLMSSP_SIGNATURE.copy(msg, 0);
  msg.writeUInt32LE(2, 8);
  msg.writeUInt16LE(target.length, 12);
  msg.writeUInt16LE(target.length, 14);
  msg.writeUInt32LE(targetOffset, 16);
  msg.writeUInt32LE(flags >>> 0, 20);
  serverChallenge.copy(msg, 24);
  Buffer.alloc(8).copy(msg, 32);                        // Reserved
  msg.writeUInt16LE(targetInfo.length, 40);
  msg.writeUInt16LE(targetInfo.length, 42);
  msg.writeUInt32LE(infoOffset, 44);
  target.copy(msg, targetOffset);
  targetInfo.copy(msg, infoOffset);
  return msg;
}

/* ------------------------------------------------------------- DCE/RPC wire */

function pduHeader(ptype, flags, fragLength, authLength, callId) {
  const buf = Buffer.alloc(16);
  buf[0] = 5;                                           // version
  buf[1] = 0;                                           // minor
  buf[2] = ptype;
  buf[3] = flags;
  buf[4] = 0x10;                                        // little endian, ASCII
  buf.writeUInt16LE(fragLength, 8);
  buf.writeUInt16LE(authLength, 10);
  buf.writeUInt32LE(callId >>> 0, 12);
  return buf;
}

function bindAckPDU(callId, opts) {
  const secondary = Buffer.from("\\PIPE\\netlogon\0", "binary");
  const secAddrLen = secondary.length;
  const padTo4 = (n) => (4 - (n % 4)) % 4;
  const secAddrField = Buffer.concat([u16(secAddrLen), secondary]);
  const padding = Buffer.alloc(padTo4(secAddrField.length));
  const results = opts.results.map(() => Buffer.concat([
    u16(opts.resultCode), u16(opts.reason || 0), uuidBytes(NDR_UUID), u16(2), u16(0),
  ]));
  const body = Buffer.concat([
    u16(opts.maxXmit || 4280), u16(opts.maxRecv || 4280), u32(opts.assocGroup || 0x1234),
    secAddrField, padding,
    Buffer.from([opts.results.length, 0]), u16(0),
    ...results,
  ]);
  return Buffer.concat([pduHeader(PDU.BIND_ACK, PFC_FIRST_FRAG | PFC_LAST_FRAG, 16 + body.length, 0, callId), body]);
}

function bindNakPDU(callId, reason) {
  const body = Buffer.concat([u16(0), u16(0), u32(0), Buffer.from([1, 0]), u16(0), u16(reason)]);
  return Buffer.concat([pduHeader(PDU.BIND_NAK, PFC_FIRST_FRAG | PFC_LAST_FRAG, 16 + body.length, 0, callId), body]);
}

function responsePDU(callId, contextId, stub) {
  const body = Buffer.concat([u32(stub.length), u16(contextId), Buffer.from([0, 0]), stub]);
  return Buffer.concat([pduHeader(PDU.RESPONSE, PFC_FIRST_FRAG | PFC_LAST_FRAG, 16 + body.length, 0, callId), body]);
}

function faultPDU(callId, status) {
  const body = Buffer.concat([u32(0), u16(0), Buffer.from([0, 0]), u32(0), u32(status >>> 0), u32(0)]);
  return Buffer.concat([pduHeader(PDU.FAULT, PFC_FIRST_FRAG | PFC_LAST_FRAG, 16 + body.length, 0, callId), body]);
}

function parsePDU(buf) {
  if (buf.length < 16) throw new Error("PDU shorter than 16 bytes");
  const hdr = new Reader(buf);
  const version = hdr.u8();
  const minor = hdr.u8();
  const ptype = hdr.u8();
  const flags = hdr.u8();
  hdr.bytes(4);                                         // drep
  const fragLength = hdr.u16();
  const authLength = hdr.u16();
  const callId = hdr.u32();
  if (version !== 5 || minor !== 0) throw new Error(`unsupported DCERPC version ${version}.${minor}`);
  if (authLength !== 0) throw new Error("authenticated PDUs are not expected by this mock");
  if (fragLength !== buf.length) throw new Error(`frag_length ${fragLength} does not match the ${buf.length} byte PDU`);
  if (!(flags & PFC_FIRST_FRAG) || !(flags & PFC_LAST_FRAG)) throw new Error("PDU is not a complete single fragment");
  return { ptype, flags, callId, body: buf.subarray(16) };
}

/* ------------------------------------------------------ NDR stub inspection */

// Read a "[string, unique] wchar_t*" header and remember the referent for the
// deferred pass. The mock does not trust the writer's deferred layout: it
// checks that every referent lands exactly where NDR alignment says it must.
function readUniqueString(reader, referents, fieldName, expect) {
  const length = reader.u16();
  const maximum = reader.u16();
  const referent = reader.u32();
  if (referent === 0) {
    throw new Error(`${fieldName}: null referent, a unique string must be transmitted`);
  }
  if (referent < NDR_REFERENT_BASE) {
    throw new Error(`${fieldName}: referent 0x${referent.toString(16)} below the 0x00020000 base`);
  }
  if (maximum !== length + 2) {
    throw new Error(`${fieldName}: MaximumLength ${maximum} is not Length+2 (${length + 2})`);
  }
  if (expect !== undefined && length !== expect.length * 2) {
    throw new Error(`${fieldName}: Length ${length} does not match ${expect.length} UTF-16 characters`);
  }
  referents.push({ field: fieldName, referent, length, maximum });
  return { length, maximum, referent };
}

function resolveDeferredStrings(stub, referents, deferredStart) {
  const seen = new Map();
  const ordered = referents.slice().sort((a, b) => a.referent - b.referent);
  let cursor = deferredStart;
  for (const entry of ordered) {
    const expectedOffset = entry.referent - NDR_REFERENT_BASE;
    if (expectedOffset !== cursor) {
      throw new Error(`${entry.field}: referent points at offset ${expectedOffset}, but NDR ordering puts it at ${cursor}`);
    }
    const reader = new Reader(stub);
    reader.pos = expectedOffset;
    const maxCount = reader.u32();
    if (maxCount !== entry.length / 2 + 1) {
      throw new Error(`${entry.field}: conformant string maximum count ${maxCount} is not ${entry.length / 2 + 1}`);
    }
    const chars = reader.bytes(entry.length + 2);
    if (chars[chars.length - 1] !== 0 || chars[chars.length - 2] !== 0) {
      throw new Error(`${entry.field}: string is not null terminated`);
    }
    const text = chars.subarray(0, chars.length - 2).toString("utf16le");
    if (text.length !== entry.length / 2) {
      throw new Error(`${entry.field}: decoded ${text.length} characters, header announced ${entry.length / 2}`);
    }
    seen.set(entry.referent, { text, consumed: 4 + entry.length + 2 });
    cursor = expectedOffset + 4 + entry.length + 2;
    cursor += (4 - (cursor % 4)) % 4;
  }
  return seen;
}

function parseServerReqChallengeStub(stub, expect) {
  const reader = new Reader(stub);
  const referents = [];
  readUniqueString(reader, referents, "PrimaryName", expect.primaryName);
  readUniqueString(reader, referents, "ComputerName", expect.computerName);
  const clientChallenge = reader.bytes(8);
  const deferredStart = (reader.pos + 3) & ~3;
  const strings = resolveDeferredStrings(stub, referents, deferredStart);
  const names = [...strings.values()].map((entry) => entry.text);
  if (expect.primaryName !== undefined && names[0] !== expect.primaryName) {
    throw new Error(`PrimaryName decoded as ${JSON.stringify(names[0])}, expected ${JSON.stringify(expect.primaryName)}`);
  }
  if (expect.computerName !== undefined && names[1] !== expect.computerName) {
    throw new Error(`ComputerName decoded as ${JSON.stringify(names[1])}, expected ${JSON.stringify(expect.computerName)}`);
  }
  return { primaryName: names[0], computerName: names[1], clientChallenge };
}

function parseServerAuthenticateStub(stub, expect) {
  const reader = new Reader(stub);
  const referents = [];
  readUniqueString(reader, referents, "PrimaryName", expect.primaryName);
  readUniqueString(reader, referents, "AccountName", expect.accountName);
  const secureChannelType = reader.u16();
  reader.align4("ComputerName");
  readUniqueString(reader, referents, "ComputerName", expect.computerName);
  const clientCredential = reader.bytes(8);
  const negotiateFlags = reader.u32();
  const trailingPointers = [];
  if (expect.withAccountRid) {
    const accountRidReferent = reader.u32();
    if (accountRidReferent !== 0) {
      // An [out]-only pointer must be transmitted as a null referent; a
      // non-zero value here would make the server interpret the deferred data
      // as a return value the client claims to have allocated.
      throw new Error(`AccountRid is an [out] parameter but was sent as referent 0x${accountRidReferent.toString(16)}`);
    }
    trailingPointers.push(accountRidReferent);
  }
  const deferredStart = (reader.pos + 3) & ~3;
  const strings = resolveDeferredStrings(stub, referents, deferredStart);
  const names = [...strings.values()].map((entry) => entry.text);
  if (expect.primaryName !== undefined && names[0] !== expect.primaryName) {
    throw new Error(`PrimaryName decoded as ${JSON.stringify(names[0])}`);
  }
  if (expect.computerName !== undefined && names[2] !== expect.computerName) {
    throw new Error(`ComputerName decoded as ${JSON.stringify(names[2])}`);
  }
  return {
    primaryName: names[0],
    accountName: names[1],
    computerName: names[2],
    secureChannelType,
    clientCredential,
    negotiateFlags,
    trailingPointers,
  };
}

function parseBindPDU(pdu) {
  const reader = new Reader(pdu.body);
  const maxXmit = reader.u16();
  const maxRecv = reader.u16();
  const assocGroup = reader.u32();
  const nContexts = reader.u8();
  reader.u8();                                          // reserved
  reader.u16();                                         // reserved2
  const contexts = [];
  for (let i = 0; i < nContexts; i++) {
    const contextId = reader.u16();
    const nTransfer = reader.u8();
    reader.u8();
    const abstractSyntax = uuidText(reader.bytes(16));
    const abstractVersion = { major: reader.u16(), minor: reader.u16() };
    const transferSyntaxes = [];
    for (let t = 0; t < nTransfer; t++) {
      transferSyntaxes.push({ uuid: uuidText(reader.bytes(16)), version: { major: reader.u16(), minor: reader.u16() } });
    }
    contexts.push({ contextId, abstractSyntax, abstractVersion, transferSyntaxes });
  }
  return { maxXmit, maxRecv, assocGroup, contexts };
}

function parseRequestPDU(pdu) {
  const reader = new Reader(pdu.body);
  const allocHint = reader.u32();
  const contextId = reader.u16();
  const opnum = reader.u16();
  const stub = reader.bytes(reader.remaining);
  return { allocHint, contextId, opnum, stub };
}

/* ----------------------------------------------------------------- the mock */

function createMockNetlogon(scenario = {}) {
  const serverName = scenario.serverName || "DC01";
  const domainName = scenario.domainName || "EXAMPLE.COM";
  const dnsDomain = scenario.dnsDomain || "example.com";
  const state = {
    requests: [],
    sends: 0,
    calls: [],
    smb: { negotiate: 0, sessionSetup: 0, treeConnect: 0, create: 0, write: 0, read: 0, close: 0, logoff: 0 },
    sawNullSession: false,
    sawZeroCredential: null,
    lastCredentialWasZero: null,
    lastBind: null,
    lastChallenge: null,
    lastAuthenticate: null,
    protocolErrors: [],
    notes: [],
    deferred: [],
    queue: [],
    sessionId: 0x1000,
    treeId: 0x2000,
    pipeFileId: { persistent: 0x1234, volatile: 0x5678 },
    challenge: Buffer.from(scenario.serverChallenge || "8f3c2a1b6d4e5f70", "hex"),
    negotiatedFlags: scenario.negotiatedFlags,
    handshake: { negotiate: false, authenticated: false, tree: false, pipe: false, bound: false },
  };

  function dropThisSend() {
    if (scenario.silent) return true;
    if (state.sends <= (scenario.dropFirstSends || 0)) return true;
    if (scenario.idleAfter !== null && scenario.idleAfter !== undefined && state.sends > scenario.idleAfter) return true;
    return false;
  }

  function statusResponse(request, command, status, body, sessionIdOverride) {
    const message = Buffer.concat([
      smb2Header({
        status,
        command,
        messageId: request.messageId,
        treeId: request.treeId,
        sessionId: sessionIdOverride === undefined ? state.sessionId : sessionIdOverride,
        credits: 1,
      }),
      body,
    ]);
    return message;
  }

  function negotiateResponse(request) {
    const dial = request.body;
    const structureSize = dial.readUInt16LE(0);
    if (structureSize !== 36) {
      throw new Error(`NEGOTIATE StructureSize is ${structureSize}, expected 36 (the dialect list starts at offset 36)`);
    }
    const dialectCount = dial.readUInt16LE(2);
    if (dialectCount < 1 || 36 + dialectCount * 2 > dial.length) {
      throw new Error(`NEGOTIATE announces ${dialectCount} dialect(s) in a ${dial.length} byte request`);
    }
    const offered = [];
    for (let i = 0; i < dialectCount; i++) offered.push(dial.readUInt16LE(36 + i * 2));
    if (offered.length === 0) throw new Error("NEGOTIATE request offered no dialects");
    const supported = [0x0311, 0x0302, 0x0300, 0x0210, 0x0202];
    const cap = scenario.dialect || 0x0302;
    const chosen = offered.filter((d) => supported.includes(d) && d <= cap).sort((a, b) => b - a)[0];
    if (chosen === undefined) throw new Error(`no mutually supported dialect (offered ${offered.map((d) => "0x" + d.toString(16)).join(",")})`);
    const securityMode = (scenario.signingRequired ? 0x0002 : 0) | 0x0001;
    const body = Buffer.alloc(64);
    body.writeUInt16LE(65, 0);                          // StructureSize
    body.writeUInt16LE(securityMode, 2);
    body.writeUInt16LE(chosen, 4);
    body.writeUInt16LE(0, 6);                           // NegotiateContextCount
    Buffer.from("0123456789abcdef", "hex").copy(body, 8); // ServerGuid
    body.writeUInt32LE(0x00000007, 24);                 // Capabilities: large MTU + leasing
    body.writeUInt32LE(1048576, 28);                    // MaxTransactSize
    body.writeUInt32LE(1048576, 32);                    // MaxReadSize
    body.writeUInt32LE(1048576, 36);                    // MaxWriteSize
    body.writeBigUInt64LE(BigInt(filetime()), 40);      // SystemTime
    body.writeBigUInt64LE(BigInt(filetime(new Date(Date.now() - 86400000))), 48); // ServerStartTime
    const blob = Buffer.from("mock-gss-token", "binary");
    const offset = 64 + body.length;                    // SMB2 header + 64 byte fixed body
    body.writeUInt16LE(offset, 56);
    body.writeUInt16LE(blob.length, 58);
    // A NEGOTIATE response carries no session: the session id arrives in
    // the first SESSION_SETUP response.
    return statusResponse(request, CMD.NEGOTIATE, STATUS.SUCCESS, Buffer.concat([body, blob]), 0);
  }

  function sessionSetupResponse(request, status, securityBlob, sessionFlags) {
    const offset = 64 + 8;
    const body = Buffer.alloc(8 + securityBlob.length);
    body.writeUInt16LE(9, 0);                           // StructureSize
    body.writeUInt16LE(sessionFlags || 0, 2);
    body.writeUInt16LE(offset, 4);
    body.writeUInt16LE(securityBlob.length, 6);
    securityBlob.copy(body, 8);
    return statusResponse(request, CMD.SESSION_SETUP, status, body);
  }

  function handleSessionSetup(request) {
    state.smb.sessionSetup += 1;
    // SESSION_SETUP Request: StructureSize(2) Flags(1) SecurityMode(1)
    // Capabilities(4) Channel(4) SecurityBufferOffset(2) SecurityBufferLength(2)
    // PreviousSessionId(8), so the security buffer fields are at 12 and 14.
    const secOffset = request.body.readUInt16LE(12);
    const secLength = request.body.readUInt16LE(14);
    const blob = request.body.subarray(secOffset - 64, secOffset - 64 + secLength);
    let message;
    try {
      message = parseNTLMSSP(blob, blob.readUInt32LE(8));
    } catch (err) {
      state.protocolErrors.push(`SESSION_SETUP: ${err.message}`);
      return statusResponse(request, CMD.SESSION_SETUP, STATUS.LOGON_FAILURE, Buffer.alloc(8));
    }
    if (message.type === 1) {
      const flags = NTLM_FLAGS.NEGOTIATE_UNICODE | NTLM_FLAGS.REQUEST_TARGET | NTLM_FLAGS.NEGOTIATE_NTLM
        | NTLM_FLAGS.NEGOTIATE_ALWAYS_SIGN | NTLM_FLAGS.NEGOTIATE_EXTENDED_SESSIONSECURITY
        | NTLM_FLAGS.NEGOTIATE_TARGET_INFO | NTLM_FLAGS.NEGOTIATE_128;
      const challenge = ntlmChallengeMessage(scenario, flags, state.challenge);
      state.handshake.negotiate = true;
      state.handshake.challenge = true;
      return sessionSetupResponse(request, STATUS.MORE_PROCESSING_REQUIRED, challenge, 0);
    }
    if (message.type === 3) {
      const emptyResponses = message.lm.length === 0 && message.nt.length === 0;
      const emptyUser = !message.user.text;
      if (scenario.anonymousAuthenticateRequired !== false && !(emptyResponses && emptyUser)) {
        state.protocolErrors.push("the AUTHENTICATE message carried credentials; a null session probe must send empty responses");
        return sessionSetupResponse(request, STATUS.LOGON_FAILURE, Buffer.alloc(0), 0);
      }
      state.sawNullSession = emptyResponses && emptyUser;
      if (scenario.allowNullSession === false) {
        return sessionSetupResponse(request, STATUS.ACCESS_DENIED, Buffer.alloc(0), 0);
      }
      state.handshake.authenticated = true;
      return sessionSetupResponse(request, STATUS.SUCCESS, Buffer.alloc(0), 0x0002);
    }
    throw new Error(`unexpected NTLMSSP type ${message.type}`);
  }

  function handleTreeConnect(request) {
    state.smb.treeConnect += 1;
    const pathOffset = request.body.readUInt16LE(4);
    const pathLength = request.body.readUInt16LE(6);
    const path = request.body.subarray(pathOffset - 64, pathOffset - 64 + pathLength).toString("utf16le");
    const expected = "\\\\" + serverName + "\\IPC$";
    if (path.toUpperCase() !== expected.toUpperCase()) {
      // A first attempt under a different name is legitimate: the client then
      // retries with the name the NTLMSSP challenge disclosed, so this is a
      // note rather than a protocol violation.
      state.notes.push(`TREE_CONNECT attempt used ${JSON.stringify(path)}, the controller is ${JSON.stringify(expected)}`);
      return statusResponse(request, CMD.TREE_CONNECT, STATUS.BAD_NETWORK_NAME, Buffer.alloc(16));
    }
    state.handshake.tree = true;
    const body = Buffer.alloc(16);
    body.writeUInt16LE(16, 0);
    body[2] = 2;                                        // ShareType: pipe
    body.writeUInt32LE(0x00000001, 4);                  // ShareFlags: manual caching
    body.writeUInt32LE(0, 8);
    body.writeUInt32LE(0x001f003f, 12);                 // MaximalAccess
    return statusResponse(request, CMD.TREE_CONNECT, STATUS.SUCCESS, body);
  }

  function handleCreate(request) {
    state.smb.create += 1;
    const nameOffset = request.body.readUInt16LE(44);
    const nameLength = request.body.readUInt16LE(46);
    const name = request.body.subarray(nameOffset - 64, nameOffset - 64 + nameLength).toString("utf16le");
    if (name.toLowerCase() !== "netlogon") {
      return statusResponse(request, CMD.CREATE, STATUS.OBJECT_NAME_NOT_FOUND, Buffer.alloc(88));
    }
    if (scenario.pipeAvailable === false) {
      return statusResponse(request, CMD.CREATE, STATUS.PIPE_NOT_AVAILABLE, Buffer.alloc(88));
    }
    if (scenario.pipeAccessDenied) {
      return statusResponse(request, CMD.CREATE, STATUS.ACCESS_DENIED, Buffer.alloc(88));
    }
    state.handshake.pipe = true;
    // CREATE Response layout (MS-SMB2 2.2.14): StructureSize(2) OplockLevel(1)
    // Flags(1) CreateAction(4) CreationTime(8) LastAccessTime(8)
    // LastWriteTime(8) ChangeTime(8) AllocationSize(8) EndOfFile(8)
    // FileAttributes(4) Reserved2(4) FileId(16) CreateContexts...
    const body = Buffer.alloc(88);
    body.writeUInt16LE(89, 0);
    body.writeUInt32LE(1, 4);                           // CreateAction: opened
    const now = BigInt(filetime());
    body.writeBigUInt64LE(now, 8);                      // CreationTime
    body.writeBigUInt64LE(now, 16);                     // LastAccessTime
    body.writeBigUInt64LE(now, 24);                     // LastWriteTime
    body.writeBigUInt64LE(now, 32);                     // ChangeTime
    body.writeBigUInt64LE(0n, 40);                      // AllocationSize
    body.writeBigUInt64LE(0n, 48);                      // EndOfFile
    body.writeUInt32LE(0x00000080, 56);                 // FileAttributes: normal
    body.writeUInt32LE(0, 60);                          // Reserved2
    // FileId is two 64-bit values: Persistent then Volatile.
    body.writeBigUInt64LE(BigInt(state.pipeFileId.persistent), 64);
    body.writeBigUInt64LE(BigInt(state.pipeFileId.volatile), 72);
    return statusResponse(request, CMD.CREATE, STATUS.SUCCESS, body);
  }


  // The file id a request carries must be the one CREATE handed out; a 64-bit
  // field mishandled as two 32-bit values shows up here immediately.
  function checkFileId(body, offset, command) {
    const persistent = body.readBigUInt64LE(offset);
    const volatile = body.readBigUInt64LE(offset + 8);
    if (persistent !== BigInt(state.pipeFileId.persistent) || volatile !== BigInt(state.pipeFileId.volatile)) {
      state.protocolErrors.push(`${command}: FileId ${persistent}/${volatile} is not the one CREATE issued (${state.pipeFileId.persistent}/${state.pipeFileId.volatile})`);
      return false;
    }
    return true;
  }

  function handleWrite(request) {
    state.smb.write += 1;
    // WRITE Request: StructureSize(2) DataOffset(2) Length(4) Offset(8)
    // FileId(16) Channel(4) RemainingBytes(4) WriteChannelInfoOffset(2)
    // WriteChannelInfoLength(2) Flags(4), then the payload.
    const dataOffset = request.body.readUInt16LE(2);
    const length = request.body.readUInt32LE(4);
    checkFileId(request.body, 16, "WRITE");
    if (dataOffset - 64 + length > request.body.length) {
      state.protocolErrors.push(`WRITE: data window ${dataOffset}+${length} exceeds the ${request.body.length} byte body`);
    }
    const data = request.body.subarray(dataOffset - 64, dataOffset - 64 + length);
    let pdu;
    try {
      pdu = parsePDU(data);
    } catch (err) {
      state.protocolErrors.push(`WRITE: ${err.message}`);
      const body = Buffer.alloc(16);
      body.writeUInt16LE(17, 0);
      return statusResponse(request, CMD.WRITE, STATUS.INVALID_PARAMETER, body);
    }
    try {
      if (pdu.ptype === PDU.BIND) {
        const bind = parseBindPDU(pdu);
        state.lastBind = bind;
        const context = bind.contexts[0];
        if (!context || context.abstractSyntax !== NETLOGON_UUID) {
          state.protocolErrors.push(`BIND: abstract syntax ${context && context.abstractSyntax} is not the Netlogon interface`);
          state.queue.push(bindAckPDU(pdu.callId, { results: [0], resultCode: 2, reason: 0 }));
          return writeOk(request, 16);
        }
        if (context.abstractVersion.major !== 1 || context.abstractVersion.minor !== 0) {
          state.protocolErrors.push(`BIND: Netlogon version ${context.abstractVersion.major}.${context.abstractVersion.minor} is not 1.0`);
        }
        const transfer = context.transferSyntaxes[0];
        if (scenario.acceptTransferSyntax !== false && (!transfer || transfer.uuid !== NDR_UUID)) {
          state.protocolErrors.push(`BIND: transfer syntax ${transfer && transfer.uuid} is not NDR32`);
          state.queue.push(bindAckPDU(pdu.callId, { results: [0], resultCode: 2 }));
          return writeOk(request, 16);
        }
        if (scenario.bindRejected) {
          state.queue.push(bindNakPDU(pdu.callId, 2));
          return writeOk(request, 16);
        }
        if (bind.maxXmit < 1024 || bind.maxRecv < 1024) {
          state.protocolErrors.push(`BIND: fragment sizes ${bind.maxXmit}/${bind.maxRecv} are implausibly small`);
        }
        state.handshake.bound = true;
        state.queue.push(bindAckPDU(pdu.callId, { results: [0], assocGroup: 0x0badc0de }));
        return writeOk(request, 16);
      }
      if (pdu.ptype === PDU.REQUEST) {
        const request2 = parseRequestPDU(pdu);
        state.calls.push(request2.opnum);
        if (scenario.faultOnOpnum && scenario.faultOnOpnum.opnum === request2.opnum) {
          state.queue.push(faultPDU(pdu.callId, scenario.faultOnOpnum.status >>> 0));
          return writeOk(request, 16);
        }
        if (request2.opnum === 4) {
          const stub = parseServerReqChallengeStub(request2.stub, {
            primaryName: scenario.expectPrimaryName,
            computerName: scenario.expectComputerName,
          });
          state.lastChallenge = stub;
          state.queue.push(responsePDU(pdu.callId, request2.contextId, state.challenge));
          return writeOk(request, 16);
        }
        if (request2.opnum === 26 || request2.opnum === 15) {
          const stub = parseServerAuthenticateStub(request2.stub, {
            primaryName: scenario.expectPrimaryName,
            accountName: scenario.expectAccountName,
            computerName: scenario.expectComputerName,
            withAccountRid: request2.opnum === 26,
          });
          state.lastAuthenticate = stub;
          state.lastCredentialWasZero = stub.clientCredential.equals(Buffer.alloc(8));
          // Sticky: the probe deliberately follows the zero-credential attempts with a
          // non-zero control attempt, so a plain assignment would forget the finding.
          state.sawZeroCredential = state.sawZeroCredential || state.lastCredentialWasZero;
          const verdict = scenario.zerologon || "patched";
          let status = STATUS.ACCESS_DENIED;
          if (verdict === "vulnerable" || verdict === "accepts-any") {
            status = STATUS.SUCCESS;
          } else if (verdict === "enforced") {
            status = STATUS.DOWNGRADE_DETECTED;
          } else if (verdict === "patched") {
            status = STATUS.ACCESS_DENIED;
          }
          // Only the all-zero credential is special: a vulnerable controller
          // computes a server credential that can be all zeros, while a random
          // credential still fails. The control probe relies on this.
          if (!state.lastCredentialWasZero && scenario.requireZeroCredential !== false) {
            // A non-zero credential is the control probe: a healthy DC refuses
            // it, so the mock refuses it too, unless the scenario models a
            // server that checks nothing.
            if (verdict !== "accepts-any") {
              status = STATUS.ACCESS_DENIED;
            }
          }
          if (request2.opnum === 15 && scenario.rejectAuthenticate2) {
            status = STATUS.NOT_SUPPORTED;
          }
          const negotiated = scenario.negotiatedFlags !== undefined
            ? scenario.negotiatedFlags
            : (scenario.aesSupported === false ? 0x202fffff : 0x212fffff)
              | (scenario.secureRpcSupported === false ? 0 : 0x40000000);
          state.negotiatedFlags = negotiated;
          const rid = request2.opnum === 26 ? u32(1001) : Buffer.alloc(0);
          const stubOut = Buffer.concat([
            Buffer.from("aabbccdd00112233", "hex"),      // ServerCredential
            u32(negotiated),
            rid,
            u32(status),
          ]);
          state.queue.push(responsePDU(pdu.callId, request2.contextId, stubOut));
          return writeOk(request, 16);
        }
        state.protocolErrors.push(`REQUEST: unsupported opnum ${request2.opnum}`);
        state.queue.push(faultPDU(pdu.callId, 0x000006f7));
        return writeOk(request, 16);
      }
      state.protocolErrors.push(`WRITE: unexpected PDU type ${PDU_NAME[pdu.ptype] || pdu.ptype}`);
      return writeOk(request, 16);
    } catch (err) {
      state.protocolErrors.push(`WRITE(${PDU_NAME[pdu.ptype] || pdu.ptype}): ${err.message}`);
      return writeOk(request, 16);                      // no queued answer -> client timeout
    }
  }

  function writeOk(request, size) {
    const body = Buffer.alloc(16);
    body.writeUInt16LE(17, 0);                          // StructureSize
    body.writeUInt32LE(size, 4);                        // Count
    return statusResponse(request, CMD.WRITE, STATUS.SUCCESS, body);
  }

  function handleRead(request) {
    state.smb.read += 1;
    checkFileId(request.body, 16, "READ");
    if (state.queue.length === 0) {
      const body = Buffer.alloc(16);
      body.writeUInt8(17, 0);
      body.writeUInt32LE(0, 2);
      return statusResponse(request, CMD.READ, STATUS.NO_MORE_FILES, body);
    }
    const pdu = state.queue[0];
    const chunk = scenario.maxReadChunk || pdu.length;
    const data = pdu.subarray(0, Math.min(chunk, pdu.length));
    if (data.length === pdu.length) {
      state.queue.shift();
    } else {
      state.queue[0] = pdu.subarray(data.length);
    }
    const offset = 64 + 16;
    const body = Buffer.alloc(16 + data.length);
    body.writeUInt8(17, 0);
    body.writeUInt8(offset, 1);
    body.writeUInt32LE(data.length, 2);
    body.writeUInt32LE(state.queue.length > 0 ? state.queue[0].length : 0, 6);
    data.copy(body, 16);
    const status = state.queue.length > 0 ? STATUS.BUFFER_OVERFLOW : STATUS.SUCCESS;
    return statusResponse(request, CMD.READ, status, body);
  }

  function handle(hexPayload, proto, meta) {
    const payload = Buffer.from(hexPayload, "hex");
    state.sends += 1;
    state.requests.push({ proto: proto || "tcp", length: payload.length, port: meta && meta.port });
    if (dropThisSend()) {
      return { raw: null };
    }
    if (proto && proto !== "tcp") {
      return { raw: null, error: "the Netlogon probe is a TCP conversation" };
    }
    // SMB over TCP carries a four byte transport header: a zero byte and a
    // 24-bit big-endian length. A client that forgets it, or gets the length
    // wrong, is caught here rather than by a confusing decode failure later.
    if (payload.length < 4) {
      state.protocolErrors.push("frame shorter than the 4 byte SMB transport header");
      return { raw: null, error: "short frame" };
    }
    const frameLength = (payload[1] << 16) | (payload[2] << 8) | payload[3];
    if (payload[0] !== 0) {
      state.protocolErrors.push(`SMB transport header first byte is ${payload[0]}, expected 0`);
    }
    if (frameLength !== payload.length - 4) {
      state.protocolErrors.push(`SMB transport header announces ${frameLength} bytes but ${payload.length - 4} followed`);
    }
    let request;
    try {
      request = parseSMB2Header(payload.subarray(4));
    } catch (err) {
      state.protocolErrors.push(err.message);
      return { raw: null, error: err.message };
    }
    let message;
    try {
      switch (request.command) {
        case CMD.NEGOTIATE:
          state.smb.negotiate += 1;
          message = negotiateResponse(request);
          break;
        case CMD.SESSION_SETUP:
          message = handleSessionSetup(request);
          break;
        case CMD.TREE_CONNECT:
          message = handleTreeConnect(request);
          break;
        case CMD.CREATE:
          message = handleCreate(request);
          break;
        case CMD.WRITE:
          message = handleWrite(request);
          break;
        case CMD.READ:
          message = handleRead(request);
          break;
        case CMD.CLOSE: {
          state.smb.close += 1;
          checkFileId(request.body, 8, "CLOSE");
          const body = Buffer.alloc(60);
          body.writeUInt16LE(60, 0);
          message = statusResponse(request, CMD.CLOSE, STATUS.SUCCESS, body);
          break;
        }
        case CMD.LOGOFF: {
          state.smb.logoff += 1;
          const body = Buffer.alloc(4);
          body.writeUInt16LE(4, 0);
          message = statusResponse(request, CMD.LOGOFF, STATUS.SUCCESS, body);
          break;
        }
        case CMD.TREE_DISCONNECT: {
          const body = Buffer.alloc(4);
          body.writeUInt16LE(4, 0);
          message = statusResponse(request, CMD.TREE_DISCONNECT, STATUS.SUCCESS, body);
          break;
        }
        case CMD.ECHO: {
          const body = Buffer.alloc(4);
          body.writeUInt16LE(4, 0);
          message = statusResponse(request, CMD.ECHO, STATUS.SUCCESS, body);
          break;
        }
        default:
          state.protocolErrors.push(`unsupported SMB2 command ${request.command}`);
          message = statusResponse(request, request.command, STATUS.NOT_SUPPORTED, Buffer.alloc(0));
      }
    } catch (err) {
      state.protocolErrors.push(`command ${CMD_NAME[request.command] || request.command}: ${err.message}`);
      message = statusResponse(request, request.command, STATUS.INVALID_PARAMETER, Buffer.alloc(0));
    }
    let framed = smb2Frame(message);
    if (scenario.coalesceFrames) {
      // An unrelated frame (a stale ECHO response for a different message id)
      // ahead of the real answer: the client must skip it.
      const stray = smb2Frame(statusResponse(
        { messageId: 0xdead, treeId: 0, sessionId: 0 }, CMD.ECHO, STATUS.SUCCESS, Buffer.alloc(4)));
      framed = Buffer.concat([stray, framed]);
    }
    return { raw: framed };
  }

  return { handle, state };
}

module.exports = {
  createMockNetlogon,
  parseServerReqChallengeStub,
  parseServerAuthenticateStub,
  parseBindPDU,
  parsePDU,
  uuidBytes,
  uuidText,
  STATUS,
  CMD,
  PDU,
};
