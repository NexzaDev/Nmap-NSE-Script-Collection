"use strict";
/*
 * tools/mocks/rabbitmq.js
 * ---------------------------------------------------------------------------
 * The broker side of the AMQP 0-9-1 engine and of the rabbitmq_management HTTP
 * API, written independently of nselib/rabbitmq.lua: the mock encodes frames,
 * field tables and JSON documents from its own tables, so an encoder bug in the
 * library cannot be mirrored by the mock that is supposed to catch it.
 *
 * Two listeners are served from one mock, dispatched on the destination port:
 *   * 5672  AMQP 0-9-1: protocol header, connection.start (with the broker's own
 *           capability table, SASL mechanisms and locales), start-ok parsing and
 *           authentication against the configured accounts, tune, open, vhost
 *           authorisation, channel.open and passive queue.declare.
 *   * 15672 rabbitmq_management: a routing table of the documented endpoints,
 *           each with its own authentication and permission requirement, plus
 *           the response shapes that make a scanner's life hard - chunked
 *           bodies, truncated bodies, HTML error pages, redirects.
 *
 * Everything a script could do that changes broker state is recorded in
 * state.violations instead of being silently allowed: a non-passive queue
 * declaration, a purge, a definitions import, or a queue get with the
 * destructive ackmode. A suite asserting "no violations" is then asserting that
 * the scan is read-only, which is the property the scripts claim.
 */

const crypto = require("crypto");

const FRAME_METHOD = 1;
const FRAME_HEADER = 2;
const FRAME_BODY = 3;
const FRAME_HEARTBEAT = 8;
const FRAME_END = 0xce;

// -- field table codec -------------------------------------------------------
// AMQP 0-9-1 long string tables: a 4 byte length, then entries of
// (short name, type character, value). Types RabbitMQ emits and this mock
// produces: t boolean, b/B byte, U/u short, I/i long, L/l long long,
// f/d float and double, D decimal, s short string, S long string, A array,
// T timestamp, F nested table, V void, x byte array.

function writeShortString(value) {
  const text = Buffer.from(String(value), "utf8").subarray(0, 255);
  return Buffer.concat([Buffer.from([text.length]), text]);
}

function writeLongString(value) {
  const text = Buffer.from(String(value), "utf8");
  const out = Buffer.alloc(4);
  out.writeUInt32BE(text.length, 0);
  return Buffer.concat([out, text]);
}

function writeFieldEntry(name, value) {
  const head = writeShortString(name);
  if (typeof value === "boolean") return Buffer.concat([head, Buffer.from("t"), Buffer.from([value ? 1 : 0])]);
  if (typeof value === "string") return Buffer.concat([head, Buffer.from("S"), writeLongString(value)]);
  if (typeof value === "number") {
    const body = Buffer.alloc(5);
    body.writeInt8(0x49, 0); // 'I'
    body.writeInt32BE(value | 0, 1);
    return Buffer.concat([head, body]);
  }
  if (Array.isArray(value)) {
    const items = Buffer.concat(value.map((item) => encodeFieldValue(item)));
    const size = Buffer.alloc(4);
    size.writeUInt32BE(items.length, 0);
    return Buffer.concat([head, Buffer.from("A"), size, items]);
  }
  if (value && typeof value === "object") {
    return Buffer.concat([head, Buffer.from("F"), writeTable(value)]);
  }
  return Buffer.concat([head, Buffer.from("V")]);
}

function encodeFieldValue(value) {
  if (typeof value === "boolean") return Buffer.concat([Buffer.from("t"), Buffer.from([value ? 1 : 0])]);
  if (typeof value === "string") return Buffer.concat([Buffer.from("S"), writeLongString(value)]);
  if (Array.isArray(value)) {
    const items = Buffer.concat(value.map(encodeFieldValue));
    const size = Buffer.alloc(4);
    size.writeUInt32BE(items.length, 0);
    return Buffer.concat([Buffer.from("A"), size, items]);
  }
  if (value && typeof value === "object") return Buffer.concat([Buffer.from("F"), writeTable(value)]);
  return Buffer.from("V");
}

function writeTable(values) {
  const names = Object.keys(values || {}).sort();
  const body = Buffer.concat(names.map((name) => writeFieldEntry(name, values[name])));
  const size = Buffer.alloc(4);
  size.writeUInt32BE(body.length, 0);
  return Buffer.concat([size, body]);
}

function readFieldValue(buf, state) {
  const type = String.fromCharCode(buf[state.offset]);
  state.offset += 1;
  switch (type) {
    case "t": {
      const value = buf[state.offset] !== 0;
      state.offset += 1;
      return value;
    }
    case "b": {
      const value = buf.readInt8(state.offset);
      state.offset += 1;
      return value;
    }
    case "B": {
      const value = buf[state.offset];
      state.offset += 1;
      return value;
    }
    case "U": {
      const value = buf.readInt16BE(state.offset);
      state.offset += 2;
      return value;
    }
    case "u": {
      const value = buf.readUInt16BE(state.offset);
      state.offset += 2;
      return value;
    }
    case "I": {
      const value = buf.readInt32BE(state.offset);
      state.offset += 4;
      return value;
    }
    case "i": {
      const value = buf.readUInt32BE(state.offset);
      state.offset += 4;
      return value;
    }
    case "L":
    case "T": {
      const high = buf.readInt32BE(state.offset);
      const low = buf.readUInt32BE(state.offset + 4);
      state.offset += 8;
      return high * 4294967296 + low;
    }
    case "l": {
      const high = buf.readUInt32BE(state.offset);
      const low = buf.readUInt32BE(state.offset + 4);
      state.offset += 8;
      return high * 4294967296 + low;
    }
    case "f": {
      const value = buf.readFloatBE(state.offset);
      state.offset += 4;
      return value;
    }
    case "d": {
      const value = buf.readDoubleBE(state.offset);
      state.offset += 8;
      return value;
    }
    case "D": {
      const scale = buf[state.offset];
      const value = buf.readUInt32BE(state.offset + 1);
      state.offset += 5;
      return value / 10 ** scale;
    }
    case "s": {
      const length = buf[state.offset];
      const value = buf.subarray(state.offset + 1, state.offset + 1 + length).toString("latin1");
      state.offset += 1 + length;
      return value;
    }
    case "S":
    case "x": {
      const length = buf.readUInt32BE(state.offset);
      const value = buf.subarray(state.offset + 4, state.offset + 4 + length);
      state.offset += 4 + length;
      return type === "x" ? value : value.toString("utf8");
    }
    case "A": {
      const length = buf.readUInt32BE(state.offset);
      const end = state.offset + 4 + length;
      state.offset += 4;
      const items = [];
      while (state.offset < end) items.push(readFieldValue(buf, state));
      return items;
    }
    case "F": {
      const length = buf.readUInt32BE(state.offset);
      const end = state.offset + 4 + length;
      state.offset += 4;
      const table = {};
      while (state.offset < end) {
        const nameLength = buf[state.offset];
        const name = buf.subarray(state.offset + 1, state.offset + 1 + nameLength).toString("latin1");
        state.offset += 1 + nameLength;
        table[name] = readFieldValue(buf, state);
      }
      return table;
    }
    case "V":
    default:
      return null;
  }
}

// A field table whose declared length does not fit in what arrived is a
// truncated table, not a crash: the parser reports what it could read and marks
// the result, which is what a broker does when a client sends it nonsense.
function readTable(buf, offset) {
  const table = {};
  if (!buf || buf.length < offset + 4) return { table, offset: buf ? buf.length : 0, truncated: true };
  const length = buf.readUInt32BE(offset);
  const state = { offset: offset + 4 };
  const end = Math.min(state.offset + length, buf.length);
  const truncated = state.offset + length > buf.length;
  while (state.offset < end) {
    if (state.offset + 1 > buf.length) break;
    const nameLength = buf[state.offset];
    if (state.offset + 1 + nameLength > buf.length) break;
    const name = buf.subarray(state.offset + 1, state.offset + 1 + nameLength).toString("latin1");
    state.offset += 1 + nameLength;
    try {
      table[name] = readFieldValue(buf, state);
    } catch (error) {
      return { table, offset: state.offset, truncated: true, error: error.message };
    }
  }
  return { table, offset: end };
}

function readShortString(buf, offset) {
  const length = buf[offset];
  return { value: buf.subarray(offset + 1, offset + 1 + length).toString("latin1"), offset: offset + 1 + length };
}

function readLongString(buf, offset) {
  const length = buf.readUInt32BE(offset);
  return { value: buf.subarray(offset + 4, offset + 4 + length), offset: offset + 4 + length };
}

// -- frames ------------------------------------------------------------------
function header(classId, methodId, body) {
  const out = Buffer.alloc(4);
  out.writeUInt16BE(classId, 0);
  out.writeUInt16BE(methodId, 2);
  return Buffer.concat([out, body || Buffer.alloc(0)]);
}

function frame(type, channel, payload) {
  const out = Buffer.alloc(7);
  out.writeUInt8(type, 0);
  out.writeUInt16BE(channel, 1);
  out.writeUInt32BE(payload.length, 3);
  return Buffer.concat([out, payload, Buffer.from([FRAME_END])]);
}

function methodFrame(classId, methodId, channel, body) {
  return frame(FRAME_METHOD, channel || 0, header(classId, methodId, body));
}

function u16(value) {
  const out = Buffer.alloc(2);
  out.writeUInt16BE(value & 0xffff, 0);
  return out;
}

function u32(value) {
  const out = Buffer.alloc(4);
  out.writeUInt32BE(value >>> 0, 0);
  return out;
}

function bit(value) {
  return Buffer.from([value ? 1 : 0]);
}

// -- the AMQP side -----------------------------------------------------------
const CLASS_NAMES = {
  10: { name: "connection", methods: { 11: "start-ok", 31: "tune-ok", 40: "open", 50: "close", 51: "close-ok" } },
  20: { name: "channel", methods: { 10: "open", 20: "flow", 21: "flow-ok", 40: "close", 41: "close-ok" } },
  40: { name: "exchange", methods: { 10: "declare", 20: "delete", 30: "bind", 40: "unbind" } },
  50: { name: "queue", methods: { 10: "declare", 20: "bind", 30: "purge", 40: "delete", 50: "unbind" } },
  60: { name: "basic", methods: { 10: "qos", 20: "consume", 30: "cancel", 40: "publish", 70: "get",
    80: "ack", 90: "reject", 110: "recover", 120: "nack" } },
  85: { name: "confirm", methods: { 10: "select" } },
  90: { name: "tx", methods: { 10: "select", 20: "commit", 30: "rollback" } },
};

function methodName(classId, methodId) {
  const entry = CLASS_NAMES[classId];
  if (!entry) return `class-${classId}.${methodId}`;
  return `${entry.name}.${entry.methods[methodId] || `method-${methodId}`}`;
}

function createMockRabbitMQ(options = {}) {
  const scenario = Object.assign({
    // AMQP
    amqpPort: 5672,
    version: "3.13.7",
    product: "RabbitMQ",
    platform: "Erlang/OTP 26.2.1",
    clusterName: "rabbit@node1",
    mechanisms: ["PLAIN", "AMQPLAIN"],
    locales: ["en_US"],
    capabilities: {
      publisher_confirms: true,
      exchange_exchange_bindings: true,
      basic_nack: true,
      consumer_cancel_notify: true,
      connection_blocked: true,
      consumer_priorities: true,
      authentication_failure_close: true,
      per_consumer_qos: true,
      direct_reply_to: true,
    },
    vhosts: ["/"],
    channelMax: 2047,
    frameMax: 131072,
    heartbeat: 60,
    // Accounts: an empty object means "authentication is disabled and every
    // connection opens", which is a configuration RabbitMQ allows on purpose
    // (the rabbitmq_auth_backend_* plugins and the loopback user exemptions).
    credentials: {},
    acceptAnonymous: false,
    acceptAnyPassword: false,
    guestFromRemote: false, // guest/guest only from 127.0.0.1 since 3.3
    authenticationFailureClose: true,
    authHang: false,          // accept the connection and never answer start-ok
    dropAfterHeader: false,   // a port that answers nothing at all
    closeAfterHeader: false,  // accepts, then closes without a byte
    httpOnAmqpPort: false,    // an HTTP listener that answers the AMQP header
    protocolMismatch: "close", // close | amqp1 | http
    truncateStart: false,     // send a frame whose payload is short
    heartbeatBeforeStart: false,
    queues: {},               // "vhost/name" -> { messages, consumers, durable, arguments }
    queueAccessDenied: [],
    // management HTTP API
    httpPort: 15672,
    httpAnonymous: [],        // paths that answer without credentials
    httpRequireAuth: true,
    httpCredentials: { guest: "guest", monitoring: "monitor-pass", legacy: "legacy-pass" },
    httpTags: { guest: "administrator", monitoring: "monitoring", legacy: "administrator" },
    httpPermissionByPath: {}, // path prefix -> required tag
    httpChunked: false,
    httpTruncateBody: 0,
    httpHtmlErrors: false,
    httpRedirect: null,       // { from: "/api/definitions", to: "http://127.0.0.1:15672/api/overview" }
    httpServerHeader: "Cowboy",
    httpDocuments: {},
    messagePayloads: null,
  }, options);

  const state = {
    requests: [],
    amqpFrames: [],
    amqpAttempts: [],
    httpRequests: [],
    protocolErrors: [],
    violations: [],
    openedVhosts: [],
    declaredQueues: [],
    messageReads: [],
    authFailures: [],
    tlsHellos: [],
    protocolHeaders: [],
    tlsHellosOnPlaintext: 0,
    scram: null,
  };

  // -- AMQP ---------------------------------------------------------------
  function serverProperties() {
    const properties = {
      capabilities: scenario.capabilities,
      product: scenario.product,
      version: scenario.version,
      platform: scenario.platform,
      copyright: "Copyright (c) 2007-2024 Broadcom Inc. and/or its subsidiaries.",
      information: "Licensed under the MPL 2.0. Website: https://rabbitmq.com",
    };
    if (scenario.clusterName) properties.cluster_name = scenario.clusterName;
    return properties;
  }

  function connectionStart() {
    const body = Buffer.concat([
      Buffer.from([0, 9]),
      writeTable(serverProperties()),
      writeLongString(scenario.mechanisms.join(" ")),
      writeLongString(scenario.locales.join(" ")),
    ]);
    return methodFrame(10, 10, 0, body);
  }

  function connectionClose(code, text, classId, methodId) {
    const body = Buffer.concat([
      u16(code),
      writeShortString(text),
      u16(classId || 0),
      u16(methodId || 0),
    ]);
    return methodFrame(10, 50, 0, body);
  }

  function channelClose(channel, code, text, classId, methodId) {
    const body = Buffer.concat([
      u16(code),
      writeShortString(text),
      u16(classId || 0),
      u16(methodId || 0),
    ]);
    return methodFrame(20, 40, channel, body);
  }

  // A PLAIN response is "\0user\0password" exactly: two separators. Anything
  // else is not a PLAIN response, and treating it as one is how a permissive
  // backend turns a malformed probe into a session.
  function parsePlain(response) {
    const text = response.toString("latin1");
    const parts = text.split("\0");
    if (parts.length === 3) return { user: parts[1], password: parts[2], form: "PLAIN" };
    return { user: text, password: "", form: "PLAIN-malformed", malformed: true };
  }

  function parseAmqplain(response) {
    const parsed = readTable(response, 0);
    const table = parsed.table || {};
    if (parsed.truncated || table.LOGIN === undefined) {
      return { user: "", password: "", form: "AMQPLAIN-malformed", malformed: true };
    }
    return { user: table.LOGIN, password: table.PASSWORD, form: "AMQPLAIN" };
  }

  function credentialsAccepted(user, password, mechanism) {
    // The mechanisms that carry no password are accepted or refused by their own
    // configuration: the anonymous plugin has its own account, and EXTERNAL
    // depends on what the transport proved.
    if (mechanism === "ANONYMOUS") {
      return scenario.acceptAnonymous
        ? { ok: true, reason: "the anonymous plugin accepts the connection" }
        : { ok: false, code: 403, reason: "anonymous access is disabled" };
    }
    if (mechanism === "EXTERNAL") {
      return scenario.acceptExternal
        ? { ok: true, reason: "the transport identity was accepted" }
        : { ok: false, code: 403, reason: "no transport identity is configured" };
    }
    if (scenario.acceptAnyPassword) return { ok: true, reason: "the broker accepts any password" };
    if (scenario.acceptAnonymous) return { ok: true, reason: "the broker allows anonymous access" };
    // A broker does not accept an identity it does not know: with no account
    // configured the mock falls back to the one RabbitMQ always has, so an
    // unconfigured scenario still refuses an unknown user instead of waving it
    // through.
    const accounts = Object.assign({ guest: "guest" }, scenario.credentials || {});
    const expected = accounts[user];
    if (expected === undefined) {
      return { ok: false, code: 403, reason: `user '${user}' does not exist` };
    }
    if (expected !== password) return { ok: false, code: 403, reason: "password does not match" };
    if (user === "guest" && !scenario.guestFromRemote) {
      // guest is restricted to loopback; a remote connection is refused with a
      // message that says exactly why, which is what a scan quotes.
      return { ok: false, code: 403, reason: "user 'guest' can only connect via localhost" };
    }
    return { ok: true, reason: "the credentials match the configured account" };
  }

  function handleProtocolHeader(payload) {
    const major = payload[5];
    const minor = payload[6];
    const revision = payload[7];
    state.protocolHeader = { major, minor, revision, bytes: payload.length };
    state.protocolHeaders.push(state.protocolHeader);
    if (major === 0 && minor === 9 && revision === 1) {
      if (scenario.dropAfterHeader) return null;
      if (scenario.closeAfterHeader) return { raw: Buffer.alloc(0) };
      if (scenario.httpOnAmqpPort) {
        return { raw: Buffer.from("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n", "latin1") };
      }
      const frames = [connectionStart()];
      if (scenario.heartbeatBeforeStart) frames.unshift(frame(FRAME_HEARTBEAT, 0, Buffer.alloc(0)));
      if (scenario.truncateStart) {
        const truncated = connectionStart();
        truncated.writeUInt32BE(truncated.readUInt32BE(3) + 64, 3);
        return { raw: truncated };
      }
      return { raw: Buffer.concat(frames) };
    }
    // A protocol version the broker does not speak is answered with the
    // broker's own protocol header and then a close, which is what the
    // specification requires and what RabbitMQ does.
    if (scenario.protocolMismatch === "silent") return null;
    if (scenario.protocolMismatch !== "http" && scenario.protocolMismatch !== "amqp1") {
      return { raw: Buffer.from("AMQP\x00\x00\x09\x01", "latin1") };
    }
    if (scenario.protocolMismatch === "http") {
      return { raw: Buffer.from("HTTP/1.0 505 HTTP Version Not Supported\r\nContent-Length: 0\r\n\r\n", "latin1") };
    }
    if (scenario.protocolMismatch === "amqp1") {
      return { raw: Buffer.concat([Buffer.from("AMQP\x00\x01\x00\x00", "latin1"),
        frame(FRAME_METHOD, 0, Buffer.concat([Buffer.from([0, 1]), Buffer.alloc(0)]))]) };
    }
    return null;
  }

  function parseFrame(payload, offset) {
    if (payload.length < offset + 7) {
      state.protocolErrors.push("frame header shorter than 7 bytes");
      return null;
    }
    const type = payload[offset];
    const channel = payload.readUInt16BE(offset + 1);
    const size = payload.readUInt32BE(offset + 3);
    if (payload.length < offset + 7 + size + 1) {
      state.protocolErrors.push(`frame announces ${size} byte(s) but only ${payload.length - offset - 8} arrived`);
      return null;
    }
    const body = payload.subarray(offset + 7, offset + 7 + size);
    const end = payload[offset + 7 + size];
    if (end !== FRAME_END) state.protocolErrors.push(`frame end marker is 0x${end.toString(16)}`);
    const out = { type, channel, size, body, next: offset + 8 + size };
    if (type === FRAME_METHOD) {
      out.classId = body.readUInt16BE(0);
      out.methodId = body.readUInt16BE(2);
      out.args = body.subarray(4);
      out.method = methodName(out.classId, out.methodId);
    }
    return out;
  }

  function handleConnectionStartOk(packet) {
    const clientProperties = readTable(packet.args, 0);
    let offset = clientProperties.offset;
    const mechanism = readShortString(packet.args, offset);
    offset = mechanism.offset;
    const response = readLongString(packet.args, offset);
    offset = response.offset;
    const locale = readShortString(packet.args, offset);
    // Each mechanism carries its response in its own shape: AMQPLAIN a field
    // table, ANONYMOUS and EXTERNAL the identity as plain bytes, PLAIN the
    // NUL-separated triple.
    let parsed;
    if (mechanism.value === "AMQPLAIN") parsed = parseAmqplain(response.value);
    else if (mechanism.value === "ANONYMOUS") {
      parsed = { user: response.value.toString("utf8"), password: "", form: "ANONYMOUS" };
    } else if (mechanism.value === "EXTERNAL") {
      parsed = { user: response.value.toString("utf8"), password: "", form: "EXTERNAL" };
    } else parsed = parsePlain(response.value);
    if (parsed.malformed) {
      // A response that is not well formed for the mechanism it claims: the
      // ordinary broker refuses it, and a backend that accepts it is the finding
      // the shape probe is looking for. It is recorded as an attempt either way.
      state.amqpAttempts.push({ mechanism: mechanism.value, form: parsed.form, user: parsed.user,
        passwordBytes: 0, responseBytes: response.value.length, locale: locale.value,
        malformed: true, clientProduct: clientProperties.table.product });
      state.lastMechanism = mechanism.value;
      state.authFailures.push({ user: parsed.user, mechanism: mechanism.value, reason: "malformed response" });
      if (!scenario.acceptMalformed) {
        return { raw: scenario.authenticationFailureClose
          ? connectionClose(403, "ACCESS_REFUSED - malformed SASL response", 10, 11)
          : Buffer.alloc(0) };
      }
      state.authenticated = { user: parsed.user || scenario.anonymousUser || "anonymous",
        mechanism: mechanism.value };
      const tune = Buffer.concat([u16(scenario.channelMax), u32(scenario.frameMax), u16(scenario.heartbeat)]);
      return { raw: methodFrame(10, 30, 0, tune) };
    }
    const attempt = {
      mechanism: mechanism.value,
      form: parsed.form,
      user: parsed.user,
      passwordBytes: parsed.password ? parsed.password.length : 0,
      responseBytes: response.value.length,
      locale: locale.value,
      clientProduct: clientProperties.table.product,
      clientCapabilities: clientProperties.table.capabilities || {},
    };
    state.amqpAttempts.push(attempt);
    state.lastMechanism = mechanism.value;
    const offered = scenario.mechanisms.indexOf(mechanism.value) >= 0;
    if (!offered) {
      state.authFailures.push({ ...attempt, reason: "mechanism not offered" });
      return { raw: scenario.authenticationFailureClose
        ? connectionClose(403, `SASL mechanism ${mechanism.value} not offered`, 10, 11)
        : Buffer.alloc(0) };
    }
    const verdict = credentialsAccepted(parsed.user, parsed.password, mechanism.value);
    attempt.accepted = verdict.ok;
    attempt.reason = verdict.reason;
    if (!verdict.ok) state.authFailures.push({ ...attempt, reason: verdict.reason });
    if (scenario.authHang) return null; // the connection is accepted and then nothing
    if (!verdict.ok) {
      if (!scenario.authenticationFailureClose) return { raw: Buffer.alloc(0) };
      // RabbitMQ sends the generic ACCESS_REFUSED text in the close frame and
      // puts the reason in its log. A broker (or an authentication backend)
      // that echoes the reason is modelled by closeRefusalReason, because that
      // echoed reason is what turns the login path into an enumeration oracle.
      const text = scenario.closeRefusalReason
        ? `ACCESS_REFUSED - ${verdict.reason}`
        : `ACCESS_REFUSED - Login was refused using authentication mechanism ${mechanism.value}. For details see the broker logfile.`;
      return { raw: connectionClose(verdict.code, text, 10, 11) };
    }
    state.authenticated = { user: parsed.user, mechanism: mechanism.value };
    const tune = Buffer.concat([u16(scenario.channelMax), u32(scenario.frameMax), u16(scenario.heartbeat)]);
    return { raw: methodFrame(10, 30, 0, tune) };
  }

  function handleConnectionOpen(packet) {
    const vhost = readShortString(packet.args, 0);
    state.openedVhosts.push(vhost.value);
    if (scenario.vhosts.indexOf(vhost.value) < 0) {
      return { raw: connectionClose(530, `NOT_ALLOWED - vhost ${vhost.value} not found`, 10, 40) };
    }
    if (scenario.vhostAccessDenied && scenario.vhostAccessDenied.indexOf(vhost.value) >= 0) {
      return { raw: connectionClose(530, `NOT_ALLOWED - access to vhost '${vhost.value}' refused for user '${(state.authenticated || {}).user}'`, 10, 40) };
    }
    return { raw: methodFrame(10, 41, 0, writeShortString("")) };
  }

  function handleQueueDeclare(packet) {
    let offset = 2; // reserved-1
    const queue = readShortString(packet.args, offset);
    offset = queue.offset;
    const flags = packet.args[offset];
    offset += 1;
    const passive = (flags & 0x01) !== 0;
    const durable = (flags & 0x02) !== 0;
    const exclusive = (flags & 0x04) !== 0;
    const autoDelete = (flags & 0x08) !== 0;
    const noWait = (flags & 0x10) !== 0;
    const entry = { queue: queue.value, passive, durable, exclusive, autoDelete, channel: packet.channel };
    state.declaredQueues.push(entry);
    if (!passive) {
      // A passive declaration cannot create anything; anything else can, and an
      // audit has no business creating queues on a production broker.
      state.violations.push({ kind: "queue.declare-not-passive", queue: queue.value, channel: packet.channel });
    }
    if (passive && scenario.queueAccessDenied.indexOf(`${state.vhost}/${queue.value}`) >= 0) {
      return { raw: channelClose(packet.channel, 403, `ACCESS_REFUSED - access to queue '${queue.value}' in vhost '${state.vhost}' refused for user '${(state.authenticated || {}).user}'`, 50, 10) };
    }
    const key = `${state.vhost}/${queue.value}`;
    const info = scenario.queues[key];
    if (passive && !info) {
      return { raw: channelClose(packet.channel, 404, `NOT_FOUND - no queue '${queue.value}' in vhost '${state.vhost}'`, 50, 10) };
    }
    const record = info || { messages: 0, consumers: 0 };
    const body = Buffer.concat([
      writeShortString(queue.value),
      u32(record.messages || 0),
      u32(record.consumers || 0),
    ]);
    if (noWait) return { raw: Buffer.alloc(0) };
    return { raw: methodFrame(50, 11, packet.channel, body) };
  }

  // -- TLS ------------------------------------------------------------------
  // A listener that speaks TLS cannot answer a plaintext protocol, and a plaintext
  // listener cannot answer a ClientHello: whichever arrives is the wrong shape for
  // the other, and the difference is what the transport probe has to see.
  function tlsRecord(type, body) {
    const head = Buffer.alloc(5);
    head.writeUInt8(type, 0);
    head.writeUInt16BE(0x0303, 1);
    head.writeUInt16BE(body.length, 3);
    return Buffer.concat([head, body]);
  }

  function tlsServerHello(hello) {
    const random = Buffer.alloc(32, 7);
    const cipher = Buffer.from([0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    const supportedVersions = Buffer.from([0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
    const keyShareBody = Buffer.concat([Buffer.from([0x00, 0x1d, 0x00, 0x20]), Buffer.alloc(32, 9)]);
    const keyShare = Buffer.concat([Buffer.from([0x00, 0x33]),
      Buffer.from([(keyShareBody.length >> 8) & 0xff, keyShareBody.length & 0xff]), keyShareBody]);
    const all = Buffer.concat([supportedVersions, keyShare]);
    const extensionBlock = Buffer.concat([Buffer.from([(all.length >> 8) & 0xff, all.length & 0xff]), all]);
    const body = Buffer.concat([Buffer.from([0x03, 0x03]), random, Buffer.from([0]), cipher,
      Buffer.from([0]), extensionBlock]);
    const handshake = Buffer.concat([Buffer.from([2]), Buffer.from([
      (body.length >> 16) & 0xff, (body.length >> 8) & 0xff, body.length & 0xff]), body]);
    state.tlsHellos.push({ bytes: hello.length, answer: "server-hello" });
    return tlsRecord(22, handshake);
  }

  function isTlsHello(payload) {
    return payload.length > 5 && payload[0] === 0x16 && payload[1] === 0x03;
  }

  // The transport answer for one payload: a TLS listener answers a hello and
  // rejects anything else with an alert, a plaintext listener answers its own
  // protocol and treats a hello as garbage.
  function handleTlsPayload(payload) {
    if (isTlsHello(payload)) {
      if (scenario.tls === "alert") {
        state.tlsHellos.push({ bytes: payload.length, answer: "alert" });
        return { raw: tlsRecord(21, Buffer.from([2, scenario.tlsAlert === undefined ? 40 : scenario.tlsAlert])) };
      }
      if (scenario.tls === "junk") {
        state.tlsHellos.push({ bytes: payload.length, answer: "junk" });
        return { raw: Buffer.from(scenario.tlsJunk || "HTTP/1.0 400 Bad Request\r\n\r\n", "latin1") };
      }
      return { raw: tlsServerHello(payload) };
    }
    // Plaintext on a TLS port: RabbitMQ answers a TLS alert (or closes), and it
    // certainly does not parse AMQP out of it. That is the listener behaving
    // correctly, so it is counted rather than recorded as a protocol error.
    state.plaintextOnTlsPort = (state.plaintextOnTlsPort || 0) + 1;
    return { raw: tlsRecord(21, Buffer.from([2, 10])) };
  }

  function handleAmqpPayload(payload) {
    if (scenario.tls) return handleTlsPayload(payload);
    // A ClientHello sent to a plaintext listener is not a protocol error, it is
    // the transport probe doing its job: the listener has nothing to say to TLS
    // and the client learns the port speaks its own protocol in the clear.
    if (isTlsHello(payload)) {
      state.tlsHellosOnPlaintext = (state.tlsHellosOnPlaintext || 0) + 1;
      return null;
    }
    if (payload.length >= 8 && payload.subarray(0, 4).toString("latin1") === "AMQP") {
      const headerReply = handleProtocolHeader(payload);
      return headerReply;
    }
    // A client that connected without a protocol header is speaking into the
    // void; the mock says so instead of guessing what it meant.
    if (payload.length >= 1 && !state.negotiating && !state.protocolHeader) {
      state.protocolErrors.push("frame sent before the AMQP protocol header");
    }
    let offset = 0;
    const replies = [];
    while (offset < payload.length) {
      const packet = parseFrame(payload, offset);
      if (!packet) break;
      offset = packet.next;
      state.amqpFrames.push({ method: packet.method || `frame-${packet.type}`, channel: packet.channel, bytes: packet.size });
      if (packet.type === FRAME_HEARTBEAT) continue;
      if (packet.classId === 10 && packet.methodId === 11) {
        state.protocolHeader = state.protocolHeader || { major: 0, minor: 9, revision: 1 };
        const reply = handleConnectionStartOk(packet);
        if (reply && reply.raw) replies.push(reply.raw);
        continue;
      }
      if (packet.classId === 10 && packet.methodId === 31) {
        const accepted = {};
        accepted.channelMax = packet.args.readUInt16BE(0);
        accepted.frameMax = packet.args.readUInt32BE(2);
        accepted.heartbeat = packet.args.readUInt16BE(6);
        state.tuneOk = accepted;
        continue; // the server says nothing until connection.open
      }
      if (packet.classId === 10 && packet.methodId === 40) {
        const vhost = readShortString(packet.args, 0);
        state.vhost = vhost.value;
        const reply = handleConnectionOpen(packet);
        if (reply && reply.raw) replies.push(reply.raw);
        continue;
      }
      if (packet.classId === 10 && packet.methodId === 50) {
        state.connectionClosed = true;
        replies.push(methodFrame(10, 51, 0, Buffer.alloc(0)));
        continue;
      }
      if (packet.classId === 20 && packet.methodId === 10) {
        replies.push(methodFrame(20, 11, packet.channel, writeLongString("")));
        continue;
      }
      if (packet.classId === 20 && packet.methodId === 40) {
        replies.push(methodFrame(20, 41, packet.channel, Buffer.alloc(0)));
        continue;
      }
      if (packet.classId === 50 && packet.methodId === 10) {
        const reply = handleQueueDeclare(packet);
        if (reply && reply.raw) replies.push(reply.raw);
        continue;
      }
      if (packet.classId === 60 && packet.methodId === 10) {
        // basic.qos is answered on the channel and touches no queue, so it is a
        // legitimate liveness question rather than a state change.
        state.qosRequests = (state.qosRequests || 0) + 1;
        replies.push(methodFrame(60, 11, packet.channel, Buffer.alloc(0)));
        continue;
      }
      if (packet.classId === 60 && packet.methodId === 70) {
        // basic.get would hand message bodies to the caller; the AMQP half of
        // the mock answers get-empty, because reading payloads is the management
        // API's job and a scan that goes looking here is doing something else.
        replies.push(methodFrame(60, 72, packet.channel, writeShortString("")));
        continue;
      }
      if (packet.classId === 40 || packet.classId === 50 || packet.classId === 60 || packet.classId === 85
        || packet.classId === 90) {
        state.violations.push({ kind: "amqp-request-outside-an-audit", method: packet.method,
          channel: packet.channel });
        continue;
      }
    }
    if (replies.length === 0) return { raw: null };
    return { raw: Buffer.concat(replies) };
  }

  // -- dispatch -------------------------------------------------------------
  function handle(payload, proto, meta) {
    const port = meta && meta.port;
    state.requests.push({ port, bytes: payload.length, at: Date.now() });
    if (port === scenario.httpPort) return handleHttpPayload(payload);
    const reply = handleAmqpPayload(Buffer.from(payload));
    if (!reply || !reply.raw) return null;
    return { raw: reply.raw };
  }

  // -- management HTTP API -------------------------------------------------
  // Every document below is shaped like the real one (field names, nesting and
  // value types), because a script that reads /api/queues/<vhost>/<name> has to
  // find the same keys a real broker sends. The scenario can override any
  // document wholesale through httpDocuments.

  function defaultDocuments() {
    const passwordHash256 = "rabbit_password_hashing_sha256:" + crypto.createHash("sha256")
      .update("nse-mock-salt" + "guest").digest("base64").slice(0, 44);
    const passwordHash512 = "rabbit_password_hashing_sha512:" + crypto.createHash("sha512")
      .update("nse-mock-salt" + "monitoring").digest("base64").slice(0, 88);
    const legacyHash = Buffer.from("nse-mock-salt").toString("base64")
      + Buffer.from("legacy-pass").toString("base64");
    const queues = [
      {
        name: "orders", vhost: "prod", type: "quorum", state: "running", node: "rabbit@node1",
        durable: true, auto_delete: false, exclusive: false, arguments: { "x-queue-type": "quorum", "x-message-ttl": 86400000 },
        messages: 5, messages_ready: 5, messages_unacknowledged: 0, consumers: 0, policy: "ha-quorum",
        head_message_timestamp: 1739000000000, exclusive_consumer_tag: null,
        message_stats: { publish: 128, deliver: 123, ack: 123, deliver_get: 5 },
        consumer_utilisation: null, effective_policy_definition: { "ha-mode": "all" },
      },
      {
        name: "audit.events", vhost: "/", type: "classic", state: "running", node: "rabbit@node1",
        durable: false, auto_delete: true, exclusive: false, arguments: {},
        messages: 1, messages_ready: 1, messages_unacknowledged: 0, consumers: 1,
        message_stats: { publish: 9, deliver: 8, ack: 8 },
      },
    ];
    const users = [
      { name: "guest", tags: "administrator", password_hash: passwordHash256,
        hashing_algorithm: "rabbit_password_hashing_sha256", limits: {} },
      { name: "monitoring", tags: "monitoring", password_hash: passwordHash512,
        hashing_algorithm: "rabbit_password_hashing_sha512", limits: {} },
      { name: "legacy", tags: "administrator", password_hash: legacyHash,
        hashing_algorithm: "rabbit_password_hashing_md5", limits: {} },
    ];
    const connections = [
      {
        name: "127.0.0.1:52144 -> 127.0.0.1:5672", node: "rabbit@node1", vhost: "/", user: "guest",
        peer_host: "127.0.0.1", peer_port: 52144, host: "127.0.0.1", port: 5672, ssl: false,
        auth_mechanism: "PLAIN", protocol: "AMQP 0-9-1", state: "running", channels: 2,
        frame_max: 131072, timeout: 60, client_properties: { product: "pika", platform: "Python 3.11",
          version: "1.3.2", connection_name: "order-worker-1" },
      },
    ];
    const channels = [
      { name: "127.0.0.1:52144 -> 127.0.0.1:5672 (1)", connection_details: { name: "127.0.0.1:52144 -> 127.0.0.1:5672" },
        node: "rabbit@node1", number: 1, user: "guest", vhost: "/", state: "running", consumer_count: 1,
        messages_unacknowledged: 0, prefetch_count: 10, confirm: false, transactional: false },
    ];
    const consumers = [
      { consumer_tag: "ctag-order-worker-1", exclusive: false, ack_required: true,
        queue: { name: "audit.events", vhost: "/" }, channel_details: { name: "127.0.0.1:52144 -> 127.0.0.1:5672 (1)",
          number: 1 }, prefetch_count: 10, activity_status: "up" },
    ];
    const definitions = {
      rabbit_version: "3.13.7", rabbitmq_version: "3.13.7",
      users: users.map((user) => ({ name: user.name, password_hash: user.password_hash, tags: user.tags,
        limits: {} })),
      vhosts: [{ name: "/" }, { name: "prod" }],
      permissions: [
        { user: "guest", vhost: "/", configure: ".*", write: ".*", read: ".*" },
        { user: "guest", vhost: "prod", configure: ".*", write: ".*", read: ".*" },
      ],
      topic_permissions: [],
      parameters: [
        { component: "federation-upstream", vhost: "/", name: "upstream-prod",
          value: { uri: "amqp://svc-federation:f3d-pass@upstream.internal:5672/prod", prefetch_count: 100 } },
      ],
      global_parameters: [{ name: "cluster_name", value: "rabbit@node1" }],
      policies: [{ vhost: "prod", name: "ha-quorum", pattern: "^orders", "apply-to": "queues",
        definition: { "ha-mode": "all" }, priority: 1 }],
      queues: queues.map((queue) => ({ name: queue.name, vhost: queue.vhost, durable: queue.durable,
        auto_delete: queue.auto_delete, arguments: queue.arguments })),
      exchanges: [
        { name: "", vhost: "/", type: "direct", durable: true, auto_delete: false, arguments: {} },
        { name: "amq.topic", vhost: "/", type: "topic", durable: true, auto_delete: false, arguments: {} },
      ],
      bindings: [
        { source: "amq.topic", vhost: "/", destination: "audit.events", destination_type: "queue",
          routing_key: "audit.#", arguments: {} },
      ],
    };
    return {
      "/api/overview": {
        management_version: "3.13.7", rabbitmq_version: "3.13.7", cluster_name: "rabbit@node1",
        erlang_version: "26.2.1", erlang_full_version: "Erlang/OTP 26 [erts-14.2.1]",
        product_name: "RabbitMQ", product_version: "3.13.7", platform: "Erlang/OTP 26.2.1",
        disable_stats: false, enable_queue_totals: false,
        listeners: [
          { node: "rabbit@node1", protocol: "amqp", ip: "::", port: 5672, socket_opts: { backlog: 128, nodelay: true, exit_on_close: false } },
          { node: "rabbit@node1", protocol: "clustering", ip: "::", port: 25672, socket_opts: { backlog: 128 } },
          { node: "rabbit@node1", protocol: "http", ip: "::", port: 15672, socket_opts: { backlog: 1024, nodelay: true } },
        ],
        contexts: [
          { description: "RabbitMQ Management", path: "/", port: "15672", protocol: "http", ssl_opts: [] },
          { description: "RabbitMQ Management", path: "/", port: "15671", protocol: "https", ssl_opts: [{ verify: "verify_none" }] },
          { description: "RabbitMQ AMQP 1.0", path: "/", port: "5672", protocol: "http", ssl_opts: [] },
        ],
        object_totals: { consumers: 1, queues: 2, exchanges: 9, connections: 1, channels: 2 },
        queue_totals: { messages: 6, messages_ready: 6, messages_unacknowledged: 0 },
        message_stats: { publish: 137, publish_details: { rate: 0.4 }, deliver: 131, ack: 131, deliver_get: 5 },
      },
      "/api/nodes": [
        { name: "rabbit@node1", type: "disc", running: true, uptime: 604800123, mem_used: 187236352,
          mem_limit: 8267702272, mem_alarm: false, disk_free: 41823760384, disk_free_limit: 50000000,
          disk_free_alarm: false, run_queue: 1, processors: 8, os_pid: "4211",
          fd_used: 42, fd_total: 1048479, sockets_used: 9, sockets_total: 943626, proc_used: 512,
          proc_total: 1048576, gc_num: 128374, rates_mode: "basic",
          applications: [{ name: "rabbit", version: "3.13.7", description: "RabbitMQ" },
            { name: "rabbitmq_management", version: "3.13.7" },
            { name: "rabbitmq_management_agent", version: "3.13.7" },
            { name: "rabbitmq_web_dispatch", version: "3.13.7" },
            { name: "rabbitmq_amqp1_0", version: "3.13.7" }],
          enabled_plugins: ["rabbitmq_management", "rabbitmq_management_agent", "rabbitmq_web_dispatch",
            "rabbitmq_amqp1_0"],
          contexts: [{ description: "RabbitMQ Management", path: "/", port: "15672", protocol: "http",
            ssl_opts: [] }],
          auth_attempts: 12, auth_attempts_failed: 2, auth_attempts_succeeded: 10,
          cluster_links: [] },
      ],
      "/api/cluster/name": { name: "rabbit@node1" },
      "/api/vhosts": [{ name: "/", description: "", tags: [], messages: 1, messages_ready: 1,
        messages_unacknowledged: 0, tracing: false }, { name: "prod", description: "", tags: [],
        messages: 5, messages_ready: 5, messages_unacknowledged: 0, tracing: false }],
      "/api/queues": queues,
      "/api/queues/%2F": [queues[1]],
      "/api/queues/prod": [queues[0]],
      "/api/queues/prod/orders": queues[0],
      "/api/queues/%2F/audit.events": queues[1],
      "/api/exchanges": [
        { name: "", vhost: "/", type: "direct", durable: true, auto_delete: false, internal: false, arguments: {} },
        { name: "amq.direct", vhost: "/", type: "direct", durable: true, auto_delete: false, internal: false, arguments: {} },
        { name: "amq.topic", vhost: "/", type: "topic", durable: true, auto_delete: false, internal: false, arguments: {} },
        { name: "amq.fanout", vhost: "/", type: "fanout", durable: true, auto_delete: false, internal: false, arguments: {} },
        { name: "amq.headers", vhost: "/", type: "headers", durable: true, auto_delete: false, internal: false, arguments: {} },
        { name: "amq.rabbitmq.trace", vhost: "/", type: "topic", durable: true, auto_delete: false, internal: true, arguments: {} },
        { name: "orders.events", vhost: "prod", type: "topic", durable: true, auto_delete: false, internal: false,
          arguments: { "alternate-exchange": "orders.unrouted" } },
      ],
      "/api/bindings": [
        { source: "amq.topic", vhost: "/", destination: "audit.events", destination_type: "queue",
          routing_key: "audit.#", arguments: {}, properties_key: "audit.#" },
        { source: "orders.events", vhost: "prod", destination: "orders", destination_type: "queue",
          routing_key: "order.#", arguments: {}, properties_key: "order.#" },
      ],
      "/api/users": users,
      "/api/users/guest": users[0],
      "/api/users/without-permissions": [],
      "/api/permissions": [
        { user: "guest", vhost: "/", configure: ".*", write: ".*", read: ".*" },
        { user: "guest", vhost: "prod", configure: ".*", write: ".*", read: ".*" },
        { user: "monitoring", vhost: "/", configure: "", write: "", read: ".*" },
      ],
      "/api/topic-permissions": [
        { user: "monitoring", vhost: "/", exchange: "amq.topic", write: "", read: "audit.*" },
      ],
      "/api/policies": [
        { vhost: "prod", name: "ha-quorum", pattern: "^orders", "apply-to": "queues",
          definition: { "ha-mode": "all" }, priority: 1 },
        { vhost: "/", name: "ttl", pattern: "^audit", "apply-to": "queues",
          definition: { "message-ttl": 3600000 }, priority: 0 },
      ],
      "/api/parameters": [
        { component: "federation-upstream", vhost: "/", name: "upstream-prod",
          value: { uri: "amqp://svc-federation:f3d-pass@upstream.internal:5672/prod", prefetch_count: 100,
            ack_mode: "on-confirm" } },
      ],
      "/api/global-parameters": [{ name: "cluster_name", value: "rabbit@node1" }],
      "/api/operator-policies": [],
      "/api/connections": connections,
      "/api/channels": channels,
      "/api/consumers": consumers,
      "/api/definitions": definitions,
      "/api/definitions/%2F": definitions,
      "/api/healthchecks/node": { status: "ok" },
      "/api/feature-flags": [
        { name: "classic_mirrored_queue_version", state: "enabled", stability: "stable" },
        { name: "stream_queue", state: "enabled", stability: "stable" },
        { name: "khepri_db", state: "disabled", stability: "experimental" },
      ],
      "/api/extensions": [
        { name: "rabbitmq_management", version: "3.13.7" },
        { name: "rabbitmq_amqp1_0", version: "3.13.7" },
      ],
      "/api/whoami": null, // filled in per request, because it echoes the identity
    };
  }

  const DEFAULT_PAYLOADS = [
    JSON.stringify({ order_id: 1001, submitted_by: "ops@example.com", password: "not-a-real-password",
      trace_id: "4bf92f3577b34da6a3ce929d0e0e4736" }),
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzZXJ2aWNlLWV0bCIsInNjb3BlIjoiYWRtaW4ifQ.Pl5JQ4n0m2Y9qY",
    "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\n-----END PRIVATE KEY-----",
    "AKIAIOSFODNN7EXAMPLE",
    JSON.stringify({ card_number: "4111 1111 1111 1111", currency: "EUR", amount: 1299 }),
    "connect to amqp://svc-etl:s3cr3t-pass@broker.internal:5672/prod",
  ];

  function documents() {
    return Object.assign(defaultDocuments(), scenario.httpDocuments || {});
  }

  function parseAuth(header) {
    if (!header) return null;
    const match = /^Basic\s+([A-Za-z0-9+/=]+)$/i.exec(header.trim());
    if (!match) return { user: "", password: "", malformed: true };
    const decoded = Buffer.from(match[1], "base64").toString("latin1");
    const index = decoded.indexOf(":");
    if (index < 0) return { user: decoded, password: "", malformed: true };
    return { user: decoded.slice(0, index), password: decoded.slice(index + 1) };
  }

  function jsonResponse(status, reason, document, extraHeaders) {
    const body = document === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(document), "utf8");
    const headers = {
      Server: scenario.httpServerHeader,
      "Content-Type": "application/json",
    };
    if (scenario.httpChunked && body.length > 0) {
      headers["Transfer-Encoding"] = "chunked";
      const half = Math.max(1, Math.floor(body.length / 2));
      const first = body.subarray(0, half);
      const second = body.subarray(half);
      const chunk = (data) => Buffer.concat([
        Buffer.from(data.length.toString(16), "latin1"), Buffer.from("\r\n", "latin1"), data,
        Buffer.from("\r\n", "latin1"),
      ]);
      const payload = Buffer.concat([chunk(first), chunk(second), Buffer.from("0\r\n\r\n", "latin1")]);
      const head = [`HTTP/1.1 ${status} ${reason}`, ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`),
        ...Object.entries(extraHeaders || {}).map(([k, v]) => `${k}: ${v}`), "Connection: close", "", ""].join("\r\n");
      return { raw: Buffer.concat([Buffer.from(head, "latin1"), payload]) };
    }
    const declared = scenario.httpTruncateBody && body.length > scenario.httpTruncateBody
      ? body.length : body.length;
    headers["Content-Length"] = String(declared);
    const head = [`HTTP/1.1 ${status} ${reason}`, ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`),
      ...Object.entries(extraHeaders || {}).map(([k, v]) => `${k}: ${v}`), "Connection: close", "", ""].join("\r\n");
    const sent = scenario.httpTruncateBody ? body.subarray(0, scenario.httpTruncateBody) : body;
    return { raw: Buffer.concat([Buffer.from(head, "latin1"), sent]) };
  }

  function htmlResponse(status, reason, message) {
    const body = `<!DOCTYPE html><html><head><title>${status} ${reason}</title></head><body><h1>${status} ${reason}</h1><p>${message}</p></body></html>`;
    const head = [`HTTP/1.1 ${status} ${reason}`, "Server: " + scenario.httpServerHeader,
      "Content-Type: text/html; charset=utf-8", `Content-Length: ${Buffer.byteLength(body)}`,
      "Connection: close", "", ""].join("\r\n");
    return { raw: Buffer.concat([Buffer.from(head, "latin1"), Buffer.from(body, "utf8")]) };
  }

  function handleHttpPayload(payload) {
    if (scenario.httpTls) return handleTlsPayload(payload);
    const text = payload.toString("latin1");
    const headEnd = text.indexOf("\r\n\r\n");
    if (headEnd < 0) {
      state.protocolErrors.push("HTTP request without a complete head");
      return null;
    }
    const lines = text.slice(0, headEnd).split("\r\n");
    const requestLine = lines[0].split(" ");
    const method = (requestLine[0] || "").toUpperCase();
    const path = requestLine[1] || "";
    const headers = {};
    for (const line of lines.slice(1)) {
      const index = line.indexOf(":");
      if (index > 0) headers[line.slice(0, index).toLowerCase()] = line.slice(index + 1).trim();
    }
    const declaredLength = parseInt(headers["content-length"] || "0", 10);
    const body = declaredLength > 0 ? text.slice(headEnd + 4, headEnd + 4 + declaredLength) : "";
    const auth = parseAuth(headers["authorization"]);
    const cleanPath = path.split("?")[0];
    state.httpRequests.push({ method, path, cleanPath, user: auth ? auth.user : null,
      hasAuth: !!auth, bytes: payload.length, body: body.slice(0, 400),
      headers: { accept: headers["accept"], userAgent: headers["user-agent"],
        authorization: headers["authorization"] ? "present" : null } });

    // State-changing requests are recorded rather than served: a scan that purges
    // a queue, imports definitions or deletes a user must fail its own suite.
    if (method === "DELETE" || method === "PUT" || (method === "POST" && cleanPath === "/api/definitions")) {
      state.violations.push({ kind: "state-changing-management-request", method, path: cleanPath });
      return jsonResponse(204, "No Content", undefined);
    }
    if (cleanPath === "/api/aliveness-test/" + encodeURIComponent("/") || cleanPath.startsWith("/api/aliveness-test/")) {
      state.violations.push({ kind: "aliveness-test-creates-queue", path: cleanPath });
      return jsonResponse(200, "OK", { status: "ok" });
    }

    const anonymous = scenario.httpAnonymous.some((entry) => cleanPath === entry || cleanPath.startsWith(entry));
    if (!anonymous && scenario.httpRequireAuth) {
      if (!auth) {
        return scenario.httpHtmlErrors
          ? htmlResponse(401, "Unauthorized", "Login required")
          : jsonResponse(401, "Unauthorized", { error: "not_authorised", reason: "Login required" },
            { "WWW-Authenticate": 'Basic realm="RabbitMQ Management"' });
      }
      if (auth.malformed) {
        return jsonResponse(400, "Bad Request", { error: "bad_request", reason: "Malformed Authorization header" });
      }
      const expected = scenario.httpCredentials[auth.user];
      if (expected === undefined || expected !== auth.password) {
        state.authFailures.push({ surface: "management", user: auth.user, bytes: auth.password.length });
        return scenario.httpHtmlErrors
          ? htmlResponse(401, "Unauthorized", "Login failed")
          : jsonResponse(401, "Unauthorized", { error: "not_authorised", reason: "Login failed" },
            { "WWW-Authenticate": 'Basic realm="RabbitMQ Management"' });
      }
    } else if (auth && auth.user && scenario.httpCredentials[auth.user] === undefined) {
      // Credentials offered on an anonymous endpoint are still checked when the
      // broker is only serving that endpoint without auth: an invalid login is an
      // invalid login, and a scan should see the difference.
      state.authFailures.push({ surface: "management", user: auth.user, bytes: auth.password.length });
      return jsonResponse(401, "Unauthorized", { error: "not_authorised", reason: "Login failed" },
        { "WWW-Authenticate": 'Basic realm="RabbitMQ Management"' });
    }

    const tag = auth && auth.user ? scenario.httpTags[auth.user] : null;
    const required = Object.keys(scenario.httpPermissionByPath)
      .filter((prefix) => cleanPath.startsWith(prefix))
      .map((prefix) => scenario.httpPermissionByPath[prefix])[0];
    if (required === "administrator" && tag !== "administrator") {
      return jsonResponse(403, "Forbidden", {
        error: "not_authorised", reason: "Access refused to user",
      });
    }
    if (required === "policymaker" && tag !== "administrator" && tag !== "policymaker") {
      return jsonResponse(403, "Forbidden", { error: "not_authorised", reason: "Access refused to user" });
    }
    if (required === "monitoring" && !["administrator", "policymaker", "management", "monitoring"].includes(tag)) {
      return jsonResponse(403, "Forbidden", { error: "not_authorised", reason: "Access refused to user" });
    }

    if (scenario.httpRedirect && scenario.httpRedirect.from === cleanPath) {
      return {
        raw: Buffer.from(`HTTP/1.1 302 Found\r\nServer: ${scenario.httpServerHeader}\r\nLocation: ${scenario.httpRedirect.to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`, "latin1"),
      };
    }

    // The queue get endpoint: this is the one place the mock hands message
    // payloads to the client, and the ackmode in the body decides whether the
    // broker would have destroyed them.
    const getMatch = /^\/api\/queues\/([^/]+)\/([^/]+)\/get$/.exec(cleanPath);
    if (method === "POST" && getMatch) {
      const vhost = decodeURIComponent(getMatch[1]);
      const queue = decodeURIComponent(getMatch[2]);
      let request = {};
      try {
        request = JSON.parse(body || "{}");
      } catch (error) {
        state.protocolErrors.push("queue get body is not JSON");
      }
      const ackmode = request.ackmode || "ack_requeue_false";
      const destructive = ackmode !== "ack_requeue_true" && ackmode !== "reject_requeue_true";
      state.messageReads.push({ vhost, queue, ackmode, count: request.count || 1, destructive });
      if (destructive) {
        state.violations.push({ kind: "destructive-queue-get", vhost, queue, ackmode });
      }
      const payloads = scenario.messagePayloads || DEFAULT_PAYLOADS;
      const count = Math.max(1, Math.min(Number(request.count) || 1, payloads.length));
      const messages = [];
      for (let index = 0; index < count; index += 1) {
        const raw = payloads[index % payloads.length];
        const bytes = Buffer.isBuffer(raw) ? raw : Buffer.from(String(raw), "utf8");
        messages.push({
          payload_bytes: bytes.length,
          redelivered: false,
          exchange: "orders.events",
          routing_key: "order.created",
          message_count: count - index - 1,
          properties: {
            headers: { "x-retry": index, trace_id: "4bf92f3577b34da6a3ce929d0e0e4736" },
            delivery_mode: 2,
            content_type: "application/json",
            timestamp: 1739000000 + index,
          },
          payload: (request.encoding === "base64" ? bytes.toString("base64") : bytes.toString("utf8")),
          payload_encoding: request.encoding === "base64" ? "base64" : "string",
        });
      }
      return jsonResponse(200, "OK", messages);
    }

    const document = documents()[cleanPath];
    if (document === undefined) {
      return scenario.httpHtmlErrors
        ? htmlResponse(404, "Not Found", `Could not find resource at ${cleanPath}`)
        : jsonResponse(404, "Not Found", { error: "Object Not Found", reason: `Not Found: ${cleanPath}` });
    }
    if (cleanPath === "/api/whoami") {
      if (!auth) return jsonResponse(401, "Unauthorized", { error: "not_authorised", reason: "Login required" },
        { "WWW-Authenticate": 'Basic realm="RabbitMQ Management"' });
      return jsonResponse(200, "OK", { name: auth.user, tags: [scenario.httpTags[auth.user] || "monitoring"],
        auth_backend: "rabbit_auth_backend_internal" });
    }
    if (typeof document === "function") {
      return jsonResponse(200, "OK", document({ auth, method, path: cleanPath, body, state, scenario }));
    }
    return jsonResponse(200, "OK", document);
  }

  return { handle, state, scenario, codec: { readTable, writeTable, methodFrame, frame, u16, u32,
    writeShortString, writeLongString } };
}

module.exports = { createMockRabbitMQ, methodName, readTable, writeTable, frame, methodFrame, u16, u32,
  writeShortString, writeLongString, FRAME_END, FRAME_METHOD, FRAME_HEARTBEAT };

