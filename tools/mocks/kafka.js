"use strict";
/*
 * tools/mocks/kafka.js
 * ---------------------------------------------------------------------------
 * A scenario driven mock Apache Kafka broker used by tools/nse-sim.js.
 *
 * It is a second, independent implementation of the Kafka wire protocol: the
 * encoders and decoders below share no code with nselib/kafka.lua, so a schema
 * mistake in the engine shows up as a decode failure here instead of being
 * mirrored by a matching mistake. The mock also enforces the *safety* contract
 * of the audit scripts:
 *
 *   * CreateTopics must carry validate_only = true on every version that has
 *     the field. A request without it records a violation instead of creating
 *     a topic.
 *   * DeleteTopics must not name a topic the scenario says exists. If it does,
 *     the mock records a violation and refuses.
 *
 * Scenario fields (all optional):
 *   brokers, clusterId, controllerId, topics, groups, offsets, configs,
 *   apiVersions, versionCaps, anonymousAllowed, saslRequired, mechanisms,
 *   plainCredentials, scramCredentials, scramSalt, scramIterations,
 *   allowCreateTopics, createValidationError, deleteBehaviour, records,
 *   baseOffset, highWatermark, throttleMs, negotiateError,
 *   dropFirst, silent, truncateBytes, idleAfter, faultOnApi
 */

const crypto = require("crypto");

const API = {
  PRODUCE: 0, FETCH: 1, LIST_OFFSETS: 2, METADATA: 3, OFFSET_COMMIT: 8, OFFSET_FETCH: 9,
  FIND_COORDINATOR: 10, JOIN_GROUP: 11, HEARTBEAT: 12, LEAVE_GROUP: 13, SYNC_GROUP: 14,
  DESCRIBE_GROUPS: 15, LIST_GROUPS: 16, SASL_HANDSHAKE: 17, API_VERSIONS: 18,
  CREATE_TOPICS: 19, DELETE_TOPICS: 20, DELETE_RECORDS: 21, DESCRIBE_CONFIGS: 32,
  SASL_AUTHENTICATE: 36,
  DESCRIBE_CLUSTER: 60,
};
// Kafka's own specification spells the operations in CamelCase; the mock
// reports that spelling so a test can assert on the protocol vocabulary
// instead of on the mock's internal constant names.
const API_NAMES = {
  0: "Produce", 1: "Fetch", 2: "ListOffsets", 3: "Metadata", 8: "OffsetCommit", 9: "OffsetFetch",
  10: "FindCoordinator", 11: "JoinGroup", 12: "Heartbeat", 13: "LeaveGroup", 14: "SyncGroup",
  15: "DescribeGroups", 16: "ListGroups", 17: "SaslHandshake", 18: "ApiVersions",
  19: "CreateTopics", 20: "DeleteTopics", 21: "DeleteRecords", 32: "DescribeConfigs",
  36: "SaslAuthenticate",
  60: "DescribeCluster",
};

const FLEXIBLE_FROM = {
  0: 9, 1: 12, 2: 6, 3: 9, 9: 6, 10: 3, 15: 5, 16: 3, 18: 3, 19: 5, 20: 4, 21: 2, 32: 4,
  36: 2, 60: 0,
};
const STATUS = {
  NONE: 0, UNKNOWN_TOPIC_OR_PARTITION: 3, NOT_LEADER_OR_FOLLOWER: 6, NOT_COORDINATOR: 16,
  TOPIC_AUTHORIZATION_FAILED: 29, GROUP_AUTHORIZATION_FAILED: 30, CLUSTER_AUTHORIZATION_FAILED: 31,
  UNSUPPORTED_SASL_MECHANISM: 33, ILLEGAL_SASL_STATE: 34, UNSUPPORTED_VERSION: 35,
  TOPIC_ALREADY_EXISTS: 36, INVALID_CONFIG: 40, INVALID_REQUEST: 42, SECURITY_DISABLED: 54,
  SASL_AUTHENTICATION_FAILED: 58, RESOURCE_NOT_FOUND: 91, UNKNOWN_TOPIC_ID: 100,
};

function isFlexible(api, version) {
  const from = FLEXIBLE_FROM[api];
  return from !== undefined && version >= from;
}

class Reader {
  constructor(buf) { this.buf = buf; this.pos = 0; }
  get left() { return this.buf.length - this.pos; }
  need(n) {
    if (n < 0 || this.pos + n > this.buf.length) {
      throw new Error(`reader underflow: need ${n}, have ${this.left}`);
    }
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  peekI32() { return this.buf.readInt32BE(this.pos); }
  u8() { return this.need(1)[0]; }
  i8() { const v = this.u8(); return v >= 128 ? v - 256 : v; }
  bool() { return this.u8() !== 0; }
  u16() { return this.need(2).readUInt16BE(0); }
  i16() { return this.need(2).readInt16BE(0); }
  u32() { return this.need(4).readUInt32BE(0); }
  i32() { return this.need(4).readInt32BE(0); }
  u64() { return Number(this.need(8).readBigUInt64BE(0)); }
  i64() { return Number(this.need(8).readBigInt64BE(0)); }
  uvarint() {
    let shift = 0, value = 0;
    for (;;) {
      const b = this.u8();
      value += (b & 0x7f) * 2 ** shift;
      if ((b & 0x80) === 0) return value;
      shift += 7;
      if (shift > 35) throw new Error("varint longer than five bytes");
    }
  }
  varint() { const v = this.uvarint(); return v % 2 ? -(v + 1) / 2 : v / 2; }
  str() { const n = this.i16(); return n < 0 ? null : this.need(n).toString("latin1"); }
  bytes() { const n = this.i32(); return n < 0 ? null : this.need(n); }
  compactStr() { const n = this.uvarint(); return n === 0 ? null : this.need(n - 1).toString("latin1"); }
  compactBytes() { const n = this.uvarint(); return n === 0 ? null : this.need(n - 1); }
  // Kafka's array encoding says -1 is null and 0 is empty. Conflating the two
  // made "give me every topic" (which the engine writes as -1) look like "give
  // me nothing", so a classic-schema Metadata request answered with no topics.
  array(fn) {
    const n = this.i32();
    if (n < 0) return null;
    const out = [];
    for (let i = 0; i < n; i += 1) out.push(fn(this));
    return out;
  }
  compactArray(fn) {
    const n = this.uvarint();
    if (n === 0) return null;
    const out = [];
    for (let i = 0; i < n - 1; i += 1) out.push(fn(this));
    return out;
  }
  tags() {
    const count = this.uvarint();
    for (let i = 0; i < count; i += 1) {
      this.uvarint();
      this.need(this.uvarint());
    }
    return count;
  }
}

class Writer {
  constructor() { this.parts = []; }
  raw(b) { this.parts.push(Buffer.isBuffer(b) ? b : Buffer.from(b, "latin1")); return this; }
  u8(v) { this.parts.push(Buffer.from([v & 0xff])); return this; }
  i8(v) { return this.u8(v < 0 ? v + 256 : v); }
  bool(v) { return this.u8(v ? 1 : 0); }
  u16(v) { const b = Buffer.alloc(2); b.writeUInt16BE(v >>> 0, 0); this.parts.push(b); return this; }
  i16(v) { const b = Buffer.alloc(2); b.writeInt16BE(v | 0, 0); this.parts.push(b); return this; }
  u32(v) { const b = Buffer.alloc(4); b.writeUInt32BE(v >>> 0, 0); this.parts.push(b); return this; }
  i32(v) { const b = Buffer.alloc(4); b.writeInt32BE(v | 0, 0); this.parts.push(b); return this; }
  u64(v) { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(Math.max(0, Math.trunc(v))), 0); this.parts.push(b); return this; }
  i64(v) { const b = Buffer.alloc(8); b.writeBigInt64BE(BigInt(Math.trunc(v)), 0); this.parts.push(b); return this; }
  uvarint(v) {
    let value = Math.trunc(v);
    const out = [];
    do {
      let b = value % 128;
      value = Math.floor(value / 128);
      if (value > 0) b |= 0x80;
      out.push(b);
    } while (value > 0);
    this.parts.push(Buffer.from(out));
    return this;
  }
  // Kafka's record format uses signed (zigzag) varints, so a negative value
  // such as a null key length survives the round trip.
  varint(v) { const n = Math.trunc(v); return this.uvarint(n < 0 ? -2 * n - 1 : 2 * n); }
  varlong(v) { return this.varint(v); }
  str(s) { if (s === null || s === undefined) return this.i16(-1); const b = Buffer.from(s, "latin1"); this.i16(b.length); return this.raw(b); }
  bytes(b) { if (b === null || b === undefined) return this.i32(-1); this.i32(b.length); return this.raw(b); }
  compactStr(s) { if (s === null || s === undefined) return this.uvarint(0); const b = Buffer.from(s, "latin1"); this.uvarint(b.length + 1); return this.raw(b); }
  compactBytes(b) { if (b === null || b === undefined) return this.uvarint(0); this.uvarint(b.length + 1); return this.raw(b); }
  array(items, fn) { this.i32(items.length); items.forEach((item, i) => fn(this, item, i)); return this; }
  compactArray(items, fn) { if (!items) return this.uvarint(0); this.uvarint(items.length + 1); items.forEach((item, i) => fn(this, item, i)); return this; }
  tags() { return this.u8(0); }
  result() { return Buffer.concat(this.parts); }
}

// The flexible and the classic schema differ in exactly two places for the
// fields this mock cares about, so every read/write goes through one pair of
// helpers instead of one ternary per call site.
function wStr(w, flexible, s) { return flexible ? w.compactStr(s) : w.str(s); }
function wBytes(w, flexible, b) { return flexible ? w.compactBytes(b) : w.bytes(b); }
function wArray(w, flexible, items, fn) { return flexible ? w.compactArray(items, fn) : w.array(items, fn); }
function rStr(r, flexible) { return flexible ? r.compactStr() : r.str(); }
function rBytes(r, flexible) { return flexible ? r.compactBytes() : r.bytes(); }
function rArray(r, flexible, fn) { return flexible ? r.compactArray(fn) : r.array(fn); }

function frame(payload) {
  const head = Buffer.alloc(4);
  head.writeUInt32BE(payload.length, 0);
  return Buffer.concat([head, payload]);
}

const CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let crc = i;
    for (let b = 0; b < 8; b += 1) crc = (crc & 1) ? (crc >>> 1) ^ 0x82f63b78 : crc >>> 1;
    table[i] = crc;
  }
  return table;
})();

function crc32c(buf) {
  let crc = 0xffffffff;
  for (const byte of buf) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

/*
 * One uncompressed v2 record batch carrying the scenario's records.
 * Layout after the 12 byte prefix: leaderEpoch(4) magic(1) crc(4)
 * attributes(2) ... and the checksum covers everything from the attributes
 * field (offset 9 of the batch body) to the end.
 */
/*
 * The ConsumerProtocol payloads that DescribeGroups returns as opaque BYTES are
 * versioned on their own and always use the classic (non-compact) schema:
 *   Subscription: version, topics[], user_data, [v1+] owned_partitions, [v2+] generation_id, [v3+] rack_id
 *   Assignment:   version, assigned_partitions[], [v1+] user_data
 */
function encodeSubscription(spec) {
  const w = new Writer();
  const version = spec.version === undefined ? 1 : spec.version;
  w.i16(version);
  wArray(w, false, spec.topics || [], (ww, name) => ww.str(name));
  w.bytes(spec.userData ? Buffer.from(spec.userData) : null);
  if (version >= 1) {
    wArray(w, false, spec.ownedPartitions || [], (ww, entry) => {
      ww.str(entry.topic);
      ww.array(entry.partitions || [], (w3, index) => w3.i32(index));
    });
  }
  if (version >= 2) w.i32(spec.generationId === undefined ? -1 : spec.generationId);
  if (version >= 3) w.str(spec.rackId === undefined ? null : spec.rackId);
  return w.result();
}

function encodeAssignment(spec) {
  const w = new Writer();
  const version = spec.version === undefined ? 1 : spec.version;
  w.i16(version);
  wArray(w, false, spec.topics || [], (ww, entry) => {
    ww.str(entry.name);
    ww.array(entry.partitions || [], (w3, index) => w3.i32(index));
  });
  if (version >= 1) w.bytes(spec.userData ? Buffer.from(spec.userData) : null);
  return w.result();
}

function buildRecordBatch(records, baseOffset) {
  const body = new Writer();
  records.forEach((record, index) => {
    const rec = new Writer();
    rec.i8(0);
    rec.varlong(0);                            // timestampDelta
    rec.varint(index);                         // offsetDelta
    const key = record.key === undefined || record.key === null ? null : Buffer.from(String(record.key), "utf8");
    const value = record.value === undefined || record.value === null ? null : Buffer.from(String(record.value), "utf8");
    if (key) { rec.varint(key.length); rec.raw(key); } else rec.varint(-1);
    if (value) { rec.varint(value.length); rec.raw(value); } else rec.varint(-1);
    rec.varint((record.headers || []).length);
    for (const header of record.headers || []) {
      const hk = Buffer.from(header.key, "utf8");
      const hv = header.value === null || header.value === undefined ? null : Buffer.from(String(header.value), "utf8");
      rec.varint(hk.length).raw(hk);
      if (hv) rec.varint(hv.length).raw(hv); else rec.varint(-1);
    }
    const payload = rec.result();
    body.varint(payload.length).raw(payload);
  });
  const recordBytes = body.result();

  const batchBody = new Writer();
  batchBody.i32(0);                 // partitionLeaderEpoch
  batchBody.i8(2);                  // magic
  batchBody.u32(0);                 // crc placeholder
  batchBody.i16(0);                 // attributes (no compression, create-time)
  batchBody.i32(Math.max(0, records.length - 1));
  batchBody.i64(0);                 // baseTimestamp
  batchBody.i64(0);                 // maxTimestamp
  batchBody.i64(-1);                // producerId
  batchBody.i16(-1);                // producerEpoch
  batchBody.i32(-1);                // baseSequence
  batchBody.i32(records.length);
  const withRecords = Buffer.concat([batchBody.result(), recordBytes]);
  withRecords.writeUInt32BE(crc32c(withRecords.subarray(9)), 5);

  const prefix = new Writer();
  prefix.i64(baseOffset);
  prefix.i32(withRecords.length);
  return Buffer.concat([prefix.result(), withRecords]);
}

function createMockKafka(scenario = {}) {
  const brokers = scenario.brokers || [{ nodeId: 1, host: "broker-1.local", port: 9092, rack: "rack-a" }];
  const topics = scenario.topics || [
    { name: "orders", partitions: 3, replicas: [1], isr: [1], internal: false, leader: 1 },
    { name: "__consumer_offsets", partitions: 1, replicas: [1], isr: [1], internal: true, leader: 1 },
  ];
  const groups = scenario.groups || [
    { group: "checkout-workers", state: "Stable", protocolType: "consumer",
      members: [{ id: "consumer-1-abc", clientId: "checkout-app", clientHost: "/10.0.0.7",
        subscription: { version: 1, topics: ["orders"], userData: "nmap-mock-1" },
        assignment: { version: 1, topics: [{ name: "orders", partitions: [0, 1] }] } }] },
  ];
  const offsets = scenario.offsets || {};
  const configs = scenario.configs || {};
  const mechanisms = scenario.mechanisms || ["PLAIN"];
  const apiVersions = scenario.apiVersions || [
    { key: 0, min: 0, max: 9 }, { key: 1, min: 0, max: 13 }, { key: 2, min: 0, max: 7 },
    { key: 3, min: 0, max: 12 }, { key: 8, min: 0, max: 8 }, { key: 9, min: 0, max: 8 },
    { key: 10, min: 0, max: 4 }, { key: 15, min: 0, max: 5 }, { key: 16, min: 0, max: 4 },
    { key: 17, min: 0, max: 1 }, { key: 18, min: 0, max: 3 }, { key: 19, min: 0, max: 7 },
    { key: 20, min: 0, max: 6 }, { key: 21, min: 0, max: 2 }, { key: 32, min: 0, max: 4 },
    { key: 36, min: 0, max: 2 },
    { key: 60, min: 0, max: 1 },
  ];

  const state = {
    requests: [], dropped: 0, protocolErrors: [], violations: [],
    saslAttempts: [], anonymousRequests: 0, createTopicsCalls: [], deleteTopicsCalls: [],
    scram: null, lastMechanism: null,
    autoCreateRequests: 0, autoCreatedTopics: [], createdTopics: [], deleteRecordsCalls: [],
    topicsAtStart: topics.map((t) => t.name),
  };

  function versionFor(api, requested) {
    const cap = (scenario.versionCaps || {})[api];
    let max = cap === undefined ? requested : cap;
    const advertised = apiVersions.find((entry) => entry.key === api);
    if (advertised) max = Math.min(max, advertised.max);
    return Math.min(requested, max);
  }

  function authError() {
    if (scenario.saslRequired === "silent") return null;
    if (scenario.anonymousAllowed === false) return STATUS.CLUSTER_AUTHORIZATION_FAILED;
    return null;
  }

  // -- API handlers ---------------------------------------------------------

  function handleApiVersions(req, version) {
    const flex = isFlexible(API.API_VERSIONS, version);
    const error = scenario.negotiateError || 0;
    const w = new Writer();
    w.i16(error);
    wArray(w, flex, error === 0 ? apiVersions : [], (ww, entry) => {
      ww.i16(entry.key).i16(entry.min).i16(entry.max);
      if (flex) ww.tags();
    });
    w.i32(scenario.throttleMs || 0);
    if (flex) w.tags();
    return w.result();
  }

  // A topic id is 16 bytes chosen by the controller. The mock derives it from
  // the name so that a scan sees a stable id per topic and a script can compare
  // ids across responses.
  function topicId(t) {
    if (!t.topicIdBuffer) {
      t.topicIdBuffer = crypto.createHash("md5").update(String(t.name)).digest();
      t.topicId = t.topicIdBuffer.toString("hex");
    }
    return t.topicIdBuffer;
  }

  function handleMetadata(req, version) {
    // Metadata became flexible at v9, which changes three things at once: the
    // broker/topic/partition arrays become compact, every string becomes a
    // compact string, and every struct gains a tagged field buffer.
    const flex = isFlexible(API.METADATA, version);
    const error = authError();
    const w = new Writer();
    if (version >= 3) w.i32(0);
    wArray(w, flex, brokers, (ww, b) => {
      ww.i32(b.nodeId);
      wStr(ww, flex, b.host);
      ww.i32(b.port);
      if (version >= 1) wStr(ww, flex, b.rack || null);
      if (flex) ww.tags();
    });
    if (version >= 2) wStr(w, flex, scenario.clusterId || "nse-mock-cluster");
    if (version >= 1) w.i32(scenario.controllerId === undefined ? 1 : scenario.controllerId);
    if (req.autoCreate || scenario.autoCreateIgnoringFlag) {
      // The probe asked the broker to create what it names. The mock records the
      // request, and only creates when the scenario opted in: every script in
      // this collection is required to send allow_auto_topic_creation=false.
      // autoCreateIgnoringFlag models the other failure mode: the broker that
      // creates the topic even though the caller asked it not to.
      if (req.autoCreate) state.autoCreateRequests += 1;
      if (scenario.autoCreateOnMetadata || scenario.autoCreateIgnoringFlag) {
        for (const name of req.topics || []) {
          if (!topics.some((t) => t.name === name)) {
            topics.push({ name, partitions: scenario.autoCreatePartitions || 1, replicas: [1], isr: [1] });
            state.autoCreatedTopics.push(name);
          }
        }
      }
    }
    let selected;
    if (req.topics === null || req.topics === undefined) {
      const hidden = scenario.hiddenTopics || [];
      selected = topics.filter((t) => !hidden.includes(t.name));
    } else {
      selected = topics.filter((t) => req.topics.includes(t.name));
      // Requesting a name the cluster does not host is a question about
      // existence, so the answer is a per-topic error code, not silence.
      for (const name of req.topics) {
        if (!topics.some((t) => t.name === name)) {
          selected.push({ name, partitions: 0, missing: true });
        }
      }
    }
    wArray(w, flex, error ? [] : selected, (ww, t) => {
      const namedError = (scenario.topicErrors || {})[t.name];
      const topicError = t.topicError || namedError
        || (t.missing ? (scenario.unknownTopicError || STATUS.UNKNOWN_TOPIC_OR_PARTITION) : 0);
      ww.i16(error || topicError);
      wStr(ww, flex, t.name);
      if (version >= 10) ww.raw(topicId(t));
      if (version >= 1) ww.bool(!!t.internal);
      const partitionCount = topicError ? 0 : t.partitions;
      wArray(ww, flex, Array.from({ length: partitionCount || 0 }, (_, i) => i), (w3, index) => {
        w3.i16(0);
        w3.i32(index);
        w3.i32(t.leader === undefined ? 1 : t.leader);
        if (version >= 7) w3.i32(t.leaderEpoch === undefined ? 0 : t.leaderEpoch);
        wArray(w3, flex, t.replicas || [1], (w4, r) => w4.i32(r));
        wArray(w3, flex, t.isr || t.replicas || [1], (w4, r) => w4.i32(r));
        if (version >= 5) wArray(w3, flex, t.offline || [], (w4, r) => w4.i32(r));
        if (flex) w3.tags();
      });
      if (version >= 8) ww.i32(error ? -2147483648 : 0x1f);
      if (flex) ww.tags();
    });
    if (version >= 8 && version <= 10) w.i32(error ? -2147483648 : 0x3f);
    if (version >= 13) w.i16(error || 0);
    if (flex) w.tags();
    return w.result();
  }

  function handleDescribeCluster(req, version) {
    const error = authError();
    const w = new Writer();
    w.i32(0);
    w.i16(error || 0);
    w.compactStr(error ? "cluster authorization failed" : null);
    if (version >= 1) w.i8(1);
    w.compactStr(error ? null : (scenario.clusterId || "nse-mock-cluster"));
    w.i32(scenario.controllerId === undefined ? 1 : scenario.controllerId);
    w.compactArray(error ? [] : brokers, (ww, b) => {
      ww.i32(b.nodeId).compactStr(b.host).i32(b.port).compactStr(b.rack || null);
      if (version >= 2) ww.bool(false);
      ww.tags();
    });
    w.i32(error ? -2147483648 : 0x3f);
    w.tags();
    return w.result();
  }

  function handleListGroups(req, version) {
    const flex = isFlexible(API.LIST_GROUPS, version);
    const error = authError();
    const w = new Writer();
    if (version >= 1) w.i32(0);
    w.i16(error || 0);
    wArray(w, flex, error ? [] : groups, (ww, g) => {
      wStr(ww, flex, g.group);
      wStr(ww, flex, g.protocolType || "consumer");
      if (version >= 4) wStr(ww, flex, g.state || "Stable");
      if (version >= 5) wStr(ww, flex, "classic");
      if (flex) ww.tags();
    });
    if (flex) w.tags();
    return w.result();
  }

  function handleDescribeGroups(req, version) {
    const flex = isFlexible(API.DESCRIBE_GROUPS, version);
    const error = authError();
    const w = new Writer();
    if (version >= 1) w.i32(0);
    wArray(w, flex, req.groups || [], (ww, name) => {
      const g = groups.find((entry) => entry.group === name);
      ww.i16(error || 0);
      if (version >= 6) wStr(ww, flex, null);
      wStr(ww, flex, name);
      wStr(ww, flex, g ? (g.state || "Stable") : "Empty");
      wStr(ww, flex, g ? (g.protocolType || "consumer") : "");
      wStr(ww, flex, "range");
      wArray(ww, flex, g ? (g.members || []) : [], (w3, m) => {
        wStr(w3, flex, m.id);
        if (version >= 4) wStr(w3, flex, m.groupInstanceId || null);
        wStr(w3, flex, m.clientId);
        wStr(w3, flex, m.clientHost);
        wBytes(w3, flex, m.rawMetadata !== undefined ? Buffer.from(m.rawMetadata, "hex")
          : encodeSubscription(m.subscription || {
          version: 1, topics: [topics[0] ? topics[0].name : "orders"], userData: "nmap-mock-1",
        }));
        wBytes(w3, flex, m.rawAssignment !== undefined ? Buffer.from(m.rawAssignment, "hex")
          : encodeAssignment(m.assignment || {
            version: 1,
            topics: [{ name: topics[0] ? topics[0].name : "orders",
              partitions: (g.assignmentPartitions || [0]) }],
          }));
        if (flex) w3.tags();
      });
      if (version >= 3) ww.i32(error ? -2147483648 : 0x1f);
      if (flex) ww.tags();
    });
    if (flex) w.tags();
    return w.result();
  }

  function handleFindCoordinator(req, version) {
    const flex = isFlexible(API.FIND_COORDINATOR, version);
    const error = authError();
    const w = new Writer();
    if (version >= 1) w.i32(0);
    if (version <= 3) {
      w.i16(error || 0);
      if (version >= 1) wStr(w, flex, error ? "authorization failed" : null);
      w.i32(error ? -1 : 1);
      wStr(w, flex, error ? "" : "broker-1.local");
      w.i32(error ? -1 : 9092);
    } else {
      w.compactArray([req.key], (ww, key) => {
        ww.compactStr(key).i32(error ? -1 : 1).compactStr(error ? "" : "broker-1.local")
          .i32(error ? -1 : 9092).i16(error || 0).compactStr(error ? "authorization failed" : null);
        ww.tags();
      });
    }
    if (flex) w.tags();
    return w.result();
  }

  function handleOffsetFetch(req, version) {
    const flex = isFlexible(API.OFFSET_FETCH, version);
    const error = authError();
    const w = new Writer();
    if (version >= 3) w.i32(0);
    const groupOffsets = offsets[req.group] || {};
    const topicNames = req.topics && req.topics.length ? req.topics.map((t) => t.name) : Object.keys(groupOffsets);
    if (version >= 8) {
      w.compactArray([req.group], (ww) => {
        ww.compactStr(req.group);
        w.compactArray(topicNames, (w3, name) => {
          w3.compactStr(name);
          const partitions = groupOffsets[name] || {};
          w3.compactArray(Object.keys(partitions).map(Number), (w4, index) => {
            w4.i32(index).i64(partitions[index]).i32(0).compactStr(null).i16(error || 0);
            w4.tags();
          });
          w3.tags();
        });
        ww.i16(error || 0);
        ww.tags();
      });
    } else {
      wArray(w, flex, topicNames, (ww, name) => {
        wStr(ww, flex, name);
        const partitions = groupOffsets[name] || {};
        wArray(ww, flex, Object.keys(partitions).map(Number), (w3, index) => {
          w3.i32(index).i64(partitions[index]);
          if (version >= 5) w3.i32(0);
          wStr(w3, flex, null);
          w3.i16(error || 0);
          if (flex) w3.tags();
        });
        if (flex) ww.tags();
      });
      if (version >= 2) w.i16(error || 0);
    }
    if (flex) w.tags();
    return w.result();
  }

  function handleListOffsets(req, version) {
    const flex = isFlexible(API.LIST_OFFSETS, version);
    const error = authError();
    const w = new Writer();
    if (version >= 2) w.i32(0);
    wArray(w, flex, req.topics || [], (ww, topic) => {
      wStr(ww, flex, topic.name);
      wArray(ww, flex, topic.partitions || [], (w3, part) => {
        const exists = topics.some((t) => t.name === topic.name && part.partition < t.partitions);
        w3.i32(part.partition);
        w3.i16(error || (exists ? 0 : STATUS.UNKNOWN_TOPIC_OR_PARTITION));
        w3.i64(1757000000000);
        const offset = part.timestamp === -2 ? 0 : (scenario.highWatermark || 250);
        w3.i64(exists ? offset : -1);
        if (version >= 4) w3.i32(0);
        if (flex) w3.tags();
      });
      if (flex) ww.tags();
    });
    if (flex) w.tags();
    return w.result();
  }

  function handleFetch(req, version) {
    const error = authError();
    const batch = buildRecordBatch(scenario.records || [{ key: "order-1", value: "{\"id\":1}" }], scenario.baseOffset || 100);
    const w = new Writer();
    w.i32(0);
    if (version >= 7) {
      w.i16(error || 0);
      w.i32(0);
    }
    w.array(req.topics || [], (ww, topic) => {
      ww.str(topic.name);
      ww.array(topic.partitions || [], (w3, part) => {
        const exists = topics.some((t) => t.name === topic.name);
        w3.i32(part.partition);
        w3.i16(error || (exists ? 0 : STATUS.UNKNOWN_TOPIC_OR_PARTITION));
        w3.i64(scenario.highWatermark || 250);
        if (version >= 4) w3.i64(scenario.highWatermark || 250);
        if (version >= 5) w3.i64(0);
        if (version >= 4) w3.array([], () => {});
        w3.bytes(exists ? batch : null);
      });
    });
    if (version >= 7) w.array([], () => {});
    return w.result();
  }

  // The settings the config API answers with when a scenario does not supply its
  // own table. The broker set carries the four settings that decide whether the
  // cluster's ACLs are enforced at all, plus the sensitive keystore password
  // that a broker is supposed to redact - which is why the scenario can turn
  // that disclosure off explicitly.
  function brokerDefaults() {
    const sensitive = scenario.discloseSensitive === false;
    return [
      { name: "allow.everyone.if.no.acl.found", readOnly: false, sensitive: false, source: 5,
        value: String(scenario.allowEveryoneIfNoAclFound === undefined ? false : scenario.allowEveryoneIfNoAclFound) },
      { name: "authorizer.class.name", readOnly: false, sensitive: false, source: 5,
        value: scenario.authorizerClass === undefined
          ? "org.apache.kafka.metadata.authorizer.StandardAuthorizer" : scenario.authorizerClass },
      { name: "super.users", readOnly: false, sensitive: false, source: 5,
        value: scenario.superUsers === undefined ? "" : scenario.superUsers },
      { name: "auto.create.topics.enable", readOnly: false, sensitive: false, source: 5,
        value: String(scenario.autoCreateEnabled === undefined ? false : scenario.autoCreateEnabled) },
      { name: "unclean.leader.election.enable", readOnly: false, sensitive: false, source: 5,
        value: String(!!scenario.uncleanElection) },
      { name: "zookeeper.connect", readOnly: false, sensitive: false, source: 5,
        value: scenario.zookeeperConnect === undefined ? "" : scenario.zookeeperConnect },
      { name: "listeners", readOnly: false, sensitive: false, source: 5,
        value: scenario.listeners === undefined ? "SASL_SSL://0.0.0.0:9093" : scenario.listeners },
      { name: "ssl.keystore.location", readOnly: false, sensitive: false, source: 5,
        value: "/etc/kafka/ssl/kafka.keystore.jks" },
      { name: "ssl.keystore.password", readOnly: false, sensitive: true, source: 4,
        value: sensitive ? null : (scenario.keystorePassword || "admin123") },
      { name: "offsets.topic.replication.factor", readOnly: false, sensitive: false, source: 5,
        value: String(scenario.offsetsReplication === undefined ? 3 : scenario.offsetsReplication) },
      { name: "log.retention.hours", readOnly: false, sensitive: false, source: 5,
        value: String(scenario.retentionHours === undefined ? 168 : scenario.retentionHours) },
      { name: "min.insync.replicas", readOnly: false, sensitive: false, source: 5,
        value: String(scenario.minInsync === undefined ? 1 : scenario.minInsync) },
    ];
  }

  // Topic settings: retention is the number that decides how much data a leak
  // of the topic exposes, and min.insync.replicas is the one that decides what
  // a write costs.
  function topicDefaults() {
    return [
      { name: "cleanup.policy", readOnly: false, sensitive: false, source: 5, value: "delete" },
      { name: "retention.ms", readOnly: false, sensitive: false, source: 5,
        value: String(scenario.retentionMs === undefined ? 604800000 : scenario.retentionMs) },
      { name: "segment.bytes", readOnly: false, sensitive: false, source: 5, value: "1073741824" },
      { name: "min.insync.replicas", readOnly: false, sensitive: false, source: 5,
        value: String(scenario.minInsync === undefined ? 1 : scenario.minInsync) },
      { name: "unclean.leader.election.enable", readOnly: false, sensitive: false, source: 5,
        value: String(!!scenario.uncleanElection) },
      { name: "max.message.bytes", readOnly: false, sensitive: false, source: 5, value: "1048588" },
      { name: "message.timestamp.type", readOnly: false, sensitive: false, source: 5, value: "CreateTime" },
    ];
  }

  function handleDescribeConfigs(req, version) {
    const flex = isFlexible(API.DESCRIBE_CONFIGS, version);
    const error = authError();
    const w = new Writer();
    w.i32(0);
    wArray(w, flex, req.resources || [], (ww, resource) => {
      const isTopic = (resource.type || 2) === 2;
      const known = !isTopic || topics.some((t) => t.name === resource.name);
      const code = error || (known ? 0 : STATUS.UNKNOWN_TOPIC_OR_PARTITION);
      ww.i16(code);
      wStr(ww, flex, code ? "resource not available" : null);
      ww.i8(resource.type || 2);
      wStr(ww, flex, resource.name);
      const entries = code ? [] : (configs[resource.name] || (isTopic ? topicDefaults() : brokerDefaults()));
      wArray(ww, flex, entries, (w3, entry) => {
        wStr(w3, flex, entry.name);
        wStr(w3, flex, entry.value);
        w3.bool(!!entry.readOnly);
        if (version === 0) w3.bool(false);
        if (version >= 1) w3.i8(entry.source === undefined ? 5 : entry.source);
        w3.bool(!!entry.sensitive);
        // An empty array still has to use the schema of the version that is
        // being answered: a compact array count of one, not an INT32 of zero.
        if (version >= 1) wArray(w3, flex, [], (w4) => { w4.str(""); w4.str(""); w4.i8(5); });
        if (version >= 3) w3.i8(entry.configType === undefined ? 0 : entry.configType);
        if (version >= 3) wStr(w3, flex, null);
        if (flex) w3.tags();
      });
      if (flex) ww.tags();
    });
    if (flex) w.tags();
    return w.result();
  }

  function handleCreateTopics(req, version) {
    const flex = isFlexible(API.CREATE_TOPICS, version);
    const error = authError();
    state.createTopicsCalls.push({
      validateOnly: req.validateOnly, topics: (req.topics || []).map((t) => t.name),
      partitions: (req.topics || []).map((t) => t.partitions),
    });
    if (version >= 1 && req.validateOnly !== true) {
      state.violations.push({ api: "CreateTopics", message: "validate_only was not set: this would create a real topic" });
    }
    const w = new Writer();
    if (version >= 2) w.i32(scenario.throttleMs || 0);
    wArray(w, flex, req.topics || [], (ww, topic) => {
      let code = 0;
      let message = null;
      const exists = topics.some((t) => t.name === topic.name);
      if (error) { code = error; message = "authorization failed"; }
      else if (scenario.allowCreateTopics === false) {
        code = STATUS.TOPIC_AUTHORIZATION_FAILED; message = "not authorized to create topics";
      } else if (scenario.createValidationError) {
        code = scenario.createValidationError; message = "invalid topic configuration";
      } else if (exists) {
        // Existence is checked after authorization, so this answer is only ever
        // given to a caller the ACL let through.
        code = STATUS.TOPIC_ALREADY_EXISTS; message = "Topic '" + topic.name + "' already exists.";
      } else if (req.validateOnly === true && scenario.createIgnoresValidateOnly) {
        // The failure mode the probe is looking for: a broker that creates the
        // topic even though the request asked it not to.
        topics.push({ name: topic.name, partitions: topic.partitions || 1, replicas: [1], isr: [1] });
        state.createdTopics.push(topic.name);
      }
      wStr(ww, flex, topic.name);
      if (version >= 7) ww.raw(Buffer.alloc(16, 2));
      ww.i16(code);
      if (version >= 1) wStr(ww, flex, message);
      if (version >= 5) {
        ww.i32(topic.partitions || 1);
        ww.i16(topic.replicationFactor || 1);
        w.compactArray(code === 0 ? [
          { name: "cleanup.policy", value: "delete", readOnly: true, source: 5, sensitive: false },
        ] : [], (w3, config) => {
          w3.compactStr(config.name).compactStr(config.value).bool(!!config.readOnly)
            .i8(config.source).bool(!!config.sensitive).tags();
        });
      }
      if (flex) ww.tags();
    });
    if (flex) w.tags();
    return w.result();
  }

  function handleDeleteTopics(req, version) {
    const flex = isFlexible(API.DELETE_TOPICS, version);
    const error = authError();
    const w = new Writer();
    if (version >= 1) w.i32(0);
    const requestedIds = req.ids || [];
    state.deleteTopicsCalls.push({ names: req.names || [], ids: requestedIds });
    wArray(w, flex, req.names || [], (ww, name) => {
      const index = (req.names || []).indexOf(name);
      const id = requestedIds[index];
      const exists = topics.some((t) => t.name === name);
      if (exists) {
        state.violations.push({ api: "DeleteTopics", message: `probe tried to delete existing topic ${name}` });
      }
      let code = 0;
      let message = null;
      // Authorization runs before the lookup on every version, so the denial
      // is answered first on the id path too.
      if (error) { code = error; message = "authorization failed"; }
      else if (scenario.deleteBehaviour === "denied") {
        code = STATUS.TOPIC_AUTHORIZATION_FAILED; message = "not authorized to delete topics";
      } else if (version >= 6 && id && !/^0+$/.test(id)) {
        // The v6 form is a lookup by id: a real id is chosen by the controller,
        // so an id the cluster does not know is answered with UNKNOWN_TOPIC_ID.
        // An all-zero id is the protocol's way of saying "use the name".
        const known = topics.some((t) => t.topicId === id);
        code = known ? STATUS.NONE : STATUS.UNKNOWN_TOPIC_ID;
        message = known ? null : "This server does not host this topic ID.";
      } else if (exists) { code = STATUS.INVALID_REQUEST; message = "refusing to delete a real topic"; }
      else if (scenario.deleteBehaviour === "invalid") {
        code = STATUS.INVALID_REQUEST; message = "topic name is invalid";
      } else {
        code = STATUS.UNKNOWN_TOPIC_OR_PARTITION;
        message = "This server does not host this topic-partition.";
      }
      wStr(ww, flex, name);
      ww.i16(code);
      if (version >= 5) wStr(ww, flex, message);
      if (flex) ww.tags();
    });
    if (flex) w.tags();
    return w.result();
  }

  function handleDeleteRecords(req, version) {
    // DeleteRecords moves the log start offset forward. The mock records the
    // request, answers the low watermark it would produce, and flags any
    // request that asked for an offset above zero on a topic that holds
    // records, because that would discard data on a live cluster.
    const flex = isFlexible(API.DELETE_RECORDS, version);
    const error = authError();
    const w = new Writer();
    if (version >= 1) w.i32(scenario.throttleMs || 0);
    wArray(w, flex, req.deleteTopics || [], (ww, topic) => {
      wStr(ww, flex, topic.name);
      const known = topics.some((t) => t.name === topic.name);
      wArray(ww, flex, topic.partitions || [], (w3, partition) => {
        state.deleteRecordsCalls.push({
          name: topic.name, partition: partition.partition, offset: Number(partition.offset),
        });
        let code = 0;
        if (error) code = error;
        else if (!known) code = STATUS.UNKNOWN_TOPIC_OR_PARTITION;
        else if (scenario.deleteRecordsDenied) code = STATUS.TOPIC_AUTHORIZATION_FAILED;
        else if (Number(partition.offset) > 0) {
          code = STATUS.INVALID_REQUEST;
          state.violations.push({
            api: "DeleteRecords",
            message: `probe asked to discard records below offset ${partition.offset} of ${topic.name}`,
          });
        }
        w3.i32(partition.partition);
        w3.i64(code === 0 ? 0 : -1);
        w3.i16(code);
        if (flex) w3.tags();
      });
      if (flex) ww.tags();
    });
    if (flex) w.tags();
    return w.result();
  }

  function handleSaslHandshake(req, version) {
    const w = new Writer();
    const enabled = mechanisms.includes(req.mechanism);
    w.i16(enabled ? 0 : STATUS.UNSUPPORTED_SASL_MECHANISM);
    w.array(mechanisms, (ww, name) => ww.str(name));
    return w.result();
  }

  function scramServerStep(payload, hash) {
    if (!state.scram) {
      const bare = payload.startsWith("n,,") ? payload.slice(3) : payload;
      const fields = Object.fromEntries(bare.split(",").map((kv) => kv.split("=")));
      const salt = Buffer.from(scenario.scramSalt || "nse-mock-salt", "utf8");
      const iterations = scenario.scramIterations || 4096;
      const serverNonce = `${fields.r}srvmock`;
      state.scram = {
        user: fields.n, clientNonce: fields.r, serverNonce, salt, iterations,
        clientFirstBare: bare,
        serverFirst: `r=${serverNonce},s=${salt.toString("base64")},i=${iterations}`,
      };
      return { code: 0, bytes: Buffer.from(state.scram.serverFirst, "latin1"), user: state.scram.user };
    }
    const session = state.scram;
    const fields = Object.fromEntries(payload.split(",").map((kv) => kv.split("=")));
    const user = session.user;
    const expected = (scenario.scramCredentials || {})[user];
    state.scram = null;
    if (expected === undefined) {
      return { code: STATUS.SASL_AUTHENTICATION_FAILED, bytes: Buffer.from("e=unknown-user", "latin1"), user };
    }
    if (!fields.r || fields.r !== session.serverNonce) {
      return { code: STATUS.SASL_AUTHENTICATION_FAILED, bytes: Buffer.from("e=nonce-mismatch", "latin1"), user };
    }
    const salted = crypto.pbkdf2Sync(expected, session.salt, session.iterations, hash === "sha512" ? 64 : 32, hash);
    const clientKey = crypto.createHmac(hash, salted).update("Client Key").digest();
    const storedKey = crypto.createHash(hash).update(clientKey).digest();
    const finalNoProof = payload.slice(0, payload.lastIndexOf(",p="));
    const authMessage = `${session.clientFirstBare},${session.serverFirst},${finalNoProof}`;
    const clientSignature = crypto.createHmac(hash, storedKey).update(authMessage).digest();
    const proof = Buffer.from(fields.p || "", "base64");
    let matches = proof.length === clientSignature.length;
    for (let i = 0; matches && i < proof.length; i += 1) matches = proof[i] === clientSignature[i];
    if (!matches) {
      return { code: STATUS.SASL_AUTHENTICATION_FAILED, bytes: Buffer.from("e=invalid-proof", "latin1"), user };
    }
    const serverKey = crypto.createHmac(hash, salted).update("Server Key").digest();
    const serverSignature = crypto.createHmac(hash, serverKey).update(authMessage).digest("base64");
    return { code: 0, bytes: Buffer.from(`v=${serverSignature}`, "latin1"), user };
  }

  function handleSaslAuthenticate(req, version) {
    const flex = isFlexible(API.SASL_AUTHENTICATE, version);
    const w = new Writer();
    const payload = req.authBytes ? req.authBytes.toString("latin1") : "";
    const attempt = { mechanism: state.lastMechanism, bytes: payload.length };
    let code = STATUS.ILLEGAL_SASL_STATE;
    let message = "No SASL handshake was performed";
    let responseBytes = Buffer.alloc(0);
    if (state.lastMechanism === "PLAIN") {
      const parts = payload.split("\0");
      const user = parts[1] || "";
      const password = parts[2] || "";
      const expected = (scenario.plainCredentials || {})[user];
      attempt.user = user;
      if (expected !== undefined && expected === password) {
        code = 0;
        message = null;
      } else {
        code = STATUS.SASL_AUTHENTICATION_FAILED;
        message = "Authentication failed: Invalid username or password";
      }
    } else if (state.lastMechanism === "SCRAM-SHA-256" || state.lastMechanism === "SCRAM-SHA-512") {
      const step = scramServerStep(payload, state.lastMechanism === "SCRAM-SHA-512" ? "sha512" : "sha256");
      code = step.code;
      responseBytes = step.bytes;
      attempt.user = step.user;
      if (code !== 0) message = "Authentication failed during SCRAM exchange";
    }
    state.saslAttempts.push(attempt);
    w.i16(code);
    wStr(w, flex, message);
    wBytes(w, flex, responseBytes);
    if (version >= 1) w.i64(0);
    if (flex) w.tags();
    return w.result();
  }

  const handlers = {
    [API.API_VERSIONS]: handleApiVersions,
    [API.METADATA]: handleMetadata,
    [API.DESCRIBE_CLUSTER]: handleDescribeCluster,
    [API.LIST_GROUPS]: handleListGroups,
    [API.DESCRIBE_GROUPS]: handleDescribeGroups,
    [API.FIND_COORDINATOR]: handleFindCoordinator,
    [API.OFFSET_FETCH]: handleOffsetFetch,
    [API.LIST_OFFSETS]: handleListOffsets,
    [API.FETCH]: handleFetch,
    [API.DESCRIBE_CONFIGS]: handleDescribeConfigs,
    [API.CREATE_TOPICS]: handleCreateTopics,
    [API.DELETE_RECORDS]: handleDeleteRecords,
    [API.DELETE_TOPICS]: handleDeleteTopics,
  };

  // -- request parsers ------------------------------------------------------
  // Each one walks the schema for the negotiated version, so a client that
  // encodes a field in the wrong order, or uses the wrong schema family, fails
  // loudly instead of being answered with plausible nonsense.
  function parseRequest(apiKey, version, r) {
    const flex = isFlexible(apiKey, version);
    switch (apiKey) {
      case API.API_VERSIONS:
        if (flex) { r.compactStr(); r.compactStr(); r.tags(); }
        return {};
      case API.METADATA: {
        // Topics is an array of strings, not of structs: a TAG_BUFFER only
        // exists per struct, so no tags are read after each name.
        const topics = rArray(r, flex, (rr) => rStr(rr, flex));
        const autoCreate = version >= 4 ? r.bool() : false;
        let includeTopicOps = false;
        if (version >= 8) {
          r.bool();
          includeTopicOps = r.bool();
        }
        if (flex) r.tags();
        return { topics, autoCreate, includeTopicOps };
      }
      case API.DESCRIBE_CLUSTER:
        r.bool();
        if (version >= 1) r.i8();
        r.tags();
        return {};
      case API.LIST_GROUPS: {
        let states = null;
        if (version >= 4) states = rArray(r, flex, (rr) => rStr(rr, flex));
        if (flex) r.tags();
        return { states };
      }
      case API.DESCRIBE_GROUPS: {
        const groups = rArray(r, flex, (rr) => rStr(rr, flex));
        if (version >= 3) r.bool();
        if (flex) r.tags();
        return { groups };
      }
      case API.FIND_COORDINATOR: {
        const key = r.str();
        if (version >= 1) r.i8();
        if (flex) r.tags();
        return { key };
      }
      case API.OFFSET_FETCH: {
        if (version >= 8) {
          const groups = r.compactArray((rr) => {
            const group = rr.compactStr();
            const topics = rr.compactArray((r3) => {
              const name = r3.compactStr();
              const partitions = r3.compactArray((r4) => r4.i32());
              r3.tags();
              return { name, partitions };
            });
            rr.tags();
            return { group, topics };
          });
          r.bool();
          r.tags();
          const first = groups && groups[0] ? groups[0] : { group: null, topics: null };
          return { group: first.group, topics: first.topics };
        }
        const group = r.str();
        let topics = null;
        const count = r.peekI32();
        if (count < 0) {
          r.i32();
        } else {
          topics = rArray(r, flex, (rr) => {
            const name = rStr(rr, flex);
            const partitions = rArray(rr, flex, (r3) => r3.i32());
            if (flex) rr.tags();
            return { name, partitions };
          });
        }
        if (flex) r.tags();
        return { group, topics };
      }
      case API.LIST_OFFSETS: {
        r.i32();
        if (version >= 2) r.i8();
        const topics = rArray(r, flex, (rr) => {
          const name = rStr(rr, flex);
          const partitions = rArray(rr, flex, (r3) => {
            const partition = r3.i32();
            if (version >= 4) r3.i32();
            const timestamp = r3.i64();
            if (flex) r3.tags();
            return { partition, timestamp };
          });
          if (flex) rr.tags();
          return { name, partitions };
        });
        if (flex) r.tags();
        return { topics };
      }
      case API.FETCH: {
        r.i32();
        r.i32();
        r.i32();
        if (version >= 3) r.i32();
        if (version >= 4) r.i8();
        if (version >= 7) { r.i32(); r.i32(); }
        const topics = r.array((rr) => {
          const name = rr.str();
          const partitions = rr.array((r3) => {
            const partition = r3.i32();
            if (version >= 9) r3.i32();
            const fetchOffset = r3.i64();
            if (version >= 5) r3.i64();
            r3.i32();
            return { partition, fetchOffset };
          });
          return { name, partitions };
        });
        if (version >= 7) r.array(() => []);
        return { topics };
      }
      case API.DESCRIBE_CONFIGS: {
        const resources = rArray(r, flex, (rr) => {
          const type = rr.i8();
          const name = rStr(rr, flex);
          const configNames = rArray(rr, flex, (r3) => rStr(r3, flex));
          if (flex) rr.tags();
          return { type, name, configNames };
        });
        if (version >= 1) r.bool();
        if (version >= 3) r.bool();
        if (flex) r.tags();
        return { resources };
      }
      case API.CREATE_TOPICS: {
        const topics = rArray(r, flex, (rr) => {
          const name = rStr(rr, flex);
          const partitions = rr.i32();
          const replicationFactor = rr.i16();
          rArray(rr, flex, (r3) => {
            r3.i32();
            rArray(r3, flex, (r4) => r4.i32());
            if (flex) r3.tags();
            return null;
          });
          rArray(rr, flex, (r3) => {
            const cname = rStr(r3, flex);
            const cvalue = rStr(r3, flex);
            if (flex) r3.tags();
            return { name: cname, value: cvalue };
          });
          if (flex) rr.tags();
          return { name, partitions, replicationFactor };
        });
        const timeoutMs = r.i32();
        const validateOnly = version >= 1 ? r.bool() : false;
        if (flex) r.tags();
        return { topics, timeoutMs, validateOnly };
      }
      case API.DELETE_RECORDS: {
        const deleteTopics = rArray(r, flex, (rr) => {
          const name = rStr(rr, flex);
          const partitions = rArray(rr, flex, (r3) => {
            const partition = r3.i32();
            const offset = r3.i64();
            if (flex) r3.tags();
            return { partition, offset };
          });
          if (flex) rr.tags();
          return { name, partitions };
        });
        const timeoutMs = r.i32();
        if (flex) r.tags();
        return { deleteTopics, timeoutMs };
      }
      case API.DELETE_TOPICS: {
        let names;
        let ids = [];
        if (version >= 6) {
          const entries = r.compactArray((rr) => {
            const name = rr.compactStr();
            const id = rr.need(16);
            rr.tags();
            return { name, id };
          });
          names = entries.map((entry) => entry.name);
          ids = entries.map((entry) => entry.id.toString("hex"));
        } else {
          names = rArray(r, flex, (rr) => rStr(rr, flex));
        }
        r.i32();
        if (flex) r.tags();
        return { names, ids };
      }
      default:
        return {};
    }
  }

  function handle(payload) {
    state.requests.push({ bytes: payload.length, at: Date.now() });
    if (scenario.changeTopicsAfterRequests
      && state.requests.length === scenario.changeTopicsAfterRequests) {
      // Models the other actor: something outside the scan changes the cluster
      // while it runs, which the script's before/after comparison must notice.
      topics.push({ name: scenario.changeTopicName || "ghost-topic", partitions: 1,
        replicas: [1], isr: [1] });
      state.externalTopicChanges = (state.externalTopicChanges || 0) + 1;
    }
    if (scenario.dropFirst && state.dropped < scenario.dropFirst) {
      state.dropped += 1;
      return null;
    }
    if (scenario.silent) return null;
    if (payload.length < 4) {
      state.protocolErrors.push({ message: "frame shorter than its length prefix" });
      return null;
    }
    const declared = payload.readUInt32BE(0);
    if (declared !== payload.length - 4) {
      state.protocolErrors.push({ message: `length prefix says ${declared}, frame carries ${payload.length - 4}` });
      return null;
    }
    const r = new Reader(payload.subarray(4));
    let apiKey;
    let version;
    try {
      apiKey = r.i16();
      version = r.i16();
      const correlation = r.i32();
      const requestFlexible = isFlexible(apiKey, version);
      // The client id follows the schema family: a compact (uvarint) string
      // once the request header is v2, a plain INT16 string before that.
      const clientId = requestFlexible ? r.compactStr() : r.str();
      if (requestFlexible) r.tags();
      const entry = Object.assign(state.requests[state.requests.length - 1], {
        api: apiKey, apiName: API_NAMES[apiKey] || `API_${apiKey}`, version,
        correlation, clientId, flexible: requestFlexible,
      });

      const effective = versionFor(apiKey, version);
      const flex = isFlexible(apiKey, effective);
      const w = new Writer();
      w.i32(correlation);
      if (apiKey !== API.API_VERSIONS && flex) w.tags();

      if (apiKey === API.SASL_HANDSHAKE) {
        const mechanism = r.str();
        state.lastMechanism = mechanism;
        entry.mechanism = mechanism;
        w.raw(handleSaslHandshake({ mechanism }, effective));
        return { raw: frame(w.result()) };
      }
      if (apiKey === API.SASL_AUTHENTICATE) {
        const authBytes = flex ? r.compactBytes() : r.bytes();
        entry.saslBytes = authBytes ? authBytes.length : 0;
        if (scenario.saslRequired === "silent" && state.lastMechanism === null) {
          return null;
        }
        w.raw(handleSaslAuthenticate({ authBytes }, effective));
        return { raw: frame(w.result()) };
      }
      if (scenario.saslRequired === "silent" && !state.authenticated) {
        return null;
      }
      if (state.lastMechanism && apiKey !== API.API_VERSIONS) {
        // Once a SASL exchange has happened the broker only accepts the
        // authenticated connection's admin traffic; the mock keeps answering
        // so a script can still audit what an authenticated principal sees.
        entry.postSasl = true;
      }
      const handler = handlers[apiKey];
      if (!handler) {
        state.protocolErrors.push({ message: `no handler for api ${apiKey} v${version}` });
        return null;
      }
      if ((scenario.faultOnApi || {})[apiKey]) return null;
      const request = parseRequest(apiKey, effective, r);
      if (apiKey === API.METADATA) {
        entry.topicCount = (request.topics === null || request.topics === undefined)
          ? null : request.topics.length;
        entry.autoCreate = request.autoCreate === true;
        entry.namedTopics = request.topics || null;
      }
      if (scenario.idleAfter && state.requests.length > scenario.idleAfter + 1) return null;
      w.raw(handler(request, effective));
      const framed = frame(w.result());
      if (scenario.truncateBytes) return { raw: framed.subarray(0, scenario.truncateBytes) };
      return { raw: framed };
    } catch (err) {
      state.protocolErrors.push({ message: err.message, api: apiKey, version });
      return null;
    }
  }

  return { handle, state };
}

module.exports = { createMockKafka, buildRecordBatch, crc32c, Reader, Writer, API, STATUS };
