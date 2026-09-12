"use strict";
/*
 * tools/mocks/sntp.js
 * ---------------------------------------------------------------------------
 * A minimal but faithful SNTP (RFC 5905 / RFC 4330) responder for the NSE
 * simulator. It builds the 48 byte reply from scratch, independently of the
 * script under test, so a mistake in the script's decoder cannot be hidden by a
 * matching mistake here.
 *
 * The scenario controls the server's clock relative to the host's:
 *   { offsetSeconds: 12, stratum: 2, rootDispersion: 0.004, unsynchronised: false }
 */

const NTP_EPOCH_OFFSET = 2208988800;

function encodeTimestamp(unixSeconds) {
  const seconds = Math.floor(unixSeconds) + NTP_EPOCH_OFFSET;
  const fraction = Math.floor((unixSeconds - Math.floor(unixSeconds)) * 4294967296);
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(seconds >>> 0, 0);
  buf.writeUInt32BE(fraction >>> 0, 4);
  return buf;
}

function decodeTimestamp(buf, offset) {
  const seconds = buf.readUInt32BE(offset);
  const fraction = buf.readUInt32BE(offset + 4);
  if (seconds === 0 && fraction === 0) return null;
  return (seconds - NTP_EPOCH_OFFSET) + fraction / 4294967296;
}

function createMockSntp(scenario = {}) {
  const state = { requests: 0, rejected: 0 };

  function handle(payload) {
    state.requests += 1;
    if (payload.length < 48) {
      return { raw: null, error: "SNTP request shorter than 48 bytes" };
    }
    const mode = payload[0] & 0x07;
    if (mode !== 3) {
      return { raw: null, error: `expected client mode 3, got ${mode}` };
    }
    if (scenario.silent) {
      return { raw: null };
    }

    const now = Date.now() / 1000 + (scenario.offsetSeconds || 0);
    const t1 = decodeTimestamp(payload, 40); // the client's transmit timestamp

    const reply = Buffer.alloc(48);
    const leap = scenario.unsynchronised ? 3 : 0;
    reply[0] = (leap << 6) | (4 << 3) | (scenario.broadcast ? 5 : 4);
    reply[1] = scenario.stratum !== undefined ? scenario.stratum : 2;
    reply[2] = 6;                                  // poll interval
    reply[3] = 0xEC;                               // precision 2^-20
    reply.writeUInt32BE(Math.round(0.001 * 65536), 4);   // root delay ~1 ms
    reply.writeUInt32BE(Math.round((scenario.rootDispersion || 0.004) * 65536), 8);
    reply.write("GPS\0", 12, 4, "ascii");          // reference identifier
    encodeTimestamp(now - 16).copy(reply, 16);     // reference timestamp
    if (t1 !== null) encodeTimestamp(t1).copy(reply, 24); // originate: echo the client
    encodeTimestamp(now - 0.001).copy(reply, 32);  // receive timestamp
    encodeTimestamp(now).copy(reply, 40);          // transmit timestamp
    return { raw: reply };
  }

  return { handle, state };
}

module.exports = { createMockSntp, encodeTimestamp, decodeTimestamp };
