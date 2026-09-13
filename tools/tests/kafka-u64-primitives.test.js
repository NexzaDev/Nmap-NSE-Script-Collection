"use strict";
const fs = require("fs");
const path = require("path");
// The reference values are generated from an independent 64-bit implementation
// (Python integers, masked to 2^64) and kept in the repository, so the vectors
// survive a clean checkout.
const vec = JSON.parse(fs.readFileSync(
  path.join(__dirname, "..", "..", "test-fixtures", "kafka-u64-vectors.json"), "utf8"));
const expect = {};
for (const [k, v] of Object.entries(vec)) expect[k] = v;
module.exports = {
  name: "kafka-u64-primitives",
  scenarios: [{
    name: "64-bit rotate/shift/add match BigInt references",
    script: "test-fixtures/kafka-u64-probe.nse",
    port: { number: 9092, protocol: "tcp", state: "open", service: "kafka" },
    mockFactory: () => ({ handle: () => null, state: { requests: [] } }),
    expect,
  }],
};
