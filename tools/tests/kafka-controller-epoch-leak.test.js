"use strict";
/*
 * tools/tests/kafka-controller-epoch-leak.test.js
 * ---------------------------------------------------------------------------
 * Integration scenarios for KAFKA-AMQP/kafka-controller-epoch-leak.nse.
 *
 * The scenarios describe clusters whose metadata says something: an
 * under-replicated topic, a controller that is not a broker, leadership piled
 * on one node, a controller election during the scan, and a listener that
 * refuses Metadata entirely. The verify hooks watch the wire - how many
 * Metadata samples were taken and that no request in the script can write.
 */

const { createMockKafka } = require("../mocks/kafka");

const PORT = { number: 9092, protocol: "tcp", state: "open", service: "kafka" };

function scenario(name, options) {
  const mock = createMockKafka(options.broker || {});
  return Object.assign({
    name,
    script: "KAFKA-AMQP/kafka-controller-epoch-leak.nse",
    port: PORT,
    args: Object.assign({ "kafka.timeout": "2000", "kafka.sample-gap-ms": "0" }, options.args || {}),
    mockFactory: () => mock,
    expect: options.expect,
    expectAll: options.expectAll,
    verify: (result, state) => {
      const checks = [];
      const say = (ok, message) => checks.push({ ok, message });
      say((state.protocolErrors || []).length === 0,
        `the mock decoded every request without a protocol error (${JSON.stringify(state.protocolErrors)})`);
      say((state.violations || []).length === 0,
        `no request could change broker state (violations: ${JSON.stringify(state.violations)})`);
      if (options.verify) options.verify({ state, result, say });
      return checks;
    },
  }, options.scenario || {});
}

const healthyBrokers = [
  { nodeId: 1, host: "broker-1.internal", port: 9092, rack: "rack-a" },
  { nodeId: 2, host: "broker-2.internal", port: 9092, rack: "rack-b" },
  { nodeId: 3, host: "broker-3.internal", port: 9092, rack: "rack-c" },
];

module.exports = {
  name: "kafka-controller-epoch-leak",
  scenarios: [
    scenario("under-replicated partitions are reported as an availability exposure", {
      broker: {
        clusterId: "nse-leak-cluster",
        controllerId: 1,
        brokers: healthyBrokers,
        topics: [
          { name: "orders", partitions: 4, replicas: [1, 2, 3], isr: [1, 2], internal: false, leader: 1 },
          { name: "payments", partitions: 2, replicas: [1, 2, 3], isr: [1, 2, 3], internal: false, leader: 2 },
          { name: "__consumer_offsets", partitions: 2, replicas: [1, 2, 3], isr: [2, 3], internal: true, leader: 3 },
        ],
        highWatermark: 500,
      },
      expect: {
        "Replica health": "Under-replicated partitions:",
        "Findings": "KAFKA-UNDER-REPLICATED-PARTITIONS",
        "Risk Level": "MEDIUM",
      },
      expectAll: [
        { contains: "KAFKA-CONTROLLER-IDENTITY-LEAK" },
        { contains: "KAFKA-TOPOLOGY-DISCLOSURE" },
      ],
      verify: ({ state, say }) => {
        const metadata = state.requests.filter((r) => r.apiName === "Metadata");
        say(metadata.length >= 3, `Metadata was sampled repeatedly (${metadata.length} requests)`);
        say(metadata.every((r) => r.version >= 7), "the probe asked for leader epochs");
      },
    }),

    scenario("a controller that is not a broker is reported as a separate quorum", {
      broker: {
        clusterId: "nse-kraft-quorum",
        controllerId: 99,
        brokers: healthyBrokers,
        topics: [{ name: "orders", partitions: 3, replicas: [1, 2, 3], isr: [1, 2, 3], internal: false, leader: 1 }],
      },
      expect: {
        "Cluster": "not in the broker list",
        "Exposure": "controller identity",
      },
      expectAll: [{ contains: "controller id 99" }],
    }),

    scenario("leadership concentrated on one broker is a finding", {
      broker: {
        controllerId: 1,
        brokers: healthyBrokers,
        topics: [
          { name: "orders", partitions: 6, replicas: [1, 2, 3], isr: [1, 2, 3], internal: false, leader: 1 },
          { name: "payments", partitions: 4, replicas: [1, 2, 3], isr: [1, 2, 3], internal: false, leader: 1 },
        ],
      },
      expect: {
        "Replica health": "leads",
        "Findings": "KAFKA-LEADER-CONCENTRATION",
      },
      expectAll: [{ contains: "leads 10 of 10 partitions" }],
    }),

    scenario("leader epochs and offline replicas are quoted when the broker reports them", {
      broker: {
        controllerId: 2,
        brokers: healthyBrokers,
        topics: [{ name: "orders", partitions: 2, replicas: [1, 2, 3], isr: [1, 2, 3], internal: false,
          leader: 2, offline: [3], leaderEpoch: 7 }],
      },
      expect: {
        "Cluster": "Metadata fields available",
        "Topic map": "epoch=",
      },
      expectAll: [{ contains: "leader epochs" }],
    }),

    scenario("a listener that refuses metadata reports no exposure", {
      broker: { anonymousAllowed: false },
      expect: {
        "Exposure": "broker inventory",
        "Risk Level": "NONE",
      },
      expectAll: [{ contains: "not computed (the broker withheld the mask)" }],
      verify: ({ state, say }) => {
        const metadata = state.requests.filter((r) => r.apiName === "Metadata");
        say(metadata.length >= 1, "the request was still attempted");
        say(metadata.every((r) => r.version >= 7), "the probe still asked for the richest schema");
      },
    }),

    scenario("a listener that answers nothing at all is reported as unmeasured", {
      broker: { faultOnApi: { 3: true, 60: true } },
      expect: {
        "Exposure": "No exposure was measured",
        "Findings": "KAFKA-METADATA-NOT-AVAILABLE",
        "Risk Level": "UNKNOWN",
      },
      verify: ({ state, say }) => {
        say(state.requests.length >= 3, `the probes were still sent (${state.requests.length} requests)`);
      },
    }),

    scenario("a silent listener produces an unknown verdict, not a clean one", {
      broker: { saslRequired: "silent" },
      expect: {
        "Risk Level": "UNKNOWN",
        "Stability samples": "no answer",
      },
      verify: ({ state, say }) => {
        say(state.dropped === 0, "the mock dropped frames instead of closing the socket");
      },
    }),
  ],
};
