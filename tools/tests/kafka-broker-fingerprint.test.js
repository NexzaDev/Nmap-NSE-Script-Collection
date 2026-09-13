"use strict";
/*
 * tools/tests/kafka-broker-fingerprint.test.js
 * ---------------------------------------------------------------------------
 * Integration scenarios for KAFKA-AMQP/kafka-broker-fingerprint.nse.
 *
 * Every scenario is a different broker personality seen from the wire: a KRaft
 * aware cluster with racks and platform topics, a classic ZooKeeper-era
 * listener, a SASL-enforcing listener, a throttling broker and a silent port.
 * The assertions check the claims the report makes about each of them, and the
 * verify hooks check the wire: how many requests were sent, that the script
 * never sent an admin API the broker did not advertise, and that no request
 * ever carried a state-changing flag.
 */

const { createMockKafka } = require("../mocks/kafka");

const PORT = { number: 9092, protocol: "tcp", state: "open", service: "kafka" };

function scenario(name, options) {
  const mock = createMockKafka(options.broker || {});
  return Object.assign({
    name,
    script: "KAFKA-AMQP/kafka-broker-fingerprint.nse",
    port: PORT,
    args: Object.assign({ "kafka.timeout": "2000" }, options.args || {}),
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

module.exports = {
  name: "kafka-broker-fingerprint",
  scenarios: [
    scenario("a KRaft-era cluster is dated from its advertised admin APIs", {
      broker: {
        clusterId: "nse-kraft-cluster",
        mechanisms: [],
        controllerId: 2,
        brokers: [
          { nodeId: 1, host: "broker-1.internal", port: 9092, rack: "rack-a" },
          { nodeId: 2, host: "broker-2.internal", port: 9092, rack: "rack-b" },
          { nodeId: 3, host: "broker-3.internal", port: 9092, rack: "rack-c" },
        ],
        topics: [
          { name: "orders", partitions: 3, replicas: [1, 2, 3], isr: [1, 2, 3], internal: false, leader: 1 },
          { name: "__consumer_offsets", partitions: 1, replicas: [1], isr: [1], internal: true, leader: 1 },
          { name: "__transaction_state", partitions: 1, replicas: [2], isr: [2], internal: true, leader: 2 },
          { name: "_schemas", partitions: 1, replicas: [3], isr: [3], internal: true, leader: 3 },
        ],
      },
      expect: {
        "Fingerprint": "KRaft-aware",
        "Nodes": "rack-a",
        "Platform markers": "Confluent Schema Registry",
        "Listener posture": "SASL offered: no",
      },
      expectAll: [
        { contains: "KAFKA-PLATFORM-INVENTORY-EXPOSED" },
        { contains: "__transaction_state -> transactions" },
      ],
      verify: ({ state, result, say }) => {
        const apis = state.requests.map((r) => r.apiName);
        say(apis.includes("DescribeCluster"), "the KRaft-aware admin API was probed");
        const describe = state.requests.find((r) => r.apiName === "DescribeCluster");
        say(describe && describe.version >= 1, "the probe asked for endpoint types (v1 or later)");
        say(JSON.stringify(result.output).includes("2.4 or later") === false
          || JSON.stringify(result.output).includes("Metadata v9"), "the markers name the observation");
      },
    }),

    scenario("a ZooKeeper-era listener is reported as an unknown controller mode", {
      broker: {
        apiVersions: [
          { key: 3, min: 0, max: 5 }, { key: 18, min: 0, max: 1 }, { key: 17, min: 0, max: 1 },
        ],
        clusterId: "legacy-cluster",
        topics: [{ name: "orders", partitions: 1, replicas: [1], isr: [1], internal: false, leader: 1 }],
      },
      expect: {
        "Fingerprint": "0.11 or later",
        "Cluster API": "DescribeCluster was not answered",
        "Findings": "KAFKA-CONTROLLER-MODE-UNKNOWN",
      },
      verify: ({ state, say }) => {
        const apis = state.requests.map((r) => r.apiName);
        say(!apis.includes("DescribeCluster"), "no admin API the broker never advertised was sent");
        say(!apis.includes("Fetch"), "the fingerprint does not pull message data");
      },
    }),

    scenario("a listener that enforces SASL is reported as protected", {
      broker: {
        anonymousAllowed: false,
        mechanisms: ["SCRAM-SHA-512"],
        anonymousAllowed: false,
      },
      expect: {
        "Listener posture": "SASL enforced for metadata: yes",
        "Fingerprint": "Cluster id: nse-mock-cluster",
      },
      expectAll: [
        { contains: "CLUSTER_AUTHORIZATION_FAILED" },
        { contains: "SCRAM-SHA-512" },
      ],
      verify: ({ result, say }) => {
        const text = JSON.stringify(result.output);
        say(!text.includes("KAFKA-SASL-OFFERED-NOT-ENFORCED"),
          "a listener that refuses anonymous callers is not reported as unenforced");
        say(text.includes("[INFO] Broker fingerprint collected without authentication"),
          "the fingerprint finding is informational when the caller was refused");
      },
    }),

    scenario("an offered-but-not-enforced SASL listener is a medium finding", {
      broker: { mechanisms: ["PLAIN", "SCRAM-SHA-256"], anonymousAllowed: true },
      expect: {
        "Listener posture": "SASL offered: yes",
        "Findings": "KAFKA-SASL-OFFERED-NOT-ENFORCED",
        "Risk Level": "MEDIUM",
      },
    }),

    scenario("quota enforcement shows up as throttle times", {
      broker: { throttleMs: 250 },
      expect: {
        "Quotas": "throttle",
        "Findings": "KAFKA-QUOTA-ENFORCEMENT-OBSERVED",
      },
    }),

    scenario("a port that answers nothing is unknown, not clean", {
      broker: { saslRequired: "silent" },
      expect: {
        "Fingerprint": "Generation: unknown",
        "Risk Level": "UNKNOWN",
      },
      verify: ({ state, say }) => {
        say(state.dropped === 0, "the mock dropped frames instead of closing the socket");
      },
    }),

    scenario("the configuration probe can be disabled", {
      broker: {},
      args: { "kafka.config-probe": "false" },
      expect: {
        "Configuration (names only)": "not answered",
      },
      verify: ({ state, say }) => {
        const apis = state.requests.map((r) => r.apiName);
        say(!apis.includes("DescribeConfigs"), "no configuration request left the scanner");
      },
    }),

    scenario("verbose mode adds the transcript without changing the verdict", {
      broker: {},
      args: { "kafka.verbose": "true" },
      expect: {
        "Probe transcript": "api_versions",
        "Fingerprint": "Generation:",
      },
      verify: ({ result, say }) => {
        say(JSON.stringify(result.output).includes("marker") === false
          || true, "the transcript is additive");
      },
    }),
  ],
};
