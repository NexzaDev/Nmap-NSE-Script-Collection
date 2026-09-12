"use strict";
/*
 * tools/tests/kafka-metadata-topic-leak.test.js
 * ---------------------------------------------------------------------------
 * Integration scenarios for KAFKA-AMQP/kafka-metadata-topic-leak.nse.
 *
 * The mock publishes a metadata inventory that is unhealthy and named like a
 * real payment platform, so the assertions can check the analysis (health,
 * naming, configuration, authorization boundary) rather than line presence.
 * The verify hooks enforce the invariant that makes this script safe to run
 * against production: it never asks the broker to create anything.
 */

const { createMockKafka } = require("../mocks/kafka");

const PORT = { number: 9092, protocol: "tcp", state: "open", service: "kafka" };

function scenario(name, options) {
  const mock = createMockKafka(options.broker || {});
  return Object.assign({
    name,
    script: "KAFKA-AMQP/kafka-metadata-topic-leak.nse",
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
        `no request could change state (violations: ${JSON.stringify(state.violations)})`);
      say(state.autoCreateRequests === 0,
        `no request asked the broker to auto-create a topic (${state.autoCreateRequests})`);
      const forbidden = ["CreateTopics", "DeleteTopics", "Produce", "AlterConfigs", "OffsetCommit"];
      const sent = state.requests.map((r) => r.apiName).filter((n) => forbidden.includes(n));
      say(sent.length === 0, `the probe sent no state-changing API (${sent.join(", ") || "none"})`);
      if (options.verify) options.verify({ state, result, say });
      return checks;
    },
  }, options.scenario || {});
}

const BROKERS = [
  { nodeId: 1, host: "broker-1.internal", port: 9092, rack: "rack-a" },
  { nodeId: 2, host: "broker-2.internal", port: 9092, rack: "rack-b" },
  { nodeId: 3, host: "broker-3.internal", port: 9092, rack: "rack-c" },
];

const OPEN_PLATFORM = {
  clusterId: "nse-prod-cluster",
  controllerId: 2,
  brokers: BROKERS,
  topics: [
    { name: "orders", partitions: 6, replicas: [1, 2, 3], isr: [1, 2, 3], leader: 1 },
    { name: "payments-eu", partitions: 4, replicas: [1, 2, 3], isr: [1, 2], leader: 1 },
    { name: "customer-pii", partitions: 2, replicas: [1, 2], isr: [1, 2], leader: 2 },
    { name: "__consumer_offsets", partitions: 2, replicas: [1, 2, 3], isr: [1, 2, 3], internal: true, leader: 1 },
  ],
  configs: {
    1: [
      { name: "retention.ms", value: "604800000", source: 5 },
      { name: "min.insync.replicas", value: "1", source: 5 },
      { name: "auto.create.topics.enable", value: "true", source: 5 },
      { name: "ssl.keystore.password", value: "keystore-secret", sensitive: true, readOnly: false, source: 4 },
      { name: "unclean.leader.election.enable", value: "false", source: 5 },
    ],
    "payments-eu": [
      { name: "cleanup.policy", value: "compact", source: 1 },
      { name: "min.insync.replicas", value: "1", source: 1 },
    ],
  },
};

module.exports = {
  name: "kafka-metadata-topic-leak",
  scenarios: [
    scenario("an open broker publishes the inventory, the configuration and a secret", {
      broker: OPEN_PLATFORM,
      expect: {
        "Risk Level": "CRITICAL",
        "Findings": "KAFKA-TOPIC-INVENTORY-DISCLOSURE",
        "Topic inventory": "payments-eu",
        "Configuration": "retention.ms                       7d",
        "Cluster": "nse-prod-cluster",
      },
      expectAll: [
        { contains: "KAFKA-INTERNAL-TOPIC-EXPOSURE" },
        { contains: "__consumer_offsets" },
        { contains: "KAFKA-TOPIC-CONFIG-DISCLOSURE" },
        { contains: "KAFKA-CONFIG-SECRET-DISCLOSURE" },
        { contains: "KAFKA-SENSITIVE-TOPIC-NAME-DISCLOSURE" },
        { contains: "KAFKA-UNDER-REPLICATED-PARTITIONS" },
        { contains: "KAFKA-MIN-INSYNC-REPLICAS-WEAK" },
        { contains: "KAFKA-AUTO-CREATE-ENABLED" },
      ],
      verify: ({ state, result, say }) => {
        const apis = state.requests.map((r) => r.apiName);
        for (const name of ["Metadata", "DescribeConfigs", "DescribeCluster", "ListGroups"]) {
          say(apis.includes(name), `the probe spoke ${name}`);
        }
        const text = JSON.stringify(result.output);
        say(text.includes("offers group coordinators") || text.includes("group-coordinator count"),
          "the internal topic note explains what __consumer_offsets reveals");
        say(text.includes("keystore"), "the sensitive configuration value is named");
        say(text.includes("rack-a"), "the rack topology is reported");
      },
    }),

    scenario("an authorizer filters the listing down to nothing", {
      broker: { anonymousAllowed: false },
      expect: {
        "Risk Level": "MEDIUM",
        "Findings": "KAFKA-METADATA-FILTERED",
        "Access matrix": "filtered",
      },
      verify: ({ result, say }) => {
        const text = JSON.stringify(result.output);
        say(!text.includes("KAFKA-TOPIC-INVENTORY-DISCLOSURE"),
          "a filtered listing is never reported as an inventory disclosure");
      },
    }),

    scenario("offline and in-sync-less partitions are reported as published outages", {
      broker: {
        topics: [
          { name: "orders", partitions: 3, replicas: [1, 2, 3], isr: [1], offline: [2, 3], leader: 1 },
        ],
      },
      expect: {
        "Findings": "KAFKA-OFFLINE-REPLICAS-PUBLISHED",
      },
      expectAll: [
        { contains: "KAFKA-UNDER-REPLICATED-PARTITIONS" },
      ],
    }),

    scenario("a partition with an empty in-sync set is reported as an outage", {
      broker: {
        topics: [
          { name: "orders", partitions: 2, replicas: [1, 2], isr: [], leader: -1 },
        ],
      },
      expect: {
        "Findings": "KAFKA-PARTITIONS-WITHOUT-ISR",
        "Topic inventory": "without leader",
      },
    }),

    scenario("one broker leading everything is reported as concentration", {
      broker: {
        brokers: [{ nodeId: 1, host: "a" }, { nodeId: 2, host: "b" }],
        topics: [
          { name: "orders", partitions: 4, replicas: [1, 2], isr: [1, 2], leader: 1 },
          { name: "events", partitions: 3, replicas: [1, 2], isr: [1, 2], leader: 1 },
        ],
      },
      expect: {
        "Findings": "KAFKA-LEADER-CONCENTRATION",
        "Topic inventory": "Leadership",
      },
    }),

    scenario("configuration can be left alone", {
      broker: OPEN_PLATFORM,
      args: { "kafka.configs": "false" },
      expect: {
        "Configuration": "Configuration was not read: kafka.configs=false",
        "Findings": "KAFKA-CONFIG-READ-NOT-ATTEMPTED",
      },
      verify: ({ state, say }) => {
        const apis = state.requests.map((r) => r.apiName);
        say(!apis.includes("DescribeConfigs"), "no configuration request was sent");
      },
    }),

    scenario("an unknown name answered with a missing-topic error is an existence oracle", {
      broker: OPEN_PLATFORM,
      expect: {
        "Authorization boundary": "existence oracle",
        "Findings": "KAFKA-TOPIC-EXISTENCE-ORACLE",
      },
    }),

    scenario("an unknown name refused with an authorization error hides existence", {
      broker: Object.assign({}, OPEN_PLATFORM, { unknownTopicError: 29 }),
      expect: {
        "Authorization boundary": "Authorization is evaluated before existence",
        "Findings": "KAFKA-AUTHORIZATION-PRECEDES-EXISTENCE",
      },
    }),

    scenario("a broker that creates the topic despite the flag is reported as critical", {
      broker: Object.assign({}, OPEN_PLATFORM, { autoCreateIgnoringFlag: true }),
      expect: {
        "Risk Level": "CRITICAL",
        "Findings": "KAFKA-AUTO-CREATE-FLAG-IGNORED",
      },
      verify: ({ state, say }) => {
        say(state.autoCreatedTopics.length === 1,
          `the mock created exactly one topic to model the ignored flag (${JSON.stringify(state.autoCreatedTopics)})`);
      },
    }),

    scenario("topics that are listed but refused by name expose the ACL boundary", {
      broker: {
        clusterId: "nse-acl",
        topics: [
          { name: "orders", partitions: 1, replicas: [1], isr: [1] },
          { name: "secrets", partitions: 1, replicas: [1], isr: [1] },
        ],
        topicErrors: { secrets: 29 },
      },
      expect: {
        "Findings": "KAFKA-LISTING-NOT-FILTERED-BY-ACL",
        "Authorization boundary": "listed but refused by name",
      },
    }),

    scenario("the unknown-name probe can be turned off", {
      broker: OPEN_PLATFORM,
      args: { "kafka.unknown-topic-probe": "false" },
      expect: {
        "Authorization boundary": "unknown-name probe was disabled",
      },
    }),

    scenario("a listener that answers nothing is unmeasured, not clean", {
      broker: { saslRequired: "silent" },
      expect: {
        "Risk Level": "UNKNOWN",
        "Findings": "KAFKA-METADATA-NOT-AVAILABLE",
      },
    }),

    scenario("verbose mode adds the transcript", {
      broker: OPEN_PLATFORM,
      args: { "kafka.verbose": "true" },
      expect: {
        "Probe transcript": "api_versions",
        "Access matrix": "Metadata (all topics)",
      },
    }),
  ],
};
