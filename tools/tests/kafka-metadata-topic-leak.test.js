"use strict";
/*
 * tools/tests/kafka-metadata-topic-leak.test.js
 * ---------------------------------------------------------------------------
 * Integration scenarios for KAFKA-AMQP/kafka-metadata-topic-leak.nse.
 *
 * The script is read-only by construction, so the properties the mock asserts
 * are: no Metadata request ever asked the broker to create what it named, every
 * random name the script invented came from the script itself, and the two
 * inventory reads bracket the probes.
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
      say((state.autoCreateRequests || 0) === 0,
        `no Metadata request set allow_auto_topic_creation (${state.autoCreateRequests})`);
      const apis = state.requests.map((r) => r.apiName);
      say(apis.filter((api) => api === "Metadata").length >= 2,
        `the inventory was read at least twice (${apis.filter((a) => a === "Metadata").length})`);
      say(apis.includes("ApiVersions"), "the probe negotiated the API surface first");
      if (options.verify) options.verify({ state, result, say });
      return checks;
    },
  }, options.scenario || {});
}

const TOPICS = [
  { name: "orders", partitions: 3, replicas: [1, 2, 3], isr: [1, 2, 3], leader: 1 },
  { name: "payments-eu", partitions: 2, replicas: [1, 2], isr: [1], offline: [2], leader: 1 },
  { name: "user-profiles", partitions: 1, replicas: [1], isr: [1], leader: 2 },
  { name: "__consumer_offsets", partitions: 2, replicas: [1, 2, 3], isr: [1, 2, 3], internal: true, leader: 1 },
  { name: "__transaction_state", partitions: 1, replicas: [1, 2, 3], isr: [1, 2, 3], internal: true, leader: 3 },
  { name: "connect-configs", partitions: 1, replicas: [1, 2], isr: [1, 2], internal: true, leader: 1 },
  { name: "audit-trail", partitions: 4, replicas: [1, 2], isr: [1, 2], leader: 2 },
];

const CLUSTER = {
  clusterId: "prod-eu-central-1",
  brokers: [
    { nodeId: 1, host: "kafka-1.internal.example", port: 9092, rack: "az-a" },
    { nodeId: 2, host: "kafka-2.internal.example", port: 9092, rack: "az-b" },
    { nodeId: 3, host: "kafka-3.internal.example", port: 9092, rack: "az-c" },
  ],
  topics: TOPICS,
};

module.exports = {
  name: "kafka-metadata-topic-leak",
  scenarios: [
    scenario("an open broker publishes the whole inventory, internal subsystems and broker settings", {
      broker: Object.assign({}, CLUSTER, {
        allowEveryoneIfNoAclFound: true,
        autoCreateEnabled: true,
        offsetsReplication: 1,
        uncleanElection: true,
        retentionMs: 7776000000,
      }),
      args: { "kafka.unknown-probe": "true" },
      expect: {
        "Risk Level": "CRITICAL",
        "Cluster": "prod-eu-central-1",
        "Topic inventory": "payments-eu",
        "Internal topics": "__transaction_state",
        "Availability posture": "under-replicated",
        "Name exposure": "user-profiles",
        "Configuration exposure": "ssl.keystore.password",
        "Listing versus named requests": "Per-name requests:",
      },
      expectAll: [
        { contains: "KAFKA-METADATA-TOPIC-INVENTORY" },
        { contains: "KAFKA-METADATA-INTERNAL-SUBSYSTEMS" },
        { contains: "KAFKA-METADATA-SENSITIVE-TOPIC-NAMES" },
        { contains: "KAFKA-METADATA-TOPOLOGY-DISCLOSURE" },
        { contains: "KAFKA-METADATA-AUTHORIZED-OPERATIONS" },
        { contains: "KAFKA-METADATA-HEALTH-DISCLOSURE" },
        { contains: "KAFKA-METADATA-SENSITIVE-CONFIG-DISCLOSED" },
        { contains: "KAFKA-METADATA-AUTHORIZATION-BYPASS-SETTING" },
        { contains: "KAFKA-METADATA-AUTO-CREATE-ENABLED" },
        { contains: "KAFKA-METADATA-UNCLEAN-ELECTION-ENABLED" },
        { contains: "KAFKA-METADATA-EXISTENCE-ORACLE" },
        { contains: "KAFKA-METADATA-LONG-RETENTION" },
        { contains: "KAFKA-METADATA-TOPIC-CONFIG-EXPOSURE" },
        { contains: "KAFKA-METADATA-GROUP-NAMES-DISCLOSED" },
        { contains: "Kafka Connect" },
        { contains: "consumer groups are in use" },
      ],
      verify: ({ state, result, say }) => {
        const text = JSON.stringify(result.output);
        say(text.includes("authorizer.class.name"), "the authorizer setting is quoted from the response");
        const published = (result.vulns || []).map((entry) => entry.id);
        for (const id of ["KAFKA-METADATA-TOPIC-INVENTORY", "KAFKA-METADATA-SENSITIVE-CONFIG-DISCLOSED"]) {
          say(published.includes(id), `the finding ${id} was published to Nmap's vulnerability table`);
        }
        const names = state.requests.filter((r) => r.apiName === "Metadata").map((r) => r.version);
        say(names.every((v) => v >= 9), `Metadata was asked with a flexible schema (${JSON.stringify(names)})`);
      },
    }),

    scenario("a broker that requires authentication returns no inventory", {
      broker: Object.assign({}, CLUSTER, { anonymousAllowed: false }),
      expect: {
        "Risk Level": "NONE",
        "Findings": "KAFKA-METADATA-NO-FINDING",
        "Topic inventory": "0 topic",
      },
      verify: ({ result, say }) => {
        const text = JSON.stringify(result.output);
        say(!text.includes("KAFKA-METADATA-TOPIC-INVENTORY"),
          "an empty answer is never reported as a full inventory");
      },
    }),

    scenario("a filtered listing hides topics that a direct request still describes", {
      broker: Object.assign({}, CLUSTER, {
        hiddenTopics: ["payments-eu", "audit-trail"],
      }),
      args: { "kafka.names": "payments-eu,audit-trail" },
      expect: {
        // The listing itself is still complete enough to be critical on this
        // cluster; the hidden-name path is asserted through the finding below.
        "Risk Level": "CRITICAL",
        "Listing versus named requests": "Hidden from the listing but described by name",
      },
      expectAll: [
        { contains: "KAFKA-METADATA-HIDDEN-TOPIC-ORACLE" },
      ],
      verify: ({ state, say }) => {
        const wildcard = state.requests.filter((r) => r.apiName === "Metadata" && r.topicCount === null);
        say(wildcard.length >= 2, `the wildcard listing was read twice (${wildcard.length})`);
      },
    }),

    scenario("a broker that creates what a metadata request names is caught by the before and after read", {
      broker: Object.assign({}, CLUSTER, { autoCreateIgnoringFlag: true }),
      args: { "kafka.unknown-probe": "true" },
      expect: {
        "Risk Level": "CRITICAL",
        "Findings": "KAFKA-METADATA-AUTO-CREATED-TOPIC",
        "Safety ledger": "FAILED",
      },
      verify: ({ state, say }) => {
        say((state.autoCreatedTopics || []).length >= 1,
          `the mock materialised the name it was asked about (${JSON.stringify(state.autoCreatedTopics)})`);
      },
    }),

    scenario("configuration can be left alone", {
      broker: CLUSTER,
      args: { "kafka.max-configs": "0" },
      expect: {
        "Configuration exposure": "Broker settings that matter",
        "Topic inventory": "orders",
      },
      verify: ({ state, say }) => {
        const configCalls = state.requests.filter((r) => r.apiName === "DescribeConfigs");
        say(configCalls.length === 1,
          `only the broker configs were requested (${configCalls.length} DescribeConfigs call)`);
      },
    }),

    scenario("the per-name probe can be left alone", {
      broker: CLUSTER,
      args: { "kafka.named-probe": "false" },
      expect: {
        "Listing versus named requests": "the per-name probe is disabled",
      },
      verify: ({ state, say }) => {
        const byName = state.requests.filter((r) => r.apiName === "Metadata" && r.topicCount !== null);
        say(byName.length === 0, `no Metadata request named a topic (${JSON.stringify(byName.length)})`);
      },
    }),

    scenario("a listener that never answers is unmeasured rather than clean", {
      broker: { saslRequired: "silent" },
      expect: {
        "Risk Level": "UNKNOWN",
        "Findings": "KAFKA-METADATA-NOT-MEASURED",
      },
    }),

    scenario("an old broker without DescribeConfigs or DescribeCluster still yields the inventory", {
      broker: Object.assign({}, CLUSTER, {
        apiVersions: [
          { key: 3, min: 0, max: 8 }, { key: 16, min: 0, max: 4 }, { key: 17, min: 0, max: 1 },
          { key: 18, min: 0, max: 3 },
        ],
      }),
      expect: {
        "Cluster": "DescribeCluster: the broker does not advertise DescribeCluster",
        "Configuration exposure": "the broker does not advertise DescribeConfigs",
        "Topic inventory": "orders",
      },
      expectAll: [
        { contains: "KAFKA-METADATA-TOPIC-INVENTORY" },
      ],
    }),

    scenario("a KRaft deployment is identified from DescribeCluster and its internal topics", {
      broker: {
        clusterId: "MkU3OEVBNTcwNTJENDM2Qk",
        controllerId: 3001,
        brokers: [
          { nodeId: 1, host: "broker-1.kraft.internal", port: 9092, rack: "az-a" },
          { nodeId: 3001, host: "controller-1.kraft.internal", port: 9093, rack: "az-a" },
        ],
        topics: [
          { name: "orders", partitions: 6, replicas: [1], isr: [1], leader: 1 },
          { name: "__cluster_metadata", partitions: 1, replicas: [3001], isr: [3001], internal: true, leader: 3001 },
          { name: "_schemas", partitions: 4, replicas: [1], isr: [1], internal: true, leader: 1 },
          { name: "__strimzi-topic-operator-kstreams-topic-store-changelog", partitions: 1,
            replicas: [1], isr: [1], internal: true, leader: 1 },
        ],
      },
      expect: {
        "Cluster": "DescribeCluster v1",
        "Internal topics": "the KRaft controller",
        "Topic inventory": "__strimzi",
        "Risk Level": "CRITICAL",
      },
      expectAll: [
        { contains: "Confluent Schema Registry" },
        { contains: "Strimzi topic operator" },
        { contains: "the cluster runs without ZooKeeper" },
      ],
    }),

    scenario("a listing that is refused per topic is reported as a filtered listing", {
      broker: {
        topics: [{ name: "orders", partitions: 3, replicas: [1], isr: [1], topicError: 29 }],
        topicErrors: {},
      },
      expect: {
        // The listing carried no usable entry, so it is reported as a filtered
        // listing rather than as a full inventory; the broker still answered
        // DescribeConfigs, which is what keeps the risk high on this one.
        "Findings": "KAFKA-METADATA-LISTING-REFUSED",
      },
      verify: ({ result, say }) => {
        const text = JSON.stringify(result.output);
        say(!text.includes("KAFKA-METADATA-TOPIC-INVENTORY"),
          "a listing without a usable entry is not reported as a full inventory");
      },
    }),

    scenario("partitions without an in-sync set or with offline replicas are reported", {
      broker: {
        topics: [
          { name: "telemetry", partitions: 2, replicas: [1, 2, 3], isr: [], offline: [3], leader: 1 },
          { name: "cold-storage", partitions: 1, replicas: [1], isr: [1], leader: -1 },
        ],
      },
      expect: {
        "Availability posture": "with an empty in-sync set",
        "Topic inventory": "telemetry",
      },
      expectAll: [
        { contains: "KAFKA-METADATA-HEALTH-DISCLOSURE" },
        { contains: "KAFKA-METADATA-SINGLE-REPLICA-PARTITIONS" },
      ],
    }),

    scenario("verbose mode adds the stage transcript", {
      broker: CLUSTER,
      args: { "kafka.verbose": "true" },
      expect: {
        "Probe transcript": "metadata_all",
        "Target": "Stages:",
      },
    }),
  ],
};
