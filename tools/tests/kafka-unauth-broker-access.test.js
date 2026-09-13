"use strict";
/*
 * tools/tests/kafka-unauth-broker-access.test.js
 * ---------------------------------------------------------------------------
 * Integration scenarios for KAFKA-AMQP/kafka-unauth-broker-access.nse.
 *
 * Each scenario runs the script against tools/mocks/kafka.js, a second
 * implementation of the broker side of the wire protocol. Besides the report
 * lines the script is expected to produce, every scenario checks two safety
 * invariants on the mock's own state:
 *
 *   * no violation was recorded, i.e. CreateTopics always carried
 *     validate_only=true and DeleteTopics never named a real topic;
 *   * every DeleteTopics call used a name the script generated for the run.
 */

const { createMockKafka } = require("../mocks/kafka");

const PORT = { number: 9092, protocol: "tcp", state: "open", service: "kafka" };

function safetyChecks(state, say) {
  const violations = state.violations || [];
  say(violations.length === 0,
    `the probe never sent a state changing request (violations: ${JSON.stringify(violations)})`);
  const deletes = (state.deleteTopicsCalls || []).flatMap((call) => call.names || []);
  say(deletes.every((name) => String(name).startsWith("nmap-audit-nonexistent-")),
    `every DeleteTopics call used a generated name (${deletes.join(", ") || "none"})`);
  const creates = state.createTopicsCalls || [];
  say(creates.every((call) => call.validateOnly === true),
    "every CreateTopics call carried validate_only=true");
  say((state.protocolErrors || []).length === 0,
    `the mock decoded every request without a protocol error (${JSON.stringify(state.protocolErrors)})`);
}

function scenario(name, options) {
  const mock = createMockKafka(options.broker || {});
  return Object.assign({
    name,
    script: "KAFKA-AMQP/kafka-unauth-broker-access.nse",
    port: PORT,
    args: Object.assign({ "kafka.timeout": "2000" }, options.args || {}),
    mockFactory: () => mock,
    expect: options.expect,
    expectAll: options.expectAll,
    verify: (result, state) => {
      const checks = [];
      const say = (ok, message) => checks.push({ ok, message });
      safetyChecks(state, say);
      if (options.verify) options.verify({ state, result, say, checks });
      return checks;
    },
  }, options.scenario || {});
}

module.exports = {
  name: "kafka-unauth-broker-access",
  scenarios: [
    scenario("an open broker leaks cluster, group and configuration data", {
      broker: {
        clusterId: "nse-open-cluster",
        mechanisms: ["PLAIN", "SCRAM-SHA-256"],
        configs: {
          orders: [
            { name: "cleanup.policy", value: "delete", readOnly: true, sensitive: false, source: 5 },
            { name: "ssl.keystore.password", value: "s3cr3t-keystore", readOnly: false, sensitive: true, source: 4 },
          ],
        },
        offsets: { "checkout-workers": { orders: { 0: 120, 1: 80 } } },
        highWatermark: 250,
      },
      expect: {
        "Risk Level": "CRITICAL",
        "Access summary": "granted",
        "Findings": "KAFKA-ANONYMOUS-BROKER-ACCESS",
        "Topics": "__consumer_offsets",
        "Consumer groups": "checkout-workers",
        "Write access (create)": "validate_only",
        "Configuration": "sensitive",
      },
      expectAll: [
        { contains: "KAFKA-SASL-OFFERED-NOT-REQUIRED" },
        { contains: "KAFKA-CLEARTEXT-SASL-MECHANISM" },
        { contains: "KAFKA-CONFIGURATION-DISCLOSURE" },
        { contains: "KAFKA-INTERNAL-TOPICS-EXPOSED" },
      ],
      verify: ({ state, result, say }) => {
        say(state.requests.length >= 10, `the mock saw every probe family (${state.requests.length} requests)`);
        const apis = state.requests.map((r) => r.apiName);
        for (const name of ["ApiVersions", "Metadata", "ListGroups", "DescribeGroups", "DescribeConfigs",
          "CreateTopics", "DeleteTopics", "SaslHandshake"]) {
          say(apis.includes(name), `the probe spoke ${name}`);
        }
        say(JSON.stringify(result.output).includes("nse-open-cluster"),
          "the cluster id observed on the wire appears in the report");
        say(JSON.stringify(result.output).includes("s3cr3t-keystore"),
          "the sensitive configuration value the broker returned is quoted as evidence");
      },
    }),

    scenario("an ACL-enforced broker is reported as protected", {
      broker: { anonymousAllowed: false },
      expect: {
        "Access summary": "denied",
        "Risk Level": "HIGH",
        "Findings": "KAFKA-",
      },
      verify: ({ state, say }) => {
        say((state.createTopicsCalls || []).length === 1,
          "the create probe still ran, because a denial is a finding too");
      },
    }),

    scenario("a listener that drops unauthenticated frames yields no conclusions", {
      broker: { saslRequired: "silent" },
      expect: {
        "Access summary": "without a conclusion",
        "Risk Level": "UNKNOWN",
      },
      verify: ({ state, say }) => {
        say(state.dropped === 0, "the mock dropped frames rather than closing the socket");
      },
    }),

    scenario("topic creation denied for anonymous callers is reported as a protected control", {
      broker: { allowCreateTopics: false },
      expect: {
        "Write access (create)": "TOPIC_AUTHORIZATION_FAILED",
        "Findings": "KAFKA-TOPIC-CREATE-DENIED",
      },
    }),

    scenario("anonymous delete authorization is distinguished from a missing topic", {
      broker: { deleteBehaviour: "authorized" },
      expect: {
        "Write access (delete)": "UNKNOWN_TOPIC_OR_PARTITION",
        "Findings": "KAFKA-ANONYMOUS-TOPIC-DELETE",
      },
    }),

    scenario("payload sampling proves record exposure when it is enabled", {
      broker: {
        records: [{ key: "order-99", value: "{\"card\":\"4111-1111-1111-1111\"}" }],
        topics: [{ name: "orders", partitions: 1, replicas: [1], isr: [1], internal: false, leader: 1 }],
      },
      args: { "kafka.sample-records": "true" },
      expect: {
        "Payload sample": "record",
        "Risk Level": "CRITICAL",
      },
      expectAll: [{ contains: "KAFKA-RECORD-PAYLOAD-EXPOSURE" }],
      verify: ({ state, result, say }) => {
        const fetch = state.requests.find((r) => r.apiName === "Fetch");
        say(!!fetch, "the script sent a Fetch request for the bounded sample");
        say(JSON.stringify(result.output).includes("4111-1111-1111-1111"),
          "the sampled payload is quoted in the report");
      },
    }),

    scenario("a truncated response is reported, not parsed as a valid answer", {
      broker: { truncateBytes: 24 },
      expect: { "Access summary": "without a conclusion" },
      verify: ({ state, say }) => {
        say(state.requests.length >= 1, "the request reached the mock before the truncation");
      },
    }),

    scenario("an old broker that lacks the admin APIs is not reported as open", {
      broker: {
        apiVersions: [{ key: 18, min: 0, max: 2 }, { key: 3, min: 0, max: 2 }, { key: 16, min: 0, max: 0 }],
      },
      expect: { "Kafka API access matrix": "unsupported-version" },
      verify: ({ state, say }) => {
        const apis = state.requests.map((r) => r.apiName);
        say(!apis.includes("DescribeCluster"),
          "the probe did not send an API the broker never advertised");
      },
    }),
  ],
};
