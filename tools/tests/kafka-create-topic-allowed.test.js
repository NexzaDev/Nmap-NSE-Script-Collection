"use strict";
/*
 * tools/tests/kafka-create-topic-allowed.test.js
 * ---------------------------------------------------------------------------
 * Integration scenarios for KAFKA-AMQP/kafka-create-topic-allowed.nse.
 *
 * The mock records every CreateTopics call with its validate_only flag, so the
 * verify hooks can assert the invariant the whole script is built around: a
 * scanner must not be able to create a topic on the cluster it audits. The
 * scenarios then exercise each answer a broker can give - accepted, refused by
 * the ACL, refused by validation, created despite the flag - and check that the
 * report turns each one into the right finding.
 */

const { createMockKafka } = require("../mocks/kafka");

const PORT = { number: 9092, protocol: "tcp", state: "open", service: "kafka" };

function scenario(name, options) {
  const mock = createMockKafka(options.broker || {});
  return Object.assign({
    name,
    script: "KAFKA-AMQP/kafka-create-topic-allowed.nse",
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
        `no request would have created a topic (violations: ${JSON.stringify(state.violations)})`);
      const creates = state.createTopicsCalls || [];
      // Either the request carried validate_only, or it named a topic the mock
      // already had - the two ways this script is allowed to ask the question.
      const existing = new Set((state.topicsAtStart || []));
      const unguarded = creates.filter((call) => call.validateOnly !== true
        && !call.topics.every((name) => existing.has(name)));
      say(unguarded.length === 0,
        `every CreateTopics call was guarded by validate_only or named an existing topic (${JSON.stringify(unguarded)})`);
      say(state.autoCreateRequests === 0, "no request asked the broker to auto-create a topic");
      if (options.verify) options.verify({ state, result, say });
      return checks;
    },
  }, options.scenario || {});
}

const BASE = {
  clusterId: "nse-create-cluster",
  topics: [{ name: "orders", partitions: 3, replicas: [1], isr: [1], internal: false }],
};

module.exports = {
  name: "kafka-create-topic-allowed",
  scenarios: [
    scenario("an open broker accepts a validate-only creation", {
      broker: BASE,
      expect: {
        "Risk Level": "HIGH",
        "Findings": "KAFKA-ANONYMOUS-TOPIC-CREATE",
        "Variant matrix": "authorized",
        "Safety ledger": "do not exist",
      },
      expectAll: [
        { contains: "validate_only" },
        { contains: "KAFKA-CREATE-GRANT-CONFIRMED" },
      ],
      verify: ({ state, result, say }) => {
        const creates = state.createTopicsCalls;
        say(creates.length >= 3, `the matrix sent several variants (${creates.length})`);
        say(creates.every((call) => call.validateOnly === true), "every creation carried validate_only");
        const text = JSON.stringify(result.output);
        say(text.includes("Partitions") && text.includes("Replication"),
          "the variant matrix is printed as a table");
      },
    }),

    scenario("an ACL-refused creation is reported as enforced", {
      broker: Object.assign({}, BASE, { allowCreateTopics: false }),
      expect: {
        "Findings": "KAFKA-TOPIC-CREATE-DENIED",
        "Variant matrix": "denied",
        "Risk Level": "INFO",
      },
      verify: ({ result, say }) => {
        const text = JSON.stringify(result.output);
        say(!text.includes("KAFKA-ANONYMOUS-TOPIC-CREATE"),
          "a refusal is never reported as an anonymous create");
        say(text.includes("TOPIC_AUTHORIZATION_FAILED"), "the refusal names the authorization error");
      },
    }),

    scenario("a validation failure proves the authorization check passed", {
      broker: Object.assign({}, BASE, { createValidationError: 38 }),
      expect: {
        "Findings": "KAFKA-TOPIC-CREATE-PERMITTED-PARAMETERS-REJECTED",
        "Risk Level": "HIGH",
      },
      expectAll: [{ contains: "INVALID_REPLICATION_FACTOR" }],
      verify: ({ result, say }) => {
        say(JSON.stringify(result.output).includes("authorization check ran before"),
          "the report explains why a validation error is evidence");
      },
    }),

    scenario("a topic created despite validate_only is an incident", {
      broker: Object.assign({}, BASE, { createIgnoresValidateOnly: true }),
      expect: {
        "Risk Level": "CRITICAL",
        "Findings": "KAFKA-PROBE-TOPIC-MATERIALISED",
      },
      verify: ({ result, say }) => {
        say(JSON.stringify(result.output).includes("despite validate_only"),
          "the incident is described as a violation of the flag");
      },
    }),

    scenario("a broker whose CreateTopics predates validate_only is never sent a creating request", {
      broker: Object.assign({}, BASE, {
        apiVersions: [
          { key: 3, min: 0, max: 12 }, { key: 18, min: 0, max: 3 },
          { key: 19, min: 0, max: 0 }, { key: 32, min: 0, max: 4 },
        ],
      }),
      expect: {
        "Findings": "KAFKA-VALIDATE-ONLY-UNAVAILABLE",
        "Target": "CreateTopics: v0 (validate_only unavailable)",
        "Safety ledger": "with an existing name (v0 path)",
      },
      expectAll: [{ contains: "KAFKA-TOPIC-CREATE-AUTHORIZED-EXISTING-NAME" }],
      verify: ({ state, result, say }) => {
        const creates = state.createTopicsCalls || [];
        const names = creates.flatMap((call) => call.topics);
        say(names.length > 0 && names.every((n) => n === "orders"),
          `the v0 path only named a topic that exists (${JSON.stringify(names)})`);
        say(JSON.stringify(result.output).includes("existing topic"),
          "the report explains the existing-topic path");
      },
    }),

    scenario("auto-creation is reported as the same permission without an ACL", {
      broker: Object.assign({}, BASE, {
        allowCreateTopics: false,
        configs: {
          1: [
            { name: "auto.create.topics.enable", value: "true", source: 5 },
            { name: "num.partitions", value: "1", source: 5 },
            { name: "default.replication.factor", value: "1", source: 5 },
            { name: "min.insync.replicas", value: "1", source: 5 },
          ],
        },
      }),
      expect: {
        "Findings": "KAFKA-AUTO-CREATE-ENABLED",
        "New topic defaults": "auto.create.topics.enable",
      },
      expectAll: [
        { contains: "KAFKA-WEAK-NEW-TOPIC-DEFAULTS" },
        { contains: "KAFKA-TOPIC-CREATE-DENIED" },
      ],
    }),

    scenario("the defaults read can be switched off", {
      broker: BASE,
      args: { "kafka.defaults": "false" },
      expect: {
        "New topic defaults": "kafka.defaults=false",
        "Findings": "KAFKA-CREATE-DEFAULTS-NOT-READ",
      },
      verify: ({ state, say }) => {
        const apis = state.requests.map((r) => r.apiName);
        say(!apis.includes("DESCRIBE_CONFIGS"), "no configuration read was sent");
      },
    }),

    scenario("the cleanup re-check can be switched off, and the report stops claiming anything", {
      broker: BASE,
      args: { "kafka.verify-cleanup": "false" },
      expect: {
        "Safety ledger": "cannot state that no topic was created",
      },
    }),

    scenario("a throttled creation records the quota that delayed it", {
      broker: Object.assign({}, BASE, { throttleMs: 2000 }),
      expect: {
        "Findings": "KAFKA-CREATE-QUOTA-OBSERVED",
        "Variant matrix": "throttled by",
      },
    }),

    scenario("a broker that does not advertise CreateTopics is reported as such", {
      broker: Object.assign({}, BASE, {
        apiVersions: [
          { key: 3, min: 0, max: 12 }, { key: 18, min: 0, max: 3 }, { key: 32, min: 0, max: 4 },
        ],
      }),
      expect: {
        "Findings": "KAFKA-CREATE-API-NOT-OFFERED",
        "Target": "CreateTopics: vnot offered",
      },
      verify: ({ state, say }) => {
        say((state.createTopicsCalls || []).length === 0, "no creation request was sent");
      },
    }),

    scenario("a listener that answers nothing is unmeasured, not clean", {
      broker: { saslRequired: "silent" },
      expect: {
        "Risk Level": "UNKNOWN",
        "Findings": "KAFKA-CREATE-PERMISSION-NOT-MEASURED",
      },
    }),

    scenario("the variant matrix can be widened and the configuration override can be skipped", {
      broker: BASE,
      args: { "kafka.partitions": "1,2,4", "kafka.replication": "2", "kafka.config-check": "false" },
      expect: {
        "Variant matrix": "authorized",
      },
      verify: ({ state, say }) => {
        const creates = state.createTopicsCalls;
        say(creates.length === 4, `three variants plus the confirmation were sent (${creates.length})`);
        const hasConfig = creates.some((call) => (call.topics || []).some((t) => t.includes("-config")));
        say(!hasConfig, "no configuration variant was sent");
        const text = JSON.stringify(creates);
        say(text.includes("-p4-r2"), "the widened partition list reached the broker");
      },
    }),

    scenario("verbose mode adds the transcript and the version table", {
      broker: BASE,
      args: { "kafka.verbose": "true" },
      expect: {
        "Probe transcript": "api_versions",
        "Version negotiation": "CreateTopics",
      },
    }),
  ],
};
