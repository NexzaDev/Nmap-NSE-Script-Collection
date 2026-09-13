"use strict";
/*
 * tools/tests/kafka-delete-topic-allowed.test.js
 * ---------------------------------------------------------------------------
 * Integration scenarios for KAFKA-AMQP/kafka-delete-topic-allowed.nse.
 *
 * DeleteTopics has no dry run, so the property that matters is the negative
 * one: the script must never name a topic that exists, and it must never ask
 * DeleteRecords for an offset above zero. Both are enforced here from the
 * mock's own record of every request it decoded, and a scenario that lets an
 * external actor change the topic list proves that the before/after comparison
 * reports a change instead of hiding it.
 */

const { createMockKafka } = require("../mocks/kafka");

const PORT = { number: 9092, protocol: "tcp", state: "open", service: "kafka" };

function scenario(name, options) {
  const mock = createMockKafka(options.broker || {});
  return Object.assign({
    name,
    script: "KAFKA-AMQP/kafka-delete-topic-allowed.nse",
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
        `no request could have deleted anything (violations: ${JSON.stringify(state.violations)})`);
      const existing = new Set(state.topicsAtStart || []);
      const dangerous = (state.deleteTopicsCalls || [])
        .flatMap((call) => call.names || [])
        .filter((topicName) => existing.has(topicName));
      say(dangerous.length === 0,
        `no DeleteTopics request named a topic that exists (${JSON.stringify(dangerous)})`);
      const offsets = (state.deleteRecordsCalls || []).map((call) => call.offset);
      say(offsets.every((offset) => offset === 0),
        `every DeleteRecords request asked for offset 0 (${JSON.stringify(offsets)})`);
      if (options.verify) options.verify({ state, result, say });
      return checks;
    },
  }, options.scenario || {});
}

const BASE = {
  clusterId: "nse-delete-cluster",
  topics: [
    { name: "orders", partitions: 3, replicas: [1], isr: [1], internal: false },
    { name: "shipments", partitions: 1, replicas: [1], isr: [1], internal: false },
    { name: "__consumer_offsets", partitions: 1, replicas: [1], isr: [1], internal: true },
  ],
};

module.exports = {
  name: "kafka-delete-topic-allowed",
  scenarios: [
    scenario("an open broker permits deletion on both paths and record truncation", {
      broker: BASE,
      expect: {
        "Risk Level": "HIGH",
        "Findings": "KAFKA-ANONYMOUS-TOPIC-DELETE",
        "Permission matrix": "DeleteTopics by name",
        "Topic inventory": "names identical to the first read: yes",
      },
      expectAll: [
        { contains: "KAFKA-TOPIC-DELETE-BY-ID-PERMITTED" },
        { contains: "KAFKA-DELETE-RECORDS-PERMITTED" },
        { contains: "KAFKA-INTERNAL-TOPIC-RECORDS-IN-SCOPE" },
        { contains: "KAFKA-DELETE-RECORDS-NOOP-MEASUREMENT" },
        { contains: "UNKNOWN_TOPIC_ID" },
      ],
      verify: ({ state, result, say }) => {
        const apis = state.requests.map((r) => r.apiName);
        for (const api of ["ApiVersions", "Metadata", "DeleteTopics", "DeleteRecords"]) {
          say(apis.includes(api), `the probe spoke ${api}`);
        }
        const text = JSON.stringify(result.output);
        say(text.includes("nmap-delete-audit-"), "the generated names are printed");
        say(text.includes("authorized-name-absent"),
          "the existence error is classified as proof that authorization passed");
        const idRequests = state.deleteTopicsCalls.filter((call) => (call.ids || [])
          .some((id) => !/^0+$/.test(id)));
        say(idRequests.length === 1,
          `the topic-id form was sent exactly once with a non-zero id (${JSON.stringify(idRequests)})`);
      },
    }),

    scenario("a refusal on every path is reported as enforcement, not exposure", {
      broker: Object.assign({}, BASE, { deleteBehaviour: "denied", deleteRecordsDenied: true }),
      expect: {
        "Risk Level": "INFO",
        "Findings": "KAFKA-TOPIC-DELETE-DENIED",
        "Permission matrix": "the ACL refused every request",
      },
      expectAll: [
        { contains: "KAFKA-TOPIC-DELETE-BY-ID-DENIED" },
        { contains: "KAFKA-DELETE-RECORDS-DENIED" },
      ],
      verify: ({ result, say }) => {
        const text = JSON.stringify(result.output);
        say(!text.includes("KAFKA-ANONYMOUS-TOPIC-DELETE"),
          "a refusal is never reported as an anonymous delete");
      },
    }),

    scenario("an external change to the topic list is reported as critical", {
      broker: Object.assign({}, BASE, { changeTopicsAfterRequests: 4, changeTopicName: "ghost-topic" }),
      expect: {
        "Risk Level": "CRITICAL",
        "Findings": "KAFKA-DELETE-INVENTORY-CHANGED",
        "Safety ledger": "ghost-topic",
      },
      verify: ({ state, result, say }) => {
        say(state.externalTopicChanges === 1, "the mock changed the cluster once");
        const text = JSON.stringify(result.output);
        say(text.includes("the cluster changed under it") || text.includes("cluster changed"),
          "the finding does not blame the script for a change it did not make");
      },
    }),

    scenario("a broker that does not advertise DeleteTopics is reported as such", {
      broker: Object.assign({}, BASE, {
        apiVersions: [
          { key: 3, min: 0, max: 12 }, { key: 18, min: 0, max: 3 },
          { key: 21, min: 0, max: 2 }, { key: 32, min: 0, max: 4 },
        ],
      }),
      expect: {
        "Findings": "KAFKA-DELETE-API-NOT-OFFERED",
        "Target": "DeleteTopics: not offered",
      },
      verify: ({ state, say }) => {
        say((state.deleteTopicsCalls || []).length === 0, "no deletion request was sent");
      },
    }),

    scenario("a broker without DeleteRecords leaves that path unmeasured", {
      broker: Object.assign({}, BASE, {
        apiVersions: [
          { key: 3, min: 0, max: 12 }, { key: 18, min: 0, max: 3 },
          { key: 20, min: 0, max: 6 }, { key: 32, min: 0, max: 4 },
        ],
      }),
      expect: {
        "Findings": "KAFKA-DELETE-RECORDS-NOT-PROBED",
        "Target": "DeleteRecords: not offered",
      },
      verify: ({ state, say }) => {
        say((state.deleteRecordsCalls || []).length === 0, "no record deletion request was sent");
      },
    }),

    scenario("the topic-id form can be left alone", {
      broker: BASE,
      args: { "kafka.topic-id-probe": "false" },
      expect: {
        "DeleteTopics by topic id": "kafka.topic-id-probe=false",
      },
      verify: ({ state, say }) => {
        const withIds = state.deleteTopicsCalls.filter((call) => (call.ids || [])
          .some((id) => !/^0+$/.test(id)));
        say(withIds.length === 0, `no request carried a non-zero topic id (${JSON.stringify(withIds)})`);
      },
    }),

    scenario("the record probe can be left alone", {
      broker: BASE,
      args: { "kafka.records-probe": "false" },
      expect: {
        "DeleteRecords at offset 0": "kafka.records-probe=false",
      },
      verify: ({ state, say }) => {
        say((state.deleteRecordsCalls || []).length === 0, "no DeleteRecords request was sent");
      },
    }),

    scenario("the record probe can be pointed at a bounded number of topics", {
      broker: BASE,
      args: { "kafka.records-topics": "1" },
      expect: {
        "DeleteRecords at offset 0": "Summary:",
      },
      verify: ({ state, say }) => {
        const topics = new Set((state.deleteRecordsCalls || []).map((call) => call.name));
        say(topics.size === 1, `exactly one topic was probed (${JSON.stringify([...topics])})`);
      },
    }),

    scenario("a broker that redirects the request to the controller is reported as broker-dependent", {
      broker: Object.assign({}, BASE, { deleteBehaviour: "invalid" }),
      expect: {
        "Findings": "KAFKA-DELETE-BROKER-DEPENDENT-ANSWER",
        "DeleteTopics by name": "INVALID_REQUEST",
      },
    }),

    scenario("a quota on the deletion path is reported", {
      broker: Object.assign({}, BASE, { throttleMs: 1500 }),
      expect: {
        "Findings": "KAFKA-DELETE-QUOTA-OBSERVED",
      },
    }),

    scenario("a listener that answers nothing is unmeasured, not clean", {
      broker: { saslRequired: "silent" },
      expect: {
        "Risk Level": "UNKNOWN",
        "Findings": "KAFKA-DELETE-PERMISSION-NOT-MEASURED",
      },
      verify: ({ state, say }) => {
        say((state.deleteTopicsCalls || []).length === 0, "no deletion request was sent");
      },
    }),

    scenario("verbose mode adds the transcript and the reference tables", {
      broker: BASE,
      args: { "kafka.verbose": "true" },
      expect: {
        "Probe transcript": "api_versions",
        "Deletion path reference": "DeleteTopics by name",
        "What a deletion does": "controller",
      },
    }),
  ],
};
