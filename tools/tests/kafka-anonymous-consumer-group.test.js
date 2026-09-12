"use strict";
/*
 * tools/tests/kafka-anonymous-consumer-group.test.js
 * ---------------------------------------------------------------------------
 * Integration scenarios for KAFKA-AMQP/kafka-anonymous-consumer-group.nse.
 *
 * The mock broker answers the group plane with realistic ConsumerProtocol
 * payloads, so the assertions can check the decoded subscription, the decoded
 * assignment and the lag arithmetic rather than just the presence of a line.
 * The verify hooks enforce the two invariants that matter for a CRITICAL
 * script: nothing it sends can change state, and the mock decoded every frame.
 */

const { createMockKafka } = require("../mocks/kafka");

const PORT = { number: 9092, protocol: "tcp", state: "open", service: "kafka" };

function scenario(name, options) {
  const mock = createMockKafka(options.broker || {});
  return Object.assign({
    name,
    script: "KAFKA-AMQP/kafka-anonymous-consumer-group.nse",
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
      const forbidden = ["JoinGroup", "OffsetCommit", "SyncGroup", "Heartbeat", "Produce", "Fetch"];
      const sent = state.requests.map((r) => r.apiName).filter((n) => forbidden.includes(n));
      say(sent.length === 0, `the probe sent no consuming or committing API (${sent.join(", ") || "none"})`);
      if (options.verify) options.verify({ state, result, say });
      return checks;
    },
  }, options.scenario || {});
}

const GROUP_MEMBER = {
  id: "consumer-1-abc",
  clientId: "checkout-app",
  clientHost: "/10.0.0.7",
  subscription: { version: 1, topics: ["orders"], userData: "nmap-mock-1" },
  assignment: { version: 1, topics: [{ name: "orders", partitions: [0, 1] }] },
};

module.exports = {
  name: "kafka-anonymous-consumer-group",
  scenarios: [
    scenario("an open broker publishes groups, member identity, assignments and lag", {
      broker: {
        clusterId: "nse-groups",
        topics: [{ name: "orders", partitions: 4, replicas: [1], isr: [1], internal: false, leader: 1 }],
        groups: [{ group: "checkout-workers", state: "Stable", protocolType: "consumer", members: [GROUP_MEMBER] }],
        offsets: { "checkout-workers": { orders: { 0: 120, 1: 80 } } },
        highWatermark: 250,
      },
      expect: {
        "Risk Level": "CRITICAL",
        "Findings": "KAFKA-ANONYMOUS-CONSUMER-GROUP-ACCESS",
        "Members and identity": "checkout-app",
        "Subscriptions and ownership": "consumer-1-abc owns [0, 1]",
        "Committed offsets and lag": "130",
      },
      expectAll: [
        { contains: "KAFKA-MEMBER-IDENTITY-DISCLOSURE" },
        { contains: "KAFKA-CONSUMER-ASSIGNMENT-DISCLOSURE" },
        { contains: "KAFKA-COMMITTED-OFFSET-DISCLOSURE" },
        { contains: "KAFKA-CONSUMER-LAG-EXPOSURE" },
      ],
      verify: ({ state, result, say }) => {
        const apis = state.requests.map((r) => r.apiName);
        for (const name of ["ListGroups", "DescribeGroups", "FindCoordinator", "OffsetFetch", "ListOffsets"]) {
          say(apis.includes(name), `the probe spoke ${name}`);
        }
        const text = JSON.stringify(result.output);
        say(text.includes("subscription v1: topics orders"), "the decoded subscription is quoted");
        say(text.includes("owns: orders[0, 1]"), "the decoded assignment is quoted");
        say(text.includes("170"), "the lag of the second partition is computed");
      },
    }),

    scenario("an ACL-protected group plane is reported as denied, not as a leak", {
      broker: { anonymousAllowed: false },
      expect: {
        "Risk Level": "LOW",
        "Findings": "KAFKA-GROUP-ENUMERATION-DENIED",
        "Access matrix": "denied",
      },
      verify: ({ result, say }) => {
        const text = JSON.stringify(result.output);
        say(!text.includes("KAFKA-ANONYMOUS-CONSUMER-GROUP-ACCESS"),
          "a refusal is never reported as anonymous access");
      },
    }),

    scenario("an empty group plane is reported as an empty answer", {
      broker: { groups: [] },
      expect: {
        "Findings": "KAFKA-GROUP-PLANE-EMPTY",
        "Group inventory": "listed no consumer group",
      },
    }),

    scenario("a group without members is described with its state", {
      broker: {
        groups: [{ group: "abandoned-workers", state: "Empty", protocolType: "consumer", members: [] }],
        offsets: { "abandoned-workers": { orders: { 0: 500 } } },
        topics: [{ name: "orders", partitions: 1, replicas: [1], isr: [1], internal: false, leader: 1 }],
      },
      expect: {
        "Group inventory": "consumer/Empty",
        "Members and identity": "No member was described",
      },
      expectAll: [{ contains: "offsets are kept" }],
    }),

    scenario("two members claiming one partition is reported as an anomaly", {
      broker: {
        topics: [{ name: "orders", partitions: 2, replicas: [1], isr: [1], internal: false, leader: 1 }],
        groups: [{
          group: "checkout-workers",
          state: "CompletingRebalance",
          protocolType: "consumer",
          members: [
            { id: "consumer-1", clientId: "app", clientHost: "/10.0.0.7",
              assignment: { version: 1, topics: [{ name: "orders", partitions: [0] }] } },
            { id: "consumer-2", clientId: "app", clientHost: "/10.0.0.8",
              assignment: { version: 1, topics: [{ name: "orders", partitions: [0] }] } },
          ],
        }],
      },
      expect: {
        "Findings": "KAFKA-PARTITION-DOUBLE-OWNERSHIP",
        "Subscriptions and ownership": "claimed by two members",
      },
      expectAll: [{ contains: "KAFKA-REBALANCE-OBSERVED" }],
    }),

    scenario("a payload the consumer protocol cannot explain is reported as undecodable", {
      broker: {
        topics: [{ name: "orders", partitions: 1, replicas: [1], isr: [1], internal: false, leader: 1 }],
        groups: [{
          group: "legacy-bridge",
          state: "Stable",
          protocolType: "consumer",
          members: [{
            id: "bridge-1", clientId: "bridge", clientHost: "/10.0.0.9",
            rawMetadata: "0000ff", rawAssignment: "0001ff",
          }],
        }],
      },
      expect: {
        "Members and identity": "subscription not decoded",
        "Access matrix": "granted",
      },
      verify: ({ result, say }) => {
        say(JSON.stringify(result.output).includes("undecodable 1"),
          "the undecodable payload is counted instead of guessed at");
      },
    }),

    scenario("lag resolution can be turned off", {
      broker: {
        topics: [{ name: "orders", partitions: 2, replicas: [1], isr: [1], internal: false, leader: 1 }],
        groups: [{ group: "checkout-workers", state: "Stable", protocolType: "consumer", members: [GROUP_MEMBER] }],
        offsets: { "checkout-workers": { orders: { 0: 10 } } },
      },
      args: { "kafka.lag": "false" },
      expect: {
        "Committed offsets and lag": "kafka.lag=false",
      },
      verify: ({ state, say }) => {
        const apis = state.requests.map((r) => r.apiName);
        say(!apis.includes("ListOffsets"), "no watermark request was sent");
      },
    }),

    scenario("a listener that answers nothing is unmeasured, not clean", {
      broker: { saslRequired: "silent" },
      expect: {
        "Risk Level": "UNKNOWN",
        "Findings": "KAFKA-GROUP-PLANE-UNREACHABLE",
      },
      verify: ({ state, say }) => {
        say(state.dropped === 0, "the mock dropped frames instead of closing the socket");
      },
    }),

    scenario("verbose mode adds the transcript", {
      broker: {
        topics: [{ name: "orders", partitions: 1, replicas: [1], isr: [1], internal: false, leader: 1 }],
        groups: [{ group: "checkout-workers", state: "Stable", protocolType: "consumer", members: [GROUP_MEMBER] }],
      },
      args: { "kafka.verbose": "true" },
      expect: {
        "Probe transcript": "api_versions",
        "Access matrix": "ListGroups",
      },
    }),
  ],
};
