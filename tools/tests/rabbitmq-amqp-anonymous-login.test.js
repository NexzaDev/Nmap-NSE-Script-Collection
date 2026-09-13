"use strict";
/*
 * tools/tests/rabbitmq-amqp-anonymous-login.test.js
 * ---------------------------------------------------------------------------
 * Integration scenarios for KAFKA-AMQP/rabbitmq-amqp-anonymous-login.nse.
 *
 * Each scenario is a different broker configuration seen from the wire: the
 * anonymous plugin enabled, a broker that refuses every credential-free login,
 * an EXTERNAL listener that trusts the transport, the built-in guest account
 * with a blank password, a backend that accepts a malformed SASL response, a
 * TLS listener, a broker that goes silent after the first login, and a port that
 * drops the protocol header. The verify hooks check the audit's manners: no
 * queue may be created, nothing may be declared non-passively, and the audit may
 * only touch the sentinel name it generated.
 */

const { createMockRabbitMQ } = require("../mocks/rabbitmq");

const AMQP_PORT = { number: 5672, protocol: "tcp", state: "open", service: "amqp" };
const AMQPS_PORT = { number: 5671, protocol: "tcp", state: "open", service: "amqps" };

function scenario(name, options) {
  const mock = createMockRabbitMQ(options.broker || {});
  return Object.assign({
    name,
    script: "KAFKA-AMQP/rabbitmq-amqp-anonymous-login.nse",
    port: options.port || AMQP_PORT,
    args: Object.assign({ "rabbitmq.timeout": "1200", "rabbitmq.confirm": "2" }, options.args || {}),
    mockFactory: () => mock,
    expect: options.expect,
    expectAll: options.expectAll,
    verify: (result, state) => {
      const checks = [];
      const say = (ok, message) => checks.push({ ok, message });
      say((state.violations || []).length === 0,
        `nothing the audit sent could change a resource (violations: ${JSON.stringify(state.violations)})`);
      const created = (state.declaredQueues || []).filter((entry) => entry.passive === false);
      say(created.length === 0,
        `every declare was passive, so no queue was created (${JSON.stringify(created)})`);
      if (options.verify) options.verify({ state, result, say });
      return checks;
    },
  }, options.scenario || {});
}

module.exports = {
  name: "rabbitmq-amqp-anonymous-login",
  scenarios: [
    scenario("the anonymous plugin is enabled and a confirmed session reads the vhost", {
      broker: { mechanisms: ["ANONYMOUS", "PLAIN", "AMQPLAIN"], acceptAnonymous: true },
      expect: {
        "Target": "Exposure: CRITICAL",
        "Confirmed session": "Mechanism: ANONYMOUS",
        "Authorization evidence": "404",
        "Risk Level": "CRITICAL",
      },
      expectAll: [
        { contains: "RABBITMQ-ANON-LOGIN-ACCEPTED" },
        { contains: "RABBITMQ-ANON-PLUGIN-ENABLED" },
        { contains: "RABBITMQ-ANON-PLAINTEXT" },
        { contains: "an unauthenticated session reached a vhost" },
        { contains: "confirmed on 2 of 2 independent connections" },
        { contains: "Account inferred" },
      ],
      verify: ({ state, say }) => {
        say(state.openedVhosts.includes("/"), "the unauthenticated session opened the default vhost");
        say((state.declaredQueues || []).length >= 1,
          "the audit asked the sentinel question at least once");
        const sentinels = (state.declaredQueues || []).map((entry) => entry.queue);
        say(sentinels.every((name) => name.startsWith("nse-probe-")),
          `only generated sentinel names were declared (${sentinels.join(", ")})`);
        say((state.qosRequests || 0) >= 1, "the liveness question was asked on the channel");
        const anonymous = (state.amqpAttempts || []).filter((a) => a.mechanism === "ANONYMOUS");
        say(anonymous.length >= 3,
          `the matrix and its confirmation both used ANONYMOUS (${anonymous.length} start-ok frames)`);
      },
    }),

    scenario("a broker that refuses every credential-free login is reported as healthy", {
      expect: {
        "Login attempt matrix": "accepted 0",
        "Risk Level": "INFO",
      },
      expectAll: [
        { contains: "RABBITMQ-ANON-REFUSED" },
        { contains: "RABBITMQ-ANON-SHAPES-REFUSED" },
        { contains: "ACCESS_REFUSED" },
      ],
      verify: ({ state, result, say }) => {
        const text = JSON.stringify(result.output);
        say(!text.includes("RABBITMQ-ANON-LOGIN-ACCEPTED"),
          "no accepted-login finding is produced when every attempt was refused");
        const levels = (result.output["Findings"] || []).join("\n");
        say(!levels.includes("[CRITICAL]") && !levels.includes("[HIGH]"),
          "a refusing broker produces no CRITICAL or HIGH finding");
        say((state.amqpAttempts || []).length >= 3,
          `every attempt that could carry a credential reached the broker (${(state.amqpAttempts || []).length})`);
        const offered = (state.amqpAttempts || []).map((a) => a.mechanism);
        say(new Set(offered).size >= 2, `both offered mechanisms were exercised (${offered.join(", ")})`);
      },
    }),

    scenario("an EXTERNAL listener that trusts the transport is graded HIGH", {
      broker: { mechanisms: ["EXTERNAL"], acceptExternal: true },
      expect: {
        "Target": "Exposure: HIGH",
        "Risk Level": "HIGH",
      },
      expectAll: [
        { contains: "RABBITMQ-ANON-LOGIN-ACCEPTED" },
        { contains: "RABBITMQ-ANON-EXTERNAL-TRUSTED" },
        { contains: "the transport" },
      ],
      verify: ({ state, say }) => {
        const external = (state.amqpAttempts || []).filter((a) => a.mechanism === "EXTERNAL");
        say(external.length >= 2, `EXTERNAL was used for the attempt and the confirmation (${external.length})`);
        say(external.every((a) => a.form === "EXTERNAL"),
          "the responses were decoded as EXTERNAL identities, not as PLAIN triples");
      },
    }),

    scenario("guest with a blank password from a remote host is quoted as its own finding", {
      broker: { credentials: { guest: "" }, guestFromRemote: true },
      args: { "rabbitmq.timeout": "1200" },
      expect: {
        "Risk Level": "CRITICAL",
      },
      expectAll: [
        { contains: "RABBITMQ-ANON-GUEST-REMOTE" },
        { contains: "RABBITMQ-ANON-EMPTY-CREDENTIAL" },
        { contains: "guest" },
      ],
      verify: ({ state, say }) => {
        const guest = (state.amqpAttempts || []).filter((a) => a.user === "guest");
        say(guest.length >= 1, "the guest attempt reached the broker");
        say(guest.every((a) => a.passwordBytes === 0), "the guest attempt carried an empty password");
      },
    }),

    scenario("a backend that accepts a malformed SASL response is graded CRITICAL", {
      broker: { mechanisms: ["PLAIN", "AMQPLAIN"], acceptMalformed: true },
      expect: {
        "Response-shape matrix": "accepted",
        "Risk Level": "CRITICAL",
      },
      expectAll: [
        { contains: "RABBITMQ-ANON-MALFORMED-RESPONSE-ACCEPTED" },
        { contains: "malformed for its mechanism" },
        { contains: "malformed-plain" },
      ],
      verify: ({ state, result, say }) => {
        const shapes = result.output["Response-shape matrix"].join("\n");
        say(shapes.includes("malformed-plain") && shapes.includes("accepted"),
          "the malformed PLAIN shape is reported as accepted");
        say((state.amqpAttempts || []).length >= 3,
          `the shape matrix sent real start-ok frames (${(state.amqpAttempts || []).length})`);
        const text = JSON.stringify(result.output);
        say(!text.includes("RABBITMQ-ANON-LOGIN-ACCEPTED"),
          "the malformed-response finding does not claim a credentialed login was accepted");
      },
    }),

    scenario("the same broker with a strict parser refuses every shape", {
      broker: { mechanisms: ["PLAIN", "AMQPLAIN"] },
      expect: {
        "Response-shape matrix": "refused",
      },
      expectAll: [
        { contains: "RABBITMQ-ANON-SHAPES-REFUSED" },
        { contains: "ACCESS_REFUSED" },
      ],
      verify: ({ state, say }) => {
        say((state.authFailures || []).some((f) => /malformed/.test(f.reason || "")),
          "the broker logged the malformed responses as authentication failures");
      },
    }),

    scenario("a TLS listener answers the plaintext handshake with a TLS record", {
      port: AMQPS_PORT,
      broker: { tls: true, mechanisms: ["PLAIN"] },
      args: { "rabbitmq.shapes": "false" },
      expect: {
        "Risk Level": "INFO",
        "Pre-authentication handshake": "Not read",
      },
      expectAll: [
        { contains: "RABBITMQ-ANON-NOT-AMQP" },
        { contains: "tls-listener" },
      ],
      verify: ({ state, say }) => {
        say(state.plaintextOnTlsPort >= 1, "the plaintext header reached the TLS listener");
        say(state.tlsHellos.length >= 1, "the TLS probe reached the listener as a ClientHello");
        say((state.amqpAttempts || []).length === 0,
          "no login was attempted against a listener that cannot answer plaintext AMQP");
      },
    }),

    scenario("a broker that goes silent leaves the matrix inconclusive, not clean", {
      broker: { mechanisms: ["PLAIN"], authHang: true },
      args: { "rabbitmq.timeout": "600", "rabbitmq.shapes": "false", "rabbitmq.burst": "0" },
      expect: {
        "Risk Level": "INFO",
      },
      expectAll: [
        { contains: "RABBITMQ-ANON-AUDIT-INCONCLUSIVE" },
        { contains: "produced no answer at all" },
      ],
      verify: ({ state, result, say }) => {
        const matrix = result.output["Login attempt matrix"].join("\n");
        say(matrix.includes("inconclusive"), "the attempts that timed out are marked inconclusive");
        say(matrix.includes("accepted 0"), "no attempt is reported as accepted on silence");
        say((state.protocolErrors || []).length === 0,
          `the mock decoded every frame it received (${JSON.stringify(state.protocolErrors)})`);
      },
    }),

    scenario("a port that drops the protocol header is reported as not AMQP", {
      broker: { dropAfterHeader: true },
      args: { "rabbitmq.shapes": "false", "rabbitmq.burst": "0" },
      expect: {
        "Risk Level": "INFO",
      },
      expectAll: [
        { contains: "RABBITMQ-ANON-NOT-AMQP" },
        { contains: "did not answer the AMQP protocol header" },
      ],
      verify: ({ state, say }) => {
        say(state.protocolHeaders.length >= 1,
          `the protocol header reached the mock before it dropped the port (${state.protocolHeaders.length})`);
      },
    }),
  ],
};
