"use strict";
/*
 * Integration scenarios for KERBEROS/kerberos-weak-encryption.nse.
 *
 * The mock KDC applies a per-etype policy and builds the real
 * KDC_ERR_PREAUTH_REQUIRED e-data (PA-ETYPE-INFO2 + PA-SUPPORTED-ENCTYPES),
 * so the script's negotiation matrix and its advertisement decoding are both
 * exercised against a server that behaves like a KDC.
 */

const REALM = "EXAMPLE.COM";

module.exports = {
  name: "kerberos-weak-encryption",
  scenarios: [
    {
      name: "legacy realm accepting DES and RC4 is rated CRITICAL",
      script: "KERBEROS/kerberos-weak-encryption.nse",
      mock: "tools/mocks/kdc.js",
      kdc: {
        realm: REALM,
        accounts: {},
        acceptsEtype: [1, 3, 16, 17, 18, 23],
        answerUnknownPrincipals: true,
      },
      args: {
        "kerberos.realm": REALM,
        "kerberos.etypes": "1,3,16,17,18,23",
        "kerberos.delay-ms": "0",
        "kerberos.retries": "0",
      },
      expect: {
        "Realm": REALM,
        "Risk Level": "CRITICAL",
        "Accepted etypes": "23 rc4-hmac",
        "Accepted etypes": "1 des-cbc-crc, 3 des-cbc-md5",
        "Strongest negotiable etype": "etype 23",
        "Weakest negotiable etype": "etype 1",
        "Findings[0]": "CRITICAL",
      },
    },
    {
      name: "modern realm with AES only is rated LOW and shows the refused matrix",
      script: "KERBEROS/kerberos-weak-encryption.nse",
      mock: "tools/mocks/kdc.js",
      kdc: {
        realm: REALM,
        accounts: {},
        acceptsEtype: [17, 18],
        answerUnknownPrincipals: true,
      },
      args: {
        "kerberos.realm": REALM,
        "kerberos.etypes": "1,3,23,17,18",
        "kerberos.delay-ms": "0",
        "kerberos.retries": "0",
      },
      expect: {
        "Risk Level": "LOW",
        "Accepted etypes": "17 aes128-cts-hmac-sha1-96, 18 aes256-cts-hmac-sha1-96",
        "Refused etypes": "1, 3, 23",
        "Encryption type support matrix[0]": "REFUSED",
      },
    },
    {
      name: "AES-SHA2 realm: the missing-generation finding must disappear",
      script: "KERBEROS/kerberos-weak-encryption.nse",
      mock: "tools/mocks/kdc.js",
      kdc: {
        realm: REALM,
        accounts: {},
        acceptsEtype: [17, 18, 19, 20],
        answerUnknownPrincipals: true,
      },
      args: {
        "kerberos.realm": REALM,
        "kerberos.etypes": "19,20,17,18",
        "kerberos.delay-ms": "0",
        "kerberos.retries": "0",
      },
      expect: {
        "Risk Level": "LOW",
        "Accepted etypes": "19 aes128-cts-hmac-sha256-128",
        "Verdict[0]": "No weak encryption type is negotiable",
        "Strongest negotiable etype": "etype 20",
        "Offline attack cost by accepted etype (estimates)[0]": "etype 17",
      },
    },
    {
      name: "PA-SUPPORTED-ENCTYPES advertising weak bits raises a finding",
      script: "KERBEROS/kerberos-weak-encryption.nse",
      mock: "tools/mocks/kdc.js",
      kdc: {
        realm: REALM,
        accounts: {},
        acceptsEtype: [17, 18, 23],
        answerUnknownPrincipals: true,
        supportedMask: 0x00430000,  // PA-SUPPORTED-ENCTYPES bits for etype 17, 18 and 23
      },
      args: {
        "kerberos.realm": REALM,
        "kerberos.etypes": "18,23",
        "kerberos.delay-ms": "0",
        "kerberos.retries": "0",
      },
      expect: {
        "Risk Level": "HIGH",
        "Realm advertisement[0]": "PA-SUPPORTED-ENCTYPES mask: 0x00430000",
        "Realm advertisement[3]": "etype 23",
      },
      expectAll: [
        { contains: "advertises weak encryption types in PA-SUPPORTED-ENCTYPES" },
        { contains: "bit set for etype 23  rc4-hmac" },
      ],
    },
    {
      name: "principal rejected before the etype decision yields an honest UNDETERMINED",
      script: "KERBEROS/kerberos-weak-encryption.nse",
      mock: "tools/mocks/kdc.js",
      kdc: {
        realm: REALM,
        accounts: {},
        acceptsEtype: [17, 18],
        answerUnknownPrincipals: false,
      },
      args: {
        "kerberos.realm": REALM,
        "kerberos.etypes": "17,23",
        "kerberos.delay-ms": "0",
        "kerberos.retries": "0",
      },
      expect: {
        "Risk Level": "INCONCLUSIVE",
        "Undetermined etypes": "KDC_ERR_C_PRINCIPAL_UNKNOWN",
      },
    },
  ],
};
