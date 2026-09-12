"use strict";
const PORT = { number: 9092, protocol: "tcp", state: "open", service: "kafka" };
module.exports = {
  name: "kafka-crypto-selftest",
  scenarios: [{
    name: "hashes, bit ops and SASL crypto match published test vectors",
    script: "test-fixtures/kafka-crypto-probe.nse",
    port: PORT,
    mockFactory: () => ({ handle: () => null, state: { requests: [] } }),
    expect: {
      "sha256_abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      "sha256_empty": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "sha256_long": "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3",
      "sha512_abc": "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
      "sha512_empty": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
      "rotr": "2147483648/1",
      "band": "4026593280",
      "bxor": "4294901760",
      "bnot": "4294967295",
      "addwrap": "0",
      "crc32c": "e3069283",
      "b64": "S2Fma2Eh/Kafka!",
      "hmac": "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
      "pbkdf2": "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
    },
  }],
};
