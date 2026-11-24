/**
 * Offline: @qorechain/qoresign builds exactly the bytes the deployed PQPermit verifies.
 * The fixture is the owner's real permit relayed on testnet (tx 0xe77f18d3…), see fixtures/make.ts.
 *   npm test
 */
import { shake256 } from "@noble/hashes/sha3.js";
import { MESSAGE_PQ_DOMAIN, messagePqSignBytes, pqKeyFromSeed, pqSign, pqVerify } from "@qorechain/qoresign";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { bytesToHex, concat, hexToBytes, toBytes, type Hex } from "viem";

const fx = JSON.parse(readFileSync(new URL("./fixtures/relayed-permit.json", import.meta.url), "utf8")) as {
  permitText: Hex;
  publicKey: Hex;
  signature: Hex;
};
const text = hexToBytes(fx.permitText);
const publicKey = hexToBytes(fx.publicKey);
const signature = hexToBytes(fx.signature);

test("QoreSign message-signing-v1 bytes are the prefix PQSig.sol uses", () => {
  assert.equal(MESSAGE_PQ_DOMAIN, "qorechain-msg-v1|");
  const handBuilt = concat([toBytes("qorechain-msg-v1|qorechain-diana|"), text]);
  assert.equal(bytesToHex(messagePqSignBytes("qorechain-diana", text)), bytesToHex(handBuilt));
});

test("the owner's real on-chain permit signature verifies over QoreSign's bytes", () => {
  assert.equal(publicKey.length, 2592);
  assert.equal(signature.length, 4627);
  assert.ok(pqVerify(publicKey, messagePqSignBytes("qorechain-diana", text), signature));
});

test("changing one character of the text, the chain id, or one signature bit breaks it", () => {
  const tampered = text.slice();
  tampered[tampered.length - 1] ^= 1;
  assert.ok(!pqVerify(publicKey, messagePqSignBytes("qorechain-diana", tampered), signature));
  assert.ok(!pqVerify(publicKey, messagePqSignBytes("qorechain-vladi", text), signature));
  const flipped = signature.slice();
  flipped[100] ^= 1;
  assert.ok(!pqVerify(publicKey, messagePqSignBytes("qorechain-diana", text), flipped));
});

test("the public demo owner's key comes from its published seed and signs verifiable permits", () => {
  const seed = shake256(new TextEncoder().encode("pq-permit:public-demo-owner:v1"), { dkLen: 32 });
  assert.equal(bytesToHex(seed), "0x0abc3a8e1d33a581539a0e14ff05969c39648dcf33b41cc93f03e179d70da283");
  const key = pqKeyFromSeed(seed);
  const msg = messagePqSignBytes("qorechain-diana", text);
  assert.ok(pqVerify(key.publicKey, msg, pqSign(key.secretKey, msg)));
});
