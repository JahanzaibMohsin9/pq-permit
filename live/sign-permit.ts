/**
 * Sign a permit composed on the PQ Permit page with the owner's ML-DSA-87 key (QoreSign message-signing-v1).
 * Until QoreX supports signArbitrary, this is how an owner signs. Nothing is sent to the chain.
 *   npm run sign-permit -- '<json copied from the page>'
 * Needs OWNER_MNEMONIC in .env (the owner's recovery phrase; it never leaves this machine).
 */
import { pqcSign } from "@qorechain/sdk";
import { concat, getAddress, toBytes, toHex, type Address, type Hex } from "viem";
import { accountFromEnv, artifact, loadState, publicClient } from "./lib.ts";

const raw = process.argv[2];
if (!raw) {
  console.error("usage: npm run sign-permit -- '<json from the page>'");
  process.exit(1);
}
const { owner, permit } = JSON.parse(raw) as {
  owner: Address;
  permit: { token: Address; spender: Address; amount: string; expiration: number; nonce: string; sigDeadline: string };
};
const p = { ...permit, amount: BigInt(permit.amount), nonce: BigInt(permit.nonce), sigDeadline: BigInt(permit.sigDeadline) };
if (!process.env.OWNER_MNEMONIC) {
  console.error("Set OWNER_MNEMONIC in live/.env first.");
  process.exit(1);
}
const acc = await accountFromEnv("OWNER_MNEMONIC");
if (getAddress(acc.evm) !== getAddress(owner)) {
  console.error(`OWNER_MNEMONIC belongs to ${acc.evm}, but the permit is for ${owner}.`);
  process.exit(1);
}
// The contract writes the text, so the signature covers exactly what it will verify.
const PQ = artifact("out/PQPermit.sol/PQPermit.json");
const text = (await publicClient.readContract({ address: loadState().PQPermit as Address, abi: PQ.abi, functionName: "permitText", args: [owner, p] })) as Hex;
const sig = pqcSign(acc.pqc.secretKey, concat([toBytes("qorechain-msg-v1|qorechain-diana|"), toBytes(text)]));
console.log(toHex(sig));
