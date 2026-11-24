/**
 * Sign a permit composed on the PQ Permit page with the owner's ML-DSA-87 key, using @qorechain/qoresign
 * (message-signing-v1). QoreX refuses signArbitrary today, so this is how an owner signs with their own key.
 * Nothing is sent to the chain.
 *   npm run sign-permit -- '<json copied from the page>'
 * Needs OWNER_MNEMONIC in .env (the owner's recovery phrase; it never leaves this machine).
 */
import { deriveCanonicalPqKey, messagePqSignBytes, pqSign, pqVerify } from "@qorechain/qoresign";
import { bytesToHex, getAddress, hexToBytes, toHex, type Address, type Hex } from "viem";
import { NET, accountFromEnv, artifact, loadState, publicClient } from "./lib.ts";

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
// QoreSign's canonical derivation gives the key QoreChain wallets and the SDK register; check it is the one on chain.
const key = deriveCanonicalPqKey({ mnemonic: process.env.OWNER_MNEMONIC.trim(), address: acc.cosmos });
const [, , registered] = (await publicClient.readContract({
  address: "0x0000000000000000000000000000000000000a02",
  abi: [{ type: "function", name: "pqcKeyStatus", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "bool" }, { type: "uint8" }, { type: "bytes" }, { type: "bool" }] }],
  functionName: "pqcKeyStatus",
  args: [owner],
})) as [boolean, number, Hex, boolean];
if (registered.toLowerCase() !== bytesToHex(key.publicKey)) {
  console.error("The ML-DSA-87 key derived from OWNER_MNEMONIC is not the key registered on chain for this owner.");
  process.exit(1);
}
const message = messagePqSignBytes(NET.chainId, hexToBytes(text)); // "qorechain-msg-v1|qorechain-diana|" + text
const sig = pqSign(key.secretKey, message);
if (!pqVerify(key.publicKey, message, sig)) throw new Error("self-check failed");
console.log(toHex(sig));
