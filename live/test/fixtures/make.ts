/**
 * Rebuilds relayed-permit.json from the chain: the owner's real permit (tx 0xe77f18d3…), the exact text the
 * deployed contract wrote for it, and the owner's registered ML-DSA-87 key. The offline test then checks that
 * @qorechain/qoresign reproduces the bytes that signature covers.   npx tsx test/fixtures/make.ts
 */
import { writeFileSync } from "node:fs";
import { decodeFunctionData, type Address, type Hex } from "viem";
import { artifact, loadState, publicClient } from "../../lib.ts";

const RELAYED = "0xe77f18d3451748ffed17df43ae5e3b79a8f8ea984c772835399203b9ecc403f5" as Hex;
const PQ = artifact("out/PQPermit.sol/PQPermit.json").abi;
const pq = loadState().PQPermit as Address;
const tx = await publicClient.getTransaction({ hash: RELAYED });
const { args } = decodeFunctionData({ abi: PQ, data: tx.input });
const [owner, permit, signature] = args as [Address, Record<string, unknown>, Hex];
const text = (await publicClient.readContract({ address: pq, abi: PQ, functionName: "permitText", args: [owner, permit] })) as Hex;
const [, , publicKey] = (await publicClient.readContract({
  address: "0x0000000000000000000000000000000000000a02",
  abi: [{ type: "function", name: "pqcKeyStatus", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "bool" }, { type: "uint8" }, { type: "bytes" }, { type: "bool" }] }],
  functionName: "pqcKeyStatus",
  args: [owner],
})) as [boolean, number, Hex, boolean];
const json = JSON.stringify({ tx: RELAYED, contract: pq, owner, permitText: text, publicKey, signature }, null, 2);
writeFileSync(new URL("./relayed-permit.json", import.meta.url), json + "\n");
console.log("wrote relayed-permit.json");
