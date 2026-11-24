/**
 * One-off setup of the PUBLIC demo owner used by the web page's "sign in this browser" button.
 *
 * Its ML-DSA-87 seed is public on purpose: SHAKE-256("pq-permit:public-demo-owner:v1", 32 bytes).
 * Anyone can sign permits as this owner, which is the point: a judge can try a valid permit end to end
 * without a wallet. The account holds no tokens, so a permit from it moves nothing of value.
 * Its secp256k1 key stays private (DEMO_OWNER_MNEMONIC in .env, generated on first run, never printed).
 *
 *   npm run demo-owner
 * Spends about 0.35 testnet QOR from the owner account (0.25 QOR funding + fees).
 */
import { shake256 } from "@noble/hashes/sha3.js";
import { parseAddress, pqKeyFromSeed } from "@qorechain/qoresign";
import { fetchPqcStatus } from "@qorechain/sdk";
import { bytesToHex, type Address, type Hex } from "viem";
import { EXPLORER_TX, NET, accountFromEnv, broadcastNative, ensurePqcKey, loadState, publicClient, saveState, sendQorMsg, sleep } from "./lib.ts";

export const DEMO_SEED_DOMAIN = "pq-permit:public-demo-owner:v1";
const seed = shake256(new TextEncoder().encode(DEMO_SEED_DOMAIN), { dkLen: 32 });
const pq = pqKeyFromSeed(seed);

const funder = await accountFromEnv("OWNER_MNEMONIC");
const demo = { ...(await accountFromEnv("DEMO_OWNER_MNEMONIC")), pqc: { publicKey: pq.publicKey, secretKey: pq.secretKey } };
console.log(`demo owner ${demo.evm} (${parseAddress(demo.evm).bech32})`);
console.log(`demo ML-DSA-87 seed ${bytesToHex(seed)} (public)`);

const balance = async () => {
  const r = await fetch(`${NET.rest}/cosmos/bank/v1beta1/balances/${demo.cosmos}`, { headers: { "user-agent": "Mozilla/5.0" } });
  const b = (await r.json()) as { balances?: { denom: string; amount: string }[] };
  return BigInt(b.balances?.find((x) => x.denom === "uqor")?.amount ?? "0");
};

if ((await balance()) < 150_000n) {
  const h = await broadcastNative(funder, "hybrid", [sendQorMsg(funder.cosmos, demo.cosmos, 250_000n)]);
  console.log(`fund 0.25 QOR: ${EXPLORER_TX}${h}`);
  for (let i = 0; i < 30 && (await balance()) < 150_000n; i++) await sleep(2000);
}

const reg = await ensurePqcKey(demo);
console.log(reg ? `register ML-DSA-87 key with proof of possession: ${EXPLORER_TX}${reg}` : "key already registered");
for (let i = 0; i < 30; i++) {
  const st = await fetchPqcStatus({ rest: NET.rest, address: demo.cosmos });
  if (st.registered) break;
  await sleep(2000);
}

const [registered, alg, key, proven] = (await publicClient.readContract({
  address: "0x0000000000000000000000000000000000000a02",
  abi: [{ type: "function", name: "pqcKeyStatus", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "bool" }, { type: "uint8" }, { type: "bytes" }, { type: "bool" }] }],
  functionName: "pqcKeyStatus",
  args: [demo.evm as Address],
})) as [boolean, number, Hex, boolean];
const same = key.toLowerCase() === bytesToHex(pq.publicKey).toLowerCase();
console.log(`pqcKeyStatus: registered=${registered} alg=${alg} possession=${proven} key matches public seed=${same}`);
if (!(registered && alg === 1 && proven && same)) process.exit(1);

const st = loadState();
st.demoOwner = demo.evm;
if (reg) st.demoOwnerRegisterTx = reg;
saveState(st);
