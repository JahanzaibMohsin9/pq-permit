/**
 * PQ Permit: live testnet run on qorechain-diana.
 *
 *  PART A (the hole): a standard EIP-2612 token. A victim who never sends a transaction (no window,
 *          no PQ key) signs a permit with their ECDSA key, i.e. a leaked key. Someone else relays it and drains them.
 *  PART B (the fix): PQ Permit. The owner approves PQ Permit once inside a SCOPED window (one tx, one
 *          target). After that:
 *          - an ECDSA-signed permit is rejected,
 *          - a permit signed by another ML-DSA key is rejected,
 *          - a direct EVM tx with the owner's (leaked) ECDSA key is refused by the chain (window used up),
 *          - the owner's real ML-DSA-87 permit, relayed by someone else, works.
 *
 * Writes docs/TESTNET_RUN.md and live/state.json. Run: cd live && npm run live
 */
import { pqcSign } from "@qorechain/sdk";
import { classifyEvmWindowRejection, evmWindowCost } from "@qorechain/evm";
import { mldsa87 } from "@qorechain/pqc";
import { writeFileSync } from "node:fs";
import { BaseError, ContractFunctionRevertedError, concat, getAddress, maxUint160, maxUint256, toBytes, toHex, type Address, type Hex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import {
  EXPLORER_TX, FEES, accountFromEnv, artifact, broadcastNative, ensurePqcKey, loadState, openWindow,
  publicClient, saveState, sendQorMsg, sleep, walletFor,
} from "./lib.ts";

const log: string[] = [];
const say = (s: string) => { console.log(s); log.push(s); };
const tx = (label: string, hash: string) => say(`- ${label}: [\`${hash.slice(0, 10)}…\`](${EXPLORER_TX}${hash})`);

const PQ = artifact("out/PQPermit.sol/PQPermit.json");
const DUSD = artifact("out/Tokens.sol/FestUSDLike.json");
const PUSD = artifact("out/Tokens.sol/PermitUSD.json");

async function deploy(wallet: ReturnType<typeof walletFor>, a: { abi: any; bytecode: Hex }, label: string): Promise<Address> {
  const hash = await wallet.deployContract({ abi: a.abi, bytecode: a.bytecode, args: [], gas: 3_000_000n, ...FEES });
  const r = await publicClient.waitForTransactionReceipt({ hash });
  if (r.status !== "success" || !r.contractAddress) throw new Error(`${label} deploy failed: ${hash}`);
  tx(`deploy ${label} at \`${r.contractAddress}\``, hash);
  return r.contractAddress;
}

async function write(wallet: ReturnType<typeof walletFor>, address: Address, abi: any, functionName: string, args: any[], label: string, gas = 300_000n) {
  const hash = await wallet.writeContract({ address, abi, functionName, args, gas, ...FEES });
  const r = await publicClient.waitForTransactionReceipt({ hash });
  if (r.status !== "success") throw new Error(`${label} reverted: ${hash}`);
  tx(`${label} (gas billed ${r.gasUsed})`, hash);
  return r;
}

async function expectRevert(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return "NO REVERT (unexpected!)";
  } catch (e) {
    if (e instanceof BaseError) {
      const rev = e.walk((x) => x instanceof ContractFunctionRevertedError) as ContractFunctionRevertedError | null;
      if (rev?.data?.errorName) return `reverted: ${rev.data.errorName}`;
      return `refused by the chain: ${(e.details || e.shortMessage).replace(/\s+/g, " ").trim()}`;
    }
    return `refused: ${String(e)}`;
  }
}

async function main() {
  const state = loadState();
  const deployer = await accountFromEnv("QORE_MNEMONIC");
  const owner = await accountFromEnv("OWNER_MNEMONIC");
  const D = walletFor(deployer);
  const O = walletFor(owner);
  const merchant = getAddress(privateKeyToAccount(generatePrivateKey()).address);

  say(`# PQ Permit: live testnet run (qorechain-diana, EVM 9800)\n`);
  say(`Run at ${new Date().toISOString()}.\n`);
  say(`| Role | Address |\n|---|---|`);
  say(`| Deployer / relayer / spender | \`${deployer.evm}\` (\`${deployer.cosmos}\`) |`);
  say(`| Owner (PQ Permit user) | \`${owner.evm}\` (\`${owner.cosmos}\`) |`);
  say(`| Merchant (receives funds) | \`${merchant}\` |\n`);

  // ------------------------------------------------------------------ PART A
  say(`## Part A: the hole. A leaked ECDSA key drains a standard EIP-2612 token\n`);
  const victimKey = generatePrivateKey();
  const victim = privateKeyToAccount(victimKey);
  const pusd = await deploy(D, PUSD, "PermitUSD (OpenZeppelin ERC20Permit)");
  await write(D, pusd, PUSD.abi, "mint", [victim.address, 1000n * 10n ** 18n], `mint 1000 pUSD to victim \`${victim.address}\``);

  const deadline = BigInt(Math.floor(Date.now() / 1000) + 3600);
  const nonce = (await publicClient.readContract({ address: pusd, abi: PUSD.abi, functionName: "nonces", args: [victim.address] })) as bigint;
  const sig = await victim.signTypedData({
    domain: { name: "Permit USD", version: "1", chainId: 9800, verifyingContract: pusd },
    types: { Permit: [
      { name: "owner", type: "address" }, { name: "spender", type: "address" }, { name: "value", type: "uint256" },
      { name: "nonce", type: "uint256" }, { name: "deadline", type: "uint256" },
    ] },
    primaryType: "Permit",
    message: { owner: victim.address, spender: getAddress(deployer.evm), value: maxUint256, nonce, deadline },
  });
  const r = BigInt(`0x${sig.slice(2, 66)}`), s = BigInt(`0x${sig.slice(66, 130)}`), v = parseInt(sig.slice(130, 132), 16);
  say(`The victim's ECDSA key signs a permit **offline**. The attacker relays it from their own account:`);
  await write(D, pusd, PUSD.abi, "permit", [victim.address, deployer.evm, maxUint256, deadline, v, toHex(r, { size: 32 }), toHex(s, { size: 32 })], "attacker relays permit(victim → attacker, unlimited)");
  await write(D, pusd, PUSD.abi, "transferFrom", [victim.address, deployer.evm, 1000n * 10n ** 18n], "attacker transferFrom(victim → attacker, 1000 pUSD)");
  const vBal = await publicClient.readContract({ address: pusd, abi: PUSD.abi, functionName: "balanceOf", args: [victim.address] });
  const vNonce = await publicClient.getTransactionCount({ address: victim.address });
  say(`\n**Result:** victim balance = **${vBal}**. The victim's EVM nonce is **${vNonce}**: they never sent a transaction, had no EVM window and no PQ key. EVM windows protect transactions, not signatures.\n`);

  // ------------------------------------------------------------------ PART B
  say(`## Part B: the fix. PQ Permit (ML-DSA-87 signed approvals)\n`);
  const dusd = await deploy(D, DUSD, "Demo USD (no permit)");
  const pq = await deploy(D, PQ, "PQPermit");
  await write(D, dusd, DUSD.abi, "mint", [owner.evm, 1000n * 10n ** 6n], "mint 1000 dUSD to owner");

  say(`\nThe owner gets 2 QOR for fees, registers an ML-DSA-87 key with proof of possession, and opens a **scoped** EVM window: 1 transaction, only to the dUSD contract.`);
  tx("fund owner with 2 QOR (hybrid-signed native send)", await broadcastNative(deployer, "hybrid", [sendQorMsg(deployer.cosmos, owner.cosmos, 2_000_000n)]));
  await sleep(4000);
  const reg = await ensurePqcKey(owner);
  if (reg) tx("owner registers ML-DSA-87 key + proof of possession", reg);
  await sleep(4000);
  const perTx = evmWindowCost({ gas: 120_000n, maxFeePerGas: FEES.maxFeePerGas });
  tx(`owner opens scoped window (1 tx, allowedTargets=[dUSD], cap ${perTx} uqor)`, await openWindow(owner, { blocks: 300n, maxTxs: 1n, maxValueUqor: perTx, allowedTargets: [dusd] }));
  await sleep(4000);
  await write(O, dusd, DUSD.abi, "approve", [pq, maxUint256], "owner approves PQPermit once (the only EVM tx the owner ever sends)", 120_000n);

  const ks = (await publicClient.readContract({
    address: "0x0000000000000000000000000000000000000a02",
    abi: [{ type: "function", name: "pqcKeyStatus", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "bool" }, { type: "uint8" }, { type: "bytes" }, { type: "bool" }] }],
    functionName: "pqcKeyStatus",
    args: [owner.evm as Address],
  })) as [boolean, number, Hex, boolean];
  say(`\nOwner key status from the \`pqcKeyStatus\` precompile: registered=${ks[0]}, algorithm=${ks[1]}, key=${(ks[2].length - 2) / 2} bytes, possessionProven=${ks[3]}.\n`);

  const permit = {
    token: dusd, spender: getAddress(deployer.evm), amount: 100n * 10n ** 6n,
    expiration: Number(BigInt(Math.floor(Date.now() / 1000)) + 86_400n), nonce: 0n,
    sigDeadline: BigInt(Math.floor(Date.now() / 1000) + 3600),
  };
  const text = (await publicClient.readContract({ address: pq, abi: PQ.abi, functionName: "permitText", args: [owner.evm, permit] })) as Hex;
  const message = concat([toBytes("qorechain-msg-v1|qorechain-diana|"), toBytes(text)]);
  say(`The owner signs this human-readable text (QoreSign message-signing-v1, the format QoreX \`signArbitrary\` uses; the extension doesn't support \`signArbitrary\` yet, so this run signs with \`@qorechain/sdk\`):\n\n\`\`\`\n${Buffer.from(text.slice(2), "hex").toString("utf8")}\n\`\`\`\n`);

  say(`Attacks (each simulated with \`eth_call\` and refused, so no gas is spent):`);
  const ecdsaSig = await privateKeyToAccount(owner.privateKey as Hex).signMessage({ message: { raw: toHex(message) } });
  say(`- ECDSA signature by the owner's (leaked) key → **${await expectRevert(publicClient.simulateContract({ account: deployer.evm as Address, address: pq, abi: PQ.abi, functionName: "permit", args: [owner.evm, permit, ecdsaSig] }))}**`);
  const fake = mldsa87.keygen(crypto.getRandomValues(new Uint8Array(32)));
  const fakeSig = toHex(mldsa87.sign(fake.secretKey, message));
  say(`- ML-DSA-87 signature by an attacker's own key → **${await expectRevert(publicClient.simulateContract({ account: deployer.evm as Address, address: pq, abi: PQ.abi, functionName: "permit", args: [owner.evm, permit, fakeSig] }))}**`);
  const direct = await expectRevert(O.writeContract({ address: dusd, abi: DUSD.abi, functionName: "transfer", args: [deployer.evm, 1n], gas: 120_000n, ...FEES }));
  let why = "";
  try { why = classifyEvmWindowRejection(new Error(direct)) ?? ""; } catch { /* best effort */ }
  say(`- Direct EVM transfer signed with the owner's leaked ECDSA key → **${direct.slice(0, 160)}**${why ? ` (window: ${why})` : ""}\n`);

  const realSig = toHex(pqcSign(owner.pqc.secretKey, message)); // `message` is already bytes
  const realGas = await publicClient.estimateContractGas({ account: deployer.evm as Address, address: pq, abi: PQ.abi, functionName: "permit", args: [owner.evm, permit, realSig] });
  say(`The owner's real ML-DSA-87 signature (${(realSig.length - 2) / 2} bytes), relayed by someone else:`);
  const rp = await write(D, pq, PQ.abi, "permit", [owner.evm, permit, realSig], "relayer submits PQ permit (owner sends nothing)", 2_000_000n);
  await write(D, pq, PQ.abi, "transferFrom", [owner.evm, merchant, 60n * 10n ** 6n, dusd], "spender pulls 60 dUSD to merchant", 200_000n);
  const [allowance] = (await publicClient.readContract({ address: pq, abi: PQ.abi, functionName: "allowance", args: [owner.evm, dusd, deployer.evm] })) as [bigint, number];
  const mBal = await publicClient.readContract({ address: dusd, abi: DUSD.abi, functionName: "balanceOf", args: [merchant] });
  say(`\n**Result:** merchant received **${Number(mBal) / 1e6} dUSD**. Remaining allowance **${Number(allowance) / 1e6} dUSD**. Real gas cost of an ML-DSA-87 permit (estimateGas): **~${realGas}**; billed ${rp.gasUsed} because of the 2M limit we set (see notes).`);
  say(`A replay of the same signature → **${await expectRevert(publicClient.simulateContract({ account: deployer.evm as Address, address: pq, abi: PQ.abi, functionName: "permit", args: [owner.evm, permit, realSig] }))}**`);

  say(`\n## Notes and findings`);
  say(`- **Gas billing:** on QoreChain a receipt's \`gasUsed\` is at least **50% of the gas limit**. Every billed figure above is exactly half the limit we set. The real cost of an ML-DSA-87 PQ permit is **~${realGas} gas** (\`eth_estimateGas\`). Set tight gas limits.`);
  say(`- **Scoped window:** the owner's window admitted exactly one transaction, only to the token (\`allowedTargets\`). After that, a direct transfer signed with the owner's ECDSA key was **refused by the chain**.`);
  say(`- **Precompile behaviour that differs from the docs:** see [pqc-forge](https://github.com/JahanzaibMohsin9/pqc-forge). An unknown selector reverts, non-canonical ABI input reverts, and an empty message returns false.`);
  say(`- Reproduce: \`cd live && npm ci && npm run live\` (needs a funded deployer in \`live/.env\`).`);
  Object.assign(state, { PQPermit: pq, DemoUSD: dusd, PermitUSD: pusd, owner: owner.evm, deployer: deployer.evm });
  saveState(state);
  writeFileSync(new URL("../docs/TESTNET_RUN.md", import.meta.url), log.join("\n") + "\n");
  console.log("\nWrote docs/TESTNET_RUN.md");
  void maxUint160;
}

main().catch((e) => {
  console.error(e instanceof BaseError ? e.shortMessage + "\n" + e.details : e);
  writeFileSync(new URL("../docs/TESTNET_RUN.partial.md", import.meta.url), log.join("\n") + "\n");
  process.exit(1);
});
