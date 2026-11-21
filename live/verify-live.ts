/**
 * Read-only check of the live testnet deployment: re-reads everything docs/TESTNET_RUN.md claims and
 * re-tries the attacks as eth_call simulations. Sends no transactions and needs no funds or keys.
 *   npm run verify
 * If OWNER_MNEMONIC is set in .env, it also signs the attack with the owner's real secp256k1 key
 * (the "leaked key"); otherwise a random ECDSA key stands in for it.
 */
import { mldsa87 } from "@qorechain/pqc";
import { BaseError, ContractFunctionRevertedError, concat, toBytes, toHex, type Address, type Hex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { artifact, loadState, publicClient } from "./lib.ts";
import { deriveUnifiedAccount } from "@qorechain/sdk";

const st = loadState();
const PQ = artifact("out/PQPermit.sol/PQPermit.json").abi;
const ERC20 = artifact("out/Tokens.sol/PermitUSD.json").abi;
const pq = st.PQPermit as Address;
const dusd = st.DemoUSD as Address;
const pusd = st.PermitUSD as Address;
const owner = st.owner as Address;
const relayer = st.deployer as Address;
const VICTIM = "0x893f60582E7eDc579E025fF363539b5a7A3258E2" as Address; // Part A victim (docs/TESTNET_RUN.md)
const MERCHANT = "0x737986bfc4CD9010c100C6eb0fea65F26D7c5222" as Address; // Part B merchant
const KEY_STATUS = "0x0000000000000000000000000000000000000a02" as Address;

const ok = (cond: boolean) => (cond ? "✓" : "✗ MISMATCH");
const line = (s: string) => console.log(s);
const read = (address: Address, abi: any, functionName: string, args: unknown[]) =>
  publicClient.readContract({ address, abi, functionName, args }) as Promise<any>;

async function revertName(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return "NO REVERT";
  } catch (e) {
    if (e instanceof BaseError) {
      const rev = e.walk((x) => x instanceof ContractFunctionRevertedError) as ContractFunctionRevertedError | null;
      if (rev?.data?.errorName) return rev.data.errorName;
      return (e.shortMessage || e.message).split("\n")[0];
    }
    return String(e);
  }
}

line(`PQ Permit, live check on qorechain-diana (block ${await publicClient.getBlockNumber()})`);
line(`read-only: no transactions are sent\n`);

line(`Part A: the hole (standard EIP-2612 token ${pusd.slice(0, 10)}...)`);
const vBal = (await read(pusd, ERC20, "balanceOf", [VICTIM])) as bigint;
const vNonce = await publicClient.getTransactionCount({ address: VICTIM });
line(`  victim pUSD balance ........ ${vBal} ${ok(vBal === 0n)}`);
line(`  victim transactions sent ... ${vNonce} ${ok(vNonce === 0)}  (drained by a relayed ECDSA permit)\n`);

line(`Part B: PQ Permit ${pq.slice(0, 10)}...`);
const ks = (await read(KEY_STATUS, [{ type: "function", name: "pqcKeyStatus", stateMutability: "view", inputs: [{ type: "address" }], outputs: [{ type: "bool" }, { type: "uint8" }, { type: "bytes" }, { type: "bool" }] }], "pqcKeyStatus", [owner])) as [boolean, number, Hex, boolean];
line(`  owner ML-DSA-87 key ........ registered=${ks[0]} alg=${ks[1]} ${(ks[2].length - 2) / 2} bytes possession=${ks[3]} ${ok(ks[0] && ks[1] === 1 && ks[3])}`);
const mBal = (await read(dusd, ERC20, "balanceOf", [MERCHANT])) as bigint;
line(`  merchant dUSD .............. ${Number(mBal) / 1e6} ${ok(mBal === 60_000_000n)}`);
const [allow] = (await read(pq, PQ, "allowance", [owner, dusd, relayer])) as [bigint, number];
line(`  remaining allowance ........ ${Number(allow) / 1e6} dUSD ${ok(allow === 40_000_000n)}`);
const nonce = (await read(pq, PQ, "nonces", [owner])) as bigint;
line(`  owner permit nonce ......... ${nonce}\n`);

line(`Attacks, re-tried now as eth_call:`);
const now = BigInt(Math.floor(Date.now() / 1000));
const permit = { token: dusd, spender: "0xDc4925077A595F6029379DD7faCFBB0713218F09" as Address, amount: 40_000_000n, expiration: Number(now + 3600n), nonce, sigDeadline: now + 600n };
const text = (await read(pq, PQ, "permitText", [owner, permit])) as Hex;
const message = concat([toBytes("qorechain-msg-v1|qorechain-diana|"), toBytes(text)]);
const sim = (signature: Hex) =>
  publicClient.simulateContract({ account: relayer, address: pq, abi: PQ, functionName: "permit", args: [owner, permit, signature] });

const ownerMnemonic = process.env.OWNER_MNEMONIC?.trim();
const ecdsa = ownerMnemonic
  ? privateKeyToAccount((await deriveUnifiedAccount(ownerMnemonic, 0)).privateKey as Hex)
  : privateKeyToAccount(generatePrivateKey());
const ecdsaLabel = ownerMnemonic ? "owner's own (leaked) ECDSA key" : "an ECDSA key";
line(`  permit signed by the ${ecdsaLabel} -> ${await revertName(sim(await ecdsa.signMessage({ message: { raw: toHex(message) } })))}`);
const fake = mldsa87.keygen(crypto.getRandomValues(new Uint8Array(32)));
line(`  permit signed by an attacker's ML-DSA-87 key -> ${await revertName(sim(toHex(mldsa87.sign(fake.secretKey, message))))}`);
line(`  permit with an empty signature -> ${await revertName(sim("0x"))}`);

// The owner's real, already-used permit, taken from the chain and replayed.
const RELAYED = "0xe77f18d3451748ffed17df43ae5e3b79a8f8ea984c772835399203b9ecc403f5" as Hex;
const tx = await publicClient.getTransaction({ hash: RELAYED });
const { decodeFunctionData } = await import("viem");
const used = decodeFunctionData({ abi: PQ, data: tx.input });
line(`  replay of the owner's real ${((used.args![2] as Hex).length - 2) / 2}-byte signature -> ${await revertName(
  publicClient.simulateContract({ account: relayer, address: pq, abi: PQ, functionName: "permit", args: used.args as any }),
)} (and its nonce ${(used.args![1] as { nonce: bigint }).nonce} is already used)`);
line(`\nEverything above is read from the chain at this block.`);
