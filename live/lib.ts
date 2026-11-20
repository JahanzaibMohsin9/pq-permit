// Shared helpers for testnet operations. Native-lane broadcast adapted from
// qorechain/build-before-qday workshop-1 scripts/window.ts (Apache-2.0).
import { StargateClient } from "@cosmjs/stargate";
import {
  EthNativeSigner,
  MSG_SEND_TYPE_URL,
  buildRegisterPqcKeyMsg,
  deriveUnifiedAccount,
  fetchPqcStatus,
  generateMnemonic,
  openEvmWindowMsg,
  signProofOfPossession,
  type UnifiedAccount,
} from "@qorechain/sdk";
import { qorechainTestnet } from "@qorechain/evm";
import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { createPublicClient, createWalletClient, http, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";

export const NET = {
  chainId: "qorechain-diana",
  rest: "https://api-testnet.qore.host",
  rpc: "https://rpc-testnet.qore.host",
} as const;
export const EXPLORER_TX = "https://explore.qore.network/tx/";

const ENV_PATH = new URL("./.env", import.meta.url);
const STATE_PATH = new URL("./state.json", import.meta.url);

/** Account from a mnemonic stored in ops/.env under `name`; created (and stored, never printed) if missing. */
export async function accountFromEnv(name: string): Promise<UnifiedAccount> {
  let m = process.env[name]?.trim();
  if (!m) {
    m = generateMnemonic();
    appendFileSync(ENV_PATH, `${name}="${m}"\n`);
    process.env[name] = m;
  }
  return deriveUnifiedAccount(m, 0);
}

export function loadState(): Record<string, string> {
  return existsSync(STATE_PATH) ? JSON.parse(readFileSync(STATE_PATH, "utf8")) : {};
}
export function saveState(s: Record<string, string>) {
  writeFileSync(STATE_PATH, JSON.stringify(s, null, 2));
}

async function accountSequence(address: string) {
  const res = await fetch(`${NET.rest}/cosmos/auth/v1beta1/accounts/${address}`);
  if (!res.ok) throw new Error(`account ${address} not found on chain (HTTP ${res.status}); fund it first`);
  const body = (await res.json()) as { account?: Record<string, unknown> };
  const acc = (body.account?.base_account ?? body.account ?? {}) as Record<string, string>;
  return { accountNumber: BigInt(acc.account_number ?? "0"), sequence: BigInt(acc.sequence ?? "0") };
}

const FEE = { amount: [{ denom: "uqor", amount: "100000" }], gas: "800000" };

export async function broadcastNative(
  acc: UnifiedAccount,
  mode: "hybrid" | "classical",
  messages: Parameters<EthNativeSigner["sign"]>[0]["messages"],
  memo = "",
): Promise<string> {
  const { accountNumber, sequence } = await accountSequence(acc.cosmos);
  const signer = new EthNativeSigner(acc, { signMode: mode, rest: NET.rest });
  const transport = await StargateClient.connect(NET.rpc);
  try {
    const res = await signer.signAndBroadcast(transport, { chainId: NET.chainId, accountNumber, sequence, fee: FEE, messages, memo });
    return res.transactionHash;
  } finally {
    transport.disconnect();
  }
}

export const sendQorMsg = (from: string, to: string, uqor: bigint) => ({
  typeUrl: MSG_SEND_TYPE_URL,
  value: { fromAddress: from, toAddress: to, amount: [{ denom: "uqor", amount: uqor.toString() }] },
});

/** Register the account's ML-DSA-87 key with proof of possession (classically signed; the one allowed case). */
export async function ensurePqcKey(acc: UnifiedAccount): Promise<string | undefined> {
  const st = await fetchPqcStatus({ rest: NET.rest, address: acc.cosmos });
  if (st.registered) return undefined;
  const proofOfPossession = signProofOfPossession({ chainId: NET.chainId, account: acc.cosmos, keypair: acc.pqc });
  return broadcastNative(acc, "classical", [buildRegisterPqcKeyMsg(acc.cosmos, { pqcKeypair: acc.pqc, proofOfPossession })]);
}

export async function openWindow(
  acc: UnifiedAccount,
  p: { blocks: bigint; maxTxs: bigint; maxValueUqor: bigint; allowedTargets?: string[] },
): Promise<string> {
  const msg = openEvmWindowMsg({
    sender: acc.cosmos,
    blocks: p.blocks,
    maxTxs: p.maxTxs,
    maxValue: p.maxValueUqor,
    ...(p.allowedTargets ? { allowedTargets: p.allowedTargets } : {}),
  });
  return broadcastNative(acc, "hybrid", [msg]);
}

export const publicClient = createPublicClient({ chain: qorechainTestnet, transport: http() });
export const walletFor = (acc: UnifiedAccount) =>
  createWalletClient({ chain: qorechainTestnet, transport: http(), account: privateKeyToAccount(acc.privateKey as Hex) });

/** EIP-1559 fees with a fixed cap, so the EVM window's value budget is predictable. */
export const FEES = { maxFeePerGas: 250_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n } as const;

export function artifact(path: string): { abi: any; bytecode: Hex } {
  const j = JSON.parse(readFileSync(new URL(`../${path}`, import.meta.url), "utf8"));
  return { abi: j.abi, bytecode: j.bytecode.object as Hex };
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
