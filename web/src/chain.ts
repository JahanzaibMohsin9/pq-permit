import { messagePqSignBytes, pqKeyFromSeed } from "@qorechain/qoresign";
import { QORECHAIN_TESTNET_CHAIN_ID } from "@qorechain/qorex-types";
import {
  BaseError,
  ContractFunctionRevertedError,
  createPublicClient,
  defineChain,
  hexToBytes,
  http,
  parseAbi,
  type Address,
  type Hex,
} from "viem";
import { pqPermitAbi } from "./abi.ts";

export const diana = defineChain({
  id: 9800,
  name: "QoreChain testnet (qorechain-diana)",
  nativeCurrency: { name: "QOR", symbol: "QOR", decimals: 18 },
  rpcUrls: { default: { http: ["https://evm-testnet.qore.host"] } },
});
export const client = createPublicClient({ chain: diana, transport: http() });

/** The live deployment from docs/TESTNET_RUN.md. */
export const LIVE = {
  pqPermit: "0x851a2704f0c9fc282ca1f2e28353f46e3c04a27a",
  dusd: "0xed467f20f5dc4972eb3b896935d8a22565a53138",
  pusd: "0x225bff609fbd6d2fa908b5a7036db13d78ab9dc6",
  owner: "0xC9408C71DC123c611Ce29424A42273FC8669c37C",
  relayer: "0x1D71563914D38D25b33962EC32DA9fB8F7f292C9",
  victim: "0x893f60582E7eDc579E025fF363539b5a7A3258E2",
  merchant: "0x737986bfc4CD9010c100C6eb0fea65F26D7c5222",
  relayedPermitTx: "0xe77f18d3451748ffed17df43ae5e3b79a8f8ea984c772835399203b9ecc403f5",
} as const satisfies Record<string, Address | Hex>;

/**
 * Public demo owner (live/demo-owner.ts). Its ML-DSA-87 seed is public on purpose:
 * SHAKE-256("pq-permit:public-demo-owner:v1", 32 bytes). It is registered on chain with proof of possession and
 * holds no tokens, so anyone can sign a real, valid permit for it in the browser.
 */
export const DEMO = {
  owner: "0xab147494dfb095c1a086fcfefC1719e02dB1df20" as Address,
  seed: "0x0abc3a8e1d33a581539a0e14ff05969c39648dcf33b41cc93f03e179d70da283" as Hex,
};
export const demoKey = () => pqKeyFromSeed(hexToBytes(DEMO.seed));

export const CHAIN_ID = QORECHAIN_TESTNET_CHAIN_ID; // "qorechain-diana"

export const REPO = "https://github.com/JahanzaibMohsin9/pq-permit";
export const VIDEO = "https://youtu.be/FMYFrOpnuGQ";

export const erc20Abi = parseAbi([
  "function balanceOf(address) view returns (uint256)",
  "function decimals() view returns (uint8)",
  "function symbol() view returns (string)",
]);
export const keyStatusAbi = parseAbi(["function pqcKeyStatus(address) view returns (bool, uint8, bytes, bool)"]);
export const PQC_KEY_STATUS = "0x0000000000000000000000000000000000000a02" as const;
export { pqPermitAbi };

export type PermitSingle = { token: Address; spender: Address; amount: bigint; expiration: number; nonce: bigint; sigDeadline: bigint };

/** QoreSign message-signing-v1 (@qorechain/qoresign): "qorechain-msg-v1|qorechain-diana|" + text, the bytes PQSig.sol verifies. */
export const qoreSignBytes = (textHex: Hex) => messagePqSignBytes(CHAIN_ID, hexToBytes(textHex));

export async function keyStatus(account: Address) {
  const [registered, alg, pubkey, proven] = (await client.readContract({
    address: PQC_KEY_STATUS,
    abi: keyStatusAbi,
    functionName: "pqcKeyStatus",
    args: [account],
  })) as [boolean, number, Hex, boolean];
  return { registered, alg, pubkey, keyBytes: (pubkey.length - 2) / 2, proven, ready: registered && alg === 1 && proven };
}

/** Name of the custom error a call reverts with, "OK" if it succeeds. */
export async function outcome(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return "OK";
  } catch (e) {
    if (e instanceof BaseError) {
      const rev = e.walk((x) => x instanceof ContractFunctionRevertedError) as ContractFunctionRevertedError | null;
      if (rev?.data?.errorName) return rev.data.errorName;
      return e.shortMessage;
    }
    return String(e);
  }
}

export const simulatePermit = (owner: Address, p: PermitSingle, signature: Hex) =>
  client.simulateContract({ account: LIVE.relayer, address: LIVE.pqPermit, abi: pqPermitAbi, functionName: "permit", args: [owner, p, signature] });
