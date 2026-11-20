# PQ Permit

**Gasless token approvals signed with ML-DSA-87, because QoreChain's EVM windows protect *transactions*, not *signatures*.**

> Build Before Q-Day · Post-Quantum dApp track

## The hole
QoreChain admits an EVM transaction only from an account with a registered ML-DSA-87 key and an open EVM window, so a leaked secp256k1 key cannot *send* anything. But **EIP-2612 `permit`** (used by most modern ERC-20s, and by Uniswap's Permit2) is checked on chain with `ecrecover`. A leaked ECDSA key signs a permit **offline**, and the attacker relays it from **their own** account. The victim never sends a transaction, so the window never gets a say.

**Proven live on testnet:** a victim with **EVM nonce 0** (no transaction ever sent, no window, no PQ key) was drained through a relayed permit. See [docs/TESTNET_RUN.md](docs/TESTNET_RUN.md), Part A.

## The fix
**PQ Permit** is a Permit2-style approval contract whose signatures are **ML-DSA-87**, checked with QoreChain's `pqcVerify` precompile against the owner's key from `pqcKeyStatus` (possession proven):

1. The owner approves PQ Permit **once**, inside a **scoped EVM window** (1 transaction, `allowedTargets=[token]`), so even the window cannot be abused afterwards.
2. From then on, approvals are **off-chain ML-DSA-87 signatures over human-readable text** (QoreSign message-signing-v1, the format QoreX uses):
   ```
   PQ Permit v1
   chain: 9800
   verifier: 0x1cef…b5d1
   owner: 0xc940…c37c
   token: 0x3fa2…ed4c
   spender: 0x1d71…92c9
   amount: 100000000
   allowance expires: 1795294174
   nonce: 0
   signature valid until: 1795211374
   ```
3. **Anyone can relay them**, so approvals are gasless for the owner. A leaked ECDSA key is worthless.

**Proven live** (Part B): ECDSA permit **rejected**, the attacker's own ML-DSA key **rejected**, a direct transfer with the leaked ECDSA key **refused by the chain** (window used up), the real ML-DSA-87 permit **works**, and a replay is **rejected**. A PQ permit costs **about 285,665 gas**.

## How it meets the track requirements
| Requirement | PQ Permit |
|---|---|
| **Scoped EVM window** | The owner's one-time `approve` goes through a window with `maxTxs=1` and `allowedTargets=[token]` (`MsgOpenEVMWindow` via `@qorechain/sdk`). A later ECDSA-signed transfer was refused live. |
| **`pqcVerify`** | `PQSig.verifyMessageBy` → `pqcKeyStatus` (registered, algorithm 1, **possession proven**) → `pqcVerify` over QoreSign bytes. It fails closed if the precompile is inactive. |
| **Two-stage QCAI audit** | `docs/audit/` and `docs/AUDIT.md` (see that file). |
| **Foundry tests** | **22 tests with real ML-DSA-87** via [pqc-forge](https://github.com/JahanzaibMohsin9/pqc-forge): forgery, replay (same nonce, cross-chain, cross-contract, another owner), expiry, a copied key without proof, an inactive precompile, overspend, lockdown, nonce invalidation, a fuzz test of allowance accounting, and the exploit itself. |

## Contracts
| File | What |
|---|---|
| `src/PQPermit.sol` | `permit` (ML-DSA-87 signature, relayable), `transferFrom` (spender), `approve`, `lockdown`, `invalidateNonces`, and `permitText` (the exact signed text). |
| `@pqc-forge/PQSig.sol` | The fail-closed verification library (from [pqc-forge](https://github.com/JahanzaibMohsin9/pqc-forge)). |
| `test/LeakedKeyExploit.t.sol` | Before and after: the EIP-2612 drain, then three failed forgeries against PQ Permit. |

### Live on qorechain-diana
| | Address |
|---|---|
| PQPermit | `0x1cefcba4d31480b833cc2401cc1224a8df18b5d1` |
| Demo USD (no permit) | `0x3fa22e786682951e8ea8604c52883264e57bed4c` |
| PermitUSD (EIP-2612, exploit demo) | `0x03a0e3a88c61a269bff0afc9cee373fe61de64c8` |

## Run
```sh
git clone --recursive https://github.com/JahanzaibMohsin9/pq-permit && cd pq-permit
(cd lib/pqc-forge && npm ci) && forge test      # 22 tests, real ML-DSA-87
cd live && npm ci && npm run live               # the testnet run (needs a funded deployer in live/.env)
```

## Findings worth knowing (measured live)
- QoreChain bills **at least 50% of the gas limit**, so set tight limits. A PQ permit really costs about 285k gas.
- The `pqcVerify` precompile **reverts on an unknown selector** and **on non-canonical ABI input**, and returns **false for an empty message**, all differently from the docs. Details are in [pqc-forge](https://github.com/JahanzaibMohsin9/pqc-forge).
- Testnet **fUSD has no `permit`**, so it is not exposed. PQ Permit gives it gasless approvals without adding the hole. To check any token, use [Permit Exposure Check](https://github.com/JahanzaibMohsin9/permit-exposure-check).

See also [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Credits
- [pqc-forge](https://github.com/JahanzaibMohsin9/pqc-forge), OpenZeppelin Contracts v5.4.0, forge-std, `@qorechain/sdk`, `@qorechain/evm`, `@qorechain/pqc` and viem.
- The Permit2 design (Uniswap) inspired the allowance model.
- The native-lane helpers are adapted from qorechain/build-before-qday (Apache-2.0).

MIT licence.
