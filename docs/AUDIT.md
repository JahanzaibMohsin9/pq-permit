# QCAI audit

The Post-Quantum dApp track asks for a **two-stage QCAI audit**. Both stages use the **"Ethereum (EVM/Solidity)"** setting, as the Builder FAQ recommends. Quantum readiness shows "Not scored" for EVM settings; the FAQ says that is expected, so the PQC design is explained [below](#pqc-design-where-the-precompiles-are-called).

| Stage | Date | Report | Score | Findings |
|---|---|---|---|---|
| Stage 1 | 2026-11-21 | [`audit/stage1-2026-11-21.pdf`](audit/stage1-2026-11-21.pdf) | 85/100 (risk: medium) | 1 high, 2 medium, 1 low, 1 info |
| Stage 2 | 2026-11-21 | [`audit/stage2-2026-11-21.pdf`](audit/stage2-2026-11-21.pdf) | 85/100 (risk: medium) | 1 high, 2 medium, 1 low |

**Audited code.** One file, `PQPermit.audit.sol`, pasted into QCAI. It is the three sources below concatenated without changes; OpenZeppelin v5.4.0 is left as imports.
- `lib/pqc-forge/src/IQorePQC.sol`
- `lib/pqc-forge/src/PQSig.sol`
- `src/PQPermit.sol`

The report's line numbers refer to that file, so findings are matched here by function.

## Stage 1 findings and what we did

All five findings were worked through. None needed a change to the contract: each one is intended behaviour, or is already prevented by the language or the design. Every finding now has a regression test that proves it, so the source and the live deployment (`0x851a2704f0c9fc282ca1f2e28353f46e3c04a27a`) are unchanged.

| # | QCAI finding | Severity | Resolution | Regression test (in `test/PQPermit.t.sol`) |
|---|---|---|---|---|
| QCAI-1 | Missing access control on `permit` | HIGH | **False positive, by design.** See [QCAI-1](#qcai-1). | `test_qcai1_anyCallerCanRelayButOnlyTheSignedSpenderGetsTheAllowance`, plus the existing `test_rejectsSignatureFromAnotherKey`, `test_rejectsTamperedSpender`, `test_rejectsTamperedAmount`, `test_rejectsTamperedTokenExpirationOrDeadline`, `test_rejectsSignatureForAnotherOwner` |
| QCAI-2 | Front-running of `permit` | MEDIUM | **Accepted and documented. No loss of funds is possible.** See [QCAI-2](#qcai-2). | `test_qcai2_frontRunnerProducesTheSameStateAndTheLateCopyRevertsHarmlessly` |
| QCAI-3 | Potential overflow in nonce management | MEDIUM | **False positive.** See [QCAI-3](#qcai-3). | `test_qcai3_nonceArithmeticRevertsInsteadOfWrapping`, `testFuzz_qcai3_nonceOnlyGrowsAndIsBoundedPerCall`, `test_invalidateNoncesIsCapped`, invariant `invariant_nonceIsMonotonic` |
| QCAI-4 | Unbounded loop in `lockdown` | LOW | **Accepted, no contract change needed.** See [QCAI-4](#qcai-4). | `test_qcai4_lockdownCostIsLinearAndOnlyAffectsTheCaller` |
| QCAI-5 | Compliance with a Permit2-like interface | INFO | **Intentional divergence.** See [QCAI-5](#qcai-5). | `test_permitTextIsHumanReadableAndFitsQoreX` |

### QCAI-1
`permit` is meant to be callable by anyone; that is what makes approvals gasless (Permit2 works the same way). The access control is the owner's **ML-DSA-87 signature**. It covers the chain, this verifier contract, owner, token, spender, amount, expiry, nonce and deadline, and it is checked against the key registered for the owner on chain.

So a caller can only submit what the owner signed:
- the allowance goes to the signed spender, never to the caller;
- any change to a signed field gives `InvalidSignature`.

### QCAI-2
A front-runner can only submit the owner's own signed permit, so the state it produces is the one the owner asked for. The honest relayer's late copy reverts with `InvalidNonce`, and no tokens move. The contract's NatSpec tells integrators that bundle `permit` with another action to tolerate `InvalidNonce` when the allowance is already in place. A commit-reveal scheme or time delay, as suggested, would break single-transaction gasless relaying and protect no value.

### QCAI-3
Solidity 0.8 arithmetic is checked, so a nonce can never wrap. The test forces a nonce near `type(uint256).max` and shows `lockdown` **reverts** instead of resetting the nonce space.

Nonces can only grow:
- `invalidateNonces` is capped at `MAX_NONCE_JUMP` (65,535) per call;
- `lockdown` adds exactly `MAX_NONCE_JUMP`.

Reaching 2^256 would take about 1.8 × 10^72 transactions.

### QCAI-4
The loop runs over the **caller's own calldata** and writes only the **caller's own** allowances. It reads no shared or unbounded storage, so its cost is paid by, and bounded for, the caller alone. No one else can be blocked. Measured cost is under 30,000 gas per pair; 200 pairs fit easily in a block.

A hard cap was not added, because an owner under attack should be able to revoke everything in one call. It would also change the deployed bytecode for no security gain.

### QCAI-5
PQ Permit keeps Permit2's model: allowances, expirations, nonces, `transferFrom` by the spender, `lockdown` and `invalidateNonces`. It deliberately **replaces the EIP-712 ECDSA signature** with an ML-DSA-87 signature over human-readable text (QoreSign message-signing-v1), because ECDSA is exactly what a quantum attacker breaks. Signature-level compatibility with Permit2 is therefore a non-goal. The function shapes stay close, so integrators can reuse Permit2 patterns.

## Stage 2: after working through Stage 1

Stage 2 used the same setting on the same file. The contract source is unchanged: Stage 1 was worked through with explanations and regression tests, and the FAQ counts all of these as valid. It scored **85/100 with 4 findings, down from 5**. The informational Permit2-compatibility note is gone. The other four are the Stage 1 items again, sometimes reworded. QCAI's line numbers don't match the audited file (line 157 is an error declaration, for example), so they are matched by title:

| Stage 2 finding | Severity | Same as | Resolution |
|---|---|---|---|
| Missing access control on critical functions; it suggests `onlyOwner` | HIGH | QCAI-1 | **False positive, by design.** Stage 2 now points at the self-service functions (`lockdown`, `invalidateNonces`, `approve`) as well as `permit`. They act only on `msg.sender`'s own nonce and allowances. PQ Permit deliberately has **no owner or admin**: an `onlyOwner` role would add a central key that could freeze everyone's approvals. New test: `test_qcai1_selfServiceFunctionsOnlyTouchTheCaller` (a stranger calling all three changes only their own state). |
| Potential overflow in nonce management | MEDIUM | QCAI-3 | Checked arithmetic, so it reverts instead of wrapping; growth per call is bounded (tests listed above). |
| Front-running in `permit` | MEDIUM | QCAI-2 | The front-runner can only submit the owner's own signed permit, and the state is identical (test above). |
| Unbounded loop in `lockdown` | LOW | QCAI-4 | The loop runs over the caller's own input and state, and its gas is linear (test above). |

**Result:** no finding remains that needs a code change. Every finding from both stages is covered by a named regression test, and there are **36 tests**, all passing.

## PQC design: where the precompiles are called

The FAQ asks for this section, because QCAI cannot score PQC on EVM settings.

| Call | Where | What it protects | Tests |
|---|---|---|---|
| `pqcKeyStatus(owner)` (`0x…0a02`) | `PQSig.registeredKey`, called from `PQPermit.permit` through `PQSig.verifyMessageBy` | Signatures are only checked against the key the **chain** has registered for the owner. The algorithm must be ML-DSA-87 (id 1) and **possession must be proven**. An attacker cannot supply their own key, and a key copied without its proof is refused. | `test_rejectsUnregisteredOwner`, `test_rejectsKeyWithoutPossessionProof`, `test_rejectsSignatureForAnotherOwner`, `test_failsClosedWhenPrecompileInactive` |
| `pqcVerify(pubkey, sig, msg)` (`0x…0a01`) | `PQSig.verify`, called from `PQPermit.permit` | The owner's ML-DSA-87 signature over `"qorechain-msg-v1|" + cosmosChainId + "|" + permitText(...)`. That text binds chain, verifier contract, owner, token, spender, amount, expiry, nonce and deadline. | `test_rejectsSignatureFromAnotherKey`, all `test_rejectsTampered*`, `test_rejectsCrossChainReplay`, `test_rejectsSignatureForAnotherVerifierContract`, `test_rejectsReplay`, `test_rejectsWrongSizeSignature`, `test_relayedPermitThenSpend`, `test_pqPermit_leakedEcdsaKeyCannotApprove` |

**Fail-closed behaviour.**
- If either precompile is missing or returns an unexpected shape, PQSig **reverts** (`PqcPrecompileUnavailable`). It never treats that as a valid signature.
- `pqcVerify` must return exactly 32 bytes.
- Unknown chains revert (`UnknownChain`).

Behaviour checked on the live chain differs from the docs in a few places: an unknown selector reverts, non-canonical ABI input reverts, and an empty message returns false. These are reproduced in [pqc-forge](https://github.com/JahanzaibMohsin9/pqc-forge).

All tests use **real ML-DSA-87** (FIPS 204) through pqc-forge, which is checked against the official test vectors and against the live chain. That includes the stateful invariant suite (`test/PQPermit.invariant.t.sol`).

## Cryptographic inventory (QoreScan CBOM)

[`cbom.json`](cbom.json) is a CycloneDX 1.6 CBOM written by QoreScan Community (`@qorechain/qorescan`, `cd live && npm run cbom`). It scans the audited Solidity (`src/`, `PQSig.sol`, `IQorePQC.sol`) and reads live testnet state: the active precompiles and the registered keys of the owner, the public demo owner and the relayer. It records:
- **ML-DSA-87** at `pqcVerify` (`0x…0a01`) and `pqcKeyStatus` (`0x…0a02`), where `IQorePQC.sol` declares them and `PQSig.sol` imports them, plus each account's registered key;
- the classical algorithms that remain: secp256k1 ECDSA and Keccak-256 on the EVM lane, and Ed25519 for validator consensus keys.

It is an inventory aid, not a certification; it complements the audit above.

## Scope and notes
- In scope: `src/PQPermit.sol` and `lib/pqc-forge/src/PQSig.sol` (with `IQorePQC.sol`).
- `pqcVerify` and `pqcKeyStatus` are QoreChain precompiles. Static analysers see them as external calls to addresses with no code. They are active on qorechain-diana.
- Threat model and residual risks: [`THREAT_MODEL.md`](THREAT_MODEL.md).
