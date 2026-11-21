# PQ Permit threat model

## Assets
Tokens the owner approved to PQ Permit, and the allowances granted from them.

## Threats
| # | Threat | Mitigation | Evidence |
|---|---|---|---|
| T1 | **Leaked or quantum-broken ECDSA key** signs an approval offline | PQ Permit accepts **only ML-DSA-87** signatures by the owner's registered key. ECDSA signatures are meaningless to it. | Live: ECDSA permit gives `InvalidSignature`. Test: `test_pqPermit_leakedEcdsaKeyCannotApprove`. |
| T2 | A leaked ECDSA key **sends a transaction** directly | QoreChain EVM windows. The owner's one-time approve runs in a **scoped** window (1 tx, token only), so nothing else is admitted. | Live: direct transfer refused (window used up). |
| T3 | An attacker signs with **their own** ML-DSA key | The key is looked up on chain for the **owner** (`pqcKeyStatus`), so other keys fail. | Live and test: `InvalidSignature`. |
| T4 | A **copied public key** is registered under another address | `possessionProven` is required. | Test: `test_rejectsKeyWithoutPossessionProof`. |
| T5 | **Replay**: same nonce, another chain, another PQ Permit deployment, another owner | Sequential nonce; the signed text binds the chain id (and the Cosmos chain id in the QoreSign prefix), the verifier address and the owner. | Tests: replay, cross-chain, cross-verifier, other owner. Live: replay gives `InvalidNonce`. |
| T6 | A signature is used **long after** it was made | `sigDeadline`; the allowance has its own `expiration`. | Tests. |
| T7 | Tampered amount or spender | All fields are inside the signed text. | Tests. |
| T8 | The owner wants to cancel | `lockdown` zeroes allowances **and** cancels every signed-but-unrelayed permit (the nonce advances by `MAX_NONCE_JUMP`). `invalidateNonces` cancels up to a chosen nonce, capped so the owner can't brick their own nonce space. | Tests: `test_lockdownCancelsSignedButUnrelayedPermits`, `test_invalidateNoncesIsCapped`. **`approve(token, spender, 0, …)` is not a revoke**: like Permit2, it doesn't cancel a permit that is signed but not yet relayed. Wallets and docs must offer `lockdown` as "revoke" (`test_review_approveZeroDoesNotRevokeASignedPermitButLockdownDoes`). |
| T9 | The precompile is **inactive** (mainnet today) and returns empty data | `PQSig` fails closed: it requires exactly 32 bytes back, otherwise it reverts. | Test: `test_failsClosedWhenPrecompileInactive`. |
| T10 | The precompile call **runs out of gas** (the caller carries on) | The call result is checked; a failure reverts. | Code (PQSig). |
| T11 | A **phishing** text: the user signs something they don't understand | The signed data is human-readable and binds every field, never a hash. It starts with `PQ Permit v1`, not a reserved `qorechain-` prefix. | `test_permitTextIsHumanReadableAndFitsQoreX`. |
| T12 | **Front-running** a permit (anyone may relay it first) | It only reproduces the same allowance. Integrators bundling `permit` and an action must tolerate `InvalidNonce` (Permit2 behaves the same way). | Documented. |
| T13 | **Fee-on-transfer tokens** | The allowance is charged the gross amount and the recipient gets the net (as in Permit2). | Documented. |

## Residual risks
1. **Tokens that keep their own EIP-2612 `permit` remain exposed** through that function. PQ Permit cannot remove it from an existing token. Use tokens without ECDSA permit (like testnet fUSD), or new tokens; check with [Permit Exposure Check](https://github.com/JahanzaibMohsin9/permit-exposure-check).
2. **Spenders are trusted up to their allowance.** Grant small, expiring allowances.
3. **Wallet support:** QoreX's `signArbitrary` is documented as not yet supported in the extension. Today owners sign with `@qorechain/sdk` / `@qorechain/qoresign` (as in `live/`). The format is already QoreX's (message-signing-v1), so no contract change is needed when wallet support lands.
4. **Mainnet:** the PQC precompiles are testnet-only until a chain upgrade, and PQ Permit fails closed there.
