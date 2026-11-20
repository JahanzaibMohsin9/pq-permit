# PQ Permit: live testnet run (qorechain-diana, EVM 9800)

Run at 2026-11-20T22:46:51.895Z.

| Role | Address |
|---|---|
| Deployer / relayer / spender | `0x1D71563914D38D25b33962EC32DA9fB8F7f292C9` (`qor1r4c4vwg56wxjtveevtkr9k5lhrml9ykf6a2dqx`) |
| Owner (PQ Permit user) | `0xC9408C71DC123c611Ce29424A42273FC8669c37C` (`qor1e9qgcuwuzg7xz88zjsj2ggnnljrxnsmup7pvfa`) |
| Merchant (receives funds) | `0x737986bfc4CD9010c100C6eb0fea65F26D7c5222` |

## Part A: the hole. A leaked ECDSA key drains a standard EIP-2612 token

- deploy PermitUSD (OpenZeppelin ERC20Permit) at `0x225bff609fbd6d2fa908b5a7036db13d78ab9dc6`: [`0xe82f7d11…`](https://explore.qore.network/tx/0xe82f7d11b94949e302c24224fe07ccdf9cb44c84cebc2bca75a7d51e289079c0)
- mint 1000 pUSD to victim `0x893f60582E7eDc579E025fF363539b5a7A3258E2` (gas billed 150000): [`0x04b80f40…`](https://explore.qore.network/tx/0x04b80f407c4fb88d0cfe3f4b4909da2d7d7e7426278be2d91bcc81092bc4830d)
The victim's ECDSA key signs a permit **offline**. The attacker relays it from their own account:
- attacker relays permit(victim → attacker, unlimited) (gas billed 150000): [`0x01e077b6…`](https://explore.qore.network/tx/0x01e077b6105d6ed5bb4597414a8a2948d281f432f0fefa98478cb862b7ac4642)
- attacker transferFrom(victim → attacker, 1000 pUSD) (gas billed 150000): [`0x07350868…`](https://explore.qore.network/tx/0x07350868864484ea0ba891b69015d8a2e6f7e0112483f359c77d670121441fae)

**Result:** victim balance = **0**. The victim's EVM nonce is **0**: they never sent a transaction, had no EVM window and no PQ key. EVM windows protect transactions, not signatures.

## Part B: the fix. PQ Permit (ML-DSA-87 signed approvals)

- deploy Demo USD (no permit) at `0xed467f20f5dc4972eb3b896935d8a22565a53138`: [`0xd81a0bc8…`](https://explore.qore.network/tx/0xd81a0bc8418ff25202ffc141c11819baa9464361058d0028c486126e41f5dace)
- deploy PQPermit at `0x851a2704f0c9fc282ca1f2e28353f46e3c04a27a`: [`0x9f31c480…`](https://explore.qore.network/tx/0x9f31c480dfea6815bd00ea7161388cf49eb5678358760fa8b17dcd518cfab518)
- mint 1000 dUSD to owner (gas billed 150000): [`0x544d2831…`](https://explore.qore.network/tx/0x544d28311f0a96d2b320cab604fee46f5ba34a6c0f4dbfed7884db186d7931d7)

The owner gets 2 QOR for fees, registers an ML-DSA-87 key with proof of possession, and opens a **scoped** EVM window: 1 transaction, only to the dUSD contract.
- fund owner with 2 QOR (hybrid-signed native send): [`B0CF14BF8F…`](https://explore.qore.network/tx/B0CF14BF8FD9D01B12BBF1A3E7A48D3EBCCAE86D90DC363AF2209CA4EADE058A)
- owner opens scoped window (1 tx, allowedTargets=[dUSD], cap 30000 uqor): [`917EE88A31…`](https://explore.qore.network/tx/917EE88A31C572FD21F9F7FDBC2646752A23AAEDE09FCD1B52B05F1F60D57DCC)
- owner approves PQPermit once (the only EVM tx the owner ever sends) (gas billed 60000): [`0xab747059…`](https://explore.qore.network/tx/0xab74705904fdddee28f91f6358d0d172e752212d2ac55c99f02bb66da1036365)

Owner key status from the `pqcKeyStatus` precompile: registered=true, algorithm=1, key=2592 bytes, possessionProven=true.

The owner signs this human-readable text (QoreSign message-signing-v1, exactly what QoreX `signArbitrary` signs):

```
PQ Permit v1
chain: 9800
verifier: 0x851a2704f0c9fc282ca1f2e28353f46e3c04a27a
owner: 0xc9408c71dc123c611ce29424a42273fc8669c37c
token: 0xed467f20f5dc4972eb3b896935d8a22565a53138
spender: 0x1d71563914d38d25b33962ec32da9fb8f7f292c9
amount: 100000000
allowance expires: 1795301261
nonce: 0
signature valid until: 1795218461
```

Attacks (each simulated with `eth_call` and refused, so no gas is spent):
- ECDSA signature by the owner's (leaked) key → **reverted: InvalidSignature**
- ML-DSA-87 signature by an attacker's own key → **reverted: InvalidSignature**
- Direct EVM transfer signed with the owner's leaked ECDSA key → **refused by the chain: failed to broadcast transaction: the EVM authorisation window for qor1e9qgcuwuzg7xz88zjsj2ggnnljrxnsmup7pvfa does not admit this transacti** (window: exhausted)

The owner's real ML-DSA-87 signature (4627 bytes), relayed by someone else:
- relayer submits PQ permit (owner sends nothing) (gas billed 1000000): [`0xe77f18d3…`](https://explore.qore.network/tx/0xe77f18d3451748ffed17df43ae5e3b79a8f8ea984c772835399203b9ecc403f5)
- spender pulls 60 dUSD to merchant (gas billed 100000): [`0x01edf995…`](https://explore.qore.network/tx/0x01edf995587765ece3ea4320b753f62b3db37f9c3bbff77dc590bfdbcd427977)

**Result:** merchant received **60 dUSD**. Remaining allowance **40 dUSD**. Real gas cost of an ML-DSA-87 permit (estimateGas): **~321331**; billed 1000000 because of the 2M limit we set (see notes).
A replay of the same signature → **reverted: InvalidNonce**

## Notes and findings
- **Gas billing:** on QoreChain a receipt's `gasUsed` is at least **50% of the gas limit**. Every billed figure above is exactly half the limit we set. The real cost of an ML-DSA-87 PQ permit is **~321331 gas** (`eth_estimateGas`). Set tight gas limits.
- **Scoped window:** the owner's window admitted exactly one transaction, only to the token (`allowedTargets`). After that, a direct transfer signed with the owner's ECDSA key was **refused by the chain**.
- **Precompile behaviour that differs from the docs:** see [pqc-forge](https://github.com/JahanzaibMohsin9/pqc-forge). An unknown selector reverts, non-canonical ABI input reverts, and an empty message returns false.
- Reproduce: `cd live && npm ci && npm run live` (needs a funded deployer in `live/.env`).
