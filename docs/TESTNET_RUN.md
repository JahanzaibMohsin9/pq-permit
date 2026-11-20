# PQ Permit: live testnet run (qorechain-diana, EVM 9800)

Run at 2026-11-20T20:48:29.273Z.

| Role | Address |
|---|---|
| Deployer / relayer / spender | `0x1D71563914D38D25b33962EC32DA9fB8F7f292C9` (`qor1r4c4vwg56wxjtveevtkr9k5lhrml9ykf6a2dqx`) |
| Owner (PQ Permit user) | `0xC9408C71DC123c611Ce29424A42273FC8669c37C` (`qor1e9qgcuwuzg7xz88zjsj2ggnnljrxnsmup7pvfa`) |
| Merchant (receives funds) | `0x96d677f2470AdC562506985c92ff69E8a30B9dF2` |

## Part A: the hole. A leaked ECDSA key drains a standard EIP-2612 token

- deploy PermitUSD (OpenZeppelin ERC20Permit) at `0x03a0e3a88c61a269bff0afc9cee373fe61de64c8`: [`0xdc3f4d8d…`](https://explore.qore.network/tx/0xdc3f4d8d1de2530091f4a6b35b67e539e1cfdd6bedeb1b5534a98abae63ce742)
- mint 1000 pUSD to victim `0xD0A962194b95A6276bf5D4C503aC1Af3e63a2b49` (gas billed 150000): [`0x762d6bd6…`](https://explore.qore.network/tx/0x762d6bd64c03bafed2ca2a938bece118d4e51d601401d72e8e62c2c529c3aa5c)
The victim's ECDSA key signs a permit **offline**. The attacker relays it from their own account:
- attacker relays permit(victim → attacker, unlimited) (gas billed 150000): [`0x2043ee5d…`](https://explore.qore.network/tx/0x2043ee5d55ee93d2d82f21688ee8fba9d2d0e50b66ba2410f42418d5c4d3c7b9)
- attacker transferFrom(victim → attacker, 1000 pUSD) (gas billed 150000): [`0x25c0b5e5…`](https://explore.qore.network/tx/0x25c0b5e5e60d6567a298d4880c1f60a6cc53c0ee50535a30ea32d8a547e09ab7)

**Result:** victim balance = **0**. The victim's EVM nonce is **0**: they never sent a transaction, had no EVM window and no PQ key. EVM windows protect transactions, not signatures.

## Part B: the fix. PQ Permit (ML-DSA-87 signed approvals)

- deploy Demo USD (no permit) at `0x3fa22e786682951e8ea8604c52883264e57bed4c`: [`0xa59aa344…`](https://explore.qore.network/tx/0xa59aa3447ffc2270f245b2acf7ff8b8b75ee0b4dc69c6452a6a277b03a97d18e)
- deploy PQPermit at `0x1cefcba4d31480b833cc2401cc1224a8df18b5d1`: [`0x96354fa1…`](https://explore.qore.network/tx/0x96354fa14ece8ae25a4fcd784773e1ce1e9ef19e626bbf56d99cf9d13ecd8525)
- mint 1000 dUSD to owner (gas billed 150000): [`0x2ea4723e…`](https://explore.qore.network/tx/0x2ea4723eec91a1387df161104332850d3c24a64306c87888daf715487a3da51d)

The owner gets 2 QOR for fees, registers an ML-DSA-87 key with proof of possession, and opens a **scoped** EVM window: 1 transaction, only to the dUSD contract.
- fund owner with 2 QOR (hybrid-signed native send): [`0375338D5F…`](https://explore.qore.network/tx/0375338D5F9177159C9A72BF4C8ADB2CC25D6ABB8147914BC427247F76FD1363)
- owner opens scoped window (1 tx, allowedTargets=[dUSD], cap 30000 uqor): [`DDF61B7F40…`](https://explore.qore.network/tx/DDF61B7F402EF81C1D18E2B7154B95EB8ED8653D85A4A049B1B33FE075FE1C38)
- owner approves PQPermit once (the only EVM tx the owner ever sends) (gas billed 60000): [`0xc4ae9535…`](https://explore.qore.network/tx/0xc4ae9535d272c8896a321ec1791678c78d6baf28aa4cc42307f14932a6dbdff0)

Owner key status from the `pqcKeyStatus` precompile: registered=true, algorithm=1, key=2592 bytes, possessionProven=true.

The owner signs this human-readable text (QoreSign message-signing-v1, exactly what QoreX `signArbitrary` signs):

```
PQ Permit v1
chain: 9800
verifier: 0x1cefcba4d31480b833cc2401cc1224a8df18b5d1
owner: 0xc9408c71dc123c611ce29424a42273fc8669c37c
token: 0x3fa22e786682951e8ea8604c52883264e57bed4c
spender: 0x1d71563914d38d25b33962ec32da9fb8f7f292c9
amount: 100000000
allowance expires: 1795294174
nonce: 0
signature valid until: 1795211374
```

Attacks (each simulated with `eth_call` and refused, so no gas is spent):
- ECDSA signature by the owner's (leaked) key → **reverted: InvalidSignature**
- ML-DSA-87 signature by an attacker's own key → **reverted: InvalidSignature**
- Direct EVM transfer signed with the owner's leaked ECDSA key → **refused by the chain: failed to broadcast transaction: the EVM authorisation window for qor1e9qgcuwuzg7xz88zjsj2ggnnljrxnsmup7pvfa does not admit this transacti** (window: exhausted)

The owner's real ML-DSA-87 signature (4627 bytes), relayed by someone else:
- relayer submits PQ permit (owner sends nothing) (gas billed 1000000): [`0x2f9520cc…`](https://explore.qore.network/tx/0x2f9520cc10c341fcfddab84214d25dab74984cd20681a7a11492527b5ab9fe30)
- spender pulls 60 dUSD to merchant (gas billed 100000): [`0x00fd3e5a…`](https://explore.qore.network/tx/0x00fd3e5a28ec9f0679ddac50caf7f827376b09e00ddcfdeb27f5a022307a5f42)

**Result:** merchant received **60 dUSD**. Remaining allowance **40 dUSD**. Real gas cost of an ML-DSA-87 permit (estimateGas): **~285,665**; billed 1,000,000 because of the 2M limit we set (see notes).
A replay of the same signature → **reverted: InvalidNonce**

## Notes and findings
- **Gas billing:** on QoreChain a receipt's `gasUsed` is at least **50% of the gas limit**. Every billed figure above is exactly half the limit we set. The real cost of an ML-DSA-87 PQ permit is about **285,665 gas** (`eth_estimateGas`). Set tight gas limits.
- **Scoped window:** the owner's window admitted one transaction, only to the token (`allowedTargets`). After that, a direct transfer signed with the owner's ECDSA key was **refused by the chain**: "window … does not admit this transaction", classified as `exhausted`.
- **Precompile behaviour that differs from the docs** (see [pqc-forge](https://github.com/JahanzaibMohsin9/pqc-forge), `ffi/live-parity.mjs`): an unknown selector reverts, non-canonical ABI input reverts, and a valid signature over an empty message returns false.
- Reproduce: `cd live && npm ci && npm run live` (needs a funded deployer in `live/.env`).
