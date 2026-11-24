# PQ Permit: live testnet run (qorechain-diana, EVM 9800)

Run at 2026-11-20T22:46:51.895Z.

> **Explorer links:** [explore.qore.network](https://explore.qore.network) opens on **mainnet**. Click **Testnet** in its top bar once (it remembers the choice), then the links below resolve. EVM transactions are linked by their Cosmos transaction hash, because the explorer does not look up `0x` hashes; the link text keeps the EVM hash.

| Role | Address |
|---|---|
| Deployer / relayer / spender | `0x1D71563914D38D25b33962EC32DA9fB8F7f292C9` (`qor1r4c4vwg56wxjtveevtkr9k5lhrml9ykf6a2dqx`) |
| Owner (PQ Permit user) | `0xC9408C71DC123c611Ce29424A42273FC8669c37C` (`qor1e9qgcuwuzg7xz88zjsj2ggnnljrxnsmup7pvfa`) |
| Merchant (receives funds) | `0x737986bfc4CD9010c100C6eb0fea65F26D7c5222` |

## Part A: the hole. A leaked ECDSA key drains a standard EIP-2612 token

- deploy PermitUSD (OpenZeppelin ERC20Permit) at `0x225bff609fbd6d2fa908b5a7036db13d78ab9dc6`: [`0xe82f7d11…`](https://explore.qore.network/tx/A964DB64A5B33B169259AD6C084DDBF567A853224801D534D4FD19246A7FD918)
- mint 1000 pUSD to victim `0x893f60582E7eDc579E025fF363539b5a7A3258E2` (gas billed 150000): [`0x04b80f40…`](https://explore.qore.network/tx/6FA63C63D9F452A1BEA96B3463C48A76FBAF5FFBEA683890D807313CD3AEB47D)
The victim's ECDSA key signs a permit **offline**. The attacker relays it from their own account:
- attacker relays permit(victim → attacker, unlimited) (gas billed 150000): [`0x01e077b6…`](https://explore.qore.network/tx/666A74BDA08702EB8F4B44283DB033B0D564EF4F77075DE401A9C6321402D229)
- attacker transferFrom(victim → attacker, 1000 pUSD) (gas billed 150000): [`0x07350868…`](https://explore.qore.network/tx/19C6567E2796FF779BBCB0FE44A8AE11D6442E188A6C989ECFE25495F5E6957D)

**Result:** victim balance = **0**. The victim's EVM nonce is **0**: they never sent a transaction, had no EVM window and no PQ key. EVM windows protect transactions, not signatures.

## Part B: the fix. PQ Permit (ML-DSA-87 signed approvals)

- deploy Demo USD (no permit) at `0xed467f20f5dc4972eb3b896935d8a22565a53138`: [`0xd81a0bc8…`](https://explore.qore.network/tx/60D453F09498B0F805A40B9E9BC75B67692DD40CD1E2D253B23F578D379FFDFA)
- deploy PQPermit at `0x851a2704f0c9fc282ca1f2e28353f46e3c04a27a`: [`0x9f31c480…`](https://explore.qore.network/tx/35C1853D4E884D8C66688E3B95C5B08D2E04DE0F0779A30F90C2C31E2BAC1606)
- mint 1000 dUSD to owner (gas billed 150000): [`0x544d2831…`](https://explore.qore.network/tx/12E98C4BF9E6666CEF970AEDDFEDDE0D138FBA92591000C97CCE94E7C4BB1D68)

The owner gets 2 QOR for fees, registers an ML-DSA-87 key with proof of possession, and opens a **scoped** EVM window: 1 transaction, only to the dUSD contract.
- fund owner with 2 QOR (hybrid-signed native send): [`B0CF14BF8F…`](https://explore.qore.network/tx/B0CF14BF8FD9D01B12BBF1A3E7A48D3EBCCAE86D90DC363AF2209CA4EADE058A)
- owner opens scoped window (1 tx, allowedTargets=[dUSD], cap 30000 uqor): [`917EE88A31…`](https://explore.qore.network/tx/917EE88A31C572FD21F9F7FDBC2646752A23AAEDE09FCD1B52B05F1F60D57DCC)
- owner approves PQPermit once (the only EVM tx the owner ever sends) (gas billed 60000): [`0xab747059…`](https://explore.qore.network/tx/E9B48A5413E26A4287CAA29407CE540A40550F18A29BC7B8D472DE58060F89B4)

Owner key status from the `pqcKeyStatus` precompile: registered=true, algorithm=1, key=2592 bytes, possessionProven=true.

The owner signs this human-readable text (QoreSign message-signing-v1, the format QoreX `signArbitrary` uses; the extension doesn't support `signArbitrary` yet, so the live run signs with `@qorechain/sdk`):

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
- relayer submits PQ permit (owner sends nothing) (gas billed 1000000): [`0xe77f18d3…`](https://explore.qore.network/tx/5B2BF5A8DE1BF7FEA78758EB7C1F65DC5143BB8CA84F509D426006B6E97DC283)
- spender pulls 60 dUSD to merchant (gas billed 100000): [`0x01edf995…`](https://explore.qore.network/tx/D714BC03E8AC83BA321758B034CD65ED9427A529D288C6B74D254CE4EC08B397)

**Result:** merchant received **60 dUSD**. Remaining allowance **40 dUSD**. Real gas cost of an ML-DSA-87 permit (estimateGas): **~321331**; billed 1000000 because of the 2M limit we set (see notes).
A replay of the same signature → **reverted: InvalidNonce**

## Part C: public demo owner (2026-11-25), so anyone can sign a valid permit
The web page and `npm run verify` need an owner whose ML-DSA-87 key anyone can use. `live/demo-owner.ts` set one up:
- demo owner `0xab147494dfb095c1a086fcfefC1719e02dB1df20` (`qor14v28f9xlkz2urgyxlnl0c9ceuqkmrheqcvnl3y`); its ML-DSA-87 seed is public: `SHAKE-256("pq-permit:public-demo-owner:v1")` = `0x0abc3a8e…0da283`. Its secp256k1 key stays private and it holds no tokens.
- fund 0.25 QOR from the owner (hybrid-signed native send): [`C1C8951D…`](https://explore.qore.network/tx/C1C8951D0ECF75BF487054A48AA1C1C201DB6112C4779272BB7E8365BB4A99FF)
- register its ML-DSA-87 key with proof of possession: [`B9C8916C…`](https://explore.qore.network/tx/B9C8916C391D160193D8866EB2D347C3D3753FA13EC6CE88FBDE07DFE36196CE)
- `pqcKeyStatus`: registered, algorithm 1, possession proven, and the key equals the one derived from the public seed.

`npm run verify` now ends with the positive case, signed on the spot with `@qorechain/qoresign`:
```
A valid permit, signed now with @qorechain/qoresign by the public demo owner:
  demo owner key on chain = public seed's key . ✓
  QoreSign pqVerify (off chain) ............... ✓
  PQPermit.permit (eth_call) .................. accepted ✓
  same signature, one bit flipped -> InvalidSignature
  same signature, amount changed  -> InvalidSignature
```
The owner's own key, derived with QoreSign's canonical derivation (`npm run sign-permit`), was also checked: its permit is accepted by `eth_call`.

## Notes and findings
- **Gas billing:** on QoreChain a receipt's `gasUsed` is at least **50% of the gas limit**. Every billed figure above is exactly half the limit we set. The real cost of an ML-DSA-87 PQ permit is **~321331 gas** (`eth_estimateGas`). Set tight gas limits.
- **Scoped window:** the owner's window admitted exactly one transaction, only to the token (`allowedTargets`). After that, a direct transfer signed with the owner's ECDSA key was **refused by the chain**.
- **Precompile behaviour that differs from the docs:** see [pqc-forge](https://github.com/JahanzaibMohsin9/pqc-forge). An unknown selector reverts, non-canonical ABI input reverts, and an empty message returns false.
- Reproduce: `cd live && npm ci && npm run live` (needs a funded deployer in `live/.env`).
