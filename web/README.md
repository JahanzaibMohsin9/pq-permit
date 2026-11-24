# PQ Permit web

A small page for PQ Permit on qorechain-diana. Live: **https://jahanzaibmohsin9.github.io/pq-permit/**

1. **Live proof.** Your browser re-reads the testnet run and re-tries the attacks with `eth_call`, so nothing is sent:
   - the ECDSA permit;
   - an attacker's ML-DSA-87 signature, generated in the browser;
   - a replay of the owner's real signature, read from the chain.
   It ends with the positive case: a fresh permit signed in the browser by the **public demo owner** is accepted.
2. **Check an account.** For any `0x` or `qor1` owner (parsed with `@qorechain/qoresign`), your QoreX account (`@qorechain/qorex-types`), or the public demo owner, it shows the ML-DSA-87 key status (`pqcKeyStatus`), the next permit nonce and allowances.
3. **Compose, sign and check a permit.** The contract's `permitText` writes the exact text to sign.
   - **Public demo owner:** the page signs it with `@qorechain/qoresign` (`pqSign` over `messagePqSignBytes`). The demo owner's ML-DSA-87 seed is public on purpose, `SHAKE-256("pq-permit:public-demo-owner:v1")`, its key is registered on chain with proof of possession, and it holds no tokens. Set up by [`../live/demo-owner.ts`](../live/demo-owner.ts).
   - **QoreX:** "Sign with QoreX" asks the wallet's native `signArbitrary`. QoreX refuses it for now, and the page shows the wallet's answer.
   - **Your own key:** `npm run sign-permit` in `../live` (QoreSign's canonical key derivation, checked against the key registered on chain).

   The signature is then checked twice: by QoreSign `pqVerify` in the browser against the owner's on-chain key, and by the deployed contract with `eth_call`.

```sh
npm ci && npm run dev          # http://localhost:5173/pq-permit/
BASE=/ npm run build           # for hosts that serve from the root
```
The EVM JSON-RPC allows CORS, so the page needs no proxy. GitHub Pages deploys it from `.github/workflows/pages.yml`.
