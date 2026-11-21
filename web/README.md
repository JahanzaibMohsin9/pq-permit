# PQ Permit web

A small page for PQ Permit on qorechain-diana. Live: **https://jahanzaibmohsin9.github.io/pq-permit/**

1. **Live proof.** Your browser re-reads the testnet run and re-tries the attacks with `eth_call`, so nothing is sent:
   - the ECDSA permit;
   - an attacker's ML-DSA-87 signature, generated in the browser;
   - a replay of the owner's real signature, read from the chain.
2. **Check an account.** For any `0x` or `qor1` owner, or your QoreX account, it shows the ML-DSA-87 key status (`pqcKeyStatus`), the next permit nonce and allowances.
3. **Compose and check a permit.** The contract's `permitText` writes the exact text to sign. The owner signs it with `npm run sign-permit` in `../live`, because QoreX doesn't support `signArbitrary` yet. The page then checks the signature on chain with `eth_call`.

```sh
npm ci && npm run dev          # http://localhost:5173/pq-permit/
BASE=/ npm run build           # for hosts that serve from the root
```
The EVM JSON-RPC allows CORS, so the page needs no proxy. GitHub Pages deploys it from `.github/workflows/pages.yml`.
