# AI usage

Built with **Claude Code** (Anthropic) as a pair programmer. A human developer chose the direction, made the decisions and reviewed the work.

## Workflow
1. **Idea selection:** three rounds, each with two independent AI reviewers (a jury perspective, and an engineer who read QoreChain's source and probed the live testnet). The reviewers converged on PQ Permit and pqc-forge, and on its framing: "EVM windows protect transactions, not signatures".
2. **Code:** drafted with AI, reviewed by a human. Tests use **real ML-DSA-87**, never a mocked hash.
3. **Verified against the live chain, not assumed:**
   - the precompile's real behaviour (three differences from the docs);
   - fUSD having no permit (`eth_call`);
   - the scoped window refusing the leaked-key transfer;
   - real gas (`eth_estimateGas`).

## Bugs the process caught
- **A pre-audit review of the published repo** (by a separately prompted AI reviewer) found that `lockdown` did not cancel signed permits, that past expirations were accepted, and that nonce invalidation was unbounded. All three are fixed, each with a regression test.
- **A signing bug in the first live run (in the script, not the contract).** viem's `toBytes()` was applied to a byte array, which turned it into its text form. The contract correctly rejected the signature. It was found by isolating key against message on the live precompile, fixed, and the run repeated cleanly.
- **Misleading gas numbers:** QoreChain bills at least 50% of the gas limit. This was found by comparing receipts with `eth_estimateGas`, and the report was corrected.

## AI-generated vs human
| Part | AI | Human |
|---|---|---|
| Threat framing and design | proposed through reviews | chose |
| Solidity and tests | drafted | reviewed; ran |
| Live run script | drafted | ran on testnet; checked results |
| Docs | drafted from evidence | reviewed |
