# QCAI audit

The Post-Quantum dApp track asks for a **two-stage QCAI audit** (FAQ: use the **"Ethereum (EVM/Solidity)"** setting; Stage 2 is a second run after working through Stage 1's findings; zero findings is not required).

| Stage | Date | Report | Status |
|---|---|---|---|
| Stage 1 | – | `docs/audit/stage1-YYYY-MM-DD.pdf` | **to run** |
| Stage 2 | – | `docs/audit/stage2-YYYY-MM-DD.pdf` | **to run after Stage 1 fixes** |

## Stage 1 findings → resolution
Map each finding as: *fixed in commit X (with a regression test)*, *documented false positive (with the reason)*, or *accepted risk (see THREAT_MODEL.md)*.

| # | Finding | Severity | Resolution |
|---|---|---|---|
| | | | |

## Scope
- `src/PQPermit.sol`
- `lib/pqc-forge/src/PQSig.sol` (the verification library it depends on)

## Notes for the auditor
- `pqcVerify` / `pqcKeyStatus` are QoreChain precompiles at `0x…0a01` / `0x…0a02`. Static analysers see them as external calls to addresses with no code. On qorechain-diana they are active; on other networks PQSig deliberately fails closed.
- Quantum readiness shows "Not scored" for EVM settings (FAQ); that is expected.
