# Engine subtree instructions

Read and follow the repository-wide [`AGENTS.md`](../../AGENTS.md). This file adds only deterministic-engine constraints.

- Keep transforms, canonical encodings, checkpoints, receipts, and gates deterministic and replayable.
- Depend on typed ports for source/target access; provider drivers remain under the corridor adapter boundary.
- Engine packages may use typed harness ports, but cannot import model/provider implementations. Agent analysis cannot alter an engine outcome or verifier proof.
- Make cancellation, retries, duplicate/stale input, crash recovery, and budget exhaustion explicit and testable.
