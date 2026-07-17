# Web subtree instructions

Read and follow the repository-wide [`AGENTS.md`](../AGENTS.md). This file adds only presentation-specific constraints.

- Import boundary-crossing shapes only from `src/lib/api/generated`; do not hand-copy DTOs or import Go/domain source.
- Keep aliases in a web-contained `tsconfig.json` or `jsconfig.json`; bundler/test alias maps are rejected because the architecture checker cannot prove their target domain.
- Keep authentication, authorization, consent, and canonical workflow decisions server-side. UI state is never authority.
- Do not proxy API or evidence traffic through the presentation deployment or expose server credentials there.
- Preserve exhaustive state rendering, keyboard access, reduced motion, responsive behavior, and safe stale/reconnect handling.
