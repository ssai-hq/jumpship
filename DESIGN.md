# Jumpship Product Design Baseline

Status: architecture baseline only; P22 owns executable visual implementation and qualification.

## Product scene

The primary interaction is a calm, Codex-like migration workspace: one left-sidebar migration thread, one dominant conversation, sparse evidence-linked state, and detail on demand. Custody and connection setup render inline in the new thread. Live attempts become timeline widgets; failed attempts freeze into expandable, causally linked stubs. Sync health remains pinned while CDC is active. Consent takes over the full screen because it is an evidence review and authorization event, not a routine card.

Reports are derivatives, not the main product. Canonical readiness, integrity, deletion, and dossier artifacts always exist, while PDF or Markdown rendering happens only after an explicit make-report action.

## Authority legibility

Every surface must visibly distinguish:

- Jumpship recommendation from customer decision;
- draft PR publication from customer validation, merge, and deployment;
- advisory external review from approval;
- authenticated decisions from the two consent kinds;
- current evidence from stale, pending, degraded, or blocked state;
- reversible work from doors that are closing or closed.

Approval stays disabled while computations or user threads are unresolved. Reject, override, and postpone remain available. Unknown state renders as unsupported or blocked, never as a silent fallback.

## Visual system contract

- Tiempos Text is the selected editorial face, paired with Geist Sans and Geist Mono. Production Tiempos self-hosting remains blocked until ADR-018's webfont license and asset-provenance gate is actually accepted; no repository file implies that evidence already exists.
- The palette is warm, neutral, and expressed as future OKLCH tokens. Decorative gradients are prohibited; a structural grid treatment may be used only where it carries layout meaning.
- The radius hierarchy is closed at 6, 9, 12, 14, 16, and 18 pixels.
- Frosted chrome is limited to approved navigation/overlay surfaces with white hairlines, restrained blur, and opaque fallbacks. Dense reading or dark-focus surfaces remain opaque.
- Lucide is the base icon set; Lucide Animated is reserved for meaningful state transitions. Provider marks require recorded provenance.
- Motion is manual or pausable, respects reduced-motion preferences, and never carries the only representation of state.
- Responsive layouts preserve reading order, keyboard reachability, compact-scale legibility, touch targets, contrast, and visible focus.

P22 must bind executable tokens, UI catalogue fixtures, visual baselines, accessibility evidence, and font provenance to this file. Until then this is a design contract, not a claim that the UI exists.
