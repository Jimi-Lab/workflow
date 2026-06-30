# VulnGraph History Event Reconstruction v1

This engineering artifact reconstructs wrapper-owned history event evidence from existing raw candidates and the reusable Git Graph Index.

- Cases: 30
- Input candidates: 61
- HistoryEventPacketV1 generated: 61
- Strong candidates: 37
- Fallback candidates: 24
- Blame variant disagreements: 14
- Needs later event judgment: 33
- Censored packets: 0
- Forbidden scan ok: True

## Strong vs Fallback

- strong: candidates=37, disagreements=9, needs_judge=9, censored=0
- fallback: candidates=24, disagreements=5, needs_judge=24, censored=0

No model call, event judgment, final boundary validation, or version-state propagation is performed in this run.
All generated candidate lifecycles remain raw_history_event_candidate.
