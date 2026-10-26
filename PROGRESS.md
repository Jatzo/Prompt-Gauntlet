# Progress

Update this at the end of every Claude Code session.

## Phases (v1 core)
- [ ] 1. Foundations
- [ ] 2. Measurement
- [ ] 3. Learning loop (v1)
- [ ] 4. Adaptive attacker and architecture arm
- [ ] 5. Pre-registered experiments
- [ ] 6. Findings and case studies
- [ ] 7. Harden and publish

v2 extensions are deferred until v1 produces results (see PLAN.md section 4).

## Decisions made
- Repo name: `prompt-gauntlet` (public)
- Headline metric: end-to-end attack success under an adaptive attacker, with utility cost. Detection TPR@1%FPR is secondary.
- Models: Opus 5.5 for CEO and case-study writer; Sonnet 5.5 for other agents; detector and target models configurable
- No fixed usage cap by default; operator starts, pauses and stops the run (optional hard cap available, off by default)
- v1 defender search space is data-only (`DetectorConfig`); no code execution, no Docker in v1
- Develop in WSL2 (recommended)
- Runs on the operator's Claude plan (no separate API key)

## Next session
Start Phase 1 in plan mode.
