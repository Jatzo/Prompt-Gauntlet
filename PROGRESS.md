# Progress

Update this at the end of every working session.

## Phases (v1 core)
- [x] 1. Foundations (built and checked; waiting for the operator's review)
- [ ] 2. Measurement
- [ ] 3. Learning loop (v1)
- [ ] 4. Adaptive attacker and architecture arm
- [ ] 5. Pre-registered experiments
- [ ] 6. Findings and case studies
- [ ] 7. Harden and publish

v2 extensions are deferred until v1 produces results (see PLAN.md section 4).

## Decisions made
- Repo name: `prompt-gauntlet` (public), MIT licence.
- Headline metric: end-to-end attack success under an adaptive attacker, with utility cost. Detection TPR@1%FPR is secondary.
- Models: Opus 5.5 for CEO and case-study writer; Sonnet 5.5 for other agents; detector and weak target on Haiku 4.5 (`claude-haiku-4-5-20251001`), because there is no Haiku 5.5.
- No fixed usage cap by default; operator starts, pauses and stops the run (optional hard cap available, off by default).
- v1 defender search space is data-only (`DetectorConfig`); no code execution, no Docker in v1.
- Develop in WSL2 on the Linux filesystem, repo at `~/code/prompt-gauntlet`.
- Runs on the operator's Claude plan (no separate API key). The live backend is a refusing stub until the operator has checked the terms for automated use.
- The committed PLAN.md is trimmed of build-tooling notes; the full copy and the build rules stay private.
- Judge transport is JSON lines over stdin and stdout, with no port. Judge data defaults to `~/.prompt-gauntlet/judge/`, unencrypted for now.
- An unknown field or tool in agent output is a hijack (the cycle is abandoned and the run pauses); a bad value in a known field is a schema failure.
- The case-study writer and the grader have no tools.

## Phase 1 state
- `make test-phase1`: ruff, format check, tracked-files guard, 432 tests, gitleaks. All green.
- Hostile dispatcher matrix: every role against every registered tool and 12 near-miss names, in `tests/test_dispatcher.py`.
- Kill and resume: `tests/test_resume.py` kills the CLI during step 3 and restarts it. The plan step's model is called once across both processes, the Judge evaluates once, and the post-mortem is called once.
- Constitution, Judge files and `data/test.sha256` are hash-pinned in `tests/test_integrity.py`. The constitution is a draft until the end of Phase 2.
- `docs/references.md`: 12 sources verified, 2 corrected.

## Open items
- `arena/judge/process.py` writes timestamps without milliseconds, unlike the rest of the code. It is pinned, so it changes only on instruction.
- Phase 3: calibration must ignore predictions from rolled-back cycles. Lesson evidence already does.
- Phase 2: the database integrity check scans the whole file on every connect, and usage totals are summed on every call. Both are fine at today's size; revisit when detector sweeps make thousands of calls.
- Before release: re-check the OWASP LLM01 edition, and confirm the datamarking variant in the Spotlighting full text.

## Next session
Review Phase 1. Then start Phase 2 (measurement).
