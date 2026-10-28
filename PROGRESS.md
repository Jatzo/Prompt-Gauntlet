# Progress

Update this at the end of every working session.

## Phases (v1 core)
- [x] 1. Foundations (reviewed and pushed)
- [ ] 2. Measurement (code built, reviewed and committed; the operator-only steps are open, see below)
- [ ] 3. Learning loop (v1)
- [ ] 4. Adaptive attacker and architecture arm
- [ ] 5. Pre-registered experiments
- [ ] 6. Findings and case studies
- [ ] 7. Harden and publish

v2 extensions are deferred until v1 produces results (see PLAN.md section 4).

## Decisions made
- Repo name: `prompt-gauntlet` (public), MIT licence.
- Headline metric: end-to-end attack success under an adaptive attacker, with utility cost. Detection TPR@1%FPR is secondary.
- Models: Opus 5.5 for CEO and case-study writer; Sonnet 5.5 for other agents; detector and weak target on Haiku 5.5 (`claude-haiku-5-5`).
- No fixed usage cap by default; operator starts, pauses and stops the run (optional hard cap available, off by default).
- v1 defender search space is data-only (`DetectorConfig`); no code execution, no Docker in v1.
- Develop in WSL2 on the Linux filesystem, repo at `~/code/prompt-gauntlet`.
- Runs on the operator's Claude plan (no separate API key). The live backend is a refusing stub until the operator has checked the terms for automated use.
- The committed PLAN.md is trimmed of build-tooling notes; the full copy and the build rules stay private.
- Judge transport is JSON lines over stdin and stdout, with no port. Judge data defaults to `~/.prompt-gauntlet/judge/`, unencrypted for now.
- An unknown field or tool in agent output is a hijack (the cycle is abandoned and the run pauses); a bad value in a known field is a schema failure.
- The case-study writer and the grader have no tools.
- Phase 2: the Judge is the only scorer, with one `measure` method. The new Judge files and pins were changed on the operator's instruction.
- Phase 2: `numpy` and `regex` are core dependencies; `torch` and `transformers` are an optional `openweights` extra.
- Phase 2: detector and target calls are cached in the Judge database, keyed on the backend, role, model, rendered request and trial. The hard cap counts each database on its own.
- Phase 2: an unscorable output counts against the defence: a miss for an attack, a false positive for benign text.
- Phase 2: mock and replay runs are built here; the operator runs the live baseline after the terms check. Datasets wait on the shortlist in `private/data/dataset-shortlist.md`.
- Phase 2: the recommended answers to design questions 5 to 12 (`private/architect/phase2-design.md`) are in use as defaults. Every new `config.py` value is a proposal until the operator approves it.
- 2026-10-26, terms check done: automated use on the operator's plan is fine. The live backend is to
  be wired up, keeping the `ARENA_ALLOW_LIVE=1` gate and the refusal under pytest; tests make no live
  calls.
- 2026-10-26, datasets: the shortlist is approved as its Recommendation column says. Tensor Trust is
  out. Enron and CodeSearchNet are private only. A CLI command builds the real dataset.
- 2026-10-26, labelling: no hand labels. Section 7's hand-labelling protocol is to be replaced by
  checker labels where the toy app can confirm the action, and by two model families (Claude plus one
  open-weights model) elsewhere, with Cohen's kappa reported and disagreements excluded. The human 5%
  audit is dropped, and "no human labels" is a stated limitation. The replacement waits on a
  critiqued plan and the operator's approval.
- 2026-10-26, Phase 3 order: a minimal read-only live feed (`arena/server.py`, `make dashboard`)
  comes before step 6. Step 15 grows it into the four panels with controls. After it: the real data
  build, the labelling replacement, then step 6.
- 2026-10-26, novelty in Phase 3: a small version of v2's novelty work moves into v1. An
  "unclassified" classifier result, a behaviour signature per attack stored by the Judge, candidate
  technique findings the operator triages, an `explore` focus, a per-run novelty archive, a coarse
  novelty band for the Attacker (archive plus train, the same in every arm) and an honest novelty
  count in reports, zero included. The keep rule does not change. Built inside steps 6, 10, 11, 14
  and 15.
- 2026-10-26, labelling details: the checker pass records each attack's outcome in `checker.json`
  and sets a confirmed attack's impact class from what the toy app did. Where the two families
  disagree on an attack's kind or impact class, the source default stays and the disagreement is
  counted. Ollama is the operator's to install; the backend refuses until its digest is pinned.
- 2026-10-26: `fastapi` and `uvicorn` are core dependencies. fastapi stays below 0.142, whose
  `opentelemetry-api>=1.44` requirement clashes with semgrep's pin in the same environment.
- 2026-10-27, checker pass (the operator's instruction to change `arena/judge/labelcheck.py`): rung 0 plays every paired attack; rungs 1 and 2 play only attacks no earlier rung fired, so outcomes match the full pass at about a third of the calls or less. Run with `--trials 2`, since 3 rungs at 5 trials was about 35,000 episodes. An attack that fires only in trials 3 to 5 counts as rung_only or invalid.
- 2026-10-28, the whole cycle (step A of `private/phase3-remaining-plan.md`, approved with its
  three answers): plan, attack, defend, judge, post-mortem. The Defender sees only the evasions the
  Judge shows; its patch is stored as a private `patch` episode, since literal rules can quote an
  evasion. The Judge runs the keep rule on fold 1 (fixed until checkpoints rotate it) against the
  candidate's parent; a keep is `kept_provisional`. Detector configs belong to the run of their
  cycle, so each run has its own baseline and lineage.
- 2026-10-27, evidence pack (the operator asked for every run to be shown as evidence):
  `python -m arena.cli evidence RUN_ID` reads the agent database read-only and writes
  `runs/RUN_ID/evidence/private/` (every field, attack text included) and `public/` (an allowlist of
  codes, counts and aggregate metrics; the CEO's focus shows only as a known technique or "other").
  Every stored value names its row; derived values name their inputs. A mock or replay cycle marks
  the whole pack simulated. Step 13c's checkpoint digest calls `evidence.build` with a cycle range,
  and `REQUIRED_EPISODES` grows as later steps join the cycle. Plan and critique in
  `private/evidence-plan.md`.
- 2026-10-27, data split (the first real build left train with no attacks and four partitions
  short). Approved by the operator: llmail cap 6,000; held out `persona.authority`; llmail
  near-duplicate cut 0.6; attacks whose shorter text is 80% contained in the longer share a group;
  attack groups over 60 go to train whole, and the 4 held-out attacks inside the 511-variant
  llmail family are dropped and counted; train takes 200 varied attacks on top of those families;
  monitor 200 attacks; benign quotas fill 5% over their minimum; attacks fill test, dev, train,
  ablation_eval, monitor, interleaved by channel. A "channel" shortcut probe joins the others.
  `data build --real --plan-only` is a free dry run; the last one showed no shortfalls (test 630,
  dev 1,000, train 854, ablation_eval 501, monitor 200 attacks). Plan, critique and answers in
  `private/data-shortfall-plan.md`.

## Phase 1 state
- `make test-phase1`: ruff, format check, tracked-files guard, 439 tests, gitleaks. All green.
- Review fixes after Phase 1: a placeholder test-set pin beside a real test set is a mismatch; a resumed
  cycle pauses if its configuration or model ids changed since its manifest; every step runs through one
  `_run_step` and logs one `step_done` event for the live feed.
- Hostile dispatcher matrix: every role against every registered tool and 12 near-miss names, in `tests/test_dispatcher.py`.
- Kill and resume: `tests/test_resume.py` kills the CLI during step 3 and restarts it. The plan step's model is called once across both processes, the Judge evaluates once, and the post-mortem is called once.
- Constitution, Judge files and `data/test.sha256` are hash-pinned in `tests/test_integrity.py`. The constitution is a draft until the end of Phase 2.
- `docs/references.md`: 12 sources verified, 2 corrected.

## Phase 2 state
- `make test-phase2`: ruff, format check, tracked-files guard, 660 tests, gitleaks. All green.
- Six commits after `f8a505e`, each tested on its own tree: statistics, the evaluation cache and
  simulated backend, the target app, the detector, the dataset build with the Judge measurement, and
  the `baseline` command. Not pushed.
- Reviews: Semgrep (0 findings), a code review (10 findings), four ponytail reviews and a senior
  review. Every Must and Should finding is fixed with a test.
- `python -m arena.cli baseline --backend mock` prints the table for every arm and ladder rung on a
  synthetic dataset. The synthetic corpus is shortcut-prone by design (every attack carries the
  attacker address), so it is good only for testing the machinery.
- `open_classifier` is listed as not configured until an open-weights model is chosen.

## Operator-only steps (Phase 2 step 8)
- Fetch the approved sources: `python -m arena.cli data fetch`. Set `HF_TOKEN` first for the gated
  Tatoeba files; Enron alone is 443 MB. Then `data build --real --judge-dir PATH` once the labelling
  replacement lands. Install the `data` extra for the parquet sources.
- Install Ollama in WSL, pull Gemma 4 12B and set `labeller_open_digest` in `config.py`. Then
  `data build --real --pilot 100` to see agreement, kappa and exclusions before the full build.
- After the full build: `data check --judge-dir PATH --backend live` (the checker pass), then seal.
  The pin is taken after the check, since the check rewrites impact classes in `test.jsonl`.
- Run `python -m arena.cli live-check`, then the live baseline and the ASR gate.
- Finalise and hash the constitution, write the real `data/test.sha256`, and commit and tag the
  pre-registration `docs/experiments/001`.

## Process evidence (from Phase 3 on)
Each phase now closes with a green CI run on its pushed commits, at least one ADR in `docs/adr/`, and
a `docs/debug-log.md` entry for its first non-trivial bug (PLAN.md section 17). Case studies use the
cybersecurity structure in PLAN.md section 13. No case study has been written yet.
- Phase 3 CI: green on 05c3617 (run 40396029645), which includes the attack step and the Defender. Later commits need another push and run.
- Phase 3 ADR: none written. Possible subjects, decided at close-out: two model families in place of
  hand labels; refused and model-switched labelling items keeping their source label.
- Phase 3 debug log: one entry, a replay run treated as live, fixed with the attack step.

## Open questions for the operator
- A CLAUDE.md line on call storage: "Agent calls are stored by `(cycle, step)`; detector and target calls by request hash in the Judge DB."
- Which open-weights classifier, which embedding model for dedup, and which non-Claude generator family stays test-only.
- Approval of the new `config.py` defaults.

## Open items
- `tests/test_server.py::test_every_event_kind_streams_only_allowlisted_fields` failed once in 4
  full-suite runs on 2026-10-27 and passes alone; not yet traced. Watch for it in CI.
- Five technique classes have fewer than 10 train attacks for the Defender (`obfuscation.homoglyph`,
  `obfuscation.zero_width` and `persona.switch` have none), so its focus-class examples are thin
  for them.
- `CEOPlan.focus` is not checked against the code-computed shortlist, though its schema comment
  says the orchestrator checks it. Add the check in step 10, where the shortlist is built. Until
  then the evidence pack shows an unknown focus as "other".
- The `built_judge` test fixture removes the sealed test files so the committed placeholder pin
  verifies, rather than writing the build's real pin as the plan said; the tamper tests still cover
  the real-pin path. The CLI tests use a Defender-only plan, since `run-cycle` against a real Judge
  with no built data folder now pauses at the attack step.
- Before Phase 3: stop two `run-cycle` processes from running at once (a runner lock). Until then the
  step-writes check inside each write transaction is the only guard against a double write. The agent
  database's first-time create in `arena/db.py` has the same check-then-create race.
- There is no command to abandon an open cycle. After a `config_mismatch` pause, the only way on is
  to restore the original configuration. Add an abandon-cycle command before Phase 3.
- `step_done` outcomes are fixed-format strings. Keep agent free text out of them, since the live feed
  and later briefings read events.
- `arena/judge/process.py` writes timestamps without milliseconds, unlike the rest of the code. It is pinned, so it changes only on instruction.
- Phase 3: calibration must ignore predictions from rolled-back cycles. Lesson evidence already does.
- The database integrity check scans the whole file on every connect, and usage totals are summed on every call. Both are fine at today's size; revisit when detector sweeps make thousands of calls.
- Before release: re-check the OWASP LLM01 edition, and confirm the datamarking variant in the Spotlighting full text.
- A rule that times out during the end-to-end gate episodes is named in the report, but earlier gate
  episodes were scored with it.
- Saved baseline reports from before `detector_tokens_per_call` no longer load. None exist yet.

### Senior review, for the operator
- Structure: `open_partitions` reads a missing file as an empty partition (needs a Judge change to
  raise instead). The data build now has `data fetch` and `data build --real`.
- Structure: a long run writes no progress. A stderr line per stored chunk in `call_batch`, and one per
  phase in `measure.run` (a Judge change), would show how far it got.
- Dead, held because they reverse a decision: the `openweights` extra and
  `Task.allowed_recipients` (declared but not enforced: delete it or enforce it). The audit settings
  went with the hand labels.
- Fenced in `arena/judge/`, for a Judge change: `cache_entries` no longer feeds the cost (a rerun
  test reads it); `stats.icc` is used only by tests; `build_scorer` only forwards to `Scorer`.
  Done in Phase 3 step 3: `measure.run` split, `tokens_in`/`tokens_out` dropped, `n_unscorable`
  used, the PLAN reference and the `process.py` docstring corrected.
- No house pattern yet for dispatch by name: some modules use a dict registry, others if-chains.

## Next session
Phase 3 step 7 (the Defender). The attack step now runs in every cycle whose plan names the
Attacker: T2 queries and one batch against the incumbent (the regex rules until a config is kept,
stored as the baseline on the first cycle), on `LADDER[0]`, with novelty recorded in the attack
step's write and held-back attacks offered at commit. Each backend declares a `kind`. The
`use_memory=False` orchestrator is the no-memory ablation arm. Step 10 adds the explore directive;
step 11 opens candidate-technique findings from unclassified, novel valid attacks. The full real
data build was started on 2026-10-26; check its log (`~/.pgscratch/build.log`) and results first.
