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
- 2026-10-28, step B: the Judge measures with its own backend (`--judge simulated|live`,
  simulated by default), whatever the agents run on. Each manifest records it (schema version 4),
  a resumed cycle must keep it, and the evidence pack marks a cycle live only when its agents and
  its Judge were both live. `run --cycles N` runs cycles back to back and stops at a pause; both
  commands take `--backend live`. A live-agent run needs a calibrated novelty threshold, or the
  attack step pauses with `NotCalibrated`: settle that before the first live demo (step E).
- 2026-10-28, step C: seeded simulated agents (`arena/sim_agents.py`) for a free battle, reached
  with `--backend sim`, not by changing `--backend mock` as the plan said: the mock backend's
  scripted outputs and blocking hooks carry the kill-and-resume test. The CEO picks a focus, the
  Attacker mixes payloads the regex baseline catches with variants it misses, and the Defender picks
  from a menu of keepers, near misses, no-ops and refused patches. On the small synthetic folder,
  8 cycles against the real Judge gave one keep and seven rejects. On that folder dev holds two
  attack families, one per fold, and the regex baseline catches neither, so only a patch that
  catches both passes the replication condition.
- 2026-10-29, the arena view (replaces step D's four panels; `private/arena-view-plan.md`, approved
  with a clean-diagram look, live and replayable). Each finished cycle replays as dots from the
  Attacker through the Detector to the Target in four lanes (refused, no effect, caught, got past;
  held back ringed), then the patch at the gate and the Judge's stamp, with a scoreboard and a strip
  that replays any past cycle. `/arena/cycles` serves codes, flags and counts only, through
  `arena/arena_feed.py`; the evidence pack is unchanged. A fresh page plays only the latest cycle and
  puts the rest in the strip. The feed's status label reads "Connected" so it is never confused with
  a live run. A run_id per cycle and a run picker are left for when one database holds two runs.
- 2026-10-29, siege arena (Joe's chosen design; plan, critique and answers in
  `private/siege-plan.md`): the arena is now a ring. The blue shield carries one slot per allowed
  rule, lit for each rule in use; attacks fly from the red launch node at the ring, cut into one
  slice per technique, so a mark's position names its technique. Caught attacks stop with a cross,
  ones that get past reach the target in the centre and leave a red notch, held-back ones (which
  also got past) show an amber ring. Red, blue and purple cards give the cycle's numbers. Purple is
  now the target and the Judge, so kept cycles are purple squares. Dark only, IBM Plex served from
  two fixed font routes, every panel restyled to match. The arena feed gains `rules.cap`.
- 2026-10-29, dashboard redesign (Joe asked for motion and security role colours; plan, critique and
  answers in `private/dashboard-redesign-plan.md`): a dark-first threat console, light kept as a
  fallback. Attacker red, Defender blue, CEO purple, Judge amber, each with a shape and a name as
  well as a colour; every text colour passes AA in both modes. Each cycle replays as one sequence
  (CEO beams, comets, shield ripple or target hit, patch sweep, stamp, count-up), with a slow grid
  drift between replays. A "Motion" switch follows the computer's reduced-motion setting until the
  operator chooses; the in-app browser runs with reduced motion, which is why the first version
  looked still there. Front end only; screenshots in `docs/dashboard/` replaced.
- 2026-10-29, step D (the four-panel dashboard, PLAN section 15; plan, critique and Joe's answers
  in `private/dashboard-plan.md`): PLAN's four panels, with each part that waits on a later step
  shown as a labelled empty state. Panels read one run, the newest by default, through
  `arena/dashboard_feed.py`; only the memory panel carries agent text, shown as plain text. The
  only writes are the control flag and operator notes, through `arena/operator_writes.py`: a token
  made at server start, a matching Origin and a JSON body on every POST, no framing, a refusal on
  a missing file or another schema, notes capped at 1,000 characters and refused while a run is
  mid-cycle in a database holding more than one run. The CEO's briefing is stored before the call
  and read back on resume. The event list and the bar's counts still cover all runs, and say so.
  Screenshots in `docs/dashboard/` come from a fresh sim run and are retaken after steps 11 and 13b.
- 2026-10-29, step 10 (the CEO; Joe's step F answers): code builds the focus shortlist each
  cycle: the technique this run focused on least, the one with the most evasions shown in recent
  batches, one in the scope of the oldest active lesson, and `explore`. Ties follow the seed and a
  held-out technique is never listed. A focus off the list, a hypothesis with a token overlap of 0.7
  or more with a committed plan of the run, a cited lesson the briefing did not show, or a
  post-mortem missing a new operator note is stored as a failed attempt and asked again with the
  reason. My choices, open to change: after `plateau_switch_n` cycles with no keep the focus type
  chosen last leaves the list; after `plateau_pause_m` the run pauses with a state-of-the-lab
  report, and the count restarts after each pause. The mock plan takes the first focus its
  shortlist lists, so a long mock run follows the switch.
- 2026-10-29, step 9 (briefing and memory reads; Joe's step F answers in
  `private/phase3-remaining-plan.md`): code builds the CEO's briefing each cycle in PLAN section 9's
  order with per-section budgets; operator notes are never cut, weaker lessons go first, and agent
  text arrives datamarked. The constitution stays in the system prompt and counts against the budget.
  A prediction pairs with the dev ASR change (candidate minus incumbent, from the Judge's ASR
  condition). A cited lesson is disputed when ASR moves against the prediction beyond the CI
  half-width. Both happen at commit, so a rolled-back cycle teaches nothing. Calibration enters the
  briefing after 50 committed pairs. Rejecting a lineage disputes nothing yet: that lands with the
  review queue in 13b.
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
- 2026-10-29, placebo test (Phase 3 step 8). Approved by the operator: a `placebo` sim profile
  (attack and benign scores overlap, TPR about 0.6 at 1% FPR), 300 cycles a run, and a
  placebo-only synthetic folder five times the test sizes, from 80 extra subjects, with the
  train-only group cap raised to 120 for that folder alone. On the test-sized folder a real gain
  was kept in only 8 of 20 runs, so the number meant little. `python -m arena.cli placebo`
  builds the folder in `private/placebo/`, deletes it after, and writes aggregates to
  `runs/placebo/`. First mock run: 1 of 300 kept (0.3%, upper bound 1.6%, under the 5% limit);
  both determinism checks rejected with a gain of exactly 0; the positive control kept in 20 of
  30. The rule is cautious in mock: the ASR condition alone rejected 154 of the 300 placebo
  cycles on noise, and 10 of the 30 real gains failed on utility or category FPR. Mock draws have
  no item difficulty, so this number vouches only for simulated-Judge keeps; the real-data
  placebo stays with step 16. Plan and critique in `private/placebo-plan.md`.
- 2026-10-29, hill-climb control (Phase 3 step 8, arm C). Approved by the operator: a bank of 11
  regex rules written from the taxonomy's technique descriptions (none for a held-out technique,
  none on the attacker's address); moves over normalisers and rules only, not the classifier
  prompt; arm B now shows the Attacker its last batch as every arm does (PLAN section 14); control
  keeps are reviewed with the queue in step 13b. `run --arm full|no_memory|control`. The control
  arm makes no CEO or Defender call: the focus rotates over each cycle's shortlist, one move is
  chosen at plan time and stored privately, a move rejected against an incumbent is not tried
  again until every move has been, and there is no post-mortem, prediction or lesson. A run is one
  arm (schema 5 records the arm and the bank's hash). On the small synthetic folder a one-step
  move is rarely kept: dev holds two attack families, one per fold, so a rule for one family fails
  to replicate on fold two. Plan and critique in `private/hillclimb-plan.md`.
- 2026-10-29, a larger synthetic folder (Joe: "give dev more families"; plan and critique in
  `private/family-folder-plan.md`). Ten extra attack frames, two for each technique not held out,
  opt-in only, so the default corpus is unchanged (pinned by hash). `data build --synthetic
  --large` builds 40 subjects a family with a chosen build seed, which puts indirect.email,
  obfuscation.spacing and override.direct on both dev folds. The placebo keeps its own folder and
  result. The control still keeps nothing there: the regex baseline already catches every
  fold-one family but one, and no bank rule catches that one. Joe chose to keep the folder and
  record the limit (`docs/limitations.md`) rather than fit frames or rules to each other. The
  bank now has a frame-level test: no rule fires on another technique's frames or on benign text,
  and each fires on its own.

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
The project now runs as three parts: the static test of public attacks, the arena, and a recorded
walk-through of one injection. Direction, order and open decisions: `private/research-direction-plan.md`.
The checker pass fired 0 of 2,331 public attacks on rungs 0 and 1 (`target_strong`, `target_weak`,
strict tools); rung 2 started 2026-10-31. Why so few could fire, and the options:
`private/attack-actionability-plan.md` (option E chosen: no data changes, rung 2 on every pair).
The checker pass finished on 2026-10-31 at 17:45 UTC: rung 2 fired 649 of 2,331, so 0 confirmed,
649 on another rung only and 1,682 invalid. Every measured figure is in `docs/run-record.md`.

2026-10-31, live isolation (plan, opus critique and Joe's answer in
`private/live-tool-exposure-plan.md`): live sessions offered the operator's account connectors, and
the target tried them 113 times (all refused for want of a grant). Now `--strict-mcp-config`,
`dontAsk`, the account-connector env lock, and an init-message guard (`ToolExposure`). The Judge ends
with the CLI (`PR_SET_PDEATHSIG`). Joe chose to keep the cached checker and labelling calls rather
than pay for them again; recorded in `docs/limitations.md`.

Phase 3, in the order of `private/phase3-remaining-plan.md`. Done: steps A to D, 9 and 10, and
step 8 (the placebo in mock, and the hill-climb control). Next:
1. With Joe's yes, one `python -m arena.cli live-check` to confirm a live session's init lists only
   `StructuredOutput` with no MCP server. Then the live baseline (about 120,000 calls at 5 trials;
   no-defence arm first), the seal and pre-registration. Stop a run with
   `pkill -f "arena.cli data check"`; the Judge now goes with it.
2. Step E, the live demo: calibrate a novelty threshold first, since a live-agent run pauses with
   NotCalibrated without one.
3. Step G: 11 findings and regression tracker, 12 Researcher, 13b review queue (with the
   automated review and sampled audit for placebo and control keeps), 13c checkpoints and digests.
4. Step H, the phase close-out.
Small leftovers: retake `docs/dashboard/1-replay-in-flight.jpg` with the notes showing; dashboard
step D findings 4 (redrawing lists loses text selection) and 5 (two scripts page `/arena/cycles`
separately).
