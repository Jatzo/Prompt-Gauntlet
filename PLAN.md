# Prompt Gauntlet: Project Plan

Repo: `prompt-gauntlet`

> Self-improving prompt-injection defence. A CEO agent, an attacker, a defender and a judge race each other while a live dashboard shows the arms race, and the system writes up every weakness it finds and fixes.

Suggested GitHub topics: `prompt-injection`, `llm-security`, `red-teaming`, `ai-agents`, `multi-agent`, `adversarial-ml`, `evals`.

An autonomous, goal-driven system that makes itself better at detecting prompt injection, and writes up what it learns. One CEO agent, four sub-agents, a live dashboard, and an automatic case-study engine.

This file is the handoff document for Claude Code. Build it phase by phase (section 12). Do not skip the guardrails in section 7.

---

## 1. Purpose

Three things at once:

1. **Learn.** Become genuinely expert in prompt injection (attack and defence) by building the thing that studies it.
2. **CV.** Produce measurable results and published case studies: "found weakness X, here's the attack, root cause, fix, before/after numbers."
3. **Spectacle.** A live UI where you can watch an attacker and defender co-evolve.

Everything runs against our own sandboxed defenders guarding a dummy canary secret. No real systems, no real credentials, no third-party targets.

## 2. The goal (what the CEO is given)

> Maximise the defender's block rate on the frozen held-out attack set while keeping the false-positive rate on benign inputs at or below 1%. You run until the operator pauses or stops you, and you keep a lab notebook. Work out the rest yourself. Every confirmed weakness you find and fix must be written up as a case study.

The CEO is never given a task list. It forms hypotheses, chooses experiments, allocates budget, and decides when to stop.

## 3. Learning path (the "become a master" track)

The project is organised around a taxonomy so coverage is visible and gaps are obvious. The dashboard shows a coverage heatmap: technique class × (attack success rate, detection rate).

**Taxonomy (build the labelled dataset around this):**
- **Direct injection**: instruction override, role/persona switching, fake system messages, authority claims
- **Indirect injection**: payload hidden in web pages, emails, documents, tool outputs, retrieved RAG chunks, filenames, metadata
- **Obfuscation**: case/spacing tricks, leetspeak, zero-width characters, homoglyphs, base64/rot13/hex, translation, payload splitting across fields
- **Delimiter and format abuse**: fake end-of-prompt markers, markdown/HTML/JSON/XML smuggling, comment injection
- **Multi-turn and persistence**: instructions planted early, "sleeper" payloads, memory poisoning
- **Tool and agent attacks**: tool-description poisoning (MCP), confused deputy, argument injection, cross-tool chaining
- **Exfiltration channels**: markdown image/link beacons, tool-call parameters, encoded output
- **Goal hijacking vs. data theft vs. denial of service** (classify by *impact*, not only technique)

**Structured study (do alongside the build, one item per week):**
1. Read the OWASP Top 10 for LLM Applications (LLM01: Prompt Injection) and the foundational indirect-injection paper (Greshake et al., 2023).
2. Study defences by name and implement a small version of each as a Defender strategy: **spotlighting/datamarking**, **instruction hierarchy**, **dual-LLM / privilege separation**, **CaMeL-style capability control**, **output filtering**, **canary tokens**, **classifier-based screening**.
3. Study the evaluation work: AgentDojo, InjecAgent, BIPIA. Learn how they define attack success and utility loss. Mirror their metrics.
4. Follow Simon Willison's writing on the "lethal trifecta" (private data + untrusted content + external communication) and use it as your threat-modelling lens for every case study.
5. Play public CTF-style challenges (e.g. Gandalf-type games) and log what you learn in the notebook by hand. Only use platforms that explicitly invite it.
6. Keep a personal **technique journal**: each time the arena discovers something, write in your own words why it worked. That habit is the mastery.

(Verify every link and title before citing; the field moves fast.)

## 4. Architecture

```
                 ┌────────────────────────────┐
                 │  CEO agent (strong model)  │
                 │  goal + budget + notebook  │
                 └──────────────┬─────────────┘
          assigns experiments   │   reads results, writes decisions
     ┌───────────┬──────────────┼──────────────┬────────────┐
 ┌───▼────┐ ┌────▼─────┐ ┌──────▼─────┐ ┌──────▼────┐
 │Research│ │ Attacker │ │  Defender  │ │   Judge   │
 └───┬────┘ └────┬─────┘ └──────┬─────┘ └──────┬────┘
     │ (read-only web)  │ (attack lib)    │ (sandboxed)   │ (frozen, code-first)
     └──────────────────┴────────┬────────┴───────────────┘
                          SQLite (single source of truth)
                                 │
                   FastAPI + SSE ─► Dashboard UI
                                 │
                        Case-study engine ─► docs/case-studies/*.md
```

### Agents and permissions

| Agent | Job | Can touch | Cannot touch |
|---|---|---|---|
| **CEO** | Strategy, budget allocation, reads results, writes decision log, triggers case studies | Notebook, experiment queue, budget | Judge, frozen test set |
| **Researcher** | Turns papers, public datasets, security write-ups into new attack techniques and labelled examples | Web (read-only, via the firewall) | Code execution, defender internals |
| **Attacker** | Invents and mutates injections to evade the *current* defender | Attack library | Judge, defender code, test set |
| **Defender** | Proposes detection changes (rules, prompts, classifiers, layered strategies) | Defender config/code in a sandbox, no network | Test set, scorer |
| **Judge** | Scores everything. Plain code; LLM only to grade ambiguous outcomes | Scoring | Nobody can modify it, including the CEO |

Default models, all set per role in config: **Opus 5.5** for the CEO and the case-study writer; **Sonnet 5.5** for the Researcher, Attacker, Defender agent and Judge-ambiguity grading. The **detector under test** is a separate setting from the Defender agent (default: a small fast model such as Haiku 5.5). Benchmark two or three detector models and report each one.

Auth: a project calling the Anthropic SDK normally needs an API key, and that is billed separately from a Claude subscription. If you want to run off your plan instead, drive Claude Code / the Agent SDK signed in to your account, after checking Anthropic's current terms. Put all model calls behind one `llm.py` interface so the backend can be swapped without touching the agents.

## 5. Data model (SQLite, WAL mode)

- `events(id, ts, cycle, agent, kind, payload_json)`: everything shown in the live feed
- `experiments(id, cycle, hypothesis, diff, dev_before, dev_after, fpr_after, decision, defender_version, commit_sha)`
- `scores(ts, cycle, split, block_rate, fpr, defender_version)`: `split` is `dev` or `frozen`
- `attacks(id, text, technique, impact_class, source, split, evaded_versions_json)`
- `defender_versions(version, config_json, parent, created_by_experiment)`
- `elo(ts, entity, rating)`: attacker strategies and defender versions
- `notebook(id, ts, cycle, author, text)`: the CEO's persistent memory
- `findings(id, title, technique, severity, status, first_seen_cycle, fixed_in_version, case_study_path)`
- `budget(tokens_used, steps_used, started_at)` and `control(key, value)` for pause/stop

## 6. Datasets and splits

- **Seed from public labelled datasets** (check each licence): e.g. deepset prompt-injections, BIPIA, InjecAgent, AgentDojo task suites. Add a generated set from the taxonomy templates.
- **Three splits:** `train` (agents can see and learn from), `dev` (keep/revert decisions), `test` (frozen, report-only).
- **Hold techniques out of train.** Put some technique classes only in `test` so the headline number measures generalisation, not memorisation.
- **Benign set matters as much as the attack set.** Include hard negatives: legitimate text that mentions "ignore", "system prompt", security tutorials, code comments, translated text, pasted emails containing instructions. False positives are what make a defender useless.
- Store the test file read-only, record its SHA-256 at start, and have the Judge verify the hash before every evaluation.

## 7. Guardrails (non-negotiable)

1. **Separation of powers.** Scorer and test set are read-only to every agent. Agents get aggregate scores for `test`, never per-sample results.
2. **Decisions use `dev`, headline uses `test`.** Otherwise the system overfits the number you put on your CV.
3. **Reward-hacking watch.** Log every diff the Defender proposes. Reject any change that special-cases known test strings (n-gram overlap with test set, hardcoded canary strings, whitelisting by dataset-specific markers). Add an automated check, and review samples by hand.
4. **Researcher runs behind the firewall.** All fetched content goes through the current defender before the Researcher sees it. Anything flagged is quarantined and logged. This is dogfooding and a case study in itself.
5. **Code execution isolation.** Defender code runs in Docker with no network, a read-only filesystem except a scratch dir, CPU/memory/time limits. The Researcher gets network but no execution. Nothing crosses between them unscreened.
6. **ReDoS and resource safety.** If rules are regexes, enforce length limits, forbid nested quantifiers, and evaluate with a timeout.
7. **Operator control, no fixed cap.** The system runs until the operator pauses or stops it. Start, pause, resume and stop are UI buttons that write to `control`, checked every cycle. Usage (tokens, calls, time) is tracked and displayed but doesn't stop the run. If a rate or plan limit is hit, the orchestrator pauses cleanly, records where it was, and resumes on the operator's say-so (or automatically when the limit resets, if enabled). Fail closed on any unexpected error.
8. **Contained targets only.** The "secret" is a random canary token in a toy app. No real credentials or third-party systems appear anywhere. Check site terms before any scraping; prefer APIs and public datasets.
9. **Human gates.** Adding a new data source, publishing a case study, and any change to the Judge require explicit approval in the UI.

## 7b. Public-repo rules (the repo is public)

1. **The frozen test set is not in the repo.** A public test set leaks into future model training data and invites overfitting. Keep it private and out of git. Commit only its SHA-256 and size as a public commitment, plus a script that builds a fresh test set from a private seed so others can run the benchmark methodology without the answers. Publish a small public dev set for reproducibility.
2. **Generated attack corpus stays private.** Everything the Attacker invents lives in a gitignored `private/` directory (or an encrypted archive). The public repo gets a small curated set of sanitised, representative examples per technique class, enough to explain each case study and run the demo, not a ready-made attack library.
3. **No secrets, ever.** API keys come from environment variables only. Add `.gitignore` for `.env`, `private/`, `runs/`, `*.db` and logs. Add a pre-commit secret scanner (e.g. gitleaks) and run it in CI. If a secret is ever committed, rotate it immediately; deleting it from history is not enough.
4. **Scraped content is referenced, not copied.** The Researcher's sources are stored as URL + date + your own summary. Don't commit copied articles, forum posts or anything containing personal data. Respect site terms and `robots.txt`.
5. **Licences.** Pick Apache-2.0 or MIT for the code. Keep a `DATASETS.md` listing every third-party dataset with its licence and attribution, and don't redistribute any whose licence forbids it (link to it and provide a download script instead).
6. **Responsible disclosure.** Case studies cover *your own* defenders and the toy canary app. If the system ever surfaces a genuine vulnerability in someone else's product or model, do not publish it. Report it privately to the vendor first and wait for a fix or an agreed disclosure window.
7. **No public live instance.** A public endpoint would be a real attack surface and an uncapped cost. Show the project with a recorded demo GIF/video and a seeded sample run (`make demo`) that anyone can replay offline.
8. **Clean history from commit one.** Because the CEO's experiments are git commits, make sure commit messages never contain private test content or secrets. The commit history is part of the CV, so keep it readable.
9. **CI on the public repo:** tests, linting, secret scan, and a check that fails if `data/test*` or `private/` is ever staged.

## 8. The loop (one cycle)

1. **CEO reads** the notebook, recent scores, open findings and budget, then writes a hypothesis and chooses a focus (research / attack / defend / consolidate / write up).
2. **Researcher** (if chosen): fetch via firewall, extract techniques, propose new labelled examples. New sources need approval.
3. **Attacker** generates a batch targeting the current defender version. Evasions are recorded with technique and impact class.
4. **Defender** receives evasions (train split only) plus a sample of hard benign cases, and proposes a patch.
5. **Judge** evaluates the candidate on `dev`: keep only if block rate improves and FPR ≤ 1%. Every kept change is a git commit with the hypothesis in the message.
6. **Judge** logs a frozen `test` score for each kept version.
7. **Findings tracker** opens or updates a finding for each new evasion class, and closes it when a fix lands and holds.
8. **Case-study engine** drafts a write-up for closed findings (section 9).
9. **CEO writes** its decision and lessons to the notebook, then picks the next move.

Expect plateaus and drift in unattended runs. Add review checkpoints (every N cycles) where you read the notebook and can nudge the CEO.

## 9. Case-study engine (the CV centrepiece)

**Trigger:** a finding reaches `fixed` and the fix survives a regression run on `dev` and a fresh attacker batch.

**Evidence required before drafting** (the engine refuses to write without these):
- The original evading example(s), with technique class and impact class
- Reproduction steps against the pinned defender version
- Root-cause analysis (why the defender missed it)
- The fix diff and defender version
- Before/after metrics: attack success on that technique, overall block rate, FPR, `test` delta
- Regression check: what else changed, any new false positives

**Each case study is a markdown file** in `docs/case-studies/NNN-slug.md`:

1. **Title and one-line summary**
2. **Threat model**: what an attacker gains, mapped to the lethal-trifecta lens
3. **How it was found**: which agent, which cycle, which hypothesis
4. **The attack**: sanitised example and technique class
5. **Root cause**
6. **The fix**: diff summary and the design principle behind it
7. **Results**: before/after table plus a chart
8. **Residual risk and what didn't work**: dead ends are the most credible part
9. **Lessons**: what you'd do differently, linked to your technique journal
10. **Reproduce**: a command and a pinned version

**Handling dangerous detail (public repo):** case studies describe technique classes and defensive lessons. They don't ship a ready-to-use attack library. The full attack corpus stays private (section 7b); each case study includes one sanitised, representative example and the fix. A pre-publish check strips anything that looks like a working payload beyond that.

**Review:** the engine drafts, the CEO critiques, and you approve in the UI before it's published. Never auto-publish.

**Aggregates for the CV:**
- Auto-generated `RESULTS.md`: block rate over iterations, FPR, Elo curves, coverage heatmap, number of findings found/fixed, time-to-fix
- One long-form write-up at the end: "Co-evolving prompt-injection attackers and defenders: what an autonomous loop found in N cycles"
- Draft CV lines, filled from real numbers: *"Built an autonomous multi-agent red/blue system that raised held-out injection detection from X% to Y% at ≤1% FPR; documented N root-caused vulnerabilities as published case studies."*

Also build a **negative-results log**: ideas that failed and why. Include it in the write-up.

## 10. Dashboard UI

Single page, live via server-sent events, works offline (no CDN dependencies).

- **Live feed**: attacks and defences as they happen, filterable by agent, technique and outcome
- **Score charts**: frozen-test block rate and FPR over versions; arena Elo over time
- **Coverage heatmap**: technique class × detection rate (shows what you haven't studied)
- **CEO panel**: current hypothesis, decision log, notebook (readable)
- **Lineage tree**: defender versions and attacker strategies, with the experiment that made each
- **Findings board**: open / fixed / case-study-drafted / published
- **Case-study review queue**: read, comment, approve, publish
- **Usage meter and controls**: tokens, calls, time (display only); start, pause, resume, stop, approve-source

Backend: FastAPI with an SSE endpoint polling `events` by id; control actions as POSTs writing to `control`.

## 11. Tech stack and repo layout

Python 3.12+, asyncio orchestrator, SQLite, FastAPI, vanilla JS front end, Docker for the defender sandbox, pytest, Claude via the Anthropic SDK (model per role in config).

```
prompt-gauntlet/
  PLAN.md
  CLAUDE.md                 # rules for Claude Code (section 13)
  RESULTS.md                # generated
  arena/
    config.py  db.py  budget.py  llm.py
    orchestrator.py  cycle.py
    judge/   (frozen: judge.py, hash check)
    agents/  ceo.py researcher.py attacker.py defender.py
    defenders/  baseline_rules.py  llm_classifier.py  layered.py
    firewall.py             # screens untrusted content
    findings.py  casestudy.py  taxonomy.py
    sandbox/  (docker runner)
    server.py  static/index.html
  data/  public_dev.jsonl  test.sha256  build_test.py   (real test set lives outside git)
  private/                  # gitignored: test set, full attack corpus, scraped notes
  docs/case-studies/  journal/  DATASETS.md  SECURITY.md
  runs/                     # gitignored: logs, DBs, defender versions
  .gitignore  .gitleaks.toml  .github/workflows/ci.yml
  tests/
```

## 12. Phases (each has a "done when")

1. **Skeleton.** Repo (with `.gitignore`, secret scanning and CI from the first commit), DB schema, config, usage tracking, start/pause/resume/stop controls, orchestrator loop, stub agents, dashboard shell.
   *Done when:* a stub run produces events in the UI and the kill switch halts it.
2. **Measure first.** Dataset loader, splits, frozen Judge with hash check, naive baseline defender, taxonomy tags.
   *Done when:* baseline block rate and FPR are reproducible on dev and test, and tampering with the test file is detected.
3. **Autonomy.** Real CEO, Attacker and Defender using the LLM. Experiments, keep/revert, git commits, notebook.
   *Done when:* an unattended 30-cycle run improves the dev score and the CEO's notebook explains why.
4. **Co-evolution and defences.** Attacker adapts to the live defender, Elo, coverage heatmap, add the named defence strategies from section 3 as selectable Defender approaches.
   *Done when:* the frozen-test curve and Elo curves both move, and you can compare defence strategies head to head.
5. **Findings and case studies.** Findings tracker, case-study engine, review queue, `RESULTS.md` generation.
   *Done when:* three real case studies are drafted from real findings and pass your review.
6. **Researcher behind the firewall.** Source approval flow, quarantine log, new techniques flowing into the attack library.
   *Done when:* a technique the Researcher found appears in a case study.
7. **Harden and publish.** Reward-hacking audit, ReDoS tests, sandbox hardening, README, the long-form write-up, demo GIF.
   *Done when:* a stranger can clone, run a short demo, and read the results.

## 13. Handoff to Claude Code

**Suggested `CLAUDE.md` (put in the repo root):**
- Read `PLAN.md` first. Work one phase at a time and stop at each "done when" for review.
- Never modify `arena/judge/` or `data/test.jsonl` without explicit instruction. Add tests that fail if they change.
- Agents must never receive per-sample test results.
- All attack content targets the local sandbox and the dummy canary only. Don't add real endpoints, credentials or third-party targets.
- Write tests alongside code. Run them before claiming a phase is done.
- Prefer small commits with the hypothesis or purpose in the message.
- This repo is PUBLIC. Never commit secrets, the real test set, the full attack corpus, scraped third-party text or personal data. Follow section 7b; run the secret scan before every push.

**First prompt to give Claude Code:**
> Read PLAN.md. Implement Phase 1 only. Ask me before making any choice the plan doesn't settle. Show me the test results and a screenshot of the dashboard before moving on.

## 14. Risks and open questions

- **Metric overfitting.** Mitigated by held-out technique classes and a frozen test set. Revisit test composition if scores jump suspiciously.
- **Plateau or drift.** Add checkpoints; let the CEO escalate to you instead of looping.
- **Usage limits.** No fixed cap by design, so the risk is hitting plan or rate limits mid-run. Handle with pause/resume (guardrail 7), a usage meter in the UI, and cheaper models for high-volume calls.
- **Attack content hygiene.** Settled: public repo, private corpus and test set, sanitised examples only (sections 7b and 9).
- **Public-repo exposure.** Anyone can read your methodology, so the held-out set and a hash commitment are what keep the numbers credible.
- **LLM-as-judge noise.** Keep the Judge deterministic wherever possible and measure agreement on a hand-labelled sample.
- **Decisions needed from you:** API key vs running off your plan, which detector models to benchmark, repo licence (Apache-2.0 vs MIT), whether the Gandalf-style practice notes go in the repo.
