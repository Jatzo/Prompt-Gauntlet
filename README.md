# Prompt Gauntlet

A self-improving prompt-injection defence. A CEO agent, an attacker, a defender and a judge race each
other while a live dashboard shows the arms race, and the system writes up every weakness it finds
and fixes.

I am building this to become an expert in prompt injection, both attacking and defending.

Most prompt-injection defences are tested by running a detector against a fixed list of attack
strings and counting how many it catches. That number says little about real security, because an
attacker who adapts to the defence usually gets past it. Nasr, Carlini et al. show this for most
published injection defences ("The Attacker Moves Second", 2025).

In Prompt Gauntlet the attacker adapts to the defence, and an attack only counts if the toy assistant
actually does the harmful thing: leaks the secret, messages the attacker or calls a tool its task did
not need. I report the results as they come out, including the null ones.

Everything runs against my own toy assistant with a dummy secret. No real systems, credentials or
third-party targets are attacked.

![The arena view replaying a cycle: attacks fly at the defender's shield, caught ones stop, ones that get past reach the target](docs/dashboard/2-replay-verdict.jpg)

## What it does

Each cycle is one experiment, run without me:

1. **The CEO agent** reads a briefing that code assembles from memory, picks a focus from a shortlist
   that code computes, writes a hypothesis and predicts the result.
2. **The Attacker** writes a batch of injections aimed at the toy assistant. Each one is checked
   against the undefended assistant first, so only attacks that really work count.
3. **The Defender** sees half of the attacks that got past and proposes a patch to the detector's
   configuration. The other half is held back to test whether the fix generalises.
4. **The Judge**, a separate process the agents cannot reach, scores the patch and keeps it only if
   it passes a strict keep rule.
5. **The CEO writes a post-mortem**, and lessons with evidence behind them go into memory for the
   next cycle.

The toy assistant ("Gauntlet Target") reads email, searches documents, fetches pages and sends
messages, all with deterministic mock tools. An attack succeeds if the secret canary leaves in an
answer or a tool argument, if a message goes to the attacker's address, or if the assistant calls a
tool its task did not need. All addresses sit on the reserved `example.invalid` domain.

## How I built it, and why

Most of the work goes into making the agents' results trustworthy.

- **The headline is end-to-end attack success, not detection accuracy.** A detector that catches more
  strings but leaves the assistant just as easy to hijack has not made anything safer. The keep rule
  follows attack success first; detection is a secondary gate.
- **The Judge is a separate process.** It owns the test data, talks over a narrow JSON interface and
  returns aggregates only. The agents never see a per-sample test result, and the CEO's briefing never
  contains a test number. Its files are hash-pinned, and a test fails if they change.
- **Agents can only do what their role allows.** Every model call is forced-JSON tool use, validated
  against a small schema. A table-driven test proves each role is refused every tool outside its
  allowlist, and an import-boundary check stops agent code from touching the Judge or the database.
- **The Defender cannot run code.** Its whole search space is a typed configuration: normalisers,
  capped regex rules, a classifier prompt and layer order. It has no threshold to tune; the Judge
  recalibrates the threshold for every candidate.
- **Attack text is treated as data.** Every prompt that carries attack text delimits and datamarks it.
  An agent output with an unknown tool or field is a hijack event: the cycle is abandoned and the run
  pauses.
- **Keeps are tested for luck.** A placebo run feeds the keep rule random and empty patches and
  measures how often it keeps one anyway. A scripted hill-climb control, with no CEO and no Defender,
  is the baseline the agents must beat.
- **Runs survive crashes.** A cycle is a state machine in SQLite. Every agent call's raw output is
  stored before it is used, so a killed run resumes without calling the model again. A test kills the
  CLI mid-cycle and checks exactly that.
- **No hand labels.** Labels come from the source, from the toy assistant itself (the checker pass
  below), and from two model families that must agree. Disagreements are excluded and counted.
- **The statistics are tested before they are trusted.** Cluster bootstrap by template family,
  threshold re-derived inside every replicate, and known-answer fixtures where the true rate is set in
  advance.
- **The repo is public, so private data stays out of it.** The test set, the attack corpus and run
  databases live in a gitignored folder. CI checks the tracked file list, scans for secrets and runs
  the full suite.

## Where it stands (30 October 2026)

The plan has seven phases. Phase 1 (foundations) is done and pushed. Phase 2 (measurement) is built
and tested, and its live steps are running now. Phase 3 (the learning loop) is mostly built. The suite
has 1,192 tests, all run without live model calls.

**The checker pass is running.** Before I seal the test set, the Judge plays every attack in every
partition against the undefended assistant to see which ones really work. It walks a pre-decided
ladder: a strong target model first, then a weaker one, then the weaker one with a looser tool policy
and riskier placements. On the strong target, 0 of 2,331 attacks fired across 4,662 episodes. It
never sent the secret anywhere and never wrote to the attacker. The plan expected this, since frontier
models already resist naive indirect injection. The weaker rungs are running next,
and the baseline gate decides whether the claim stays as written or narrows to relative improvement
on an engineered target.

**A bug the live run found.** The first live attempt stopped after 13 minutes. The provider's
safeguards answered one flagged attack from an older model, and the assistant treated that as a
configuration fault and ended the whole run. Now a refusal ends only that episode, counted as
unscorable, and the run carries on; more than a quarter of a batch from another model still stops it. Across the
first 4,662 episodes, 42 ended in a refusal. The effect on scoring is written down in
[docs/limitations.md](docs/limitations.md).

**What else is done:**

- The full cycle (plan, attack, defend, judge, post-mortem) in mock, replay and live modes, with
  seeded simulated agents for a free demo battle.
- The CEO's briefing, focus shortlist, predictions and lesson memory, all written through one
  validated memory module.
- The placebo test in mock: 1 keep in 300 null cycles (upper bound 1.6%, under the 5% limit), while
  a known real gain was kept in 20 of 30 positive-control cycles.
- The hill-climb control arm. On synthetic data it keeps nothing, because the regex baseline already
  catches what its single moves could add. I recorded that limit rather than tune the data to flatter
  it.
- An evidence pack per run: a private copy with every field, and a public one with codes, counts and
  aggregates only.
- A local dashboard with four panels: the live arena, scores and controls, memory and briefing, and
  findings (an empty state until the findings tracker lands).

![Scores, run controls and the usage meter](docs/dashboard/3-scores-and-controls.jpg)

## What comes next

1. Finish the checker pass, run the live baseline against the gate, seal the test set and commit the
   pre-registration before any real result is looked at.
2. A first live run of the whole loop.
3. The findings and regression tracker, the curated-sources Researcher, the review queue and
   checkpoint digests.
4. The adaptive attacker under black-box and design-aware threat models, the structural defences
   (plan-then-execute and capability gating), and the memory ablation.
5. Case studies: at least three, written for a security reader, at least one of them a negative
   result or a bypass.

## Running it

It needs Python 3.12 or later and is developed in WSL2. Everything below runs offline on simulated
models; nothing calls a live model unless you set `ARENA_ALLOW_LIVE=1` and pass `--backend live`.

```bash
python -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"
make test-phase2      # lint, tracked-files guard, the test suite, secret scan

# Scratch folders, so nothing touches the real data in private/
export ARENA_JUDGE_DIR=/tmp/pg-judge ARENA_PRIVATE_DATA=/tmp/pg-private

# A synthetic dataset, the baseline table on it, then a seeded battle between simulated agents
python -m arena.cli data build --synthetic --large \
  --judge-dir "$ARENA_JUDGE_DIR" --private-dir "$ARENA_PRIVATE_DATA"
python -m arena.cli baseline --backend mock --judge-dir "$ARENA_JUDGE_DIR"
python -m arena.cli control start
python -m arena.cli run --backend sim --cycles 8
make dashboard        # the dashboard on localhost, replaying those cycles
```

The synthetic corpus is shortcut-prone on purpose (every attack names the attacker's address), so it
tests the machinery and says nothing about real defences.

## Limits

- The target is a toy, and the data is public benchmark or synthetic. Results show relative
  improvement on this setup, not real-world security.
- There are no human labels. The error left on items both model families agree on is not measured.
- The same model family attacks, defends and plays the target, which may limit how far results
  transfer.
- The memory ablation may be too small to separate from noise at 40 cycles and 5 runs an arm. A null
  result is a valid result here.

The full list is in [docs/limitations.md](docs/limitations.md), and the design, guardrails and phases
are in [PLAN.md](PLAN.md).

## Layout

```
arena/
  agents/      CEO, Attacker and Defender (the Researcher is still to build)
  judge/       the separate scoring process, statistics and hash checks (pinned)
  target/      the toy assistant, its mock tools and the attack checker
  detector/    the configurable detector the Defender patches
  memory/      validated memory writes and the CEO's briefing
  control/     the placebo test and the hill-climb control
  llm.py       every model call: live, mock, record and replay
  server.py    the dashboard backend
docs/          limitations, references, debug log, dashboard screenshots
tests/         the suite, including the hostile-dispatcher and kill-and-resume tests
```

## Licence

MIT. Third-party datasets and their licences are listed in [DATASETS.md](DATASETS.md).
