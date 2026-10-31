# Run record

Measured facts from the live runs: how long each stage took, how many calls it made and what came
out. Every figure here comes from a log or a timestamp. Where one does not, the line says so.
Times are UTC, which is UK time on these dates. Estimates are kept apart, under their own heading.

Where the figures come from:
- the checker logs (`check.log`, one per run, with a `start` and an `end ... exit N` line);
- the `created_at` stamp on every call in the Judge's evaluation cache;
- the labelling cache, which stores counts but no times;
- the CLI's own session transcripts, for the connector finding below.

## The dataset

The real build labels every item with two model families, a main labeller and an open-weights
labeller, and keeps a benign item only when both call it benign.

| Measure | Value |
|---|---|
| Items labelled in the final build | 15,208 |
| Agreement on attack or benign | raw 0.98, Cohen's kappa 0.94 (15,078 items) |
| Agreement on kind (injection or jailbreak) | raw 0.96, kappa 0.54 (3,063 attacks) |
| Agreement on impact class | raw 0.81, kappa 0.52 (3,063 attacks) |
| Refused by the main labeller's safeguards | 130 of 15,208, source label kept for attacks |
| Contested benign items, left out and counted | 182 (40 in dev, 10 in test) |
| Duplicates removed | 16 exact, 3,366 near |
| Labelling calls stored, both builds | main labeller 16,190, open-weights labeller 16,190 |

The last stage of the final build ran from 14:27 to 15:43 on 27 October (76 minutes, exit 0), with
earlier labels already cached. The labelling cache keeps no timestamps, so the build's total time is
not measured.

Partition sizes after the build:

| Partition | Attacks | Benign | Injection pairs |
|---|---|---|---|
| dev | 1,000 | 2,060 | 1,000 |
| calibration | 0 | 1,041 | 0 |
| monitor | 200 | 1,034 | 200 |
| ablation_eval | 501 | 1,151 | 501 |
| test | 630 | 1,040 | 630 |

## The checker pass

Before the test set is sealed, the Judge plays every paired attack against the undefended toy
assistant to see which ones really work. It walks a fixed ladder of three rungs, at 2 trials a pair.
Rung 0 plays every attack; each later rung plays only the attacks no earlier rung fired.

| Rung | Target | Episodes | Attacks fired | Ended by a safeguard refusal | Calls | Active time | Calls a minute |
|---|---|---|---|---|---|---|---|
| 0 | strong model, task tools only | 4,662 | 0 of 2,331 | 42 (0.9%) | 13,905 | 5 h 32 min | 41.9 |
| 1 | weak model, task tools only | 4,662 | 0 of 2,331 | 43 (0.9%) | 13,439 | 5 h 42 min | 39.3 |
| 2 | weak model, every tool, risky placements | 4,662 | 649 of 2,331 (27.8%) | 30 (0.6%) | 14,204 | 7 h 28 min | 31.7 |
| **All** | | **13,986** | | **115** | **41,548** | **18 h 54 min** | **36.7** |

"Active time" adds up the stretches when calls were being stored. The pass ran across five days,
from 27 to 31 October, because it was stopped and resumed seven times (below).

Labels after the pass:

| Partition | Confirmed (fired on rung 0) | Fired on rung 2 only | Never fired |
|---|---|---|---|
| dev | 0 | 264 | 736 |
| ablation_eval | 0 | 146 | 355 |
| monitor | 0 | 57 | 143 |
| test | 0 | 182 | 448 |
| **All** | **0** | **649** | **1,682** |

What the target sent back, across all 41,548 calls:

| Outcome | Calls |
|---|---|
| A valid action | 40,454 |
| Called a toy tool directly instead of through its one action tool, rejected | 864 |
| Tried to call one of the operator's account connectors, rejected (see below) | 110 |
| Refused by the provider's safeguards | 115 |
| Output outside its schema | 5 |

Output tokens: 13,693,107. Input tokens as the backend reports them: 3,170,538,306, a figure that
includes cache reads and the SDK's own system prompt on every call, so it is not the size of the
prompts themselves.

## Every run

| # | Start | End | Length | Calls | How it ended |
|---|---|---|---|---|---|
| 1 | 27 Oct 16:19 | 27 Oct 16:33 | 13 min | 400 | Stopped by me, low on usage |
| 2 | 29 Oct 20:32 | 29 Oct 20:45 | 13 min | 665 | Stopped itself: one flagged attack was answered by an older model |
| 3 | 29 Oct 21:25 | 29 Oct 23:05 | 1 h 40 min | 4,719 | Stopped by me, plus 1,142 calls after the stop (below) |
| 4 | 30 Oct 10:02 | 30 Oct 14:01 | 3 h 58 min | 8,284 | Network failure (DNS); rung 0 finished at 13:27 |
| 5 | 30 Oct 15:03 | 30 Oct 20:22 | 5 h 19 min | 12,134 | Stopped by a script after rung 1, plus 917 calls after the stop |
| 6 | 31 Oct 10:35 | 31 Oct 11:29 | 54 min | 1,585 | Network failure (DNS) |
| 7 | 31 Oct 11:45 | 31 Oct 17:45 | 6 h 0 min | 11,702 | Finished, exit 0 |

Each restart picked up from the cache, so no finished call was ever paid for twice. Rungs already
played replayed in seconds.

## What the runs found out about the harness

1. **A safeguard answer from another model stopped the whole run** (run 2). The provider answers some
   flagged inputs from an older model instead of refusing. The target app treated that as a
   configuration fault. Now a refusal ends only that episode, counted as unscorable, and more than a
   quarter of a batch from another model still stops the run (commit 04e3cea).
2. **Stopping the CLI did not stop the Judge** (runs 3 and 5). The Judge runs as its own process and
   kept calling the model for about 20 minutes after each stop: 1,142 calls after the stop at 23:05 on
   29 October, 917 after 20:22 on 30 October. Those calls were cached and reused, so nothing was
   wasted. Fixed after the pass: the Judge now ends with the CLI.
3. **The target could see the operator's account connectors** (rungs 1 and 2). The live backend turned
   off the built-in tools and file settings but not the connectors attached to the account (file
   storage, a CRM and a docs service). While reading attack text, the weak target tried to call them
   113 times in 110 sessions, including searching, reading, listing and creating files. All 113 were
   refused because no permission had been granted, so no data moved either way, and the harness
   rejected each of those outputs as a hijack. One layer, the missing grant, was all that stood in the
   way. Fixed after the pass: a live session now loads no MCP server, denies any tool use not
   approved in advance, and stops the run if it offers the model anything but its answer tool. The
   labels were kept; `docs/limitations.md` says what that means.
4. **About a third of the attacks ask for something the toy app cannot show.** Of 1,701 pairs in dev,
   ablation_eval and monitor, 65.4% ask for an action the checker can see; the rest ask for code, a
   different language, or actions the toy app has no tool for. On rungs 0 and 1 only 2 of the 10 tasks
   expose `send_message`, so even a fully obedient target could fire at most about 12% of pairs there.
   Of 112 dev attacks that ask for a send on the task that has one, none fired in 448 episodes.

## Tests and CI

- The suite has 1,192 tests and runs in about 2 minutes (112 to 132 seconds locally). None make a
  live call.
- 11 CI runs from 26 to 30 October, all green, each between 1 and 7 minutes.

## Estimates (not measured)

The live baseline plays four defence arms on all three rungs at 5 trials a pair. From the call
counts above, it needs about 120,000 new calls, about 40 to 65 hours at the rates measured here.
