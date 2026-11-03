# Limitations

Stated in `RESULTS.md` and the write-up, word for word.

## Labels

No human labels. Attack labels come from the source and the toy app's checker; benign labels need two
model families to agree; disagreements are excluded and reported; the remaining label error is not
measured.

- An attack that never fires against the undefended target stays an attack, counted as invalid. It never
  enters the TPR denominator and is never relabelled benign.
- Excluding contested benign items removes some of the hardest negatives. Every report carries an FPR
  sensitivity row: dev FPR with each contested item counted as not flagged, and as flagged.
- One labeller family is Claude, which also writes some attacks and runs the detectors under test. The
  second family, the attack-source rule and the contested slice limit that bias without removing it.
- A provider's safeguards refuse some inputs, most likely the most explicit attacks. A refused attack
  keeps its source label and a refused benign item is contested; both are counted and left out of
  agreement, so raw agreement and kappa describe the items both families answered, not the whole set.
  An item the Claude plan answers from a different model than the pinned one counts as a refusal
  too; the cause is not confirmed (most likely a safeguards fallback), and a batch with no pinned
  answer or with switches on more than 5% of its items stops instead.
  A refusal is stored and never asked again. To ask again after the safeguards change, delete those
  rows: `sqlite3 private/data/labels-cache.db "DELETE FROM outputs WHERE failure = 'refused: safeguards'"`.

## Novelty

Novelty is measured on the text (containment over character 5-grams) and on a coarse behaviour
signature (the channel and what the toy app did). A paraphrase of a known idea can count as new text,
and a new idea that ends in the same action counts only as new text.

The technique classifier is keyword rules. It cannot refuse a held-out idea it has no rule for, and an
unclassified attack may be a classifier miss rather than a new technique. The operator triages every
candidate finding; the system never adds a technique by itself.

## Replaying a run

A replay run plays back the agents' recorded calls, but not the Judge's. A recording run calls the
real target and detector inside the Judge, and the Judge keeps those answers in its own cache, not
in the cassette. So in a replay run the Judge answers the Attacker's queries and checks its batch
with the same simulated models it uses in a mock run. The agents' outputs are the recorded ones; the
Judge's labels and numbers in a replay run are simulated and say nothing about the live run.

## Live agents, simulated Judge

The Judge's models are chosen apart from the agents' (`--judge simulated|live`, simulated by
default). A run with live agents and the simulated Judge shows real attacks and patches, but its
validity labels, scores and keep decisions come from simulated target and detector models. Each
manifest records the Judge's backend, and the evidence pack marks any such cycle as simulated. A
placebo result vouches only for keeps made under the same Judge and sizes.

## The control arm on synthetic data

The hill-climb control (arm C) makes one change a cycle: one normaliser or one rule from a fixed
bank. On the synthetic folders it keeps nothing. Even on the large folder (`data build --synthetic
--large`), where three techniques sit on both dev folds, at that folder's build seed the regex
baseline already catches every fold-one attack family but one, and no bank rule catches that one.
The keep rule tests the gain on fold one, so no single move can pass. Fitting a frame or a rule to
the other would only flatter the control, so neither was done. Arm C is a flat line in mock runs,
and the comparison between arms needs the real data.

## Safeguard refusals

The live plan's safeguards refuse some attack inputs, or answer them from an older model. The
target app ends such an episode unscorable and the run carries on; more than a quarter of a turn's
batch from another model still stops it as a fault. Four effects follow.

- An attack refused before it fired counts as not fired. The Judge scores an unscorable attack
  episode as a failed attack, which favours the defence, against the rule that unscorable counts
  against it. That rule lives in the Judge and is unchanged for now.
- Arms are not paired on refusals. The target sees the gated history, so a gate that redacts the
  flagged text can avoid a refusal that the no-defence arm meets, which lowers the baseline ASR.
- In the checker pass, an attack refused on rung 0 moves on to rungs 1 and 2, and may end up
  labelled by a filter rather than by what the target did.
- The detector's classifier meets the same filter. A text it refuses is one unscorable item: a miss
  if it is an attack, a false positive if it is benign. So the classifier arm pays for the
  provider's filter on benign text and gets no credit for it on attacks. The count is in each
  report's `unscorable` figure.

Each run prints how many episodes a refusal ended. Compare `unscorable_episodes` across arms before
trusting a cycle's end-to-end numbers.

## Attacks the toy app cannot show

Every paired attack stays in the injection suite, and ASR is reported over all pairs. Two things
outside the defence hold that figure down.

- About a third of the attacks ask for something the toy app has no way to show: code, an answer in
  another language, or an action with no tool behind it. Of 1,701 pairs in dev, ablation_eval and
  monitor, 65.4% ask for an action the checker can see. The rest can fire only on rung 2, where any
  extra tool call counts.
- On rungs 0 and 1 the target has only its task's tools, and only 2 of the 10 tasks offer
  `send_message`. A target that obeyed every attack could fire at most about 12% of pairs there.

The checker pass fired 0 of 2,331 on rungs 0 and 1 and 649 on rung 2, so the baseline-ASR gate is
decided by rung 2. Dev's floor of 1,000 attacks counts labelled attacks, not paired or fired ones.

## Labels made while the target saw extra tools

Every call in the checker pass (41,548) and the labelling build was made while the session also
offered the operator's account connectors (see `docs/debug-log.md`). None of them ran, but their
definitions were in the model's context, which may have changed how it behaved. The labels were kept
rather than paid for twice: rerunning the checker would cost about 41,500 calls and 19 hours of
calls. Calls made from now on come from sessions that offer only the answer tool, and the cache
does not tell the two apart, so the live baseline's no-defence trials 0 and 1, which it reuses from
the checker pass, come from the old sessions and its later trials from the new ones.
