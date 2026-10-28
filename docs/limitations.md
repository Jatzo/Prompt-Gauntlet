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
