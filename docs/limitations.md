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

## Novelty

Novelty is measured on the text (containment over character 5-grams) and on a coarse behaviour
signature (the channel and what the toy app did). A paraphrase of a known idea can count as new text,
and a new idea that ends in the same action counts only as new text.

The technique classifier is keyword rules. It cannot refuse a held-out idea it has no rule for, and an
unclassified attack may be a classifier miss rather than a new technique. The operator triages every
candidate finding; the system never adds a technique by itself.
