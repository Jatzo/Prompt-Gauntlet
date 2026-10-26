"""Builds the labelled, deduplicated, partitioned dataset, and writes it where only the Judge
reads it.

Operator-side code. The partitions an agent must never see (calibration, dev, monitor, regression,
ablation_eval and test) go into the Judge's data directory; train goes into `private/`. Public
datasets join only once the operator approves each one in the shortlist; until then the corpus is
synthetic, from `templates.py`.
"""
