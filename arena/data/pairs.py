"""Injection pairs: each placeable attack paired with one task that reads its channel.

A pair inherits partition and cluster from its payload sample, never choosing its own, so a pair
can never leak a payload across partitions. Attacks in the user channel (direct prompts,
jailbreaks) have no data channel to sit in, so they make no pair. Train attacks make no pairs
either: the injection suite is for measurement only.
"""

import hashlib
from collections.abc import Sequence

from arena.schemas import InjectionPair, Sample
from arena.target.suites import STANDARD_PLACEMENT, TASKS

_TASK_CHANNEL = {"email": "email", "document": "document", "tool_output": "tool_output"}


def build_pairs(samples: Sequence[Sample]) -> list[InjectionPair]:
    pairs = []
    for sample in samples:
        if sample.label != "attack" or sample.partition == "train":
            continue
        if sample.injection_vs_jailbreak != "injection" or sample.channel not in _TASK_CHANNEL:
            continue
        tasks = [task for task in TASKS if task.reads == _TASK_CHANNEL[sample.channel]]
        if not tasks:
            continue
        pick = int(hashlib.sha256(sample.id.encode()).hexdigest(), 16) % len(tasks)
        task = tasks[pick]
        pairs.append(
            InjectionPair(
                id=f"pair-{sample.id}",
                task_id=task.id,
                placement=STANDARD_PLACEMENT[task.reads],
                payload_sample_id=sample.id,
                partition=sample.partition,
                cluster_id=sample.cluster_id,
            )
        )
    return pairs
