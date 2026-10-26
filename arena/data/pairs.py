"""Injection pairs: each placeable attack paired with one task that reads its channel.

A pair inherits partition and cluster from its payload sample, never choosing its own, so a pair
can never leak a payload across partitions. Attacks in the user channel (direct prompts,
jailbreaks) have no data channel to sit in, so they make no pair. Train attacks make no pairs
either: the injection suite is for measurement only.
"""

import hashlib
from collections.abc import Sequence

from arena.schemas import InjectionPair, Sample, Task
from arena.target.suites import STANDARD_PLACEMENT, TASKS


def pick_task(sample_id: str, channel: str) -> Task | None:
    """The task a payload is placed in: one that reads its channel, chosen by its id. No task
    reads the user channel, so a direct prompt gets none."""
    tasks = [task for task in TASKS if task.reads == channel]
    if not tasks:
        return None
    return tasks[int(hashlib.sha256(sample_id.encode()).hexdigest(), 16) % len(tasks)]


def build_pairs(samples: Sequence[Sample]) -> list[InjectionPair]:
    pairs = []
    for sample in samples:
        if sample.label != "attack" or sample.partition == "train":
            continue
        if sample.injection_vs_jailbreak != "injection":
            continue
        task = pick_task(sample.id, sample.channel)
        if task is None:
            continue
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
