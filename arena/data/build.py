"""Builds the dataset end to end and writes it out: deduplicate, split, pair, check, write.

Every partition the agents must not see goes to the Judge data directory, in the layout
`arena.judge.data` reads. Train goes to `private/data/`. Nothing here decides validity: whether an
attack succeeds against the undefended target is measured by the Judge, per target rung.
"""

import json
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from arena.config import DEFAULTS, REPO_ROOT, ArenaConfig
from arena.data.dedup import deduplicate
from arena.data.feasibility import Feasibility, check_feasible
from arena.data.pairs import build_pairs
from arena.data.splits import split
from arena.judge.data import MEASURABLE, PLACEHOLDER_PREFIX, pin_lines, verify_test_set
from arena.judge.stats import LabelNoise
from arena.schemas import Sample


class SealedTestSet(RuntimeError):
    """A rebuild would replace a test set that data/test.sha256 has already sealed."""


@dataclass(frozen=True)
class BuildSummary:
    counts: dict[str, dict[str, int]]
    exact_removed: int
    near_removed: int
    pairs: dict[str, int]
    feasibility: Feasibility
    test_pin: str


def _write_jsonl(path: Path, rows: Sequence[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="\n") as out:
        for row in rows:
            out.write(json.dumps(row, sort_keys=True) + "\n")


def build_dataset(
    samples: Sequence[Sample],
    *,
    judge_dir: Path,
    private_dir: Path,
    config: ArenaConfig = DEFAULTS,
    label_noise: dict[str, LabelNoise] | None = None,
    root: Path = REPO_ROOT,
) -> BuildSummary:
    report = deduplicate(samples, config)
    rows = split(report.kept, config)
    split_samples = [row.sample for row in rows]
    pairs = build_pairs(split_samples)

    partitions = (*MEASURABLE, "test", "train")
    records = {
        partition: [
            {"sample": row.sample.model_dump(mode="json"), "fold": row.fold}
            for row in rows
            if row.sample.partition == partition
        ]
        for partition in partitions
    }
    partition_pairs = {
        partition: [p.model_dump(mode="json") for p in pairs if p.partition == partition]
        for partition in partitions
    }

    def write_test(folder: Path) -> None:
        _write_jsonl(folder / "test.jsonl", records["test"])
        _write_jsonl(folder / "test_pairs.jsonl", partition_pairs["test"])

    # Once the test set is sealed, a rebuild may only write the same bytes again: check a staged
    # copy against the pin before anything in the Judge directory is touched.
    pin = root / "data" / "test.sha256"
    if pin.exists() and not pin.read_text().startswith(PLACEHOLDER_PREFIX):
        with tempfile.TemporaryDirectory() as staging:
            write_test(Path(staging))
            if verify_test_set(root, Path(staging)) != "ok":
                raise SealedTestSet(
                    f"{pin} seals a test set, and this build would write a different one. "
                    "Nothing was written."
                )

    for partition in partitions:
        if partition == "train":
            _write_jsonl(private_dir / "train.jsonl", records[partition])
        elif partition == "test":
            write_test(judge_dir)
        else:
            _write_jsonl(judge_dir / "partitions" / f"{partition}.jsonl", records[partition])
            _write_jsonl(judge_dir / "pairs" / f"{partition}.jsonl", partition_pairs[partition])
    # Written on every build, empty when there is no audit, so a rebuild never keeps old rates.
    noise = {
        name: {"errors": n.errors, "audited": n.audited} for name, n in (label_noise or {}).items()
    }
    (judge_dir / "labels.json").write_text(json.dumps(noise, sort_keys=True))

    pair_counts: dict[str, int] = {}
    for pair in pairs:
        pair_counts[pair.partition] = pair_counts.get(pair.partition, 0) + 1
    feasibility = check_feasible(rows, config)
    return BuildSummary(
        counts=feasibility.counts,
        exact_removed=report.exact_removed,
        near_removed=report.near_removed,
        pairs=pair_counts,
        feasibility=feasibility,
        test_pin=pin_lines(judge_dir),
    )
