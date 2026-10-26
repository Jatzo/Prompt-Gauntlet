"""The Judge's custody of the partitions: who may read what, and the frozen test set's pin.

Layout of the Judge data directory:
- partitions/<name>.jsonl: one row per sample, {"sample": {...}, "fold": 1 | 2 | null}
- pairs/<name>.jsonl: one InjectionPair per line
- labels.json: {"<partition>": {"errors": n, "audited": n}} from the audits
- test.jsonl and test_pairs.jsonl: the frozen test set, pinned in data/test.sha256

`open_partitions` refuses test outright: no measurement in this phase may read it. The pin file has
one line per test file, `<sha256>  <bytes>  <file>`, over the file's LF-normalised bytes.
"""

import json
from dataclasses import dataclass
from pathlib import Path

from arena.judge.hashing import sha256_text
from arena.judge.stats import LabelNoise
from arena.schemas import InjectionPair, Sample

MEASURABLE = ("calibration", "dev", "monitor", "regression", "ablation_eval")
TEST_FILES = ("test.jsonl", "test_pairs.jsonl")
PLACEHOLDER_PREFIX = "PLACEHOLDER"


@dataclass(frozen=True)
class Row:
    sample: Sample
    fold: int | None


@dataclass(frozen=True)
class Partition:
    name: str
    rows: tuple[Row, ...]
    pairs: tuple[InjectionPair, ...]


def open_partitions(data_dir: Path, names: tuple[str, ...]) -> dict[str, Partition]:
    refused = [name for name in names if name not in MEASURABLE]
    if refused:
        raise PermissionError(f"The Judge does not open {refused} for measurement.")
    opened = {}
    for name in names:
        rows = tuple(
            Row(Sample.model_validate(line["sample"]), line["fold"])
            for line in _read_jsonl(data_dir / "partitions" / f"{name}.jsonl")
        )
        pairs = tuple(
            InjectionPair.model_validate(line)
            for line in _read_jsonl(data_dir / "pairs" / f"{name}.jsonl")
        )
        for row in rows:
            if row.sample.partition != name:
                raise ValueError(f"{row.sample.id} is filed under {name} but labelled otherwise.")
        opened[name] = Partition(name, rows, pairs)
    return opened


def label_noise(data_dir: Path) -> dict[str, LabelNoise]:
    path = data_dir / "labels.json"
    if not path.exists():
        return {}
    return {name: LabelNoise(**value) for name, value in json.loads(path.read_text()).items()}


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _normalised_size(path: Path) -> int:
    return len(path.read_bytes().replace(b"\r\n", b"\n"))


def pin_lines(data_dir: Path) -> str:
    """The text to commit as data/test.sha256 once the test set is sealed."""
    return "".join(
        f"{sha256_text(data_dir / name)}  {_normalised_size(data_dir / name)}  {name}\n"
        for name in TEST_FILES
    )


def verify_test_set(root: Path, data_dir: Path) -> str:
    """ok, placeholder, mismatch, size_mismatch, missing_pin or missing_test_set.

    A placeholder pin is accepted only while no test file exists: a real file beside a placeholder
    means the pin was never written, or was reverted.
    """
    pin = root / "data" / "test.sha256"
    present = [name for name in TEST_FILES if (data_dir / name).exists()]
    if not pin.exists():
        return "missing_pin"
    text = pin.read_text()
    if text.startswith(PLACEHOLDER_PREFIX):
        return "mismatch" if present else "placeholder"
    expected = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 3 or not parts[1].isdigit():
            return "mismatch"
        expected[parts[2]] = (parts[0], int(parts[1]))
    if set(expected) != set(TEST_FILES):
        return "mismatch"
    if len(present) != len(TEST_FILES):
        return "missing_test_set"
    for name, (digest, size) in expected.items():
        if _normalised_size(data_dir / name) != size:
            return "size_mismatch"
        if sha256_text(data_dir / name) != digest:
            return "mismatch"
    return "ok"
