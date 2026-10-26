"""The real data build: approved sources, read from their fetched files into `Sample`s.

`sources.toml` lists each source and how its rows map onto a sample. Each adapter in `adapters.py`
reads one source's raw files into `Raw` rows; `finish` does the rest the same way for every source:
the transforms, the length limit, the technique, the id and a seeded cap. Labels here are the
source's own; the model labels and the checker pass replace hand labels later in the build.
"""

import hashlib
import random
import re
import tomllib
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from arena.data.fetch import FetchedFile, verify
from arena.schemas import Sample
from arena.taxonomy import classify

SOURCES_TOML = Path(__file__).resolve().parent.parent / "sources.toml"

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_URL_HOST = re.compile(r"https?://[^\s/\"'<>)\]]+")
_PHONE = re.compile(r"(?<!\w)(?:\+?\d[\d ().-]{7,}\d)(?!\w)")
_IDENTIFIER_CHARS = re.compile(r"[^A-Za-z0-9_.:-]+")


@dataclass(frozen=True)
class Source:
    name: str
    use: str
    label: str
    channel: str
    impact_class: str
    origin: str
    generator_family: str
    non_claude: bool
    private_only: bool
    licence: str
    cap: int
    max_chars: int
    transforms: tuple[str, ...]
    files: tuple[FetchedFile, ...]
    category: str | None = None
    options: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Raw:
    """One row as an adapter reads it. `group` names its near relatives (one template, one goal,
    one mailbox), which the split keeps in one partition."""

    text: str
    group: str
    label: str | None = None
    channel: str | None = None
    category: str | None = None
    impact_class: str | None = None


def load_sources(path: Path = SOURCES_TOML) -> tuple[int, dict[str, Source]]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    seed = data.pop("seed")
    sources = {}
    for name, entry in data.items():
        files = tuple(FetchedFile(path=f["path"], url=f["url"]) for f in entry.pop("files"))
        entry["transforms"] = tuple(entry["transforms"])
        sources[name] = Source(name=name, files=files, **entry)
    return seed, sources


def identifier(*parts: object) -> str:
    """A `Sample` identifier: the allowed characters only, at most 64 of them."""
    text = _IDENTIFIER_CHARS.sub("_", "-".join(str(part) for part in parts))
    if len(text) <= 64:
        return text
    return f"{text[:51]}-{hashlib.sha256(text.encode()).hexdigest()[:12]}"


def retemplate_attacker(text: str) -> str:
    """Every address and URL host in attack text becomes the toy app's placeholder."""
    return _URL_HOST.sub("https://{ATTACKER}", _EMAIL.sub("{ATTACKER}", text))


def scrub_contacts(text: str) -> str:
    return _PHONE.sub("000 0000 0000", _EMAIL.sub("someone@example.invalid", text))


TRANSFORMS: dict[str, Callable[[str], str]] = {
    "attacker_address": retemplate_attacker,
    "scrub_contacts": scrub_contacts,
}


@dataclass(frozen=True)
class Finished:
    samples: list[Sample]
    read: int
    unusable: int
    duplicates: int


def finish(source: Source, rows: Iterable[Raw], seed: int) -> Finished:
    """Raw rows to samples, the same way for every source."""
    samples: dict[str, Sample] = {}
    read = unusable = duplicates = 0
    for row in rows:
        read += 1
        label = row.label or source.label
        text = row.text.strip()
        for name in source.transforms:
            # Address swaps are for attack text; scrubbing applies to whatever the source holds.
            if name != "attacker_address" or label == "attack":
                text = TRANSFORMS[name](text)
        if not text or len(text) > source.max_chars:
            unusable += 1
            continue
        channel = row.channel or source.channel
        digest = hashlib.sha256(text.encode()).hexdigest()[:16]
        sample_id = identifier(source.name, digest)
        if sample_id in samples:
            duplicates += 1
            continue
        attack = label == "attack"
        group = identifier(source.name, row.group)
        samples[sample_id] = Sample(
            id=sample_id,
            text=text,
            label=label,
            technique=(
                classify(text, channel) if attack else f"benign.{row.category or source.category}"
            ),
            impact_class=(row.impact_class or source.impact_class) if attack else "none",
            injection_vs_jailbreak="injection" if attack else "neither",
            source=source.origin,
            generator_family=source.generator_family,
            template_family=group,
            cluster_id=group,
            partition="train",
            channel=channel,
        )
    kept = sorted(samples.values(), key=lambda sample: sample.id)
    if len(kept) > source.cap:
        kept = sorted(
            # A seeded, repeatable sample, not a secret.
            random.Random(f"{seed}:{source.name}").sample(kept, source.cap),  # noqa: S311
            key=lambda sample: sample.id,
        )
    return Finished(kept, read, unusable, duplicates)


@dataclass(frozen=True)
class SourceReport:
    name: str
    status: str
    kept: int = 0
    read: int = 0
    unusable: int = 0
    duplicates: int = 0


@dataclass(frozen=True)
class RealCorpus:
    samples: list[Sample]
    reports: list[SourceReport]
    non_claude_attack_share: float | None


def real_corpus(raw_dir: Path, path: Path = SOURCES_TOML) -> RealCorpus:
    """Every dataset source that has been fetched, checked against the manifest first. A source not
    fetched yet is reported and left out; a changed file stops the build (`verify` raises)."""
    from arena.data.sources.adapters import ADAPTERS

    seed, sources = load_sources(path)
    samples: list[Sample] = []
    reports: list[SourceReport] = []
    non_claude = attacks = 0
    for source in sources.values():
        if source.use != "dataset":
            continue
        folder = raw_dir / source.name
        missing = verify(raw_dir, source.name, source.files)
        if missing:
            reports.append(SourceReport(source.name, f"not fetched: {', '.join(missing)}"))
            continue
        done = finish(source, ADAPTERS[source.name](folder, source), seed)
        samples += done.samples
        attack_count = sum(sample.label == "attack" for sample in done.samples)
        attacks += attack_count
        non_claude += attack_count if source.non_claude else 0
        reports.append(
            SourceReport(
                source.name, "ok", len(done.samples), done.read, done.unusable, done.duplicates
            )
        )
    return RealCorpus(samples, reports, non_claude / attacks if attacks else None)
