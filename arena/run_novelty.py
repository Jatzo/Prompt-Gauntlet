"""The orchestrator's novelty hooks for one run (PLAN section 10).

- `record_batch` bands a validated batch against train and the run's archive as it stood before the
  batch, offers the candidates to the archive and records the batch, inside the caller's transaction
  (the attack step's write). A resumed cycle gets its stored bands back instead of recording twice.
- `close_cycle` runs inside the transaction that commits the cycle and offers the held-back attacks
  only, once: a `novelty_closed` episode marks the cycle as done, since eviction may have removed
  the rows themselves. A held-back attack keeps the band it got when it was recorded. A rolled-back
  cycle never closes, so its held-back attacks never enter.
- `last_view` is what the Attacker sees next: the newest committed cycle's valid attacks and bands,
  leaving out held-back ones, which no agent may see.

The threshold and train's 5-grams load on first use, once per orchestrator. A live run with no
calibrated threshold raises `NotCalibrated`, which pauses the run.
"""

import json
import sqlite3
from functools import cached_property
from pathlib import Path

from arena import novelty
from arena.agents.attacker import ShownAttack
from arena.config import ArenaConfig
from arena.memory.memory import Memory
from arena.schemas import AttackVerdict, BatchReport

STEP = "novelty"
ROLE = "orchestrator"


class RunNovelty:
    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        run_id: str,
        live: bool,
        private_dir: Path,
        config: ArenaConfig,
    ):
        self.conn, self.run_id, self.live = conn, run_id, live
        self.private_dir, self.config = private_dir, config

    @cached_property
    def threshold(self) -> float:
        return novelty.threshold(
            self.private_dir / "train.jsonl",
            self.private_dir / "novelty.json",
            percentile=self.config.novelty_percentile,
            sample=self.config.novelty_calibration_sample,
            seed=self.config.seed,
            allow_mock=not self.live,
        )

    @cached_property
    def train(self) -> list[frozenset[str]]:
        path = self.private_dir / "train.jsonl"
        if not path.exists():
            return []
        rows = map(json.loads, path.read_text().splitlines())
        return [
            novelty.grams(row["sample"]["text"])
            for row in rows
            if row["sample"]["label"] == "attack"
        ]

    def record_batch(
        self, memory: Memory, cycle_id: int, texts: list[str], report: BatchReport
    ) -> list[novelty.Band]:
        """Called inside the attack step's write transaction."""
        stored = memory.episode(cycle_id, "attack_batch")
        if stored is not None:
            return stored["bands"]
        archive = [novelty.grams(text) for text in memory.archive_texts(self.run_id)]
        bands = novelty.bands(texts, self.train + archive, self.threshold)
        memory.offer_to_archive(
            novelty.archive_candidates(report.verdicts, texts, bands),
            cycle_id=cycle_id,
            step=STEP,
            role=ROLE,
        )
        memory.record_episode(
            kind="attack_batch",
            body={
                "texts": texts,
                "bands": bands,
                "verdicts": [verdict.model_dump(mode="json") for verdict in report.verdicts],
            },
            cycle_id=cycle_id,
            step=STEP,
            role=ROLE,
        )
        return bands

    def close_cycle(self, memory: Memory, cycle_id: int) -> None:
        """Called inside the commit's transaction."""
        if memory.episode(cycle_id, "novelty_closed") is not None:
            return
        batch = memory.episode(cycle_id, "attack_batch")
        if batch is None:
            return
        held = [
            (AttackVerdict.model_validate(verdict), text, found)
            for verdict, text, found in zip(
                batch["verdicts"], batch["texts"], batch["bands"], strict=True
            )
            if verdict["held_back"]
        ]
        offered = novelty.archive_candidates(
            [verdict for verdict, _, _ in held],
            [text for _, text, _ in held],
            [found for _, _, found in held],
            include_held_back=True,
        )
        memory.offer_to_archive(offered, cycle_id=cycle_id, step=STEP, role=ROLE)
        memory.record_episode(
            kind="novelty_closed",
            body={"offered": len(offered)},
            cycle_id=cycle_id,
            step=STEP,
            role=ROLE,
        )

    def last_view(self) -> tuple[ShownAttack, ...]:
        batch = Memory(self.conn, self.config).latest_committed_episode(self.run_id, "attack_batch")
        if batch is None:
            return ()
        return tuple(
            ShownAttack(text, found)
            for verdict, text, found in zip(
                batch["verdicts"], batch["texts"], batch["bands"], strict=True
            )
            if verdict["valid"] and not verdict["held_back"]
        )
