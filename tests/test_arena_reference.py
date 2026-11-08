"""The arena's reference target (PLAN section 7 note of 2026-11-08): `run --reference guided` makes
the cycles validate attacks on guided Gemma, while every default, the ladder and the baseline keep
rung 0 as before."""

import json
import sqlite3

from arena import cli
from arena.config import DEFAULTS, config_hash
from arena.orchestrator import CycleOutcome, phase1_mock_script
from arena.target.ladder import LADDER, reference_target


def test_the_default_reference_is_unchanged():
    assert reference_target(DEFAULTS) == LADDER[0]
    assert cli.run_config("ladder") is DEFAULTS


def test_guided_reference_is_the_part_2_screening_target():
    config = cli.run_config("guided")
    assert reference_target(config).key == DEFAULTS.discovery_target_key
    assert config_hash(config) != config_hash(DEFAULTS)
    assert (config.trials_per_pair, DEFAULTS.trials_per_pair) == (1, 5)


def test_the_flag_reaches_the_orchestrator(tmp_path, monkeypatch, built_judge):
    monkeypatch.setenv("ARENA_JUDGE_DIR", str(built_judge))
    seen = []

    def run_cycle(self):
        seen.append(reference_target(self.config).key)
        return CycleOutcome("committed", 1, "all steps done")

    monkeypatch.setattr(cli.Orchestrator, "run_cycle", run_cycle)
    path = str(tmp_path / "arena.db")
    cli.main(["--db", path, "control", "start"])
    assert cli.main(["--db", path, "run", "--cycles", "1", "--reference", "guided"]) == 0
    assert cli.main(["--db", path, "run", "--cycles", "1"]) == 0
    assert seen == [DEFAULTS.discovery_target_key, LADDER[0].key]


def defender_only_script(cycles=1, first=1):
    script = phase1_mock_script(cycles, first)
    plans = [json.loads(raw) for raw in script["plan"]]
    script["plan"] = [json.dumps(dict(plan, agents_to_run=["defender"])) for plan in plans]
    return script


def test_a_guided_mock_cycle_records_its_config_in_the_manifest(tmp_path, monkeypatch, built_judge):
    monkeypatch.setenv("ARENA_JUDGE_DIR", str(built_judge))
    monkeypatch.setattr(cli, "phase1_mock_script", defender_only_script)
    path = str(tmp_path / "arena.db")
    cli.main(["--db", path, "control", "start"])
    args = ["--db", path, "run", "--cycles", "1", "--backend", "mock", "--reference", "guided"]
    assert cli.main(args) == 0
    [(recorded,)] = sqlite3.connect(path).execute("SELECT config_hash FROM manifests").fetchall()
    assert recorded == config_hash(cli.run_config("guided"))
