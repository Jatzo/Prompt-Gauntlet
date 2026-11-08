"""The open-model pilot script picks the rung PLAN section 7 names: the guided switch gives the
part 2 screening target, and closed-model rungs are refused. No model is called."""

import importlib.util

import pytest

from arena.config import DEFAULTS, REPO_ROOT

_spec = importlib.util.spec_from_file_location(
    "gemma_pilot", REPO_ROOT / "scripts" / "gemma_pilot.py"
)
pilot = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pilot)


def test_guided_switch_gives_the_screening_target(monkeypatch):
    monkeypatch.delenv("PILOT_SIGNATURES", raising=False)
    monkeypatch.setenv("PILOT_GUIDED", "1")
    number, rung = pilot.pick_rung(["gemma_pilot.py", "3"])
    assert number == 3
    assert rung.key == DEFAULTS.discovery_target_key


def test_default_is_plain_rung_three(monkeypatch):
    monkeypatch.delenv("PILOT_SIGNATURES", raising=False)
    monkeypatch.delenv("PILOT_GUIDED", raising=False)
    _, rung = pilot.pick_rung(["gemma_pilot.py"])
    assert rung.key == "target_open.strict.standard"


def test_closed_model_rungs_are_refused(monkeypatch):
    monkeypatch.delenv("PILOT_GUIDED", raising=False)
    with pytest.raises(AssertionError):
        pilot.pick_rung(["gemma_pilot.py", "0"])
