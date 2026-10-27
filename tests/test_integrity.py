"""Hash pins for the Judge, the constitution and the test-set commitment.

These files change only on the operator's explicit instruction. Any edit fails here until the pin
below is updated deliberately, in the same commit, so an accidental or agent-made change cannot slip
through quietly.
"""

from pathlib import Path

import pytest

from arena.judge.hashing import read_pin, sha256_text

ROOT = Path(__file__).resolve().parents[1]

PINS = {
    "arena/judge/__init__.py": "78b75ca2d6c0e4cebcd829adee180b0b1a629c9bae05d8720ee61e2779da03c2",
    "arena/judge/__main__.py": "b8416a83c61e63dbb058d9da8b2081352431655890d78420a18ef986fc8cb5d3",
    "arena/judge/attacks.py": "1f3a53081b67b6b2c0e50c2adc988896c802b9ee885ac702ce4e00099083a827",
    "arena/judge/data.py": "c6d33139e81dc4a76b4ec4a84ad19ee192d9a35df56fa9d7d133e63f1965c712",
    "arena/judge/hashing.py": "a62562b195e5634c0e2c65df952f70619cecd162b7ce4443378c9fae8ca3e395",
    "arena/judge/keep.py": "ea1869b75d071c0f0da7b96a35bd6e6792c7e57ceb7ac9972e492b3c5b840d53",
    "arena/judge/labelcheck.py": "d7dd3b241fe20dccb643d831577ef69b9f13a26d1978e7e08899c7b570d80e44",
    "arena/judge/measure.py": "765ae5d2a015b59e1e8ae1945c0da5e798d4c49f14452b07db2d2e09a89a39ba",
    "arena/judge/process.py": "322fa8c4d88057adc7407b2b7a7be5c29114dc08cc82729fce3bb7bc63c6c9ba",
    "arena/judge/stats.py": "5e2a2037b4131e811c52e0c38a434a6bf8fac2019ade613acc927e7aac8ebf63",
    "arena/judge/store.py": "3ed4fbc5df9bcebeaedcef27c26d2e4bbc35ccfa3782a2b0daa43c48cae2f6ca",
    "constitution.md": "f823500c55e3efc4a1c03aa0242b786484866938b3758eddbc832109143b9616",
    "data/test.sha256": "730573c29ee86e63e87cfd2c1e27f0c2a9c6a33a433dfb9b379718629b7bf51b",
    "tests/fixtures/known_answer.json": "18f35c94e49fbeb05c902cfba78e62184fdd65186c1fd186c016e75eeb8355c8",
}


@pytest.mark.parametrize("path", sorted(PINS))
def test_a_pinned_file_is_unchanged(path):
    assert sha256_text(ROOT / path) == PINS[path], (
        f"{path} changed. It may only change on explicit instruction; then update its pin here."
    )


def test_every_judge_file_is_pinned():
    judge_files = {
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "arena" / "judge").rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }
    assert judge_files <= PINS.keys(), f"unpinned Judge files: {sorted(judge_files - PINS.keys())}"


def test_the_constitution_pin_the_judge_reads_matches_this_one():
    assert read_pin(ROOT / "constitution.sha256") == PINS["constitution.md"]
