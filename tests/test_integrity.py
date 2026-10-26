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
    "arena/judge/data.py": "89281c06be6451fc7632b8a336a1a8af148eaa3cd440970a9ea3b6c61bd0af15",
    "arena/judge/hashing.py": "a62562b195e5634c0e2c65df952f70619cecd162b7ce4443378c9fae8ca3e395",
    "arena/judge/measure.py": "eae6260838f27a880aa70e8eb3b5d58076dbc4c094e7b3dd0a23a7a2894206dd",
    "arena/judge/process.py": "4546c00899d463772dd50007c4a35c3541b05f2f4868f14fe17a944c30318c76",
    "arena/judge/stats.py": "0c7f898a271ae05ee890b35d7b113c21df46c03e4993d0b3fa37a967075c5dc8",
    "arena/judge/store.py": "2b71cb72a0862c0bf2622540099e009127363cad9fc0fff5722677fbb925fabf",
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
