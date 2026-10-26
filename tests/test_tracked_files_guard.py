import pytest

from scripts.check_tracked_files import forbidden_paths

BAD = [
    "private/phase1-plan.md",
    "private/attacks/corpus.jsonl",
    "runs/arena.db",
    "runs/digests/0010.md",
    "anything/else.db",
    "voice.md",
    "VOICE.md",
    "docs/Voice.md",
    ".env",
    "config/.env.local",
    "CLAUDE.md",
    "data/test.jsonl",
    "data/test_adaptive.jsonl",
    "data/test.sha256.bak",
    "data/testset.csv",
    "recordings/run1.cassette.jsonl",
    "tests/run2.cassette.jsonl",
]

GOOD = [
    "PLAN.md",
    "data/test.sha256",
    "data/public_dev.jsonl",
    "arena/db.py",
    "docs/private-notes-policy.md",
    "tests/fixtures/plan_step.cassette.jsonl",
    "tests/test_db.py",
]


@pytest.mark.parametrize("path", BAD)
def test_the_guard_rejects_a_private_or_runtime_path(path):
    assert forbidden_paths([path]) == [path]


@pytest.mark.parametrize("path", GOOD)
def test_the_guard_allows_an_ordinary_source_path(path):
    assert forbidden_paths([path]) == []


def test_the_guard_reports_only_the_bad_paths_in_a_mixed_list():
    assert forbidden_paths(GOOD + BAD) == BAD
