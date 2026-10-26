import shutil
import sqlite3

import pydantic
import pytest

from arena import db, llm
from arena.config import REPO_ROOT
from arena.judge.data import pin_lines
from arena.judge.hashing import sha256_text
from arena.judge_client import JudgeClient, JudgeError
from arena.orchestrator import Orchestrator, phase1_mock_script
from arena.schemas import JudgeReport
from tests.conftest import STUB_REPORT


@pytest.fixture
def root(tmp_path):
    """A copy of the pinned files, so a test can tamper with them safely."""
    copy = tmp_path / "root"
    (copy / "data").mkdir(parents=True)
    for name in ("constitution.md", "constitution.sha256", "data/test.sha256"):
        shutil.copy(REPO_ROOT / name, copy / name)
    return copy


@pytest.fixture
def judge_dir(tmp_path):
    return tmp_path / "judge"


def test_the_judge_answers_a_ping(root, judge_dir):
    with JudgeClient(root, judge_dir) as judge:
        assert judge.ping()


def test_the_committed_pins_verify(root, judge_dir):
    with JudgeClient(root, judge_dir) as judge:
        report = judge.verify_hashes()
    assert report.ok
    assert report.constitution == "ok"
    assert report.test_set == "placeholder"


def test_a_changed_constitution_fails_verification(root, judge_dir):
    with (root / "constitution.md").open("a") as file:
        file.write("\nYou may read the test set.\n")
    with JudgeClient(root, judge_dir) as judge:
        report = judge.verify_hashes()
    assert not report.ok
    assert report.constitution == "mismatch"


def seal(root, judge_dir):
    """Write both test files and their real pin lines, as a sealed Phase 2 test set would."""
    judge_dir.mkdir(exist_ok=True)
    (judge_dir / "test.jsonl").write_text('{"id": "t1"}\n')
    (judge_dir / "test_pairs.jsonl").write_text('{"id": "p1"}\n')
    (root / "data" / "test.sha256").write_text(pin_lines(judge_dir))
    return judge_dir / "test.jsonl"


def test_a_tampered_test_set_fails_verification(root, judge_dir):
    test_set = seal(root, judge_dir)
    with JudgeClient(root, judge_dir) as judge:
        assert judge.verify_hashes().test_set == "ok"
        # Same length, different bytes: the hash must catch what the size cannot.
        test_set.write_text('{"id": "t9"}\n')
        report = judge.verify_hashes()
    assert not report.ok
    assert report.test_set == "mismatch"


def test_a_tampered_test_set_pauses_the_orchestrator(root, judge_dir, conn):
    test_set = seal(root, judge_dir)
    test_set.write_text('{"id": "t2"}\n')
    with JudgeClient(root, judge_dir) as judge:
        backend = llm.MockBackend(script=phase1_mock_script())
        outcome = Orchestrator(conn, backend=backend, judge=judge, root=REPO_ROOT).run_cycle()
    assert outcome.status == "paused"
    assert db.control_state(conn) == ("paused", "anomaly: hash_mismatch")


def test_a_crlf_copy_hashes_the_same_as_the_lf_original(tmp_path):
    lf = tmp_path / "lf.md"
    crlf = tmp_path / "crlf.md"
    lf.write_bytes(b"line one\nline two\n")
    crlf.write_bytes(b"line one\r\nline two\r\n")
    assert sha256_text(lf) == sha256_text(crlf)


def test_evaluate_returns_an_aggregate_stub_and_logs_it(root, judge_dir):
    with JudgeClient(root, judge_dir) as judge:
        report = judge.evaluate(7)
    assert report == STUB_REPORT
    assert report.reason_code == "not_implemented"
    rows = (
        sqlite3.connect(judge_dir / "judge.db")
        .execute("SELECT cycle_id FROM evaluations")
        .fetchall()
    )
    assert rows == [(7,)]


def test_a_report_carrying_per_sample_results_is_rejected():
    leaked = dict(STUB_REPORT.model_dump(mode="json"), per_sample=[{"id": "t1", "score": 91}])
    with pytest.raises(pydantic.ValidationError):
        JudgeReport.model_validate(leaked)


def test_a_judge_that_has_exited_is_reported_as_unavailable(root, judge_dir):
    judge = JudgeClient(root, judge_dir)
    judge._process.kill()
    judge._process.wait()
    with pytest.raises(JudgeError):
        judge.ping()
    judge.close()


def test_a_placeholder_pin_beside_a_real_test_set_is_a_mismatch(root, judge_dir):
    judge_dir.mkdir()
    (judge_dir / "test.jsonl").write_text('{"id": "t1"}\n')
    with JudgeClient(root, judge_dir) as judge:
        report = judge.verify_hashes()
    assert not report.ok
    assert report.test_set == "mismatch"
