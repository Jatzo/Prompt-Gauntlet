import json
import re
import shutil
import sqlite3

import pydantic
import pytest

from arena import db, llm
from arena.config import DEFAULTS, REPO_ROOT
from arena.judge.data import pin_lines
from arena.judge.hashing import sha256_text
from arena.judge_client import JudgeClient, JudgeError
from arena.orchestrator import Orchestrator, phase1_mock_script
from arena.schemas import AttackVerdict, JudgeReport
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


@pytest.mark.parametrize("which", ["fake", "real"])
def test_one_attack_cycle_gives_the_same_shape_from_the_fake_and_the_real_judge(
    which, conn, built_judge
):
    """The contract the fake must keep: what the orchestrator stores from the real Judge."""
    from tests.conftest import FakeJudge

    backend = llm.MockBackend(script=phase1_mock_script())
    if which == "fake":
        outcome = Orchestrator(conn, backend=backend, judge=FakeJudge()).run_cycle()
    else:
        with JudgeClient(REPO_ROOT, built_judge) as judge:
            outcome = Orchestrator(conn, backend=backend, judge=judge).run_cycle()
    assert outcome.status == "committed", outcome.detail
    [body] = [
        json.loads(row[0])
        for row in conn.execute("SELECT body FROM memory_episodic WHERE kind = 'attack_batch'")
    ]
    assert len(body["texts"]) == len(body["verdicts"]) == len(body["bands"]) == 1
    verdicts = [AttackVerdict.model_validate(verdict) for verdict in body["verdicts"]]
    for verdict in verdicts:
        # Only a valid attack can evade, and only an evading one can be held back.
        assert not verdict.evaded or verdict.valid
        assert not verdict.held_back or verdict.evaded
        assert verdict.valid == (verdict.behaviour is not None)
    detail = json.loads(
        conn.execute("SELECT detail FROM events WHERE kind = 'step_done'").fetchall()[1][0]
    )
    assert detail["step"] == "attack"
    counts = re.fullmatch(r"(\d+) attacks, (\d+) valid, (\d+) evading clusters", detail["outcome"])
    attacks, valid, evading = (int(group) for group in counts.groups())
    assert attacks == len(verdicts)
    assert valid == sum(verdict.valid for verdict in verdicts)
    assert evading == len({verdict.cluster_id for verdict in verdicts if verdict.evaded})


def cassette_from(script, path):
    """A cassette holding exactly what the mock script would answer, step by step. A replay
    fills in nothing, so the plan's placeholder focus becomes `explore`, which is always listed."""
    from arena.memory.shortlist import EXPLORE, FIRST_LISTED

    tools = {
        "plan": ("ceo", "propose_plan"),
        "defend": ("defender", "submit_detector_patch"),
        "postmortem": ("ceo", "write_postmortem"),
    }
    models = DEFAULTS.models
    with path.open("w") as out:
        for step, outputs in script.items():
            role, tool = tools.get(step, ("attacker", "query_detector"))
            if step == "attack.submit":
                tool = "submit_attack_batch"
            for raw in outputs:
                entry = {
                    "role": role,
                    "step": step,
                    "tool": tool,
                    "raw_output": raw.replace(FIRST_LISTED, EXPLORE),
                    "model_id": getattr(models, role),
                }
                out.write(json.dumps(entry) + "\n")
    return path


@pytest.mark.parametrize("which", ["fake", "real"])
def test_a_replayed_cycle_with_the_attacker_commits(which, conn, built_judge, tmp_path):
    """Phase 3's replay runs: the agents' calls come from the cassette, and the Judge measures with
    its simulated models, since the cassette holds none of its answers."""
    from tests.conftest import FakeJudge

    cassette = cassette_from(phase1_mock_script(), tmp_path / "cycle.cassette.jsonl")
    backend = llm.ReplayBackend(cassette)
    if which == "fake":
        judge = FakeJudge()
        outcome = Orchestrator(conn, backend=backend, judge=judge).run_cycle()
        assert {batch.measure.backend for batch in judge.batches} == {"mock"}
    else:
        with JudgeClient(REPO_ROOT, built_judge) as judge:
            outcome = Orchestrator(conn, backend=backend, judge=judge).run_cycle()
    assert outcome.status == "committed", outcome.detail
    kinds = [row[0] for row in conn.execute("SELECT kind FROM memory_episodic ORDER BY id")]
    assert "attack_batch" in kinds
