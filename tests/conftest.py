import pytest

from arena import db
from arena.judge_client import HashReport
from arena.schemas import JudgeReport

STUB_REPORT = JudgeReport.model_validate(
    {
        "asr": None,
        "utility": None,
        "tpr_at_target_fpr": None,
        "achieved_fpr": None,
        "per_category_fpr": {},
        "regression_status": "not_run",
        "decision": "none",
        "reason_code": "not_implemented",
    }
)


class FakeJudge:
    """Stands in for the Judge process in tests that are not about the process itself."""

    def __init__(self, hashes_ok: bool = True):
        self.hashes_ok = hashes_ok
        self.evaluations: list[int] = []

    def verify_hashes(self) -> HashReport:
        return HashReport(
            ok=self.hashes_ok,
            constitution="ok" if self.hashes_ok else "mismatch",
            constitution_hash="0" * 64,
            test_set="placeholder",
        )

    def evaluate(self, cycle_id: int) -> JudgeReport:
        self.evaluations.append(cycle_id)
        return STUB_REPORT


@pytest.fixture
def conn(tmp_path):
    connection = db.connect(tmp_path / "arena.db")
    with db.transaction(connection):
        db.set_control(connection, "running", "test")
    yield connection
    connection.close()
