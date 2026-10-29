import json

import pytest

from arena import db
from arena.config import DEFAULTS
from arena.data.build import build_dataset
from arena.data.templates import synthetic_corpus
from arena.judge_client import HashReport
from arena.schemas import (
    AttackVerdict,
    BatchReport,
    EvaluateRequest,
    JudgeReport,
    QueryReply,
    QueryRequest,
    ValidateBatchRequest,
)

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


def numbered(script: dict[str, list], conn) -> dict[str, list]:
    """Number each scripted plan after the cycles already in the database, since a hypothesis an
    earlier cycle tried is refused. Plans that are not JSON objects are left as they are."""
    start = conn.execute("SELECT COUNT(*) FROM cycles").fetchone()[0]
    plans = []
    for n, raw in enumerate(script.get("plan", []), start + 1):
        plan = json.loads(raw) if isinstance(raw, str) else None
        if isinstance(plan, dict) and plan:
            raw = json.dumps(plan | {"hypothesis_text": f"Scripted plan {n}."})
        plans.append(raw)
    return script | {"plan": plans}


class FakeJudge:
    """Stands in for the Judge process in tests that are not about the process itself."""

    def __init__(self, hashes_ok: bool = True, keep: bool = True):
        self.hashes_ok = hashes_ok
        self.keep = keep
        self.evaluations: list[int] = []
        self.candidates: list[EvaluateRequest] = []
        self.batches: list[ValidateBatchRequest] = []
        self.queries: list[QueryRequest] = []
        # Kept by (cycle, step), as the Judge keeps them, so a repeated step spends nothing.
        self._replies: dict[tuple[int, str], QueryReply] = {}

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

    def evaluate_candidate(self, request: EvaluateRequest) -> JudgeReport:
        """Keeps every candidate unless `keep` is false; the decision is the test's to choose."""
        self.candidates.append(request)
        if self.keep:
            return STUB_REPORT.model_copy(update={"decision": "keep", "reason_code": "kept"})
        return STUB_REPORT.model_copy(update={"decision": "reject", "reason_code": "no_tpr_gain"})

    def query_detector(self, request: QueryRequest) -> QueryReply:
        self.queries.append(request)
        key = (request.cycle_id, request.step)
        if key not in self._replies:
            spent = sum(cycle == request.cycle_id for cycle, _ in self._replies)
            remaining = DEFAULTS.query_budget_t2 - spent - 1
            self._replies[key] = QueryReply(flagged=len(request.text) % 2 == 0, remaining=remaining)
        return self._replies[key]

    def validate_batch(self, request: ValidateBatchRequest) -> BatchReport:
        """Every attack valid and one in three evading, each in its own cluster; the second
        evading cluster is held back, as the Judge's seeded split would hold back half."""
        self.batches.append(request)
        evaded = [index % 3 == 0 for index in range(len(request.attacks))]
        held = {index for index in range(len(evaded)) if evaded[index]}
        held = set(sorted(held)[1::2])
        verdicts = [
            AttackVerdict(
                index=index,
                technique="override.direct",
                cluster_id=f"c{request.cycle_id}-{index}",
                refused=False,
                valid=True,
                evaded=evaded[index],
                held_back=index in held,
                classified=True,
                behaviour=f"{attack.channel}:sent_to_attacker",
            )
            for index, attack in enumerate(request.attacks)
        ]
        return BatchReport(
            verdicts=verdicts, evading_clusters=sum(evaded), held_back_clusters=len(held)
        )


@pytest.fixture(autouse=True)
def no_real_private_data(tmp_path, monkeypatch):
    """Point the private data folder at a temporary one, so no test reads the real build."""
    monkeypatch.setenv("ARENA_PRIVATE_DATA", str(tmp_path / "private-data"))


@pytest.fixture
def built_judge(tmp_path):
    """A Judge data folder built from the synthetic corpus, for tests that run the real Judge
    process through a cycle. The sealed test files are removed, so the committed placeholder pin
    still verifies; the Judge never opens test for a query or a batch check."""
    from tests.test_baseline import SMALL

    judge_dir = tmp_path / "judge"
    build_dataset(
        synthetic_corpus(),
        judge_dir=judge_dir,
        private_dir=tmp_path / "build-private",
        config=SMALL,
    )
    for name in ("test.jsonl", "test_pairs.jsonl"):
        (judge_dir / name).unlink(missing_ok=True)
    return judge_dir


@pytest.fixture
def conn(tmp_path):
    connection = db.connect(tmp_path / "arena.db")
    with db.transaction(connection):
        db.set_control(connection, "running", "test")
    yield connection
    connection.close()
