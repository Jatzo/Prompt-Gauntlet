"""Part 2's novelty check, in mock mode: a synthetic train file and scripted rewordings, so each
count is exact. Every rule errs towards a higher `high` rate, and the tests pin that."""

import builtins
import hashlib
import json
import random
from pathlib import Path

import pytest

from arena import db, llm, novelty_check
from arena.novelty_check import PASS_MAX, SIZE, STEP, Item, Report

# Seeded filler words for a synthetic train file, not a secret.
WORDS = ["invoice", "ledger", "badge", "parcel", "rota", "memo", "vault", "token", "audit", "pager"]


def write_train(path: Path, attacks: int = 60) -> list[dict]:
    rng = random.Random(3)  # noqa: S311
    rows = []
    for i in range(attacks):
        text = f"Item {i}: " + " ".join(rng.choice(WORDS) for _ in range(30)) + " to {ATTACKER}."
        rows.append(
            {
                "id": f"train-{i:03d}",
                "label": "attack",
                "text": text,
                "generator_family": "llmail-human" if i % 5 else "agentdojo-mixed",
            }
        )
    rows.append(
        {
            "id": "train-benign",
            "label": "benign",
            "text": "Lunch is at noon.",
            "generator_family": "dolly",
        }
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps({"sample": row}) + "\n" for row in rows))
    return rows


def chunks(train_path: Path) -> list[list]:
    chosen = novelty_check.select(novelty_check._train(train_path))
    return [chosen[i : i + 10] for i in range(0, SIZE, 10)]


def heavy(i: int) -> str:
    """Text sharing no 5-gram with the synthetic train."""
    return f"Zqx {i} wjv kyb fxz qwp jvk xzq " * 4


class Recording(llm.MockBackend):
    def __post_init__(self):
        super().__post_init__()
        self.requests = []

    def complete(self, *, role, model_id, step_key, request):
        self.requests.append(request)
        return super().complete(role=role, model_id=model_id, step_key=step_key, request=request)


def reply(items: list[tuple[int, str]]) -> str:
    return json.dumps({"rewordings": [{"source": n, "text": t} for n, t in items]})


@pytest.fixture
def setup(tmp_path):
    train = tmp_path / "private" / "train.jsonl"
    write_train(train)
    c = chunks(train)
    retries = llm.DEFAULTS.retries + 1
    script = {
        STEP: [
            # Call 1: verbatim copies, with case and spacing changed.
            reply([(n, "  " + s.text.upper() + " ") for n, s in enumerate(c[0], 1)]),
            # Call 2: heavy rewrites.
            reply([(n, heavy(n)) for n, _ in enumerate(c[1], 1)]),
            # Call 3: light rewrites, which keep almost every 5-gram.
            reply([(n, s.text + " Thanks.") for n, s in enumerate(c[2], 1)]),
            # Call 4: declined: no valid output in any attempt.
            *["not json"] * retries,
            # Call 5: half missing, and source 1 twice (the first is kept).
            reply(
                [(1, heavy(101)), (1, c[4][0].text), *[(n, heavy(100 + n)) for n in range(2, 6)]]
            ),
        ]
    }
    conn = db.connect(tmp_path / "novelty-check.db")
    yield train, conn, Recording(script=script), c
    conn.close()


def test_the_fifty_follow_the_pre_registered_order_and_skip_benign_rows(tmp_path):
    train = tmp_path / "train.jsonl"
    rows = write_train(train)
    chosen = novelty_check.select(novelty_check._train(train))
    attacks = [r for r in rows if r["label"] == "attack"]
    expected = sorted(
        attacks, key=lambda r: hashlib.sha256(f"novelty-check:{r['id']}".encode()).hexdigest()
    )[:SIZE]
    assert [s.id for s in chosen] == [r["id"] for r in expected]


def test_every_kind_of_rewording_is_counted_towards_the_worst_case(setup):
    train, conn, backend, _ = setup
    counts = novelty_check.run(conn, backend=backend, train_path=train).counts
    assert (counts["verbatim"], counts["declined"], counts["missing"]) == (10, 10, 5)
    assert counts["high"] == 15 and counts["low"] == 10
    assert counts["worst_case_rate"] == pytest.approx((15 + 25) / SIZE)
    assert counts["high_rate"] == pytest.approx(15 / SIZE)
    assert not counts["passes"]
    assert counts["dropped_placeholder"] == 15


def test_the_check_passes_at_five_and_fails_at_six():
    def report(high, bad):
        items = [Item("s", "f", band="high") for _ in range(high)]
        items += [Item("s", "f", bad="missing") for _ in range(bad)]
        items += [Item("s", "f", band="low") for _ in range(SIZE - high - bad)]
        return Report(0.6, items)

    assert report(PASS_MAX - 1, 1).counts["passes"]
    assert not report(PASS_MAX, 1).counts["passes"]


def test_a_resumed_check_makes_no_new_call_and_never_re_asks_a_declined_one(setup):
    train, conn, backend, _ = setup
    first = novelty_check.run(conn, backend=backend, train_path=train).counts
    asked = len(backend.requests)
    again = novelty_check.run(conn, backend=backend, train_path=train).counts
    assert again == first and len(backend.requests) == asked


def test_the_check_writes_no_novelty_archive(setup):
    train, conn, backend, _ = setup
    novelty_check.run(conn, backend=backend, train_path=train)
    assert conn.execute("SELECT COUNT(*) FROM novelty_archive").fetchone()[0] == 0


def test_the_check_never_opens_the_test_set_or_a_judge_file(setup, monkeypatch):
    train, conn, backend, _ = setup
    opened = []
    real_open, real_read = builtins.open, Path.read_text

    def spy_open(file, *args, **kwargs):
        opened.append(str(file))
        return real_open(file, *args, **kwargs)

    def spy_read(self, *args, **kwargs):
        opened.append(str(self))
        return real_read(self, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", spy_open)
    monkeypatch.setattr(Path, "read_text", spy_read)
    novelty_check.run(conn, backend=backend, train_path=train)
    assert not [p for p in opened if p.endswith("test.jsonl") or "judge" in p.split("/")]


def test_the_cli_prints_counts_and_writes_ids_not_text_under_private(
    setup, tmp_path, monkeypatch, capsys
):
    from arena import cli

    train, _, backend, c = setup
    monkeypatch.setenv("ARENA_PRIVATE_DATA", str(train.parent))
    monkeypatch.setattr(cli, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(cli.llm, "get_backend", lambda *a, **k: backend)
    code = cli.main(["--db", str(tmp_path / "nc.db"), "discover", "novelty-check"])
    assert code == cli.ExitCode.OK
    printed = capsys.readouterr().out
    assert "does not pass" in printed and "worst case 80%" in printed
    assert c[0][0].text not in printed
    written = (tmp_path / "private" / "findings" / "novelty-check.jsonl").read_text()
    assert c[0][0].id in written and c[0][0].text not in written
    assert len(written.splitlines()) == SIZE


def test_a_database_holding_another_backends_calls_is_refused(setup, tmp_path):
    train, conn, backend, _ = setup
    novelty_check.run(conn, backend=backend, train_path=train)
    other = Recording(script={}, name="mock-other")
    with pytest.raises(novelty_check.MixedBackends, match="mock-other"):
        novelty_check.run(conn, backend=other, train_path=train)
    assert other.requests == []


def test_each_backend_gets_its_own_database_by_default():
    from arena import cli

    assert cli.novelty_check_db("mock") != cli.novelty_check_db("live")
    assert cli.novelty_check_db("live").name == "novelty-check-live.db"


def test_duplicate_rewordings_are_counted_and_the_first_one_kept(setup):
    train, conn, backend, _ = setup
    counts = novelty_check.run(conn, backend=backend, train_path=train).counts
    assert counts["duplicates"] == 1


def test_an_anomaly_in_the_check_exits_for_the_operator(tmp_path, monkeypatch, capsys):
    from arena import cli
    from arena.anomaly import HijackDetected

    def hijacked(*args, **kwargs):
        raise HijackDetected("steered", role="rewriter", step=STEP)

    monkeypatch.setattr(cli.novelty_check, "run", hijacked)
    code = cli.main(["--db", str(tmp_path / "nc.db"), "discover", "novelty-check"])
    assert code == cli.ExitCode.NEEDS_OPERATOR
    assert "paused for the operator" in capsys.readouterr().err
