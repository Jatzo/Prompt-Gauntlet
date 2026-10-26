import sqlite3
from dataclasses import replace

from arena import llm
from arena.judge import store
from arena.llm import CachedOutput
from arena.schemas import DetectorResult


def output(key: str, valid: bool = True) -> CachedOutput:
    return CachedOutput(
        key=key,
        item_id=f"item-{key}",
        raw_output='{"score": 1}',
        valid=valid,
        failure=None if valid else "hijack: unknown fields ['x']",
        model_id="m",
        input_tokens=10,
        output_tokens=2,
        backend="live",
    )


def test_a_new_judge_database_is_created_at_the_current_schema(tmp_path):
    conn = store.connect(tmp_path / "judge.db")
    assert conn.execute("SELECT version FROM schema_version").fetchone()[0] == store.SCHEMA_VERSION
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"llm_calls", "usage", "events", "evaluations", "eval_cache"} <= tables


def test_a_version_1_database_migrates_forward_and_keeps_its_rows(tmp_path):
    path = tmp_path / "judge.db"
    conn = sqlite3.connect(path)
    for statement in store._V1:
        conn.execute(statement)
    conn.execute("INSERT INTO schema_version (version) VALUES (1)")
    conn.execute("INSERT INTO evaluations (cycle_id, report, created_at) VALUES (7, '{}', 'now')")
    conn.commit()
    conn.close()

    migrated = store.connect(path)
    version = migrated.execute("SELECT version FROM schema_version").fetchone()[0]
    assert version == store.SCHEMA_VERSION
    assert migrated.execute("SELECT cycle_id FROM evaluations").fetchall() == [(7,)]
    store.EvalCache(migrated).store_many([output("k")])


def test_the_cache_round_trips_valid_and_invalid_outputs(tmp_path):
    cache = store.EvalCache(store.connect(tmp_path / "judge.db"))
    cache.store_many([output("a"), output("b", valid=False)])
    found = cache.lookup_many(["a", "b", "missing"])
    assert set(found) == {"a", "b"}
    assert found["a"] == output("a") and not found["b"].valid
    assert cache.tokens() == (20, 4)


def test_lookup_handles_more_keys_than_sqlite_binds_at_once(tmp_path):
    cache = store.EvalCache(store.connect(tmp_path / "judge.db"))
    cache.store_many([output(str(i)) for i in range(1200)])
    assert len(cache.lookup_many([str(i) for i in range(1200)])) == 1200


def test_call_batch_works_against_the_judge_cache(tmp_path):
    cache = store.EvalCache(store.connect(tmp_path / "judge.db"))

    class Backend:
        name = "test"

        def complete(self, *, role, model_id, step_key, request):
            body = '{"score": 5.0, "label": "benign", "reasons": []}'
            return llm.LLMResponse(tool="report_score", raw_output=body, model_id=model_id)

    request = llm.LLMRequest(tool="report_score", tools=(), system="s", user="u")
    [result] = llm.call_batch(
        "detector", [llm.KeyedRequest("i", 0, request)], DetectorResult, cache, backend=Backend()
    )
    assert result.score == 5.0
    assert cache.conn.execute("SELECT COUNT(*) FROM eval_cache").fetchone()[0] == 1


def test_a_judge_that_read_an_old_version_does_not_migrate_twice(tmp_path, monkeypatch):
    path = tmp_path / "judge.db"
    store.connect(path).close()
    real = store._version
    reads = []

    def stale_first(conn):
        # The first read happens before another Judge's migration commits.
        reads.append(1)
        return 1 if len(reads) == 1 else real(conn)

    monkeypatch.setattr(store, "_version", stale_first)
    conn = store.connect(path)
    assert len(reads) == 2
    assert conn.execute("SELECT version FROM schema_version").fetchone()[0] == store.SCHEMA_VERSION


def test_usage_for_one_model_leaves_out_every_other_model(tmp_path):
    cache = store.EvalCache(store.connect(tmp_path / "judge.db"))
    target_turn = replace(output("t"), model_id="target", input_tokens=1500, output_tokens=100)
    mock = replace(output("c"), backend="mock", input_tokens=900)
    cache.store_many([output("a"), output("b"), target_turn, mock])
    assert cache.usage_for("m", "live") == (24, 2)
    assert cache.usage_for("target", "live") == (1600, 1)
    assert cache.usage_for("m", "mock") == (902, 1)


def test_a_version_2_cache_gains_a_backend_column_and_keeps_its_rows(tmp_path):
    path = tmp_path / "judge.db"
    conn = sqlite3.connect(path, isolation_level=None)
    for statement in [*store._V1, *store._V2]:
        conn.execute(statement)
    conn.execute("INSERT INTO schema_version (version) VALUES (2)")
    conn.execute(
        "INSERT INTO eval_cache (key, item_id, raw_output, valid, failure, model_id,"
        " input_tokens, output_tokens, created_at) VALUES ('k', 'i', '{}', 1, NULL, 'm', 5, 1, 't')"
    )
    conn.close()
    cache = store.EvalCache(store.connect(path))
    assert cache.lookup_many(["k"])["k"].backend == ""
    assert cache.usage_for("m", "") == (6, 1)
