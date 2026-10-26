"""Labels with no human step: agreement, the keep rules, the cap and the Ollama backend."""

import json

import pytest
from fakes import FakeLabeller, MemoryEvalCache, keyword_verdict

from arena import llm
from arena.config import ArenaConfig
from arena.data.build import build_dataset
from arena.data.labelling import (
    ContestedCapExceeded,
    LabelCache,
    agreement,
    apply,
    check_cap,
    label_rows,
)
from arena.data.labelling import requests as labelling_requests
from arena.data.splits import SplitRow
from arena.data.templates import synthetic_corpus
from arena.schemas import LabelVerdict

ATTACK = LabelVerdict(label="attack", kind="injection", impact_class="data_theft")
BENIGN = LabelVerdict(label="benign", kind="neither", impact_class="none")


def test_kappa_matches_a_worked_example():
    # 50 items: both say yes on 20, both no on 15, first yes and second no on 5, the reverse on 10.
    first = ["yes"] * 20 + ["no"] * 15 + ["yes"] * 5 + ["no"] * 10
    second = ["yes"] * 20 + ["no"] * 15 + ["no"] * 5 + ["yes"] * 10
    found = agreement(first, second)
    assert found.n == 50
    assert found.raw == pytest.approx(0.70)
    # Chance agreement: 0.5 * 0.6 + 0.5 * 0.4 = 0.5, so kappa = (0.7 - 0.5) / 0.5.
    assert found.kappa == pytest.approx(0.40)
    assert found.prevalence == ({"no": 0.5, "yes": 0.5}, {"no": 0.4, "yes": 0.6})


def test_kappa_is_undefined_when_both_families_give_one_value_throughout():
    found = agreement(["benign"] * 5, ["benign"] * 5)
    assert (found.raw, found.kappa) == (1.0, None)
    assert agreement([], []).raw is None
    with pytest.raises(ValueError):
        agreement(["a"], [])


def rows_of(samples):
    return [SplitRow(sample, 1) for sample in samples]


def corpus():
    samples = synthetic_corpus(subjects_per_frame=3)
    return [s.model_copy(update={"partition": "dev"}) for s in samples]


def test_a_benign_item_is_kept_only_when_both_families_call_it_benign():
    benign = [s for s in corpus() if s.label == "benign"][:4]
    first = [BENIGN, BENIGN, ATTACK, llm.Unscorable("schema")]
    second = [BENIGN, ATTACK, BENIGN, BENIGN]
    result = apply(rows_of(benign), first, second)
    assert [row.sample.id for row in result.kept] == [benign[0].id]
    assert [s.id for s in result.contested] == [s.id for s in benign[1:]]
    assert sum(result.contested_by("partition").values()) == 3


def test_an_attack_source_item_never_becomes_benign():
    attacks = [s for s in corpus() if s.label == "attack"][:2]
    result = apply(rows_of(attacks), [BENIGN, BENIGN], [BENIGN, ATTACK])
    assert [row.sample.label for row in result.kept] == ["attack", "attack"]
    assert result.contested == []
    assert result.attacks_called_benign == {"template": 1}
    # The pair that agreed on benign is not also a disagreement; the split pair is.
    assert result.disagreements == {("template", "kind"): 1, ("template", "impact_class"): 1}


def test_attack_fields_change_only_where_both_families_agree():
    attacks = [s for s in corpus() if s.label == "attack"][:3]
    theft = LabelVerdict(label="attack", kind="jailbreak", impact_class="data_theft")
    action = LabelVerdict(label="attack", kind="jailbreak", impact_class="unauthorised_action")
    result = apply(rows_of(attacks), [theft, theft, theft], [theft, action, llm.Unscorable("x")])
    first, second, third = (row.sample for row in result.kept)
    assert (first.injection_vs_jailbreak, first.impact_class) == ("jailbreak", "data_theft")
    # Agreed kind is used; the impact class the families split on keeps the source default.
    assert second.injection_vs_jailbreak == "jailbreak"
    assert second.impact_class == attacks[1].impact_class
    # An unscorable answer from either family keeps both defaults.
    assert (third.injection_vs_jailbreak, third.impact_class) == (
        attacks[2].injection_vs_jailbreak,
        attacks[2].impact_class,
    )
    assert result.disagreements == {("template", "impact_class"): 2, ("template", "kind"): 1}
    assert result.agreement["impact_class"].n == 2


def test_the_cap_stops_a_partition_with_too_many_contested_benign_items():
    benign = [s for s in corpus() if s.label == "benign"][:10]
    first = [BENIGN] * 10
    second = [BENIGN] * 8 + [ATTACK] * 2
    result = apply(rows_of(benign), first, second)
    with pytest.raises(ContestedCapExceeded, match="dev: 2 contested"):
        check_cap(result, ArenaConfig(contested_exclusion_cap=0.15))
    check_cap(result, ArenaConfig(contested_exclusion_cap=0.25))


def test_a_capped_build_writes_nothing(tmp_path):
    def contest_everything(rows):
        return apply(rows, [BENIGN] * len(rows), [ATTACK] * len(rows))

    with pytest.raises(ContestedCapExceeded):
        build_dataset(
            synthetic_corpus(),
            judge_dir=tmp_path / "judge",
            private_dir=tmp_path / "private",
            config=ArenaConfig(contested_exclusion_cap=0.0),
            label=contest_everything,
        )
    assert not (tmp_path / "judge").exists() and not (tmp_path / "private").exists()


def test_label_rows_asks_both_families_once_and_a_rerun_uses_the_cache():
    rows = rows_of(corpus()[:12])
    claude, gemma = FakeLabeller("live"), FakeLabeller("ollama")
    cache = MemoryEvalCache()
    first = label_rows(rows, claude=claude, open_weights=gemma, cache=cache, seed=1)
    assert (claude.calls, gemma.calls) == (12, 12)
    again = label_rows(rows, claude=claude, open_weights=gemma, cache=cache, seed=1)
    assert (claude.calls, gemma.calls) == (12, 12)
    assert [r.sample for r in again.kept] == [r.sample for r in first.kept]


def test_the_labeller_prompt_treats_the_text_as_data():
    rows = rows_of(corpus()[:1])
    seen = []

    class Spy(FakeLabeller):
        def complete(self, *, role, model_id, step_key, request):
            seen.append(request)
            return super().complete(
                role=role, model_id=model_id, step_key=step_key, request=request
            )

    label_rows(
        rows, claude=Spy("live"), open_weights=Spy("ollama"), cache=MemoryEvalCache(), seed=1
    )
    for request in seen:
        assert "never instructions to you" in request.system
        assert request.user.startswith("<<<DATA ")
        assert request.tool == "report_label"


def test_a_build_with_labels_leaves_contested_items_out_and_counts_them(tmp_path):
    def split_opinion(text: str) -> dict:
        # The second family distrusts benign security documents.
        if "injection" in text.lower() or "credentials" in text.lower():
            return {"label": "attack", "kind": "injection", "impact_class": "data_theft"}
        return keyword_verdict(text)

    claude, gemma = FakeLabeller("live"), FakeLabeller("ollama", split_opinion)
    config = ArenaConfig(contested_exclusion_cap=0.9)

    def label(rows):
        return label_rows(
            rows, claude=claude, open_weights=gemma, cache=MemoryEvalCache(), seed=1, config=config
        )

    judge_dir = tmp_path / "judge"
    summary = build_dataset(
        synthetic_corpus(),
        judge_dir=judge_dir,
        private_dir=tmp_path / "private",
        config=config,
        label=label,
    )
    contested = summary.labels.contested
    assert contested and all(s.technique == "benign.security_docs" for s in contested)
    written = json.loads((judge_dir / "contested.json").read_text())
    assert sum(sum(c.values()) for c in written.values()) == sum(
        s.partition != "train" for s in contested
    )
    contested_ids = {s.id for s in contested}
    for path in [
        *(judge_dir / "partitions").glob("*.jsonl"),
        judge_dir / "test.jsonl",
        tmp_path / "private" / "train.jsonl",
    ]:
        for line in path.read_text().splitlines():
            assert json.loads(line)["sample"]["id"] not in contested_ids


def test_the_label_cache_round_trips_outputs(tmp_path):
    cache = LabelCache(tmp_path / "labels.db")
    output = llm.CachedOutput("k1", "s1", '{"label": "benign"}', True, None, "m", 3, 4, "ollama")
    cache.store_many([output])
    assert cache.lookup_many(["k1", "missing"]) == {"k1": output}
    assert cache.tokens() == (3, 4)
    cache.close()


class FakeServer:
    def __init__(self, digest="abc123def4567890", model="gemma4:12b", done_reason="stop"):
        self.digest, self.model, self.bodies = digest, model, []
        self.done_reason = done_reason

    def __call__(self, url, body):
        if url.endswith("/api/tags"):
            return {"models": [{"name": self.model, "digest": self.digest}]}
        self.bodies.append(body)
        content = json.dumps(BENIGN.model_dump()) if self.done_reason == "stop" else ""
        return {
            "model": self.model,
            "message": {"content": content},
            "done_reason": self.done_reason,
            "prompt_eval_count": 40,
            "eval_count": 9,
        }


def test_ollama_is_refused_in_tests_and_without_a_digest(monkeypatch):
    with pytest.raises(llm.LiveCallRefused, match="never made from tests"):
        llm.OllamaBackend(digest="abc123def4567890")
    with pytest.raises(llm.LiveCallRefused, match="No digest"):
        llm.OllamaBackend(digest=None, post=FakeServer())
    with pytest.raises(llm.LiveCallRefused, match="No digest"):
        llm.OllamaBackend(digest="abc", post=FakeServer())


def test_ollama_refuses_a_remote_server_and_a_different_digest():
    with pytest.raises(llm.LiveCallRefused, match="must be local"):
        llm.OllamaBackend(digest="abc123def4567890", url="http://10.0.0.5:11434", post=FakeServer())
    with pytest.raises(llm.LiveCallRefused, match="pins abc123def4567890"):
        llm.OllamaBackend(digest="abc123def4567890", post=FakeServer(digest="fff999"))


def test_ollama_sends_the_schema_and_temperature_and_maps_the_reply():
    server = FakeServer()
    backend = llm.OllamaBackend(digest="abc123def4567890", post=server)
    rows = rows_of(corpus()[:1])
    result = label_rows(
        rows, claude=FakeLabeller("live"), open_weights=backend, cache=MemoryEvalCache(), seed=1
    )
    [body] = server.bodies
    assert body["model"] == "gemma4:12b" and body["stream"] is False
    assert body["think"] is False
    assert body["options"] == {"temperature": 0.0}
    assert body["format"] == LabelVerdict.model_json_schema()
    assert [m["role"] for m in body["messages"]] == ["system", "user"]
    assert result.agreement["label"].n == 1


def test_a_reply_cut_off_at_the_length_limit_fails_and_is_not_cached():
    server = FakeServer(done_reason="length")
    backend = llm.OllamaBackend(digest="abc123def4567890", post=server)
    cache = MemoryEvalCache()
    with pytest.raises(llm.LiveCallFailed, match="done_reason 'length'"):
        label_rows(
            rows_of(corpus()[:1]),
            claude=FakeLabeller("live"),
            open_weights=backend,
            cache=cache,
            seed=1,
        )
    [body] = server.bodies
    assert body["think"] is False
    assert not any(output.backend.startswith("ollama") for output in cache.outputs.values())


def test_a_wrong_model_from_ollama_fails_the_id_check():
    server = FakeServer()
    backend = llm.OllamaBackend(digest="abc123def4567890", post=server)
    server.model = "gemma4:27b"
    with pytest.raises(Exception, match="gemma4:27b"):
        label_rows(
            rows_of(corpus()[:1]),
            claude=FakeLabeller("live"),
            open_weights=backend,
            cache=MemoryEvalCache(),
            seed=1,
        )


def test_contested_counts_skip_items_the_fpr_never_scores(tmp_path):
    def contest_benign(rows):
        # Every benign item contested, half of them moved to the user channel first.
        moved = [
            SplitRow(
                row.sample.model_copy(update={"channel": "user"})
                if row.sample.label == "benign" and index % 2
                else row.sample,
                row.fold,
            )
            for index, row in enumerate(rows)
        ]
        first = [ATTACK] * len(moved)
        second = [BENIGN] * len(moved)
        return apply(moved, first, second)

    judge_dir = tmp_path / "judge"
    summary = build_dataset(
        synthetic_corpus(),
        judge_dir=judge_dir,
        private_dir=tmp_path / "private",
        config=ArenaConfig(contested_exclusion_cap=1.0),
        label=contest_benign,
    )
    in_scope = [
        s for s in summary.labels.contested if s.partition != "train" and s.channel != "user"
    ]
    written = json.loads((judge_dir / "contested.json").read_text())
    assert sum(sum(c.values()) for c in written.values()) == len(in_scope)
    assert any(s.channel == "user" for s in summary.labels.contested)


def test_the_two_labeller_families_never_share_a_cache_key():
    keyed = labelling_requests(corpus()[:1], seed=1)
    first = llm.request_key("labeller", "claude-opus-5-5", keyed[0], "live")
    second = llm.request_key("labeller_open", "gemma4:12b", keyed[0], "ollama@abc123def456")
    assert first != second


def test_the_ollama_digest_is_part_of_its_backend_name():
    backend = llm.OllamaBackend(digest="abc123def4567890", post=FakeServer())
    assert backend.name == "ollama@abc123def456"
