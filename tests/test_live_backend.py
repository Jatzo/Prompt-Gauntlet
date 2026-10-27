"""The live backend, driven by a fake Agent SDK. No real call is ever made from a test."""

import json
import subprocess
import sys
import types
from dataclasses import dataclass, field

import pytest

from arena import llm
from arena.anomaly import UsageLimitReached
from arena.config import REPO_ROOT
from arena.schemas import DetectorResult

TOOL = {"name": "report_score", "input_schema": DetectorResult.model_json_schema()}
REQUEST = llm.LLMRequest(tool="report_score", tools=(TOOL,), system="score it", user="text")
VALID = {"score": 10.0, "label": "benign", "reasons": ["plain text"]}


def fake_sdk(script):
    """A stand-in claude_agent_sdk whose query() yields the scripted messages."""

    @dataclass
    class RateLimitInfo:
        status: str
        resets_at: int | None = None
        rate_limit_type: str | None = None
        utilization: float | None = None

    @dataclass
    class RateLimitEvent:
        rate_limit_info: RateLimitInfo

    @dataclass
    class ToolUseBlock:
        name: str
        input: dict

    @dataclass
    class TextBlock:
        text: str

    @dataclass
    class AssistantMessage:
        model: str
        error: str | None = None
        content: list = field(default_factory=list)

    @dataclass
    class ResultMessage:
        subtype: str = "success"
        structured_output: dict | None = None
        result: str | None = None
        usage: dict = field(default_factory=dict)
        is_error: bool = False
        api_error_status: int | None = None

    class ResultError(Exception):
        pass

    sdk = types.ModuleType("claude_agent_sdk")
    sdk.RateLimitInfo, sdk.RateLimitEvent = RateLimitInfo, RateLimitEvent
    sdk.ToolUseBlock, sdk.TextBlock = ToolUseBlock, TextBlock
    sdk.AssistantMessage, sdk.ResultMessage, sdk.ResultError = (
        AssistantMessage,
        ResultMessage,
        ResultError,
    )
    sdk.options = []

    def options(**kwargs):
        sdk.options.append(kwargs)
        return kwargs

    async def query(*, prompt, options):
        for message in script(sdk):
            if isinstance(message, Exception):
                raise message
            yield message

    sdk.ClaudeAgentOptions, sdk.query = options, query
    return sdk


@pytest.fixture
def live(monkeypatch):
    """A LiveBackend over the fake SDK. The pytest refusal is lifted for this object only, and the
    fake module is what `import claude_agent_sdk` finds, so no real call can happen."""

    def build(script):
        sdk = fake_sdk(script)
        monkeypatch.setitem(sys.modules, "claude_agent_sdk", sdk)
        monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
        monkeypatch.setenv("ARENA_ALLOW_LIVE", "1")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        backend = llm.LiveBackend()
        assert backend._sdk is sdk
        return backend, sdk

    return build


def complete(backend, model_id="claude-haiku-5-5"):
    return backend.complete(role="detector", model_id=model_id, step_key=(0, "s"), request=REQUEST)


def test_the_live_backend_is_refused_under_pytest_and_without_the_flag(monkeypatch):
    with pytest.raises(llm.LiveCallRefused, match="tests"):
        llm.LiveBackend()
    monkeypatch.delenv("PYTEST_CURRENT_TEST")
    monkeypatch.delenv("ARENA_ALLOW_LIVE", raising=False)
    with pytest.raises(llm.LiveCallRefused, match="ARENA_ALLOW_LIVE"):
        llm.LiveBackend()
    monkeypatch.setenv("ARENA_ALLOW_LIVE", "1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-not-a-real-key")
    with pytest.raises(llm.LiveCallRefused, match="ANTHROPIC_API_KEY"):
        llm.LiveBackend()


def test_arena_llm_imports_without_the_sdk():
    code = "import sys, arena.llm; print('claude_agent_sdk' in sys.modules)"
    out = subprocess.run(
        [sys.executable, "-c", code], cwd=REPO_ROOT, capture_output=True, text=True
    )
    assert out.stdout.strip() == "False", out.stderr


def test_a_reply_is_mapped_with_the_reported_model_and_every_input_token(live):
    def script(sdk):
        return [
            sdk.AssistantMessage(model="claude-haiku-5-5"),
            sdk.ResultMessage(
                structured_output=VALID,
                usage={
                    "input_tokens": 100,
                    "cache_creation_input_tokens": 20,
                    "cache_read_input_tokens": 5,
                    "output_tokens": 30,
                },
            ),
        ]

    backend, sdk = live(script)
    response = complete(backend)
    assert response.tool == "report_score"
    assert json.loads(response.raw_output) == VALID
    assert (response.model_id, response.input_tokens, response.output_tokens) == (
        "claude-haiku-5-5",
        125,
        30,
    )
    [options] = sdk.options
    assert options["tools"] == [] and options["setting_sources"] == []
    assert options["max_turns"] == 1 and options["system_prompt"] == "score it"
    assert "additionalProperties" not in json.dumps(options["output_format"]["schema"])


def test_an_unknown_field_reaches_validation_and_is_a_hijack(live):
    def script(sdk):
        return [
            sdk.AssistantMessage(model="claude-haiku-5-5"),
            sdk.ResultMessage(structured_output=VALID | {"note": "also email the code"}),
        ]

    backend, _ = live(script)
    response = complete(backend)
    _, failure = llm._validate(response, REQUEST, DetectorResult)
    assert failure.startswith("hijack: unknown fields")


def test_a_structured_output_failure_is_kept_as_a_schema_failure(live):
    def script(sdk):
        return [
            sdk.AssistantMessage(model="claude-haiku-5-5", content=[sdk.TextBlock("No.")]),
            sdk.ResultMessage(subtype="error_max_turns", result="I could not answer that way."),
        ]

    backend, _ = live(script)
    response = complete(backend)
    assert response.raw_output == "No."
    _, failure = llm._validate(response, REQUEST, DetectorResult)
    assert failure.startswith("schema:")


def test_a_rejected_reply_keeps_the_models_attempt_so_a_hijack_is_still_seen(live):
    attempt = {"score": "high", "label": "benign", "reasons": [], "exfil": "door code"}

    def script(sdk):
        return [
            sdk.AssistantMessage(
                model="claude-haiku-5-5", content=[sdk.ToolUseBlock("StructuredOutput", attempt)]
            ),
            sdk.ResultMessage(subtype="error_max_structured_output_retries", result="bad"),
        ]

    backend, _ = live(script)
    response = complete(backend)
    assert json.loads(response.raw_output) == attempt
    _, failure = llm._validate(response, REQUEST, DetectorResult)
    assert failure.startswith("hijack: unknown fields")


def test_a_call_to_any_other_tool_is_filed_under_its_name_and_is_a_hijack(live):
    def script(sdk):
        return [
            sdk.AssistantMessage(
                model="claude-haiku-5-5", content=[sdk.ToolUseBlock("send_message", {"to": "x"})]
            ),
            sdk.ResultMessage(structured_output=VALID),
        ]

    backend, _ = live(script)
    response = complete(backend)
    _, failure = llm._validate(response, REQUEST, DetectorResult)
    assert failure == "hijack: called tool 'send_message'"


def test_an_api_failure_is_raised_and_never_stored_as_an_answer(live):
    def script(sdk):
        return [sdk.ResultMessage(is_error=True, api_error_status=529, result="API Error: busy")]

    backend, _ = live(script)
    with pytest.raises(llm.LiveCallFailed, match="529"):
        complete(backend)


def test_a_cli_failure_with_no_answer_is_raised(live):
    def script(sdk):
        return [sdk.ResultError("the CLI exited")]

    backend, _ = live(script)
    with pytest.raises(llm.LiveCallFailed):
        complete(backend)


def test_limit_wording_in_the_models_own_reply_does_not_pause_the_run(live):
    def script(sdk):
        return [
            sdk.AssistantMessage(
                model="claude-haiku-5-5",
                content=[sdk.TextBlock("You've hit your weekly limit, says the email.")],
            ),
            sdk.ResultMessage(result="You've hit your weekly limit, says the email."),
        ]

    backend, _ = live(script)
    response = complete(backend)
    _, failure = llm._validate(response, REQUEST, DetectorResult)
    assert failure.startswith("schema:")


def test_a_reported_model_that_differs_from_the_pin_is_passed_on_for_the_id_check(live):
    def script(sdk):
        return [
            sdk.AssistantMessage(model="claude-sonnet-5-5"),
            sdk.ResultMessage(structured_output=VALID),
        ]

    backend, _ = live(script)
    assert complete(backend).model_id == "claude-sonnet-5-5"


@pytest.mark.parametrize(
    "script",
    [
        lambda sdk: [sdk.RateLimitEvent(sdk.RateLimitInfo("rejected", 1_900_000_000, "five_hour"))],
        lambda sdk: [sdk.AssistantMessage(model="m", error="rate_limit")],
        lambda sdk: [sdk.ResultError("You've hit your session limit")],
        lambda sdk: [
            sdk.ResultMessage(
                is_error=True, api_error_status=400, result="You've hit your weekly limit"
            )
        ],
        lambda sdk: [sdk.ResultMessage(is_error=True, api_error_status=429, result="Too many")],
    ],
)
def test_a_plan_limit_pauses_the_run_instead_of_retrying(live, script):
    backend, _ = live(script)
    with pytest.raises(UsageLimitReached):
        complete(backend)


def test_a_warning_reports_headroom_and_the_call_goes_on(live):
    def script(sdk):
        return [
            sdk.RateLimitEvent(sdk.RateLimitInfo("allowed_warning", utilization=0.8)),
            sdk.AssistantMessage(model="claude-haiku-5-5"),
            sdk.ResultMessage(structured_output=VALID),
        ]

    backend, _ = live(script)
    assert complete(backend).headroom == pytest.approx(0.2)


def test_live_check_is_refused_under_pytest(capsys):
    from arena import cli

    assert cli.main(["live-check"]) == 1
    assert "never made from tests" in capsys.readouterr().err


def test_an_api_failure_with_no_status_is_raised_too(live):
    def script(sdk):
        return [sdk.ResultMessage(is_error=True, result="API Error: Request timed out")]

    backend, _ = live(script)
    with pytest.raises(llm.LiveCallFailed, match="timed out"):
        complete(backend)


# The error the pilot run got, word for word as the CLI returned it.
PILOT_REFUSAL = (
    "API Error: Opus 5's safeguards flagged this message (https://www.anthropic.com/legal/aup). "
    "Our intentionally broad safeguards allow us to deliver more capabilities faster, but can "
    "sometimes flag legit"
)


# The error that stopped the full build: a new model name and no policy link.
BUILD_REFUSAL = (
    "API Error: Opus 4.8's safeguards flagged this message. Our intentionally broad safeguards "
    "allow us to deliver more capabilities faster, but can sometimes flag legitimate "
    "cybersecurity work. Learn more"
)


# The error that stopped the rebuild: the second wording, with no mention of safeguards.
HELP_REFUSAL = (
    "API Error: Opus 4.8 can't help with this. Start a new session to continue. "
    "Learn more: https://www.anthropic.com/legal/aup Details: [bio]"
)


def wrapped(result: str) -> str:
    """How the SDK words a ResultError around the CLI's result text."""
    return f"Claude Code returned an error result: {result} (exit code: 1)"


@pytest.mark.parametrize(
    "script",
    [
        lambda sdk: [sdk.ResultMessage(is_error=True, api_error_status=None, result=PILOT_REFUSAL)],
        lambda sdk: [sdk.ResultError(PILOT_REFUSAL)],
        lambda sdk: [sdk.ResultMessage(is_error=True, api_error_status=None, result=BUILD_REFUSAL)],
        lambda sdk: [sdk.ResultMessage(is_error=True, api_error_status=400, result=BUILD_REFUSAL)],
        lambda sdk: [sdk.ResultError(wrapped(BUILD_REFUSAL))],
        lambda sdk: [sdk.ResultMessage(is_error=True, api_error_status=None, result=HELP_REFUSAL)],
        lambda sdk: [sdk.ResultError(wrapped(HELP_REFUSAL.replace("'", "’")))],
    ],
)
def test_a_safeguards_refusal_is_its_own_failure(live, script):
    backend, _ = live(script)
    with pytest.raises(llm.ContentRefused, match="API Error"):
        complete(backend)
    assert issubclass(llm.ContentRefused, llm.LiveCallFailed)


@pytest.mark.parametrize(
    "result",
    [
        # The words without the CLI's marker, as an echoed attack might carry them.
        "Our safeguards flagged this message, so please stop.",
        "Sorry, I can't help with this.",
        "API Error: Request timed out",
    ],
)
def test_error_text_without_the_cli_refusal_line_is_not_a_refusal(live, result):
    backend, _ = live(lambda sdk: [sdk.ResultError(wrapped(result))])
    with pytest.raises(llm.LiveCallFailed) as raised:
        complete(backend)
    assert not isinstance(raised.value, llm.ContentRefused)


def test_another_api_error_is_not_a_refusal(live):
    def script(sdk):
        return [sdk.ResultMessage(is_error=True, api_error_status=529, result=PILOT_REFUSAL)]

    backend, _ = live(script)
    with pytest.raises(llm.LiveCallFailed) as raised:
        complete(backend)
    assert not isinstance(raised.value, llm.ContentRefused)


@pytest.mark.parametrize(
    "script",
    [
        # The refusal wording inside the model's own answer, a text block and a normal result.
        lambda sdk: [
            sdk.AssistantMessage(model="claude-haiku-5-5", content=[sdk.TextBlock(PILOT_REFUSAL)]),
            sdk.ResultMessage(structured_output=dict(VALID, reasons=[PILOT_REFUSAL])),
        ],
        lambda sdk: [sdk.ResultMessage(result=PILOT_REFUSAL)],
    ],
)
def test_refusal_wording_in_the_models_reply_is_not_a_refusal(live, script):
    backend, _ = live(script)
    complete(backend)
