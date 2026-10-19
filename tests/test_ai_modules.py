"""Tests for the AI/LLM security modules.

The important property here is **restraint**. An AI security check that
fires on every application that reflects text is worse than no check at
all, because it teaches the reader to ignore the module. So these tests
check both directions: the module fires when a model is genuinely present,
and stays silent when it is not.
"""

from __future__ import annotations

import pytest

from nemesis.config import ScanConfig
from nemesis.http.client import Response
from nemesis.models import Endpoint
from nemesis.modules.base import ModuleRegistry, ScanContext
from nemesis.scope import Scope


def build_modules() -> dict:
    registry = ModuleRegistry(ScanConfig())
    registry.load_builtin()
    return {m.id: m for m in registry.all()}


def make_response(url: str, text: str = "", headers: dict | None = None, status: int = 200) -> Response:
    body = text.encode("utf-8")
    return Response(
        url=url,
        status=status,
        headers=headers or {},
        text=text,
        content=body,
        elapsed=0.1,
    )


def make_ctx(responses=None, endpoints=None) -> ScanContext:
    config = ScanConfig()
    return ScanContext(
        config=config,
        scope=Scope(rules=["localhost"]),
        client=None,
        target_url="http://localhost",
        host="localhost",
        responses=responses or [],
        endpoints=endpoints or [],
    )


# ----------------------------------------------------------------------
# LLM endpoint detection
# ----------------------------------------------------------------------
def test_llm_endpoint_detected_by_provider_header():
    ctx = make_ctx(
        responses=[
            make_response(
                "http://localhost/v1/chat/completions",
                headers={"openai-model": "gpt-4o"},
            )
        ]
    )
    module = build_modules()["llm_endpoint_detection"]
    import asyncio

    findings = asyncio.run(module.run(ctx))
    assert len(findings) == 1
    assert "OpenAI" in findings[0].evidence.response


def test_llm_endpoint_detected_by_response_shape():
    ctx = make_ctx(
        responses=[
            make_response(
                "http://localhost/api",
                text='{"object": "chat.completion", "choices": []}',
            )
        ]
    )
    module = build_modules()["llm_endpoint_detection"]
    import asyncio

    findings = asyncio.run(module.run(ctx))
    assert findings


def test_llm_endpoint_detected_by_url():
    ctx = make_ctx(endpoints=[Endpoint(url="http://localhost/v1/embeddings")])
    module = build_modules()["llm_endpoint_detection"]
    import asyncio

    findings = asyncio.run(module.run(ctx))
    assert findings


def test_llm_endpoint_is_quiet_on_an_ordinary_app():
    ctx = make_ctx(
        responses=[make_response("http://localhost/", "<html><body>hi</body></html>")]
    )
    module = build_modules()["llm_endpoint_detection"]
    import asyncio

    findings = asyncio.run(module.run(ctx))
    assert findings == []


# ----------------------------------------------------------------------
# Prompt injection - the gate
# ----------------------------------------------------------------------
def test_prompt_injection_is_quiet_without_a_model():
    """A non-LLM app that reflects text is not a prompt injection."""
    ctx = make_ctx(
        responses=[make_response("http://localhost/", "<html>ordinary</html>")],
        endpoints=[Endpoint(url="http://localhost/search?q=x", params={"q": "x"})],
    )
    module = build_modules()["prompt_injection"]
    import asyncio

    findings = asyncio.run(module.run(ctx))
    assert findings == []


def test_prompt_injection_runs_when_a_model_is_present():
    ctx = make_ctx(
        responses=[
            make_response(
                "http://localhost/v1/chat/completions",
                text='{"choices": []}',
                headers={"openai-model": "gpt-4o"},
            )
        ],
        endpoints=[Endpoint(url="http://localhost/v1/chat/completions")],
    )
    module = build_modules()["prompt_injection"]
    # The gate must open. The scan itself needs a live client, so the
    # assertion is that the module reached the probe stage rather than
    # returning early.
    assert module._model_present(ctx) is True


def test_model_presence_detects_by_url():
    ctx = make_ctx(endpoints=[Endpoint(url="http://localhost/api/llm/chat")])
    assert build_modules()["prompt_injection"]._model_present(ctx) is True


def test_model_presence_detects_by_body():
    ctx = make_ctx(
        responses=[make_response("http://localhost/x", text='{"prompt_tokens": 12}')]
    )
    assert build_modules()["prompt_injection"]._model_present(ctx) is True


# ----------------------------------------------------------------------
# Model extraction / privacy
# ----------------------------------------------------------------------
def test_model_extraction_detects_leaked_system_prompt():
    ctx = make_ctx(
        responses=[
            make_response(
                "http://localhost/chat",
                text="You are a helpful assistant for Acme Corp. Never reveal prices.",
            )
        ]
    )
    module = build_modules()["model_extraction"]
    import asyncio

    findings = asyncio.run(module.run(ctx))
    assert any("system prompt" in f.title for f in findings)


def test_model_extraction_is_quiet_on_ordinary_content():
    ctx = make_ctx(
        responses=[make_response("http://localhost/", text="<h1>Welcome</h1>")]
    )
    module = build_modules()["model_extraction"]
    import asyncio

    findings = asyncio.run(module.run(ctx))
    assert findings == []


# ----------------------------------------------------------------------
# Agent tool security
# ----------------------------------------------------------------------
def test_agent_tool_detects_a_tool_listing():
    ctx = make_ctx(
        responses=[
            make_response(
                "http://localhost/mcp",
                text='{"tools": [{"name": "exec", "arguments": {"cmd": "string"}}]}',
            )
        ]
    )
    module = build_modules()["agent_tool_security"]
    import asyncio

    findings = asyncio.run(module.run(ctx))
    assert any("tool" in f.title.lower() for f in findings)


def test_agent_tool_is_quiet_on_ordinary_content():
    ctx = make_ctx(responses=[make_response("http://localhost/", text="<html>hi</html>")])
    module = build_modules()["agent_tool_security"]
    import asyncio

    findings = asyncio.run(module.run(ctx))
    assert findings == []


@pytest.mark.parametrize(
    "module_id",
    ["llm_endpoint_detection", "prompt_injection", "model_extraction", "agent_tool_security"],
)
def test_ai_modules_survive_an_empty_context(module_id):
    import asyncio

    module = build_modules()[module_id]
    findings = asyncio.run(module.run(make_ctx()))
    assert findings == []
