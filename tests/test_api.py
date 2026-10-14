"""Smoke tests for the FastAPI app wiring.

These import the full application (which transitively imports the agent, MCP, and
data layers) and exercise the health endpoint via TestClient — proving the service
actually wires together without real AWS/LLM credentials.
"""

from fastapi.testclient import TestClient


def test_app_imports_and_health_ok():
    from src.api.app import create_app

    app = create_app()
    client = TestClient(app)
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_routes_registered():
    from src.api.app import create_app

    app = create_app()
    paths = {getattr(route, "path", None) for route in app.routes}
    assert "/v1/chat" in paths
    assert "/v1/kb/documents" in paths
    assert "/v1/admin/tenants" in paths


def test_orchestrator_factory_returns_invokable():
    """create_orchestrator returns an Orchestrator exposing invoke(message, tenant_id, thread_id).

    We assert the surface without calling it (calling would require live Anthropic creds).
    """
    import os

    os.environ.setdefault("ANTHROPIC_API_KEY", "test-key-not-used")
    from src.agent.orchestrator import create_orchestrator, Orchestrator

    orch = create_orchestrator()
    assert isinstance(orch, Orchestrator)
    assert hasattr(orch, "invoke")


def test_chat_request_validation():
    import pytest
    from pydantic import ValidationError
    from src.api.models import ChatRequest

    assert ChatRequest(message="hi", thread_id="abc-123").message == "hi"
    for bad in ({"message": ""}, {"message": "   "}, {"message": "x" * 4001},
                {"message": "hi", "thread_id": "bad id!"}, {"message": "hi", "thread_id": "a" * 129}):
        with pytest.raises(ValidationError):
            ChatRequest(**bad)


def test_kb_upload_request_validation():
    import pytest
    from pydantic import ValidationError
    from src.api.models import KBUploadRequest

    assert KBUploadRequest(document_key="faq/a.md", content_base64="aGk=").document_key == "faq/a.md"
    for key in ("", "/abs", "../x", "a/../b", "a//b", "a\\b", "a\x00b"):
        with pytest.raises(ValidationError):
            KBUploadRequest(document_key=key, content_base64="aGk=")
    with pytest.raises(ValidationError):
        KBUploadRequest(document_key="a", content_base64="")
