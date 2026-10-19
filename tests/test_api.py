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
                {"message": "hi", "thread_id": "../x"}):
        with pytest.raises(ValidationError):
            ChatRequest(**bad)


def test_kb_upload_request_validation():
    import pytest
    from pydantic import ValidationError
    from src.api.models import KBUploadRequest

    assert KBUploadRequest(document_key="faq/a.md", content_base64="aGk=")
    for key in ("../etc/passwd", "/abs", "a//b", "a\\b", "", "a/./b"):
        with pytest.raises(ValidationError):
            KBUploadRequest(document_key=key, content_base64="aGk=")


def test_get_kb_document_rejects_traversal_key():
    from src.api.models import validate_document_key
    import pytest

    assert validate_document_key("faq/a.md") == "faq/a.md"
    for key in ("../x", "/abs", "a//b", "a\\b", "x" * 513):
        with pytest.raises(ValueError):
            validate_document_key(key)


def test_chat_ignores_tenant_header_and_requires_jwt():
    from src.api.app import create_app

    client = TestClient(create_app())
    resp = client.post(
        "/v1/chat", json={"message": "hi"}, headers={"X-Tenant-Id": "other-tenant"}
    )
    assert resp.status_code == 401


def test_chat_rejects_forged_jwt():
    import jwt
    from src.api.app import create_app

    forged = jwt.encode({"tenant_id": "victim"}, "wrong-secret", algorithm="HS256")
    client = TestClient(create_app())
    resp = client.post(
        "/v1/chat",
        json={"message": "hi"},
        headers={"Authorization": f"Bearer {forged}", "X-Tenant-Id": "victim"},
    )
    assert resp.status_code == 401
