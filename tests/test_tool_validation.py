import pytest

from src.agent import tools


def test_validate_id_rejects_injection():
    with pytest.raises(ValueError):
        tools._validate_id("1' OR '1'='1", "order_id")
    assert tools._validate_id("ord_123", "order_id") == "ord_123"


@pytest.mark.parametrize("amount", [0, -5, float("nan"), float("inf"), 1e9, True, "5"])
def test_refund_amount_rejected(amount):
    with pytest.raises(ValueError):
        tools._validate_refund_amount(amount)


def test_refund_amount_ok():
    assert tools._validate_refund_amount(25) == 25.0


@pytest.mark.parametrize("p", ["../other/", "/abs", "a\\b", "a/../b"])
def test_query_prefix_rejected(p):
    with pytest.raises(ValueError):
        tools._validate_query_prefix(p)


def test_text_blank_rejected():
    with pytest.raises(ValueError):
        tools._validate_text("   ", "subject", 10)


@pytest.mark.parametrize("v", ["a b", "t1'; DROP", "x" * 65, "../t"])
def test_tenant_header_rejected(v):
    import asyncio

    from fastapi import HTTPException

    from src.auth.jwt_validator import get_tenant_from_header

    with pytest.raises(HTTPException):
        asyncio.run(get_tenant_from_header(v))


def test_tenant_header_ok():
    import asyncio

    from src.auth.jwt_validator import get_tenant_from_header

    assert asyncio.run(get_tenant_from_header("tenant_1-A")) == "tenant_1-A"
