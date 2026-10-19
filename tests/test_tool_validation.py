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


def test_validate_tool_output_schemas():
    from src.agent.tool_validation import validate_tool_output

    ok = {"order_id": "o1", "tenant_id": "t1", "status": "open", "amount": 5}
    assert validate_tool_output("lookup_order", ok)["amount"] == 5.0
    assert validate_tool_output("lookup_order", {}) == {}
    assert validate_tool_output("read_file", "hi") == {"content": "hi"}
    with pytest.raises(ValueError):
        validate_tool_output("lookup_order", {"order_id": "o1"})
    with pytest.raises(ValueError):
        validate_tool_output("read_file", "x" * 50_001)
    with pytest.raises(ValueError):
        validate_tool_output("issue_refund", "yes")
    with pytest.raises(ValueError):
        validate_tool_output("unknown_tool", "x")


def test_truncate_output():
    assert len(tools._truncate_output("read_file", "x" * 60_000)) == 50_000
