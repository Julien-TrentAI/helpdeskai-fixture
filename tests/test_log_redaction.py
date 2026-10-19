import logging

from src.logging_config import REDACTED, install_pii_redaction


def test_redaction(caplog):
    install_pii_redaction()
    log = logging.getLogger("t")
    with caplog.at_level(logging.INFO):
        log.info(
            "user a@b.com card 4111 1111 1111 1111 tok eyJhbGci.eyJzdWI.sig email=x@y.io",
            extra={"tenant_id": "t-1", "email": "a@b.com", "ticket_id": "T1"},
        )
    r = caplog.records[0]
    out = r.getMessage()
    for leak in ("a@b.com", "4111", "eyJhbGci", "x@y.io"):
        assert leak not in out
    assert r.tenant_id == REDACTED and r.email == REDACTED
    assert r.ticket_id == "T1"
