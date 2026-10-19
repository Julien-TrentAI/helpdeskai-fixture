from unittest.mock import MagicMock, patch

import pytest

from src.data.s3_client import S3Client


@pytest.fixture
def client():
    with patch("src.data.s3_client.boto3.client", return_value=MagicMock()):
        yield S3Client()


def test_own_tenant_key_allowed(client):
    client.get_document_url("acme", "acme/guide.pdf")
    client._s3.generate_presigned_url.assert_called_once()


@pytest.mark.parametrize(
    "key",
    ["other/guide.pdf", "acme", "acme/../other/x", "acmeX/guide.pdf", "/acme/x", "guide.pdf"],
)
def test_foreign_key_rejected(client, key):
    with pytest.raises(PermissionError):
        client.get_document_url("acme", key)
    client._s3.generate_presigned_url.assert_not_called()
