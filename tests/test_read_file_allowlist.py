import os

import pytest

from src.agent import tools


def _read(path):
    return tools.read_file.invoke({"path": path})


@pytest.mark.parametrize("path", [
    "/etc/passwd",
    "../../../etc/passwd",
    "prompts/../../../etc/passwd",
    "/proc/self/environ",
    "prompts/\x00x",
    ".env",
])
def test_denied(path):
    with pytest.raises(ValueError):
        _read(path)


def test_allowed_and_symlink_escape(tmp_path):
    root = tools.READ_ALLOWED_ROOTS[0]
    files = os.listdir(root)
    assert files
    assert isinstance(_read(os.path.join(root, files[0])), str)
    link = os.path.join(root, "_escape_link")
    os.symlink("/etc/passwd", link)
    try:
        with pytest.raises(ValueError):
            _read(link)
    finally:
        os.unlink(link)
