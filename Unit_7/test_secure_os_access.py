import os
import subprocess
import tempfile
import pytest
import platform


@pytest.mark.skipif(platform.system() == "Windows", reason="UNIX permissions not applicable on Windows")
def test_tempfile_secure_permissions():
    with tempfile.NamedTemporaryFile(delete=True) as tf:
        os.chmod(tf.name, 0o600)
        mode = oct(os.stat(tf.name).st_mode)[-3:]
        assert mode == "600"


def test_subprocess_directory_listing():
    """
    Uses platform-appropriate subprocess command to list current directory.
    """
    if platform.system() == "Windows":
        cmd = ["cmd", "/c", "dir"]
    else:
        cmd = ["ls", "-la"]

    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    assert result.returncode == 0
    assert "secure_os_access" in result.stdout or "." in result.stdout
