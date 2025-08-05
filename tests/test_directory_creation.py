import os
import subprocess
import sys
from pathlib import Path


def test_creates_dirs_and_fails_without_bind_mount(tmp_path):
    config_dir = tmp_path / "config"
    state_dir = tmp_path / "state"
    env = os.environ.copy()
    env["PLEXYTRACK_CONFIG_DIR"] = str(config_dir)
    env["PLEXYTRACK_STATE_DIR"] = str(state_dir)
    # Ensure directories do not exist before startup
    assert not config_dir.exists()
    assert not state_dir.exists()
    result = subprocess.run(
        [sys.executable, "app.py"],
        env=env,
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert config_dir.is_dir()
    assert state_dir.is_dir()
    assert "must be a mounted volume" in result.stderr
