import hashlib
import importlib.util
from pathlib import Path

ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location("bridge", ROOT / "src/bridge.py")
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


def test_tokens_are_unique_and_hashed():
    a = bridge.make_session()
    b = bridge.make_session()
    assert a[0] != b[0]
    assert a[1] != b[1]
    assert hashlib.sha256(a[1].encode()).hexdigest() == a[2]


def test_state_path_uses_plugin_state(monkeypatch, tmp_path):
    monkeypatch.setenv("HERDR_PLUGIN_STATE_DIR", str(tmp_path))
    assert bridge.state_path() == tmp_path / "pending.json"
