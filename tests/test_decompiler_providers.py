"""Provider selection contract; no IDA installation needed."""
import importlib.util
from pathlib import Path
import sys
import pytest

spec = importlib.util.spec_from_file_location(
    "test_provider_registry",
    Path(__file__).resolve().parents[1] / "src/ida_pro_mcp/ida_mcp/decompiler_providers.py",
)
registry = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = registry
spec.loader.exec_module(registry)

@pytest.fixture(autouse=True)
def clean_registry(monkeypatch):
    registry._providers.clear()
    registry._loaded_entries.clear()
    registry._discovery_path = None
    monkeypatch.setattr(registry, 'entry_points', lambda **kw: [])
    yield
    registry._providers.clear()

def make(name="lua", supports=lambda: True, ready=None, priority=0):
    return registry.DecompilerProvider(name, "Lua", supports, lambda ea, markers: f"return {ea}", ready=ready, priority=priority)

def test_native_fallback_and_truthful_status():
    assert registry.get_provider() is None
    assert registry.decompiler_status(True)["decompiler_backend"] == "Hex-Rays"
    assert registry.decompiler_status(False)["decompiler_ready"] is False

def test_provider_works_without_hexrays():
    provider = make()
    registry.register_provider(provider)
    assert registry.get_provider() is provider
    assert registry.decompiler_status(False)["decompiler_ready"] is True
    assert "standard decompile tool" in registry.decompiler_status(False)["decompiler_hint"]

def test_other_database_keeps_native_backend():
    registry.register_provider(make(supports=lambda: False))
    assert registry.get_provider() is None
    assert registry.decompiler_status(True)["decompiler_backend"] == "Hex-Rays"

def test_priority_and_deterministic_tie():
    for provider in (make("z"), make("b", priority=2), make("a", priority=2)):
        registry.register_provider(provider)
    assert registry.get_provider().name == "a"

def test_failed_probe_is_isolated():
    def bad():
        raise RuntimeError("not initialized")
    registry.register_provider(make("bad", supports=bad, priority=10))
    good=make("good")
    registry.register_provider(good)
    assert registry.get_provider() is good

def test_duplicate_and_ownership():
    p=make()
    registry.register_provider(p)
    registry.register_provider(p)
    with pytest.raises(ValueError):
        registry.register_provider(make())
    registry.unregister_provider(make())
    assert registry.get_provider() is p
    registry.unregister_provider(p)
    assert registry.get_provider() is None

def test_readiness_failure_does_not_claim_hexrays():
    registry.register_provider(make(ready=lambda: False))
    status=registry.decompiler_status(True)
    assert not status["decompiler_ready"]
    assert status["decompiler_backend"] == "lua"

def test_readiness_exception_is_reported():
    def bad():
        raise RuntimeError("missing runtime")
    registry.register_provider(make(ready=bad))
    assert "missing runtime" in registry.decompiler_status(False)["decompiler_hint"]

def test_provider_call_contract():
    p=make()
    assert p.decompile(123,False) == "return 123"

def test_empty_identity_is_rejected():
    with pytest.raises(ValueError):
        registry.register_provider(make(name=""))


def test_installed_discovery_and_path_change(monkeypatch):
    from types import SimpleNamespace
    loaded = []
    def factory(cls):
        loaded.append(cls)
        return make('installed')
    entries = []
    monkeypatch.setattr(registry, 'entry_points', lambda **kw: entries)
    assert registry.get_provider() is None
    entries.append(SimpleNamespace(name='example', value='example:create', load=lambda: factory))
    monkeypatch.setattr(sys, 'path', sys.path + ['/test/ida/user/python'])
    assert registry.get_provider().name == 'installed'
    registry.get_provider()
    assert loaded == [registry.DecompilerProvider]


def test_broken_discovery_is_isolated(monkeypatch):
    from types import SimpleNamespace
    def bad():
        raise ImportError('missing optional runtime')
    monkeypatch.setattr(registry, 'entry_points', lambda **kw: [
        SimpleNamespace(name='bad', value='bad:create', load=bad),
        SimpleNamespace(name='good', value='good:create', load=lambda: lambda cls: make('good')),
    ])
    assert registry.get_provider().name == 'good'
