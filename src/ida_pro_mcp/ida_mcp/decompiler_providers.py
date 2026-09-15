"""Optional decompilers registered by installed IDA plugins.

Providers run on the IDA main thread through existing tool dispatch. Native
Hex-Rays remains the fallback when no provider claims the current database.
"""
from dataclasses import dataclass
from importlib.metadata import entry_points
import logging
import sys
from typing import Callable

@dataclass(frozen=True)
class DecompilerProvider:
    name: str
    language: str
    supports: Callable[[], bool]
    decompile: Callable[[int, bool], str]
    references: Callable[[int], list[dict]] | None = None
    ready: Callable[[], bool] | None = None
    priority: int = 0

_providers: dict[str, DecompilerProvider] = {}
_discovery_path: tuple[str, ...] | None = None
_loaded_entries: set[tuple[str, str]] = set()
_logger = logging.getLogger(__name__)


def discover_providers() -> None:
    """Load trusted installed entry points, lazily and on the IDA main thread.

    A factory in the ``ida_pro_mcp.decompiler_providers`` entry-point group
    receives DecompilerProvider and returns an instance. Passing the class keeps
    GUI (ida_mcp) and idalib (ida_pro_mcp.ida_mcp) package identities independent.
    Rescan when IDA adds a user Python directory after opening a database.
    """
    global _discovery_path
    path = tuple(sys.path)
    if path == _discovery_path:
        return
    _discovery_path = path  # Also guard against recursive factory imports.
    try:
        entries = entry_points(group="ida_pro_mcp.decompiler_providers")
    except Exception:
        _logger.exception("Could not discover decompiler providers")
        return
    for entry in sorted(entries, key=lambda ep: (ep.name, ep.value)):
        key = (entry.name, entry.value)
        if key in _loaded_entries:
            continue
        _loaded_entries.add(key)
        try:
            provider = entry.load()(DecompilerProvider)
            if not isinstance(provider, DecompilerProvider):
                raise TypeError("Decompiler provider factory returned an invalid object")
            register_provider(provider)
        except Exception:
            _logger.exception("Could not load decompiler provider %s", entry.name)

def register_provider(provider: DecompilerProvider) -> None:
    """Register once by name. Call from IDA plugin initialization on its main thread."""
    if not provider.name or not provider.language:
        raise ValueError("Provider name and language must be non-empty")
    if provider.name in _providers:
        if _providers[provider.name] is provider:
            return
        raise ValueError(f"Decompiler provider already registered: {provider.name}")
    _providers[provider.name] = provider

def unregister_provider(provider: DecompilerProvider) -> None:
    """Only remove the instance owned by the caller, e.g. on plugin termination."""
    if _providers.get(provider.name) is provider:
        del _providers[provider.name]

def get_provider() -> DecompilerProvider | None:
    """Select deterministically; failed capability probes do not hide other backends."""
    discover_providers()
    for provider in sorted(_providers.values(), key=lambda p: (-p.priority, p.name)):
        try:
            if provider.supports():
                return provider
        except Exception:
            continue
    return None

def decompiler_status(hexrays_ready: bool) -> dict:
    """Report effective availability without misreporting Hex-Rays readiness."""
    provider = get_provider()
    if provider is None:
        return {
            "decompiler_ready": hexrays_ready,
            "decompiler_backend": "Hex-Rays" if hexrays_ready else "none",
            "decompiler_hint": "Use the standard decompile tool when decompiler_ready is true.",
        }
    try:
        ready = provider.ready is None or bool(provider.ready())
        hint = (
            f"Use the standard decompile tool for {provider.language} functions by name or address. "
            "This provider does not require Hex-Rays."
            if ready else f"{provider.name} is registered but its dependencies are not ready."
        )
    except Exception as exc:
        ready, hint = False, f"{provider.name}: {exc}"
    return {
        "decompiler_ready": ready,
        "decompiler_backend": provider.name,
        "decompiler_hint": hint,
    }
