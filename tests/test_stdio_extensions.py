"""Opt-in stdio extensions use the same forwarding path as HTTP requests."""
from unittest.mock import Mock
import pytest
from ida_pro_mcp import idalib_supervisor as module


def test_stdio_extensions_forward_on_tools_and_calls():
    server = module.McpServer("test")
    supervisor = module.IdalibSupervisor(server, extensions={"dbg"})
    assert supervisor._worker_request_path() == "/mcp?ext=dbg"
    # No thread-local monkey patch is needed, and the setting is per supervisor.
    assert not hasattr(server._enabled_extensions, "data")
    plain = module.IdalibSupervisor(module.McpServer("plain"))
    assert plain._worker_request_path() == "/mcp"


def test_http_extension_selection_remains_request_scoped():
    server = module.McpServer("test")
    supervisor = module.IdalibSupervisor(server)
    server._enabled_extensions.data = {"dbg"}
    assert supervisor._worker_request_path() == "/mcp?ext=dbg"
    server._enabled_extensions.data = set()
    assert supervisor._worker_request_path() == "/mcp"


def test_tool_cache_uses_effective_extension_set(monkeypatch):
    server = module.McpServer("test")
    supervisor = module.IdalibSupervisor(server, extensions={"dbg"})
    monkeypatch.setattr(supervisor, "_schema_or_idle_worker", lambda: object())
    paths = []
    def rpc(worker, payload):
        paths.append(supervisor._worker_request_path())
        return {"result": {"tools": [{"name": "dbg_status", "inputSchema": {"type": "object"}}]}}
    monkeypatch.setattr(supervisor, "_worker_rpc", rpc)
    assert supervisor.worker_tools()[0]["name"] == "dbg_status"
    supervisor.worker_tools()
    assert paths == ["/mcp?ext=dbg"]
    server._enabled_extensions.data = {"extra"}
    supervisor.worker_tools()
    assert paths == ["/mcp?ext=dbg", "/mcp?ext=dbg,extra"]


@pytest.mark.parametrize("arguments", [
    ["--ext", "dbg"],
    ["--stdio", "--ext", "dbg&bad=1"],
])
def test_cli_rejects_invalid_transport_or_extension(monkeypatch, arguments):
    monkeypatch.setattr(module.sys, "argv", ["idalib-mcp", *arguments])
    with pytest.raises(SystemExit) as exc:
        module.main()
    assert exc.value.code == 2


def test_cli_passes_extensions_and_existing_worker_flags(monkeypatch):
    instance = Mock()
    instance.open_session = Mock()
    factory = Mock(return_value=instance)
    monkeypatch.setattr(module, "IdalibSupervisor", factory)
    monkeypatch.setattr(module, "supervisor", None)
    monkeypatch.setattr(module.signal, "signal", lambda *args: None)
    monkeypatch.setattr(module.mcp, "stdio", Mock())
    monkeypatch.setattr(module.mcp.registry, "dispatch", module.mcp.registry.dispatch)
    monkeypatch.setattr(module.sys, "argv", ["idalib-mcp", "--stdio", "--unsafe", "--ext", "dbg, dbg"])
    module.main()
    assert factory.call_args.kwargs["extensions"] == {"dbg"}
    assert factory.call_args.kwargs["worker_args"] == ["--unsafe"]
    module.mcp.stdio.assert_called_once()
    instance.shutdown.assert_called_once()
