"""Opt-in integration: run with IDA 9.4 and the Lua provider installed.

Usage: python tests/ida_provider_smoke.py path/to/disposable.i64 [--native]
The native fixture must contain a function named provider_native_test.
"""
import sys
import os
import json
from dataclasses import replace
import idapro
from ida_pro_mcp.ida_mcp import MCP_SERVER
from ida_pro_mcp.ida_mcp import decompiler_providers as registry
from jsonschema import validate

def call(name, args=None):
    response = MCP_SERVER.registry.dispatch({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": args or {}},
    })
    assert "error" not in response, response
    result = response["result"]
    assert not result.get("isError"), result
    value = result["structuredContent"]
    validate(value, schemas[name])
    return value

# Force discovery before opening a DB: the loader may add its Python path later.
registry.get_provider()
assert idapro.open_database(sys.argv[1], True) == 0
try:
    import ida_auto, ida_kernwin, ida_ida, ida_name, ida_bytes
    ida_auto.auto_wait()
    listed = MCP_SERVER._mcp_tools_list()["tools"]
    schemas = {t["name"]: t["outputSchema"] for t in listed if "outputSchema" in t}
    description = next(t["description"] for t in listed if t["name"] == "decompile")
    assert "Lua" in description and "decompiler_ready" in description
    health = call("server_health")
    assert ida_kernwin.get_kernel_version().startswith("9.4")
    if "--native" in sys.argv:
        assert registry.get_provider() is None
        import idautils
        matches = [ea for ea in idautils.Functions() if "provider_native_test" in ida_name.get_name(ea)]
        assert len(matches) == 1, matches
        result = call("decompile", {"addr": hex(matches[0])})
        assert result["code"] and not result.get("error"), result
        assert "backend" not in result, result
    else:
        from lua_re_ida import database
        from lua_re_ida.pseudocode import decompile
        chunk = database.current_chunk()
        p = next((p for p in chunk.prototypes if "get_sign" in p.name), chunk.root)
        name = ida_name.get_name(p.code_offset)
        assert health["decompiler_ready"] and not health["hexrays_ready"], health
        previous_java = os.environ.get("LUA_RE_JAVA")
        os.environ["LUA_RE_JAVA"] = "/missing/lua-re-test/java"
        missing = call("server_health")
        assert not missing["decompiler_ready"] and "--configure-java" in missing["decompiler_hint"]
        missing_source = call("decompile", {"addr": name})
        assert missing_source["code"] is None and "--configure-java" in missing_source["error"]
        if previous_java is None:
            del os.environ["LUA_RE_JAVA"]
        else:
            os.environ["LUA_RE_JAVA"] = previous_java
        result = call("decompile", {"addr": name, "include_addresses": False})
        assert result["language"] == "Lua" and result["backend"] == "Lua RE / unluac", result
        assert result["code"] == decompile(p.code_offset).source
        assert result.get("refs"), result
        bad = call("decompile", {"addr": "this_name_does_not_exist"})
        assert bad["code"] is None and bad["error"]
        original = registry.get_provider()
        def fail(ea, markers):
            raise RuntimeError("intentional provider failure")
        registry.unregister_provider(original)
        broken = replace(original, decompile=fail)
        registry.register_provider(broken)
        bad = call("decompile", {"addr": name})
        assert bad["code"] is None and "intentional provider failure" in bad["error"]
        registry.unregister_provider(broken)
        registry.register_provider(original)
        # Cached metadata and analysis must reflect patches, and invalid changes
        # must fail clearly instead of silently reading original file bytes.
        constant = next(k for k in p.constants if isinstance(k.value, bytes) and k.value)
        old = ida_bytes.get_byte(constant.payload)
        ida_bytes.patch_byte(constant.payload, old ^ 1)
        fresh = database.current_chunk()
        assert fresh.data != chunk.data
        assert database.get_analysis().chunk.data == fresh.data
        ida_bytes.revert_byte(constant.payload)
        assert database.current_chunk().data == chunk.data
        first = ida_bytes.get_byte(p.code_offset)
        ida_bytes.patch_byte(p.code_offset, 127)
        bad = call("decompile", {"addr": name})
        assert bad["code"] is None and bad["error"]
        ida_bytes.revert_byte(p.code_offset)
        assert database.current_chunk().data == chunk.data
        ida_auto.auto_wait()
    print(json.dumps({"ida": ida_kernwin.get_kernel_version(), "processor": ida_ida.inf_get_procname(),
                      "health": health, "code_lines": len(result["code"].splitlines()),
                      "backend": result.get("backend", "Hex-Rays"), "passed": True}, indent=2))
finally:
    idapro.close_database(False)
