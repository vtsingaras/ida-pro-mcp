# Decompiler providers

Installed IDA plugins can supply source for bytecode or other processors while
MCP clients keep using decompile, analyze_function, and the other consumers of
decompile_function_safe. Native databases keep the existing Hex-Rays path.

Register on IDA's main thread, after importing the active MCP package:

~~~python
from ida_pro_mcp.ida_mcp.decompiler_providers import (
    DecompilerProvider, register_provider, unregister_provider,
)

provider = DecompilerProvider(
    name="Example bytecode decompiler",
    language="Example",
    supports=lambda: ida_ida.inf_get_procname() == "example",
    decompile=lambda ea, include_addresses: recover_source(ea, include_addresses),
    references=lambda ea: [{"addr": "0x100", "name": "example_symbol"}],
    ready=dependencies_available,
)
register_provider(provider)
# During plugin termination:
unregister_provider(provider)
~~~

GUI installations may import the package as ida_mcp; use the package already
loaded by that installation. Do not import a second independent MCP package.

Callbacks run on IDA's main thread under the existing tool timeout. They must not
execute the analyzed program. A provider's decompile callback returns text and
may raise an exception. A matching provider owns decompilation errors; failures
are returned to the client instead of invoking a native decompiler on bytecode.
References are optional and use the existing addr, name, optional string shape.
A references failure does not discard successfully recovered source.

Selection uses descending priority, then name. Duplicate names are rejected.
Keep the registered object to unregister precisely that instance on shutdown.
The registry discovers installed Python entry points in the
`ida_pro_mcp.decompiler_providers` group. Each entry names a factory that accepts
the host's `DecompilerProvider` class and returns an instance. Discovery is lazy
and rescans if IDA adds a Python path after opening a database. A factory is
loaded at most once per process. Import failures are logged and isolated.

```ini
[ida_pro_mcp.decompiler_providers]
example = example_package.mcp_provider:create_provider
```

```python
def create_provider(provider_type):
    return provider_type(
        name="Example", language="Example",
        supports=is_example_database,
        decompile=recover_source,
    )
```

Only trusted installed Python packages supply factories. The registry never
loads code from an IDB, an analyzed binary, or a network source. It does not import
another MCP package to register a provider; the host passes its own class to the
factory. This handles both GUI and idalib import layouts.

server_health.hexrays_ready retains its original meaning. Clients should use
decompiler_ready, decompiler_backend, and decompiler_hint for the effective
backend. The decompile tool description advertises provider support even before
a database is opened. Custom results also identify backend and language.

Source providers do not need to implement Hex-Rays ctree or microcode. APIs that
specifically manipulate those representations remain Hex-Rays-only.

## Lua RE and Java onboarding

[Lua RE](https://github.com/vtsingaras/lua-re/tree/master/lua/ida) is a separate
AGPL-3.0 IDA loader/processor/plugin. This MIT MCP fork contains only the generic
provider interface. Install Lua RE into IDA's user directory and restart the
worker. Its installed entry-point metadata registers Lua recovery automatically.

From the Lua RE `lua/ida` directory:

```sh
python3 install.py --list-java --json
python3 install.py --configure-java
python3 install.py --java /path/to/java
```

Interactive selection is an explicit terminal operation. MCP startup and tools
never prompt for Java. An unavailable runtime makes `decompiler_ready` false and
produces an actionable error, while bytecode analysis remains available.
