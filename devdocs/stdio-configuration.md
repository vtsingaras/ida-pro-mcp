# Stdio configuration

Codex starts the installed plugin through its packaged MCP configuration:

    uv run idalib-mcp --stdio --unsafe --ext dbg

This personal fork's Codex entry explicitly enables the restricted worker tools
and debugger extension that the local launcher previously selected. The CLI
itself keeps both options off unless requested. This does not start a debugger
or execute an input binary.

The supported --ext option selects a comma-separated list of worker extension
groups for stdio. The supervisor applies the same selection to tool discovery,
schema caching and tool calls. HTTP clients retain per-request ?ext= selection;
--ext is rejected without --stdio.

No external script must import the supervisor or change its private fields.
The installed plugin owns the working directory and source version, so moving
between marketplaces or upgrading its cache does not leave a hard-coded path.

When migrating from a separately configured server with the same name, back up
that server's settings and remove the global override:

    codex mcp remove idalib

Keep the marketplace plugin installed and enabled. The global entry otherwise
takes precedence over the plugin's packaged command. Reconnect the server or
restart the app after migration. Plugin-scoped tool policy can be configured
under plugins.<plugin>.mcp_servers.<server> in Codex, independently of server
startup.

See [OpenAI plugin packaging](https://developers.openai.com/plugins/build/plugins)
and [MCP transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).
