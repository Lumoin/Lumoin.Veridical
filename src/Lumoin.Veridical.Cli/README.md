# veridical

A command-line and [Model Context Protocol](https://modelcontextprotocol.io) (MCP)
tool for [Lumoin.Veridical](https://github.com/lumoin/Veridical).

## Install

```
dotnet tool install --global Lumoin.Veridical.Cli
```

## Commands

```
veridical info                 Print platform and scalar-backend information.
veridical hash <input>         BLAKE3-256 hash of UTF-8 text (or --hex bytes).
veridical hash <hex> --hex     BLAKE3-256 hash of a hex-encoded byte string.
veridical selftest             Run known-answer conformance vectors; exit non-zero on failure.
```

`selftest` runs deterministic known-answer vectors — a BLAKE3 test vector, field
arithmetic (multiply, invert), and the batch multiply checked against the
single-element path across lane-group boundaries. It is the same code used as the
native-AOT conformance check in CI, so it validates that the AOT-compiled build
computes correct results on each target (including the SIMD paths on ARM).

## MCP server

Run as an MCP stdio server:

```
veridical -mcp
```

Exposed tools: `Info`, `Hash`, `SelfTest`. The packaged `.mcp/server.json` lets
MCP-aware clients discover and launch the server.
