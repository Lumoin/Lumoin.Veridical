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
veridical prove <request>      Prove a supply-chain predicate bundle from local data; artifact JSON to stdout.
veridical verify <artifact>    Verify a proof artifact and report the statement it proves; exit non-zero if it does not.
```

For `prove` and `verify`, the file argument may be `-` to read from standard input.

`selftest` runs deterministic known-answer vectors — a BLAKE3 test vector, field
arithmetic (multiply, invert), and the batch multiply checked against the
single-element path across lane-group boundaries. It is the same code used as the
native-AOT conformance check in CI, so it validates that the AOT-compiled build
computes correct results on each target (including the SIMD paths on ARM).

## Predicate proofs

`prove` and `verify` cover a supply-chain predicate bundle: an ordered conjunction of
*at-least* / *at-most* fixed-point claims (for example, a battery-passport bundle —
recycled content at or above a minimum **and** carbon footprint at or below a cap),
proven over Spartan-over-Ligero — a transparent (hash-based) proof system with no
trusted setup and no key material to distribute. The measured quantities are private
witness inputs and are not written into the artifact: it carries the statement and
any public bounds, not the measured values.

- **`prove`** reads a request that carries the statement parameters and the *private*
  measured quantities, and writes a proof artifact. The measured values stay local —
  they never appear in the artifact. Driven through the MCP server, this is an on-prem
  prover: the artifact is the only thing that leaves.
- **`verify`** needs only the artifact — no private data, no PKI, no platform change.
  It rebuilds the statement circuit from the artifact's claim descriptors, reconstructs
  the public instance from the revealed public inputs (no witness), and checks the
  proof. It then prints the described statement.

A regulatory bound is either a **constant** baked into the circuit or a **public input**
the artifact reveals. Either way the bound is bound to the proof: changing a constant
in the descriptor, a revealed public input, or the commitment parameters causes
verification to fail. The proof attests that the *described* statement is satisfiable —
`verify` prints that statement so an operator confirms it is the compliance claim they
require.

The commitment parameters (curve, query count, digest size) are pinned to one wired set
that both verbs enforce, so an artifact cannot silently weaken them.

### Example

A request proving recycled content ≥ 30.0% and carbon footprint ≤ 12.50, over private
measurements of 32.5% and 11.20:

```json
{
  "format": "veridical-supply-chain-predicate-request/1",
  "curve": "bls12-381",
  "transcriptDomain": "veridical.supplychain.batterypassport.v1",
  "queryCount": 32,
  "digestBytes": 32,
  "claims": [
    { "name": "recycled_content", "direction": "atLeast", "fractionalDigits": 1, "inclusiveMaximum": "100.0", "bound": "constant", "boundValue": "30.0", "measured": "32.5" },
    { "name": "carbon_footprint", "direction": "atMost", "fractionalDigits": 2, "inclusiveMaximum": "100.00", "bound": "constant", "boundValue": "12.50", "measured": "11.20" }
  ]
}
```

```
veridical prove request.json > artifact.json
veridical verify artifact.json
# VALID: proves recycled_content >= 30.0 (constant); carbon_footprint <= 12.50 (constant)
```

The artifact and request JSON are serialized by `Lumoin.Veridical.Json`, an AOT-safe
(source-generated) reference serializer that consumers can reuse.

## MCP server

Run as an MCP stdio server:

```
veridical -mcp
```

Exposed tools: `Info`, `Hash`, `SelfTest`, `Prove`, `Verify`. The packaged
`.mcp/server.json` lets MCP-aware clients discover and launch the server.
