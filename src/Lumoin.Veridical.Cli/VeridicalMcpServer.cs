using Lumoin.Base;
using Lumoin.Veridical.Core.ConstraintSystems;
using ModelContextProtocol.Server;
using System;
using System.ComponentModel;
using System.Text.Json;

namespace Lumoin.Veridical.Cli;

/// <summary>
/// The MCP tools the Veridical server exposes to AI clients when run in MCP mode
/// (<c>veridical -mcp</c>). Each tool forwards to the same
/// <see cref="VeridicalOperations"/> the CLI subcommands use, so the two surfaces
/// stay in lockstep.
/// </summary>
[McpServerToolType]
internal sealed class VeridicalMcpServer
{
    [McpServerTool(Name = McpToolNames.Info), Description("Get platform and scalar-backend information: OS, process architecture, runtime, and whether each curve's scalar arithmetic is hardware-accelerated (SIMD) on this host.")]
    public static string Info()
    {
        return VeridicalOperations.Info();
    }


    [McpServerTool(Name = McpToolNames.Hash), Description("Compute the BLAKE3-256 hash of a text input. Returns the lowercase-hex digest.")]
    public static string Hash(
        [Description("The text to hash (interpreted as UTF-8).")] string text)
    {
        return VeridicalOperations.HashBlake3Text(text);
    }


    [McpServerTool(Name = McpToolNames.SelfTest), Description("Run the known-answer conformance vectors (BLAKE3, field arithmetic, batch multiply) and return a pass/fail report.")]
    public static string SelfTest()
    {
        (bool _, string report) = VeridicalOperations.RunSelfTest();

        return report;
    }


    [McpServerTool(Name = McpToolNames.Prove), Description("Prove a supply-chain predicate bundle (at-least / at-most fixed-point claims, in zero knowledge over Spartan-over-Ligero) from a prove-request JSON string that carries the private measured quantities. Returns the proof artifact JSON on success, or an error message when the request is malformed or the statement is not provable.")]
    public static string Prove(
        [Description("The prove-request JSON: the statement parameters and the private measured quantities.")] string request)
    {
        try
        {
            return PredicateProofOperations.ProveToJson(request, BaseMemoryPool.Shared);
        }
        catch(JsonException error)
        {
            return $"Error: the request is not valid JSON ({error.Message}).";
        }
        catch(R1csCircuitCompilationException error)
        {
            return $"Not provable: {error.Message}";
        }
        catch(ArgumentException error)
        {
            return $"Error: {error.Message}";
        }
    }


    [McpServerTool(Name = McpToolNames.Verify), Description("Verify a supply-chain predicate proof artifact (JSON string) and return a one-line report of the statement it proves, or the reason it does not verify. Verification needs no private data — only the artifact.")]
    public static string Verify(
        [Description("The proof artifact JSON to verify.")] string artifact)
    {
        return PredicateProofOperations.VerifyFromJson(artifact, BaseMemoryPool.Shared).ToReport();
    }
}
