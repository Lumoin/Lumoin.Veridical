using ModelContextProtocol.Server;
using System.ComponentModel;

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
}
