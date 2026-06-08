namespace Lumoin.Veridical.Cli;

/// <summary>
/// Stable names for the MCP tools the Veridical MCP server exposes. Pinned as
/// constants so the server registration and any test or documentation reference
/// the same identifiers.
/// </summary>
internal static class McpToolNames
{
    /// <summary>Platform and scalar-backend information.</summary>
    public const string Info = "Info";

    /// <summary>BLAKE3-256 hash of a text input.</summary>
    public const string Hash = "Hash";

    /// <summary>Run the known-answer conformance vectors.</summary>
    public const string SelfTest = "SelfTest";

    /// <summary>All exposed tool names.</summary>
    public static readonly string[] All =
    [
        Info,
        Hash,
        SelfTest
    ];
}
