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


    [McpServerTool(Name = McpToolNames.Prove), Description("Prove a supply-chain predicate bundle (at-least / at-most fixed-point range claims over transparent Spartan-over-Ligero, and allowed-value memberOf claims over LogUp-over-Ligero lookups — sound and binding, not witness-hiding: treat the artifact as disclosing the measured quantities to its recipient) from a prove-request JSON string that carries the measured quantities. Returns the proof artifact JSON on success, or an error message when the request is malformed or the statement is not provable.")]
    public static string Prove(
        [Description("The prove-request JSON: the statement parameters and the measured quantities.")] string request)
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

    [McpServerTool(Name = McpToolNames.LongfellowJwtProve), Description("Prove a Longfellow JWT presentation token (issuerJws~keyBindingJws, restricted format) against the issuer public key and the disclosed attributes. The token is the private witness, so it is read from a file and never passes through the conversation; the proof (lowercase hex, carrying no witness) is written to a file. Returns a confirmation, or an error message when the inputs do not describe a provable statement.")]
    public static string LongfellowJwtProve(
        [Description("Path to the file holding the presentation token: issuerJws~keyBindingJws.")] string tokenFile,
        [Description("The issuer public key x coordinate, 32 bytes as hex.")] string issuerKeyX,
        [Description("The issuer public key y coordinate, 32 bytes as hex.")] string issuerKeyY,
        [Description("The disclosed attributes, one id=value per line.")] string attributes,
        [Description("The session seed text; the verifier must use the same value.")] string seed,
        [Description("Path the proof (hex) is written to.")] string proofFile,
        [Description("The SHA-256 block capacity of the issuer signing input, 7 or 9.")] int blocks = LongfellowJwtOperations.DefaultBlockCapacity)
    {
        if(!CliFiles.TryRead(tokenFile, "token", out string token, out string readFailure))
        {
            return $"Error: {readFailure}";
        }

        string proofHex;
        try
        {
            proofHex = LongfellowJwtOperations.Prove(token, issuerKeyX, issuerKeyY, LongfellowJwtOperations.SplitAttributeLines(attributes), blocks, seed, BaseMemoryPool.Shared);
        }
        catch(ArgumentException error)
        {
            return $"Error: {error.Message}";
        }

        if(!CliFiles.TryWrite(proofFile, proofHex, "proof file", out string writeFailure))
        {
            return $"Error: {writeFailure}";
        }

        return $"Wrote the proof ({proofHex.Length / 2} bytes) to {proofFile}.";
    }


    [McpServerTool(Name = McpToolNames.LongfellowJwtVerify), Description("Verify a Longfellow JWT proof against the issuer public key, the disclosed attributes and the key-binding JWS of the presentation, and return a one-line report of the statement it proves or the reason it does not verify.")]
    public static string LongfellowJwtVerify(
        [Description("Path to the file holding the proof as hex.")] string proofFile,
        [Description("Path to the file holding the presentation token, or just its key-binding JWS (the part after the last ~).")] string presentationFile,
        [Description("The issuer public key x coordinate, 32 bytes as hex.")] string issuerKeyX,
        [Description("The issuer public key y coordinate, 32 bytes as hex.")] string issuerKeyY,
        [Description("The disclosed attributes, one id=value per line.")] string attributes,
        [Description("The session seed text the prover used.")] string seed,
        [Description("The SHA-256 block capacity of the issuer signing input, 7 or 9.")] int blocks = LongfellowJwtOperations.DefaultBlockCapacity)
    {
        if(!CliFiles.TryRead(proofFile, "proof", out string proofHex, out string proofFailure))
        {
            return $"Error: {proofFailure}";
        }

        if(!CliFiles.TryRead(presentationFile, "presentation", out string presentation, out string presentationFailure))
        {
            return $"Error: {presentationFailure}";
        }

        return LongfellowJwtOperations.Verify(proofHex, presentation, issuerKeyX, issuerKeyY, LongfellowJwtOperations.SplitAttributeLines(attributes), blocks, seed, BaseMemoryPool.Shared).ToReport();
    }
}
