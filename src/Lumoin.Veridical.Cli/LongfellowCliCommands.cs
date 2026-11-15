using Lumoin.Base;
using System;
using System.CommandLine;

namespace Lumoin.Veridical.Cli;

/// <summary>
/// The Longfellow subcommands of the command line. Each forwards to
/// <see cref="LongfellowJwtOperations"/>, the same operations the MCP tools call.
/// </summary>
internal static class LongfellowCliCommands
{
    /// <summary>Builds <c>longfellow-jwt-prove</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildJwtProveCommand()
    {
        Argument<string> tokenArgument = new("token-file") { Description = "Path to the presentation token (issuerJws~keyBindingJws), or - for standard input. The token is the private witness: it is read only from this file or standard input and is never echoed." };
        Option<string> keyXOption = new("--issuer-key-x") { Description = "The issuer public key x coordinate, 32 bytes as hex.", Required = true };
        Option<string> keyYOption = new("--issuer-key-y") { Description = "The issuer public key y coordinate, 32 bytes as hex.", Required = true };
        Option<string[]> attributeOption = new("--attribute") { Description = "A disclosed attribute written id=value; repeat the option for each attribute.", Required = true, AllowMultipleArgumentsPerToken = false };
        Option<int> blocksOption = new("--blocks") { Description = "The SHA-256 block capacity of the issuer signing input, 7 or 9.", DefaultValueFactory = _ => LongfellowJwtOperations.DefaultBlockCapacity };
        Option<string> seedOption = new("--seed") { Description = "The session seed text; the verifier must use the same value.", Required = true };
        Option<string?> outputOption = new("--output") { Description = "Path the proof (hex) is written to instead of standard output." };

        Command command = new("longfellow-jwt-prove", "Prove a presentation token against the issuer key and the disclosed attributes; writes the proof as hex to standard output or --output (the proof carries no witness).")
        {
            tokenArgument,
            keyXOption,
            keyYOption,
            attributeOption,
            blocksOption,
            seedOption,
            outputOption
        };

        command.SetAction(parseResult =>
        {
            string path = parseResult.GetValue(tokenArgument) ?? "-";
            if(!Program.TryReadInput(path, "token", out string token))
            {
                return 1;
            }

            string proofHex;
            try
            {
                proofHex = LongfellowJwtOperations.Prove(
                    token,
                    parseResult.GetValue(keyXOption) ?? string.Empty,
                    parseResult.GetValue(keyYOption) ?? string.Empty,
                    parseResult.GetValue(attributeOption) ?? [],
                    parseResult.GetValue(blocksOption),
                    parseResult.GetValue(seedOption) ?? string.Empty,
                    BaseMemoryPool.Shared);
            }
            catch(ArgumentException error)
            {
                Console.Error.WriteLine($"Error: {error.Message}");

                return 1;
            }

            string? outputPath = parseResult.GetValue(outputOption);
            if(outputPath is null)
            {
                Console.WriteLine(proofHex);

                return 0;
            }

            if(!CliFiles.TryWrite(outputPath, proofHex, "proof file", out string failure))
            {
                Console.Error.WriteLine($"Error: {failure}");

                return 1;
            }

            return 0;
        });

        return command;
    }


    /// <summary>Builds <c>longfellow-jwt-verify</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildJwtVerifyCommand()
    {
        Argument<string> proofArgument = new("proof-file") { Description = "Path to the proof hex, or - for standard input." };
        Option<string> presentationOption = new("--presentation") { Description = "Path to the presentation token or just its key-binding JWS (the part after the last ~); only the key-binding JWS is used.", Required = true };
        Option<string> keyXOption = new("--issuer-key-x") { Description = "The issuer public key x coordinate, 32 bytes as hex.", Required = true };
        Option<string> keyYOption = new("--issuer-key-y") { Description = "The issuer public key y coordinate, 32 bytes as hex.", Required = true };
        Option<string[]> attributeOption = new("--attribute") { Description = "A disclosed attribute written id=value; repeat the option for each attribute.", Required = true, AllowMultipleArgumentsPerToken = false };
        Option<int> blocksOption = new("--blocks") { Description = "The SHA-256 block capacity of the issuer signing input, 7 or 9.", DefaultValueFactory = _ => LongfellowJwtOperations.DefaultBlockCapacity };
        Option<string> seedOption = new("--seed") { Description = "The session seed text the prover used.", Required = true };

        Command command = new("longfellow-jwt-verify", "Verify a Longfellow JWT proof and report the statement it proves (exit non-zero when it does not verify).")
        {
            proofArgument,
            presentationOption,
            keyXOption,
            keyYOption,
            attributeOption,
            blocksOption,
            seedOption
        };

        command.SetAction(parseResult =>
        {
            string proofPath = parseResult.GetValue(proofArgument) ?? "-";
            if(!Program.TryReadInput(proofPath, "proof", out string proofHex))
            {
                return 1;
            }

            string presentationPath = parseResult.GetValue(presentationOption) ?? "-";
            if(!Program.TryReadInput(presentationPath, "presentation", out string presentation))
            {
                return 1;
            }

            VerificationResult result = LongfellowJwtOperations.Verify(
                proofHex,
                presentation,
                parseResult.GetValue(keyXOption) ?? string.Empty,
                parseResult.GetValue(keyYOption) ?? string.Empty,
                parseResult.GetValue(attributeOption) ?? [],
                parseResult.GetValue(blocksOption),
                parseResult.GetValue(seedOption) ?? string.Empty,
                BaseMemoryPool.Shared);
            Console.WriteLine(result.ToReport());

            return result.IsValid ? 0 : 1;
        });

        return command;
    }
}
