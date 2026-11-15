using System;
using System.CommandLine;

namespace Lumoin.Veridical.Cli;

/// <summary>
/// The BBS subcommands of the command line. Each forwards to <see cref="BbsOperations"/>, the same operations
/// the MCP tools call. Keys, signatures and proofs are hex text; messages are one UTF-8 line each, or hex
/// lines with <c>--hex</c>.
/// </summary>
internal static class BbsCliCommands
{
    /// <summary>Builds <c>bbs-keygen</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildKeyGenerateCommand()
    {
        Option<string> secretKeyFile = new("--secret-key-file") { Description = "Path the secret key (hex) is written to. The file must not exist and is readable by its owner only; the secret key is never printed.", Required = true };
        Option<string> ciphersuite = NewCiphersuiteOption();
        Option<string?> keyMaterialFile = new("--key-material-file") { Description = "Path to key material as hex (at least 32 bytes), or - for standard input. When omitted, fresh key material is drawn from the operating system." };
        Option<string> keyInfo = new("--key-info") { Description = "Key info text bound into the derivation.", DefaultValueFactory = _ => string.Empty };

        Command command = new("bbs-keygen", "Generate a BBS key pair; writes the secret key to --secret-key-file and prints the public key as hex.")
        {
            secretKeyFile,
            ciphersuite,
            keyMaterialFile,
            keyInfo
        };

        command.SetAction(parseResult =>
        {
            string? materialPath = parseResult.GetValue(keyMaterialFile);
            string? material = null;
            if(materialPath is not null && !Program.TryReadInput(materialPath, "key material", out material))
            {
                return 1;
            }

            string secretHex;
            string publicHex;
            try
            {
                (secretHex, publicHex) = BbsOperations.GenerateKey(parseResult.GetValue(ciphersuite) ?? BbsPlatformComposition.Sha256Name, material, parseResult.GetValue(keyInfo) ?? string.Empty);
            }
            catch(ArgumentException error)
            {
                Console.Error.WriteLine($"Error: {error.Message}");

                return 1;
            }

            if(!CliFiles.TryWriteSecret(parseResult.GetValue(secretKeyFile) ?? string.Empty, secretHex, "secret key file", out string failure))
            {
                Console.Error.WriteLine($"Error: {failure}");

                return 1;
            }

            Console.WriteLine(publicHex);

            return 0;
        });

        return command;
    }


    /// <summary>Builds <c>bbs-sign</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildSignCommand()
    {
        Argument<string> messagesArgument = NewMessagesArgument("The messages to sign, one per line.");
        Option<string> secretKeyFile = new("--secret-key-file") { Description = "Path to the secret key (hex). The secret key is read only from this file and is never echoed.", Required = true };
        Option<string> publicKey = NewPublicKeyOption();
        Option<string> ciphersuite = NewCiphersuiteOption();
        Option<string> header = NewTextOption("--header", "The header text bound into the signature.");
        Option<bool> hex = NewHexOption();

        Command command = new("bbs-sign", "Sign messages with a BBS secret key; writes the signature as hex to standard output.")
        {
            messagesArgument,
            secretKeyFile,
            publicKey,
            ciphersuite,
            header,
            hex
        };

        command.SetAction(parseResult =>
        {
            if(!Program.TryReadInput(parseResult.GetValue(messagesArgument) ?? "-", "messages", out string messages)
                || !Program.TryReadInput(parseResult.GetValue(secretKeyFile) ?? string.Empty, "secret key", out string secret))
            {
                return 1;
            }

            string signature;
            try
            {
                signature = BbsOperations.Sign(
                    parseResult.GetValue(ciphersuite) ?? BbsPlatformComposition.Sha256Name,
                    secret.Trim(),
                    parseResult.GetValue(publicKey) ?? string.Empty,
                    parseResult.GetValue(header) ?? string.Empty,
                    BbsOperations.SplitLines(messages),
                    parseResult.GetValue(hex));
            }
            catch(ArgumentException error)
            {
                Console.Error.WriteLine($"Error: {error.Message}");

                return 1;
            }

            Console.WriteLine(signature);

            return 0;
        });

        return command;
    }


    /// <summary>Builds <c>bbs-verify</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildVerifyCommand()
    {
        Argument<string> signatureArgument = new("signature-file") { Description = "Path to the signature hex, or - for standard input." };
        Option<string> messagesFile = new("--messages-file") { Description = "Path to the signed messages, one per line.", Required = true };
        Option<string> publicKey = NewPublicKeyOption();
        Option<string> ciphersuite = NewCiphersuiteOption();
        Option<string> header = NewTextOption("--header", "The header text the signature was made with.");
        Option<bool> hex = NewHexOption();

        Command command = new("bbs-verify", "Verify a BBS signature over messages (exit non-zero when it does not verify).")
        {
            signatureArgument,
            messagesFile,
            publicKey,
            ciphersuite,
            header,
            hex
        };

        command.SetAction(parseResult =>
        {
            if(!Program.TryReadInput(parseResult.GetValue(signatureArgument) ?? "-", "signature", out string signature)
                || !Program.TryReadInput(parseResult.GetValue(messagesFile) ?? string.Empty, "messages", out string messages))
            {
                return 1;
            }

            VerificationResult result = BbsOperations.Verify(
                parseResult.GetValue(ciphersuite) ?? BbsPlatformComposition.Sha256Name,
                parseResult.GetValue(publicKey) ?? string.Empty,
                signature,
                parseResult.GetValue(header) ?? string.Empty,
                BbsOperations.SplitLines(messages),
                parseResult.GetValue(hex));
            Console.WriteLine(result.ToReport());

            return result.IsValid ? 0 : 1;
        });

        return command;
    }


    /// <summary>Builds <c>bbs-proof-generate</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildProofGenerateCommand()
    {
        Argument<string> signatureArgument = new("signature-file") { Description = "Path to the signature hex, or - for standard input." };
        Option<string> messagesFile = new("--messages-file") { Description = "Path to all the signed messages, one per line. The messages are the prover's private input; they are read only from this file and never echoed.", Required = true };
        Option<string> disclose = new("--disclose") { Description = "The zero-based indices of the messages to disclose, comma-separated; omit to disclose none.", DefaultValueFactory = _ => string.Empty };
        Option<string> publicKey = NewPublicKeyOption();
        Option<string> ciphersuite = NewCiphersuiteOption();
        Option<string> header = NewTextOption("--header", "The header text the signature was made with.");
        Option<string> presentationHeader = NewTextOption("--presentation-header", "The presentation header text bound into this proof.");
        Option<bool> hex = NewHexOption();

        Command command = new("bbs-proof-generate", "Derive a selective-disclosure proof from a BBS signature; writes the proof as hex to standard output.")
        {
            signatureArgument,
            messagesFile,
            disclose,
            publicKey,
            ciphersuite,
            header,
            presentationHeader,
            hex
        };

        command.SetAction(parseResult =>
        {
            if(!Program.TryReadInput(parseResult.GetValue(signatureArgument) ?? "-", "signature", out string signature)
                || !Program.TryReadInput(parseResult.GetValue(messagesFile) ?? string.Empty, "messages", out string messages))
            {
                return 1;
            }

            string proof;
            try
            {
                proof = BbsOperations.GenerateProof(
                    parseResult.GetValue(ciphersuite) ?? BbsPlatformComposition.Sha256Name,
                    parseResult.GetValue(publicKey) ?? string.Empty,
                    signature,
                    parseResult.GetValue(header) ?? string.Empty,
                    parseResult.GetValue(presentationHeader) ?? string.Empty,
                    BbsOperations.SplitLines(messages),
                    parseResult.GetValue(hex),
                    parseResult.GetValue(disclose) ?? string.Empty);
            }
            catch(ArgumentException error)
            {
                Console.Error.WriteLine($"Error: {error.Message}");

                return 1;
            }

            Console.WriteLine(proof);

            return 0;
        });

        return command;
    }


    /// <summary>Builds <c>bbs-proof-verify</c>.</summary>
    /// <returns>The command.</returns>
    public static Command BuildProofVerifyCommand()
    {
        Argument<string> proofArgument = new("proof-file") { Description = "Path to the proof hex, or - for standard input." };
        Option<string> disclosedFile = new("--disclosed-messages-file") { Description = "Path to the disclosed messages, one per line written index=message with strictly ascending zero-based indices.", Required = true };
        Option<string> publicKey = NewPublicKeyOption();
        Option<string> ciphersuite = NewCiphersuiteOption();
        Option<string> header = NewTextOption("--header", "The header text the signature was made with.");
        Option<string> presentationHeader = NewTextOption("--presentation-header", "The presentation header text the proof was bound to.");
        Option<bool> hex = NewHexOption();

        Command command = new("bbs-proof-verify", "Verify a BBS selective-disclosure proof against the disclosed messages (exit non-zero when it does not verify).")
        {
            proofArgument,
            disclosedFile,
            publicKey,
            ciphersuite,
            header,
            presentationHeader,
            hex
        };

        command.SetAction(parseResult =>
        {
            if(!Program.TryReadInput(parseResult.GetValue(proofArgument) ?? "-", "proof", out string proof)
                || !Program.TryReadInput(parseResult.GetValue(disclosedFile) ?? string.Empty, "disclosed messages", out string disclosed))
            {
                return 1;
            }

            VerificationResult result = BbsOperations.VerifyProof(
                parseResult.GetValue(ciphersuite) ?? BbsPlatformComposition.Sha256Name,
                parseResult.GetValue(publicKey) ?? string.Empty,
                proof,
                parseResult.GetValue(header) ?? string.Empty,
                parseResult.GetValue(presentationHeader) ?? string.Empty,
                BbsOperations.SplitLines(disclosed),
                parseResult.GetValue(hex));
            Console.WriteLine(result.ToReport());

            return result.IsValid ? 0 : 1;
        });

        return command;
    }


    private static Argument<string> NewMessagesArgument(string description) => new("messages-file") { Description = $"Path to the file of messages, or - for standard input. {description}" };


    private static Option<string> NewPublicKeyOption() => new("--public-key") { Description = "The public key as hex (the 96-byte compressed G2 point; public).", Required = true };


    private static Option<string> NewCiphersuiteOption() => new("--ciphersuite") { Description = "The BBS ciphersuite, sha256 or shake256.", DefaultValueFactory = _ => BbsPlatformComposition.Sha256Name };


    private static Option<string> NewTextOption(string name, string description) => new(name) { Description = description, DefaultValueFactory = _ => string.Empty };


    private static Option<bool> NewHexOption() => new("--hex") { Description = "Interpret each message line as a hex-encoded byte string." };
}
