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


    [McpServerTool(Name = McpToolNames.BbsKeyGenerate), Description("Generate a BBS key pair (BLS12-381, sha256 or shake256 ciphersuite). The secret key is written to the named file, which must not exist, and is never returned; the public key is returned as hex.")]
    public static string BbsKeyGenerate(
        [Description("Path the secret key (hex) is written to; the file must not exist.")] string secretKeyFile,
        [Description("The ciphersuite, sha256 or shake256.")] string ciphersuite = BbsPlatformComposition.Sha256Name,
        [Description("Key info text bound into the derivation.")] string keyInfo = "")
    {
        string secretHex;
        string publicHex;
        try
        {
            (secretHex, publicHex) = BbsOperations.GenerateKey(ciphersuite, null, keyInfo);
        }
        catch(ArgumentException error)
        {
            return $"Error: {error.Message}";
        }

        if(!CliFiles.TryWriteSecret(secretKeyFile, secretHex, "secret key file", out string failure))
        {
            return $"Error: {failure}";
        }

        return publicHex;
    }


    [McpServerTool(Name = McpToolNames.BbsSign), Description("Sign messages with a BBS secret key read from a file (it never passes through the conversation). Returns the signature as hex, or an error message.")]
    public static string BbsSign(
        [Description("The messages to sign, one per line (hex lines when hex is true).")] string messages,
        [Description("Path to the file holding the secret key (hex).")] string secretKeyFile,
        [Description("The public key as hex.")] string publicKey,
        [Description("The ciphersuite, sha256 or shake256.")] string ciphersuite = BbsPlatformComposition.Sha256Name,
        [Description("The header text bound into the signature.")] string header = "",
        [Description("Whether each message line is a hex-encoded byte string.")] bool hex = false)
    {
        if(!CliFiles.TryRead(secretKeyFile, "secret key", out string secret, out string failure))
        {
            return $"Error: {failure}";
        }

        try
        {
            return BbsOperations.Sign(ciphersuite, secret.Trim(), publicKey, header, BbsOperations.SplitLines(messages), hex);
        }
        catch(ArgumentException error)
        {
            return $"Error: {error.Message}";
        }
    }


    [McpServerTool(Name = McpToolNames.BbsVerify), Description("Verify a BBS signature over messages and return a one-line report, or the reason it does not verify.")]
    public static string BbsVerify(
        [Description("The signature as hex.")] string signature,
        [Description("The signed messages, one per line (hex lines when hex is true).")] string messages,
        [Description("The public key as hex.")] string publicKey,
        [Description("The ciphersuite, sha256 or shake256.")] string ciphersuite = BbsPlatformComposition.Sha256Name,
        [Description("The header text the signature was made with.")] string header = "",
        [Description("Whether each message line is a hex-encoded byte string.")] bool hex = false)
    {
        return BbsOperations.Verify(ciphersuite, publicKey, signature, header, BbsOperations.SplitLines(messages), hex).ToReport();
    }


    [McpServerTool(Name = McpToolNames.BbsProofGenerate), Description("Derive a BBS selective-disclosure proof from a signature, disclosing the messages at the named indices. Returns the proof as hex, or an error message. The proof reveals only the disclosed messages.")]
    public static string BbsProofGenerate(
        [Description("The signature as hex.")] string signature,
        [Description("All the signed messages, one per line (hex lines when hex is true).")] string messages,
        [Description("The zero-based indices to disclose, comma-separated; empty discloses none.")] string disclose,
        [Description("The public key as hex.")] string publicKey,
        [Description("The ciphersuite, sha256 or shake256.")] string ciphersuite = BbsPlatformComposition.Sha256Name,
        [Description("The header text the signature was made with.")] string header = "",
        [Description("The presentation header text bound into this proof.")] string presentationHeader = "",
        [Description("Whether each message line is a hex-encoded byte string.")] bool hex = false)
    {
        try
        {
            return BbsOperations.GenerateProof(ciphersuite, publicKey, signature, header, presentationHeader, BbsOperations.SplitLines(messages), hex, disclose);
        }
        catch(ArgumentException error)
        {
            return $"Error: {error.Message}";
        }
    }


    [McpServerTool(Name = McpToolNames.BbsProofVerify), Description("Verify a BBS selective-disclosure proof against the disclosed messages and return a one-line report, or the reason it does not verify.")]
    public static string BbsProofVerify(
        [Description("The proof as hex.")] string proof,
        [Description("The disclosed messages, one per line written index=message with strictly ascending zero-based indices.")] string disclosedMessages,
        [Description("The public key as hex.")] string publicKey,
        [Description("The ciphersuite, sha256 or shake256.")] string ciphersuite = BbsPlatformComposition.Sha256Name,
        [Description("The header text the signature was made with.")] string header = "",
        [Description("The presentation header text the proof was bound to.")] string presentationHeader = "",
        [Description("Whether each message is a hex-encoded byte string.")] bool hex = false)
    {
        return BbsOperations.VerifyProof(ciphersuite, publicKey, proof, header, presentationHeader, BbsOperations.SplitLines(disclosedMessages), hex).ToReport();
    }


    [McpServerTool(Name = McpToolNames.SecdsaSplitSign), Description("SECDSA split sign over software keys: produces a standard ECDSA signature r || s (hex) under d = P*u. The PIN-key and hardware-key scalars are read from files and never pass through the conversation.")]
    public static string SecdsaSplitSign(
        [Description("Path to the file holding the PIN-key scalar P (hex).")] string pinKeyFile,
        [Description("Path to the file holding the hardware-key scalar u (hex).")] string hardwareKeyFile,
        [Description("The message hash e = H(M), 32 bytes as hex.")] string messageHash)
    {
        return WithSecrets([pinKeyFile, hardwareKeyFile], secrets => SecdsaOperations.SplitSign(secrets[0], secrets[1], messageHash));
    }


    [McpServerTool(Name = McpToolNames.SecdsaPublicKey), Description("Derive the split public key (P*u)*G as a compressed point (hex). The key scalars are read from files and never pass through the conversation.")]
    public static string SecdsaPublicKey(
        [Description("Path to the file holding the PIN-key scalar P (hex).")] string pinKeyFile,
        [Description("Path to the file holding the hardware-key scalar u (hex).")] string hardwareKeyFile)
    {
        return WithSecrets([pinKeyFile, hardwareKeyFile], secrets => SecdsaOperations.DerivePublicKey(secrets[0], secrets[1]));
    }


    [McpServerTool(Name = McpToolNames.SecdsaVerify), Description("Verify an ECDSA signature r || s under a compressed public key and return a one-line report, or the reason it does not verify.")]
    public static string SecdsaVerify(
        [Description("The compressed public key, 33 bytes as hex.")] string publicKey,
        [Description("The message hash, 32 bytes as hex.")] string messageHash,
        [Description("The signature r || s, 64 bytes as hex.")] string signature)
    {
        return SecdsaOperations.Verify(publicKey, messageHash, signature).ToReport();
    }


    [McpServerTool(Name = McpToolNames.SecdsaRecoverNoncePoint), Description("Recover the nonce point R of an ECDSA signature as a compressed point (hex), or an error message when none is recoverable.")]
    public static string SecdsaRecoverNoncePoint(
        [Description("The compressed public key, 33 bytes as hex.")] string publicKey,
        [Description("The message hash, 32 bytes as hex.")] string messageHash,
        [Description("The signature r || s, 64 bytes as hex.")] string signature)
    {
        return Produced(() => SecdsaOperations.RecoverNoncePoint(publicKey, messageHash, signature));
    }


    [McpServerTool(Name = McpToolNames.SecdsaVerifyFull), Description("Verify a signature given as its nonce point R and s, and return a one-line report, or the reason it does not verify.")]
    public static string SecdsaVerifyFull(
        [Description("The compressed public key, 33 bytes as hex.")] string publicKey,
        [Description("The message hash, 32 bytes as hex.")] string messageHash,
        [Description("The compressed nonce point R, 33 bytes as hex.")] string noncePoint,
        [Description("The component s, 32 bytes as hex.")] string s)
    {
        return SecdsaOperations.VerifyFull(publicKey, messageHash, noncePoint, s).ToReport();
    }


    [McpServerTool(Name = McpToolNames.SecdsaDlProve), Description("Prove that every pair (G_i, D_i) shares one private key d (DL-equality NIZK); returns the proof r || s as hex. The witness is read from a file and never passes through the conversation.")]
    public static string SecdsaDlProve(
        [Description("Path to the file holding the private key d (hex).")] string witnessFile,
        [Description("The concatenated compressed generators G_i as hex.")] string generators,
        [Description("The concatenated compressed public keys D_i = d*G_i as hex.")] string publicKeys,
        [Description("The challenge byte string N as hex; empty for an empty challenge.")] string challenge = "")
    {
        return WithSecrets([witnessFile], secrets => SecdsaOperations.DlEqualityProve(secrets[0], generators, publicKeys, challenge));
    }


    [McpServerTool(Name = McpToolNames.SecdsaDlVerify), Description("Verify a DL-equality proof and return a one-line report, or the reason it does not verify.")]
    public static string SecdsaDlVerify(
        [Description("The concatenated compressed generators G_i as hex.")] string generators,
        [Description("The concatenated compressed public keys D_i as hex.")] string publicKeys,
        [Description("The proof r || s, 64 bytes as hex.")] string proof,
        [Description("The challenge byte string N as hex; empty for an empty challenge.")] string challenge = "")
    {
        return SecdsaOperations.DlEqualityVerify(generators, publicKeys, challenge, proof).ToReport();
    }


    [McpServerTool(Name = McpToolNames.SecdsaBlindingProve), Description("Prove the blinding relation ZKP[(G,G''),(Y',Y'')]; returns the proof r || s as hex. The witness is read from a file and never passes through the conversation.")]
    public static string SecdsaBlindingProve(
        [Description("The standard base point G, compressed, as hex.")] string g,
        [Description("The point G'', compressed, as hex.")] string gDoublePrime,
        [Description("The point Y', compressed, as hex.")] string yPrime,
        [Description("The point Y'', compressed, as hex.")] string yDoublePrime,
        [Description("Path to the file holding the blinding witness (hex).")] string witnessFile)
    {
        return WithSecrets([witnessFile], secrets => SecdsaOperations.BlindingRelationProve(g, gDoublePrime, yPrime, yDoublePrime, secrets[0]));
    }


    [McpServerTool(Name = McpToolNames.SecdsaBlindingVerify), Description("Verify the blinding relation and return a one-line report, or the reason it does not verify.")]
    public static string SecdsaBlindingVerify(
        [Description("The standard base point G, compressed, as hex.")] string g,
        [Description("The point G'', compressed, as hex.")] string gDoublePrime,
        [Description("The point Y', compressed, as hex.")] string yPrime,
        [Description("The point Y'', compressed, as hex.")] string yDoublePrime,
        [Description("The proof r || s, 64 bytes as hex.")] string proof)
    {
        return SecdsaOperations.BlindingRelationVerify(g, gDoublePrime, yPrime, yDoublePrime, proof).ToReport();
    }


    [McpServerTool(Name = McpToolNames.SecdsaControlProve), Description("Prove the control relation ZKP[(H,H'),(W,W'),H(T_I)]; returns the proof r || s as hex. The witness is read from a file and never passes through the conversation.")]
    public static string SecdsaControlProve(
        [Description("The point H, compressed, as hex.")] string h,
        [Description("The point W, compressed, as hex.")] string w,
        [Description("The point H', compressed, as hex.")] string hPrime,
        [Description("The point W', compressed, as hex.")] string wPrime,
        [Description("Path to the file holding the control witness (hex).")] string witnessFile,
        [Description("The record context T_I as hex.")] string recordContext)
    {
        return WithSecrets([witnessFile], secrets => SecdsaOperations.ControlRelationProve(h, w, hPrime, wPrime, secrets[0], recordContext));
    }


    [McpServerTool(Name = McpToolNames.SecdsaControlVerify), Description("Verify the control relation and return a one-line report, or the reason it does not verify.")]
    public static string SecdsaControlVerify(
        [Description("The point H, compressed, as hex.")] string h,
        [Description("The point W, compressed, as hex.")] string w,
        [Description("The point H', compressed, as hex.")] string hPrime,
        [Description("The point W', compressed, as hex.")] string wPrime,
        [Description("The record context T_I as hex.")] string recordContext,
        [Description("The proof r || s, 64 bytes as hex.")] string proof)
    {
        return SecdsaOperations.ControlRelationVerify(h, w, hPrime, wPrime, recordContext, proof).ToReport();
    }


    [McpServerTool(Name = McpToolNames.SecdsaEcdhMacDeriveKey), Description("Derive the ECDH-MAC key shared with a peer public point. The private scalar is read from a file; the MAC key is written to the named file, which must not exist, and is never returned.")]
    public static string SecdsaEcdhMacDeriveKey(
        [Description("Path to the file holding the private scalar (hex).")] string privateKeyFile,
        [Description("The peer's compressed public point as hex.")] string peerPublicPoint,
        [Description("Path the MAC key (hex) is written to; the file must not exist.")] string outputFile,
        [Description("The HKDF salt as hex; empty for an empty salt.")] string salt = "",
        [Description("The HKDF info as hex; empty for empty info.")] string sharedInfo = "")
    {
        if(!CliFiles.TryRead(privateKeyFile, "private key", out string privateKey, out string readFailure))
        {
            return $"Error: {readFailure}";
        }

        string macKey;
        try
        {
            macKey = SecdsaOperations.EcdhMacDeriveKey(privateKey.Trim(), peerPublicPoint, salt, sharedInfo);
        }
        catch(ArgumentException error)
        {
            return $"Error: {error.Message}";
        }

        if(!CliFiles.TryWriteSecret(outputFile, macKey, "MAC key file", out string writeFailure))
        {
            return $"Error: {writeFailure}";
        }

        return $"Wrote the MAC key to {outputFile}.";
    }


    [McpServerTool(Name = McpToolNames.SecdsaEcdhMacSign), Description("Compute the ECDH-MAC of a message under the prover's private scalar and the verifier's ephemeral public key; returns the MAC as hex. The private scalar is read from a file and never passes through the conversation.")]
    public static string SecdsaEcdhMacSign(
        [Description("Path to the file holding the prover's private scalar (hex).")] string privateKeyFile,
        [Description("The verifier's ephemeral compressed public key as hex.")] string verifierEphemeralPublicKey,
        [Description("The HKDF salt as hex; empty for an empty salt.")] string salt = "",
        [Description("The HKDF info as hex; empty for empty info.")] string sharedInfo = "",
        [Description("The message as hex; empty for an empty message.")] string message = "")
    {
        return WithSecrets([privateKeyFile], secrets => SecdsaOperations.EcdhMacSign(secrets[0], verifierEphemeralPublicKey, salt, sharedInfo, message));
    }


    [McpServerTool(Name = McpToolNames.SecdsaEcdhMacVerify), Description("Verify an ECDH-MAC with the verifier's ephemeral private scalar (read from a file) and return a one-line report, or the reason it does not verify.")]
    public static string SecdsaEcdhMacVerify(
        [Description("The prover's compressed public key as hex.")] string proverPublicKey,
        [Description("Path to the file holding the verifier's ephemeral private scalar (hex).")] string verifierEphemeralPrivateKeyFile,
        [Description("The MAC, 32 bytes as hex.")] string mac,
        [Description("The HKDF salt as hex; empty for an empty salt.")] string salt = "",
        [Description("The HKDF info as hex; empty for empty info.")] string sharedInfo = "",
        [Description("The message as hex; empty for an empty message.")] string message = "")
    {
        if(!CliFiles.TryRead(verifierEphemeralPrivateKeyFile, "verifier ephemeral private key", out string privateKey, out string failure))
        {
            return $"Error: {failure}";
        }

        return SecdsaOperations.EcdhMacVerify(proverPublicKey, privateKey.Trim(), salt, sharedInfo, message, mac).ToReport();
    }


    [McpServerTool(Name = McpToolNames.SecdsaEcdhMacSplitSign), Description("Compute the ECDH-MAC from the wallet and WSCA key shares and the base key; returns the MAC as hex. The shares are read from files and never pass through the conversation.")]
    public static string SecdsaEcdhMacSplitSign(
        [Description("Path to the file holding the wallet key share (hex).")] string walletKeyShareFile,
        [Description("Path to the file holding the WSCA key share (hex).")] string wscaKeyShareFile,
        [Description("Path to the file holding the base key (hex).")] string baseKeyFile,
        [Description("The verifier's ephemeral compressed public key as hex.")] string verifierEphemeralPublicKey,
        [Description("The HKDF salt as hex; empty for an empty salt.")] string salt = "",
        [Description("The HKDF info as hex; empty for empty info.")] string sharedInfo = "",
        [Description("The message as hex; empty for an empty message.")] string message = "")
    {
        return WithSecrets(
            [walletKeyShareFile, wscaKeyShareFile, baseKeyFile],
            secrets => SecdsaOperations.EcdhMacSplitSign(secrets[0], secrets[1], secrets[2], verifierEphemeralPublicKey, salt, sharedInfo, message));
    }


    //Reads each secret file, runs the operation over the trimmed contents and returns its result, or the
    //error message when a file cannot be read or an input is invalid.
    private static string WithSecrets(string[] files, Func<string[], string> operation)
    {
        var secrets = new string[files.Length];
        for(int i = 0; i < files.Length; i++)
        {
            if(!CliFiles.TryRead(files[i], "secret", out string content, out string failure))
            {
                return $"Error: {failure}";
            }

            secrets[i] = content.Trim();
        }

        return Produced(() => operation(secrets));
    }


    private static string Produced(Func<string> operation)
    {
        try
        {
            return operation();
        }
        catch(ArgumentException error)
        {
            return $"Error: {error.Message}";
        }
    }
}
