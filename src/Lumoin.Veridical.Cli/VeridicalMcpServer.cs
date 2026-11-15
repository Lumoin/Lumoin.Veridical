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


    [McpServerTool(Name = McpToolNames.SecdsaSplitSignPrepare), Description("SECDSA split sign, prepare phase: computes the blinded representative e' = P^-1 * e for the key holder's raw ECDSA sign and writes it to the named file, which must not exist; it is never returned, because e' together with the message hash reveals the PIN key. The PIN key is read from a file and never passes through the conversation.")]
    public static string SecdsaSplitSignPrepare(
        [Description("Path to the file holding the PIN-key scalar P (hex).")] string pinKeyFile,
        [Description("The message hash e = H(M), 32 bytes as hex.")] string messageHash,
        [Description("Path the blinded representative e' (hex) is written to; the file must not exist.")] string outputFile)
    {
        return WithSecretsToFile([pinKeyFile], outputFile, "blinded representative file", secrets => SecdsaOperations.SplitSignPrepare(secrets[0], messageHash));
    }


    [McpServerTool(Name = McpToolNames.SecdsaSplitSignComplete), Description("SECDSA split sign, complete phase: masks the key holder's raw signature r || s0 with the PIN key and returns the ECDSA signature r || s (hex) only if it verifies under the composite public key; otherwise returns an error and no signature. The PIN key and s0 are read from files and never pass through the conversation.")]
    public static string SecdsaSplitSignComplete(
        [Description("Path to the file holding the PIN-key scalar P (hex).")] string pinKeyFile,
        [Description("The message hash e = H(M) given to the prepare phase, 32 bytes as hex.")] string messageHash,
        [Description("The composite compressed public key Y = (P*u)*G, 33 bytes as hex.")] string publicKey,
        [Description("Path to the file holding the key holder's raw signature r || s0 (hex, 64 bytes).")] string rawSignatureFile)
    {
        return WithSecrets([pinKeyFile, rawSignatureFile], secrets => SecdsaOperations.SplitSignComplete(secrets[0], messageHash, publicKey, secrets[1]));
    }


    [McpServerTool(Name = McpToolNames.SecdsaEcdhMacPrepare), Description("ECDH-MAC prepare phase: validates the verifier's ephemeral public key (length, not infinity, on the curve) and returns the canonical compressed point (hex) to send to the key holder's ECDH, or an error message.")]
    public static string SecdsaEcdhMacPrepare(
        [Description("The verifier's ephemeral compressed public key as hex.")] string peerPublicKey)
    {
        return Produced(() => SecdsaOperations.EcdhMacPrepare(peerPublicKey));
    }


    [McpServerTool(Name = McpToolNames.SecdsaEcdhMacApplyKeyShare), Description("Split ECDH-MAC, wallet and WSCA step: multiplies a compressed point by the party's key share (E' = zU*E at the wallet, E'' = zW*E' at the WSCA) and returns the product (hex). The key share is read from a file and never passes through the conversation.")]
    public static string SecdsaEcdhMacApplyKeyShare(
        [Description("Path to the file holding the key-share scalar (hex).")] string keyShareFile,
        [Description("The compressed point to multiply as hex.")] string point)
    {
        return WithSecrets([keyShareFile], secrets => SecdsaOperations.EcdhMacApplyKeyShare(secrets[0], point));
    }


    [McpServerTool(Name = McpToolNames.SecdsaEcdhMacCompleteSign), Description("ECDH-MAC complete phase for signing: derives K = HKDF(Z_AB, SharedInfo) from the shared secret the key holder's ECDH returned and returns the MAC (hex). The shared secret is read from a file and never passes through the conversation.")]
    public static string SecdsaEcdhMacCompleteSign(
        [Description("Path to the file holding the shared secret Z_AB (hex, 32 bytes).")] string sharedSecretFile,
        [Description("The HKDF salt as hex; empty for an empty salt.")] string salt = "",
        [Description("The HKDF info as hex; empty for empty info.")] string sharedInfo = "",
        [Description("The message as hex; empty for an empty message.")] string message = "")
    {
        return WithSecrets([sharedSecretFile], secrets => SecdsaOperations.EcdhMacCompleteSign(secrets[0], salt, sharedInfo, message));
    }


    [McpServerTool(Name = McpToolNames.SecdsaEcdhMacCompleteVerify), Description("ECDH-MAC complete phase for verification: derives K from the shared secret the verifier's key holder returned and compares the MAC in constant time; returns a one-line report, or the reason it does not verify. The shared secret is read from a file.")]
    public static string SecdsaEcdhMacCompleteVerify(
        [Description("Path to the file holding the shared secret Z_AB (hex, 32 bytes).")] string sharedSecretFile,
        [Description("The MAC, 32 bytes as hex.")] string mac,
        [Description("The HKDF salt as hex; empty for an empty salt.")] string salt = "",
        [Description("The HKDF info as hex; empty for empty info.")] string sharedInfo = "",
        [Description("The message as hex; empty for an empty message.")] string message = "")
    {
        if(!CliFiles.TryRead(sharedSecretFile, "shared secret", out string sharedSecret, out string failure))
        {
            return $"Error: {failure}";
        }

        return SecdsaOperations.EcdhMacCompleteVerify(sharedSecret.Trim(), salt, sharedInfo, message, mac).ToReport();
    }


    [McpServerTool(Name = McpToolNames.SecdsaEcdhMacVerifyMac), Description("Verify an ECDH-MAC under a MAC key the key holder derived itself, comparing in constant time; returns a one-line report, or the reason it does not verify. The MAC key is read from a file.")]
    public static string SecdsaEcdhMacVerifyMac(
        [Description("Path to the file holding the MAC key K (hex).")] string macKeyFile,
        [Description("The MAC, 32 bytes as hex.")] string mac,
        [Description("The message as hex; empty for an empty message.")] string message = "")
    {
        if(!CliFiles.TryRead(macKeyFile, "MAC key", out string macKey, out string failure))
        {
            return $"Error: {failure}";
        }

        return SecdsaOperations.EcdhMacVerifyMac(macKey.Trim(), message, mac).ToReport();
    }


    [McpServerTool(Name = McpToolNames.SecdsaResultProve), Description("Signature-result conformity, prover side: proves that a signature result is consistent with the user key and returns the record (R, G'', Q_U'', proof) as hex, or an error message.")]
    public static string SecdsaResultProve(
        [Description("The user public key Q_U, 33 bytes as hex.")] string publicKey,
        [Description("The message hash, 32 bytes as hex.")] string messageHash,
        [Description("The signature r || s, 64 bytes as hex.")] string signature)
    {
        return Produced(() => SecdsaProofOperations.ResultProve(publicKey, messageHash, signature));
    }


    [McpServerTool(Name = McpToolNames.SecdsaResultCheck), Description("Signature-result conformity, verifier side: checks the proof and the nonce-point equation of a record and returns a one-line report; any alarm is reported as a rejection.")]
    public static string SecdsaResultCheck(
        [Description("The user public key Q_U, 33 bytes as hex.")] string publicKey,
        [Description("The message hash, 32 bytes as hex.")] string messageHash,
        [Description("The record produced by SecdsaResultProve, as hex.")] string record)
    {
        return SecdsaProofOperations.ResultCheck(publicKey, messageHash, record).ToReport();
    }


    [McpServerTool(Name = McpToolNames.SecdsaEciesEncrypt), Description("ECIES encryption (X9.63 over SHA-256, AES-256-GCM, 96-bit IV, 128-bit tag) towards a recipient public key; returns the ciphertext E || T || C as hex. The plaintext is read from a file and never passes through the conversation.")]
    public static string SecdsaEciesEncrypt(
        [Description("The recipient public key, 33 bytes as hex.")] string recipientPublicKey,
        [Description("Path to the file holding the plaintext (hex).")] string plaintextFile,
        [Description("The additional authenticated data as hex; empty for none.")] string associatedData = "")
    {
        return WithSecrets([plaintextFile], secrets => SecdsaProofOperations.EciesEncrypt(recipientPublicKey, secrets[0], associatedData));
    }


    [McpServerTool(Name = McpToolNames.SecdsaEciesDecrypt), Description("ECIES decryption with the private key in this process. The key is read from a file; the plaintext is written to the named file, which must not exist, only if the tag verifies, and is never returned.")]
    public static string SecdsaEciesDecrypt(
        [Description("Path to the file holding the recipient private scalar (hex).")] string privateKeyFile,
        [Description("The ciphertext E || T || C as hex.")] string ciphertext,
        [Description("Path the plaintext (hex) is written to; the file must not exist.")] string outputFile,
        [Description("The additional authenticated data as hex; empty for none.")] string associatedData = "")
    {
        return WithSecretsToFile([privateKeyFile], outputFile, "plaintext file", secrets => SecdsaProofOperations.EciesDecrypt(secrets[0], ciphertext, associatedData));
    }


    [McpServerTool(Name = McpToolNames.SecdsaEciesPrepareDecryption), Description("ECIES decryption, prepare phase: validates the ephemeral public key E of a ciphertext (not infinity, on the curve, canonical) and returns it (hex) to send to the key holder's ECDH, or an error message.")]
    public static string SecdsaEciesPrepareDecryption(
        [Description("The ciphertext E || T || C as hex.")] string ciphertext)
    {
        return Produced(() => SecdsaProofOperations.EciesPrepareDecryption(ciphertext));
    }


    [McpServerTool(Name = McpToolNames.SecdsaEciesAgree), Description("The key holder's raw agreement in software: computes Z_AB = x(d*E). The private scalar is read from a file; the shared secret is written to the named file, which must not exist, and is never returned.")]
    public static string SecdsaEciesAgree(
        [Description("Path to the file holding the private scalar (hex).")] string privateKeyFile,
        [Description("The compressed point to agree with, such as the ephemeral public key, as hex.")] string point,
        [Description("Path the shared secret (hex) is written to; the file must not exist.")] string outputFile)
    {
        return WithSecretsToFile([privateKeyFile], outputFile, "shared secret file", secrets => SecdsaProofOperations.EciesAgree(secrets[0], point));
    }


    [McpServerTool(Name = McpToolNames.SecdsaEciesCompleteDecryption), Description("ECIES decryption, complete phase: derives the key from the key holder's shared secret and writes the plaintext to the named file, which must not exist, only if the tag verifies; it is never returned. The shared secret is read from a file.")]
    public static string SecdsaEciesCompleteDecryption(
        [Description("Path to the file holding the shared secret Z_AB (hex, 32 bytes).")] string sharedSecretFile,
        [Description("The ciphertext E || T || C as hex.")] string ciphertext,
        [Description("Path the plaintext (hex) is written to; the file must not exist.")] string outputFile,
        [Description("The additional authenticated data as hex; empty for none.")] string associatedData = "")
    {
        return WithSecretsToFile([sharedSecretFile], outputFile, "plaintext file", secrets => SecdsaProofOperations.EciesCompleteDecryption(secrets[0], ciphertext, associatedData));
    }


    [McpServerTool(Name = McpToolNames.SecdsaProofChallenge), Description("Transferable proof, challenge generation (Algorithm 22): returns a JSON object with the signed challenge and the ECIES ciphertext (hex). The signing key and the optional additional secret data are read from files and never pass through the conversation.")]
    public static string SecdsaProofChallenge(
        [Description("Path to the file holding the challenger's signing scalar (hex).")] string signingKeyFile,
        [Description("The concatenated compressed generators G_0..G_n as hex.")] string generators,
        [Description("The concatenated compressed public keys D_0..D_n as hex, pairwise with the generators.")] string publicKeys,
        [Description("The additional authenticated data as hex; empty for none.")] string associatedData = "",
        [Description("Path to the file holding the additional secret data (hex); empty for none.")] string additionalSecretDataFile = "")
    {
        string secretData = string.Empty;
        if(additionalSecretDataFile.Length > 0)
        {
            if(!CliFiles.TryRead(additionalSecretDataFile, "additional secret data", out string content, out string failure))
            {
                return $"Error: {failure}";
            }

            secretData = content.Trim();
        }

        return WithSecrets([signingKeyFile], secrets => SecdsaProofOperations.ProofChallenge(secrets[0], generators, publicKeys, associatedData, secretData));
    }


    [McpServerTool(Name = McpToolNames.SecdsaProofRespondPrepare), Description("Transferable proof, response prepare phase (Algorithm 23 steps 1 to 4): verifies the challenge for the statement and returns the validated ephemeral public key E (hex) to send to the key holder's ECDH, or an error message.")]
    public static string SecdsaProofRespondPrepare(
        [Description("The challenge as hex.")] string challenge,
        [Description("The concatenated compressed generators as hex.")] string generators,
        [Description("The concatenated compressed public keys as hex.")] string publicKeys,
        [Description("The challenger's public key S, 33 bytes as hex.")] string challengerPublicKey,
        [Description("The additional authenticated data the prover expects, as hex; empty for none.")] string associatedData = "")
    {
        return Produced(() => SecdsaProofOperations.ProofRespondPrepare(challenge, generators, publicKeys, associatedData, challengerPublicKey));
    }


    [McpServerTool(Name = McpToolNames.SecdsaProofRespondComplete), Description("Transferable proof, response complete phase (Algorithm 23 steps 4 and 6 to 15): verifies the challenge signature, decrypts the seed with the key holder's shared secret, repeats the decryption under the key from the public keys (step 11) and returns the signed response (hex); the additional secret data is written to the named file, which must not exist. The shared secret and the signing key are read from files. Any failed check returns an error and no response.")]
    public static string SecdsaProofRespondComplete(
        [Description("Path to the file holding the shared secret Z_AB (hex, 32 bytes).")] string sharedSecretFile,
        [Description("The challenge as hex.")] string challenge,
        [Description("The ECIES ciphertext E || T || C as hex.")] string ciphertext,
        [Description("The concatenated compressed generators as hex.")] string generators,
        [Description("The concatenated compressed public keys as hex.")] string publicKeys,
        [Description("Path to the file holding the prover's record signing scalar (hex).")] string signingKeyFile,
        [Description("The challenger's public key S, 33 bytes as hex, under which the challenge signature is verified.")] string challengerPublicKey,
        [Description("Path the recovered additional secret data (hex) is written to; the file must not exist; empty to discard it.")] string additionalSecretDataOutputFile = "",
        [Description("The additional authenticated data the prover expects, as hex; empty for none.")] string associatedData = "")
    {
        if(!CliFiles.TryRead(sharedSecretFile, "shared secret", out string sharedSecret, out string readFailure)
            || !CliFiles.TryRead(signingKeyFile, "signing key", out string signingKey, out readFailure))
        {
            return $"Error: {readFailure}";
        }

        ProofResponseResult result;
        try
        {
            result = SecdsaProofOperations.ProofRespondComplete(sharedSecret.Trim(), challenge, ciphertext, generators, publicKeys, associatedData, signingKey.Trim(), challengerPublicKey);
        }
        catch(ArgumentException error)
        {
            return $"Error: {error.Message}";
        }

        if(additionalSecretDataOutputFile.Length > 0
            && !CliFiles.TryWriteSecret(additionalSecretDataOutputFile, result.AdditionalSecretData, "additional secret data file", out string writeFailure))
        {
            return $"Error: {writeFailure}";
        }

        return result.Response;
    }


    [McpServerTool(Name = McpToolNames.SecdsaProofVerify), Description("Transferable proof, verification by a third party (Algorithm 24): checks the profile, the statement, both signatures and H2 = H(H1), and returns a one-line report, or the reason the proof is rejected.")]
    public static string SecdsaProofVerify(
        [Description("The challenge as hex.")] string challenge,
        [Description("The response as hex.")] string response,
        [Description("The concatenated compressed generators as hex.")] string generators,
        [Description("The concatenated compressed public keys as hex.")] string publicKeys,
        [Description("The challenger's public key S, 33 bytes as hex.")] string challengerPublicKey,
        [Description("The prover's record public key V, 33 bytes as hex.")] string proverPublicKey,
        [Description("The additional authenticated data as hex; empty for none.")] string associatedData = "")
    {
        return SecdsaProofOperations.ProofVerify(challenge, response, generators, publicKeys, associatedData, challengerPublicKey, proverPublicKey).ToReport();
    }


    //Reads each secret file, runs the operation, and writes its result to a new file that must not exist,
    //returning a confirmation, or the error message; the result is never returned.
    private static string WithSecretsToFile(string[] files, string outputFile, string what, Func<string[], string> operation)
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

        string result;
        try
        {
            result = operation(secrets);
        }
        catch(ArgumentException error)
        {
            return $"Error: {error.Message}";
        }

        if(!CliFiles.TryWriteSecret(outputFile, result, what, out string writeFailure))
        {
            return $"Error: {writeFailure}";
        }

        return $"Wrote the {what} to {outputFile}.";
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


    [McpServerTool(Name = McpToolNames.AnalysisBaseFoldLeakage), Description("Run the BaseFold leakage experiments (byte statistics, classifier, commitment recoverability) against the plain or the hiding commitment provider and return one report line per experiment. A finding is a result, not an error.")]
    public static string AnalysisBaseFoldLeakage(
        [Description("The number of committed-polynomial variables.")] int variables = AnalysisOperations.DefaultVariableCount,
        [Description("The number of samples each experiment draws.")] int samples = AnalysisOperations.DefaultSampleCount,
        [Description("The significance level, strictly between 0 and 1.")] double significance = AnalysisOperations.DefaultSignificanceLevel,
        [Description("Run against the hiding (salted) commitment provider instead of the plain one.")] bool hiding = false)
    {
        try
        {
            return AnalysisOperations.BaseFoldLeakage(variables, samples, significance, hiding, BaseMemoryPool.Shared);
        }
        catch(ArgumentException error)
        {
            return $"Error: {error.Message}";
        }
    }


    [McpServerTool(Name = McpToolNames.AnalysisWelchT), Description("Run Welch's two-sample t-test over two sample sets and return a report line with the statistic, degrees of freedom and p-value.")]
    public static string AnalysisWelchT(
        [Description("The first sample set, one number per line.")] string first,
        [Description("The second sample set, one number per line.")] string second,
        [Description("The significance level, strictly between 0 and 1.")] double significance = AnalysisOperations.DefaultSignificanceLevel)
    {
        try
        {
            return AnalysisOperations.WelchT(first, second, significance);
        }
        catch(ArgumentException error)
        {
            return $"Error: {error.Message}";
        }
    }


    [McpServerTool(Name = McpToolNames.AnalysisKolmogorovSmirnov), Description("Run the two-sample Kolmogorov-Smirnov test over two sample sets and return a report line with the statistic and p-value.")]
    public static string AnalysisKolmogorovSmirnov(
        [Description("The first sample set, one number per line.")] string first,
        [Description("The second sample set, one number per line.")] string second,
        [Description("The significance level, strictly between 0 and 1.")] double significance = AnalysisOperations.DefaultSignificanceLevel)
    {
        try
        {
            return AnalysisOperations.KolmogorovSmirnov(first, second, significance);
        }
        catch(ArgumentException error)
        {
            return $"Error: {error.Message}";
        }
    }


    [McpServerTool(Name = McpToolNames.AnalysisChiSquared), Description("Run the chi-squared homogeneity test of two observed count sets, or with expected set the goodness-of-fit test of observed against expected counts, and return a report line.")]
    public static string AnalysisChiSquared(
        [Description("The observed counts, one integer per line.")] string observed,
        [Description("A second observed count set (homogeneity), or with expected the expected counts (goodness of fit), one number per line.")] string comparison,
        [Description("Treat the comparison as expected counts and test goodness of fit.")] bool expected = false,
        [Description("The significance level, strictly between 0 and 1.")] double significance = AnalysisOperations.DefaultSignificanceLevel)
    {
        try
        {
            return AnalysisOperations.ChiSquared(observed, comparison, expected, significance);
        }
        catch(ArgumentException error)
        {
            return $"Error: {error.Message}";
        }
    }
}
