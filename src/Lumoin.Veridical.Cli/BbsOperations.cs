using Lumoin.Base;
using Lumoin.Veridical.Bbs;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Lumoin.Veridical.Cli;

/// <summary>
/// The BBS operations behind the <c>bbs-*</c> subcommands and their MCP tools: key generation, signing,
/// signature verification, proof generation with selective disclosure, and proof verification. Keys,
/// signatures and proofs travel as lowercase hex; messages are UTF-8 text lines, or hex lines when the
/// caller says so. The secret key is returned only to the caller that writes it to a file and is never
/// echoed.
/// </summary>
internal static class BbsOperations
{
    /// <summary>The key-material length drawn from the operating system random generator.</summary>
    public const int KeyMaterialBytes = 32;

    //The separator between a disclosed message's index and its text.
    private const char DisclosedSeparator = '=';

    private const string IndexSeparator = ",";


    /// <summary>
    /// Generates a key pair from fresh operating system randomness, or from caller-supplied key material.
    /// </summary>
    /// <param name="suite">The ciphersuite name, <c>sha256</c> or <c>shake256</c>.</param>
    /// <param name="keyMaterialHex">The key material as hex (at least 32 bytes), or <see langword="null"/> to draw it from the operating system.</param>
    /// <param name="keyInfo">The key-info text bound into the derivation.</param>
    /// <returns>The secret key and the public key, each as lowercase hex.</returns>
    /// <exception cref="ArgumentException">The ciphersuite, the key material or the key info is invalid.</exception>
    public static (string SecretKeyHex, string PublicKeyHex) GenerateKey(string suite, string? keyMaterialHex, string keyInfo)
    {
        ArgumentNullException.ThrowIfNull(keyInfo);

        using BbsPlatformComposition composition = BbsPlatformComposition.Create(suite);
        BaseMemoryPool pool = BbsPlatformComposition.Pool;
        int materialLength = keyMaterialHex is null ? KeyMaterialBytes : keyMaterialHex.Trim().Length / 2;
        using IMemoryOwner<byte> materialOwner = pool.Rent(Math.Max(materialLength, 1));
        Span<byte> material = materialOwner.Memory.Span[..materialLength];
        try
        {
            if(keyMaterialHex is null)
            {
                RandomNumberGenerator.Fill(material);
            }
            else
            {
                DecodeHex(keyMaterialHex, material, "key material");
            }

            using BbsKeyPair pair = composition.Ciphersuite.Generate(
                material, Encoding.UTF8.GetBytes(keyInfo), composition.HashToScalar, composition.G2ScalarMultiply, pool);

            return (Convert.ToHexStringLower(pair.SecretKey.AsReadOnlySpan()), Convert.ToHexStringLower(pair.PublicKey.AsReadOnlySpan()));
        }
        finally
        {
            material.Clear();
        }
    }


    /// <summary>Signs the messages and returns the signature as lowercase hex.</summary>
    /// <param name="suite">The ciphersuite name.</param>
    /// <param name="secretKeyHex">The secret key as hex.</param>
    /// <param name="publicKeyHex">The public key as hex.</param>
    /// <param name="header">The header text.</param>
    /// <param name="messages">The messages, one per entry.</param>
    /// <param name="hexMessages">Whether each message is hex instead of text.</param>
    /// <returns>The signature as lowercase hex.</returns>
    /// <exception cref="ArgumentException">An input is invalid.</exception>
    public static string Sign(string suite, string secretKeyHex, string publicKeyHex, string header, IReadOnlyList<string> messages, bool hexMessages)
    {
        ArgumentNullException.ThrowIfNull(secretKeyHex);
        ArgumentNullException.ThrowIfNull(header);

        using BbsPlatformComposition composition = BbsPlatformComposition.Create(suite);
        BaseMemoryPool pool = BbsPlatformComposition.Pool;
        BbsMessage[] decoded = DecodeMessages(messages, hexMessages);
        using BbsPublicKey publicKey = ReadPublicKey(publicKeyHex, composition, pool);
        using BbsSecretKey secretKey = ReadSecretKey(secretKeyHex, composition, pool);
        using BbsSignature signature = secretKey.Sign(
            publicKey,
            new BbsHeader(Encoding.UTF8.GetBytes(header)),
            decoded,
            composition.ExpandMessage,
            composition.HashToScalar,
            composition.ScalarAdd,
            composition.ScalarInvert,
            composition.G1Add,
            composition.G1ScalarMultiply,
            composition.G1MultiScalarMultiply,
            composition.G1HashToCurve,
            pool);

        return Convert.ToHexStringLower(signature.AsReadOnlySpan());
    }


    /// <summary>Verifies a signature over the messages.</summary>
    /// <param name="suite">The ciphersuite name.</param>
    /// <param name="publicKeyHex">The public key as hex.</param>
    /// <param name="signatureHex">The signature as hex.</param>
    /// <param name="header">The header text.</param>
    /// <param name="messages">The messages, one per entry.</param>
    /// <param name="hexMessages">Whether each message is hex instead of text.</param>
    /// <returns>The verification outcome.</returns>
    public static VerificationResult Verify(string suite, string publicKeyHex, string signatureHex, string header, IReadOnlyList<string> messages, bool hexMessages)
    {
        ArgumentNullException.ThrowIfNull(signatureHex);
        ArgumentNullException.ThrowIfNull(header);

        try
        {
            using BbsPlatformComposition composition = BbsPlatformComposition.Create(suite);
            BaseMemoryPool pool = BbsPlatformComposition.Pool;
            BbsMessage[] decoded = DecodeMessages(messages, hexMessages);
            using BbsPublicKey publicKey = ReadPublicKey(publicKeyHex, composition, pool);
            using BbsSignature signature = ReadSignature(signatureHex, composition, pool);
            string statement = string.Create(CultureInfo.InvariantCulture, $"a BBS signature over {decoded.Length} message(s)");
            bool valid = publicKey.Verify(
                signature,
                new BbsHeader(Encoding.UTF8.GetBytes(header)),
                decoded,
                composition.ExpandMessage,
                composition.HashToScalar,
                composition.G1Add,
                composition.G1MultiScalarMultiply,
                composition.G1HashToCurve,
                composition.G1IsOnCurve,
                composition.G1IsInPrimeOrderSubgroup,
                composition.G2Add,
                composition.G2ScalarMultiply,
                composition.G2IsOnCurve,
                composition.G2IsInPrimeOrderSubgroup,
                composition.Pairing,
                pool);

            return valid ? VerificationResult.Valid(statement) : VerificationResult.Rejected(statement);
        }
        catch(ArgumentException error)
        {
            return VerificationResult.Malformed(error.Message);
        }
    }


    /// <summary>Generates a selective-disclosure proof from a signature.</summary>
    /// <param name="suite">The ciphersuite name.</param>
    /// <param name="publicKeyHex">The public key as hex.</param>
    /// <param name="signatureHex">The signature as hex.</param>
    /// <param name="header">The header text.</param>
    /// <param name="presentationHeader">The presentation header text.</param>
    /// <param name="messages">All the signed messages, one per entry.</param>
    /// <param name="hexMessages">Whether each message is hex instead of text.</param>
    /// <param name="disclosed">The zero-based indices to disclose, comma-separated; empty discloses none.</param>
    /// <returns>The proof as lowercase hex.</returns>
    /// <exception cref="ArgumentException">An input is invalid.</exception>
    public static string GenerateProof(string suite, string publicKeyHex, string signatureHex, string header, string presentationHeader, IReadOnlyList<string> messages, bool hexMessages, string disclosed)
    {
        ArgumentNullException.ThrowIfNull(signatureHex);
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(presentationHeader);

        using BbsPlatformComposition composition = BbsPlatformComposition.Create(suite);
        BaseMemoryPool pool = BbsPlatformComposition.Pool;
        BbsMessage[] decoded = DecodeMessages(messages, hexMessages);
        int[] indices = ParseIndices(disclosed);
        using BbsPublicKey publicKey = ReadPublicKey(publicKeyHex, composition, pool);
        using BbsSignature signature = ReadSignature(signatureHex, composition, pool);
        using BbsProof proof = signature.GenerateProof(
            publicKey,
            new BbsHeader(Encoding.UTF8.GetBytes(header)),
            new BbsPresentationHeader(Encoding.UTF8.GetBytes(presentationHeader)),
            decoded,
            indices,
            composition.ExpandMessage,
            composition.HashToScalar,
            composition.ScalarAdd,
            composition.ScalarSubtract,
            composition.ScalarMultiply,
            composition.ScalarNegate,
            composition.ScalarInvert,
            composition.ScalarRandom,
            composition.G1Add,
            composition.G1ScalarMultiply,
            composition.G1MultiScalarMultiply,
            composition.G1HashToCurve,
            composition.G1IsOnCurve,
            composition.G1IsInPrimeOrderSubgroup,
            pool);

        return Convert.ToHexStringLower(proof.AsReadOnlySpan());
    }


    /// <summary>Verifies a selective-disclosure proof against the disclosed messages.</summary>
    /// <param name="suite">The ciphersuite name.</param>
    /// <param name="publicKeyHex">The public key as hex.</param>
    /// <param name="proofHex">The proof as hex.</param>
    /// <param name="header">The header text.</param>
    /// <param name="presentationHeader">The presentation header text.</param>
    /// <param name="disclosedMessages">The disclosed messages, each written <c>index=message</c> with strictly ascending zero-based indices.</param>
    /// <param name="hexMessages">Whether each message is hex instead of text.</param>
    /// <returns>The verification outcome.</returns>
    public static VerificationResult VerifyProof(string suite, string publicKeyHex, string proofHex, string header, string presentationHeader, IReadOnlyList<string> disclosedMessages, bool hexMessages)
    {
        ArgumentNullException.ThrowIfNull(proofHex);
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(presentationHeader);
        ArgumentNullException.ThrowIfNull(disclosedMessages);

        try
        {
            using BbsPlatformComposition composition = BbsPlatformComposition.Create(suite);
            BaseMemoryPool pool = BbsPlatformComposition.Pool;
            var indexList = new List<int>(disclosedMessages.Count);
            var textList = new List<string>(disclosedMessages.Count);
            foreach(string entry in disclosedMessages)
            {
                int separator = entry.IndexOf(DisclosedSeparator, StringComparison.Ordinal);
                if(separator <= 0 || !int.TryParse(entry.AsSpan(0, separator), NumberStyles.None, CultureInfo.InvariantCulture, out int index))
                {
                    throw new ArgumentException($"A disclosed message is written index=message; received '{entry}'.", nameof(disclosedMessages));
                }

                indexList.Add(index);
                textList.Add(entry[(separator + 1)..]);
            }

            BbsMessage[] decoded = DecodeMessages(textList, hexMessages);
            using BbsPublicKey publicKey = ReadPublicKey(publicKeyHex, composition, pool);
            using BbsProof proof = ReadProof(proofHex, composition, pool);
            string statement = string.Create(
                CultureInfo.InvariantCulture,
                $"a BBS proof disclosing {string.Join("; ", disclosedMessages)} ({proof.UndisclosedMessageCount} undisclosed)");
            bool valid = publicKey.VerifyProof(
                proof,
                new BbsHeader(Encoding.UTF8.GetBytes(header)),
                new BbsPresentationHeader(Encoding.UTF8.GetBytes(presentationHeader)),
                decoded,
                indexList.ToArray(),
                composition.ExpandMessage,
                composition.HashToScalar,
                composition.G1Add,
                composition.G1MultiScalarMultiply,
                composition.G1HashToCurve,
                composition.G1IsOnCurve,
                composition.G1IsInPrimeOrderSubgroup,
                composition.G2Add,
                composition.G2ScalarMultiply,
                composition.G2IsOnCurve,
                composition.G2IsInPrimeOrderSubgroup,
                composition.Pairing,
                pool);

            return valid ? VerificationResult.Valid(statement) : VerificationResult.Rejected(statement);
        }
        catch(ArgumentException error)
        {
            return VerificationResult.Malformed(error.Message);
        }
    }


    /// <summary>Splits a newline-separated list (the MCP form) into its non-empty entries.</summary>
    /// <param name="lines">The text to split.</param>
    /// <returns>The entries, trimmed of surrounding whitespace.</returns>
    public static IReadOnlyList<string> SplitLines(string lines)
    {
        ArgumentNullException.ThrowIfNull(lines);

        return lines.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }


    private static BbsMessage[] DecodeMessages(IReadOnlyList<string> messages, bool hexMessages)
    {
        ArgumentNullException.ThrowIfNull(messages);

        var decoded = new BbsMessage[messages.Count];
        for(int i = 0; i < decoded.Length; i++)
        {
            byte[] bytes;
            if(hexMessages)
            {
                try
                {
                    bytes = Convert.FromHexString(messages[i].Trim());
                }
                catch(FormatException)
                {
                    throw new ArgumentException($"Message {i.ToString(CultureInfo.InvariantCulture)} is not a valid hex string.", nameof(messages));
                }
            }
            else
            {
                bytes = Encoding.UTF8.GetBytes(messages[i]);
            }

            decoded[i] = new BbsMessage(bytes);
        }

        return decoded;
    }


    private static int[] ParseIndices(string disclosed)
    {
        ArgumentNullException.ThrowIfNull(disclosed);

        string trimmed = disclosed.Trim();
        if(trimmed.Length == 0)
        {
            return [];
        }

        string[] parts = trimmed.Split(IndexSeparator, StringSplitOptions.TrimEntries);
        var indices = new int[parts.Length];
        for(int i = 0; i < parts.Length; i++)
        {
            if(!int.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out indices[i]))
            {
                throw new ArgumentException($"A disclosed index is a non-negative integer; received '{parts[i]}'.", nameof(disclosed));
            }
        }

        return indices;
    }


    private static void DecodeHex(string hex, Span<byte> destination, string what)
    {
        string trimmed = hex.Trim();
        if(trimmed.Length != destination.Length * 2 || Convert.FromHexString(trimmed, destination, out _, out int written) != OperationStatus.Done || written != destination.Length)
        {
            throw new ArgumentException($"The {what} is not a valid hex string of {destination.Length.ToString(CultureInfo.InvariantCulture)} bytes.", nameof(hex));
        }
    }


    private static BbsSecretKey ReadSecretKey(string hex, BbsPlatformComposition composition, BaseMemoryPool pool)
    {
        Span<byte> bytes = stackalloc byte[BbsSecretKey.SizeBytes];
        try
        {
            DecodeHex(hex, bytes, "secret key");

            return BbsSecretKey.FromCanonical(bytes, composition.Ciphersuite, pool);
        }
        finally
        {
            bytes.Clear();
        }
    }


    private static BbsPublicKey ReadPublicKey(string hex, BbsPlatformComposition composition, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(hex);

        Span<byte> bytes = stackalloc byte[BbsPublicKey.SizeBytes];
        DecodeHex(hex, bytes, "public key");

        return BbsPublicKey.FromCanonical(bytes, composition.Ciphersuite, pool);
    }


    private static BbsSignature ReadSignature(string hex, BbsPlatformComposition composition, BaseMemoryPool pool)
    {
        Span<byte> bytes = stackalloc byte[BbsSignature.SizeBytes];
        DecodeHex(hex, bytes, "signature");

        return BbsSignature.FromCanonical(bytes, composition.Ciphersuite, pool);
    }


    private static BbsProof ReadProof(string hex, BbsPlatformComposition composition, BaseMemoryPool pool)
    {
        string trimmed = hex.Trim();
        int length = trimmed.Length / 2;
        using IMemoryOwner<byte> owner = pool.Rent(Math.Max(length, 1));
        Span<byte> bytes = owner.Memory.Span[..length];
        DecodeHex(trimmed, bytes, "proof");

        return BbsProof.FromCanonical(bytes, composition.Ciphersuite, pool);
    }
}
