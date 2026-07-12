using Lumoin.Veridical.Backends.Managed;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Lumoin.Veridical.Tests.Cryptography.Wycheproof;

/// <summary>
/// Loads and parses the vendored C2SP/wycheproof ECDSA secp256r1 fixture files into
/// flat vector lists ready for the harness tests. Each group's raw affine public key
/// (wx, wy) is parsed, on-curve-checked against the P-256 reference, and compressed
/// to the 33-byte SEC1 form the library's verifiers accept. Provenance and SHA-256
/// integrity pins are recorded in <c>Cryptography/Wycheproof/Fixtures/FIXTURES.md</c>.
/// </summary>
internal static class WycheproofEcdsaFixtures
{
    //Sub-path inside AppContext.BaseDirectory (and as a repo-relative fallback).
    private const string FixtureSubdirectory = "Cryptography/Wycheproof/Fixtures";

    //P-256 coordinate is 256 bits = 32 bytes.
    private const int CoordinateSizeBytes = 32;

    //SEC1 compressed point: one parity-prefix byte plus the 32-byte x-coordinate.
    private const int CompressedKeySizeBytes = 33;

    //SHA-256 output is 256 bits = 32 bytes.
    private const int Sha256SizeBytes = 32;


    /// <summary>File name of the IEEE P1363 (raw r‖s) fixture.</summary>
    public const string P1363FileName = "ecdsa_secp256r1_sha256_p1363_test.json";

    /// <summary>File name of the ASN.1/DER fixture.</summary>
    public const string Asn1FileName = "ecdsa_secp256r1_sha256_test.json";


    /// <summary>
    /// Loads the P1363 fixture file. Returns <see langword="null"/> when the file is absent so
    /// callers can call <see cref="Microsoft.VisualStudio.TestTools.UnitTesting.Assert.Inconclusive"/>.
    /// </summary>
    public static WycheproofFileResult? TryLoadP1363() => TryLoad(P1363FileName);


    /// <summary>
    /// Loads the ASN.1/DER fixture file. Returns <see langword="null"/> when the file is absent.
    /// </summary>
    public static WycheproofFileResult? TryLoadAsn1() => TryLoad(Asn1FileName);


    /// <summary>
    /// Computes the lower-hex SHA-256 of the named fixture file, or an empty string when the
    /// file cannot be found. Used by the fixture-integrity test.
    /// </summary>
    public static string ComputeFileSha256Hex(string fileName)
    {
        string? path = ResolvePath(fileName);
        if(path is null)
        {
            return string.Empty;
        }

        byte[] fileBytes = File.ReadAllBytes(path);
        Span<byte> hash = stackalloc byte[Sha256SizeBytes];
        SHA256.HashData(fileBytes, hash);

        return Convert.ToHexStringLower(hash);
    }


    private static WycheproofFileResult? TryLoad(string fileName)
    {
        string? path = ResolvePath(fileName);
        if(path is null)
        {
            return null;
        }

        string json = File.ReadAllText(path);
        JsonRoot root = JsonSerializer.Deserialize<JsonRoot>(json, JsonOptions)
            ?? throw new InvalidOperationException($"Deserializing {fileName} produced null.");

        var vectors = new List<WycheproofVector>(root.NumberOfTests);
        foreach(JsonGroup group in root.TestGroups)
        {
            byte[] compressedKey = ParseCompressedKey(group.PublicKey);
            foreach(JsonTestCase tc in group.Tests)
            {
                vectors.Add(new WycheproofVector(
                    tc.TcId,
                    tc.Comment,
                    tc.Flags,
                    Convert.FromHexString(tc.Msg),
                    Convert.FromHexString(tc.Sig),
                    tc.Result == "valid",
                    compressedKey));
            }
        }

        return new WycheproofFileResult(root.NumberOfTests, vectors);
    }


    private static string? ResolvePath(string fileName)
    {
        string primary = Path.Combine(AppContext.BaseDirectory, FixtureSubdirectory, fileName);
        if(File.Exists(primary))
        {
            return primary;
        }

        //Fall back to repo-relative when the test host does not copy
        //AppContext.BaseDirectory's parallel folders (some MTP configs).
        string fallback = Path.Combine(FixtureSubdirectory, fileName);
        if(File.Exists(fallback))
        {
            return fallback;
        }

        return null;
    }


    private static byte[] ParseCompressedKey(JsonPublicKey key)
    {
        //Prepend "0" so that a leading 0xFF high nibble is not parsed as negative.
        BigInteger xBig = BigInteger.Parse("0" + key.Wx, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        BigInteger yBig = BigInteger.Parse("0" + key.Wy, NumberStyles.HexNumber, CultureInfo.InvariantCulture);

        Span<byte> x32 = stackalloc byte[CoordinateSizeBytes];
        Span<byte> y32 = stackalloc byte[CoordinateSizeBytes];
        x32.Clear();
        y32.Clear();

        if(!xBig.TryWriteBytes(x32, out int xWritten, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException(
                $"Public key wx does not fit {CoordinateSizeBytes} bytes (wx = {key.Wx}).");
        }

        if(!yBig.TryWriteBytes(y32, out int yWritten, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException(
                $"Public key wy does not fit {CoordinateSizeBytes} bytes (wy = {key.Wy}).");
        }

        //TryWriteBytes (big-endian) writes MSB-first at index 0 and returns the
        //number of bytes written. When the value is small, shift right to left-pad.
        if(xWritten < CoordinateSizeBytes)
        {
            int shift = CoordinateSizeBytes - xWritten;
            x32[..xWritten].CopyTo(x32[shift..]);
            x32[..shift].Clear();
        }

        if(yWritten < CoordinateSizeBytes)
        {
            int shift = CoordinateSizeBytes - yWritten;
            y32[..yWritten].CopyTo(y32[shift..]);
            y32[..shift].Clear();
        }

        //SEC1 compression silently repairs an off-curve y (it re-derives y from x);
        //checking the raw affine pair here catches fixture-drift before compression
        //could mask it.
        var point = new P256BigIntegerG1Reference.AffinePoint(xBig, yBig, IsInfinity: false);
        if(!P256BigIntegerG1Reference.IsOnCurve(point))
        {
            throw new InvalidOperationException(
                $"Public key (wx = {key.Wx}, wy = {key.Wy}) is not on the P-256 curve.");
        }

        //SEC1 §2.3.3: 0x02 prefix if y is even, 0x03 if odd; then x big-endian.
        byte[] compressedKey = new byte[CompressedKeySizeBytes];
        compressedKey[0] = (byte)(0x02 | (y32[^1] & 0x01));
        x32.CopyTo(compressedKey.AsSpan(1));

        return compressedKey;
    }


    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };


    private sealed record JsonRoot(
        [property: JsonPropertyName("numberOfTests")] int NumberOfTests,
        [property: JsonPropertyName("testGroups")] JsonGroup[] TestGroups);


    private sealed record JsonGroup(
        [property: JsonPropertyName("publicKey")] JsonPublicKey PublicKey,
        [property: JsonPropertyName("tests")] JsonTestCase[] Tests);


    private sealed record JsonPublicKey(
        [property: JsonPropertyName("wx")] string Wx,
        [property: JsonPropertyName("wy")] string Wy);


    private sealed record JsonTestCase(
        [property: JsonPropertyName("tcId")] int TcId,
        [property: JsonPropertyName("comment")] string Comment,
        [property: JsonPropertyName("flags")] string[] Flags,
        [property: JsonPropertyName("msg")] string Msg,
        [property: JsonPropertyName("sig")] string Sig,
        [property: JsonPropertyName("result")] string Result);
}
