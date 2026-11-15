using Lumoin.Base;
using Lumoin.Veridical.Longfellow;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Lumoin.Veridical.Cli;

/// <summary>
/// The Longfellow JWT operations behind the <c>longfellow-jwt-prove</c> and <c>longfellow-jwt-verify</c>
/// subcommands and their MCP tools. The proof travels as lowercase hex text; the statement is the issuer
/// public key, the disclosed attributes, the block capacity and the session seed, all public. The
/// presentation token is the prover's private witness and is only ever read from a file, standard input or
/// an MCP argument, never echoed.
/// </summary>
internal static class LongfellowJwtOperations
{
    /// <summary>The block capacity selected when the caller names none.</summary>
    public const int DefaultBlockCapacity = 7;

    private const int SevenBlocks = 7;

    private const int NineBlocks = 9;

    //The separator between a presentation token's issuer JWS and its key-binding JWS.
    private const char PresentationSeparator = '~';

    //The separator between an attribute identifier and its value.
    private const char AttributeSeparator = '=';

    private const string HexPrefix = "0x";

    private const int HexCharactersPerByte = 2;


    /// <summary>
    /// Proves a presentation token against the statement and returns the proof as lowercase hex.
    /// </summary>
    /// <param name="token">The <c>issuerJws~keyBindingJws</c> presentation token (the private witness).</param>
    /// <param name="issuerKeyX">The issuer public key x coordinate as hex.</param>
    /// <param name="issuerKeyY">The issuer public key y coordinate as hex.</param>
    /// <param name="attributes">The disclosed attributes, each as <c>id=value</c>.</param>
    /// <param name="blockCapacity">The block capacity, 7 or 9.</param>
    /// <param name="seed">The session seed text both parties use.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The proof as lowercase hex.</returns>
    /// <exception cref="ArgumentException">The inputs do not describe a provable statement.</exception>
    public static string Prove(
        string token,
        string issuerKeyX,
        string issuerKeyY,
        IReadOnlyList<string> attributes,
        int blockCapacity,
        string seed,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(pool);

        LongfellowJwtStatement statement = BuildStatement(issuerKeyX, issuerKeyY, attributes, blockCapacity);
        byte[] seedBytes = Encoding.UTF8.GetBytes(RequireSeed(seed));
        ReadOnlySpan<char> tokenText = token.AsSpan().Trim();
        int tokenLength = Encoding.ASCII.GetByteCount(tokenText);
        using IMemoryOwner<byte> tokenOwner = pool.Rent(Math.Max(tokenLength, 1));
        Span<byte> tokenBytes = tokenOwner.Memory.Span[..tokenLength];
        try
        {
            Encoding.ASCII.GetBytes(tokenText, tokenBytes);
            using LongfellowJwtProof proof = LongfellowJwt.Prove(
                tokenBytes, statement, seedBytes, pool, LongfellowPlatformComposition.JwtSuite, LongfellowPlatformComposition.NewProverRandomness());

            return Convert.ToHexStringLower(proof.AsReadOnlySpan());
        }
        finally
        {
            tokenBytes.Clear();
        }
    }


    /// <summary>
    /// Verifies a hex proof against the statement and the key-binding JWS of the presentation.
    /// </summary>
    /// <param name="proofHex">The proof as hex.</param>
    /// <param name="presentation">The presentation token, or just its key-binding JWS.</param>
    /// <param name="issuerKeyX">The issuer public key x coordinate as hex.</param>
    /// <param name="issuerKeyY">The issuer public key y coordinate as hex.</param>
    /// <param name="attributes">The disclosed attributes, each as <c>id=value</c>.</param>
    /// <param name="blockCapacity">The block capacity, 7 or 9.</param>
    /// <param name="seed">The session seed text both parties used.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The verification outcome.</returns>
    public static VerificationResult Verify(
        string proofHex,
        string presentation,
        string issuerKeyX,
        string issuerKeyY,
        IReadOnlyList<string> attributes,
        int blockCapacity,
        string seed,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(proofHex);
        ArgumentNullException.ThrowIfNull(presentation);
        ArgumentNullException.ThrowIfNull(pool);

        LongfellowJwtStatement statement;
        byte[] seedBytes;
        try
        {
            statement = BuildStatement(issuerKeyX, issuerKeyY, attributes, blockCapacity);
            seedBytes = Encoding.UTF8.GetBytes(RequireSeed(seed));
        }
        catch(ArgumentException error)
        {
            return VerificationResult.Malformed(error.Message);
        }

        ReadOnlySpan<char> proofText = proofHex.AsSpan().Trim();
        if(proofText.Length % HexCharactersPerByte != 0)
        {
            return VerificationResult.Malformed("the proof is not an even-length hex string.");
        }

        int proofLength = proofText.Length / HexCharactersPerByte;
        using IMemoryOwner<byte> proofOwner = pool.Rent(Math.Max(proofLength, 1));
        Span<byte> proofBytes = proofOwner.Memory.Span[..proofLength];
        if(Convert.FromHexString(proofText, proofBytes, out _, out int written) != OperationStatus.Done || written != proofLength)
        {
            return VerificationResult.Malformed("the proof is not a valid hex string (0-9a-f).");
        }

        if(proofLength < LongfellowJwtProof.MinimumSizeBytes)
        {
            return VerificationResult.Malformed($"the proof is shorter than the {LongfellowJwtProof.MinimumSizeBytes}-byte minimum.");
        }

        ReadOnlySpan<char> presentationText = presentation.AsSpan().Trim();
        int separator = presentationText.LastIndexOf(PresentationSeparator);
        ReadOnlySpan<char> keyBindingText = separator < 0 ? presentationText : presentationText[(separator + 1)..];
        int keyBindingLength = Encoding.ASCII.GetByteCount(keyBindingText);
        using IMemoryOwner<byte> keyBindingOwner = pool.Rent(Math.Max(keyBindingLength, 1));
        Span<byte> keyBinding = keyBindingOwner.Memory.Span[..keyBindingLength];
        Encoding.ASCII.GetBytes(keyBindingText, keyBinding);

        using LongfellowJwtProof proof = LongfellowJwtProof.FromCanonical(proofBytes, pool);
        LongfellowJwtVerdict verdict = LongfellowJwt.Verify(
            proof, keyBinding, statement, seedBytes, pool, LongfellowPlatformComposition.JwtSuite);
        string description = Describe(statement);

        return verdict switch
        {
            LongfellowJwtVerdict.Accepted => VerificationResult.Valid(description),
            LongfellowJwtVerdict.Rejected => VerificationResult.Rejected(description),
            LongfellowJwtVerdict.MalformedKeyBinding => VerificationResult.Malformed("the key-binding JWS is not a well-formed compact JWS with a fixed-width signature."),
            _ => VerificationResult.Malformed("the proof envelope cannot be parsed for this statement.")
        };
    }


    /// <summary>Splits a newline-separated attribute list (the MCP form) into its entries.</summary>
    /// <param name="attributes">The attribute lines, each <c>id=value</c>.</param>
    /// <returns>The non-empty entries.</returns>
    public static IReadOnlyList<string> SplitAttributeLines(string attributes)
    {
        ArgumentNullException.ThrowIfNull(attributes);

        return attributes.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }


    private static LongfellowJwtStatement BuildStatement(string issuerKeyX, string issuerKeyY, IReadOnlyList<string> attributes, int blockCapacity)
    {
        ArgumentNullException.ThrowIfNull(issuerKeyX);
        ArgumentNullException.ThrowIfNull(issuerKeyY);
        ArgumentNullException.ThrowIfNull(attributes);

        LongfellowJwtZkSpec spec = blockCapacity switch
        {
            SevenBlocks => LongfellowJwtZkSpec.SevenBlocks,
            NineBlocks => LongfellowJwtZkSpec.NineBlocks,
            _ => throw new ArgumentException($"The block capacity is 7 or 9; received {blockCapacity.ToString(CultureInfo.InvariantCulture)}.", nameof(blockCapacity))
        };

        var parsed = new List<LongfellowJwtAttribute>(attributes.Count);
        foreach(string entry in attributes)
        {
            int separator = entry.IndexOf(AttributeSeparator, StringComparison.Ordinal);
            if(separator <= 0)
            {
                throw new ArgumentException($"An attribute is written id=value; received '{entry}'.", nameof(attributes));
            }

            parsed.Add(LongfellowJwtAttribute.FromStrings(entry[..separator], entry[(separator + 1)..]));
        }

        return LongfellowJwtStatement.Create(ParseCoordinate(issuerKeyX, nameof(issuerKeyX)), ParseCoordinate(issuerKeyY, nameof(issuerKeyY)), parsed, spec);
    }


    private static byte[] ParseCoordinate(string hex, string name)
    {
        string trimmed = hex.Trim();
        if(trimmed.StartsWith(HexPrefix, StringComparison.OrdinalIgnoreCase))
        {
            trimmed = trimmed[HexPrefix.Length..];
        }

        try
        {
            return Convert.FromHexString(trimmed);
        }
        catch(FormatException)
        {
            throw new ArgumentException("The issuer key coordinate is not a valid hex string.", name);
        }
    }


    private static string RequireSeed(string seed)
    {
        ArgumentNullException.ThrowIfNull(seed);
        if(seed.Length == 0)
        {
            throw new ArgumentException("The session seed must not be empty.", nameof(seed));
        }

        return seed;
    }


    private static string Describe(LongfellowJwtStatement statement)
    {
        var builder = new StringBuilder();
        for(int i = 0; i < statement.Attributes.Count; i++)
        {
            if(i > 0)
            {
                builder.Append("; ");
            }

            builder.Append(Encoding.UTF8.GetString(statement.Attributes[i].Id.Span)).Append(" = ").Append(Encoding.UTF8.GetString(statement.Attributes[i].Value.Span));
        }

        builder.Append(" (issuer key x ").Append(Convert.ToHexStringLower(statement.IssuerKeyX.Span)).Append(')');

        return builder.ToString();
    }
}
