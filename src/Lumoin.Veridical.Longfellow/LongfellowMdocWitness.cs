using System;

namespace Lumoin.Veridical.Longfellow;

/// <summary>
/// The caller-assembled witness material a dual-field mdoc prove consumes: the two field witness columns (with
/// their public MAC/key regions left zero — the prover patches them post-commit from the transcript), the
/// three common values the cross-field MACs authenticate, and the six shared MAC keys. The caller's own
/// mdoc/CBOR walk fills these; the library performs no parsing.
/// </summary>
/// <remarks>
/// This is a validated view over caller-owned buffers — the caller owns the secret material's lifetime and
/// clears it. The signature column is supplied in CANONICAL big-endian form; the facade lifts it to the
/// Montgomery working domain internally and clears its own lifted copy. The MAC wire indices are circuit-shape
/// facts and ride in the <see cref="LongfellowMdocZkSpec"/> the prove call is parameterized by, not here.
/// </remarks>
public sealed class LongfellowMdocWitness
{
    //One canonical field element per 32-byte big-endian slot, shared by every region.
    private const int ScalarSizeBytes = 32;

    //compute_macs authenticates exactly three common Fp256 values: the issuer hash and the device key x/y.
    private const int CommonValueCount = 3;

    //Six per-credential MAC values bind the hash and signature circuits together.
    private const int MacCount = 6;


    private LongfellowMdocWitness(
        ReadOnlyMemory<byte> hashColumn,
        ReadOnlyMemory<byte> signatureColumnCanonical,
        ReadOnlyMemory<byte> commonValues,
        ReadOnlyMemory<byte> apKeys)
    {
        HashColumn = hashColumn;
        SignatureColumn = signatureColumnCanonical;
        CommonValues = commonValues;
        ApKeys = apKeys;
    }


    /// <summary>The GF(2^128) hash witness column, one canonical element per 32-byte slot; its public MAC/key region is zero.</summary>
    public ReadOnlyMemory<byte> HashColumn { get; }

    /// <summary>The canonical big-endian P-256 signature witness column; its public MAC/key region is zero.</summary>
    public ReadOnlyMemory<byte> SignatureColumn { get; }

    /// <summary>The three common values the cross-field MACs authenticate, canonical big-endian.</summary>
    public ReadOnlyMemory<byte> CommonValues { get; }

    /// <summary>The six shared MAC keys, canonical big-endian.</summary>
    public ReadOnlyMemory<byte> ApKeys { get; }


    /// <summary>
    /// Validates and wraps the caller-assembled witness regions.
    /// </summary>
    /// <param name="hashColumn">The hash witness column; a non-zero multiple of 32 bytes.</param>
    /// <param name="signatureColumnCanonical">The canonical big-endian signature witness column; a non-zero multiple of 32 bytes.</param>
    /// <param name="commonValues">The three common values; <see cref="CommonValueCount"/> · 32 bytes.</param>
    /// <param name="apKeys">The six shared MAC keys; <see cref="MacCount"/> · 32 bytes.</param>
    /// <returns>A validated witness view over the supplied buffers.</returns>
    /// <exception cref="ArgumentException">When a region length is invalid.</exception>
    public static LongfellowMdocWitness FromComponents(
        ReadOnlyMemory<byte> hashColumn,
        ReadOnlyMemory<byte> signatureColumnCanonical,
        ReadOnlyMemory<byte> commonValues,
        ReadOnlyMemory<byte> apKeys)
    {
        if(hashColumn.Length == 0 || hashColumn.Length % ScalarSizeBytes != 0)
        {
            throw new ArgumentException($"The hash column must be a non-zero multiple of {ScalarSizeBytes} bytes; received {hashColumn.Length}.", nameof(hashColumn));
        }

        if(signatureColumnCanonical.Length == 0 || signatureColumnCanonical.Length % ScalarSizeBytes != 0)
        {
            throw new ArgumentException($"The signature column must be a non-zero multiple of {ScalarSizeBytes} bytes; received {signatureColumnCanonical.Length}.", nameof(signatureColumnCanonical));
        }

        if(commonValues.Length != CommonValueCount * ScalarSizeBytes)
        {
            throw new ArgumentException($"The common values must be {CommonValueCount * ScalarSizeBytes} bytes; received {commonValues.Length}.", nameof(commonValues));
        }

        if(apKeys.Length != MacCount * ScalarSizeBytes)
        {
            throw new ArgumentException($"The MAC keys must be {MacCount * ScalarSizeBytes} bytes; received {apKeys.Length}.", nameof(apKeys));
        }

        return new LongfellowMdocWitness(hashColumn, signatureColumnCanonical, commonValues, apKeys);
    }
}
