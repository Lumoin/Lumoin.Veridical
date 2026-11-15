using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// A non-empty vector of P-256 scalars in <c>[1, n−1]</c>: the ephemeral private keys <c>e₀, …, eₙ</c> of a
/// transferable challenge (Verheul Algorithm 22 step 4). The canonical bytes are the scalars back to back, 32 bytes
/// each, big-endian; the byte form <c>e₀ ‖ … ‖ eₙ</c> that <c>H1</c> hashes is a layout decision made by a
/// <see cref="SecdsaLayoutProfile"/>.
/// </summary>
/// <remarks>
/// <b>Secret.</b> The ephemeral keys are known to the challenger and, after it decrypts the seed, to the prover; they
/// never leave those two parties, and whoever holds the vector disposes it, which clears its memory. Anyone
/// holding them together with the ciphertext can recompute the ECIES key, which is why the response carries the
/// hash <c>H1</c> and not the keys.
/// </remarks>
public sealed class P256ScalarVector: SensitiveMemory
{
    /// <summary>The byte length of one scalar.</summary>
    public const int ScalarSizeBytes = WellKnownCurves.P256ScalarSizeBytes;


    /// <summary>The tag every scalar vector carries: its structure kind and the P-256 curve.</summary>
    public static Tag AlgebraicTag { get; } = Tag.Create(SecdsaStructureKind.ScalarVector)
        .With(CurveParameterSet.P256);


    /// <summary>The number of scalars in the vector.</summary>
    public int Count => AsReadOnlySpan().Length / ScalarSizeBytes;


    /// <summary>Wraps an already-populated, already-validated rental; only <see cref="FromCanonical"/> and the algorithms construct a vector.</summary>
    internal P256ScalarVector(IMemoryOwner<byte> owner, Tag tag) : base(owner, tag)
    {
    }


    /// <summary>Copies caller-supplied canonical bytes into a pool-rented buffer and returns a vector wrapping it.</summary>
    /// <param name="canonicalBytes">One or more 32-byte big-endian scalars, back to back, each in <c>[1, n−1]</c>.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries; merged with the identity entries.</param>
    /// <returns>A vector wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the length is zero or not a multiple of 32, or a scalar is zero or not below the group order.</exception>
    public static P256ScalarVector FromCanonical(ReadOnlySpan<byte> canonicalBytes, BaseMemoryPool pool, Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(canonicalBytes.IsEmpty || canonicalBytes.Length % ScalarSizeBytes != 0)
        {
            throw new ArgumentException(
                $"A scalar vector must be a non-empty multiple of {ScalarSizeBytes} bytes; received {canonicalBytes.Length}.",
                nameof(canonicalBytes));
        }

        for(int offset = 0; offset < canonicalBytes.Length; offset += ScalarSizeBytes)
        {
            ReadOnlySpan<byte> scalar = canonicalBytes.Slice(offset, ScalarSizeBytes);
            if(!WellKnownCurves.IsCanonicalScalar(scalar, CurveParameterSet.P256) || scalar.IndexOfAnyExcept((byte)0) < 0)
            {
                throw new ArgumentException("Every scalar of a scalar vector must be in [1, n-1].", nameof(canonicalBytes));
            }
        }

        IMemoryOwner<byte> owner = pool.Rent(canonicalBytes.Length);
        canonicalBytes.CopyTo(owner.Memory.Span);
        Tag baseTag = tag ?? Tag.Empty;

        return new P256ScalarVector(owner, baseTag.With(SecdsaStructureKind.ScalarVector).With(CurveParameterSet.P256));
    }


    /// <summary>Returns the scalar at <paramref name="index"/>, 32-byte big-endian.</summary>
    /// <param name="index">The zero-based index.</param>
    /// <exception cref="ArgumentOutOfRangeException">When the index is outside the vector.</exception>
    public ReadOnlySpan<byte> GetScalarBytes(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, Count);

        return AsReadOnlySpan().Slice(index * ScalarSizeBytes, ScalarSizeBytes);
    }
}
