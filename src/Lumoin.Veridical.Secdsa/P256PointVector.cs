using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using static Lumoin.Veridical.Secdsa.P256PointValidation;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// A non-empty vector of SEC1 compressed P-256 points <c>P₀, …, Pₙ</c>: the generators <c>Gᵢ</c> or the public keys
/// <c>Dᵢ = d·Gᵢ</c> of Verheul's statement (9). The canonical bytes are the points back to back, 33 bytes each; the
/// byte form <c>Ḡ = Ḡ₀ ‖ … ‖ Ḡₙ</c> that the paper hashes and signs is a layout decision made by a
/// <see cref="SecdsaLayoutProfile"/>, never by an algorithm.
/// </summary>
/// <remarks>
/// <b>Public.</b> Generators and public keys are public. <see cref="FromCanonical"/> checks the length and that every
/// point has the shape of a finite compressed point; on-curve membership is checked by the algorithms that consume
/// the vector, through the group delegate's decode contract.
/// </remarks>
public sealed class P256PointVector: SensitiveMemory
{
    /// <summary>The byte length of one SEC1 compressed P-256 point.</summary>
    public const int PointSizeBytes = WellKnownCurves.P256CompressedSizeBytes;


    /// <summary>The tag every point vector carries: its structure kind and the P-256 curve.</summary>
    public static Tag AlgebraicTag { get; } = Tag.Create(SecdsaStructureKind.PointVector)
        .With(CurveParameterSet.P256);


    /// <summary>The number of points in the vector.</summary>
    public int Count => AsReadOnlySpan().Length / PointSizeBytes;


    /// <summary>Wraps an already-populated, already-validated rental; only <see cref="FromCanonical"/> constructs a vector.</summary>
    internal P256PointVector(IMemoryOwner<byte> owner, Tag tag) : base(owner, tag)
    {
    }


    /// <summary>Copies caller-supplied canonical bytes into a pool-rented buffer and returns a vector wrapping it.</summary>
    /// <param name="canonicalBytes">One or more 33-byte compressed points, back to back.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries; merged with the identity entries.</param>
    /// <returns>A vector wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the length is zero or not a multiple of 33, or a point does not have the shape of a finite compressed point.</exception>
    public static P256PointVector FromCanonical(ReadOnlySpan<byte> canonicalBytes, BaseMemoryPool pool, Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(canonicalBytes.IsEmpty || canonicalBytes.Length % PointSizeBytes != 0)
        {
            throw new ArgumentException(
                $"A point vector must be a non-empty multiple of {PointSizeBytes} bytes; received {canonicalBytes.Length}.",
                nameof(canonicalBytes));
        }

        for(int offset = 0; offset < canonicalBytes.Length; offset += PointSizeBytes)
        {
            if(!HasFinitePointShape(canonicalBytes.Slice(offset, PointSizeBytes)))
            {
                throw new ArgumentException("Every point of a point vector must be a finite SEC1 compressed point.", nameof(canonicalBytes));
            }
        }

        IMemoryOwner<byte> owner = pool.Rent(canonicalBytes.Length);
        canonicalBytes.CopyTo(owner.Memory.Span);
        Tag baseTag = tag ?? Tag.Empty;

        return new P256PointVector(owner, baseTag.With(SecdsaStructureKind.PointVector).With(CurveParameterSet.P256));
    }


    /// <summary>Returns the point at <paramref name="index"/>, SEC1 compressed.</summary>
    /// <param name="index">The zero-based index.</param>
    /// <exception cref="ArgumentOutOfRangeException">When the index is outside the vector.</exception>
    public ReadOnlySpan<byte> GetPointBytes(int index)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, Count);

        return AsReadOnlySpan().Slice(index * PointSizeBytes, PointSizeBytes);
    }
}
