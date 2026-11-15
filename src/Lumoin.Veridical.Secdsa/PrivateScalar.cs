using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using static Lumoin.Veridical.Secdsa.P256ScalarValidation;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// A P-256 private scalar in <c>[1, n−1]</c>: the hardware key <c>u</c> of split ECDSA, a signing key, a key-agreement
/// key, a proof witness or a key share, anything that is the discrete logarithm of a public point.
/// </summary>
/// <remarks>
/// <b>Secret.</b> The value is cleared when disposed. <see cref="FromCanonical"/> enforces the range, so the entry
/// points that take it do not validate it again. The PIN key of split ECDSA has its own type, <see cref="PinKey"/>,
/// because it carries different pairing rules.
/// </remarks>
public sealed class PrivateScalar: SensitiveMemory
{
    /// <summary>The byte length of the value: one P-256 scalar.</summary>
    public const int SizeBytes = WellKnownCurves.P256ScalarSizeBytes;


    /// <summary>The tag every PrivateScalar carries: its structure kind and the P-256 curve.</summary>
    public static Tag AlgebraicTag { get; } = Tag.Create(SecdsaStructureKind.PrivateScalar)
        .With(CurveParameterSet.P256);


    /// <summary>Wraps an already-populated rental; only <see cref="FromCanonical"/> constructs the value.</summary>
    internal PrivateScalar(IMemoryOwner<byte> owner, Tag tag) : base(owner, tag)
    {
    }


    /// <summary>Copies canonical bytes into a pool-rented buffer and returns the value wrapping it.</summary>
    /// <param name="canonicalBytes">Exactly <see cref="SizeBytes"/> bytes, big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries; merged with the identity entries.</param>
    /// <returns>The value wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="canonicalBytes"/> has the wrong length, or the scalar is zero or not below the group order.</exception>
    public static PrivateScalar FromCanonical(ReadOnlySpan<byte> canonicalBytes, BaseMemoryPool pool, Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        RequireLength(canonicalBytes, SizeBytes, nameof(canonicalBytes));
        if(IsOutOfRange(canonicalBytes))
        {
            throw new ArgumentException("The scalar must be in [1, n-1] for the P-256 group order.", nameof(canonicalBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(SizeBytes);
        canonicalBytes.CopyTo(owner.Memory.Span);
        Tag effectiveTag = tag is null ? AlgebraicTag : tag.With(SecdsaStructureKind.PrivateScalar).With(CurveParameterSet.P256);

        return new PrivateScalar(owner, effectiveTag);
    }
}
