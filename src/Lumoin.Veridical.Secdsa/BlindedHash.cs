using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using static Lumoin.Veridical.Secdsa.P256ScalarValidation;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The blinded representative <c>e' = P⁻¹·e mod n</c> of split ECDSA (Verheul Algorithm 2 step 3): the only value the
/// key holder is given to raw-sign.
/// </summary>
/// <remarks>
/// <b>Secret in combination.</b> <c>e'</c> alone is uniformly random and reveals nothing, but together with the message
/// hash <c>e</c> of the same signing it reveals the PIN key <c>P = e·e'⁻¹</c>. The key holder is therefore given only
/// this value, never the message hash, and the pair must not travel over one channel. The value is cleared when disposed.
/// </remarks>
public sealed class BlindedHash: SensitiveMemory
{
    /// <summary>The byte length of the value: one P-256 scalar.</summary>
    public const int SizeBytes = WellKnownCurves.P256ScalarSizeBytes;


    /// <summary>The tag every BlindedHash carries: its structure kind and the P-256 curve.</summary>
    public static Tag AlgebraicTag { get; } = Tag.Create(SecdsaStructureKind.BlindedHash)
        .With(CurveParameterSet.P256);


    /// <summary>Wraps an already-populated rental; only <see cref="FromCanonical"/> constructs the value.</summary>
    internal BlindedHash(IMemoryOwner<byte> owner, Tag tag) : base(owner, tag)
    {
    }


    /// <summary>Copies canonical bytes into a pool-rented buffer and returns the value wrapping it.</summary>
    /// <param name="canonicalBytes">Exactly <see cref="SizeBytes"/> bytes, big-endian, below the group order.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries; merged with the identity entries.</param>
    /// <returns>The value wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="canonicalBytes"/> has the wrong length, or the value is not below the group order.</exception>
    public static BlindedHash FromCanonical(ReadOnlySpan<byte> canonicalBytes, BaseMemoryPool pool, Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        RequireLength(canonicalBytes, SizeBytes, nameof(canonicalBytes));
        if(!WellKnownCurves.IsCanonicalScalar(canonicalBytes, CurveParameterSet.P256))
        {
            throw new ArgumentException("The value must be below the P-256 group order.", nameof(canonicalBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(SizeBytes);
        canonicalBytes.CopyTo(owner.Memory.Span);
        Tag effectiveTag = tag is null ? AlgebraicTag : tag.With(SecdsaStructureKind.BlindedHash).With(CurveParameterSet.P256);

        return new BlindedHash(owner, effectiveTag);
    }
}
