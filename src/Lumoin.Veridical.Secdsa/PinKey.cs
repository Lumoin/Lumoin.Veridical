using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using static Lumoin.Veridical.Secdsa.P256ScalarValidation;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The PIN-key scalar <c>P</c> of split ECDSA (Verheul Algorithm 2): the secret that blinds the message hash and masks
/// the key holder's signature, and half of the composite key <c>d = P·u</c>. A key share (<c>zU</c>, <c>zW</c> of
/// Algorithm 11) is used as a PIN key by the party that holds it.
/// </summary>
/// <remarks>
/// <b>Secret.</b> The value never leaves the party that holds it and is cleared when disposed. It is a scalar in
/// <c>[1, n−1]</c>, which <see cref="FromCanonical"/> enforces, so the entry points that take it do not validate it
/// again. Anyone who sees both a message hash <c>e</c> and the blinded hash <c>e' = P⁻¹·e</c> computes <c>P</c>.
/// </remarks>
public sealed class PinKey: SensitiveMemory
{
    /// <summary>The byte length of the value: one P-256 scalar.</summary>
    public const int SizeBytes = WellKnownCurves.P256ScalarSizeBytes;


    /// <summary>The tag every PinKey carries: its structure kind and the P-256 curve.</summary>
    public static Tag AlgebraicTag { get; } = Tag.Create(SecdsaStructureKind.PinKey)
        .With(CurveParameterSet.P256);


    /// <summary>Wraps an already-populated rental; only <see cref="FromCanonical"/> constructs the value.</summary>
    internal PinKey(IMemoryOwner<byte> owner, Tag tag) : base(owner, tag)
    {
    }


    /// <summary>Copies canonical bytes into a pool-rented buffer and returns the value wrapping it.</summary>
    /// <param name="canonicalBytes">Exactly <see cref="SizeBytes"/> bytes, big-endian, in <c>[1, n−1]</c>.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries; merged with the identity entries.</param>
    /// <returns>The value wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="canonicalBytes"/> has the wrong length, or the scalar is zero or not below the group order.</exception>
    public static PinKey FromCanonical(ReadOnlySpan<byte> canonicalBytes, BaseMemoryPool pool, Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        RequireLength(canonicalBytes, SizeBytes, nameof(canonicalBytes));
        if(IsOutOfRange(canonicalBytes))
        {
            throw new ArgumentException("The scalar must be in [1, n-1] for the P-256 group order.", nameof(canonicalBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(SizeBytes);
        canonicalBytes.CopyTo(owner.Memory.Span);
        Tag effectiveTag = tag is null ? AlgebraicTag : tag.With(SecdsaStructureKind.PinKey).With(CurveParameterSet.P256);

        return new PinKey(owner, effectiveTag);
    }
}
