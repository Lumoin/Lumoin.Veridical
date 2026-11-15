using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using static Lumoin.Veridical.Secdsa.P256ScalarValidation;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The message representative <c>e = H(M)</c> of an ECDSA signature: a 32-byte big-endian value that the algorithms reduce
/// modulo the group order <c>n</c>.
/// </summary>
/// <remarks>
/// A message hash is usually public, which is why it must never be paired with the blinded hash <c>e' = P⁻¹·e</c> of the
/// same signing: the pair reveals the PIN key <c>P = e·e'⁻¹</c>. The value is cleared when disposed.
/// </remarks>
public sealed class MessageHash: SensitiveMemory
{
    /// <summary>The byte length of the value: one P-256 scalar.</summary>
    public const int SizeBytes = WellKnownCurves.P256ScalarSizeBytes;


    /// <summary>The tag every MessageHash carries: its structure kind and the P-256 curve.</summary>
    public static Tag AlgebraicTag { get; } = Tag.Create(SecdsaStructureKind.MessageHash)
        .With(CurveParameterSet.P256);


    /// <summary>Wraps an already-populated rental; only <see cref="FromCanonical"/> constructs the value.</summary>
    internal MessageHash(IMemoryOwner<byte> owner, Tag tag) : base(owner, tag)
    {
    }


    /// <summary>Copies canonical bytes into a pool-rented buffer and returns the value wrapping it.</summary>
    /// <param name="canonicalBytes">Exactly <see cref="SizeBytes"/> bytes, big-endian (any 32 bytes, reduced modulo <c>n</c> by the algorithms).</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries; merged with the identity entries.</param>
    /// <returns>The value wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="canonicalBytes"/> has the wrong length.</exception>
    public static MessageHash FromCanonical(ReadOnlySpan<byte> canonicalBytes, BaseMemoryPool pool, Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        RequireLength(canonicalBytes, SizeBytes, nameof(canonicalBytes));

        IMemoryOwner<byte> owner = pool.Rent(SizeBytes);
        canonicalBytes.CopyTo(owner.Memory.Span);
        Tag effectiveTag = tag is null ? AlgebraicTag : tag.With(SecdsaStructureKind.MessageHash).With(CurveParameterSet.P256);

        return new MessageHash(owner, effectiveTag);
    }
}
