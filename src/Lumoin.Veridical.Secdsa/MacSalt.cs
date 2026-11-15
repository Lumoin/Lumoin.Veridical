using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The HKDF extraction salt of an ECDH-MAC key derivation (Verheul Algorithms 16 and 17). It may be empty, which selects
/// the paper's plain form.
/// </summary>
/// <remarks>
/// The salt is public protocol data. Both parties must use the same salt, or the derived MAC keys differ and verification
/// fails.
/// </remarks>
public sealed class MacSalt: SensitiveMemory
{
    /// <summary>The tag every MacSalt carries: its structure kind and the P-256 curve.</summary>
    public static Tag AlgebraicTag { get; } = Tag.Create(SecdsaStructureKind.MacSalt)
        .With(CurveParameterSet.P256);


    /// <summary>Wraps an already-populated rental; only <see cref="FromCanonical"/> and the algorithms construct the value.</summary>
    internal MacSalt(IMemoryOwner<byte> owner, Tag tag) : base(owner, tag)
    {
    }


    /// <summary>Copies the bytes into a pool-rented buffer and returns the value wrapping it.</summary>
    /// <param name="canonicalBytes">The bytes of the value.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries; merged with the identity entries.</param>
    /// <returns>The value wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="canonicalBytes"/> is shorter than the value allows.</exception>
    public static MacSalt FromCanonical(ReadOnlySpan<byte> canonicalBytes, BaseMemoryPool pool, Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        IMemoryOwner<byte> owner = SecdsaMemory.CopyOf(canonicalBytes, pool);
        Tag effectiveTag = tag is null ? AlgebraicTag : tag.With(SecdsaStructureKind.MacSalt).With(CurveParameterSet.P256);

        return new MacSalt(owner, effectiveTag);
    }
}
