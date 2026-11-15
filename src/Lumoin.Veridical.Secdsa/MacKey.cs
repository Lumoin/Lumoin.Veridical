using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The MAC key <c>K = KDF(Z_AB, SharedInfo)</c> of an ECDH-MAC (Verheul Algorithms 16 and 17): one or more bytes, 32 for
/// HMAC-SHA-256 under the paper's parameters.
/// </summary>
/// <remarks>
/// <b>Secret.</b> The key is derived from the Diffie-Hellman shared secret and is cleared when disposed. Whoever holds it
/// can form and verify tags, so it is never published or logged.
/// </remarks>
public sealed class MacKey: SensitiveMemory
{
    /// <summary>The tag every MacKey carries: its structure kind and the P-256 curve.</summary>
    public static Tag AlgebraicTag { get; } = Tag.Create(SecdsaStructureKind.MacKey)
        .With(CurveParameterSet.P256);


    /// <summary>Wraps an already-populated rental; only <see cref="FromCanonical"/> and the algorithms construct the value.</summary>
    internal MacKey(IMemoryOwner<byte> owner, Tag tag) : base(owner, tag)
    {
    }


    /// <summary>Copies the bytes into a pool-rented buffer and returns the value wrapping it.</summary>
    /// <param name="canonicalBytes">The bytes of the value.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries; merged with the identity entries.</param>
    /// <returns>The value wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="canonicalBytes"/> is shorter than the value allows.</exception>
    public static MacKey FromCanonical(ReadOnlySpan<byte> canonicalBytes, BaseMemoryPool pool, Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(canonicalBytes.Length < 1)
        {
            throw new ArgumentException("A MAC key must be at least 1 byte.", nameof(canonicalBytes));
        }

        IMemoryOwner<byte> owner = SecdsaMemory.CopyOf(canonicalBytes, pool);
        Tag effectiveTag = tag is null ? AlgebraicTag : tag.With(SecdsaStructureKind.MacKey).With(CurveParameterSet.P256);

        return new MacKey(owner, effectiveTag);
    }
}
