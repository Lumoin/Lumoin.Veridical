using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The MAC tag <c>HMAC(K, M)</c> of an ECDH-MAC signature (Verheul Algorithm 16): 32 bytes of HMAC-SHA-256.
/// </summary>
/// <remarks>
/// The tag is the public output of the signature; it authenticates the message to the holder of the shared MAC key
/// only, and is cleared when disposed.
/// </remarks>
public sealed class MacTag: SensitiveMemory
{
    /// <summary>The byte length of the tag: one HMAC-SHA-256 output.</summary>
    public const int SizeBytes = 32;


    /// <summary>The tag every MacTag carries: its structure kind and the P-256 curve.</summary>
    public static Tag AlgebraicTag { get; } = Tag.Create(SecdsaStructureKind.MacTag)
        .With(CurveParameterSet.P256);


    /// <summary>Wraps an already-populated rental; only <see cref="FromCanonical"/> and the algorithms construct the value.</summary>
    internal MacTag(IMemoryOwner<byte> owner, Tag tag) : base(owner, tag)
    {
    }


    /// <summary>Copies a tag into a pool-rented buffer and returns the value wrapping it.</summary>
    /// <param name="canonicalBytes">Exactly <see cref="SizeBytes"/> bytes.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries; merged with the identity entries.</param>
    /// <returns>The value wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="canonicalBytes"/> has the wrong length.</exception>
    public static MacTag FromCanonical(ReadOnlySpan<byte> canonicalBytes, BaseMemoryPool pool, Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(canonicalBytes.Length != SizeBytes)
        {
            throw new ArgumentException($"A MAC tag must be exactly {SizeBytes} bytes; received {canonicalBytes.Length}.", nameof(canonicalBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(SizeBytes);
        canonicalBytes.CopyTo(owner.Memory.Span);
        Tag effectiveTag = tag is null ? AlgebraicTag : tag.With(SecdsaStructureKind.MacTag).With(CurveParameterSet.P256);

        return new MacTag(owner, effectiveTag);
    }
}
