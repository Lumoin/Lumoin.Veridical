using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The Diffie-Hellman shared secret <c>Z_AB</c> of an ECIES exchange: the 32-byte x-coordinate of the shared point
/// <c>S_AB</c> (Verheul Annex A.4, Algorithms 18 and 19). It is the value an external key holder returns from its
/// raw ECDH, and the input of the key derivation.
/// </summary>
/// <remarks>
/// <b>Secret.</b> The shared secret never crosses a trust boundary other than between the party and its own key
/// holder, and the caller disposes it, which clears its memory. The library cannot detect an incorrect
/// <c>Z_AB</c> from a key holder; a wrong value derives a wrong key and the authenticated decryption fails.
/// </remarks>
public sealed class SharedSecret: SensitiveMemory
{
    /// <summary>The byte length of the shared secret: the P-256 x-coordinate.</summary>
    public const int SizeBytes = WellKnownCurves.P256ScalarSizeBytes;


    /// <summary>The tag every shared secret carries: its structure kind and the P-256 curve.</summary>
    public static Tag AlgebraicTag { get; } = Tag.Create(SecdsaStructureKind.SharedSecret)
        .With(CurveParameterSet.P256);


    /// <summary>Wraps an already-populated rental; only <see cref="FromCanonical"/> and the algorithms construct a shared secret.</summary>
    internal SharedSecret(IMemoryOwner<byte> owner, Tag tag) : base(owner, tag)
    {
    }


    /// <summary>Copies a key holder's returned <c>Z_AB</c> into a pool-rented buffer and returns a shared secret wrapping it.</summary>
    /// <param name="canonicalBytes">Exactly <see cref="SizeBytes"/> bytes.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries; merged with the identity entries.</param>
    /// <returns>A shared secret wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="canonicalBytes"/> has the wrong length.</exception>
    public static SharedSecret FromCanonical(ReadOnlySpan<byte> canonicalBytes, BaseMemoryPool pool, Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(canonicalBytes.Length != SizeBytes)
        {
            throw new ArgumentException($"A shared secret must be exactly {SizeBytes} bytes; received {canonicalBytes.Length}.", nameof(canonicalBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(SizeBytes);
        canonicalBytes.CopyTo(owner.Memory.Span);
        Tag effectiveTag = tag is null ? AlgebraicTag : tag.With(SecdsaStructureKind.SharedSecret).With(CurveParameterSet.P256);

        return new SharedSecret(owner, effectiveTag);
    }
}
