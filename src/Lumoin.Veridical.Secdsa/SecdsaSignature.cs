using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// A standard ECDSA-P-256 signature: the pair <c>(r, s)</c>, each a 32-byte canonical big-endian scalar in
/// <c>[1, n−1]</c>, serialised as 64 bytes total in <c>r || s</c> order. SECDSA's split sign produces an
/// ordinary ECDSA signature under the composite key <c>P·u</c>, so the wire format is the standard one — there
/// is nothing split-specific in the bytes.
/// </summary>
public sealed class SecdsaSignature: SensitiveMemory
{
    /// <summary>The byte offset of the component <c>r</c>.</summary>
    public const int ROffset = 0;

    /// <summary>The canonical byte length of the component <c>r</c> (a P-256 scalar).</summary>
    public const int RSizeBytes = WellKnownCurves.P256ScalarSizeBytes;

    /// <summary>The byte offset of the component <c>s</c>.</summary>
    public const int SOffset = RSizeBytes;

    /// <summary>The canonical byte length of the component <c>s</c> (a P-256 scalar).</summary>
    public const int SSizeBytes = WellKnownCurves.P256ScalarSizeBytes;

    /// <summary>The canonical byte length of a complete signature (<c>r</c> + <c>s</c>).</summary>
    public const int SizeBytes = RSizeBytes + SSizeBytes;


    /// <summary>The shared algebraic-identity tag every SECDSA signature carries: signature role, P-256 curve.</summary>
    public static Tag AlgebraicTag { get; } = Tag.Create(
        (typeof(AlgebraicRole), (object)AlgebraicRole.Signature),
        (typeof(CurveParameterSet), (object)CurveParameterSet.P256));


    internal SecdsaSignature(IMemoryOwner<byte> owner, Tag tag) : base(owner, SizeBytes, tag)
    {
    }


    /// <summary>
    /// Copies caller-supplied canonical bytes into a pool-rented buffer and returns a signature wrapping it.
    /// </summary>
    /// <param name="canonicalBytes">Exactly <see cref="SizeBytes"/> bytes (32 for <c>r</c>, 32 for <c>s</c>).</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries; merged with the algebraic-identity tag.</param>
    /// <returns>A signature wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="canonicalBytes"/> has the wrong length.</exception>
    public static SecdsaSignature FromCanonical(
        ReadOnlySpan<byte> canonicalBytes,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(canonicalBytes.Length != SizeBytes)
        {
            throw new ArgumentException(
                $"SECDSA signature must be exactly {SizeBytes} bytes; received {canonicalBytes.Length}.",
                nameof(canonicalBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(SizeBytes);
        canonicalBytes.CopyTo(owner.Memory.Span);

        Tag effectiveTag = tag is null ? AlgebraicTag : MergeWithAlgebraicTag(tag);

        return new SecdsaSignature(owner, effectiveTag);
    }


    /// <summary>Returns the canonical bytes of the component <c>r</c>.</summary>
    public ReadOnlySpan<byte> GetRBytes() => AsReadOnlySpan().Slice(ROffset, RSizeBytes);


    /// <summary>Returns the canonical bytes of the component <c>s</c>.</summary>
    public ReadOnlySpan<byte> GetSBytes() => AsReadOnlySpan().Slice(SOffset, SSizeBytes);


    private static Tag MergeWithAlgebraicTag(Tag tag)
    {
        return tag.With(
            (typeof(AlgebraicRole), (object)AlgebraicRole.Signature),
            (typeof(CurveParameterSet), (object)CurveParameterSet.P256));
    }
}
