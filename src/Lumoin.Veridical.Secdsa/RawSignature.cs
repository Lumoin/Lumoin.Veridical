using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using static Lumoin.Veridical.Secdsa.P256ScalarValidation;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The raw ECDSA signature <c>(r, s₀)</c> that the key holder returns for the blinded hash in split ECDSA (Verheul
/// Algorithm 2 step 7): 64 bytes, <c>r || s₀</c>, each component a scalar in <c>[1, n−1]</c>.
/// </summary>
/// <remarks>
/// <b>Secret.</b> <c>r</c> becomes part of the public signature, but <c>s₀</c> is secret in the same way the blinded hash
/// is: the released <c>s = P·s₀</c> is public, so anyone who also sees <c>s₀</c> computes <c>P = s·s₀⁻¹</c>. Neither the
/// value nor <c>s₀</c> may be published or logged, and the value is cleared when disposed. It is the answer of an
/// external key holder, so <see cref="FromCanonical"/> rejects zero and out-of-range components as a defective answer.
/// </remarks>
public sealed class RawSignature: SensitiveMemory
{
    /// <summary>The byte offset of the component <c>r</c>.</summary>
    public const int ROffset = 0;

    /// <summary>The byte length of the component <c>r</c>.</summary>
    public const int RSizeBytes = WellKnownCurves.P256ScalarSizeBytes;

    /// <summary>The byte offset of the component <c>s₀</c>.</summary>
    public const int RawSOffset = RSizeBytes;

    /// <summary>The byte length of the component <c>s₀</c>.</summary>
    public const int RawSSizeBytes = WellKnownCurves.P256ScalarSizeBytes;

    /// <summary>The byte length of the value: <c>r</c> followed by <c>s₀</c>.</summary>
    public const int SizeBytes = RSizeBytes + RawSSizeBytes;


    /// <summary>The tag every raw signature carries: its structure kind and the P-256 curve.</summary>
    public static Tag AlgebraicTag { get; } = Tag.Create(SecdsaStructureKind.RawSignature)
        .With(CurveParameterSet.P256);


    /// <summary>Wraps an already-populated rental; only <see cref="FromCanonical"/> constructs the value.</summary>
    internal RawSignature(IMemoryOwner<byte> owner, Tag tag) : base(owner, tag)
    {
    }


    /// <summary>Copies the key holder's <c>r || s₀</c> into a pool-rented buffer and returns the value wrapping it.</summary>
    /// <param name="canonicalBytes">Exactly <see cref="SizeBytes"/> bytes, <c>r</c> then <c>s₀</c>, each in <c>[1, n−1]</c>.</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries; merged with the identity entries.</param>
    /// <returns>The value wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="canonicalBytes"/> has the wrong length, or a component is zero or not below the group order.</exception>
    public static RawSignature FromCanonical(ReadOnlySpan<byte> canonicalBytes, BaseMemoryPool pool, Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        RequireLength(canonicalBytes, SizeBytes, nameof(canonicalBytes));
        if(IsOutOfRange(canonicalBytes.Slice(ROffset, RSizeBytes)) | IsOutOfRange(canonicalBytes.Slice(RawSOffset, RawSSizeBytes)))
        {
            throw new ArgumentException("The raw signature components r and s0 must each be in [1, n-1].", nameof(canonicalBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(SizeBytes);
        canonicalBytes.CopyTo(owner.Memory.Span);
        Tag effectiveTag = tag is null ? AlgebraicTag : tag.With(SecdsaStructureKind.RawSignature).With(CurveParameterSet.P256);

        return new RawSignature(owner, effectiveTag);
    }


    /// <summary>Returns the bytes of the component <c>r</c>.</summary>
    public ReadOnlySpan<byte> GetRBytes() => AsReadOnlySpan().Slice(ROffset, RSizeBytes);


    /// <summary>Returns the bytes of the secret component <c>s₀</c>.</summary>
    public ReadOnlySpan<byte> GetRawSBytes() => AsReadOnlySpan().Slice(RawSOffset, RawSSizeBytes);
}
