using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// A Chaum–Pedersen / Schnorr discrete-log-equality proof <c>(r, s)</c> (Verheul Algorithm 19), serialised as
/// 64 bytes in <c>r || s</c> order. The proof attests that a set of public keys <c>D_i</c> share one private
/// key <c>d</c> across their respective generators <c>G_i</c> (statement (9): <c>D_i = d·G_i</c>), without
/// revealing <c>d</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b><c>r</c> is NOT a reduced scalar.</b> Unlike a signature's <c>r</c>, the proof's <c>r</c> is the
/// <em>full-width</em> Fiat–Shamir hash value — the raw digest integer in <c>[1, 2^(8·|q|)−1]</c>, which may
/// exceed the group order <c>n</c>. It is stored, range-checked, and compared (<c>v == r</c>) as the raw 32-byte
/// digest; it is reduced mod <c>n</c> only where it is used as a scalar coefficient. For SHA-256 + P-256 the
/// digest happens to be 32 bytes wide, so it shares <see cref="RSizeBytes"/> with the scalar <c>s</c>, but the
/// two ranges differ. Reducing <c>r</c> before storage would self-verify yet break interoperability.
/// </para>
/// </remarks>
public sealed class DlEqualityProof: SensitiveMemory
{
    /// <summary>The byte offset of the full-width Fiat–Shamir value <c>r</c>.</summary>
    public const int ROffset = 0;

    /// <summary>The byte length of <c>r</c> (a SHA-256 digest, 32 bytes — full-width, not a reduced scalar).</summary>
    public const int RSizeBytes = WellKnownCurves.P256ScalarSizeBytes;

    /// <summary>The byte offset of the response scalar <c>s</c>.</summary>
    public const int SOffset = RSizeBytes;

    /// <summary>The canonical byte length of the response scalar <c>s</c> (a P-256 scalar in <c>[1, n−1]</c>).</summary>
    public const int SSizeBytes = WellKnownCurves.P256ScalarSizeBytes;

    /// <summary>The canonical byte length of a complete proof (<c>r</c> + <c>s</c>).</summary>
    public const int SizeBytes = RSizeBytes + SSizeBytes;


    /// <summary>The shared algebraic-identity tag every DL-equality proof carries: zero-knowledge-proof role, P-256 curve.</summary>
    public static Tag AlgebraicTag { get; } = Tag.Create(
        (typeof(AlgebraicRole), (object)AlgebraicRole.ZkProof),
        (typeof(CurveParameterSet), (object)CurveParameterSet.P256));


    internal DlEqualityProof(IMemoryOwner<byte> owner, Tag tag) : base(owner, SizeBytes, tag)
    {
    }


    /// <summary>
    /// Copies caller-supplied canonical bytes into a pool-rented buffer and returns a proof wrapping it.
    /// </summary>
    /// <param name="canonicalBytes">Exactly <see cref="SizeBytes"/> bytes (32 for <c>r</c>, 32 for <c>s</c>).</param>
    /// <param name="pool">The pool to rent the backing buffer from.</param>
    /// <param name="tag">An optional tag carrying provenance entries; merged with the algebraic-identity tag.</param>
    /// <returns>A proof wrapping a pool-rented copy of the supplied bytes.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="canonicalBytes"/> has the wrong length.</exception>
    public static DlEqualityProof FromCanonical(
        ReadOnlySpan<byte> canonicalBytes,
        BaseMemoryPool pool,
        Tag? tag = null)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(canonicalBytes.Length != SizeBytes)
        {
            throw new ArgumentException(
                $"DL-equality proof must be exactly {SizeBytes} bytes; received {canonicalBytes.Length}.",
                nameof(canonicalBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(SizeBytes);
        canonicalBytes.CopyTo(owner.Memory.Span);

        Tag effectiveTag = tag is null ? AlgebraicTag : MergeWithAlgebraicTag(tag);

        return new DlEqualityProof(owner, effectiveTag);
    }


    /// <summary>Returns the full-width Fiat–Shamir bytes <c>r</c> (raw digest, not a reduced scalar).</summary>
    public ReadOnlySpan<byte> GetRBytes() => AsReadOnlySpan().Slice(ROffset, RSizeBytes);


    /// <summary>Returns the canonical bytes of the response scalar <c>s</c>.</summary>
    public ReadOnlySpan<byte> GetSBytes() => AsReadOnlySpan().Slice(SOffset, SSizeBytes);


    private static Tag MergeWithAlgebraicTag(Tag tag)
    {
        return tag.With(
            (typeof(AlgebraicRole), (object)AlgebraicRole.ZkProof),
            (typeof(CurveParameterSet), (object)CurveParameterSet.P256));
    }
}
