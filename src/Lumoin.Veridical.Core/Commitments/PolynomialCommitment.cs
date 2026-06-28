using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// A scheme-agnostic commitment to a multilinear polynomial: the
/// canonical bytes a polynomial-commitment scheme produces, tagged with
/// the curve and the <see cref="CommitmentScheme"/> that produced them.
/// Spartan commits, absorbs, and opens against this broad type rather
/// than a scheme-specific one, so a future scheme (BaseFold, WHIR, …)
/// drops in behind the same surface.
/// </summary>
/// <remarks>
/// <para>
/// The byte layout is the scheme's own (for Hyrax: the concatenated
/// per-row compressed-G1 Pedersen commitments). This type does not
/// interpret them — it carries them and identifies their producer. The
/// <see cref="Scheme"/> on the <c>Tag</c> lets a runtime guard reject a
/// commitment from the wrong scheme the same way the curve tag rejects a
/// cross-curve mismatch.
/// </para>
/// <para>
/// The polynomial-commitment surface mirrors Microsoft Research's
/// Spartan2 PCS abstraction (the <c>PCSEngineTrait</c> / <c>Commitment</c>
/// associated type); structural inspiration only, no code dependency. See
/// microsoft/Spartan2 on GitHub for the canonical Rust implementation.
/// </para>
/// </remarks>
public sealed class PolynomialCommitment: SensitiveMemory
{
    /// <summary>The curve identifying the group the commitment lives in.</summary>
    public CurveParameterSet Curve { get; }

    /// <summary>The commitment scheme that produced these bytes.</summary>
    public CommitmentScheme Scheme { get; }


    internal PolynomialCommitment(
        IMemoryOwner<byte> owner,
        int length,
        CurveParameterSet curve,
        CommitmentScheme scheme,
        Tag tag)
        : base(owner, tag)
    {
        Curve = curve;
        Scheme = scheme;
    }


    /// <summary>Builds the identifying tag for a commitment over <paramref name="curve"/> from <paramref name="scheme"/>.</summary>
    internal static Tag CreateTag(CurveParameterSet curve, CommitmentScheme scheme)
    {
        return Tag.Create(AlgebraicRole.Commitment)
            .With(curve)
            .With(scheme);
    }


    /// <summary>
    /// Wraps a pool-rented buffer that a scheme has populated with
    /// commitment bytes. Used by the scheme provider; the commitment
    /// takes ownership of <paramref name="owner"/>.
    /// </summary>
    internal static PolynomialCommitment Create(
        IMemoryOwner<byte> owner,
        int length,
        CurveParameterSet curve,
        CommitmentScheme scheme)
    {
        return new PolynomialCommitment(owner, length, curve, scheme, CreateTag(curve, scheme));
    }


    /// <summary>
    /// Reconstructs a commitment from its canonical wire bytes (typically
    /// extracted from a proof on the verifier side). Copies the bytes into
    /// a fresh pool-rented buffer; the caller retains ownership of
    /// <paramref name="commitmentBytes"/>.
    /// </summary>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is null.</exception>
    /// <exception cref="ArgumentException">When <paramref name="commitmentBytes"/> is empty.</exception>
    public static PolynomialCommitment FromBytes(
        ReadOnlySpan<byte> commitmentBytes,
        CurveParameterSet curve,
        CommitmentScheme scheme,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(commitmentBytes.IsEmpty)
        {
            throw new ArgumentException("Commitment bytes must be non-empty.", nameof(commitmentBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(commitmentBytes.Length);
        commitmentBytes.CopyTo(owner.Memory.Span[..commitmentBytes.Length]);

        return Create(owner, commitmentBytes.Length, curve, scheme);
    }
}
