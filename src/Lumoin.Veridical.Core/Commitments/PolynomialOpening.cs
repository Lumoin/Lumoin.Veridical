using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// A scheme-agnostic evaluation argument (opening proof): the bytes a
/// polynomial-commitment scheme produces to attest that a committed
/// polynomial evaluates to a claimed value at a point. Tagged with the
/// curve and the <see cref="CommitmentScheme"/> that produced it.
/// </summary>
/// <remarks>
/// <para>
/// The byte layout is the scheme's own (for Hyrax: the inner-product
/// argument's round elements and final scalars). This type carries the
/// bytes and identifies their producer; it does not interpret them.
/// </para>
/// <para>
/// Mirrors Microsoft Research's Spartan2 PCS <c>EvaluationArgument</c>
/// associated type; structural inspiration only, no code dependency. See
/// microsoft/Spartan2 on GitHub for the canonical Rust implementation.
/// </para>
/// </remarks>
public sealed class PolynomialOpening: SensitiveMemory
{
    /// <summary>The curve identifying the scalar field and group the argument is over.</summary>
    public CurveParameterSet Curve { get; }

    /// <summary>The commitment scheme that produced this opening.</summary>
    public CommitmentScheme Scheme { get; }


    internal PolynomialOpening(
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


    /// <summary>Builds the identifying tag for an opening over <paramref name="curve"/> from <paramref name="scheme"/>.</summary>
    internal static Tag CreateTag(CurveParameterSet curve, CommitmentScheme scheme)
    {
        return Tag.Create(AlgebraicRole.OpeningProof)
            .With(curve)
            .With(scheme);
    }


    /// <summary>Wraps a pool-rented buffer a scheme has populated with opening bytes; takes ownership of <paramref name="owner"/>.</summary>
    internal static PolynomialOpening Create(
        IMemoryOwner<byte> owner,
        int length,
        CurveParameterSet curve,
        CommitmentScheme scheme)
    {
        return new PolynomialOpening(owner, length, curve, scheme, CreateTag(curve, scheme));
    }


    /// <summary>
    /// Reconstructs an opening from its canonical wire bytes (verifier
    /// side). Copies into a fresh pool-rented buffer; the caller retains
    /// ownership of <paramref name="openingBytes"/>.
    /// </summary>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is null.</exception>
    /// <exception cref="ArgumentException">When <paramref name="openingBytes"/> is empty.</exception>
    public static PolynomialOpening FromBytes(
        ReadOnlySpan<byte> openingBytes,
        CurveParameterSet curve,
        CommitmentScheme scheme,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(openingBytes.IsEmpty)
        {
            throw new ArgumentException("Opening bytes must be non-empty.", nameof(openingBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(openingBytes.Length);
        openingBytes.CopyTo(owner.Memory.Span[..openingBytes.Length]);

        return Create(owner, openingBytes.Length, curve, scheme);
    }
}
