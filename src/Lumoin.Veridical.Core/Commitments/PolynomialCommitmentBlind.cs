using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// A scheme-agnostic commitment blind: the secret randomness a hiding
/// polynomial-commitment scheme uses to blind a commitment, retained by
/// the prover for the matching open. Tagged with the curve and the
/// <see cref="CommitmentScheme"/> that produced it.
/// </summary>
/// <remarks>
/// <para>
/// For Hyrax this is the per-row Pedersen blinding-factor vector (today's
/// <c>HyraxOpeningWitness</c>). Folding schemes combine blinds
/// homomorphically alongside the commitments they blind, so the blind is
/// a first-class artifact of the surface, not an opaque prover detail.
/// </para>
/// <para>
/// Mirrors Microsoft Research's Spartan2 PCS <c>Blind</c> associated type;
/// structural inspiration only, no code dependency. See microsoft/Spartan2
/// on GitHub for the canonical Rust implementation.
/// </para>
/// </remarks>
public sealed class PolynomialCommitmentBlind: SensitiveMemory
{
    /// <summary>The curve identifying the scalar field the blinding factors live in.</summary>
    public CurveParameterSet Curve { get; }

    /// <summary>The commitment scheme that produced this blind.</summary>
    public CommitmentScheme Scheme { get; }


    internal PolynomialCommitmentBlind(
        IMemoryOwner<byte> owner,
        int length,
        CurveParameterSet curve,
        CommitmentScheme scheme,
        Tag tag)
        : base(owner, length, tag)
    {
        Curve = curve;
        Scheme = scheme;
    }


    /// <summary>Builds the identifying tag for a blind over <paramref name="curve"/> from <paramref name="scheme"/>.</summary>
    internal static Tag CreateTag(CurveParameterSet curve, CommitmentScheme scheme)
    {
        return Tag.Create(
            (typeof(AlgebraicRole), (object)AlgebraicRole.CommitmentWitness),
            (typeof(CurveParameterSet), (object)curve),
            (typeof(CommitmentScheme), (object)scheme));
    }


    /// <summary>Wraps a pool-rented buffer a scheme has populated with blind bytes; takes ownership of <paramref name="owner"/>.</summary>
    internal static PolynomialCommitmentBlind Create(
        IMemoryOwner<byte> owner,
        int length,
        CurveParameterSet curve,
        CommitmentScheme scheme)
    {
        return new PolynomialCommitmentBlind(owner, length, curve, scheme, CreateTag(curve, scheme));
    }


    /// <summary>
    /// Reconstructs a blind from its canonical bytes. A scheme's open
    /// operation uses this to re-materialize the blind it produced at
    /// commit time, and a folding scheme uses it to wrap the combined
    /// blind it assembles from the folded instances' blinds. Copies the
    /// bytes into a pool-rented buffer; the caller retains ownership of
    /// <paramref name="blindBytes"/>.
    /// </summary>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is null.</exception>
    /// <exception cref="ArgumentException">When <paramref name="blindBytes"/> is empty.</exception>
    internal static PolynomialCommitmentBlind FromCanonical(
        ReadOnlySpan<byte> blindBytes,
        CurveParameterSet curve,
        CommitmentScheme scheme,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(blindBytes.IsEmpty)
        {
            throw new ArgumentException("Blind bytes must be non-empty.", nameof(blindBytes));
        }

        IMemoryOwner<byte> owner = pool.Rent(blindBytes.Length);
        blindBytes.CopyTo(owner.Memory.Span[..blindBytes.Length]);

        return Create(owner, blindBytes.Length, curve, scheme);
    }


    /// <summary>
    /// Creates an all-zero blind of <paramref name="lengthBytes"/> bytes:
    /// the blind matching the identity commitment to a zero vector — the
    /// error blind a raw instance carries after preparation (no hiding
    /// randomness). The byte length is the scheme's blind size for the
    /// committed polynomial (for Hyrax / Pedersen-family schemes, the
    /// per-row blinding-factor count times the scalar size); a folded
    /// instance instead carries a real combined blind via
    /// <see cref="FromCanonical"/>.
    /// </summary>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="lengthBytes"/> is non-positive.</exception>
    internal static PolynomialCommitmentBlind CreateZero(
        int lengthBytes,
        CurveParameterSet curve,
        CommitmentScheme scheme,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(lengthBytes);

        IMemoryOwner<byte> owner = pool.Rent(lengthBytes);
        owner.Memory.Span[..lengthBytes].Clear();

        return Create(owner, lengthBytes, curve, scheme);
    }
}
