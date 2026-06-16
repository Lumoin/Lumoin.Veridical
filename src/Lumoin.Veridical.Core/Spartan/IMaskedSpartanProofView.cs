using System;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// The scheme-shaped sections a masked Spartan proof exposes to the
/// scheme-neutral masked verifier core: the three commitments, the two masking
/// sums, and the four openings. The scheme-independent sumcheck middle is read
/// through <see cref="SpartanSumcheckProofPart"/> instead, so it is not part of
/// this view. Both <see cref="MaskedSpartanProof"/> (Hyrax-shaped) and
/// <see cref="BaseFoldMaskedSpartanProof"/> implement it, letting one verifier
/// core serve both schemes.
/// </summary>
internal interface IMaskedSpartanProofView
{
    /// <summary>The witness commitment bytes.</summary>
    ReadOnlySpan<byte> GetWitnessCommitmentBytes();

    /// <summary>The outer masking-polynomial commitment bytes.</summary>
    ReadOnlySpan<byte> GetOuterMaskCommitmentBytes();

    /// <summary>The inner masking-polynomial commitment bytes.</summary>
    ReadOnlySpan<byte> GetInnerMaskCommitmentBytes();

    /// <summary>The outer masking-sum <c>σ_outer</c> bytes.</summary>
    ReadOnlySpan<byte> GetOuterMaskSumBytes();

    /// <summary>The inner masking-sum <c>σ_inner</c> bytes.</summary>
    ReadOnlySpan<byte> GetInnerMaskSumBytes();

    /// <summary>The outer mask's filler-sum <c>σ_F</c> bytes.</summary>
    ReadOnlySpan<byte> GetOuterMaskFillerSumBytes();

    /// <summary>The inner mask's filler-sum <c>σ_F</c> bytes.</summary>
    ReadOnlySpan<byte> GetInnerMaskFillerSumBytes();

    /// <summary>The error-commitment opening proof bytes (at <c>r_x</c>).</summary>
    ReadOnlySpan<byte> GetErrorOpeningProofBytes();

    /// <summary>The outer masking opening proof bytes.</summary>
    ReadOnlySpan<byte> GetOuterMaskOpeningProofBytes();

    /// <summary>The inner masking opening proof bytes.</summary>
    ReadOnlySpan<byte> GetInnerMaskOpeningProofBytes();

    /// <summary>The witness opening proof bytes.</summary>
    ReadOnlySpan<byte> GetWitnessOpeningProofBytes();
}
