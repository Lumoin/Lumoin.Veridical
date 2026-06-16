namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// The structural dimensions of a <see cref="SpartanProof"/>: the
/// outer-sumcheck round count, the inner-sumcheck round count, the
/// Hyrax-IPA round count of the embedded witness opening proof, and the
/// Hyrax-IPA round count of the embedded error-commitment opening proof.
/// </summary>
/// <param name="OuterRoundCount">Number of outer sumcheck rounds; equals <c>log_2(rows)</c> of the underlying R1CS instance.</param>
/// <param name="InnerRoundCount">Number of inner sumcheck rounds; equals <c>log_2(columns)</c>.</param>
/// <param name="IpaRoundCount">Number of IPA rounds inside the witness Hyrax opening proof.</param>
/// <param name="ErrorIpaRoundCount">Number of IPA rounds inside the error-commitment Hyrax opening proof at <c>r_x</c>.</param>
/// <remarks>
/// Surfaced as a tag entry so callers can read the shape without
/// unwrapping the leaf type and without recomputing round counts from
/// instance dimensions.
/// </remarks>
public readonly record struct SpartanProofDimensions(int OuterRoundCount, int InnerRoundCount, int IpaRoundCount, int ErrorIpaRoundCount);