namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// Stable Fiat-Shamir operation labels of the Bulletproofs range proof
/// (<see cref="BulletproofRangeProver"/> / <see cref="BulletproofRangeVerifier"/>).
/// Pinned strings so the verifier replays the prover's transcript
/// byte-for-byte; the transcript's domain label is the consumer's to choose,
/// these are the per-operation labels within it.
/// </summary>
public static class WellKnownBulletproofRangeLabels
{
    /// <summary>Absorb label for the Pedersen value commitment <c>V = v·g + γ·h</c>.</summary>
    public const string ValueCommitment = "veridical.bulletproofs.range.value-commitment";

    /// <summary>Absorb label for the bit-decomposition commitment <c>A</c>.</summary>
    public const string BitCommitment = "veridical.bulletproofs.range.a";

    /// <summary>Absorb label for the blinding-vector commitment <c>S</c>.</summary>
    public const string BlindingCommitment = "veridical.bulletproofs.range.s";

    /// <summary>Squeeze label for the challenge <c>y</c>.</summary>
    public const string ChallengeY = "veridical.bulletproofs.range.y";

    /// <summary>Squeeze label for the challenge <c>z</c>.</summary>
    public const string ChallengeZ = "veridical.bulletproofs.range.z";

    /// <summary>Absorb label for the polynomial commitment <c>T₁</c>.</summary>
    public const string PolynomialCommitmentT1 = "veridical.bulletproofs.range.t1";

    /// <summary>Absorb label for the polynomial commitment <c>T₂</c>.</summary>
    public const string PolynomialCommitmentT2 = "veridical.bulletproofs.range.t2";

    /// <summary>Squeeze label for the challenge <c>x</c>.</summary>
    public const string ChallengeX = "veridical.bulletproofs.range.x";

    /// <summary>Absorb label for the blinding aggregate <c>τ_x</c>.</summary>
    public const string TauX = "veridical.bulletproofs.range.tau-x";

    /// <summary>Absorb label for the commitment blinding aggregate <c>μ</c>.</summary>
    public const string Mu = "veridical.bulletproofs.range.mu";

    /// <summary>Absorb label for the inner-product value <c>t̂ = ⟨l, r⟩</c>.</summary>
    public const string THat = "veridical.bulletproofs.range.t-hat";

    /// <summary>Per-round label prefix of the embedded two-vector inner-product argument.</summary>
    public const string IpaRoundLabelPrefix = "veridical.bulletproofs.range.ipa.round";

    /// <summary>Absorb label for the aggregation count — keeps aggregated transcripts separated from single-value ones over the same statement context.</summary>
    public const string AggregationCount = "veridical.bulletproofs.range.aggregation-count";
}
