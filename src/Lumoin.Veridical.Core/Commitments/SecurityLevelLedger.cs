using System;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// The term-by-term knowledge-soundness accounting of one Spartan proof path
/// under one polynomial-commitment scheme: each bound the Fiat-Shamir-compiled
/// argument grants, in bits, plus the path's hiding character. The effective
/// level is the bottleneck — the minimum term — because a forger attacks the
/// cheapest event. Produced by <see cref="WellKnownSecurityLevels"/>.
/// </summary>
/// <param name="Scheme">The polynomial-commitment scheme the path runs over.</param>
/// <param name="Curve">The curve whose scalar field the argument works in.</param>
/// <param name="ProximityBits">The commitment-opening query term: the soundness the opened columns (Ligero) or query repetitions (BaseFold) actually realise, including any per-polynomial clamp.</param>
/// <param name="SumcheckBits">The Spartan sumcheck Fiat-Shamir term: the field-size bound on a per-round polynomial forgery across both sumcheck phases.</param>
/// <param name="FieldTermBits">The remaining field-side low-order events (random linear combinations, decode gaps, commit-phase bad events), under a deliberately conservative weight.</param>
/// <param name="Hiding">The path's hiding character; orthogonal to the soundness terms.</param>
public readonly record struct SecurityLevelLedger(
    CommitmentScheme Scheme,
    CurveParameterSet Curve,
    double ProximityBits,
    double SumcheckBits,
    double FieldTermBits,
    HidingKind Hiding)
{
    /// <summary>
    /// The effective (bottleneck) knowledge-soundness level in bits: the
    /// minimum of the terms. For a Fiat-Shamir-compiled non-interactive proof
    /// this is also the grinding exponent — a forger expects about
    /// <c>2^EffectiveBits</c> hash evaluations to find an accepted transcript.
    /// </summary>
    public double EffectiveBits => Math.Min(ProximityBits, Math.Min(SumcheckBits, FieldTermBits));
}
