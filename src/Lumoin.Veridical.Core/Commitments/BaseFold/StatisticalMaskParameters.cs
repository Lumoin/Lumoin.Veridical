using System;
using System.Diagnostics;

namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// The resolved shape of a statistical sumcheck mask's coefficient commitment
/// (<c>ZK-STATMASK-DESIGN.md</c> §2 v3): the committed vector
/// <c>C* = (mask coefficients ‖ random filler)</c> lives on
/// <c>2^CoefficientVariableCount</c> coordinates and — over BaseFold — is
/// dimension-lifted by <see cref="ExtraVariableCount"/> for its
/// bounded-independence query hiding (zero over Pedersen/IPA, which needs no
/// lift). Derived deterministically by
/// <see cref="WellKnownStatisticalMaskParameters.CreateClassicalSecurity"/> or
/// <see cref="WellKnownStatisticalMaskParameters.CreatePedersenIpa"/> so
/// prover and verifier agree without any wire data.
/// </summary>
[DebuggerDisplay("StatisticalMaskParameters (d = {SumcheckVariableCount}, ℓ₂ = {CoefficientVariableCount}, t = {ExtraVariableCount})")]
public readonly struct StatisticalMaskParameters: IEquatable<StatisticalMaskParameters>
{
    /// <summary>The masked sumcheck's variable count <c>d</c>.</summary>
    public int SumcheckVariableCount { get; }

    /// <summary>The mask's coefficient count <c>perVariableDegree·d + 1</c> (the sum-of-univariates basis at the masked round's degree).</summary>
    public int MaskCoefficientCount { get; }

    /// <summary>The committed coefficient multilinear's variable count <c>ℓ₂</c>; the vector is <c>2^ℓ₂</c> wide.</summary>
    public int CoefficientVariableCount { get; }

    /// <summary>The dimension lift <c>t_C</c> the coefficient commitment carries (its bounded-independence hiding budget).</summary>
    public int ExtraVariableCount { get; }


    internal StatisticalMaskParameters(int sumcheckVariableCount, int maskCoefficientCount, int coefficientVariableCount, int extraVariableCount)
    {
        SumcheckVariableCount = sumcheckVariableCount;
        MaskCoefficientCount = maskCoefficientCount;
        CoefficientVariableCount = coefficientVariableCount;
        ExtraVariableCount = extraVariableCount;
    }


    /// <summary>The committed vector's total coordinate count <c>2^ℓ₂</c>.</summary>
    public int CoefficientCount => 1 << CoefficientVariableCount;

    /// <summary>The filler coordinate count: every coordinate beyond the mask coefficients is laundering entropy with an all-ones weight.</summary>
    public int FillerCount => CoefficientCount - MaskCoefficientCount;

    /// <summary>The lifted variable count <c>ℓ₂ + t_C</c> — the coefficient commitment's code layer count and the weighted opening's round count.</summary>
    public int LiftedVariableCount => CoefficientVariableCount + ExtraVariableCount;


    /// <inheritdoc/>
    public bool Equals(StatisticalMaskParameters other) =>
        SumcheckVariableCount == other.SumcheckVariableCount
        && MaskCoefficientCount == other.MaskCoefficientCount
        && CoefficientVariableCount == other.CoefficientVariableCount
        && ExtraVariableCount == other.ExtraVariableCount;

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is StatisticalMaskParameters other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => HashCode.Combine(SumcheckVariableCount, MaskCoefficientCount, CoefficientVariableCount, ExtraVariableCount);

    /// <summary>Equality operator.</summary>
    public static bool operator ==(StatisticalMaskParameters left, StatisticalMaskParameters right) => left.Equals(right);

    /// <summary>Inequality operator.</summary>
    public static bool operator !=(StatisticalMaskParameters left, StatisticalMaskParameters right) => !left.Equals(right);
}
