using System;
using System.Collections.Generic;
using System.Numerics;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>Supplies the raw measured decimal for a named claim; the supply-chain witness helper encodes it at the claim's domain scale.</summary>
public delegate decimal SupplyChainMeasuredValue(string claimName);


/// <summary>
/// Computes the auxiliary bindings the supply-chain predicates need. Like
/// <see cref="R1csPredicateWitness"/> it fills a caller-supplied dictionary under
/// the predicate's naming convention; unlike it, these helpers also bind the
/// measured witness variable itself — encoding the caller's decimal at the
/// domain's scale — so the value a comparison sees cannot be bound at a mismatched
/// scale. The helper owns the measured and auxiliary bindings; for a public-input
/// bound the caller still binds the declared bound variable itself (to
/// <see cref="FixedPointBound.Encode"/>), since a public input is part of the
/// instance the caller assembles.
/// </summary>
/// <remarks>
/// The bit-decomposition math is delegated to <see cref="R1csPredicateWitness"/>,
/// the single source of the field reduction the compiler applies, so an
/// out-of-range measured value is decomposed honestly and rejected by the
/// predicate's own constraints rather than silently masked here.
/// </remarks>
public static class R1csSupplyChainWitness
{
    /// <summary>
    /// Adds the bindings for
    /// <see cref="R1csCircuitBuilderSupplyChainPredicates.AssertQuantityAtLeast"/>:
    /// the measured variable <paramref name="measuredVariableName"/> encoded at the
    /// threshold's domain scale, the domain range-check bits under
    /// <c>{name}_domain</c>, the public-bound range-check bits under
    /// <c>{name}_bound</c> (only when the threshold is a public input), and the
    /// ordering bits under <paramref name="name"/>.
    /// </summary>
    /// <exception cref="ArgumentNullException">When <paramref name="bindings"/> is null.</exception>
    /// <exception cref="ArgumentException">When <paramref name="name"/> or <paramref name="measuredVariableName"/> is null or empty.</exception>
    public static void AddQuantityAtLeastBindings(
        IDictionary<string, BigInteger> bindings,
        string name,
        string measuredVariableName,
        FixedPointBound threshold,
        decimal measured,
        CurveParameterSet curve)
    {
        ArgumentNullException.ThrowIfNull(bindings);
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentException.ThrowIfNullOrEmpty(measuredVariableName);

        FixedPointDomain domain = threshold.Domain;
        BigInteger encodedMeasured = domain.Encode(measured);
        BigInteger encodedThreshold = threshold.Encode();

        bindings[measuredVariableName] = encodedMeasured;
        R1csPredicateWitness.AddRangeCheckBits(bindings, $"{name}_domain", encodedMeasured, domain.Bits, curve);
        if(threshold.IsPublicInput)
        {
            R1csPredicateWitness.AddRangeCheckBits(bindings, $"{name}_bound", encodedThreshold, domain.Bits, curve);
        }

        R1csPredicateWitness.AddGreaterThanOrEqualBits(bindings, name, encodedMeasured, encodedThreshold, domain.Bits, curve);
    }


    /// <summary>
    /// Adds the bindings for
    /// <see cref="R1csCircuitBuilderSupplyChainPredicates.AssertQuantityAtMost"/>:
    /// the measured variable <paramref name="measuredVariableName"/> encoded at the
    /// domain scale, the domain range-check bits under <c>{name}_domain</c>, the
    /// public-bound range-check bits under <c>{name}_bound</c> (only when the cap is
    /// a public input), and the ordering bits under <paramref name="name"/>.
    /// </summary>
    /// <exception cref="ArgumentNullException">When <paramref name="bindings"/> is null.</exception>
    /// <exception cref="ArgumentException">When <paramref name="name"/> or <paramref name="measuredVariableName"/> is null or empty.</exception>
    public static void AddQuantityAtMostBindings(
        IDictionary<string, BigInteger> bindings,
        string name,
        string measuredVariableName,
        FixedPointBound cap,
        decimal measured,
        CurveParameterSet curve)
    {
        ArgumentNullException.ThrowIfNull(bindings);
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentException.ThrowIfNullOrEmpty(measuredVariableName);

        FixedPointDomain domain = cap.Domain;
        BigInteger encodedMeasured = domain.Encode(measured);
        BigInteger encodedCap = cap.Encode();

        bindings[measuredVariableName] = encodedMeasured;
        R1csPredicateWitness.AddRangeCheckBits(bindings, $"{name}_domain", encodedMeasured, domain.Bits, curve);
        if(cap.IsPublicInput)
        {
            R1csPredicateWitness.AddRangeCheckBits(bindings, $"{name}_bound", encodedCap, domain.Bits, curve);
        }

        R1csPredicateWitness.AddLessThanOrEqualBits(bindings, name, encodedMeasured, encodedCap, domain.Bits, curve);
    }


    /// <summary>
    /// Adds the bindings for
    /// <see cref="R1csCircuitBuilderSupplyChainPredicates.AssertBatteryPassport"/>,
    /// dispatching each claim to the at-least or at-most helper. The measured
    /// decimal for each claim comes from <paramref name="measuredValues"/>, keyed by
    /// the claim name, and each claim's name is both its auxiliary prefix and its
    /// measured variable name. Public-input bound variables are the caller's to bind
    /// in the instance.
    /// </summary>
    /// <exception cref="ArgumentNullException">When <paramref name="bindings"/> or <paramref name="measuredValues"/> is null.</exception>
    public static void AddBatteryPassportBindings(
        IDictionary<string, BigInteger> bindings,
        ReadOnlySpan<SupplyChainClaim> claims,
        SupplyChainMeasuredValue measuredValues,
        CurveParameterSet curve)
    {
        ArgumentNullException.ThrowIfNull(bindings);
        ArgumentNullException.ThrowIfNull(measuredValues);

        foreach(SupplyChainClaim claim in claims)
        {
            decimal measured = measuredValues(claim.Name);
            switch(claim.Direction)
            {
                case SupplyChainDirection.AtLeast:
                    AddQuantityAtLeastBindings(bindings, claim.Name, claim.Name, claim.Bound, measured, curve);
                    break;
                case SupplyChainDirection.AtMost:
                    AddQuantityAtMostBindings(bindings, claim.Name, claim.Name, claim.Bound, measured, curve);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(claims), claim.Direction, "Unknown supply-chain direction.");
            }
        }
    }
}
