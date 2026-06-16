using System;
using System.Collections.Generic;
using System.Numerics;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// Computes the auxiliary input bindings the predicate library's generators
/// need. Each aux-introducing predicate
/// (<see cref="R1csCircuitBuilderPredicates"/>) declares variables under
/// derived names that the caller must bind at compile time; the methods here
/// produce those bindings for concrete values, so a caller does not hand-roll
/// bit decompositions, modular inverses, or partial products.
/// </summary>
/// <remarks>
/// Each method adds its bindings to a supplied dictionary (the one the caller
/// is assembling for <see cref="R1csCircuitInputs"/>), using the same
/// <c>name</c> prefix and naming convention as the matching predicate. Values
/// are reduced modulo the curve's scalar field, matching what the compiler
/// does, so a difference that is negative over the integers is bound as its
/// canonical field representative.
/// </remarks>
public static class R1csPredicateWitness
{
    /// <summary>
    /// Adds the zero bindings for the witness columns that
    /// <see cref="R1csCircuitTransformations.PowerOfTwoPadding"/> introduced —
    /// every variable in <paramref name="paddedCircuit"/> whose name starts with
    /// <see cref="R1csCircuitTransformations.PaddingWitnessNamePrefix"/> is bound
    /// to zero. Call after padding, before compiling.
    /// </summary>
    public static void AddPowerOfTwoPaddingBindings(IDictionary<string, BigInteger> bindings, R1csCircuit paddedCircuit)
    {
        ArgumentNullException.ThrowIfNull(bindings);
        ArgumentNullException.ThrowIfNull(paddedCircuit);

        foreach(R1csVariableMetadata variable in paddedCircuit.Variables)
        {
            if(variable.Name.StartsWith(R1csCircuitTransformations.PaddingWitnessNamePrefix, StringComparison.Ordinal))
            {
                bindings[variable.Name] = BigInteger.Zero;
            }
        }
    }


    /// <summary>
    /// Adds the bit decomposition <c>{name}_bit_0 … {name}_bit_{bits-1}</c> for
    /// <see cref="R1csCircuitBuilderPredicates.AssertRangeCheck"/>, the low
    /// <paramref name="bits"/> bits of <paramref name="value"/> reduced modulo
    /// the field. (An out-of-range value is bound honestly; the predicate's
    /// summation constraint is what then rejects it.)
    /// </summary>
    public static void AddRangeCheckBits(
        IDictionary<string, BigInteger> bindings,
        string name,
        BigInteger value,
        int bits,
        CurveParameterSet curve)
    {
        ArgumentNullException.ThrowIfNull(bindings);
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentOutOfRangeException.ThrowIfLessThan(bits, 1);

        BigInteger reduced = Reduce(value, curve);
        for(int i = 0; i < bits; i++)
        {
            bindings[$"{name}_bit_{i}"] = (reduced >> i) & BigInteger.One;
        }
    }


    /// <summary>
    /// Adds the bits proving <paramref name="left"/> ≤ <paramref name="right"/>
    /// for <see cref="R1csCircuitBuilderPredicates.AssertLessThanOrEqual"/>:
    /// the decomposition of <c>right - left</c> under <paramref name="name"/>.
    /// </summary>
    public static void AddLessThanOrEqualBits(
        IDictionary<string, BigInteger> bindings,
        string name,
        BigInteger left,
        BigInteger right,
        int bits,
        CurveParameterSet curve) =>
        AddRangeCheckBits(bindings, name, right - left, bits, curve);


    /// <summary>
    /// Adds the bits proving <paramref name="left"/> ≥ <paramref name="right"/>
    /// for <see cref="R1csCircuitBuilderPredicates.AssertGreaterThanOrEqual"/>:
    /// the decomposition of <c>left - right</c> under <paramref name="name"/>.
    /// </summary>
    public static void AddGreaterThanOrEqualBits(
        IDictionary<string, BigInteger> bindings,
        string name,
        BigInteger left,
        BigInteger right,
        int bits,
        CurveParameterSet curve) =>
        AddRangeCheckBits(bindings, name, left - right, bits, curve);


    /// <summary>
    /// Adds <c>{name}_inverse</c> for
    /// <see cref="R1csCircuitBuilderPredicates.AssertNotEqual"/>: the modular
    /// inverse of <c>left - right</c>.
    /// </summary>
    /// <exception cref="InvalidOperationException">When <paramref name="left"/> equals <paramref name="right"/> modulo the field — no inverse exists, and the not-equal assertion cannot hold.</exception>
    public static void AddNotEqualInverse(
        IDictionary<string, BigInteger> bindings,
        string name,
        BigInteger left,
        BigInteger right,
        CurveParameterSet curve)
    {
        ArgumentNullException.ThrowIfNull(bindings);
        ArgumentException.ThrowIfNullOrEmpty(name);

        BigInteger order = WellKnownCurves.GetScalarFieldOrder(curve);
        BigInteger difference = Reduce(left - right, curve);
        if(difference.IsZero)
        {
            throw new InvalidOperationException(
                $"Cannot bind '{name}_inverse': the two values are equal modulo the field, so their difference has no inverse and the not-equal assertion cannot be satisfied.");
        }

        bindings[$"{name}_inverse"] = BigInteger.ModPow(difference, order - 2, order);
    }


    /// <summary>
    /// Adds the partial products <c>{name}_product_1 … {name}_product_{n-2}</c>
    /// for <see cref="R1csCircuitBuilderPredicates.AssertInSet"/>, where
    /// <c>{name}_product_k = Π_{j=0}^{k} (value - set[j])</c>. A set with one or
    /// two elements introduces no products, so nothing is added.
    /// </summary>
    public static void AddSetMembershipProducts(
        IDictionary<string, BigInteger> bindings,
        string name,
        BigInteger value,
        ReadOnlySpan<BigInteger> set,
        CurveParameterSet curve)
    {
        ArgumentNullException.ThrowIfNull(bindings);
        ArgumentException.ThrowIfNullOrEmpty(name);
        if(set.Length == 0)
        {
            throw new ArgumentException("Membership set must be non-empty.", nameof(set));
        }

        BigInteger accumulator = Reduce(value - set[0], curve);
        for(int i = 1; i < set.Length - 1; i++)
        {
            accumulator = Reduce(accumulator * Reduce(value - set[i], curve), curve);
            bindings[$"{name}_product_{i}"] = accumulator;
        }
    }


    private static BigInteger Reduce(BigInteger value, CurveParameterSet curve)
    {
        BigInteger order = WellKnownCurves.GetScalarFieldOrder(curve);
        BigInteger remainder = value % order;
        return remainder.Sign < 0 ? remainder + order : remainder;
    }
}
