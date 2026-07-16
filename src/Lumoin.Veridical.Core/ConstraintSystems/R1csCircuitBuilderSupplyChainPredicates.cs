using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// Named supply-chain predicate generators for <see cref="R1csCircuitBuilder"/>:
/// a measured quantity at least, or at most, a public bound, and a
/// battery-passport bundle of such claims. Each is expressed over the existing
/// predicate primitives (a domain range check plus an ordering check) — no new op
/// types. The bound is a <see cref="FixedPointBound"/>: a constant baked into the
/// circuit id, or a public-input variable the verifier supplies. Each returns the
/// builder for chaining.
/// </summary>
/// <remarks>
/// <para>
/// A one-sided threshold check over an untrusted witness is unsound on its own in
/// the at-most direction: a measured value bound to the field element just below
/// the modulus reads as a small positive difference and clears a bare cap check.
/// Both predicates therefore also range-check the measured value into
/// <c>[0, 2^Bits)</c> (auxiliaries under <c>{name}_domain</c>), the width the
/// <see cref="FixedPointDomain"/> sizes so no false difference can wrap the field.
/// The symmetric domain check makes the soundness argument independent of the
/// operands' magnitudes and of which curve compiles the circuit.
/// </para>
/// <para>
/// A constant bound is validated at compile time to lie within the exact domain
/// maximum; a public-input bound is range-checked in-circuit into the field-safe
/// width <c>[0, 2^Bits)</c> (auxiliaries under <c>{name}_bound</c>) — enough to keep
/// the difference from wrapping, though not clamped to the exact maximum the way a
/// constant is. Every value a comparison mixes passes through one
/// <see cref="FixedPointDomain"/>, so nothing enters at a mismatched scale.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class R1csCircuitBuilderSupplyChainPredicates
{
    extension(R1csCircuitBuilder builder)
    {
        /// <summary>
        /// Asserts the measured quantity <paramref name="measured"/> is at least
        /// <paramref name="threshold"/>. Emits a domain range check on
        /// <paramref name="measured"/> (<c>domain.Bits</c> boolean auxiliaries
        /// under <c>{name}_domain</c> plus one summation), a range check on a
        /// public-input threshold (a further <c>domain.Bits</c> under
        /// <c>{name}_bound</c>; none for a constant threshold), and an
        /// <see cref="R1csCircuitBuilderPredicates.AssertGreaterThanOrEqual"/> of
        /// the measured value over the threshold (a further <c>domain.Bits</c>
        /// under <paramref name="name"/> plus one summation). The caller binds the
        /// auxiliaries with
        /// <see cref="R1csSupplyChainWitness.AddQuantityAtLeastBindings"/>.
        /// </summary>
        /// <returns>The builder, for chaining.</returns>
        /// <exception cref="ArgumentException">When <paramref name="name"/> is null or empty.</exception>
        public R1csCircuitBuilder AssertQuantityAtLeast(R1csLinearCombination measured, FixedPointBound threshold, string name)
        {
            ArgumentNullException.ThrowIfNull(builder);
            ArgumentNullException.ThrowIfNull(measured);
            ArgumentException.ThrowIfNullOrEmpty(name);

            builder.AssertRangeCheck(measured, threshold.Domain.Bits, $"{name}_domain");
            R1csLinearCombination bound = ResolveBound(builder, threshold, name);

            return builder.AssertGreaterThanOrEqual(measured, bound, threshold.Domain.Bits, name);
        }


        /// <summary>
        /// Asserts the measured quantity <paramref name="measured"/> is at most
        /// <paramref name="cap"/>. Emits a domain range check on
        /// <paramref name="measured"/>, a range check on a public-input cap (none
        /// for a constant cap), and an
        /// <see cref="R1csCircuitBuilderPredicates.AssertLessThanOrEqual"/> of the
        /// measured value under the cap. The measured domain range check is
        /// load-bearing here — it rejects a measured value bound near the field
        /// modulus that would otherwise clear a bare cap check. The caller binds
        /// the auxiliaries with
        /// <see cref="R1csSupplyChainWitness.AddQuantityAtMostBindings"/>.
        /// </summary>
        /// <returns>The builder, for chaining.</returns>
        /// <exception cref="ArgumentException">When <paramref name="name"/> is null or empty.</exception>
        public R1csCircuitBuilder AssertQuantityAtMost(R1csLinearCombination measured, FixedPointBound cap, string name)
        {
            ArgumentNullException.ThrowIfNull(builder);
            ArgumentNullException.ThrowIfNull(measured);
            ArgumentException.ThrowIfNullOrEmpty(name);

            builder.AssertRangeCheck(measured, cap.Domain.Bits, $"{name}_domain");
            R1csLinearCombination bound = ResolveBound(builder, cap, name);

            return builder.AssertLessThanOrEqual(measured, bound, cap.Domain.Bits, name);
        }


        /// <summary>
        /// Asserts every claim in <paramref name="claims"/>. The battery-passport
        /// shape is the conjunction, so the bundle proves only when all claims
        /// hold. Each claim contributes its own <c>{name}_domain</c>,
        /// <c>{name}</c>, and (for a public-input bound) <c>{name}_bound</c>
        /// auxiliaries; claim names must be distinct <em>and</em> none may extend
        /// another with a reserved suffix (<c>_domain</c>, <c>_bound</c>,
        /// <c>_bit_</c>), so those derived names do not collide. Each claim
        /// dispatches to <see cref="AssertQuantityAtLeast"/> or
        /// <see cref="AssertQuantityAtMost"/> on its measured variable.
        /// </summary>
        /// <returns>The builder, for chaining.</returns>
        /// <exception cref="ArgumentException">When <paramref name="claims"/> is empty, two claims share a name, or one claim name extends another by a reserved auxiliary suffix.</exception>
        public R1csCircuitBuilder AssertBatteryPassport(ReadOnlySpan<SupplyChainClaim> claims)
        {
            ArgumentNullException.ThrowIfNull(builder);
            if(claims.Length == 0)
            {
                throw new ArgumentException("A battery passport must bundle at least one claim.", nameof(claims));
            }

            ThrowIfNamesNotDistinct(claims);

            foreach(SupplyChainClaim claim in claims)
            {
                R1csLinearCombination measured = R1csLinearCombination.From(claim.Measured);
                switch(claim.Direction)
                {
                    case SupplyChainDirection.AtLeast:
                        builder.AssertQuantityAtLeast(measured, claim.Bound, claim.Name);
                        break;
                    case SupplyChainDirection.AtMost:
                        builder.AssertQuantityAtMost(measured, claim.Bound, claim.Name);
                        break;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(claims), claim.Direction, "Unknown supply-chain direction.");
                }
            }

            return builder;
        }
    }


    //Resolves a bound to the linear combination the ordering check compares against:
    //a constant term for a baked bound (known in-domain at compile time), or the
    //public-input variable range-checked into the domain (so a public bound carries
    //the same in-domain guarantee a constant does).
    private static R1csLinearCombination ResolveBound(R1csCircuitBuilder builder, FixedPointBound bound, string name)
    {
        if(bound.PublicInputVariable is R1csVariableIndex variable)
        {
            R1csLinearCombination boundValue = R1csLinearCombination.From(variable);
            builder.AssertRangeCheck(boundValue, bound.Domain.Bits, $"{name}_bound");

            return boundValue;
        }

        return R1csLinearCombination.FromConstant(bound.Encode());
    }


    //The reserved suffixes a claim's derived witness names begin with, relative to
    //the claim name: {name}_domain..., {name}_bound..., {name}_bit_.... A claim name
    //that extends another by one of these would produce a colliding derived name.
    private static readonly string[] ReservedAuxiliarySuffixes = ["_domain", "_bound", "_bit_"];


    private static void ThrowIfNamesNotDistinct(ReadOnlySpan<SupplyChainClaim> claims)
    {
        var seen = new HashSet<string>(claims.Length, StringComparer.Ordinal);
        foreach(SupplyChainClaim claim in claims)
        {
            if(!seen.Add(claim.Name))
            {
                throw new ArgumentException($"Duplicate claim name '{claim.Name}'; each claim in a bundle must have a distinct name so its auxiliary witnesses do not collide.", nameof(claims));
            }
        }

        //Distinct names are necessary but not sufficient: a name that extends another
        //by a reserved auxiliary suffix collides on the derived witness variables
        //(for example "carbon" and "carbon_domain" both reach "carbon_domain_bit_0").
        for(int i = 0; i < claims.Length; i++)
        {
            for(int j = 0; j < claims.Length; j++)
            {
                if(i != j && ExtendsByReservedSuffix(claims[j].Name, claims[i].Name))
                {
                    throw new ArgumentException($"Claim names '{claims[i].Name}' and '{claims[j].Name}' collide: one extends the other with a reserved auxiliary suffix ('_domain', '_bound', '_bit_'), so their derived witness variables would clash. Rename one so neither is the other followed by such a suffix.", nameof(claims));
                }
            }
        }
    }


    private static bool ExtendsByReservedSuffix(string candidate, string prefix)
    {
        foreach(string suffix in ReservedAuxiliarySuffixes)
        {
            if(candidate.StartsWith(prefix + suffix, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
