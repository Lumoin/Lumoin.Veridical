using System;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// Predicate generators for <see cref="R1csCircuitBuilder"/>: equality,
/// boolean-ness, range, ordering, and set membership. Each is built from the
/// declaration extensions (<c>AddConstraint</c> plus, where it needs them,
/// <c>DeclareIntermediateVariable</c>) — predicates are generators that emit
/// the existing op set, not new op types — and each returns the builder for
/// chaining.
/// </summary>
/// <remarks>
/// <para>
/// Predicates that introduce auxiliary variables take a <c>name</c> prefix
/// and declare their auxiliaries under deterministic derived names; the
/// caller must bind those names at compile time (the builder does not
/// auto-compute auxiliary values). Each predicate's summary documents its
/// constraint count, the auxiliaries it introduces, and the binding the
/// caller must supply. Calling the same aux-introducing predicate twice with
/// the same <c>name</c> collides on the derived names and throws — give each
/// use a distinct name.
/// </para>
/// <para>
/// Coefficients and constants are <see cref="BigInteger"/>; reduction modulo
/// the scalar field happens at compile time, so the predicates are
/// curve-agnostic.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class R1csCircuitBuilderPredicates
{
    //The largest bit width a range check accepts. Both wired curves have a
    //~254-bit scalar field, so 2^253 < r and the range semantics hold without
    //modular wraparound for any width up to this bound.
    private const int MaximumRangeCheckBits = 253;


    extension(R1csCircuitBuilder builder)
    {
        /// <summary>
        /// Asserts <paramref name="left"/> equals <paramref name="right"/>.
        /// One constraint <c>(left - right) · 1 = 0</c>; no auxiliary variables.
        /// </summary>
        /// <returns>The builder, for chaining.</returns>
        public R1csCircuitBuilder AssertEqual(R1csLinearCombination left, R1csLinearCombination right)
        {
            ArgumentNullException.ThrowIfNull(builder);
            ArgumentNullException.ThrowIfNull(left);
            ArgumentNullException.ThrowIfNull(right);

            return builder.AddConstraint(left - right, One, R1csLinearCombination.Zero);
        }


        /// <summary>
        /// Asserts <paramref name="left"/> does not equal <paramref name="right"/>.
        /// One constraint <c>(left - right) · inverse = 1</c> with one auxiliary
        /// witness variable <c>{name}_inverse</c>. The caller must bind
        /// <c>{name}_inverse</c> to <c>(left - right)^(-1) mod r</c>; no inverse
        /// exists when the two are equal, which is exactly what makes the
        /// predicate unsatisfiable in that case.
        /// </summary>
        /// <returns>The builder, for chaining.</returns>
        public R1csCircuitBuilder AssertNotEqual(R1csLinearCombination left, R1csLinearCombination right, string name)
        {
            ArgumentNullException.ThrowIfNull(builder);
            ArgumentNullException.ThrowIfNull(left);
            ArgumentNullException.ThrowIfNull(right);
            ArgumentException.ThrowIfNullOrEmpty(name);

            R1csVariableIndex inverse = builder.DeclareIntermediateVariable($"{name}_inverse");

            return builder.AddConstraint(left - right, R1csLinearCombination.From(inverse), One);
        }


        /// <summary>
        /// Asserts <paramref name="value"/> is 0 or 1. One constraint
        /// <c>value · (1 - value) = 0</c>; no auxiliary variables. The building
        /// block for bit decomposition.
        /// </summary>
        /// <returns>The builder, for chaining.</returns>
        public R1csCircuitBuilder AssertBoolean(R1csLinearCombination value)
        {
            ArgumentNullException.ThrowIfNull(builder);
            ArgumentNullException.ThrowIfNull(value);

            return builder.AddConstraint(value, One - value, R1csLinearCombination.Zero);
        }


        /// <summary>
        /// Asserts <paramref name="value"/> lies in <c>[0, 2^bits)</c>. Introduces
        /// <paramref name="bits"/> auxiliary witness variables
        /// <c>{name}_bit_0 … {name}_bit_{bits-1}</c>, asserts each boolean
        /// (<paramref name="bits"/> constraints), and adds one summation
        /// constraint <c>Σ bit_i · 2^i = value</c> — <c>bits + 1</c> constraints
        /// in total. The caller must bind each <c>{name}_bit_i</c> to bit
        /// <c>i</c> of <paramref name="value"/>.
        /// </summary>
        /// <returns>The builder, for chaining.</returns>
        public R1csCircuitBuilder AssertRangeCheck(R1csLinearCombination value, int bits, string name)
        {
            ArgumentNullException.ThrowIfNull(builder);
            ArgumentNullException.ThrowIfNull(value);
            ArgumentException.ThrowIfNullOrEmpty(name);
            ArgumentOutOfRangeException.ThrowIfLessThan(bits, 1);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(bits, MaximumRangeCheckBits);

            R1csLinearCombination sum = R1csLinearCombination.Zero;
            for(int i = 0; i < bits; i++)
            {
                R1csVariableIndex bit = builder.DeclareIntermediateVariable($"{name}_bit_{i}");
                builder.AssertBoolean(R1csLinearCombination.From(bit));
                sum += (BigInteger.One << i) * R1csLinearCombination.From(bit);
            }

            return builder.AddConstraint(sum, One, value);
        }


        /// <summary>
        /// Asserts <paramref name="left"/> ≤ <paramref name="right"/>, by range-
        /// checking their difference: <c>right - left ∈ [0, 2^bits)</c>. Both
        /// values must be small enough that the true difference is non-negative
        /// and fits in <paramref name="bits"/> bits. Introduces the same
        /// auxiliaries as <see cref="AssertRangeCheck"/> on the difference, under
        /// <paramref name="name"/>.
        /// </summary>
        /// <returns>The builder, for chaining.</returns>
        public R1csCircuitBuilder AssertLessThanOrEqual(R1csLinearCombination left, R1csLinearCombination right, int bits, string name)
        {
            ArgumentNullException.ThrowIfNull(builder);
            ArgumentNullException.ThrowIfNull(left);
            ArgumentNullException.ThrowIfNull(right);

            return builder.AssertRangeCheck(right - left, bits, name);
        }


        /// <summary>
        /// Asserts <paramref name="left"/> ≥ <paramref name="right"/>, i.e.
        /// <see cref="AssertLessThanOrEqual"/> with the operands swapped
        /// (<c>left - right ∈ [0, 2^bits)</c>).
        /// </summary>
        /// <returns>The builder, for chaining.</returns>
        public R1csCircuitBuilder AssertGreaterThanOrEqual(R1csLinearCombination left, R1csLinearCombination right, int bits, string name)
        {
            ArgumentNullException.ThrowIfNull(builder);
            ArgumentNullException.ThrowIfNull(left);
            ArgumentNullException.ThrowIfNull(right);

            return builder.AssertLessThanOrEqual(right, left, bits, name);
        }


        /// <summary>
        /// Asserts <paramref name="value"/> equals one of <paramref name="set"/>,
        /// by requiring the product <c>Π (value - sᵢ) = 0</c>. The product is
        /// chained through two-input multiplications: for a set of <c>n</c>
        /// elements there are <c>n - 1</c> constraints and <c>max(0, n - 2)</c>
        /// auxiliary witness variables <c>{name}_product_1 … {name}_product_{n-2}</c>,
        /// where <c>{name}_product_k = Π_{j=0}^{k} (value - set[j])</c>. The caller
        /// must bind each. A single-element set reduces to one equality
        /// constraint with no auxiliaries; an empty set is rejected (membership
        /// in the empty set is unsatisfiable).
        /// </summary>
        /// <returns>The builder, for chaining.</returns>
        public R1csCircuitBuilder AssertInSet(R1csLinearCombination value, ReadOnlySpan<BigInteger> set, string name)
        {
            ArgumentNullException.ThrowIfNull(builder);
            ArgumentNullException.ThrowIfNull(value);
            ArgumentException.ThrowIfNullOrEmpty(name);

            if(set.Length == 0)
            {
                throw new ArgumentException("Membership set must be non-empty; nothing can belong to the empty set.", nameof(set));
            }

            R1csLinearCombination accumulator = value - R1csLinearCombination.FromConstant(set[0]);

            if(set.Length == 1)
            {
                //x = s_0.
                return builder.AddConstraint(accumulator, One, R1csLinearCombination.Zero);
            }

            for(int i = 1; i < set.Length; i++)
            {
                R1csLinearCombination factor = value - R1csLinearCombination.FromConstant(set[i]);
                if(i == set.Length - 1)
                {
                    //Final factor: the whole product must be zero.
                    builder.AddConstraint(accumulator, factor, R1csLinearCombination.Zero);
                }
                else
                {
                    R1csVariableIndex partialProduct = builder.DeclareIntermediateVariable($"{name}_product_{i}");
                    builder.AddConstraint(accumulator, factor, R1csLinearCombination.From(partialProduct));
                    accumulator = R1csLinearCombination.From(partialProduct);
                }
            }

            return builder;
        }
    }


    private static R1csLinearCombination One => R1csLinearCombination.FromConstant(BigInteger.One);
}
