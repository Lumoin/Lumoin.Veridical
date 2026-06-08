using System;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Extension members on <see cref="Polynomial"/> that report on its
/// contents without performing arithmetic.
/// </summary>
/// <remarks>
/// <para>
/// These predicates work exclusively against the public read-only span
/// and the canonical low-degree-first layout. They do not call backend
/// delegates and therefore do not depend on any backend wiring — they
/// are safe to use in debugger displays, assertions, and test helpers
/// without first composing a backend.
/// </para>
/// <para>
/// All predicates walk every byte with an OR-accumulator rather than
/// returning early on the first mismatch, so timing is uniform across
/// inputs.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class PolynomialInspectionExtensions
{
    extension(Polynomial polynomial)
    {
        /// <summary>The storage degree of the polynomial bundled into a value.</summary>
        public PolynomialDegree DegreeValue
        {
            get
            {
                ArgumentNullException.ThrowIfNull(polynomial);

                return new PolynomialDegree(polynomial.Degree);
            }
        }


        /// <summary>
        /// Indicates whether every coefficient is the field zero.
        /// </summary>
        public bool IsZero
        {
            get
            {
                ArgumentNullException.ThrowIfNull(polynomial);

                ReadOnlySpan<byte> bytes = polynomial.AsReadOnlySpan();
                byte accumulator = 0;
                for(int i = 0; i < bytes.Length; i++)
                {
                    accumulator |= bytes[i];
                }


                return accumulator == 0;
            }
        }


        /// <summary>
        /// Indicates whether the polynomial represents a constant —
        /// either it has storage degree zero, or every non-constant
        /// coefficient is the field zero.
        /// </summary>
        /// <remarks>
        /// Algebraic-degree zero is the structural meaning of constant:
        /// the polynomial takes the same value at every point.
        /// Equivalently, only the <c>c_0</c> term is non-zero. Storage
        /// degree may be higher when the polynomial was constructed
        /// with extra coefficient slots that happen to hold zero.
        /// </remarks>
        public bool IsConstant
        {
            get
            {
                ArgumentNullException.ThrowIfNull(polynomial);

                if(polynomial.Degree == 0)
                {
                    return true;
                }

                ReadOnlySpan<byte> bytes = polynomial.AsReadOnlySpan();
                int elementSize = polynomial.FieldElementSizeBytes;
                byte accumulator = 0;
                for(int i = elementSize; i < bytes.Length; i++)
                {
                    accumulator |= bytes[i];
                }


                return accumulator == 0;
            }
        }


        /// <summary>
        /// Indicates whether the polynomial has storage degree exactly one.
        /// </summary>
        /// <remarks>
        /// Storage-degree-based predicate; an algebraically linear
        /// polynomial may have higher storage degree if it was
        /// constructed with zero leading coefficients. Inspection
        /// reports the structural fact; consumers who want algebraic
        /// linearity compose <c>!IsConstant</c> with a check that
        /// every coefficient at index 2 and above is zero.
        /// </remarks>
        public bool IsLinear
        {
            get
            {
                ArgumentNullException.ThrowIfNull(polynomial);

                return polynomial.Degree == 1;
            }
        }
    }
}