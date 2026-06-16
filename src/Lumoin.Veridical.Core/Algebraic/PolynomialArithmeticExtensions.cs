using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Extension members on <see cref="Polynomial"/> that produce a new
/// polynomial or scalar by dispatching to a BLS12-381 backend delegate.
/// </summary>
/// <remarks>
/// <para>
/// Same bridge pattern as
/// <see cref="MultilinearExtensionArithmeticExtensions"/>, and likewise
/// curve-broad: the receiver polynomial's <see cref="Polynomial.Curve"/>
/// is threaded through the backend delegate and into the result's tag,
/// and a guard rejects curves that are not yet wired (Bls12Curve381,
/// Bn254). Binary verbs additionally require both operands to share a
/// curve. Inputs and outputs typed as <see cref="Scalar"/> carry the
/// curve identity statically.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class PolynomialArithmeticExtensions
{
    extension(Polynomial polynomial)
    {
        /// <summary>
        /// Evaluates the polynomial at <paramref name="point"/>.
        /// </summary>
        /// <param name="point">The evaluation point.</param>
        /// <param name="evaluate">The backend implementation of polynomial evaluation.</param>
        /// <param name="pool">The pool to rent the destination buffer from.</param>
        /// <returns>A scalar wrapping the evaluation result.</returns>
        /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">When the receiver's <see cref="Polynomial.Curve"/> is not BLS12-381.</exception>
        public Scalar Evaluate(
            Scalar point,
            PolynomialEvaluateDelegate evaluate,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(polynomial);
            ArgumentNullException.ThrowIfNull(point);
            ArgumentNullException.ThrowIfNull(evaluate);
            ArgumentNullException.ThrowIfNull(pool);

            WellKnownCurves.ThrowIfCurveNotWired(polynomial.Curve);

            int elementSize = polynomial.FieldElementSizeBytes;
            IMemoryOwner<byte> owner = pool.Rent(elementSize);
            evaluate(
                polynomial.AsReadOnlySpan(),
                point.AsReadOnlySpan(),
                owner.Memory.Span[..elementSize],
                polynomial.Degree,
                polynomial.Curve);

            return new Scalar(owner, polynomial.Curve, WellKnownAlgebraicTags.ScalarFor(polynomial.Curve));
        }


        /// <summary>
        /// Returns the coefficient-wise sum of this polynomial and
        /// <paramref name="other"/>.
        /// </summary>
        /// <param name="other">The right-hand polynomial; must have the same storage degree as the receiver.</param>
        /// <param name="add">The backend implementation of polynomial addition.</param>
        /// <param name="pool">The pool to rent the destination buffer from.</param>
        /// <returns>A polynomial wrapping the coefficient-wise sum, with storage degree equal to both inputs'.</returns>
        /// <exception cref="ArgumentException">When the receiver is not over BLS12-381, when <paramref name="other"/>'s curve does not match, or when storage degrees differ.</exception>
        public Polynomial Add(
            Polynomial other,
            PolynomialAddDelegate add,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(polynomial);
            ArgumentNullException.ThrowIfNull(other);
            ArgumentNullException.ThrowIfNull(add);
            ArgumentNullException.ThrowIfNull(pool);

            WellKnownCurves.ThrowIfCurveNotWired(polynomial.Curve);
            WellKnownCurves.ThrowIfCurveNotWired(other.Curve);
            WellKnownCurves.ThrowIfCurvesDiffer(polynomial.Curve, other.Curve);
            if(polynomial.Degree != other.Degree)
            {
                throw new ArgumentException(
                    $"Polynomial addition requires equal storage degrees; received {polynomial.Degree} and {other.Degree}. Pad the shorter operand with zero coefficients before calling.",
                    nameof(other));
            }

            int elementSize = polynomial.FieldElementSizeBytes;
            int bufferSize = (polynomial.Degree + 1) * elementSize;

            IMemoryOwner<byte> owner = pool.Rent(bufferSize);
            add(
                polynomial.AsReadOnlySpan(),
                other.AsReadOnlySpan(),
                owner.Memory.Span[..bufferSize],
                polynomial.Degree,
                polynomial.Curve);

            Tag tag = Tag.Create(
                (typeof(AlgebraicRole), (object)AlgebraicRole.PolynomialCoefficients),
                (typeof(CurveParameterSet), (object)polynomial.Curve),
                (typeof(PolynomialDegree), (object)new PolynomialDegree(polynomial.Degree)));

            return new Polynomial(owner, polynomial.Degree, elementSize, polynomial.Curve, tag);
        }


        /// <summary>
        /// Returns the polynomial product. Storage degree of the result
        /// equals <c>this.Degree + other.Degree</c>.
        /// </summary>
        /// <param name="other">The right-hand polynomial.</param>
        /// <param name="multiply">The backend implementation of polynomial multiplication.</param>
        /// <param name="pool">The pool to rent the destination buffer from.</param>
        /// <returns>A polynomial wrapping the canonical-form product.</returns>
        /// <exception cref="ArgumentException">When either polynomial is not over BLS12-381.</exception>
        public Polynomial Multiply(
            Polynomial other,
            PolynomialMultiplyDelegate multiply,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(polynomial);
            ArgumentNullException.ThrowIfNull(other);
            ArgumentNullException.ThrowIfNull(multiply);
            ArgumentNullException.ThrowIfNull(pool);

            WellKnownCurves.ThrowIfCurveNotWired(polynomial.Curve);
            WellKnownCurves.ThrowIfCurveNotWired(other.Curve);
            WellKnownCurves.ThrowIfCurvesDiffer(polynomial.Curve, other.Curve);

            int elementSize = polynomial.FieldElementSizeBytes;
            int productDegree = polynomial.Degree + other.Degree;
            int bufferSize = (productDegree + 1) * elementSize;

            IMemoryOwner<byte> owner = pool.Rent(bufferSize);
            multiply(
                polynomial.AsReadOnlySpan(),
                polynomial.Degree,
                other.AsReadOnlySpan(),
                other.Degree,
                owner.Memory.Span[..bufferSize],
                polynomial.Curve);

            Tag tag = Tag.Create(
                (typeof(AlgebraicRole), (object)AlgebraicRole.PolynomialCoefficients),
                (typeof(CurveParameterSet), (object)polynomial.Curve),
                (typeof(PolynomialDegree), (object)new PolynomialDegree(productDegree)));

            return new Polynomial(owner, productDegree, elementSize, polynomial.Curve, tag);
        }
    }
}