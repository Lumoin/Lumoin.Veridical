using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Extension members on <see cref="Scalar"/> that produce a new scalar by
/// dispatching to a backend-supplied delegate.
/// </summary>
/// <remarks>
/// <para>
/// Every operation has the same shape: rent a destination buffer from the
/// pool, hand the operands' read-only spans and the destination's writable
/// span to the supplied delegate, and wrap the destination buffer in a fresh
/// <see cref="Scalar"/> over the receiver's curve. The delegate is responsible
/// for producing a reduced canonical-form result; this extension class neither
/// validates the reduction nor stamps provenance per call. Provenance is a
/// boundary concern stamped by entropy and hash-to-field producers, not by
/// inner-loop arithmetic.
/// </para>
/// <para>
/// The <see cref="CurveParameterSet"/> passed to each delegate is the
/// receiver's <see cref="Scalar.Curve"/>. Binary operations assert that both
/// operands share a curve before dispatching — this runtime check replaces
/// the compile-time guarantee the per-curve leaf types used to provide, and
/// the thrown message names both curves so a stack trace identifies the bug.
/// </para>
/// <para>
/// Every result reuses the per-curve cached tag from
/// <see cref="WellKnownAlgebraicTags.ScalarFor"/> by reference. The only
/// allocation per arithmetic call is the pool-rented destination buffer; the
/// tag is shared.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class ScalarArithmeticExtensions
{
    extension(Scalar a)
    {
        /// <summary>
        /// Returns <c>a + b mod r</c>.
        /// </summary>
        /// <param name="b">The right-hand operand.</param>
        /// <param name="add">The backend implementation of scalar addition.</param>
        /// <param name="pool">The pool to rent the destination buffer from.</param>
        /// <returns>A scalar wrapping a freshly rented buffer that holds the canonical big-endian sum.</returns>
        /// <exception cref="ArgumentException">When the operands are over different curves.</exception>
        public Scalar Add(
            Scalar b,
            ScalarAddDelegate add,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(b);
            ArgumentNullException.ThrowIfNull(add);
            ArgumentNullException.ThrowIfNull(pool);
            ThrowIfCurveMismatch(a, b);

            IMemoryOwner<byte> owner = pool.Rent(Scalar.SizeBytes);
            add(
                a.AsReadOnlySpan(),
                b.AsReadOnlySpan(),
                owner.Memory.Span[..Scalar.SizeBytes],
                a.Curve);

            return new Scalar(owner, a.Curve, WellKnownAlgebraicTags.ScalarFor(a.Curve));
        }


        /// <summary>
        /// Returns <c>a - b mod r</c>.
        /// </summary>
        /// <param name="b">The right-hand operand to subtract from <c>a</c>.</param>
        /// <param name="subtract">The backend implementation of scalar subtraction.</param>
        /// <param name="pool">The pool to rent the destination buffer from.</param>
        /// <returns>A scalar wrapping a freshly rented buffer that holds the canonical big-endian difference.</returns>
        /// <exception cref="ArgumentException">When the operands are over different curves.</exception>
        public Scalar Subtract(
            Scalar b,
            ScalarSubtractDelegate subtract,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(b);
            ArgumentNullException.ThrowIfNull(subtract);
            ArgumentNullException.ThrowIfNull(pool);
            ThrowIfCurveMismatch(a, b);

            IMemoryOwner<byte> owner = pool.Rent(Scalar.SizeBytes);
            subtract(
                a.AsReadOnlySpan(),
                b.AsReadOnlySpan(),
                owner.Memory.Span[..Scalar.SizeBytes],
                a.Curve);

            return new Scalar(owner, a.Curve, WellKnownAlgebraicTags.ScalarFor(a.Curve));
        }


        /// <summary>
        /// Returns <c>a * b mod r</c>.
        /// </summary>
        /// <param name="b">The right-hand operand.</param>
        /// <param name="multiply">The backend implementation of scalar multiplication.</param>
        /// <param name="pool">The pool to rent the destination buffer from.</param>
        /// <returns>A scalar wrapping a freshly rented buffer that holds the canonical big-endian product.</returns>
        /// <exception cref="ArgumentException">When the operands are over different curves.</exception>
        public Scalar Multiply(
            Scalar b,
            ScalarMultiplyDelegate multiply,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(b);
            ArgumentNullException.ThrowIfNull(multiply);
            ArgumentNullException.ThrowIfNull(pool);
            ThrowIfCurveMismatch(a, b);

            IMemoryOwner<byte> owner = pool.Rent(Scalar.SizeBytes);
            multiply(
                a.AsReadOnlySpan(),
                b.AsReadOnlySpan(),
                owner.Memory.Span[..Scalar.SizeBytes],
                a.Curve);

            return new Scalar(owner, a.Curve, WellKnownAlgebraicTags.ScalarFor(a.Curve));
        }


        /// <summary>
        /// Returns <c>-a mod r</c>.
        /// </summary>
        /// <param name="negate">The backend implementation of scalar negation.</param>
        /// <param name="pool">The pool to rent the destination buffer from.</param>
        /// <returns>A scalar wrapping a freshly rented buffer that holds the canonical big-endian additive inverse.</returns>
        public Scalar Negate(
            ScalarNegateDelegate negate,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(negate);
            ArgumentNullException.ThrowIfNull(pool);

            IMemoryOwner<byte> owner = pool.Rent(Scalar.SizeBytes);
            negate(
                a.AsReadOnlySpan(),
                owner.Memory.Span[..Scalar.SizeBytes],
                a.Curve);

            return new Scalar(owner, a.Curve, WellKnownAlgebraicTags.ScalarFor(a.Curve));
        }


        /// <summary>
        /// Returns <c>a^(-1) mod r</c> if <c>a</c> is non-zero; otherwise the
        /// behaviour depends on the backend convention. A correct backend
        /// throws or returns a sentinel for a zero input — application code
        /// must check <see cref="ScalarInspectionExtensions.IsZero"/>
        /// before calling this when the value's invertibility is uncertain.
        /// </summary>
        /// <param name="invert">The backend implementation of scalar inversion.</param>
        /// <param name="pool">The pool to rent the destination buffer from.</param>
        /// <returns>A scalar wrapping a freshly rented buffer that holds the canonical big-endian multiplicative inverse.</returns>
        public Scalar Invert(
            ScalarInvertDelegate invert,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(invert);
            ArgumentNullException.ThrowIfNull(pool);

            IMemoryOwner<byte> owner = pool.Rent(Scalar.SizeBytes);
            invert(
                a.AsReadOnlySpan(),
                owner.Memory.Span[..Scalar.SizeBytes],
                a.Curve);

            return new Scalar(owner, a.Curve, WellKnownAlgebraicTags.ScalarFor(a.Curve));
        }
    }


    private static void ThrowIfCurveMismatch(Scalar a, Scalar b)
    {
        if(a.Curve.Code != b.Curve.Code)
        {
            throw new ArgumentException(
                $"Cannot combine Scalars over different curves: {a.Curve} and {b.Curve}.");
        }
    }
}