using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Extension members on <see cref="G2Point"/> that produce a new G2 point —
/// or a yes-or-no answer — by dispatching to a backend-supplied delegate.
/// Parallel to <see cref="G1PointArithmeticExtensions"/>; binary operations
/// assert both operands share a curve before dispatching.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class G2PointArithmeticExtensions
{
    extension(G2Point p)
    {
        /// <summary>
        /// Returns <c>p + q</c> in the G2 group.
        /// </summary>
        /// <param name="q">The right-hand operand.</param>
        /// <param name="add">The backend implementation of G2 point addition.</param>
        /// <param name="pool">The pool to rent the destination buffer from.</param>
        /// <returns>A G2 point wrapping the canonical compressed sum.</returns>
        /// <exception cref="ArgumentException">When the operands are on different curves.</exception>
        public G2Point Add(
            G2Point q,
            G2AddDelegate add,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(p);
            ArgumentNullException.ThrowIfNull(q);
            ArgumentNullException.ThrowIfNull(add);
            ArgumentNullException.ThrowIfNull(pool);
            ThrowIfCurveMismatch(p.Curve, q.Curve);

            int sizeBytes = p.SizeBytes;
            IMemoryOwner<byte> owner = pool.Rent(sizeBytes);
            add(
                p.AsReadOnlySpan(),
                q.AsReadOnlySpan(),
                owner.Memory.Span[..sizeBytes],
                p.Curve);

            return new G2Point(owner, p.Curve, WellKnownAlgebraicTags.G2PointFor(p.Curve));
        }


        /// <summary>
        /// Returns <c>-p</c> in the G2 group.
        /// </summary>
        /// <param name="negate">The backend implementation of G2 point negation.</param>
        /// <param name="pool">The pool to rent the destination buffer from.</param>
        /// <returns>A G2 point wrapping the canonical compressed additive inverse.</returns>
        public G2Point Negate(
            G2NegateDelegate negate,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(p);
            ArgumentNullException.ThrowIfNull(negate);
            ArgumentNullException.ThrowIfNull(pool);

            int sizeBytes = p.SizeBytes;
            IMemoryOwner<byte> owner = pool.Rent(sizeBytes);
            negate(
                p.AsReadOnlySpan(),
                owner.Memory.Span[..sizeBytes],
                p.Curve);

            return new G2Point(owner, p.Curve, WellKnownAlgebraicTags.G2PointFor(p.Curve));
        }


        /// <summary>
        /// Returns <c>[scalar] p</c> in the G2 group.
        /// </summary>
        /// <param name="scalar">The scalar factor.</param>
        /// <param name="multiply">The backend implementation of G2 scalar multiplication.</param>
        /// <param name="pool">The pool to rent the destination buffer from.</param>
        /// <returns>A G2 point wrapping the canonical compressed scalar multiple.</returns>
        /// <exception cref="ArgumentException">When the point and scalar are over different curves.</exception>
        public G2Point ScalarMultiply(
            Scalar scalar,
            G2ScalarMultiplyDelegate multiply,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(p);
            ArgumentNullException.ThrowIfNull(scalar);
            ArgumentNullException.ThrowIfNull(multiply);
            ArgumentNullException.ThrowIfNull(pool);
            ThrowIfCurveMismatch(p.Curve, scalar.Curve);

            int sizeBytes = p.SizeBytes;
            IMemoryOwner<byte> owner = pool.Rent(sizeBytes);
            multiply(
                p.AsReadOnlySpan(),
                scalar.AsReadOnlySpan(),
                owner.Memory.Span[..sizeBytes],
                p.Curve);

            return new G2Point(owner, p.Curve, WellKnownAlgebraicTags.G2PointFor(p.Curve));
        }


        /// <summary>
        /// Determines whether <c>p</c>'s affine coordinates satisfy the G2 curve
        /// equation.
        /// </summary>
        /// <param name="isOnCurve">The backend implementation of on-curve validation.</param>
        /// <returns><see langword="true"/> if the encoded coordinates lie on the curve; otherwise <see langword="false"/>.</returns>
        public bool IsOnCurve(G2IsOnCurveDelegate isOnCurve)
        {
            ArgumentNullException.ThrowIfNull(p);
            ArgumentNullException.ThrowIfNull(isOnCurve);

            return isOnCurve(p.AsReadOnlySpan(), p.Curve);
        }


        /// <summary>
        /// Determines whether <c>p</c> lies in the prime-order subgroup of G2.
        /// </summary>
        /// <param name="check">The backend implementation of prime-order subgroup membership.</param>
        /// <returns><see langword="true"/> if <c>[r] p</c> is the identity; otherwise <see langword="false"/>.</returns>
        public bool IsInPrimeOrderSubgroup(G2IsInPrimeOrderSubgroupDelegate check)
        {
            ArgumentNullException.ThrowIfNull(p);
            ArgumentNullException.ThrowIfNull(check);

            return check(p.AsReadOnlySpan(), p.Curve);
        }
    }


    private static void ThrowIfCurveMismatch(CurveParameterSet left, CurveParameterSet right)
    {
        if(left.Code != right.Code)
        {
            throw new ArgumentException(
                $"Cannot combine G2 operands over different curves: {left} and {right}.");
        }
    }
}