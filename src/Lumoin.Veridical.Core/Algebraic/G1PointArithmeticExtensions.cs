using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Extension members on <see cref="G1Point"/> that produce a new G1 point —
/// or a yes-or-no answer — by dispatching to a backend-supplied delegate.
/// </summary>
/// <remarks>
/// <para>
/// Arithmetic operations have the same shape as their scalar counterparts:
/// rent a destination buffer, hand the operands' read-only spans and the
/// destination's writable span to the delegate, and wrap the destination in a
/// fresh <see cref="G1Point"/> over the receiver's curve. Binary operations
/// assert that both operands share a curve before dispatching — the runtime
/// check that replaces the compile-time guarantee the per-curve leaf types
/// used to give.
/// </para>
/// <para>
/// Validation operations return <see cref="bool"/> directly from the delegate.
/// Every arithmetic result reuses the per-curve cached tag from
/// <see cref="WellKnownAlgebraicTags.G1PointFor"/> by reference.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class G1PointArithmeticExtensions
{
    extension(G1Point p)
    {
        /// <summary>
        /// Returns <c>p + q</c> in the G1 group.
        /// </summary>
        /// <param name="q">The right-hand operand.</param>
        /// <param name="add">The backend implementation of G1 point addition.</param>
        /// <param name="pool">The pool to rent the destination buffer from.</param>
        /// <returns>A G1 point wrapping a freshly rented buffer that holds the canonical compressed sum.</returns>
        /// <exception cref="ArgumentException">When the operands are on different curves.</exception>
        public G1Point Add(
            G1Point q,
            G1AddDelegate add,
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

            return new G1Point(owner, p.Curve, WellKnownAlgebraicTags.G1PointFor(p.Curve));
        }


        /// <summary>
        /// Returns <c>-p</c> in the G1 group.
        /// </summary>
        /// <param name="negate">The backend implementation of G1 point negation.</param>
        /// <param name="pool">The pool to rent the destination buffer from.</param>
        /// <returns>A G1 point wrapping a freshly rented buffer that holds the canonical compressed additive inverse.</returns>
        public G1Point Negate(
            G1NegateDelegate negate,
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

            return new G1Point(owner, p.Curve, WellKnownAlgebraicTags.G1PointFor(p.Curve));
        }


        /// <summary>
        /// Returns <c>[scalar] p</c> in the G1 group.
        /// </summary>
        /// <param name="scalar">The scalar factor.</param>
        /// <param name="multiply">The backend implementation of G1 scalar multiplication.</param>
        /// <param name="pool">The pool to rent the destination buffer from.</param>
        /// <returns>A G1 point wrapping a freshly rented buffer that holds the canonical compressed scalar multiple.</returns>
        /// <exception cref="ArgumentException">When the point and scalar are over different curves.</exception>
        public G1Point ScalarMultiply(
            Scalar scalar,
            G1ScalarMultiplyDelegate multiply,
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

            return new G1Point(owner, p.Curve, WellKnownAlgebraicTags.G1PointFor(p.Curve));
        }


        /// <summary>
        /// Determines whether <c>p</c>'s affine coordinates satisfy the curve
        /// equation.
        /// </summary>
        /// <param name="isOnCurve">The backend implementation of on-curve validation.</param>
        /// <returns><see langword="true"/> if the encoded coordinates lie on the curve; otherwise <see langword="false"/>.</returns>
        /// <remarks>
        /// On-curve membership is necessary but not sufficient for an untrusted
        /// point: a curve with a non-trivial cofactor admits on-curve points
        /// outside the prime-order subgroup. Pair this with
        /// <see cref="IsInPrimeOrderSubgroup"/> before treating a deserialised
        /// point as a cryptographic input.
        /// </remarks>
        public bool IsOnCurve(G1IsOnCurveDelegate isOnCurve)
        {
            ArgumentNullException.ThrowIfNull(p);
            ArgumentNullException.ThrowIfNull(isOnCurve);

            return isOnCurve(p.AsReadOnlySpan(), p.Curve);
        }


        /// <summary>
        /// Determines whether <c>p</c> lies in the prime-order subgroup of G1.
        /// </summary>
        /// <param name="check">The backend implementation of prime-order subgroup membership.</param>
        /// <returns><see langword="true"/> if <c>[r] p</c> is the identity; otherwise <see langword="false"/>.</returns>
        /// <remarks>
        /// The caller is responsible for first verifying on-curve membership via
        /// <see cref="IsOnCurve"/>; behaviour on input that is not on the curve
        /// is backend-defined.
        /// </remarks>
        public bool IsInPrimeOrderSubgroup(G1IsInPrimeOrderSubgroupDelegate check)
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
                $"Cannot combine G1 operands over different curves: {left} and {right}.");
        }
    }
}