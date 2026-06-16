using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Decides whether the canonical-form encoding in <paramref name="point"/>
/// represents a point in the prime-order subgroup of the curve identified by
/// <paramref name="curve"/>.
/// </summary>
/// <param name="point">The candidate point in canonical compressed byte layout. The caller is responsible for first verifying on-curve membership via <see cref="G1IsOnCurveDelegate"/>; behaviour on input that is not on the curve is backend-defined.</param>
/// <param name="curve">Identifies the curve whose prime-order subgroup is tested.</param>
/// <returns><see langword="true"/> if scalar-multiplying the point by the group order yields the identity; otherwise <see langword="false"/>.</returns>
/// <remarks>
/// <para>
/// BLS12-381 G1 has a non-trivial cofactor
/// <c>h = 0x396c8c005555e1568c00aaab0000aaab</c>, so a point on the curve is
/// not automatically in the prime-order subgroup of order <c>r</c>. The
/// canonical check is <c>[r] P == O</c>; an equivalent endomorphism-based
/// shortcut exists and is preferred for performance-sensitive backends, but
/// the contract observed here is the same yes-or-no answer.
/// </para>
/// <para>
/// Verifiers must reject points outside the prime-order subgroup before
/// using them as cryptographic inputs. Hash-to-curve outputs (per RFC 9380
/// §3) and freshly multiplied points are subgroup members by construction;
/// untrusted serialised points are not.
/// </para>
/// </remarks>
public delegate bool G1IsInPrimeOrderSubgroupDelegate(
    ReadOnlySpan<byte> point,
    CurveParameterSet curve);