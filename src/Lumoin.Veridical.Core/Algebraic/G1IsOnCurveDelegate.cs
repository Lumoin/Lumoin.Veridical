using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Decides whether the canonical-form encoding in <paramref name="point"/>
/// represents a point on the curve identified by <paramref name="curve"/>.
/// </summary>
/// <param name="point">The candidate point in canonical compressed byte layout.</param>
/// <param name="curve">Identifies the curve to test membership against.</param>
/// <returns><see langword="true"/> if the encoded affine coordinates satisfy the curve equation; otherwise <see langword="false"/>.</returns>
/// <remarks>
/// <para>
/// On-curve membership is the first of two validation steps for an
/// untrusted point. The second — prime-order subgroup membership — is a
/// separate check delegated to
/// <see cref="G1IsInPrimeOrderSubgroupDelegate"/> because the cofactor of
/// BLS12-381 G1 is non-trivial: a byte sequence that decodes to a point on
/// the curve is not automatically in the prime-order subgroup. Both checks
/// must pass before an untrusted serialised point is safe to use as a
/// cryptographic input.
/// </para>
/// <para>
/// The identity point trivially satisfies the curve equation; correct
/// backends return <see langword="true"/> for it.
/// </para>
/// </remarks>
public delegate bool G1IsOnCurveDelegate(
    ReadOnlySpan<byte> point,
    CurveParameterSet curve);