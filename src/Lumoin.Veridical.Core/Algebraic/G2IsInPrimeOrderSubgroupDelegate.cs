using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Reports whether a candidate G2 point lies in the prime-order
/// subgroup of the curve identified by <paramref name="curve"/>.
/// </summary>
/// <param name="point">The candidate in canonical compressed byte layout.</param>
/// <param name="curve">Identifies the curve.</param>
/// <returns><see langword="true"/> when the point is in the prime-order subgroup.</returns>
/// <remarks>
/// The BLS12-381 G2 cofactor is non-trivial; on-curve points are not
/// automatically in the prime-order subgroup. A standard check is
/// <c>[r] · P == identity</c> where <c>r</c> is the scalar-field
/// order, but optimised backends use the Bowe / Wahby endomorphism
/// trick to avoid the full scalar multiplication.
/// </remarks>
public delegate bool G2IsInPrimeOrderSubgroupDelegate(
    ReadOnlySpan<byte> point,
    CurveParameterSet curve);