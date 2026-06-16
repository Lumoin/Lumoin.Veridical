using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Reports whether a candidate G2 point's canonical compressed bytes
/// represent a point on the curve identified by
/// <paramref name="curve"/> (the twisted curve
/// <c>y² = x³ + 4·(1 + u)</c> over Fp2 for BLS12-381).
/// </summary>
/// <param name="point">The candidate in canonical compressed byte layout.</param>
/// <param name="curve">Identifies the curve.</param>
/// <returns><see langword="true"/> when the point lies on the curve.</returns>
/// <remarks>
/// On-curve membership is a separate check from prime-order subgroup
/// membership; see <see cref="G2IsInPrimeOrderSubgroupDelegate"/>.
/// </remarks>
public delegate bool G2IsOnCurveDelegate(
    ReadOnlySpan<byte> point,
    CurveParameterSet curve);