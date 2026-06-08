using System;

namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// The parameters defining a random foldable linear code instance: the
/// inverse rate, the base-code dimension, the number of foldable layers, and
/// the curve whose scalar field the code is over.
/// </summary>
/// <remarks>
/// <para>
/// Following the random foldable code of Zeilberger, Chen, Fisch (CRYPTO 2024,
/// IACR ePrint 2023/1705, Definition 9): a message of <c>k_d = k0 · 2^d</c>
/// field elements encodes to a codeword of <c>n_d = c · k0 · 2^d</c> elements,
/// so the rate is <c>1/c</c>. The code is built from a <c>[c · k0, k0]</c>
/// maximum-distance-separable base code and <c>d</c> layers of random diagonal
/// folding (the matrices <c>T_0, …, T_{d-1}</c>).
/// </para>
/// <para>
/// The wired configuration is <c>c = 8</c>, <c>k0 = 1</c>, matching the paper's
/// Table 1 rows for cryptographically-sized fields (the BN254 and BLS12-381
/// scalar fields are roughly <c>2^254</c>); the base code is then the
/// <c>[8, 1, 8]</c> repetition code, which is MDS. The number of layers
/// <c>d</c> equals the variable count of the multilinear polynomial being
/// committed (its <c>2^d</c> evaluations are the message).
/// </para>
/// <para>
/// This type fixes only the code's shape. The IOPP query (repetition) count
/// that achieves a target security level derives from the BaseFold IOPP
/// soundness bound and is pinned where the IOPP is implemented, not here — the
/// code construction does not depend on it.
/// </para>
/// </remarks>
public readonly record struct FoldableCodeParameters
{
    /// <summary>The inverse rate <c>c</c>: a codeword is <c>c</c> times the message length, so the rate is <c>1/c</c>.</summary>
    public int InverseRate { get; }

    /// <summary>The base-code dimension <c>k0</c>; the base code is a <c>[c · k0, k0]</c> MDS code.</summary>
    public int BaseDimension { get; }

    /// <summary>The number of foldable layers <c>d</c>; the message holds <c>k0 · 2^d</c> field elements.</summary>
    public int LayerCount { get; }

    /// <summary>The curve whose scalar field the code's elements live in.</summary>
    public CurveParameterSet Curve { get; }

    /// <summary>The message length <c>k_d = k0 · 2^d</c> in field elements.</summary>
    public int MessageLength => BaseDimension << LayerCount;

    /// <summary>The codeword length <c>n_d = c · k0 · 2^d</c> in field elements.</summary>
    public int CodewordLength => InverseRate * MessageLength;


    private FoldableCodeParameters(int inverseRate, int baseDimension, int layerCount, CurveParameterSet curve)
    {
        InverseRate = inverseRate;
        BaseDimension = baseDimension;
        LayerCount = layerCount;
        Curve = curve;
    }


    /// <summary>
    /// Creates a validated parameter set. The inverse rate must be at least
    /// two (a rate below one), the base dimension at least one, and the layer
    /// count non-negative.
    /// </summary>
    /// <param name="inverseRate">The inverse rate <c>c</c> (at least 2).</param>
    /// <param name="baseDimension">The base-code dimension <c>k0</c> (at least 1).</param>
    /// <param name="layerCount">The number of foldable layers <c>d</c> (at least 0).</param>
    /// <param name="curve">The curve whose scalar field the code is over.</param>
    /// <returns>The validated parameter set.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When a numeric parameter is below its minimum.</exception>
    public static FoldableCodeParameters Create(int inverseRate, int baseDimension, int layerCount, CurveParameterSet curve)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(inverseRate, 2);
        ArgumentOutOfRangeException.ThrowIfLessThan(baseDimension, 1);
        ArgumentOutOfRangeException.ThrowIfNegative(layerCount);

        return new FoldableCodeParameters(inverseRate, baseDimension, layerCount, curve);
    }
}
