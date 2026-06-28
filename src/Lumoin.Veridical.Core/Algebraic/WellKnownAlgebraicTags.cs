using Lumoin.Veridical.Core;
using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Per-curve cached algebraic-identity <see cref="Tag"/>s for the broad
/// leaf types (<see cref="Scalar"/>, and — as they land — the group-point
/// and field-tower types). Each accessor returns a singleton tag reused by
/// reference, so inner-loop arithmetic over a broad leaf type allocates only
/// its rented buffer and never a fresh tag.
/// </summary>
/// <remarks>
/// <para>
/// Before the curve-genericity refactor, each per-curve leaf type
/// (<c>Scalar</c>, …) held its own statically-cached
/// <c>AlgebraicTag</c>. With the broad leaf types, the equivalent per-curve
/// singletons live here so the broad type can look up the right tag from a
/// <see cref="CurveParameterSet"/> at construction without re-allocating.
/// </para>
/// <para>
/// Entries exist only for wired curves. A lookup for a curve with no entry
/// throws, with a message pointing at this class — adding a curve is a matter
/// of adding its cached tags here when its backends are wired.
/// </para>
/// </remarks>
public static class WellKnownAlgebraicTags
{
    private static Tag ScalarBls12Curve381 { get; } = Tag.Create(AlgebraicRole.Scalar)
        .With(CurveParameterSet.Bls12Curve381);

    private static Tag ScalarBn254 { get; } = Tag.Create(AlgebraicRole.Scalar)
        .With(CurveParameterSet.Bn254);

    private static Tag ScalarP256 { get; } = Tag.Create(AlgebraicRole.Scalar)
        .With(CurveParameterSet.P256);

    private static Tag G1PointBls12Curve381 { get; } = Tag.Create(AlgebraicRole.G1Point)
        .With(CurveParameterSet.Bls12Curve381);

    private static Tag G1PointBn254 { get; } = Tag.Create(AlgebraicRole.G1Point)
        .With(CurveParameterSet.Bn254);

    private static Tag G1PointP256 { get; } = Tag.Create(AlgebraicRole.G1Point)
        .With(CurveParameterSet.P256);

    private static Tag G2PointBls12Curve381 { get; } = Tag.Create(AlgebraicRole.G2Point)
        .With(CurveParameterSet.Bls12Curve381);

    private static Tag G2PointBn254 { get; } = Tag.Create(AlgebraicRole.G2Point)
        .With(CurveParameterSet.Bn254);

    private static Tag ExtensionFieldElementBls12Curve381 { get; } = Tag.Create(AlgebraicRole.ExtensionFieldElement)
        .With(CurveParameterSet.Bls12Curve381);

    private static Tag ExtensionFieldElementBn254 { get; } = Tag.Create(AlgebraicRole.ExtensionFieldElement)
        .With(CurveParameterSet.Bn254);


    /// <summary>
    /// Returns the cached algebraic-identity tag for a <see cref="Scalar"/> in
    /// <paramref name="curve"/>'s scalar field:
    /// <c>(AlgebraicRole.Scalar, curve)</c>.
    /// </summary>
    /// <param name="curve">The curve whose scalar tag is requested.</param>
    /// <returns>The singleton scalar tag for the curve, reused by reference.</returns>
    /// <exception cref="ArgumentException">When no cached scalar tag exists for the curve.</exception>
    public static Tag ScalarFor(CurveParameterSet curve)
    {
        if(curve.Code == CurveParameterSet.Bls12Curve381.Code)
        {
            return ScalarBls12Curve381;
        }

        if(curve.Code == CurveParameterSet.Bn254.Code)
        {
            return ScalarBn254;
        }

        if(curve.Code == CurveParameterSet.P256.Code)
        {
            return ScalarP256;
        }

        throw new ArgumentException(
            $"No cached scalar tag for {curve}; add a WellKnownAlgebraicTags entry when wiring this curve.",
            nameof(curve));
    }


    /// <summary>
    /// Returns the cached algebraic-identity tag for a <see cref="G1Point"/> on
    /// <paramref name="curve"/>: <c>(AlgebraicRole.G1Point, curve)</c>.
    /// </summary>
    /// <param name="curve">The curve whose G1-point tag is requested.</param>
    /// <returns>The singleton G1-point tag for the curve, reused by reference.</returns>
    /// <exception cref="ArgumentException">When no cached G1-point tag exists for the curve.</exception>
    public static Tag G1PointFor(CurveParameterSet curve)
    {
        if(curve.Code == CurveParameterSet.Bls12Curve381.Code)
        {
            return G1PointBls12Curve381;
        }

        if(curve.Code == CurveParameterSet.Bn254.Code)
        {
            return G1PointBn254;
        }

        if(curve.Code == CurveParameterSet.P256.Code)
        {
            return G1PointP256;
        }

        throw new ArgumentException(
            $"No cached G1-point tag for {curve}; add a WellKnownAlgebraicTags entry when wiring this curve.",
            nameof(curve));
    }


    /// <summary>
    /// Returns the cached algebraic-identity tag for a <see cref="G2Point"/> on
    /// <paramref name="curve"/>: <c>(AlgebraicRole.G2Point, curve)</c>.
    /// </summary>
    /// <param name="curve">The curve whose G2-point tag is requested.</param>
    /// <returns>The singleton G2-point tag for the curve, reused by reference.</returns>
    /// <exception cref="ArgumentException">When no cached G2-point tag exists for the curve.</exception>
    public static Tag G2PointFor(CurveParameterSet curve)
    {
        if(curve.Code == CurveParameterSet.Bls12Curve381.Code)
        {
            return G2PointBls12Curve381;
        }

        if(curve.Code == CurveParameterSet.Bn254.Code)
        {
            return G2PointBn254;
        }

        throw new ArgumentException(
            $"No cached G2-point tag for {curve}; add a WellKnownAlgebraicTags entry when wiring this curve.",
            nameof(curve));
    }


    /// <summary>
    /// Returns the cached algebraic-identity tag for a field-tower extension
    /// element (<c>Fp2</c>/<c>Fp6</c>/<c>Fp12</c>) on <paramref name="curve"/>:
    /// <c>(AlgebraicRole.ExtensionFieldElement, curve)</c>. The three tower
    /// levels share this role, so one cached tag serves all of them.
    /// </summary>
    /// <param name="curve">The curve whose extension-field tag is requested.</param>
    /// <returns>The singleton extension-field tag for the curve, reused by reference.</returns>
    /// <exception cref="ArgumentException">When no cached extension-field tag exists for the curve.</exception>
    public static Tag ExtensionFieldElementFor(CurveParameterSet curve)
    {
        if(curve.Code == CurveParameterSet.Bls12Curve381.Code)
        {
            return ExtensionFieldElementBls12Curve381;
        }

        if(curve.Code == CurveParameterSet.Bn254.Code)
        {
            return ExtensionFieldElementBn254;
        }

        throw new ArgumentException(
            $"No cached extension-field tag for {curve}; add a WellKnownAlgebraicTags entry when wiring this curve.",
            nameof(curve));
    }
}