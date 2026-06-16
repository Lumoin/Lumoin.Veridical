using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// The wired Poseidon parameter shapes: circomlib-compatible round counts
/// (<c>R_F = 8</c>, the per-width <c>R_P</c> table circomlib pins) over the
/// two wired scalar fields, generated on demand by
/// <see cref="PoseidonParameterGenerator"/>. For BN254 the generated
/// constants are byte-identical to circomlib's pinned tables (same Grain
/// procedure, same descriptor) — gated by the known-answer tests; for
/// BLS12-381 the same procedure instantiates the construction over the
/// 255-bit field (no upstream table exists to compare against; the
/// determinism and the construction are the claim).
/// </summary>
public static class WellKnownPoseidonParameters
{
    /// <summary>The circomlib full-round count.</summary>
    public const int CircomlibFullRounds = 8;

    //circomlib's partial-round table, indexed by t − 2 (state widths 2…17).
    private static readonly int[] CircomlibPartialRounds =
    [
        56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68
    ];

    //The wired scalar-field moduli (canonical big-endian) and bit lengths.
    private const int Bn254FieldSizeBits = 254;
    private const int Bls12Curve381FieldSizeBits = 255;

    private static readonly byte[] Bn254Modulus = Convert.FromHexString(
        "30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001");

    private static readonly byte[] Bls12Curve381Modulus = Convert.FromHexString(
        "73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001");


    /// <summary>
    /// Generates the circomlib-compatible parameter set for a Poseidon hash
    /// of <paramref name="inputCount"/> field elements (state width
    /// <c>t = inputCount + 1</c>) over <paramref name="curve"/>'s scalar
    /// field.
    /// </summary>
    /// <param name="inputCount">The hash arity; in <c>[1, 16]</c> (the widths circomlib pins round counts for).</param>
    /// <param name="curve">The wired curve.</param>
    /// <param name="add">Scalar-addition backend.</param>
    /// <param name="invert">Scalar-inversion backend.</param>
    /// <returns>The generated parameters.</returns>
    /// <exception cref="ArgumentNullException">When a delegate argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="inputCount"/> is outside <c>[1, 16]</c>.</exception>
    /// <exception cref="ArgumentException">When the curve is not wired.</exception>
    public static PoseidonParameters CreateCircomlibCompatible(int inputCount, CurveParameterSet curve, ScalarAddDelegate add, ScalarInvertDelegate invert)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(inputCount, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(inputCount, CircomlibPartialRounds.Length);

        int stateWidth = inputCount + 1;
        int partialRounds = CircomlibPartialRounds[stateWidth - 2];

        (byte[] modulus, int fieldSizeBits) = curve.Code == CurveParameterSet.Bn254.Code
            ? (Bn254Modulus, Bn254FieldSizeBits)
            : curve.Code == CurveParameterSet.Bls12Curve381.Code
                ? (Bls12Curve381Modulus, Bls12Curve381FieldSizeBits)
                : throw new ArgumentException($"Poseidon parameters are wired for Bn254 and Bls12Curve381; received '{curve}'.", nameof(curve));

        return PoseidonParameterGenerator.Generate(
            stateWidth, CircomlibFullRounds, partialRounds, fieldSizeBits, modulus, curve, add, invert);
    }
}
