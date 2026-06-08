using System;
using System.Globalization;
using System.Numerics;

namespace Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;

/// <summary>
/// Reconciles a ZkInterface <c>field_maximum</c> against a wired curve's
/// scalar field. Shared by the instance and witness builders so the
/// modulus constants and the field-matching rule live in one place.
/// </summary>
/// <remarks>
/// <c>field_maximum</c> is the canonical little-endian field order minus
/// one, so the field prime is <c>field_maximum + 1</c>; it must equal the
/// requested curve's scalar modulus. BLS12-381 and BN254 are wired.
/// </remarks>
internal static class ZkInterfaceFieldReconciler
{
    private static readonly BigInteger Bls12Curve381ScalarFieldModulus = BigInteger.Parse(
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);

    private static readonly BigInteger Bn254ScalarFieldModulus = BigInteger.Parse(
        "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);


    /// <summary>The scalar field modulus the wired <paramref name="curve"/> expects.</summary>
    public static BigInteger ExpectedModulus(CurveParameterSet curve) =>
        curve.Code == CurveParameterSet.Bn254.Code ? Bn254ScalarFieldModulus : Bls12Curve381ScalarFieldModulus;


    /// <summary>
    /// Validates a declared <c>field_maximum</c> against <paramref name="curve"/>,
    /// throwing <see cref="R1csUnsupportedFieldException"/> on a mismatch.
    /// </summary>
    public static void ThrowIfFieldDoesNotMatch(ReadOnlySpan<byte> fieldMaximumLittleEndian, CurveParameterSet curve)
    {
        BigInteger prime = new BigInteger(fieldMaximumLittleEndian, isUnsigned: true, isBigEndian: false) + BigInteger.One;
        BigInteger expected = ExpectedModulus(curve);

        if(prime != expected)
        {
            throw new R1csUnsupportedFieldException(
                expected.ToString("x", CultureInfo.InvariantCulture),
                prime.ToString("x", CultureInfo.InvariantCulture));
        }
    }


    /// <summary>
    /// The exception to throw when no <c>field_maximum</c> was declared at
    /// all: an undeclared field cannot be validated against the curve.
    /// </summary>
    public static R1csUnsupportedFieldException AbsentFieldException(CurveParameterSet curve) =>
        new(ExpectedModulus(curve).ToString("x", CultureInfo.InvariantCulture), "(field_maximum absent)");
}
