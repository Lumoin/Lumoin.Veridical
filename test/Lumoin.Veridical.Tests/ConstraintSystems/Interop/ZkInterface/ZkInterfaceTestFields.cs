using Lumoin.Veridical.Core;
using System;
using System.Globalization;
using System.Numerics;

namespace Lumoin.Veridical.Tests.ConstraintSystems.Interop.ZkInterface;

/// <summary>
/// Synthetic field data for the ZkInterface builder/reader tests: the
/// <c>field_maximum</c> a producer would declare for a wired curve, i.e.
/// the canonical little-endian scalar field order minus one.
/// </summary>
internal static class ZkInterfaceTestFields
{
    /// <summary>The scalar element width for both wired curves (BLS12-381 and BN254 are 254-bit fields → 32 bytes).</summary>
    public const int FieldElementSizeBytes = 32;

    private static readonly BigInteger Bls12Curve381ScalarFieldModulus = BigInteger.Parse(
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);

    private static readonly BigInteger Bn254ScalarFieldModulus = BigInteger.Parse(
        "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);


    /// <summary>
    /// Writes <c>(field order - 1)</c> for <paramref name="curve"/> as a
    /// little-endian byte sequence into <paramref name="destination"/>
    /// (which must be <see cref="FieldElementSizeBytes"/> long).
    /// </summary>
    public static void WriteFieldMaximumLittleEndian(CurveParameterSet curve, Span<byte> destination)
    {
        if(destination.Length != FieldElementSizeBytes)
        {
            throw new ArgumentException($"Destination must be {FieldElementSizeBytes} bytes.", nameof(destination));
        }

        destination.Clear();
        BigInteger fieldMaximum = ModulusFor(curve) - BigInteger.One;
        if(!fieldMaximum.TryWriteBytes(destination, out _, isUnsigned: true, isBigEndian: false))
        {
            throw new InvalidOperationException("field_maximum did not fit the destination span.");
        }
    }


    /// <summary>Allocates and returns the <c>field_maximum</c> bytes for <paramref name="curve"/> (a fixture-data factory).</summary>
    public static byte[] FieldMaximumLittleEndian(CurveParameterSet curve)
    {
        byte[] bytes = new byte[FieldElementSizeBytes];
        WriteFieldMaximumLittleEndian(curve, bytes);
        return bytes;
    }


    private static BigInteger ModulusFor(CurveParameterSet curve) =>
        curve.Code == CurveParameterSet.Bn254.Code ? Bn254ScalarFieldModulus : Bls12Curve381ScalarFieldModulus;
}
