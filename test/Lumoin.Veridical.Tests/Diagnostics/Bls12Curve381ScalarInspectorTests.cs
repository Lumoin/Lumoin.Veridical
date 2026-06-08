using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Diagnostics;
using Lumoin.Veridical.Core.Memory;
using System;

namespace Lumoin.Veridical.Tests.Diagnostics;

/// <summary>
/// Behavioural tests for <see cref="Bls12Curve381ScalarInspector"/>. Verify
/// each field of <see cref="ScalarInspectionReport"/> against scalars whose
/// expected values are unambiguous: zero, one, and a value that exceeds the
/// scalar field order.
/// </summary>
[TestClass]
internal sealed class Bls12Curve381ScalarInspectorTests
{
    [TestMethod]
    public void InspectingZeroScalarReportsIsZeroAndCanonical()
    {
        Span<byte> zeroBytes = stackalloc byte[Scalar.SizeBytes];
        zeroBytes.Clear();

        using Scalar scalar = Scalar.FromCanonical(zeroBytes, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        ScalarInspectionReport report = Bls12Curve381ScalarInspector.Inspect(scalar);

        Assert.AreEqual(Scalar.SizeBytes, report.ByteLength);
        Assert.IsTrue(report.IsZero, "Zero scalar should report IsZero.");
        Assert.IsFalse(report.IsOne, "Zero scalar should not report IsOne.");
        Assert.IsTrue(report.IsInCanonicalRange, "Zero is in [0, r).");
        Assert.AreEqual("0000000000000000000000000000000000000000000000000000000000000000", report.CanonicalHex);
    }


    [TestMethod]
    public void InspectingOneScalarReportsIsOneAndCanonical()
    {
        Span<byte> oneBytes = stackalloc byte[Scalar.SizeBytes];
        oneBytes.Clear();
        oneBytes[^1] = 0x01;

        using Scalar scalar = Scalar.FromCanonical(oneBytes, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        ScalarInspectionReport report = Bls12Curve381ScalarInspector.Inspect(scalar);

        Assert.IsFalse(report.IsZero, "One scalar should not report IsZero.");
        Assert.IsTrue(report.IsOne, "One scalar should report IsOne.");
        Assert.IsTrue(report.IsInCanonicalRange, "One is in [0, r).");
        Assert.AreEqual("0000000000000000000000000000000000000000000000000000000000000001", report.CanonicalHex);
    }


    [TestMethod]
    public void InspectingAllOnesBytesReportsNotInCanonicalRange()
    {
        // 0xff..ff (32 bytes) = 2^256 - 1, which is greater than the scalar
        // field order r. The leaf type does not validate the value at
        // construction (FromCanonical only checks length), so the report's
        // IsInCanonicalRange flag is the only way to detect this drift.
        Span<byte> allOnes = stackalloc byte[Scalar.SizeBytes];
        allOnes.Fill(0xff);

        using Scalar scalar = Scalar.FromCanonical(allOnes, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        ScalarInspectionReport report = Bls12Curve381ScalarInspector.Inspect(scalar);

        Assert.IsFalse(report.IsInCanonicalRange, "2^256 - 1 is not in [0, r).");
        Assert.IsFalse(report.IsZero);
        Assert.IsFalse(report.IsOne);
    }


    [TestMethod]
    public void InspectingScalarFieldOrderExactlyReportsNotInCanonicalRange()
    {
        // Canonical range is [0, r) — strictly less than r. A scalar equal to
        // r exactly is out of range.
        ReadOnlySpan<byte> scalarFieldOrderBytes =
        [
            0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48,
            0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
            0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe,
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01
        ];

        using Scalar scalar = Scalar.FromCanonical(scalarFieldOrderBytes, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        ScalarInspectionReport report = Bls12Curve381ScalarInspector.Inspect(scalar);

        Assert.IsFalse(report.IsInCanonicalRange, "A scalar equal to r is not in [0, r).");
    }


    [TestMethod]
    public void InspectThrowsOnNullScalar()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => Bls12Curve381ScalarInspector.Inspect(null!));
    }
}