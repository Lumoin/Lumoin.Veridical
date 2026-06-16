using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Diagnostics;
using Lumoin.Veridical.Core.Memory;
using System;

namespace Lumoin.Veridical.Tests.Diagnostics;

/// <summary>
/// Behavioural tests for <see cref="Bls12Curve381G1PointInspector"/>. Verify
/// the report against the two distinguished public points (identity and
/// generator), where the expected flag-bit pattern is fixed by the IETF /
/// ZCash compressed-encoding spec.
/// </summary>
[TestClass]
internal sealed class Bls12Curve381G1PointInspectorTests
{
    [TestMethod]
    public void InspectingIdentityReportsInfinityFlagAndCompressionFlag()
    {
        using G1Point identity = G1Point.Identity(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        G1PointInspectionReport report = Bls12Curve381G1PointInspector.Inspect(identity);

        Assert.AreEqual(WellKnownCurves.Bls12Curve381G1CompressedSizeBytes, report.ByteLength);
        Assert.IsTrue(report.IsIdentity, "Identity point should report IsIdentity.");
        Assert.IsTrue(report.CompressionFlagSet, "Canonical compressed encoding always has the compression flag set.");
        Assert.IsTrue(report.InfinityFlagSet, "Identity has the infinity flag set.");
        Assert.IsFalse(report.YParityFlagSet, "Identity does not carry a meaningful y-parity flag; it should be clear.");

        // c0 high byte; remaining 47 bytes zero.
        Assert.AreEqual(
            "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            report.CanonicalHex);
    }


    [TestMethod]
    public void InspectingGeneratorReportsCompressionFlagAndNotIdentity()
    {
        using G1Point generator = G1Point.Generator(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        G1PointInspectionReport report = Bls12Curve381G1PointInspector.Inspect(generator);

        Assert.AreEqual(WellKnownCurves.Bls12Curve381G1CompressedSizeBytes, report.ByteLength);
        Assert.IsFalse(report.IsIdentity, "Generator is not the identity.");
        Assert.IsTrue(report.CompressionFlagSet, "Canonical generator has the compression flag set.");
        Assert.IsFalse(report.InfinityFlagSet, "Canonical generator does not have the infinity flag set.");
        // 0x97 = 0x80 | 0x17. The 0x20 (y-parity) bit is clear, so YParityFlagSet should be false.
        Assert.IsFalse(report.YParityFlagSet, "Generator's published y is the smaller root; parity flag is clear.");
    }


    [TestMethod]
    public void InspectingPointWithYParityFlagSetReportsYParityFlagSet()
    {
        // Synthetic encoding: take the generator bytes and set the y-parity
        // flag to confirm the inspector reads it. The result is not a valid
        // canonical generator encoding (the parity flag must match y's
        // lexicographic position), but the inspector reports flag bits as
        // observed without judging validity — that's exactly the read-only
        // boundary the inspector defines.
        Span<byte> bytes = stackalloc byte[WellKnownCurves.Bls12Curve381G1CompressedSizeBytes];
        using(G1Point generator = G1Point.Generator(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared))
        {
            generator.AsReadOnlySpan().CopyTo(bytes);
        }

        bytes[0] |= 0x20;

        using G1Point withParityFlagSet = G1Point.FromCanonical(bytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        G1PointInspectionReport report = Bls12Curve381G1PointInspector.Inspect(withParityFlagSet);

        Assert.IsTrue(report.YParityFlagSet, "Inspector should observe the y-parity flag bit as set.");
        Assert.IsTrue(report.CompressionFlagSet);
        Assert.IsFalse(report.InfinityFlagSet);
    }


    [TestMethod]
    public void InspectThrowsOnNullPoint()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => Bls12Curve381G1PointInspector.Inspect(null!));
    }
}