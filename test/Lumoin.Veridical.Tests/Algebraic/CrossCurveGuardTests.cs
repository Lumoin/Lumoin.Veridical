using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Diagnostics.CodeAnalysis;

using static Lumoin.Veridical.Tests.Spartan.MaskedSpartanTestFixtures;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Guards the runtime cross-curve safety model that replaced the
/// per-curve leaf types' compile-time guarantee (Batch T). With the broad
/// sealed leaf types, the curve a value belongs to travels in its tag
/// (surfaced as <c>Curve</c>), and mixing curves in one operation is caught
/// at runtime by the arithmetic extension entry points rather than by the
/// type system.
/// </summary>
/// <remarks>
/// <para>
/// The test uses BLS12-381 and BN254 as two distinct curves. BN254 has its
/// metadata wired (sizes and algebraic-identity tags) but no arithmetic
/// backend, which is sufficient here: the leaf factories validate byte length
/// and tag the curve without touching a backend, and the cross-curve mismatch
/// checks fire <em>before</em> any delegate is invoked, so the operation
/// delegates are never reached on the mismatch path. Full multi-curve protocol
/// coverage arrives when BN254's backend lands (Batch U); this test locks in
/// the safety net the broad-type design depends on.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CrossCurveGuardTests
{
    private static CurveParameterSet Bls => CurveParameterSet.Bls12Curve381;

    private static CurveParameterSet Bn => CurveParameterSet.Bn254;

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    //Stub delegates for the group/pairing operations not wired in the shared
    //fixtures. The cross-curve checks throw before these run; if one is ever
    //reached the test fails loudly with the wrong exception type.
    private static G2AddDelegate StubG2Add { get; } =
        (a, b, result, curve) => throw new InvalidOperationException("G2 add delegate must not be reached on a curve mismatch.");

    private static PairingDelegate StubPairing { get; } =
        (p, q, result, curve) => throw new InvalidOperationException("Pairing delegate must not be reached on a curve mismatch.");


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000", Justification = "Leaf values are disposed via using declarations before the assertion completes.")]
    public void LeafFactoriesTagTheSuppliedCurve()
    {
        using Scalar blsScalar = Scalar.FromCanonical(new byte[Scalar.SizeBytes], Bls, Pool);
        using Scalar bnScalar = Scalar.FromCanonical(new byte[Scalar.SizeBytes], Bn, Pool);
        using G1Point blsG1 = G1Point.FromCanonical(new byte[WellKnownCurves.GetG1CompressedSizeBytes(Bls)], Bls, Pool);
        using G1Point bnG1 = G1Point.FromCanonical(new byte[WellKnownCurves.GetG1CompressedSizeBytes(Bn)], Bn, Pool);
        using G2Point bnG2 = G2Point.FromCanonical(new byte[WellKnownCurves.GetG2CompressedSizeBytes(Bn)], Bn, Pool);
        using Fp12Element bnFp12 = Fp12Element.FromCanonical(new byte[WellKnownCurves.GetFp12SizeBytes(Bn)], Bn, Pool);

        Assert.AreEqual(Bls.Code, blsScalar.Curve.Code, "Scalar factory must tag the supplied curve.");
        Assert.AreEqual(Bn.Code, bnScalar.Curve.Code, "Scalar factory must tag the supplied curve.");
        Assert.AreEqual(Bls.Code, blsG1.Curve.Code, "G1 factory must tag the supplied curve.");
        Assert.AreEqual(Bn.Code, bnG1.Curve.Code, "G1 factory must tag the supplied curve.");
        Assert.AreEqual(Bn.Code, bnG2.Curve.Code, "G2 factory must tag the supplied curve.");
        Assert.AreEqual(Bn.Code, bnFp12.Curve.Code, "Fp12 factory must tag the supplied curve.");
    }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000", Justification = "Operands are disposed via using declarations; the operation throws before allocating a result.")]
    public void ScalarCrossCurveArithmeticThrows()
    {
        using Scalar bls = Scalar.FromCanonical(new byte[Scalar.SizeBytes], Bls, Pool);
        using Scalar bn = Scalar.FromCanonical(new byte[Scalar.SizeBytes], Bn, Pool);

        Assert.ThrowsExactly<ArgumentException>(() => { using Scalar _ = bls.Add(bn, Add, Pool); }, "Adding scalars over different curves must throw.");
        Assert.ThrowsExactly<ArgumentException>(() => { using Scalar _ = bls.Subtract(bn, Subtract, Pool); }, "Subtracting scalars over different curves must throw.");
        Assert.ThrowsExactly<ArgumentException>(() => { using Scalar _ = bls.Multiply(bn, Multiply, Pool); }, "Multiplying scalars over different curves must throw.");
    }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000", Justification = "Operands are disposed via using declarations; the operation throws before allocating a result.")]
    public void GroupAndScalarMixCrossCurveThrows()
    {
        using G1Point blsG1 = G1Point.FromCanonical(new byte[WellKnownCurves.GetG1CompressedSizeBytes(Bls)], Bls, Pool);
        using G1Point bnG1 = G1Point.FromCanonical(new byte[WellKnownCurves.GetG1CompressedSizeBytes(Bn)], Bn, Pool);
        using G2Point blsG2 = G2Point.FromCanonical(new byte[WellKnownCurves.GetG2CompressedSizeBytes(Bls)], Bls, Pool);
        using G2Point bnG2 = G2Point.FromCanonical(new byte[WellKnownCurves.GetG2CompressedSizeBytes(Bn)], Bn, Pool);
        using Scalar bnScalar = Scalar.FromCanonical(new byte[Scalar.SizeBytes], Bn, Pool);

        Assert.ThrowsExactly<ArgumentException>(() => { using G1Point _ = blsG1.Add(bnG1, G1Add, Pool); }, "Adding G1 points over different curves must throw.");
        Assert.ThrowsExactly<ArgumentException>(() => { using G1Point _ = blsG1.ScalarMultiply(bnScalar, G1ScalarMul, Pool); }, "Scaling a G1 point by a scalar of a different curve must throw.");
        Assert.ThrowsExactly<ArgumentException>(() => { using G2Point _ = blsG2.Add(bnG2, StubG2Add, Pool); }, "Adding G2 points over different curves must throw.");
        Assert.ThrowsExactly<ArgumentException>(() => { using Fp12Element _ = blsG1.PairWith(bnG2, StubPairing, Pool); }, "Pairing operands over different curves must throw.");
    }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000", Justification = "Operands and result are disposed via using declarations before the assertion completes.")]
    public void SameCurveArithmeticResultCarriesTheCurve()
    {
        using Scalar a = Scalar.FromCanonical(new byte[Scalar.SizeBytes], Bls, Pool);
        using Scalar b = Scalar.FromCanonical(new byte[Scalar.SizeBytes], Bls, Pool);

        using Scalar sum = a.Add(b, Add, Pool);

        Assert.AreEqual(Bls.Code, sum.Curve.Code, "A same-curve scalar sum must carry the operands' curve.");
    }
}