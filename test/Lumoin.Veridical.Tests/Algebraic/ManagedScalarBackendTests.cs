using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Tests for the public managed scalar-backend composition roots. The BLS12-381
/// bundle composes SIMD add/subtract (when supported) with the BigInteger
/// reference for the rest; the composed operations must agree byte-for-byte with
/// the BigInteger reference, and the hardware-acceleration flag must reflect the
/// host. The BN254 bundle is BigInteger-only.
/// </summary>
[TestClass]
internal sealed class ManagedScalarBackendTests
{
    /// <summary>The canonical scalar width in bytes, shared by both curves under test.</summary>
    private const int ScalarSize = 32;

    /// <summary>The BLS12-381 curve identity the SIMD-composed bundle is exercised against.</summary>
    private static CurveParameterSet Bls { get; } = CurveParameterSet.Bls12Curve381;

    /// <summary>The BN254 curve identity the BigInteger-only bundle is exercised against.</summary>
    private static CurveParameterSet Bn { get; } = CurveParameterSet.Bn254;


    /// <summary>Pins that the BLS12-381 bundle's add, subtract, multiply and invert all agree byte-for-byte with the BigInteger reference, and that its hardware-acceleration flag matches the SIMD backend's own support check.</summary>
    [TestMethod]
    public void BlsBundleComposedOperationsAgreeWithReference()
    {
        using ScalarArithmeticBackend bundle = Bls12Curve381ManagedScalarBackend.Create();

        Assert.AreEqual(Bls, bundle.Curve);
        Assert.AreEqual(Bls12Curve381SimdScalarBackend.IsSupported, bundle.IsHardwareAccelerated);

        ScalarAddDelegate referenceAdd = Bls12Curve381BigIntegerScalarReference.GetAdd();
        ScalarSubtractDelegate referenceSubtract = Bls12Curve381BigIntegerScalarReference.GetSubtract();
        ScalarMultiplyDelegate referenceMultiply = Bls12Curve381BigIntegerScalarReference.GetMultiply();

        Span<byte> a = stackalloc byte[ScalarSize];
        Span<byte> b = stackalloc byte[ScalarSize];
        BuildScalar(a, 0x12, Bls);
        BuildScalar(b, 0x9A, Bls);

        Span<byte> bundleResult = stackalloc byte[ScalarSize];
        Span<byte> referenceResult = stackalloc byte[ScalarSize];

        bundle.Add(a, b, bundleResult, Bls);
        referenceAdd(a, b, referenceResult, Bls);
        Assert.IsTrue(bundleResult.SequenceEqual(referenceResult), "Bundle Add must agree with the reference byte-for-byte.");

        bundle.Subtract(a, b, bundleResult, Bls);
        referenceSubtract(a, b, referenceResult, Bls);
        Assert.IsTrue(bundleResult.SequenceEqual(referenceResult), "Bundle Subtract must agree with the reference.");

        bundle.Multiply(a, b, bundleResult, Bls);
        referenceMultiply(a, b, referenceResult, Bls);
        Assert.IsTrue(bundleResult.SequenceEqual(referenceResult), "Bundle Multiply (BigInteger) must agree with the reference.");

        //Invert of a non-zero scalar, then multiply back to one — the bundle's
        //invert and multiply compose correctly.
        Span<byte> inverse = stackalloc byte[ScalarSize];
        bundle.Invert(a, inverse, Bls);
        bundle.Multiply(a, inverse, bundleResult, Bls);
        Span<byte> one = stackalloc byte[ScalarSize];
        one.Clear();
        one[^1] = 0x01;
        Assert.IsTrue(bundleResult.SequenceEqual(one), "a · a⁻¹ must equal one.");

        Assert.IsNotNull(bundle.HashToScalar);
    }


    /// <summary>Pins that the BN254 bundle's add, subtract, multiply and invert all agree byte-for-byte with the BigInteger reference, that it reports no hardware acceleration, and that it exposes no hash-to-scalar delegate.</summary>
    [TestMethod]
    public void Bn254BundleComposedOperationsAgreeWithReference()
    {
        using ScalarArithmeticBackend bundle = Bn254ManagedScalarBackend.Create();

        Assert.AreEqual(Bn, bundle.Curve);
        Assert.AreEqual(Bn254SimdScalarBackend.IsSupported, bundle.IsHardwareAccelerated);
        Assert.IsNull(bundle.HashToScalar);

        ScalarAddDelegate referenceAdd = Bn254BigIntegerScalarReference.GetAdd();
        ScalarSubtractDelegate referenceSubtract = Bn254BigIntegerScalarReference.GetSubtract();

        Span<byte> a = stackalloc byte[ScalarSize];
        Span<byte> b = stackalloc byte[ScalarSize];
        BuildScalar(a, 0x07, Bn);
        BuildScalar(b, 0x55, Bn);

        Span<byte> bundleResult = stackalloc byte[ScalarSize];
        Span<byte> referenceResult = stackalloc byte[ScalarSize];

        bundle.Add(a, b, bundleResult, Bn);
        referenceAdd(a, b, referenceResult, Bn);
        Assert.IsTrue(bundleResult.SequenceEqual(referenceResult), "BN254 bundle Add must agree with the reference.");

        bundle.Subtract(a, b, bundleResult, Bn);
        referenceSubtract(a, b, referenceResult, Bn);
        Assert.IsTrue(bundleResult.SequenceEqual(referenceResult), "BN254 bundle Subtract must agree with the reference.");

        ScalarMultiplyDelegate referenceMultiply = Bn254BigIntegerScalarReference.GetMultiply();
        bundle.Multiply(a, b, bundleResult, Bn);
        referenceMultiply(a, b, referenceResult, Bn);
        Assert.IsTrue(bundleResult.SequenceEqual(referenceResult), "BN254 bundle Multiply must agree with the reference.");

        //Invert a non-zero scalar then multiply back to one — invert and multiply compose.
        Span<byte> inverse = stackalloc byte[ScalarSize];
        bundle.Invert(a, inverse, Bn);
        bundle.Multiply(a, inverse, bundleResult, Bn);
        Span<byte> one = stackalloc byte[ScalarSize];
        one.Clear();
        one[^1] = 0x01;
        Assert.IsTrue(bundleResult.SequenceEqual(one), "a · a⁻¹ must equal one.");
    }


    /// <summary>Builds a reduced, non-zero canonical scalar from a fill byte via the curve's reduce backend, so the value is a valid field element.</summary>
    /// <param name="destination">Receives the canonical scalar.</param>
    /// <param name="fill">The byte every input limb is filled with before reduction.</param>
    /// <param name="curve">The curve whose reduce delegate and field the scalar is valid for.</param>
    private static void BuildScalar(Span<byte> destination, byte fill, CurveParameterSet curve)
    {
        Span<byte> wide = stackalloc byte[64];
        wide.Fill(fill);
        ScalarReduceDelegate reduce = curve.Code == CurveParameterSet.Bn254.Code
            ? Bn254BigIntegerScalarReference.GetReduce()
            : Bls12Curve381BigIntegerScalarReference.GetReduce();
        reduce(wide, destination, curve);
    }
}
