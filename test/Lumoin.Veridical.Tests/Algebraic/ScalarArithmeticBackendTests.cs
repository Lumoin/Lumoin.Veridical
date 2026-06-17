using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Tests for the <see cref="ScalarArithmeticBackend"/> delegate bundle: a
/// well-formed bundle exposes every operation, null required delegates are
/// rejected, the optional hash-to-scalar may be omitted, and disposal is
/// idempotent and forwards to the owned resource.
/// </summary>
[TestClass]
internal sealed class ScalarArithmeticBackendTests
{
    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    public void BundleFromReferenceExposesEveryOperation()
    {
        using ScalarArithmeticBackend backend = BuildFromReference(isHardwareAccelerated: false);

        Assert.AreEqual(Curve, backend.Curve);
        Assert.IsNotNull(backend.Reduce);
        Assert.IsNotNull(backend.Add);
        Assert.IsNotNull(backend.Subtract);
        Assert.IsNotNull(backend.Multiply);
        Assert.IsNotNull(backend.Negate);
        Assert.IsNotNull(backend.Invert);
        Assert.IsNotNull(backend.Random);
        Assert.IsNotNull(backend.BatchAdd);
        Assert.IsNotNull(backend.BatchSubtract);
        Assert.IsNotNull(backend.HashToScalar);
        Assert.IsFalse(backend.IsHardwareAccelerated);
    }


    [TestMethod]
    public void HashToScalarMayBeOmitted()
    {
        using var backend = new ScalarArithmeticBackend(
            Curve,
            Bls12Curve381BigIntegerScalarReference.GetReduce(),
            Bls12Curve381BigIntegerScalarReference.GetAdd(),
            Bls12Curve381BigIntegerScalarReference.GetSubtract(),
            Bls12Curve381BigIntegerScalarReference.GetMultiply(),
            Bls12Curve381BigIntegerScalarReference.GetNegate(),
            Bls12Curve381BigIntegerScalarReference.GetInvert(),
            Bls12Curve381BigIntegerScalarReference.GetRandom(),
            Bls12Curve381BigIntegerScalarReference.GetBatchAdd(),
            Bls12Curve381BigIntegerScalarReference.GetBatchSubtract(),
            Bls12Curve381BigIntegerScalarReference.GetBatchMultiply(),
            hashToScalar: null);

        Assert.IsNull(backend.HashToScalar);
    }


    [TestMethod]
    public void NullRequiredDelegateThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new ScalarArithmeticBackend(
            Curve,
            Bls12Curve381BigIntegerScalarReference.GetReduce(),
            add: null!,
            Bls12Curve381BigIntegerScalarReference.GetSubtract(),
            Bls12Curve381BigIntegerScalarReference.GetMultiply(),
            Bls12Curve381BigIntegerScalarReference.GetNegate(),
            Bls12Curve381BigIntegerScalarReference.GetInvert(),
            Bls12Curve381BigIntegerScalarReference.GetRandom(),
            Bls12Curve381BigIntegerScalarReference.GetBatchAdd(),
            Bls12Curve381BigIntegerScalarReference.GetBatchSubtract(),
            Bls12Curve381BigIntegerScalarReference.GetBatchMultiply()));
    }


    [TestMethod]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the counter transfers to the backend, which disposes it; the test asserts exactly that forwarding.")]
    public void DisposeForwardsToOwnedResourceAndIsIdempotent()
    {
        var owned = new DisposeCounter();
        var backend = new ScalarArithmeticBackend(
            Curve,
            Bls12Curve381BigIntegerScalarReference.GetReduce(),
            Bls12Curve381BigIntegerScalarReference.GetAdd(),
            Bls12Curve381BigIntegerScalarReference.GetSubtract(),
            Bls12Curve381BigIntegerScalarReference.GetMultiply(),
            Bls12Curve381BigIntegerScalarReference.GetNegate(),
            Bls12Curve381BigIntegerScalarReference.GetInvert(),
            Bls12Curve381BigIntegerScalarReference.GetRandom(),
            Bls12Curve381BigIntegerScalarReference.GetBatchAdd(),
            Bls12Curve381BigIntegerScalarReference.GetBatchSubtract(),
            Bls12Curve381BigIntegerScalarReference.GetBatchMultiply(),
            ownedResource: owned);

        backend.Dispose();
        backend.Dispose();

        Assert.AreEqual(1, owned.DisposeCount);
    }


    private static ScalarArithmeticBackend BuildFromReference(bool isHardwareAccelerated)
    {
        return new ScalarArithmeticBackend(
            Curve,
            Bls12Curve381BigIntegerScalarReference.GetReduce(),
            Bls12Curve381BigIntegerScalarReference.GetAdd(),
            Bls12Curve381BigIntegerScalarReference.GetSubtract(),
            Bls12Curve381BigIntegerScalarReference.GetMultiply(),
            Bls12Curve381BigIntegerScalarReference.GetNegate(),
            Bls12Curve381BigIntegerScalarReference.GetInvert(),
            Bls12Curve381BigIntegerScalarReference.GetRandom(),
            Bls12Curve381BigIntegerScalarReference.GetBatchAdd(),
            Bls12Curve381BigIntegerScalarReference.GetBatchSubtract(),
            Bls12Curve381BigIntegerScalarReference.GetBatchMultiply(),
            Bls12Curve381BigIntegerScalarReference.GetHashToScalar(),
            isHardwareAccelerated);
    }


    private sealed class DisposeCounter: IDisposable
    {
        public int DisposeCount { get; private set; }

        public void Dispose() => DisposeCount++;
    }
}
