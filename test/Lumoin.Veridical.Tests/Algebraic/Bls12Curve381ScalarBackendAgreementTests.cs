using CsCheck;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Property-based cross-implementation tests for BLS12-381 scalar field
/// arithmetic. Sweeps random scalar inputs through two independent
/// implementations — <see cref="Bls12Curve381BigIntegerScalarReference"/>
/// (heap-allocated arbitrary-precision integers) and
/// <see cref="Bls12Curve381SimdScalarBackend"/> (4-limb 64-bit unsigned
/// arithmetic with AVX2-backed constant-time conditional reduction) — and
/// asserts they produce bit-identical canonical bytes for every sample.
/// </summary>
/// <remarks>
/// <para>
/// This is the test pattern this batch introduces: a sweep over random
/// inputs that compares the output of two backends against each other.
/// The point of the pattern is not to verify a single backend in
/// isolation — that is what the algebraic-invariant tests and the
/// canonical-constants tests do — but to verify that two implementations
/// of the same delegate contract agree. When they diverge, CsCheck
/// shrinks the failing sample to a minimal counterexample, which is by
/// far the fastest way to localise the bug in either implementation.
/// </para>
/// <para>
/// Scalar arithmetic is cheap enough for sweeps to be practical here.
/// The cost in this batch's BigInteger G1 reference made sweep-style
/// testing of point arithmetic impractical, which is why the G1 test
/// surface uses invariant-style fixed-input tests instead. Once a
/// production-grade G1 backend lands, an analogous agreement test will
/// sweep G1 inputs through it against the BigInteger reference; the
/// pattern carries straight over.
/// </para>
/// <para>
/// All tests skip cleanly with <see cref="Assert.Inconclusive(string)"/>
/// when AVX2 is not present on the host CPU.
/// </para>
/// </remarks>
[TestClass]
internal sealed class Bls12Curve381ScalarBackendAgreementTests
{
    private static readonly ScalarReduceDelegate ReduceDelegate =
        Bls12Curve381BigIntegerScalarReference.GetReduce();

    private static readonly ScalarAddDelegate BigIntegerAdd =
        Bls12Curve381BigIntegerScalarReference.GetAdd();

    private static readonly ScalarSubtractDelegate BigIntegerSubtract =
        Bls12Curve381BigIntegerScalarReference.GetSubtract();

    private static readonly Gen<byte[]> RawScalarBytesGen =
        Gen.Byte.Array[Scalar.SizeBytes];


    /// <summary>
    /// The number of CsCheck samples per property test. Scalar arithmetic
    /// is microseconds per call in both backends, so several hundred
    /// samples complete in well under a second while still probing a
    /// meaningfully wide region of the scalar field.
    /// </summary>
    private const long IterationCount = 200;


    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void DispatchFacadeReportsSupportedWhenAtLeastOneIsaBackendIsAvailable()
    {
        //Structural invariant: the dispatch facade's IsSupported is true exactly
        //when at least one underlying per-ISA backend is supported, and false
        //otherwise. Catches a wiring error where the facade silently disagrees
        //with the backends it is supposed to expose.
        bool anyBackendSupported =
            Bls12Curve381Avx2ScalarBackend.IsSupported
            || Bls12Curve381NeonScalarBackend.IsSupported;

        Assert.AreEqual(
            anyBackendSupported,
            Bls12Curve381SimdScalarBackend.IsSupported,
            "Dispatch facade IsSupported must reflect the OR of per-ISA backend support flags.");
    }


    [TestMethod]
    public void DispatchFacadeMatchesHostCpuCapabilityFlags()
    {
        //Lower-level check: the per-ISA backends' IsSupported must match what
        //the underlying intrinsic surface reports for that ISA. A failure here
        //means our IsSupported gate is gating on something other than the
        //instruction set it claims to require.
        Assert.AreEqual(Avx2.IsSupported, Bls12Curve381Avx2ScalarBackend.IsSupported);
        Assert.AreEqual(AdvSimd.Arm64.IsSupported, Bls12Curve381NeonScalarBackend.IsSupported);

        TestContext.WriteLine(
            $"Host CPU capabilities: AVX2={Avx2.IsSupported}, AArch64 NEON={AdvSimd.Arm64.IsSupported}.");
    }


    [TestMethod]
    public void SimdAddAgreesWithBigIntegerAddAcrossRandomInputs()
    {
        if(!Bls12Curve381SimdScalarBackend.IsSupported)
        {
            Assert.Inconclusive("AVX2 is not available on the host CPU; the SIMD scalar backend cannot run.");
            return;
        }

        ScalarAddDelegate simdAdd = Bls12Curve381SimdScalarBackend.GetAdd();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes) =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
                using Scalar b = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);

                using Scalar bigIntegerSum = a.Add(b, BigIntegerAdd, pool);
                using Scalar simdSum = a.Add(b, simdAdd, pool);

                return bigIntegerSum.AsReadOnlySpan().SequenceEqual(simdSum.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void SimdSubtractAgreesWithBigIntegerSubtractAcrossRandomInputs()
    {
        if(!Bls12Curve381SimdScalarBackend.IsSupported)
        {
            Assert.Inconclusive("AVX2 is not available on the host CPU; the SIMD scalar backend cannot run.");
            return;
        }

        ScalarSubtractDelegate simdSubtract = Bls12Curve381SimdScalarBackend.GetSubtract();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes) =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
                using Scalar b = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);

                using Scalar bigIntegerDiff = a.Subtract(b, BigIntegerSubtract, pool);
                using Scalar simdDiff = a.Subtract(b, simdSubtract, pool);

                return bigIntegerDiff.AsReadOnlySpan().SequenceEqual(simdDiff.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void SimdAddCommutativeAgreesWithItself()
    {
        //Sanity check on the SIMD backend independent of the BigInteger one:
        //its own output should satisfy commutativity. If this passes but the
        //cross-backend test fails, the bug is in the bytes produced (not in
        //the algebraic property); if both fail the bug is in the SIMD code's
        //add itself.
        if(!Bls12Curve381SimdScalarBackend.IsSupported)
        {
            Assert.Inconclusive("AVX2 is not available on the host CPU; the SIMD scalar backend cannot run.");
            return;
        }

        ScalarAddDelegate simdAdd = Bls12Curve381SimdScalarBackend.GetAdd();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes) =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
                using Scalar b = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);

                using Scalar leftThenRight = a.Add(b, simdAdd, pool);
                using Scalar rightThenLeft = b.Add(a, simdAdd, pool);

                return leftThenRight.AsReadOnlySpan().SequenceEqual(rightThenLeft.AsReadOnlySpan());
            }, iter: IterationCount);
    }
}