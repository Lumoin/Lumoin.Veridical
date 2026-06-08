using CsCheck;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Property-based agreement tests for the BN254 NEON (AArch64) scalar backend, the
/// BN254 mirror of <see cref="Bls12Curve381NeonScalarBackendAgreementTests"/>.
/// Inconclusive on x64 and 32-bit ARM; runs only on real AArch64. Add and subtract
/// are covered here.
/// </summary>
[TestClass]
internal sealed class Bn254NeonScalarBackendAgreementTests
{
    private static readonly ScalarReduceDelegate ReduceDelegate =
        Bn254BigIntegerScalarReference.GetReduce();

    private static readonly Gen<byte[]> RawScalarBytesGen =
        Gen.Byte.Array[Scalar.SizeBytes];

    private const long IterationCount = 200;


    public TestContext TestContext { get; set; } = null!;


    [TestInitialize]
    public void RequireNeon() => InstructionSetRequirements.RequireNeon();


    [TestMethod]
    public void NeonBatchMultiplyAgreesWithBigIntegerMultiply()
    {
        ScalarMultiplyDelegate bigIntegerMultiply = Bn254BigIntegerScalarReference.GetMultiply();
        ScalarBatchMultiplyDelegate neonBatchMultiply = Bn254NeonScalarBackend.GetBatchMultiply();

        const int Count = 7;
        int size = Scalar.SizeBytes;

        Gen<byte[]> batchGen = Gen.Byte.Array[Count * size];
        Gen.Select(batchGen, batchGen)
            .Sample((leftRaw, rightRaw) =>
            {
                Span<byte> left = stackalloc byte[Count * size];
                Span<byte> right = stackalloc byte[Count * size];
                Span<byte> batched = stackalloc byte[Count * size];
                Span<byte> expected = stackalloc byte[Count * size];

                for(int i = 0; i < Count; i++)
                {
                    int offset = i * size;
                    ReduceDelegate(leftRaw.AsSpan(offset, size), left.Slice(offset, size), CurveParameterSet.Bn254);
                    ReduceDelegate(rightRaw.AsSpan(offset, size), right.Slice(offset, size), CurveParameterSet.Bn254);
                }

                neonBatchMultiply(left, right, batched, Count, CurveParameterSet.Bn254);

                for(int i = 0; i < Count; i++)
                {
                    int offset = i * size;
                    bigIntegerMultiply(left.Slice(offset, size), right.Slice(offset, size), expected.Slice(offset, size), CurveParameterSet.Bn254);
                }

                return batched.SequenceEqual(expected);
            }, iter: IterationCount);
    }


    [TestMethod]
    public void NeonAddAgreesWithBigIntegerAdd()
    {
        ScalarAddDelegate bigIntegerAdd = Bn254BigIntegerScalarReference.GetAdd();
        ScalarAddDelegate neonAdd = Bn254NeonScalarBackend.GetAdd();
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes) =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);
                using Scalar b = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);

                using Scalar referenceSum = a.Add(b, bigIntegerAdd, pool);
                using Scalar neonSum = a.Add(b, neonAdd, pool);

                return referenceSum.AsReadOnlySpan().SequenceEqual(neonSum.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void NeonSubtractAgreesWithBigIntegerSubtract()
    {
        ScalarSubtractDelegate bigIntegerSubtract = Bn254BigIntegerScalarReference.GetSubtract();
        ScalarSubtractDelegate neonSubtract = Bn254NeonScalarBackend.GetSubtract();
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes) =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);
                using Scalar b = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);

                using Scalar referenceDiff = a.Subtract(b, bigIntegerSubtract, pool);
                using Scalar neonDiff = a.Subtract(b, neonSubtract, pool);

                return referenceDiff.AsReadOnlySpan().SequenceEqual(neonDiff.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void NeonMultiplyAgreesWithBigIntegerMultiply()
    {
        ScalarMultiplyDelegate bigIntegerMultiply = Bn254BigIntegerScalarReference.GetMultiply();
        ScalarMultiplyDelegate neonMultiply = Bn254NeonScalarBackend.GetMultiply();
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes) =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);
                using Scalar b = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);

                using Scalar referenceProduct = a.Multiply(b, bigIntegerMultiply, pool);
                using Scalar neonProduct = a.Multiply(b, neonMultiply, pool);

                return referenceProduct.AsReadOnlySpan().SequenceEqual(neonProduct.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void NeonNegateAgreesWithBigIntegerNegate()
    {
        ScalarNegateDelegate bigIntegerNegate = Bn254BigIntegerScalarReference.GetNegate();
        ScalarNegateDelegate neonNegate = Bn254NeonScalarBackend.GetNegate();
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;

        RawScalarBytesGen
            .Sample(aBytes =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);

                using Scalar referenceNegation = a.Negate(bigIntegerNegate, pool);
                using Scalar neonNegation = a.Negate(neonNegate, pool);

                return referenceNegation.AsReadOnlySpan().SequenceEqual(neonNegation.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void NeonInvertAgreesWithBigIntegerInvert()
    {
        ScalarInvertDelegate bigIntegerInvert = Bn254BigIntegerScalarReference.GetInvert();
        ScalarInvertDelegate neonInvert = Bn254NeonScalarBackend.GetInvert();
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;

        RawScalarBytesGen
            .Sample(aBytes =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);
                if(a.IsZero)
                {
                    return true;
                }

                using Scalar referenceInverse = a.Invert(bigIntegerInvert, pool);
                using Scalar neonInverse = a.Invert(neonInvert, pool);

                return referenceInverse.AsReadOnlySpan().SequenceEqual(neonInverse.AsReadOnlySpan());
            }, iter: IterationCount);
    }
}
