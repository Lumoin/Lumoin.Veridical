using CsCheck;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Property-based agreement tests for the BN254 AVX2 scalar backend, the BN254
/// mirror of <see cref="Bls12Curve381Avx2ScalarBackendAgreementTests"/>. Gated on
/// <see cref="System.Runtime.Intrinsics.X86.Avx2"/> support; add and subtract are
/// covered here (multiply and invert land with the BN254 Montgomery path).
/// </summary>
[TestClass]
internal sealed class Bn254Avx2ScalarBackendAgreementTests
{
    private static readonly ScalarReduceDelegate ReduceDelegate =
        Bn254BigIntegerScalarReference.GetReduce();

    private static readonly Gen<byte[]> RawScalarBytesGen =
        Gen.Byte.Array[Scalar.SizeBytes];

    private const long IterationCount = 200;


    public TestContext TestContext { get; set; } = null!;


    [TestInitialize]
    public void RequireAvx2() => InstructionSetRequirements.RequireAvx2();


    [TestMethod]
    public void Avx2BatchMultiplyAgreesWithBigIntegerMultiply()
    {
        ScalarMultiplyDelegate bigIntegerMultiply = Bn254BigIntegerScalarReference.GetMultiply();
        ScalarBatchMultiplyDelegate avx2BatchMultiply = Bn254Avx2ScalarBackend.GetBatchMultiply();

        const int Count = 11;
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

                avx2BatchMultiply(left, right, batched, Count, CurveParameterSet.Bn254);

                for(int i = 0; i < Count; i++)
                {
                    int offset = i * size;
                    bigIntegerMultiply(left.Slice(offset, size), right.Slice(offset, size), expected.Slice(offset, size), CurveParameterSet.Bn254);
                }

                return batched.SequenceEqual(expected);
            }, iter: IterationCount);
    }


    [TestMethod]
    public void Avx2AddAgreesWithBigIntegerAdd()
    {
        ScalarAddDelegate bigIntegerAdd = Bn254BigIntegerScalarReference.GetAdd();
        ScalarAddDelegate avx2Add = Bn254Avx2ScalarBackend.GetAdd();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes) =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);
                using Scalar b = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);

                using Scalar referenceSum = a.Add(b, bigIntegerAdd, pool);
                using Scalar avx2Sum = a.Add(b, avx2Add, pool);

                return referenceSum.AsReadOnlySpan().SequenceEqual(avx2Sum.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void Avx2SubtractAgreesWithBigIntegerSubtract()
    {
        ScalarSubtractDelegate bigIntegerSubtract = Bn254BigIntegerScalarReference.GetSubtract();
        ScalarSubtractDelegate avx2Subtract = Bn254Avx2ScalarBackend.GetSubtract();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes) =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);
                using Scalar b = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);

                using Scalar referenceDiff = a.Subtract(b, bigIntegerSubtract, pool);
                using Scalar avx2Diff = a.Subtract(b, avx2Subtract, pool);

                return referenceDiff.AsReadOnlySpan().SequenceEqual(avx2Diff.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void Avx2MultiplyAgreesWithBigIntegerMultiply()
    {
        ScalarMultiplyDelegate bigIntegerMultiply = Bn254BigIntegerScalarReference.GetMultiply();
        ScalarMultiplyDelegate avx2Multiply = Bn254Avx2ScalarBackend.GetMultiply();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes) =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);
                using Scalar b = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);

                using Scalar referenceProduct = a.Multiply(b, bigIntegerMultiply, pool);
                using Scalar avx2Product = a.Multiply(b, avx2Multiply, pool);

                return referenceProduct.AsReadOnlySpan().SequenceEqual(avx2Product.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void Avx2NegateAgreesWithBigIntegerNegate()
    {
        ScalarNegateDelegate bigIntegerNegate = Bn254BigIntegerScalarReference.GetNegate();
        ScalarNegateDelegate avx2Negate = Bn254Avx2ScalarBackend.GetNegate();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        RawScalarBytesGen
            .Sample(aBytes =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);

                using Scalar referenceNegation = a.Negate(bigIntegerNegate, pool);
                using Scalar avx2Negation = a.Negate(avx2Negate, pool);

                return referenceNegation.AsReadOnlySpan().SequenceEqual(avx2Negation.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void Avx2InvertAgreesWithBigIntegerInvert()
    {
        ScalarInvertDelegate bigIntegerInvert = Bn254BigIntegerScalarReference.GetInvert();
        ScalarInvertDelegate avx2Invert = Bn254Avx2ScalarBackend.GetInvert();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        RawScalarBytesGen
            .Sample(aBytes =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);
                if(a.IsZero)
                {
                    return true;
                }

                using Scalar referenceInverse = a.Invert(bigIntegerInvert, pool);
                using Scalar avx2Inverse = a.Invert(avx2Invert, pool);

                return referenceInverse.AsReadOnlySpan().SequenceEqual(avx2Inverse.AsReadOnlySpan());
            }, iter: IterationCount);
    }
}
