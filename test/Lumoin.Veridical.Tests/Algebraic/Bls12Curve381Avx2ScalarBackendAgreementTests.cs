using CsCheck;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Property-based agreement tests for the AVX2 scalar backend
/// specifically — not the dispatch facade. On hosts that also have
/// AVX-512, the facade picks AVX-512 and the AVX2 path goes untested
/// there unless these tests exist. <see cref="TestInitialize"/> gates
/// the whole class on <see cref="System.Runtime.Intrinsics.X86.Avx2.IsSupported"/>.
/// </summary>
[TestClass]
internal sealed class Bls12Curve381Avx2ScalarBackendAgreementTests
{
    private static readonly ScalarReduceDelegate ReduceDelegate =
        Bls12Curve381BigIntegerScalarReference.GetReduce();

    private static readonly Gen<byte[]> RawScalarBytesGen =
        Gen.Byte.Array[Scalar.SizeBytes];

    private const long IterationCount = 200;


    public TestContext TestContext { get; set; } = null!;


    [TestInitialize]
    public void RequireAvx2() => InstructionSetRequirements.RequireAvx2();


    [TestMethod]
    public void Avx2AddAgreesWithBigIntegerAdd()
    {
        ScalarAddDelegate bigIntegerAdd = Bls12Curve381BigIntegerScalarReference.GetAdd();
        ScalarAddDelegate avx2Add = Bls12Curve381Avx2ScalarBackend.GetAdd();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes) =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
                using Scalar b = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);

                using Scalar referenceSum = a.Add(b, bigIntegerAdd, pool);
                using Scalar avx2Sum = a.Add(b, avx2Add, pool);

                return referenceSum.AsReadOnlySpan().SequenceEqual(avx2Sum.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void Avx2SubtractAgreesWithBigIntegerSubtract()
    {
        ScalarSubtractDelegate bigIntegerSubtract = Bls12Curve381BigIntegerScalarReference.GetSubtract();
        ScalarSubtractDelegate avx2Subtract = Bls12Curve381Avx2ScalarBackend.GetSubtract();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes) =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
                using Scalar b = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);

                using Scalar referenceDiff = a.Subtract(b, bigIntegerSubtract, pool);
                using Scalar avx2Diff = a.Subtract(b, avx2Subtract, pool);

                return referenceDiff.AsReadOnlySpan().SequenceEqual(avx2Diff.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void Avx2MultiplyAgreesWithBigIntegerMultiply()
    {
        ScalarMultiplyDelegate bigIntegerMultiply = Bls12Curve381BigIntegerScalarReference.GetMultiply();
        ScalarMultiplyDelegate avx2Multiply = Bls12Curve381Avx2ScalarBackend.GetMultiply();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes) =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
                using Scalar b = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);

                using Scalar referenceProduct = a.Multiply(b, bigIntegerMultiply, pool);
                using Scalar avx2Product = a.Multiply(b, avx2Multiply, pool);

                return referenceProduct.AsReadOnlySpan().SequenceEqual(avx2Product.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void Avx2BatchMultiplyAgreesWithBigIntegerMultiply()
    {
        ScalarMultiplyDelegate bigIntegerMultiply = Bls12Curve381BigIntegerScalarReference.GetMultiply();
        ScalarBatchMultiplyDelegate avx2BatchMultiply = Bls12Curve381Avx2ScalarBackend.GetBatchMultiply();

        //Eleven elements exercise two full lane-quartets plus a three-element serial
        //tail in one call.
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
                    ReduceDelegate(leftRaw.AsSpan(offset, size), left.Slice(offset, size), CurveParameterSet.Bls12Curve381);
                    ReduceDelegate(rightRaw.AsSpan(offset, size), right.Slice(offset, size), CurveParameterSet.Bls12Curve381);
                }

                avx2BatchMultiply(left, right, batched, Count, CurveParameterSet.Bls12Curve381);

                for(int i = 0; i < Count; i++)
                {
                    int offset = i * size;
                    bigIntegerMultiply(left.Slice(offset, size), right.Slice(offset, size), expected.Slice(offset, size), CurveParameterSet.Bls12Curve381);
                }

                return batched.SequenceEqual(expected);
            }, iter: IterationCount);
    }


    [TestMethod]
    public void Avx2NegateAgreesWithBigIntegerNegate()
    {
        ScalarNegateDelegate bigIntegerNegate = Bls12Curve381BigIntegerScalarReference.GetNegate();
        ScalarNegateDelegate avx2Negate = Bls12Curve381Avx2ScalarBackend.GetNegate();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        RawScalarBytesGen
            .Sample(aBytes =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);

                using Scalar referenceNegation = a.Negate(bigIntegerNegate, pool);
                using Scalar avx2Negation = a.Negate(avx2Negate, pool);

                return referenceNegation.AsReadOnlySpan().SequenceEqual(avx2Negation.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void Avx2InvertAgreesWithBigIntegerInvert()
    {
        ScalarInvertDelegate bigIntegerInvert = Bls12Curve381BigIntegerScalarReference.GetInvert();
        ScalarInvertDelegate avx2Invert = Bls12Curve381Avx2ScalarBackend.GetInvert();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        RawScalarBytesGen
            .Sample(aBytes =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);

                //Zero is not invertible; both backends throw on it. A random reduced
                //value lands on zero with negligible probability, but skip it so the
                //sweep tests only the inversion identity, not the throw contract.
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