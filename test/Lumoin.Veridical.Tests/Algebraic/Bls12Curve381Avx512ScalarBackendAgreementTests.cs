using CsCheck;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Property-based agreement tests for the AVX-512 scalar backend
/// specifically. Inconclusive when the host CPU lacks AVX-512F (which
/// is most consumer x64 chips and all ARM hosts), so these tests light
/// up only on Sapphire Rapids / Zen 4+ silicon. Without these the
/// AVX-512 path is exercised only indirectly through the dispatch
/// facade — and only on hosts where it is the top-pick path.
/// </summary>
[TestClass]
internal sealed class Bls12Curve381Avx512ScalarBackendAgreementTests
{
    private static readonly ScalarReduceDelegate ReduceDelegate =
        Bls12Curve381BigIntegerScalarReference.GetReduce();

    private static readonly Gen<byte[]> RawScalarBytesGen =
        Gen.Byte.Array[Scalar.SizeBytes];

    private const long IterationCount = 200;


    public TestContext TestContext { get; set; } = null!;


    [TestInitialize]
    public void RequireAvx512() => InstructionSetRequirements.RequireAvx512();


    [TestMethod]
    public void Avx512BatchMultiplyAgreesWithBigIntegerMultiply()
    {
        ScalarMultiplyDelegate bigIntegerMultiply = Bls12Curve381BigIntegerScalarReference.GetMultiply();
        ScalarBatchMultiplyDelegate avx512BatchMultiply = Bls12Curve381Avx512ScalarBackend.GetBatchMultiply();

        //Nineteen elements exercise two full lane-octets plus a three-element serial
        //tail in one call.
        const int Count = 19;
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

                avx512BatchMultiply(left, right, batched, Count, CurveParameterSet.Bls12Curve381);

                for(int i = 0; i < Count; i++)
                {
                    int offset = i * size;
                    bigIntegerMultiply(left.Slice(offset, size), right.Slice(offset, size), expected.Slice(offset, size), CurveParameterSet.Bls12Curve381);
                }

                return batched.SequenceEqual(expected);
            }, iter: IterationCount);
    }


    [TestMethod]
    public void Avx512AddAgreesWithBigIntegerAdd()
    {
        ScalarAddDelegate bigIntegerAdd = Bls12Curve381BigIntegerScalarReference.GetAdd();
        ScalarAddDelegate avx512Add = Bls12Curve381Avx512ScalarBackend.GetAdd();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes) =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
                using Scalar b = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);

                using Scalar referenceSum = a.Add(b, bigIntegerAdd, pool);
                using Scalar avx512Sum = a.Add(b, avx512Add, pool);

                return referenceSum.AsReadOnlySpan().SequenceEqual(avx512Sum.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void Avx512SubtractAgreesWithBigIntegerSubtract()
    {
        ScalarSubtractDelegate bigIntegerSubtract = Bls12Curve381BigIntegerScalarReference.GetSubtract();
        ScalarSubtractDelegate avx512Subtract = Bls12Curve381Avx512ScalarBackend.GetSubtract();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes) =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
                using Scalar b = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);

                using Scalar referenceDiff = a.Subtract(b, bigIntegerSubtract, pool);
                using Scalar avx512Diff = a.Subtract(b, avx512Subtract, pool);

                return referenceDiff.AsReadOnlySpan().SequenceEqual(avx512Diff.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void Avx512MultiplyAgreesWithBigIntegerMultiply()
    {
        ScalarMultiplyDelegate bigIntegerMultiply = Bls12Curve381BigIntegerScalarReference.GetMultiply();
        ScalarMultiplyDelegate avx512Multiply = Bls12Curve381Avx512ScalarBackend.GetMultiply();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes) =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
                using Scalar b = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);

                using Scalar referenceProduct = a.Multiply(b, bigIntegerMultiply, pool);
                using Scalar avx512Product = a.Multiply(b, avx512Multiply, pool);

                return referenceProduct.AsReadOnlySpan().SequenceEqual(avx512Product.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void Avx512NegateAgreesWithBigIntegerNegate()
    {
        ScalarNegateDelegate bigIntegerNegate = Bls12Curve381BigIntegerScalarReference.GetNegate();
        ScalarNegateDelegate avx512Negate = Bls12Curve381Avx512ScalarBackend.GetNegate();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        RawScalarBytesGen
            .Sample(aBytes =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);

                using Scalar referenceNegation = a.Negate(bigIntegerNegate, pool);
                using Scalar avx512Negation = a.Negate(avx512Negate, pool);

                return referenceNegation.AsReadOnlySpan().SequenceEqual(avx512Negation.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void Avx512InvertAgreesWithBigIntegerInvert()
    {
        ScalarInvertDelegate bigIntegerInvert = Bls12Curve381BigIntegerScalarReference.GetInvert();
        ScalarInvertDelegate avx512Invert = Bls12Curve381Avx512ScalarBackend.GetInvert();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        RawScalarBytesGen
            .Sample(aBytes =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bls12Curve381, pool);
                if(a.IsZero)
                {
                    return true;
                }

                using Scalar referenceInverse = a.Invert(bigIntegerInvert, pool);
                using Scalar avx512Inverse = a.Invert(avx512Invert, pool);

                return referenceInverse.AsReadOnlySpan().SequenceEqual(avx512Inverse.AsReadOnlySpan());
            }, iter: IterationCount);
    }
}