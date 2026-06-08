using CsCheck;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Property-based agreement tests for the BN254 AVX-512 scalar backend, the BN254
/// mirror of <see cref="Bls12Curve381Avx512ScalarBackendAgreementTests"/>.
/// Inconclusive on hosts lacking AVX-512F; add and subtract are covered here.
/// </summary>
[TestClass]
internal sealed class Bn254Avx512ScalarBackendAgreementTests
{
    private static readonly ScalarReduceDelegate ReduceDelegate =
        Bn254BigIntegerScalarReference.GetReduce();

    private static readonly Gen<byte[]> RawScalarBytesGen =
        Gen.Byte.Array[Scalar.SizeBytes];

    private const long IterationCount = 200;


    public TestContext TestContext { get; set; } = null!;


    [TestInitialize]
    public void RequireAvx512() => InstructionSetRequirements.RequireAvx512();


    [TestMethod]
    public void Avx512BatchMultiplyAgreesWithBigIntegerMultiply()
    {
        ScalarMultiplyDelegate bigIntegerMultiply = Bn254BigIntegerScalarReference.GetMultiply();
        ScalarBatchMultiplyDelegate avx512BatchMultiply = Bn254Avx512ScalarBackend.GetBatchMultiply();

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
                    ReduceDelegate(leftRaw.AsSpan(offset, size), left.Slice(offset, size), CurveParameterSet.Bn254);
                    ReduceDelegate(rightRaw.AsSpan(offset, size), right.Slice(offset, size), CurveParameterSet.Bn254);
                }

                avx512BatchMultiply(left, right, batched, Count, CurveParameterSet.Bn254);

                for(int i = 0; i < Count; i++)
                {
                    int offset = i * size;
                    bigIntegerMultiply(left.Slice(offset, size), right.Slice(offset, size), expected.Slice(offset, size), CurveParameterSet.Bn254);
                }

                return batched.SequenceEqual(expected);
            }, iter: IterationCount);
    }


    [TestMethod]
    public void Avx512AddAgreesWithBigIntegerAdd()
    {
        ScalarAddDelegate bigIntegerAdd = Bn254BigIntegerScalarReference.GetAdd();
        ScalarAddDelegate avx512Add = Bn254Avx512ScalarBackend.GetAdd();
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes) =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);
                using Scalar b = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);

                using Scalar referenceSum = a.Add(b, bigIntegerAdd, pool);
                using Scalar avx512Sum = a.Add(b, avx512Add, pool);

                return referenceSum.AsReadOnlySpan().SequenceEqual(avx512Sum.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void Avx512SubtractAgreesWithBigIntegerSubtract()
    {
        ScalarSubtractDelegate bigIntegerSubtract = Bn254BigIntegerScalarReference.GetSubtract();
        ScalarSubtractDelegate avx512Subtract = Bn254Avx512ScalarBackend.GetSubtract();
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes) =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);
                using Scalar b = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);

                using Scalar referenceDiff = a.Subtract(b, bigIntegerSubtract, pool);
                using Scalar avx512Diff = a.Subtract(b, avx512Subtract, pool);

                return referenceDiff.AsReadOnlySpan().SequenceEqual(avx512Diff.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void Avx512MultiplyAgreesWithBigIntegerMultiply()
    {
        ScalarMultiplyDelegate bigIntegerMultiply = Bn254BigIntegerScalarReference.GetMultiply();
        ScalarMultiplyDelegate avx512Multiply = Bn254Avx512ScalarBackend.GetMultiply();
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes) =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);
                using Scalar b = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);

                using Scalar referenceProduct = a.Multiply(b, bigIntegerMultiply, pool);
                using Scalar avx512Product = a.Multiply(b, avx512Multiply, pool);

                return referenceProduct.AsReadOnlySpan().SequenceEqual(avx512Product.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void Avx512NegateAgreesWithBigIntegerNegate()
    {
        ScalarNegateDelegate bigIntegerNegate = Bn254BigIntegerScalarReference.GetNegate();
        ScalarNegateDelegate avx512Negate = Bn254Avx512ScalarBackend.GetNegate();
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;

        RawScalarBytesGen
            .Sample(aBytes =>
            {
                using Scalar a = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);

                using Scalar referenceNegation = a.Negate(bigIntegerNegate, pool);
                using Scalar avx512Negation = a.Negate(avx512Negate, pool);

                return referenceNegation.AsReadOnlySpan().SequenceEqual(avx512Negation.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void Avx512InvertAgreesWithBigIntegerInvert()
    {
        ScalarInvertDelegate bigIntegerInvert = Bn254BigIntegerScalarReference.GetInvert();
        ScalarInvertDelegate avx512Invert = Bn254Avx512ScalarBackend.GetInvert();
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
                using Scalar avx512Inverse = a.Invert(avx512Invert, pool);

                return referenceInverse.AsReadOnlySpan().SequenceEqual(avx512Inverse.AsReadOnlySpan());
            }, iter: IterationCount);
    }
}
