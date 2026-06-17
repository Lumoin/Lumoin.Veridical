using CsCheck;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Provenance;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Tests for the BN254 (alt_bn128) managed scalar-field backend
/// (<see cref="Bn254BigIntegerScalarReference"/>). Two layers cover the
/// eight scalar delegates: a property-based suite that states the algebraic
/// laws (commutativity, associativity, distributivity, additive and
/// multiplicative inverse) and verifies them over randomly sampled scalars,
/// and a known-answer suite whose expected values were produced by two
/// independent big-integer engines (JavaScript <c>BigInt</c> and CPython,
/// neither of which shares code with <see cref="System.Numerics.BigInteger"/>).
/// </summary>
/// <remarks>
/// <para>
/// The reference is wired in exactly as an application would wire a backend:
/// the test retrieves the delegate it needs and passes it into the operation,
/// dispatching on <see cref="CurveParameterSet.Bn254"/>. The property tests
/// reduce raw CsCheck bytes to canonical scalars via
/// <see cref="Scalar.FromBytesReduced"/>; the test code itself never performs
/// modular arithmetic.
/// </para>
/// <para>
/// BN254's scalar field has no Ethereum precompile vectors of its own — the
/// alt_bn128 precompiles (EIP-196/197) exercise base-field and group
/// arithmetic, with the scalar field appearing only as the exponent of a
/// scalar multiplication. The known-answer vectors here are therefore
/// generated and cross-checked between two independent engines per the
/// batch's test-vector policy, with edge cases (the order's neighbours
/// <c>r - 1</c> and <c>r + 1</c>, and a wide reduction input) chosen to catch
/// off-by-one and sign-handling faults.
/// </para>
/// <para>
/// Working buffers are <c>stackalloc</c> spans or pool rentals, never
/// heap-allocated arrays, matching the memory discipline of the production
/// backend and the existing BLS scalar tests.
/// </para>
/// </remarks>
[TestClass]
internal sealed class Bn254ScalarBackendTests
{
    private static readonly ScalarReduceDelegate ReduceDelegate =
        Bn254BigIntegerScalarReference.GetReduce();


    private static readonly Gen<byte[]> RawScalarBytesGen =
        Gen.Byte.Array[Scalar.SizeBytes];


    private static readonly int[] BatchSizesToSweep = [1, 3, 4, 5, 8, 17];

    private const long BatchIterationCount = 50;


    //Known-answer vectors over the BN254 scalar field, columns:
    //(a, b, a+b, a-b, a*b, -a, -b, a^-1, b^-1), all canonical 32-byte big-endian
    //hex. Cross-checked between JavaScript BigInt and CPython. The second row is
    //the order's lower neighbour r-1 paired with 2: a+b wraps to 1, a*b wraps to
    //r-2, and (r-1)^-1 is r-1 since (r-1)^2 = 1 mod r.
    private static readonly (string A, string B, string Add, string Sub, string Mul, string NegA, string NegB, string InvA, string InvB)[] ArithmeticVectors =
    [
        ("0000000000000000000000000000000000000000000000000000000000000007",
         "0000000000000000000000000000000000000000000000000000000000000005",
         "000000000000000000000000000000000000000000000000000000000000000c",
         "0000000000000000000000000000000000000000000000000000000000000002",
         "0000000000000000000000000000000000000000000000000000000000000023",
         "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffffa",
         "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffffc",
         "06e9c21069503b73ac9dc0d0edede80d4ee2d80a5a8834a709b290cbfdb6db6e",
         "135b52945a13d9aa49b9b57c33cd568ba9ae5ce9ca4a2d06e7f3fbd4c6666667"),

        ("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",
         "0000000000000000000000000000000000000000000000000000000000000002",
         "0000000000000000000000000000000000000000000000000000000000000001",
         "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffffe",
         "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffffff",
         "0000000000000000000000000000000000000000000000000000000000000001",
         "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffffff",
         "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",
         "183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000001"),

        ("001f3e5c7a9b0d2468ace013579bdf2468ace013579bdf2468ace013579bdf02",
         "0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829",
         "0a2a4a6988aa1d357abff4286db2f73d82c7fc3075baff458ad004387dc3072b",
         "267880c24dbd9d3d0eea11b4c3061f6876c5ac3eb3362f948a6bb1822174b6da",
         "2491348dccdf2ae8e557d11c66996044cc933940bb54df24d46c23ea512577de",
         "30451016669693054fa365a329e57938bf870835221d916cdb351580986420ff",
         "26594265d3229018a63d31a16b6a40440e18cc2b5b9a507021bed16ec9d8d7d8",
         "2fc563df399b662cb56375f360cf59e544e5b6e9dcb29e9ed05f2b36674071f8",
         "0fc29474236236002c612cc543de101b89ccb746118b1bd3a3f0a17e57a81e2e"),
    ];


    //Reduce vectors, (arbitrary-width big-endian input, canonical reduced output).
    //The 64-byte all-ones input exercises a value far wider than the modulus; the
    //32-byte input with a high top byte (0x91...) confirms the reducer treats the
    //input as unsigned rather than tripping the BigInteger sign bit.
    private static readonly (string Input, string Output)[] ReduceVectors =
    [
        ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
         "0216d0b17f4e44a58c49833d53bb808553fe3ab1e35c59e31bb8e645ae216da6"),

        ("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000002",
         "0000000000000000000000000000000000000000000000000000000000000001"),

        ("912ceb58a394e07d28f0d12384840917789bb8d96d2c51b3cba5e0bbd75bcd18",
         "00000000000000000000000000000000000000000000000000000000075bcd15"),
    ];


    //The order itself, big-endian; reduces to zero. Widest reduce input is 64 bytes.
    private const string FieldOrderHex =
        "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";

    private const int MaxReduceInputBytes = 64;


    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void AddMatchesReferenceVectors()
    {
        ScalarAddDelegate add = Bn254BigIntegerScalarReference.GetAdd();

        Span<byte> a = stackalloc byte[Scalar.SizeBytes];
        Span<byte> b = stackalloc byte[Scalar.SizeBytes];
        Span<byte> expected = stackalloc byte[Scalar.SizeBytes];
        Span<byte> result = stackalloc byte[Scalar.SizeBytes];

        foreach((string aHex, string bHex, string sumHex, _, _, _, _, _, _) in ArithmeticVectors)
        {
            Decode(aHex, a);
            Decode(bHex, b);
            Decode(sumHex, expected);
            add(a, b, result, CurveParameterSet.Bn254);
            AssertSpanEqual(expected, result, $"add({aHex}, {bHex})");
        }
    }


    [TestMethod]
    public void SubtractMatchesReferenceVectors()
    {
        ScalarSubtractDelegate subtract = Bn254BigIntegerScalarReference.GetSubtract();

        Span<byte> a = stackalloc byte[Scalar.SizeBytes];
        Span<byte> b = stackalloc byte[Scalar.SizeBytes];
        Span<byte> expected = stackalloc byte[Scalar.SizeBytes];
        Span<byte> result = stackalloc byte[Scalar.SizeBytes];

        foreach((string aHex, string bHex, _, string diffHex, _, _, _, _, _) in ArithmeticVectors)
        {
            Decode(aHex, a);
            Decode(bHex, b);
            Decode(diffHex, expected);
            subtract(a, b, result, CurveParameterSet.Bn254);
            AssertSpanEqual(expected, result, $"subtract({aHex}, {bHex})");
        }
    }


    [TestMethod]
    public void MultiplyMatchesReferenceVectors()
    {
        ScalarMultiplyDelegate multiply = Bn254BigIntegerScalarReference.GetMultiply();

        Span<byte> a = stackalloc byte[Scalar.SizeBytes];
        Span<byte> b = stackalloc byte[Scalar.SizeBytes];
        Span<byte> expected = stackalloc byte[Scalar.SizeBytes];
        Span<byte> result = stackalloc byte[Scalar.SizeBytes];

        foreach((string aHex, string bHex, _, _, string productHex, _, _, _, _) in ArithmeticVectors)
        {
            Decode(aHex, a);
            Decode(bHex, b);
            Decode(productHex, expected);
            multiply(a, b, result, CurveParameterSet.Bn254);
            AssertSpanEqual(expected, result, $"multiply({aHex}, {bHex})");
        }
    }


    [TestMethod]
    public void NegateMatchesReferenceVectors()
    {
        ScalarNegateDelegate negate = Bn254BigIntegerScalarReference.GetNegate();

        Span<byte> operand = stackalloc byte[Scalar.SizeBytes];
        Span<byte> expected = stackalloc byte[Scalar.SizeBytes];
        Span<byte> result = stackalloc byte[Scalar.SizeBytes];

        foreach((string aHex, string bHex, _, _, _, string negAHex, string negBHex, _, _) in ArithmeticVectors)
        {
            Decode(aHex, operand);
            Decode(negAHex, expected);
            negate(operand, result, CurveParameterSet.Bn254);
            AssertSpanEqual(expected, result, $"negate({aHex})");

            Decode(bHex, operand);
            Decode(negBHex, expected);
            negate(operand, result, CurveParameterSet.Bn254);
            AssertSpanEqual(expected, result, $"negate({bHex})");
        }
    }


    [TestMethod]
    public void InvertMatchesReferenceVectorsAndProducesUnitProduct()
    {
        ScalarInvertDelegate invert = Bn254BigIntegerScalarReference.GetInvert();
        ScalarMultiplyDelegate multiply = Bn254BigIntegerScalarReference.GetMultiply();

        foreach((string aHex, string bHex, _, _, _, _, _, string invAHex, string invBHex) in ArithmeticVectors)
        {
            AssertInverse(aHex, invAHex, invert, multiply);
            AssertInverse(bHex, invBHex, invert, multiply);
        }
    }


    private static void AssertInverse(string valueHex, string expectedInverseHex, ScalarInvertDelegate invert, ScalarMultiplyDelegate multiply)
    {
        Span<byte> value = stackalloc byte[Scalar.SizeBytes];
        Span<byte> expectedInverse = stackalloc byte[Scalar.SizeBytes];
        Span<byte> inverse = stackalloc byte[Scalar.SizeBytes];
        Span<byte> product = stackalloc byte[Scalar.SizeBytes];

        Decode(valueHex, value);
        Decode(expectedInverseHex, expectedInverse);

        invert(value, inverse, CurveParameterSet.Bn254);
        AssertSpanEqual(expectedInverse, inverse, $"invert({valueHex})");

        multiply(value, inverse, product, CurveParameterSet.Bn254);

        Span<byte> one = stackalloc byte[Scalar.SizeBytes];
        one[^1] = 1;
        AssertSpanEqual(one, product, $"{valueHex} * invert({valueHex}) should be one");
    }


    [TestMethod]
    public void InvertZeroThrows()
    {
        ScalarInvertDelegate invert = Bn254BigIntegerScalarReference.GetInvert();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using IMemoryOwner<byte> zeroOwner = pool.Rent(Scalar.SizeBytes);
        using IMemoryOwner<byte> resultOwner = pool.Rent(Scalar.SizeBytes);
        zeroOwner.Memory.Span[..Scalar.SizeBytes].Clear();

        Assert.ThrowsExactly<InvalidOperationException>(() =>
            invert(zeroOwner.Memory.Span[..Scalar.SizeBytes], resultOwner.Memory.Span[..Scalar.SizeBytes], CurveParameterSet.Bn254));
    }


    [TestMethod]
    public void ReduceMatchesReferenceVectors()
    {
        ScalarReduceDelegate reduce = Bn254BigIntegerScalarReference.GetReduce();

        Span<byte> input = stackalloc byte[MaxReduceInputBytes];
        Span<byte> expected = stackalloc byte[Scalar.SizeBytes];
        Span<byte> result = stackalloc byte[Scalar.SizeBytes];

        foreach((string inputHex, string outputHex) in ReduceVectors)
        {
            int inputLength = Decode(inputHex, input);
            Decode(outputHex, expected);
            reduce(input[..inputLength], result, CurveParameterSet.Bn254);
            AssertSpanEqual(expected, result, $"reduce({inputHex})");
        }
    }


    [TestMethod]
    public void ReduceOfFieldOrderIsZero()
    {
        ScalarReduceDelegate reduce = Bn254BigIntegerScalarReference.GetReduce();

        Span<byte> input = stackalloc byte[Scalar.SizeBytes];
        Span<byte> expected = stackalloc byte[Scalar.SizeBytes];
        Span<byte> result = stackalloc byte[Scalar.SizeBytes];

        Decode(FieldOrderHex, input);
        expected.Clear();
        reduce(input, result, CurveParameterSet.Bn254);
        AssertSpanEqual(expected, result, "reduce(r) should be zero");
    }


    [TestMethod]
    public void AdditionIsCommutative()
    {
        ScalarAddDelegate add = Bn254BigIntegerScalarReference.GetAdd();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes) =>
            {
                using Scalar scalarA = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);
                using Scalar scalarB = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);
                using Scalar leftThenRight = scalarA.Add(scalarB, add, pool);
                using Scalar rightThenLeft = scalarB.Add(scalarA, add, pool);

                return leftThenRight.AsReadOnlySpan().SequenceEqual(rightThenLeft.AsReadOnlySpan());
            }, time: 1);
    }


    [TestMethod]
    public void AdditionIsAssociative()
    {
        ScalarAddDelegate add = Bn254BigIntegerScalarReference.GetAdd();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes, cBytes) =>
            {
                using Scalar sA = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);
                using Scalar sB = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);
                using Scalar sC = Scalar.FromBytesReduced(cBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);

                using Scalar aPlusB = sA.Add(sB, add, pool);
                using Scalar abThenC = aPlusB.Add(sC, add, pool);
                using Scalar bPlusC = sB.Add(sC, add, pool);
                using Scalar aThenBc = sA.Add(bPlusC, add, pool);

                return abThenC.AsReadOnlySpan().SequenceEqual(aThenBc.AsReadOnlySpan());
            }, time: 1);
    }


    [TestMethod]
    public void NegationIsAdditiveInverse()
    {
        ScalarAddDelegate add = Bn254BigIntegerScalarReference.GetAdd();
        ScalarNegateDelegate negate = Bn254BigIntegerScalarReference.GetNegate();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        RawScalarBytesGen.Sample(aBytes =>
        {
            using Scalar scalarA = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);
            using Scalar negatedA = scalarA.Negate(negate, pool);
            using Scalar sum = scalarA.Add(negatedA, add, pool);

            return sum.IsZero;
        }, time: 1);
    }


    [TestMethod]
    public void MultiplicationIsCommutative()
    {
        ScalarMultiplyDelegate multiply = Bn254BigIntegerScalarReference.GetMultiply();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes) =>
            {
                using Scalar sA = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);
                using Scalar sB = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);
                using Scalar leftThenRight = sA.Multiply(sB, multiply, pool);
                using Scalar rightThenLeft = sB.Multiply(sA, multiply, pool);

                return leftThenRight.AsReadOnlySpan().SequenceEqual(rightThenLeft.AsReadOnlySpan());
            }, time: 1);
    }


    [TestMethod]
    public void MultiplicationIsAssociative()
    {
        ScalarMultiplyDelegate multiply = Bn254BigIntegerScalarReference.GetMultiply();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes, cBytes) =>
            {
                using Scalar sA = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);
                using Scalar sB = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);
                using Scalar sC = Scalar.FromBytesReduced(cBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);

                using Scalar aTimesB = sA.Multiply(sB, multiply, pool);
                using Scalar abThenC = aTimesB.Multiply(sC, multiply, pool);
                using Scalar bTimesC = sB.Multiply(sC, multiply, pool);
                using Scalar aThenBc = sA.Multiply(bTimesC, multiply, pool);

                return abThenC.AsReadOnlySpan().SequenceEqual(aThenBc.AsReadOnlySpan());
            }, time: 1);
    }


    [TestMethod]
    public void MultiplicationDistributesOverAddition()
    {
        ScalarAddDelegate add = Bn254BigIntegerScalarReference.GetAdd();
        ScalarMultiplyDelegate multiply = Bn254BigIntegerScalarReference.GetMultiply();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        Gen.Select(RawScalarBytesGen, RawScalarBytesGen, RawScalarBytesGen)
            .Sample((aBytes, bBytes, cBytes) =>
            {
                using Scalar sA = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);
                using Scalar sB = Scalar.FromBytesReduced(bBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);
                using Scalar sC = Scalar.FromBytesReduced(cBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);

                using Scalar bPlusC = sB.Add(sC, add, pool);
                using Scalar leftSide = sA.Multiply(bPlusC, multiply, pool);

                using Scalar aTimesB = sA.Multiply(sB, multiply, pool);
                using Scalar aTimesC = sA.Multiply(sC, multiply, pool);
                using Scalar rightSide = aTimesB.Add(aTimesC, add, pool);

                return leftSide.AsReadOnlySpan().SequenceEqual(rightSide.AsReadOnlySpan());
            }, time: 1);
    }


    [TestMethod]
    public void InverseTimesValueIsOne()
    {
        ScalarMultiplyDelegate multiply = Bn254BigIntegerScalarReference.GetMultiply();
        ScalarInvertDelegate invert = Bn254BigIntegerScalarReference.GetInvert();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        RawScalarBytesGen.Sample(aBytes =>
        {
            using Scalar scalarA = Scalar.FromBytesReduced(aBytes, ReduceDelegate, CurveParameterSet.Bn254, pool);
            if(scalarA.IsZero)
            {
                return true;
            }

            using Scalar invA = scalarA.Invert(invert, pool);
            using Scalar product = scalarA.Multiply(invA, multiply, pool);

            return product.IsOne;
        }, time: 1);
    }


    [TestMethod]
    public void BatchAddAgreesWithPerElementAddAcrossBatchSizes()
    {
        ScalarAddDelegate add = Bn254BigIntegerScalarReference.GetAdd();
        ScalarBatchAddDelegate batchAdd = Bn254BigIntegerScalarReference.GetBatchAdd();

        foreach(int batchSize in BatchSizesToSweep)
        {
            Gen.Select(RawScalarBytesGen.Array[batchSize], RawScalarBytesGen.Array[batchSize])
                .Sample((aBatch, bBatch) =>
                {
                    int stride = Scalar.SizeBytes;
                    int total = batchSize * stride;

                    using IMemoryOwner<byte> aBufOwner = BaseMemoryPool.Shared.Rent(total);
                    using IMemoryOwner<byte> bBufOwner = BaseMemoryPool.Shared.Rent(total);
                    using IMemoryOwner<byte> batchedResultOwner = BaseMemoryPool.Shared.Rent(total);
                    using IMemoryOwner<byte> perElementResultOwner = BaseMemoryPool.Shared.Rent(total);

                    Span<byte> aBuf = aBufOwner.Memory.Span[..total];
                    Span<byte> bBuf = bBufOwner.Memory.Span[..total];
                    Span<byte> batchedResult = batchedResultOwner.Memory.Span[..total];
                    Span<byte> perElementResult = perElementResultOwner.Memory.Span[..total];

                    PackReducedScalars(aBatch, aBuf);
                    PackReducedScalars(bBatch, bBuf);

                    batchAdd(aBuf, bBuf, batchedResult, batchSize, CurveParameterSet.Bn254);
                    for(int i = 0; i < batchSize; i++)
                    {
                        int offset = i * stride;
                        add(aBuf.Slice(offset, stride), bBuf.Slice(offset, stride), perElementResult.Slice(offset, stride), CurveParameterSet.Bn254);
                    }

                    return batchedResult.SequenceEqual(perElementResult);
                }, iter: BatchIterationCount);
        }
    }


    [TestMethod]
    public void BatchSubtractAgreesWithPerElementSubtractAcrossBatchSizes()
    {
        ScalarSubtractDelegate subtract = Bn254BigIntegerScalarReference.GetSubtract();
        ScalarBatchSubtractDelegate batchSubtract = Bn254BigIntegerScalarReference.GetBatchSubtract();

        foreach(int batchSize in BatchSizesToSweep)
        {
            Gen.Select(RawScalarBytesGen.Array[batchSize], RawScalarBytesGen.Array[batchSize])
                .Sample((aBatch, bBatch) =>
                {
                    int stride = Scalar.SizeBytes;
                    int total = batchSize * stride;

                    using IMemoryOwner<byte> aBufOwner = BaseMemoryPool.Shared.Rent(total);
                    using IMemoryOwner<byte> bBufOwner = BaseMemoryPool.Shared.Rent(total);
                    using IMemoryOwner<byte> batchedResultOwner = BaseMemoryPool.Shared.Rent(total);
                    using IMemoryOwner<byte> perElementResultOwner = BaseMemoryPool.Shared.Rent(total);

                    Span<byte> aBuf = aBufOwner.Memory.Span[..total];
                    Span<byte> bBuf = bBufOwner.Memory.Span[..total];
                    Span<byte> batchedResult = batchedResultOwner.Memory.Span[..total];
                    Span<byte> perElementResult = perElementResultOwner.Memory.Span[..total];

                    PackReducedScalars(aBatch, aBuf);
                    PackReducedScalars(bBatch, bBuf);

                    batchSubtract(aBuf, bBuf, batchedResult, batchSize, CurveParameterSet.Bn254);
                    for(int i = 0; i < batchSize; i++)
                    {
                        int offset = i * stride;
                        subtract(aBuf.Slice(offset, stride), bBuf.Slice(offset, stride), perElementResult.Slice(offset, stride), CurveParameterSet.Bn254);
                    }

                    return batchedResult.SequenceEqual(perElementResult);
                }, iter: BatchIterationCount);
        }
    }


    [TestMethod]
    public void BatchAddRejectsMisShapedBuffers()
    {
        ScalarBatchAddDelegate batchAdd = Bn254BigIntegerScalarReference.GetBatchAdd();
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        int stride = Scalar.SizeBytes;

        //The left buffer is one stride wide while count = 2 demands two strides;
        //the delegate's length guard must reject the mismatch.
        using IMemoryOwner<byte> tooShortOwner = pool.Rent(stride);
        using IMemoryOwner<byte> rightOwner = pool.Rent(2 * stride);
        using IMemoryOwner<byte> resultOwner = pool.Rent(2 * stride);

        Assert.ThrowsExactly<ArgumentException>(() =>
            batchAdd(
                tooShortOwner.Memory.Span[..stride],
                rightOwner.Memory.Span[..(2 * stride)],
                resultOwner.Memory.Span[..(2 * stride)],
                count: 2,
                CurveParameterSet.Bn254));
    }


    [TestMethod]
    public void RandomProducesScalarsCarryingProvenance()
    {
        ScalarRandomDelegate random = Bn254BigIntegerScalarReference.GetRandom();
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using Scalar scalar = Scalar.FromRandom(random, CurveParameterSet.Bn254, pool);

        Assert.IsTrue(scalar.Tag.TryGet(out ProviderClass providerClass),
            "Provenance entries should be present after a boundary operation.");
        Assert.AreEqual(nameof(Bn254BigIntegerScalarReference), providerClass.Name);

        Assert.AreEqual(AlgebraicRole.Scalar, scalar.Tag.Get<AlgebraicRole>());
        Assert.AreEqual(CurveParameterSet.Bn254, scalar.Tag.Get<CurveParameterSet>());
    }


    //Decodes a big-endian hex string into the destination span, returning the
    //number of bytes written. The destination must be at least hex.Length / 2 wide.
    private static int Decode(string hex, Span<byte> destination)
    {
        Convert.FromHexString(hex, destination, out _, out int bytesWritten);
        return bytesWritten;
    }


    private static void AssertSpanEqual(ReadOnlySpan<byte> expected, ReadOnlySpan<byte> actual, string because)
    {
        if(!actual.SequenceEqual(expected))
        {
            //Hex strings are built only on the failure path so the success path stays allocation-free.
            Assert.Fail($"{because}: expected {Convert.ToHexStringLower(expected)}, got {Convert.ToHexStringLower(actual)}");
        }
    }


    private static void PackReducedScalars(byte[][] rawBatch, Span<byte> destination)
    {
        //Reduce each raw 32-byte sample modulo r so the batched delegate inputs
        //are always canonical-form scalars in [0, r).
        int stride = Scalar.SizeBytes;
        for(int i = 0; i < rawBatch.Length; i++)
        {
            ReduceDelegate(rawBatch[i], destination.Slice(i * stride, stride), CurveParameterSet.Bn254);
        }
    }
}
