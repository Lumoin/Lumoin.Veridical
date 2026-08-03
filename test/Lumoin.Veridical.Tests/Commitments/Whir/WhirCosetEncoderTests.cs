using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Whir;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Tests.Commitments.Whir;

/// <summary>
/// Tests for the WHIR smooth-coset encoder (4.2 phase A): natural-order
/// encoding must equal naive Horner evaluation at every domain point on both
/// wired curves — pinning the transform's bit-reversal bookkeeping to the
/// mathematical definition — and the coset-contiguous leaf layout must be the
/// exact stride gather of the natural order that the verifier's query-index
/// arithmetic assumes.
/// </summary>
[TestClass]
internal sealed class WhirCosetEncoderTests
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = 32;

    /// <summary>
    /// The message's variable count: a 2^3-coefficient message is small
    /// enough for the O(domain · coefficients) naive reference.
    /// </summary>
    private const int VariableCount = 3;

    /// <summary>
    /// The domain exponent: a 2^5-point domain is large enough that natural
    /// order, bit-reversed order and coset order all differ.
    /// </summary>
    private const int DomainSizeLog2 = 5;

    /// <summary>
    /// The coset exponent for the layout test; two blocks of coset stride
    /// survive at k = 4 on the 2^5 domain.
    /// </summary>
    private const int FoldingParameter = 4;

    /// <summary>A fill salt distinct from other test classes' streams.</summary>
    private const int CoefficientSalt = 11;


    [TestMethod]
    [DataRow("Bls12Curve381")]
    [DataRow("Bn254")]
    public void EncodeMatchesNaiveHornerEvaluation(string curveName)
    {
        ScalarArithmeticBackend backend = BackendFor(curveName);
        CurveParameterSet curve = backend.Curve;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        WhirCosetEncoder encoder = WhirCosetEncoder.Create(backend.Add, backend.Subtract, backend.Multiply, curve, pool);

        int coefficientCount = 1 << VariableCount;
        int domainLength = 1 << DomainSizeLog2;
        using IMemoryOwner<byte> buffersOwner = pool.Rent((coefficientCount + domainLength) * ScalarSize);
        Span<byte> buffers = buffersOwner.Memory.Span[..((coefficientCount + domainLength) * ScalarSize)];
        Span<byte> coefficients = buffers[..(coefficientCount * ScalarSize)];
        Span<byte> evaluations = buffers.Slice(coefficientCount * ScalarSize, domainLength * ScalarSize);
        DeterministicScalarFill.FillCanonical(coefficients, CoefficientSalt, backend.Reduce, curve);

        encoder.Encode(coefficients, DomainSizeLog2, evaluations);

        Span<byte> root = stackalloc byte[ScalarSize];
        Span<byte> point = stackalloc byte[ScalarSize];
        Span<byte> expected = stackalloc byte[ScalarSize];
        encoder.DeriveDomainRoot(DomainSizeLog2, root);
        for(int exponent = 0; exponent < domainLength; exponent++)
        {
            WhirFold.ComputeDomainPoint(root, exponent, point, backend.Multiply, curve);
            EvaluateNaiveHorner(coefficients, coefficientCount, point, expected, backend, curve);

            Assert.IsTrue(
                expected.SequenceEqual(evaluations.Slice(exponent * ScalarSize, ScalarSize)),
                $"The encoding of {curveName} must match the naive evaluation at ω^{exponent}.");
        }
    }


    [TestMethod]
    public void CosetLeavesAreTheStrideGatherOfNaturalOrder()
    {
        ScalarArithmeticBackend backend = TestScalarBackends.Bls12Curve381;
        CurveParameterSet curve = backend.Curve;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        WhirCosetEncoder encoder = WhirCosetEncoder.Create(backend.Add, backend.Subtract, backend.Multiply, curve, pool);

        int coefficientCount = 1 << VariableCount;
        int domainLength = 1 << DomainSizeLog2;
        using IMemoryOwner<byte> buffersOwner = pool.Rent((coefficientCount + (2 * domainLength)) * ScalarSize);
        Span<byte> buffers = buffersOwner.Memory.Span[..((coefficientCount + (2 * domainLength)) * ScalarSize)];
        Span<byte> coefficients = buffers[..(coefficientCount * ScalarSize)];
        Span<byte> natural = buffers.Slice(coefficientCount * ScalarSize, domainLength * ScalarSize);
        Span<byte> leaves = buffers.Slice((coefficientCount + domainLength) * ScalarSize, domainLength * ScalarSize);
        DeterministicScalarFill.FillCanonical(coefficients, CoefficientSalt, backend.Reduce, curve);

        encoder.Encode(coefficients, DomainSizeLog2, natural);
        encoder.EncodeToCosetLeaves(coefficients, DomainSizeLog2, FoldingParameter, leaves);

        int blockCount = domainLength >> FoldingParameter;
        int blockSize = 1 << FoldingParameter;
        for(int block = 0; block < blockCount; block++)
        {
            for(int position = 0; position < blockSize; position++)
            {
                ReadOnlySpan<byte> fromLeaves = leaves.Slice(((block * blockSize) + position) * ScalarSize, ScalarSize);
                ReadOnlySpan<byte> fromNatural = natural.Slice((block + (position * blockCount)) * ScalarSize, ScalarSize);

                Assert.IsTrue(
                    fromLeaves.SequenceEqual(fromNatural),
                    $"Leaf position ({block}, {position}) must gather natural index {block + (position * blockCount)}.");
            }
        }
    }


    [TestMethod]
    public void ZeroKnowledgeEncodeWithEmptyRandomnessMatchesThePlainPaths()
    {
        //The t = 0 degeneration pin: with no randomness the zero-knowledge
        //encode must reproduce the plain layout byte for byte, on both the
        //natural-order and the coset-leaf surfaces.
        ScalarArithmeticBackend backend = TestScalarBackends.Bls12Curve381;
        CurveParameterSet curve = backend.Curve;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        WhirCosetEncoder encoder = WhirCosetEncoder.Create(backend.Add, backend.Subtract, backend.Multiply, curve, pool);

        int coefficientCount = 1 << VariableCount;
        int domainLength = 1 << DomainSizeLog2;
        using IMemoryOwner<byte> buffersOwner = pool.Rent((coefficientCount + (4 * domainLength)) * ScalarSize);
        Span<byte> buffers = buffersOwner.Memory.Span[..((coefficientCount + (4 * domainLength)) * ScalarSize)];
        Span<byte> coefficients = buffers[..(coefficientCount * ScalarSize)];
        Span<byte> plainNatural = buffers.Slice(coefficientCount * ScalarSize, domainLength * ScalarSize);
        Span<byte> zeroKnowledgeNatural = buffers.Slice((coefficientCount + domainLength) * ScalarSize, domainLength * ScalarSize);
        Span<byte> plainLeaves = buffers.Slice((coefficientCount + (2 * domainLength)) * ScalarSize, domainLength * ScalarSize);
        Span<byte> zeroKnowledgeLeaves = buffers.Slice((coefficientCount + (3 * domainLength)) * ScalarSize, domainLength * ScalarSize);
        DeterministicScalarFill.FillCanonical(coefficients, CoefficientSalt, backend.Reduce, curve);

        encoder.Encode(coefficients, DomainSizeLog2, plainNatural);
        encoder.EncodeWithRandomness(coefficients, ReadOnlySpan<byte>.Empty, DomainSizeLog2, zeroKnowledgeNatural);
        encoder.EncodeToCosetLeaves(coefficients, DomainSizeLog2, FoldingParameter, plainLeaves);
        encoder.EncodeToCosetLeavesWithRandomness(coefficients, ReadOnlySpan<byte>.Empty, DomainSizeLog2, FoldingParameter, zeroKnowledgeLeaves);

        Assert.IsTrue(plainNatural.SequenceEqual(zeroKnowledgeNatural), "With no randomness the natural-order encode must match the plain encode.");
        Assert.IsTrue(plainLeaves.SequenceEqual(zeroKnowledgeLeaves), "With no randomness the coset-leaf encode must match the plain encode.");
    }


    [TestMethod]
    public void ZeroKnowledgeEncodeIsThePlainEncodeOfTheExtendedCoefficientVector()
    {
        //The C1-Q1 orientation pin: the randomness is a contiguous
        //coefficient block appended at the message degree, consumed by the
        //same single transform — Enc(f, r) = Σ f_j·x^j + Σ r_s·x^(len+s).
        ScalarArithmeticBackend backend = TestScalarBackends.Bls12Curve381;
        CurveParameterSet curve = backend.Curve;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        WhirCosetEncoder encoder = WhirCosetEncoder.Create(backend.Add, backend.Subtract, backend.Multiply, curve, pool);

        int coefficientCount = 1 << VariableCount;
        int randomnessCount = 1 << FoldingParameter;
        int extendedCount = coefficientCount + randomnessCount;
        int domainLength = 1 << DomainSizeLog2;
        using IMemoryOwner<byte> buffersOwner = pool.Rent((extendedCount + (2 * domainLength)) * ScalarSize);
        Span<byte> buffers = buffersOwner.Memory.Span[..((extendedCount + (2 * domainLength)) * ScalarSize)];
        Span<byte> extended = buffers[..(extendedCount * ScalarSize)];
        Span<byte> coefficients = extended[..(coefficientCount * ScalarSize)];
        Span<byte> randomness = extended.Slice(coefficientCount * ScalarSize, randomnessCount * ScalarSize);
        Span<byte> natural = buffers.Slice(extendedCount * ScalarSize, domainLength * ScalarSize);
        Span<byte> leaves = buffers.Slice((extendedCount + domainLength) * ScalarSize, domainLength * ScalarSize);
        DeterministicScalarFill.FillCanonical(extended, CoefficientSalt, backend.Reduce, curve);

        encoder.EncodeWithRandomness(coefficients, randomness, DomainSizeLog2, natural);
        encoder.EncodeToCosetLeavesWithRandomness(coefficients, randomness, DomainSizeLog2, FoldingParameter, leaves);

        //Naive Horner over the extended vector at every domain point, and the
        //coset layout as the stride gather of the natural order.
        Span<byte> root = stackalloc byte[ScalarSize];
        Span<byte> point = stackalloc byte[ScalarSize];
        Span<byte> expected = stackalloc byte[ScalarSize];
        encoder.DeriveDomainRoot(DomainSizeLog2, root);
        int blockCount = domainLength >> FoldingParameter;
        int blockSize = 1 << FoldingParameter;
        for(int exponent = 0; exponent < domainLength; exponent++)
        {
            WhirFold.ComputeDomainPoint(root, exponent, point, backend.Multiply, curve);
            EvaluateNaiveHorner(extended, extendedCount, point, expected, backend, curve);

            Assert.IsTrue(
                expected.SequenceEqual(natural.Slice(exponent * ScalarSize, ScalarSize)),
                $"The zero-knowledge encoding must match the naive evaluation of the extended vector at ω^{exponent}.");

            int block = exponent % blockCount;
            int position = exponent / blockCount;
            Assert.IsTrue(
                expected.SequenceEqual(leaves.Slice(((block * blockSize) + position) * ScalarSize, ScalarSize)),
                $"The zero-knowledge coset layout must gather ω^{exponent} into leaf ({block}, {position}).");
        }
    }


    [TestMethod]
    public void ZeroKnowledgeRandomnessNotAMultipleOfTheLimbCountIsRejected()
    {
        Assert.Throws<ArgumentException>(static () => EncodeZeroKnowledgeLeavesWithShape(
            coefficientElements: 1 << VariableCount,
            randomnessElements: (1 << FoldingParameter) - 1));
    }


    [TestMethod]
    public void ZeroKnowledgeOverfilledDomainIsRejected()
    {
        Assert.Throws<ArgumentException>(static () => EncodeZeroKnowledgeLeavesWithShape(
            coefficientElements: 1 << VariableCount,
            randomnessElements: 1 << DomainSizeLog2));
    }


    [TestMethod]
    public void ZeroKnowledgeNonPowerOfTwoMessageIsRejectedOnTheCosetSurface()
    {
        Assert.Throws<ArgumentException>(static () => EncodeZeroKnowledgeLeavesWithShape(
            coefficientElements: 3,
            randomnessElements: 1 << FoldingParameter));
    }


    [TestMethod]
    public void MismatchedDestinationLengthIsRejected()
    {
        Assert.Throws<ArgumentException>(static () => EncodeWithShape(coefficientElements: 2, destinationElements: 3));
    }


    [TestMethod]
    public void NonPowerOfTwoCoefficientCountIsRejected()
    {
        Assert.Throws<ArgumentException>(static () => EncodeWithShape(coefficientElements: 3, destinationElements: 1 << DomainSizeLog2));
    }


    /// <summary>
    /// Runs one Encode call with the given zeroed shape; the guard tests
    /// assert on the exceptions this raises.
    /// </summary>
    private static void EncodeWithShape(int coefficientElements, int destinationElements)
    {
        ScalarArithmeticBackend backend = TestScalarBackends.Bls12Curve381;
        WhirCosetEncoder encoder = WhirCosetEncoder.Create(backend.Add, backend.Subtract, backend.Multiply, backend.Curve, BaseMemoryPool.Shared);

        Span<byte> coefficients = stackalloc byte[coefficientElements * ScalarSize];
        Span<byte> destination = stackalloc byte[destinationElements * ScalarSize];
        encoder.Encode(coefficients, DomainSizeLog2, destination);
    }


    /// <summary>
    /// Runs one zero-knowledge coset-leaf encode with the given zeroed shape;
    /// the guard tests assert on the exceptions this raises.
    /// </summary>
    private static void EncodeZeroKnowledgeLeavesWithShape(int coefficientElements, int randomnessElements)
    {
        ScalarArithmeticBackend backend = TestScalarBackends.Bls12Curve381;
        WhirCosetEncoder encoder = WhirCosetEncoder.Create(backend.Add, backend.Subtract, backend.Multiply, backend.Curve, BaseMemoryPool.Shared);

        Span<byte> coefficients = stackalloc byte[coefficientElements * ScalarSize];
        Span<byte> randomness = stackalloc byte[randomnessElements * ScalarSize];
        Span<byte> destination = stackalloc byte[(1 << DomainSizeLog2) * ScalarSize];
        encoder.EncodeToCosetLeavesWithRandomness(coefficients, randomness, DomainSizeLog2, FoldingParameter, destination);
    }


    /// <summary>
    /// Resolves a data-row curve name to its cached backend bundle.
    /// </summary>
    private static ScalarArithmeticBackend BackendFor(string curveName)
    {
        return curveName == "Bn254" ? TestScalarBackends.Bn254 : TestScalarBackends.Bls12Curve381;
    }


    /// <summary>
    /// The reference path: plain descending Horner over the univariate
    /// coefficient vector, independent of any transform bookkeeping.
    /// </summary>
    private static void EvaluateNaiveHorner(
        ReadOnlySpan<byte> coefficients,
        int coefficientCount,
        ReadOnlySpan<byte> point,
        Span<byte> result,
        ScalarArithmeticBackend backend,
        CurveParameterSet curve)
    {
        coefficients.Slice((coefficientCount - 1) * ScalarSize, ScalarSize).CopyTo(result);
        for(int index = coefficientCount - 2; index >= 0; index--)
        {
            backend.Multiply(result, point, result, curve);
            backend.Add(result, coefficients.Slice(index * ScalarSize, ScalarSize), result, curve);
        }
    }
}
