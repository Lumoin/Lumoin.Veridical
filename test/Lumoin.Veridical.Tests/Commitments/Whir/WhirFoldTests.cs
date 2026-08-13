using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Whir;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Tests.Commitments.Whir;

/// <summary>
/// Tests for the WHIR folding operator: the encode/fold
/// commutation gate — butterfly-folding every encoded coset block must equal
/// encoding the coefficient-folded polynomial on the squared domain, the
/// content of WHIR Claim 4.15 — plus the partial-evaluation identity
/// <c>Fold(f, α)(z) = f̂(α, pow(z, m−k))</c> the claim states, and the
/// in-place aliasing contract of the coefficient fold.
/// </summary>
[TestClass]
internal sealed class WhirFoldTests
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = 32;

    /// <summary>
    /// The message's variable count: with the constant fold below, two
    /// variables remain after a full fold, so the partial-evaluation identity
    /// has a non-trivial suffix.
    /// </summary>
    private const int VariableCount = 6;

    /// <summary>The domain exponent: sixteen coset blocks survive a k = 4 fold of the 2^8 domain.</summary>
    private const int DomainSizeLog2 = 8;

    /// <summary>The paper's constant folding parameter k = 4.</summary>
    private const int FoldingParameter = 4;

    /// <summary>A fill salt for the coefficient stream, distinct from the challenge stream.</summary>
    private const int CoefficientSalt = 21;

    /// <summary>A fill salt for the challenge stream, distinct from the coefficient stream.</summary>
    private const int ChallengeSalt = 22;

    /// <summary>The BLS12-381 scalar backend bundle.</summary>
    private static ScalarArithmeticBackend Backend { get; } = TestScalarBackends.Bls12Curve381;

    /// <summary>The curve under test.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(FoldingParameter)]
    public void FoldingEncodedBlocksMatchesEncodingFoldedCoefficients(int foldDepth)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        WhirCosetEncoder encoder = WhirCosetEncoder.Create(Backend.Add, Backend.Subtract, Backend.Multiply, Curve, pool);

        int coefficientCount = 1 << VariableCount;
        int domainLength = 1 << DomainSizeLog2;
        int foldedDomainLog2 = DomainSizeLog2 - foldDepth;
        int foldedDomainLength = 1 << foldedDomainLog2;
        int blockSize = 1 << foldDepth;

        int totalBytes = (coefficientCount + foldDepth + domainLength + foldedDomainLength + blockSize) * ScalarSize;
        using IMemoryOwner<byte> buffersOwner = pool.Rent(totalBytes);
        Span<byte> buffers = buffersOwner.Memory.Span[..totalBytes];
        Span<byte> coefficients = buffers[..(coefficientCount * ScalarSize)];
        Span<byte> challenges = buffers.Slice(coefficientCount * ScalarSize, foldDepth * ScalarSize);
        Span<byte> leaves = buffers.Slice((coefficientCount + foldDepth) * ScalarSize, domainLength * ScalarSize);
        Span<byte> foldedEvaluations = buffers.Slice((coefficientCount + foldDepth + domainLength) * ScalarSize, foldedDomainLength * ScalarSize);
        Span<byte> blockScratch = buffers.Slice((coefficientCount + foldDepth + domainLength + foldedDomainLength) * ScalarSize, blockSize * ScalarSize);

        DeterministicScalarFill.FillCanonical(coefficients, CoefficientSalt, Backend.Reduce, Curve);
        DeterministicScalarFill.FillCanonical(challenges, ChallengeSalt, Backend.Reduce, Curve);

        encoder.EncodeToCosetLeaves(coefficients, DomainSizeLog2, foldDepth, leaves);

        //The prover-side path: fold the coefficients variable by variable and
        //encode the result on the squared domain.
        Span<byte> foldedCoefficients = stackalloc byte[(1 << VariableCount) * ScalarSize];
        coefficients.CopyTo(foldedCoefficients);
        for(int level = 0; level < foldDepth; level++)
        {
            int currentLength = coefficientCount >> level;
            WhirFold.FoldCoefficients(
                foldedCoefficients[..(currentLength * ScalarSize)],
                challenges.Slice(level * ScalarSize, ScalarSize),
                foldedCoefficients[..(currentLength / 2 * ScalarSize)],
                Backend.Add,
                Backend.Multiply,
                Curve);
        }

        encoder.Encode(foldedCoefficients[..((coefficientCount >> foldDepth) * ScalarSize)], foldedDomainLog2, foldedEvaluations);

        //The verifier-side path: butterfly-fold every queried block.
        Span<byte> domainRoot = stackalloc byte[ScalarSize];
        Span<byte> strideRoot = stackalloc byte[ScalarSize];
        Span<byte> basePoint = stackalloc byte[ScalarSize];
        Span<byte> foldedValue = stackalloc byte[ScalarSize];
        encoder.DeriveDomainRoot(DomainSizeLog2, domainRoot);
        encoder.DeriveDomainRoot(foldDepth, strideRoot);
        for(int block = 0; block < foldedDomainLength; block++)
        {
            leaves.Slice(block * blockSize * ScalarSize, blockSize * ScalarSize).CopyTo(blockScratch);
            WhirFold.ComputeDomainPoint(domainRoot, block, basePoint, Backend.Multiply, Curve);
            WhirFold.FoldCosetBlock(
                blockScratch,
                foldDepth,
                challenges,
                basePoint,
                strideRoot,
                foldedValue,
                Backend.Add,
                Backend.Subtract,
                Backend.Multiply,
                Backend.Invert,
                Curve,
                pool);

            Assert.IsTrue(
                foldedValue.SequenceEqual(foldedEvaluations.Slice(block * ScalarSize, ScalarSize)),
                $"The butterfly fold of block {block} must equal the encoded folded polynomial at depth {foldDepth}.");
        }
    }


    [TestMethod]
    public void FoldedBlockEqualsPartialEvaluationOfTheExtension()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        WhirCosetEncoder encoder = WhirCosetEncoder.Create(Backend.Add, Backend.Subtract, Backend.Multiply, Curve, pool);

        int coefficientCount = 1 << VariableCount;
        int domainLength = 1 << DomainSizeLog2;
        int blockSize = 1 << FoldingParameter;
        int suffixCount = VariableCount - FoldingParameter;

        int totalBytes = (coefficientCount + FoldingParameter + domainLength + blockSize) * ScalarSize;
        using IMemoryOwner<byte> buffersOwner = pool.Rent(totalBytes);
        Span<byte> buffers = buffersOwner.Memory.Span[..totalBytes];
        Span<byte> coefficients = buffers[..(coefficientCount * ScalarSize)];
        Span<byte> challenges = buffers.Slice(coefficientCount * ScalarSize, FoldingParameter * ScalarSize);
        Span<byte> leaves = buffers.Slice((coefficientCount + FoldingParameter) * ScalarSize, domainLength * ScalarSize);
        Span<byte> blockScratch = buffers.Slice((coefficientCount + FoldingParameter + domainLength) * ScalarSize, blockSize * ScalarSize);

        DeterministicScalarFill.FillCanonical(coefficients, CoefficientSalt, Backend.Reduce, Curve);
        DeterministicScalarFill.FillCanonical(challenges, ChallengeSalt, Backend.Reduce, Curve);
        encoder.EncodeToCosetLeaves(coefficients, DomainSizeLog2, FoldingParameter, leaves);

        Span<byte> domainRoot = stackalloc byte[ScalarSize];
        Span<byte> strideRoot = stackalloc byte[ScalarSize];
        Span<byte> basePoint = stackalloc byte[ScalarSize];
        Span<byte> foldedValue = stackalloc byte[ScalarSize];
        Span<byte> queryPoint = stackalloc byte[ScalarSize];
        Span<byte> expected = stackalloc byte[ScalarSize];
        Span<byte> fullPoint = stackalloc byte[VariableCount * ScalarSize];
        Span<byte> queryDomainRoot = stackalloc byte[ScalarSize];
        encoder.DeriveDomainRoot(DomainSizeLog2, domainRoot);
        encoder.DeriveDomainRoot(FoldingParameter, strideRoot);
        encoder.DeriveDomainRoot(DomainSizeLog2 - FoldingParameter, queryDomainRoot);

        int blockCount = domainLength >> FoldingParameter;
        for(int block = 0; block < blockCount; block++)
        {
            leaves.Slice(block * blockSize * ScalarSize, blockSize * ScalarSize).CopyTo(blockScratch);
            WhirFold.ComputeDomainPoint(domainRoot, block, basePoint, Backend.Multiply, Curve);
            WhirFold.FoldCosetBlock(
                blockScratch,
                FoldingParameter,
                challenges,
                basePoint,
                strideRoot,
                foldedValue,
                Backend.Add,
                Backend.Subtract,
                Backend.Multiply,
                Backend.Invert,
                Curve,
                pool);

            //Claim 4.15: the folded value at z is f̂(α, pow(z, m − k)) for
            //z = basePoint^(2^k), an element of the folded query domain.
            WhirFold.ComputeDomainPoint(queryDomainRoot, block, queryPoint, Backend.Multiply, Curve);
            challenges.CopyTo(fullPoint[..(FoldingParameter * ScalarSize)]);
            WhirMultilinear.ExpandPowPoint(queryPoint, suffixCount, fullPoint.Slice(FoldingParameter * ScalarSize, suffixCount * ScalarSize), Backend.Multiply, Curve);
            WhirMultilinear.EvaluateCoefficientsAtPoint(coefficients, fullPoint, VariableCount, expected, Backend.Add, Backend.Multiply, Curve, pool);

            Assert.IsTrue(
                foldedValue.SequenceEqual(expected),
                $"The folded value of block {block} must equal the partial evaluation of the multilinear extension.");
        }
    }


    [TestMethod]
    public void InPlaceCoefficientFoldMatchesSeparateDestination()
    {
        int coefficientCount = 1 << VariableCount;
        Span<byte> coefficients = stackalloc byte[coefficientCount * ScalarSize];
        Span<byte> challenge = stackalloc byte[ScalarSize];
        Span<byte> separate = stackalloc byte[coefficientCount / 2 * ScalarSize];
        DeterministicScalarFill.FillCanonical(coefficients, CoefficientSalt, Backend.Reduce, Curve);
        DeterministicScalarFill.FillCanonical(challenge, ChallengeSalt, Backend.Reduce, Curve);

        WhirFold.FoldCoefficients(coefficients, challenge, separate, Backend.Add, Backend.Multiply, Curve);
        WhirFold.FoldCoefficients(coefficients, challenge, coefficients[..(coefficientCount / 2 * ScalarSize)], Backend.Add, Backend.Multiply, Curve);

        Assert.IsTrue(
            coefficients[..(coefficientCount / 2 * ScalarSize)].SequenceEqual(separate),
            "Folding into the source's first half must equal folding into a separate destination.");
    }
}
