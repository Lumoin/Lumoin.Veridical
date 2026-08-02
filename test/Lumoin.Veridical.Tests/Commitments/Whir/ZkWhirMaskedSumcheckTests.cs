using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Whir;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Sumcheck;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.Spartan;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Text;

namespace Lumoin.Veridical.Tests.Commitments.Whir;

/// <summary>
/// Tests for the masked sumcheck of the hiding WHIR path (4.2 phase C1,
/// eprint 2026/391 Construction 6.3): the mask total must equal the
/// brute-force cube sum, the prover and a replaying verifier must agree on
/// the combining challenge, the fold challenges and the chained residual, and
/// the residual must decompose as
/// <c>ε·(plain final claim) + Σ_j s_j(γ_j)</c> — the identity every round
/// weight, endpoint and past-evaluation term of the wire assembly feeds, so
/// any bookkeeping error in the construction's <c>2^(k-j)</c> scales breaks
/// it. The residual covectors must reproduce the mask part as dot products,
/// which is the form the code-switch composition later discharges against the
/// mask oracle.
/// </summary>
[TestClass]
internal sealed class ZkWhirMaskedSumcheckTests
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = 32;

    /// <summary>
    /// The batch's round count <c>k</c>: the library's default folding
    /// parameter, so the batch shape matches a production fold batch.
    /// </summary>
    private const int MaskCount = 4;

    /// <summary>
    /// The table variable count: equal to <see cref="MaskCount"/> so one
    /// batch folds the tables to single entries and the plain final claim is
    /// directly readable.
    /// </summary>
    private const int TableVariableCount = 4;

    /// <summary>
    /// A test-scale mask spot-check budget. The algebra under test is
    /// independent of the spot-check count; a small budget keeps the mask
    /// codewords short.
    /// </summary>
    private const int TestMaskQueryCount = 8;

    /// <summary>The mask codes' inverse-rate exponent, the production floor.</summary>
    private const int TestMaskRateLog2 = WhirZkParameters.DefaultMaskRateLog2;

    /// <summary>A fill salt for the function table, distinct from the weight stream.</summary>
    private const int FunctionSalt = 41;

    /// <summary>A fill salt for the weight table, distinct from the function stream.</summary>
    private const int WeightSalt = 42;

    /// <summary>The BLS12-381 scalar backend bundle.</summary>
    private static ScalarArithmeticBackend Bls { get; } = TestScalarBackends.Bls12Curve381;

    /// <summary>The transcript's fixed-output BLAKE3 hash backend.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The transcript's BLAKE3 XOF backend.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();

    /// <summary>The two-to-one Merkle compression over BLAKE3.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    /// <summary>The deterministic mask-sampling seed, distinct per test class.</summary>
    private static byte[] MaskSeed { get; } = Encoding.UTF8.GetBytes("zk-whir-masked-sumcheck-tests");


    [TestMethod]
    public void MaskTotalMatchesTheBruteForceCubeSum()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using ZkWhirSumcheckMasks masks = NewMasks(pool);

        Span<byte> maskTotal = stackalloc byte[ScalarSize];
        masks.WriteMaskTotal(maskTotal, Bls.Add, Bls.Multiply);

        //Independent reference: every mask evaluated at its round's bit of
        //every cube point, summed over the whole cube.
        Span<byte> expected = stackalloc byte[ScalarSize];
        expected.Clear();
        Span<byte> point = stackalloc byte[ScalarSize];
        Span<byte> value = stackalloc byte[ScalarSize];
        for(int cubePoint = 0; cubePoint < 1 << MaskCount; cubePoint++)
        {
            for(int mask = 0; mask < MaskCount; mask++)
            {
                point.Clear();
                point[ScalarSize - 1] = (byte)((cubePoint >> mask) & 1);
                masks.EvaluateMask(mask, point, value, Bls.Add, Bls.Multiply);
                Bls.Add(expected, value, expected, Bls.Curve);
            }
        }

        Assert.IsTrue(expected.SequenceEqual(maskTotal), "The mask total must equal the brute-force sum over the Boolean cube.");
    }


    [TestMethod]
    public void ProverAndReplayAgreeAndTheResidualDecomposes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using ZkWhirSumcheckMasks masks = NewMasks(pool);

        int size = 1 << TableVariableCount;
        using IMemoryOwner<byte> tablesOwner = pool.Rent(2 * size * ScalarSize);
        Span<byte> tables = tablesOwner.Memory.Span[..(2 * size * ScalarSize)];
        Span<byte> functionTable = tables[..(size * ScalarSize)];
        Span<byte> weightTable = tables.Slice(size * ScalarSize, size * ScalarSize);
        DeterministicScalarFill.FillCanonical(functionTable, FunctionSalt, Bls.Reduce, Bls.Curve);
        DeterministicScalarFill.FillCanonical(weightTable, WeightSalt, Bls.Reduce, Bls.Curve);

        //The batch's incoming plain claim: μ = Σ_b f(b)·w(b) over the cube.
        Span<byte> plainClaim = stackalloc byte[ScalarSize];
        plainClaim.Clear();
        Span<byte> product = stackalloc byte[ScalarSize];
        for(int index = 0; index < size; index++)
        {
            Bls.Multiply(
                functionTable.Slice(index * ScalarSize, ScalarSize),
                weightTable.Slice(index * ScalarSize, ScalarSize),
                product,
                Bls.Curve);
            Bls.Add(plainClaim, product, plainClaim, Bls.Curve);
        }

        Span<byte> maskTotal = stackalloc byte[ScalarSize];
        masks.WriteMaskTotal(maskTotal, Bls.Add, Bls.Multiply);

        Span<byte> proverEpsilon = stackalloc byte[ScalarSize];
        Span<byte> proverChallenges = stackalloc byte[MaskCount * ScalarSize];
        CompressedRoundPolynomial[] wires;
        using(FiatShamirTranscript proverTranscript = NewTranscript())
        {
            wires = ZkWhirMaskedSumcheckProver.RunBatch(
                functionTable, weightTable, size, masks, proverTranscript,
                Hash, Squeeze, Bls.Reduce, Bls.Add, Bls.Subtract, Bls.Multiply, pool,
                proverEpsilon, proverChallenges);
        }

        try
        {
            Span<byte> replayEpsilon = stackalloc byte[ScalarSize];
            Span<byte> replayChallenges = stackalloc byte[MaskCount * ScalarSize];
            Span<byte> residual = stackalloc byte[ScalarSize];
            using(FiatShamirTranscript replayTranscript = NewTranscript())
            {
                ZkWhirMaskedSumcheckVerifier.ReplayBatch(
                    wires, masks.Tree.Root, maskTotal, plainClaim, WhirZkParameters.DefaultMaskMessageLength,
                    replayTranscript, Hash, Squeeze, Bls.Reduce, Bls.Add, Bls.Subtract, Bls.Multiply,
                    Bls.Curve, pool, replayEpsilon, replayChallenges, residual);
            }

            Assert.IsTrue(proverEpsilon.SequenceEqual(replayEpsilon), "Both endpoints must derive the same combining challenge.");
            Assert.IsTrue(proverChallenges.SequenceEqual(replayChallenges), "Both endpoints must derive the same fold challenges.");

            //The load-bearing identity: after the batch the tables are bound
            //to f(γ)·w(γ), and the chained residual must decompose as
            //ε·(plain final claim) + Σ_j s_j(γ_j). Every 2^(k-j) weight, the
            //past-evaluation carry and the future-endpoint carry feed this.
            Span<byte> expectedResidual = stackalloc byte[ScalarSize];
            Bls.Multiply(functionTable[..ScalarSize], weightTable[..ScalarSize], expectedResidual, Bls.Curve);
            Bls.Multiply(expectedResidual, proverEpsilon, expectedResidual, Bls.Curve);
            Span<byte> maskResidual = stackalloc byte[ScalarSize];
            masks.WriteMaskResidual(proverChallenges, maskResidual, Bls.Add, Bls.Multiply);
            Bls.Add(expectedResidual, maskResidual, expectedResidual, Bls.Curve);

            Assert.IsTrue(expectedResidual.SequenceEqual(residual), "The chained residual must decompose into the scaled plain claim plus the mask residual.");
        }
        finally
        {
            foreach(CompressedRoundPolynomial wire in wires)
            {
                wire.Dispose();
            }
        }
    }


    [TestMethod]
    public void ResidualCovectorsReproduceTheMaskResidual()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using ZkWhirSumcheckMasks masks = NewMasks(pool);

        Span<byte> challenges = stackalloc byte[MaskCount * ScalarSize];
        DeterministicScalarFill.FillCanonical(challenges, FunctionSalt, Bls.Reduce, Bls.Curve);

        Span<byte> viaMasks = stackalloc byte[ScalarSize];
        masks.WriteMaskResidual(challenges, viaMasks, Bls.Add, Bls.Multiply);

        Span<byte> viaCovectors = stackalloc byte[ScalarSize];
        viaCovectors.Clear();
        Span<byte> covector = stackalloc byte[WhirZkParameters.DefaultMaskMessageLength * ScalarSize];
        Span<byte> term = stackalloc byte[ScalarSize];
        for(int mask = 0; mask < MaskCount; mask++)
        {
            ZkWhirMaskedSumcheckVerifier.WriteMaskResidualCovector(
                challenges.Slice(mask * ScalarSize, ScalarSize),
                WhirZkParameters.DefaultMaskMessageLength,
                covector,
                Bls.Multiply,
                Bls.Curve);
            ReadOnlySpan<byte> coefficients = masks.MaskCoefficients(mask);
            for(int power = 0; power < WhirZkParameters.DefaultMaskMessageLength; power++)
            {
                Bls.Multiply(
                    coefficients.Slice(power * ScalarSize, ScalarSize),
                    covector.Slice(power * ScalarSize, ScalarSize),
                    term,
                    Bls.Curve);
                Bls.Add(viaCovectors, term, viaCovectors, Bls.Curve);
            }
        }

        Assert.IsTrue(viaCovectors.SequenceEqual(viaMasks), "The covector dot products must reproduce the closed-form mask residual.");
    }


    [TestMethod]
    public void WireDegreeMismatchIsRejectedOnReplay()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using ZkWhirSumcheckMasks masks = NewMasks(pool);

        int size = 1 << TableVariableCount;
        using IMemoryOwner<byte> tablesOwner = pool.Rent(2 * size * ScalarSize);
        Span<byte> tables = tablesOwner.Memory.Span[..(2 * size * ScalarSize)];
        Span<byte> functionTable = tables[..(size * ScalarSize)];
        Span<byte> weightTable = tables.Slice(size * ScalarSize, size * ScalarSize);
        DeterministicScalarFill.FillCanonical(functionTable, FunctionSalt, Bls.Reduce, Bls.Curve);
        DeterministicScalarFill.FillCanonical(weightTable, WeightSalt, Bls.Reduce, Bls.Curve);

        Span<byte> maskTotal = stackalloc byte[ScalarSize];
        masks.WriteMaskTotal(maskTotal, Bls.Add, Bls.Multiply);
        Span<byte> epsilon = stackalloc byte[ScalarSize];
        Span<byte> challenges = stackalloc byte[MaskCount * ScalarSize];
        CompressedRoundPolynomial[] wires;
        using(FiatShamirTranscript proverTranscript = NewTranscript())
        {
            wires = ZkWhirMaskedSumcheckProver.RunBatch(
                functionTable, weightTable, size, masks, proverTranscript,
                Hash, Squeeze, Bls.Reduce, Bls.Add, Bls.Subtract, Bls.Multiply, pool,
                epsilon, challenges);
        }

        try
        {
            Assert.Throws<ArgumentException>(
                () => ReplayWithMaskMessageLength(wires, masks, pool, WhirZkParameters.DefaultMaskMessageLength + 1));
        }
        finally
        {
            foreach(CompressedRoundPolynomial wire in wires)
            {
                wire.Dispose();
            }
        }
    }


    [TestMethod]
    public void MasklessBatchIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        ScalarArithmeticBackend backend = Bls;
        WhirCosetEncoder encoder = WhirCosetEncoder.Create(backend.Add, backend.Subtract, backend.Multiply, backend.Curve, pool);
        WhirMaskCodeShape shape = WhirMaskCodeShape.Derive(WhirZkParameters.DefaultMaskMessageLength, TestMaskQueryCount, TestMaskRateLog2);

        Assert.Throws<ArgumentOutOfRangeException>(
            () => ZkWhirSumcheckMasks.Create(
                shape, maskCount: 0, encoder, Merkle, new DeterministicScalarRandom(MaskSeed).AsDelegate(), backend.Curve, pool));
    }


    /// <summary>
    /// Replays a batch under a divergent mask message length; the degree
    /// mismatch guard test asserts on the exception this raises.
    /// </summary>
    private static void ReplayWithMaskMessageLength(
        CompressedRoundPolynomial[] wires,
        ZkWhirSumcheckMasks masks,
        BaseMemoryPool pool,
        int maskMessageLength)
    {
        Span<byte> zeroTotal = stackalloc byte[ScalarSize];
        Span<byte> zeroClaim = stackalloc byte[ScalarSize];
        Span<byte> replayEpsilon = stackalloc byte[ScalarSize];
        Span<byte> replayChallenges = stackalloc byte[MaskCount * ScalarSize];
        Span<byte> residual = stackalloc byte[ScalarSize];
        using FiatShamirTranscript replayTranscript = NewTranscript();
        ZkWhirMaskedSumcheckVerifier.ReplayBatch(
            wires, masks.Tree.Root, zeroTotal, zeroClaim, maskMessageLength,
            replayTranscript, Hash, Squeeze, Bls.Reduce, Bls.Add, Bls.Subtract, Bls.Multiply,
            Bls.Curve, pool, replayEpsilon, replayChallenges, residual);
    }


    /// <summary>
    /// Builds one committed reference mask batch of <see cref="MaskCount"/>
    /// masks over the test-scale mask code.
    /// </summary>
    private static ZkWhirSumcheckMasks NewMasks(BaseMemoryPool pool)
    {
        WhirCosetEncoder encoder = WhirCosetEncoder.Create(Bls.Add, Bls.Subtract, Bls.Multiply, Bls.Curve, pool);
        WhirMaskCodeShape shape = WhirMaskCodeShape.Derive(WhirZkParameters.DefaultMaskMessageLength, TestMaskQueryCount, TestMaskRateLog2);

        return ZkWhirSumcheckMasks.Create(
            shape, MaskCount, encoder, Merkle, new DeterministicScalarRandom(MaskSeed).AsDelegate(), Bls.Curve, pool);
    }


    /// <summary>
    /// A fresh transcript under the WHIR domain label, as both endpoints
    /// initialise it.
    /// </summary>
    private static FiatShamirTranscript NewTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownWhirParameters.TranscriptDomainLabel),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }


    /// <summary>
    /// The two-to-one compression: BLAKE3 over the concatenated children.
    /// </summary>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * ScalarSize];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }
}
