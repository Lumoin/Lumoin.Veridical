using Lumoin.Veridical.Analysis.Simulation;
using Lumoin.Veridical.Analysis.StatisticalTests;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

namespace Lumoin.Veridical.Tests.Analysis;

/// <summary>
/// The programmable-Fiat-Shamir-oracle simulator gates — the literal
/// real-versus-simulated proof test <c>ZK-STATMASK-DESIGN.md</c> §7 recorded
/// as the open follow-on. <see cref="ZkBaseFoldOpeningSimulator"/> produces,
/// from the public statement alone, a commitment and opening that a verifier
/// holding the programmed oracle accepts; the structural gates assert the
/// acceptance and that the programming is doing real work (the same output
/// is rejected under the real oracle, where the patched σ breaks every
/// post-divergence challenge derivation). The two-sample experiment then
/// compares real and simulated proof bytes; per the established doctrine its
/// verdicts are logged, not asserted — a Detected or NotDetected finding is
/// an honest outcome at test-suite sample scales.
/// </summary>
[TestClass]
internal sealed class ZkBaseFoldSimulatorTests
{
    /// <summary>Test context, for emitting the two-sample findings to the test log.</summary>
    public TestContext TestContext { get; set; } = null!;

    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static ScalarAddDelegate Add { get; } = Bls12Curve381BigIntegerScalarReference.GetAdd();
    private static ScalarSubtractDelegate Subtract { get; } = Bls12Curve381BigIntegerScalarReference.GetSubtract();
    private static ScalarMultiplyDelegate Multiply { get; } = Bls12Curve381BigIntegerScalarReference.GetMultiply();
    private static ScalarInvertDelegate Invert { get; } = Bls12Curve381BigIntegerScalarReference.GetInvert();
    private static ScalarRandomDelegate Random { get; } = Bls12Curve381BigIntegerScalarReference.GetRandom();
    private static ScalarHashToScalarDelegate HashToScalar { get; } = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    private const int ScalarSize = 32;
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;
    private const int QueryCount = 8;
    private const int VariableCount = 2;
    //The minimal budget-meeting lift for d = 2 at QueryCount = 8
    //(GetMinimumExtraVariableCount); the provider refuses under-budget shapes.
    private const int ExtraVariableCount = 5;
    //Two-sample scale: each sample is a full commit+open, so this trades
    //statistical power against suite runtime exactly as the sibling
    //hiding-validation experiments do.
    private const int SampleCount = 24;
    //Byte-value bins for the per-proof histograms.
    private const int ByteValueCount = 256;

    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;
    private static readonly byte[] ProviderSeed = Encoding.UTF8.GetBytes("veridical.analysis.fs-simulator.code.v1");


    [TestMethod]
    public void SimulatedOpeningVerifiesUnderTheProgrammedOracle()
    {
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        Scalar[] point = BuildPoint(VariableCount, salt: 41, pool);
        try
        {
            //The real statement: y = f(z) for a real witness — which is then
            //gone before the simulator runs. The simulator sees (z, y) only.
            using Scalar claimedValue = EvaluateAndDiscardWitness(point, witnessSalt: 43, pool);

            (PolynomialCommitment commitment, PolynomialOpening opening, ProgrammableFiatShamirOracle oracle) =
                ZkBaseFoldOpeningSimulator.Simulate(
                    ProviderSeed, point, claimedValue, ExtraVariableCount, Curve, QueryCount, NewTranscript(),
                    Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random, HashToScalar, pool);

            using(commitment)
            {
                using(opening)
                {
                    using PolynomialCommitmentProvider replayProvider = NewProvider(oracle.CreateReplaySqueeze());
                    using FiatShamirTranscript verifyTx = NewTranscript();
                    Assert.IsTrue(
                        replayProvider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool),
                        "The witness-free simulated opening must verify under the programmed oracle.");

                    //The verifier consumed the programmed responses one-to-one:
                    //its squeeze sequence is structurally the prover's.
                    Assert.AreEqual(oracle.RecordedCount, oracle.ReplayedCount, "The verifier must squeeze exactly the recorded sequence.");
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    [TestMethod]
    public void SimulatedOpeningIsRejectedByTheRealOracle()
    {
        //Without the programming, the patched σ diverges the transcript at the
        //blend challenge and the chain collapses — the simulation is a ROM
        //capability, not a forgery.
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        Scalar[] point = BuildPoint(VariableCount, salt: 47, pool);
        try
        {
            using Scalar claimedValue = EvaluateAndDiscardWitness(point, witnessSalt: 53, pool);

            (PolynomialCommitment commitment, PolynomialOpening opening, ProgrammableFiatShamirOracle oracle) =
                ZkBaseFoldOpeningSimulator.Simulate(
                    ProviderSeed, point, claimedValue, ExtraVariableCount, Curve, QueryCount, NewTranscript(),
                    Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random, HashToScalar, pool);

            using(commitment)
            {
                using(opening)
                {
                    using PolynomialCommitmentProvider realProvider = NewProvider(Squeeze);
                    using FiatShamirTranscript verifyTx = NewTranscript();
                    Assert.IsFalse(
                        realProvider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool),
                        "The simulated opening must be rejected when the oracle is not programmed.");
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    [TestMethod]
    public void RealAndSimulatedOpeningsCompareInTwoSampleTests()
    {
        //The literal real-versus-simulated comparison (design doc §5): mean
        //proof byte per opening under Kolmogorov-Smirnov, and per-proof byte
        //histograms under the chi-squared statistic with the LABEL-PERMUTATION
        //null — the analytic chi-squared p-value is invalid here (the batch SM
        //finding: intra-proof byte dependence makes it reject even
        //witness-independent labelings). Verdicts logged, not asserted, per
        //the sibling hiding-validation doctrine.
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        Scalar[] point = BuildPoint(VariableCount, salt: 59, pool);
        try
        {
            double[] realMeans = new double[SampleCount];
            double[] simulatedMeans = new double[SampleCount];
            var histograms = new List<long[]>(2 * SampleCount);
            var labels = new int[2 * SampleCount];

            for(int i = 0; i < SampleCount; i++)
            {
                //A real proof of a real witness.
                using(MultilinearExtension witness = BuildRandomMle(VariableCount, salt: 1000 + i, pool))
                {
                    using PolynomialCommitmentProvider provider = NewProvider(Squeeze);
                    (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(witness, pool);
                    using(commitment)
                    {
                        using(blind)
                        {
                            using FiatShamirTranscript openTx = NewTranscript();
                            (PolynomialOpening opening, Scalar value) = provider.Open(commitment, blind, witness, point, openTx, pool);
                            using(opening)
                            {
                                using(value)
                                {
                                    long[] histogram = new long[ByteValueCount];
                                    realMeans[i] = Accumulate(opening.AsReadOnlySpan(), histogram);
                                    histograms.Add(histogram);
                                    labels[histograms.Count - 1] = 0;
                                }
                            }
                        }
                    }
                }

                //A simulated proof of the same statement shape; the claimed
                //value is a fresh real evaluation so both samples answer real
                //statements.
                using(Scalar claimedValue = EvaluateAndDiscardWitness(point, witnessSalt: 2000 + i, pool))
                {
                    (PolynomialCommitment commitment, PolynomialOpening opening, ProgrammableFiatShamirOracle oracle) =
                        ZkBaseFoldOpeningSimulator.Simulate(
                            ProviderSeed, point, claimedValue, ExtraVariableCount, Curve, QueryCount, NewTranscript(),
                            Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random, HashToScalar, pool);
                    using(commitment)
                    {
                        using(opening)
                        {
                            long[] histogram = new long[ByteValueCount];
                            simulatedMeans[i] = Accumulate(opening.AsReadOnlySpan(), histogram);
                            histograms.Add(histogram);
                            labels[histograms.Count - 1] = 1;
                        }
                    }
                }
            }

            StatisticalTestResult ks = KolmogorovSmirnovTest.TwoSample(realMeans, simulatedMeans);
            StatisticalTestResult permutation = PermutationTest.HomogeneityOfPooledHistograms(histograms, labels);

            TestContext.WriteLine($"real-vs-simulated mean-byte KS: {ks.Interpretation}, statistic {ks.TestStatistic:F4}, p {ks.PValue:F4}");
            TestContext.WriteLine($"real-vs-simulated byte-histogram permutation: {permutation.Interpretation}, chi-squared statistic {permutation.TestStatistic:F1}, permutation p {permutation.PValue:F4}");

            Assert.IsTrue(ks.PValue is >= 0 and <= 1, "The KS two-sample test must produce a well-formed p-value.");
            Assert.IsTrue(permutation.PValue is > 0 and <= 1, "The permutation test must produce a well-formed p-value.");
        }
        finally
        {
            DisposePoint(point);
        }
    }


    [TestMethod]
    public void RecordingAndReplayRoundTripAndReplayIsStrict()
    {
        //The oracle primitive itself: recorded responses replay in order, the
        //inputs are inspectable, and over-consumption throws.
        var oracle = new ProgrammableFiatShamirOracle();
        FiatShamirSqueezeDelegate recording = oracle.CreateRecordingSqueeze(Squeeze);

        Span<byte> input = stackalloc byte[16];
        Span<byte> first = stackalloc byte[64];
        Span<byte> second = stackalloc byte[64];
        input.Fill(0xA5);
        recording(input, first, WellKnownHashAlgorithms.Blake3);
        input.Fill(0x5A);
        recording(input, second, WellKnownHashAlgorithms.Blake3);

        Assert.AreEqual(2, oracle.RecordedCount, "Both squeezes must be recorded.");
        Assert.AreEqual(0xA5, oracle.GetRecordedInput(0)[0], "The recorded input must be inspectable.");

        FiatShamirSqueezeDelegate replay = oracle.CreateReplaySqueeze();
        Span<byte> replayed = stackalloc byte[64];
        Span<byte> different = stackalloc byte[16];
        different.Fill(0x77);
        replay(different, replayed, WellKnownHashAlgorithms.Blake3);
        Assert.IsTrue(replayed.SequenceEqual(first), "The first replayed response must be the first recording regardless of input.");

        replay(different, replayed, WellKnownHashAlgorithms.Blake3);
        Assert.IsTrue(replayed.SequenceEqual(second), "The second replayed response must be the second recording.");
        Assert.AreEqual(2, oracle.ReplayedCount, "Two responses must have been consumed.");

        byte[] exhaustedOutput = new byte[64];
        _ = Assert.ThrowsExactly<InvalidOperationException>(
            () => oracle.CreateReplaySqueeze()(ReadOnlySpan<byte>.Empty, exhaustedOutput, WellKnownHashAlgorithms.Blake3));
    }


    //Evaluates a fresh real witness at the point and returns y = f(z); the
    //witness itself does not outlive this method — the statement is real,
    //the witness is unavailable to the simulator.
    private static Scalar EvaluateAndDiscardWitness(Scalar[] point, int witnessSalt, SensitiveMemoryPool<byte> pool)
    {
        using MultilinearExtension witness = BuildRandomMle(VariableCount, witnessSalt, pool);

        return witness.Evaluate(point, MleEvaluate, pool);
    }


    private static double Accumulate(ReadOnlySpan<byte> proof, long[] histogram)
    {
        double sum = 0;
        for(int i = 0; i < proof.Length; i++)
        {
            sum += proof[i];
            histogram[proof[i]]++;
        }

        return sum / proof.Length;
    }


    private static PolynomialCommitmentProvider NewProvider(FiatShamirSqueezeDelegate squeeze)
    {
        return ZkBaseFoldPolynomialCommitmentScheme.CreateFullZeroKnowledge(
            ProviderSeed, Curve, QueryCount, Merkle, Hash, squeeze, Reduce, Add, Subtract, Multiply, Invert,
            Random, HashToScalar, ExtraVariableCount, DigestSizeBytes);
    }


    private static FiatShamirTranscript NewTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownBaseFoldEvaluationParameters.TranscriptDomainLabel),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            SensitiveMemoryPool<byte>.Shared);
    }


    private static MultilinearExtension BuildRandomMle(int variableCount, int salt, SensitiveMemoryPool<byte> pool)
    {
        int evaluationCount = 1 << variableCount;
        using IMemoryOwner<byte> owner = pool.Rent(evaluationCount * ScalarSize);
        Span<byte> evals = owner.Memory.Span[..(evaluationCount * ScalarSize)];
        Span<byte> wide = stackalloc byte[ScalarSize];
        for(int i = 0; i < evaluationCount; i++)
        {
            wide.Clear();
            BinaryPrimitives.WriteInt32BigEndian(wide[..4], (salt * 137) + (i * 19) + 1);
            BinaryPrimitives.WriteInt32BigEndian(wide[^4..], (salt * 11) + (i * 31) + 3);
            Reduce(wide, evals.Slice(i * ScalarSize, ScalarSize), Curve);
        }

        return MultilinearExtension.FromEvaluations(evals, variableCount, Curve, pool);
    }


    private static Scalar[] BuildPoint(int variableCount, int salt, SensitiveMemoryPool<byte> pool)
    {
        var point = new Scalar[variableCount];
        Span<byte> wide = stackalloc byte[ScalarSize];
        for(int i = 0; i < variableCount; i++)
        {
            wide.Clear();
            BinaryPrimitives.WriteInt32BigEndian(wide[..4], (salt * 59) + (i * 23) + 2);
            BinaryPrimitives.WriteInt32BigEndian(wide[^4..], (salt * 29) + (i * 43) + 5);
            IMemoryOwner<byte> owner = pool.Rent(ScalarSize);
            Reduce(wide, owner.Memory.Span[..ScalarSize], Curve);
            point[i] = new Scalar(owner, Curve, WellKnownAlgebraicTags.ScalarFor(Curve));
        }

        return point;
    }


    private static void DisposePoint(Scalar[] point)
    {
        foreach(Scalar coordinate in point)
        {
            coordinate.Dispose();
        }
    }


    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }
}
