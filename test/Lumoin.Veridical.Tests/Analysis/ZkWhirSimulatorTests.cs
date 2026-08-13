using Lumoin.Veridical.Analysis.Simulation;
using Lumoin.Veridical.Analysis.StatisticalTests;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Whir;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Analysis;

/// <summary>
/// The programmable-Fiat-Shamir-oracle simulator gates for hiding WHIR: the
/// ZK-BaseFold mold applied to HVZK-WHIR.
/// <see cref="ZkWhirOpeningSimulator"/> produces, from the public statement
/// alone, a commitment and opening that a verifier holding the programmed
/// oracle accepts; the structural gates assert the acceptance and that the
/// programming is doing real work (the same output is rejected under the
/// real oracle, where the patched batch-0 mask total breaks every
/// post-divergence challenge derivation). The two-sample experiment then
/// compares real and simulated proof bytes; per the established doctrine its
/// verdicts are logged, not asserted — a Detected or NotDetected finding is
/// an honest outcome at test-suite sample scales.
/// </summary>
[TestClass]
internal sealed class ZkWhirSimulatorTests
{
    /// <summary>Test context, for emitting the two-sample findings to the test log.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The transcript's fixed-output BLAKE3 hash backend.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The transcript's BLAKE3 XOF backend.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();

    /// <summary>The scalar-reduce backend.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();

    /// <summary>The scalar-add backend.</summary>
    private static ScalarAddDelegate Add { get; } = Bls12Curve381BigIntegerScalarReference.GetAdd();

    /// <summary>The scalar-subtract backend.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = Bls12Curve381BigIntegerScalarReference.GetSubtract();

    /// <summary>The scalar-multiply backend.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = Bls12Curve381BigIntegerScalarReference.GetMultiply();

    /// <summary>The scalar-invert backend.</summary>
    private static ScalarInvertDelegate Invert { get; } = Bls12Curve381BigIntegerScalarReference.GetInvert();

    /// <summary>The entropy-sourced scalar sampler behind the fake witness and every hiding ingredient.</summary>
    private static ScalarRandomDelegate Random { get; } = Bls12Curve381BigIntegerScalarReference.GetRandom();

    /// <summary>The independent big-integer MLE evaluation reference.</summary>
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();

    /// <summary>The two-to-one Merkle compression over BLAKE3.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = 32;

    /// <summary>The wired Merkle digest size: BLAKE3's 32 bytes.</summary>
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    /// <summary>
    /// The simulated shape's variable count: the hiding-admissible fast
    /// shape of the WHIR provider tests — two iterations, one code-switch
    /// round, three mask groups.
    /// </summary>
    private const int VariableCount = 8;

    /// <summary>The simulated shape's initial inverse-rate exponent: rate 1/4.</summary>
    private const int InitialRateLog2 = 2;

    /// <summary>The simulated shape's per-round target.</summary>
    private const int SecurityLevelBits = 24;

    /// <summary>
    /// The two-sample scale: each sample is a full hiding commit+open,
    /// markedly heavier than the BaseFold sibling's, so this uses the
    /// masked-Spartan experiment's count.
    /// </summary>
    private const int SampleCount = 12;

    /// <summary>Byte-value bins for the per-proof histograms.</summary>
    private const int ByteValueCount = 256;

    /// <summary>The curve every artifact is tagged with.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    public void SimulatedOpeningVerifiesUnderTheProgrammedOracle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Scalar[] point = BuildPoint(VariableCount, salt: 41, pool);
        try
        {
            //The real statement: y = f(z) for a real witness — which is then
            //gone before the simulator runs. The simulator sees (z, y) only.
            using Scalar claimedValue = EvaluateAndDiscardWitness(point, witnessSalt: 43, pool);

            (PolynomialCommitment commitment, PolynomialOpening opening, ProgrammableFiatShamirOracle oracle) =
                ZkWhirOpeningSimulator.Simulate(
                    point, claimedValue, Curve, InitialRateLog2, NewTranscript(),
                    Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random, pool,
                    securityLevelBits: SecurityLevelBits);

            using(commitment)
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
        finally
        {
            DisposePoint(point);
        }
    }


    [TestMethod]
    public void SimulatedOpeningIsRejectedByTheRealOracle()
    {
        //Without the programming, the patched mask total diverges the
        //transcript at the batch-0 combination challenge and the chain
        //collapses — the simulation is a ROM capability, not a forgery.
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Scalar[] point = BuildPoint(VariableCount, salt: 47, pool);
        try
        {
            using Scalar claimedValue = EvaluateAndDiscardWitness(point, witnessSalt: 53, pool);

            (PolynomialCommitment commitment, PolynomialOpening opening, ProgrammableFiatShamirOracle oracle) =
                ZkWhirOpeningSimulator.Simulate(
                    point, claimedValue, Curve, InitialRateLog2, NewTranscript(),
                    Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random, pool,
                    securityLevelBits: SecurityLevelBits);

            using(commitment)
            using(opening)
            {
                using PolynomialCommitmentProvider realProvider = NewProvider(Squeeze);
                using FiatShamirTranscript verifyTx = NewTranscript();
                Assert.IsFalse(
                    realProvider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool),
                    "The simulated opening must be rejected when the oracle is not programmed.");
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
        //The real-versus-simulated comparison of the ZK-BaseFold doctrine:
        //mean proof byte per opening under Kolmogorov-Smirnov, and per-proof
        //byte histograms under the chi-squared statistic with the
        //LABEL-PERMUTATION null (the analytic chi-squared p-value is invalid
        //here — intra-proof byte dependence makes it reject even
        //witness-independent labelings). Verdicts logged, not asserted.
        BaseMemoryPool pool = BaseMemoryPool.Shared;
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
                    using(blind)
                    {
                        using FiatShamirTranscript openTx = NewTranscript();
                        (PolynomialOpening opening, Scalar value) = provider.Open(commitment, blind, witness, point, openTx, pool);
                        using(opening)
                        using(value)
                        {
                            long[] histogram = new long[ByteValueCount];
                            realMeans[i] = Accumulate(opening.AsReadOnlySpan(), histogram);
                            histograms.Add(histogram);
                            labels[histograms.Count - 1] = 0;
                        }
                    }
                }

                //A simulated proof of the same statement shape; the claimed
                //value is a fresh real evaluation so both samples answer real
                //statements.
                using(Scalar claimedValue = EvaluateAndDiscardWitness(point, witnessSalt: 2000 + i, pool))
                {
                    (PolynomialCommitment commitment, PolynomialOpening opening, ProgrammableFiatShamirOracle oracle) =
                        ZkWhirOpeningSimulator.Simulate(
                            point, claimedValue, Curve, InitialRateLog2, NewTranscript(),
                            Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random, pool,
                            securityLevelBits: SecurityLevelBits);
                    using(commitment)
                    using(opening)
                    {
                        long[] histogram = new long[ByteValueCount];
                        simulatedMeans[i] = Accumulate(opening.AsReadOnlySpan(), histogram);
                        histograms.Add(histogram);
                        labels[histograms.Count - 1] = 1;
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


    /// <summary>
    /// Evaluates a fresh real witness at the point and returns
    /// <c>y = f(z)</c>; the witness itself does not outlive this method —
    /// the statement is real, the witness is unavailable to the simulator.
    /// </summary>
    private static Scalar EvaluateAndDiscardWitness(Scalar[] point, int witnessSalt, BaseMemoryPool pool)
    {
        using MultilinearExtension witness = BuildRandomMle(VariableCount, witnessSalt, pool);

        return witness.Evaluate(point, MleEvaluate, pool);
    }


    /// <summary>
    /// Adds a proof's bytes to a value histogram and returns its mean byte.
    /// </summary>
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


    /// <summary>
    /// The hiding WHIR provider at the experiment's figures over the given
    /// squeeze — the real backend or a programmed oracle's side.
    /// </summary>
    private static PolynomialCommitmentProvider NewProvider(FiatShamirSqueezeDelegate squeeze)
    {
        return WhirPolynomialCommitmentScheme.CreateZeroKnowledge(
            Curve, InitialRateLog2, Merkle, Hash, squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
            securityLevelBits: SecurityLevelBits, digestSizeBytes: DigestSizeBytes);
    }


    /// <summary>
    /// A fresh transcript under the WHIR domain label with empty context.
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
    /// A deterministic dense MLE over the boolean cube.
    /// </summary>
    private static MultilinearExtension BuildRandomMle(int variableCount, int salt, BaseMemoryPool pool)
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


    /// <summary>
    /// A deterministic evaluation point, one scalar per variable.
    /// </summary>
    private static Scalar[] BuildPoint(int variableCount, int salt, BaseMemoryPool pool)
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


    /// <summary>
    /// Disposes every coordinate of an evaluation point.
    /// </summary>
    private static void DisposePoint(Scalar[] point)
    {
        foreach(Scalar coordinate in point)
        {
            coordinate.Dispose();
        }
    }


    /// <summary>
    /// The two-to-one compression: BLAKE3 over the concatenated children.
    /// </summary>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }
}
