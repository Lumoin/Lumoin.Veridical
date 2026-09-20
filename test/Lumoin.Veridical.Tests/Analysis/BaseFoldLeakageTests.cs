using Lumoin.Veridical.Analysis.BaseFoldLeakage;
using Lumoin.Veridical.Analysis.StatisticalTests;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.Spartan;
using System;
using System.Collections.Generic;
using System.Text;

namespace Lumoin.Veridical.Tests.Analysis;

/// <summary>
/// Runs the BaseFold leakage experiments at small scale. The statistical
/// experiments are asserted only to run to completion and produce a well-formed
/// result (a finding, inconclusive or not, is an honest outcome — not a test
/// failure). The commitment-recoverability experiment is asserted to succeed,
/// because the structural leak is certain for a non-hiding commitment: BaseFold's
/// commitment is a deterministic fingerprint of the witness.
/// </summary>
[TestClass]
internal sealed class BaseFoldLeakageTests
{
    /// <summary>The BLAKE3 Fiat–Shamir hash delegate this test's transcripts and commitment providers share.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    /// <summary>The BLAKE3 Fiat–Shamir squeeze delegate this test's transcripts and commitment providers share.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    /// <summary>The BLS12-381 scalar-field reduction delegate used throughout these tests.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    /// <summary>The BLS12-381 scalar addition delegate the commitment providers use.</summary>
    private static ScalarAddDelegate Add { get; } = Bls12Curve381BigIntegerScalarReference.GetAdd();
    /// <summary>The BLS12-381 scalar subtraction delegate the commitment providers use.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = Bls12Curve381BigIntegerScalarReference.GetSubtract();
    /// <summary>The BLS12-381 scalar multiplication delegate the commitment providers use.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = Bls12Curve381BigIntegerScalarReference.GetMultiply();
    /// <summary>The BLS12-381 scalar inversion delegate the commitment providers use.</summary>
    private static ScalarInvertDelegate Invert { get; } = Bls12Curve381BigIntegerScalarReference.GetInvert();
    /// <summary>The BLS12-381 hash-to-scalar delegate the BaseFold-family commitment providers use to derive challenges.</summary>
    private static ScalarHashToScalarDelegate HashToScalar { get; } = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();
    /// <summary>The two-to-one Merkle compression function, delegated to <see cref="HashTwoToOne"/>.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    /// <summary>The byte width of a BLAKE3 digest, as used by the Merkle and BaseFold commitments in these tests.</summary>
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;
    /// <summary>The number of BaseFold query repetitions these leakage experiments use.</summary>
    private const int QueryCount = 8;
    /// <summary>The number of committed-polynomial variables the small-scale leakage experiments use.</summary>
    private const int VariableCount = 2;
    /// <summary>The number of samples the small-scale leakage experiments draw.</summary>
    private const int SampleCount = 40;

    /// <summary>The BaseFold code seed shared by the plain and hiding commitment providers.</summary>
    private static byte[] CodeSeed { get; } = Encoding.UTF8.GetBytes("veridical.analysis.basefold-leakage.code.v1");
    /// <summary>The seed for the harness's deterministic prover-randomness source.</summary>
    private static byte[] RandomSeed { get; } = Encoding.UTF8.GetBytes("veridical.analysis.basefold-leakage.rng.v1");
    /// <summary>The BLS12-381 curve parameters used throughout these tests.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    /// <summary>Checks that the byte-statistics experiment completes.</summary>
    [TestMethod]
    public void ByteStatisticsExperimentRunsToCompletion()
    {
        using PolynomialCommitmentProvider provider = NewProvider(BaseMemoryPool.Shared);
        BaseFoldLeakageHarness harness = NewHarness(provider);

        BaseFoldLeakageExperimentResult result = BaseFoldByteStatisticsExperiment.Run(harness, VariableCount, SampleCount);

        Assert.AreEqual("byte-distribution", result.Experiment);
        Assert.AreEqual(SampleCount, result.SampleCount);
        Assert.IsNotNull(result.StatisticalTest);
        Assert.IsTrue(Enum.IsDefined(result.Signal));
    }


    /// <summary>Checks that the classifier experiment completes.</summary>
    [TestMethod]
    public void ClassifierExperimentRunsToCompletion()
    {
        using PolynomialCommitmentProvider provider = NewProvider(BaseMemoryPool.Shared);
        BaseFoldLeakageHarness harness = NewHarness(provider);

        BaseFoldLeakageExperimentResult result = BaseFoldClassifierExperiment.Run(harness, VariableCount, SampleCount);

        Assert.AreEqual("classifier", result.Experiment);
        Assert.IsNotNull(result.ObservedMetric);
        Assert.IsGreaterThanOrEqualTo(0.0, result.ObservedMetric!.Value);
        Assert.IsLessThanOrEqualTo(1.0, result.ObservedMetric!.Value);
        Assert.AreEqual(0.5, result.BaselineMetric);
    }


    /// <summary>Checks that commitment recoverability is structurally certain.</summary>
    [TestMethod]
    public void CommitmentRecoverabilityIsStructurallyCertain()
    {
        using PolynomialCommitmentProvider provider = NewProvider(BaseMemoryPool.Shared);
        BaseFoldLeakageHarness harness = NewHarness(provider);

        BaseFoldLeakageExperimentResult result = BaseFoldCommitmentRecoverabilityExperiment.Run(harness, VariableCount, SampleCount);

        //BaseFold's commitment is a deterministic fingerprint of the witness, so
        //recovery from the commitment is certain — the definitive non-hiding leak.
        Assert.AreEqual(BaseFoldLeakageSignal.StructurallyCertain, result.Signal);
    }


    /// <summary>Checks that hiding provider flips commitment recoverability to not detected.</summary>
    [TestMethod]
    public void HidingProviderFlipsCommitmentRecoverabilityToNotDetected()
    {
        //The ZK BaseFold provider salts the Merkle leaves with fresh entropy, so
        //the commitment is not a deterministic fingerprint of the witness; the
        //recoverability experiment that is StructurallyCertain for the plain
        //provider must report NotDetected here. This is the hiding provider's
        //leakage flip: recoverability moves from StructurallyCertain to NotDetected.
        using PolynomialCommitmentProvider provider = NewHidingProvider(BaseMemoryPool.Shared);
        BaseFoldLeakageHarness harness = NewHarness(provider);

        BaseFoldLeakageExperimentResult result = BaseFoldCommitmentRecoverabilityExperiment.Run(harness, VariableCount, SampleCount);

        Assert.AreEqual(BaseFoldLeakageSignal.NotDetected, result.Signal);
    }


    /// <summary>Checks that the experiment suite returns its three results.</summary>
    [TestMethod]
    public void RunAllProducesThreeResults()
    {
        using PolynomialCommitmentProvider provider = NewProvider(BaseMemoryPool.Shared);
        BaseFoldLeakageHarness harness = NewHarness(provider);

        IReadOnlyList<BaseFoldLeakageExperimentResult> results = BaseFoldLeakageExperimentRunner.RunAll(harness, VariableCount, SampleCount);

        Assert.HasCount(3, results);
        Assert.AreEqual(BaseFoldLeakageSignal.StructurallyCertain, results[2].Signal);
    }


    /// <summary>Test context, for emitting the at-scale findings to the test log.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>Checks that the experiment suite reports findings at the configured sample count.</summary>
    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void RunAllAtScaleReportsFindings()
    {
        using PolynomialCommitmentProvider provider = NewProvider(BaseMemoryPool.Shared);
        BaseFoldLeakageHarness harness = NewHarness(provider);

        const int ScaleVariableCount = 3;
        const int ScaleSampleCount = 200;

        IReadOnlyList<BaseFoldLeakageExperimentResult> results = BaseFoldLeakageExperimentRunner.RunAll(harness, ScaleVariableCount, ScaleSampleCount);

        foreach(BaseFoldLeakageExperimentResult result in results)
        {
            TestContext.WriteLine($"[{result.Experiment}] signal={result.Signal} | {result.Summary}");
        }

        //Regardless of the statistical findings, the structural leak is certain.
        Assert.AreEqual(BaseFoldLeakageSignal.StructurallyCertain, results[2].Signal);
    }


    /// <summary>Builds the leakage harness around the given commitment provider, with deterministic prover randomness and fresh transcripts.</summary>
    private static BaseFoldLeakageHarness NewHarness(PolynomialCommitmentProvider provider)
    {
        ScalarRandomDelegate random = new DeterministicScalarRandom(RandomSeed).AsDelegate();
        return new BaseFoldLeakageHarness(provider, Curve, random, NewTranscript, BaseMemoryPool.Shared);
    }


    /// <summary>Builds the commitment provider using the caller's pool.</summary>
    /// <param name="pool">The pool supplied by the test.</param>
    private static PolynomialCommitmentProvider NewProvider(BaseMemoryPool pool)
    {
        return BaseFoldPolynomialCommitmentScheme.Create(
            CodeSeed, Curve, QueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, HashToScalar, pool, DigestSizeBytes);
    }


    /// <summary>Builds the zero-knowledge BaseFold commitment provider, whose Merkle leaves are salted with entropy-backed (not deterministic) randomness so committing the same witness twice yields different roots — the hiding property.</summary>
    /// <param name="pool">The pool supplied by the test.</param>
    private static PolynomialCommitmentProvider NewHidingProvider(BaseMemoryPool pool)
    {
        //Entropy-backed salts (not the deterministic sampler) so committing the
        //same witness twice yields different roots — the hiding property.
        ScalarRandomDelegate saltRandom = Bls12Curve381BigIntegerScalarReference.GetRandom();
        return ZkBaseFoldPolynomialCommitmentScheme.Create(
            CodeSeed, Curve, QueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, saltRandom, HashToScalar, pool, DigestSizeBytes);
    }


    /// <summary>Creates a new Fiat–Shamir transcript under the BaseFold evaluation domain label.</summary>
    private static FiatShamirTranscript NewTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownBaseFoldEvaluationParameters.TranscriptDomainLabel),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }


    /// <summary>Computes the two-to-one Merkle compression of <paramref name="left"/> and <paramref name="right"/> using BLAKE3.</summary>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }
}
