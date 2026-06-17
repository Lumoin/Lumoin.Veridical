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
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static ScalarAddDelegate Add { get; } = Bls12Curve381BigIntegerScalarReference.GetAdd();
    private static ScalarSubtractDelegate Subtract { get; } = Bls12Curve381BigIntegerScalarReference.GetSubtract();
    private static ScalarMultiplyDelegate Multiply { get; } = Bls12Curve381BigIntegerScalarReference.GetMultiply();
    private static ScalarInvertDelegate Invert { get; } = Bls12Curve381BigIntegerScalarReference.GetInvert();
    private static ScalarHashToScalarDelegate HashToScalar { get; } = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;
    private const int QueryCount = 8;
    private const int VariableCount = 2;
    private const int SampleCount = 40;

    private static readonly byte[] CodeSeed = Encoding.UTF8.GetBytes("veridical.analysis.basefold-leakage.code.v1");
    private static readonly byte[] RandomSeed = Encoding.UTF8.GetBytes("veridical.analysis.basefold-leakage.rng.v1");
    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    public void ByteStatisticsExperimentRunsToCompletion()
    {
        using PolynomialCommitmentProvider provider = NewProvider();
        BaseFoldLeakageHarness harness = NewHarness(provider);

        BaseFoldLeakageExperimentResult result = BaseFoldByteStatisticsExperiment.Run(harness, VariableCount, SampleCount);

        Assert.AreEqual("byte-distribution", result.Experiment);
        Assert.AreEqual(SampleCount, result.SampleCount);
        Assert.IsNotNull(result.StatisticalTest);
        Assert.IsTrue(Enum.IsDefined(result.Signal));
    }


    [TestMethod]
    public void ClassifierExperimentRunsToCompletion()
    {
        using PolynomialCommitmentProvider provider = NewProvider();
        BaseFoldLeakageHarness harness = NewHarness(provider);

        BaseFoldLeakageExperimentResult result = BaseFoldClassifierExperiment.Run(harness, VariableCount, SampleCount);

        Assert.AreEqual("classifier", result.Experiment);
        Assert.IsNotNull(result.ObservedMetric);
        Assert.IsGreaterThanOrEqualTo(0.0, result.ObservedMetric!.Value);
        Assert.IsLessThanOrEqualTo(1.0, result.ObservedMetric!.Value);
        Assert.AreEqual(0.5, result.BaselineMetric);
    }


    [TestMethod]
    public void CommitmentRecoverabilityIsStructurallyCertain()
    {
        using PolynomialCommitmentProvider provider = NewProvider();
        BaseFoldLeakageHarness harness = NewHarness(provider);

        BaseFoldLeakageExperimentResult result = BaseFoldCommitmentRecoverabilityExperiment.Run(harness, VariableCount, SampleCount);

        //BaseFold's commitment is a deterministic fingerprint of the witness, so
        //recovery from the commitment is certain — the definitive non-hiding leak.
        Assert.AreEqual(BaseFoldLeakageSignal.StructurallyCertain, result.Signal);
    }


    [TestMethod]
    public void HidingProviderFlipsCommitmentRecoverabilityToNotDetected()
    {
        //The ZK BaseFold provider salts the Merkle leaves with fresh entropy, so
        //the commitment is no longer a deterministic fingerprint of the witness;
        //the recoverability experiment that is StructurallyCertain for the plain
        //provider must report NotDetected here. This is the ZK.1 leakage flip.
        using PolynomialCommitmentProvider provider = NewHidingProvider();
        BaseFoldLeakageHarness harness = NewHarness(provider);

        BaseFoldLeakageExperimentResult result = BaseFoldCommitmentRecoverabilityExperiment.Run(harness, VariableCount, SampleCount);

        Assert.AreEqual(BaseFoldLeakageSignal.NotDetected, result.Signal);
    }


    [TestMethod]
    public void RunAllProducesThreeResults()
    {
        using PolynomialCommitmentProvider provider = NewProvider();
        BaseFoldLeakageHarness harness = NewHarness(provider);

        IReadOnlyList<BaseFoldLeakageExperimentResult> results = BaseFoldLeakageExperimentRunner.RunAll(harness, VariableCount, SampleCount);

        Assert.HasCount(3, results);
        Assert.AreEqual(BaseFoldLeakageSignal.StructurallyCertain, results[2].Signal);
    }


    /// <summary>Test context, for emitting the at-scale findings to the test log.</summary>
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void RunAllAtScaleReportsFindings()
    {
        using PolynomialCommitmentProvider provider = NewProvider();
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


    private static BaseFoldLeakageHarness NewHarness(PolynomialCommitmentProvider provider)
    {
        ScalarRandomDelegate random = new DeterministicScalarRandom(RandomSeed).AsDelegate();
        return new BaseFoldLeakageHarness(provider, Curve, random, NewTranscript, BaseMemoryPool.Shared);
    }


    private static PolynomialCommitmentProvider NewProvider()
    {
        return BaseFoldPolynomialCommitmentScheme.Create(
            CodeSeed, Curve, QueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, HashToScalar, DigestSizeBytes);
    }


    private static PolynomialCommitmentProvider NewHidingProvider()
    {
        //Entropy-backed salts (not the deterministic sampler) so committing the
        //same witness twice yields different roots — the hiding property.
        ScalarRandomDelegate saltRandom = Bls12Curve381BigIntegerScalarReference.GetRandom();
        return ZkBaseFoldPolynomialCommitmentScheme.Create(
            CodeSeed, Curve, QueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, saltRandom, HashToScalar, DigestSizeBytes);
    }


    private static FiatShamirTranscript NewTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownBaseFoldEvaluationParameters.TranscriptDomainLabel),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }


    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }
}
