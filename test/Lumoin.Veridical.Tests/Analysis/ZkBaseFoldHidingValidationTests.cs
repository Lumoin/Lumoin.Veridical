using Lumoin.Veridical.Analysis.BaseFoldLeakage;
using Lumoin.Veridical.Analysis.StatisticalTests;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.Spartan;
using System;
using System.Text;

namespace Lumoin.Veridical.Tests.Analysis;

/// <summary>
/// ZK.4 — empirical validation that the full zero-knowledge BaseFold provider
/// (<see cref="ZkBaseFoldPolynomialCommitmentScheme.CreateFullZeroKnowledge"/>)
/// closes the <em>structural</em> leakage the plain provider exhibits. The
/// guaranteed, discriminating evidence is the
/// <see cref="BaseFoldCommitmentRecoverabilityExperiment"/>: it is
/// <see cref="BaseFoldLeakageSignal.StructurallyCertain"/> for the plain provider
/// (the commitment is a deterministic fingerprint of the witness) and flips to
/// <see cref="BaseFoldLeakageSignal.NotDetected"/> here, because the commitment and
/// every fold root are salted with fresh entropy.
/// </summary>
/// <remarks>
/// <para>
/// <b>Verdicts are logged, not asserted.</b> The
/// sumcheck mask is the statistical mask
/// (<c>ZK-STATMASK-DESIGN.md</c> v3): every round coefficient is
/// blended with exact degrees-of-freedom coverage, the mask's terminal value is
/// bound by a filler-laundered weighted opening, and the byte-distribution
/// experiment assesses its statistic against a label-permutation null (the
/// analytic chi-squared was shown during batch SM to reject witness-independent
/// labelings on this proof structure — intra-proof byte duplication breaks its
/// independence assumption, which had also confounded the pre-SM attribution of
/// its Detected verdict to the multilinear mask's degree-two residual). The
/// statistical experiments are still asserted only to run to completion and
/// produce a well-formed result — a Detected or NotDetected finding is an honest
/// outcome at test-suite sample scales, not a pass/fail gate — with the verdicts
/// logged for the record. The structural recoverability flip is the claim that
/// is guaranteed and discriminating.
/// </para>
/// <para>
/// A literal real-versus-simulated proof-byte test compares a real proof to a
/// simulator's output (design doc §5). Since the FS batch this EXISTS: the
/// transcript's squeeze delegate is the programmable seam (the production
/// BLAKE3 hash needed no change), and <c>ZkBaseFoldSimulatorTests</c> runs the
/// witness-free <c>ZkBaseFoldOpeningSimulator</c> with its verifying and
/// distribution gates. The witness-independence two-sample form here remains
/// complementary evidence; <see cref="WitnessIndependenceTwoSampleTestHasPower"/>
/// confirms the test can reject when the distributions genuinely differ.
/// </para>
/// </remarks>
[TestClass]
internal sealed class ZkBaseFoldHidingValidationTests
{
    /// <summary>Test context, for emitting the at-scale findings to the test log.</summary>
    public TestContext TestContext { get; set; } = null!;

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
    //The minimal budget-meeting lift for d = 2 at QueryCount = 8
    //(GetMinimumExtraVariableCount): the provider refuses under-budget
    //configurations since the hiding-budget enforcement landed.
    private const int ExtraVariableCount = 5;
    private const int SampleCount = 40;

    private static readonly byte[] CodeSeed = Encoding.UTF8.GetBytes("veridical.analysis.zk-basefold.code.v1");
    private static readonly byte[] WitnessSeed = Encoding.UTF8.GetBytes("veridical.analysis.zk-basefold.witness.v1");
    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    public void CommitmentRecoverabilityIsCertainForPlainAndNotDetectedUnderFullZeroKnowledge()
    {
        using PolynomialCommitmentProvider plain = NewPlainProvider();
        BaseFoldLeakageExperimentResult plainResult =
            BaseFoldCommitmentRecoverabilityExperiment.Run(NewHarness(plain), VariableCount, SampleCount);
        Assert.AreEqual(
            BaseFoldLeakageSignal.StructurallyCertain, plainResult.Signal,
            "Plain BaseFold's commitment is a deterministic witness fingerprint — recovery is certain.");

        using PolynomialCommitmentProvider fullZk = NewFullZeroKnowledgeProvider();
        BaseFoldLeakageExperimentResult zkResult =
            BaseFoldCommitmentRecoverabilityExperiment.Run(NewHarness(fullZk), VariableCount, SampleCount);
        Assert.AreEqual(
            BaseFoldLeakageSignal.NotDetected, zkResult.Signal,
            "Full-ZK BaseFold salts the commitment with fresh entropy, so it is no longer a witness fingerprint.");
    }


    [TestMethod]
    public void StatisticalExperimentsRunToCompletionUnderFullZeroKnowledge()
    {
        //The statistical experiments are asserted to run and produce a well-formed
        //result, not to reach a particular verdict: at test-suite sample scales a
        //borderline finding either way is honest, not a failure (the SM statistical
        //mask makes NotDetected the expected outcome — observed at permutation
        //p ≈ 0.24 when the fix landed). The findings are logged for the record.
        using PolynomialCommitmentProvider fullZk = NewFullZeroKnowledgeProvider();

        BaseFoldLeakageExperimentResult byteStats =
            BaseFoldByteStatisticsExperiment.Run(NewHarness(fullZk), VariableCount, SampleCount);
        Assert.AreEqual("byte-distribution", byteStats.Experiment);
        Assert.IsNotNull(byteStats.StatisticalTest);
        Assert.IsTrue(Enum.IsDefined(byteStats.Signal));
        TestContext.WriteLine($"[byte-distribution] signal={byteStats.Signal} | {byteStats.Summary}");

        BaseFoldLeakageExperimentResult classifier =
            BaseFoldClassifierExperiment.Run(NewHarness(fullZk), VariableCount, SampleCount);
        Assert.AreEqual("classifier", classifier.Experiment);
        Assert.IsNotNull(classifier.ObservedMetric);
        Assert.AreEqual(0.5, classifier.BaselineMetric);
        Assert.IsTrue(Enum.IsDefined(classifier.Signal));
        TestContext.WriteLine($"[classifier] signal={classifier.Signal} | {classifier.Summary}");

        BaseFoldLeakageExperimentResult witnessIndependence =
            BaseFoldProofWitnessIndependenceExperiment.Run(NewHarness(fullZk), VariableCount, SampleCount);
        Assert.AreEqual("witness-independence", witnessIndependence.Experiment);
        Assert.IsNotNull(witnessIndependence.StatisticalTest);
        Assert.IsTrue(Enum.IsDefined(witnessIndependence.Signal));
        TestContext.WriteLine($"[witness-independence] signal={witnessIndependence.Signal} | {witnessIndependence.Summary}");
    }


    //The figure-grade at-scale case takes ~5 minutes of full-ZK openings, which
    //would triple the suite; it runs only when explicitly requested via this
    //environment variable (the Inconclusive-gating idiom NEON and the CLI
    //integration tests use).
    private const string AtScaleOptInVariable = "VERIDICAL_AT_SCALE_LEAKAGE";


    [TestMethod]
    [TestCategory("Slow")]
    public void StatisticalExperimentsAtScaleReportFindings()
    {
        if(Environment.GetEnvironmentVariable(AtScaleOptInVariable) != "1")
        {
            Assert.Inconclusive($"The figure-grade at-scale run is opt-in; set {AtScaleOptInVariable}=1 to execute it (~5 minutes).");
        }

        //The at-scale companion of the run-to-completion case above: the same
        //three experiments at the figure-grade sample count the leakage
        //write-up quotes (BASEFOLD-LEAKAGE.md). Verdicts stay logged-not-
        //asserted — sample-scale statistics must not be flaky CI gates — but a
        //named, repeatable case replaces the one-off observation the doc's
        //full-ZK figures previously rested on.
        const int ScaleSampleCount = 200;

        using PolynomialCommitmentProvider fullZk = NewFullZeroKnowledgeProvider();

        BaseFoldLeakageExperimentResult byteStats =
            BaseFoldByteStatisticsExperiment.Run(NewHarness(fullZk), VariableCount, ScaleSampleCount);
        Assert.IsTrue(Enum.IsDefined(byteStats.Signal));
        TestContext.WriteLine($"[byte-distribution] signal={byteStats.Signal} | {byteStats.Summary}");

        BaseFoldLeakageExperimentResult classifier =
            BaseFoldClassifierExperiment.Run(NewHarness(fullZk), VariableCount, ScaleSampleCount);
        Assert.IsTrue(Enum.IsDefined(classifier.Signal));
        TestContext.WriteLine($"[classifier] signal={classifier.Signal} | {classifier.Summary}");

        BaseFoldLeakageExperimentResult witnessIndependence =
            BaseFoldProofWitnessIndependenceExperiment.Run(NewHarness(fullZk), VariableCount, ScaleSampleCount);
        Assert.IsTrue(Enum.IsDefined(witnessIndependence.Signal));
        TestContext.WriteLine($"[witness-independence] signal={witnessIndependence.Signal} | {witnessIndependence.Summary}");
    }


    [TestMethod]
    public void CommittingTheSameWitnessTwiceUnderFullZeroKnowledgeYieldsDifferentProofs()
    {
        //The strong, guaranteed hiding property at the proof level: fresh salts and
        //a fresh sumcheck mask each open, so an opening is not a deterministic
        //function of the witness.
        using PolynomialCommitmentProvider fullZk = NewFullZeroKnowledgeProvider();
        BaseFoldLeakageHarness harness = NewHarness(fullZk);

        using MultilinearExtension witness = harness.SamplePolynomial(VariableCount);
        Scalar[] point = harness.SamplePoint(VariableCount);
        try
        {
            byte[] first = harness.ProofBytes(witness, point);
            byte[] second = harness.ProofBytes(witness, point);

            int firstLength = first.Length;
            int secondLength = second.Length;
            Assert.AreEqual(firstLength, secondLength, "Two proofs of the same statement must share the wire length.");
            Assert.IsFalse(
                first.AsSpan().SequenceEqual(second),
                "Two full-ZK proofs of the same witness must differ (fresh salts and mask).");
        }
        finally
        {
            foreach(Scalar coordinate in point)
            {
                coordinate.Dispose();
            }
        }
    }


    [TestMethod]
    public void WitnessIndependenceTwoSampleTestHasPower()
    {
        //Positive control: the two-sample test the witness-independence experiment
        //relies on must reject when the two distributions genuinely differ, or its
        //NotDetected verdict above would be vacuous.
        double[] low = [0.10, 0.12, 0.14, 0.16, 0.18, 0.20, 0.22, 0.24, 0.26, 0.28];
        double[] high = [0.70, 0.72, 0.74, 0.76, 0.78, 0.80, 0.82, 0.84, 0.86, 0.88];

        StatisticalTestResult result = KolmogorovSmirnovTest.TwoSample(low, high);

        Assert.AreEqual(
            StatisticalTestInterpretation.Reject, result.Interpretation,
            "The KS two-sample test must reject two clearly separated distributions (it has power).");
    }


    private static BaseFoldLeakageHarness NewHarness(PolynomialCommitmentProvider provider)
    {
        //Witnesses are drawn from a deterministic stream (reproducible sampling);
        //the providers' own salt/mask entropy is what makes the ZK provider hiding.
        ScalarRandomDelegate witnessRandom = new DeterministicScalarRandom(WitnessSeed).AsDelegate();
        return new BaseFoldLeakageHarness(provider, Curve, witnessRandom, NewTranscript, SensitiveMemoryPool<byte>.Shared);
    }


    private static PolynomialCommitmentProvider NewPlainProvider()
    {
        return BaseFoldPolynomialCommitmentScheme.Create(
            CodeSeed, Curve, QueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, HashToScalar, DigestSizeBytes);
    }


    private static PolynomialCommitmentProvider NewFullZeroKnowledgeProvider()
    {
        //Entropy-backed salts and mask (not the deterministic sampler) so the
        //commitment and opening are genuinely hiding.
        ScalarRandomDelegate entropy = Bls12Curve381BigIntegerScalarReference.GetRandom();
        return ZkBaseFoldPolynomialCommitmentScheme.CreateFullZeroKnowledge(
            CodeSeed, Curve, QueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
            entropy, HashToScalar, ExtraVariableCount, DigestSizeBytes);
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


    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }
}
