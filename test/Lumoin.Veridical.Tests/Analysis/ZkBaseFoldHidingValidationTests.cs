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
using System.Text;

namespace Lumoin.Veridical.Tests.Analysis;

/// <summary>
/// Empirical validation that the full zero-knowledge BaseFold provider
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
/// sumcheck mask is the statistical mask: every round coefficient is
/// blended with exact degrees-of-freedom coverage, the mask's terminal value is
/// bound by a filler-laundered weighted opening, and the byte-distribution
/// experiment assesses its statistic against a label-permutation null. The
/// analytic chi-squared test is invalid here, because intra-proof byte
/// duplication breaks the independence assumption the test relies on — that
/// same duplication can otherwise make a Detected verdict look like it comes
/// from the multilinear mask's degree-two residual, when it is really an
/// artifact of the broken independence assumption, not genuine leakage. The
/// statistical experiments are still asserted only to run to completion and
/// produce a well-formed result — a Detected or NotDetected finding is an honest
/// outcome at test-suite sample scales, not a pass/fail gate — with the verdicts
/// logged for the record. The structural recoverability flip is the claim that
/// is guaranteed and discriminating.
/// </para>
/// <para>
/// A literal real-versus-simulated proof-byte test compares a real proof to a
/// simulator's output. This is possible because the transcript's squeeze
/// delegate is the programmable seam (the production BLAKE3 hash needed no
/// change), and <c>ZkBaseFoldSimulatorTests</c> runs the
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

    /// <summary>The transcript's fixed-output BLAKE3 hash backend.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The transcript's BLAKE3 XOF backend.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();

    /// <summary>The BLS12-381 scalar reduction backend.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();

    /// <summary>The BLS12-381 scalar addition backend.</summary>
    private static ScalarAddDelegate Add { get; } = Bls12Curve381BigIntegerScalarReference.GetAdd();

    /// <summary>The BLS12-381 scalar subtraction backend.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = Bls12Curve381BigIntegerScalarReference.GetSubtract();

    /// <summary>The BLS12-381 scalar multiplication backend.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = Bls12Curve381BigIntegerScalarReference.GetMultiply();

    /// <summary>The BLS12-381 scalar inversion backend.</summary>
    private static ScalarInvertDelegate Invert { get; } = Bls12Curve381BigIntegerScalarReference.GetInvert();

    /// <summary>The BLS12-381 hash-to-scalar backend.</summary>
    private static ScalarHashToScalarDelegate HashToScalar { get; } = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();

    /// <summary>The two-to-one Merkle compression over BLAKE3.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    /// <summary>The wired Merkle digest size: BLAKE3's 32 bytes.</summary>
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    /// <summary>The Ligero-style query count both providers are built with.</summary>
    private const int QueryCount = 8;

    /// <summary>The polynomial variable count every experiment and roundtrip test commits at.</summary>
    private const int VariableCount = 2;

    /// <summary>
    /// The minimal budget-meeting lift for d = 2 at QueryCount = 8 (<c>GetMinimumExtraVariableCount</c>):
    /// the provider refuses any under-budget configuration below this lift.
    /// </summary>
    private const int ExtraVariableCount = 5;

    /// <summary>The two-sample scale used by the run-to-completion statistical experiments.</summary>
    private const int SampleCount = 40;

    /// <summary>The code seed both BaseFold flavors derive their encoder from.</summary>
    private static byte[] CodeSeed { get; } = Encoding.UTF8.GetBytes("veridical.analysis.zk-basefold.code.v1");

    /// <summary>The deterministic witness-sampling seed, distinct from the code seed.</summary>
    private static byte[] WitnessSeed { get; } = Encoding.UTF8.GetBytes("veridical.analysis.zk-basefold.witness.v1");

    /// <summary>The curve every artifact is tagged with.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    /// <summary>Checks that commitment recoverability is certain for plain and not detected under full zero knowledge.</summary>
    [TestMethod]
    public void CommitmentRecoverabilityIsCertainForPlainAndNotDetectedUnderFullZeroKnowledge()
    {
        using PolynomialCommitmentProvider plain = NewPlainProvider(BaseMemoryPool.Shared);
        BaseFoldLeakageExperimentResult plainResult =
            BaseFoldCommitmentRecoverabilityExperiment.Run(NewHarness(plain), VariableCount, SampleCount);
        Assert.AreEqual(
            BaseFoldLeakageSignal.StructurallyCertain, plainResult.Signal,
            "Plain BaseFold's commitment is a deterministic witness fingerprint — recovery is certain.");

        using PolynomialCommitmentProvider fullZk = NewFullZeroKnowledgeProvider(BaseMemoryPool.Shared);
        BaseFoldLeakageExperimentResult zkResult =
            BaseFoldCommitmentRecoverabilityExperiment.Run(NewHarness(fullZk), VariableCount, SampleCount);
        Assert.AreEqual(
            BaseFoldLeakageSignal.NotDetected, zkResult.Signal,
            "Full-ZK BaseFold salts the commitment with fresh entropy, so it is no longer a witness fingerprint.");
    }


    /// <summary>Checks that statistical experiments run to completion under full zero knowledge.</summary>
    [TestMethod]
    public void StatisticalExperimentsRunToCompletionUnderFullZeroKnowledge()
    {
        //The statistical experiments are asserted to run and produce a well-formed
        //result, not to reach a particular verdict: at test-suite sample scales a
        //borderline finding either way is a valid outcome, not a failure (the
        //statistical mask makes NotDetected the expected outcome, observed at
        //permutation p ≈ 0.24). The findings are logged for the record.
        using PolynomialCommitmentProvider fullZk = NewFullZeroKnowledgeProvider(BaseMemoryPool.Shared);

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


    /// <summary>
    /// The environment variable that opts into the figure-grade at-scale case, which takes ~5 minutes of
    /// full-ZK openings and would triple the suite if run by default — the same Inconclusive-gating idiom
    /// the NEON and CLI integration tests use.
    /// </summary>
    private const string AtScaleOptInVariable = "VERIDICAL_AT_SCALE_LEAKAGE";


    /// <summary>Checks that statistical experiments at scale report findings.</summary>
    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void StatisticalExperimentsAtScaleReportFindings()
    {
        if(Environment.GetEnvironmentVariable(AtScaleOptInVariable) != "1")
        {
            Assert.Inconclusive($"The figure-grade at-scale run is opt-in; set {AtScaleOptInVariable}=1 to execute it (~5 minutes).");
        }

        //The at-scale companion of the run-to-completion case above: the same
        //three experiments at a figure-grade sample count. Verdicts stay logged-not-
        //asserted — sample-scale statistics must not be flaky CI gates — but a
        //named, repeatable case gives the full-zero-knowledge leakage figures a
        //reproducible source instead of a one-off observation.
        const int ScaleSampleCount = 200;

        using PolynomialCommitmentProvider fullZk = NewFullZeroKnowledgeProvider(BaseMemoryPool.Shared);

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


    /// <summary>Checks that committing the same witness twice under full zero knowledge yields different proofs.</summary>
    [TestMethod]
    public void CommittingTheSameWitnessTwiceUnderFullZeroKnowledgeYieldsDifferentProofs()
    {
        //The strong, guaranteed hiding property at the proof level: fresh salts and
        //a fresh sumcheck mask each open, so an opening is not a deterministic
        //function of the witness.
        using PolynomialCommitmentProvider fullZk = NewFullZeroKnowledgeProvider(BaseMemoryPool.Shared);
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


    /// <summary>Positive control: pins that the Kolmogorov-Smirnov two-sample test rejects two clearly separated distributions, so the witness-independence experiment's NotDetected verdict elsewhere is not vacuous.</summary>
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


    /// <summary>Builds the leakage harness over the given provider, sampling witnesses from a deterministic stream so only the provider's own salt and mask entropy can make the result hiding.</summary>
    private static BaseFoldLeakageHarness NewHarness(PolynomialCommitmentProvider provider)
    {
        //Witnesses are drawn from a deterministic stream (reproducible sampling);
        //the providers' own salt/mask entropy is what makes the ZK provider hiding.
        ScalarRandomDelegate witnessRandom = new DeterministicScalarRandom(WitnessSeed).AsDelegate();
        return new BaseFoldLeakageHarness(provider, Curve, witnessRandom, NewTranscript, BaseMemoryPool.Shared);
    }


    /// <summary>Builds the commitment provider using the caller's pool.</summary>
    /// <param name="pool">The pool supplied by the test.</param>
    private static PolynomialCommitmentProvider NewPlainProvider(BaseMemoryPool pool)
    {
        return BaseFoldPolynomialCommitmentScheme.Create(
            CodeSeed, Curve, QueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, HashToScalar, pool, DigestSizeBytes);
    }


    /// <summary>Builds the commitment provider using the caller's pool.</summary>
    /// <param name="pool">The pool supplied by the test.</param>
    private static PolynomialCommitmentProvider NewFullZeroKnowledgeProvider(BaseMemoryPool pool)
    {
        //Entropy-backed salts and mask (not the deterministic sampler) so the
        //commitment and opening are genuinely hiding.
        ScalarRandomDelegate entropy = Bls12Curve381BigIntegerScalarReference.GetRandom();
        return ZkBaseFoldPolynomialCommitmentScheme.CreateFullZeroKnowledge(
            CodeSeed, Curve, QueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
            entropy, HashToScalar, ExtraVariableCount, pool, DigestSizeBytes);
    }


    /// <summary>A fresh transcript under the BaseFold domain label with empty context.</summary>
    private static FiatShamirTranscript NewTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownBaseFoldEvaluationParameters.TranscriptDomainLabel),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }


    /// <summary>The two-to-one compression: BLAKE3 over the concatenated children.</summary>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }
}
