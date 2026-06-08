using Lumoin.Veridical.Analysis.Simulation;
using Lumoin.Veridical.Analysis.StatisticalTests;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Text;

namespace Lumoin.Veridical.Tests.Analysis;

/// <summary>
/// The witness-free masked-Spartan simulator gates —
/// <see cref="ZkBaseFoldMaskedSpartanSimulator"/> lifting the FS-batch recipe
/// from one opening to the whole <c>ProveZkBaseFold</c> proof. The instance
/// has four distinct nonzero constraint rows (two row variables), so the
/// <c>E_τ = g̃(τ)</c> computation's row-indexing and challenge-order
/// conventions are genuinely pinned — a reversal would flip the patch and
/// fail the verify gate, which a single-row-variable instance could not
/// detect. The simulator receives the instance only; the satisfying witness
/// <c>(x, y) = (3, 5)</c> exists solely on the real-proof side of the
/// two-sample comparison.
/// </summary>
[TestClass]
internal sealed class ZkBaseFoldMaskedSpartanSimulatorTests
{
    /// <summary>Test context, for emitting the two-sample findings to the test log.</summary>
    public TestContext TestContext { get; set; } = null!;

    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;
    private static ScalarRandomDelegate Random { get; } = Bls12Curve381BigIntegerScalarReference.GetRandom();
    private static ScalarHashToScalarDelegate HashToScalar { get; } = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    private const int ScalarSize = 32;
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;
    private const int QueryCount = 8;
    //The smallest committed polynomial this instance routes through the
    //provider has d = 1 (the two-scalar witness), which at QueryCount = 8
    //needs t = 6 (GetMinimumExtraVariableCount).
    private const int ExtraVariableCount = 6;
    //Two-sample scale: each sample is a full masked-Spartan prove, so this
    //trades statistical power against suite runtime as the sibling
    //experiments do.
    private const int SampleCount = 12;
    //Byte-value bins for the per-proof histograms.
    private const int ByteValueCount = 256;
    private const string TranscriptDomain = "veridical.analysis.spartan2.simulator.test.v1";

    private static readonly byte[] CodeSeed = Encoding.UTF8.GetBytes("veridical.analysis.spartan2.simulator.code.v1");
    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    public void SimulatedMaskedSpartanProofVerifiesUnderTheProgrammedOracle()
    {
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        using RawR1csInstance instance = BuildInstance();

        (ZkBaseFoldMaskedSpartanProof proof, ProgrammableFiatShamirOracle oracle) = Simulate(instance, pool);

        using(proof)
        {
            Assert.IsTrue(
                Verify(proof, instance, oracle.CreateReplaySqueeze(), pool),
                "The witness-free simulated masked-Spartan proof must verify under the programmed oracle.");

            //The verifier consumed the programmed responses one-to-one.
            Assert.AreEqual(oracle.RecordedCount, oracle.ReplayedCount, "The verifier must squeeze exactly the recorded sequence.");
        }
    }


    [TestMethod]
    public void SimulatedMaskedSpartanProofIsRejectedByTheRealOracle()
    {
        //Without the programming, the patched σ_outer diverges the transcript
        //at the blend challenge and the chain collapses — soundness against
        //honest oracles is untouched.
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        using RawR1csInstance instance = BuildInstance();

        (ZkBaseFoldMaskedSpartanProof proof, ProgrammableFiatShamirOracle oracle) = Simulate(instance, pool);

        using(proof)
        {
            Assert.IsFalse(
                Verify(proof, instance, Squeeze, pool),
                "The simulated proof must be rejected when the oracle is not programmed.");
        }
    }


    [TestMethod]
    public void RealAndSimulatedMaskedSpartanProofsCompareInTwoSampleTests()
    {
        //Real proofs of the satisfying witness versus witness-free simulated
        //proofs: mean proof byte under Kolmogorov-Smirnov, per-proof byte
        //histograms under the label-permutation null (the analytic chi-squared
        //p-value is invalid under intra-proof byte dependence — the SM.6
        //finding). Verdicts logged, not asserted, per the established
        //doctrine.
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        using RawR1csInstance instance = BuildInstance();

        double[] realMeans = new double[SampleCount];
        double[] simulatedMeans = new double[SampleCount];
        var histograms = new List<long[]>(2 * SampleCount);
        var labels = new int[2 * SampleCount];

        for(int i = 0; i < SampleCount; i++)
        {
            using(ZkBaseFoldMaskedSpartanProof real = ProveReal(instance, pool))
            {
                long[] histogram = new long[ByteValueCount];
                realMeans[i] = Accumulate(real.AsReadOnlySpan(), histogram);
                histograms.Add(histogram);
                labels[histograms.Count - 1] = 0;
            }

            (ZkBaseFoldMaskedSpartanProof simulated, ProgrammableFiatShamirOracle oracle) = Simulate(instance, pool);
            using(simulated)
            {
                long[] histogram = new long[ByteValueCount];
                simulatedMeans[i] = Accumulate(simulated.AsReadOnlySpan(), histogram);
                histograms.Add(histogram);
                labels[histograms.Count - 1] = 1;
            }
        }

        StatisticalTestResult ks = KolmogorovSmirnovTest.TwoSample(realMeans, simulatedMeans);
        StatisticalTestResult permutation = PermutationTest.HomogeneityOfPooledHistograms(histograms, labels);

        TestContext.WriteLine($"real-vs-simulated masked-Spartan mean-byte KS: {ks.Interpretation}, statistic {ks.TestStatistic:F4}, p {ks.PValue:F4}");
        TestContext.WriteLine($"real-vs-simulated masked-Spartan byte-histogram permutation: {permutation.Interpretation}, chi-squared statistic {permutation.TestStatistic:F1}, permutation p {permutation.PValue:F4}");

        Assert.IsTrue(ks.PValue is >= 0 and <= 1, "The KS two-sample test must produce a well-formed p-value.");
        Assert.IsTrue(permutation.PValue is > 0 and <= 1, "The permutation test must produce a well-formed p-value.");
    }


    private static (ZkBaseFoldMaskedSpartanProof Proof, ProgrammableFiatShamirOracle Oracle) Simulate(
        RawR1csInstance instance, SensitiveMemoryPool<byte> pool)
    {
        using FiatShamirTranscript transcript = FreshTranscript();

        return ZkBaseFoldMaskedSpartanSimulator.Simulate(
            instance, transcript, BuildProvider, BuildErrorProvider,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold,
            QueryCount, DigestSizeBytes, ExtraVariableCount, pool);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The Spartan key takes ownership of the provider and the prover disposes the key; the proof transfers to the caller.")]
    private static ZkBaseFoldMaskedSpartanProof ProveReal(RawR1csInstance instance, SensitiveMemoryPool<byte> pool)
    {
        using RawR1csWitness witness = BuildSatisfyingWitness();
        var provingKey = new SpartanProvingKey(BuildProvider(Squeeze));
        using var prover = new MaskedSpartanProver(provingKey);
        using FiatShamirTranscript transcript = FreshTranscript();
        using PolynomialCommitmentProvider errorProvider = BuildErrorProvider(Squeeze);

        return prover.ProveZkBaseFold(
            instance, witness, transcript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, errorProvider, pool);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The Spartan key takes ownership of the provider and the verifier disposes the key.")]
    private static bool Verify(
        ZkBaseFoldMaskedSpartanProof proof, RawR1csInstance instance, FiatShamirSqueezeDelegate squeeze, SensitiveMemoryPool<byte> pool)
    {
        var verifyingKey = new SpartanVerifyingKey(BuildProvider(squeeze));
        using var verifier = new MaskedSpartanVerifier(verifyingKey);
        using FiatShamirTranscript transcript = FreshTranscript();
        using PolynomialCommitmentProvider errorProvider = BuildErrorProvider(squeeze);

        return verifier.VerifyZkBaseFold(
            proof, instance, transcript,
            Add, Multiply, Subtract, Invert, Reduce, Hash, squeeze, errorProvider, pool);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The provider holds no disposable key; the consumer disposes it.")]
    private static PolynomialCommitmentProvider BuildProvider(FiatShamirSqueezeDelegate squeeze)
    {
        return ZkBaseFoldPolynomialCommitmentScheme.CreateFullZeroKnowledge(
            CodeSeed, Curve, QueryCount, Merkle, Hash, squeeze, Reduce, Add, Subtract, Multiply, Invert,
            Random, HashToScalar, ExtraVariableCount, DigestSizeBytes);
    }


    //The plain (deterministic) BaseFold provider for the public zero-error
    //vector, over the same code parameters so prover and verifier recompute
    //the identical error commitment.
    [SuppressMessage("Reliability", "CA2000", Justification = "The provider holds no disposable key; the consumer disposes it.")]
    private static PolynomialCommitmentProvider BuildErrorProvider(FiatShamirSqueezeDelegate squeeze)
    {
        return BaseFoldPolynomialCommitmentScheme.Create(
            CodeSeed, Curve, QueryCount, Merkle, Hash, squeeze, Reduce, Add, Subtract, Multiply, Invert, HashToScalar, DigestSizeBytes);
    }


    //Four distinct nonzero constraints over z = (1, 15, x, y), satisfied by
    //(x, y) = (3, 5): x·y = 15, x·x = 9·1, y·y = 25·1, x·15 = 45·1. Two row
    //variables pin the E_τ index conventions.
    private static RawR1csInstance BuildInstance()
    {
        int[] aRows = [0, 1, 2, 3];
        int[] aCols = [2, 2, 3, 2];
        int[] bRows = [0, 1, 2, 3];
        int[] bCols = [3, 2, 3, 1];
        int[] cRows = [0, 1, 2, 3];
        int[] cCols = [1, 0, 0, 0];

        byte[] aValues = BuildCanonicalScalars(1, 1, 1, 1);
        byte[] bValues = BuildCanonicalScalars(1, 1, 1, 1);
        byte[] cValues = BuildCanonicalScalars(1, 9, 25, 45);

        R1csMatrix a = R1csMatrix.FromSortedTriples(aRows, aCols, aValues, 4, 4, Curve, SensitiveMemoryPool<byte>.Shared);
        R1csMatrix b = R1csMatrix.FromSortedTriples(bRows, bCols, bValues, 4, 4, Curve, SensitiveMemoryPool<byte>.Shared);
        R1csMatrix c = R1csMatrix.FromSortedTriples(cRows, cCols, cValues, 4, 4, Curve, SensitiveMemoryPool<byte>.Shared);

        byte[] publicInput = BuildCanonicalScalars(15);

        return RawR1csInstance.Create(a, b, c, publicInput, SensitiveMemoryPool<byte>.Shared);
    }


    private static RawR1csWitness BuildSatisfyingWitness()
    {
        byte[] witnessBytes = BuildCanonicalScalars(3, 5);

        return RawR1csWitness.FromCanonical(witnessBytes, Curve, SensitiveMemoryPool<byte>.Shared);
    }


    private static byte[] BuildCanonicalScalars(params int[] values)
    {
        byte[] bytes = new byte[values.Length * ScalarSize];
        for(int i = 0; i < values.Length; i++)
        {
            WriteCanonical(new BigInteger(values[i]), bytes.AsSpan(i * ScalarSize, ScalarSize));
        }

        return bytes;
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


    private static FiatShamirTranscript FreshTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(TranscriptDomain),
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


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        BigInteger r = Bls12Curve381BigIntegerScalarReference.FieldOrder;
        BigInteger nonNegative = ((value % r) + r) % r;
        if(!nonNegative.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("Reduced scalar did not fit in the canonical span.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }
}
