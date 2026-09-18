using Lumoin.Veridical.Analysis.Simulation;
using Lumoin.Veridical.Analysis.StatisticalTests;
using Lumoin.Veridical.Backends.Managed;
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

    /// <summary>The BLAKE3 Fiat–Shamir hash delegate this test's transcripts and commitment providers share.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    /// <summary>The BLAKE3 Fiat–Shamir squeeze delegate this test's transcripts and commitment providers share.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    /// <summary>The BLS12-381 scalar-field reduction delegate used throughout these tests.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    /// <summary>The BLS12-381 scalar addition delegate the masked-Spartan prover and verifier use.</summary>
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;
    /// <summary>The BLS12-381 scalar subtraction delegate the masked-Spartan prover and verifier use.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;
    /// <summary>The BLS12-381 scalar multiplication delegate the masked-Spartan prover and verifier use.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;
    /// <summary>The BLS12-381 scalar inversion delegate the masked-Spartan prover and verifier use.</summary>
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;
    /// <summary>The BLS12-381 scalar randomness delegate the masking terms are drawn from.</summary>
    private static ScalarRandomDelegate Random { get; } = Bls12Curve381BigIntegerScalarReference.GetRandom();
    /// <summary>The BLS12-381 hash-to-scalar delegate the BaseFold-family commitment providers use to derive challenges.</summary>
    private static ScalarHashToScalarDelegate HashToScalar { get; } = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();
    /// <summary>The BLS12-381 G1 point addition delegate the commitment providers use.</summary>
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();
    /// <summary>The BLS12-381 G1 scalar multiplication delegate the commitment providers use.</summary>
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    /// <summary>The BLS12-381 G1 multi-scalar multiplication delegate the commitment providers use.</summary>
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;
    /// <summary>The multilinear-extension evaluation delegate the masked-Spartan verifier uses to check round claims.</summary>
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();
    /// <summary>The multilinear-extension folding delegate the masked-Spartan prover uses to build its sumcheck rounds.</summary>
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();
    /// <summary>The two-to-one Merkle compression function, delegated to <see cref="HashTwoToOne"/>.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    /// <summary>The byte width of a canonical BLS12-381 scalar.</summary>
    private const int ScalarSize = 32;
    /// <summary>The byte width of a BLAKE3 digest, as used by the Merkle and BaseFold commitments in these tests.</summary>
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;
    /// <summary>The number of BaseFold query repetitions these fixtures use.</summary>
    private const int QueryCount = 8;
    /// <summary>The number of extra masking variables the commitment providers pad with. The smallest committed polynomial this instance routes through the provider has degree 1 (the two-scalar witness), which at <see cref="QueryCount"/> = 8 needs 6 extra variables (see <c>GetMinimumExtraVariableCount</c>).</summary>
    private const int ExtraVariableCount = 6;
    /// <summary>The number of real and simulated proofs the two-sample comparison draws. Each sample is a full masked-Spartan prove, so this count trades statistical power against suite runtime, the same tradeoff the sibling statistical experiments make.</summary>
    private const int SampleCount = 12;
    /// <summary>The number of byte-value bins in each per-proof histogram.</summary>
    private const int ByteValueCount = 256;
    /// <summary>The Fiat–Shamir domain-separation label for every transcript this test class creates.</summary>
    private const string TranscriptDomain = "veridical.analysis.spartan2.simulator.test.v1";

    /// <summary>The BaseFold code seed shared by the zero-knowledge and error commitment providers, so the prover and verifier derive identical codes.</summary>
    private static byte[] CodeSeed { get; } = Encoding.UTF8.GetBytes("veridical.analysis.spartan2.simulator.code.v1");
    /// <summary>The BLS12-381 curve parameters used throughout these tests.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    /// <summary>Verifies that a witness-free simulated masked-Spartan proof verifies when the verifier replays the oracle responses the simulator programmed, consuming exactly the recorded sequence.</summary>
    [TestMethod]
    public void SimulatedMaskedSpartanProofVerifiesUnderTheProgrammedOracle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
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


    /// <summary>Verifies that a witness-free simulated proof is rejected when verified against an honest, unprogrammed oracle, since the patched challenge diverges the transcript from that point on.</summary>
    [TestMethod]
    public void SimulatedMaskedSpartanProofIsRejectedByTheRealOracle()
    {
        //Without the programming, the patched σ_outer diverges the transcript
        //at the blend challenge and the chain collapses — soundness against
        //honest oracles is untouched.
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using RawR1csInstance instance = BuildInstance();

        (ZkBaseFoldMaskedSpartanProof proof, ProgrammableFiatShamirOracle oracle) = Simulate(instance, pool);

        using(proof)
        {
            Assert.IsFalse(
                Verify(proof, instance, Squeeze, pool),
                "The simulated proof must be rejected when the oracle is not programmed.");
        }
    }


    /// <summary>Compares real (witness-backed) and simulated (witness-free) masked-Spartan proofs across independent samples, checking that the Kolmogorov–Smirnov and permutation tests each produce a well-formed p-value; the tests' own reject/not-reject verdicts are logged for review rather than asserted, since any fixed-significance statistical test has a nonzero false-positive rate.</summary>
    [TestMethod]
    public void RealAndSimulatedMaskedSpartanProofsCompareInTwoSampleTests()
    {
        //Real proofs of the satisfying witness versus witness-free simulated
        //proofs: mean proof byte under Kolmogorov-Smirnov, per-proof byte
        //histograms under the label-permutation null (the analytic chi-squared
        //p-value is invalid here, because intra-proof byte dependence breaks
        //its independence assumption). A statistical test has a nonzero
        //false-positive rate at any fixed significance level, so its
        //reject/not-reject verdict is logged for review rather than asserted;
        //only the p-value's well-formedness is asserted below.
        BaseMemoryPool pool = BaseMemoryPool.Shared;
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


    /// <summary>Simulates a proof with provider factories funded by the caller's pool.</summary>
    private static (ZkBaseFoldMaskedSpartanProof Proof, ProgrammableFiatShamirOracle Oracle) Simulate(
        RawR1csInstance instance, BaseMemoryPool pool)
    {
        using FiatShamirTranscript transcript = FreshTranscript();

        return ZkBaseFoldMaskedSpartanSimulator.Simulate(
            instance, transcript, squeeze => BuildProvider(pool, squeeze), squeeze => BuildErrorProvider(pool, squeeze),
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold,
            QueryCount, DigestSizeBytes, ExtraVariableCount, pool);
    }


    /// <summary>Produces a witness-backed proof using the caller's pool and transfers provider ownership to the prover.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The provider's pooled storage transfers to the proving key and the key to the prover, which the using declaration releases; the key and prover constructors cannot fail for a non-null argument, so no path leaves the provider unreleased.")]
    private static ZkBaseFoldMaskedSpartanProof ProveReal(RawR1csInstance instance, BaseMemoryPool pool)
    {
        using RawR1csWitness witness = BuildSatisfyingWitness();
        var provingKey = new SpartanProvingKey(BuildProvider(pool, Squeeze));
        using var prover = new MaskedSpartanProver(provingKey);
        using FiatShamirTranscript transcript = FreshTranscript();
        using PolynomialCommitmentProvider errorProvider = BuildErrorProvider(pool, Squeeze);

        return prover.ProveZkBaseFold(
            instance, witness, transcript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, errorProvider, pool);
    }


    /// <summary>Verifies the test proof and releases provider storage through the owning verifier.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The provider's pooled storage transfers to the verifying key and the key to the verifier, which the using declaration releases; the key and verifier constructors cannot fail for a non-null argument, so no path leaves the provider unreleased.")]
    private static bool Verify(
        ZkBaseFoldMaskedSpartanProof proof, RawR1csInstance instance, FiatShamirSqueezeDelegate squeeze, BaseMemoryPool pool)
    {
        var verifyingKey = new SpartanVerifyingKey(BuildProvider(pool, squeeze));
        using var verifier = new MaskedSpartanVerifier(verifyingKey);
        using FiatShamirTranscript transcript = FreshTranscript();
        using PolynomialCommitmentProvider errorProvider = BuildErrorProvider(pool, squeeze);

        return verifier.VerifyZkBaseFold(
            proof, instance, transcript,
            Add, Multiply, Subtract, Invert, Reduce, Hash, squeeze, errorProvider, pool);
    }


    /// <summary>Builds the commitment provider using the caller's pool.</summary>
    /// <param name="pool">The pool supplied by the test.</param>
    /// <param name="squeeze">The transcript squeeze backend.</param>
    private static PolynomialCommitmentProvider BuildProvider(BaseMemoryPool pool, FiatShamirSqueezeDelegate squeeze)
    {
        return ZkBaseFoldPolynomialCommitmentScheme.CreateFullZeroKnowledge(
            CodeSeed, Curve, QueryCount, Merkle, Hash, squeeze, Reduce, Add, Subtract, Multiply, Invert,
            Random, HashToScalar, ExtraVariableCount, pool, DigestSizeBytes);
    }


    /// <summary>
    /// Builds the plain (deterministic) BaseFold commitment provider for the public zero-error
    /// vector, using the caller's pool over the same code parameters so the prover and verifier
    /// recompute the identical error commitment.
    /// </summary>
    /// <param name="pool">The pool supplied by the test.</param>
    /// <param name="squeeze">The transcript squeeze backend.</param>
    private static PolynomialCommitmentProvider BuildErrorProvider(BaseMemoryPool pool, FiatShamirSqueezeDelegate squeeze)
    {
        return BaseFoldPolynomialCommitmentScheme.Create(
            CodeSeed, Curve, QueryCount, Merkle, Hash, squeeze, Reduce, Add, Subtract, Multiply, Invert, HashToScalar, pool, DigestSizeBytes);
    }


    /// <summary>Builds the four-constraint R1CS instance over <c>z = (1, 15, x, y)</c>, satisfied by <c>(x, y) = (3, 5)</c>: <c>x·y = 15</c>, <c>x·x = 9·1</c>, <c>y·y = 25·1</c>, <c>x·15 = 45·1</c>. Two row variables pin the <c>E_τ</c> index conventions.</summary>
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

        R1csMatrix a = R1csMatrix.FromSortedTriples(aRows, aCols, aValues, 4, 4, Curve, BaseMemoryPool.Shared);
        R1csMatrix b = R1csMatrix.FromSortedTriples(bRows, bCols, bValues, 4, 4, Curve, BaseMemoryPool.Shared);
        R1csMatrix c = R1csMatrix.FromSortedTriples(cRows, cCols, cValues, 4, 4, Curve, BaseMemoryPool.Shared);

        byte[] publicInput = BuildCanonicalScalars(15);

        return RawR1csInstance.Create(a, b, c, publicInput, BaseMemoryPool.Shared);
    }


    /// <summary>Builds the witness <c>(x, y) = (3, 5)</c> that satisfies <see cref="BuildInstance"/>'s constraints.</summary>
    private static RawR1csWitness BuildSatisfyingWitness()
    {
        byte[] witnessBytes = BuildCanonicalScalars(3, 5);

        return RawR1csWitness.FromCanonical(witnessBytes, Curve, BaseMemoryPool.Shared);
    }


    /// <summary>Encodes each value in <paramref name="values"/> as a canonical big-endian BLS12-381 scalar, concatenated.</summary>
    private static byte[] BuildCanonicalScalars(params int[] values)
    {
        byte[] bytes = new byte[values.Length * ScalarSize];
        for(int i = 0; i < values.Length; i++)
        {
            WriteCanonical(new BigInteger(values[i]), bytes.AsSpan(i * ScalarSize, ScalarSize));
        }

        return bytes;
    }


    /// <summary>Sums the bytes of <paramref name="proof"/> into <paramref name="histogram"/>'s per-byte-value bins and returns the proof's mean byte value.</summary>
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


    /// <summary>Creates a new Fiat–Shamir transcript domain-separated by <see cref="TranscriptDomain"/>.</summary>
    private static FiatShamirTranscript FreshTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(TranscriptDomain),
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


    /// <summary>Reduces <paramref name="value"/> modulo the BLS12-381 scalar field order and writes it to <paramref name="destination"/> as a canonical big-endian, non-negative scalar.</summary>
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
