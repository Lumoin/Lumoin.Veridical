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
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Text;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// End-to-end round-trip tests for masked Spartan2 over the genuinely
/// zero-knowledge BaseFold provider
/// (<see cref="ZkBaseFoldPolynomialCommitmentScheme.CreateFullZeroKnowledge"/>):
/// the masked prover assembles a <see cref="ZkBaseFoldMaskedSpartanProof"/> over
/// <c>x · y = 15</c> through <c>ProveZkBaseFold</c>, and the masked verifier
/// accepts it through <c>VerifyZkBaseFold</c>. Tampering a witness-opening byte or
/// a sumcheck-middle byte is rejected.
/// </summary>
/// <remarks>
/// Unlike the sound-but-not-hiding <see cref="BaseFoldMaskedSpartanProof"/> path,
/// the full-ZK provider makes every opening hiding and simulatable, so this is
/// the configuration in which masked-Spartan-over-BaseFold delivers the witness
/// privacy the "masked" name implies. The hiding budget itself (the lift size vs
/// the query count) is a separately validated statistical claim; these tests gate
/// correctness and binding. Real BLS12-381 arithmetic and production BLAKE3.
/// </remarks>
[TestClass]
internal sealed class ZkBaseFoldMaskedSpartanRoundtripTests
{
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
    /// <summary>The multilinear-extension folding delegate the masked-Spartan prover uses to build its sumcheck rounds, unless a test overrides it with a batched implementation.</summary>
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();
    /// <summary>The two-to-one Merkle compression function, delegated to <see cref="HashTwoToOne"/>.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    /// <summary>The byte width of a BLAKE3 digest, as used by the Merkle and BaseFold commitments in these tests.</summary>
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;
    /// <summary>The number of BaseFold query repetitions these fixtures use.</summary>
    private const int TestQueryCount = 8;
    /// <summary>The number of extra masking variables the commitment providers pad with. The provider enforces the hiding budget per committed polynomial, and the smallest one this instance routes through it has degree 1 (the one-variable outer-rounds side of <c>x·y = 15</c>), which at <see cref="TestQueryCount"/> = 8 needs 6 extra variables (see <c>GetMinimumExtraVariableCount</c>).</summary>
    private const int ExtraVariableCount = 6;
    /// <summary>The Fiat–Shamir domain-separation label for every transcript this test class creates.</summary>
    private const string TranscriptDomain = "veridical.spartan2.basefold.zkmasked.test.v1";

    /// <summary>The BaseFold code seed shared by the full-ZK and error commitment providers, so the prover and verifier derive identical codes.</summary>
    private static byte[] CodeSeed { get; } = Encoding.UTF8.GetBytes("veridical.spartan2.basefold.zkmasked.code.v1");
    /// <summary>The seed for the masked-Spartan prover's own masking randomness.</summary>
    private static byte[] SpartanRandomSeed { get; } = Encoding.UTF8.GetBytes("veridical.spartan2.basefold.zkmasked.rng.v1");
    /// <summary>The seed for the full-ZK commitment provider's internal randomness.</summary>
    private static byte[] ProviderRandomSeed { get; } = Encoding.UTF8.GetBytes("veridical.spartan2.basefold.zkmasked.provider.rng.v1");

    /// <summary>The BLS12-381 curve parameters used throughout these tests.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    /// <summary>Verifies that an honest full-ZK masked BaseFold-backed Spartan proof of <c>x · y = 15</c> verifies.</summary>
    [TestMethod]
    public void XyEquals15RoundTripsThroughFullZeroKnowledgeBaseFold()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using ZkBaseFoldMaskedSpartanProof proof = Prove(pool);

        Assert.IsTrue(Verify(proof, pool), "An honest full-ZK masked BaseFold-backed Spartan proof must verify.");
    }


    /// <summary>Verifies that flipping the last byte of the proof — inside the witness-opening section — causes verification to fail.</summary>
    [TestMethod]
    public void TamperedWitnessOpeningIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using ZkBaseFoldMaskedSpartanProof proof = Prove(pool);

        //The witness opening is the final section; flip its last byte.
        MemoryMarshal.AsMemory(proof.AsReadOnlyMemory()).Span[^1] ^= 0x01;

        Assert.IsFalse(Verify(proof, pool), "A tampered witness-opening section must be rejected.");
    }


    /// <summary>Verifies that flipping the first byte of the first outer sumcheck round causes verification to fail.</summary>
    [TestMethod]
    public void TamperedSumcheckMiddleIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using ZkBaseFoldMaskedSpartanProof proof = Prove(pool);

        //The sumcheck middle starts after three 32-byte roots and the two
        //mask-sum scalars; flip the first byte of the first outer round.
        MemoryMarshal.AsMemory(proof.AsReadOnlyMemory()).Span[(3 * DigestSizeBytes) + (2 * 32)] ^= 0x01;

        Assert.IsFalse(Verify(proof, pool), "A tampered sumcheck-middle byte must be rejected.");
    }


    /// <summary>Verifies that the full-ZK proof (lifted, masked openings) is strictly larger than the sound-but-not-hiding BaseFold masked proof of the same <c>x·y=15</c> instance (rows = 2, one row variable; columns = 4, two column variables).</summary>
    [TestMethod]
    public void FullZeroKnowledgeProofIsLargerThanTheSoundOnlyProof()
    {
        //The full-ZK openings (lift + mask) make the proof strictly larger than
        //the sound-but-not-hiding BaseFold masked proof of the same instance.
        //x·y=15 has rows = 2 (1 row variable) and columns = 4 (2 column variables).
        const int OuterRoundCount = 1;
        const int InnerRoundCount = 2;

        int soundOnly = BaseFoldMaskedSpartanProof.GetBufferSizeBytes(
            OuterRoundCount, InnerRoundCount, TestQueryCount, DigestSizeBytes, Curve);
        int fullZk = ZkBaseFoldMaskedSpartanProof.GetBufferSizeBytes(
            OuterRoundCount, InnerRoundCount, TestQueryCount, DigestSizeBytes, ExtraVariableCount, Curve);

        Assert.IsGreaterThan(soundOnly, fullZk, "The full-ZK masked proof must be larger than the sound-only one (lifted, masked openings).");
    }


    /// <summary>Verifies that proving with the batched multiply/fold seam (the Spartan sumcheck, the provider-internal BaseFold paths, and the managed batched MLE fold) produces a byte-identical proof to the per-element path, since the batch delegate swaps only the multiplication strategy, never the algebra.</summary>
    [TestMethod]
    public void BatchMultiplyPathProducesTheByteIdenticalProof()
    {
        //The batch-multiply seam threaded end to end — the Spartan sumcheck
        //AND the provider-internal BaseFold encode/fold/round-poly paths (the
        //providers are built with the batch delegate too) plus the managed
        //batched MLE fold: with identical deterministic randomness, the
        //batched prove must emit the same proof bytes as the per-element
        //prove — the seams swap the multiplication strategy, never the
        //algebra.
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using ZkBaseFoldMaskedSpartanProof scalarProof = Prove(pool);
        ScalarArithmeticBackend backend = TestScalarBackends.Bls12Curve381;
        MleFoldDelegate batchedFold = ManagedMultilinearExtensionBackend.CreateFold(backend, pool);
        using ZkBaseFoldMaskedSpartanProof batchedProof = Prove(pool, backend, batchedFold);

        Assert.IsTrue(
            scalarProof.AsReadOnlySpan().SequenceEqual(batchedProof.AsReadOnlySpan()),
            "The batched prove must be byte-identical to the per-element prove.");
    }


    /// <summary>Produces the test proof and releases provider storage through the owning prover.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The provider's pooled storage transfers to the proving key and the key to the prover, which the using declaration releases; the key and prover constructors cannot fail for a non-null argument, so no path leaves the provider unreleased.")]
    private static ZkBaseFoldMaskedSpartanProof Prove(BaseMemoryPool pool, ScalarArithmeticBackend? batch = null, MleFoldDelegate? mleFold = null)
    {
        using RawR1csInstance instance = BuildInstance();
        using RawR1csWitness witness = BuildWitness();

        var provingKey = new SpartanProvingKey(BuildProvider(pool, batch));
        using var prover = new MaskedSpartanProver(provingKey);
        using FiatShamirTranscript transcript = FreshTranscript();

        ScalarRandomDelegate random = new DeterministicScalarRandom(SpartanRandomSeed).AsDelegate();

        using PolynomialCommitmentProvider errorProvider = BuildErrorProvider(pool, batch);

        return prover.ProveZkBaseFold(
            instance, witness, transcript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, mleFold ?? MleFold, errorProvider, pool, batch);
    }


    /// <summary>Verifies the test proof and releases provider storage through the owning verifier.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The provider's pooled storage transfers to the verifying key and the key to the verifier, which the using declaration releases; the key and verifier constructors cannot fail for a non-null argument, so no path leaves the provider unreleased.")]
    private static bool Verify(ZkBaseFoldMaskedSpartanProof proof, BaseMemoryPool pool)
    {
        var verifyingKey = new SpartanVerifyingKey(BuildProvider(pool));
        using var verifier = new MaskedSpartanVerifier(verifyingKey);
        using RawR1csInstance instance = BuildInstance();
        using FiatShamirTranscript transcript = FreshTranscript();
        using PolynomialCommitmentProvider errorProvider = BuildErrorProvider(pool);

        return verifier.VerifyZkBaseFold(
            proof, instance, transcript,
            Add, Multiply, Subtract, Invert, Reduce, Hash, Squeeze, errorProvider, pool);
    }


    /// <summary>Builds the commitment provider using the caller's pool.</summary>
    /// <param name="pool">The pool supplied by the test.</param>
    /// <param name="batch">The optional batched scalar backend.</param>
    private static PolynomialCommitmentProvider BuildProvider(BaseMemoryPool pool, ScalarArithmeticBackend? batch = null)
    {
        ScalarRandomDelegate providerRandom = new DeterministicScalarRandom(ProviderRandomSeed).AsDelegate();

        return ZkBaseFoldPolynomialCommitmentScheme.CreateFullZeroKnowledge(
            CodeSeed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
            providerRandom, HashToScalar, ExtraVariableCount, pool, DigestSizeBytes, batch);
    }


    /// <summary>Builds the commitment provider using the caller's pool.</summary>
    /// <remarks>
    /// The plain (deterministic) BaseFold provider for the public zero-error
    /// vector, over the same code parameters as the full-ZK provider so prover
    /// and verifier recompute the identical error commitment.
    /// </remarks>
    /// <param name="pool">The pool supplied by the test.</param>
    /// <param name="batch">The optional batched scalar backend.</param>
    private static PolynomialCommitmentProvider BuildErrorProvider(BaseMemoryPool pool, ScalarArithmeticBackend? batch = null)
    {
        return BaseFoldPolynomialCommitmentScheme.Create(
            CodeSeed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, HashToScalar, pool, DigestSizeBytes, batch);
    }


    /// <summary>Builds the two-constraint R1CS instance for <c>x·y = 15</c> over <c>z = (1, 15, x, y)</c>.</summary>
    private static RawR1csInstance BuildInstance()
    {
        int scalarSize = Scalar.SizeBytes;
        int[] aRows = [0, 1];
        int[] aCols = [2, 0];
        int[] bRows = [0, 1];
        int[] bCols = [3, 0];
        int[] cRows = [0, 1];
        int[] cCols = [1, 0];

        byte[] ones = new byte[2 * scalarSize];
        WriteCanonical(BigInteger.One, ones.AsSpan(0, scalarSize));
        WriteCanonical(BigInteger.One, ones.AsSpan(scalarSize, scalarSize));

        R1csMatrix a = R1csMatrix.FromSortedTriples(aRows, aCols, ones, 2, 4, Curve, BaseMemoryPool.Shared);
        R1csMatrix b = R1csMatrix.FromSortedTriples(bRows, bCols, ones, 2, 4, Curve, BaseMemoryPool.Shared);
        R1csMatrix c = R1csMatrix.FromSortedTriples(cRows, cCols, ones, 2, 4, Curve, BaseMemoryPool.Shared);

        byte[] publicInput = new byte[scalarSize];
        WriteCanonical(new BigInteger(15), publicInput);

        return RawR1csInstance.Create(a, b, c, publicInput, BaseMemoryPool.Shared);
    }


    /// <summary>Builds the witness <c>(x, y) = (3, 5)</c> that satisfies <see cref="BuildInstance"/>'s constraints.</summary>
    private static RawR1csWitness BuildWitness()
    {
        int scalarSize = Scalar.SizeBytes;
        byte[] witnessBytes = new byte[2 * scalarSize];
        WriteCanonical(new BigInteger(3), witnessBytes.AsSpan(0 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(5), witnessBytes.AsSpan(1 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witnessBytes, Curve, BaseMemoryPool.Shared);
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
