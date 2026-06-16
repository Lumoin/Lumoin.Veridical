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

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// ZK.3 — end-to-end round-trip tests for masked Spartan2 over the genuinely
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
/// the query count) is the statistical claim validated in ZK.4; these tests gate
/// correctness and binding. Real BLS12-381 arithmetic and production BLAKE3.
/// </remarks>
[TestClass]
internal sealed class ZkBaseFoldMaskedSpartanRoundtripTests
{
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;
    private static ScalarHashToScalarDelegate HashToScalar { get; } = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;
    private const int TestQueryCount = 8;
    //The provider enforces the hiding budget per committed polynomial, and the
    //smallest one this instance routes through it has d = 1 (the one-variable
    //outer-rounds side of x·y = 15), which at TestQueryCount = 8 needs t = 6
    //(GetMinimumExtraVariableCount).
    private const int ExtraVariableCount = 6;
    private const string TranscriptDomain = "veridical.spartan2.basefold.zkmasked.test.v1";

    private static readonly byte[] CodeSeed = Encoding.UTF8.GetBytes("veridical.spartan2.basefold.zkmasked.code.v1");
    private static readonly byte[] SpartanRandomSeed = Encoding.UTF8.GetBytes("veridical.spartan2.basefold.zkmasked.rng.v1");
    private static readonly byte[] ProviderRandomSeed = Encoding.UTF8.GetBytes("veridical.spartan2.basefold.zkmasked.provider.rng.v1");

    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    public void XyEquals15RoundTripsThroughFullZeroKnowledgeBaseFold()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using ZkBaseFoldMaskedSpartanProof proof = Prove(pool);

        Assert.IsTrue(Verify(proof, pool), "An honest full-ZK masked BaseFold-backed Spartan proof must verify.");
    }


    [TestMethod]
    public void TamperedWitnessOpeningIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using ZkBaseFoldMaskedSpartanProof proof = Prove(pool);

        //The witness opening is the final section; flip its last byte.
        proof.AsSpan()[^1] ^= 0x01;

        Assert.IsFalse(Verify(proof, pool), "A tampered witness-opening section must be rejected.");
    }


    [TestMethod]
    public void TamperedSumcheckMiddleIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using ZkBaseFoldMaskedSpartanProof proof = Prove(pool);

        //The sumcheck middle starts after three 32-byte roots and the two
        //mask-sum scalars; flip the first byte of the first outer round.
        proof.AsSpan()[(3 * DigestSizeBytes) + (2 * 32)] ^= 0x01;

        Assert.IsFalse(Verify(proof, pool), "A tampered sumcheck-middle byte must be rejected.");
    }


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


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership transfers through using declarations; the returned proof transfers to the caller.")]
    private static ZkBaseFoldMaskedSpartanProof Prove(BaseMemoryPool pool, ScalarArithmeticBackend? batch = null, MleFoldDelegate? mleFold = null)
    {
        using RawR1csInstance instance = BuildInstance();
        using RawR1csWitness witness = BuildWitness();

        var provingKey = new SpartanProvingKey(BuildProvider(batch));
        using var prover = new MaskedSpartanProver(provingKey);
        using FiatShamirTranscript transcript = FreshTranscript();

        ScalarRandomDelegate random = new DeterministicScalarRandom(SpartanRandomSeed).AsDelegate();

        using PolynomialCommitmentProvider errorProvider = BuildErrorProvider(batch);

        return prover.ProveZkBaseFold(
            instance, witness, transcript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, mleFold ?? MleFold, errorProvider, pool, batch);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership transfers through using declarations.")]
    private static bool Verify(ZkBaseFoldMaskedSpartanProof proof, BaseMemoryPool pool)
    {
        var verifyingKey = new SpartanVerifyingKey(BuildProvider());
        using var verifier = new MaskedSpartanVerifier(verifyingKey);
        using RawR1csInstance instance = BuildInstance();
        using FiatShamirTranscript transcript = FreshTranscript();
        using PolynomialCommitmentProvider errorProvider = BuildErrorProvider();

        return verifier.VerifyZkBaseFold(
            proof, instance, transcript,
            Add, Multiply, Subtract, Invert, Reduce, Hash, Squeeze, errorProvider, pool);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The BaseFold provider holds no disposable key; the Spartan key that consumes it disposes it.")]
    private static PolynomialCommitmentProvider BuildProvider(ScalarArithmeticBackend? batch = null)
    {
        ScalarRandomDelegate providerRandom = new DeterministicScalarRandom(ProviderRandomSeed).AsDelegate();

        return ZkBaseFoldPolynomialCommitmentScheme.CreateFullZeroKnowledge(
            CodeSeed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
            providerRandom, HashToScalar, ExtraVariableCount, DigestSizeBytes, batch);
    }


    //The plain (deterministic) BaseFold provider for the public zero-error vector,
    //over the same code parameters as the full-ZK provider so prover and verifier
    //recompute the identical error commitment.
    [SuppressMessage("Reliability", "CA2000", Justification = "The provider holds no disposable key; the caller disposes it via a using declaration.")]
    private static PolynomialCommitmentProvider BuildErrorProvider(ScalarArithmeticBackend? batch = null)
    {
        return BaseFoldPolynomialCommitmentScheme.Create(
            CodeSeed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, HashToScalar, DigestSizeBytes, batch);
    }


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


    private static RawR1csWitness BuildWitness()
    {
        int scalarSize = Scalar.SizeBytes;
        byte[] witnessBytes = new byte[2 * scalarSize];
        WriteCanonical(new BigInteger(3), witnessBytes.AsSpan(0 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(5), witnessBytes.AsSpan(1 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witnessBytes, Curve, BaseMemoryPool.Shared);
    }


    private static FiatShamirTranscript FreshTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(TranscriptDomain),
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
