using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Tests.Commitments;

/// <summary>
/// Round-trip, boundary, and tamper tests for the Bulletproofs range proof
/// (<see cref="BulletproofRangeProver"/> / <see cref="BulletproofRangeVerifier"/>):
/// a committed value's range membership proven and verified without the value,
/// the prover's loud refusal of out-of-range input, wire-format rehydration,
/// and rejection of tampered sections and mismatched commitments.
/// </summary>
[TestClass]
internal sealed class BulletproofRangeProofTests
{
    private const string TranscriptDomain = "veridical.test.bulletproofs.range.v1";
    private const string KeySeed = "veridical.test.bulletproofs.range.key.v1";

    private static readonly G1HashToCurveDelegate HashToCurve = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();
    private static readonly G1AddDelegate G1Add = Bls12Curve381BigIntegerG1Reference.GetAdd();
    private static readonly G1ScalarMultiplyDelegate G1ScalarMul = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    private static readonly G1MultiScalarMultiplyDelegate G1Msm = TestG1Backends.Bls12Curve381Msm;
    private static readonly ScalarAddDelegate Add = TestScalarBackends.Bls12Curve381.Add;
    private static readonly ScalarSubtractDelegate Subtract = TestScalarBackends.Bls12Curve381.Subtract;
    private static readonly ScalarMultiplyDelegate Multiply = TestScalarBackends.Bls12Curve381.Multiply;
    private static readonly ScalarInvertDelegate Invert = TestScalarBackends.Bls12Curve381.Invert;
    private static readonly ScalarReduceDelegate Reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static readonly FiatShamirHashDelegate Hash = FiatShamirBlake3Reference.GetHash();
    private static readonly FiatShamirSqueezeDelegate Squeeze = FiatShamirBlake3Reference.GetSqueeze();

    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    [DataRow(8, 173UL)]
    [DataRow(16, 54321UL)]
    [DataRow(32, 3_000_000_017UL)]
    [DataRow(64, ulong.MaxValue / 3)]
    public void ProveVerifyRoundtrip(int bitWidth, ulong value)
    {
        ExerciseRoundtrip(bitWidth, value, expectVerified: true);
    }


    [TestMethod]
    [DataRow(8, 0UL)]
    [DataRow(8, 255UL)]
    [DataRow(64, 0UL)]
    [DataRow(64, ulong.MaxValue)]
    public void BoundaryValuesRoundtrip(int bitWidth, ulong value)
    {
        ExerciseRoundtrip(bitWidth, value, expectVerified: true);
    }


    [TestMethod]
    public void ProverRefusesOutOfRangeValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using RangeProofKey key = RangeProofKey.Derive(8, KeySeed, Curve, HashToCurve, pool);

        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
        using System.Buffers.IMemoryOwner<byte> blindingOwner = pool.Rent(Scalar.SizeBytes);
        using System.Buffers.IMemoryOwner<byte> commitmentOwner = pool.Rent(g1Size);
        MakeFixedRandom(seed: 99)(blindingOwner.Memory.Span[..Scalar.SizeBytes], Curve, Tag.Empty);

        using FiatShamirTranscript transcript = NewTranscript();
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
            BulletproofRangeProver.Prove(
                key, value: 256UL, blindingOwner.Memory.Span[..Scalar.SizeBytes],
                commitmentOwner.Memory.Span[..g1Size], transcript,
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, MakeFixedRandom(seed: 7),
                G1Add, G1ScalarMul, G1Msm, BaseMemoryPool.Shared));
    }


    [TestMethod]
    public void RehydratedProofVerifies()
    {
        const int BitWidth = 16;
        const ulong Value = 4242UL;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using RangeProofKey key = RangeProofKey.Derive(BitWidth, KeySeed, Curve, HashToCurve, pool);

        Span<byte> blinding = stackalloc byte[Scalar.SizeBytes];
        MakeFixedRandom(seed: 13)(blinding, Curve, Tag.Empty);
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
        Span<byte> commitment = stackalloc byte[g1Size];

        using FiatShamirTranscript proverTx = NewTranscript();
        using RangeProof proof = BulletproofRangeProver.Prove(
            key, Value, blinding, commitment, proverTx,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, MakeFixedRandom(seed: 17),
            G1Add, G1ScalarMul, G1Msm, pool);

        //Through the wire: serialize, rehydrate, verify.
        using RangeProof rehydrated = RangeProof.FromBytes(proof.AsReadOnlySpan(), BitWidth, Curve, pool);

        using FiatShamirTranscript verifierTx = NewTranscript();
        bool verified = BulletproofRangeVerifier.Verify(
            key, commitment, rehydrated, verifierTx,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
            G1Add, G1ScalarMul, G1Msm, pool);

        Assert.IsTrue(verified, "A rehydrated honest range proof must verify.");
    }


    [TestMethod]
    [DataRow(0)]    //Inside A.
    [DataRow(150)]  //Inside T1.
    [DataRow(200)]  //Inside τ_x.
    [DataRow(260)]  //Inside t̂.
    public void TamperedProofIsRejected(int byteOffset)
    {
        const int BitWidth = 16;
        const ulong Value = 31337UL;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using RangeProofKey key = RangeProofKey.Derive(BitWidth, KeySeed, Curve, HashToCurve, pool);

        Span<byte> blinding = stackalloc byte[Scalar.SizeBytes];
        MakeFixedRandom(seed: 19)(blinding, Curve, Tag.Empty);
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
        Span<byte> commitment = stackalloc byte[g1Size];

        using FiatShamirTranscript proverTx = NewTranscript();
        using RangeProof proof = BulletproofRangeProver.Prove(
            key, Value, blinding, commitment, proverTx,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, MakeFixedRandom(seed: 23),
            G1Add, G1ScalarMul, G1Msm, pool);

        MemoryMarshal.AsMemory(proof.AsReadOnlyMemory()).Span[byteOffset] ^= 0x01;

        using FiatShamirTranscript verifierTx = NewTranscript();
        bool verified = BulletproofRangeVerifier.Verify(
            key, commitment, proof, verifierTx,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
            G1Add, G1ScalarMul, G1Msm, pool);

        Assert.IsFalse(verified, $"A range proof with a flipped byte at offset {byteOffset} must be rejected.");
    }


    [TestMethod]
    public void ProofForOneCommitmentDoesNotVerifyAgainstAnother()
    {
        const int BitWidth = 16;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using RangeProofKey key = RangeProofKey.Derive(BitWidth, KeySeed, Curve, HashToCurve, pool);

        Span<byte> blinding = stackalloc byte[Scalar.SizeBytes];
        MakeFixedRandom(seed: 29)(blinding, Curve, Tag.Empty);
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
        Span<byte> commitment = stackalloc byte[g1Size];
        Span<byte> otherCommitment = stackalloc byte[g1Size];

        using FiatShamirTranscript proverTx = NewTranscript();
        using RangeProof proof = BulletproofRangeProver.Prove(
            key, value: 777UL, blinding, commitment, proverTx,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, MakeFixedRandom(seed: 31),
            G1Add, G1ScalarMul, G1Msm, pool);

        //A commitment to a different value under the same blinding.
        key.CommitValue(778UL, blinding, otherCommitment, G1Msm, pool);

        using FiatShamirTranscript verifierTx = NewTranscript();
        bool verified = BulletproofRangeVerifier.Verify(
            key, otherCommitment, proof, verifierTx,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
            G1Add, G1ScalarMul, G1Msm, pool);

        Assert.IsFalse(verified, "A range proof must be bound to its own value commitment.");
    }


    [TestMethod]
    public void TwoProofsOfTheSameStatementDiffer()
    {
        const int BitWidth = 8;
        const ulong Value = 99UL;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using RangeProofKey key = RangeProofKey.Derive(BitWidth, KeySeed, Curve, HashToCurve, pool);

        Span<byte> blinding = stackalloc byte[Scalar.SizeBytes];
        MakeFixedRandom(seed: 37)(blinding, Curve, Tag.Empty);
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
        Span<byte> firstCommitment = stackalloc byte[g1Size];
        Span<byte> secondCommitment = stackalloc byte[g1Size];

        using FiatShamirTranscript firstTx = NewTranscript();
        using RangeProof first = BulletproofRangeProver.Prove(
            key, Value, blinding, firstCommitment, firstTx,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, MakeFixedRandom(seed: 41),
            G1Add, G1ScalarMul, G1Msm, pool);

        using FiatShamirTranscript secondTx = NewTranscript();
        using RangeProof second = BulletproofRangeProver.Prove(
            key, Value, blinding, secondCommitment, secondTx,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, MakeFixedRandom(seed: 43),
            G1Add, G1ScalarMul, G1Msm, pool);

        Assert.IsTrue(firstCommitment.SequenceEqual(secondCommitment), "The same (value, blinding) pair must commit identically.");
        Assert.IsFalse(
            first.AsReadOnlySpan().SequenceEqual(second.AsReadOnlySpan()),
            "Two proofs of the same statement must differ (fresh α, ρ, s-vectors, τ₁, τ₂).");
    }


    private static void ExerciseRoundtrip(int bitWidth, ulong value, bool expectVerified)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using RangeProofKey key = RangeProofKey.Derive(bitWidth, KeySeed, Curve, HashToCurve, pool);

        Span<byte> blinding = stackalloc byte[Scalar.SizeBytes];
        MakeFixedRandom(seed: (int)(value % 1000) + bitWidth)(blinding, Curve, Tag.Empty);
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
        Span<byte> commitment = stackalloc byte[g1Size];

        using FiatShamirTranscript proverTx = NewTranscript();
        using RangeProof proof = BulletproofRangeProver.Prove(
            key, value, blinding, commitment, proverTx,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, MakeFixedRandom(seed: bitWidth * 7),
            G1Add, G1ScalarMul, G1Msm, pool);

        using FiatShamirTranscript verifierTx = NewTranscript();
        bool verified = BulletproofRangeVerifier.Verify(
            key, commitment, proof, verifierTx,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
            G1Add, G1ScalarMul, G1Msm, pool);

        Assert.AreEqual(expectVerified, verified, $"Range proof round-trip for n = {bitWidth}, v = {value}.");
    }


    private static FiatShamirTranscript NewTranscript() =>
        FiatShamirTranscript.Initialise(new FiatShamirDomainLabel(TranscriptDomain), ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);


    private static ScalarRandomDelegate MakeFixedRandom(int seed)
    {
        int counter = 0;
        return Sample;

        Tag Sample(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
        {
            Span<byte> hashInput = stackalloc byte[8];
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(hashInput[..4], seed);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(hashInput[4..], counter);
            counter++;

            Span<byte> wide = stackalloc byte[32];
            SHA256.HashData(hashInput, wide);
            Reduce(wide, destination, curve);
            return inboundTag;
        }
    }
}
