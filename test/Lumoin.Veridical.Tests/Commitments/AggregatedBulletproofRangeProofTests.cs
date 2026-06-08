using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Commitments;

/// <summary>
/// Round-trip, boundary, shape, and tamper tests for the aggregated
/// Bulletproofs range proof
/// (<see cref="AggregatedBulletproofRangeProver"/> /
/// <see cref="AggregatedBulletproofRangeVerifier"/>): <c>m</c> committed
/// values' range membership in one logarithmic argument, the per-value
/// out-of-range refusal, wire rehydration through the shared
/// <see cref="RangeProof"/> container, rejection of tampered sections and of
/// commitments swapped between slots (the per-value <c>z</c> powers make
/// slot order binding).
/// </summary>
[TestClass]
internal sealed class AggregatedBulletproofRangeProofTests
{
    private const string TranscriptDomain = "veridical.test.bulletproofs.range.aggregated.v1";
    private const string KeySeed = "veridical.test.bulletproofs.range.aggregated.key.v1";

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
    [DataRow(8, new ulong[] { 173UL, 254UL })]
    [DataRow(8, new ulong[] { 0UL, 255UL, 17UL, 200UL })]
    [DataRow(16, new ulong[] { 54321UL, 0UL })]
    [DataRow(32, new ulong[] { 3_000_000_017UL, 1UL, 4_294_967_295UL, 12UL })]
    public void AggregatedProveVerifyRoundtrip(int bitWidth, ulong[] values)
    {
        ExerciseRoundtrip(bitWidth, values, expectVerified: true);
    }


    [TestMethod]
    public void ProverRefusesAnOutOfRangeValue()
    {
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        using RangeProofKey key = RangeProofKey.Derive(16, KeySeed, Curve, HashToCurve, pool);

        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
        using IMemoryOwner<byte> blindingsOwner = pool.Rent(2 * Scalar.SizeBytes);
        using IMemoryOwner<byte> commitmentsOwner = pool.Rent(2 * g1Size);
        MakeFixedRandom(seed: 99)(blindingsOwner.Memory.Span[..Scalar.SizeBytes], Curve, Tag.Empty);
        MakeFixedRandom(seed: 98)(blindingsOwner.Memory.Span.Slice(Scalar.SizeBytes, Scalar.SizeBytes), Curve, Tag.Empty);

        using FiatShamirTranscript transcript = NewTranscript();
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
            AggregatedBulletproofRangeProver.Prove(
                key, bitWidth: 8, [12UL, 256UL], blindingsOwner.Memory.Span[..(2 * Scalar.SizeBytes)],
                commitmentsOwner.Memory.Span[..(2 * g1Size)], transcript,
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, MakeFixedRandom(seed: 7),
                G1Add, G1ScalarMul, G1Msm, SensitiveMemoryPool<byte>.Shared));
    }


    [TestMethod]
    public void ProverRefusesAMismatchedKeyShape()
    {
        //The key's vector length must equal bitWidth · valueCount.
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        using RangeProofKey key = RangeProofKey.Derive(16, KeySeed, Curve, HashToCurve, pool);

        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
        using IMemoryOwner<byte> blindingsOwner = pool.Rent(2 * Scalar.SizeBytes);
        using IMemoryOwner<byte> commitmentsOwner = pool.Rent(2 * g1Size);

        using FiatShamirTranscript transcript = NewTranscript();
        Assert.ThrowsExactly<ArgumentException>(() =>
            AggregatedBulletproofRangeProver.Prove(
                key, bitWidth: 16, [12UL, 13UL], blindingsOwner.Memory.Span[..(2 * Scalar.SizeBytes)],
                commitmentsOwner.Memory.Span[..(2 * g1Size)], transcript,
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, MakeFixedRandom(seed: 7),
                G1Add, G1ScalarMul, G1Msm, SensitiveMemoryPool<byte>.Shared));
    }


    [TestMethod]
    public void TamperedProofIsRejected()
    {
        const int BitWidth = 8;
        ulong[] values = [99UL, 161UL];
(RangeProof proof, IMemoryOwner<byte> commitmentsOwner, int commitmentBytes, RangeProofKey key) = Prove(BitWidth, values, out SensitiveMemoryPool<byte> pool);
        using IMemoryOwner<byte> ownedCommitments = commitmentsOwner;
        ReadOnlySpan<byte> commitments = commitmentsOwner.Memory.Span[..commitmentBytes];
        using(key)
        {
            using(proof)
            {
                //Flip a byte in the IPA tail.
                proof.AsSpan()[^1] ^= 0x01;

                using FiatShamirTranscript verifyTx = NewTranscript();
                Assert.IsFalse(
                    AggregatedBulletproofRangeVerifier.Verify(
                        key, BitWidth, values.Length, commitments, proof, verifyTx,
                        Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, G1Add, G1ScalarMul, G1Msm, pool),
                    "A tampered aggregated proof must be rejected.");
            }
        }
    }


    [TestMethod]
    public void SwappedCommitmentSlotsAreRejected()
    {
        //The per-value z powers bind each commitment to its slot: swapping
        //two commitments must break verification even though the set is the
        //same.
        const int BitWidth = 8;
        ulong[] values = [99UL, 161UL];
(RangeProof proof, IMemoryOwner<byte> commitmentsOwner, int commitmentBytes, RangeProofKey key) = Prove(BitWidth, values, out SensitiveMemoryPool<byte> pool);
        using IMemoryOwner<byte> ownedCommitments = commitmentsOwner;
        ReadOnlySpan<byte> commitments = commitmentsOwner.Memory.Span[..commitmentBytes];
        using(key)
        {
            using(proof)
            {
                int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
                using IMemoryOwner<byte> swappedOwner = pool.Rent(commitmentBytes);
                Span<byte> swapped = swappedOwner.Memory.Span[..commitmentBytes];
                commitments.CopyTo(swapped);
                commitments.Slice(g1Size, g1Size).CopyTo(swapped[..g1Size]);
                commitments[..g1Size].CopyTo(swapped.Slice(g1Size, g1Size));

                using FiatShamirTranscript verifyTx = NewTranscript();
                Assert.IsFalse(
                    AggregatedBulletproofRangeVerifier.Verify(
                        key, BitWidth, values.Length, swapped, proof, verifyTx,
                        Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, G1Add, G1ScalarMul, G1Msm, pool),
                    "Swapped commitment slots must be rejected.");
            }
        }
    }


    [TestMethod]
    public void RehydratedAggregatedProofVerifies()
    {
        const int BitWidth = 8;
        ulong[] values = [4UL, 250UL];
(RangeProof proof, IMemoryOwner<byte> commitmentsOwner, int commitmentBytes, RangeProofKey key) = Prove(BitWidth, values, out SensitiveMemoryPool<byte> pool);
        using IMemoryOwner<byte> ownedCommitments = commitmentsOwner;
        ReadOnlySpan<byte> commitments = commitmentsOwner.Memory.Span[..commitmentBytes];
        using(key)
        {
            int total = BitWidth * values.Length;
            using RangeProof rehydrated = RangeProof.FromBytes(proof.AsReadOnlySpan(), total, Curve, pool);
            proof.Dispose();

            using FiatShamirTranscript verifyTx = NewTranscript();
            Assert.IsTrue(
                AggregatedBulletproofRangeVerifier.Verify(
                    key, BitWidth, values.Length, commitments, rehydrated, verifyTx,
                    Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, G1Add, G1ScalarMul, G1Msm, pool),
                "A wire-rehydrated aggregated proof must verify.");
        }
    }


    private static void ExerciseRoundtrip(int bitWidth, ulong[] values, bool expectVerified)
    {
(RangeProof proof, IMemoryOwner<byte> commitmentsOwner, int commitmentBytes, RangeProofKey key) = Prove(bitWidth, values, out SensitiveMemoryPool<byte> pool);
        using IMemoryOwner<byte> ownedCommitments = commitmentsOwner;
        ReadOnlySpan<byte> commitments = commitmentsOwner.Memory.Span[..commitmentBytes];
        using(key)
        {
            using(proof)
            {
                using FiatShamirTranscript verifyTx = NewTranscript();
                Assert.AreEqual(
                    expectVerified,
                    AggregatedBulletproofRangeVerifier.Verify(
                        key, bitWidth, values.Length, commitments, proof, verifyTx,
                        Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, G1Add, G1ScalarMul, G1Msm, pool),
                    $"Aggregated roundtrip at bitWidth = {bitWidth}, m = {values.Length}.");
            }
        }
    }


    private static (RangeProof Proof, IMemoryOwner<byte> Commitments, int CommitmentBytes, RangeProofKey Key) Prove(int bitWidth, ulong[] values, out SensitiveMemoryPool<byte> pool)
    {
        pool = SensitiveMemoryPool<byte>.Shared;
        int m = values.Length;
        RangeProofKey key = RangeProofKey.Derive(bitWidth * m, KeySeed, Curve, HashToCurve, pool);

        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
        IMemoryOwner<byte> commitmentsOwner = pool.Rent(m * g1Size);
        Span<byte> commitments = commitmentsOwner.Memory.Span[..(m * g1Size)];
        using IMemoryOwner<byte> blindingsOwner = pool.Rent(m * Scalar.SizeBytes);
        Span<byte> blindings = blindingsOwner.Memory.Span[..(m * Scalar.SizeBytes)];
        ScalarRandomDelegate blindingRandom = MakeFixedRandom(seed: 211);
        for(int j = 0; j < m; j++)
        {
            _ = blindingRandom(blindings.Slice(j * Scalar.SizeBytes, Scalar.SizeBytes), Curve, Tag.Empty);
        }

        using FiatShamirTranscript proverTx = NewTranscript();
        RangeProof proof = AggregatedBulletproofRangeProver.Prove(
            key, bitWidth, values, blindings, commitments, proverTx,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, MakeFixedRandom(seed: 223),
            G1Add, G1ScalarMul, G1Msm, pool);

        return (proof, commitmentsOwner, m * g1Size, key);
    }


    private static FiatShamirTranscript NewTranscript() =>
        FiatShamirTranscript.Initialise(new FiatShamirDomainLabel(TranscriptDomain), ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, SensitiveMemoryPool<byte>.Shared);


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

            return Tag.Empty;
        }
    }
}
