using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Commitments;

/// <summary>
/// Cross-instance mixing tests (the gnark CVE-2024-45039 pattern): a component
/// taken from one fully independent honest proof instance must not verify when
/// spliced into a second instance's statement. Where the existing suites swap
/// components <em>within one batch</em>, these characterize the binding across
/// two separately produced proofs — the case a missing randomizer-to-object
/// binding would let slip through.
/// </summary>
/// <remarks>
/// <para>
/// The Hyrax weighted opening binds a proof to its own row commitment through
/// the blinding-correction check and the inner-product argument's initial
/// commitment, so an opening of vector A cannot pass as an opening of the
/// committed vector B. The aggregated Bulletproofs verifier absorbs every value
/// commitment into the per-proof transcript before drawing the <c>y</c>,
/// <c>z</c>, and <c>x</c> challenges, so a proof computed against one set of
/// commitments does not verify against another. Both are pinned here directly
/// rather than left implicit in the composing protocol.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CrossInstanceMixingTests
{
    //Maps a coordinate index to its integer value when building a test vector.
    private delegate int VectorEntryDelegate(int index);

    private const string HyraxTranscriptDomain = "veridical.test.mixing.hyrax.v1";
    private const string RangeTranscriptDomain = "veridical.test.mixing.range.v1";
    private const string RangeKeySeed = "veridical.test.mixing.range.key.v1";
    private const int RangeBitWidth = 8;
    private const int RangeValueCount = 4;
    private const int HyraxVariableCount = 3;

    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;

    private static readonly G1HashToCurveDelegate HashToCurve = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();
    private static readonly G1AddDelegate G1Add = Bls12Curve381BigIntegerG1Reference.GetAdd();
    private static readonly G1ScalarMultiplyDelegate G1ScalarMul = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    private static readonly G1MultiScalarMultiplyDelegate G1Msm = TestG1Backends.Bls12Curve381Msm;
    private static readonly ScalarAddDelegate ScalarAdd = TestScalarBackends.Bls12Curve381.Add;
    private static readonly ScalarSubtractDelegate ScalarSubtract = TestScalarBackends.Bls12Curve381.Subtract;
    private static readonly ScalarMultiplyDelegate ScalarMul = TestScalarBackends.Bls12Curve381.Multiply;
    private static readonly ScalarInvertDelegate ScalarInvert = TestScalarBackends.Bls12Curve381.Invert;
    private static readonly ScalarReduceDelegate ScalarReduce = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static readonly FiatShamirHashDelegate Hash = FiatShamirBlake3Reference.GetHash();
    private static readonly FiatShamirSqueezeDelegate Squeeze = FiatShamirBlake3Reference.GetSqueeze();


    //Disposables opened during a test, released together in cleanup so the test
    //bodies stay free of nested using ladders (the accepted CA2000 pattern).
    private List<IDisposable> Disposables { get; } = [];


    [TestCleanup]
    public void DisposeRentals()
    {
        for(int i = Disposables.Count - 1; i >= 0; i--)
        {
            Disposables[i].Dispose();
        }

        Disposables.Clear();
    }


    [TestMethod]
    public void AWeightedOpeningOfAnotherCommitmentIsRejected()
    {
        int vectorLength = 1 << HyraxVariableCount;
        HyraxCommitmentKey key = Track(DeriveHyraxKey(vectorLength));

        //Two independent committed vectors under one key and one weight vector.
        MultilinearExtension vectorA = Track(BuildVector(i => (i * 13) + 7));
        MultilinearExtension vectorB = Track(BuildVector(i => (i * 29) + 11));
        MultilinearExtension weights = Track(BuildVector(i => (i * 5) + 3));

        HyraxWeightedOpening openingA = OpenWeighted(key, vectorA, weights, seed: 101);
        HyraxWeightedOpening openingB = OpenWeighted(key, vectorB, weights, seed: 202);

        //Instance A's opening, presented against instance B's commitment. The
        //row-commitment binding must reject it even though the weight vector and
        //the key match.
        FiatShamirTranscript verifierTx = Track(NewHyraxTranscript());
        bool ok = openingB.Commitment.VerifyWeightedSum(
            weights, openingA.ClaimedValue, openingA.Proof, key, verifierTx,
            Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert,
            G1Add, G1ScalarMul, G1Msm, BaseMemoryPool.Shared);

        Assert.IsFalse(ok, "An opening produced against one commitment must not verify against a different commitment.");
    }


    [TestMethod]
    public void AWeightedOpeningVerifiesAgainstItsOwnCommitment()
    {
        int vectorLength = 1 << HyraxVariableCount;
        HyraxCommitmentKey key = Track(DeriveHyraxKey(vectorLength));

        MultilinearExtension vectorA = Track(BuildVector(i => (i * 13) + 7));
        MultilinearExtension weights = Track(BuildVector(i => (i * 5) + 3));

        HyraxWeightedOpening openingA = OpenWeighted(key, vectorA, weights, seed: 303);

        //The honest same-instance opening is the control: the cross-instance
        //rejection above must not be an artifact of a broken round-trip.
        FiatShamirTranscript verifierTx = Track(NewHyraxTranscript());
        bool ok = openingA.Commitment.VerifyWeightedSum(
            weights, openingA.ClaimedValue, openingA.Proof, key, verifierTx,
            Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert,
            G1Add, G1ScalarMul, G1Msm, BaseMemoryPool.Shared);

        Assert.IsTrue(ok, "An opening must verify against the commitment it was produced for.");
    }


    [TestMethod]
    public void AnAggregatedRangeProofOfOtherCommitmentsIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        RangeProofKey key = Track(RangeProofKey.Derive(RangeBitWidth * RangeValueCount, RangeKeySeed, Curve, HashToCurve, pool));

        //Two independent aggregated instances, each over its own value block.
        AggregatedRangeInstance instanceA = ProveAggregatedRange(key, seed: 11, pool);
        AggregatedRangeInstance instanceB = ProveAggregatedRange(key, seed: 22, pool);

        //Instance A's proof, verified against instance B's value commitments. The
        //per-proof transcript absorbs the commitments before the challenges, so
        //A's responses do not satisfy B's derived relations.
        FiatShamirTranscript verifierTx = Track(NewRangeTranscript());
        bool ok = AggregatedBulletproofRangeVerifier.Verify(
            key, RangeBitWidth, RangeValueCount, instanceB.Commitments, instanceA.Proof, verifierTx,
            Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert, G1Add, G1ScalarMul, G1Msm, pool);

        Assert.IsFalse(ok, "An aggregated range proof must not verify against a different instance's value commitments.");
    }


    [TestMethod]
    public void AnAggregatedRangeProofVerifiesAgainstItsOwnCommitments()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        RangeProofKey key = Track(RangeProofKey.Derive(RangeBitWidth * RangeValueCount, RangeKeySeed, Curve, HashToCurve, pool));

        AggregatedRangeInstance instanceA = ProveAggregatedRange(key, seed: 33, pool);

        FiatShamirTranscript verifierTx = Track(NewRangeTranscript());
        bool ok = AggregatedBulletproofRangeVerifier.Verify(
            key, RangeBitWidth, RangeValueCount, instanceA.Commitments, instanceA.Proof, verifierTx,
            Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert, G1Add, G1ScalarMul, G1Msm, pool);

        Assert.IsTrue(ok, "An aggregated range proof must verify against the commitments it was produced for.");
    }


    private HyraxWeightedOpening OpenWeighted(HyraxCommitmentKey key, MultilinearExtension vector, MultilinearExtension weights, int seed)
    {
        ScalarRandomDelegate fixedRandom = MakeFixedRandom(seed);
        (HyraxCommitment commitment, HyraxOpeningWitness witness) = key.CommitVector(vector, fixedRandom, G1Msm, BaseMemoryPool.Shared);
        Track(commitment);
        Track(witness);

        FiatShamirTranscript proverTx = Track(NewHyraxTranscript());
        (HyraxOpeningProof proof, Scalar claimedValue) = commitment.OpenWeightedSum(
            witness, vector, weights, key, proverTx,
            Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert, fixedRandom,
            G1Add, G1ScalarMul, G1Msm, BaseMemoryPool.Shared);
        Track(proof);
        Track(claimedValue);

        return new HyraxWeightedOpening(commitment, proof, claimedValue);
    }


    private AggregatedRangeInstance ProveAggregatedRange(RangeProofKey key, int seed, BaseMemoryPool pool)
    {
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
        int commitmentBytes = RangeValueCount * g1Size;
        IMemoryOwner<byte> commitmentsOwner = Track(pool.Rent(commitmentBytes));
        Span<byte> commitments = commitmentsOwner.Memory.Span[..commitmentBytes];

        using IMemoryOwner<byte> blindingsOwner = pool.Rent(RangeValueCount * Scalar.SizeBytes);
        Span<byte> blindings = blindingsOwner.Memory.Span[..(RangeValueCount * Scalar.SizeBytes)];

        ulong[] values = new ulong[RangeValueCount];
        ScalarRandomDelegate blindingRandom = MakeFixedRandom(seed);
        for(int j = 0; j < RangeValueCount; j++)
        {
            values[j] = (ulong)(((seed * 31) + (j * 9973)) % 256);
            _ = blindingRandom(blindings.Slice(j * Scalar.SizeBytes, Scalar.SizeBytes), Curve, Tag.Empty);
        }

        FiatShamirTranscript proverTx = Track(NewRangeTranscript());
        RangeProof proof = AggregatedBulletproofRangeProver.Prove(
            key, RangeBitWidth, values, blindings, commitments, proverTx,
            Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert, MakeFixedRandom(seed + 1000),
            G1Add, G1ScalarMul, G1Msm, pool);
        Track(proof);

        return new AggregatedRangeInstance(proof, commitmentsOwner, commitmentBytes);
    }


    private T Track<T>(T disposable) where T : IDisposable
    {
        Disposables.Add(disposable);

        return disposable;
    }


    private static HyraxCommitmentKey DeriveHyraxKey(int vectorLength) =>
        HyraxCommitmentKey.Derive(vectorLength, WellKnownHyraxDomainLabels.CanonicalSeedV1, Curve, HashToCurve, BaseMemoryPool.Shared);


    private static FiatShamirTranscript NewHyraxTranscript() =>
        FiatShamirTranscript.Initialise(new FiatShamirDomainLabel(HyraxTranscriptDomain), ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);


    private static FiatShamirTranscript NewRangeTranscript() =>
        FiatShamirTranscript.Initialise(new FiatShamirDomainLabel(RangeTranscriptDomain), ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);


    private static MultilinearExtension BuildVector(VectorEntryDelegate valueAt)
    {
        int evaluationCount = 1 << HyraxVariableCount;
        int elementSize = Scalar.SizeBytes;
        using IMemoryOwner<byte> bufferOwner = BaseMemoryPool.Shared.Rent(evaluationCount * elementSize);
        Span<byte> buffer = bufferOwner.Memory.Span[..(evaluationCount * elementSize)];
        for(int i = 0; i < evaluationCount; i++)
        {
            WriteCanonical(new BigInteger(valueAt(i)), buffer.Slice(i * elementSize, elementSize));
        }

        return MultilinearExtension.FromEvaluations(buffer, HyraxVariableCount, Curve, BaseMemoryPool.Shared);
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
            ScalarReduce(wide, destination, curve);

            return inboundTag;
        }
    }


    //A produced Hyrax weighted opening bundled with the commitment it binds to.
    private readonly struct HyraxWeightedOpening(HyraxCommitment commitment, HyraxOpeningProof proof, Scalar claimedValue)
    {
        public HyraxCommitment Commitment { get; } = commitment;
        public HyraxOpeningProof Proof { get; } = proof;
        public Scalar ClaimedValue { get; } = claimedValue;
    }


    //A produced aggregated range proof bundled with its value-commitment buffer.
    private readonly struct AggregatedRangeInstance(RangeProof proof, IMemoryOwner<byte> commitmentsOwner, int commitmentBytes)
    {
        public RangeProof Proof { get; } = proof;
        public ReadOnlySpan<byte> Commitments => commitmentsOwner.Memory.Span[..commitmentBytes];
    }
}
