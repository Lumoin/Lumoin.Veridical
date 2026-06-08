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
/// Round-trip and tamper tests for the two-secret-vector Bulletproofs
/// inner-product argument (<see cref="TwoVectorInnerProductArgument"/>) — the
/// primitive the range gadget reduces to. The commitment
/// <c>P = ⟨a, G⟩ + ⟨b, H⟩</c> is constructed directly from independent
/// generator families, so the tests pin the argument itself rather than any
/// consumer's reduction.
/// </summary>
[TestClass]
internal sealed class TwoVectorInnerProductArgumentTests
{
    private const string TranscriptDomain = "veridical.test.two-vector-ipa.v1";
    private const string RoundLabelPrefix = "test.two-vector-ipa.round";

    private static readonly G1HashToCurveDelegate HashToCurve = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();
    private static readonly G1AddDelegate G1Add = Bls12Curve381BigIntegerG1Reference.GetAdd();
    private static readonly G1ScalarMultiplyDelegate G1ScalarMul = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    private static readonly G1MultiScalarMultiplyDelegate G1Msm = TestG1Backends.Bls12Curve381Msm;
    private static readonly ScalarAddDelegate ScalarAdd = TestScalarBackends.Bls12Curve381.Add;
    private static readonly ScalarMultiplyDelegate ScalarMul = TestScalarBackends.Bls12Curve381.Multiply;
    private static readonly ScalarInvertDelegate ScalarInvert = TestScalarBackends.Bls12Curve381.Invert;
    private static readonly ScalarReduceDelegate ScalarReduce = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static readonly FiatShamirHashDelegate Hash = FiatShamirBlake3Reference.GetHash();
    private static readonly FiatShamirSqueezeDelegate Squeeze = FiatShamirBlake3Reference.GetSqueeze();

    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    [DataRow(4)]
    [DataRow(8)]
    [DataRow(16)]
    public void ProveVerifyRoundtrip(int vectorLength)
    {
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        int scalarSize = Scalar.SizeBytes;
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);

        using HyraxCommitmentKey gKey = DeriveKey("veridical.test.two-vector-ipa.g.v1", vectorLength);
        using HyraxCommitmentKey hKey = DeriveKey("veridical.test.two-vector-ipa.h.v1", vectorLength);

        Span<byte> a = stackalloc byte[vectorLength * scalarSize];
        Span<byte> b = stackalloc byte[vectorLength * scalarSize];
        FillScalars(a, vectorLength, seed: 11);
        FillScalars(b, vectorLength, seed: 23);

        //P = ⟨a, G⟩ + ⟨b, H⟩ and c = ⟨a, b⟩, computed directly.
        Span<byte> pCommitment = stackalloc byte[g1Size];
        Span<byte> claimed = stackalloc byte[scalarSize];
        ComputeCommitmentAndInnerProduct(a, b, gKey, hKey, vectorLength, pCommitment, claimed, pool);

        int roundCount = TwoVectorInnerProductArgument.GetRoundCount(vectorLength);
        Span<byte> roundPairs = stackalloc byte[roundCount * 2 * g1Size];
        Span<byte> finalA = stackalloc byte[scalarSize];
        Span<byte> finalB = stackalloc byte[scalarSize];

        Span<byte> aWorking = stackalloc byte[vectorLength * scalarSize];
        Span<byte> bWorking = stackalloc byte[vectorLength * scalarSize];
        a.CopyTo(aWorking);
        b.CopyTo(bWorking);
        Span<byte> gWorking = stackalloc byte[vectorLength * g1Size];
        Span<byte> hWorking = stackalloc byte[vectorLength * g1Size];
        LoadGenerators(gKey, vectorLength, gWorking);
        LoadGenerators(hKey, vectorLength, hWorking);

        using(FiatShamirTranscript proverTx = NewTranscript())
        {
            TwoVectorInnerProductArgument.Prove(
                aWorking, bWorking, gWorking, hWorking, gKey.GetValueGenerator(),
                roundPairs, finalA, finalB, vectorLength, RoundLabelPrefix, proverTx,
                ScalarAdd, ScalarMul, ScalarInvert, ScalarReduce, G1Add, G1ScalarMul, G1Msm,
                Hash, Squeeze, Curve, pool);
        }

        LoadGenerators(gKey, vectorLength, gWorking);
        LoadGenerators(hKey, vectorLength, hWorking);
        using(FiatShamirTranscript verifierTx = NewTranscript())
        {
            bool verified = TwoVectorInnerProductArgument.Verify(
                pCommitment, claimed, finalA, finalB, roundPairs, gKey.GetValueGenerator(),
                gWorking, hWorking, vectorLength, RoundLabelPrefix, verifierTx,
                ScalarAdd, ScalarMul, ScalarInvert, ScalarReduce, G1Add, G1ScalarMul,
                Hash, Squeeze, Curve, pool);

            Assert.IsTrue(verified, $"An honest two-vector IPA must round-trip for n = {vectorLength}.");
        }
    }


    [TestMethod]
    public void WrongClaimedInnerProductIsRejected()
    {
        ExerciseTamper(tamperClaim: true, tamperPairByte: -1);
    }


    [TestMethod]
    [DataRow(0)]   //First byte of the first L point.
    [DataRow(60)]  //Inside the first R point.
    public void CorruptedRoundPairIsRejected(int byteOffset)
    {
        ExerciseTamper(tamperClaim: false, tamperPairByte: byteOffset);
    }


    private static void ExerciseTamper(bool tamperClaim, int tamperPairByte)
    {
        const int VectorLength = 8;
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        int scalarSize = Scalar.SizeBytes;
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);

        using HyraxCommitmentKey gKey = DeriveKey("veridical.test.two-vector-ipa.g.v1", VectorLength);
        using HyraxCommitmentKey hKey = DeriveKey("veridical.test.two-vector-ipa.h.v1", VectorLength);

        Span<byte> a = stackalloc byte[VectorLength * scalarSize];
        Span<byte> b = stackalloc byte[VectorLength * scalarSize];
        FillScalars(a, VectorLength, seed: 31);
        FillScalars(b, VectorLength, seed: 43);

        Span<byte> pCommitment = stackalloc byte[g1Size];
        Span<byte> claimed = stackalloc byte[scalarSize];
        ComputeCommitmentAndInnerProduct(a, b, gKey, hKey, VectorLength, pCommitment, claimed, pool);

        int roundCount = TwoVectorInnerProductArgument.GetRoundCount(VectorLength);
        Span<byte> roundPairs = stackalloc byte[roundCount * 2 * g1Size];
        Span<byte> finalA = stackalloc byte[scalarSize];
        Span<byte> finalB = stackalloc byte[scalarSize];

        Span<byte> gWorking = stackalloc byte[VectorLength * g1Size];
        Span<byte> hWorking = stackalloc byte[VectorLength * g1Size];
        LoadGenerators(gKey, VectorLength, gWorking);
        LoadGenerators(hKey, VectorLength, hWorking);

        using(FiatShamirTranscript proverTx = NewTranscript())
        {
            TwoVectorInnerProductArgument.Prove(
                a, b, gWorking, hWorking, gKey.GetValueGenerator(),
                roundPairs, finalA, finalB, VectorLength, RoundLabelPrefix, proverTx,
                ScalarAdd, ScalarMul, ScalarInvert, ScalarReduce, G1Add, G1ScalarMul, G1Msm,
                Hash, Squeeze, Curve, pool);
        }

        if(tamperClaim)
        {
            claimed[^1] ^= 0x01;
        }

        if(tamperPairByte >= 0)
        {
            roundPairs[tamperPairByte] ^= 0x01;
        }

        LoadGenerators(gKey, VectorLength, gWorking);
        LoadGenerators(hKey, VectorLength, hWorking);
        using(FiatShamirTranscript verifierTx = NewTranscript())
        {
            bool verified = TwoVectorInnerProductArgument.Verify(
                pCommitment, claimed, finalA, finalB, roundPairs, gKey.GetValueGenerator(),
                gWorking, hWorking, VectorLength, RoundLabelPrefix, verifierTx,
                ScalarAdd, ScalarMul, ScalarInvert, ScalarReduce, G1Add, G1ScalarMul,
                Hash, Squeeze, Curve, pool);

            Assert.IsFalse(verified, "A tampered two-vector IPA must be rejected.");
        }
    }


    private static HyraxCommitmentKey DeriveKey(string seed, int vectorLength) =>
        HyraxCommitmentKey.Derive(vectorLength, seed, Curve, HashToCurve, SensitiveMemoryPool<byte>.Shared);


    private static FiatShamirTranscript NewTranscript() =>
        FiatShamirTranscript.Initialise(new FiatShamirDomainLabel(TranscriptDomain), ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, SensitiveMemoryPool<byte>.Shared);


    private static void FillScalars(Span<byte> destination, int count, int seed)
    {
        int scalarSize = Scalar.SizeBytes;
        Span<byte> hashInput = stackalloc byte[8];
        Span<byte> wide = stackalloc byte[32];
        for(int i = 0; i < count; i++)
        {
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(hashInput[..4], seed);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(hashInput[4..], i);
            SHA256.HashData(hashInput, wide);
            ScalarReduce(wide, destination.Slice(i * scalarSize, scalarSize), Curve);
        }
    }


    private static void LoadGenerators(HyraxCommitmentKey key, int count, Span<byte> destination)
    {
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
        for(int i = 0; i < count; i++)
        {
            key.GetGenerator(i).CopyTo(destination.Slice(i * g1Size, g1Size));
        }
    }


    //P = ⟨a, G⟩ + ⟨b, H⟩ and c = ⟨a, b⟩, both computed directly from the inputs.
    private static void ComputeCommitmentAndInnerProduct(
        ReadOnlySpan<byte> a,
        ReadOnlySpan<byte> b,
        HyraxCommitmentKey gKey,
        HyraxCommitmentKey hKey,
        int vectorLength,
        Span<byte> pCommitment,
        Span<byte> claimed,
        SensitiveMemoryPool<byte> pool)
    {
        int scalarSize = Scalar.SizeBytes;
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);

        using IMemoryOwner<byte> gOwner = pool.Rent(vectorLength * g1Size);
        using IMemoryOwner<byte> hOwner = pool.Rent(vectorLength * g1Size);
        Span<byte> g = gOwner.Memory.Span[..(vectorLength * g1Size)];
        Span<byte> h = hOwner.Memory.Span[..(vectorLength * g1Size)];
        LoadGenerators(gKey, vectorLength, g);
        LoadGenerators(hKey, vectorLength, h);

        Span<byte> aTimesG = stackalloc byte[48];
        Span<byte> bTimesH = stackalloc byte[48];
        G1Msm(g, a, vectorLength, aTimesG[..g1Size], Curve);
        G1Msm(h, b, vectorLength, bTimesH[..g1Size], Curve);
        G1Add(aTimesG[..g1Size], bTimesH[..g1Size], pCommitment, Curve);

        claimed.Clear();
        Span<byte> term = stackalloc byte[32];
        for(int i = 0; i < vectorLength; i++)
        {
            ScalarMul(a.Slice(i * scalarSize, scalarSize), b.Slice(i * scalarSize, scalarSize), term[..scalarSize], Curve);
            ScalarAdd(claimed, term[..scalarSize], claimed, Curve);
        }
    }
}
