using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Commitments;

/// <summary>
/// Tests for the standalone <see cref="InnerProductArgument"/>. Verifies
/// the IPA proves <c>⟨f, R⟩ = c</c> correctly for committed <c>f</c>,
/// rejects corrupted proofs, and is transcript-deterministic.
/// </summary>
[TestClass]
internal sealed class InnerProductArgumentTests
{
    private const string TranscriptDomain = "veridical.test.ipa.v1";
    private const string RoundLabelPrefix = "ipa.test.round";

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


    [TestMethod]
    [DataRow(2)]
    [DataRow(4)]
    [DataRow(8)]
    [DataRow(16)]
    public void ProveVerifyRoundtripAtLength(int k)
    {
        using HyraxCommitmentKey key = HyraxCommitmentKey.Derive(k, TranscriptDomain, CurveParameterSet.Bls12Curve381, HashToCurve, BaseMemoryPool.Shared);

        int scalarSize = Scalar.SizeBytes;
        int g1Size = WellKnownCurves.Bls12Curve381G1CompressedSizeBytes;

        //Set up f, R, generator copies. f and R deterministic, so the
        //correct inner product is computable below.
        using IMemoryOwner<byte> fProverOwner = BaseMemoryPool.Shared.Rent(k * scalarSize);
        using IMemoryOwner<byte> rProverOwner = BaseMemoryPool.Shared.Rent(k * scalarSize);
        using IMemoryOwner<byte> gProverOwner = BaseMemoryPool.Shared.Rent(k * g1Size);
        Span<byte> fProver = fProverOwner.Memory.Span[..(k * scalarSize)];
        Span<byte> rProver = rProverOwner.Memory.Span[..(k * scalarSize)];
        Span<byte> gProver = gProverOwner.Memory.Span[..(k * g1Size)];

        FillScalarVector(fProver, i => i + 1, scalarSize);
        FillScalarVector(rProver, i => i + 5, scalarSize);
        for(int i = 0; i < k; i++)
        {
            key.GetGenerator(i).CopyTo(gProver.Slice(i * g1Size, g1Size));
        }

        //claimed_value = <f, R>
        using IMemoryOwner<byte> claimedOwner = BaseMemoryPool.Shared.Rent(scalarSize);
        Span<byte> claimedBytes = claimedOwner.Memory.Span[..scalarSize];
        BigInteger claimed = BigInteger.Zero;
        for(int i = 0; i < k; i++)
        {
            claimed += new BigInteger(i + 1) * new BigInteger(i + 5);
        }

        WriteCanonical(claimed, claimedBytes);

        //Blinding factor r = 99.
        using IMemoryOwner<byte> blindingOwner = BaseMemoryPool.Shared.Rent(scalarSize);
        Span<byte> blindingBytes = blindingOwner.Memory.Span[..scalarSize];
        WriteCanonical(new BigInteger(99), blindingBytes);

        //Initial commitment C = <f, G> + r · H. Compute via MSM with (k+1) operands.
        using IMemoryOwner<byte> commitOwner = BaseMemoryPool.Shared.Rent(g1Size);
        Span<byte> commitmentBytes = commitOwner.Memory.Span[..g1Size];
        ComputePedersenCommitment(fProver, blindingBytes, key, k, commitmentBytes);

        //Prove.
        int roundCount = InnerProductArgument.GetRoundCount(k);
        using IMemoryOwner<byte> roundPairsOwner = BaseMemoryPool.Shared.Rent(roundCount * 2 * g1Size);
        using IMemoryOwner<byte> finalScalarOwner = BaseMemoryPool.Shared.Rent(scalarSize);
        Span<byte> roundPairs = roundPairsOwner.Memory.Span[..(roundCount * 2 * g1Size)];
        Span<byte> finalScalar = finalScalarOwner.Memory.Span[..scalarSize];

        using FiatShamirTranscript proverTx = FiatShamirTranscript.Initialise(new FiatShamirDomainLabel(TranscriptDomain), ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);

        InnerProductArgument.Prove(
            fProver, gProver, rProver,
            key.GetBlindingGenerator(), key.GetValueGenerator(),
            roundPairs, finalScalar,
            k, RoundLabelPrefix,
            proverTx,
            ScalarAdd, ScalarMul, ScalarInvert, ScalarReduce,
            G1Add, G1ScalarMul, G1Msm,
            Hash, Squeeze, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        //Verify with fresh G and R copies.
        using IMemoryOwner<byte> gVerifierOwner = BaseMemoryPool.Shared.Rent(k * g1Size);
        using IMemoryOwner<byte> rVerifierOwner = BaseMemoryPool.Shared.Rent(k * scalarSize);
        Span<byte> gVerifier = gVerifierOwner.Memory.Span[..(k * g1Size)];
        Span<byte> rVerifier = rVerifierOwner.Memory.Span[..(k * scalarSize)];
        for(int i = 0; i < k; i++)
        {
            key.GetGenerator(i).CopyTo(gVerifier.Slice(i * g1Size, g1Size));
        }

        FillScalarVector(rVerifier, i => i + 5, scalarSize);

        using FiatShamirTranscript verifierTx = FiatShamirTranscript.Initialise(new FiatShamirDomainLabel(TranscriptDomain), ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);

        bool ok = InnerProductArgument.Verify(
            commitmentBytes,
            claimedBytes,
            blindingBytes,
            finalScalar,
            roundPairs,
            key.GetBlindingGenerator(), key.GetValueGenerator(),
            gVerifier, rVerifier,
            k, RoundLabelPrefix,
            verifierTx,
            ScalarAdd, ScalarMul, ScalarInvert, ScalarReduce,
            G1Add, G1ScalarMul,
            Hash, Squeeze, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        Assert.IsTrue(ok, $"IPA round-trip should succeed at length {k}.");
    }


    [TestMethod]
    public void CorruptedFinalScalarFailsVerification()
    {
        const int K = 4;
        var setup = RunRoundTrip(K, corruptionMode: CorruptionMode.FlipFinalScalar);
        Assert.IsFalse(setup, "Bit-flipped final scalar must cause verify to reject.");
    }


    [TestMethod]
    public void CorruptedRoundPointFailsVerification()
    {
        const int K = 8;
        var setup = RunRoundTrip(K, corruptionMode: CorruptionMode.FlipFirstRoundLeftPoint);
        Assert.IsFalse(setup, "Bit-flipped IPA round point must cause verify to reject.");
    }


    private enum CorruptionMode { None, FlipFinalScalar, FlipFirstRoundLeftPoint }


    private static bool RunRoundTrip(int k, CorruptionMode corruptionMode)
    {
        using HyraxCommitmentKey key = HyraxCommitmentKey.Derive(k, TranscriptDomain, CurveParameterSet.Bls12Curve381, HashToCurve, BaseMemoryPool.Shared);

        int scalarSize = Scalar.SizeBytes;
        int g1Size = WellKnownCurves.Bls12Curve381G1CompressedSizeBytes;

        using IMemoryOwner<byte> fProverOwner = BaseMemoryPool.Shared.Rent(k * scalarSize);
        using IMemoryOwner<byte> rProverOwner = BaseMemoryPool.Shared.Rent(k * scalarSize);
        using IMemoryOwner<byte> gProverOwner = BaseMemoryPool.Shared.Rent(k * g1Size);
        Span<byte> fProver = fProverOwner.Memory.Span[..(k * scalarSize)];
        Span<byte> rProver = rProverOwner.Memory.Span[..(k * scalarSize)];
        Span<byte> gProver = gProverOwner.Memory.Span[..(k * g1Size)];

        FillScalarVector(fProver, i => i + 1, scalarSize);
        FillScalarVector(rProver, i => i + 5, scalarSize);
        for(int i = 0; i < k; i++)
        {
            key.GetGenerator(i).CopyTo(gProver.Slice(i * g1Size, g1Size));
        }

        using IMemoryOwner<byte> claimedOwner = BaseMemoryPool.Shared.Rent(scalarSize);
        Span<byte> claimedBytes = claimedOwner.Memory.Span[..scalarSize];
        BigInteger claimed = BigInteger.Zero;
        for(int i = 0; i < k; i++)
        {
            claimed += new BigInteger(i + 1) * new BigInteger(i + 5);
        }

        WriteCanonical(claimed, claimedBytes);

        using IMemoryOwner<byte> blindingOwner = BaseMemoryPool.Shared.Rent(scalarSize);
        Span<byte> blindingBytes = blindingOwner.Memory.Span[..scalarSize];
        WriteCanonical(new BigInteger(99), blindingBytes);

        using IMemoryOwner<byte> commitOwner = BaseMemoryPool.Shared.Rent(g1Size);
        Span<byte> commitmentBytes = commitOwner.Memory.Span[..g1Size];
        ComputePedersenCommitment(fProver, blindingBytes, key, k, commitmentBytes);

        int roundCount = InnerProductArgument.GetRoundCount(k);
        using IMemoryOwner<byte> roundPairsOwner = BaseMemoryPool.Shared.Rent(roundCount * 2 * g1Size);
        using IMemoryOwner<byte> finalScalarOwner = BaseMemoryPool.Shared.Rent(scalarSize);
        Span<byte> roundPairs = roundPairsOwner.Memory.Span[..(roundCount * 2 * g1Size)];
        Span<byte> finalScalar = finalScalarOwner.Memory.Span[..scalarSize];

        using FiatShamirTranscript proverTx = FiatShamirTranscript.Initialise(new FiatShamirDomainLabel(TranscriptDomain), ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);

        InnerProductArgument.Prove(
            fProver, gProver, rProver,
            key.GetBlindingGenerator(), key.GetValueGenerator(),
            roundPairs, finalScalar,
            k, RoundLabelPrefix,
            proverTx,
            ScalarAdd, ScalarMul, ScalarInvert, ScalarReduce,
            G1Add, G1ScalarMul, G1Msm,
            Hash, Squeeze, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        //Inject corruption before verification.
        switch(corruptionMode)
        {
            case CorruptionMode.FlipFinalScalar:
            {
                finalScalar[scalarSize - 1] ^= 0x01;
                break;
            }
            case CorruptionMode.FlipFirstRoundLeftPoint:
            {
                roundPairs[g1Size - 1] ^= 0x01;
                break;
            }
        }

        using IMemoryOwner<byte> gVerifierOwner = BaseMemoryPool.Shared.Rent(k * g1Size);
        using IMemoryOwner<byte> rVerifierOwner = BaseMemoryPool.Shared.Rent(k * scalarSize);
        Span<byte> gVerifier = gVerifierOwner.Memory.Span[..(k * g1Size)];
        Span<byte> rVerifier = rVerifierOwner.Memory.Span[..(k * scalarSize)];
        for(int i = 0; i < k; i++)
        {
            key.GetGenerator(i).CopyTo(gVerifier.Slice(i * g1Size, g1Size));
        }

        FillScalarVector(rVerifier, i => i + 5, scalarSize);

        using FiatShamirTranscript verifierTx = FiatShamirTranscript.Initialise(new FiatShamirDomainLabel(TranscriptDomain), ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);

        return InnerProductArgument.Verify(
            commitmentBytes,
            claimedBytes,
            blindingBytes,
            finalScalar,
            roundPairs,
            key.GetBlindingGenerator(), key.GetValueGenerator(),
            gVerifier, rVerifier,
            k, RoundLabelPrefix,
            verifierTx,
            ScalarAdd, ScalarMul, ScalarInvert, ScalarReduce,
            G1Add, G1ScalarMul,
            Hash, Squeeze, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    private static void ComputePedersenCommitment(
        ReadOnlySpan<byte> f,
        ReadOnlySpan<byte> blindingBytes,
        HyraxCommitmentKey key,
        int k,
        Span<byte> destination)
    {
        int g1Size = WellKnownCurves.Bls12Curve381G1CompressedSizeBytes;
        int scalarSize = Scalar.SizeBytes;
        int operandCount = k + 1;

        using IMemoryOwner<byte> pointsOwner = BaseMemoryPool.Shared.Rent(operandCount * g1Size);
        using IMemoryOwner<byte> scalarsOwner = BaseMemoryPool.Shared.Rent(operandCount * scalarSize);
        Span<byte> points = pointsOwner.Memory.Span[..(operandCount * g1Size)];
        Span<byte> scalars = scalarsOwner.Memory.Span[..(operandCount * scalarSize)];
        for(int i = 0; i < k; i++)
        {
            key.GetGenerator(i).CopyTo(points.Slice(i * g1Size, g1Size));
        }

        key.GetBlindingGenerator().CopyTo(points.Slice(k * g1Size, g1Size));
        f.CopyTo(scalars[..(k * scalarSize)]);
        blindingBytes.CopyTo(scalars.Slice(k * scalarSize, scalarSize));

        G1Msm(points, scalars, operandCount, destination, CurveParameterSet.Bls12Curve381);
    }


    private static void FillScalarVector(Span<byte> destination, Func<int, int> valueAt, int scalarSize)
    {
        int count = destination.Length / scalarSize;
        for(int i = 0; i < count; i++)
        {
            WriteCanonical(new BigInteger(valueAt(i)), destination.Slice(i * scalarSize, scalarSize));
        }
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