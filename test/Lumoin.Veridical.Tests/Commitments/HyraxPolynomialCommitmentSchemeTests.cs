using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Numerics;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Commitments;

/// <summary>
/// AA.2 byte-identity proof for the Hyrax adapter: routing commit / open /
/// verify through the scheme-agnostic <see cref="PolynomialCommitmentProvider"/>
/// produced by <see cref="HyraxPolynomialCommitmentScheme"/> yields exactly the
/// same wire bytes as calling the Hyrax extension methods directly, and the
/// provider's own commit → open → verify round-trip succeeds. This is the
/// adapter-level guarantee that AA.2's consumer rewiring rests on.
/// </summary>
[TestClass]
internal sealed class HyraxPolynomialCommitmentSchemeTests
{
    private const string TranscriptDomain = "veridical.test.hyrax.pcs.v1";

    //A representative non-trivial size: n = 4 gives a 4 × 4 matrix (multiple
    //rows to combine) and a 2-round IPA (multiple folds), so the commitment,
    //the blind, and every proof section are exercised.
    private const int VariableCount = 4;
    private const int SampleSeed = 7654;

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


    [TestMethod]
    public void ProviderCommitOpenIsByteIdenticalToDirectHyrax()
    {
        var dimensions = HyraxCommitmentDimensions.ForVariableCount(VariableCount);
        using HyraxCommitmentKey key = HyraxCommitmentKey.Derive(
            dimensions.ColumnCount, WellKnownHyraxDomainLabels.CanonicalSeedV1, CurveParameterSet.Bls12Curve381, HashToCurve, SensitiveMemoryPool<byte>.Shared);

        using MultilinearExtension mle = BuildMle(VariableCount);

        //Direct path: the same seed and a fresh transcript as the provider path,
        //so the blinding-sample sequence and Fiat-Shamir challenges coincide.
        ScalarRandomDelegate directRandom = MakeFixedRandom(SampleSeed);
        var (directCommitment, directWitness) = key.CommitMultilinearExtension(mle, directRandom, G1Msm, SensitiveMemoryPool<byte>.Shared);

        //Provider path: an independent RNG seeded identically.
        ScalarRandomDelegate providerRandom = MakeFixedRandom(SampleSeed);
        using PolynomialCommitmentProvider provider = HyraxPolynomialCommitmentScheme.Create(
            key, CurveParameterSet.Bls12Curve381,
            Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert, providerRandom, G1Add, G1ScalarMul, G1Msm);

        var (providerCommitment, providerBlind) = provider.Commit(mle, SensitiveMemoryPool<byte>.Shared);

        using(directCommitment)
        using(directWitness)
        using(providerCommitment)
        using(providerBlind)
        using(PointArray point = BuildPointArray(VariableCount))
        using(FiatShamirTranscript directTx = NewTranscript())
        using(FiatShamirTranscript providerTx = NewTranscript())
        {
            Assert.IsTrue(
                providerCommitment.AsReadOnlySpan().SequenceEqual(directCommitment.AsReadOnlySpan()),
                "Provider commitment bytes must equal the direct Hyrax commitment bytes.");
            Assert.IsTrue(
                providerBlind.AsReadOnlySpan().SequenceEqual(directWitness.AsReadOnlySpan()),
                "Provider blind bytes must equal the direct Hyrax opening-witness bytes.");

            var (directProof, directClaimed) = directCommitment.Open(
                directWitness, mle, point.AsSpan, key, directTx,
                Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert, directRandom,
                G1Add, G1ScalarMul, G1Msm, SensitiveMemoryPool<byte>.Shared);

            var (providerOpening, providerClaimed) = provider.Open(
                providerCommitment, providerBlind, mle, point.AsSpan, providerTx, SensitiveMemoryPool<byte>.Shared);

            using(directProof)
            using(directClaimed)
            using(providerOpening)
            using(providerClaimed)
            {
                Assert.IsTrue(
                    providerOpening.AsReadOnlySpan().SequenceEqual(directProof.AsReadOnlySpan()),
                    "Provider opening bytes must equal the direct Hyrax opening-proof bytes.");
                Assert.IsTrue(
                    providerClaimed.AsReadOnlySpan().SequenceEqual(directClaimed.AsReadOnlySpan()),
                    "Provider claimed value must equal the direct Hyrax claimed value.");
            }
        }
    }


    [TestMethod]
    public void ProviderRoundtripVerifies()
    {
        var dimensions = HyraxCommitmentDimensions.ForVariableCount(VariableCount);
        using HyraxCommitmentKey key = HyraxCommitmentKey.Derive(
            dimensions.ColumnCount, WellKnownHyraxDomainLabels.CanonicalSeedV1, CurveParameterSet.Bls12Curve381, HashToCurve, SensitiveMemoryPool<byte>.Shared);

        using MultilinearExtension mle = BuildMle(VariableCount);
        ScalarRandomDelegate random = MakeFixedRandom(SampleSeed);
        using PolynomialCommitmentProvider provider = HyraxPolynomialCommitmentScheme.Create(
            key, CurveParameterSet.Bls12Curve381,
            Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert, random, G1Add, G1ScalarMul, G1Msm);

        Assert.AreEqual(CommitmentScheme.Hyrax, provider.Scheme, "scheme identity");
        Assert.AreEqual(CurveParameterSet.Bls12Curve381.Code, provider.Curve.Code, "curve identity");

        var (commitment, blind) = provider.Commit(mle, SensitiveMemoryPool<byte>.Shared);

        using(commitment)
        using(blind)
        using(PointArray point = BuildPointArray(VariableCount))
        using(FiatShamirTranscript proverTx = NewTranscript())
        using(FiatShamirTranscript verifierTx = NewTranscript())
        {
            var (opening, claimedValue) = provider.Open(
                commitment, blind, mle, point.AsSpan, proverTx, SensitiveMemoryPool<byte>.Shared);

            using(opening)
            using(claimedValue)
            {
                bool ok = provider.VerifyEvaluation(
                    commitment, point.AsSpan, claimedValue, opening, verifierTx, SensitiveMemoryPool<byte>.Shared);

                Assert.IsTrue(ok, "Provider commit → open → verify round-trip must succeed.");
            }
        }
    }


    private static FiatShamirTranscript NewTranscript() =>
        FiatShamirTranscript.Initialise(new FiatShamirDomainLabel(TranscriptDomain), ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, SensitiveMemoryPool<byte>.Shared);


    private static MultilinearExtension BuildMle(int variableCount)
    {
        int evalCount = 1 << variableCount;
        int elementSize = Scalar.SizeBytes;
        using IMemoryOwner<byte> bufOwner = SensitiveMemoryPool<byte>.Shared.Rent(evalCount * elementSize);
        Span<byte> buf = bufOwner.Memory.Span[..(evalCount * elementSize)];
        for(int i = 0; i < evalCount; i++)
        {
            WriteCanonical(new BigInteger((i * 13) + 7), buf.Slice(i * elementSize, elementSize));
        }

        return MultilinearExtension.FromEvaluations(buf, variableCount, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
    }


    private static PointArray BuildPointArray(int variableCount)
    {
        var scalars = new Scalar[variableCount];
        for(int i = 0; i < variableCount; i++)
        {
            scalars[i] = MakeScalar((i * 5) + 3);
        }

        return new PointArray(scalars);
    }


    private static Scalar MakeScalar(int value)
    {
        using IMemoryOwner<byte> owner = SensitiveMemoryPool<byte>.Shared.Rent(Scalar.SizeBytes);
        Span<byte> span = owner.Memory.Span[..Scalar.SizeBytes];
        WriteCanonical(new BigInteger(value), span);
        return Scalar.FromCanonical(span, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
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
            ScalarReduceDelegate reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();
            reduce(wide, destination, curve);
            return inboundTag;
        }
    }


    private readonly struct PointArray: IDisposable
    {
        private readonly Scalar[] scalars;

        public PointArray(Scalar[] scalars) { this.scalars = scalars; }

        public ReadOnlySpan<Scalar> AsSpan => scalars;

        public void Dispose()
        {
            if(scalars is null)
            {
                return;
            }

            foreach(Scalar s in scalars)
            {
                s?.Dispose();
            }
        }
    }
}
