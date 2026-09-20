using Lumoin.Veridical.Backends.Managed;
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
/// Byte-identity proof for the Hyrax adapter: routing commit / open /
/// verify through the scheme-agnostic <see cref="PolynomialCommitmentProvider"/>
/// produced by <see cref="HyraxPolynomialCommitmentScheme"/> yields exactly the
/// same wire bytes as calling the Hyrax extension methods directly, and the
/// provider's own commit → open → verify round-trip succeeds. This is the
/// adapter-level guarantee that consumers migrating onto the scheme-agnostic
/// provider surface can rely on.
/// </summary>
[TestClass]
internal sealed class HyraxPolynomialCommitmentSchemeTests
{
    /// <summary>The Fiat–Shamir transcript domain label for this test's transcripts.</summary>
    private const string TranscriptDomain = "veridical.test.hyrax.pcs.v1";

    /// <summary>
    /// A representative non-trivial size: n = 4 gives a 4 × 4 matrix (multiple rows to combine) and a
    /// 2-round IPA (multiple folds), so the commitment, the blind, and every proof section are
    /// exercised.
    /// </summary>
    private const int VariableCount = 4;

    /// <summary>The fixed seed for this test's deterministic random-scalar source.</summary>
    private const int SampleSeed = 7654;

    /// <summary>The BLS12-381 G1 hash-to-curve delegate.</summary>
    private static G1HashToCurveDelegate HashToCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();

    /// <summary>The BLS12-381 G1 addition delegate.</summary>
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();

    /// <summary>The BLS12-381 G1 scalar-multiplication delegate.</summary>
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();

    /// <summary>The BLS12-381 G1 multi-scalar-multiplication delegate.</summary>
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;

    /// <summary>The BLS12-381 G1 on-curve check delegate.</summary>
    private static G1IsOnCurveDelegate G1IsOnCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetIsOnCurve();

    /// <summary>The BLS12-381 G1 prime-order-subgroup membership check delegate.</summary>
    private static G1IsInPrimeOrderSubgroupDelegate G1IsInPrimeOrderSubgroup { get; } = Bls12Curve381BigIntegerG1Reference.GetIsInPrimeOrderSubgroup();

    /// <summary>The BLS12-381 scalar addition delegate.</summary>
    private static ScalarAddDelegate ScalarAdd { get; } = TestScalarBackends.Bls12Curve381.Add;

    /// <summary>The BLS12-381 scalar subtraction delegate.</summary>
    private static ScalarSubtractDelegate ScalarSubtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;

    /// <summary>The BLS12-381 scalar multiplication delegate.</summary>
    private static ScalarMultiplyDelegate ScalarMul { get; } = TestScalarBackends.Bls12Curve381.Multiply;

    /// <summary>The BLS12-381 scalar inversion delegate.</summary>
    private static ScalarInvertDelegate ScalarInvert { get; } = TestScalarBackends.Bls12Curve381.Invert;

    /// <summary>The BLS12-381 scalar reduction delegate.</summary>
    private static ScalarReduceDelegate ScalarReduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();

    /// <summary>The Blake3-backed Fiat–Shamir hash delegate.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The Blake3-backed Fiat–Shamir squeeze delegate.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();


    /// <summary>Verifies that committing and opening through the scheme-agnostic provider produces byte-identical commitment, blind, opening and claimed-value bytes to calling the Hyrax extension methods directly.</summary>
    [TestMethod]
    public void ProviderCommitOpenIsByteIdenticalToDirectHyrax()
    {
        var dimensions = HyraxCommitmentDimensions.ForVariableCount(VariableCount);
        using HyraxCommitmentKey key = HyraxCommitmentKey.Derive(
            dimensions.ColumnCount, WellKnownHyraxDomainLabels.CanonicalSeedV1, CurveParameterSet.Bls12Curve381, HashToCurve, BaseMemoryPool.Shared);

        using MultilinearExtension mle = BuildMle(VariableCount);

        //Direct path: the same seed and a fresh transcript as the provider path,
        //so the blinding-sample sequence and Fiat-Shamir challenges coincide.
        ScalarRandomDelegate directRandom = MakeFixedRandom(SampleSeed);
        var (directCommitment, directWitness) = key.CommitMultilinearExtension(mle, directRandom, G1Msm, BaseMemoryPool.Shared);

        //Provider path: an independent RNG seeded identically.
        ScalarRandomDelegate providerRandom = MakeFixedRandom(SampleSeed);
        using PolynomialCommitmentProvider provider = HyraxPolynomialCommitmentScheme.Create(
            key, CurveParameterSet.Bls12Curve381,
            Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert, providerRandom, G1Add, G1ScalarMul, G1Msm,
            G1IsOnCurve, G1IsInPrimeOrderSubgroup);

        var (providerCommitment, providerBlind) = provider.Commit(mle, BaseMemoryPool.Shared);

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
                G1Add, G1ScalarMul, G1Msm, BaseMemoryPool.Shared);

            var (providerOpening, providerClaimed) = provider.Open(
                providerCommitment, providerBlind, mle, point.AsSpan, providerTx, BaseMemoryPool.Shared);

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


    /// <summary>Verifies that the provider's own commit → open → verify round-trip succeeds, and that the provider reports the Hyrax scheme and the BLS12-381 curve.</summary>
    [TestMethod]
    public void ProviderRoundtripVerifies()
    {
        var dimensions = HyraxCommitmentDimensions.ForVariableCount(VariableCount);
        using HyraxCommitmentKey key = HyraxCommitmentKey.Derive(
            dimensions.ColumnCount, WellKnownHyraxDomainLabels.CanonicalSeedV1, CurveParameterSet.Bls12Curve381, HashToCurve, BaseMemoryPool.Shared);

        using MultilinearExtension mle = BuildMle(VariableCount);
        ScalarRandomDelegate random = MakeFixedRandom(SampleSeed);
        using PolynomialCommitmentProvider provider = HyraxPolynomialCommitmentScheme.Create(
            key, CurveParameterSet.Bls12Curve381,
            Hash, Squeeze, ScalarReduce, ScalarAdd, ScalarSubtract, ScalarMul, ScalarInvert, random, G1Add, G1ScalarMul, G1Msm,
            G1IsOnCurve, G1IsInPrimeOrderSubgroup);

        Assert.AreEqual(CommitmentScheme.Hyrax, provider.Scheme, "scheme identity");
        Assert.AreEqual(CurveParameterSet.Bls12Curve381.Code, provider.Curve.Code, "curve identity");

        var (commitment, blind) = provider.Commit(mle, BaseMemoryPool.Shared);

        using(commitment)
        using(blind)
        using(PointArray point = BuildPointArray(VariableCount))
        using(FiatShamirTranscript proverTx = NewTranscript())
        using(FiatShamirTranscript verifierTx = NewTranscript())
        {
            var (opening, claimedValue) = provider.Open(
                commitment, blind, mle, point.AsSpan, proverTx, BaseMemoryPool.Shared);

            using(opening)
            using(claimedValue)
            {
                bool ok = provider.VerifyEvaluation(
                    commitment, point.AsSpan, claimedValue, opening, verifierTx, BaseMemoryPool.Shared);

                Assert.IsTrue(ok, "Provider commit → open → verify round-trip must succeed.");
            }
        }
    }


    /// <summary>Creates a fresh transcript under this test's domain label.</summary>
    /// <returns>The new transcript.</returns>
    private static FiatShamirTranscript NewTranscript() =>
        FiatShamirTranscript.Initialise(new FiatShamirDomainLabel(TranscriptDomain), ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);


    /// <summary>Builds a deterministic multilinear extension over <paramref name="variableCount"/> variables, evaluation <c>i</c> set to <c>13i + 7</c>.</summary>
    /// <param name="variableCount">The number of variables.</param>
    /// <returns>The new multilinear extension.</returns>
    private static MultilinearExtension BuildMle(int variableCount)
    {
        int evalCount = 1 << variableCount;
        int elementSize = Scalar.SizeBytes;
        using IMemoryOwner<byte> bufOwner = BaseMemoryPool.Shared.Rent(evalCount * elementSize);
        Span<byte> buf = bufOwner.Memory.Span[..(evalCount * elementSize)];
        for(int i = 0; i < evalCount; i++)
        {
            WriteCanonical(new BigInteger((i * 13) + 7), buf.Slice(i * elementSize, elementSize));
        }

        return MultilinearExtension.FromEvaluations(buf, variableCount, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    /// <summary>Builds a deterministic evaluation point of <paramref name="variableCount"/> coordinates, coordinate <c>i</c> set to <c>5i + 3</c>.</summary>
    /// <param name="variableCount">The number of coordinates.</param>
    /// <returns>The owned point array.</returns>
    private static PointArray BuildPointArray(int variableCount)
    {
        var scalars = new Scalar[variableCount];
        for(int i = 0; i < variableCount; i++)
        {
            scalars[i] = MakeScalar((i * 5) + 3);
        }

        return new PointArray(scalars);
    }


    /// <summary>Builds a canonical scalar from a small non-negative integer.</summary>
    /// <param name="value">The integer value.</param>
    /// <returns>The new scalar.</returns>
    private static Scalar MakeScalar(int value)
    {
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(Scalar.SizeBytes);
        Span<byte> span = owner.Memory.Span[..Scalar.SizeBytes];
        WriteCanonical(new BigInteger(value), span);
        return Scalar.FromCanonical(span, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    /// <summary>Reduces <paramref name="value"/> mod the BLS12-381 scalar-field order and writes it as canonical big-endian bytes.</summary>
    /// <param name="value">The integer to reduce and encode.</param>
    /// <param name="destination">Receives the canonical big-endian bytes.</param>
    /// <exception cref="InvalidOperationException">When the reduced value does not fit <paramref name="destination"/>.</exception>
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


    /// <summary>Creates a deterministic random-scalar source: each draw hashes an incrementing counter under <paramref name="seed"/>.</summary>
    /// <param name="seed">The seed value.</param>
    /// <returns>The deterministic random-scalar delegate.</returns>
    private static ScalarRandomDelegate MakeFixedRandom(int seed)
    {
        int counter = 0;
        return Sample;

        //Computes the next draw as SHA-256(seed, counter) reduced mod the scalar-field order into destination, and returns inboundTag unchanged.
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


    /// <summary>An owned array of scalars representing a multilinear evaluation point, disposed as a unit.</summary>
    private readonly struct PointArray: IDisposable
    {
        /// <summary>The owned scalar coordinates.</summary>
        private Scalar[] Scalars { get; }

        /// <summary>Wraps an existing scalar array for disposal as a unit.</summary>
        /// <param name="scalars">The scalars to own.</param>
        public PointArray(Scalar[] scalars) { this.Scalars = scalars; }

        /// <summary>The coordinates as a read-only span.</summary>
        public ReadOnlySpan<Scalar> AsSpan => Scalars;

        /// <summary>Disposes every non-null coordinate scalar.</summary>
        public void Dispose()
        {
            if(Scalars is null)
            {
                return;
            }

            foreach(Scalar s in Scalars)
            {
                s?.Dispose();
            }
        }
    }
}
