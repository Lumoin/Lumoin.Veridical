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
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Text;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// End-to-end round-trip tests for Spartan with Ligero as its polynomial
/// commitment scheme: the prover assembles a <see cref="LigeroSpartanProof"/>
/// over the <c>x · y = 15</c> circuit through <c>ProveLigero</c>, and the
/// verifier accepts it through <c>VerifyLigero</c> — confirming Ligero drops into
/// Spartan behind the <see cref="PolynomialCommitmentProvider"/> seam exactly as
/// Hyrax and BaseFold do. Negative tests confirm that flipping a byte in the
/// witness-opening section or the shared sumcheck middle is rejected. Real
/// BLS12-381 arithmetic and production BLAKE3 throughout; the proof is a
/// transparent, hash-based argument (no pairing-group commitments).
/// </summary>
[TestClass]
internal sealed class LigeroSpartanRoundtripTests
{
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;
    private const int TestQueryCount = 8;
    private const string TranscriptDomain = "veridical.spartan2.ligero.test.v1";

    private static readonly byte[] RandomSeed = Encoding.UTF8.GetBytes("veridical.spartan2.ligero.roundtrip.rng.v1");

    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    public void XyEquals15RoundTripsThroughLigero()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using LigeroSpartanProof proof = Prove(pool);

        bool verified = Verify(proof, pool);
        Assert.IsTrue(verified, "An honest Ligero-backed Spartan proof must verify.");
    }


    [TestMethod]
    public void TamperedWitnessOpeningIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using LigeroSpartanProof proof = Prove(pool);

        //The witness opening is the final section; flip its last byte.
        proof.AsSpan()[^1] ^= 0x01;

        bool verified = Verify(proof, pool);
        Assert.IsFalse(verified, "A tampered witness-opening section must be rejected.");
    }


    [TestMethod]
    public void TamperedSumcheckMiddleIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using LigeroSpartanProof proof = Prove(pool);

        //The sumcheck middle starts right after the witness commitment (the
        //digest-wide column-commitment root): flip the first byte of the first
        //outer round.
        proof.AsSpan()[DigestSizeBytes] ^= 0x01;

        bool verified = Verify(proof, pool);
        Assert.IsFalse(verified, "A tampered sumcheck-middle byte must be rejected.");
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the proving key and prover transfers through using declarations; the returned proof transfers to the caller.")]
    private static LigeroSpartanProof Prove(BaseMemoryPool pool)
    {
        using RawR1csInstance instance = BuildInstance();
        using RawR1csWitness witness = BuildWitness();

        var provingKey = new SpartanProvingKey(BuildProvider());
        using var prover = new SpartanProver(provingKey);
        using FiatShamirTranscript transcript = FreshTranscript();

        ScalarRandomDelegate random = new DeterministicScalarRandom(RandomSeed).AsDelegate();

        return prover.ProveLigero(
            instance, witness, transcript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, pool);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the verifying key and verifier transfers through using declarations.")]
    private static bool Verify(LigeroSpartanProof proof, BaseMemoryPool pool)
    {
        var verifyingKey = new SpartanVerifyingKey(BuildProvider());
        using var verifier = new SpartanVerifier(verifyingKey);
        using RawR1csInstance instance = BuildInstance();
        using FiatShamirTranscript transcript = FreshTranscript();

        return verifier.VerifyLigero(
            proof, instance, transcript,
            Add, Multiply, Subtract, Reduce, Hash, Squeeze, pool);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The Ligero provider holds no disposable key; the Spartan key that consumes it disposes it.")]
    private static PolynomialCommitmentProvider BuildProvider()
    {
        return LigeroPolynomialCommitmentScheme.Create(
            Curve,
            TestQueryCount,
            Add,
            Subtract,
            Multiply,
            Invert,
            Reduce,
            Hash,
            Squeeze,
            Hash,
            Merkle,
            WellKnownHashAlgorithms.Blake3,
            DigestSizeBytes);
    }


    //The fixture circuit x · y = 15: z = (1, 15, x, y), rows = 2, columns = 4.
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
