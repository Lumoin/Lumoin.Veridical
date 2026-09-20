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
/// End-to-end round-trip tests for Spartan with BaseFold as its polynomial
/// commitment scheme: the prover assembles a
/// <see cref="CommitmentSpartanProof"/> over the <c>x · y = 15</c> circuit through
/// <c>ProveCommitted</c>, and the verifier accepts it through
/// <c>VerifyCommitted</c>. Negative tests confirm that flipping a byte in the
/// witness-opening section or the shared sumcheck middle is rejected. Real
/// BLS12-381 arithmetic and production BLAKE3 throughout; the proof is a
/// transparent, post-quantum-style argument (no pairing-group commitments).
/// </summary>
[TestClass]
internal sealed class BaseFoldSpartanRoundtripTests
{
    /// <summary>The production BLAKE3 Fiat-Shamir hash delegate driving both the prover's and verifier's transcripts.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The production BLAKE3 Fiat-Shamir squeeze delegate drawing challenges from the transcript.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();

    /// <summary>The BLS12-381 scalar-field reduction delegate from the BigInteger-backed reference implementation.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();

    /// <summary>The BLS12-381 scalar-field addition delegate under test.</summary>
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;

    /// <summary>The BLS12-381 scalar-field subtraction delegate under test.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;

    /// <summary>The BLS12-381 scalar-field multiplication delegate under test.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;

    /// <summary>The BLS12-381 scalar-field inversion delegate under test.</summary>
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;

    /// <summary>The BLS12-381 hash-to-scalar delegate from the BigInteger-backed reference implementation.</summary>
    private static ScalarHashToScalarDelegate HashToScalar { get; } = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();

    /// <summary>The BLS12-381 G1 addition delegate from the BigInteger-backed reference implementation.</summary>
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();

    /// <summary>The BLS12-381 G1 scalar-multiplication delegate from the BigInteger-backed reference implementation.</summary>
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();

    /// <summary>The BLS12-381 G1 multi-scalar-multiplication delegate under test.</summary>
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;

    /// <summary>The multilinear-extension evaluation delegate from the BigInteger-backed reference implementation.</summary>
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();

    /// <summary>The multilinear-extension fold delegate from the BigInteger-backed reference implementation.</summary>
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();

    /// <summary>The Merkle two-to-one compression delegate, backed by <see cref="HashTwoToOne"/>.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    /// <summary>The default Merkle digest width this provider is wired at.</summary>
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    /// <summary>The BaseFold query count this round-trip commits and opens at.</summary>
    private const int TestQueryCount = 8;

    /// <summary>The Fiat-Shamir domain label this class's transcripts are initialised under.</summary>
    private const string TranscriptDomain = "veridical.spartan2.basefold.test.v1";

    /// <summary>The deterministic seed for the BaseFold linear code's construction.</summary>
    private static byte[] CodeSeed { get; } = Encoding.UTF8.GetBytes("veridical.spartan2.basefold.roundtrip.code.v1");

    /// <summary>The deterministic seed for this class's reproducible prover randomness.</summary>
    private static byte[] RandomSeed { get; } = Encoding.UTF8.GetBytes("veridical.spartan2.basefold.roundtrip.rng.v1");

    /// <summary>The curve parameter set selecting the BLS12-381 instantiation throughout this class.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    /// <summary>Verifies that an honest Spartan proof over the x · y = 15 circuit, committed with BaseFold, proves and verifies end-to-end.</summary>
    [TestMethod]
    public void XyEquals15RoundTripsThroughBaseFold()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using CommitmentSpartanProof proof = Prove(pool);

        bool verified = Verify(proof, pool);
        Assert.IsTrue(verified, "An honest BaseFold-backed Spartan proof must verify.");
    }


    /// <summary>Verifies that flipping the last byte of the proof — inside the final witness-opening section — makes verification reject it.</summary>
    [TestMethod]
    public void TamperedWitnessOpeningIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using CommitmentSpartanProof proof = Prove(pool);

        //The witness opening is the final section; flip its last byte.
        MemoryMarshal.AsMemory(proof.AsReadOnlyMemory()).Span[^1] ^= 0x01;

        bool verified = Verify(proof, pool);
        Assert.IsFalse(verified, "A tampered witness-opening section must be rejected.");
    }


    /// <summary>Verifies that flipping the first byte of the shared sumcheck middle, right after the witness commitment's Merkle root, makes verification reject the proof.</summary>
    [TestMethod]
    public void TamperedSumcheckMiddleIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using CommitmentSpartanProof proof = Prove(pool);

        //The sumcheck middle starts right after the witness commitment (the
        //32-byte Merkle root): flip the first byte of the first outer round.
        MemoryMarshal.AsMemory(proof.AsReadOnlyMemory()).Span[DigestSizeBytes] ^= 0x01;

        bool verified = Verify(proof, pool);
        Assert.IsFalse(verified, "A tampered sumcheck-middle byte must be rejected.");
    }


    /// <summary>Produces the test proof and releases provider storage through the owning prover.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The provider's pooled storage transfers to the proving key and the key to the prover, which the using declaration releases; the key and prover constructors cannot fail for a non-null argument, so no path leaves the provider unreleased.")]
    private static CommitmentSpartanProof Prove(BaseMemoryPool pool)
    {
        using RawR1csInstance instance = BuildInstance();
        using RawR1csWitness witness = BuildWitness();

        var provingKey = new SpartanProvingKey(BuildProvider(pool));
        using var prover = new SpartanProver(provingKey);
        using FiatShamirTranscript transcript = FreshTranscript();

        ScalarRandomDelegate random = new DeterministicScalarRandom(RandomSeed).AsDelegate();

        return prover.ProveCommitted(
            instance, witness, transcript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, pool);
    }


    /// <summary>Verifies the test proof and releases provider storage through the owning verifier.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The provider's pooled storage transfers to the verifying key and the key to the verifier, which the using declaration releases; the key and verifier constructors cannot fail for a non-null argument, so no path leaves the provider unreleased.")]
    private static bool Verify(CommitmentSpartanProof proof, BaseMemoryPool pool)
    {
        var verifyingKey = new SpartanVerifyingKey(BuildProvider(pool));
        using var verifier = new SpartanVerifier(verifyingKey);
        using RawR1csInstance instance = BuildInstance();
        using FiatShamirTranscript transcript = FreshTranscript();

        return verifier.VerifyCommitted(
            proof, instance, transcript,
            Add, Multiply, Subtract, Reduce, Hash, Squeeze, pool);
    }


    /// <summary>Builds the commitment provider using the caller's pool.</summary>
    /// <param name="pool">The pool supplied by the test.</param>
    private static PolynomialCommitmentProvider BuildProvider(BaseMemoryPool pool)
    {
        return BaseFoldPolynomialCommitmentScheme.Create(
            CodeSeed,
            Curve,
            TestQueryCount,
            Merkle,
            Hash,
            Squeeze,
            Reduce,
            Add,
            Subtract,
            Multiply,
            Invert,
            HashToScalar, pool,
            DigestSizeBytes);
    }


    /// <summary>Builds the fixture circuit x · y = 15: z = (1, 15, x, y), 2 rows, 4 columns.</summary>
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


    /// <summary>Builds the satisfying witness (x, y) = (3, 5) for the x · y = 15 fixture circuit.</summary>
    private static RawR1csWitness BuildWitness()
    {
        int scalarSize = Scalar.SizeBytes;
        byte[] witnessBytes = new byte[2 * scalarSize];
        WriteCanonical(new BigInteger(3), witnessBytes.AsSpan(0 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(5), witnessBytes.AsSpan(1 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witnessBytes, Curve, BaseMemoryPool.Shared);
    }


    /// <summary>Initializes a fresh Fiat-Shamir transcript under this class's domain label, for either a prover's or a verifier's independent run.</summary>
    private static FiatShamirTranscript FreshTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(TranscriptDomain),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }


    /// <summary>Computes the Merkle two-to-one compression of <paramref name="left"/> and <paramref name="right"/> via BLAKE3.</summary>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>Reduces a value modulo the BLS12-381 scalar order and writes it into <paramref name="destination"/> as a canonical big-endian scalar, throwing if it does not fit.</summary>
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
