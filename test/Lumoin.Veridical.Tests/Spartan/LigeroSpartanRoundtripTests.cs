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
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// End-to-end round-trip tests for Spartan with Ligero as its polynomial
/// commitment scheme: the prover assembles a <see cref="CommitmentSpartanProof"/>
/// over the <c>x · y = 15</c> circuit through <c>ProveCommitted</c>, and the
/// verifier accepts it through <c>VerifyCommitted</c> — confirming Ligero drops
/// into Spartan behind the <see cref="PolynomialCommitmentProvider"/> seam, through
/// the entry points every scheme whose openings are opaque byte sections shares.
/// Negative tests confirm that flipping a byte in the
/// witness-opening section or the shared sumcheck middle is rejected. Real
/// BLS12-381 arithmetic and production BLAKE3 throughout; the proof is a
/// transparent, hash-based argument (no pairing-group commitments).
/// </summary>
[TestClass]
internal sealed class LigeroSpartanRoundtripTests
{
    /// <summary>The production BLAKE3 Fiat-Shamir hash delegate every transcript in this class is built from.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The production BLAKE3 Fiat-Shamir squeeze delegate every transcript in this class draws challenges through.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();

    /// <summary>The BigInteger reference scalar-reduction delegate for the BLS12-381 scalar field.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();

    /// <summary>The validated BLS12-381 scalar addition delegate the Spartan-over-Ligero prove/verify runs on.</summary>
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;

    /// <summary>The validated BLS12-381 scalar subtraction delegate the Spartan-over-Ligero prove/verify runs on.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;

    /// <summary>The validated BLS12-381 scalar multiplication delegate the Spartan-over-Ligero prove/verify runs on.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;

    /// <summary>The validated BLS12-381 scalar inversion delegate the Spartan-over-Ligero prove/verify runs on.</summary>
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;

    /// <summary>The BigInteger reference G1 point-addition delegate for BLS12-381.</summary>
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();

    /// <summary>The BigInteger reference G1 scalar-multiplication delegate for BLS12-381.</summary>
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();

    /// <summary>The validated BLS12-381 G1 multi-scalar-multiplication delegate the Spartan commitments run on.</summary>
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;

    /// <summary>The BigInteger reference multilinear-extension evaluation delegate.</summary>
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();

    /// <summary>The BigInteger reference multilinear-extension folding delegate.</summary>
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();

    /// <summary>The two-to-one Merkle hash delegate backing the Ligero provider, implemented with production BLAKE3 through <see cref="HashTwoToOne"/>.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    /// <summary>The Merkle digest width the Ligero provider and hash delegate use, taken from the library's default Merkle parameters.</summary>
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    /// <summary>The opened-column count the Ligero provider uses; small enough to keep the fixture fast.</summary>
    private const int TestQueryCount = 8;

    /// <summary>The Fiat-Shamir domain-separation label for this test's transcript, distinguishing it from every other transcript domain in the suite.</summary>
    private const string TranscriptDomain = "veridical.spartan2.ligero.test.v1";

    /// <summary>The seed for the deterministic randomness the Spartan prover draws its masking scalars from.</summary>
    private static byte[] RandomSeed { get; } = Encoding.UTF8.GetBytes("veridical.spartan2.ligero.roundtrip.rng.v1");

    /// <summary>The BLS12-381 curve parameter set this test's arithmetic and commitments run over.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    /// <summary>Verifies that an honest Ligero-backed Spartan proof of <c>x · y = 15</c> verifies.</summary>
    [TestMethod]
    public void XyEquals15RoundTripsThroughLigero()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using CommitmentSpartanProof proof = Prove(pool);

        bool verified = Verify(proof, pool);
        Assert.IsTrue(verified, "An honest Ligero-backed Spartan proof must verify.");
    }


    /// <summary>Verifies that flipping the last byte of an honest proof (inside the witness-opening section) makes verification reject.</summary>
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


    /// <summary>Verifies that flipping the first byte of the shared sumcheck middle (right after the witness commitment) makes verification reject.</summary>
    [TestMethod]
    public void TamperedSumcheckMiddleIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using CommitmentSpartanProof proof = Prove(pool);

        //The sumcheck middle starts right after the witness commitment (the
        //digest-wide column-commitment root): flip the first byte of the first
        //outer round.
        MemoryMarshal.AsMemory(proof.AsReadOnlyMemory()).Span[DigestSizeBytes] ^= 0x01;

        bool verified = Verify(proof, pool);
        Assert.IsFalse(verified, "A tampered sumcheck-middle byte must be rejected.");
    }


    /// <summary>Proves the fixture circuit through the Ligero-backed Spartan prover.</summary>
    /// <param name="pool">The pool the prover rents its working buffers from.</param>
    /// <returns>The resulting proof; the caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the proving key and prover transfers through using declarations; the returned proof transfers to the caller.")]
    private static CommitmentSpartanProof Prove(BaseMemoryPool pool)
    {
        using RawR1csInstance instance = BuildInstance();
        using RawR1csWitness witness = BuildWitness();

        var provingKey = new SpartanProvingKey(BuildProvider());
        using var prover = new SpartanProver(provingKey);
        using FiatShamirTranscript transcript = FreshTranscript();

        ScalarRandomDelegate random = new DeterministicScalarRandom(RandomSeed).AsDelegate();

        return prover.ProveCommitted(
            instance, witness, transcript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, pool);
    }


    /// <summary>Verifies a proof against the fixture circuit through the Ligero-backed Spartan verifier.</summary>
    /// <param name="proof">The proof to verify.</param>
    /// <param name="pool">The pool the verifier rents its working buffers from.</param>
    /// <returns><see langword="true"/> when the proof verifies.</returns>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the verifying key and verifier transfers through using declarations.")]
    private static bool Verify(CommitmentSpartanProof proof, BaseMemoryPool pool)
    {
        var verifyingKey = new SpartanVerifyingKey(BuildProvider());
        using var verifier = new SpartanVerifier(verifyingKey);
        using RawR1csInstance instance = BuildInstance();
        using FiatShamirTranscript transcript = FreshTranscript();

        return verifier.VerifyCommitted(
            proof, instance, transcript,
            Add, Multiply, Subtract, Reduce, Hash, Squeeze, pool);
    }


    /// <summary>Builds the Ligero-backed commitment provider this test's Spartan prover and verifier commit and open through.</summary>
    /// <returns>A new Ligero provider; ownership transfers to whichever Spartan key consumes it.</returns>
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


    /// <summary>Builds the fixture circuit's public instance for <c>x · y = 15</c>: <c>z = (1, 15, x, y)</c>, two rows, four columns.</summary>
    /// <returns>The raw R1CS instance; the caller disposes it.</returns>
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


    /// <summary>Builds the fixture circuit's satisfying witness <c>(x, y) = (3, 5)</c>.</summary>
    /// <returns>The raw R1CS witness; the caller disposes it.</returns>
    private static RawR1csWitness BuildWitness()
    {
        int scalarSize = Scalar.SizeBytes;
        byte[] witnessBytes = new byte[2 * scalarSize];
        WriteCanonical(new BigInteger(3), witnessBytes.AsSpan(0 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(5), witnessBytes.AsSpan(1 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witnessBytes, Curve, BaseMemoryPool.Shared);
    }


    /// <summary>Creates a fresh Fiat-Shamir transcript under this test's domain label, ready to absorb a prove or verify run.</summary>
    /// <returns>A new transcript backed by the shared pool.</returns>
    private static FiatShamirTranscript FreshTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(TranscriptDomain),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }


    /// <summary>Concatenates two digests and hashes them with production BLAKE3, the two-to-one compression the Ligero provider's Merkle tree uses.</summary>
    /// <param name="left">The left digest, placed first in the concatenation.</param>
    /// <param name="right">The right digest, placed after <paramref name="left"/>.</param>
    /// <param name="output">The buffer receiving the combined digest.</param>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>Reduces <paramref name="value"/> modulo the BLS12-381 scalar field order and writes it as a canonical big-endian scalar.</summary>
    /// <param name="value">The integer value to reduce and encode.</param>
    /// <param name="destination">The buffer receiving the canonical big-endian scalar; its length fixes the scalar width.</param>
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
