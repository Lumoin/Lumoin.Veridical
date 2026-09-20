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
/// End-to-end round-trip tests for the masked Spartan2 construction with
/// BaseFold as its polynomial commitment scheme: the masked
/// prover assembles a <see cref="BaseFoldMaskedSpartanProof"/> over
/// <c>x · y = 15</c> through <c>ProveBaseFoldSound</c>, and the masked verifier
/// accepts it through <c>VerifyBaseFoldSound</c>. Tampering a mask-opening byte and a
/// sumcheck-middle byte is rejected.
/// </summary>
/// <remarks>
/// The masked construction's zero-knowledge guarantee assumes a hiding
/// commitment; BaseFold's Merkle commitment is binding but not hiding, so this
/// exercises structural correctness (a sound argument of knowledge), not the
/// witness privacy the "masked" name implies: witness hiding requires a
/// hiding polynomial commitment scheme, and a Merkle-tree commitment is
/// binding without being hiding.
/// </remarks>
[TestClass]
internal sealed class BaseFoldMaskedSpartanRoundtripTests
{
    /// <summary>The production BLAKE3 Fiat-Shamir hash delegate every transcript in this class is built from.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The production BLAKE3 Fiat-Shamir squeeze delegate every transcript in this class draws challenges through.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();

    /// <summary>The BigInteger reference scalar-reduction delegate for the BLS12-381 scalar field.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();

    /// <summary>The validated BLS12-381 scalar addition delegate the masked Spartan-over-BaseFold prove/verify runs on.</summary>
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;

    /// <summary>The validated BLS12-381 scalar subtraction delegate the masked Spartan-over-BaseFold prove/verify runs on.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;

    /// <summary>The validated BLS12-381 scalar multiplication delegate the masked Spartan-over-BaseFold prove/verify runs on.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;

    /// <summary>The validated BLS12-381 scalar inversion delegate the masked Spartan-over-BaseFold prove/verify runs on.</summary>
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;

    /// <summary>The BigInteger reference hash-to-scalar delegate the BaseFold provider derives its challenges through.</summary>
    private static ScalarHashToScalarDelegate HashToScalar { get; } = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();

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

    /// <summary>The two-to-one Merkle hash delegate backing the BaseFold provider, implemented with production BLAKE3 through <see cref="HashTwoToOne"/>.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    /// <summary>The Merkle digest width the BaseFold provider and hash delegate use, taken from the library's default Merkle parameters.</summary>
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    /// <summary>The opened-column count the BaseFold provider uses; small enough to keep the fixture fast.</summary>
    private const int TestQueryCount = 8;

    /// <summary>The Fiat-Shamir domain-separation label for this test's transcript, distinguishing it from every other transcript domain in the suite.</summary>
    private const string TranscriptDomain = "veridical.spartan2.basefold.masked.test.v1";

    /// <summary>The BaseFold code seed deriving this test's provider's linear code, distinguishing it from every other test's codes.</summary>
    private static byte[] CodeSeed { get; } = Encoding.UTF8.GetBytes("veridical.spartan2.basefold.masked.code.v1");

    /// <summary>The seed for the deterministic randomness the masked Spartan prover draws its masking scalars from.</summary>
    private static byte[] RandomSeed { get; } = Encoding.UTF8.GetBytes("veridical.spartan2.basefold.masked.rng.v1");

    /// <summary>The BLS12-381 curve parameter set this test's arithmetic and commitments run over.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    /// <summary>Verifies that an honest masked BaseFold-backed Spartan proof of <c>x · y = 15</c> verifies.</summary>
    [TestMethod]
    public void XyEquals15RoundTripsThroughMaskedBaseFold()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using BaseFoldMaskedSpartanProof proof = Prove(pool);

        Assert.IsTrue(Verify(proof, pool), "An honest masked BaseFold-backed Spartan proof must verify.");
    }


    /// <summary>Verifies that flipping the last byte of an honest proof (inside the witness-opening section) makes verification reject.</summary>
    [TestMethod]
    public void TamperedWitnessOpeningIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using BaseFoldMaskedSpartanProof proof = Prove(pool);

        //The witness opening is the final section; flip its last byte.
        MemoryMarshal.AsMemory(proof.AsReadOnlyMemory()).Span[^1] ^= 0x01;

        Assert.IsFalse(Verify(proof, pool), "A tampered witness-opening section must be rejected.");
    }


    /// <summary>Verifies that flipping the first byte of the shared sumcheck middle (right after the three roots and two mask-sum scalars) makes verification reject.</summary>
    [TestMethod]
    public void TamperedSumcheckMiddleIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using BaseFoldMaskedSpartanProof proof = Prove(pool);

        //The sumcheck middle starts after three 32-byte roots and the two
        //mask-sum scalars; flip the first byte of the first outer round.
        MemoryMarshal.AsMemory(proof.AsReadOnlyMemory()).Span[(3 * DigestSizeBytes) + (2 * 32)] ^= 0x01;

        Assert.IsFalse(Verify(proof, pool), "A tampered sumcheck-middle byte must be rejected.");
    }


    /// <summary>Produces the test proof and releases provider storage through the owning prover.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The provider's pooled storage transfers to the proving key and the key to the prover, which the using declaration releases; the key and prover constructors cannot fail for a non-null argument, so no path leaves the provider unreleased.")]
    private static BaseFoldMaskedSpartanProof Prove(BaseMemoryPool pool)
    {
        using RawR1csInstance instance = BuildInstance();
        using RawR1csWitness witness = BuildWitness();

        var provingKey = new SpartanProvingKey(BuildProvider(pool));
        using var prover = new MaskedSpartanProver(provingKey);
        using FiatShamirTranscript transcript = FreshTranscript();

        ScalarRandomDelegate random = new DeterministicScalarRandom(RandomSeed).AsDelegate();

        return prover.ProveBaseFoldSound(
            instance, witness, transcript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, pool);
    }


    /// <summary>Verifies the test proof and releases provider storage through the owning verifier.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The provider's pooled storage transfers to the verifying key and the key to the verifier, which the using declaration releases; the key and verifier constructors cannot fail for a non-null argument, so no path leaves the provider unreleased.")]
    private static bool Verify(BaseFoldMaskedSpartanProof proof, BaseMemoryPool pool)
    {
        var verifyingKey = new SpartanVerifyingKey(BuildProvider(pool));
        using var verifier = new MaskedSpartanVerifier(verifyingKey);
        using RawR1csInstance instance = BuildInstance();
        using FiatShamirTranscript transcript = FreshTranscript();

        return verifier.VerifyBaseFoldSound(
            proof, instance, transcript,
            Add, Multiply, Subtract, Invert, Reduce, Hash, Squeeze, pool);
    }


    /// <summary>Builds the commitment provider using the caller's pool.</summary>
    /// <param name="pool">The pool supplied by the test.</param>
    private static PolynomialCommitmentProvider BuildProvider(BaseMemoryPool pool)
    {
        return BaseFoldPolynomialCommitmentScheme.Create(
            CodeSeed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, HashToScalar, pool, DigestSizeBytes);
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


    /// <summary>Concatenates two digests and hashes them with production BLAKE3, the two-to-one compression the BaseFold provider's Merkle tree uses.</summary>
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
