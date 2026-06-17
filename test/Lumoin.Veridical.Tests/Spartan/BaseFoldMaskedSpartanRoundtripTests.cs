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

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// End-to-end round-trip tests for the masked Spartan2 construction with
/// BaseFold as its polynomial commitment scheme (AB.5 Stage B): the masked
/// prover assembles a <see cref="BaseFoldMaskedSpartanProof"/> over
/// <c>x · y = 15</c> through <c>ProveBaseFold</c>, and the masked verifier
/// accepts it through <c>VerifyBaseFold</c>. Tampering a mask-opening byte and a
/// sumcheck-middle byte is rejected.
/// </summary>
/// <remarks>
/// The masked construction's zero-knowledge guarantee assumes a hiding
/// commitment; BaseFold's Merkle commitment is binding but not hiding, so this
/// exercises structural correctness (a sound argument of knowledge), not the
/// witness privacy the "masked" name implies. See BASEFOLD.md.
/// </remarks>
[TestClass]
internal sealed class BaseFoldMaskedSpartanRoundtripTests
{
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;
    private static ScalarHashToScalarDelegate HashToScalar { get; } = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;
    private const int TestQueryCount = 8;
    private const string TranscriptDomain = "veridical.spartan2.basefold.masked.test.v1";

    private static readonly byte[] CodeSeed = Encoding.UTF8.GetBytes("veridical.spartan2.basefold.masked.code.v1");
    private static readonly byte[] RandomSeed = Encoding.UTF8.GetBytes("veridical.spartan2.basefold.masked.rng.v1");

    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    public void XyEquals15RoundTripsThroughMaskedBaseFold()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using BaseFoldMaskedSpartanProof proof = Prove(pool);

        Assert.IsTrue(Verify(proof, pool), "An honest masked BaseFold-backed Spartan proof must verify.");
    }


    [TestMethod]
    public void TamperedWitnessOpeningIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using BaseFoldMaskedSpartanProof proof = Prove(pool);

        //The witness opening is the final section; flip its last byte.
        proof.AsSpan()[^1] ^= 0x01;

        Assert.IsFalse(Verify(proof, pool), "A tampered witness-opening section must be rejected.");
    }


    [TestMethod]
    public void TamperedSumcheckMiddleIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using BaseFoldMaskedSpartanProof proof = Prove(pool);

        //The sumcheck middle starts after three 32-byte roots and the two
        //mask-sum scalars; flip the first byte of the first outer round.
        proof.AsSpan()[(3 * DigestSizeBytes) + (2 * 32)] ^= 0x01;

        Assert.IsFalse(Verify(proof, pool), "A tampered sumcheck-middle byte must be rejected.");
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership transfers through using declarations; the returned proof transfers to the caller.")]
    private static BaseFoldMaskedSpartanProof Prove(BaseMemoryPool pool)
    {
        using RawR1csInstance instance = BuildInstance();
        using RawR1csWitness witness = BuildWitness();

        var provingKey = new SpartanProvingKey(BuildProvider());
        using var prover = new MaskedSpartanProver(provingKey);
        using FiatShamirTranscript transcript = FreshTranscript();

        ScalarRandomDelegate random = new DeterministicScalarRandom(RandomSeed).AsDelegate();

        return prover.ProveBaseFold(
            instance, witness, transcript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, pool);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership transfers through using declarations.")]
    private static bool Verify(BaseFoldMaskedSpartanProof proof, BaseMemoryPool pool)
    {
        var verifyingKey = new SpartanVerifyingKey(BuildProvider());
        using var verifier = new MaskedSpartanVerifier(verifyingKey);
        using RawR1csInstance instance = BuildInstance();
        using FiatShamirTranscript transcript = FreshTranscript();

        return verifier.VerifyBaseFold(
            proof, instance, transcript,
            Add, Multiply, Subtract, Invert, Reduce, Hash, Squeeze, pool);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The BaseFold provider holds no disposable key; the Spartan key that consumes it disposes it.")]
    private static PolynomialCommitmentProvider BuildProvider()
    {
        return BaseFoldPolynomialCommitmentScheme.Create(
            CodeSeed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, HashToScalar, DigestSizeBytes);
    }


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
