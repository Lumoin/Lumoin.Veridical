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
using Lumoin.Veridical.Tests.ConstraintSystems;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Text;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// End-to-end round-trip tests for the scheme-generic Spartan proof
/// (<see cref="CommitmentSpartanProof"/>) over the hiding BaseFold providers
/// (<see cref="ZkBaseFoldPolynomialCommitmentScheme"/>): each of the three
/// flavours — salted, dimension-lifted, and lifted-plus-masked — proves
/// <c>x · y = 15</c> through <c>ProveCommitted</c> and verifies through
/// <c>VerifyCommitted</c>. Tampering any of the three opaque sections — the
/// shared sumcheck middle, the error opening, or the witness opening — is
/// rejected. Real BLS12-381 arithmetic and production BLAKE3 throughout.
/// </summary>
/// <remarks>
/// <para>
/// A hiding provider draws fresh randomness on every commit, so the two sides
/// cannot each commit the zero error vector and land on the same bytes. Relaxed
/// R1CS already carries the error commitment as public instance data — the
/// property that lets a folded instance carry a non-zero error — so it is
/// committed once here and published to both sides, and the blind that commit
/// returns is the error-opening witness the relaxed prover opens it with. The
/// raw-instance entry points cannot serve a hiding provider for exactly this
/// reason, and the prover's refuses one outright.
/// </para>
/// <para>
/// The proof crosses to the verifier as wire bytes and is reassembled through
/// <see cref="CommitmentSpartanProof.FromBytes"/> with every section length
/// taken from the verifier's own provider. That makes the provider's stated
/// opening and commitment lengths load-bearing: a length the provider states
/// wrongly fails the round-trip instead of passing unnoticed.
/// </para>
/// </remarks>
[TestClass]
internal sealed class ZkBaseFoldCommitmentSpartanRoundtripTests
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

    //The fixture circuit x · y = 15 over z = (1, 15, x, y): two constraints and
    //four columns, so the outer sumcheck runs over one row variable and the
    //inner over two column variables.
    private const int ConstraintCount = 2;
    private const int ColumnCount = 4;
    private const int OuterRoundCount = 1;
    private const int InnerRoundCount = 2;
    private const int WitnessLength = 2;

    //The lifting providers enforce the bounded-independence hiding budget per
    //committed polynomial, and the smallest one this instance routes through a
    //provider has d = 1 (the error vector over the row variable). Because the
    //mask's degrees of freedom are (2^t − 1)·2^d, a smaller witness needs a
    //larger lift, so d = 1 rather than d = 2 sets the floor: t = 6 at
    //TestQueryCount = 8 (GetMinimumExtraVariableCount).
    private const int ExtraVariableCount = 6;

    private const string TranscriptDomain = "veridical.spartan2.basefold.zkgeneric.test.v1";

    private static byte[] CodeSeed { get; } = Encoding.UTF8.GetBytes("veridical.spartan2.basefold.zkgeneric.code.v1");
    private static byte[] SpartanRandomSeed { get; } = Encoding.UTF8.GetBytes("veridical.spartan2.basefold.zkgeneric.rng.v1");
    private static byte[] ProviderRandomSeed { get; } = Encoding.UTF8.GetBytes("veridical.spartan2.basefold.zkgeneric.provider.rng.v1");

    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    /// <summary>Builds a fresh provider of the flavour under test; prover and verifier each get their own.</summary>
    /// <returns>A hiding BaseFold provider.</returns>
    private delegate PolynomialCommitmentProvider ProviderFactory();


    /// <summary>Picks the wire-byte offset to flip, reading the section boundaries off the honest proof.</summary>
    /// <param name="proof">The honest proof whose bytes are about to be copied and tampered.</param>
    /// <returns>The index of the byte to flip.</returns>
    private delegate int TamperOffsetSelector(CommitmentSpartanProof proof);


    /// <summary>
    /// The salted-leaf flavour: a hiding commitment with an ordinary opening
    /// still carries a full Spartan proof through the scheme-generic path, and
    /// the verifier reassembles it from its own provider's stated lengths.
    /// </summary>
    [TestMethod]
    public void XyEquals15RoundTripsThroughTheSaltedProvider()
    {
        AssertRoundTrips(BuildSaltedProvider);
    }


    /// <summary>
    /// The dimension-lift flavour: opening at the lifted layer count leaves the
    /// proven value and the round-trip unchanged, so the lift stays invisible to
    /// the Spartan layer above it.
    /// </summary>
    [TestMethod]
    public void XyEquals15RoundTripsThroughTheLiftedProvider()
    {
        AssertRoundTrips(BuildLiftedProvider);
    }


    /// <summary>
    /// The lift plus the CFS-2017 sumcheck mask: the widest opening this scheme
    /// produces still lays out at the lengths the provider states and verifies.
    /// </summary>
    [TestMethod]
    public void XyEquals15RoundTripsThroughTheFullZeroKnowledgeProvider()
    {
        AssertRoundTrips(BuildFullZeroKnowledgeProvider);
    }


    /// <summary>
    /// The witness opening is the final section, so a flipped byte at the end of
    /// the wire bytes must not verify.
    /// </summary>
    [TestMethod]
    public void TamperedWitnessOpeningIsRejected()
    {
        //The witness opening is the final section; flip its last byte.
        AssertTamperingIsRejected(proof => proof.AsReadOnlySpan().Length - 1);
    }


    /// <summary>
    /// The error opening is the section that ties the error value the sumcheck
    /// identities use to the published hiding commitment, so a flipped byte in it
    /// must not verify.
    /// </summary>
    [TestMethod]
    public void TamperedErrorOpeningIsRejected()
    {
        //The error opening sits between the sumcheck middle and the witness
        //opening; flip its last byte. Nothing else in the proof carries this
        //section's verdict: both identities are checked against E(r_x) as the
        //proof states it, so only this opening binds that value to the
        //commitment the verifier was handed.
        AssertTamperingIsRejected(proof => proof.AsReadOnlySpan().Length - proof.WitnessOpeningSizeBytes - 1);
    }


    /// <summary>
    /// The sumcheck middle begins directly after the witness commitment, so a
    /// flipped byte in the first outer round must not verify.
    /// </summary>
    [TestMethod]
    public void TamperedSumcheckMiddleIsRejected()
    {
        //The sumcheck middle begins where the witness-commitment section ends, so
        //the boundary is the length the proof carries rather than a width this
        //test assumes: flip the first byte of the first outer round.
        AssertTamperingIsRejected(proof => proof.WitnessCommitmentSizeBytes);
    }


    /// <summary>
    /// Preparing a relaxed instance from a raw one reconstructs the error
    /// commitment by recommitting the zero vector, which only reproduces the
    /// other side's commitment where the scheme commits deterministically. The
    /// refusal lives there rather than at each entry point because that is where
    /// the assumption is spent.
    /// </summary>
    [TestMethod]
    public void PreparingFromARawInstanceRefusesAHidingProvider()
    {
        using PolynomialCommitmentProvider provider = BuildFullZeroKnowledgeProvider();
        using RawR1csInstance raw = R1csTestCircuits.BuildMultiplyCircuit();

        Assert.ThrowsExactly<InvalidOperationException>(
            () => raw.Prepare(provider, BaseMemoryPool.Shared),
            "A hiding provider draws fresh randomness per commit, so the commitment reconstructed here is one no other party made.");
    }


    /// <summary>
    /// The raw-instance verify overload reconstructs the error commitment rather
    /// than receiving it, so it refuses a hiding provider outright. Returning the
    /// mismatch as an ordinary rejection would make an honest proof and a forgery
    /// indistinguishable to the caller.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000", Justification = "The provider transfers to the verifying key, which the verifier disposes; every other intermediate is disposed through using declarations.")]
    public void VerifyingAgainstARawInstanceRefusesAHidingProvider()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using IMemoryOwner<byte> publishedOwner = RentPublishedErrorCommitment(BuildFullZeroKnowledgeProvider, pool, out int commitmentLength);
        Span<byte> publishedErrorCommitment = publishedOwner.Memory.Span[..commitmentLength];

        using CommitmentSpartanProof proof = Prove(BuildFullZeroKnowledgeProvider, publishedErrorCommitment, pool);

        PolynomialCommitmentProvider provider = BuildFullZeroKnowledgeProvider();
        var verifyingKey = new SpartanVerifyingKey(provider);
        using var verifier = new SpartanVerifier(verifyingKey);
        using RawR1csInstance raw = R1csTestCircuits.BuildMultiplyCircuit();
        using FiatShamirTranscript transcript = FreshTranscript(pool);

        Assert.ThrowsExactly<InvalidOperationException>(
            () => verifier.VerifyCommitted(proof, raw, transcript, Add, Multiply, Subtract, Reduce, Hash, Squeeze, pool),
            "An honest proof under a hiding provider must not come back as an ordinary rejection.");
    }


    //One honest proof, carried to the verifier as wire bytes and reassembled
    //from the verifier's own section lengths.
    [SuppressMessage("Reliability", "CA2000", Justification = "The proof and the published-commitment buffer are disposed through using declarations.")]
    private static void AssertRoundTrips(ProviderFactory buildProvider)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using IMemoryOwner<byte> publishedOwner = RentPublishedErrorCommitment(buildProvider, pool, out int commitmentLength);
        Span<byte> publishedErrorCommitment = publishedOwner.Memory.Span[..commitmentLength];

        using CommitmentSpartanProof proof = Prove(buildProvider, publishedErrorCommitment, pool);

        AssertSectionLengthsComeFromTheProvider(buildProvider, proof);

        bool verified = Verify(proof.AsReadOnlySpan(), publishedErrorCommitment, buildProvider, pool);
        Assert.IsTrue(verified, "An honest hiding-BaseFold-backed generic Spartan proof must verify.");
    }


    //The same round-trip with one byte flipped in the wire bytes, at the offset
    //the caller derives from the proof's own section lengths.
    [SuppressMessage("Reliability", "CA2000", Justification = "The proof and the rented buffers are disposed through using declarations.")]
    private static void AssertTamperingIsRejected(TamperOffsetSelector chooseOffset)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using IMemoryOwner<byte> publishedOwner = RentPublishedErrorCommitment(BuildFullZeroKnowledgeProvider, pool, out int commitmentLength);
        Span<byte> publishedErrorCommitment = publishedOwner.Memory.Span[..commitmentLength];

        using CommitmentSpartanProof proof = Prove(BuildFullZeroKnowledgeProvider, publishedErrorCommitment, pool);

        int proofLength = proof.AsReadOnlySpan().Length;
        using IMemoryOwner<byte> wireOwner = pool.Rent(proofLength);
        Span<byte> wireBytes = wireOwner.Memory.Span[..proofLength];
        proof.AsReadOnlySpan().CopyTo(wireBytes);
        wireBytes[chooseOffset(proof)] ^= 0x01;

        bool verified = Verify(wireBytes, publishedErrorCommitment, BuildFullZeroKnowledgeProvider, pool);
        Assert.IsFalse(verified, "A tampered proof section must be rejected.");
    }


    //Rents a buffer wide enough for the error commitment, sized from the
    //provider rather than from a figure this test holds.
    private static IMemoryOwner<byte> RentPublishedErrorCommitment(ProviderFactory buildProvider, BaseMemoryPool pool, out int commitmentLength)
    {
        using PolynomialCommitmentProvider provider = buildProvider();
        commitmentLength = provider.CommitmentSizeBytes!(OuterRoundCount);

        return pool.Rent(commitmentLength);
    }


    //Commits the zero error vector, publishes its bytes to the caller, and
    //proves against the relaxed instance that carries them. The blind stays
    //private: it is the error-opening witness, and the raw entry point's
    //zero placeholder would not open a salted commitment.
    [SuppressMessage("Reliability", "CA2000", Justification = "The provider transfers to the proving key, which the prover disposes; every other intermediate is disposed through using declarations, and the returned proof transfers to the caller.")]
    private static CommitmentSpartanProof Prove(ProviderFactory buildProvider, Span<byte> publishedErrorCommitment, BaseMemoryPool pool)
    {
        PolynomialCommitmentProvider provider = buildProvider();
        var provingKey = new SpartanProvingKey(provider);
        using var prover = new SpartanProver(provingKey);

        using MultilinearExtension zeroError = MultilinearExtension.Zero(OuterRoundCount, Curve, pool);
        (PolynomialCommitment errorCommitment, PolynomialCommitmentBlind errorOpeningWitness) = provider.Commit(zeroError, pool);

        using(errorCommitment)
        using(errorOpeningWitness)
        {
            errorCommitment.AsReadOnlySpan().CopyTo(publishedErrorCommitment);

            using RelaxedR1csInstance instance = BuildInstance(publishedErrorCommitment, provider.Scheme, pool);
            using RelaxedR1csWitness witness = BuildWitness(pool);
            using FiatShamirTranscript transcript = FreshTranscript(pool);

            ScalarRandomDelegate random = new DeterministicScalarRandom(SpartanRandomSeed).AsDelegate();

            return prover.ProveCommitted(
                instance, witness, errorOpeningWitness, transcript,
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, random,
                G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, pool);
        }
    }


    //Reassembles the wire bytes from the verifier's own provider figures and
    //verifies against the published error commitment.
    [SuppressMessage("Reliability", "CA2000", Justification = "The provider transfers to the verifying key, which the verifier disposes; every other intermediate is disposed through using declarations.")]
    private static bool Verify(ReadOnlySpan<byte> wireBytes, ReadOnlySpan<byte> publishedErrorCommitment, ProviderFactory buildProvider, BaseMemoryPool pool)
    {
        PolynomialCommitmentProvider provider = buildProvider();
        var verifyingKey = new SpartanVerifyingKey(provider);
        using var verifier = new SpartanVerifier(verifyingKey);

        //The witness is committed and opened over the column variables and the
        //error over the row variables, so the commitment and the two openings
        //are sized at the inner, outer, and inner round counts in turn.
        PolynomialOpeningSizeDelegate openingSize = provider.EvaluationProofSizeBytes!;
        PolynomialCommitmentSizeDelegate commitmentSize = provider.CommitmentSizeBytes!;

        using CommitmentSpartanProof received = CommitmentSpartanProof.FromBytes(
            wireBytes, provider.Scheme, OuterRoundCount, InnerRoundCount,
            commitmentSize(InnerRoundCount), openingSize(OuterRoundCount), openingSize(InnerRoundCount), Curve, pool);

        using RelaxedR1csInstance instance = BuildInstance(publishedErrorCommitment, provider.Scheme, pool);
        using FiatShamirTranscript transcript = FreshTranscript(pool);

        return verifier.VerifyCommitted(
            received, instance, transcript,
            Add, Multiply, Subtract, Reduce, Hash, Squeeze, pool);
    }


    //A total length that happens to match would let compensating section errors
    //through FromBytes unnoticed, so each section is pinned individually against
    //the length the prover actually produced.
    [SuppressMessage("Reliability", "CA2000", Justification = "The provider is disposed through a using declaration.")]
    private static void AssertSectionLengthsComeFromTheProvider(ProviderFactory buildProvider, CommitmentSpartanProof proof)
    {
        using PolynomialCommitmentProvider provider = buildProvider();
        PolynomialOpeningSizeDelegate openingSize = provider.EvaluationProofSizeBytes!;
        PolynomialCommitmentSizeDelegate commitmentSize = provider.CommitmentSizeBytes!;

        Assert.AreEqual(
            commitmentSize(InnerRoundCount),
            proof.WitnessCommitmentSizeBytes,
            "The commitment length the provider states must match the witness commitment it produced.");
        Assert.AreEqual(
            openingSize(OuterRoundCount),
            proof.ErrorOpeningSizeBytes,
            "The opening length the provider states at the row-variable count must match the error opening it produced.");
        Assert.AreEqual(
            openingSize(InnerRoundCount),
            proof.WitnessOpeningSizeBytes,
            "The opening length the provider states at the column-variable count must match the witness opening it produced.");
    }


    //The hiding-commitment flavour: salted Merkle leaves, ordinary opening.
    [SuppressMessage("Reliability", "CA2000", Justification = "The provider holds no disposable key; the caller or the Spartan key that consumes it disposes it.")]
    private static PolynomialCommitmentProvider BuildSaltedProvider()
    {
        ScalarRandomDelegate providerRandom = new DeterministicScalarRandom(ProviderRandomSeed).AsDelegate();

        return ZkBaseFoldPolynomialCommitmentScheme.Create(
            CodeSeed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
            providerRandom, HashToScalar, DigestSizeBytes);
    }


    //The dimension-lift flavour: the opening is query and base-oracle hiding.
    [SuppressMessage("Reliability", "CA2000", Justification = "The provider holds no disposable key; the caller or the Spartan key that consumes it disposes it.")]
    private static PolynomialCommitmentProvider BuildLiftedProvider()
    {
        ScalarRandomDelegate providerRandom = new DeterministicScalarRandom(ProviderRandomSeed).AsDelegate();

        return ZkBaseFoldPolynomialCommitmentScheme.CreateZeroKnowledge(
            CodeSeed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
            providerRandom, HashToScalar, ExtraVariableCount, DigestSizeBytes);
    }


    //The lift plus the CFS-2017 sumcheck mask: the opening is simulatable.
    [SuppressMessage("Reliability", "CA2000", Justification = "The provider holds no disposable key; the caller or the Spartan key that consumes it disposes it.")]
    private static PolynomialCommitmentProvider BuildFullZeroKnowledgeProvider()
    {
        ScalarRandomDelegate providerRandom = new DeterministicScalarRandom(ProviderRandomSeed).AsDelegate();

        return ZkBaseFoldPolynomialCommitmentScheme.CreateFullZeroKnowledge(
            CodeSeed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
            providerRandom, HashToScalar, ExtraVariableCount, DigestSizeBytes);
    }


    //The relaxed instance for x · y = 15 at u = 1, carrying the published error
    //commitment as the public data both sides read it as.
    [SuppressMessage("Reliability", "CA2000", Justification = "The matrices and the error commitment transfer to the returned instance, which disposes them.")]
    private static RelaxedR1csInstance BuildInstance(ReadOnlySpan<byte> errorCommitmentBytes, CommitmentScheme scheme, BaseMemoryPool pool)
    {
        int scalarSize = Scalar.SizeBytes;
        int[] aRows = [0, 1];
        int[] aCols = [2, 0];
        int[] bRows = [0, 1];
        int[] bCols = [3, 0];
        int[] cRows = [0, 1];
        int[] cCols = [1, 0];

        Span<byte> ones = stackalloc byte[2 * Scalar.SizeBytes];
        WriteCanonical(BigInteger.One, ones[..scalarSize]);
        WriteCanonical(BigInteger.One, ones.Slice(scalarSize, scalarSize));

        R1csMatrix a = R1csMatrix.FromSortedTriples(aRows, aCols, ones, ConstraintCount, ColumnCount, Curve, pool);
        R1csMatrix b = R1csMatrix.FromSortedTriples(bRows, bCols, ones, ConstraintCount, ColumnCount, Curve, pool);
        R1csMatrix c = R1csMatrix.FromSortedTriples(cRows, cCols, ones, ConstraintCount, ColumnCount, Curve, pool);

        Span<byte> publicInput = stackalloc byte[Scalar.SizeBytes];
        WriteCanonical(new BigInteger(15), publicInput);

        Span<byte> uBytes = stackalloc byte[Scalar.SizeBytes];
        WriteCanonical(BigInteger.One, uBytes);

        PolynomialCommitment errorCommitment = PolynomialCommitment.FromBytes(errorCommitmentBytes, Curve, scheme, pool);

        return RelaxedR1csInstance.Create(a, b, c, publicInput, uBytes, errorCommitment, pool);
    }


    //The satisfying witness (x, y) = (3, 5) with the zero error vector the
    //published commitment commits to.
    private static RelaxedR1csWitness BuildWitness(BaseMemoryPool pool)
    {
        int scalarSize = Scalar.SizeBytes;
        Span<byte> witnessBytes = stackalloc byte[WitnessLength * Scalar.SizeBytes];
        WriteCanonical(new BigInteger(3), witnessBytes[..scalarSize]);
        WriteCanonical(new BigInteger(5), witnessBytes.Slice(scalarSize, scalarSize));

        Span<byte> errorBytes = stackalloc byte[ConstraintCount * Scalar.SizeBytes];
        errorBytes.Clear();

        return RelaxedR1csWitness.FromCanonical(witnessBytes, errorBytes, Curve, pool);
    }


    private static FiatShamirTranscript FreshTranscript(BaseMemoryPool pool)
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(TranscriptDomain),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            pool);
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
