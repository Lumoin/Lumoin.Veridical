using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Whir;
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
using System.Runtime.InteropServices;
using System.Text;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// End-to-end round-trip tests for Spartan with WHIR as its polynomial
/// commitment scheme, through the scheme-generic
/// <see cref="CommitmentSpartanProof"/>. The prover assembles a proof over a
/// padded <c>x · y = 15</c> instance and the verifier accepts it; flipping a
/// byte in the witness-opening section or in the shared sumcheck middle is
/// rejected. Real BLS12-381 arithmetic and production BLAKE3 throughout.
/// </summary>
/// <remarks>
/// <para>
/// The instance is padded to 256 rows and 256 columns rather than using the
/// two-row form the other round-trip tests share, because WHIR imposes a floor
/// the other schemes do not. It cannot open a polynomial in fewer variables
/// than its folding parameter, and each round's queries must land on distinct
/// cosets of the folded domain, so a polynomial in one or two variables carries
/// no meaningful soundness under it at any rate. Padding an R1CS with zero rows
/// preserves satisfaction — a zero row asserts <c>0 · 0 = 0</c> — so the padded
/// instance proves the same statement at a shape WHIR can actually commit to.
/// </para>
/// <para>
/// The per-round soundness target is deliberately low. It is the largest whole
/// level this shape can place on distinct query cosets, matching the figure the
/// other WHIR tests use; a deployment target belongs to a deployment-sized
/// instance, not to a fixture.
/// </para>
/// </remarks>
[TestClass]
internal sealed class WhirSpartanRoundtripTests
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = 32;

    /// <summary>
    /// The padded instance's row and column count. Both give eight variables,
    /// which clears the folding parameter and leaves a folded query domain of
    /// 64 cosets against a query count of 36.
    /// </summary>
    private const int PaddedDimension = 256;

    /// <summary>The number of leading <c>z</c> entries that are not witness: the constant one and the single public input.</summary>
    private const int NonWitnessEntryCount = 2;

    /// <summary>The provider's initial inverse-rate exponent: rate 1/4.</summary>
    private const int InitialRateLog2 = 2;

    /// <summary>
    /// The provider's per-round target: 24 bits is the largest whole level the
    /// padded shape can place on distinct query cosets.
    /// </summary>
    private const int SecurityLevelBits = 24;

    /// <summary>The wired Merkle digest size: BLAKE3's 32 bytes.</summary>
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    /// <summary>The transcript domain separating these fixtures from every other protocol.</summary>
    private const string TranscriptDomain = "veridical.spartan2.whir.test.v1";

    /// <summary>The Blake3-backed Fiat–Shamir hash delegate.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The Blake3-backed Fiat–Shamir squeeze delegate.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();

    /// <summary>The BLS12-381 scalar reduction delegate.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();

    /// <summary>The BLS12-381 scalar addition delegate.</summary>
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;

    /// <summary>The BLS12-381 scalar subtraction delegate.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;

    /// <summary>The BLS12-381 scalar multiplication delegate.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;

    /// <summary>The BLS12-381 scalar inversion delegate.</summary>
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;

    /// <summary>The BLS12-381 G1 addition delegate.</summary>
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();

    /// <summary>The BLS12-381 G1 scalar-multiplication delegate.</summary>
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();

    /// <summary>The BLS12-381 G1 multi-scalar-multiplication delegate.</summary>
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;

    /// <summary>The reference multilinear-extension evaluation delegate.</summary>
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();

    /// <summary>The reference multilinear-extension fold delegate.</summary>
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();

    /// <summary>The two-to-one Merkle compression delegate, wired to <see cref="HashTwoToOne"/>.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    /// <summary>The deterministic seed the prover's randomness is drawn from.</summary>
    private static byte[] RandomSeed { get; } = Encoding.UTF8.GetBytes("veridical.spartan2.whir.roundtrip.rng.v1");

    /// <summary>The curve every artifact is tagged with.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    /// <summary>
    /// The scheme-generic Spartan path produces a WHIR-backed proof that the
    /// scheme-generic verifier accepts. This is the statement that WHIR is a
    /// usable Spartan commitment scheme at all.
    /// </summary>
    [TestMethod]
    public void PaddedMultiplyRoundTripsThroughWhir()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using CommitmentSpartanProof proof = Prove(pool);

        Assert.AreEqual(CommitmentScheme.Whir, proof.Scheme, "The proof must record the scheme it was produced under.");
        Assert.IsTrue(Verify(proof, pool), "An honest WHIR-backed Spartan proof must verify.");
    }


    /// <summary>
    /// The proof's section lengths must be exactly what the provider's sizing
    /// seam states for the two opening variable counts. If they drifted, the
    /// verifier would slice the wire bytes at the wrong offsets.
    /// </summary>
    [TestMethod]
    public void SectionLengthsMatchTheProviderSizingSeam()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using CommitmentSpartanProof proof = Prove(pool);
        using PolynomialCommitmentProvider provider = BuildProvider();

        PolynomialOpeningSizeDelegate seam = provider.EvaluationProofSizeBytes!;

        Assert.AreEqual(DigestSizeBytes, proof.WitnessCommitmentSizeBytes, "The WHIR witness commitment is one Merkle root.");
        Assert.AreEqual(seam(proof.OuterRoundCount), proof.ErrorOpeningSizeBytes, "The error opening must be the length the provider states for the row variables.");
        Assert.AreEqual(seam(proof.InnerRoundCount), proof.WitnessOpeningSizeBytes, "The witness opening must be the length the provider states for the column variables.");
    }


    /// <summary>
    /// The witness opening is the final section; a flipped byte there must not
    /// verify.
    /// </summary>
    [TestMethod]
    public void TamperedWitnessOpeningIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using CommitmentSpartanProof proof = Prove(pool);

        MemoryMarshal.AsMemory(proof.AsReadOnlyMemory()).Span[^1] ^= 0x01;

        Assert.IsFalse(Verify(proof, pool), "A tampered witness-opening section must be rejected.");
    }


    /// <summary>
    /// The sumcheck middle begins directly after the witness commitment; a
    /// flipped byte in the first outer round must not verify.
    /// </summary>
    [TestMethod]
    public void TamperedSumcheckMiddleIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using CommitmentSpartanProof proof = Prove(pool);

        MemoryMarshal.AsMemory(proof.AsReadOnlyMemory()).Span[proof.WitnessCommitmentSizeBytes] ^= 0x01;

        Assert.IsFalse(Verify(proof, pool), "A tampered sumcheck-middle byte must be rejected.");
    }


    /// <summary>Proves the padded instance and witness through the WHIR-backed scheme-generic Spartan prover.</summary>
    /// <param name="pool">The pool the proof rents from.</param>
    /// <returns>The pooled proof; the caller disposes it.</returns>
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


    /// <summary>Verifies a proof against a freshly built instance through the WHIR-backed scheme-generic Spartan verifier.</summary>
    /// <param name="proof">The proof to verify.</param>
    /// <param name="pool">The pool the verifier rents from.</param>
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


    /// <summary>Builds the WHIR polynomial commitment provider these tests share, at the padded shape's fixed rate and security level.</summary>
    /// <returns>The new provider.</returns>
    [SuppressMessage("Reliability", "CA2000", Justification = "The WHIR provider holds no disposable key; the Spartan key that consumes it disposes it.")]
    private static PolynomialCommitmentProvider BuildProvider()
    {
        return WhirPolynomialCommitmentScheme.Create(
            Curve,
            InitialRateLog2,
            Merkle,
            Hash,
            Squeeze,
            Reduce,
            Add,
            Subtract,
            Multiply,
            Invert,
            securityLevelBits: SecurityLevelBits);
    }


    /// <summary>
    /// Builds the <c>x · y = 15</c> circuit padded to 256 x 256: <c>z = (1, 15, x, y, 0, …)</c>.
    /// The two live rows carry the multiplication and its trivial companion; every other row is
    /// all-zero, which asserts <c>0 · 0 = 0</c> and is satisfied by any <c>z</c>.
    /// </summary>
    private static RawR1csInstance BuildInstance()
    {
        int[] aRows = [0, 1];
        int[] aCols = [2, 0];
        int[] bRows = [0, 1];
        int[] bCols = [3, 0];
        int[] cRows = [0, 1];
        int[] cCols = [1, 0];

        Span<byte> ones = stackalloc byte[2 * ScalarSize];
        WriteCanonical(BigInteger.One, ones[..ScalarSize]);
        WriteCanonical(BigInteger.One, ones.Slice(ScalarSize, ScalarSize));

        R1csMatrix a = R1csMatrix.FromSortedTriples(aRows, aCols, ones, PaddedDimension, PaddedDimension, Curve, BaseMemoryPool.Shared);
        R1csMatrix b = R1csMatrix.FromSortedTriples(bRows, bCols, ones, PaddedDimension, PaddedDimension, Curve, BaseMemoryPool.Shared);
        R1csMatrix c = R1csMatrix.FromSortedTriples(cRows, cCols, ones, PaddedDimension, PaddedDimension, Curve, BaseMemoryPool.Shared);

        Span<byte> publicInput = stackalloc byte[ScalarSize];
        WriteCanonical(new BigInteger(15), publicInput);

        return RawR1csInstance.Create(a, b, c, publicInput, BaseMemoryPool.Shared);
    }


    /// <summary>Builds the witness: <c>(x, y)</c> followed by the zero padding the extra columns need.</summary>
    private static RawR1csWitness BuildWitness()
    {
        int witnessEntryCount = PaddedDimension - NonWitnessEntryCount;
        int witnessBytes = witnessEntryCount * ScalarSize;

        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(witnessBytes);
        Span<byte> witness = owner.Memory.Span[..witnessBytes];
        witness.Clear();
        WriteCanonical(new BigInteger(3), witness[..ScalarSize]);
        WriteCanonical(new BigInteger(5), witness.Slice(ScalarSize, ScalarSize));

        return RawR1csWitness.FromCanonical(witness, Curve, BaseMemoryPool.Shared);
    }


    /// <summary>Creates a fresh transcript under this test's domain label.</summary>
    /// <returns>The new transcript.</returns>
    private static FiatShamirTranscript FreshTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(TranscriptDomain),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }


    /// <summary>The two-to-one compression: BLAKE3 over the concatenated children.</summary>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>Writes a field element in canonical big-endian form.</summary>
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
